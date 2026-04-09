"""
Parallel Scan Engine — asyncio + multiprocessing parallel scanning
===================================================================
Manages a priority queue of scan tasks and executes them concurrently
across multiple worker coroutines, with per-domain rate limiting to avoid
hammering the same target simultaneously.

Usage:
    from oneinfinity.scan.parallel_scan_engine import parallel_scan_engine

    task_id = parallel_scan_engine.submit("example.com", priority=8)
    parallel_scan_engine.run_until_complete()
    result = parallel_scan_engine.get_status(task_id)

    # Or via the simple wrapper:
    from oneinfinity.scan.parallel_scan_engine import scan_queue_manager
    scan_queue_manager.add_target("example.com", priority=5)
    scan_queue_manager.process_all()
    results = scan_queue_manager.get_results()
"""

import asyncio
import multiprocessing
import concurrent.futures
import threading
import time
import logging
import uuid
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, List

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanTask:
    """Represents a single scan job in the queue."""
    task_id: str
    target: str
    priority: int = 5                 # 1 (lowest) – 10 (highest)
    config: dict = field(default_factory=dict)
    status: str = "queued"            # queued / running / complete / failed
    result: Optional[dict] = None
    error: str = ""
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "target": self.target,
            "priority": self.priority,
            "config": self.config,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_s": (
                round(self.completed_at - self.started_at, 2)
                if self.started_at and self.completed_at
                else None
            ),
        }


@dataclass
class WorkerStats:
    """Accumulated statistics for a single worker coroutine."""
    worker_id: int
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_duration_s: float = 0.0

    @property
    def avg_duration_s(self) -> float:
        total = self.tasks_completed + self.tasks_failed
        return round(self.total_duration_s / total, 2) if total else 0.0

    def to_dict(self) -> dict:
        return {
            "worker_id": self.worker_id,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "total_duration_s": round(self.total_duration_s, 2),
            "avg_duration_s": self.avg_duration_s,
        }


# ══════════════════════════════════════════════════════════════════════════════
# PARALLEL SCAN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class ParallelScanEngine:
    """
    Manages multiple async worker coroutines that consume from a shared priority
    queue.  Each worker runs one scan at a time; at most ``max_workers`` scans
    run concurrently.  A per-domain lock prevents the same domain from being
    scanned twice in parallel.

    Thread safety: all public methods are safe to call from any thread.  They
    post to an internal asyncio queue that is consumed on the engine's event
    loop thread.
    """

    def __init__(self, max_workers: int = 4, max_queue_size: int = 100):
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        self.max_concurrent_per_domain = 1

        # Task registry — keyed by task_id
        self._tasks: Dict[str, ScanTask] = {}
        self._tasks_lock = threading.Lock()

        # Pending queue (sorted list, guarded by lock)
        self._pending: List[ScanTask] = []
        self._pending_lock = threading.Lock()

        # Worker statistics
        self._worker_stats: Dict[int, WorkerStats] = {
            i: WorkerStats(worker_id=i) for i in range(max_workers)
        }

        # Active domains set — prevents duplicate concurrent domain scans
        self._active_domains: set = set()
        self._domains_lock = threading.Lock()

        # Asyncio primitives (created lazily on the engine's loop)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_queue: Optional[asyncio.Queue] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._background_thread: Optional[threading.Thread] = None
        self._running = False
        self._shutdown_event = threading.Event()

        # Thread-pool for blocking pipeline calls
        cpu_count = multiprocessing.cpu_count()
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(max_workers, cpu_count),
            thread_name_prefix="scan-worker",
        )

        # Optional progress callback: fn(task_id, status, msg)
        self._progress_cb: Optional[Callable] = None

    # ── Submission API ────────────────────────────────────────────────────────

    def submit(self, target: str, priority: int = 5,
               config: Optional[dict] = None) -> str:
        """
        Enqueue a scan task. Returns the task_id.

        Parameters
        ----------
        target   : hostname or URL to scan
        priority : 1 (low) – 10 (high); higher priority tasks run first
        config   : optional dict forwarded to PipelineConfig
        """
        if len(self._tasks) >= self.max_queue_size:
            raise RuntimeError(
                f"Queue is full ({self.max_queue_size} tasks). "
                "Call run_until_complete() or cancel some tasks first."
            )

        task = ScanTask(
            task_id=str(uuid.uuid4()),
            target=target,
            priority=max(1, min(10, priority)),
            config=config or {},
        )

        with self._tasks_lock:
            self._tasks[task.task_id] = task

        with self._pending_lock:
            self._pending.append(task)
            self._prioritize_queue_locked()

        # If a live async queue exists, push immediately
        if self._async_queue and self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(
                self._async_queue.put(task.task_id), self._loop
            )

        logger.info("[parallel] Submitted task %s for %s (priority=%d)",
                    task.task_id[:8], target, priority)
        return task.task_id

    def submit_batch(self, targets: List[str],
                     config: Optional[dict] = None) -> List[str]:
        """Submit multiple targets with default priority. Returns list of task_ids."""
        return [self.submit(t, priority=5, config=config) for t in targets]

    # ── Execution API ─────────────────────────────────────────────────────────

    def run_until_complete(self):
        """
        Process all queued (and subsequently submitted) tasks synchronously.
        Blocks the calling thread until the queue is drained.
        """
        loop = asyncio.new_event_loop()
        self._loop = loop
        try:
            loop.run_until_complete(self._run_event_loop())
        finally:
            self._loop = None
            loop.close()

    def run_background(self):
        """
        Start processing tasks in a background daemon thread.  Returns
        immediately.  Use ``get_status()`` / ``get_results()`` to poll.
        """
        if self._background_thread and self._background_thread.is_alive():
            logger.warning("[parallel] Background thread already running.")
            return

        self._shutdown_event.clear()
        self._running = True

        def _bg():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            try:
                loop.run_until_complete(self._run_event_loop())
            finally:
                self._running = False
                self._loop = None
                loop.close()

        self._background_thread = threading.Thread(
            target=_bg, daemon=True, name="parallel-scan-engine"
        )
        self._background_thread.start()
        logger.info("[parallel] Background scan engine started (%d workers)", self.max_workers)

    def stop(self):
        """Signal the background loop to stop after finishing current tasks."""
        self._shutdown_event.set()
        self._running = False
        if self._background_thread:
            self._background_thread.join(timeout=10)

    # ── Status / Results API ──────────────────────────────────────────────────

    def get_status(self, task_id: str) -> Optional[ScanTask]:
        """Return the ScanTask for a given task_id, or None if unknown."""
        with self._tasks_lock:
            return self._tasks.get(task_id)

    def get_all_tasks(self) -> List[ScanTask]:
        """Return a copy of all registered tasks."""
        with self._tasks_lock:
            return list(self._tasks.values())

    def get_results(self) -> List[ScanTask]:
        """Return only completed tasks (status == 'complete')."""
        with self._tasks_lock:
            return [t for t in self._tasks.values() if t.status == "complete"]

    def cancel(self, task_id: str) -> bool:
        """
        Cancel a queued task. Returns True if cancelled, False if it was
        already running/complete or not found.
        """
        with self._tasks_lock:
            task = self._tasks.get(task_id)
            if not task or task.status != "queued":
                return False
            task.status = "failed"
            task.error = "Cancelled by user"
            task.completed_at = time.time()

        with self._pending_lock:
            self._pending = [t for t in self._pending if t.task_id != task_id]

        logger.info("[parallel] Task %s cancelled", task_id[:8])
        return True

    def set_progress_callback(self, cb: Callable):
        """Register a callback fn(task_id, status, message) for progress updates."""
        self._progress_cb = cb

    # ── Stats API ─────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return engine-wide statistics dict."""
        with self._tasks_lock:
            all_tasks = list(self._tasks.values())

        queued    = sum(1 for t in all_tasks if t.status == "queued")
        running   = sum(1 for t in all_tasks if t.status == "running")
        completed = sum(1 for t in all_tasks if t.status == "complete")
        failed    = sum(1 for t in all_tasks if t.status == "failed")

        with self._domains_lock:
            active_domains = list(self._active_domains)

        return {
            "queue_size": queued,
            "running": running,
            "completed": completed,
            "failed": failed,
            "total": len(all_tasks),
            "active_domains": active_domains,
            "worker_stats": [ws.to_dict() for ws in self._worker_stats.values()],
            "max_workers": self.max_workers,
        }

    # ── Internal Async Core ───────────────────────────────────────────────────

    async def _run_event_loop(self):
        """Main coroutine: sets up shared primitives and spawns workers."""
        self._async_queue = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(self.max_workers)

        # Seed queue from already-pending tasks (submitted before loop started)
        with self._pending_lock:
            for task in list(self._pending):
                await self._async_queue.put(task.task_id)

        # Spawn workers
        workers = [
            asyncio.create_task(self._worker(worker_id))
            for worker_id in range(self.max_workers)
        ]

        logger.info("[parallel] %d workers started", self.max_workers)

        # Wait for queue to drain (or shutdown signal)
        drain_task = asyncio.create_task(self._async_queue.join())
        shutdown_check = asyncio.create_task(self._poll_shutdown())

        done, pending = await asyncio.wait(
            [drain_task, shutdown_check],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Cancel workers
        for w in workers:
            w.cancel()
        for p in pending:
            p.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        logger.info("[parallel] All workers stopped")

    async def _poll_shutdown(self):
        """Coroutine that resolves when the shutdown event is set."""
        while not self._shutdown_event.is_set():
            await asyncio.sleep(0.5)

    async def _worker(self, worker_id: int):
        """
        Worker coroutine: continuously pulls task IDs from the async queue,
        respects per-domain rate limiting, and runs each task.
        """
        stats = self._worker_stats[worker_id]
        logger.debug("[worker-%d] Started", worker_id)

        while True:
            try:
                task_id = await self._async_queue.get()
            except asyncio.CancelledError:
                logger.debug("[worker-%d] Cancelled", worker_id)
                break

            try:
                with self._tasks_lock:
                    task = self._tasks.get(task_id)

                if task is None or task.status in ("failed", "complete"):
                    # Already cancelled or processed
                    self._async_queue.task_done()
                    continue

                # Per-domain rate limiting
                domain = self._extract_domain(task.target)
                domain_available = False
                for _ in range(30):           # wait up to ~15s
                    with self._domains_lock:
                        if domain not in self._active_domains:
                            self._active_domains.add(domain)
                            domain_available = True
                            break
                    await asyncio.sleep(0.5)

                if not domain_available:
                    # Re-queue with slight delay to avoid starvation
                    logger.warning(
                        "[worker-%d] Domain %s still busy, re-queuing task %s",
                        worker_id, domain, task_id[:8]
                    )
                    await asyncio.sleep(2.0)
                    await self._async_queue.put(task_id)
                    self._async_queue.task_done()
                    continue

                # Run the task under the concurrency semaphore
                async with self._semaphore:
                    t0 = time.time()
                    try:
                        await self._run_task(task, worker_id)
                        stats.tasks_completed += 1
                    except Exception as exc:
                        stats.tasks_failed += 1
                        logger.error("[worker-%d] Task %s failed: %s",
                                     worker_id, task_id[:8], exc, exc_info=True)
                        with self._tasks_lock:
                            task.status = "failed"
                            task.error = str(exc)
                            task.completed_at = time.time()
                    finally:
                        stats.total_duration_s += time.time() - t0
                        with self._domains_lock:
                            self._active_domains.discard(domain)

            except asyncio.CancelledError:
                logger.debug("[worker-%d] Cancelled mid-task", worker_id)
                break
            except Exception as exc:
                logger.error("[worker-%d] Unexpected error: %s", worker_id, exc, exc_info=True)
            finally:
                try:
                    self._async_queue.task_done()
                except Exception:
                    pass

        logger.debug("[worker-%d] Exiting", worker_id)

    async def _run_task(self, task: ScanTask, worker_id: int):
        """
        Execute a single scan task.  Updates task status, calls
        autonomous_scan_pipeline.run_async(), and stores result.
        """
        with self._tasks_lock:
            task.status = "running"
            task.started_at = time.time()

        # Remove from pending list
        with self._pending_lock:
            self._pending = [t for t in self._pending if t.task_id != task.task_id]

        self._emit_progress(task.task_id, "running",
                            f"[worker-{worker_id}] Starting scan of {task.target}")
        logger.info("[worker-%d] Running scan: %s  task=%s",
                    worker_id, task.target, task.task_id[:8])

        try:
            # Build PipelineConfig from task config dict
            from oneinfinity.scan.autonomous_scan_pipeline import (
                autonomous_scan_pipeline, PipelineConfig, PipelinePhase
            )

            cfg_dict = task.config or {}
            phases_raw = cfg_dict.pop("phases", None)
            if phases_raw:
                try:
                    phases = [PipelinePhase(p) for p in phases_raw]
                except ValueError:
                    phases = list(PipelinePhase)
            else:
                phases = list(PipelinePhase)

            pipeline_config = PipelineConfig(
                target=task.target,
                phases=phases,
                max_duration_s=cfg_dict.get("max_duration_s", 3600),
                auto_exploit=cfg_dict.get("auto_exploit", False),
                validate_findings=cfg_dict.get("validate_findings", True),
                generate_report=cfg_dict.get("generate_report", True),
            )

            scan_result = await autonomous_scan_pipeline.run_async(
                task.target, pipeline_config
            )
            result_dict = scan_result.to_dict() if hasattr(scan_result, "to_dict") else {}

            with self._tasks_lock:
                task.status = "complete"
                task.result = result_dict
                task.completed_at = time.time()

            duration = round(task.completed_at - task.started_at, 2)
            self._emit_progress(task.task_id, "complete",
                                f"[worker-{worker_id}] Scan complete: {task.target} ({duration}s)")
            logger.info("[worker-%d] Completed: %s  task=%s  duration=%.1fs  findings=%d",
                        worker_id, task.target, task.task_id[:8], duration,
                        len(result_dict.get("findings", [])))

        except ImportError as exc:
            # autonomous_scan_pipeline not importable — minimal fallback
            logger.error("[worker-%d] autonomous_scan_pipeline unavailable: %s", worker_id, exc)
            with self._tasks_lock:
                task.status = "failed"
                task.error = f"autonomous_scan_pipeline not available: {exc}"
                task.completed_at = time.time()
            self._emit_progress(task.task_id, "failed",
                                f"Pipeline unavailable: {exc}")

    # ── Queue Management ──────────────────────────────────────────────────────

    def _prioritize_queue(self):
        """Sort the pending list by priority (descending). Thread-safe."""
        with self._pending_lock:
            self._prioritize_queue_locked()

    def _prioritize_queue_locked(self):
        """Sort pending queue by priority descending. Caller must hold _pending_lock."""
        self._pending.sort(key=lambda t: t.priority, reverse=True)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_domain(target: str) -> str:
        """Extract the bare hostname from a URL or domain string."""
        import urllib.parse as _up
        if "://" in target:
            parsed = _up.urlparse(target)
            return parsed.netloc.split(":")[0]
        return target.split(":")[0].split("/")[0]

    def _emit_progress(self, task_id: str, status: str, msg: str):
        """Call progress callback if registered, always log."""
        if self._progress_cb:
            try:
                self._progress_cb(task_id, status, msg)
            except Exception as exc:
                logger.debug("Progress callback error: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# SIMPLE QUEUE MANAGER WRAPPER
# ══════════════════════════════════════════════════════════════════════════════

class ScanQueueManager:
    """
    Simplified facade over ParallelScanEngine for quick use-cases:

        mgr = ScanQueueManager()
        mgr.add_target("example.com", priority=8)
        mgr.add_target("other.com")
        mgr.process_all()
        for task in mgr.get_results():
            print(task.target, task.status)
    """

    def __init__(self, max_workers: int = 4):
        self._engine = ParallelScanEngine(max_workers=max_workers)
        self._submitted_ids: List[str] = []

    def add_target(self, target: str, priority: int = 5,
                   config: Optional[dict] = None) -> str:
        """Enqueue a target. Returns task_id."""
        task_id = self._engine.submit(target, priority=priority, config=config)
        self._submitted_ids.append(task_id)
        return task_id

    def add_targets(self, targets: List[str],
                    config: Optional[dict] = None) -> List[str]:
        """Enqueue multiple targets. Returns list of task_ids."""
        ids = self._engine.submit_batch(targets, config=config)
        self._submitted_ids.extend(ids)
        return ids

    def process_all(self):
        """Block until all queued tasks are processed."""
        self._engine.run_until_complete()

    def get_results(self) -> List[ScanTask]:
        """Return all completed tasks submitted via this manager."""
        results = []
        for task_id in self._submitted_ids:
            task = self._engine.get_status(task_id)
            if task and task.status == "complete":
                results.append(task)
        return results

    def get_all_tasks(self) -> List[ScanTask]:
        """Return all tasks (any status) submitted via this manager."""
        tasks = []
        for task_id in self._submitted_ids:
            task = self._engine.get_status(task_id)
            if task:
                tasks.append(task)
        return tasks

    def get_stats(self) -> dict:
        return self._engine.get_stats()

    def cancel(self, task_id: str) -> bool:
        return self._engine.cancel(task_id)


# ── Global Singletons ─────────────────────────────────────────────────────────

parallel_scan_engine = ParallelScanEngine()
scan_queue_manager   = ScanQueueManager()
