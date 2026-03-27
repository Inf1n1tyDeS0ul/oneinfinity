"""
core/distributed_engine.py — Distributed Scanning Engine (Phase 6 Fix 4)

Scales OneInfinity beyond a single machine by distributing scan tasks across
worker nodes via a shared queue.

Queue backends (auto-detected, best available):
  1. Redis  — fast, durable, ideal for multi-machine setups
               Set ONEINFINITY_REDIS_URL=redis://host:6379/0
  2. File   — JSON file on a shared filesystem (NFS/Docker volume)
               Set ONEINFINITY_QUEUE_DIR=/shared/queue
  3. Memory — in-process queue (same as ParallelScanEngine, fallback)

Architecture:
  Master: DistributedEngine.submit(target) → pushes to queue
  Worker: WorkerNode.run() → polls queue, executes scan, writes result
  Master: DistributedEngine.aggregate_results() → merges all worker outputs

CLI:
  oneinfinity distributed --workers 5 --targets targets.txt
  oneinfinity distributed worker   # start a worker process
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Callable, Dict, List, Optional

log = logging.getLogger("oneinfinity.core.distributed")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_REDIS_URL      = os.environ.get("ONEINFINITY_REDIS_URL", "")
_QUEUE_DIR      = os.environ.get("ONEINFINITY_QUEUE_DIR", "")
_QUEUE_KEY      = "oneinfinity:scan_queue"
_RESULTS_KEY    = "oneinfinity:scan_results"
_RESULT_TTL_S   = 3600 * 24   # 24 h result retention in Redis


# ---------------------------------------------------------------------------
# Queue backends
# ---------------------------------------------------------------------------


class _RedisQueue:
    """Redis-backed FIFO queue."""

    def __init__(self, redis_url: str) -> None:
        import redis as _redis  # type: ignore[import]
        self._r = _redis.from_url(redis_url, decode_responses=True)
        self._queue_key   = _QUEUE_KEY
        self._results_key = _RESULTS_KEY

    def push(self, item: dict) -> None:
        self._r.rpush(self._queue_key, json.dumps(item))

    def pop(self, timeout_s: float = 2.0) -> Optional[dict]:
        result = self._r.blpop(self._queue_key, timeout=int(timeout_s))
        if result:
            _, raw = result
            return json.loads(raw)
        return None

    def push_result(self, task_id: str, result: dict) -> None:
        self._r.hset(self._results_key, task_id, json.dumps(result))
        self._r.expire(self._results_key, _RESULT_TTL_S)

    def get_result(self, task_id: str) -> Optional[dict]:
        raw = self._r.hget(self._results_key, task_id)
        return json.loads(raw) if raw else None

    def all_results(self) -> Dict[str, dict]:
        raw = self._r.hgetall(self._results_key)
        return {k: json.loads(v) for k, v in raw.items()}

    def queue_len(self) -> int:
        return self._r.llen(self._queue_key)


class _FileQueue:
    """File-based queue using a shared directory (works across Docker volumes)."""

    def __init__(self, queue_dir: str) -> None:
        self._dir = Path(queue_dir)
        self._tasks_dir   = self._dir / "tasks"
        self._results_dir = self._dir / "results"
        self._tasks_dir.mkdir(parents=True, exist_ok=True)
        self._results_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def push(self, item: dict) -> None:
        task_id = item.get("task_id", str(uuid.uuid4())[:12])
        item["task_id"] = task_id
        p = self._tasks_dir / f"{task_id}.json"
        p.write_text(json.dumps(item))

    def pop(self, timeout_s: float = 2.0) -> Optional[dict]:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            with self._lock:
                pending = sorted(self._tasks_dir.glob("*.json"))
                if pending:
                    p = pending[0]
                    try:
                        data = json.loads(p.read_text())
                        # Mark as claimed — rename to .processing
                        proc = p.with_suffix(".processing")
                        p.rename(proc)
                        return data
                    except Exception:
                        pass
            time.sleep(0.3)
        return None

    def push_result(self, task_id: str, result: dict) -> None:
        p = self._results_dir / f"{task_id}.json"
        p.write_text(json.dumps(result, indent=2))
        # Clean up processing file
        proc = self._tasks_dir / f"{task_id}.processing"
        if proc.exists():
            proc.unlink(missing_ok=True)

    def get_result(self, task_id: str) -> Optional[dict]:
        p = self._results_dir / f"{task_id}.json"
        if p.exists():
            return json.loads(p.read_text())
        return None

    def all_results(self) -> Dict[str, dict]:
        results = {}
        for p in self._results_dir.glob("*.json"):
            try:
                data = json.loads(p.read_text())
                results[p.stem] = data
            except Exception:
                pass
        return results

    def queue_len(self) -> int:
        return len(list(self._tasks_dir.glob("*.json")))


class _MemoryQueue:
    """In-process queue — same-machine only, fallback."""

    def __init__(self) -> None:
        import queue as _q
        self._q: _q.Queue = _q.Queue()
        self._results: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def push(self, item: dict) -> None:
        self._q.put(item)

    def pop(self, timeout_s: float = 2.0) -> Optional[dict]:
        import queue as _q
        try:
            return self._q.get(timeout=timeout_s)
        except _q.Empty:
            return None

    def push_result(self, task_id: str, result: dict) -> None:
        with self._lock:
            self._results[task_id] = result

    def get_result(self, task_id: str) -> Optional[dict]:
        with self._lock:
            return self._results.get(task_id)

    def all_results(self) -> Dict[str, dict]:
        with self._lock:
            return dict(self._results)

    def queue_len(self) -> int:
        return self._q.qsize()


def _build_queue():
    """Auto-detect best queue backend."""
    if _REDIS_URL:
        try:
            q = _RedisQueue(_REDIS_URL)
            # Test connection
            q._r.ping()
            log.info("[distributed] Queue backend: Redis (%s)", _REDIS_URL[:40])
            return q
        except Exception as exc:
            log.warning("[distributed] Redis unavailable (%s) — trying file queue", exc)

    if _QUEUE_DIR:
        log.info("[distributed] Queue backend: File (%s)", _QUEUE_DIR)
        return _FileQueue(_QUEUE_DIR)

    log.info("[distributed] Queue backend: Memory (single-machine)")
    return _MemoryQueue()


# ---------------------------------------------------------------------------
# Scan task model
# ---------------------------------------------------------------------------


class DistributedTask:
    """A single scan task in the distributed queue."""

    def __init__(
        self,
        target: str,
        priority: int = 5,
        config: Optional[dict] = None,
        task_id: Optional[str] = None,
    ) -> None:
        self.task_id   = task_id or str(uuid.uuid4())[:12]
        self.target    = target
        self.priority  = max(1, min(10, priority))
        self.config    = config or {}
        self.submitted_at = time.time()

    def to_dict(self) -> dict:
        return {
            "task_id":      self.task_id,
            "target":       self.target,
            "priority":     self.priority,
            "config":       self.config,
            "submitted_at": self.submitted_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DistributedTask":
        return cls(
            target=d["target"],
            priority=d.get("priority", 5),
            config=d.get("config", {}),
            task_id=d.get("task_id"),
        )


# ---------------------------------------------------------------------------
# Worker node
# ---------------------------------------------------------------------------


class WorkerNode:
    """
    Pulls tasks from the shared queue and executes scans.

    Each worker runs in a dedicated thread/process; multiple workers can run
    on different machines sharing the same Redis or file-based queue.
    """

    def __init__(
        self,
        worker_id: int = 0,
        scan_fn: Optional[Callable[[str, dict], dict]] = None,
        queue=None,
    ) -> None:
        self._id      = worker_id
        self._scan_fn = scan_fn or self._default_scan
        self._queue   = queue or _build_queue()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _default_scan(target: str, config: dict) -> dict:
        """Default scan: delegate to unified_scan_engine."""
        try:
            from unified_scan_engine import get_engine
            engine = get_engine()
            session = engine.scan(target)
            result = session.to_dict() if hasattr(session, "to_dict") else {}
            result.setdefault("target", target)
            return result
        except Exception as exc:
            return {"target": target, "error": str(exc), "findings": []}

    def run(self, max_tasks: Optional[int] = None) -> None:
        """Synchronously process tasks until queue empty or max_tasks reached."""
        self._running = True
        processed = 0
        log.info("[worker-%d] Started", self._id)

        while self._running:
            if max_tasks and processed >= max_tasks:
                log.info("[worker-%d] Reached max_tasks=%d, stopping", self._id, max_tasks)
                break

            task_dict = self._queue.pop(timeout_s=3.0)
            if task_dict is None:
                break  # queue drained

            task = DistributedTask.from_dict(task_dict)
            log.info("[worker-%d] Scanning: %s (task=%s)", self._id, task.target, task.task_id)

            t0 = time.time()
            try:
                result = self._scan_fn(task.target, task.config)
                result["task_id"]   = task.task_id
                result["worker_id"] = self._id
                result["duration_s"] = round(time.time() - t0, 2)
                result["status"]    = "complete"
            except Exception as exc:
                log.error("[worker-%d] Scan failed: %s", self._id, exc)
                result = {
                    "task_id":   task.task_id,
                    "target":    task.target,
                    "worker_id": self._id,
                    "duration_s": round(time.time() - t0, 2),
                    "status":    "failed",
                    "error":     str(exc),
                    "findings":  [],
                }

            self._queue.push_result(task.task_id, result)
            processed += 1
            log.info("[worker-%d] Done: %s (%ds, findings=%d)",
                     self._id, task.target, result["duration_s"],
                     len(result.get("findings", [])))

        log.info("[worker-%d] Stopped (processed=%d)", self._id, processed)

    def start_background(self) -> None:
        """Start worker in a background daemon thread."""
        self._thread = threading.Thread(
            target=self.run, daemon=True, name=f"dist-worker-{self._id}"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)


# ---------------------------------------------------------------------------
# Distributed Engine (master node)
# ---------------------------------------------------------------------------


class DistributedEngine:
    """
    Master-side distributed scan coordinator.

    Submits tasks to the shared queue, optionally spawns local worker threads,
    waits for results, and aggregates findings.

    Fallback: if no queue backend is configured, delegates to ParallelScanEngine.
    """

    def __init__(self, max_workers: int = 4) -> None:
        self._max_workers = max_workers
        self._queue = _build_queue()
        self._submitted_tasks: List[DistributedTask] = []

    # ── Submission API ────────────────────────────────────────────────────────

    def submit(self, target: str, priority: int = 5, config: Optional[dict] = None) -> str:
        """Enqueue a target. Returns task_id."""
        task = DistributedTask(target=target, priority=priority, config=config or {})
        self._queue.push(task.to_dict())
        self._submitted_tasks.append(task)
        log.info("[distributed] Submitted: %s (task=%s)", target, task.task_id)
        return task.task_id

    def submit_batch(
        self,
        targets: List[str],
        config: Optional[dict] = None,
    ) -> List[str]:
        """Submit multiple targets. Returns list of task_ids."""
        return [self.submit(t, config=config) for t in targets]

    # ── Execution ─────────────────────────────────────────────────────────────

    def run(
        self,
        targets: Optional[List[str]] = None,
        config: Optional[dict] = None,
        scan_fn: Optional[Callable] = None,
    ) -> List[dict]:
        """
        Submit targets + spawn local workers + wait for all results.

        This is the primary entry point for local (non-Redis) distributed runs.
        Returns aggregated findings list.
        """
        if targets:
            self.submit_batch(targets, config=config)

        if self._queue.queue_len() == 0 and not self._submitted_tasks:
            log.warning("[distributed] No tasks in queue")
            return []

        # Spawn workers in a thread pool
        workers = [
            WorkerNode(worker_id=i, scan_fn=scan_fn, queue=self._queue)
            for i in range(self._max_workers)
        ]

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="dist-worker",
        ) as pool:
            futures = [pool.submit(w.run) for w in workers]
            concurrent.futures.wait(futures, timeout=3600)

        return self.aggregate_results()

    # ── Results ───────────────────────────────────────────────────────────────

    def get_result(self, task_id: str) -> Optional[dict]:
        return self._queue.get_result(task_id)

    def aggregate_results(self) -> List[dict]:
        """
        Merge all findings from completed tasks.

        Returns a flat list of finding dicts, deduped by (vuln_type, url).
        """
        all_results = self._queue.all_results()
        all_findings: List[dict] = []
        seen: set = set()

        for task_id, result in all_results.items():
            findings = result.get("findings", [])
            for f in findings:
                key = (
                    (f.get("vuln_type") or f.get("type") or "").lower(),
                    (f.get("url") or "").split("?")[0].lower(),
                )
                if key not in seen:
                    seen.add(key)
                    f["_source_task"] = task_id
                    all_findings.append(f)

        log.info(
            "[distributed] Aggregated %d unique findings from %d tasks",
            len(all_findings), len(all_results),
        )
        return all_findings

    def stats(self) -> dict:
        return {
            "submitted":   len(self._submitted_tasks),
            "queue_len":   self._queue.queue_len(),
            "results":     len(self._queue.all_results()),
            "max_workers": self._max_workers,
            "backend":     type(self._queue).__name__,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional[DistributedEngine] = None


def get_distributed_engine(max_workers: int = 4) -> DistributedEngine:
    global _instance
    if _instance is None:
        _instance = DistributedEngine(max_workers=max_workers)
    return _instance
