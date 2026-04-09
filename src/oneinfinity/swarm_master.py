"""
Swarm Master — Task scheduling, graph maintenance, result aggregation.

Responsibilities:
  - Maintain a priority queue of ScanTasks (heapq-based)
  - Dispatch tasks to registered workers
  - Detect stalled/timed-out tasks and requeue them
  - Periodically flush the attack graph to disk
  - Provide a result aggregation hook via an optional ResultAggregator
"""

import uuid
import time
import json
import logging
import threading
import queue
import heapq
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict
from pathlib import Path

from oneinfinity.path_manager import raw_dir

log = logging.getLogger(__name__)


# ── Task Status Constants ─────────────────────────────────────────────────────

class TaskStatus(str):
    QUEUED     = "queued"
    DISPATCHED = "dispatched"
    RUNNING    = "running"
    COMPLETE   = "complete"
    FAILED     = "failed"
    RETRYING   = "retrying"


# ── ScanTask Dataclass ────────────────────────────────────────────────────────

@dataclass
class ScanTask:
    task_id: str
    target: str
    module: str                  # recon / vuln_scan / exploit / ai_security / mobile / full_pipeline
    priority: int                # 1 (highest) – 10 (lowest)
    status: str
    worker_id: Optional[str]
    created_at: float
    started_at: Optional[float]
    completed_at: Optional[float]
    retry_count: int
    max_retries: int
    result: Optional[dict]
    error: Optional[str]
    config: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "task_id":       self.task_id,
            "target":        self.target,
            "module":        self.module,
            "priority":      self.priority,
            "status":        self.status,
            "worker_id":     self.worker_id,
            "created_at":    self.created_at,
            "started_at":    self.started_at,
            "completed_at":  self.completed_at,
            "retry_count":   self.retry_count,
            "max_retries":   self.max_retries,
            "result":        self.result,
            "error":         self.error,
            "config":        self.config,
        }

    def is_terminal(self) -> bool:
        return self.status in (TaskStatus.COMPLETE, TaskStatus.FAILED)


# ── Priority Queue Item ────────────────────────────────────────────────────────

@dataclass(order=True)
class _PQItem:
    """Wrapper for heapq — sorts by (priority, created_at)."""
    priority: int
    created_at: float
    task_id: str = field(compare=False)


# ── Swarm Master ──────────────────────────────────────────────────────────────

class SwarmMaster:
    """
    Master node: manages the task lifecycle from submission to completion.

    Thread-safe. All public methods acquire self._lock before mutating state.

    Internal threads:
      - _schedule_loop:  dispatches queued tasks to available workers
      - _health_monitor: detects stalled tasks and requeues them
      - _graph_sync_loop: periodically flushes attack graph to disk
    """

    # Stalled task threshold: if RUNNING for longer than this, requeue
    STALL_TIMEOUT_S = 300

    def __init__(self, max_workers: int = 4, result_aggregator=None):
        self.max_workers = max_workers
        self.result_aggregator = result_aggregator

        self._lock = threading.RLock()
        self._running = False

        # Task storage
        self._tasks: dict[str, ScanTask] = {}              # task_id → ScanTask
        self._pq: list[_PQItem] = []                        # heapq of pending tasks
        self._pq_set: set[str] = set()                      # task_ids in the heap

        # Worker registry
        self._workers: dict[str, dict] = {}                 # worker_id → {capabilities, load, last_heartbeat}

        # Stats counters
        self._stats = defaultdict(int)                       # queued/running/completed/failed

        # Graph reference (optional)
        self._graph = None
        self._graph_sync_interval = 30
        self._graph_dir = str(raw_dir() / "graphs")

        # Background threads
        self._schedule_thread: Optional[threading.Thread] = None
        self._health_thread: Optional[threading.Thread] = None
        self._graph_thread: Optional[threading.Thread] = None

        # Result aggregation hook
        self._result_callbacks: list = []

        # Optional Redis client (set by cluster when in Redis mode)
        self._redis_client = None
        self._task_router = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Start background threads for scheduling, health monitoring, graph sync."""
        self._running = True

        self._schedule_thread = threading.Thread(
            target=self._schedule_loop,
            name="swarm-master-scheduler",
            daemon=True,
        )
        self._schedule_thread.start()

        self._health_thread = threading.Thread(
            target=self._health_monitor,
            name="swarm-master-health",
            daemon=True,
        )
        self._health_thread.start()

        self._graph_thread = threading.Thread(
            target=self._graph_sync_loop,
            name="swarm-master-graph-sync",
            daemon=True,
        )
        self._graph_thread.start()

        log.info("[master] Started (max_workers=%d)", self.max_workers)

    def stop(self):
        """Signal background threads to stop."""
        self._running = False
        log.info("[master] Stopping")

    # ── Task Submission ────────────────────────────────────────────────────────

    def submit_task(self, target: str, module: str,
                    priority: int = 5, config: dict = None) -> str:
        """
        Create and enqueue a new ScanTask.
        Returns the task_id.
        """
        task_id = f"task_{uuid.uuid4().hex[:12]}"
        now = time.time()
        task = ScanTask(
            task_id=task_id,
            target=target,
            module=module,
            priority=max(1, min(10, priority)),
            status=TaskStatus.QUEUED,
            worker_id=None,
            created_at=now,
            started_at=None,
            completed_at=None,
            retry_count=0,
            max_retries=3,
            result=None,
            error=None,
            config=config or {},
        )

        with self._lock:
            self._tasks[task_id] = task
            heapq.heappush(self._pq, _PQItem(priority=task.priority,
                                              created_at=now,
                                              task_id=task_id))
            self._pq_set.add(task_id)
            self._stats["queued"] += 1

        log.debug("[master] Submitted task_id=%s target=%s module=%s priority=%d",
                  task_id, target, module, priority)
        return task_id

    # ── Task Access ────────────────────────────────────────────────────────────

    def get_task(self, task_id: str) -> Optional[ScanTask]:
        with self._lock:
            return self._tasks.get(task_id)

    def get_all_tasks(self) -> list:
        with self._lock:
            return list(self._tasks.values())

    def get_pending_tasks(self) -> list:
        """Return all QUEUED tasks sorted by priority (lowest number = highest priority)."""
        with self._lock:
            pending = [t for t in self._tasks.values()
                       if t.status == TaskStatus.QUEUED]
        pending.sort(key=lambda t: (t.priority, t.created_at))
        return pending

    # ── Worker-Facing API ─────────────────────────────────────────────────────

    def claim_task(self, worker_id: str) -> Optional[ScanTask]:
        """
        Called by a worker to atomically claim the next available task.
        Returns the claimed ScanTask or None if no work is available.
        """
        with self._lock:
            # Pop from heap until we find a QUEUED task
            while self._pq:
                item = heapq.heappop(self._pq)
                self._pq_set.discard(item.task_id)
                task = self._tasks.get(item.task_id)
                if task is None or task.status != TaskStatus.QUEUED:
                    continue

                # Check worker capability
                worker_info = self._workers.get(worker_id, {})
                caps = worker_info.get("capabilities", [])
                if caps and task.module not in caps and "full_pipeline" not in caps:
                    # Put it back and skip
                    heapq.heappush(self._pq, item)
                    self._pq_set.add(item.task_id)
                    continue

                # Claim it
                task.status = TaskStatus.RUNNING
                task.worker_id = worker_id
                task.started_at = time.time()
                self._stats["running"] += 1
                self._stats["queued"] = max(0, self._stats["queued"] - 1)

                # Update worker load
                if worker_id in self._workers:
                    self._workers[worker_id]["load"] = \
                        self._workers[worker_id].get("load", 0) + 1
                    self._workers[worker_id]["last_heartbeat"] = time.time()

                log.debug("[master] Claimed task_id=%s by worker=%s",
                          task.task_id, worker_id)
                return task

        return None

    def complete_task(self, task_id: str, result: dict):
        """Called by worker when a task finishes successfully."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                log.warning("[master] complete_task: unknown task_id=%s", task_id)
                return

            task.status = TaskStatus.COMPLETE
            task.completed_at = time.time()
            task.result = result
            task.error = None
            self._stats["running"] = max(0, self._stats["running"] - 1)
            self._stats["completed"] += 1

            # Decrement worker load
            if task.worker_id and task.worker_id in self._workers:
                self._workers[task.worker_id]["load"] = max(
                    0, self._workers[task.worker_id].get("load", 1) - 1
                )

        log.info("[master] Task COMPLETE task_id=%s target=%s",
                 task_id, task.target)

        # Invoke result callbacks
        for cb in self._result_callbacks:
            try:
                cb(task)
            except Exception as exc:
                log.debug("[master] Result callback error: %s", exc)

        # Delegate to ResultAggregator if present
        if self.result_aggregator:
            try:
                self.result_aggregator.ingest_task_result(task)
            except Exception as exc:
                log.debug("[master] ResultAggregator ingest error: %s", exc)

    def fail_task(self, task_id: str, error: str):
        """
        Called by worker when a task fails.
        Handles retry logic: re-enqueues up to max_retries times.
        """
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                log.warning("[master] fail_task: unknown task_id=%s", task_id)
                return

            task.error = error
            self._stats["running"] = max(0, self._stats["running"] - 1)

            # Decrement worker load
            if task.worker_id and task.worker_id in self._workers:
                self._workers[task.worker_id]["load"] = max(
                    0, self._workers[task.worker_id].get("load", 1) - 1
                )

            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.RETRYING
                task.worker_id = None
                task.started_at = None
                # Backoff: slightly lower priority on retry
                backoff_priority = min(10, task.priority + 1)
                heapq.heappush(self._pq,
                               _PQItem(priority=backoff_priority,
                                       created_at=time.time(),
                                       task_id=task_id))
                self._pq_set.add(task_id)
                task.status = TaskStatus.QUEUED
                self._stats["queued"] += 1
                log.info("[master] Task RETRYING (%d/%d) task_id=%s",
                         task.retry_count, task.max_retries, task_id)
            else:
                task.status = TaskStatus.FAILED
                task.completed_at = time.time()
                self._stats["failed"] += 1
                log.warning("[master] Task FAILED (max retries) task_id=%s error=%s",
                            task_id, error)

    # ── Worker Registry ────────────────────────────────────────────────────────

    def register_worker(self, worker_id: str, capabilities: list):
        with self._lock:
            self._workers[worker_id] = {
                "capabilities": capabilities,
                "load": 0,
                "last_heartbeat": time.time(),
                "registered_at": time.time(),
            }
        log.info("[master] Worker registered: %s caps=%s", worker_id, capabilities)

    def unregister_worker(self, worker_id: str):
        with self._lock:
            self._workers.pop(worker_id, None)
        log.info("[master] Worker unregistered: %s", worker_id)

    def update_heartbeat(self, worker_id: str):
        with self._lock:
            if worker_id in self._workers:
                self._workers[worker_id]["last_heartbeat"] = time.time()

    def get_available_worker(self) -> Optional[str]:
        """
        Return worker_id with lowest current load that is still alive.
        Returns None if no worker is available.
        """
        with self._lock:
            now = time.time()
            alive = [
                (wid, info) for wid, info in self._workers.items()
                if now - info.get("last_heartbeat", 0) < 60
            ]
            if not alive:
                return None
            # Pick least loaded
            alive.sort(key=lambda x: x[1].get("load", 0))
            return alive[0][0]

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "queued":    self._stats["queued"],
                "running":   self._stats["running"],
                "completed": self._stats["completed"],
                "failed":    self._stats["failed"],
                "retrying":  sum(1 for t in self._tasks.values()
                                 if t.status == TaskStatus.RETRYING),
                "workers":   len(self._workers),
                "total":     len(self._tasks),
            }

    # ── Background Threads ─────────────────────────────────────────────────────

    def _schedule_loop(self):
        """
        Background thread: wakes up regularly and notifies workers when tasks
        are available. In threading mode this is informational — workers poll
        via claim_task(). In Redis mode this would push to queues.
        """
        while self._running:
            try:
                # In Redis mode, route pending tasks to Redis queues
                if self._redis_client and self._task_router:
                    with self._lock:
                        pending = [t for t in self._tasks.values()
                                   if t.status == TaskStatus.QUEUED]
                    for task in pending:
                        try:
                            routed = self._task_router.route_via_redis(
                                task, self._redis_client
                            )
                            if routed:
                                with self._lock:
                                    task.status = TaskStatus.DISPATCHED
                        except Exception as exc:
                            log.debug("[master] Redis route error: %s", exc)

                # Log periodic stats
                stats = self.get_stats()
                if stats["queued"] > 0 or stats["running"] > 0:
                    log.debug("[master] Stats: queued=%d running=%d completed=%d failed=%d",
                              stats["queued"], stats["running"],
                              stats["completed"], stats["failed"])
            except Exception as exc:
                log.error("[master] Schedule loop error: %s", exc)

            time.sleep(5)

    def _health_monitor(self):
        """
        Background thread: periodically detects stalled tasks and requeues them.
        A task is stalled if it has been RUNNING for longer than STALL_TIMEOUT_S.
        """
        while self._running:
            try:
                self._requeue_stalled(timeout_s=self.STALL_TIMEOUT_S)
            except Exception as exc:
                log.error("[master] Health monitor error: %s", exc)
            time.sleep(60)

    def _graph_sync_loop(self):
        """
        Background thread: periodically flushes the in-memory attack graph to disk.
        """
        while self._running:
            try:
                self._flush_graph()
            except Exception as exc:
                log.debug("[master] Graph sync error: %s", exc)
            time.sleep(self._graph_sync_interval)

    def _requeue_stalled(self, timeout_s: int = 300):
        """
        If a task has been in RUNNING state for longer than timeout_s, requeue it.
        This handles crashed/hung workers.
        """
        now = time.time()
        stalled = []

        with self._lock:
            for task in self._tasks.values():
                if (task.status == TaskStatus.RUNNING
                        and task.started_at is not None
                        and now - task.started_at > timeout_s):
                    stalled.append(task.task_id)

        for task_id in stalled:
            log.warning("[master] Stalled task detected: %s — requeueing", task_id)
            self.fail_task(task_id, f"stalled (>{timeout_s}s)")

    def _flush_graph(self):
        """Save the current attack graph to disk if one is attached."""
        if self._graph is None:
            return
        try:
            import pathlib
            graph_dir = pathlib.Path(self._graph_dir)
            graph_dir.mkdir(parents=True, exist_ok=True)
            graph_file = graph_dir / f"{self._graph.target}.json"
            graph_data = self._graph.to_dict() if hasattr(self._graph, "to_dict") else {}
            graph_file.write_text(json.dumps(graph_data, indent=2))
            log.debug("[master] Graph flushed to %s", graph_file)
        except Exception as exc:
            log.debug("[master] Graph flush error: %s", exc)

    # ── Callback Registration ──────────────────────────────────────────────────

    def add_result_callback(self, callback):
        """Register a function(task: ScanTask) called on every completed task."""
        self._result_callbacks.append(callback)


# ── Global Singleton ──────────────────────────────────────────────────────────

swarm_master = SwarmMaster()
