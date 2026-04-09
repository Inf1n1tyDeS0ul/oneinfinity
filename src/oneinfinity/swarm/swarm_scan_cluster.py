"""
Swarm Scan Cluster — Distributed scanning with master-worker architecture.
Falls back to local threading when Redis/Celery unavailable.

Architecture:
  - SwarmScanCluster: top-level coordinator that wires together master and workers
  - Backend detection: auto-detects Redis availability, falls back to threading
  - ClusterConfig: tunable parameters for workers, timeouts, modules
  - ClusterStatus: runtime snapshot of cluster health
"""

import os
import time
import json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


# ── Config & Status Dataclasses ───────────────────────────────────────────────

@dataclass
class ClusterConfig:
    num_workers: int = 4
    use_redis: bool = False
    redis_url: str = "redis://localhost:6379"
    worker_timeout_s: int = 3600
    task_retry_count: int = 3
    result_ttl_s: int = 86400
    graph_sync_interval_s: int = 30
    modules: list = field(default_factory=lambda: [
        "recon", "vuln_scan", "exploit", "ai_security", "mobile"
    ])


@dataclass
class ClusterStatus:
    is_running: bool
    num_workers: int
    active_tasks: int
    completed_tasks: int
    failed_tasks: int
    targets_queued: int
    targets_completed: int
    graph_nodes: int
    uptime_s: float


# ── Main Cluster Class ─────────────────────────────────────────────────────────

class SwarmScanCluster:
    """
    Top-level coordinator for the distributed swarm scanning cluster.

    Wires together SwarmMaster and SwarmWorker instances.
    Supports Redis-backed task distribution or pure threading fallback.

    Lifecycle:
        cluster.start()
        task_ids = cluster.submit_batch(["target1.com", "target2.com"])
        results = cluster.wait_for_completion(task_ids)
        cluster.stop()
    """

    def __init__(self, config: ClusterConfig = None):
        self.config = config or ClusterConfig()
        self._master = None
        self._workers: list = []
        self._backend: str = "threading"
        self._start_time: Optional[float] = None
        self._running = False
        self._lock = threading.Lock()
        self._task_targets: dict = {}     # task_id → target
        self._completed_targets: set = set()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """
        Start the cluster. Detects backend, spins up master + workers.
        Returns True if startup succeeded.
        """
        if self._running:
            log.warning("[cluster] Already running")
            return True

        self._backend = self._detect_backend()
        log.info("[cluster] Starting with backend=%s workers=%d",
                 self._backend, self.config.num_workers)

        try:
            if self._backend == "redis":
                self._start_redis_backend()
            else:
                self._start_threading_backend()

            self._start_time = time.time()
            self._running = True
            log.info("[cluster] Started successfully (backend=%s)", self._backend)
            return True

        except Exception as exc:
            log.error("[cluster] Startup failed: %s", exc)
            # Attempt fallback to threading if redis failed
            if self._backend == "redis":
                log.info("[cluster] Falling back to threading backend")
                self._backend = "threading"
                try:
                    self._start_threading_backend()
                    self._start_time = time.time()
                    self._running = True
                    return True
                except Exception as exc2:
                    log.error("[cluster] Threading fallback also failed: %s", exc2)
            return False

    def stop(self):
        """Graceful shutdown: stop all workers then the master."""
        if not self._running:
            return

        log.info("[cluster] Stopping %d workers...", len(self._workers))
        for worker in self._workers:
            try:
                worker.stop()
            except Exception as exc:
                log.debug("[cluster] Worker stop error: %s", exc)

        if self._master:
            try:
                self._master.stop()
            except Exception as exc:
                log.debug("[cluster] Master stop error: %s", exc)

        self._running = False
        log.info("[cluster] Stopped")

    # ── Task Submission ────────────────────────────────────────────────────────

    def submit_target(self, target: str, priority: int = 5,
                      modules: list = None) -> str:
        """
        Submit a single target for scanning.
        Returns a task_id that can be used to poll for results.
        """
        if not self._running:
            raise RuntimeError("Cluster is not running. Call start() first.")

        modules = modules or self.config.modules
        task_id = self._master.submit_task(
            target=target,
            module="full_pipeline",
            priority=priority,
            config={"modules": modules, "target": target},
        )
        with self._lock:
            self._task_targets[task_id] = target

        log.info("[cluster] Submitted target=%s task_id=%s", target, task_id)
        return task_id

    def submit_batch(self, targets: list, **kwargs) -> list:
        """
        Submit multiple targets. Returns list of task_ids in the same order.
        """
        task_ids = []
        for target in targets:
            try:
                tid = self.submit_target(target, **kwargs)
                task_ids.append(tid)
            except Exception as exc:
                log.error("[cluster] Failed to submit target=%s: %s", target, exc)
        log.info("[cluster] Batch submitted: %d targets", len(task_ids))
        return task_ids

    # ── Status & Results ──────────────────────────────────────────────────────

    def get_status(self) -> ClusterStatus:
        """Return a snapshot of current cluster health."""
        uptime = (time.time() - self._start_time) if self._start_time else 0.0

        master_stats = {}
        if self._master:
            try:
                master_stats = self._master.get_stats()
            except Exception:
                pass

        graph_nodes = 0
        try:
            from oneinfinity.attack_graph.graph import AttackGraph
            # Master may have a shared graph reference
            if hasattr(self._master, "_graph") and self._master._graph:
                graph_nodes = len(self._master._graph.nodes)
        except Exception:
            pass

        return ClusterStatus(
            is_running=self._running,
            num_workers=len(self._workers),
            active_tasks=master_stats.get("running", 0),
            completed_tasks=master_stats.get("completed", 0),
            failed_tasks=master_stats.get("failed", 0),
            targets_queued=master_stats.get("queued", 0),
            targets_completed=len(self._completed_targets),
            graph_nodes=graph_nodes,
            uptime_s=uptime,
        )

    def get_results(self, task_id: str) -> Optional[dict]:
        """
        Retrieve results for a completed task.
        Returns None if task is not yet complete or does not exist.
        """
        if not self._master:
            return None
        task = self._master.get_task(task_id)
        if task is None:
            return None
        if task.status == "complete":
            with self._lock:
                self._completed_targets.add(self._task_targets.get(task_id, ""))
            return task.result
        return None

    def wait_for_completion(self, task_ids: list, timeout_s: int = 3600) -> dict:
        """
        Block until all given task_ids complete or timeout.
        Returns dict: {task_id: result_dict_or_None}
        """
        deadline = time.time() + timeout_s
        results = {}

        while time.time() < deadline:
            pending = []
            for tid in task_ids:
                if tid in results:
                    continue
                res = self.get_results(tid)
                if res is not None:
                    results[tid] = res
                else:
                    # Check for terminal failure
                    if self._master:
                        task = self._master.get_task(tid)
                        if task and task.status == "failed":
                            results[tid] = {"error": task.error or "task failed"}
                        elif task and task.is_terminal():
                            results[tid] = task.result or {}
                        else:
                            pending.append(tid)
                    else:
                        pending.append(tid)

            if not pending:
                break
            time.sleep(3)
        else:
            # Timeout: fill remaining with None
            for tid in task_ids:
                if tid not in results:
                    results[tid] = None
            log.warning("[cluster] wait_for_completion timed out, %d tasks incomplete",
                        len([v for v in results.values() if v is None]))

        return results

    # ── Backend Detection ─────────────────────────────────────────────────────

    def _detect_backend(self) -> str:
        """
        Detect which backend to use.
        Returns "redis" if Redis is available and config.use_redis is True,
        otherwise "threading".
        """
        if not self.config.use_redis:
            log.debug("[cluster] Redis disabled in config, using threading")
            return "threading"

        try:
            import redis  # noqa: F401
            import redis as redis_lib
            client = redis_lib.from_url(self.config.redis_url, socket_connect_timeout=2)
            client.ping()
            log.info("[cluster] Redis available at %s", self.config.redis_url)
            return "redis"
        except Exception as exc:
            log.info("[cluster] Redis not available (%s), falling back to threading", exc)
            return "threading"

    def _start_threading_backend(self):
        """
        Start master + N worker threads using pure Python threading.
        No external dependencies required.
        """
        from oneinfinity.swarm.swarm_master import SwarmMaster
        from oneinfinity.swarm.swarm_worker import SwarmWorker, WorkerConfig

        # Create master
        self._master = SwarmMaster(
            max_workers=self.config.num_workers,
        )
        self._master.start()
        log.info("[cluster] Master started (threading backend)")

        # Spin up workers
        for i in range(self.config.num_workers):
            worker_config = WorkerConfig(
                capabilities=list(self.config.modules),
                max_concurrent_tasks=2,
                task_timeout_s=self.config.worker_timeout_s,
            )
            worker = SwarmWorker(master=self._master, config=worker_config)
            worker.start()
            self._workers.append(worker)

        log.info("[cluster] %d workers started (threading backend)",
                 len(self._workers))

    def _start_redis_backend(self):
        """
        Start master + workers using Redis for task distribution.
        Workers connect to Redis queues instead of polling master directly.
        """
        import redis as redis_lib
        from oneinfinity.swarm.swarm_master import SwarmMaster
        from oneinfinity.swarm.swarm_worker import SwarmWorker, WorkerConfig
        from oneinfinity.infra.task_dispatcher import TaskRouter

        redis_client = redis_lib.from_url(self.config.redis_url)

        self._master = SwarmMaster(
            max_workers=self.config.num_workers,
        )
        self._master._redis_client = redis_client
        self._master._task_router = TaskRouter()
        self._master.start()

        log.info("[cluster] Master started (Redis backend at %s)", self.config.redis_url)

        for i in range(self.config.num_workers):
            worker_config = WorkerConfig(
                capabilities=list(self.config.modules),
                max_concurrent_tasks=2,
                task_timeout_s=self.config.worker_timeout_s,
            )
            worker = SwarmWorker(master=self._master, config=worker_config)
            worker._redis_client = redis_client
            worker.start()
            self._workers.append(worker)

        log.info("[cluster] %d workers started (Redis backend)", len(self._workers))


# ── Global Singleton ──────────────────────────────────────────────────────────

swarm_scan_cluster = SwarmScanCluster()
