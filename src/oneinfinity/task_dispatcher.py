"""
Task Dispatcher — Routes scan tasks to workers based on capabilities and load.

Two classes:
  - TaskDispatcher: in-process routing for threading-mode clusters
  - TaskRouter:     Redis-backed routing with graceful in-memory fallback

TaskDispatcher decides WHICH worker should get a task.
TaskRouter handles the actual message-passing (Redis lists or in-memory queue).
"""

import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

log = logging.getLogger(__name__)


# ── In-Memory Fallback Queue ──────────────────────────────────────────────────

# Used by TaskRouter when Redis is unavailable
_INMEMORY_QUEUES: dict = defaultdict(list)  # queue_name → [task_dict, ...]
_INMEMORY_LOCK = threading.Lock()


# ── Task Dispatcher ────────────────────────────────────────────────────────────

class TaskDispatcher:
    """
    Routes scan tasks to the most suitable available worker.

    Selection criteria (in order):
      1. Worker must support the task's module (capability check)
      2. Worker must be alive (heartbeat within last 60s)
      3. Among eligible workers, pick the one with the lowest current load

    Used by SwarmMaster in threading mode to track which worker is best
    suited for a new task.
    """

    HEARTBEAT_TIMEOUT_S = 60

    def __init__(self, master):
        """
        Args:
            master: SwarmMaster instance (provides _workers dict and _tasks dict)
        """
        self._master = master

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def dispatch_pending(self) -> int:
        """
        Dispatch all QUEUED tasks to available workers.
        Returns the number of tasks dispatched.
        """
        pending = self._master.get_pending_tasks()
        dispatched = 0
        for task in pending:
            worker_id = self.find_best_worker(task)
            if worker_id:
                success = self.assign_task(task, worker_id)
                if success:
                    dispatched += 1
        return dispatched

    def assign_task(self, task, worker_id: str) -> bool:
        """
        Assign a specific task to a specific worker.
        Returns True if assignment succeeded.

        In threading mode the actual task pickup is done by the worker's
        claim_task() call, so this method just validates the pairing and
        updates master worker load for dispatch accounting purposes.
        """
        if not self._capability_match(
                self._master._workers.get(worker_id, {}).get("capabilities", []),
                task.module):
            log.debug("[dispatcher] Worker %s lacks capability for module=%s",
                      worker_id, task.module)
            return False

        if not self._worker_is_healthy(worker_id):
            log.debug("[dispatcher] Worker %s is not healthy", worker_id)
            return False

        # Optimistically increment load (will be decremented on complete/fail)
        with self._master._lock:
            if worker_id in self._master._workers:
                self._master._workers[worker_id]["load"] = \
                    self._master._workers[worker_id].get("load", 0) + 1
        log.debug("[dispatcher] Assigned task=%s to worker=%s",
                  task.task_id, worker_id)
        return True

    def find_best_worker(self, task) -> Optional[str]:
        """
        Find the best worker for a given task.

        Algorithm:
          - Filter to workers that: (a) have the capability, (b) are healthy
          - Among those, pick the one with the lowest load
          - Return None if no eligible worker exists
        """
        with self._master._lock:
            candidates = [
                (wid, info)
                for wid, info in self._master._workers.items()
                if (self._capability_match(info.get("capabilities", []), task.module)
                    and self._worker_is_healthy(wid))
            ]

        if not candidates:
            return None

        # Sort by load ascending
        candidates.sort(key=lambda x: x[1].get("load", 0))
        best_worker_id = candidates[0][0]
        log.debug("[dispatcher] Best worker for module=%s: %s (load=%d)",
                  task.module, best_worker_id,
                  candidates[0][1].get("load", 0))
        return best_worker_id

    def rebalance(self):
        """
        Detect overloaded workers and signal that idle workers should pick up
        tasks. In threading mode, workers self-balance via the claim_task()
        polling mechanism, so this is mainly informational / logging.
        """
        loads = self.get_worker_loads()
        if not loads:
            return

        avg_load = sum(loads.values()) / len(loads)
        overloaded = [wid for wid, load in loads.items() if load > avg_load * 1.5 + 1]
        idle = [wid for wid, load in loads.items() if load == 0]

        if overloaded and idle:
            log.info("[dispatcher] Rebalance opportunity: overloaded=%s idle=%s",
                     overloaded, idle)
            # In pure threading mode, workers self-balance naturally.
            # In Redis mode, TaskRouter can redirect queues here.

    def get_worker_loads(self) -> dict:
        """Return {worker_id: num_running_tasks} for all registered workers."""
        with self._master._lock:
            return {
                wid: info.get("load", 0)
                for wid, info in self._master._workers.items()
            }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _capability_match(self, worker_caps: list, task_module: str) -> bool:
        """
        Return True if the worker supports the task module.

        Rules:
          - Empty capabilities list means the worker accepts anything
          - "full_pipeline" capability means the worker accepts any module
          - Otherwise the module must be in the capabilities list
        """
        if not worker_caps:
            return True
        if "full_pipeline" in worker_caps:
            return True
        return task_module in worker_caps

    def _worker_is_healthy(self, worker_id: str) -> bool:
        """
        Return True if the worker's last heartbeat was within HEARTBEAT_TIMEOUT_S.
        """
        with self._master._lock:
            info = self._master._workers.get(worker_id)
        if info is None:
            return False
        last_hb = info.get("last_heartbeat", 0)
        age = time.time() - last_hb
        return age <= self.HEARTBEAT_TIMEOUT_S


# ── Task Router ────────────────────────────────────────────────────────────────

class TaskRouter:
    """
    Handles task routing via Redis queues when Redis is available.
    Falls back gracefully to in-memory queues when Redis is not installed
    or not reachable.

    Queue naming convention:
      swarm:tasks:{module}   — tasks for a specific module (e.g. swarm:tasks:recon)
      swarm:tasks:default    — catch-all queue

    Each item in the queue is a JSON-serialized ScanTask dict.
    """

    QUEUE_PREFIX = "swarm:tasks"
    DEFAULT_QUEUE = "swarm:tasks:default"
    CONSUME_TIMEOUT_S = 1            # BLPOP block timeout
    MAX_QUEUE_SIZE = 10_000

    def route_via_redis(self, task, redis_client) -> bool:
        """
        Push a task onto the appropriate Redis queue.
        Returns True on success, False on failure (falls back to in-memory).
        """
        queue_name = self._queue_name_for_module(task.module)
        task_payload = json_serialize_task(task)
        try:
            redis_client.lpush(queue_name, task_payload)
            redis_client.expire(queue_name, 86400)  # 24-hour TTL
            log.debug("[router] Pushed task=%s to Redis queue=%s",
                      task.task_id, queue_name)
            return True
        except Exception as exc:
            log.warning("[router] Redis push failed (%s), falling back to in-memory", exc)
            self._inmemory_push(queue_name, task_payload)
            return False

    def consume_from_redis(self, worker_id: str, redis_client,
                           capabilities: list):
        """
        Pull a matching task from Redis for this worker.
        Tries capability-specific queues first, then the default queue.
        Returns a ScanTask-like object or None.
        """
        queues_to_try = []
        for cap in capabilities:
            queues_to_try.append(self._queue_name_for_module(cap))
        queues_to_try.append(self.DEFAULT_QUEUE)

        for queue_name in queues_to_try:
            try:
                # Non-blocking pop
                item = redis_client.rpop(queue_name)
                if item:
                    task = json_deserialize_task(item)
                    if task:
                        log.debug("[router] Worker %s consumed task=%s from queue=%s",
                                  worker_id, task.task_id, queue_name)
                        return task
            except Exception as exc:
                log.debug("[router] Redis consume error on queue=%s: %s",
                          queue_name, exc)

        # Fallback: check in-memory queues
        return self._inmemory_consume(capabilities)

    def _queue_name_for_module(self, module: str) -> str:
        return f"{self.QUEUE_PREFIX}:{module}"

    def _inmemory_push(self, queue_name: str, payload: str):
        with _INMEMORY_LOCK:
            q = _INMEMORY_QUEUES[queue_name]
            if len(q) < self.MAX_QUEUE_SIZE:
                q.insert(0, payload)   # LPUSH equivalent
            else:
                log.warning("[router] In-memory queue %s is full, dropping task",
                            queue_name)

    def _inmemory_consume(self, capabilities: list):
        """
        Try to pop a task from in-memory queues matching capabilities.
        Returns deserialized ScanTask or None.
        """
        queues_to_try = [
            self._queue_name_for_module(cap) for cap in capabilities
        ] + [self.DEFAULT_QUEUE]

        with _INMEMORY_LOCK:
            for queue_name in queues_to_try:
                q = _INMEMORY_QUEUES.get(queue_name, [])
                if q:
                    payload = q.pop()  # RPOP equivalent
                    task = json_deserialize_task(payload)
                    if task:
                        log.debug("[router] Consumed task=%s from in-memory queue=%s",
                                  task.task_id, queue_name)
                        return task
        return None

    def get_queue_lengths(self, redis_client=None) -> dict:
        """
        Return {queue_name: length} for all known queues.
        Uses Redis if available, otherwise in-memory counts.
        """
        lengths = {}
        all_modules = ["recon", "vuln_scan", "exploit", "ai_security",
                       "mobile", "full_pipeline", "default"]
        for mod in all_modules:
            qname = self._queue_name_for_module(mod) if mod != "default" \
                    else self.DEFAULT_QUEUE
            if redis_client:
                try:
                    lengths[qname] = redis_client.llen(qname)
                    continue
                except Exception:
                    pass
            with _INMEMORY_LOCK:
                lengths[qname] = len(_INMEMORY_QUEUES.get(qname, []))
        return lengths

    def flush_queues(self, redis_client=None):
        """Flush all task queues. Used for testing / cluster reset."""
        all_modules = ["recon", "vuln_scan", "exploit", "ai_security",
                       "mobile", "full_pipeline", "default"]
        for mod in all_modules:
            qname = self._queue_name_for_module(mod) if mod != "default" \
                    else self.DEFAULT_QUEUE
            if redis_client:
                try:
                    redis_client.delete(qname)
                except Exception:
                    pass
            with _INMEMORY_LOCK:
                _INMEMORY_QUEUES.pop(qname, None)


# ── Serialization Helpers ─────────────────────────────────────────────────────

def json_serialize_task(task) -> str:
    """Serialize a ScanTask to a JSON string for queue transport."""
    try:
        if hasattr(task, "to_dict"):
            return __import__("json").dumps(task.to_dict())
        return __import__("json").dumps(task.__dict__)
    except Exception as exc:
        log.error("[router] Task serialization error: %s", exc)
        return "{}"


def json_deserialize_task(payload) -> Optional[object]:
    """
    Deserialize a JSON string back to a ScanTask-like object.
    Returns a ScanTask dataclass or a simple namespace object.
    """
    try:
        import json
        data = json.loads(payload) if isinstance(payload, (str, bytes)) else payload
        if not data:
            return None

        # Try to reconstruct a proper ScanTask
        try:
            from oneinfinity.swarm_master import ScanTask
            task = ScanTask(
                task_id=data.get("task_id", ""),
                target=data.get("target", ""),
                module=data.get("module", "full_pipeline"),
                priority=data.get("priority", 5),
                status=data.get("status", "queued"),
                worker_id=data.get("worker_id"),
                created_at=data.get("created_at", time.time()),
                started_at=data.get("started_at"),
                completed_at=data.get("completed_at"),
                retry_count=data.get("retry_count", 0),
                max_retries=data.get("max_retries", 3),
                result=data.get("result"),
                error=data.get("error"),
                config=data.get("config", {}),
            )
            return task
        except ImportError:
            # Return a simple namespace if ScanTask is not importable
            ns = type("_ScanTask", (), data)()
            ns.task_id = data.get("task_id", "")
            ns.target = data.get("target", "")
            ns.module = data.get("module", "full_pipeline")
            ns.priority = data.get("priority", 5)
            ns.status = data.get("status", "queued")
            ns.config = data.get("config", {})
            ns.is_terminal = lambda: ns.status in ("complete", "failed")
            return ns

    except Exception as exc:
        log.error("[router] Task deserialization error: %s", exc)
        return None


# ── Convenience import guard ──────────────────────────────────────────────────

# Allow ``from task_dispatcher import Optional`` (re-export)
from typing import Optional  # noqa: F811, E402
import json as _json          # noqa: E402 (used inside functions via __import__ in places)
