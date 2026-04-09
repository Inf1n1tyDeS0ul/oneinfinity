"""
OneInfinity Distributed Worker
==============================
Redis-backed task consumer that integrates with the existing TaskRouter
and SwarmMaster infrastructure.

Each worker:
  1. Connects to Redis and registers itself with the orchestrator
  2. Pulls tasks from Redis queues matching its declared capabilities
  3. Executes tasks using the OneInfinity module layer
  4. Reports results back to the orchestrator API and shared SQLite
  5. Sends heartbeats every HEARTBEAT_INTERVAL seconds

Environment variables:
  REDIS_URL              Redis connection string (default: redis://redis:6379/0)
  WORKER_ID              Unique worker ID (default: auto-generated)
  WORKER_CAPABILITIES    Comma-separated capability list
                         (default: recon,vuln_scan,exploit)
  ORCHESTRATOR_URL       Orchestrator API base URL
  ONEINFINITY_HOME       Data directory (default: /data)
  WORKER_CONCURRENCY     Max concurrent tasks (default: 2)
  LOG_LEVEL              Logging verbosity (default: INFO)
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("oi.worker")

# ── Configuration ─────────────────────────────────────────────────────────────
REDIS_URL             = os.environ.get("REDIS_URL", "redis://redis:6379/0")
WORKER_ID             = os.environ.get("WORKER_ID", f"worker-{socket.gethostname()}-{uuid.uuid4().hex[:6]}")
WORKER_CAPABILITIES   = [c.strip() for c in os.environ.get("WORKER_CAPABILITIES", "recon,vuln_scan,exploit").split(",")]
ORCHESTRATOR_URL      = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8000")
WORKER_CONCURRENCY    = int(os.environ.get("WORKER_CONCURRENCY", "2"))
HEARTBEAT_INTERVAL    = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
TASK_POLL_INTERVAL    = float(os.environ.get("TASK_POLL_INTERVAL", "1.0"))
ONEINFINITY_HOME      = Path(os.environ.get("ONEINFINITY_HOME", "/data"))

# ── Queue name constants (mirrors TaskRouter in task_dispatcher.py) ───────────
QUEUE_PREFIX  = "swarm:tasks"
DEFAULT_QUEUE = "swarm:tasks:default"
RESULT_CHANNEL = "swarm:results"
WORKER_REGISTRY_KEY = "swarm:workers"


class Worker:
    """
    Core worker process.

    Architecture
    ────────────
    Main thread:
      poll_loop()  — BLPOP on Redis queues, dispatch to executor pool

    Thread pool (WORKER_CONCURRENCY threads):
      _execute_task()  — one thread per concurrent task

    Heartbeat thread:
      _heartbeat_loop()  — publishes worker status to Redis every 30s
    """

    def __init__(self):
        self._redis: Optional["redis.Redis"] = None  # noqa: F821
        self._running = False
        self._active_tasks: dict[str, threading.Thread] = {}
        self._task_semaphore = threading.Semaphore(WORKER_CONCURRENCY)
        self._lock = threading.Lock()
        self._stats = {
            "tasks_received": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "started_at": time.time(),
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        self._connect_redis()
        self._register()

        self._running = True
        log.info("[worker] %s starting | caps=%s | concurrency=%d",
                 WORKER_ID, WORKER_CAPABILITIES, WORKER_CONCURRENCY)

        # Heartbeat thread
        hb = threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat")
        hb.start()

        # Graceful shutdown on SIGTERM / SIGINT
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        self._poll_loop()

    def stop(self):
        log.info("[worker] %s shutting down gracefully…", WORKER_ID)
        self._running = False
        self._deregister()

    def _handle_signal(self, sig, frame):  # noqa: ARG002
        self.stop()

    # ── Redis connection ──────────────────────────────────────────────────────

    def _connect_redis(self, max_retries: int = 10, backoff: float = 3.0):
        try:
            import redis as redislib
        except ImportError:
            log.critical("[worker] redis-py not installed. Run: pip install redis")
            sys.exit(1)

        for attempt in range(1, max_retries + 1):
            try:
                client = redislib.from_url(REDIS_URL, decode_responses=True,
                                           socket_connect_timeout=5)
                client.ping()
                self._redis = client
                log.info("[worker] Connected to Redis at %s", REDIS_URL)
                return
            except Exception as exc:
                log.warning("[worker] Redis connection attempt %d/%d failed: %s",
                            attempt, max_retries, exc)
                time.sleep(backoff)

        log.critical(
            "[worker] FATAL: Could not connect to Redis after %d attempts. "
            "Worker requires REDIS_URL — Redis is mandatory for distributed mode, not optional. "
            "Set REDIS_URL=redis://<host>:6379 and retry.",
            max_retries,
        )
        sys.exit(1)

    # ── Registration ──────────────────────────────────────────────────────────

    def _register(self):
        info = {
            "worker_id":    WORKER_ID,
            "capabilities": json.dumps(WORKER_CAPABILITIES),
            "concurrency":  str(WORKER_CONCURRENCY),
            "hostname":     socket.gethostname(),
            "registered_at": str(time.time()),
            "status":       "idle",
        }
        # Store in a Redis hash: swarm:workers → {worker_id: json}
        self._redis.hset(WORKER_REGISTRY_KEY, WORKER_ID, json.dumps(info))
        self._redis.expire(WORKER_REGISTRY_KEY, 300)  # refreshed by heartbeat
        log.info("[worker] Registered as %s", WORKER_ID)

    def _deregister(self):
        try:
            self._redis.hdel(WORKER_REGISTRY_KEY, WORKER_ID)
        except Exception:
            pass

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def _heartbeat_loop(self):
        while self._running:
            try:
                with self._lock:
                    active = len(self._active_tasks)
                info = {
                    "worker_id":    WORKER_ID,
                    "capabilities": json.dumps(WORKER_CAPABILITIES),
                    "concurrency":  str(WORKER_CONCURRENCY),
                    "active_tasks": str(active),
                    "load":         str(active / WORKER_CONCURRENCY),
                    "last_heartbeat": str(time.time()),
                    "status":       "busy" if active > 0 else "idle",
                    "stats":        json.dumps(self._stats),
                }
                self._redis.hset(WORKER_REGISTRY_KEY, WORKER_ID, json.dumps(info))
                self._redis.expire(WORKER_REGISTRY_KEY, HEARTBEAT_INTERVAL * 3)
                log.debug("[heartbeat] sent (active=%d, load=%.0f%%)",
                          active, (active / WORKER_CONCURRENCY) * 100)
            except Exception as exc:
                log.warning("[heartbeat] failed: %s", exc)
            time.sleep(HEARTBEAT_INTERVAL)

    # ── Poll loop ─────────────────────────────────────────────────────────────

    def _poll_loop(self):
        """
        BLPOP from capability queues (priority order) → execute task.
        Falls back to TASK_POLL_INTERVAL if BLPOP isn't available.
        """
        queues = [f"{QUEUE_PREFIX}:{cap}" for cap in WORKER_CAPABILITIES]
        queues.append(DEFAULT_QUEUE)

        log.info("[worker] Polling queues: %s", queues)

        while self._running:
            try:
                # BLPOP blocks for up to TASK_POLL_INTERVAL seconds
                result = self._redis.blpop(queues, timeout=int(TASK_POLL_INTERVAL))
                if result is None:
                    continue  # timeout — loop again

                _queue_name, raw_payload = result
                task = self._deserialize_task(raw_payload)
                if task is None:
                    log.warning("[worker] Failed to deserialize task payload")
                    continue

                self._stats["tasks_received"] += 1
                log.info("[worker] Received task=%s module=%s target=%s",
                         task.get("task_id"), task.get("module"), task.get("target"))

                # Acquire semaphore (blocks if at concurrency limit)
                self._task_semaphore.acquire()
                t = threading.Thread(
                    target=self._execute_task_wrapper,
                    args=(task,),
                    daemon=True,
                    name=f"task-{task.get('task_id', 'unknown')[:8]}",
                )
                with self._lock:
                    self._active_tasks[task.get("task_id", "?")] = t
                t.start()

            except Exception as exc:
                if self._running:
                    log.error("[worker] Poll loop error: %s", exc, exc_info=True)
                    time.sleep(2)

    # ── Task execution ────────────────────────────────────────────────────────

    def _execute_task_wrapper(self, task: dict):
        """Wraps _execute_task with semaphore release and cleanup."""
        task_id = task.get("task_id", "?")
        try:
            self._execute_task(task)
        finally:
            with self._lock:
                self._active_tasks.pop(task_id, None)
            self._task_semaphore.release()

    def _execute_task(self, task: dict):
        from oneinfinity.worker.executor import TaskExecutor

        task_id  = task.get("task_id", str(uuid.uuid4()))
        module   = task.get("module", "recon")
        target   = task.get("target", "")
        config   = task.get("config", {})

        log.info("[exec] START task=%s module=%s target=%s", task_id, module, target)
        started_at = time.time()

        # Mark task as running in Redis
        self._publish_status(task_id, "running", {})

        try:
            executor = TaskExecutor(
                task_id=task_id,
                module=module,
                target=target,
                config=config,
                data_dir=ONEINFINITY_HOME,
            )
            result = executor.run()
            elapsed = round(time.time() - started_at, 1)

            log.info("[exec] DONE  task=%s module=%s elapsed=%.1fs findings=%d",
                     task_id, module, elapsed, result.get("finding_count", 0))

            self._stats["tasks_completed"] += 1
            self._publish_result(task_id, "complete", result, elapsed)

        except Exception as exc:
            elapsed = round(time.time() - started_at, 1)
            log.error("[exec] FAIL  task=%s error=%s", task_id, exc, exc_info=True)
            self._stats["tasks_failed"] += 1
            self._publish_result(task_id, "failed", {"error": str(exc)}, elapsed)

    # ── Result publishing ─────────────────────────────────────────────────────

    def _publish_status(self, task_id: str, status: str, data: dict):
        payload = json.dumps({
            "task_id":   task_id,
            "worker_id": WORKER_ID,
            "status":    status,
            "data":      data,
            "ts":        time.time(),
        })
        try:
            self._redis.publish(RESULT_CHANNEL, payload)
        except Exception as exc:
            log.warning("[worker] Could not publish status: %s", exc)

    def _publish_result(self, task_id: str, status: str, result: dict, elapsed: float):
        payload = json.dumps({
            "task_id":   task_id,
            "worker_id": WORKER_ID,
            "status":    status,
            "result":    result,
            "elapsed_s": elapsed,
            "ts":        time.time(),
        })
        try:
            # Both publish (real-time) and persist in a results list
            self._redis.publish(RESULT_CHANNEL, payload)
            self._redis.lpush(f"swarm:results:{task_id}", payload)
            self._redis.expire(f"swarm:results:{task_id}", 86400)
        except Exception as exc:
            log.warning("[worker] Could not publish result: %s", exc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _deserialize_task(raw: str) -> Optional[dict]:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            log.error("[worker] Deserialization failed: %s — raw=%r", exc, raw[:200])
            return None


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("=" * 60)
    log.info("  OneInfinity Distributed Worker")
    log.info("  ID:   %s", WORKER_ID)
    log.info("  Caps: %s", WORKER_CAPABILITIES)
    log.info("  Redis: %s", REDIS_URL)
    log.info("=" * 60)

    Worker().start()
