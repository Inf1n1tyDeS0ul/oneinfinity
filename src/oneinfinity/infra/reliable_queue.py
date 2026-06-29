"""
reliable_queue.py — Production-grade Redis task queue with at-least-once delivery.

Architecture
============
Three Redis data structures per queue name:

  swarm:pending:{name}      ZSET   score=enqueue_time  value=task_id
  swarm:leased:{name}       ZSET   score=lease_expiry  value=task_id
  swarm:payload             HASH   key=task_id         value=task_json
  swarm:dlq:{name}          ZSET   score=fail_time     value=task_id

Flow
----
push()      → HSET payload, ZADD pending (score=time.time())
claim()     → Lua: ZPOPMIN pending → ZADD leased (score=now+lease_s)
ack()       → ZREM leased, HDEL payload
nack()      → increment retry_count; if < max_retries: ZADD pending (backoff);
              else: ZREM leased, ZADD dlq
resurrect() → scan leased set for scores < now; move expired back to pending
dlq_list()  → ZRANGEBYSCORE dlq −∞ +∞ with payload
retry_dlq() → move single task from dlq → pending

This gives us:
- No task loss on Redis restart (RDB/AOF persistence handles the rest)
- At-least-once delivery (claim re-appears if worker crashes within lease window)
- Dead-letter queue for poison tasks
- Full queue depth metrics
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.reliable_queue")

# Keys
_PAYLOAD_HASH = "swarm:payload"         # task_id → task_json
_PENDING_FMT  = "swarm:pending:{}"     # ZSET: score=enqueue_time
_LEASED_FMT   = "swarm:leased:{}"      # ZSET: score=lease_expiry
_DLQ_FMT      = "swarm:dlq:{}"         # ZSET: score=fail_time

# Lua script: atomically move oldest pending task to leased set.
# Returns the task_id or nil if nothing is pending.
_LUA_CLAIM = """
local pending  = KEYS[1]
local leased   = KEYS[2]
local now      = tonumber(ARGV[1])
local expiry   = tonumber(ARGV[2])
local items = redis.call('ZPOPMIN', pending, 1)
if #items == 0 then
    return nil
end
local task_id = items[1]
redis.call('ZADD', leased, expiry, task_id)
return task_id
"""

# Lua script: atomically resurrect ALL expired leases.
# For each expired task_id, ZREM from leased then ZADD to pending ONLY if
# ZREM returned 1 (i.e., this caller is the one that removed it).
# This prevents two concurrent callers from both resurrecting the same task.
# KEYS[1] = leased_key   KEYS[2] = pending_key
# ARGV[1] = now (epoch seconds)  ARGV[2] = re-queue score (also now)
_LUA_RESURRECT = """
local leased  = KEYS[1]
local pending = KEYS[2]
local now     = tonumber(ARGV[1])
local score   = tonumber(ARGV[2])
local expired = redis.call('ZRANGEBYSCORE', leased, '-inf', now)
local count   = 0
for _, task_id in ipairs(expired) do
    local removed = redis.call('ZREM', leased, task_id)
    if removed == 1 then
        redis.call('ZADD', pending, score, task_id)
        count = count + 1
    end
end
return count
"""

# Default lease duration: 5 minutes.  Worker must ack() within this window.
DEFAULT_LEASE_S   = 300
DEFAULT_MAX_RETRY = 3
# Exponential backoff base for nack retries (seconds).
_BACKOFF_BASE     = 10.0
# DLQ retention policy
DLQ_MAX_AGE_DAYS: int = 7      # entries older than this are auto-purged
DLQ_MAX_SIZE: int = 10_000     # hard cap; oldest entries removed on overflow


class ReliableQueue:
    """
    Production-grade Redis task queue with at-least-once delivery guarantees.

    Usage
    -----
    rq = ReliableQueue(redis_client, name="full_pipeline")
    task_id = rq.push({"target": "example.com", "module": "full_pipeline"})

    # Worker side:
    item = rq.claim(worker_id="w1", lease_s=300)
    if item:
        task_id, payload = item
        try:
            run(payload)
            rq.ack(task_id)
        except Exception as exc:
            rq.nack(task_id, str(exc))

    # Periodic: call from a background thread every ~60s
    rq.resurrect_expired()
    """

    def __init__(
        self,
        redis_client,
        name: str = "default",
        lease_s: int = DEFAULT_LEASE_S,
        max_retries: int = DEFAULT_MAX_RETRY,
    ):
        self._r           = redis_client
        self._name        = name
        self._lease_s     = lease_s
        self._max_retries = max_retries

        self._pending_key = _PENDING_FMT.format(name)
        self._leased_key  = _LEASED_FMT.format(name)
        self._dlq_key     = _DLQ_FMT.format(name)

        # Register Lua scripts for atomic claim and resurrection
        try:
            self._claim_sha = self._r.script_load(_LUA_CLAIM)
        except Exception as exc:
            log.warning("ReliableQueue: could not pre-load Lua claim script: %s", exc)
            self._claim_sha = None
        try:
            self._resurrect_sha = self._r.script_load(_LUA_RESURRECT)
        except Exception as exc:
            log.warning("ReliableQueue: could not pre-load Lua resurrect script: %s", exc)
            self._resurrect_sha = None

    # ── Write ─────────────────────────────────────────────────────────────────

    def push(self, payload: Dict[str, Any], task_id: str = "") -> str:
        """
        Enqueue a task.  Returns the task_id.

        Args:
            payload:  Task dict (must be JSON-serialisable).
            task_id:  Override task_id; auto-generated if empty.
        """
        task_id = task_id or payload.get("task_id") or str(uuid.uuid4())
        payload = {**payload, "task_id": task_id, "_retry_count": 0}
        now = time.time()

        pipe = self._r.pipeline(transaction=True)
        pipe.hset(_PAYLOAD_HASH, task_id, json.dumps(payload, default=str))
        pipe.zadd(self._pending_key, {task_id: now})
        pipe.expire(self._pending_key, 86_400)   # 24-hour TTL; refreshed on activity
        pipe.execute()

        log.debug("ReliableQueue[%s]: pushed task=%s", self._name, task_id)
        return task_id

    # ── Read ──────────────────────────────────────────────────────────────────

    def claim(
        self,
        worker_id: str = "",
        lease_s: Optional[int] = None,
    ) -> Optional[tuple]:
        """
        Atomically move the oldest pending task to the leased set and return it.

        Returns:
            (task_id, payload_dict)  or None if no tasks are pending.
        """
        lease_s  = lease_s if lease_s is not None else self._lease_s
        now      = time.time()
        expiry   = now + lease_s

        try:
            if self._claim_sha:
                task_id = self._r.evalsha(
                    self._claim_sha,
                    2,
                    self._pending_key, self._leased_key,
                    now, expiry,
                )
            else:
                # Fallback: non-atomic (race window of a few ms; acceptable)
                items = self._r.zpopmin(self._pending_key, 1)
                if not items:
                    return None
                task_id = items[0][0] if isinstance(items[0], (list, tuple)) else items[0]
                task_id = task_id.decode() if isinstance(task_id, bytes) else task_id
                self._r.zadd(self._leased_key, {task_id: expiry})
                task_id = task_id   # already a string

            if task_id is None:
                return None

            # Decode bytes if needed
            if isinstance(task_id, bytes):
                task_id = task_id.decode()

            raw = self._r.hget(_PAYLOAD_HASH, task_id)
            if raw is None:
                # Payload missing (stale lease entry) — ack away and skip
                log.warning("ReliableQueue[%s]: claim got task=%s but payload missing; discarding",
                            self._name, task_id)
                self._r.zrem(self._leased_key, task_id)
                return None

            payload = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            # Stamp which worker claimed this
            if worker_id:
                payload["_worker_id"]  = worker_id
                payload["_claimed_at"] = now
                payload["_lease_expiry"] = expiry
                self._r.hset(_PAYLOAD_HASH, task_id, json.dumps(payload, default=str))

            log.debug("ReliableQueue[%s]: claimed task=%s by worker=%s",
                      self._name, task_id, worker_id)
            return (task_id, payload)

        except Exception as exc:
            log.error("ReliableQueue[%s]: claim error: %s", self._name, exc)
            return None

    def ack(self, task_id: str) -> bool:
        """
        Acknowledge successful task completion.
        Removes from leased set and deletes payload.
        """
        try:
            pipe = self._r.pipeline(transaction=True)
            pipe.zrem(self._leased_key, task_id)
            pipe.hdel(_PAYLOAD_HASH, task_id)
            pipe.execute()
            log.debug("ReliableQueue[%s]: acked task=%s", self._name, task_id)
            return True
        except Exception as exc:
            log.error("ReliableQueue[%s]: ack error task=%s: %s", self._name, task_id, exc)
            return False

    def nack(self, task_id: str, error: str = "") -> bool:
        """
        Negative-acknowledge a task (worker failure).

        Increments retry_count.  If count < max_retries: re-queues with
        exponential backoff.  Otherwise moves to DLQ.
        """
        try:
            raw = self._r.hget(_PAYLOAD_HASH, task_id)
            if raw is None:
                log.warning("ReliableQueue[%s]: nack task=%s — payload missing", self._name, task_id)
                return False

            payload = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            retry_count = payload.get("_retry_count", 0) + 1
            payload["_retry_count"] = retry_count
            payload["_last_error"]  = error

            pipe = self._r.pipeline(transaction=True)
            pipe.zrem(self._leased_key, task_id)

            if retry_count < self._max_retries:
                # Exponential backoff: 10s, 20s, 40s, …
                delay   = _BACKOFF_BASE * (2 ** (retry_count - 1))
                requeue = time.time() + delay
                payload["_next_attempt"] = requeue
                pipe.hset(_PAYLOAD_HASH, task_id, json.dumps(payload, default=str))
                pipe.zadd(self._pending_key, {task_id: requeue})
                log.info("ReliableQueue[%s]: requeued task=%s (retry %d/%d, delay=%.0fs)",
                         self._name, task_id, retry_count, self._max_retries, delay)
            else:
                # Exhausted retries → DLQ
                payload["_dlq_at"] = time.time()
                pipe.hset(_PAYLOAD_HASH, task_id, json.dumps(payload, default=str))
                pipe.zadd(self._dlq_key, {task_id: time.time()})
                log.warning("ReliableQueue[%s]: task=%s sent to DLQ after %d retries — %s",
                            self._name, task_id, retry_count, error[:200])

            pipe.execute()

            # Opportunistic DLQ housekeeping: ~5% of DLQ moves trigger a purge.
            # Keeps DLQ bounded without requiring a dedicated cron job.
            if retry_count >= self._max_retries:
                import random as _random
                if _random.random() < 0.05:
                    self.purge_old_dlq_entries()

            return True

        except Exception as exc:
            log.error("ReliableQueue[%s]: nack error task=%s: %s", self._name, task_id, exc)
            return False

    # ── Maintenance ───────────────────────────────────────────────────────────

    def resurrect_expired(self) -> int:
        """
        Atomically move tasks whose leases have expired back to the pending queue.

        Uses a Lua script so that two concurrent callers cannot both resurrect
        the same task: ZREM returns 1 only for the caller that actually removes
        the entry — the other caller's ZREM returns 0 and skips the ZADD.

        Call periodically (e.g. every 60s) from a maintenance thread.
        Returns the number of tasks resurrected by THIS caller.
        """
        now = time.time()
        try:
            if self._resurrect_sha is not None:
                # Fast path: pre-loaded SHA
                try:
                    count = self._r.evalsha(
                        self._resurrect_sha,
                        2,                          # numkeys
                        self._leased_key,
                        self._pending_key,
                        now,                        # ARGV[1]
                        now,                        # ARGV[2] = re-queue score
                    )
                    count = int(count or 0)
                    if count:
                        log.info("ReliableQueue[%s]: resurrected %d expired lease(s)",
                                 self._name, count)
                    return count
                except Exception as exc:
                    # SHA evicted after Redis restart — reload and retry inline
                    log.debug("ReliableQueue[%s]: resurrect evalsha failed (%s) — reloading", self._name, exc)
                    try:
                        self._resurrect_sha = self._r.script_load(_LUA_RESURRECT)
                    except Exception:
                        self._resurrect_sha = None

            # Fallback: eval the script inline (no SHA caching)
            count = self._r.eval(
                _LUA_RESURRECT,
                2,
                self._leased_key,
                self._pending_key,
                now,
                now,
            )
            count = int(count or 0)
            if count:
                log.info("ReliableQueue[%s]: resurrected %d expired lease(s) (inline eval)",
                         self._name, count)
            return count

        except Exception as exc:
            log.error("ReliableQueue[%s]: resurrect_expired error: %s", self._name, exc)
            return 0

    def dlq_list(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return the most recent `limit` dead-letter tasks with their payloads."""
        try:
            ids = self._r.zrevrangebyscore(self._dlq_key, "+inf", "-inf", start=0, num=limit)
            results = []
            for raw_id in ids:
                task_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                raw = self._r.hget(_PAYLOAD_HASH, task_id)
                if raw:
                    try:
                        payload = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
                        results.append(payload)
                    except Exception:
                        results.append({"task_id": task_id, "_parse_error": True})
            return results
        except Exception as exc:
            log.error("ReliableQueue[%s]: dlq_list error: %s", self._name, exc)
            return []

    def retry_dlq_task(self, task_id: str) -> bool:
        """Move a single DLQ task back to pending (operator-initiated retry)."""
        try:
            raw = self._r.hget(_PAYLOAD_HASH, task_id)
            if not raw:
                return False
            payload = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
            payload["_retry_count"] = 0
            payload.pop("_dlq_at", None)
            payload.pop("_last_error", None)

            pipe = self._r.pipeline(transaction=True)
            pipe.zrem(self._dlq_key, task_id)
            pipe.hset(_PAYLOAD_HASH, task_id, json.dumps(payload, default=str))
            pipe.zadd(self._pending_key, {task_id: time.time()})
            pipe.execute()
            log.info("ReliableQueue[%s]: DLQ task=%s retried by operator", self._name, task_id)
            return True
        except Exception as exc:
            log.error("ReliableQueue[%s]: retry_dlq_task error: %s", self._name, exc)
            return False

    def purge_old_dlq_entries(self) -> int:
        """
        Remove DLQ entries older than DLQ_MAX_AGE_DAYS and cap total DLQ size
        to DLQ_MAX_SIZE by removing oldest entries.

        Safe to call from any thread at any time.
        Returns total entries purged.
        """
        try:
            now = time.time()
            cutoff = now - (DLQ_MAX_AGE_DAYS * 86_400)
            purged = 0

            # Remove expired entries (score = dlq_at timestamp)
            expired_ids = self._r.zrangebyscore(self._dlq_key, "-inf", cutoff)
            if expired_ids:
                pipe = self._r.pipeline(transaction=False)
                for raw_id in expired_ids:
                    task_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                    pipe.zrem(self._dlq_key, task_id)
                    pipe.hdel(_PAYLOAD_HASH, task_id)
                pipe.execute()
                purged += len(expired_ids)

            # Enforce DLQ_MAX_SIZE: remove oldest entries beyond the cap
            dlq_size = self._r.zcard(self._dlq_key)
            overflow = dlq_size - DLQ_MAX_SIZE
            if overflow > 0:
                oldest = self._r.zrangebyscore(
                    self._dlq_key, "-inf", "+inf", start=0, num=overflow
                )
                if oldest:
                    pipe = self._r.pipeline(transaction=False)
                    for raw_id in oldest:
                        task_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                        pipe.zrem(self._dlq_key, task_id)
                        pipe.hdel(_PAYLOAD_HASH, task_id)
                    pipe.execute()
                    purged += len(oldest)

            if purged:
                log.info("ReliableQueue[%s]: DLQ purged %d entries (age=%dd cap=%d)",
                         self._name, purged, DLQ_MAX_AGE_DAYS, DLQ_MAX_SIZE)
            return purged

        except Exception as exc:
            log.error("ReliableQueue[%s]: DLQ purge error: %s", self._name, exc)
            return 0

    def purge_dlq(self) -> int:
        """Delete all tasks from the DLQ. Returns count purged."""
        try:
            ids = self._r.zrangebyscore(self._dlq_key, "-inf", "+inf")
            if not ids:
                return 0
            pipe = self._r.pipeline(transaction=True)
            for raw_id in ids:
                task_id = raw_id.decode() if isinstance(raw_id, bytes) else raw_id
                pipe.hdel(_PAYLOAD_HASH, task_id)
            pipe.delete(self._dlq_key)
            pipe.execute()
            log.info("ReliableQueue[%s]: purged %d DLQ tasks", self._name, len(ids))
            return len(ids)
        except Exception as exc:
            log.error("ReliableQueue[%s]: purge_dlq error: %s", self._name, exc)
            return 0

    # ── Metrics ───────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, int]:
        """Return queue depth metrics."""
        try:
            return {
                "pending":  self._r.zcard(self._pending_key),
                "leased":   self._r.zcard(self._leased_key),
                "dlq":      self._r.zcard(self._dlq_key),
                "payload":  self._r.hlen(_PAYLOAD_HASH),
            }
        except Exception:
            return {"pending": 0, "leased": 0, "dlq": 0, "payload": 0}


# ── Registry: one ReliableQueue per module ────────────────────────────────────

_queues: Dict[str, "ReliableQueue"] = {}


def get_reliable_queue(
    redis_client,
    module: str = "default",
    **kwargs,
) -> ReliableQueue:
    """Return (or create) the ReliableQueue for a given module name."""
    if module not in _queues:
        _queues[module] = ReliableQueue(redis_client, name=module, **kwargs)
    return _queues[module]


def get_all_queue_stats(redis_client) -> Dict[str, Dict[str, int]]:
    """Return stats for all known module queues."""
    modules = ["recon", "vuln_scan", "exploit", "ai_security",
               "mobile", "full_pipeline", "default"]
    result = {}
    for mod in modules:
        try:
            rq = get_reliable_queue(redis_client, mod)
            result[mod] = rq.stats()
        except Exception:
            result[mod] = {"pending": 0, "leased": 0, "dlq": 0, "payload": 0}
    return result
