"""
core/swarm_state_redis.py — Redis-backed swarm coordination state.

Provides identical interface to SharedSwarmState but persists to Redis.
Falls back to in-memory dicts when redis=None.

Redis key schema (all keys have 24h TTL unless noted):
    swarm:{scan_id}:claimed_tasks    HASH  task_id → agent_id
    swarm:{scan_id}:active_findings  SET   finding_id members
    swarm:{scan_id}:agent_stats      HASH  agent_type → count (JSON int)
    swarm:{scan_id}:heartbeat        STRING  "1"  (TTL=60s, renew every 30s)
    swarm:{scan_id}:leader           STRING  worker_id  (TTL=30s)
"""
from __future__ import annotations

import logging
import time
from typing import Optional

log = logging.getLogger("oneinfinity.swarm_state_redis")

_KEY_TTL_SEC = 86_400   # 24h
_LEADER_TTL_SEC = 30


class RedisSwarmState:
    """
    Redis-backed coordination state for a single swarm scan.

    All operations are synchronous Redis calls (CLI-compatible).
    Falls back to in-memory dicts when redis client is None.
    """

    def __init__(self, scan_id: str, redis=None):
        self._scan_id = scan_id
        self._r = redis
        self._started_at = time.time()

        # In-memory fallback storage
        self._mem_claimed: dict = {}
        self._mem_findings: set = set()
        self._mem_stats: dict = {}

    # ── Keys ────────────────────────────────────────────────────────────────

    def _k(self, suffix: str) -> str:
        return f"swarm:{self._scan_id}:{suffix}"

    # ── Claimed tasks ────────────────────────────────────────────────────────

    def claim_task(self, task_id: str, agent_id: str) -> None:
        if self._r is not None:
            self._r.hset(self._k("claimed_tasks"), mapping={task_id: agent_id})
            self._r.expire(self._k("claimed_tasks"), _KEY_TTL_SEC)
        else:
            self._mem_claimed[task_id] = agent_id

    def release_task(self, task_id: str) -> None:
        if self._r is not None:
            self._r.hdel(self._k("claimed_tasks"), task_id)
        else:
            self._mem_claimed.pop(task_id, None)

    def get_claimed_tasks(self) -> dict:
        if self._r is not None:
            return dict(self._r.hgetall(self._k("claimed_tasks")) or {})
        return dict(self._mem_claimed)

    def is_task_claimed(self, task_id: str) -> bool:
        if self._r is not None:
            return self._r.hget(self._k("claimed_tasks"), task_id) is not None
        return task_id in self._mem_claimed

    # ── Active findings ──────────────────────────────────────────────────────

    def add_active_finding(self, finding_id: str) -> None:
        if self._r is not None:
            self._r.sadd(self._k("active_findings"), finding_id)
            self._r.expire(self._k("active_findings"), _KEY_TTL_SEC)
        else:
            self._mem_findings.add(finding_id)

    def get_active_findings(self) -> set:
        if self._r is not None:
            return set(self._r.smembers(self._k("active_findings")) or set())
        return set(self._mem_findings)

    # ── Agent stats ──────────────────────────────────────────────────────────

    def increment_agent_stat(self, agent_type: str, count: int = 1) -> None:
        if self._r is not None:
            key = self._k("agent_stats")
            current = int(self._r.hget(key, agent_type) or 0)
            self._r.hset(key, mapping={agent_type: str(current + count)})
            self._r.expire(key, _KEY_TTL_SEC)
        else:
            self._mem_stats[agent_type] = self._mem_stats.get(agent_type, 0) + count

    def get_agent_stats(self) -> dict:
        if self._r is not None:
            raw = self._r.hgetall(self._k("agent_stats")) or {}
            return {k: int(v) for k, v in raw.items()}
        return dict(self._mem_stats)

    # ── Heartbeat ────────────────────────────────────────────────────────────

    def touch_heartbeat(self) -> None:
        """Renew heartbeat key (call every 30s)."""
        if self._r is not None:
            self._r.set(self._k("heartbeat"), "1", ex=60)

    # ── Leader election ──────────────────────────────────────────────────────

    def acquire_leader(self, worker_id: str) -> bool:
        """Try to become leader for this scan. Returns True if acquired."""
        if self._r is not None:
            return bool(self._r.set(self._k("leader"), worker_id, nx=True, ex=_LEADER_TTL_SEC))
        # In-memory: first caller always wins (no concurrency guarantee)
        return True

    def renew_leader(self, worker_id: str) -> bool:
        """Renew leader TTL. Returns True if still leader."""
        if self._r is not None:
            current = self._r.get(self._k("leader"))
            if current == worker_id:
                self._r.expire(self._k("leader"), _LEADER_TTL_SEC)
                return True
            return False
        return True

    def release_leader(self, worker_id: str) -> None:
        if self._r is not None:
            current = self._r.get(self._k("leader"))
            if current == worker_id:
                self._r.delete(self._k("leader"))

    # ── Cleanup ──────────────────────────────────────────────────────────────

    def expire_all(self, ttl_sec: int = 3_600) -> None:
        """Set 1h expiry on all keys after scan completion."""
        if self._r is not None:
            for suffix in ("claimed_tasks", "active_findings", "agent_stats", "heartbeat", "leader"):
                try:
                    self._r.expire(self._k(suffix), ttl_sec)
                except Exception:
                    pass

    # ── Summary ──────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "scan_id":         self._scan_id,
            "claimed_tasks":   len(self.get_claimed_tasks()),
            "active_findings": len(self.get_active_findings()),
            "agent_stats":     self.get_agent_stats(),
            "elapsed_s":       round(time.time() - self._started_at, 1),
            "backend":         "redis" if self._r is not None else "memory",
        }
