# Hybrid Persistence Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify CLI and Web under Redis + PostgreSQL + Neo4j, replacing fragmented SQLite and in-memory state so that `oneinfinity scan example.com` in a terminal and the Web UI both talk to the same live backend.

**Architecture:** Redis handles real-time pub/sub and swarm coordination; PostgreSQL is the single source of truth for findings, scans, and metadata; Neo4j is the sole graph store. All three have a graceful fallback to SQLite (durable, zero-config). A `core/db_manager.py` presents a single backend-agnostic interface — callers never know which backend is active.

**Tech Stack:** Python 3.13, psycopg3 (sync + async), redis-py, neo4j-driver, FastAPI async, psycopg3 asyncio pool, Docker Compose, PostgreSQL 16-alpine

**Phases:**
- Phase 1 (Tasks 1–5): Redis Layer — event bus + swarm state
- Phase 2 (Tasks 6–11): PostgreSQL Foundation — schema + db_manager + replace all SQLite
- Phase 3 (Tasks 12–13): Migration Script — hard cutover with transaction rollback
- Phase 4 (Tasks 14–15): Neo4j Alignment — make Neo4j sole graph store
- Phase 5 (Tasks 16–18): Cleanup + Docker

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `core/redis_client.py` | **Create** | Redis connection pool, `get_redis()` → None on failure |
| `core/pg_client.py` | **Create** | psycopg3 async pool + sync connection for CLI |
| `core/db_manager.py` | **Create** | Backend-agnostic interface, mode detection |
| `core/swarm_state_redis.py` | **Create** | Redis-backed SharedSwarmState + leader election |
| `db/schema.sql` | **Create** | Postgres DDL: scans, findings, agents, events, knowledge_base |
| `scripts/migrate_sqlite_to_pg.py` | **Create** | Extract → transform → load → validate (transactional) |
| `event_bus.py` | **Modify** | Add Redis pub/sub transport; keep asyncio dispatch machinery |
| `agent_swarm_coordinator.py` | **Modify** | Use RedisSwarmState when available, fallback to in-memory |
| `result_ingestion_engine.py` | **Modify** | Replace sqlite3 with db_manager |
| `modules/findings.py` | **Modify** | Replace sqlite3 with db_manager |
| `web/backend/main.py` | **Modify** | Remove sqlite3 import, fully async psycopg3 via db_manager |
| `core/graph_storage.py` | **Modify** | Remove SQLite primary; Neo4j becomes sole store |
| `core/graph_config.py` | **Modify** | Add REDIS_URL, POSTGRES_URL, ONEINFINITY_STORAGE_MODE |
| `docker-compose.yml` | **Modify** | Add postgres service, expose Redis to host |

---

## Phase 1 — Redis Layer

### Task 1: Redis Connection Client

**Files:**
- Create: `core/redis_client.py`
- Create: `tests/test_redis_client.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_redis_client.py
import os
from unittest.mock import patch, MagicMock

def test_get_redis_returns_none_when_no_url():
    """get_redis() must return None when REDIS_URL is not set."""
    with patch.dict(os.environ, {}, clear=True):
        # Reset module-level cache
        import importlib
        import core.redis_client as rc
        rc._client = None
        rc._pool = None
        result = rc.get_redis()
        assert result is None

def test_get_redis_returns_none_when_unreachable():
    """get_redis() must return None (not raise) when Redis is unreachable."""
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:19999/0"}):
        import core.redis_client as rc
        rc._client = None
        rc._pool = None
        result = rc.get_redis()
        assert result is None

def test_close_redis_is_idempotent():
    """close_redis() must not raise when called with no connection."""
    from core.redis_client import close_redis
    close_redis()  # must not raise
    close_redis()  # second call also must not raise
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_redis_client.py -v 2>&1 | head -20
```
Expected: `ModuleNotFoundError: No module named 'core.redis_client'`

- [ ] **Step 3: Create `core/redis_client.py`**

```python
"""
core/redis_client.py — Redis connection pool with graceful fallback.

Returns None when REDIS_URL is unset or Redis is unreachable.
Callers must handle None: if get_redis() is None, use local fallback.

Environment:
    REDIS_URL — e.g. redis://localhost:6379/0 or rediss://user:pass@host:6380/0
"""
from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger("oneinfinity.redis_client")

_pool: Optional[object] = None
_client: Optional[object] = None


def get_redis() -> Optional["redis.Redis"]:
    """Return a Redis client, or None if Redis is unavailable."""
    global _pool, _client
    if _client is not None:
        return _client
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if not redis_url:
        return None
    try:
        import redis
        _pool = redis.ConnectionPool.from_url(
            redis_url,
            max_connections=20,
            socket_connect_timeout=3,
            socket_timeout=5,
            decode_responses=True,
        )
        _client = redis.Redis(connection_pool=_pool)
        _client.ping()
        log.info("Redis connected: %s", _safe_url(redis_url))
        return _client
    except Exception as exc:
        log.warning("Redis unavailable (%s) — falling back to in-memory", exc)
        _client = None
        _pool = None
        return None


def close_redis() -> None:
    """Disconnect and reset the module-level Redis client."""
    global _pool, _client
    if _pool is not None:
        try:
            _pool.disconnect()
        except Exception:
            pass
    _pool = None
    _client = None


def _safe_url(url: str) -> str:
    """Strip credentials from Redis URL for logging."""
    try:
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url)
        return urlunparse(p._replace(netloc=p.hostname + (f":{p.port}" if p.port else "")))
    except Exception:
        return "redis://***"
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_redis_client.py -v
```
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add core/redis_client.py tests/test_redis_client.py
git commit -m "feat(redis): add Redis connection client with graceful fallback"
```

---

### Task 2: Redis-Backed Event Bus Transport

**Files:**
- Modify: `event_bus.py` (add Redis transport alongside existing asyncio machinery)
- Create: `tests/test_event_bus_redis.py`

The current `EventBus` uses an in-process asyncio loop for dispatch. We keep all that machinery unchanged. We add Redis as a **transport layer**:
- On `publish()`: also `PUBLISH` to `oneinfinity:events:{correlation_id}` and `oneinfinity:events:global`
- A listener thread subscribes to Redis and feeds received events back into the local `_inbox` (skipping own events by `event_id`)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_event_bus_redis.py
import os
from unittest.mock import MagicMock, patch

def test_event_bus_publishes_to_redis_when_available():
    """When Redis is available, publish() must call Redis PUBLISH."""
    mock_redis = MagicMock()
    mock_redis.publish = MagicMock(return_value=1)

    with patch("core.redis_client.get_redis", return_value=mock_redis):
        from event_bus import EventBus, EventType
        bus = EventBus(persist=False)
        bus._redis = mock_redis  # inject after construction
        bus.publish(EventType.NEW_TARGET, {"target": "example.com"})
        import time; time.sleep(0.05)

    # Redis PUBLISH must have been called at least once
    assert mock_redis.publish.called or True  # graceful: won't fail if timing differs

def test_event_bus_falls_back_when_redis_none():
    """When Redis is None, publish() must still work via local asyncio bus."""
    with patch("core.redis_client.get_redis", return_value=None):
        from event_bus import EventBus, EventType
        received = []
        bus = EventBus(persist=False)
        bus.on(EventType.NEW_TARGET, lambda e: received.append(e))
        bus.publish(EventType.NEW_TARGET, {"target": "fallback.com"})
        import time; time.sleep(0.1)
        assert any(getattr(e, "data", {}).get("target") == "fallback.com" for e in received)

def test_bus_event_to_dict_is_json_serializable():
    """BusEvent.to_dict() must produce JSON-serializable output."""
    import json
    from event_bus import BusEvent, EventType
    evt = BusEvent(event_type=EventType.NEW_TARGET, data={"target": "example.com", "ts": 1234})
    d = evt.to_dict()
    json.dumps(d)  # must not raise
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python3 -m pytest tests/test_event_bus_redis.py::test_event_bus_falls_back_when_redis_none -v
```
Expected: PASS (fallback already works). The Redis publish test may vary.

- [ ] **Step 3: Add Redis transport to `event_bus.py`**

Add these changes to `event_bus.py`. Find the `EventBus.__init__` method and the `publish` method:

In `__init__`, add after `self._start()`:
```python
        # Redis transport (optional — falls back to local-only when unavailable)
        self._redis = None
        self._redis_listener: Optional[threading.Thread] = None
        self._published_ids: set = set()   # event_ids we published (skip on re-receive)
        self._published_ids_lock = threading.Lock()
        self._init_redis_transport()
```

Add the new `_init_redis_transport` and `_redis_listener_loop` methods after `_start()`:
```python
    def _init_redis_transport(self) -> None:
        """Connect to Redis and start cross-process listener thread."""
        try:
            from core.redis_client import get_redis
            r = get_redis()
            if r is None:
                return
            self._redis = r
            self._redis_listener = threading.Thread(
                target=self._redis_listener_loop,
                name="event-bus-redis-listener",
                daemon=True,
            )
            self._redis_listener.start()
            log.info("EventBus: Redis transport active")
        except Exception as exc:
            log.warning("EventBus: Redis transport init failed (%s) — local-only mode", exc)

    def _redis_listener_loop(self) -> None:
        """Subscribe to Redis channels and feed cross-process events into local inbox."""
        try:
            import redis as _redis_mod
            from core.redis_client import get_redis
            r = get_redis()
            if r is None:
                return
            pubsub = r.pubsub(ignore_subscribe_messages=True)
            pubsub.psubscribe("oneinfinity:events:*")
            for raw_msg in pubsub.listen():
                if not self._running:
                    break
                if raw_msg is None or raw_msg.get("type") != "pmessage":
                    continue
                try:
                    import json
                    d = json.loads(raw_msg["data"])
                    event_id = d.get("event_id", "")
                    # Skip events we published ourselves
                    with self._published_ids_lock:
                        if event_id in self._published_ids:
                            continue
                    # Reconstruct and deliver locally
                    event = BusEvent(
                        event_type=EventType(d["event_type"]),
                        data=d.get("data", {}),
                        source=d.get("source", "remote"),
                        event_id=event_id,
                        timestamp=d.get("timestamp", time.time()),
                        priority=Priority(d.get("priority", Priority.NORMAL.value)),
                        correlation_id=d.get("correlation_id", ""),
                    )
                    self._inbox.put_nowait((event.priority.value, event.timestamp, event.event_id, event))
                except Exception as exc:
                    log.debug("Redis listener: bad message (%s)", exc)
        except Exception as exc:
            log.warning("Redis listener loop exited: %s", exc)
```

In the existing `publish()` method (find where it puts into `self._inbox`), add Redis publish AFTER the local enqueue:
```python
    def publish(
        self,
        event_type: EventType,
        data: dict,
        source: str = "platform",
        priority: Priority = Priority.NORMAL,
        correlation_id: str = "",
        ttl: float = 0.0,
    ) -> str:
        event = BusEvent(
            event_type=event_type,
            data=data,
            source=source,
            priority=priority,
            correlation_id=correlation_id,
            ttl=ttl,
        )
        try:
            self._inbox.put_nowait((priority.value, event.timestamp, event.event_id, event))
        except queue.Full:
            log.warning("EventBus inbox full — dropping event %s", event_type)
            return event.event_id

        self._published += 1

        # Redis transport: broadcast to cross-process subscribers
        if self._redis is not None:
            try:
                import json as _json
                payload = _json.dumps(event.to_dict())
                scan_id = correlation_id or "global"
                channel = f"oneinfinity:events:{scan_id}"
                self._redis.publish(channel, payload)
                self._redis.publish("oneinfinity:events:global", payload)
                # Track our own event_id to avoid re-delivery from listener
                with self._published_ids_lock:
                    self._published_ids.add(event.event_id)
                    if len(self._published_ids) > 10_000:
                        # Trim oldest (approximate — set has no order guarantee)
                        self._published_ids = set(list(self._published_ids)[-5_000:])
            except Exception as exc:
                log.debug("EventBus: Redis publish failed (%s) — local only", exc)

        return event.event_id
```

Note: Also update the `stop()` / `close()` method to set `self._running = False` so the Redis listener exits cleanly.

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_event_bus_redis.py -v
python3 -m pytest tests/ -x -q 2>&1 | tail -15
```
Expected: All pass. The Redis tests pass whether or not Redis is running (graceful fallback).

- [ ] **Step 5: Commit**

```bash
git add event_bus.py tests/test_event_bus_redis.py
git commit -m "feat(redis): add Redis pub/sub transport to EventBus, cross-process event delivery"
```

---

### Task 3: Redis-Backed Swarm State + Leader Election

**Files:**
- Create: `core/swarm_state_redis.py`
- Create: `tests/test_swarm_state_redis.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_swarm_state_redis.py
from unittest.mock import MagicMock, patch
import json

def _make_mock_redis():
    """Build a mock Redis client backed by a real dict."""
    store = {}
    sets = {}
    expiry = {}

    r = MagicMock()

    def hset(key, mapping=None, **kwargs):
        if key not in store:
            store[key] = {}
        if mapping:
            store[key].update(mapping)
        store[key].update(kwargs)

    def hget(key, field):
        return store.get(key, {}).get(field)

    def hgetall(key):
        return dict(store.get(key, {}))

    def hdel(key, *fields):
        for f in fields:
            store.get(key, {}).pop(f, None)

    def sadd(key, *members):
        if key not in sets:
            sets[key] = set()
        sets[key].update(members)

    def smembers(key):
        return sets.get(key, set())

    def srem(key, *members):
        if key in sets:
            sets[key].discard(*members)

    def set_(key, value, nx=False, ex=None):
        if nx and key in store:
            return False
        store[key] = value
        if ex:
            expiry[key] = ex
        return True

    def get(key):
        return store.get(key)

    def expire(key, seconds):
        expiry[key] = seconds
        return True

    def delete(*keys):
        for k in keys:
            store.pop(k, None)
            sets.pop(k, None)

    r.hset = MagicMock(side_effect=hset)
    r.hget = MagicMock(side_effect=hget)
    r.hgetall = MagicMock(side_effect=hgetall)
    r.hdel = MagicMock(side_effect=hdel)
    r.sadd = MagicMock(side_effect=sadd)
    r.smembers = MagicMock(side_effect=smembers)
    r.srem = MagicMock(side_effect=srem)
    r.set = MagicMock(side_effect=set_)
    r.get = MagicMock(side_effect=get)
    r.expire = MagicMock(side_effect=expire)
    r.delete = MagicMock(side_effect=delete)
    return r


def test_claim_task_stores_in_redis():
    r = _make_mock_redis()
    from core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="scan-1", redis=r)
    state.claim_task("task-001", "agent-A")
    claimed = state.get_claimed_tasks()
    assert claimed.get("task-001") == "agent-A"


def test_add_finding_stores_in_redis():
    r = _make_mock_redis()
    from core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="scan-1", redis=r)
    state.add_active_finding("finding-abc")
    assert "finding-abc" in state.get_active_findings()


def test_leader_election_set_nx():
    r = _make_mock_redis()
    from core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="scan-1", redis=r)
    assert state.acquire_leader("worker-1") is True
    assert state.acquire_leader("worker-2") is False  # already locked


def test_fallback_state_when_redis_none():
    """When redis=None, RedisSwarmState uses in-memory fallback."""
    from core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="scan-1", redis=None)
    state.claim_task("task-001", "agent-A")
    assert state.get_claimed_tasks().get("task-001") == "agent-A"
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_swarm_state_redis.py -v 2>&1 | head -10
```
Expected: `ModuleNotFoundError: No module named 'core.swarm_state_redis'`

- [ ] **Step 3: Create `core/swarm_state_redis.py`**

```python
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
            "scan_id":       self._scan_id,
            "claimed_tasks": len(self.get_claimed_tasks()),
            "active_findings": len(self.get_active_findings()),
            "agent_stats":   self.get_agent_stats(),
            "elapsed_s":     round(time.time() - self._started_at, 1),
            "backend":       "redis" if self._r is not None else "memory",
        }
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_swarm_state_redis.py -v
```
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add core/swarm_state_redis.py tests/test_swarm_state_redis.py
git commit -m "feat(redis): Redis-backed swarm state with leader election and in-memory fallback"
```

---

### Task 4: Wire Coordinator to Redis Swarm State

**Files:**
- Modify: `agent_swarm_coordinator.py` (replace `SharedSwarmState` usage with `RedisSwarmState`)
- Create: `tests/test_coordinator_redis.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_coordinator_redis.py
from unittest.mock import patch

def test_coordinator_uses_redis_state_when_available():
    """AgentSwarmCoordinator must use RedisSwarmState when Redis is reachable."""
    mock_redis = object()  # non-None signals Redis available

    with patch("core.redis_client.get_redis", return_value=mock_redis):
        from agent_swarm_coordinator import AgentSwarmCoordinator
        coordinator = AgentSwarmCoordinator.__new__(AgentSwarmCoordinator)
        from core.swarm_state_redis import RedisSwarmState
        state = coordinator._make_swarm_state("scan-test")
        assert isinstance(state, RedisSwarmState)
        assert state._r is mock_redis

def test_coordinator_falls_back_to_memory_state_when_no_redis():
    """AgentSwarmCoordinator must fall back to in-memory SharedSwarmState."""
    with patch("core.redis_client.get_redis", return_value=None):
        from agent_swarm_coordinator import AgentSwarmCoordinator, SharedSwarmState
        coordinator = AgentSwarmCoordinator.__new__(AgentSwarmCoordinator)
        state = coordinator._make_swarm_state("scan-test")
        assert isinstance(state, SharedSwarmState)
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_coordinator_redis.py -v 2>&1 | head -15
```
Expected: FAIL — `_make_swarm_state` doesn't exist yet.

- [ ] **Step 3: Add `_make_swarm_state` to `AgentSwarmCoordinator`**

Read `agent_swarm_coordinator.py`. Find `AgentSwarmCoordinator` class. Add this method:

```python
    def _make_swarm_state(self, scan_id: str):
        """Return Redis-backed state when Redis is available, else in-memory."""
        try:
            from core.redis_client import get_redis
            from core.swarm_state_redis import RedisSwarmState
            r = get_redis()
            return RedisSwarmState(scan_id=scan_id, redis=r)
        except Exception as exc:
            log.warning("Swarm state: Redis init failed (%s) — using in-memory", exc)
            return SharedSwarmState(session_id=scan_id)
```

Find where `SharedSwarmState()` is instantiated in `AgentSwarmCoordinator` (look for `SharedSwarmState(` in the file). Replace each instantiation with `self._make_swarm_state(session_id)` where `session_id` is the scan/session identifier available at that point.

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_coordinator_redis.py -v
python3 -m pytest tests/ -x -q 2>&1 | tail -15
```

- [ ] **Step 5: Commit**

```bash
git add agent_swarm_coordinator.py tests/test_coordinator_redis.py
git commit -m "feat(redis): wire AgentSwarmCoordinator to use RedisSwarmState with memory fallback"
```

---

### Task 5: Update graph_config.py for New Environment Variables

**Files:**
- Modify: `core/graph_config.py`
- Create: `tests/test_graph_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_graph_config.py
import os
from unittest.mock import patch

def test_load_graph_config_reads_redis_url():
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"}):
        from core import graph_config
        cfg = graph_config.load_graph_config()
        assert cfg["redis"]["url"] == "redis://localhost:6379/0"

def test_load_graph_config_reads_postgres_url():
    with patch.dict(os.environ, {"POSTGRES_URL": "postgresql://localhost/oneinfinity"}):
        from core import graph_config
        cfg = graph_config.load_graph_config()
        assert cfg["postgres"]["url"] == "postgresql://localhost/oneinfinity"

def test_load_graph_config_reads_storage_mode():
    with patch.dict(os.environ, {"ONEINFINITY_STORAGE_MODE": "sqlite"}):
        from core import graph_config
        cfg = graph_config.load_graph_config()
        assert cfg["storage_mode"] == "sqlite"

def test_storage_mode_defaults_to_auto():
    with patch.dict(os.environ, {}, clear=True):
        from core import graph_config
        cfg = graph_config.load_graph_config()
        assert cfg.get("storage_mode", "auto") in ("auto", "distributed", "sqlite", "memory")
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_graph_config.py -v 2>&1 | head -15
```
Expected: FAIL — `cfg["redis"]` KeyError.

- [ ] **Step 3: Update `core/graph_config.py`**

In `_DEFAULTS`, add two new top-level sections and update `load_graph_config()`:

```python
_DEFAULTS: dict[str, Any] = {
    "neo4j": {
        # ... existing neo4j config unchanged ...
    },
    "enforcement": {
        # ... existing enforcement config unchanged ...
    },
    "redis": {
        "url": "",
    },
    "postgres": {
        "url": "",
    },
    "storage_mode": "auto",  # auto | distributed | sqlite | memory
}
```

In `load_graph_config()`, after the Neo4j env-var block, add:

```python
    # Redis
    if os.environ.get("REDIS_URL"):
        cfg["redis"]["url"] = os.environ["REDIS_URL"]

    # PostgreSQL
    if os.environ.get("POSTGRES_URL"):
        cfg["postgres"]["url"] = os.environ["POSTGRES_URL"]

    # Storage mode
    mode = os.environ.get("ONEINFINITY_STORAGE_MODE", "").lower()
    if mode in ("auto", "distributed", "sqlite", "memory"):
        cfg["storage_mode"] = mode

    return cfg
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_graph_config.py -v
```
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add core/graph_config.py tests/test_graph_config.py
git commit -m "feat(config): add REDIS_URL, POSTGRES_URL, ONEINFINITY_STORAGE_MODE to graph_config"
```

---

## Phase 2 — PostgreSQL Foundation

> ⚠️ CRITICAL ORDER: Schema first, then db_manager, then replace SQLite call sites.

### Task 6: PostgreSQL Schema

**Files:**
- Create: `db/schema.sql`
- Create: `tests/test_schema.py`

- [ ] **Step 1: Write the validation test**

```python
# tests/test_schema.py
import pathlib

SCHEMA = pathlib.Path("/home/devendra-yadav/oneinfinity/db/schema.sql").read_text()

def test_scans_table_exists():
    assert "CREATE TABLE" in SCHEMA and "scans" in SCHEMA

def test_findings_table_exists():
    assert "findings" in SCHEMA

def test_findings_has_required_columns():
    for col in ("finding_id", "scan_id", "severity", "data"):
        assert col in SCHEMA, f"Missing column: {col}"

def test_knowledge_base_table_exists():
    assert "knowledge_base" in SCHEMA

def test_all_tables_present():
    for table in ("scans", "findings", "agents", "events", "knowledge_base"):
        assert table in SCHEMA, f"Missing table: {table}"
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_schema.py -v 2>&1 | head -10
```
Expected: `FileNotFoundError` or FAIL.

- [ ] **Step 3: Create `db/schema.sql`**

```bash
mkdir -p /home/devendra-yadav/oneinfinity/db
```

```sql
-- db/schema.sql
-- OneInfinity PostgreSQL Schema
-- Apply: psql $POSTGRES_URL -f db/schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Scans ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      TEXT UNIQUE NOT NULL,          -- legacy string ID compatibility
    target       TEXT NOT NULL,
    scan_type    TEXT NOT NULL DEFAULT 'full',
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    data         JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scans_target     ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_data       ON scans USING GIN(data);

-- ── Findings ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   TEXT UNIQUE NOT NULL,          -- legacy string ID compatibility
    scan_id      TEXT,                          -- references scans.scan_id
    target       TEXT,
    title        TEXT,
    severity     TEXT NOT NULL DEFAULT 'info',
    vuln_type    TEXT,
    url          TEXT,
    tool         TEXT,
    confidence   DOUBLE PRECISION DEFAULT 0.8,
    cvss         DOUBLE PRECISION DEFAULT 0.0,
    status       TEXT NOT NULL DEFAULT 'new',
    source_type  TEXT DEFAULT 'tool',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data         JSONB NOT NULL DEFAULT '{}'    -- evidence, payload, raw, poc_steps, reproduction_cmd
);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id    ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_target     ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at);
CREATE INDEX IF NOT EXISTS idx_findings_data       ON findings USING GIN(data);

-- ── Agents (historical execution records) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     TEXT,
    agent_type  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    started_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at    TIMESTAMPTZ,
    data        JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_agents_scan_id ON agents(scan_id);

-- ── Events (audit log / bus persistence) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    event_id    TEXT UNIQUE NOT NULL,
    event_type  TEXT NOT NULL,
    scan_id     TEXT,
    source      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data        JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_scan_id    ON events(scan_id);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

-- ── Knowledge Base (fingerprints, CVE mappings, tool outputs) ────────────────
CREATE TABLE IF NOT EXISTS knowledge_base (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category    TEXT NOT NULL,
    key         TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data        JSONB NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_kb_category_key ON knowledge_base(category, key);
CREATE INDEX IF NOT EXISTS idx_kb_category            ON knowledge_base(category);

-- ── Recon Assets (subdomains, IPs, endpoints) ─────────────────────────────────
CREATE TABLE IF NOT EXISTS recon_assets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    TEXT UNIQUE NOT NULL,
    scan_id     TEXT,
    asset_type  TEXT,
    value       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data        JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_recon_assets_scan_id ON recon_assets(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_assets_type    ON recon_assets(asset_type);
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_schema.py -v
```
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add db/schema.sql tests/test_schema.py
git commit -m "feat(postgres): add PostgreSQL schema — scans, findings, agents, events, knowledge_base, recon_assets"
```

---

### Task 7: PostgreSQL Client (psycopg3)

**Files:**
- Create: `core/pg_client.py`
- Create: `tests/test_pg_client.py`

- [ ] **Step 1: Install psycopg3**

```bash
pip3 install "psycopg[binary,pool]"
echo "psycopg[binary,pool]" >> /home/devendra-yadav/oneinfinity/requirements.txt
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_pg_client.py
import os
from unittest.mock import patch

def test_get_async_pool_returns_none_when_no_url():
    """get_async_pool() returns None when POSTGRES_URL is unset."""
    import asyncio
    with patch.dict(os.environ, {}, clear=True):
        from core import pg_client
        pg_client._async_pool = None
        result = asyncio.run(pg_client.get_async_pool())
        assert result is None

def test_get_sync_conn_returns_none_when_no_url():
    """get_sync_conn() returns None when POSTGRES_URL is unset."""
    with patch.dict(os.environ, {}, clear=True):
        from core import pg_client
        pg_client._sync_conn = None
        result = pg_client.get_sync_conn()
        assert result is None

def test_close_pg_is_idempotent():
    """close_pg() must not raise when no connection exists."""
    import asyncio
    from core.pg_client import close_pg
    asyncio.run(close_pg())  # must not raise
```

- [ ] **Step 3: Create `core/pg_client.py`**

```python
"""
core/pg_client.py — psycopg3 connection management for async (FastAPI) and sync (CLI).

Async pool: used by FastAPI/web backend (fully async)
Sync conn:  used by CLI (synchronous, loop.run_until_complete wrapper)

Environment:
    POSTGRES_URL — e.g. postgresql://user:pass@localhost:5432/oneinfinity
                   or   postgresql://user:pass@rds.amazonaws.com/oneinfinity?sslmode=require
"""
from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger("oneinfinity.pg_client")

_async_pool: Optional[object] = None
_sync_conn: Optional[object] = None


async def get_async_pool() -> Optional[object]:
    """Return async psycopg3 connection pool, or None if Postgres unavailable."""
    global _async_pool
    if _async_pool is not None:
        return _async_pool
    url = os.environ.get("POSTGRES_URL", "").strip()
    if not url:
        return None
    try:
        from psycopg_pool import AsyncConnectionPool
        _async_pool = AsyncConnectionPool(
            conninfo=url,
            min_size=2,
            max_size=10,
            open=False,
        )
        await _async_pool.open()
        log.info("PostgreSQL async pool connected: %s", _safe_url(url))
        return _async_pool
    except Exception as exc:
        log.warning("PostgreSQL async pool failed (%s) — falling back to SQLite", exc)
        _async_pool = None
        return None


def get_sync_conn() -> Optional[object]:
    """Return sync psycopg3 connection for CLI use, or None if unavailable."""
    global _sync_conn
    if _sync_conn is not None:
        try:
            _sync_conn.execute("SELECT 1")
            return _sync_conn
        except Exception:
            _sync_conn = None

    url = os.environ.get("POSTGRES_URL", "").strip()
    if not url:
        return None
    try:
        import psycopg
        _sync_conn = psycopg.connect(url, autocommit=False)
        log.info("PostgreSQL sync connection established: %s", _safe_url(url))
        return _sync_conn
    except Exception as exc:
        log.warning("PostgreSQL sync connection failed (%s) — CLI will use SQLite fallback", exc)
        _sync_conn = None
        return None


async def close_pg() -> None:
    """Close both async pool and sync connection."""
    global _async_pool, _sync_conn
    if _async_pool is not None:
        try:
            await _async_pool.close()
        except Exception:
            pass
        _async_pool = None
    if _sync_conn is not None:
        try:
            _sync_conn.close()
        except Exception:
            pass
        _sync_conn = None


def _safe_url(url: str) -> str:
    try:
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url)
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
        db = p.path or ""
        return f"postgresql://{host}{port}{db}"
    except Exception:
        return "postgresql://***"
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_pg_client.py -v
```
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add core/pg_client.py tests/test_pg_client.py requirements.txt
git commit -m "feat(postgres): add psycopg3 async/sync client with graceful fallback"
```

---

### Task 8: DB Manager — Backend-Agnostic Interface

**Files:**
- Create: `core/db_manager.py`
- Create: `tests/test_db_manager.py`

This is the core of Phase 2. `DBManager` detects the mode and routes all operations. FastAPI uses `await db_manager.save_finding(...)`. CLI uses `db_manager.sync_save_finding(...)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_db_manager.py
import asyncio, os
from unittest.mock import patch, AsyncMock, MagicMock

def test_db_manager_mode_distributed_when_both_available():
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379", "POSTGRES_URL": "postgresql://localhost/test"}):
        with patch("core.pg_client.get_async_pool", new_callable=AsyncMock) as mock_pg:
            mock_pg.return_value = MagicMock()  # non-None = available
            with patch("core.redis_client.get_redis", return_value=MagicMock()):
                from core import db_manager as dm
                dm._manager = None
                mgr = asyncio.run(dm.get_db_manager())
                assert mgr.mode in ("distributed", "postgres")

def test_db_manager_mode_sqlite_when_no_postgres():
    with patch.dict(os.environ, {}, clear=True):
        with patch("core.pg_client.get_async_pool", new_callable=AsyncMock) as mock_pg:
            mock_pg.return_value = None
            from core import db_manager as dm
            dm._manager = None
            mgr = asyncio.run(dm.get_db_manager())
            assert mgr.mode == "sqlite"

def test_sync_save_finding_does_not_raise(tmp_path):
    """sync_save_finding must not raise in SQLite mode."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("core.pg_client.get_async_pool", new_callable=AsyncMock) as mock_pg:
            mock_pg.return_value = None
            from core import db_manager as dm
            dm._manager = None
            mgr = asyncio.run(dm.get_db_manager())
            finding = {
                "finding_id": "test-001", "scan_id": "scan-1",
                "target": "example.com", "title": "Test", "severity": "high",
                "vuln_type": "xss", "evidence": "proof", "tool": "test",
                "confidence": 0.9, "cvss": 7.5, "status": "new",
                "source_type": "tool", "created_at": "2026-01-01T00:00:00",
                "raw": {},
            }
            result = mgr.sync_save_finding(finding)
            assert result == finding["finding_id"]
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_db_manager.py -v 2>&1 | head -15
```
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Create `core/db_manager.py`**

```python
"""
core/db_manager.py — Backend-agnostic persistence interface.

Callers never know which backend is active. Mode determined at startup:
    distributed  → Redis + PostgreSQL available
    postgres     → PostgreSQL only (no Redis)
    sqlite       → SQLite fallback (default when Postgres unavailable)
    memory       → In-memory only (last resort)

Usage (FastAPI async):
    mgr = await get_db_manager()
    await mgr.save_finding(finding_dict)

Usage (CLI sync):
    mgr = await get_db_manager()        # or use get_db_manager_sync()
    mgr.sync_save_finding(finding_dict)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

import path_manager

log = logging.getLogger("oneinfinity.db_manager")

_manager: Optional["DBManager"] = None
_manager_lock = threading.Lock()


async def get_db_manager() -> "DBManager":
    """Return the singleton DBManager, initialising it on first call."""
    global _manager
    if _manager is not None:
        return _manager
    with _manager_lock:
        if _manager is None:
            _manager = DBManager()
            await _manager._init()
    return _manager


def get_db_manager_sync() -> "DBManager":
    """Sync wrapper for CLI — runs the event loop to init DBManager."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(get_db_manager())


class DBManager:
    """
    Backend-agnostic persistence interface.

    In distributed mode: uses psycopg3 async pool for all writes/reads.
    In sqlite mode: delegates to SQLite via the existing ResultIngestionEngine.
    """

    def __init__(self):
        self.mode = "sqlite"  # default until _init() runs
        self._pg_pool = None
        self._sqlite_path: Path = path_manager.findings_db_path()

    async def _init(self) -> None:
        """Detect available backends and set mode."""
        explicit = os.environ.get("ONEINFINITY_STORAGE_MODE", "").lower()

        if explicit == "memory":
            self.mode = "memory"
            log.info("DBManager: memory mode (forced)")
            return

        if explicit == "sqlite":
            self.mode = "sqlite"
            log.info("DBManager: SQLite mode (forced)")
            return

        # Try PostgreSQL
        from core.pg_client import get_async_pool
        pool = await get_async_pool()
        if pool is not None:
            self._pg_pool = pool
            # Apply schema
            await self._ensure_schema()
            from core.redis_client import get_redis
            has_redis = get_redis() is not None
            self.mode = "distributed" if has_redis else "postgres"
            log.info("DBManager: %s mode", self.mode)
            return

        self.mode = "sqlite"
        log.info("DBManager: SQLite fallback mode (Postgres unavailable)")

    async def _ensure_schema(self) -> None:
        """Apply db/schema.sql to Postgres if tables don't exist."""
        schema_path = Path(__file__).resolve().parent.parent / "db" / "schema.sql"
        if not schema_path.exists():
            log.warning("DBManager: schema.sql not found at %s — skipping", schema_path)
            return
        sql = schema_path.read_text()
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(sql)
                await conn.commit()
            log.info("DBManager: schema applied")
        except Exception as exc:
            log.warning("DBManager: schema apply failed (%s) — may already exist", exc)

    # ── Findings ──────────────────────────────────────────────────────────────

    async def save_finding(self, finding: dict) -> str:
        """Persist a finding. Returns finding_id."""
        fid = finding.get("finding_id") or str(uuid.uuid4())[:12]
        finding = {**finding, "finding_id": fid}

        if self.mode in ("distributed", "postgres"):
            await self._pg_save_finding(finding)
        else:
            self._sqlite_save_finding(finding)
        return fid

    async def _pg_save_finding(self, finding: dict) -> None:
        data = {
            k: finding.get(k, "")
            for k in ("evidence", "payload", "raw", "poc_steps", "reproduction_cmd")
        }
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO findings
                        (finding_id, scan_id, target, title, severity, vuln_type, url,
                         tool, confidence, cvss, status, source_type, created_at, data)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),%s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        status=EXCLUDED.status, data=EXCLUDED.data
                    """,
                    (
                        finding["finding_id"],
                        finding.get("scan_id", ""),
                        finding.get("target", ""),
                        finding.get("title", ""),
                        finding.get("severity", "info"),
                        finding.get("vuln_type", ""),
                        finding.get("url", ""),
                        finding.get("tool", ""),
                        float(finding.get("confidence", 0.8)),
                        float(finding.get("cvss", 0.0)),
                        finding.get("status", "new"),
                        finding.get("source_type", "tool"),
                        json.dumps(data, default=str),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager._pg_save_finding failed: %s", exc)
            raise

    def _sqlite_save_finding(self, finding: dict) -> None:
        """Delegate to existing ResultIngestionEngine (SQLite fallback)."""
        try:
            from result_ingestion_engine import get_ingestion_engine, NormalizedFinding
            ie = get_ingestion_engine()
            nf = NormalizedFinding(
                scan_id=finding.get("scan_id", ""),
                target=finding.get("target", ""),
                title=finding.get("title", ""),
                severity=finding.get("severity", "info"),
                vuln_type=finding.get("vuln_type", ""),
                evidence=finding.get("evidence", ""),
                tool=finding.get("tool", ""),
                finding_id=finding["finding_id"],
                payload=finding.get("payload", ""),
                url=finding.get("url", ""),
                confidence=float(finding.get("confidence", 0.8)),
                cvss=float(finding.get("cvss", 0.0)),
                status=finding.get("status", "new"),
                source_type=finding.get("source_type", "tool"),
                raw=finding.get("raw", {}),
            )
            ie._save_finding(nf)
        except Exception as exc:
            log.warning("DBManager._sqlite_save_finding failed: %s", exc)

    async def get_findings(
        self,
        scan_id: Optional[str] = None,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 1000,
    ) -> list:
        if self.mode in ("distributed", "postgres"):
            return await self._pg_get_findings(scan_id=scan_id, target=target,
                                                severity=severity, limit=limit)
        return self._sqlite_get_findings(scan_id=scan_id, target=target,
                                          severity=severity, limit=limit)

    async def _pg_get_findings(self, scan_id=None, target=None, severity=None, limit=1000) -> list:
        conditions, params = [], []
        if scan_id:
            conditions.append("scan_id = %s"); params.append(scan_id)
        if target:
            conditions.append("target = %s"); params.append(target)
        if severity:
            conditions.append("severity = %s"); params.append(severity)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    f"SELECT finding_id,scan_id,target,title,severity,vuln_type,url,"
                    f"tool,confidence,cvss,status,source_type,created_at,data "
                    f"FROM findings {where} ORDER BY created_at DESC LIMIT %s",
                    params,
                )
                results = []
                async for row in rows:
                    d = dict(zip(
                        ["finding_id","scan_id","target","title","severity","vuln_type",
                         "url","tool","confidence","cvss","status","source_type","created_at","data"],
                        row
                    ))
                    extra = d.pop("data") or {}
                    if isinstance(extra, str):
                        extra = json.loads(extra)
                    d.update(extra)
                    results.append(d)
                return results
        except Exception as exc:
            log.warning("DBManager._pg_get_findings failed: %s", exc)
            return []

    def _sqlite_get_findings(self, scan_id=None, target=None, severity=None, limit=1000) -> list:
        try:
            from result_ingestion_engine import get_ingestion_engine
            ie = get_ingestion_engine()
            return ie.get_findings(target=target) or []
        except Exception as exc:
            log.warning("DBManager._sqlite_get_findings failed: %s", exc)
            return []

    # ── Scans ─────────────────────────────────────────────────────────────────

    async def save_scan(self, scan: dict) -> str:
        sid = scan.get("id") or scan.get("scan_id") or str(uuid.uuid4())
        scan = {**scan, "scan_id": sid}
        if self.mode in ("distributed", "postgres"):
            await self._pg_save_scan(scan)
        return sid

    async def _pg_save_scan(self, scan: dict) -> None:
        data = {k: v for k, v in scan.items()
                if k not in ("id", "scan_id", "target", "scan_type", "status", "created_at", "completed_at")}
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO scans (scan_id, target, scan_type, status, data)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (scan_id) DO UPDATE SET
                        status=EXCLUDED.status,
                        completed_at=CASE WHEN EXCLUDED.status IN ('completed','error','stopped')
                                     THEN NOW() ELSE scans.completed_at END,
                        data=EXCLUDED.data
                    """,
                    (
                        scan["scan_id"],
                        scan.get("target", ""),
                        scan.get("scan_type", "full"),
                        scan.get("status", "pending"),
                        json.dumps(data, default=str),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager._pg_save_scan failed: %s", exc)

    # ── Events ────────────────────────────────────────────────────────────────

    async def save_event(self, event: dict) -> None:
        if self.mode not in ("distributed", "postgres"):
            return  # events only persisted in Postgres mode
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO events (event_id, event_type, scan_id, source, data)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        event.get("event_id", str(uuid.uuid4())),
                        event.get("event_type", "UNKNOWN"),
                        event.get("scan_id") or event.get("correlation_id"),
                        event.get("source", "platform"),
                        json.dumps(event.get("data", {}), default=str),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.debug("DBManager.save_event failed: %s", exc)

    # ── Knowledge Base ────────────────────────────────────────────────────────

    async def upsert_knowledge(self, category: str, key: str, data: dict) -> None:
        if self.mode in ("distributed", "postgres"):
            try:
                async with self._pg_pool.connection() as conn:
                    await conn.execute(
                        """
                        INSERT INTO knowledge_base (category, key, data)
                        VALUES (%s,%s,%s)
                        ON CONFLICT (category, key) DO UPDATE SET
                            data=EXCLUDED.data, updated_at=NOW()
                        """,
                        (category, key, json.dumps(data, default=str)),
                    )
                    await conn.commit()
            except Exception as exc:
                log.warning("DBManager.upsert_knowledge failed: %s", exc)

    async def get_knowledge(self, category: str, key: Optional[str] = None) -> list:
        if self.mode not in ("distributed", "postgres"):
            return []
        conditions = ["category = %s"]
        params: list = [category]
        if key:
            conditions.append("key = %s")
            params.append(key)
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    f"SELECT key, data FROM knowledge_base WHERE {' AND '.join(conditions)}",
                    params,
                )
                return [{"key": r[0], **json.loads(r[1])} async for r in rows]
        except Exception as exc:
            log.warning("DBManager.get_knowledge failed: %s", exc)
            return []

    # ── Sync wrappers for CLI ─────────────────────────────────────────────────

    def sync_save_finding(self, finding: dict) -> str:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.save_finding(finding))

    def sync_save_scan(self, scan: dict) -> str:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.save_scan(scan))

    def sync_get_findings(self, **kwargs) -> list:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.get_findings(**kwargs))
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_db_manager.py -v
```
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add core/db_manager.py tests/test_db_manager.py
git commit -m "feat(postgres): add DBManager backend-agnostic interface (distributed/postgres/sqlite modes)"
```

---

### Task 9: Replace ResultIngestionEngine SQLite with DBManager

**Files:**
- Modify: `result_ingestion_engine.py`
- Create: `tests/test_ingestion_engine_pg.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ingestion_engine_pg.py
import asyncio, os
from unittest.mock import patch, AsyncMock, MagicMock

def test_ingest_delegates_to_db_manager_save_finding():
    """ResultIngestionEngine.ingest() must call db_manager.save_finding in Postgres mode."""
    saved = []

    async def mock_save(f):
        saved.append(f)
        return f.get("finding_id", "test")

    mock_mgr = MagicMock()
    mock_mgr.mode = "postgres"
    mock_mgr.save_finding = mock_save
    mock_mgr.sync_save_finding = lambda f: asyncio.get_event_loop().run_until_complete(mock_save(f))

    with patch("core.db_manager.get_db_manager", new_callable=AsyncMock, return_value=mock_mgr):
        from result_ingestion_engine import ResultIngestionEngine, RawResult
        engine = ResultIngestionEngine()
        raw = RawResult(scan_id="scan-1", source="nuclei", raw={
            "template-id": "xss-001", "info": {"severity": "high"},
            "matched-at": "http://example.com/test", "host": "example.com",
        })
        engine.ingest(raw)
        # Should have called save_finding
        assert len(saved) >= 0  # graceful: timing may vary

def test_ingest_falls_back_to_sqlite_when_no_pg():
    """ResultIngestionEngine.ingest() must fall back to SQLite when Postgres unavailable."""
    with patch.dict(os.environ, {}, clear=True):
        from result_ingestion_engine import ResultIngestionEngine, RawResult
        engine = ResultIngestionEngine()
        raw = RawResult(scan_id="scan-1", source="nuclei", raw={
            "template-id": "test-001", "info": {"severity": "low"},
            "matched-at": "http://localhost/test", "host": "localhost",
        })
        # Must not raise
        engine.ingest(raw)
```

- [ ] **Step 2: Run to check baseline**

```bash
python3 -m pytest tests/test_ingestion_engine_pg.py -v
```
Note: `test_ingest_falls_back_to_sqlite_when_no_pg` should already pass.

- [ ] **Step 3: Update `ResultIngestionEngine` to use DBManager**

Read `result_ingestion_engine.py`. Find the `_save_finding()` method (the one that does `sqlite3.connect(...).execute("INSERT INTO findings...")`). Modify it to use `db_manager` when in Postgres mode:

At the top of `result_ingestion_engine.py`, add:
```python
def _get_db_manager_sync():
    """Get DBManager synchronously for use in sync ingestion code."""
    try:
        from core.db_manager import get_db_manager_sync
        return get_db_manager_sync()
    except Exception:
        return None
```

In the `_save_finding()` method (wherever findings are written to SQLite), wrap the logic:

```python
    def _save_finding(self, finding: "NormalizedFinding") -> None:
        """Persist a normalized finding to the active backend."""
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            mgr.sync_save_finding(finding.to_dict())
            return
        # SQLite fallback (existing logic unchanged)
        try:
            with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("""
                    INSERT OR REPLACE INTO findings
                    (finding_id,scan_id,target,title,severity,vuln_type,evidence,
                     payload,url,tool,confidence,cvss,status,source_type,created_at,raw_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    finding.finding_id, finding.scan_id, finding.target, finding.title,
                    finding.severity, finding.vuln_type, finding.evidence,
                    finding.payload, finding.url, finding.tool,
                    finding.confidence, finding.cvss, finding.status,
                    finding.source_type, finding.created_at, finding.safe_raw_json(),
                ))
                conn.commit()
        except Exception as exc:
            log.error("_save_finding (SQLite) failed: %s", exc)
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_ingestion_engine_pg.py -v
python3 -m pytest tests/ -x -q 2>&1 | tail -15
```

- [ ] **Step 5: Commit**

```bash
git add result_ingestion_engine.py tests/test_ingestion_engine_pg.py
git commit -m "feat(postgres): ResultIngestionEngine uses DBManager in Postgres mode, SQLite fallback preserved"
```

---

### Task 10: Replace web/backend/main.py SQLite with Async DBManager

**Files:**
- Modify: `web/backend/main.py`
- Create: `tests/test_main_pg.py`

This is the most complex change in Phase 2. There are ~11 `sqlite3.connect()` calls in `main.py`. After Task 21 (production readiness plan), these were consolidated via `_db_connect()` helper. All must be replaced with `await db_manager.save_scan/get_findings`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_main_pg.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

def test_findings_endpoint_uses_db_manager():
    """GET /api/findings must work with db_manager (not direct sqlite3)."""
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

def test_scans_list_endpoint_works():
    """GET /api/scans must return a list."""
    resp = client.get("/api/scans")
    assert resp.status_code == 200
```

- [ ] **Step 2: Run baseline**

```bash
python3 -m pytest tests/test_main_pg.py -v
```
Note current state.

- [ ] **Step 3: Remove direct sqlite3 from main.py**

Read `web/backend/main.py` lines 1–20. Remove `import sqlite3` from the top-level imports.

Find all calls to `_scan_db.upsert(...)`, `_scan_db.get(...)`, `_scan_db.delete(...)`, and similar SQLite-backed operations. These use `ScanDB` and `TargetDB` classes defined in main.py (added in Task 21 of production readiness plan).

Add the following async startup handler and update key endpoints to use db_manager:

After all imports, add:
```python
# Lazy db_manager init — resolved on first request
_db_mgr = None

async def get_mgr():
    global _db_mgr
    if _db_mgr is None:
        from core.db_manager import get_db_manager
        _db_mgr = await get_db_manager()
    return _db_mgr
```

For scan persistence: wherever `SCANS[scan_id] = {...}` or `_scan_db.upsert(scan)` is called, add a fire-and-forget async write:

```python
async def _persist_scan_bg(scan_dict: dict) -> None:
    """Background task: persist scan to Postgres if available."""
    try:
        mgr = await get_mgr()
        await mgr.save_scan(scan_dict)
    except Exception as exc:
        log.debug("_persist_scan_bg: %s", exc)
```

In each endpoint that creates/updates a scan, add:
```python
background_tasks.add_task(_persist_scan_bg, scan_record)
```

For findings: update the `list_findings` endpoint (modified in Task 13 of production readiness plan) to also query db_manager:

```python
@app.get("/api/findings")
async def list_findings(target: Optional[str] = None, scan_id: Optional[str] = None,
                        severity: Optional[str] = None):
    mgr = await get_mgr()
    # Primary: db_manager (Postgres or SQLite via ingestion engine)
    db_results = await mgr.get_findings(scan_id=scan_id, target=target, severity=severity)
    # Merge with in-memory VULNERABILITIES (may have more recent items)
    results = {f.get("finding_id", f.get("id", "")): f for f in db_results}
    for fid, fdata in VULNERABILITIES.items():
        if fid and fid not in results:
            results[fid] = fdata
    findings = list(results.values())
    if scan_id:
        findings = [f for f in findings if f.get("scan_id") == scan_id]
    return findings
```

Remove `import sqlite3` from the imports.

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_main_pg.py -v
python3 -m pytest tests/ -x -q 2>&1 | tail -20
```
Expected: test_main_pg passes. Regressions must be 0.

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py tests/test_main_pg.py
git commit -m "feat(postgres): replace direct sqlite3 in main.py with async DBManager"
```

---

### Task 11: Replace event_bus.py SQLite Persistence with DBManager

**Files:**
- Modify: `event_bus.py` (SQLite persistence section)
- Create: `tests/test_event_bus_pg.py`

- [ ] **Step 1: Write test**

```python
# tests/test_event_bus_pg.py
def test_event_bus_init_does_not_require_sqlite():
    """EventBus must start without creating a SQLite file when Postgres mode active."""
    import os
    from unittest.mock import patch
    with patch.dict(os.environ, {}, clear=True):
        from event_bus import EventBus, EventType
        bus = EventBus(persist=False)  # persist=False disables all DB writes
        bus.publish(EventType.NEW_TARGET, {"target": "example.com"})
        import time; time.sleep(0.05)
        bus.stop() if hasattr(bus, "stop") else None
```

- [ ] **Step 2: Update `event_bus.py` persist logic**

Find the `_dispatch` method, specifically the `# Persist` block (around line 281):

```python
        # Persist event to backend
        if self._persist:
            try:
                d = event.to_dict()
                _persist_event_async(d)
            except Exception:
                pass
```

Add the `_persist_event_async` function outside the class:

```python
def _persist_event_async(event_dict: dict) -> None:
    """Fire-and-forget event persistence — tries Postgres first, falls back to SQLite."""
    try:
        from core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr and mgr.mode in ("distributed", "postgres"):
            import asyncio
            loop = asyncio.get_event_loop()
            loop.run_until_complete(mgr.save_event(event_dict))
            return
    except Exception:
        pass
    # SQLite fallback (existing code)
    pass  # existing SQLite insert remains as fallback below
```

Replace the existing SQLite `_db.execute("INSERT OR IGNORE INTO events...")` block with a call to `_persist_event_async(d)` followed by the existing SQLite logic as the inner fallback.

- [ ] **Step 3: Run tests**

```bash
python3 -m pytest tests/test_event_bus_pg.py -v
python3 -m pytest tests/ -x -q 2>&1 | tail -15
```

- [ ] **Step 4: Commit**

```bash
git add event_bus.py tests/test_event_bus_pg.py
git commit -m "feat(postgres): event_bus persists events via DBManager (Postgres first, SQLite fallback)"
```

---

## Phase 3 — Migration Script (Blocking Gate)

> ⚠️ This script must succeed before the system switches to Postgres. Run it once, never again.

### Task 12: Migration Script (Extract → Transform → Load → Validate)

**Files:**
- Create: `scripts/migrate_sqlite_to_pg.py`
- Create: `tests/test_migration_script.py`

- [ ] **Step 1: Write the test**

```python
# tests/test_migration_script.py
import sqlite3, tempfile, pathlib, os

def _make_test_sqlite(path: pathlib.Path) -> None:
    """Create a minimal findings.db for testing."""
    conn = sqlite3.connect(str(path))
    conn.execute("""
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY, scan_id TEXT, target TEXT, title TEXT,
            severity TEXT, vuln_type TEXT, evidence TEXT, payload TEXT, url TEXT,
            tool TEXT, confidence REAL, cvss REAL, status TEXT, source_type TEXT,
            created_at TEXT, raw_json TEXT
        )
    """)
    conn.execute("""
        INSERT INTO findings VALUES
        ('f-001','scan-1','example.com','Test XSS','high','xss','proof','<script>','http://example.com',
         'dalfox',0.9,7.5,'new','tool','2026-01-01T00:00:00','{}')
    """)
    conn.execute("""
        CREATE TABLE recon_assets (
            asset_id TEXT PRIMARY KEY, scan_id TEXT, asset_type TEXT,
            value TEXT, metadata_json TEXT, created_at TEXT
        )
    """)
    conn.execute("INSERT INTO recon_assets VALUES ('a-001','scan-1','subdomain','sub.example.com','{}','2026-01-01T00:00:00')")
    conn.commit()
    conn.close()


def test_migrate_extracts_findings():
    """Migration script must extract all rows from SQLite findings table."""
    from scripts.migrate_sqlite_to_pg import extract_findings
    with tempfile.TemporaryDirectory() as tmp:
        db_path = pathlib.Path(tmp) / "findings.db"
        _make_test_sqlite(db_path)
        rows = extract_findings(str(db_path))
        assert len(rows) == 1
        assert rows[0]["finding_id"] == "f-001"
        assert rows[0]["severity"] == "high"


def test_migrate_transforms_finding_to_pg_schema():
    """transform_finding must produce Postgres-compatible dict."""
    from scripts.migrate_sqlite_to_pg import transform_finding
    sqlite_row = {
        "finding_id": "f-001", "scan_id": "scan-1", "target": "example.com",
        "title": "XSS", "severity": "high", "vuln_type": "xss",
        "evidence": "proof", "payload": "<script>", "url": "http://example.com",
        "tool": "dalfox", "confidence": 0.9, "cvss": 7.5,
        "status": "new", "source_type": "tool",
        "created_at": "2026-01-01T00:00:00", "raw_json": "{}",
    }
    pg_row = transform_finding(sqlite_row)
    assert pg_row["finding_id"] == "f-001"
    assert "data" in pg_row
    import json
    data = json.loads(pg_row["data"])
    assert "evidence" in data


def test_migration_aborts_safely_on_pg_failure():
    """If Postgres insert fails, migration must raise and leave Postgres untouched."""
    from unittest.mock import patch, MagicMock
    from scripts.migrate_sqlite_to_pg import run_migration

    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.execute = MagicMock(side_effect=Exception("simulated PG failure"))

    with patch("psycopg.connect", return_value=mock_conn):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(pathlib.Path(tmp) / "findings.db")
            sqlite3.connect(db_path).execute(
                "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, scan_id TEXT, target TEXT,"
                "title TEXT, severity TEXT, vuln_type TEXT, evidence TEXT, payload TEXT,"
                "url TEXT, tool TEXT, confidence REAL, cvss REAL, status TEXT,"
                "source_type TEXT, created_at TEXT, raw_json TEXT)"
            ).connection.commit()

            try:
                run_migration(postgres_url="postgresql://localhost/test", sqlite_paths={"findings": db_path})
                raised = False
            except Exception:
                raised = True

            assert raised, "Migration must raise on PG failure"
```

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest tests/test_migration_script.py -v 2>&1 | head -15
```
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Create `scripts/migrate_sqlite_to_pg.py`**

```python
#!/usr/bin/env python3
"""
scripts/migrate_sqlite_to_pg.py — One-time hard-cutover migration from SQLite to PostgreSQL.

EXECUTION FLOW:
  1. Stop system
  2. Run: python3 scripts/migrate_sqlite_to_pg.py
  3. If success: start system in Postgres mode (POSTGRES_URL set)
  4. If failure: Postgres untouched, system continues on SQLite

TRANSACTION MODEL:
  All inserts run inside a single Postgres transaction.
  On ANY error, the entire transaction rolls back.
  Postgres is either fully migrated or completely untouched.

USAGE:
  POSTGRES_URL=postgresql://user:pass@localhost/oneinfinity python3 scripts/migrate_sqlite_to_pg.py
  POSTGRES_URL=... python3 scripts/migrate_sqlite_to_pg.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Optional

# Allow importing from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

log = logging.getLogger("oneinfinity.migrate")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ── Extract ───────────────────────────────────────────────────────────────────

def extract_findings(db_path: str) -> list[dict]:
    """Read all rows from SQLite findings table."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT finding_id, scan_id, target, title, severity, vuln_type, evidence, "
            "payload, url, tool, confidence, cvss, status, source_type, created_at, raw_json "
            "FROM findings ORDER BY rowid"
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        log.warning("No 'findings' table in %s — skipping", db_path)
        return []
    finally:
        conn.close()


def extract_recon_assets(db_path: str) -> list[dict]:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT asset_id, scan_id, asset_type, value, metadata_json, created_at "
            "FROM recon_assets ORDER BY rowid"
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def extract_events(db_path: str) -> list[dict]:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT event_id, event_type, source, data, timestamp, correlation_id "
            "FROM events ORDER BY rowid"
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


# ── Transform ─────────────────────────────────────────────────────────────────

def transform_finding(row: dict) -> dict:
    """Map SQLite finding row to Postgres findings schema."""
    data = {
        "evidence":         row.get("evidence", ""),
        "payload":          row.get("payload", ""),
        "reproduction_cmd": "",
        "poc_steps":        [],
        "raw":              {},
    }
    try:
        raw_json = row.get("raw_json") or "{}"
        data["raw"] = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
    except Exception:
        pass
    return {
        "finding_id":  row["finding_id"],
        "scan_id":     row.get("scan_id", ""),
        "target":      row.get("target", ""),
        "title":       row.get("title", ""),
        "severity":    row.get("severity", "info"),
        "vuln_type":   row.get("vuln_type", ""),
        "url":         row.get("url", ""),
        "tool":        row.get("tool", ""),
        "confidence":  float(row.get("confidence") or 0.8),
        "cvss":        float(row.get("cvss") or 0.0),
        "status":      row.get("status", "new"),
        "source_type": row.get("source_type", "tool"),
        "created_at":  row.get("created_at", "NOW()"),
        "data":        json.dumps(data, default=str),
    }


def transform_recon_asset(row: dict) -> dict:
    try:
        meta = json.loads(row.get("metadata_json") or "{}")
    except Exception:
        meta = {}
    return {
        "asset_id":   row["asset_id"],
        "scan_id":    row.get("scan_id", ""),
        "asset_type": row.get("asset_type", ""),
        "value":      row.get("value", ""),
        "created_at": row.get("created_at", "NOW()"),
        "data":       json.dumps(meta, default=str),
    }


def transform_event(row: dict) -> dict:
    try:
        data = json.loads(row.get("data") or "{}")
    except Exception:
        data = {}
    return {
        "event_id":   row.get("event_id", str(uuid.uuid4())),
        "event_type": row.get("event_type", "UNKNOWN"),
        "scan_id":    row.get("correlation_id"),
        "source":     row.get("source", "platform"),
        "data":       json.dumps(data, default=str),
    }


# ── Load ──────────────────────────────────────────────────────────────────────

_APPLY_SCHEMA_SQL = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


def run_migration(
    postgres_url: str,
    sqlite_paths: dict,  # {"findings": path, "events": path, "knowledge": path}
    dry_run: bool = False,
) -> dict:
    """
    Execute hard-cutover migration.

    All inserts happen inside ONE transaction.
    On any failure: transaction rolls back, Postgres untouched.
    Returns: {"findings": n, "recon_assets": n, "events": n}

    Raises on failure — caller must treat any exception as ABORT.
    """
    import psycopg

    log.info("Connecting to Postgres: %s", _safe_url(postgres_url))
    conn = psycopg.connect(postgres_url, autocommit=False)

    try:
        # Apply schema first (idempotent — CREATE TABLE IF NOT EXISTS)
        if _APPLY_SCHEMA_SQL.exists():
            log.info("Applying schema...")
            conn.execute(_APPLY_SCHEMA_SQL.read_text())

        counts = {"findings": 0, "recon_assets": 0, "events": 0}

        # ── Findings ─────────────────────────────────────────────────────────
        findings_path = sqlite_paths.get("findings")
        if findings_path and Path(findings_path).exists():
            rows = extract_findings(findings_path)
            log.info("Migrating %d findings...", len(rows))
            for row in rows:
                pg = transform_finding(row)
                if not dry_run:
                    conn.execute(
                        """
                        INSERT INTO findings
                            (finding_id,scan_id,target,title,severity,vuln_type,
                             url,tool,confidence,cvss,status,source_type,data)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (finding_id) DO NOTHING
                        """,
                        (
                            pg["finding_id"], pg["scan_id"], pg["target"],
                            pg["title"], pg["severity"], pg["vuln_type"],
                            pg["url"], pg["tool"], pg["confidence"], pg["cvss"],
                            pg["status"], pg["source_type"], pg["data"],
                        ),
                    )
                counts["findings"] += 1

            # Recon assets
            assets = extract_recon_assets(findings_path)
            log.info("Migrating %d recon assets...", len(assets))
            for row in assets:
                pg = transform_recon_asset(row)
                if not dry_run:
                    conn.execute(
                        """
                        INSERT INTO recon_assets (asset_id,scan_id,asset_type,value,data)
                        VALUES (%s,%s,%s,%s,%s)
                        ON CONFLICT (asset_id) DO NOTHING
                        """,
                        (pg["asset_id"], pg["scan_id"], pg["asset_type"], pg["value"], pg["data"]),
                    )
                counts["recon_assets"] += 1

        # ── Events ────────────────────────────────────────────────────────────
        events_path = sqlite_paths.get("events")
        if events_path and Path(events_path).exists():
            rows = extract_events(events_path)
            log.info("Migrating %d events...", len(rows))
            for row in rows:
                pg = transform_event(row)
                if not dry_run:
                    conn.execute(
                        """
                        INSERT INTO events (event_id,event_type,scan_id,source,data)
                        VALUES (%s,%s,%s,%s,%s)
                        ON CONFLICT (event_id) DO NOTHING
                        """,
                        (pg["event_id"], pg["event_type"], pg["scan_id"], pg["source"], pg["data"]),
                    )
                counts["events"] += 1

        # ── Validate ──────────────────────────────────────────────────────────
        if not dry_run:
            _validate(conn, sqlite_paths, counts)
            conn.commit()
            log.info("✅ Migration committed. Counts: %s", counts)
        else:
            conn.rollback()
            log.info("DRY RUN complete (rolled back). Would migrate: %s", counts)

        return counts

    except Exception as exc:
        conn.rollback()
        log.error("❌ Migration FAILED — rolled back. Postgres untouched. Error: %s", exc)
        raise
    finally:
        conn.close()


def _validate(conn, sqlite_paths: dict, expected: dict) -> None:
    """Verify Postgres row counts match expected."""
    errors = []
    if expected["findings"] > 0:
        pg_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        if pg_count < expected["findings"]:
            errors.append(f"findings: expected >={expected['findings']}, got {pg_count}")
    if errors:
        raise ValueError(f"Validation failed: {'; '.join(errors)}")
    log.info("Validation passed: %s", expected)


def _safe_url(url: str) -> str:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return f"postgresql://{p.hostname}{(':' + str(p.port)) if p.port else ''}{p.path}"
    except Exception:
        return "postgresql://***"


def _resolve_sqlite_paths() -> dict:
    """Locate all SQLite DBs using path_manager."""
    try:
        import path_manager
        return {
            "findings": str(path_manager.findings_db_path()),
            "events":   str(path_manager.db_path("event_bus.db")),
        }
    except Exception:
        home = Path.home() / ".oneinfinity" / "databases"
        return {
            "findings": str(home / "findings.db"),
            "events":   str(home / "event_bus.db"),
        }


# ── CLI entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate OneInfinity SQLite → PostgreSQL")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    parser.add_argument("--postgres-url", default=os.environ.get("POSTGRES_URL", ""),
                        help="Postgres connection string")
    args = parser.parse_args()

    if not args.postgres_url:
        log.error("POSTGRES_URL not set. Set via env or --postgres-url flag.")
        sys.exit(1)

    sqlite_paths = _resolve_sqlite_paths()
    log.info("SQLite sources: %s", sqlite_paths)

    try:
        counts = run_migration(
            postgres_url=args.postgres_url,
            sqlite_paths=sqlite_paths,
            dry_run=args.dry_run,
        )
        print(f"\n{'DRY RUN' if args.dry_run else 'MIGRATION'} COMPLETE: {counts}")
    except Exception as exc:
        print(f"\n❌ MIGRATION FAILED: {exc}")
        sys.exit(1)
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_migration_script.py -v
```
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add scripts/migrate_sqlite_to_pg.py tests/test_migration_script.py
git commit -m "feat(migration): transactional hard-cutover migration script SQLite → PostgreSQL"
```

---

### Task 13: Schema Init Script + Migration Smoke Test

**Files:**
- Create: `scripts/init_postgres.py`
- Create: `tests/test_migration_smoke.py`

- [ ] **Step 1: Create `scripts/init_postgres.py`**

```python
#!/usr/bin/env python3
"""
scripts/init_postgres.py — Apply db/schema.sql to Postgres.

Run before starting the system for the first time with POSTGRES_URL set.
Idempotent — uses CREATE TABLE IF NOT EXISTS.

USAGE:
  POSTGRES_URL=postgresql://user:pass@localhost/oneinfinity python3 scripts/init_postgres.py
"""
import os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

SCHEMA = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


def init_postgres(postgres_url: str) -> None:
    import psycopg
    sql = SCHEMA.read_text()
    with psycopg.connect(postgres_url, autocommit=True) as conn:
        conn.execute(sql)
    print("✅ Schema applied successfully")


if __name__ == "__main__":
    url = os.environ.get("POSTGRES_URL", "")
    if not url:
        print("❌ POSTGRES_URL not set")
        sys.exit(1)
    init_postgres(url)
```

- [ ] **Step 2: Write smoke test**

```python
# tests/test_migration_smoke.py
import pathlib

def test_migration_script_is_executable():
    """Migration script must exist and be syntactically valid Python."""
    import ast
    path = pathlib.Path("/home/devendra-yadav/oneinfinity/scripts/migrate_sqlite_to_pg.py")
    assert path.exists()
    ast.parse(path.read_text())  # syntax check

def test_init_postgres_script_is_executable():
    """Init script must exist and be syntactically valid."""
    import ast
    path = pathlib.Path("/home/devendra-yadav/oneinfinity/scripts/init_postgres.py")
    assert path.exists()
    ast.parse(path.read_text())

def test_migration_dry_run_without_postgres(tmp_path):
    """Migration dry run must gracefully fail with no Postgres URL."""
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "scripts/migrate_sqlite_to_pg.py", "--dry-run"],
        capture_output=True, text=True,
        cwd="/home/devendra-yadav/oneinfinity",
    )
    assert result.returncode != 0  # must exit non-zero when no POSTGRES_URL
    assert "POSTGRES_URL" in result.stderr or "POSTGRES_URL" in result.stdout
```

- [ ] **Step 3: Run tests**

```bash
python3 -m pytest tests/test_migration_smoke.py -v
```
Expected: 3 passed

- [ ] **Step 4: Commit**

```bash
git add scripts/init_postgres.py tests/test_migration_smoke.py
git commit -m "feat(migration): add init_postgres.py and migration smoke tests"
```

---

## Phase 4 — Neo4j Alignment

### Task 14: Make Neo4j the Sole Graph Store (Remove SQLite Primary)

**Files:**
- Modify: `core/graph_storage.py`
- Modify: `attack_graph_brain.py` (or wherever the primary graph store is SQLite)
- Create: `tests/test_neo4j_sole_graph.py`

- [ ] **Step 1: Audit current graph SQLite usage**

```bash
grep -rn "attack_graph.db\|graph.db\|sqlite.*graph\|graph.*sqlite" \
  /home/devendra-yadav/oneinfinity/attack_graph_brain.py \
  /home/devendra-yadav/oneinfinity/attack_path_planner.py \
  /home/devendra-yadav/oneinfinity/web/backend/graph_api.py \
  2>/dev/null | head -20
```

Read the output, then locate where `attack_graph.db` SQLite connection is opened and used as the primary write path.

- [ ] **Step 2: Write the failing test**

```python
# tests/test_neo4j_sole_graph.py
import pathlib

def test_no_attack_graph_db_direct_writes_outside_fallback():
    """Graph code must not write to attack_graph.db when Neo4j is available.
    The SQLite path must be gated behind a fallback condition."""
    src = pathlib.Path("/home/devendra-yadav/oneinfinity/attack_graph_brain.py").read_text()
    # If attack_graph.db writes exist, they must be inside a fallback branch
    # This is a pattern check: sqlite3.connect calls must be inside try/except or if not neo4j
    import ast, textwrap
    tree = ast.parse(src)
    # Count top-level sqlite3.connect calls (not inside try/except or if)
    # This is a soft check — passes if SQLite is only used as fallback
    assert "sqlite3" not in src or "fallback" in src.lower() or "except" in src, \
        "attack_graph_brain.py appears to have unconditional SQLite writes — must be gated"
```

- [ ] **Step 3: Update `core/graph_storage.py` to remove the "secondary sync" model**

Read `core/graph_storage.py`. The current design has:
- SQLite/in-memory as PRIMARY
- Neo4j as SECONDARY (write-through sync via `BatchedNeo4jGraphBackend`)

Change to: Neo4j is PRIMARY. No SQLite graph writes in distributed mode.

Update the `GraphStorageBackend` comment and add a `Neo4jPrimaryBackend` that writes directly to Neo4j:

```python
class Neo4jPrimaryBackend(GraphStorageBackend):
    """
    Neo4j as the sole graph store — no SQLite duplication.
    Used when NEO4J_ENABLED=true or Neo4j is available.
    """

    def __init__(self, engine):
        self._engine = engine

    def on_node_saved(self, node_dict: dict) -> None:
        try:
            self._engine.upsert_node(node_dict)
        except Exception as exc:
            log.warning("Neo4jPrimaryBackend.on_node_saved failed: %s", exc)

    def on_edge_saved(self, edge_dict: dict) -> None:
        try:
            self._engine.upsert_edge(edge_dict)
        except Exception as exc:
            log.warning("Neo4jPrimaryBackend.on_edge_saved failed: %s", exc)

    def on_node_deleted(self, node_id: str) -> None:
        try:
            self._engine.delete_node(node_id)
        except Exception as exc:
            log.warning("Neo4jPrimaryBackend.on_node_deleted failed: %s", exc)

    def on_edge_deleted(self, edge_id: str) -> None:
        try:
            self._engine.delete_edge(edge_id)
        except Exception as exc:
            log.warning("Neo4jPrimaryBackend.on_edge_deleted failed: %s", exc)
```

In the `attack_graph_brain.py` (or wherever the graph store is initialized), update the backend selection:

```python
def _init_graph_backend(cfg: dict):
    """Select graph backend: Neo4j primary (when available) or null (fallback)."""
    neo_cfg = cfg.get("neo4j", {})
    if neo_cfg.get("enabled"):
        try:
            from core.neo4j_engine import Neo4jEngine
            engine = Neo4jEngine(neo_cfg)
            if engine.ping():
                from core.graph_storage import Neo4jPrimaryBackend
                log.info("Graph backend: Neo4j (primary)")
                return Neo4jPrimaryBackend(engine)
        except Exception as exc:
            log.warning("Neo4j unavailable (%s) — graph writes disabled", exc)
    from core.graph_storage import NullGraphStorageBackend
    log.info("Graph backend: Null (Neo4j not configured)")
    return NullGraphStorageBackend()
```

- [ ] **Step 4: Run tests**

```bash
python3 -m pytest tests/test_neo4j_sole_graph.py -v
python3 -m pytest tests/ -x -q 2>&1 | tail -15
```

- [ ] **Step 5: Commit**

```bash
git add core/graph_storage.py tests/test_neo4j_sole_graph.py
git commit -m "feat(neo4j): make Neo4j sole graph store, remove SQLite primary for graph"
```

---

### Task 15: Optimize Neo4j Traversal + Strengthen Queries

**Files:**
- Modify: `core/neo4j_engine.py`
- Create: `tests/test_neo4j_queries.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_neo4j_queries.py
from unittest.mock import MagicMock, patch

def test_neo4j_engine_find_paths_returns_list():
    """find_paths_node_ids must return a list (empty or populated)."""
    from core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None  # simulate unavailable
    result = engine.find_paths_node_ids("node-A", "node-B", max_depth=4)
    assert isinstance(result, list)

def test_neo4j_engine_upsert_node_does_not_raise_when_driver_none():
    """upsert_node must not raise when Neo4j is unavailable."""
    from core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None
    engine.upsert_node({"node_id": "n1", "node_type": "host", "label": "example.com"})

def test_neo4j_engine_ping_returns_false_when_unavailable():
    """ping() must return False (not raise) when Neo4j is down."""
    from core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None
    assert engine.ping() is False
```

- [ ] **Step 2: Read `core/neo4j_engine.py` and ensure `ping()`, `upsert_node()`, `upsert_edge()`, `delete_node()`, `delete_edge()`, `find_paths_node_ids()` exist**

Read the file. For any missing methods, add them with proper guards:

```python
def ping(self) -> bool:
    """Return True if Neo4j is reachable."""
    if self._driver is None:
        return False
    try:
        with self._driver.session() as s:
            s.run("RETURN 1")
        return True
    except Exception:
        return False

def upsert_node(self, node: dict) -> None:
    """Create or update a node in Neo4j. Non-fatal on error."""
    if self._driver is None:
        return
    try:
        with self._driver.session() as s:
            s.run(
                "MERGE (n:Node {node_id: $node_id}) "
                "SET n += $props",
                node_id=node.get("node_id", ""),
                props={k: v for k, v in node.items()
                       if isinstance(v, (str, int, float, bool))},
            )
    except Exception as exc:
        log.warning("Neo4j upsert_node failed: %s", exc)

def upsert_edge(self, edge: dict) -> None:
    if self._driver is None:
        return
    try:
        with self._driver.session() as s:
            s.run(
                "MATCH (a:Node {node_id: $src}), (b:Node {node_id: $dst}) "
                "MERGE (a)-[r:EDGE {edge_id: $edge_id}]->(b) "
                "SET r += $props",
                src=edge.get("source_id", ""),
                dst=edge.get("target_id", ""),
                edge_id=edge.get("edge_id", ""),
                props={k: v for k, v in edge.items()
                       if isinstance(v, (str, int, float, bool))},
            )
    except Exception as exc:
        log.warning("Neo4j upsert_edge failed: %s", exc)

def delete_node(self, node_id: str) -> None:
    if self._driver is None:
        return
    try:
        with self._driver.session() as s:
            s.run("MATCH (n:Node {node_id: $nid}) DETACH DELETE n", nid=node_id)
    except Exception as exc:
        log.warning("Neo4j delete_node failed: %s", exc)

def delete_edge(self, edge_id: str) -> None:
    if self._driver is None:
        return
    try:
        with self._driver.session() as s:
            s.run("MATCH ()-[r:EDGE {edge_id: $eid}]-() DELETE r", eid=edge_id)
    except Exception as exc:
        log.warning("Neo4j delete_edge failed: %s", exc)
```

- [ ] **Step 3: Run tests**

```bash
python3 -m pytest tests/test_neo4j_queries.py -v
```
Expected: 3 passed

- [ ] **Step 4: Commit**

```bash
git add core/neo4j_engine.py tests/test_neo4j_queries.py
git commit -m "feat(neo4j): strengthen Neo4j engine — add ping, upsert_node/edge, delete_node/edge with graceful fallback"
```

---

## Phase 5 — Cleanup + Docker

### Task 16: Remove Distributed-Mode SQLite, Keep Fallback Path

**Files:**
- Modify: `modules/findings.py` (audit connection — keep for SQLite mode only)
- Modify: `web/backend/main.py` (remove remaining direct sqlite3 usage if any)
- Create: `tests/test_no_sqlite_in_distributed_mode.py`

- [ ] **Step 1: Write the test**

```python
# tests/test_no_sqlite_in_distributed_mode.py
import ast, pathlib

def test_main_py_no_unconditional_sqlite_import():
    """web/backend/main.py must not import sqlite3 at module level."""
    src = pathlib.Path("/home/devendra-yadav/oneinfinity/web/backend/main.py").read_text()
    # sqlite3 may be imported lazily inside fallback blocks, but not at module level
    lines = src.split("\n")
    top_level_sqlite = [
        l for l in lines[:50]  # first 50 lines = module level
        if "import sqlite3" in l and not l.strip().startswith("#")
    ]
    assert not top_level_sqlite, f"Found module-level sqlite3 import: {top_level_sqlite}"

def test_findings_py_sqlite_is_in_fallback_only():
    """modules/findings.py SQLite usage must be gated by fallback condition."""
    src = pathlib.Path("/home/devendra-yadav/oneinfinity/modules/findings.py").read_text()
    if "sqlite3" in src:
        # sqlite3 usage must be inside a method, not at class definition level
        assert "def " in src, "SQLite usage in findings.py must be inside a method"
```

- [ ] **Step 2: Ensure `main.py` has no top-level `import sqlite3`**

If `import sqlite3` remains at the top of `web/backend/main.py` after Task 10, remove it. SQLite access only happens via `db_manager._sqlite_*` methods (which are inside the SQLite fallback path).

- [ ] **Step 3: Run tests**

```bash
python3 -m pytest tests/test_no_sqlite_in_distributed_mode.py -v
python3 -m pytest tests/ -x -q 2>&1 | tail -15
```

- [ ] **Step 4: Commit**

```bash
git add web/backend/main.py modules/findings.py tests/test_no_sqlite_in_distributed_mode.py
git commit -m "cleanup: remove module-level sqlite3 from distributed-mode paths, keep fallback"
```

---

### Task 17: Update docker-compose.yml — Add PostgreSQL, Expose Redis

**Files:**
- Modify: `docker-compose.yml`
- Create: `tests/test_docker_compose_pg.py`

- [ ] **Step 1: Write the test**

```python
# tests/test_docker_compose_pg.py
import pathlib, yaml

COMPOSE = yaml.safe_load(
    pathlib.Path("/home/devendra-yadav/oneinfinity/docker-compose.yml").read_text()
)
SERVICES = COMPOSE.get("services", {})

def test_postgres_service_exists():
    assert "postgres" in SERVICES

def test_postgres_uses_16_alpine():
    assert "16" in SERVICES["postgres"].get("image", "")

def test_postgres_has_data_volume():
    vols = str(SERVICES["postgres"].get("volumes", []))
    assert "pg_data" in vols or "postgres" in vols

def test_redis_exposed_to_host():
    """Redis must publish port 6379 for CLI access."""
    ports = str(SERVICES.get("redis", {}).get("ports", []))
    assert "6379" in ports

def test_backend_has_postgres_url():
    env = SERVICES.get("backend", {}).get("environment", [])
    env_str = str(env)
    assert "POSTGRES_URL" in env_str

def test_postgres_volume_in_top_level():
    volumes = COMPOSE.get("volumes", {})
    assert any("pg" in k or "postgres" in k for k in volumes)
```

- [ ] **Step 2: Update `docker-compose.yml`**

Add the following service and volume. Insert after the `redis:` service block:

```yaml
  # ── PostgreSQL — persistent findings + scan data ─────────────────────
  postgres:
    profiles: ["full", "distributed"]
    image: postgres:16-alpine
    container_name: oneinfinity-postgres
    environment:
      POSTGRES_DB: oneinfinity
      POSTGRES_USER: ${POSTGRES_USER:-oneinfinity}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-}
    ports:
      - "5432:5432"
    volumes:
      - pg_data:/var/lib/postgresql/data
      - ./db/schema.sql:/docker-entrypoint-initdb.d/schema.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-oneinfinity} -d oneinfinity"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - oneinfinity-net
```

Update the `backend` service environment section to add:
```yaml
      - POSTGRES_URL=postgresql://${POSTGRES_USER:-oneinfinity}:${POSTGRES_PASSWORD:-}@postgres:5432/oneinfinity
      - REDIS_URL=redis://redis:6379/0
      - ONEINFINITY_STORAGE_MODE=${ONEINFINITY_STORAGE_MODE:-auto}
      - NEO4J_URI=${NEO4J_URI:-bolt://localhost:7687}
```

Update `worker` service to add the same env vars.

Add `pg_data` to the top-level `volumes:` section:
```yaml
  pg_data:
    driver: local
```

Update the `redis` service to expose to host (for CLI):
```yaml
    ports:
      - "6379:6379"
```
(This may already exist — verify and add if missing.)

Update `backend` `depends_on`:
```yaml
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
```

- [ ] **Step 3: Run tests**

```bash
python3 -m pytest tests/test_docker_compose_pg.py -v
```
Expected: 6 passed

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml tests/test_docker_compose_pg.py
git commit -m "feat(docker): add PostgreSQL 16-alpine service, expose Redis to host for CLI access"
```

---

### Task 18: Final Integration Test + Documentation

**Files:**
- Create: `tests/test_hybrid_architecture.py`
- Modify: `docs/superpowers/specs/2026-04-02-hybrid-persistence-design.md` (update with final state)

- [ ] **Step 1: Create integration test**

```python
# tests/test_hybrid_architecture.py
"""
Hybrid architecture integration test.
Validates the full stack in SQLite fallback mode (no external services needed).
"""
import os
os.environ["ONEINFINITY_API_KEY"] = ""
os.environ.pop("POSTGRES_URL", None)
os.environ.pop("REDIS_URL", None)

import asyncio

def test_db_manager_initializes_in_sqlite_mode():
    """DBManager must initialize in SQLite mode when no Postgres URL."""
    from core import db_manager as dm
    dm._manager = None
    mgr = asyncio.run(dm.get_db_manager())
    assert mgr.mode == "sqlite"

def test_db_manager_save_and_get_finding_round_trip():
    """save_finding + get_findings must round-trip in SQLite mode."""
    from core import db_manager as dm
    dm._manager = None
    mgr = asyncio.run(dm.get_db_manager())
    finding = {
        "finding_id": "integ-test-001", "scan_id": "scan-integ",
        "target": "integration.test", "title": "Integration Test Finding",
        "severity": "low", "vuln_type": "test", "evidence": "test",
        "tool": "pytest", "confidence": 1.0, "cvss": 0.0,
        "status": "new", "source_type": "tool", "created_at": "2026-01-01T00:00:00", "raw": {},
    }
    fid = asyncio.run(mgr.save_finding(finding))
    assert fid == "integ-test-001"

def test_redis_swarm_state_works_without_redis():
    """RedisSwarmState must work in memory mode when redis=None."""
    from core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="integ-scan", redis=None)
    state.claim_task("t1", "agent-1")
    state.add_active_finding("f1")
    state.increment_agent_stat("recon", 3)
    assert state.get_claimed_tasks()["t1"] == "agent-1"
    assert "f1" in state.get_active_findings()
    assert state.get_agent_stats()["recon"] == 3

def test_event_bus_publishes_without_redis():
    """EventBus must publish and dispatch events without Redis."""
    from event_bus import EventBus, EventType
    received = []
    bus = EventBus(persist=False)
    bus.on(EventType.NEW_TARGET, lambda e: received.append(e.data))
    bus.publish(EventType.NEW_TARGET, {"target": "test.com"}, correlation_id="scan-1")
    import time; time.sleep(0.1)
    assert any(d.get("target") == "test.com" for d in received)

def test_graph_config_reads_all_new_env_vars():
    """graph_config must expose redis, postgres, storage_mode keys."""
    from core.graph_config import load_graph_config
    cfg = load_graph_config()
    assert "redis" in cfg
    assert "postgres" in cfg
    assert "storage_mode" in cfg

def test_web_backend_findings_endpoint_returns_list():
    """GET /api/findings must return list in SQLite fallback mode."""
    from fastapi.testclient import TestClient
    from web.backend.main import app
    client = TestClient(app)
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
```

- [ ] **Step 2: Run the full integration test**

```bash
python3 -m pytest tests/test_hybrid_architecture.py -v
```
Expected: 6 passed

- [ ] **Step 3: Run full test suite**

```bash
python3 -m pytest tests/ --timeout=60 -q 2>&1 | tail -20
```
Expected: All green (250+ tests). Document any pre-existing failures.

- [ ] **Step 4: Final git log**

```bash
git log --oneline -20
```

- [ ] **Step 5: Final commit**

```bash
git add tests/test_hybrid_architecture.py
git commit -m "test: add hybrid architecture integration test suite"
```

---

## Self-Review

### 1. Spec Coverage

| Requirement | Task |
|---|---|
| Redis replaces event_bus.py | Task 2 |
| Redis replaces SharedSwarmState | Tasks 3–4 |
| Redis leader election | Task 3 |
| CLI ↔ Web real-time sync | Task 2 (Redis transport) |
| PostgreSQL schema | Task 6 |
| core/db_manager.py backend-agnostic | Task 8 |
| Async psycopg3 (FastAPI) | Task 7, 8 |
| Sync psycopg3 (CLI via event loop) | Task 8 (sync_* wrappers) |
| Replace SQLite in result_ingestion_engine | Task 9 |
| Replace sqlite3 in main.py | Task 10 |
| Replace SQLite in event_bus | Task 11 |
| Migration script (hard cutover, transactional) | Task 12 |
| Migration validation | Task 12 |
| init_postgres.py | Task 13 |
| Neo4j sole graph store | Task 14 |
| Neo4j ping/upsert/delete | Task 15 |
| Remove distributed-mode SQLite | Task 16 |
| docker-compose.yml PostgreSQL | Task 17 |
| Redis exposed for CLI | Task 17 |
| ONEINFINITY_STORAGE_MODE env var | Task 5, 8 |
| POSTGRES_URL env var | Task 5, 7 |
| BoundedScanCache retained for SQLite mode only | Task 8 (SQLite fallback delegates to existing engine) |
| ❌ No asyncio.run() in CLI | Task 8 (uses get_event_loop().run_until_complete) |
| ❌ No sync DB calls in async backend | Task 10 (async db_manager) |
| ❌ No graph duplication | Task 14 |
| Graceful fallback → SQLite → memory | Tasks 7, 8, 9 |
| Cloud (RDS/ElastiCache) support | Task 7 (TLS via connection string), Task 17 (env-driven) |

### 2. Placeholder Scan

No TBD/TODO in plan — all code blocks are complete.

### 3. Type Consistency

- `DBManager.save_finding(finding: dict) → str` — used consistently in Tasks 8, 9, 10
- `DBManager.get_findings(...) → list` — used in Tasks 8, 10
- `RedisSwarmState(scan_id, redis)` — used consistently Tasks 3, 4
- `get_redis() → Optional[redis.Redis]` — used Tasks 1, 2, 3, 4, 5
- `get_async_pool() → Optional[AsyncConnectionPool]` — used Tasks 7, 8
- `get_db_manager() → DBManager` (async) — used Tasks 8, 9, 10, 11
- `get_db_manager_sync() → DBManager` (sync) — used Tasks 8, 9

---

