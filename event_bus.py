"""
event_bus.py — Platform-wide Async Event Bus

High-performance, thread-safe publish/subscribe event bus for One&Infinity.
Supports both async coroutine subscribers and sync callable subscribers.

Architecture
------------
- Single asyncio event loop running in a dedicated daemon thread
- Per-topic subscriber registries (coroutines + sync callables)
- Ring-buffer event log (configurable, default 2000 events)
- SQLite persistence for events (optional, enabled by default)
- WebSocket broadcast interface: register_ws_client() / unregister_ws_client()
- Priority queuing: HIGH / NORMAL / LOW
- Dead-letter queue for failed handlers
- Backpressure: max 10 000 events in-flight before publish() blocks

Event Types
-----------
NEW_TARGET          — a new scan target was added (data: {target, source})
NEW_ENDPOINT        — a URL/endpoint was discovered (data: {url, target, method, params})
NEW_PARAMETER       — a new injectable parameter (data: {url, param, context})
NEW_VULNERABILITY   — a confirmed vulnerability (data: {vuln_type, severity, ...})
NEW_GRAPH_NODE      — a new attack graph node (data: {node_id, node_type, label, ...})
NEW_API             — an API endpoint was found (data: {url, method, schema})
SCAN_PROGRESS_UPDATE— phase/progress tick    (data: {phase, progress, target, ...})
EXPLOIT_ATTEMPTED   — an exploit was tried    (data: {vuln_type, payload, success, ...})
CHAIN_DETECTED      — an exploit chain found  (data: {chain_name, steps, cvss, ...})
OSINT_RESULT        — OSINT data collected    (data: {subdomains, ips, urls, ...})
HYPOTHESIS_CREATED  — a vuln theory created  (data: {theory_id, vuln_type, endpoint, ...})
PAYLOAD_MUTATED     — a payload was mutated   (data: {original, mutant, strategy, ...})
AGENT_STATUS        — swarm agent status tick  (data: {agent_type, phase, findings, ...})
WORKFLOW_DETECTED   — a workflow found        (data: {workflow_id, steps, target, ...})
LEARNING_UPDATE     — KB updated             (data: {category, delta, pattern_count, ...})
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Optional, Union

log = logging.getLogger("oneinfinity.event_bus")

from path_manager import db_path as db_path_fn

# ── Event types ───────────────────────────────────────────────────────────────

class EventType(str, Enum):
    NEW_TARGET           = "NEW_TARGET"
    NEW_ENDPOINT         = "NEW_ENDPOINT"
    NEW_PARAMETER        = "NEW_PARAMETER"
    NEW_VULNERABILITY    = "NEW_VULNERABILITY"
    NEW_GRAPH_NODE       = "NEW_GRAPH_NODE"
    NEW_API              = "NEW_API"
    SCAN_PROGRESS_UPDATE = "SCAN_PROGRESS_UPDATE"
    EXPLOIT_ATTEMPTED    = "EXPLOIT_ATTEMPTED"
    CHAIN_DETECTED       = "CHAIN_DETECTED"
    OSINT_RESULT         = "OSINT_RESULT"
    HYPOTHESIS_CREATED   = "HYPOTHESIS_CREATED"
    PAYLOAD_MUTATED      = "PAYLOAD_MUTATED"
    AGENT_STATUS         = "AGENT_STATUS"
    WORKFLOW_DETECTED    = "WORKFLOW_DETECTED"
    LEARNING_UPDATE      = "LEARNING_UPDATE"


class Priority(int, Enum):
    HIGH   = 0
    NORMAL = 1
    LOW    = 2


# ── Event model ───────────────────────────────────────────────────────────────

@dataclass
class BusEvent:
    event_type: EventType
    data: dict
    source: str = "platform"
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    priority: Priority = Priority.NORMAL
    correlation_id: str = ""      # link related events (e.g. a scan session)
    ttl: float = 0.0              # 0 = no expiry

    def to_dict(self) -> dict:
        return {
            "event_id":      self.event_id,
            "event_type":    self.event_type.value,
            "data":          self.data,
            "source":        self.source,
            "timestamp":     self.timestamp,
            "priority":      self.priority.value,
            "correlation_id":self.correlation_id,
        }

    def is_expired(self) -> bool:
        return self.ttl > 0 and (time.time() - self.timestamp) > self.ttl


# Subscriber types
SyncHandler  = Callable[[BusEvent], None]
AsyncHandler = Callable[[BusEvent], Coroutine]
AnyHandler   = Union[SyncHandler, AsyncHandler]


@dataclass
class _Subscription:
    handler: AnyHandler
    is_async: bool
    source_filter: str = ""   # if set, only fire when event.source matches
    once: bool = False        # auto-unsubscribe after first delivery


# ── Core bus ──────────────────────────────────────────────────────────────────

class EventBus:
    """
    Central event bus for One&Infinity.

    Thread-safe.  Events published from any thread are dispatched on the
    internal asyncio loop (daemon thread).

    Usage
    -----
    bus = get_bus()

    # Publish (from any thread)
    bus.publish(EventType.NEW_TARGET, {"target": "example.com"}, source="recon")

    # Subscribe async handler
    @bus.subscribe(EventType.NEW_VULNERABILITY)
    async def on_vuln(event: BusEvent): ...

    # Subscribe sync handler
    bus.on(EventType.NEW_ENDPOINT, my_sync_handler)

    # Subscribe to ALL events (wildcard)
    bus.on(None, global_handler)
    """

    RING_BUFFER_SIZE = 2000

    def __init__(self, db_path: Optional[Path] = None, persist: bool = True):
        self._lock = threading.Lock()
        # topic → list of subscriptions
        self._subs: dict[str | None, list[_Subscription]] = {}
        # WebSocket clients: set of asyncio.Queue
        self._ws_clients: set[asyncio.Queue] = set()
        self._ws_lock = threading.Lock()

        # In-memory ring buffer
        self._ring: list[dict] = []

        # Dead-letter queue
        self._dlq: list[dict] = []

        # Stats
        self._published: int = 0
        self._dispatched: int = 0
        self._failed: int = 0

        # Internal queue for cross-thread publishing
        self._inbox: queue.PriorityQueue = queue.PriorityQueue(maxsize=10_000)

        # Asyncio event loop in daemon thread
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # SQLite persistence
        self._persist = persist
        self._db: Optional[sqlite3.Connection] = None
        if persist:
            db_path = db_path or db_path_fn("event_bus.db")
            self._init_db(db_path)

        self._start()

        # Redis transport (optional — falls back to local-only when unavailable)
        self._redis = None
        self._redis_listener: Optional[threading.Thread] = None
        self._published_ids: OrderedDict = OrderedDict()  # ordered set of event_ids we published
        self._published_ids_lock = threading.Lock()
        self._init_redis_transport()

    # ── Init ──────────────────────────────────────────────────────────────────

    def _init_db(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id     TEXT PRIMARY KEY,
                event_type   TEXT NOT NULL,
                source       TEXT,
                data         TEXT,
                timestamp    REAL,
                correlation_id TEXT
            )
        """)
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_evt_type ON events(event_type)")
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_evt_ts   ON events(timestamp)")
        self._db.commit()

    def _start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._run_loop,
            name="event-bus-loop",
            daemon=True,
        )
        self._thread.start()

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

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._dispatch_loop())

    async def _dispatch_loop(self):
        while self._running:
            try:
                # Pull from priority queue (non-blocking, poll every 5ms)
                try:
                    _pri, _ts, _eid, event = self._inbox.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(0.005)
                    continue

                if event is None:
                    break

                # Skip expired events
                if event.is_expired():
                    continue

                await self._dispatch(event)
            except Exception as exc:
                log.exception("Dispatch loop error: %s", exc)

    async def _dispatch(self, event: BusEvent):
        self._dispatched += 1
        # Gather handlers: topic-specific + wildcard
        with self._lock:
            specific = list(self._subs.get(event.event_type.value, []))
            wildcard = list(self._subs.get(None, []))
        handlers = specific + wildcard

        to_remove: list[tuple[str | None, _Subscription]] = []

        for sub in handlers:
            # Source filter
            if sub.source_filter and sub.source_filter != event.source:
                continue
            try:
                if sub.is_async:
                    await sub.handler(event)
                else:
                    await self._loop.run_in_executor(None, sub.handler, event)
            except Exception as exc:
                self._failed += 1
                self._dlq.append({"event": event.to_dict(), "error": str(exc), "ts": time.time()})
                if len(self._dlq) > 200:
                    self._dlq.pop(0)
                log.warning("Handler %r failed for %s: %s", sub.handler, event.event_type, exc)

            if sub.once:
                key = event.event_type.value if sub in specific else None
                to_remove.append((key, sub))

        # Remove one-shot subscribers
        with self._lock:
            for key, sub in to_remove:
                lst = self._subs.get(key, [])
                if sub in lst:
                    lst.remove(sub)

        # Persist
        if self._db:
            try:
                d = event.to_dict()
                self._db.execute(
                    "INSERT OR IGNORE INTO events(event_id,event_type,source,data,timestamp,correlation_id)"
                    " VALUES(?,?,?,?,?,?)",
                    (d["event_id"], d["event_type"], d["source"],
                     json.dumps(d["data"]), d["timestamp"], d["correlation_id"])
                )
                self._db.commit()
            except Exception:
                pass

        # Ring buffer
        d = event.to_dict()
        self._ring.append(d)
        if len(self._ring) > self.RING_BUFFER_SIZE:
            self._ring.pop(0)

        # Broadcast to WebSocket clients
        with self._ws_lock:
            dead = set()
            for q in self._ws_clients:
                try:
                    q.put_nowait(d)
                except asyncio.QueueFull:
                    dead.add(q)
            self._ws_clients -= dead

    def stop(self):
        self._running = False
        try:
            self._inbox.put_nowait((Priority.HIGH.value, 0.0, "", None))
        except queue.Full:
            pass

    # ── Publish ───────────────────────────────────────────────────────────────

    def publish(
        self,
        event_type: EventType,
        data: dict,
        source: str = "platform",
        priority: Priority = Priority.NORMAL,
        correlation_id: str = "",
        ttl: float = 0.0,
    ) -> str:
        """Publish an event.  Thread-safe.  Returns event_id."""
        event = BusEvent(
            event_type=event_type,
            data=data,
            source=source,
            priority=priority,
            correlation_id=correlation_id,
            ttl=ttl,
        )
        try:
            self._inbox.put(
                (priority.value, event.timestamp, event.event_id, event), timeout=1.0
            )
            self._published += 1
        except queue.Full:
            log.warning("EventBus: inbox full, dropping %s", event_type)
            return event.event_id

        # Redis transport: broadcast to cross-process subscribers
        if self._redis is not None:
            try:
                payload = json.dumps(event.to_dict())
                scan_id = correlation_id or "global"
                channel = f"oneinfinity:events:{scan_id}"
                self._redis.publish(channel, payload)
                self._redis.publish("oneinfinity:events:global", payload)
                # Track our own event_id to avoid re-delivery from listener
                with self._published_ids_lock:
                    self._published_ids[event.event_id] = None
                    if len(self._published_ids) > 10_000:
                        # Remove oldest entries (OrderedDict preserves insertion order)
                        while len(self._published_ids) > 5_000:
                            self._published_ids.popitem(last=False)
            except Exception as exc:
                log.debug("EventBus: Redis publish failed (%s) — local only", exc)

        return event.event_id

    def publish_event(self, event: BusEvent) -> str:
        """Publish a pre-built BusEvent."""
        try:
            self._inbox.put(
                (event.priority.value, event.timestamp, event.event_id, event), timeout=1.0
            )
            self._published += 1
        except queue.Full:
            log.warning("EventBus: inbox full, dropping %s", event.event_type)

        # Redis transport: broadcast to cross-process subscribers
        if self._redis is not None:
            try:
                import json as _json
                payload = _json.dumps(event.to_dict())
                scan_id = getattr(event, 'correlation_id', None) or "global"
                channel = f"oneinfinity:events:{scan_id}"
                self._redis.publish(channel, payload)
                self._redis.publish("oneinfinity:events:global", payload)
                with self._published_ids_lock:
                    self._published_ids[event.event_id] = None
                    if len(self._published_ids) > 10_000:
                        while len(self._published_ids) > 5_000:
                            self._published_ids.popitem(last=False)
            except Exception as exc:
                log.debug("EventBus: Redis publish failed (%s) — local only", exc)

        return event.event_id

    # ── Subscribe ─────────────────────────────────────────────────────────────

    def on(
        self,
        event_type: Optional[EventType],
        handler: AnyHandler,
        source_filter: str = "",
        once: bool = False,
    ):
        """Register a sync or async handler.  event_type=None = wildcard."""
        is_async = asyncio.iscoroutinefunction(handler)
        sub = _Subscription(
            handler=handler,
            is_async=is_async,
            source_filter=source_filter,
            once=once,
        )
        key = event_type.value if event_type else None
        with self._lock:
            if key not in self._subs:
                self._subs[key] = []
            self._subs[key].append(sub)

    def subscribe(self, event_type: Optional[EventType], **kwargs):
        """Decorator version of on()."""
        def decorator(fn: AnyHandler):
            self.on(event_type, fn, **kwargs)
            return fn
        return decorator

    def off(self, event_type: Optional[EventType], handler: AnyHandler):
        """Unregister a handler."""
        key = event_type.value if event_type else None
        with self._lock:
            lst = self._subs.get(key, [])
            self._subs[key] = [s for s in lst if s.handler is not handler]

    # ── WebSocket support ─────────────────────────────────────────────────────

    def register_ws_client(self) -> asyncio.Queue:
        """Returns a queue from which the WebSocket handler can pull events."""
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        with self._ws_lock:
            self._ws_clients.add(q)
        return q

    def unregister_ws_client(self, q: asyncio.Queue):
        with self._ws_lock:
            self._ws_clients.discard(q)

    # ── Query ─────────────────────────────────────────────────────────────────

    def recent(self, limit: int = 100, event_type: str = "", source: str = "") -> list[dict]:
        events = list(reversed(self._ring))
        if event_type:
            events = [e for e in events if e["event_type"] == event_type]
        if source:
            events = [e for e in events if e["source"] == source]
        return events[:limit]

    def query_db(self, event_type: str = "", since: float = 0.0, limit: int = 200) -> list[dict]:
        """Query persisted events from SQLite."""
        if not self._db:
            return self.recent(limit=limit, event_type=event_type)
        q = "SELECT event_id,event_type,source,data,timestamp FROM events WHERE 1=1"
        params: list = []
        if event_type:
            q += " AND event_type=?"
            params.append(event_type)
        if since > 0:
            q += " AND timestamp>=?"
            params.append(since)
        q += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = self._db.execute(q, params).fetchall()
        return [{"event_id": r[0], "event_type": r[1], "source": r[2],
                 "data": json.loads(r[3] or "{}"), "timestamp": r[4]} for r in rows]

    def stats(self) -> dict:
        with self._lock:
            topic_counts = {k: len(v) for k, v in self._subs.items()}
        return {
            "published":    self._published,
            "dispatched":   self._dispatched,
            "failed":       self._failed,
            "ring_size":    len(self._ring),
            "inbox_size":   self._inbox.qsize(),
            "dlq_size":     len(self._dlq),
            "ws_clients":   len(self._ws_clients),
            "subscriptions": topic_counts,
            "running":      self._running,
        }

    def dlq(self, limit: int = 20) -> list[dict]:
        return list(reversed(self._dlq))[:limit]


# ── Singleton ─────────────────────────────────────────────────────────────────

_bus: Optional[EventBus] = None
_bus_lock = threading.Lock()


def get_bus() -> EventBus:
    """Return the global EventBus singleton (creates it on first call)."""
    global _bus
    if _bus is None:
        with _bus_lock:
            if _bus is None:
                db = db_path_fn("event_bus.db")
                _bus = EventBus(db_path=db)
    return _bus


# ── Convenience helpers ───────────────────────────────────────────────────────

def publish(event_type: EventType, data: dict, source: str = "platform",
            priority: Priority = Priority.NORMAL, correlation_id: str = "") -> str:
    """Module-level publish helper."""
    return get_bus().publish(event_type, data, source=source, priority=priority,
                             correlation_id=correlation_id)


def on(event_type: Optional[EventType], handler: AnyHandler, **kwargs):
    """Module-level subscribe helper."""
    get_bus().on(event_type, handler, **kwargs)


def subscribe(event_type: Optional[EventType], **kwargs):
    """Module-level subscribe decorator."""
    return get_bus().subscribe(event_type, **kwargs)
