"""
daemon_api.py — FastAPI router for the Intelligence Daemon + Event Bus

Routes under /api/daemon/ and /api/events/

GET  /api/daemon/status          — full daemon status + worker states
POST /api/daemon/start           — start daemon for target(s)
POST /api/daemon/stop            — stop daemon
POST /api/daemon/add-target      — add target while running
POST /api/daemon/remove-target   — remove target
GET  /api/daemon/workers         — per-worker state list
POST /api/daemon/workers/{name}/enable  — enable a worker
POST /api/daemon/workers/{name}/disable — disable a worker
GET  /api/daemon/config          — current DaemonConfig as dict
PATCH /api/daemon/config         — update worker config

GET  /api/events/recent          — ring buffer (latest N events)
GET  /api/events/query           — query persisted events from SQLite
GET  /api/events/stats           — bus statistics
GET  /api/events/types           — list all EventType values
GET  /api/events/dlq             — dead-letter queue
GET  /api/events/stream          — SSE stream of live events
WS   /api/events/ws              — WebSocket live event stream
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, List, Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

router = APIRouter(tags=["intelligence-daemon"])

# ── Pydantic request models ───────────────────────────────────────────────────

class StartRequest(BaseModel):
    target: str = ""
    targets: List[str] = Field(default_factory=list)
    config: Optional[dict] = None


class AddTargetRequest(BaseModel):
    target: str


class WorkerConfigPatch(BaseModel):
    worker: str   # e.g. "hypothesis", "swarm", "osint_expand"
    enabled: Optional[bool] = None
    cooldown_s: Optional[float] = None
    max_concurrent: Optional[int] = None


# ── Lazy accessors ────────────────────────────────────────────────────────────

def _daemon():
    try:
        from intelligence_daemon import get_daemon
        return get_daemon()
    except Exception as e:
        raise HTTPException(503, f"IntelligenceDaemon unavailable: {e}")


def _bus():
    try:
        from event_bus import get_bus
        return get_bus()
    except Exception as e:
        raise HTTPException(503, f"EventBus unavailable: {e}")


# ── Daemon routes ─────────────────────────────────────────────────────────────

daemon_router = APIRouter(prefix="/api/daemon")


@daemon_router.get("/status")
def daemon_status():
    return _daemon().status()


@daemon_router.post("/start")
def daemon_start(req: StartRequest):
    d = _daemon()
    targets = req.targets or ([req.target] if req.target else [])
    if not targets:
        raise HTTPException(400, "At least one target required")
    if not d._running:
        d.start(targets=targets)
    else:
        for t in targets:
            d.add_target(t)
    return {"status": "started", "targets": list(d._targets)}


@daemon_router.post("/stop")
def daemon_stop():
    _daemon().stop()
    return {"status": "stopped"}


@daemon_router.post("/add-target")
def add_target(req: AddTargetRequest):
    _daemon().add_target(req.target)
    return {"status": "added", "target": req.target}


@daemon_router.post("/remove-target")
def remove_target(req: AddTargetRequest):
    _daemon().remove_target(req.target)
    return {"status": "removed", "target": req.target}


@daemon_router.get("/workers")
def list_workers():
    return _daemon().worker_states()


@daemon_router.post("/workers/{name}/enable")
def enable_worker(name: str):
    _daemon().enable_worker(name)
    return {"status": "enabled", "worker": name}


@daemon_router.post("/workers/{name}/disable")
def disable_worker(name: str):
    _daemon().disable_worker(name)
    return {"status": "disabled", "worker": name}


@daemon_router.get("/config")
def get_config():
    return _daemon()._config.to_dict()


@daemon_router.patch("/config")
def patch_config(patch: WorkerConfigPatch):
    d = _daemon()
    cfg = d._config
    worker_cfg = getattr(cfg, patch.worker, None)
    if worker_cfg is None:
        raise HTTPException(404, f"Unknown worker config key: {patch.worker}")
    if patch.enabled is not None:
        worker_cfg.enabled = patch.enabled
    if patch.cooldown_s is not None:
        worker_cfg.cooldown_s = patch.cooldown_s
    if patch.max_concurrent is not None:
        worker_cfg.max_concurrent = patch.max_concurrent
    return {"status": "updated", "worker": patch.worker}


# ── Event bus routes ──────────────────────────────────────────────────────────

events_router = APIRouter(prefix="/api/events")


@events_router.get("/recent")
def recent_events(
    limit: int = Query(100, ge=1, le=2000),
    event_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
):
    return _bus().recent(limit=limit, event_type=event_type or "", source=source or "")


@events_router.get("/query")
def query_events(
    event_type: Optional[str] = Query(None),
    since: float = Query(0.0),
    limit: int = Query(200, ge=1, le=1000),
):
    return _bus().query_db(event_type=event_type or "", since=since, limit=limit)


@events_router.get("/stats")
def bus_stats():
    return _bus().stats()


@events_router.get("/types")
def event_types():
    try:
        from event_bus import EventType
        return [et.value for et in EventType]
    except Exception as e:
        raise HTTPException(500, str(e))


@events_router.get("/dlq")
def dead_letter_queue(limit: int = Query(20, ge=1, le=100)):
    return _bus().dlq(limit=limit)


@events_router.get("/stream")
async def event_stream(
    event_type: Optional[str] = Query(None),
    timeout_s: int = Query(300, ge=10, le=3600),
):
    """Server-Sent Events stream of live bus events."""
    bus = _bus()
    q = bus.register_ws_client()
    start = time.time()

    async def generate():
        try:
            while time.time() - start < timeout_s:
                try:
                    event = q.get_nowait()
                    if event_type and event.get("event_type") != event_type:
                        continue
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.QueueEmpty:
                    yield ": keepalive\n\n"
                    await asyncio.sleep(0.5)
        finally:
            bus.unregister_ws_client(q)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@events_router.websocket("/ws")
async def event_ws(websocket: WebSocket, event_type: Optional[str] = Query(None)):
    """WebSocket live event stream."""
    await websocket.accept()
    bus = _bus()
    q = bus.register_ws_client()
    try:
        while True:
            try:
                event = q.get_nowait()
                if event_type and event.get("event_type") != event_type:
                    continue
                await websocket.send_json(event)
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        bus.unregister_ws_client(q)


# ── Registration helper ───────────────────────────────────────────────────────

def register_daemon_routes(app):
    app.include_router(daemon_router)
    app.include_router(events_router)
