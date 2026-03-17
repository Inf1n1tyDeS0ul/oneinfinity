"""
system_evolution_api.py — FastAPI router for the Self-Evolving Architecture Engine

Endpoints registered under /api/evolution/

GET  /status           — engine status + capability snapshot + recent changes
GET  /events           — recent events from the in-memory event bus
GET  /events/{type}    — filter events by type
GET  /insights         — recent learning insights
GET  /insights/{cat}   — filter insights by category
GET  /patterns         — top attack patterns from evolution.db
GET  /chains           — exploit chains from evolution.db
GET  /capabilities     — latest capability list + history
GET  /changelog        — architecture changelog
GET  /skills           — skills registry summary
POST /emit             — emit an event from the UI (testing / manual)
"""

from __future__ import annotations

import sys
import os
import time
import json
from typing import Optional, List
from pathlib import Path

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, Field

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

router = APIRouter(prefix="/api/evolution", tags=["system-evolution"])

# ── Pydantic models ───────────────────────────────────────────────────────────

class EmitEventRequest(BaseModel):
    event_type: str = Field("feature_added", description="EventType value")
    source: str = Field("ui", description="Source module name")
    data: dict = Field(default_factory=dict)


# ── Lazy accessors ────────────────────────────────────────────────────────────

def _get_engine():
    try:
        from auto_architecture_engine import get_engine
        return get_engine()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AutoArchitectureEngine unavailable: {e}")


def _get_memory():
    try:
        from memory_manager import get_memory_manager
        return get_memory_manager()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"MemoryManager unavailable: {e}")


def _get_skills():
    try:
        from skills_tracker import get_skills_tracker
        return get_skills_tracker()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"SkillsTracker unavailable: {e}")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
def get_status():
    """Full engine status: stats, capability snapshot, recent changes + insights."""
    try:
        from auto_architecture_engine import cmd_arch_status
        return cmd_arch_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/events")
def list_events(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
):
    engine = _get_engine()
    return engine.recent_events(limit=limit, event_type=event_type or "")


@router.get("/events/{event_type}")
def list_events_by_type(event_type: str, limit: int = Query(50, ge=1, le=500)):
    engine = _get_engine()
    return engine.recent_events(limit=limit, event_type=event_type)


@router.get("/insights")
def list_insights(
    limit: int = Query(50, ge=1, le=200),
    category: Optional[str] = Query(None),
    hours: int = Query(168, ge=1),      # default: last 7 days
):
    mm = _get_memory()
    insights = mm.recent_insights(hours=hours, limit=limit)
    if category:
        insights = [i for i in insights if i.get("category") == category]
    return insights


@router.get("/insights/{category}")
def list_insights_by_category(category: str, limit: int = Query(50, ge=1, le=200)):
    mm = _get_memory()
    return mm.get_insights(category=category, limit=limit)


@router.get("/patterns")
def list_attack_patterns(
    vuln_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    top: bool = Query(False, description="Return top patterns by success_rate"),
):
    mm = _get_memory()
    if top:
        return mm.top_patterns(limit=limit)
    return mm.get_patterns(vuln_type=vuln_type or "", limit=limit)


@router.get("/chains")
def list_exploit_chains(
    confirmed_only: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
):
    mm = _get_memory()
    return mm.get_chains(confirmed_only=confirmed_only, limit=limit)


@router.get("/capabilities")
def get_capabilities():
    """Latest capability snapshot + growth history."""
    mm = _get_memory()
    st = _get_skills()
    return {
        "current": st.capability_names(),
        "total": st.total_count(),
        "by_category": st.categories_summary(),
        "snapshot": mm.latest_capability_snapshot(),
        "history": mm.capability_history(limit=30),
    }


@router.get("/changelog")
def get_changelog(limit: int = Query(50, ge=1, le=200)):
    mm = _get_memory()
    return mm.get_architecture_changelog(limit=limit)


@router.get("/skills")
def get_skills(category: Optional[str] = Query(None)):
    st = _get_skills()
    if category:
        skills = st.by_category(category)
        return [s.to_dict() for s in skills]
    return {
        "total": st.total_count(),
        "by_category": st.categories_summary(),
        "all": st.all_skills(),
    }


@router.get("/scans")
def get_scan_summaries(limit: int = Query(20, ge=1, le=100)):
    mm = _get_memory()
    return mm.get_scan_summaries(limit=limit)


@router.get("/stats")
def get_memory_stats():
    mm = _get_memory()
    return mm.stats()


@router.post("/emit")
def emit_event(req: EmitEventRequest, background_tasks: BackgroundTasks):
    """Emit a platform event from the UI (for testing / manual triggers)."""
    engine = _get_engine()
    try:
        from auto_architecture_engine import ArchEvent, EventType
        ev = ArchEvent(
            event_type=EventType(req.event_type),
            source=req.source,
            data=req.data,
        )
        event_id = engine.emit(ev)
        return {"event_id": event_id, "status": "queued"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid event_type: {req.event_type}. {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/event-types")
def list_event_types():
    try:
        from auto_architecture_engine import EventType
        return [et.value for et in EventType]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Registration helper ───────────────────────────────────────────────────────

def register_evolution_routes(app):
    app.include_router(router)
