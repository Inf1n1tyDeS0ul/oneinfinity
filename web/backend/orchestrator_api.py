"""
orchestrator_api.py — FastAPI router for the Model Orchestration Engine

GET  /api/orchestrator/status          — loaded models, budget, policy
GET  /api/orchestrator/models          — model registry
GET  /api/orchestrator/history         — recent executions
GET  /api/orchestrator/budget          — budget status + projections
GET  /api/orchestrator/budget/summary  — usage summary (today/month/all)
GET  /api/orchestrator/budget/records  — raw usage records
POST /api/orchestrator/execute         — execute a task through the orchestrator
POST /api/orchestrator/classify        — classify a task (dry-run, no model call)
POST /api/orchestrator/reload          — reload models.yaml config
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

router = APIRouter(prefix="/api/orchestrator", tags=["model-orchestrator"])


def _orch():
    try:
        from model_orchestrator import get_orchestrator
        return get_orchestrator()
    except Exception as e:
        raise HTTPException(503, f"ModelOrchestrator unavailable: {e}")


def _budget():
    try:
        from model_budget_manager import get_budget_manager
        return get_budget_manager()
    except Exception as e:
        raise HTTPException(503, f"ModelBudgetManager unavailable: {e}")


def _classifier():
    try:
        from task_classifier import get_classifier
        return get_classifier()
    except Exception as e:
        raise HTTPException(503, f"TaskClassifier unavailable: {e}")


# ── Request models ─────────────────────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    prompt:       str
    description:  str = ""
    agent_type:   str = ""
    node_type:    str = ""
    node_label:   str = ""
    target:       str = ""
    severity:     str = ""
    importance:   str = ""
    complexity:   str = ""
    graph_priority: float = 0.0
    context:      dict = Field(default_factory=dict)
    force_tier:   Optional[str] = None   # "FAST", "STANDARD", "PREMIUM"


class ClassifyRequest(BaseModel):
    prompt:      str = ""
    description: str = ""
    agent_type:  str = ""
    node_type:   str = ""
    severity:    str = ""
    importance:  str = ""
    context:     dict = Field(default_factory=dict)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/status")
def orchestrator_status():
    return _orch().status()


@router.get("/models")
def list_models(enabled_only: bool = Query(False)):
    return _orch().list_models(enabled_only=enabled_only)


@router.get("/history")
def execution_history(limit: int = Query(20, ge=1, le=100)):
    return _orch().recent_executions(limit=limit)


@router.get("/budget")
def budget_status():
    return _budget().status()


@router.get("/budget/summary")
def budget_summary(period: str = Query("today")):
    if period not in ("today", "this_month", "all_time"):
        raise HTTPException(400, "period must be today, this_month, or all_time")
    return _budget().get_summary(period).to_dict()


@router.get("/budget/records")
def budget_records(limit: int = Query(50, ge=1, le=200)):
    return _budget().recent_records(limit=limit)


@router.post("/execute")
def orchestrator_execute(req: ExecuteRequest):
    from model_orchestrator import ModelTier
    task = req.dict(exclude={"force_tier"})
    # map prompt → description key the classifier expects
    task["description"] = task.get("description") or task.pop("prompt", "")

    force_tier = None
    if req.force_tier:
        try:
            force_tier = ModelTier[req.force_tier.upper()]
        except KeyError:
            raise HTTPException(400, f"Invalid tier: {req.force_tier}. Use FAST, STANDARD, or PREMIUM")

    try:
        output = _orch().execute(task, force_tier=force_tier)
        return output.to_dict()
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/classify")
def classify_task(req: ClassifyRequest):
    task = req.dict()
    task["description"] = task.pop("prompt", "") or task.get("description", "")
    classification = _classifier().classify(task)
    return classification.to_dict()


@router.post("/reload")
def reload_config():
    orch = _orch()
    orch._loaded = False
    orch.load_config()
    return {"status": "reloaded", "models": len(orch._models)}


def register_orchestrator_routes(app) -> None:
    app.include_router(router)
