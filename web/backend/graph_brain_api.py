"""
graph_brain_api.py — FastAPI router for the Graph-Centric Brain System

Routes under /api/brain/ , /api/ede/ , /api/triggers/ , /api/decisions/

GET  /api/brain/status               — brain status + queue depth
POST /api/brain/start                — start brain + EDE for target(s)
POST /api/brain/stop                 — stop brain + EDE
POST /api/brain/add-target           — add target to running brain
GET  /api/brain/queue                — action queue snapshot
GET  /api/brain/priorities           — top priority nodes
GET  /api/brain/decisions            — decision history
POST /api/brain/integrate-node       — manually inject a node
POST /api/brain/integrate-finding    — manually inject a finding
GET  /api/brain/attack-paths/{target} — attack paths from graph
GET  /api/brain/risk-report/{target} — full risk report

GET  /api/ede/status                 — event-driven engine status
POST /api/ede/start                  — start EDE
POST /api/ede/stop                   — stop EDE

GET  /api/triggers/rules             — list trigger rules
POST /api/triggers/evaluate          — trigger evaluate_graph()
GET  /api/triggers/history           — recent trigger firings
GET  /api/triggers/stats             — trigger engine statistics

GET  /api/decisions/plan/{target}    — full decision plan
GET  /api/decisions/recent           — recent decisions
GET  /api/decisions/agent-stats      — per-agent outcome statistics
POST /api/decisions/feedback         — record outcome feedback

GET  /api/fabric/status              — fabric status (queue, active, counters)
POST /api/fabric/submit              — manually submit a fabric task
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

# ── Lazy accessors ─────────────────────────────────────────────────────────────

def _brain():
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        return get_brain()
    except Exception as e:
        raise HTTPException(503, f"AttackGraphBrain unavailable: {e}")


def _ede():
    try:
        from oneinfinity.orchestration.event_driven_engine import get_engine
        return get_engine()
    except Exception as e:
        raise HTTPException(503, f"EventDrivenEngine unavailable: {e}")


def _triggers():
    try:
        from oneinfinity.orchestration.graph_trigger_engine import get_trigger_engine
        return get_trigger_engine()
    except Exception as e:
        raise HTTPException(503, f"GraphTriggerEngine unavailable: {e}")


def _decisions():
    try:
        from oneinfinity.orchestration.autonomous_decision_engine import get_decision_engine
        return get_decision_engine()
    except Exception as e:
        raise HTTPException(503, f"AutonomousDecisionEngine unavailable: {e}")


def _fabric():
    try:
        from oneinfinity.swarm.agent_execution_fabric import get_fabric
        return get_fabric()
    except Exception as e:
        raise HTTPException(503, f"AgentExecutionFabric unavailable: {e}")


# ── Request models ─────────────────────────────────────────────────────────────

class StartRequest(BaseModel):
    target:  str = ""
    targets: List[str] = Field(default_factory=list)
    config:  Optional[dict] = None


class AddTargetRequest(BaseModel):
    target: str


class IntegrateNodeRequest(BaseModel):
    node_type:  str
    label:      str
    target:     str
    properties: dict = Field(default_factory=dict)


class IntegrateFindingRequest(BaseModel):
    node_id:    str
    agent_type: str
    finding:    dict


class FeedbackRequest(BaseModel):
    decision_id: str
    agent_type:  str
    node_id:     str
    success:     bool
    severity:    str = "info"


class FabricSubmitRequest(BaseModel):
    agent_type: str
    node_id:    str
    node_label: str
    node_type:  str
    target:     str
    priority:   float = 5.0
    context:    dict  = Field(default_factory=dict)


class EvaluateTriggerRequest(BaseModel):
    target: Optional[str] = None


# ── Brain router ───────────────────────────────────────────────────────────────

brain_router = APIRouter(prefix="/api/brain", tags=["graph-brain"])


@brain_router.get("/status")
def brain_status():
    return _brain().status().to_dict()


@brain_router.post("/start")
def brain_start(req: StartRequest):
    targets = req.targets or ([req.target] if req.target else [])
    if not targets:
        raise HTTPException(400, "At least one target required")
    brain = _brain()
    ede   = _ede()
    brain.start(targets=targets)
    if not ede._running:
        ede.start(targets=targets)
    else:
        for t in targets:
            ede.add_target(t)
    return {"status": "started", "targets": targets}


@brain_router.post("/stop")
def brain_stop():
    _brain().stop()
    _ede().stop()
    return {"status": "stopped"}


@brain_router.post("/add-target")
def brain_add_target(req: AddTargetRequest):
    _brain().add_target(req.target)
    _ede().add_target(req.target)
    return {"status": "added", "target": req.target}


@brain_router.get("/queue")
def brain_queue(limit: int = Query(50, ge=1, le=200)):
    return _brain().queue_snapshot(limit=limit)


@brain_router.get("/priorities")
def brain_priorities(limit: int = Query(20, ge=1, le=100)):
    records = _brain().top_priority_nodes(n=limit)
    return [r.__dict__ for r in records]


@brain_router.get("/decisions")
def brain_decisions(limit: int = Query(30, ge=1, le=200)):
    return _brain().decision_history(limit=limit)


@brain_router.post("/integrate-node")
def brain_integrate_node(req: IntegrateNodeRequest):
    node_id = _brain().integrate_node(
        req.node_type, req.label, req.target, req.properties
    )
    return {"status": "integrated", "node_id": node_id}


@brain_router.post("/integrate-finding")
def brain_integrate_finding(req: IntegrateFindingRequest):
    _brain().integrate_finding(req.node_id, req.agent_type, req.finding)
    return {"status": "integrated"}


@brain_router.get("/attack-paths/{target:path}")
def brain_attack_paths(target: str):
    return _brain().attack_paths(target)


@brain_router.get("/risk-report/{target:path}")
def brain_risk_report(target: str):
    return _brain().risk_report(target)


# ── Event-driven engine router ─────────────────────────────────────────────────

ede_router = APIRouter(prefix="/api/ede", tags=["event-driven-engine"])


@ede_router.get("/status")
def ede_status():
    return _ede().status().to_dict()


@ede_router.post("/start")
def ede_start(req: StartRequest):
    targets = req.targets or ([req.target] if req.target else [])
    if not targets:
        raise HTTPException(400, "At least one target required")
    ede = _ede()
    if not ede._running:
        cfg = None
        if req.config:
            from oneinfinity.orchestration.event_driven_engine import LoopConfig
            cfg = LoopConfig(**{k: v for k, v in req.config.items()
                                if hasattr(LoopConfig, k)})
            ede._config = cfg
        ede.start(targets=targets)
    else:
        for t in targets:
            ede.add_target(t)
    return {"status": "started", "targets": targets}


@ede_router.post("/stop")
def ede_stop():
    _ede().stop()
    return {"status": "stopped"}


# ── Trigger router ─────────────────────────────────────────────────────────────

trigger_router = APIRouter(prefix="/api/triggers", tags=["graph-triggers"])


@trigger_router.get("/rules")
def trigger_rules():
    return _triggers().list_rules()


@trigger_router.post("/evaluate")
def trigger_evaluate(req: EvaluateTriggerRequest):
    count = _triggers().evaluate_graph()
    return {"status": "evaluated", "firings": count}


@trigger_router.get("/history")
def trigger_history(limit: int = Query(50, ge=1, le=200)):
    return _triggers().recent_firings(limit=limit)


@trigger_router.get("/stats")
def trigger_stats():
    return _triggers().stats()


# ── Decision router ────────────────────────────────────────────────────────────

decision_router = APIRouter(prefix="/api/decisions", tags=["decision-engine"])


@decision_router.get("/plan/{target}")
def decision_plan(target: str, max_decisions: int = Query(30, ge=1, le=100)):
    plan = _decisions().generate_plan(target, max_decisions=max_decisions)
    return plan.to_dict()


@decision_router.get("/recent")
def decision_recent(limit: int = Query(20, ge=1, le=100)):
    return _decisions().recent_decisions(limit=limit)


@decision_router.get("/agent-stats")
def decision_agent_stats():
    return _decisions().agent_stats()


@decision_router.post("/feedback")
def decision_feedback(req: FeedbackRequest):
    _decisions().record_outcome(
        req.decision_id, req.agent_type, req.node_id, req.success, req.severity
    )
    return {"status": "recorded"}


# ── Fabric router ──────────────────────────────────────────────────────────────

fabric_router = APIRouter(prefix="/api/fabric", tags=["agent-fabric"])


@fabric_router.get("/status")
def fabric_status():
    return _fabric().status()


@fabric_router.post("/submit")
def fabric_submit(req: FabricSubmitRequest):
    fabric = _fabric()
    if not fabric._running:
        fabric.start()
    task_id = fabric.submit_task(
        agent_type=req.agent_type,
        node_id=req.node_id,
        node_label=req.node_label,
        node_type=req.node_type,
        target=req.target,
        priority=req.priority,
        context=req.context,
    )
    return {"status": "submitted", "task_id": task_id}


# ── Registration helper ────────────────────────────────────────────────────────

def register_brain_routes(app, require_auth=None) -> None:
    deps = [Depends(require_auth)] if require_auth else []
    app.include_router(brain_router, dependencies=deps)
    app.include_router(ede_router, dependencies=deps)
    app.include_router(trigger_router, dependencies=deps)
    app.include_router(decision_router, dependencies=deps)
    app.include_router(fabric_router, dependencies=deps)
