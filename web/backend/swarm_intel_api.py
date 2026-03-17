"""
swarm_intel_api.py — FastAPI routes for Swarm Intelligence Engine

Exposes:
  POST   /api/swarm-intel/scan              — launch swarm scan (background)
  GET    /api/swarm-intel/scan/{session_id} — status + findings
  DELETE /api/swarm-intel/scan/{session_id} — stop scan
  POST   /api/swarm-intel/simulate          — run Monte Carlo simulation
  POST   /api/swarm-intel/workflow          — run workflow attack simulation
  GET    /api/swarm-intel/workflows         — list available workflows
  GET    /api/swarm-intel/agents            — list agent types + descriptions
  GET    /api/swarm-intel/sessions          — recent sessions summary

Integrated with:
  - swarm_intelligence_engine.py (agents)
  - agent_swarm_coordinator.py   (orchestration)
  - attack_simulation_engine.py  (Monte Carlo)
  - workflow_simulation_engine.py (business logic)
  - attack_graph_core/            (graph updates)
  - learning/knowledge_base.py   (persistence)
"""

from __future__ import annotations

import asyncio
import sys
import os
import time
import uuid
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

log = logging.getLogger("oneinfinity.swarm_api")

# ── In-memory session store ───────────────────────────────────────────────────
SWARM_SESSIONS:      Dict[str, Dict] = {}
SIM_SESSIONS:        Dict[str, Dict] = {}
WORKFLOW_SESSIONS:   Dict[str, Dict] = {}

# ── Pydantic models ───────────────────────────────────────────────────────────

class SwarmScanRequest(BaseModel):
    target:      str
    agents:      Optional[List[str]] = None          # None = all 8
    concurrency: int                 = 6
    endpoints:   List[str]          = Field(default_factory=list)
    tech_stack:  List[str]          = Field(default_factory=list)
    auth_sessions: List[Dict[str, str]] = Field(default_factory=list)
    jwt_tokens:  List[str]          = Field(default_factory=list)
    context:     Dict[str, Any]     = Field(default_factory=dict)

class SimulateRequest(BaseModel):
    target:     str
    tech_stack: List[str] = Field(default_factory=list)
    waf:        bool       = False
    top_n:      int        = 15

class WorkflowSimRequest(BaseModel):
    workflow:    str        # checkout_flow | login_flow | ... | all
    base_url:    str        = "http://localhost"
    categories:  Optional[List[str]] = None
    cookie:      str        = ""
    token:       str        = ""

# ── Agent catalogue (for UI) ──────────────────────────────────────────────────

AGENT_CATALOGUE = [
    {
        "type":        "xss",
        "name":        "XSS Agent",
        "description": "Detects reflected, stored, and DOM-based Cross-Site Scripting.",
        "techniques":  ["Reflected XSS via dalfox", "DOM sink analysis", "Stored XSS with canary"],
        "cvss_range":  "7.4 – 8.8",
        "color":       "#f59e0b",
    },
    {
        "type":        "sqli",
        "name":        "SQL Injection Agent",
        "description": "Identifies error-based, blind time-based, and UNION-based SQL injection.",
        "techniques":  ["Error signature detection", "Time-based blind (≥4.8s)", "sqlmap integration"],
        "cvss_range":  "9.1 – 9.8",
        "color":       "#ef4444",
    },
    {
        "type":        "ssrf",
        "name":        "SSRF Agent",
        "description": "Tests for Server-Side Request Forgery, cloud metadata access, and LFI via SSRF.",
        "techniques":  ["AWS/GCP/Azure metadata probes", "Internal service scan", "file:// LFI"],
        "cvss_range":  "8.6 – 9.3",
        "color":       "#dc2626",
    },
    {
        "type":        "idor",
        "name":        "IDOR Agent",
        "description": "Finds Insecure Direct Object References via horizontal and path-based enumeration.",
        "techniques":  ["Sequential ID tampering", "Path-based IDOR", "Cross-session validation"],
        "cvss_range":  "8.1",
        "color":       "#f97316",
    },
    {
        "type":        "auth",
        "name":        "Authentication Agent",
        "description": "Tests authentication flaws: weak credentials, JWT attacks, auth bypass.",
        "techniques":  ["Default credential probing", "JWT none-alg / weak-secret", "SQL auth bypass"],
        "cvss_range":  "8.5 – 9.8",
        "color":       "#8b5cf6",
    },
    {
        "type":        "business_logic",
        "name":        "Business Logic Agent",
        "description": "Discovers price manipulation, race conditions, and workflow bypass flaws.",
        "techniques":  ["Negative price injection", "Concurrent request bursting", "Coupon abuse"],
        "cvss_range":  "7.5 – 9.1",
        "color":       "#06b6d4",
    },
    {
        "type":        "mobile",
        "name":        "Mobile Security Agent",
        "description": "Tests mobile applications for SSL pinning, root detection, hardcoded secrets, and insecure storage.",
        "techniques":  ["Frida bypass generation", "DEX secret scanning", "Exported component testing"],
        "cvss_range":  "6.5 – 7.8",
        "color":       "#10b981",
    },
    {
        "type":        "api",
        "name":        "API Security Agent",
        "description": "Tests REST/GraphQL APIs for BOLA, mass assignment, introspection, and rate limit bypass.",
        "techniques":  ["GraphQL introspection", "BOLA via ID swap", "Mass assignment injection"],
        "cvss_range":  "5.3 – 8.8",
        "color":       "#3b82f6",
    },
]

# ── Routers ───────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/swarm-intel", tags=["swarm-intelligence"])


@router.get("/agents")
async def list_agents():
    """Return descriptions of all 8 swarm agent types."""
    return {"agents": AGENT_CATALOGUE, "total": len(AGENT_CATALOGUE)}


@router.get("/workflows")
async def list_workflows():
    """Return available business logic workflows."""
    try:
        from workflow_simulation_engine import WorkflowSimulationEngine, AttackCategory
        engine = WorkflowSimulationEngine()
        return {
            "workflows":  engine.list_workflows(),
            "categories": engine.list_attack_categories(),
        }
    except ImportError:
        return {
            "workflows":  ["checkout_flow", "login_flow", "password_reset_flow", "fund_transfer_flow"],
            "categories": ["price_manipulation", "coupon_stacking", "workflow_step_skip",
                           "race_condition", "parameter_tampering", "privilege_escalation",
                           "negative_quantity", "integer_overflow"],
        }


@router.get("/sessions")
async def list_sessions():
    """Return recent swarm, simulation, and workflow sessions."""
    swarm = [
        {k: v for k, v in s.items() if k != "_result"}
        for s in sorted(SWARM_SESSIONS.values(), key=lambda x: x.get("started_at", 0), reverse=True)[:20]
    ]
    sim = [
        {k: v for k, v in s.items() if k != "_results"}
        for s in sorted(SIM_SESSIONS.values(), key=lambda x: x.get("started_at", 0), reverse=True)[:20]
    ]
    return {"swarm_sessions": swarm, "simulation_sessions": sim,
            "workflow_sessions": list(WORKFLOW_SESSIONS.values())[:20]}


# ── Swarm Scan ────────────────────────────────────────────────────────────────

@router.post("/scan")
async def start_swarm_scan(req: SwarmScanRequest, bg: BackgroundTasks):
    """Launch a multi-agent swarm scan in the background."""
    session_id = f"SWARM-{uuid.uuid4().hex[:8].upper()}"
    SWARM_SESSIONS[session_id] = {
        "session_id":    session_id,
        "target":        req.target,
        "agents":        req.agents or [a["type"] for a in AGENT_CATALOGUE],
        "status":        "queued",
        "started_at":    time.time(),
        "findings":      [],
        "agent_stats":   {},
        "chain_candidates": [],
        "graph_stats":   {},
        "simulation_priorities": [],
        "elapsed_s":     0,
        "dedup_removed": 0,
        "progress":      0,
        "log":           [f"[*] Swarm scan queued for {req.target}"],
    }
    bg.add_task(_run_swarm_scan_bg, session_id, req)
    return {"session_id": session_id, "status": "queued"}


@router.get("/scan/{session_id}")
async def get_swarm_scan(session_id: str):
    """Get status and findings for a swarm scan session."""
    session = SWARM_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.delete("/scan/{session_id}")
async def stop_swarm_scan(session_id: str):
    """Stop an active swarm scan."""
    session = SWARM_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session["status"]  = "stopped"
    session["log"].append("[!] Scan stopped by user")
    return {"status": "stopped"}


async def _run_swarm_scan_bg(session_id: str, req: SwarmScanRequest):
    """Background task: run the swarm coordinator and populate the session dict."""
    session = SWARM_SESSIONS[session_id]
    try:
        session["status"]   = "running"
        session["progress"] = 5
        session["log"].append(f"[*] Starting {len(session['agents'])} agents…")

        from agent_swarm_coordinator import run_swarm
        from swarm_intelligence_engine import AgentType

        agent_types = None
        if req.agents:
            try:
                agent_types = [AgentType(a) for a in req.agents]
            except ValueError:
                pass

        context = {
            "endpoints":     req.endpoints,
            "tech_stack":    req.tech_stack,
            "auth_sessions": req.auth_sessions,
            "jwt_tokens":    req.jwt_tokens,
            **req.context,
        }

        session["progress"] = 15
        result = await run_swarm(
            target=req.target,
            context=context,
            concurrency=req.concurrency,
            agent_types=agent_types,
        )
        session["progress"] = 95

        # Serialise findings (dataclasses → dicts)
        findings_dicts = []
        for f in result.findings:
            d = vars(f) if hasattr(f, "__dict__") else {}
            if hasattr(d.get("agent_type"), "value"):
                d["agent_type"] = d["agent_type"].value
            findings_dicts.append(d)

        session["findings"]              = findings_dicts
        session["agent_stats"]           = result.agent_stats
        session["chain_candidates"]      = result.chain_candidates
        session["graph_stats"]           = result.graph_stats
        session["simulation_priorities"] = result.simulation_priorities
        session["elapsed_s"]             = result.elapsed_s
        session["dedup_removed"]         = result.dedup_removed
        session["status"]                = "completed"
        session["progress"]              = 100
        session["log"].append(
            f"[+] Scan complete: {len(findings_dicts)} findings, "
            f"{result.dedup_removed} deduped, {result.elapsed_s:.1f}s"
        )

    except Exception as exc:
        log.error("Swarm scan error: %s", exc)
        session["status"] = "failed"
        session["log"].append(f"[!] Error: {exc}")


# ── Attack Simulation ─────────────────────────────────────────────────────────

@router.post("/simulate")
async def run_simulation(req: SimulateRequest, bg: BackgroundTasks):
    """Launch Monte Carlo attack simulation (non-destructive, no live testing)."""
    session_id = f"SIM-{uuid.uuid4().hex[:8].upper()}"
    SIM_SESSIONS[session_id] = {
        "session_id":  session_id,
        "target":      req.target,
        "tech_stack":  req.tech_stack,
        "waf":         req.waf,
        "status":      "running",
        "started_at":  time.time(),
        "results":     [],
        "strategy":    {},
        "elapsed_s":   0,
    }
    bg.add_task(_run_simulation_bg, session_id, req)
    return {"session_id": session_id, "status": "running"}


@router.get("/simulate/{session_id}")
async def get_simulation(session_id: str):
    """Get Monte Carlo simulation results."""
    session = SIM_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


async def _run_simulation_bg(session_id: str, req: SimulateRequest):
    session = SIM_SESSIONS[session_id]
    try:
        from attack_simulation_engine import AttackSimulationEngine
        engine  = AttackSimulationEngine()
        context = {"tech_stack": req.tech_stack, "waf_detected": req.waf}
        results = await engine.simulate_all_paths(req.target, context)
        strategy = engine.select_strategy(results, top_k=5)

        session["results"] = [
            {
                "attack_type":         r.attack_type,
                "success_probability": round(r.success_probability, 4),
                "impact_score":        round(r.impact_score, 2),
                "expected_value":      round(r.expected_value, 4),
                "recommended":         r.recommended,
                "reasoning":           r.reasoning,
                "factors":             r.factors,
            }
            for r in results[:req.top_n]
        ]
        session["strategy"] = {
            "primary":             strategy.primary.attack_type if strategy.primary else None,
            "reasoning":           strategy.reasoning,
            "recommended_agents":  strategy.recommended_agents,
            "top_paths":           [r.attack_type for r in strategy.top_paths],
        }
        session["elapsed_s"] = round(time.time() - session["started_at"], 2)
        session["status"]    = "completed"
    except Exception as exc:
        log.error("Simulation error: %s", exc)
        session["status"] = "failed"
        session["error"]  = str(exc)


# ── Workflow Simulation ───────────────────────────────────────────────────────

@router.post("/workflow")
async def run_workflow_simulation(req: WorkflowSimRequest, bg: BackgroundTasks):
    """Launch business logic workflow attack simulation."""
    session_id = f"WF-{uuid.uuid4().hex[:8].upper()}"
    WORKFLOW_SESSIONS[session_id] = {
        "session_id":  session_id,
        "workflow":    req.workflow,
        "base_url":    req.base_url,
        "categories":  req.categories,
        "status":      "running",
        "started_at":  time.time(),
        "findings":    [],
        "results":     [],
        "elapsed_s":   0,
    }
    bg.add_task(_run_workflow_bg, session_id, req)
    return {"session_id": session_id, "status": "running"}


@router.get("/workflow/{session_id}")
async def get_workflow_simulation(session_id: str):
    """Get workflow simulation results."""
    session = WORKFLOW_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


async def _run_workflow_bg(session_id: str, req: WorkflowSimRequest):
    session = WORKFLOW_SESSIONS[session_id]
    try:
        from workflow_simulation_engine import WorkflowSimulationEngine, AttackCategory

        categories = None
        if req.categories:
            try:
                categories = [AttackCategory(c) for c in req.categories]
            except ValueError:
                pass

        engine = WorkflowSimulationEngine(
            base_url=req.base_url,
            session_cookie=req.cookie,
            session_token=req.token,
        )

        workflows = (engine.list_workflows() if req.workflow == "all" else [req.workflow])
        all_findings = []
        results_summary = []

        for wf_name in workflows:
            wf_results = await engine.generate_and_run_attacks(wf_name, categories=categories)
            wf_findings = engine.get_all_findings(wf_results)
            all_findings.extend(wf_findings)
            results_summary.append({
                "workflow":         wf_name,
                "attacks_run":      len(wf_results),
                "vulnerable":       sum(1 for r in wf_results if r.vulnerable),
                "findings_count":   len(wf_findings),
            })

        findings_dicts = []
        for f in all_findings:
            d = vars(f) if hasattr(f, "__dict__") else {}
            if hasattr(d.get("agent_type"), "value"):
                d["agent_type"] = d["agent_type"].value
            findings_dicts.append(d)

        session["findings"]  = findings_dicts
        session["results"]   = results_summary
        session["elapsed_s"] = round(time.time() - session["started_at"], 2)
        session["status"]    = "completed"
    except Exception as exc:
        log.error("Workflow sim error: %s", exc)
        session["status"] = "failed"
        session["error"]  = str(exc)


@router.get("/status")
def swarm_status():
    """Return a quick status summary for the swarm intelligence system."""
    try:
        from agent_swarm_coordinator import get_coordinator
        coord = get_coordinator()
        return {
            "status": "active" if coord else "idle",
            "agents": len(getattr(coord, "_agents", {})),
            "sessions": len(getattr(coord, "_sessions", {})),
        }
    except Exception:
        return {"status": "unavailable", "agents": 0, "sessions": 0}


# ── Registration helper ───────────────────────────────────────────────────────

def register_swarm_routes(app):
    """Call this from main.py to register all swarm intelligence routes."""
    app.include_router(router)
    log.info("[swarm_intel_api] Routes registered: %d endpoints",
             len([r for r in app.routes if "/swarm-intel" in getattr(r, "path", "")]))
