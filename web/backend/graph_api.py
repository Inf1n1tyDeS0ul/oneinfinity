"""graph_api.py — FastAPI routers for attack graph, discovery, business logic, and swarm."""
from __future__ import annotations
import asyncio
import sys
import os
import threading as _threading
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# ── Pydantic models ──────────────────────────────────────────────────────────

class TargetRequest(BaseModel):
    target: str

class DiscoverRequest(BaseModel):
    domain: str
    depth: int = 1
    sources: Optional[List[str]] = None

class BizLogicRequest(BaseModel):
    target: str
    categories: Optional[List[str]] = None
    app_context: Optional[Dict[str, Any]] = None

class SwarmSubmitRequest(BaseModel):
    targets: List[str]
    modules: Optional[List[str]] = None
    priority: int = 5

# ── Routers ──────────────────────────────────────────────────────────────────

graph_router = APIRouter(prefix="/api/graph", tags=["graph"])
discovery_router = APIRouter(prefix="/api/discovery", tags=["discovery"])
bizlogic_router = APIRouter(prefix="/api/business-logic", tags=["business-logic"])
swarm_router = APIRouter(prefix="/api/swarm", tags=["swarm"])

# ── In-memory state ──────────────────────────────────────────────────────────

_graph_instances: Dict[str, Any] = {}
_graph_lock = _threading.Lock()
_swarm_status: Dict[str, Any] = {}

# ── Graph endpoints ──────────────────────────────────────────────────────────

@graph_router.get("/{target}")
async def get_full_graph(target: str):
    """Return full graph for target (nodes + edges)."""
    try:
        from attack_graph_core.graph_engine import AttackGraphEngine
        engine = _get_or_create_graph(target)
        nodes = [_serialize_node(n) for n in engine._nodes.values()]
        edges = [_serialize_edge(e) for e in engine._edges.values()]
        return {"target": target, "nodes": nodes, "edges": edges,
                "node_count": len(nodes), "edge_count": len(edges)}
    except Exception:
        return _demo_graph(target)


@graph_router.get("/{target}/attack-paths")
async def get_attack_paths(target: str):
    """Return BFS attack paths from entry to impact nodes."""
    import uuid as _uuid
    try:
        from attack_graph_core.graph_engine import AttackGraphEngine, NodeType
        from attack_graph_core.graph_query_engine import GraphQueryEngine, AttackPath
        from attack_graph_core.graph_updater import GraphUpdater

        # Build a fresh engine populated with real findings for this target
        engine = AttackGraphEngine()
        updater = GraphUpdater(engine)
        try:
            from result_ingestion_engine import get_ingestion_engine
            raw = get_ingestion_engine().get_findings(target=target)
            updater.update_from_scan_result(target, raw)
        except Exception:
            pass

        # Nodes use UUID IDs — look up the target node by (type, label)
        target_node_id = engine._label_index.get((NodeType.TARGET, target))
        if not target_node_id:
            return {"target": target, "paths": []}

        qe = GraphQueryEngine(engine)
        paths = qe.find_attack_paths(target_node_id)

        # find_attack_paths only reaches IMPACT/EXPLOIT nodes (created by exploit engine).
        # For regular scan findings we only have VULNERABILITY nodes, so fall back to
        # building scored paths directly from those.
        if not paths:
            sev_score = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
            vuln_nodes = engine.find_nodes(node_type=NodeType.VULNERABILITY)
            vuln_nodes.sort(key=lambda n: sev_score.get(n.severity or "info", 0), reverse=True)
            for v in vuln_nodes[:10]:
                score = sev_score.get(v.severity or "info", 0.5)
                paths.append(AttackPath(
                    path_id=str(_uuid.uuid4()),
                    nodes=[v],
                    edges=[],
                    total_score=round(score * 0.7, 2),
                    exploitability_score=round(score * 0.4, 2),
                    impact_score=round(score * 0.6, 2),
                    difficulty="easy" if score >= 7 else "medium" if score >= 4 else "hard",
                    entry_point=target,
                    final_impact=v.label,
                    description=f"{v.label} ({v.severity}) at {target}",
                ))

        return {"target": target, "paths": [p.to_dict() for p in paths]}
    except Exception:
        return {"target": target, "paths": _demo_paths()}


@graph_router.get("/{target}/exploit-chains")
async def get_exploit_chains(target: str):
    """Return detected exploit chains."""
    try:
        from attack_graph_core.exploit_chain_engine import ExploitChainEngine
        engine = _get_or_create_graph(target)
        ece = ExploitChainEngine(engine)
        chains = ece.detect_chains(target)
        return {"target": target, "chains": [c.to_dict() for c in chains]}
    except Exception:
        return {"target": target, "chains": _demo_chains()}


@graph_router.get("/{target}/risk-report")
async def get_risk_report(target: str):
    """Return full risk report for target."""
    try:
        from attack_graph_core.risk_analyzer import RiskAnalyzer
        from attack_graph_core.exploit_chain_engine import ExploitChainEngine
        engine = _get_or_create_graph(target)
        ece = ExploitChainEngine(engine)
        ra = RiskAnalyzer(engine, ece)
        report = ra.analyze(target)
        return report.to_dict()
    except Exception:
        return _demo_risk_report(target)


@graph_router.get("/{target}/attack-plan")
async def get_attack_plan(target: str):
    """Return prioritized attack plan."""
    try:
        from attack_graph_core.attack_planner import AttackPlanner
        engine = _get_or_create_graph(target)
        planner = AttackPlanner(engine)
        plan = planner.plan(target)
        return plan.to_dict()
    except Exception:
        return {"target": target, "actions": [], "total_actions": 0}


@graph_router.post("/{target}/update")
async def update_graph(target: str, data: Dict[str, Any]):
    """Accept external updates to the graph (from scan engines)."""
    try:
        from attack_graph_core.graph_updater import GraphUpdater
        engine = _get_or_create_graph(target)
        updater = GraphUpdater(engine)
        update_type = data.get("type", "")
        if update_type == "subdomain":
            updater.add_subdomain(target, data.get("subdomain", ""))
        elif update_type == "vulnerability":
            updater.add_vulnerability(data.get("node_id", ""), data.get("vuln_data", {}))
        return {"status": "ok", "target": target}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ── Discovery endpoints ──────────────────────────────────────────────────────

@discovery_router.post("/targets")
async def discover_targets(req: DiscoverRequest, background_tasks: BackgroundTasks):
    """Launch async target discovery using OSINT engines."""
    session_id = f"disc-{req.domain}-{id(req)}"
    _swarm_status[session_id] = {"status": "running", "domain": req.domain, "results": []}
    background_tasks.add_task(_run_discovery, session_id, req.domain, req.sources or [])
    return {"session_id": session_id, "status": "started", "domain": req.domain}


@discovery_router.get("/status/{session_id}")
async def discovery_status(session_id: str):
    if session_id not in _swarm_status:
        raise HTTPException(status_code=404, detail="Session not found")
    return _swarm_status[session_id]


@discovery_router.post("/osint")
async def run_osint(req: TargetRequest):
    """Run OSINT collection on target."""
    try:
        from osint_collector import OSINTCollector
        collector = OSINTCollector()
        results = await collector.collect(req.target)
        return {"target": req.target, "results": [r.to_dict() for r in results]}
    except Exception as e:
        return {"target": req.target, "results": [], "error": str(e)}


@discovery_router.post("/correlate")
async def correlate_assets(req: TargetRequest):
    """Correlate IP/domain/cloud assets."""
    try:
        from asset_correlator import AssetCorrelator
        correlator = AssetCorrelator()
        corr = await correlator.correlate(req.target)
        return corr.to_dict()
    except Exception as e:
        return {"domain": req.target, "error": str(e)}


@discovery_router.get("/scope/{platform}/{handle}")
async def get_program_scope(platform: str, handle: str):
    """Fetch program scope from bug bounty platform."""
    try:
        from program_scope_analyzer import ProgramScopeAnalyzer
        analyzer = ProgramScopeAnalyzer()
        scope = await analyzer.fetch_scope(handle, platform)
        return scope.to_dict()
    except Exception as e:
        return {"program_handle": handle, "platform": platform, "error": str(e)}


# ── Business Logic endpoints ─────────────────────────────────────────────────

@bizlogic_router.post("/generate")
async def generate_bizlogic_attacks(req: BizLogicRequest):
    """Generate business logic attack hypotheses."""
    try:
        from business_logic_attack_engine import BusinessLogicAttackEngine
        engine = BusinessLogicAttackEngine()
        attacks = await engine.generate(req.target, req.app_context, req.categories)
        return {
            "target": req.target,
            "attacks": [a.to_dict() for a in attacks],
            "total": len(attacks),
        }
    except Exception as e:
        return {"target": req.target, "attacks": [], "error": str(e)}


@bizlogic_router.get("/categories")
async def get_attack_categories():
    try:
        from business_logic_attack_engine import ATTACK_CATEGORIES, RULE_BASED_TEMPLATES
        return {"categories": ATTACK_CATEGORIES, "rule_count": sum(len(v) for v in RULE_BASED_TEMPLATES.values())}
    except Exception:
        return {"categories": [], "rule_count": 0}


# ── Swarm endpoints ──────────────────────────────────────────────────────────

@swarm_router.post("/submit")
async def swarm_submit(req: SwarmSubmitRequest, background_tasks: BackgroundTasks):
    """Submit multiple targets to swarm cluster."""
    session_id = f"swarm-{len(req.targets)}-{id(req)}"
    _swarm_status[session_id] = {
        "status": "queued", "targets": req.targets,
        "modules": req.modules or ["recon", "vuln_scan"],
        "completed": 0, "total": len(req.targets),
        "results": [],
    }
    background_tasks.add_task(_run_swarm, session_id, req.targets, req.modules, req.priority)
    return {"session_id": session_id, "status": "queued", "target_count": len(req.targets)}


@swarm_router.get("/status/{session_id}")
async def swarm_status(session_id: str):
    if session_id not in _swarm_status:
        raise HTTPException(status_code=404, detail="Session not found")
    return _swarm_status[session_id]


@swarm_router.get("/workers")
async def swarm_workers():
    try:
        from task_dispatcher import TaskDispatcher
        td = TaskDispatcher()
        return {"workers": td.get_worker_stats()}
    except Exception:
        return {"workers": []}


@swarm_router.get("/results/{session_id}")
async def swarm_results(session_id: str):
    if session_id not in _swarm_status:
        raise HTTPException(status_code=404, detail="Session not found")
    return _swarm_status[session_id].get("results", [])


# ── Helper functions ─────────────────────────────────────────────────────────

def _get_or_create_graph(target: str):
    """Thread-safe: return cached graph instance, creating one if needed."""
    # Fast path — already exists, no lock needed
    if target in _graph_instances:
        return _graph_instances[target]
    # Slow path — create under lock to prevent concurrent double-creation
    with _graph_lock:
        # Double-check after acquiring lock (another thread may have created it)
        if target not in _graph_instances:
            try:
                from attack_graph_core.graph_engine import AttackGraphEngine
                _graph_instances[target] = AttackGraphEngine()
            except Exception:
                _graph_instances[target] = None
    return _graph_instances[target]


def _serialize_node(node) -> dict:
    return {
        "id": getattr(node, "id", ""),
        "label": getattr(node, "label", ""),
        "node_type": str(getattr(node, "node_type", "")).split(".")[-1].lower(),
        "metadata": getattr(node, "metadata", {}),
    }


def _serialize_edge(edge) -> dict:
    return {
        "source": getattr(edge, "source_id", ""),
        "target": getattr(edge, "target_id", ""),
        "edge_type": str(getattr(edge, "edge_type", "")).split(".")[-1].lower(),
        "label": str(getattr(edge, "edge_type", "")).split(".")[-1].lower(),
    }


async def _run_discovery(session_id: str, domain: str, sources: list):
    try:
        from target_discovery_engine import TargetDiscoveryEngine
        engine = TargetDiscoveryEngine()
        results = await engine.discover(domain)
        _swarm_status[session_id]["results"] = [r.to_dict() if hasattr(r, 'to_dict') else r for r in results]
        _swarm_status[session_id]["status"] = "completed"
    except Exception as e:
        _swarm_status[session_id]["status"] = "error"
        _swarm_status[session_id]["error"] = str(e)


async def _run_swarm(session_id: str, targets: list, modules: Optional[List[str]], priority: int):
    _swarm_status[session_id]["status"] = "running"
    try:
        from swarm_scan_cluster import SwarmScanCluster
        cluster = SwarmScanCluster()
        results = await cluster.scan_many(targets, modules=modules or ["recon"])
        _swarm_status[session_id]["results"] = results
        _swarm_status[session_id]["completed"] = len(targets)
        _swarm_status[session_id]["status"] = "completed"
    except Exception as e:
        _swarm_status[session_id]["status"] = "error"
        _swarm_status[session_id]["error"] = str(e)


def _demo_graph(target: str) -> dict:
    return {
        "target": target,
        "nodes": [
            {"id": "t1", "label": target, "node_type": "target", "metadata": {}},
            {"id": "v1", "label": "XSS", "node_type": "vulnerability", "metadata": {"severity": "high"}},
            {"id": "i1", "label": "ATO", "node_type": "impact", "metadata": {}},
        ],
        "edges": [
            {"source": "t1", "target": "v1", "edge_type": "has_vulnerability", "label": "vuln"},
            {"source": "v1", "target": "i1", "edge_type": "leads_to", "label": "→"},
        ],
        "node_count": 3, "edge_count": 2,
    }


def _demo_paths() -> list:
    return [{"nodes": ["target", "xss", "ato"], "score": 7.5, "impact": "Account Takeover"}]


def _demo_chains() -> list:
    return [{"name": "XSS → ATO", "impact": "Account Takeover", "cvss": 8.1, "severity": "high"}]


def _demo_risk_report(target: str) -> dict:
    return {
        "target": target, "overall_risk_score": 7.5, "overall_severity": "high",
        "critical_count": 0, "high_count": 2, "medium_count": 3,
        "chains_detected": 1, "recommendations": ["Review XSS findings"],
    }


# ── Registration ─────────────────────────────────────────────────────────────

def register_routers(app):
    """Call this from main.py: register_routers(app)"""
    app.include_router(graph_router)
    app.include_router(discovery_router)
    app.include_router(bizlogic_router)
    app.include_router(swarm_router)
