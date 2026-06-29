"""graph_api.py — FastAPI routers for attack graph, discovery, business logic, and swarm."""
from __future__ import annotations
import asyncio
import json
import logging
import sys
import os
import threading as _threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

log = logging.getLogger("oneinfinity.graph_api")

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

# _graph_instances and _graph_lock removed — graph routes now use get_engine() singleton (ECE-02)
_swarm_status: Dict[str, Any] = {}

# ── Graph endpoints ──────────────────────────────────────────────────────────

@graph_router.get("/{target}")
async def get_full_graph(target: str):
    """Return full graph for target (nodes + edges)."""
    try:
        engine = _get_or_create_graph(target)
        if engine is None:
            raise ValueError("engine unavailable")
        # Filter to this target only — the singleton holds all scans' nodes.
        # A node belongs to this target if its label matches, it is a TARGET type,
        # or its properties['target'] matches the requested target.
        def _for_target(n) -> bool:
            if getattr(n, "label", "") == target:
                return True
            t = getattr(n, "properties", {}).get("target", "")
            return t == target or (t and target in t) or (target and t and t in target)

        target_nodes = {n.id: n for n in engine._nodes.values() if _for_target(n)}
        # Include nodes reachable within 2 hops from target nodes
        hop2_ids: set = set(target_nodes)
        for edge in engine._edges.values():
            if edge.source_id in hop2_ids or edge.target_id in hop2_ids:
                hop2_ids.add(edge.source_id)
                hop2_ids.add(edge.target_id)
        nodes = [_serialize_node(engine._nodes[nid])
                 for nid in hop2_ids if nid in engine._nodes]
        edges = [_serialize_edge(e) for e in engine._edges.values()
                 if e.source_id in hop2_ids and e.target_id in hop2_ids]
        return {"target": target, "nodes": nodes, "edges": edges,
                "node_count": len(nodes), "edge_count": len(edges)}
    except Exception:
        return {"target": target, "nodes": [], "edges": [], "node_count": 0, "edge_count": 0}


@graph_router.get("/{target}/attack-paths")
async def get_attack_paths(target: str):
    """Return scored attack paths for *target* using the live engine singleton."""
    import uuid as _uuid
    from urllib.parse import urlparse as _up
    try:
        from oneinfinity.attack_graph_core.graph_engine import NodeType, get_engine
        from oneinfinity.attack_graph_core.graph_query_engine import GraphQueryEngine, AttackPath

        engine = get_engine()
        qe     = GraphQueryEngine(engine)

        # Normalise incoming target to bare hostname (mirrors _push_finding_to_graph).
        parsed   = _up(target if "://" in target else f"https://{target}")
        hostname = parsed.hostname or parsed.netloc.split(":")[0] or target

        # Locate the TARGET node — try exact hostname match first, then
        # substring scan for legacy nodes stored with full-URL labels.
        target_node_id = engine._label_index.get((NodeType.TARGET, hostname))
        if not target_node_id:
            for (ntype, label), nid in engine._label_index.items():
                if ntype == NodeType.TARGET:
                    lbl_host = _up(label if "://" in label else f"https://{label}").hostname or ""
                    if lbl_host == hostname or label == hostname:
                        target_node_id = nid
                        break

        # BFS to IMPACT/EXPLOIT nodes (populated when exploit engine runs).
        paths = qe.find_attack_paths(target_node_id) if target_node_id else []

        # Fallback: build scored single-vulnerability paths from reachable vuln nodes.
        # This covers the common case where only scan findings exist (no exploit nodes).
        if not paths:
            sev_score = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
            if target_node_id:
                # Only vulns reachable from this target's subgraph.
                subgraph = engine.get_subgraph(target_node_id, depth=6)
                node_ids = {n["id"] for n in subgraph.get("nodes", [])}
                vuln_nodes = [engine._nodes[nid] for nid in node_ids
                              if nid in engine._nodes
                              and engine._nodes[nid].node_type == NodeType.VULNERABILITY]
            else:
                # No target node yet — filter globally by hostname match in vuln URL.
                vuln_nodes = [
                    n for n in engine.find_nodes(node_type=NodeType.VULNERABILITY)
                    if hostname in n.label or hostname in n.properties.get("url", "")
                ]
            def _sev(n):
                return n.severity or n.properties.get("severity", "info")
            vuln_nodes.sort(key=lambda n: sev_score.get(_sev(n), 0), reverse=True)
            for v in vuln_nodes[:10]:
                sev   = _sev(v)
                score = sev_score.get(sev, 0.5)
                paths.append(AttackPath(
                    path_id=str(_uuid.uuid4()),
                    nodes=[v],
                    edges=[],
                    total_score=round(score * 0.7, 2),
                    exploitability_score=round(score * 0.4, 2),
                    impact_score=round(score * 0.6, 2),
                    difficulty="easy" if score >= 7 else "medium" if score >= 4 else "hard",
                    entry_point=hostname,
                    final_impact=v.label,
                    description=f"{v.label} ({sev}) — {hostname}",
                ))

        return {"target": target, "paths": [p.to_dict() for p in paths]}
    except Exception:
        log.exception("get_attack_paths failed for %s", target)
        return {"target": target, "paths": []}


@graph_router.get("/{target}/exploit-chains")
async def get_exploit_chains(target: str):
    """Return detected exploit chains."""
    try:
        from oneinfinity.attack_graph_core.exploit_chain_engine import ExploitChainEngine
        engine = _get_or_create_graph(target)
        ece = ExploitChainEngine(engine)
        chains = ece.detect_chains(target)
        return {"target": target, "chains": [c.to_dict() for c in chains]}
    except Exception:
        return {"target": target, "chains": []}


@graph_router.get("/{target}/risk-report")
async def get_risk_report(target: str):
    """Return full risk report for target."""
    try:
        from oneinfinity.attack_graph_core.risk_analyzer import RiskAnalyzer
        from oneinfinity.attack_graph_core.exploit_chain_engine import ExploitChainEngine
        engine = _get_or_create_graph(target)
        ece = ExploitChainEngine(engine)
        ra = RiskAnalyzer(engine, ece)
        report = ra.analyze(target)
        return report.to_dict()
    except Exception:
        return {"target": target, "overall_risk_score": 0.0, "overall_severity": "none", "critical_count": 0, "high_count": 0, "medium_count": 0, "chains_detected": 0, "recommendations": []}


@graph_router.get("/{target}/attack-plan")
async def get_attack_plan(target: str):
    """Return prioritized attack plan."""
    try:
        from oneinfinity.attack_graph_core.attack_planner import AttackPlanner
        engine = _get_or_create_graph(target)
        planner = AttackPlanner(engine)
        plan = planner.plan(target)
        return plan.to_dict()
    except Exception:
        return {"target": target, "actions": [], "total_actions": 0}


@graph_router.get("/{target}/chains")
async def get_attack_chains(target: str):
    """
    Get detected attack chains using GraphChainDetector.

    Returns chains with metadata: nodes, edges, confidence, exploitability, etc.
    """
    try:
        from oneinfinity.attack_graph_core.builder import AttackGraphBuilder
        from oneinfinity.core.db_manager import get_db_manager_sync

        # Build graph from findings
        builder = AttackGraphBuilder(target)

        # Load findings from database
        db = get_db_manager_sync()
        if db:
            builder.from_findings_db()

        # Build with chain detection enabled
        graph = builder.build(detect_chains=True)

        # Extract chains from metadata
        chains = graph.metadata.get("detected_chains", [])
        chain_count = graph.metadata.get("chain_count", 0)
        high_risk_count = graph.metadata.get("high_risk_chains", 0)

        return {
            "target": target,
            "chain_count": chain_count,
            "high_risk_chains": high_risk_count,
            "chains": chains,
        }
    except Exception as e:
        log.warning("Chain detection failed for %s: %s", target, e)
        return {"target": target, "chain_count": 0, "high_risk_chains": 0, "chains": []}


@graph_router.post("/{target}/update")
async def update_graph(target: str, data: Dict[str, Any]):
    """Accept external updates to the graph (from scan engines)."""
    try:
        from oneinfinity.attack_graph_core.graph_updater import GraphUpdater
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
        from oneinfinity.recon.osint_collector import OSINTCollector
        collector = OSINTCollector()
        results = await collector.collect(req.target)
        return {"target": req.target, "results": [r.to_dict() for r in results]}
    except Exception as e:
        return {"target": req.target, "results": [], "error": str(e)}


@discovery_router.post("/correlate")
async def correlate_assets(req: TargetRequest):
    """Correlate IP/domain/cloud assets."""
    try:
        from oneinfinity.intelligence.asset_correlator import AssetCorrelator
        correlator = AssetCorrelator()
        corr = await correlator.correlate(req.target)
        return corr.to_dict()
    except Exception as e:
        return {"domain": req.target, "error": str(e)}


@discovery_router.get("/scope/{platform}/{handle}")
async def get_program_scope(platform: str, handle: str):
    """Fetch program scope from bug bounty platform."""
    try:
        from oneinfinity.recon.program_scope_analyzer import ProgramScopeAnalyzer
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
        from oneinfinity.attack.business_logic_attack_engine import BusinessLogicAttackEngine
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
        from oneinfinity.attack.business_logic_attack_engine import ATTACK_CATEGORIES, RULE_BASED_TEMPLATES
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
        from oneinfinity.infra.task_dispatcher import TaskDispatcher
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
    """Return the global scan-populated AttackGraphEngine singleton.

    Previously this created isolated per-request instances (SHAD-G02), meaning
    graph API routes always returned empty data even after real scans.  The
    singleton is populated by USE _phase_graph_update → brain.integrate_vuln()
    throughout every scan.
    """
    try:
        from oneinfinity.attack_graph_core.graph_engine import get_engine
        return get_engine()
    except Exception:
        # Fallback: create a fresh engine (maintains original behaviour on import error)
        try:
            from oneinfinity.attack_graph_core.graph_engine import AttackGraphEngine
            return AttackGraphEngine()
        except Exception:
            return None


def _serialize_node(node) -> dict:
    props    = getattr(node, "properties", {})
    severity = getattr(node, "severity", None) or props.get("severity")
    return {
        "id":        getattr(node, "id", ""),
        "label":     getattr(node, "label", ""),
        "node_type": str(getattr(node, "node_type", "")).split(".")[-1].lower(),
        "severity":  severity,
        "properties": props,
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
        from oneinfinity.recon.target_discovery_engine import TargetDiscoveryEngine
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
        from oneinfinity.swarm.swarm_scan_cluster import SwarmScanCluster
        cluster = SwarmScanCluster()
        results = await cluster.scan_many(targets, modules=modules or ["recon"])
        _swarm_status[session_id]["results"] = results
        _swarm_status[session_id]["completed"] = len(targets)
        _swarm_status[session_id]["status"] = "completed"
    except Exception as e:
        _swarm_status[session_id]["status"] = "error"
        _swarm_status[session_id]["error"] = str(e)



# ── WebSocket helpers ─────────────────────────────────────────────────────────

async def _dequeue(q: asyncio.Queue) -> Any:
    """Await the next item from *q*; propagates CancelledError cleanly."""
    return await q.get()


def _cleanup_ws_handlers(bus: Any, per_type_handlers: list) -> None:
    """Unsubscribe all per-type handlers registered for a WS session."""
    if bus is None:
        return
    for et, h in per_type_handlers:
        try:
            bus.off(et, h)
        except Exception:
            pass

# ── Registration ─────────────────────────────────────────────────────────────

def register_routers(app, require_auth=None):
    """Call this from main.py: register_routers(app)"""
    deps = [Depends(require_auth)] if require_auth else []
    app.include_router(graph_router, dependencies=deps)
    app.include_router(discovery_router, dependencies=deps)
    app.include_router(bizlogic_router, dependencies=deps)
    app.include_router(swarm_router, dependencies=deps)

    # ── Live attack-graph WebSocket ───────────────────────────────────────────
    @app.websocket("/ws/graph/{target}")
    async def graph_stream_ws(websocket: WebSocket, target: str):
        """Stream live attack graph events for *target* to the React UI.

        Uses EventBus.register_ws_client() which returns an asyncio.Queue fed by
        the bus dispatcher, so sync bus callbacks never block the event loop.

        Protocol (all frames are JSON):
          server→client  {"type": "graph_init", ...}       — initial stats on connect
          server→client  {"type": "heartbeat", "ts": ...}  — keepalive every 30 s
          server→client  {"type": <event_type>, ...}       — forwarded bus events
          client→server  "ping"                            — optional; server echoes pong
        """
        await websocket.accept()

        # ── Import bus + event types (guarded; failures degrade gracefully) ──
        bus = None
        q: asyncio.Queue | None = None
        watched_types: tuple = ()
        try:
            from oneinfinity.orchestration.event_bus import get_bus, EventType
            bus = get_bus()
            q = bus.register_ws_client()
            watched_types = (
                EventType.NEW_GRAPH_NODE,
                EventType.NEW_VULNERABILITY,
                EventType.CHAIN_DETECTED,
                EventType.HYPOTHESIS_CREATED,
            )
        except Exception as _be:
            log.warning("graph_stream_ws: EventBus unavailable: %s", _be)

        # ── Helper: subscribe per-type sync handlers that enqueue events ─────
        # We use the bus.on() sync callback path rather than the wildcard WS
        # queue so we can filter to only the 4 event types we care about.
        # If bus is available we register typed callbacks; otherwise the queue
        # stays None and we only emit heartbeats.
        per_type_handlers: list = []
        # Capture the FastAPI event loop NOW (in the async handler = correct loop).
        # Sync bus callbacks run in the EventBus daemon thread; they must use
        # call_soon_threadsafe to safely enqueue payloads into this loop's Queue.
        _fastapi_loop = asyncio.get_event_loop()
        if bus is not None and q is not None:
            # Unregister the generic ws queue — use targeted per-type callbacks instead.
            bus.unregister_ws_client(q)
            q = asyncio.Queue(maxsize=500)

            for et in watched_types:
                def _make_handler(event_type_val: str, _q: asyncio.Queue = q,
                                  _loop: asyncio.AbstractEventLoop = _fastapi_loop):
                    def _sync_handler(event):
                        try:
                            payload = {
                                "type": event_type_val,
                                "data": event.data if event and event.data else {},
                                "ts": datetime.utcnow().isoformat(),
                            }
                            # target filter — only forward events for our target
                            tgt = (event.data or {}).get("target", "") if event and event.data else ""
                            if tgt and target and tgt != target and target not in tgt and tgt not in target:
                                return
                            # Thread-safe enqueue: bus runs in daemon thread, Queue is
                            # owned by the FastAPI event loop — must use call_soon_threadsafe.
                            if not _q.full():
                                _loop.call_soon_threadsafe(_q.put_nowait, payload)
                        except Exception:
                            pass
                    return _sync_handler

                h = _make_handler(et.value)
                try:
                    from oneinfinity.orchestration.event_bus import EventType
                    bus.on(et, h)
                    per_type_handlers.append((et, h))
                except Exception:
                    pass

        # ── Initial stats snapshot ────────────────────────────────────────────
        try:
            engine = _get_or_create_graph(target)
            if engine is not None:
                all_node_ids: set = set()
                all_edge_ids: set = set()
                for edge in engine._edges.values():
                    all_node_ids.add(edge.source_id)
                    all_node_ids.add(edge.target_id)
                    all_edge_ids.add(id(edge))

                # Top-5 vulnerabilities: nodes whose node_type contains "vuln"
                vuln_nodes = [
                    n for n in engine._nodes.values()
                    if "vuln" in str(getattr(n, "node_type", "")).lower()
                ]
                top_vulns = []
                for n in sorted(
                    vuln_nodes,
                    key=lambda n: float(
                        (getattr(n, "metadata", {}) or {}).get("severity_score", 0) or 0
                    ),
                    reverse=True,
                )[:5]:
                    top_vulns.append({
                        "id": getattr(n, "id", ""),
                        "label": getattr(n, "label", ""),
                        "severity": (getattr(n, "metadata", {}) or {}).get("severity", "unknown"),
                    })

                init_msg = {
                    "type": "graph_init",
                    "target": target,
                    "node_count": len(engine._nodes),
                    "edge_count": len(engine._edges),
                    "top_vulnerabilities": top_vulns,
                    "ts": datetime.utcnow().isoformat(),
                }
            else:
                init_msg = {
                    "type": "graph_init",
                    "target": target,
                    "node_count": 0,
                    "edge_count": 0,
                    "top_vulnerabilities": [],
                    "ts": datetime.utcnow().isoformat(),
                }
            await websocket.send_text(json.dumps(init_msg))
        except (WebSocketDisconnect, RuntimeError):
            # Client already gone
            _cleanup_ws_handlers(bus, per_type_handlers)
            return
        except Exception as _ie:
            log.debug("graph_stream_ws: init snapshot error: %s", _ie)

        # ── Main loop: forward queued events + heartbeat + receive pings ─────
        HEARTBEAT_INTERVAL = 30.0  # seconds
        try:
            while True:
                # Wait up to HEARTBEAT_INTERVAL for an event from the queue;
                # on timeout emit a heartbeat.  receive_text() is checked as a
                # concurrent task so client pings are handled promptly.
                recv_task = asyncio.ensure_future(websocket.receive_text())
                try:
                    event_payload = await asyncio.wait_for(
                        _dequeue(q) if q is not None else asyncio.sleep(HEARTBEAT_INTERVAL),  # type: ignore[arg-type]
                        timeout=HEARTBEAT_INTERVAL,
                    )
                    if q is not None and event_payload is not None:
                        # Serialise and send the event
                        try:
                            await websocket.send_text(json.dumps(event_payload, default=str))
                        except (WebSocketDisconnect, RuntimeError):
                            recv_task.cancel()
                            break
                except asyncio.TimeoutError:
                    # Heartbeat
                    try:
                        await websocket.send_text(
                            json.dumps({"type": "heartbeat", "ts": datetime.utcnow().isoformat()})
                        )
                    except (WebSocketDisconnect, RuntimeError):
                        recv_task.cancel()
                        break

                # Check for client ping (non-blocking)
                if recv_task.done():
                    try:
                        data = recv_task.result()
                        if data == "ping":
                            await websocket.send_text(json.dumps({"type": "pong"}))
                    except Exception:
                        break
                else:
                    recv_task.cancel()

        except (WebSocketDisconnect, RuntimeError):
            pass
        except Exception as _ex:
            log.debug("graph_stream_ws: loop error: %s", _ex)
        finally:
            _cleanup_ws_handlers(bus, per_type_handlers)
            log.debug("graph_stream_ws: disconnected target=%s", target)
