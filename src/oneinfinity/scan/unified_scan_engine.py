"""
unified_scan_engine.py — Central 9-Phase Autonomous Scan Pipeline

Orchestrates a full security assessment for a given target, progressing through:
  1. classify     — detect target type (web / api / mobile / ai)
  2. recon        — adaptive reconnaissance (subfinder, httpx, katana, waybackurls)
  3. graph_update — push recon results into the attack graph brain
  4. agent_trigger — determine which agents to invoke based on graph nodes
  5. vuln_scan    — nuclei + dalfox + sqlmap driven by agent decisions
  6. exploit_validation — validate confirmed findings for false-positive reduction
  7. result_ingest — push all findings to result ingestion layer
  8. report       — generate human-readable report
  9. done         — finalise, persist ScanSession to SQLite

Usage::

    engine = get_engine()
    session = engine.scan("https://example.com", on_progress=my_callback)
    print(session.status, len(session.findings))

Progress callback signature::

    def on_progress(phase: str, pct: int, msg: str) -> None: ...
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from oneinfinity.infra.path_manager import db_path, get_target_path, raw_dir, resolve_output_dir

log = logging.getLogger("oneinfinity.unified_scan_engine")

# ---------------------------------------------------------------------------
# Phase ordering & percentage milestones
# ---------------------------------------------------------------------------

_PHASES: List[str] = [
    "classify",
    "recon",
    "graph_update",
    "agent_trigger",
    "oob_init",           # NEW: start OOB callback listener
    "auth_setup",         # NEW: configure authenticated sessions
    "business_logic",     # NEW: business logic attack surface enumeration (canonical phase 6)
    "vuln_scan",
    "graphql_scan",       # NEW: GraphQL endpoint detection + security testing
    "browser_analysis",   # NEW: headless browser DOM/JS/XSS analysis
    "smuggling_test",     # NEW: HTTP request smuggling detection
    "exploit_validation",
    "exploit_chaining",
    "result_ingest",
    "severity_followup",
    "graph_vuln_update",
    "report",
    "done",
]

_PHASE_PCT: Dict[str, int] = {
    "classify":           4,
    "recon":             20,
    "graph_update":      28,
    "agent_trigger":     34,
    "oob_init":          37,
    "auth_setup":        40,
    "business_logic":    47,
    "vuln_scan":         54,
    "graphql_scan":      60,
    "browser_analysis":  66,
    "smuggling_test":    70,
    "exploit_validation": 76,
    "exploit_chaining":  82,
    "result_ingest":     86,
    "severity_followup": 90,
    "graph_vuln_update": 94,
    "report":            97,
    "done":             100,
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PhaseResult:
    """Records outcome of a single pipeline phase."""
    name: str
    status: str = "pending"   # pending | running | completed | failed | skipped
    started_at: float = 0.0
    ended_at: float = 0.0
    error: str = ""
    meta: Dict = field(default_factory=dict)
    degraded: bool = False
    degraded_reason: str = ""


@dataclass
class ScanSession:
    """Full state of a single autonomous scan run."""
    scan_id: str
    target: str
    target_type: str = "web"           # web | api | mobile | ai
    status: str = "pending"            # pending | running | completed | failed
    phases: Dict[str, PhaseResult] = field(default_factory=dict)
    start_time: float = 0.0
    end_time: float = 0.0
    findings: List[dict] = field(default_factory=list)
    error: str = ""

    # ── Convenience helpers ──────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "target_type": self.target_type,
            "status": self.status,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "findings_count": len(self.findings),
            "error": self.error,
            "phases": {
                name: {
                    "status": pr.status,
                    "error": pr.error,
                    "duration_s": round(pr.ended_at - pr.started_at, 2) if pr.ended_at else None,
                }
                for name, pr in self.phases.items()
            },
        }


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _require_pg():
    """Return DBManager in PG mode, or raise if unavailable."""
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            return mgr
    except Exception as exc:
        raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
    raise RuntimeError(
        "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
    )


def _persist_session(session: ScanSession) -> None:
    """Write (upsert) the session record to PostgreSQL."""
    try:
        pg = _require_pg()
        phases_json = json.dumps(
            {n: {"status": pr.status, "error": pr.error} for n, pr in session.phases.items()}
        )
        data_json = json.dumps({
            "target_type":    session.target_type,
            "start_time":     session.start_time,
            "end_time":       session.end_time,
            "findings_count": len(session.findings),
            "phases":         phases_json,
            "error":          session.error,
        })
        pg.sync_pg_execute_write(
            """
            INSERT INTO scans (scan_id, target, scan_type, status, data)
            VALUES (%s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (scan_id) DO UPDATE SET
                status = EXCLUDED.status,
                data   = EXCLUDED.data
            """,
            (session.scan_id, session.target, session.target_type,
             session.status, data_json),
        )
    except Exception as exc:
        log.warning("Failed to persist scan session %s: %s", session.scan_id, exc)


# ---------------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------------

def _classify_target(target: str) -> str:
    """
    Heuristically determine the target type from its URL/domain string.

    Rules (first match wins):
      - ends with .apk or .ipa              → mobile
      - path contains /api/ or /graphql     → api
      - domain contains 'chat', 'llm', 'gpt' → ai
      - otherwise                            → web
    """
    lowered = target.lower()
    if lowered.endswith(".apk") or lowered.endswith(".ipa"):
        return "mobile"
    # Extract just the path portion for API checks
    path_part = ""
    if "://" in lowered:
        path_part = lowered.split("://", 1)[1]
        if "/" in path_part:
            path_part = "/" + path_part.split("/", 1)[1]
    else:
        path_part = "/" + lowered.split("/", 1)[1] if "/" in lowered else ""
    if "/api/" in path_part or "/graphql" in path_part:
        return "api"
    # Extract domain for AI checks
    domain = lowered
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]
    if any(kw in domain for kw in ("chat", "llm", "gpt")):
        return "ai"
    return "web"


# ---------------------------------------------------------------------------
# UnifiedScanEngine
# ---------------------------------------------------------------------------

from oneinfinity.core.safety import safety_guard

# Module-level buffer: AI response-analysis signals written from _run_tool_safe,
# drained into ctx["loop_history"]["ai_signals"] in _phase_vuln_scan.
_AI_SIGNAL_BUFFER: List[dict] = []

WAF_STATS = {
    "detections": 0,
    "mutations": 0,
    "successes": 0,
    "by_type": {}
}

CHAIN_CONTEXTS = {}

class UnifiedScanEngine:
    """
    Central 9-phase autonomous scan pipeline.

    Thread-safe: each scan runs in its own thread; a stop flag allows
    graceful early termination.
    """

    def __init__(self) -> None:
        self._active: Dict[str, threading.Event] = {}   # scan_id → stop event
        self._lock = threading.Lock()
        self._threads: Dict[str, threading.Thread] = {}
        self._sessions: Dict[str, ScanSession] = {}

    # ── Public API ───────────────────────────────────────────────────────────

    def scan(
        self,
        target: str,
        on_progress: Optional[Callable[[str, int, str], None]] = None,
    ) -> ScanSession:
        """
        Execute a full 9-phase scan against *target* synchronously.

        Parameters
        ----------
        target:
            URL or domain to scan.
        on_progress:
            Optional callback invoked as ``on_progress(phase, pct, msg)``.
            Exceptions raised inside the callback are suppressed.

        Returns
        -------
        ScanSession
            Completed (or failed) session object.
        """
        session = self.scan_async(target, on_progress=on_progress)
        thread = None
        with self._lock:
            thread = self._threads.get(session.scan_id)
        if thread:
            thread.join()
        return session

    def scan_async(
        self,
        target: str,
        on_progress: Optional[Callable[[str, int, str], None]] = None,
    ) -> ScanSession:
        """Start a scan in a background thread and return the live session."""
        scan_id = str(uuid.uuid4())
        session = ScanSession(
            scan_id=scan_id,
            target=target,
            start_time=time.time(),
            status="running",
            phases={name: PhaseResult(name=name) for name in _PHASES},
        )
        stop_event = threading.Event()
        with self._lock:
            self._active[scan_id] = stop_event
            self._sessions[scan_id] = session

        _persist_session(session)
        log.info("Scan %s started for target: %s", scan_id, target)

        thread = threading.Thread(
            target=self._execute_scan,
            args=(session, stop_event, on_progress),
            daemon=True,
            name=f"scan-{scan_id}",
        )
        with self._lock:
            self._threads[scan_id] = thread
        thread.start()
        return session

    def _execute_scan(
        self,
        session: ScanSession,
        stop_event: threading.Event,
        on_progress: Optional[Callable[[str, int, str], None]],
    ) -> None:
        scan_id = session.scan_id
        try:
            self._run_pipeline(session, stop_event, on_progress)
        except Exception as exc:
            log.exception("Unhandled error in scan pipeline %s: %s", scan_id, exc)
            session.status = "failed"
            session.error = str(exc)
        finally:
            session.end_time = time.time()
            if session.status == "running":
                session.status = "completed"
            with self._lock:
                self._active.pop(scan_id, None)
                self._threads.pop(scan_id, None)
            _persist_session(session)
            log.info(
                "Scan %s finished with status=%s, findings=%d",
                scan_id, session.status, len(session.findings),
            )

    def stop(self, scan_id: str) -> bool:
        """
        Request graceful stop for an active scan.

        Returns True if the scan was found and signalled, False otherwise.
        """
        with self._lock:
            event = self._active.get(scan_id)
        if event:
            event.set()
            log.info("Stop requested for scan %s", scan_id)
            return True
        log.warning("stop() called for unknown scan_id %s", scan_id)
        return False

    # ── Internal pipeline ────────────────────────────────────────────────────

    def _run_pipeline(
        self,
        session: ScanSession,
        stop: threading.Event,
        cb: Optional[Callable[[str, int, str], None]],
    ) -> None:
        """Execute phases in order, stopping early if stop is set."""
        # Shared context passed between phases
        ctx: dict = {
            "recon_intel": None,       # ReconIntelligence object
            "graph_brain": None,       # AttackGraphBrain instance
            "agent_plan": [],          # list of agent-type strings
            "tool_registry": None,     # ToolRegistry instance
            "scan_findings": [],       # raw dicts from tools
            "validated_findings": [],  # post-validation findings
            "target_type": None,
            # ── Intelligence layer ──────────────────────────────
            "kb": None,                # KnowledgeBase instance
            "kb_session_id": None,     # KB session ID for this scan
            "decision_engine": None,   # AutonomousDecisionEngine
            "pattern_insight": None,   # PatternMiner TargetInsight
            # ── Stealth layer ───────────────────────────────────
            "stealth_session": None,   # StealthSession for all outbound requests
            # ── Cross-run learning ──────────────────────────────
            "persistent_memory": None, # PersistentMemory loaded at scan start
        }

        # ── Load stealth session ────────────────────────────────────────────
        try:
            from oneinfinity.core.stealth_engine import get_stealth_session
            ctx["stealth_session"] = get_stealth_session()
            log.info("Stealth session loaded for scan %s", session.scan_id)
        except Exception as exc:
            log.warning("StealthSession unavailable (non-fatal): %s", exc)

        # ── Load persistent memory ──────────────────────────────────────────
        try:
            from oneinfinity.learning.persistent_memory import load_memory, get_memory
            load_memory()
            mem = get_memory()
            ctx["persistent_memory"] = mem
            mem_ctx = mem.to_ctx()
            ctx.update(mem_ctx)
            log.info(
                "PersistentMemory loaded: %d successful payloads, %d patterns",
                len(mem._data.get("successful_payloads", [])),
                len(mem._data.get("vulnerable_patterns", [])),
            )
        except Exception as exc:
            log.warning("PersistentMemory unavailable (non-fatal): %s", exc)

        phase_fns = {
            "classify":            self._phase_classify,
            "recon":               self._phase_recon,
            "graph_update":        self._phase_graph_update,
            "agent_trigger":       self._phase_agent_trigger,
            "oob_init":            self._phase_oob_init,
            "auth_setup":          self._phase_auth_setup,
            "business_logic":      self._phase_business_logic,
            "vuln_scan":           self._phase_vuln_scan,
            "graphql_scan":        self._phase_graphql_scan,
            "browser_analysis":    self._phase_browser_analysis,
            "smuggling_test":      self._phase_smuggling_test,
            "exploit_validation":  self._phase_exploit_validation,
            "exploit_chaining":    self._phase_exploit_chaining,
            "result_ingest":       self._phase_result_ingest,
            "severity_followup":   self._phase_severity_followup,
            "graph_vuln_update":   self._phase_graph_vuln_update,
            "report":              self._phase_report,
            "done":                self._phase_done,
        }

        fatal_phases = {
            "classify",
            "recon",
        }

        ingest_ran = False
        abort_early = False

        for phase_name in _PHASES:
            if stop.is_set():
                log.info("Scan %s stopped before phase '%s'", session.scan_id, phase_name)
                session.status = "failed"
                session.error = "Scan stopped by user request"
                abort_early = True
                break

            pr = session.phases[phase_name]
            pr.status = "running"
            pr.started_at = time.time()
            pct = _PHASE_PCT[phase_name]

            log.info("Phase start: %s (scan=%s target=%s)", phase_name, session.scan_id, session.target)
            self._emit(cb, phase_name, max(pct - 1, 0), f"Starting phase: {phase_name}")
            _persist_session(session)

            try:
                phase_fn = phase_fns[phase_name]
                if phase_name == "result_ingest":
                    ingest_ran = True
                phase_fn(session, ctx)
                pr.status = "completed"
                log.info("Phase success: %s (scan=%s)", phase_name, session.scan_id)
                self._emit(cb, phase_name, pct, f"Phase completed: {phase_name}")
            except Exception as exc:
                pr.status = "failed"
                pr.error = str(exc)
                log.error("Phase failure: %s (scan=%s): %s", phase_name, session.scan_id, exc)
                self._emit(cb, phase_name, pct, f"Phase failed: {phase_name} — {exc}")
                # Non-fatal phases: continue; fatal phases: abort
                if phase_name in fatal_phases:
                    session.status = "failed"
                    session.error = f"Phase '{phase_name}' failed: {exc}"
                    abort_early = True
                    break
            finally:
                pr.ended_at = time.time()

        if abort_early and not ingest_ran:
            pr = session.phases.get("result_ingest")
            if pr:
                pr.status = "running"
                pr.started_at = time.time()
            try:
                log.info("Running result_ingest after early failure (scan=%s)", session.scan_id)
                self._phase_result_ingest(session, ctx)
                if pr:
                    pr.status = "completed"
                    pr.ended_at = time.time()
            except Exception as exc:
                if pr:
                    pr.status = "failed"
                    pr.error = str(exc)
                    pr.ended_at = time.time()
                log.error("Post-failure result_ingest failed (scan=%s): %s", session.scan_id, exc)

    # ── Phase implementations ────────────────────────────────────────────────

    def _phase_classify(self, session: ScanSession, ctx: dict) -> None:
        """Detect target type from URL patterns."""
        t_type = _classify_target(session.target)
        session.target_type = t_type
        ctx["target_type"] = t_type
        log.info("Classified target '%s' as type: %s", session.target, t_type)
        session.phases["classify"].meta["target_type"] = t_type

    def _phase_recon(self, session: ScanSession, ctx: dict) -> None:
        """Run adaptive recon: subfinder → httpx → katana → waybackurls."""
        try:
            from oneinfinity.recon.adaptive_recon_engine import AdaptiveReconEngine
        except ImportError as exc:
            raise RuntimeError("adaptive_recon_engine is unavailable: " + str(exc)) from exc

        try:
            from oneinfinity.modules.tool_wrappers import ToolRegistry
            ctx["tool_registry"] = ToolRegistry()
        except ImportError as exc:
            log.warning("ToolRegistry unavailable, continuing without it: %s", exc)

        output_dir = get_target_path(session.target, subdir="recon")
        engine = AdaptiveReconEngine(
            target=session.target,
            output_dir=str(output_dir),
            depth="standard",
            tool_registry=ctx.get("tool_registry"),
        )
        intel = engine.run()
        ctx["recon_intel"] = intel

        # Extract data from intel
        subdomains = getattr(intel, "subdomains", []) or []
        urls = intel.all_urls
        log.info(
            "Recon complete for %s: %d subdomains, %d URLs",
            session.target, len(subdomains), len(urls),
        )
        session.phases["recon"].meta.update({
            "subdomains": len(subdomains),
            "urls": len(urls),
        })

        # Persist recon assets (best-effort)
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            eng = get_ingestion_engine()
            scan_id = session.scan_id

            for sub in subdomains[:2000]:
                if sub:
                    eng.ingest_recon_asset(scan_id, "subdomain", sub, {"source": "adaptive_recon"})

            for url in urls[:1000]:
                if url:
                    eng.ingest_recon_asset(scan_id, "url", url, {"source": "adaptive_recon"})

            techs = getattr(intel, "technologies", []) or []
            for t in techs[:200]:
                if t:
                    eng.ingest_recon_asset(scan_id, "technology", t, {"source": "adaptive_recon"})
        except Exception as exc:
            log.warning("Recon asset ingestion failed: %s", exc)

        # ── Priority 2: Knowledge Base — start session + target profile ────
        try:
            from oneinfinity.core.learning_repository import get_learning_repo_sync
            from urllib.parse import urlparse as _urlparse
            kb = get_learning_repo_sync()
            ctx["kb"] = kb
            ctx["kb_session_id"] = session.scan_id
            kb.start_session_sync(
                session_id=session.scan_id,
                target=session.target,
                phases=list(_PHASES),
            )
            domain = _urlparse(session.target).netloc or session.target
            prior = kb.get_target_profile_sync(domain)
            if prior:
                log.info("KB: prior profile found for %s — waf=%s", domain, prior.get("waf"))
            # Refresh tech profile in KB
            tech_stack = getattr(intel.tech_profile, "raw_tech", []) or []
            kb.upsert_target_profile_sync(domain, tech_stack=tech_stack)
        except Exception as exc:
            log.warning("KnowledgeBase init failed (non-fatal): %s", exc)

        # ── Priority 3: Pattern Miner — predict likely vulns from tech stack ─
        try:
            from oneinfinity.learning.pattern_miner import PatternMiner
            kb = ctx.get("kb")
            if kb:
                pm = PatternMiner(kb)
                tech_stack = getattr(intel.tech_profile, "raw_tech", []) or []
                insight = pm.predict_for_target(session.target, tech_stack)
                ctx["pattern_insight"] = insight
                log.info(
                    "PatternMiner: priority=%s suggested=%s predicted_vulns=%d",
                    insight.scan_priority,
                    insight.suggested_tools[:3],
                    len(insight.predicted_vulns),
                )
                session.phases["recon"].meta["scan_priority"] = insight.scan_priority
        except Exception as exc:
            log.warning("PatternMiner prediction failed (non-fatal): %s", exc)

        # ── Fix 5: Graph Enrichment — PARAMETER + API_ENDPOINT + AUTH_ENDPOINT
        _AUTH_PATH_PATTERNS = re.compile(
            r"/(login|signin|auth|oauth|sso|admin|account|session|password|"
            r"register|signup|token|logout|2fa|mfa|saml|oidc)(/|$|\?)",
            re.IGNORECASE,
        )
        try:
            from urllib.parse import urlparse as _up, parse_qs as _pqs
            brain = ctx.get("graph_brain")
            if brain:
                param_added = 0
                api_added = 0
                auth_added = 0
                seen_params: set = set()
                seen_auth: set = set()

                for _url in (intel.all_urls or [])[:500]:
                    _p = _up(_url)
                    # PARAMETER nodes
                    for _pname in _pqs(_p.query):
                        _key = f"{_p.netloc}{_p.path}:{_pname}"
                        if _key not in seen_params:
                            seen_params.add(_key)
                            try:
                                brain.add_node(
                                    label=_pname,
                                    node_type="PARAMETER",
                                    url=_url,
                                    properties={"endpoint": _p.path, "param": _pname},
                                )
                                param_added += 1
                            except Exception as _exc:
                                log.warning('Non-fatal exception suppressed: %s', _exc)
                    # AUTH_ENDPOINT nodes
                    if _AUTH_PATH_PATTERNS.search(_p.path) and _url not in seen_auth:
                        seen_auth.add(_url)
                        try:
                            brain.add_node(
                                label=_p.path,
                                node_type="AUTH_ENDPOINT",
                                url=_url,
                                properties={"type": "auth", "auth_required": True},
                            )
                            auth_added += 1
                        except Exception as _exc:
                            log.warning('Non-fatal exception suppressed: %s', _exc)

                # Also add auth endpoints from alive hosts
                for _host in (getattr(intel, "alive_hosts", []) or [])[:50]:
                    _base = _host.get("url", "")
                    for _apath in ("/login", "/auth", "/admin", "/account",
                                   "/signin", "/oauth/token", "/api/auth"):
                        _aurl = _base.rstrip("/") + _apath
                        if _aurl not in seen_auth:
                            seen_auth.add(_aurl)
                            try:
                                brain.add_node(
                                    label=_apath,
                                    node_type="AUTH_ENDPOINT",
                                    url=_aurl,
                                    properties={"type": "auth_probe", "auth_required": True},
                                )
                                auth_added += 1
                            except Exception as _exc:
                                log.warning('Non-fatal exception suppressed: %s', _exc)

                # API_ENDPOINT nodes
                api_map = getattr(intel, "api_map", None)
                for _bp in (getattr(api_map, "base_paths", []) or [])[:100]:
                    try:
                        brain.add_node(
                            label=_bp,
                            node_type="API_ENDPOINT",
                            url=f"{session.target.rstrip('/')}/{_bp.lstrip('/')}",
                            properties={"type": "api"},
                        )
                        api_added += 1
                    except Exception as _exc:
                        log.warning('Non-fatal exception suppressed: %s', _exc)

                log.info(
                    "Graph enrichment: +%d PARAMETER, +%d API_ENDPOINT, +%d AUTH_ENDPOINT nodes",
                    param_added, api_added, auth_added,
                )
                session.phases["recon"].meta.update({
                    "graph_params": param_added,
                    "graph_api": api_added,
                    "graph_auth": auth_added,
                })
        except Exception as exc:
            log.debug("Graph enrichment failed (non-fatal): %s", exc)

    def _phase_graph_update(self, session: ScanSession, ctx: dict) -> None:
        """Push recon findings into the attack graph brain with explicit edge types."""
        try:
            from oneinfinity.attack_graph_brain import get_brain
        except ImportError as exc:
            raise RuntimeError("AttackGraphBrain unavailable: " + str(exc)) from exc

        brain = get_brain()
        brain.add_target(session.target)
        ctx["graph_brain"] = brain

        # FIX 5: Cross-run graph memory — the global engine already uses SQLiteStore
        # (get_engine() initialises GraphStore which loads previous run data on startup).
        # Log how much historical data was loaded from the persistent store.
        try:
            eng = brain._get_engine()
            stats = eng.get_stats()
            prev_nodes = stats.get("total_nodes", 0)
            prev_edges = stats.get("total_edges", 0)
            if prev_nodes > 0:
                log.info(
                    "[GRAPH-MEMORY] Loaded %d nodes, %d edges from previous run(s) "
                    "(cross-run memory active)",
                    prev_nodes, prev_edges,
                )
        except Exception as _exc:
            log.warning('Non-fatal exception suppressed: %s', _exc)

        intel = ctx.get("recon_intel")
        if intel is None:
            log.warning("No recon intel available for graph_update")
            return

        try:
            from oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
            eng = brain._get_engine()
        except Exception:
            eng = None

        # Resolve the root TARGET node id for edge wiring
        target_node_id = None
        if eng is not None:
            target_node_id = eng._label_index.get((NodeType.TARGET, session.target))

        subdomains = getattr(intel, "subdomains", []) or []
        for sub in subdomains:
            try:
                sub_node_id = brain.integrate_node(
                    "SUBDOMAIN", sub, session.target, properties={"domain": sub}
                )
                # TARGET --[HOSTS]--> SUBDOMAIN
                if eng is not None and target_node_id and sub_node_id:
                    eng.add_edge(target_node_id, sub_node_id, EdgeType.HOSTS,
                                 label="hosts", probability=1.0)
            except Exception as exc:
                log.debug("graph_update: failed to integrate subdomain %s: %s", sub, exc)

        # Build a subdomain→node_id lookup for URL → subdomain parent wiring
        sub_index: dict = {}
        if eng is not None:
            for sub in subdomains:
                nid = eng._label_index.get((NodeType.SUBDOMAIN, sub))
                if nid:
                    sub_index[sub] = nid

        from urllib.parse import urlparse as _urlparse
        from oneinfinity.attack_graph_core.graph_updater import GraphUpdater as _GU
        urls = getattr(intel, "all_urls", []) or []
        if eng is not None:
            # GraphUpdater.add_url creates-or-retrieves the URL node and wires
            # HAS_ENDPOINT. Requires the same engine instance brain uses.
            _local_updater = _GU(engine=eng)
            for url in urls[:500]:   # cap to avoid graph bloat
                try:
                    parsed = _urlparse(url)
                    parent_domain = parsed.netloc or session.target
                    _local_updater.add_url(url, parent_domain)
                except Exception as exc:
                    log.debug("graph_update: failed to integrate url %s: %s", url, exc)

        log.info(
            "Graph updated for %s: %d subdomains, %d URLs ingested (explicit edges wired)",
            session.target, len(subdomains), min(len(urls), 500),
        )

    # Map decision engine agent_type strings → concrete tool names
    _AGENT_TO_TOOL: Dict[str, str] = {
        "xss_agent":    "dalfox",
        "sqli_agent":   "sqlmap",
        "nuclei_agent": "nuclei",
        "ssrf_agent":   "nuclei",
        "auth_agent":   "nuclei",
        "idor_agent":   "nuclei",
        "api_agent":    "nuclei",
        "lfi_agent":    "nuclei",
        "rce_agent":    "nuclei",
        "ai_agent":     "garak",
        "cmdi_agent":   "nuclei",
        "xssstrike":    "xssstrike",
        "commix":       "commix",
    }

    def _phase_agent_trigger(self, session: ScanSession, ctx: dict) -> None:
        """Decide which scan agents to invoke — rule-driven + decision engine + KB."""
        from urllib.parse import urlparse, parse_qs

        intel = ctx.get("recon_intel")
        t_type = getattr(session, "target_type", "web") or "web"
        brain = ctx.get("graph_brain")

        # ── Build params_map {url: [param_names]} from all discovered URLs ──
        params_map: Dict[str, List[str]] = {}
        all_urls: List[str] = getattr(intel, "all_urls", []) or [] if intel else []
        for _u in all_urls:
            try:
                _qs = parse_qs(urlparse(_u).query)
                if _qs:
                    params_map[_u] = list(_qs.keys())
            except Exception as _exc:
                log.warning('Non-fatal exception suppressed: %s', _exc)
        ctx["params_map"] = params_map
        log.info("params_map built: %d parameterized URLs", len(params_map))

        # ── Set-based plan — rules always included, no duplicates ────────────
        plan_set: set = set()

        # ── RULE 1: PARAMETER → INJECTION (unconditional) ────────────────────
        if params_map or any("?" in u for u in all_urls):
            plan_set.add("dalfox")
            plan_set.add("sqlmap")
            log.info("[RULE-1] Parameterized URLs found → dalfox + sqlmap enforced")

        # ── RULE 2: API → API_FUZZ (REST or GraphQL endpoints detected) ──────
        api_map = getattr(intel, "api_map", None) if intel else None
        if api_map and (getattr(api_map, "has_rest", False) or getattr(api_map, "has_graphql", False)):
            plan_set.add("kiterunner")
            plan_set.add("nuclei")
            log.info("[RULE-2] API endpoints detected → kiterunner + nuclei enforced")

        # ── RULE 3: GraphQL → dedicated GraphQL scan ──────────────────────────
        if api_map and getattr(api_map, "has_graphql", False):
            plan_set.add("graphql_scan")
            log.info("[RULE-3] GraphQL detected → graphql_scan enforced")

        # ── RULE 4: AUTH_ENDPOINT → jwt_tool ─────────────────────────────────
        auth_endpoints: List[str] = []
        if brain:
            try:
                auth_nodes = brain.get_nodes_by_type("AUTH_ENDPOINT")
                auth_endpoints = [n.get("url", "") for n in (auth_nodes or []) if n.get("url")]
            except Exception as _exc:
                log.warning('Non-fatal exception suppressed: %s', _exc)
        if not auth_endpoints:
            _AUTH_RE = re.compile(
                r"/(login|auth|admin|signin|signup|oauth|token|register|password|reset)(/|$)",
                re.IGNORECASE,
            )
            auth_endpoints = [u for u in all_urls if _AUTH_RE.search(u)]
        ctx["auth_endpoints"] = auth_endpoints
        if auth_endpoints:
            plan_set.add("jwt_tool")
            log.info("[RULE-4] AUTH endpoints found (%d) → jwt_tool enforced", len(auth_endpoints))

        # ── RULE 5: CLOUD → s3scanner ─────────────────────────────────────────
        cloud_assets = getattr(intel, "cloud_assets", None) if intel else None
        if cloud_assets and getattr(cloud_assets, "open_buckets", []):
            plan_set.add("s3scanner")
            log.info("[RULE-5] Open S3 buckets detected → s3scanner enforced")

        # ── RULE 6: MOBILE → MobileSecurityEngine ────────────────────────────
        if t_type == "mobile":
            plan_set.add("mobile_scan")
            log.info("[RULE-6] Mobile target → mobile_scan enforced")

        rules_plan = set(plan_set)  # snapshot — always executed regardless of DE

        # ── Decision Engine — merges additional tool selections ───────────────
        _de_decisions_generated = 0
        _de_decisions_executed = 0
        _de_decisions_skipped = 0
        try:
            from oneinfinity.autonomous_decision_engine import AutonomousDecisionEngine
            de = AutonomousDecisionEngine()
            ctx["decision_engine"] = de
            dec_plan = de.generate_plan(target=session.target, max_decisions=50)
            _de_decisions_generated = len(dec_plan.decisions)
            for decision in dec_plan.decisions[:20]:
                tool = self._AGENT_TO_TOOL.get(decision.agent_type, "nuclei")
                if tool not in plan_set:
                    _de_decisions_executed += 1
                else:
                    _de_decisions_skipped += 1
                plan_set.add(tool)
            log.info(
                "[DE] Coverage: generated=%d new=%d merged=%d plan_size=%d (scan=%s)",
                _de_decisions_generated, _de_decisions_executed,
                _de_decisions_skipped, len(plan_set), session.scan_id,
            )
        except Exception as exc:
            log.warning("[DE] DecisionEngine unavailable (%s); rules + fallback only", exc)

        # ── AI Reasoning Layer (Phase 4) — priority-weighted, additive ──────
        # Rules (Phase 3) + DE (Phase 2) already in plan_set.
        # High-priority AI items move to front of execution order.
        # ctx["ai_hints"] carries full item list for tool execution use.
        _ai_high_tools: List[str] = []   # will be prepended in ordering
        _ai_plan: list = []
        try:
            from oneinfinity.core.ai_reasoning_engine import get_ai_reasoning_engine
            _are = get_ai_reasoning_engine()
            _tech = str(getattr(intel, "tech_profile", "") if intel else "unknown")
            _auth_ctx = {"authenticated": bool(
                getattr(session, "scan_config", {}) and (
                    (getattr(session, "scan_config", {}) or {}).get("token")
                    or (getattr(session, "scan_config", {}) or {}).get("cookies")
                )
            )}
            _ai_plan = _are.generate_attack_plan(
                target=session.target,
                endpoints=all_urls[:50],
                params_map=params_map,
                findings=[],  # no findings yet at planning stage
                tech_stack=_tech,
                auth_context=_auth_ctx,
            )
            # Separate high-priority items — these get prepended in ordering
            _seen_ai: set = set()
            for _item in _ai_plan:
                _t = _item.tool
                if _item.priority == "high" and _t not in plan_set and _t not in _seen_ai:
                    _ai_high_tools.append(_t)
                    _seen_ai.add(_t)
            # Add all AI tools to plan_set (additive)
            _ai_all_tools = _are.map_plan_to_tools(_ai_plan)
            _ai_new = [t for t in _ai_all_tools if t not in plan_set]
            plan_set.update(_ai_new)
            # Store hints dict for tool execution phase to use
            ctx["ai_hints"] = [_item.to_dict() for _item in _ai_plan]
            if _ai_new:
                log.info("[AI-Reasoning] %d tools added (%d high-priority): %s",
                         len(_ai_new), len(_ai_high_tools), _ai_new)
            session.phases["agent_trigger"].meta["ai_plan_items"] = len(_ai_plan)
            session.phases["agent_trigger"].meta["ai_tools_added"] = _ai_new
            session.phases["agent_trigger"].meta["ai_high_priority"] = _ai_high_tools
        except Exception as exc:
            log.debug("[AI-Reasoning] unavailable (non-fatal): %s", exc)
            ctx["ai_hints"] = []

        # ── Fallback: if plan still empty after rules + DE + AI, add type defaults ─
        if not plan_set:
            if t_type == "web":
                plan_set.update(["nuclei", "dalfox", "sqlmap"])
            elif t_type == "api":
                plan_set.update(["nuclei", "sqlmap"])
            elif t_type == "ai":
                plan_set.update(["garak", "pyrit"])
            else:
                plan_set.add("nuclei")
            log.info("Fallback plan for %s (%s): %s", session.target, t_type, sorted(plan_set))

        # nuclei always present as baseline
        plan_set.add("nuclei")

        # ── KB enrichment — best tools for predicted vulns ───────────────────
        try:
            kb = ctx.get("kb")
            insight = ctx.get("pattern_insight")
            if kb and insight:
                for vp in insight.predicted_vulns[:5]:
                    best = kb.best_tool_for_vuln_sync(vp.vuln_type, top_n=1)
                    if best:
                        t = best[0].get("tool_name", "")
                        if t:
                            plan_set.add(t)
                            log.info("KB recommended '%s' for predicted '%s'", t, vp.vuln_type)
                for st in (insight.suggested_tools or [])[:3]:
                    if st:
                        plan_set.add(st)
        except Exception as exc:
            log.debug("KB plan enrichment skipped: %s", exc)

        # ── Recon task priority hints ─────────────────────────────────────────
        priority_tools: List[str] = []
        try:
            if intel and getattr(intel, "tasks", []):
                _TASK_TOOL: Dict[str, List[str]] = {
                    "injection": ["sqlmap", "nuclei"],
                    "auth":      ["nuclei"],
                    "cloud":     ["nuclei"],
                    "api":       ["nuclei"],
                    "misc":      ["nuclei"],
                }
                for task in intel.tasks:
                    if getattr(task, "priority", "low") in ("critical", "high"):
                        cat = getattr(task, "category", "misc")
                        for t in _TASK_TOOL.get(cat, ["nuclei"]):
                            if t not in priority_tools:
                                priority_tools.append(t)
                plan_set.update(priority_tools)
                if priority_tools:
                    log.info("Recon tasks added priority tools: %s", priority_tools)
        except Exception as exc:
            log.debug("Recon task enrichment skipped: %s", exc)

        # ── Build final ordered plan ──────────────────────────────────────────
        # Order: high-priority AI → recon priority → rules → medium/low AI + DE
        seen_order: List[str] = []

        def _add(t: str) -> None:
            if t and t not in seen_order:
                seen_order.append(t)

        # 1. High-priority AI tools (execute earliest — AI says these are highest value)
        for _t in _ai_high_tools:
            _add(_t)
        # 2. Recon-task priority tools
        for _t in priority_tools:
            _add(_t)
        # 3. Rule-enforced tools (Phase 3 — always present)
        for _t in sorted(rules_plan):
            _add(_t)
        # 4. Remaining: medium/low AI tools + DE additions
        _remaining = plan_set - rules_plan - set(priority_tools) - set(_ai_high_tools)
        for _t in sorted(_remaining):
            _add(_t)
        plan = seen_order

        ctx["agent_plan"] = plan
        session.phases["agent_trigger"].meta.update({
            "de_generated": _de_decisions_generated,
            "de_executed": _de_decisions_executed,
            "de_skipped": _de_decisions_skipped,
            "de_used": ctx.get("decision_engine") is not None,
            "agent_plan": plan,
            "rules_enforced": sorted(rules_plan),
            "params_map_size": len(params_map),
            "auth_endpoints_count": len(auth_endpoints),
        })
        log.info("Final agent plan for %s: %s", session.target, plan)

        # ── Execute queued agent actions via AgentExecutionFabric ─────────────
        if brain is None:
            raise RuntimeError("graph_brain not available for agent_trigger")
        try:
            from oneinfinity.swarm.agent_execution_fabric import get_fabric
        except ImportError as exc:
            raise RuntimeError("AgentExecutionFabric unavailable: " + str(exc)) from exc

        fabric = get_fabric()
        if not fabric.status().get("running"):
            fabric.start(max_workers=8)

        # Collect JWT tokens for rich context injection
        jwt_tokens: List[str] = []
        try:
            auth_mgr = ctx.get("auth_manager")
            if auth_mgr:
                tok = getattr(auth_mgr, "token", None)
                if tok:
                    jwt_tokens.append(str(tok))
        except Exception as _exc:
            log.warning('Non-fatal exception suppressed: %s', _exc)
        ctx["jwt_tokens"] = jwt_tokens

        dispatched = 0
        while True:
            action = brain.next_action()
            if action is None:
                break
            fabric.submit_task(
                agent_type=action.agent_type,
                node_id=action.node_id,
                node_label=action.node_label,
                node_type=action.node_type,
                target=action.target,
                context={
                    **(action.context or {}),
                    "endpoints": all_urls[:100],
                    "params_map": params_map,
                    "auth_endpoints": auth_endpoints[:20],
                    "jwt_tokens": jwt_tokens,
                },
                priority=action.priority,
            )
            dispatched += 1

        # RULE 6: Mobile — dispatch MobileSecurityAgent directly via fabric
        if t_type == "mobile":
            try:
                fabric.submit_task(
                    agent_type="mobile",
                    node_id=session.target,
                    node_label=session.target,
                    node_type="TARGET",
                    target=session.target,
                    context={
                        "endpoints": all_urls[:100],
                        "params_map": params_map,
                        "auth_endpoints": auth_endpoints[:20],
                        "jwt_tokens": jwt_tokens,
                    },
                    priority=10,
                )
                dispatched += 1
                log.info("[RULE-6] MobileSecurityAgent dispatched for %s", session.target)
            except Exception as exc:
                log.warning("[RULE-6] Mobile agent dispatch failed: %s", exc)

        session.phases["agent_trigger"].meta["actions_dispatched"] = dispatched
        log.info("Agent actions dispatched: %d (scan=%s)", dispatched, session.scan_id)

    def _phase_vuln_scan(self, session: ScanSession, ctx: dict) -> None:
        """Execute nuclei / dalfox / sqlmap per agent plan."""
        registry: Optional[object] = ctx.get("tool_registry")
        if registry is None:
            try:
                from oneinfinity.modules.tool_wrappers import ToolRegistry
                registry = ToolRegistry()
                ctx["tool_registry"] = registry
            except ImportError as exc:
                raise RuntimeError("ToolRegistry unavailable: " + str(exc)) from exc

        plan: List[str] = ctx.get("agent_plan", ["nuclei"])
        findings: List[dict] = []
        intel = ctx.get("recon_intel")

        urls: List[str] = []
        if intel:
            urls = getattr(intel, "all_urls", []) or []
            if not urls and getattr(intel, "alive_hosts", []):
                urls = [h.get("url", "") for h in intel.alive_hosts if h.get("url")]

        # Prioritize and cap URLs: parameterized > login/admin > rest, max 200
        urls = self._prioritize_urls(urls)[:200]

        _PRIORITY_KEYWORDS = ("login", "admin", "auth", "api", "signup", "register",
                               "dashboard", "password", "account", "user")

        for tool_name in plan:
            _tool_start = time.time()
            _tool_result: List[dict] = []
            _tool_success = False
            try:
                log.info("Running tool '%s' against %s (%d URLs)", tool_name, session.target, len(urls))
                if tool_name in ("garak", "pyrit"):
                    try:
                        from oneinfinity.ai.ai_security_engine import AISecurityEngine, AISecurityScanConfig
                        import asyncio
                        ai_engine = AISecurityEngine()
                        config = AISecurityScanConfig(
                            target=session.target,
                            tools=[tool_name],
                        )
                        res = asyncio.run(ai_engine.scan(config))
                        for f in res.findings:
                            _tool_result.append({
                                "tool": f.tool,
                                "title": f.vulnerability,
                                "severity": f.severity,
                                "target": f.target,
                                "evidence": f.evidence,
                                "vuln_type": "ai",
                                "url": session.target
                            })
                    except Exception as exc:
                        log.error("AI Scan failed for %s: %s", tool_name, exc)
                elif tool_name == "nuclei":
                    # Run in batches of 50 prioritized URLs
                    batches = [urls[i:i + 50] for i in range(0, len(urls), 50)] or [[]]
                    for batch_idx, batch in enumerate(batches):
                        log.info("nuclei batch %d/%d (%d URLs)", batch_idx + 1, len(batches), len(batch))
                        result = self._run_tool_safe(registry, "nuclei", session.target, batch)
                        _tool_result.extend(result)
                elif tool_name in ("dalfox", "sqlmap", "xssstrike", "commix") and urls:
                    # Use AI hints to reorder: hinted endpoints execute first
                    _ai_hints = ctx.get("ai_hints", [])
                    _action_map = {
                        "dalfox":   ("test_xss",),
                        "sqlmap":   ("test_sqli",),
                        "xssstrike":("test_xss",),
                        "commix":   ("test_cmdi",),
                    }
                    _actions = _action_map.get(tool_name, ())
                    _hint_targets = [
                        h["target"] for h in _ai_hints
                        if h.get("action") in _actions and h.get("target")
                    ]
                    # Reorder: AI-hinted endpoints first, then remaining
                    def _is_hinted(u: str) -> bool:
                        return any(ht in u for ht in _hint_targets)
                    _hinted_urls = [u for u in urls if _is_hinted(u)]
                    _other_urls  = [u for u in urls if not _is_hinted(u)]
                    _ordered_urls = (_hinted_urls + _other_urls)[:5]
                    if _hint_targets and _hinted_urls:
                        log.info("[AI-Hints] %s: %d hinted URLs prioritized",
                                 tool_name, len(_hinted_urls))
                    for url in _ordered_urls:
                        result = self._run_tool_safe(registry, tool_name, session.target, [url])
                        _tool_result.extend(result)
                elif tool_name == "jwt_tool":
                    # RULE 4: Test JWT tokens found during auth phase
                    jwt_tokens: List[str] = ctx.get("jwt_tokens", [])
                    if not jwt_tokens:
                        auth_mgr = ctx.get("auth_manager")
                        tok = getattr(auth_mgr, "token", None) if auth_mgr else None
                        if tok:
                            jwt_tokens = [str(tok)]
                    if jwt_tokens:
                        try:
                            from oneinfinity.modules.tool_wrappers import run_jwt_tool
                            for _tok in jwt_tokens[:3]:
                                _jres = run_jwt_tool(_tok)
                                if isinstance(_jres, dict):
                                    _jres.setdefault("tool", "jwt_tool")
                                    _jres.setdefault("vuln_type", "jwt_weakness")
                                    _tool_result.append(_jres)
                                elif isinstance(_jres, list):
                                    for _jr in _jres:
                                        _jr.setdefault("tool", "jwt_tool")
                                        _tool_result.append(_jr)
                        except Exception as exc:
                            log.warning("jwt_tool failed: %s", exc)
                    else:
                        log.info("jwt_tool: no JWT tokens available, skipping")
                elif tool_name == "s3scanner":
                    # RULE 5: Scan S3 buckets found during recon
                    try:
                        from urllib.parse import urlparse as _up_s3
                        _domain = _up_s3(session.target).netloc or session.target
                        from oneinfinity.modules.tool_wrappers import run_s3scanner
                        _s3res = run_s3scanner(_domain)
                        if isinstance(_s3res, list):
                            for _r in _s3res:
                                _r.setdefault("tool", "s3scanner")
                                _r.setdefault("vuln_type", "open_bucket")
                                _tool_result.append(_r)
                        elif isinstance(_s3res, dict):
                            _s3res.setdefault("tool", "s3scanner")
                            _s3res.setdefault("vuln_type", "open_bucket")
                            _tool_result.append(_s3res)
                    except Exception as exc:
                        log.warning("s3scanner failed: %s", exc)
                elif tool_name == "kiterunner":
                    # RULE 2: API endpoint fuzzing
                    try:
                        from oneinfinity.modules.tool_wrappers import run_kiterunner
                        _kr_target = urls[0] if urls else session.target
                        _krres = run_kiterunner(_kr_target)
                        if isinstance(_krres, list):
                            for _r in _krres:
                                _r.setdefault("tool", "kiterunner")
                                _r.setdefault("vuln_type", "api_endpoint_exposed")
                                _tool_result.append(_r)
                        elif isinstance(_krres, dict):
                            _krres.setdefault("tool", "kiterunner")
                            _krres.setdefault("vuln_type", "api_endpoint_exposed")
                            _tool_result.append(_krres)
                    except Exception as exc:
                        log.warning("kiterunner failed: %s", exc)
                elif tool_name == "graphql_scan":
                    # RULE 3: GraphQL security testing via dedicated engine
                    try:
                        from oneinfinity.scan.graphql_scan_engine import GraphQLScanEngine
                        _gql_engine = GraphQLScanEngine(target=session.target)
                        auth_mgr = ctx.get("auth_manager")
                        if auth_mgr:
                            _sessions: Dict[str, object] = {}
                            _s = getattr(auth_mgr, "session", None)
                            if _s:
                                _sessions["user"] = _s
                            _gql_engine.set_auth_sessions(_sessions)
                        _gql_findings = _gql_engine.run()
                        for _f in (_gql_findings or []):
                            if isinstance(_f, dict):
                                _f.setdefault("tool", "graphql_scan")
                                _tool_result.append(_f)
                    except Exception as exc:
                        log.warning("graphql_scan failed: %s", exc)
                elif tool_name == "mobile_scan":
                    # RULE 6: Direct MobileSecurityEngine invocation (fallback if fabric unavailable)
                    try:
                        from oneinfinity.mobile.security_engine import MobileSecurityEngine
                        _mob_engine = MobileSecurityEngine(target=session.target)
                        _mob_findings = _mob_engine.run() if hasattr(_mob_engine, "run") else []
                        for _f in (_mob_findings or []):
                            if isinstance(_f, dict):
                                _f.setdefault("tool", "mobile_scan")
                                _tool_result.append(_f)
                    except Exception as exc:
                        log.warning("mobile_scan failed: %s", exc)
                else:
                    result = self._run_tool_safe(registry, tool_name, session.target, urls)
                    _tool_result.extend(result)

                _tool_success = True
                findings.extend(_tool_result)
                log.info("Tool '%s' produced %d total findings so far", tool_name, len(findings))
            except Exception as exc:
                log.warning("Tool '%s' raised an exception: %s", tool_name, exc)
            finally:
                _tool_duration = time.time() - _tool_start
                # ── Priority 2: KB — record tool run metrics ────────────────
                try:
                    _kb = ctx.get("kb")
                    if _kb:
                        _kb.record_tool_run_sync(
                            tool_name=tool_name,
                            target_type=session.target_type or "web",
                            success=_tool_success,
                            findings_count=len(_tool_result),
                            duration_s=round(_tool_duration, 2),
                        )
                except Exception as _exc:
                    log.warning('Non-fatal exception suppressed: %s', _exc)
                # ── Priority 7: Decision Engine — record outcomes ────────────
                try:
                    _de = ctx.get("decision_engine")
                    if _de and _tool_result:
                        for _f in _tool_result[:10]:
                            _de.record_outcome(
                                decision_id=f"{tool_name}-{session.scan_id[:8]}",
                                agent_type=tool_name,
                                node_id=_f.get("url", session.target),
                                success=True,
                                severity=_f.get("severity", "info"),
                            )
                    elif _de and not _tool_result and _tool_success:
                        _de.record_outcome(
                            decision_id=f"{tool_name}-{session.scan_id[:8]}",
                            agent_type=tool_name,
                            node_id=session.target,
                            success=False,
                            severity="info",
                        )
                except Exception as _exc:
                    log.warning('Non-fatal exception suppressed: %s', _exc)

        # ── Extended OWASP coverage tests ─────────────────────────────────────
        # Run new pure-Python tests that aren't part of the tool registry plan.
        try:
            from oneinfinity.modules.tool_wrappers import (
                run_deserialization_test, run_file_upload_test,
                run_oauth_test, run_prototype_pollution_test,
                run_mfa_bypass_test, run_rate_limit_test, run_pii_scanner,
            )
            _ext_tests = [
                ("deserialization",       run_deserialization_test,       session.target),
                ("file_upload",           run_file_upload_test,           session.target),
                ("oauth",                 run_oauth_test,                 session.target),
                ("prototype_pollution",   run_prototype_pollution_test,   session.target),
                ("mfa_bypass",            run_mfa_bypass_test,            session.target),
                ("rate_limit",            run_rate_limit_test,            session.target),
            ]
            # PII scan: use discovered URLs if available, else target
            _pii_urls = list(urls[:20]) if urls else [session.target]
            _ext_tests.append(("pii_scanner", run_pii_scanner, _pii_urls[0]))

            for _tname, _tfn, _targ in _ext_tests:
                try:
                    _tres = _tfn(_targ)
                    _tlist = _tres if isinstance(_tres, list) else ([_tres] if isinstance(_tres, dict) else [])
                    _vuln = [f for f in _tlist if isinstance(f, dict) and f.get("severity") not in ("info", None)]
                    if _vuln:
                        for _f in _vuln:
                            _f.setdefault("tool", _tname)
                        findings.extend(_vuln)
                        log.info("Extended test '%s': %d finding(s)", _tname, len(_vuln))
                    else:
                        log.debug("Extended test '%s': no findings", _tname)
                except Exception as _te:
                    log.debug("Extended test '%s' skipped: %s", _tname, _te)
        except ImportError as _imp_e:
            log.debug("Extended OWASP tests unavailable: %s", _imp_e)

        # ── Fix 7: Collect fabric findings (drain async swarm agents) ────────
        try:
            from oneinfinity.swarm.agent_execution_fabric import get_fabric
            _fabric = get_fabric()
            _fabric_findings = _fabric.drain(timeout_s=20.0)
            if _fabric_findings:
                log.info("Fabric drain: +%d findings collected from swarm agents",
                         len(_fabric_findings))
                findings.extend(_fabric_findings)
        except Exception as exc:
            log.debug("Fabric drain skipped: %s", exc)

        # ── Drain AI signal buffer → ctx["loop_history"]["ai_signals"] ──────────
        # Signals collected by _run_tool_safe during the base scan feed the loop.
        try:
            if _AI_SIGNAL_BUFFER:
                from oneinfinity.core.attack_loop_engine import AttackLoopEngine
                AttackLoopEngine._init_loop_history(ctx)  # type: ignore[attr-defined]
                ctx["loop_history"]["ai_signals"].extend(_AI_SIGNAL_BUFFER)
                ctx["loop_history"]["ai_signals"] = ctx["loop_history"]["ai_signals"][-20:]
                log.info("[AI-Signals] %d signals drained into loop_history", len(_AI_SIGNAL_BUFFER))
                _AI_SIGNAL_BUFFER.clear()
        except Exception as _exc:
            log.warning('Non-fatal exception suppressed: %s', _exc)

        # ── Phase 4: Attack Loop — AI-guided iterative follow-on scans ──────────
        # Runs 1–2 additional iterations with AI-suggested tools.
        # Each iteration only executes tools NOT already in the base plan.
        # Stops on diminishing returns (< 2 new findings) or timeout.
        _loop_new_count = 0
        try:
            from oneinfinity.core.attack_loop_engine import get_attack_loop_engine

            def _iteration_runner(
                _session: object,
                _ctx: dict,
                _additional_tools: List[str],
            ) -> List[dict]:
                """
                Run one attack loop iteration with AI-suggested tools.
                Injects chain_data tokens into jwt_tool calls where available.
                """
                _iter_findings: List[dict] = []
                _base_plan: list = _ctx.get("agent_plan", [])
                # Only run tools not already in the base plan (avoids duplication)
                _new_tools = [t for t in _additional_tools if t not in _base_plan]
                if not _new_tools:
                    return []
                _iter_urls = self._prioritize_urls(
                    getattr(_ctx.get("recon_intel"), "all_urls", []) or []
                )[:50]
                # Inject chain_data tokens into jwt_tokens context if available
                _cd = _ctx.get("chain_data", {})
                if _cd:
                    _existing_jwt = list(_ctx.get("jwt_tokens", []))
                    _chain_jwt = _cd.get("tokens", {}).get("jwt", [])
                    if _chain_jwt:
                        _ctx["jwt_tokens"] = list(set(_existing_jwt + _chain_jwt))[:5]
                        log.info("[ALEngine] Injected %d chain JWT tokens for iter",
                                 len(_chain_jwt))
                for _t in _new_tools[:3]:   # cap at 3 new tools per iteration
                    try:
                        _r = self._run_tool_safe(registry, _t, _session.target, _iter_urls)
                        _iter_findings.extend(_r)
                    except Exception as _e:
                        log.debug("[ALEngine] tool '%s' raised in iteration: %s", _t, _e)
                return _iter_findings

            _loop_engine = get_attack_loop_engine(max_iterations=2)
            ctx["scan_findings"] = list(findings)   # seed context for loop dedup
            _loop_findings = _loop_engine.run(session, ctx, _iteration_runner)
            if _loop_findings:
                findings.extend(_loop_findings)
                _loop_new_count = len(_loop_findings)
                log.info("[ALEngine] Attack loop added %d new findings", _loop_new_count)
            session.phases["vuln_scan"].meta["loop_summary"] = _loop_engine.summary()
        except Exception as exc:
            log.debug("[ALEngine] Attack loop skipped (non-fatal): %s", exc)

        log.info("Raw findings (pre-validation): %d", len(findings))
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            eng = get_ingestion_engine()
            stored = eng.store_raw_findings(findings)
            log.info("Raw findings stored: %d", stored)
        except Exception as exc:
            log.error("Raw findings storage failed: %s", exc)

        ctx["scan_findings"] = findings
        session.findings.extend(findings)
        session.phases["vuln_scan"].meta.update({
            "raw_findings": len(findings),
            "de_used": ctx.get("decision_engine") is not None,
            "loop_new_findings": _loop_new_count,
        })

    def _run_tool_safe(
        self,
        registry: object,
        tool_name: str,
        target: str,
        urls: List[str],
        retry: bool = True,
        waf_retries: int = 3,
    ) -> List[dict]:
        """Run a single tool with WAF feedback, rate limiting, and scope validation."""
        # 1. Safety & Scope Validation
        from oneinfinity.core.scope_validator import ScopeValidator
        
        sv = ScopeValidator()
        sv.add_in_scope(target)

        # Validate target
        if not sv.check(target):
            log.warning(f"[SAFETY] Target {target} is out of scope!")
            return []

        # Validate action
        if not safety_guard.validate_action("scan", target):
            return []

        filtered_urls = sv.filter_in_scope(urls)
        if urls and not filtered_urls:
            log.warning(f"[{tool_name}] All URLs out of scope for {target}")
            return []
        urls = filtered_urls

        # 2. Rate Limiting
        time.sleep(safety_guard.rate_limit_delay)

        kwargs: dict = {}
        target_tool = tool_name
        
        if tool_name == "nuclei":
            if urls:
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                     tf.write("\n".join(urls))
                     targets_file = tf.name
                kwargs = {"targets_file": targets_file}
                target_tool = "nuclei_list"
            else:
                kwargs = {"target": target}
        elif tool_name in ("dalfox", "sqlmap", "xssstrike", "commix"):
            url = urls[0] if urls else target
            kwargs = {"url": url}
        elif tool_name == "kxss":
            kwargs = {"urls": urls if urls else [target]}
        elif tool_name == "httpx":
            kwargs = {"targets": urls if urls else [target]}
        elif tool_name == "subfinder":
            kwargs = {"domain": target.replace("https://", "").replace("http://", "").split("/")[0]}
        else:
            kwargs = {"target": target}

        result = registry.run(target_tool, **kwargs)

        # 3. WAF Feedback Loop — HTTP payload mutation (Fix 4 / Fix 6)
        _waf_budget_start = time.time()
        _WAF_BUDGET_SEC = 60  # max 60s total across all retries
        raw_out = result.raw or result.stderr or ""

        # ── Response-based escalation (Fix 6) ──────────────────────────────
        try:
            from oneinfinity.core.http_payload_mutator import get_http_mutator as _get_hpm
            _hpm = _get_hpm()
            _elapsed = time.time() - _waf_budget_start
            _escalation = _hpm.classify_response(raw_out, _elapsed)
            if _escalation:
                log.info(
                    "[ESCALATION] %s signal from %s response — adding %s scan",
                    _escalation, tool_name, _escalation,
                )
                # Return a hint finding so downstream can escalate
                if result.success:
                    # Append escalation hint to results that will be returned below
                    pass  # handled below in result normalisation
        except Exception:
            _escalation = None

        # ── AI Response Analysis (Phase 4) — actionable signals ─────────────
        # Signals include next_action + tool_to_run so the loop can replan.
        # Written into ctx["loop_history"]["ai_signals"] for next iteration.
        if raw_out and len(raw_out.strip()) >= 50:
            try:
                from oneinfinity.core.ai_reasoning_engine import get_ai_reasoning_engine as _get_are
                _are = _get_are()
                _ai_signals = _are.analyze_response(
                    tool_name=tool_name,
                    target=target,
                    response_text=raw_out,
                )
                for _sig in _ai_signals:
                    log.info(
                        "[AI-Analysis] %s [%s] → %s: %s",
                        _sig.get("type"), _sig.get("confidence"),
                        _sig.get("tool_to_run", ""), _sig.get("evidence", "")[:80],
                    )
                if _ai_signals:
                    # Store in loop_history for adaptive replanning
                    _lh = kwargs.get("_ctx_ref") if "_ctx_ref" in (kwargs or {}) else None
                    # We can't access ctx here directly (no ctx param), but
                    # signals are returned via a thread-safe list in the result normalisation
                    # Append to a module-level buffer read by the loop engine
                    _AI_SIGNAL_BUFFER.extend(_ai_signals)
                    _AI_SIGNAL_BUFFER[:] = _AI_SIGNAL_BUFFER[-20:]  # cap buffer
            except Exception as _exc:
                log.warning('Non-fatal exception suppressed: %s', _exc)

        if not result.success and retry and waf_retries > 0:
            try:
                from oneinfinity.ai_security.response_analyzer import ResponseAnalyzer
                _analyzer = ResponseAnalyzer()
                waf_type = _analyzer.detect_waf(raw_out, {})
            except Exception:
                waf_type = None

            if waf_type:
                if time.time() - _waf_budget_start > _WAF_BUDGET_SEC:
                    log.warning("[WAF] retry budget exhausted for %s — skipping", tool_name)
                    return [{"vuln_type": "tool_error", "error": "WAF retry budget exhausted"}]

                WAF_STATS["detections"] += 1
                WAF_STATS["mutations"] += 1
                WAF_STATS["by_type"][waf_type] = WAF_STATS["by_type"].get(waf_type, 0) + 1
                log.info("[WAF] %s detected for %s — applying HTTP mutations (%d retries left)",
                         waf_type, tool_name, waf_retries)

                # ── Use HttpPayloadMutator (Fix 4) ──────────────────────────
                try:
                    from oneinfinity.core.http_payload_mutator import get_http_mutator
                    http_mutator = get_http_mutator()
                    fallback_kwargs = kwargs.copy()

                    if "url" in fallback_kwargs:
                        # Determine vuln type from tool
                        _vtype = {
                            "sqlmap": "sqli", "dalfox": "xss",
                            "xssstrike": "xss", "commix": "cmdi",
                        }.get(tool_name, "sqli")
                        mutated_urls = http_mutator.mutate_url(
                            fallback_kwargs["url"],
                            vuln_type=_vtype,
                            waf_type=waf_type,
                            max_variants=3,
                        )
                        if mutated_urls:
                            fallback_kwargs["url"] = mutated_urls[0]
                            log.debug("[WAF] mutated URL: %s → %s",
                                      kwargs.get("url", ""), fallback_kwargs["url"])

                    elif "targets_file" in fallback_kwargs:
                        # For nuclei: generate mutated URL list
                        import tempfile
                        mutated_all: List[str] = []
                        for _u in urls[:20]:
                            mutated_all.extend(
                                http_mutator.mutate_url(_u, vuln_type="sqli",
                                                        waf_type=waf_type, max_variants=2)
                            )
                        if mutated_all:
                            with tempfile.NamedTemporaryFile(
                                mode="w", suffix=".txt", delete=False
                            ) as _tf:
                                _tf.write("\n".join(mutated_all))
                                fallback_kwargs["targets_file"] = _tf.name

                    # Run with mutated kwargs directly (not recursive — avoids double mutation)
                    retry_result = registry.run(target_tool, **fallback_kwargs)
                    if retry_result.success:
                        WAF_STATS["successes"] += 1
                        result = retry_result
                    else:
                        # One more recursive attempt with decremented retries
                        res = self._run_tool_safe(
                            registry, tool_name, target, urls, retry=False, waf_retries=0
                        )
                        if any(f.get("vuln_type") != "tool_error" for f in res):
                            WAF_STATS["successes"] += 1
                        return res
                except Exception as _mut_exc:
                    log.debug("[WAF] HTTP mutation failed: %s", _mut_exc)
                    return self._run_tool_safe(
                        registry, tool_name, target, urls, retry=False, waf_retries=0
                    )

        if not result.success and waf_retries == 0:
            log.warning("[WAF] bypass failed for %s after max retries", tool_name)

        # 4. Result Deduplication & Noise Reduction
        # ... rest of the method logic ...

        # ── Self-Healing / Retry Mechanism (Legacy) ──────────────────────────
        if not result.success and retry:
            log.warning("[%s] [RETRYING] Tool failed, attempting fallback configuration", tool_name.upper())
            fallback_kwargs = kwargs.copy()
            if tool_name == "httpx":
                fallback_kwargs["flags"] = ["-rate-limit", "10", "-threads", "5"]
            result = registry.run(target_tool, **fallback_kwargs)

        # Cleanup temp file for nuclei_list (after retry)
        if target_tool == "nuclei_list" and "targets_file" in kwargs:
            try:
                Path(kwargs["targets_file"]).unlink(missing_ok=True)
            except Exception as _exc:
                log.warning('Non-fatal exception suppressed: %s', _exc)

        # ... rest of the method ...

        # ── Runtime Validation & Structured Logging ─────────────────────────
        status = "OK"
        detail = f"{result.count} items"

        if not result.success:
            status = "FAILED"
            detail = result.error or result.stderr or "Unknown error"
            log.error("[%s] [%s] %s", tool_name.upper(), status, detail)
        elif result.count == 0:
            status = "WARNING"
            detail = "Zero results"
            log.warning("[%s] [%s] %s", tool_name.upper(), status, detail)
        else:
            log.info("[%s] [%s] %s", tool_name.upper(), status, detail)

        # ── Tool-Specific Sanity Checks ─────────────────────────────────────
        if result.success:
            if tool_name == "httpx" and result.count == 0:
                log.warning("[%s] [SANITY-CHECK] httpx returned no live hosts", tool_name.upper())
            elif tool_name == "subfinder" and result.count < 5:
                log.warning("[%s] [SANITY-CHECK] low subdomain count (%d)", tool_name.upper(), result.count)
            elif tool_name == "nuclei":
                findings = result.data.get("findings", []) if isinstance(result.data, dict) else []
                severities = [f.get("severity", "").lower() for f in findings]
                if findings and all(s in ("info", "low") for s in severities):
                    log.warning("[%s] [SANITY-CHECK] low severity findings only", tool_name.upper())
            elif tool_name == "dirsearch" and result.count == 0:
                log.warning("[%s] [SANITY-CHECK] dirsearch parsing issue or no paths found", tool_name.upper())

        if not result.success:
            return [{
                "tool": "tool_error",
                "source_tool": tool_name,
                "title": f"{tool_name} execution failed",
                "vuln_type": "tool_error",
                "severity": "info",
                "error": result.error,
                "returncode": result.returncode,
                "stderr": result.stderr,
                "stdout_head": (result.raw or "")[:500],
            }]

        # --- Normalise result.data to List[dict] ---
        raw = result.data
        items = []
        if isinstance(raw, dict):
            if "findings" in raw:
                items = raw["findings"]
            elif "hosts" in raw:
                items = raw["hosts"]
            elif "subdomains" in raw:
                items = [{"subdomain": s} for s in raw["subdomains"]]
            elif raw.get("is_vulnerable"):
                items = [{"tool": tool_name, "vuln_type": "sqli", "severity": "high", **raw}]
        elif isinstance(raw, list):
            items = raw

        findings = [r if isinstance(r, dict) else {"raw": str(r)} for r in items]
        for f in findings:
            f.setdefault("tool", tool_name)
        return findings

    # ── NEW PHASE: OOB Init ───────────────────────────────────────────────────

    def _phase_oob_init(self, session: ScanSession, ctx: dict) -> None:
        """Start OOB (out-of-band) callback listener for DNS/HTTP interaction detection."""
        try:
            from oneinfinity.scan.oob_engine import OOBEngine
            oob = OOBEngine(scan_id=session.scan_id)
            domain = oob.start()
            ctx["oob_engine"] = oob
            ctx["oob_domain"] = domain
            session.phases["oob_init"].meta["oob_domain"] = domain
            log.info("OOB engine started for scan %s: domain=%s", session.scan_id, domain)
        except Exception as exc:
            # Non-fatal: OOB is best-effort
            log.warning("oob_init: failed to start OOB engine: %s", exc)
            ctx["oob_engine"] = None
            ctx["oob_domain"] = None

    # ── NEW PHASE: Auth Setup ────────────────────────────────────────────────

    def _phase_auth_setup(self, session: ScanSession, ctx: dict) -> None:
        """Configure authenticated sessions from scan config (cookies, tokens, headers)."""
        try:
            from auth_session_manager import AuthSessionManager
            scan_config = getattr(session, "scan_config", {}) or {}
            cookies = scan_config.get("cookies") or {}
            headers = scan_config.get("headers") or {}
            token = scan_config.get("token") or ""
            mgr = AuthSessionManager(
                target=session.target,
                cookies=cookies if isinstance(cookies, dict) else {},
                headers=headers if isinstance(headers, dict) else {},
                token=str(token) if token else None,
            )
            # Auto-detect login form if no credentials supplied
            if not cookies and not token:
                login_url = mgr.detect_login_form()
                if login_url:
                    session.phases["auth_setup"].meta["login_url_detected"] = login_url
                    log.info("auth_setup: login form detected at %s", login_url)
            ctx["auth_manager"] = mgr
            session.phases["auth_setup"].meta["authenticated"] = bool(cookies or token)
            log.info("auth_setup: session manager ready (authenticated=%s)", bool(cookies or token))
        except Exception as exc:
            log.warning("auth_setup: failed: %s", exc)
            ctx["auth_manager"] = None

    # ── NEW PHASE: Business Logic ────────────────────────────────────────────

    def _phase_business_logic(self, session: ScanSession, ctx: dict) -> None:
        """Enumerate business logic attack surface (matches canonical pipeline phase 6)."""
        try:
            from oneinfinity.business_logic_attack_engine import BusinessLogicAttackEngine
            import asyncio
            engine = BusinessLogicAttackEngine()
            attacks = asyncio.run(engine.generate(session.target, {}, None))
            count = 0
            for attack in (attacks or []):
                d = attack.to_dict() if hasattr(attack, "to_dict") else (attack if isinstance(attack, dict) else {})
                d.setdefault("vuln_type", "business_logic")
                d.setdefault("source", "business_logic_engine")
                if hasattr(session, "findings"):
                    session.findings.append(d)
                count += 1
            session.phases["business_logic"].meta["attack_vectors"] = count
            log.info("Phase business_logic: %d attack vector(s) found", count)
        except Exception as exc:
            log.warning("Phase business_logic skipped: %s", exc)

    # ── NEW PHASE: GraphQL Scan ──────────────────────────────────────────────

    def _phase_graphql_scan(self, session: ScanSession, ctx: dict) -> None:
        """Detect GraphQL endpoints and run security tests (introspection, fuzzing, IDOR)."""
        try:
            from oneinfinity.scan.graphql_scan_engine import GraphQLScanEngine
        except ImportError as exc:
            log.warning("graphql_scan: engine unavailable: %s", exc)
            return

        # Smart execution: only run if GraphQL is likely present
        target = session.target
        probe_url = target if target.startswith("http") else f"https://{target}"
        output_dir = str(get_target_path(session.target, subdir="graphql"))

        try:
            engine = GraphQLScanEngine(target=probe_url, output_dir=output_dir)
            findings = engine.run()
            if not findings:
                log.info("graphql_scan: no GraphQL endpoints or vulnerabilities found for %s", target)
                session.phases["graphql_scan"].meta["endpoints"] = 0
                return

            # Apply auth session if available
            auth_mgr = ctx.get("auth_manager")
            if auth_mgr:
                for f in findings:
                    f.setdefault("authenticated", True)

            # Inject OOB domain into SSRF-like findings
            oob_domain = ctx.get("oob_domain")
            if oob_domain:
                for f in findings:
                    if "ssrf" in f.get("vuln_type", "").lower():
                        f["oob_domain"] = oob_domain

            session.findings.extend(findings)
            ctx["scan_findings"] = ctx.get("scan_findings", []) + findings
            session.phases["graphql_scan"].meta.update({
                "endpoints": engine.detected_endpoints if hasattr(engine, "detected_endpoints") else 0,
                "findings": len(findings),
            })
            log.info("graphql_scan: %d findings for %s", len(findings), target)
        except Exception as exc:
            log.warning("graphql_scan: scan failed: %s", exc)
            session.phases["graphql_scan"].error = str(exc)

    # ── NEW PHASE: Browser Analysis ──────────────────────────────────────────

    def _phase_browser_analysis(self, session: ScanSession, ctx: dict) -> None:
        """Run headless browser analysis for DOM XSS, JS secrets, and dynamic endpoints."""
        # Smart execution: only for JS-heavy targets
        target_type = session.target_type
        if target_type == "mobile":
            log.info("browser_analysis: skipping for mobile target")
            return

        try:
            from oneinfinity.scan.headless_browser_engine import HeadlessBrowserEngine
        except ImportError as exc:
            log.warning("browser_analysis: engine unavailable: %s", exc)
            return

        target = session.target
        probe_url = target if target.startswith("http") else f"https://{target}"
        output_dir = str(get_target_path(session.target, subdir="browser"))

        try:
            engine = HeadlessBrowserEngine(target=probe_url, output_dir=output_dir)
            result = engine.run()

            # Merge discovered endpoints into recon intel
            intel = ctx.get("recon_intel")
            browser_urls = result.get("endpoints", [])
            if intel and browser_urls:
                existing_urls = list(getattr(intel, "all_urls", []) or [])
                existing_urls.extend(browser_urls)
                try:
                    intel.all_urls = list(set(existing_urls))
                except Exception as _exc:
                    log.warning('Non-fatal exception suppressed: %s', _exc)

            # Add DOM XSS and JS secret findings
            browser_findings = result.get("findings", [])
            js_secrets = result.get("js_secrets", [])
            all_findings = browser_findings + js_secrets

            if all_findings:
                session.findings.extend(all_findings)
                ctx["scan_findings"] = ctx.get("scan_findings", []) + all_findings

            # FIX 2: Wire CALLS edges from JS-discovered API calls into graph
            brain = ctx.get("graph_brain")
            if brain and browser_urls:
                rel_edges = 0
                js_content = result.get("js_content", "") or ""
                for burl in browser_urls[:100]:
                    try:
                        rel_edges += brain.integrate_api_relationships(
                            source_url=probe_url,
                            response_body=js_content,
                            response_headers=result.get("response_headers", {}),
                            target=session.target,
                        )
                    except Exception as _exc:
                        log.warning('Non-fatal exception suppressed: %s', _exc)
                if rel_edges:
                    log.info("browser_analysis: +%d deep relationship edges from JS analysis",
                             rel_edges)

            session.phases["browser_analysis"].meta.update({
                "endpoints_discovered": len(browser_urls),
                "findings": len(all_findings),
                "js_secrets": len(js_secrets),
            })
            log.info(
                "browser_analysis: %d endpoints, %d findings, %d JS secrets for %s",
                len(browser_urls), len(browser_findings), len(js_secrets), target,
            )
        except Exception as exc:
            log.warning("browser_analysis: failed: %s", exc)
            session.phases["browser_analysis"].error = str(exc)

        # ── Additional browser security tests ────────────────────────────────
        extra_count = 0
        try:
            from oneinfinity.modules.tool_wrappers import run_source_map_scanner, run_clickjacking_test, run_websocket_test

            sm_results = run_source_map_scanner(probe_url)
            sm_list = sm_results if isinstance(sm_results, list) else (
                sm_results.get("findings", []) if isinstance(sm_results, dict) else []
            )
            if sm_list:
                session.findings.extend(sm_list)
                ctx["scan_findings"] = ctx.get("scan_findings", []) + sm_list
                extra_count += len(sm_list)

            cj_results = run_clickjacking_test(probe_url)
            cj_list = cj_results if isinstance(cj_results, list) else (
                [cj_results] if isinstance(cj_results, dict) else []
            )
            if cj_list:
                session.findings.extend(cj_list)
                ctx["scan_findings"] = ctx.get("scan_findings", []) + cj_list
                extra_count += len(cj_list)

            ws_results = run_websocket_test(probe_url)
            ws_list = ws_results if isinstance(ws_results, list) else (
                [ws_results] if isinstance(ws_results, dict) else []
            )
            if ws_list:
                session.findings.extend(ws_list)
                ctx["scan_findings"] = ctx.get("scan_findings", []) + ws_list
                extra_count += len(ws_list)

            if extra_count:
                log.info("browser_analysis: +%d findings from source-map/clickjacking/websocket tests", extra_count)
            session.phases["browser_analysis"].meta["extra_tests"] = extra_count
        except Exception as exc:
            log.debug("browser_analysis extra tests skipped (non-fatal): %s", exc)

    # ── NEW PHASE: Smuggling Test ────────────────────────────────────────────

    def _phase_smuggling_test(self, session: ScanSession, ctx: dict) -> None:
        """Detect HTTP request smuggling (CL.TE, TE.CL, TE.TE) via raw socket probes."""
        # Smart execution: skip for mobile targets or non-HTTP targets
        target_type = session.target_type
        if target_type == "mobile":
            log.info("smuggling_test: skipping for mobile target")
            return

        try:
            from oneinfinity.scan.smuggling_engine import SmugglingEngine
        except ImportError as exc:
            log.warning("smuggling_test: engine unavailable: %s", exc)
            return

        target = session.target
        probe_url = target if target.startswith("http") else f"https://{target}"

        try:
            engine = SmugglingEngine(target=probe_url, timeout=8)
            findings = engine.run()
            if findings:
                session.findings.extend(findings)
                ctx["scan_findings"] = ctx.get("scan_findings", []) + findings
                log.info("smuggling_test: %d smuggling findings for %s", len(findings), target)
            else:
                log.info("smuggling_test: no smuggling vulnerabilities found for %s", target)
            session.phases["smuggling_test"].meta["findings"] = len(findings)
        except Exception as exc:
            log.warning("smuggling_test: failed: %s", exc)
            session.phases["smuggling_test"].error = str(exc)

    def _phase_exploit_validation(self, session: ScanSession, ctx: dict) -> None:
        """Validate findings to remove false positives."""
        raw = ctx.get("scan_findings", [])
        if not raw:
            log.info("No findings to validate for scan %s", session.scan_id)
            session.phases["exploit_validation"].meta["validated"] = 0
            ctx["validated_findings"] = []
            return

        try:
            from oneinfinity.core.finding_validator import get_classifier
            classifier = get_classifier()
            classified = classifier.classify(raw)
        except ImportError as exc:
            raise RuntimeError("FindingClassifier unavailable: " + str(exc)) from exc

        # confirmed + unverified are reportable; false_positive + simulated are excluded
        validated = classified.all_reportable()
        removed = len(raw) - len(validated)
        log.info(
            "Validation complete: confirmed=%d unverified=%d false_positive=%d simulated=%d "
            "(%d removed from report pipeline)",
            len(classified.confirmed), len(classified.unverified),
            len(classified.false_positive), len(classified.simulated), removed,
        )
        ctx["validated_findings"] = validated
        ctx["classified_findings"] = classified   # expose buckets for report phase

        # Refresh session.findings with validated set
        session.findings = [
            f for f in session.findings
            if f not in raw  # keep any findings added outside vuln_scan
        ] + validated
        session.phases["exploit_validation"].meta.update({
            "original": len(raw),
            "confirmed": len(classified.confirmed),
            "unverified": len(classified.unverified),
            "false_positive": len(classified.false_positive),
            "simulated": len(classified.simulated),
            "validated": len(validated),
            "removed": removed,
        })

        # Extract tokens/sessions from finding evidence and ingest into graph
        brain = ctx.get("graph_brain")
        if brain and validated:
            try:
                token_count = 0
                for f in validated:
                    evidence = str(f.get("evidence", ""))
                    if evidence:
                        nids = brain.extract_tokens_from_response(
                            response_headers={},
                            response_body=evidence,
                            url=f.get("url", session.target),
                            target=session.target,
                        )
                        token_count += len(nids)
                if token_count:
                    log.info("exploit_validation: extracted %d token/session nodes from evidence",
                             token_count)
            except Exception as exc:
                log.debug("exploit_validation: token extraction failed: %s", exc)

    def _phase_exploit_chaining(self, session: ScanSession, ctx: dict) -> None:
        """Attempt to chain validated findings into attack paths."""
        brain = ctx.get("graph_brain")
        if not brain:
            log.warning("exploit_chaining: no graph_brain in ctx")
            return

        findings = ctx.get("validated_findings", [])
        if not findings:
            log.info("exploit_chaining: no validated findings to chain")
            return

        # 1. Update graph with validated findings first so paths can be planned
        for f in findings:
            brain.integrate_vuln(f)
        
        # 2. Identify potential high-impact paths
        # For simplicity, we'll try to find paths starting from SSRF or LFI
        paths = []
        try:
            # Shortest paths to 'CRITICAL' impact
            paths = brain.find_attack_paths(target=session.target, max_length=3)
        except Exception as exc:
            log.debug("exploit_chaining: find_attack_paths failed: %s", exc)

        # 2b. Validate graph paths before using them for chaining
        if paths:
            try:
                from oneinfinity.core.graph_path_validator import GraphPathValidator
                eng = brain._get_engine()
                validator = GraphPathValidator(engine=eng, strict=False)
                raw_node_lists = [p.nodes if hasattr(p, "nodes") else p for p in paths]
                valid_node_lists = validator.filter_paths(raw_node_lists)
                paths = valid_node_lists
                log.info("exploit_chaining: %d/%d attack paths passed validation",
                         len(paths), len(raw_node_lists))
            except Exception as exc:
                log.debug("exploit_chaining: path validation unavailable: %s", exc)

        if not paths:
            log.info("exploit_chaining: no multi-step attack paths found")
            return

        # 3. Detect and execute chains via restored exploit_chains package
        try:
            from oneinfinity.exploit_chains.engine import ExploitChainEngine
        except ImportError as exc:
            log.error("exploit_chaining: exploit_chains package unavailable: %s", exc)
            session.phases["exploit_chaining"].degraded = True
            session.phases["exploit_chaining"].degraded_reason = (
                "exploit_chains package not found — run: git checkout exploit_chains/"
            )
            return

        try:
            engine = ExploitChainEngine(engine=brain)
            chains = engine.detect_chains(
                findings=ctx.get("validated_findings", findings),
                target=session.target,
            )

            if chains:
                from oneinfinity.findings.result_ingestion_engine import NormalizedFinding
                for chain in chains:
                    nf = NormalizedFinding(
                        scan_id=session.scan_id,
                        target=session.target,
                        title=f"Exploit Chain: {chain.chain_type.replace('_', ' ').title()}",
                        severity=chain.severity_escalated,
                        vuln_type="exploit_chain",
                        evidence=chain.narrative,
                        tool="exploit_chain_engine",
                        confidence=chain.confidence,
                        cvss=chain.cvss_escalated,
                        source_type="simulated",
                    )
                    session.findings.append(nf.to_dict() if hasattr(nf, "to_dict") else nf.__dict__)

                session.phases["exploit_chaining"].meta["chains_detected"] = len(chains)
                session.phases["exploit_chaining"].meta["chain_types"] = [c.chain_type for c in chains]
                # Persist chain data for persistent memory + report
                ctx["successful_chains"] = [
                    {"chain_type": c.chain_type, "target": session.target,
                     "severity": c.severity_escalated, "confidence": c.confidence}
                    for c in chains
                ]
                log.info("exploit_chaining: %d chains detected on %s", len(chains), session.target)
            else:
                log.info("exploit_chaining: no chains found for %s", session.target)
                session.phases["exploit_chaining"].meta["chains_detected"] = 0

        except Exception as exc:
            log.error("exploit_chaining: chain detection failed: %s", exc)
            session.phases["exploit_chaining"].error = str(exc)

        # ── Phase 4: HTTP-based exploit chain execution ────────────────────────
        # Runs actual HTTP follow-on steps against confirmed findings.
        # New chain findings are added to session.findings with escalated severity.
        # FIX 9: Dedup guard — track (chain_type, url) pairs already executed
        _executed_chain_keys: set = ctx.setdefault("_executed_chain_keys", set())

        try:
            from oneinfinity.core.exploit_chain_executor import get_chain_executor
            _chain_exec = get_chain_executor()
            _source_findings = ctx.get("validated_findings") or ctx.get("scan_findings", [])
            _http_chains = _chain_exec.execute(
                findings=_source_findings,
                target=session.target,
                scan_id=session.scan_id,
                ctx=ctx,
            )
            if _http_chains:
                # FIX 7: Validate each chain result has real HTTP evidence before reporting
                validated_http_chains = []
                for hc in _http_chains:
                    chain_key = (hc.get("vuln_type", ""), hc.get("url", ""))
                    if chain_key in _executed_chain_keys:
                        log.debug("[ECE] dedup: skipping already-executed chain %s", chain_key)
                        continue
                    _executed_chain_keys.add(chain_key)

                    # Require evidence to be non-trivial (not just "HTTP 200")
                    evidence = hc.get("evidence", "")
                    if len(evidence) < 20:
                        log.debug("[ECE] chain result rejected: insufficient evidence (%d chars)", len(evidence))
                        # Record failure in graph for FIX 6 feedback
                        if brain:
                            brain.record_chain_failure(
                                hc.get("vuln_type", ""), hc.get("original_vuln", ""),
                                session.target
                            )
                        continue
                    validated_http_chains.append(hc)

                session.findings.extend(validated_http_chains)
                ctx.setdefault("scan_findings", []).extend(validated_http_chains)
                session.phases["exploit_chaining"].meta["http_chains_executed"] = len(validated_http_chains)
                log.info("[ECE] HTTP exploit chains: %d validated findings added", len(validated_http_chains))
            else:
                session.phases["exploit_chaining"].meta["http_chains_executed"] = 0
        except Exception as exc:
            log.debug("[ECE] exploit_chain_executor skipped (non-fatal): %s", exc)

        # FIX 3: Token execution — use graph TOKEN/SESSION nodes to test authenticated endpoints
        try:
            from oneinfinity.core.token_execution_engine import get_token_execution_engine
            token_engine = get_token_execution_engine()
            token_results = token_engine.execute_from_graph(
                brain=brain,
                scan_id=session.scan_id,
                target=session.target,
            )
            if token_results:
                token_findings = [r.to_finding(session.scan_id, session.target)
                                  for r in token_results]
                session.findings.extend(token_findings)
                ctx.setdefault("scan_findings", []).extend(token_findings)
                session.phases["exploit_chaining"].meta["token_tests"] = len(token_results)
                session.phases["exploit_chaining"].meta["token_escalations"] = sum(
                    1 for r in token_results if r.escalated
                )
                log.info("[TOKEN] %d token tests executed, %d escalations found",
                         len(token_results),
                         sum(1 for r in token_results if r.escalated))
            else:
                session.phases["exploit_chaining"].meta["token_tests"] = 0
        except Exception as exc:
            log.debug("[TOKEN] token_execution_engine skipped (non-fatal): %s", exc)

    def _phase_result_ingest(self, session: ScanSession, ctx: dict) -> None:
        """Push all findings into the result ingestion layer with integrity checks."""
        findings = ctx.get("validated_findings") or ctx.get("scan_findings", [])
        
        # ── Pipeline Integrity Check ────────────────────────────────────────
        intel = ctx.get("recon_intel")
        httpx_count = 0
        if intel:
            # Check for live hosts from httpx results
            httpx_count = len(getattr(intel, "alive_hosts", []))

        if not findings:
            log.error("CRITICAL: No findings stored (Scan produced zero results)")
        
        if not intel:
            log.error("CRITICAL: Recon failed (No intelligence gathered)")
        
        if httpx_count == 0 and session.target_type == "web":
            log.error("CRITICAL: No live hosts discovered by httpx")

        if not findings:
            log.info("No findings to ingest for scan %s", session.scan_id)
            session.phases["result_ingest"].meta["ingested"] = 0
            # Still close KB session even with no findings
            try:
                _kb = ctx.get("kb")
                if _kb:
                    _kb.finish_session_sync(ctx.get("kb_session_id", session.scan_id),
                                            total_findings=0, tools_used=[])
            except Exception as _exc:
                log.warning('Non-fatal exception suppressed: %s', _exc)
            return

        # ── Fix 8: Deduplication — always enforce + log ──────────────────────
        try:
            from oneinfinity.core.deduplicator import Deduplicator
            _dedup = Deduplicator()
            _before = len(findings)
            findings = _dedup.filter_new(findings)
            _after = len(findings)
            _removed = _before - _after
            log.info(
                "[DEDUP] %d unique findings (removed %d duplicates from %d total)",
                _after, _removed, _before,
            )
            session.phases["result_ingest"].meta.update({
                "deduplicated": _removed,
                "unique_findings": _after,
                "total_before_dedup": _before,
            })
        except Exception as exc:
            log.warning("Deduplicator failed (non-fatal): %s", exc)

        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
            eng = get_ingestion_engine()
            raw_results = [
                RawResult(
                    scan_id=session.scan_id,
                    source=f.get("tool", "unknown"),
                    raw=f,
                )
                for f in findings
            ]
            ingested = eng.ingest_batch(raw_results)
            log.info("Ingested %d findings via ResultIngestionEngine", len(ingested))
            session.phases["result_ingest"].meta["ingested"] = len(ingested)

            # Post-ingest validation
            db_count = eng.finding_count(session.scan_id)
            if db_count == 0 and len(findings) > 0:
                log.error("CRITICAL: Findings produced but zero stored in database")

            # ── Priority 2: KB — record findings + close session ────────────
            try:
                _kb = ctx.get("kb")
                if _kb:
                    _kb_sid = ctx.get("kb_session_id", session.scan_id)
                    _kb.record_findings_bulk_sync(_kb_sid, findings)
                    _tools_used = list({f.get("tool", "unknown") for f in findings})
                    _kb.finish_session_sync(_kb_sid,
                                            total_findings=len(ingested),
                                            tools_used=_tools_used)
                    log.info("KB: session %s closed (%d findings, tools=%s)",
                             _kb_sid, len(ingested), _tools_used)
            except Exception as exc:
                log.warning("KB finish_session failed (non-fatal): %s", exc)

        except ImportError as exc:
            log.error("result_ingestion_engine unavailable: %s", exc)
        except Exception as exc:
            log.error("ResultIngestionEngine.ingest_batch() failed: %s", exc)


    def _phase_severity_followup(self, session: ScanSession, ctx: dict) -> None:
        """Run deeper targeted scans for high/critical findings."""
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            findings = get_ingestion_engine().get_findings(scan_id=session.scan_id)
        except Exception as exc:
            log.warning("severity_followup: could not load findings: %s", exc)
            return

        high_crit = [f for f in findings if f.get("severity") in ("critical", "high")]
        if not high_crit:
            log.info("severity_followup: no high/critical findings, skipping (scan=%s)", session.scan_id)
            session.phases["severity_followup"].meta["triggered"] = 0
            return

        registry = ctx.get("tool_registry")
        if registry is None:
            try:
                from oneinfinity.modules.tool_wrappers import ToolRegistry
                registry = ToolRegistry()
                ctx["tool_registry"] = registry
            except ImportError as exc:
                log.warning("severity_followup: ToolRegistry unavailable: %s", exc)
                return

        triggered = 0
        new_findings: List[dict] = []
        for f in high_crit:
            vuln_type = (f.get("vuln_type") or "").lower()
            url = f.get("url") or f.get("target", "")
            if not url:
                continue
            try:
                if any(k in vuln_type for k in ("xss", "cross-site", "reflected")):
                    log.info("severity_followup: XSS → running dalfox on %s", url)
                    result = self._run_tool_safe(registry, "dalfox", session.target, [url])
                    new_findings.extend(result)
                    triggered += 1
                elif any(k in vuln_type for k in ("sql", "sqli", "injection")):
                    log.info("severity_followup: SQLi → running sqlmap on %s", url)
                    result = self._run_tool_safe(registry, "sqlmap", session.target, [url])
                    new_findings.extend(result)
                    triggered += 1
                elif any(k in vuln_type for k in ("ssrf", "server-side request")):
                    log.info(
                        "severity_followup: SSRF at %s — interactsh OOB callback recommended "
                        "(add to manual follow-up list)", url,
                    )
                    triggered += 1
            except Exception as exc:
                log.debug("severity_followup: deeper scan failed for %s: %s", url, exc)

        if new_findings:
            try:
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
                eng = get_ingestion_engine()
                raw = [
                    RawResult(scan_id=session.scan_id, source=nf.get("tool", "followup"), raw=nf)
                    for nf in new_findings
                ]
                ingested = eng.ingest_batch(raw)
                session.findings.extend(new_findings)
                log.info("severity_followup: ingested %d new findings from deeper scans", len(ingested))
            except Exception as exc:
                log.warning("severity_followup: ingest failed: %s", exc)

        log.info(
            "severity_followup: %d deeper scans triggered, %d new findings (scan=%s)",
            triggered, len(new_findings), session.scan_id,
        )
        session.phases["severity_followup"].meta.update({
            "triggered": triggered,
            "new_findings": len(new_findings),
        })

    def _phase_graph_vuln_update(self, session: ScanSession, ctx: dict) -> None:
        """Push validated findings into AttackGraphBrain as VULNERABILITY nodes."""
        brain = ctx.get("graph_brain")
        if brain is None:
            log.warning("graph_vuln_update: no brain in ctx, skipping (scan=%s)", session.scan_id)
            return

        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            findings = get_ingestion_engine().get_findings(scan_id=session.scan_id)
        except Exception as exc:
            log.warning("graph_vuln_update: could not load findings from DB: %s", exc)
            findings = []

        if not findings:
            log.info("graph_vuln_update: no findings to push for scan %s", session.scan_id)
            session.phases["graph_vuln_update"].meta["nodes_added"] = 0
            return

        added = 0
        high_critical = 0
        for f in findings:
            try:
                node_id = brain.integrate_vuln(f)
                if node_id:
                    added += 1
                    if f.get("severity") in ("critical", "high"):
                        high_critical += 1
            except Exception as exc:
                log.debug("graph_vuln_update: integrate_vuln failed [%s]: %s",
                          f.get("finding_id", "?"), exc)

        # Rescore the full graph so new VULNERABILITY nodes propagate priority
        try:
            brain.rescore_graph(target=session.target)
        except Exception as exc:
            log.debug("graph_vuln_update: rescore_graph failed: %s", exc)

        log.info(
            "[GRAPH] graph_vuln_update complete: %d nodes added (%d high/critical) (scan=%s)",
            added, high_critical, session.scan_id,
        )
        session.phases["graph_vuln_update"].meta.update({
            "nodes_added": added,
            "high_critical": high_critical,
        })

    def _phase_report(self, session: ScanSession, ctx: dict) -> None:
        """Generate rich multi-format report via core/reporter.py."""
        output_dir = get_target_path(session.target, subdir="findings")

        try:
            from oneinfinity.core.reporter import Reporter
            reporter = Reporter(
                output_dir=str(output_dir),
                target=session.target,
                platform="hackerone",
            )
            reporter.set_meta("scan_id", session.scan_id)
            reporter.set_meta("target_type", session.target_type)
            duration = round(session.end_time - session.start_time, 1) if session.end_time else 0
            reporter.set_meta("duration_s", duration)

            # Use classified findings if available (FP-filtered), else raw session findings
            classified = ctx.get("classified_findings")
            reportable = classified.all_reportable() if classified else session.findings
            reporter.add_findings(reportable)

            # Write markdown always; write JSON too for downstream tools
            paths_written: List[str] = []
            for fmt in ("markdown", "json"):
                try:
                    p = reporter.write(fmt)
                    paths_written.append(str(p))
                    log.info("Report [%s] written to %s", fmt, p)
                except Exception as exc:
                    log.warning("Report format %s failed: %s", fmt, exc)

            # FIX 8: Compute and attach graph quality metrics
            brain = ctx.get("graph_brain")
            if brain:
                try:
                    import json as _json
                    graph_metrics = brain.compute_graph_metrics()
                    reporter.set_meta("graph_metrics", graph_metrics)
                    log.info(
                        "Graph metrics: nodes=%d edges=%d avg_degree=%.2f "
                        "chain_success_rate=%.2f exploitable=%d",
                        graph_metrics.get("node_count", 0),
                        graph_metrics.get("edge_count", 0),
                        graph_metrics.get("avg_degree", 0),
                        graph_metrics.get("chain_success_rate", 0),
                        graph_metrics.get("exploitable_nodes", 0),
                    )
                    # Export full graph snapshot (nodes + edges + stats)
                    graph_export = brain._get_engine().to_dict()
                    graph_export["metrics"] = graph_metrics
                    graph_path = output_dir / f"graph_{session.scan_id[:8]}.json"
                    graph_path.write_text(_json.dumps(graph_export, indent=2), encoding="utf-8")
                    paths_written.append(str(graph_path))
                    log.info("Graph export written to %s (%d nodes, %d edges)",
                             graph_path,
                             graph_metrics.get("node_count", 0),
                             graph_metrics.get("edge_count", 0))
                except Exception as exc:
                    log.debug("Graph export/metrics failed: %s", exc)

            session.phases["report"].meta.update({
                "report_paths": paths_written,
                "findings_reported": reporter.count(),
            })
        except ImportError as exc:
            # Fallback to simple markdown if Reporter unavailable
            log.warning("core.reporter unavailable (%s) — using plain markdown fallback", exc)
            report_path = output_dir / f"report_{session.scan_id[:8]}.md"
            lines: List[str] = [
                f"# Scan Report — {session.target}",
                f"",
                f"**Scan ID:** {session.scan_id}",
                f"**Status:** {session.status}",
                f"",
                f"## Findings ({len(session.findings)} total)",
                f"",
            ]
            sev_order = ["critical", "high", "medium", "low", "info"]
            by_sev: Dict[str, List[dict]] = {s: [] for s in sev_order}
            for f in session.findings:
                sev = str(f.get("severity", "info")).lower()
                bucket = sev if sev in by_sev else "info"
                by_sev[bucket].append(f)
            for sev in sev_order:
                group = by_sev[sev]
                if not group:
                    continue
                lines.append(f"### {sev.capitalize()} ({len(group)})")
                for f in group:
                    title = f.get("name") or f.get("title") or f.get("vuln_type") or "Finding"
                    url = f.get("url") or f.get("endpoint") or f.get("target") or ""
                    repro = f.get("reproduction_cmd", "")
                    lines.append(f"- **{title}** — `{url}`")
                    if repro:
                        lines.append(f"  - Reproduce: `{repro}`")
                lines.append("")
            try:
                report_path.write_text("\n".join(lines), encoding="utf-8")
                session.phases["report"].meta["report_path"] = str(report_path)
            except Exception as write_exc:
                log.warning("Failed to write fallback report: %s", write_exc)

    def _phase_done(self, session: ScanSession, ctx: dict) -> None:
        """Mark scan as complete, emit quality metrics, and do a final DB persist."""
        session.status = "completed"

        # ── Scan Quality Metrics ─────────────────────────────────────────────
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            db_findings = get_ingestion_engine().get_findings(scan_id=session.scan_id)
        except Exception:
            db_findings = session.findings

        sev_dist: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in db_findings:
            sev = str(f.get("severity", "info")).lower()
            sev_dist[sev] = sev_dist.get(sev, 0) + 1

        urls_scanned = (session.phases.get("recon") or PhaseResult(name="recon")).meta.get("urls", 0)
        log.info(
            "[SCAN QUALITY] URLs: %d | Findings: %d | Critical: %d | High: %d"
            " | Medium: %d | Low: %d | Info: %d",
            urls_scanned, len(db_findings),
            sev_dist["critical"], sev_dist["high"],
            sev_dist["medium"], sev_dist["low"], sev_dist["info"],
        )
        session.phases["done"].meta["quality"] = {
            "urls_scanned": urls_scanned,
            "total_findings": len(db_findings),
            "by_severity": sev_dist,
        }

        log.info(
            "Scan %s done. Target=%s type=%s findings=%d",
            session.scan_id, session.target, session.target_type, len(db_findings),
        )

        # ── Persist cross-run memory ─────────────────────────────────────────
        try:
            mem = ctx.get("persistent_memory")
            if mem is not None:
                from oneinfinity.learning.persistent_memory import save_memory
                # update_from_ctx reads ctx["findings"] with confirmed/exploited flags
                mem_findings = []
                for f in db_findings:
                    vstatus = f.get("validation_status", "")
                    mem_f = dict(f)
                    mem_f["confirmed"] = vstatus == "confirmed"
                    mem_findings.append(mem_f)
                update_ctx = {
                    "findings":          mem_findings,
                    "successful_chains": ctx.get("successful_chains", []),
                    "priority_vuln_types": ctx.get("priority_vuln_types", []),
                    "focus_targets":     ctx.get("focus_targets", []),
                }
                mem.update_from_ctx(update_ctx)
                save_memory()
                log.info("PersistentMemory saved after scan %s", session.scan_id)
        except Exception as exc:
            log.warning("PersistentMemory save failed (non-fatal): %s", exc)

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _prioritize_urls(urls: List[str]) -> List[str]:
        """Order URLs: parameterized first, then login/admin paths, then rest."""
        _PRIORITY_PATHS = ("login", "admin", "auth", "api", "signup", "register",
                           "dashboard", "password", "account", "user")
        seen: set = set()
        parameterized, priority, rest = [], [], []
        for u in urls:
            if u in seen or not u:
                continue
            seen.add(u)
            lower = u.lower()
            if "?" in u:
                parameterized.append(u)
            elif any(k in lower for k in _PRIORITY_PATHS):
                priority.append(u)
            else:
                rest.append(u)
        return parameterized + priority + rest

    @staticmethod
    def _emit(
        cb: Optional[Callable[[str, int, str], None]],
        phase: str,
        pct: int,
        msg: str,
    ) -> None:
        """Fire the progress callback, suppressing any exception it raises."""
        if cb is None:
            return
        try:
            cb(phase, pct, msg)
        except Exception as exc:
            log.debug("on_progress callback raised: %s", exc)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[UnifiedScanEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> UnifiedScanEngine:
    """Return the process-wide UnifiedScanEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = UnifiedScanEngine()
    return _engine_instance
