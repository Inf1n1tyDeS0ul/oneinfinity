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
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from path_manager import db_path, get_target_path, raw_dir, resolve_output_dir

log = logging.getLogger("oneinfinity.unified_scan_engine")

# ---------------------------------------------------------------------------
# Phase ordering & percentage milestones
# ---------------------------------------------------------------------------

_PHASES: List[str] = [
    "classify",
    "recon",
    "graph_update",
    "agent_trigger",
    "vuln_scan",
    "exploit_validation",
    "exploit_chaining",
    "result_ingest",
    "severity_followup",
    "graph_vuln_update",
    "report",
    "done",
]

_PHASE_PCT: Dict[str, int] = {
    "classify":           5,
    "recon":             25,
    "graph_update":      35,
    "agent_trigger":     45,
    "vuln_scan":         60,
    "exploit_validation": 70,
    "exploit_chaining":  80,
    "result_ingest":     85,
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

_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id       TEXT PRIMARY KEY,
    target        TEXT NOT NULL,
    target_type   TEXT NOT NULL,
    status        TEXT NOT NULL,
    start_time    REAL,
    end_time      REAL,
    findings_json TEXT,
    phases_json   TEXT,
    error         TEXT
);
"""


def _get_db_conn() -> sqlite3.Connection:
    path = db_path("metadata.db")
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute(_DB_SCHEMA)
    conn.commit()
    return conn


def _persist_session(session: ScanSession) -> None:
    """Write (upsert) the session record to SQLite."""
    try:
        conn = _get_db_conn()
        phases_json = json.dumps(
            {n: {"status": pr.status, "error": pr.error} for n, pr in session.phases.items()}
        )
        conn.execute(
            """
            INSERT INTO scans
                (scan_id, target, target_type, status, start_time, end_time,
                 findings_json, phases_json, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status        = excluded.status,
                end_time      = excluded.end_time,
                findings_json = excluded.findings_json,
                phases_json   = excluded.phases_json,
                error         = excluded.error
            """,
            (
                session.scan_id,
                session.target,
                session.target_type,
                session.status,
                session.start_time,
                session.end_time,
                json.dumps(session.findings),
                phases_json,
                session.error,
            ),
        )
        conn.commit()
        conn.close()
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

from core.safety import safety_guard

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
            "recon_intel": None,     # ReconIntelligence object
            "graph_brain": None,     # AttackGraphBrain instance
            "agent_plan": [],        # list of agent-type strings
            "tool_registry": None,   # ToolRegistry instance
            "scan_findings": [],     # raw dicts from tools
        }

        phase_fns = {
            "classify":            self._phase_classify,
            "recon":               self._phase_recon,
            "graph_update":        self._phase_graph_update,
            "agent_trigger":       self._phase_agent_trigger,
            "vuln_scan":           self._phase_vuln_scan,
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
            from adaptive_recon_engine import AdaptiveReconEngine
        except ImportError as exc:
            raise RuntimeError("adaptive_recon_engine is unavailable: " + str(exc)) from exc

        try:
            from modules.tool_wrappers import ToolRegistry
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
            from result_ingestion_engine import get_ingestion_engine
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

    def _phase_graph_update(self, session: ScanSession, ctx: dict) -> None:
        """Push recon findings into the attack graph brain."""
        try:
            from attack_graph_brain import get_brain
        except ImportError as exc:
            raise RuntimeError("AttackGraphBrain unavailable: " + str(exc)) from exc

        brain = get_brain()
        brain.add_target(session.target)
        ctx["graph_brain"] = brain

        intel = ctx.get("recon_intel")
        if intel is None:
            log.warning("No recon intel available for graph_update")
            return

        subdomains = getattr(intel, "subdomains", []) or []
        for sub in subdomains:
            try:
                brain.integrate_node("SUBDOMAIN", sub, session.target, properties={"domain": sub})
            except Exception as exc:
                log.debug("graph_update: failed to integrate subdomain %s: %s", sub, exc)

        urls = getattr(intel, "all_urls", []) or []
        for url in urls[:500]:   # cap to avoid graph bloat
            try:
                brain.integrate_node("URL", url, session.target, properties={"url": url})
            except Exception as exc:
                log.debug("graph_update: failed to integrate url %s: %s", url, exc)

        log.info(
            "Graph updated for %s: %d subdomains, %d URLs ingested",
            session.target, len(subdomains), min(len(urls), 500),
        )

    def _phase_agent_trigger(self, session: ScanSession, ctx: dict) -> None:
        """Decide which scan agents to invoke based on target type and graph nodes."""
        t_type = session.target_type
        plan: List[str] = []

        if t_type == "web":
            plan = ["nuclei", "dalfox", "sqlmap"]
        elif t_type == "api":
            plan = ["nuclei", "sqlmap"]
        elif t_type == "mobile":
            plan = ["nuclei"]
        elif t_type == "ai":
            plan = ["garak", "pyrit"]
        else:
            plan = ["nuclei"]

        ctx["agent_plan"] = plan
        log.info("Agent plan for %s (%s): %s", session.target, t_type, plan)
        session.phases["agent_trigger"].meta["agent_plan"] = plan

        # Execute queued agent actions via AgentExecutionFabric
        brain = ctx.get("graph_brain")
        if brain is None:
            raise RuntimeError("graph_brain not available for agent_trigger")
        try:
            from agent_execution_fabric import get_fabric
        except ImportError as exc:
            raise RuntimeError("AgentExecutionFabric unavailable: " + str(exc)) from exc

        fabric = get_fabric()
        status = fabric.status()
        if not status.get("running"):
            fabric.start(max_workers=8)

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
                context=action.context,
                priority=action.priority,
            )
            dispatched += 1

        session.phases["agent_trigger"].meta["actions_dispatched"] = dispatched
        log.info("Agent actions dispatched: %d (scan=%s)", dispatched, session.scan_id)

    def _phase_vuln_scan(self, session: ScanSession, ctx: dict) -> None:
        """Execute nuclei / dalfox / sqlmap per agent plan."""
        registry: Optional[object] = ctx.get("tool_registry")
        if registry is None:
            try:
                from modules.tool_wrappers import ToolRegistry
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
            try:
                log.info("Running tool '%s' against %s (%d URLs)", tool_name, session.target, len(urls))
                if tool_name in ("garak", "pyrit"):
                    try:
                        from ai_security_engine import AISecurityEngine, AISecurityScanConfig
                        import asyncio
                        ai_engine = AISecurityEngine()
                        config = AISecurityScanConfig(
                            target=session.target,
                            tools=[tool_name],
                        )
                        res = asyncio.run(ai_engine.scan(config))
                        for f in res.findings:
                            findings.append({
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
                        findings.extend(result)
                elif tool_name in ("dalfox", "sqlmap", "xssstrike", "commix") and urls:
                    for url in urls[:5]:   # test top 5 discovered URLs
                        result = self._run_tool_safe(registry, tool_name, session.target, [url])
                        findings.extend(result)
                else:
                    result = self._run_tool_safe(registry, tool_name, session.target, urls)
                    findings.extend(result)
                log.info("Tool '%s' produced %d total findings so far", tool_name, len(findings))
            except Exception as exc:
                log.warning("Tool '%s' raised an exception: %s", tool_name, exc)

        log.info("Raw findings (pre-validation): %d", len(findings))
        try:
            from result_ingestion_engine import get_ingestion_engine
            eng = get_ingestion_engine()
            stored = eng.store_raw_findings(findings)
            log.info("Raw findings stored: %d", stored)
        except Exception as exc:
            log.error("Raw findings storage failed: %s", exc)

        ctx["scan_findings"] = findings
        session.findings.extend(findings)
        session.phases["vuln_scan"].meta["raw_findings"] = len(findings)

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
        from core.scope_validator import ScopeValidator
        
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

        # 3. WAF Feedback Loop with Control
        _waf_budget_start = time.time()
        _WAF_BUDGET_SEC = 60  # max 60s total across all retries
        if not result.success and retry and waf_retries > 0:
            from ai_security.response_analyzer import ResponseAnalyzer
            from ai_security.payload_mutator import PayloadMutator
            
            analyzer = ResponseAnalyzer()
            mutator = PayloadMutator()
            
            raw_out = result.raw or result.stderr or ""
            waf_type = analyzer.detect_waf(raw_out, {})
            
            if waf_type:
                if time.time() - _waf_budget_start > _WAF_BUDGET_SEC:
                    log.warning("[WAF] retry budget exhausted for %s — skipping", tool_name)
                    return [{"vuln_type": "tool_error", "error": "WAF retry budget exhausted"}]
                WAF_STATS["detections"] += 1
                WAF_STATS["mutations"] += 1
                WAF_STATS["by_type"][waf_type] = WAF_STATS["by_type"].get(waf_type, 0) + 1

                log.info("[WAF] mutation applied: Detected %s. Retrying (%d left).", waf_type, waf_retries)
                fallback_kwargs = kwargs.copy()
                strategies = mutator.select_mutation_for_waf(waf_type)
                
                if "url" in fallback_kwargs:
                    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                    u = urlparse(fallback_kwargs["url"])
                    qs = parse_qs(u.query)
                    if qs:
                        for k in qs:
                            qs[k] = [mutator.mutate_text(qs[k][0], strategies[0])]
                        fallback_kwargs["url"] = urlunparse(u._replace(query=urlencode(qs, doseq=True)))

                res = self._run_tool_safe(registry, tool_name, target, urls, retry, waf_retries - 1)
                if any(not f.get("vuln_type") == "tool_error" for f in res):
                    WAF_STATS["successes"] += 1
                return res

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
            except Exception:
                pass

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

    def _phase_exploit_validation(self, session: ScanSession, ctx: dict) -> None:
        """Validate findings to remove false positives."""
        raw = ctx.get("scan_findings", [])
        if not raw:
            log.info("No findings to validate for scan %s", session.scan_id)
            session.phases["exploit_validation"].meta["validated"] = 0
            ctx["validated_findings"] = []
            return

        validated: List[dict] = []
        try:
            from finding_validation_engine import FindingValidationEngine
            fve = FindingValidationEngine()
            for f in raw:
                try:
                    ok = fve.validate(f)
                    if ok:
                        validated.append(f)
                except Exception as exc:
                    log.debug("Validation error for finding: %s", exc)
                    validated.append(f)   # keep on error to avoid silent loss
        except ImportError as exc:
            raise RuntimeError("FindingValidationEngine unavailable: " + str(exc)) from exc

        removed = len(raw) - len(validated)
        log.info(
            "Validation complete: %d/%d findings kept (%d removed as FP)",
            len(validated), len(raw), removed,
        )
        log.info("Validated findings: %d", len(validated))
        ctx["validated_findings"] = validated
        # Refresh session.findings with validated set
        session.findings = [
            f for f in session.findings
            if f not in raw  # keep any findings added outside vuln_scan
        ] + validated
        session.phases["exploit_validation"].meta.update({
            "original": len(raw),
            "validated": len(validated),
            "removed": removed,
        })

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

        if not paths:
            log.info("exploit_chaining: no multi-step attack paths found")
            return

        # 3. Detect and execute chains via restored exploit_chains package
        try:
            from exploit_chains.engine import ExploitChainEngine
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
                from result_ingestion_engine import NormalizedFinding
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
                    )
                    session.findings.append(nf.to_dict() if hasattr(nf, "to_dict") else nf.__dict__)

                session.phases["exploit_chaining"].meta["chains_detected"] = len(chains)
                session.phases["exploit_chaining"].meta["chain_types"] = [c.chain_type for c in chains]
                log.info("exploit_chaining: %d chains detected on %s", len(chains), session.target)
            else:
                log.info("exploit_chaining: no chains found for %s", session.target)
                session.phases["exploit_chaining"].meta["chains_detected"] = 0

        except Exception as exc:
            log.error("exploit_chaining: chain detection failed: %s", exc)
            session.phases["exploit_chaining"].error = str(exc)

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
            return

        try:
            from result_ingestion_engine import get_ingestion_engine, RawResult
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
        
        except ImportError as exc:
            log.error("result_ingestion_engine unavailable: %s", exc)
        except Exception as exc:
            log.error("ResultIngestionEngine.ingest_batch() failed: %s", exc)


    def _phase_severity_followup(self, session: ScanSession, ctx: dict) -> None:
        """Run deeper targeted scans for high/critical findings."""
        try:
            from result_ingestion_engine import get_ingestion_engine
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
                from modules.tool_wrappers import ToolRegistry
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
                from result_ingestion_engine import get_ingestion_engine, RawResult
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
            from result_ingestion_engine import get_ingestion_engine
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
        """Generate a human-readable markdown report."""
        output_dir = get_target_path(session.target, subdir="findings")
        report_path = output_dir / f"report_{session.scan_id[:8]}.md"

        lines: List[str] = [
            f"# Scan Report — {session.target}",
            f"",
            f"**Scan ID:** {session.scan_id}",
            f"**Target type:** {session.target_type}",
            f"**Status:** {session.status}",
            f"**Duration:** {round(session.end_time - session.start_time, 1) if session.end_time else 'in progress'}s",
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
                lines.append(f"- **{title}** — `{url}`")
            lines.append("")

        try:
            report_path.write_text("\n".join(lines), encoding="utf-8")
            log.info("Report written to %s", report_path)
            session.phases["report"].meta["report_path"] = str(report_path)
        except Exception as exc:
            log.warning("Failed to write report to %s: %s", report_path, exc)

    def _phase_done(self, session: ScanSession, ctx: dict) -> None:
        """Mark scan as complete, emit quality metrics, and do a final DB persist."""
        session.status = "completed"

        # ── Scan Quality Metrics ─────────────────────────────────────────────
        try:
            from result_ingestion_engine import get_ingestion_engine
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
