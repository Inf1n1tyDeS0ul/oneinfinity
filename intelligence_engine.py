"""
intelligence_engine.py — Unified AI & Intelligence Interface

Merges the capabilities of five specialised engines into one coherent API:
  - ai_security_engine      (Garak, PyRIT, Giskard, Rebuff, ART)
  - ai_redteam_engine       (adversarial campaigns: jailbreak, prompt injection, etc.)
  - ai_agent_pentest_engine (tool abuse, API abuse, data exfiltration)
  - vulnerability_theory_engine (rule-based theory generation from AppModels)
  - zero_day_engine         (anomaly detection: status changes, leakage, timing)

All methods are synchronous wrappers; async internals are run via asyncio.run()
where necessary.  Every method returns ``List[dict]`` with a standardised
finding schema.

Finding schema (guaranteed keys):

    {
        "id":         str,    # UUID4
        "title":      str,
        "severity":   str,    # critical | high | medium | low | info
        "vuln_type":  str,
        "target":     str,
        "evidence":   str,
        "confidence": float,  # 0.0 – 1.0
        "tool":       str,    # originating engine / tool name
        "created_at": float,  # unix timestamp
    }

Usage::

    ie = get_intelligence_engine()
    findings = ie.run_all("https://chat.example.com", target_type="ai")
    for f in findings:
        print(f["severity"], f["title"])
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from path_manager import db_path, resolve_output_dir

log = logging.getLogger("oneinfinity.intelligence_engine")

# ---------------------------------------------------------------------------
# Finding normalisation helpers
# ---------------------------------------------------------------------------

def _new_id() -> str:
    return str(uuid.uuid4())


def _normalise(raw: Any, tool: str, target: str) -> dict:
    """
    Convert an arbitrary finding object (dict, dataclass, str) into the
    standard finding schema.  Missing fields are filled with safe defaults.
    """
    if isinstance(raw, dict):
        d = raw
    elif hasattr(raw, "__dict__"):
        d = vars(raw)
    elif hasattr(raw, "to_dict"):
        d = raw.to_dict()
    else:
        d = {"title": str(raw)}

    def _get(*keys: str, default: Any = "") -> Any:
        for k in keys:
            if d.get(k) not in (None, ""):
                return d[k]
        return default

    severity = str(_get("severity", "risk_level", default="info")).lower()
    if severity not in ("critical", "high", "medium", "low", "info"):
        severity = "info"

    return {
        "id":         _get("id", "finding_id", default=_new_id()),
        "title":      str(_get("title", "name", "vuln_type", "description", "type", default="Finding")),
        "severity":   severity,
        "vuln_type":  str(_get("vuln_type", "type", "category", default="unknown")),
        "target":     str(_get("target", "url", "endpoint", default=target)),
        "evidence":   str(_get("evidence", "details", "description", "body_snippet", default="")),
        "confidence": float(_get("confidence", "score", default=0.5)),
        "tool":       str(_get("tool", "source", default=tool)),
        "created_at": float(_get("created_at", "timestamp", default=time.time())),
    }


def _normalise_list(raw_list: List[Any], tool: str, target: str) -> List[dict]:
    out: List[dict] = []
    for item in raw_list or []:
        try:
            out.append(_normalise(item, tool, target))
        except Exception as exc:
            log.debug("Failed to normalise finding from %s: %s", tool, exc)
    return out


def _run_async(coro: Any) -> Any:
    """Run an async coroutine in a new event loop (safe from sync context)."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=600)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# IntelligenceEngine
# ---------------------------------------------------------------------------

class IntelligenceEngine:
    """
    Unified interface for all AI-related intelligence capabilities.

    Each method lazily imports its backing engine so the class can be
    instantiated even if optional dependencies are missing.
    """

    # ── AI Security Testing ──────────────────────────────────────────────────

    def run_ai_security(
        self,
        target: str,
        options: Optional[Dict] = None,
    ) -> List[dict]:
        """
        Run AI security tool suite (Garak, PyRIT, Giskard, Rebuff, ART).

        Parameters
        ----------
        target:
            AI endpoint URL or model identifier.
        options:
            Optional dict forwarded to AISecurityScanConfig.

        Returns
        -------
        List[dict]
            Normalised findings.
        """
        options = options or {}
        try:
            from ai_security_engine import AISecurityEngine, AISecurityScanConfig
        except ImportError as exc:
            log.error("run_ai_security: ai_security_engine unavailable — %s", exc)
            return []

        try:
            config = AISecurityScanConfig(
                target=target,
                output_dir=str(resolve_output_dir(None, target)),
                **{k: v for k, v in options.items() if k not in ("target",)},
            )
            engine = AISecurityEngine()
            result = _run_async(engine.scan(config))
            raw_findings = getattr(result, "findings", []) or []
            normalised = _normalise_list(raw_findings, "ai_security_engine", target)
            log.info("run_ai_security produced %d findings for %s", len(normalised), target)
            return normalised
        except Exception as exc:
            log.error("run_ai_security failed for %s: %s", target, exc)
            return []

    # ── Red Team Campaigns ───────────────────────────────────────────────────

    def run_redteam(
        self,
        target: str,
        options: Optional[Dict] = None,
    ) -> List[dict]:
        """
        Run adversarial red team campaigns (jailbreak, prompt injection, data leak, etc.).

        Parameters
        ----------
        target:
            AI endpoint URL or model identifier.
        options:
            Optional dict; ``campaign`` key selects a specific campaign name.

        Returns
        -------
        List[dict]
            Normalised findings.
        """
        options = options or {}
        try:
            from ai_redteam_engine import AIRedTeamEngine
        except ImportError as exc:
            log.error("run_redteam: ai_redteam_engine unavailable — %s", exc)
            return []

        try:
            engine = AIRedTeamEngine()
            campaign = options.get("campaign", None)
            if campaign:
                result = _run_async(engine.run_campaign(target, campaign=campaign))
                raw_findings = getattr(result, "findings", []) or []
            else:
                results = _run_async(engine.run_all_campaigns(target))
                raw_findings = []
                for r in (results or []):
                    raw_findings.extend(getattr(r, "findings", []) or [])
            normalised = _normalise_list(raw_findings, "ai_redteam_engine", target)
            log.info("run_redteam produced %d findings for %s", len(normalised), target)
            return normalised
        except Exception as exc:
            log.error("run_redteam failed for %s: %s", target, exc)
            return []

    # ── AI Agent Pentesting ──────────────────────────────────────────────────

    def run_agent_pentest(
        self,
        target: str,
        options: Optional[Dict] = None,
    ) -> List[dict]:
        """
        Run AI agent security tests: tool abuse, API abuse, data exfiltration.

        Parameters
        ----------
        target:
            AI agent endpoint URL.
        options:
            Optional dict forwarded to AgentPentestConfig.

        Returns
        -------
        List[dict]
            Normalised findings.
        """
        options = options or {}
        try:
            from ai_agent_pentest_engine import AIAgentPentestEngine, AgentPentestConfig
        except ImportError as exc:
            log.error("run_agent_pentest: ai_agent_pentest_engine unavailable — %s", exc)
            return []

        try:
            config = AgentPentestConfig(
                target=target,
                output_dir=str(resolve_output_dir(None, target)),
                **{k: v for k, v in options.items() if k not in ("target",)},
            )
            engine = AIAgentPentestEngine(config)
            result = _run_async(engine.run())
            raw_findings = getattr(result, "findings", []) or []
            normalised = _normalise_list(raw_findings, "ai_agent_pentest_engine", target)
            log.info("run_agent_pentest produced %d findings for %s", len(normalised), target)
            return normalised
        except Exception as exc:
            log.error("run_agent_pentest failed for %s: %s", target, exc)
            return []

    # ── Vulnerability Theory Generation ─────────────────────────────────────

    def generate_theories(self, app_model: Any) -> List[dict]:
        """
        Generate structured vulnerability theories from an AppModel.

        Wraps ``VulnTheoryEngine.generate_vulnerability_theories()``.

        Parameters
        ----------
        app_model:
            An ``AppModel`` instance (from ``application_intelligence``) or a
            dict with the same shape.

        Returns
        -------
        List[dict]
            Normalised findings — each theory is surfaced as a finding with
            ``vuln_type`` set to the theory type, ``confidence`` from the
            theory's confidence score, and ``severity`` from the theory.
        """
        try:
            from vulnerability_theory_engine import VulnTheoryEngine
        except ImportError as exc:
            log.error("generate_theories: vulnerability_theory_engine unavailable — %s", exc)
            return []

        try:
            engine = VulnTheoryEngine()
            theory_set = engine.generate_vulnerability_theories(app_model)
            theories = getattr(theory_set, "theories", []) or []
            target = getattr(app_model, "target", "unknown")
            raw = [t.to_dict() if hasattr(t, "to_dict") else t for t in theories]
            normalised = _normalise_list(raw, "vulnerability_theory_engine", target)
            log.info("generate_theories produced %d theories for %s", len(normalised), target)
            return normalised
        except Exception as exc:
            log.error("generate_theories failed: %s", exc)
            return []

    # ── Zero-Day Anomaly Detection ───────────────────────────────────────────

    def run_zero_day(
        self,
        target: str,
        options: Optional[Dict] = None,
    ) -> List[dict]:
        """
        Run anomaly-based zero-day detection against a web target.

        Parameters
        ----------
        target:
            Domain or URL to probe.
        options:
            Optional dict; keys ``endpoints``, ``test_results``, ``timeout``,
            and ``rate_limit`` are forwarded to ZeroDayEngine.

        Returns
        -------
        List[dict]
            Normalised anomaly findings.
        """
        options = options or {}
        try:
            from zero_day_engine import ZeroDayEngine
        except ImportError as exc:
            log.error("run_zero_day: zero_day_engine unavailable — %s", exc)
            return []

        try:
            engine = ZeroDayEngine(
                target=target,
                output_dir=str(resolve_output_dir(None, target)),
                timeout=int(options.get("timeout", 12)),
                rate_limit=float(options.get("rate_limit", 0.5)),
            )
            anomalies = engine.detect_anomalies(
                endpoints=options.get("endpoints"),
                test_results=options.get("test_results"),
            )
            raw = [a.to_dict() if hasattr(a, "to_dict") else a for a in (anomalies or [])]
            normalised = _normalise_list(raw, "zero_day_engine", target)
            log.info("run_zero_day produced %d anomalies for %s", len(normalised), target)
            return normalised
        except Exception as exc:
            log.error("run_zero_day failed for %s: %s", target, exc)
            return []

    # ── Unified Entry Point ──────────────────────────────────────────────────

    def run_all(
        self,
        target: str,
        target_type: str = "web",
    ) -> List[dict]:
        """
        Execute the appropriate intelligence methods based on *target_type*.

        Routing logic:
          - ``web`` / ``api``  → zero_day only
          - ``ai``             → ai_security + redteam + agent_pentest
          - ``mobile``         → empty (no AI intelligence applies)
          - unknown            → zero_day (safe default)

        Parameters
        ----------
        target:
            URL or domain to analyse.
        target_type:
            One of ``web``, ``api``, ``mobile``, ``ai``.

        Returns
        -------
        List[dict]
            Deduplicated, merged findings from all selected engines.
        """
        findings: List[dict] = []
        t_type = (target_type or "web").lower()

        if t_type in ("web", "api"):
            log.info("run_all(%s): running zero_day", target)
            findings.extend(self.run_zero_day(target))

        elif t_type == "ai":
            log.info("run_all(%s): running ai_security + redteam + agent_pentest", target)
            findings.extend(self.run_ai_security(target))
            findings.extend(self.run_redteam(target))
            findings.extend(self.run_agent_pentest(target))

        elif t_type == "mobile":
            log.info("run_all(%s): mobile target — no AI intelligence applicable", target)

        else:
            log.info("run_all(%s): unknown type '%s', falling back to zero_day", target, target_type)
            findings.extend(self.run_zero_day(target))

        log.info("run_all finished for %s (%s): %d total findings", target, t_type, len(findings))
        return findings


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_ie_instance: Optional[IntelligenceEngine] = None
_ie_lock: Any = None


def get_intelligence_engine() -> IntelligenceEngine:
    """Return the process-wide IntelligenceEngine singleton."""
    global _ie_instance, _ie_lock
    if _ie_lock is None:
        import threading
        _ie_lock = threading.Lock()
    if _ie_instance is None:
        with _ie_lock:
            if _ie_instance is None:
                _ie_instance = IntelligenceEngine()
    return _ie_instance
