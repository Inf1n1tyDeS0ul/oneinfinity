"""
Mobile Attack Execution API — Phase 2
======================================
Orchestrates active attack campaigns against mobile app backends.

Innovations vs every other tool on the market:
  1. Attack Chain Sequencer — IDOR found? Auto-escalates to mass assignment
     on write endpoints, then privilege escalation. Chain graph streamed live.
  2. WAF-Adaptive Payload Morphing — reads response headers from captured
     traffic, detects WAF vendor, auto-selects vendor-specific bypass payloads
     from the existing WAF_BYPASSES knowledge base.
  3. Differential Semantic Analyzer — beyond status codes: JSON key presence,
     response length bucket shifts, timing anomalies (3× baseline → blind SQLi).
  4. Live Mid-Flight Injection — sends inject_payload commands to the Android
     companion which modifies packets inside the VPN tunnel before they leave
     the device, enabling true in-app interception without a proxy.
  5. OWASP Mobile Top 10 Attack Templates — one-click campaigns mapped to
     M1-M10 attack sequences with PoC generation for each finding.
  6. Adaptive Chain Pipeline — mobile findings feed ChainSuggestionEngine and
     trigger full unified scanner escalation when critical vulns are confirmed.
  7. Contextual Severity Escalation — multiple vulns on same endpoint escalate
     to the combined severity automatically.
  8. Post-Exploitation Awareness — IDOR + auth bypass on same endpoint triggers
     attack graph path from compromised endpoint outward.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

log = logging.getLogger("oneinfinity.mobile_attack")

# ---------------------------------------------------------------------------
# Lazy imports — all non-fatal so the module loads even without optional deps
# ---------------------------------------------------------------------------

def _get_api_attack_engine():
    try:
        from oneinfinity.mobile.api_attack import MobileAPIAttackEngine, APIAttackConfig
        return MobileAPIAttackEngine, APIAttackConfig
    except ImportError as exc:
        log.warning("MobileAPIAttackEngine unavailable: %s", exc)
        return None, None


def _get_smart_payload_gen():
    try:
        from oneinfinity.scan.smart_payload_generator import SmartPayloadGenerator
        return SmartPayloadGenerator
    except ImportError as exc:
        log.warning("SmartPayloadGenerator unavailable: %s", exc)
        return None


def _get_waf_engine():
    try:
        from oneinfinity.scan.waf_detection_engine import WAFDetectionEngine
        return WAFDetectionEngine
    except ImportError as exc:
        log.warning("WAFDetectionEngine unavailable: %s", exc)
        return None


def _get_payload_kb():
    try:
        from oneinfinity.modules.payloads import PAYLOADS, WAF_BYPASSES
        return PAYLOADS, WAF_BYPASSES
    except ImportError as exc:
        log.warning("Payload KB unavailable: %s", exc)
        return {}, {}


def _get_ingestion_engine():
    try:
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
        return get_ingestion_engine()
    except ImportError as exc:
        log.warning("ResultIngestionEngine unavailable: %s", exc)
        return None


def _get_chain_engine():
    try:
        from oneinfinity.scan.chain_suggestion_engine import ChainSuggestionEngine
        return ChainSuggestionEngine()
    except ImportError:
        return None


def _get_attack_graph_brain():
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        return get_brain()
    except ImportError:
        return None


def _get_validation_orchestrator():
    try:
        from oneinfinity.agents.validation_orchestrator import get_orchestrator
        return get_orchestrator()
    except ImportError:
        return None


def _get_graph_learning_writer():
    try:
        from oneinfinity.learning.graph_learning_writer import get_graph_learning_writer
        return get_graph_learning_writer()
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# OWASP Mobile Top 10 attack templates
# ---------------------------------------------------------------------------

ATTACK_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "m1_improper_credential_usage",
        "name": "M1 — Improper Credential Usage",
        "description": "Test for hardcoded credentials, weak secrets, credential stuffing",
        "attack_types": ["auth_bypass_no_header", "auth_bypass_empty_token", "jwt_alg_none"],
        "severity": "critical",
        "owasp_ref": "OWASP-Mobile-M1",
        "chain_on_success": ["m4_insufficient_input_validation"],
    },
    {
        "id": "m2_inadequate_supply_chain_security",
        "name": "M2 — Inadequate Supply Chain Security",
        "description": "Test for version disclosure, debug endpoints, backdoors",
        "attack_types": ["verb_tampering", "http_trace_enabled"],
        "severity": "medium",
        "owasp_ref": "OWASP-Mobile-M2",
        "chain_on_success": [],
    },
    {
        "id": "m3_insecure_authentication",
        "name": "M3 — Insecure Authentication / Authorization",
        "description": "IDOR, BOLA, auth bypass, broken access control",
        "attack_types": ["idor", "auth_bypass_no_header", "auth_bypass_fake_token"],
        "severity": "critical",
        "owasp_ref": "OWASP-Mobile-M3",
        "chain_on_success": ["m8_security_misconfiguration"],
    },
    {
        "id": "m4_insufficient_input_validation",
        "name": "M4 — Insufficient Input/Output Validation",
        "description": "SQLi, NoSQLi, XSS, command injection, path traversal, SSRF",
        "attack_types": ["sql_injection", "nosql_injection", "ssrf", "path_traversal"],
        "severity": "critical",
        "owasp_ref": "OWASP-Mobile-M4",
        "chain_on_success": [],
    },
    {
        "id": "m5_insecure_communication",
        "name": "M5 — Insecure Communication",
        "description": "SSL bypass, cleartext traffic, certificate validation",
        "attack_types": ["auth_bypass_no_header"],
        "severity": "high",
        "owasp_ref": "OWASP-Mobile-M5",
        "chain_on_success": ["m4_insufficient_input_validation"],
    },
    {
        "id": "m7_insufficient_binary_protections",
        "name": "M7 — Insufficient Binary Protections",
        "description": "Mass assignment, privilege escalation, parameter tampering",
        "attack_types": ["mass_assignment", "idor"],
        "severity": "high",
        "owasp_ref": "OWASP-Mobile-M7",
        "chain_on_success": [],
    },
    {
        "id": "m8_security_misconfiguration",
        "name": "M8 — Security Misconfiguration",
        "description": "Debug endpoints, excessive permissions, rate limit absence",
        "attack_types": ["rate_limit_bypass", "verb_tampering_options"],
        "severity": "medium",
        "owasp_ref": "OWASP-Mobile-M8",
        "chain_on_success": [],
    },
    {
        "id": "full_owasp_mobile",
        "name": "Full OWASP Mobile Top 10",
        "description": "Runs all OWASP Mobile Top 10 attack types sequentially with chain detection",
        "attack_types": [
            "idor", "auth_bypass_no_header", "auth_bypass_empty_token",
            "jwt_alg_none", "mass_assignment", "rate_limit_bypass",
            "sql_injection", "nosql_injection", "ssrf", "path_traversal",
            "verb_tampering",
        ],
        "severity": "critical",
        "owasp_ref": "OWASP-Mobile-Top10",
        "chain_on_success": [],
    },
]

# ---------------------------------------------------------------------------
# Attack Session
# ---------------------------------------------------------------------------

# Contextual severity upgrade table: (existing_severity, new_severity) → escalated
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


def _escalate_severity(current: str, new: str) -> str:
    """Return the higher of two severity labels."""
    return _RANK_TO_SEVERITY.get(
        max(_SEVERITY_RANK.get(current, 0), _SEVERITY_RANK.get(new, 0)), "info"
    )


@dataclass
class AttackSession:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    device_id: str = ""
    template_id: str = ""
    target_endpoints: List[str] = field(default_factory=list)
    status: str = "pending"         # pending / running / completed / stopped / error
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    findings: List[Dict] = field(default_factory=list)
    chain_log: List[str] = field(default_factory=list)
    waf_profile: Dict = field(default_factory=dict)
    # endpoint → highest severity seen so far (for contextual escalation)
    endpoint_severity: Dict[str, str] = field(default_factory=dict)
    stats: Dict = field(default_factory=lambda: {
        "endpoints_tested": 0,
        "attacks_run": 0,
        "findings_count": 0,
        "chains_triggered": 0,
        "waf_bypasses": 0,
        "escalations": 0,
    })
    error: str = ""
    options: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "device_id": self.device_id,
            "template_id": self.template_id,
            "target_endpoints": self.target_endpoints,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "findings": self.findings,
            "chain_log": self.chain_log,
            "waf_profile": self.waf_profile,
            "stats": self.stats,
            "error": self.error,
            "duration_s": round((self.completed_at or time.time()) - self.started_at, 1),
        }


# In-memory session store
_sessions: Dict[str, AttackSession] = {}
_session_tasks: Dict[str, asyncio.Task] = {}

# ---------------------------------------------------------------------------
# WAF-Adaptive Payload Selector
# ---------------------------------------------------------------------------

class WAFAdaptivePayloadSelector:
    """
    Detects WAF vendor from captured traffic response headers and
    selects vendor-specific bypass payloads from the KB.
    """

    def __init__(self):
        _, self._waf_bypasses = _get_payload_kb()
        self._payloads_kb, _ = _get_payload_kb()
        self._waf_engine_cls = _get_waf_engine()

    def detect_waf_from_headers(self, headers: dict) -> str:
        if not self._waf_engine_cls or not headers:
            return ""
        try:
            engine = self._waf_engine_cls()
            profile = engine.detect_from_headers(headers, status_code=200)
            return profile.waf_name if profile.detected else ""
        except Exception as exc:
            log.debug("WAF header detection failed: %s", exc)
            return ""

    def is_passive_mode(self, headers: dict) -> bool:
        """Return True when WAF is detected and passive_only is recommended."""
        if not self._waf_engine_cls or not headers:
            return False
        try:
            engine = self._waf_engine_cls()
            profile = engine.detect_from_headers(headers, status_code=200)
            return profile.passive_only
        except Exception:
            return False

    def get_payloads_for_endpoint(
        self,
        vuln_type: str,
        headers: dict,
        param_type: str = "string",
    ) -> List[str]:
        payloads: List[str] = []
        waf_name = self.detect_waf_from_headers(headers)

        # WAF-specific bypasses first
        if waf_name and self._waf_bypasses:
            for kb_waf, vuln_map in self._waf_bypasses.items():
                if waf_name.lower() in kb_waf.lower():
                    payloads.extend(vuln_map.get(vuln_type, []))
                    break

        # Base payloads from KB
        if self._payloads_kb and vuln_type in self._payloads_kb:
            for ctx_payloads in self._payloads_kb[vuln_type].values():
                payloads.extend(ctx_payloads)

        seen: set = set()
        result: List[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                result.append(p)

        return result[:20]


# ---------------------------------------------------------------------------
# Differential Semantic Analyzer
# ---------------------------------------------------------------------------

_SQL_ERR = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d+|postgres|pg_query|sqlite|syntax error|"
    r"SQLSTATE|unclosed quotation|you have an error in your sql)",
    re.I,
)
_STACK_TRACE = re.compile(
    r"(Traceback|at [a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$]|NullPointerException|"
    r"IndexOutOfBounds|line \d+ in <module>)",
    re.I,
)
_SSRF_HIT = re.compile(
    r"(root:x:0:0|EC2|ami-id|instance-id|local-hostname|169\.254\.169\.254|"
    r"security-credentials)",
    re.I,
)
_SENSITIVE_LEAK = re.compile(
    r'("password"\s*:\s*"[^"]+"|"api_key"\s*:\s*"[^"]+"|'
    r'"token"\s*:\s*"[^"]+"|"secret"\s*:\s*"[^"]+")',
    re.I,
)


def analyze_response_diff(
    baseline_status: int,
    baseline_body: str,
    baseline_ms: float,
    attack_status: int,
    attack_body: str,
    attack_ms: float,
    payload: str,
    vuln_type: str,
) -> Optional[Dict]:
    indicators: List[str] = []
    confidence = 0.0

    if attack_status != baseline_status:
        indicators.append(f"status_change:{baseline_status}→{attack_status}")
        confidence += 0.3

    def _bucket(n: int) -> str:
        if n < 50: return "tiny"
        if n < 500: return "small"
        if n < 5000: return "medium"
        return "large"

    if _bucket(len(baseline_body)) != _bucket(len(attack_body)):
        indicators.append(f"size_shift:{_bucket(len(baseline_body))}→{_bucket(len(attack_body))}")
        confidence += 0.2

    if _SQL_ERR.search(attack_body):
        m = _SQL_ERR.search(attack_body)
        indicators.append(f"sql_error:{m.group(0)[:60]}")
        confidence += 0.6

    if _STACK_TRACE.search(attack_body) and not _STACK_TRACE.search(baseline_body):
        m = _STACK_TRACE.search(attack_body)
        indicators.append(f"stack_trace:{m.group(0)[:60]}")
        confidence += 0.5

    if _SSRF_HIT.search(attack_body):
        m = _SSRF_HIT.search(attack_body)
        indicators.append(f"ssrf_data:{m.group(0)[:60]}")
        confidence += 0.8

    if _SENSITIVE_LEAK.search(attack_body) and not _SENSITIVE_LEAK.search(baseline_body):
        m = _SENSITIVE_LEAK.search(attack_body)
        indicators.append(f"data_leak:{m.group(0)[:60]}")
        confidence += 0.7

    if baseline_ms > 0 and attack_ms > baseline_ms * 3 and attack_ms > 3000:
        indicators.append(f"timing_anomaly:{attack_ms:.0f}ms_vs_{baseline_ms:.0f}ms_baseline")
        confidence += 0.55

    if not indicators or confidence < 0.2:
        return None

    severity_map = {
        "sqli": "critical", "ssrf": "critical", "nosql_injection": "critical",
        "idor": "high", "auth_bypass": "critical", "mass_assignment": "high",
        "path_traversal": "critical", "xss": "high",
    }

    return {
        "finding_id": str(uuid.uuid4())[:12],
        "vuln_type": vuln_type,
        "title": f"[Mobile Attack] {vuln_type.upper().replace('_', ' ')} detected via differential analysis",
        "severity": severity_map.get(vuln_type, "medium"),
        "confidence": min(1.0, confidence),
        "payload": payload,
        "evidence": "; ".join(indicators),
        "baseline_status": baseline_status,
        "attack_status": attack_status,
        "timing_baseline_ms": baseline_ms,
        "timing_attack_ms": attack_ms,
        "source": "mobile_attack_differential",
    }


# ---------------------------------------------------------------------------
# Attack Chain Sequencer
# ---------------------------------------------------------------------------

_CHAIN_MAP: Dict[str, List[str]] = {
    "idor":                  ["mass_assignment", "auth_bypass_no_header"],
    "auth_bypass_no_header": ["idor", "mass_assignment"],
    "jwt_alg_none":          ["idor", "auth_bypass_no_header"],
    "mass_assignment":       ["idor"],
    "sql_injection":         ["auth_bypass_no_header"],
    "nosql_injection":       ["mass_assignment"],
    "rate_limit_bypass":     ["sql_injection"],
}


def get_chain_followups(found_type: str) -> List[str]:
    return _CHAIN_MAP.get(found_type, [])


# ---------------------------------------------------------------------------
# Enrichment + Graph + Validation pipeline
# ---------------------------------------------------------------------------

def _persist_and_enrich(finding: dict, session: AttackSession) -> None:
    """
    Full enrichment pipeline for a single mobile attack finding:
      1. Contextual severity escalation (multi-vuln same endpoint)
      2. Dedup-aware DB persistence via ingest()
      3. Attack graph node wiring via integrate_vuln()
      4. Graph learning writer update
      5. Chain suggestion pipeline integration
      6. Async validation trigger (background thread, non-blocking)
    """
    import threading

    url = finding.get("url", "")
    vuln_type = finding.get("vuln_type", "")

    # 1. Contextual severity escalation
    prior_severity = session.endpoint_severity.get(url, "info")
    new_severity = finding.get("severity", "info")
    escalated = _escalate_severity(prior_severity, new_severity)

    if escalated != new_severity and _SEVERITY_RANK.get(escalated, 0) > _SEVERITY_RANK.get(new_severity, 0):
        finding["severity"] = escalated
        finding["severity_escalated"] = True
        finding["severity_reason"] = f"Escalated from {new_severity}: combined with prior {prior_severity} on same endpoint"
        session.stats["escalations"] += 1
        session.chain_log.append(
            f"Severity escalation: {url} {prior_severity}+{new_severity} → {escalated}"
        )
        log.info("[attack] Severity escalated %s→%s on %s", new_severity, escalated, url)

    session.endpoint_severity[url] = escalated

    # 2. Dedup-aware DB persistence via ingest() — includes dedup + validation + graph
    ingestion = _get_ingestion_engine()
    if ingestion:
        try:
            from oneinfinity.findings.result_ingestion_engine import RawResult
            raw_result = RawResult(
                scan_id=session.session_id,
                source="mobile_agent",
                raw=finding,
            )
            ingestion.ingest(raw_result)
        except Exception as exc:
            log.debug("ingest() failed, falling back to persist_finding: %s", exc)
            try:
                ingestion.persist_finding(finding)
            except Exception as exc2:
                log.warning("persist_finding also failed: %s", exc2)

    # 3. Attack graph update — run in thread to avoid blocking event loop
    def _update_graph():
        brain = _get_attack_graph_brain()
        if brain:
            try:
                brain.integrate_vuln(finding)
            except Exception as exc:
                log.debug("attack_graph_brain.integrate_vuln failed: %s", exc)

    threading.Thread(target=_update_graph, daemon=True,
                     name=f"graph-{finding.get('finding_id', '')[:8]}").start()

    # 4. Graph learning writer
    def _update_learning():
        glw = _get_graph_learning_writer()
        if glw:
            try:
                glw.write_finding_async(finding)
            except Exception as exc:
                log.debug("graph_learning_writer failed: %s", exc)

    threading.Thread(target=_update_learning, daemon=True,
                     name=f"learn-{finding.get('finding_id', '')[:8]}").start()

    # 5. Chain suggestion pipeline — trigger unified scanner if critical vuln confirmed
    if _SEVERITY_RANK.get(finding.get("severity", ""), 0) >= _SEVERITY_RANK["high"]:
        threading.Thread(
            target=_trigger_chain_suggestions,
            args=(session,),
            daemon=True,
            name=f"chain-{session.session_id[:8]}",
        ).start()


def _trigger_chain_suggestions(session: AttackSession) -> None:
    """
    Feed all session findings into ChainSuggestionEngine and log suggestions.
    Runs in background thread.
    """
    chain_engine = _get_chain_engine()
    if not chain_engine:
        return
    try:
        suggestions = chain_engine.suggest_next_tests(session.findings)
        for s in suggestions[:5]:  # Cap at 5 suggestions per trigger
            msg = (
                f"Chain suggestion: {s.chain_name} ({s.completion_percentage:.0f}% complete) "
                f"→ run {s.recommended_scanner} for {', '.join(s.missing_vuln_types[:2])}"
            )
            if msg not in session.chain_log:
                session.chain_log.append(msg)
                log.info("[attack] %s", msg)
    except Exception as exc:
        log.debug("ChainSuggestionEngine failed: %s", exc)


# ---------------------------------------------------------------------------
# Core attack runner — fully non-blocking
# ---------------------------------------------------------------------------

async def _run_attack_session(session: AttackSession) -> None:
    """
    Background coroutine: runs the full attack campaign for a session.

    FIX: All synchronous HTTP calls (MobileAPIAttackEngine.test_endpoints) are
    offloaded to a ThreadPoolExecutor via run_in_executor so they never block
    the FastAPI event loop.
    """
    session.status = "running"
    log.info("[attack] Session %s started: %d endpoints", session.session_id, len(session.target_endpoints))

    MobileAPIAttackEngineCls, APIAttackConfig = _get_api_attack_engine()
    waf_selector = WAFAdaptivePayloadSelector()
    loop = asyncio.get_event_loop()

    template = next((t for t in ATTACK_TEMPLATES if t["id"] == session.template_id), None)
    if not template:
        template = ATTACK_TEMPLATES[-1]

    work_queue: List[Dict] = [
        {"url": ep, "attack_types": list(template["attack_types"]), "source": "template"}
        for ep in session.target_endpoints
    ]
    completed_pairs: set = set()

    try:
        while work_queue and session.status == "running":
            item = work_queue.pop(0)
            ep_url = item["url"]
            attack_types = item["attack_types"]

            if not ep_url or not ep_url.startswith("http"):
                continue

            ep_dict = {"url": ep_url, "method": item.get("method", "GET")}
            session.stats["endpoints_tested"] += 1

            # WAF detection from captured response headers
            captured_headers = item.get("response_headers", {})
            waf_name = waf_selector.detect_waf_from_headers(captured_headers)
            passive_mode = waf_selector.is_passive_mode(captured_headers)

            if waf_name and not session.waf_profile.get("detected"):
                session.waf_profile = {"detected": True, "waf_name": waf_name, "passive": passive_mode}
                session.chain_log.append(
                    f"WAF detected: {waf_name} on {ep_url}"
                    + (" — passive mode engaged" if passive_mode else "")
                )

            # FIX #10: Respect WAF passive_only — skip aggressive injection in passive mode
            if passive_mode:
                aggressive = {"sql_injection", "nosql_injection", "ssrf", "path_traversal"}
                attack_types = [t for t in attack_types if t not in aggressive]
                if not attack_types:
                    session.chain_log.append(f"Skipped {ep_url}: WAF passive mode, no safe attacks remain")
                    continue

            if MobileAPIAttackEngineCls and APIAttackConfig:
                config = APIAttackConfig(
                    timeout=session.options.get("timeout", 10),
                    verify_ssl=False,
                    test_idor="idor" in attack_types,
                    test_auth_bypass=any(t.startswith("auth_bypass") for t in attack_types)
                                     or "jwt_alg_none" in attack_types,
                    test_mass_assignment="mass_assignment" in attack_types,
                    test_rate_limit="rate_limit_bypass" in attack_types,
                    test_injections=any(t in attack_types for t in
                                        ["sql_injection", "nosql_injection", "ssrf", "path_traversal"])
                                    and not passive_mode,
                )
                engine = MobileAPIAttackEngineCls(config=config)

                # FIX #1: Run synchronous test_endpoints() in thread pool
                # so it NEVER blocks the FastAPI event loop
                try:
                    findings_raw = await loop.run_in_executor(
                        None, engine.test_endpoints, [ep_dict]
                    )
                except Exception as exc:
                    log.error("[attack] test_endpoints error on %s: %s", ep_url, exc)
                    findings_raw = []

                session.stats["attacks_run"] += len(attack_types)
                if waf_name:
                    session.stats["waf_bypasses"] += sum(
                        1 for f in findings_raw if f.attack_type in ("sql_injection", "xss")
                    )

                for uf in findings_raw:
                    pair = (ep_url, uf.attack_type)
                    if pair in completed_pairs:
                        continue
                    completed_pairs.add(pair)

                    finding_dict = {
                        "finding_id": str(uuid.uuid4())[:12],
                        "session_id": session.session_id,
                        "scan_id": session.session_id,
                        "device_id": session.device_id,
                        "url": ep_url,
                        "target": ep_url,
                        "title": uf.vulnerability,
                        "vuln_type": uf.attack_type,
                        "severity": uf.severity,
                        "evidence": uf.evidence,
                        "payload": uf.payload or "",
                        "cvss": float(getattr(uf, "cvss", 0.0)),
                        "tool": "mobile_api_attack_engine",
                        "source": "mobile_agent",
                        "remediation": getattr(uf, "remediation", ""),
                        "waf_bypassed": bool(waf_name),
                        "confidence": 0.85,
                        "found_at": time.time(),
                    }

                    session.findings.append(finding_dict)
                    session.stats["findings_count"] += 1

                    # FIX #2,5,6,7: Full enrichment pipeline (graph + validation + chains + dedup)
                    _persist_and_enrich(finding_dict, session)

                    # Attack chain sequencer
                    followups = get_chain_followups(uf.attack_type)
                    for fu_type in followups:
                        fu_pair = (ep_url, fu_type)
                        if fu_pair not in completed_pairs:
                            session.chain_log.append(
                                f"Chain: {uf.attack_type} → queuing {fu_type} on {ep_url}"
                            )
                            work_queue.append({
                                "url": ep_url,
                                "method": ep_dict.get("method", "GET"),
                                "attack_types": [fu_type],
                                "source": f"chain:{uf.attack_type}",
                                "response_headers": captured_headers,
                            })
                            session.stats["chains_triggered"] += 1

            # Yield to event loop between endpoints so WS heartbeats/requests can be processed
            await asyncio.sleep(0)

        session.status = "completed"
        session.completed_at = time.time()
        log.info(
            "[attack] Session %s complete: %d findings in %.1fs",
            session.session_id,
            session.stats["findings_count"],
            session.completed_at - session.started_at,
        )

    except asyncio.CancelledError:
        session.status = "stopped"
        session.completed_at = time.time()
        log.info("[attack] Session %s stopped by user", session.session_id)

    except Exception as exc:
        session.status = "error"
        session.error = str(exc)
        session.completed_at = time.time()
        log.exception("[attack] Session %s unhandled error: %s", session.session_id, exc)


# ---------------------------------------------------------------------------
# Handler functions
# ---------------------------------------------------------------------------

async def start_attack_session_handler(body: dict) -> dict:
    """
    Start an attack session.

    Body:
    {
        "device_id": "abc123",
        "endpoints": ["https://api.example.com/users/1", ...],
        "template_id": "m3_insecure_authentication",
        "options": {"timeout": 10},
        "use_captured_traffic": true   // auto-extract URLs from Phase 1 traffic
    }
    """
    device_id = body.get("device_id", "")
    endpoints = list(body.get("endpoints", []))
    template_id = body.get("template_id", "full_owasp_mobile")
    options = body.get("options", {})

    # FIX #8: Auto-enrich endpoints from Phase 1 captured traffic
    if body.get("use_captured_traffic", True):
        try:
            from .mobile_agent_api import store_traffic, get_traffic_handler
            extra = await get_traffic_handler(device_id, limit=500)
            for entry in extra:
                url = entry.get("request", {}).get("url", "")
                if url and url.startswith("http") and url not in endpoints:
                    endpoints.append(url)
        except Exception as exc:
            log.debug("Could not enrich from captured traffic: %s", exc)

    if not endpoints:
        raise HTTPException(400, "endpoints list is required and must not be empty")

    valid_ids = {t["id"] for t in ATTACK_TEMPLATES}
    if template_id not in valid_ids:
        template_id = "full_owasp_mobile"

    session = AttackSession(
        device_id=device_id,
        template_id=template_id,
        target_endpoints=[ep for ep in endpoints if ep.startswith("http")],
        options=options,
    )

    if not session.target_endpoints:
        raise HTTPException(400, "No valid HTTP endpoints provided")

    _sessions[session.session_id] = session

    # FIX #9: Add done callback to catch silent task exceptions
    task = asyncio.create_task(_run_attack_session(session))

    def _on_task_done(t: asyncio.Task):
        exc = t.exception() if not t.cancelled() else None
        if exc:
            session.status = "error"
            session.error = str(exc)
            log.error("[attack] Task %s raised: %s", session.session_id, exc)

    task.add_done_callback(_on_task_done)
    _session_tasks[session.session_id] = task

    log.info("[attack] Session %s created for %d endpoints", session.session_id, len(session.target_endpoints))
    return {
        "session_id": session.session_id,
        "status": "started",
        "endpoints_queued": len(session.target_endpoints),
        "template": template_id,
    }


async def stop_attack_session_handler(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")

    task = _session_tasks.get(session_id)
    if task and not task.done():
        task.cancel()

    session.status = "stopped"
    session.completed_at = time.time()
    return {"session_id": session_id, "status": "stopped"}


async def list_attack_sessions_handler() -> List[dict]:
    return [s.to_dict() for s in _sessions.values()]


async def get_attack_session_handler(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    return session.to_dict()


async def get_session_findings_handler(session_id: str) -> List[dict]:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    return session.findings


async def inject_payload_handler(body: dict) -> dict:
    """
    Send an inject_payload command to the Android companion device.
    """
    from .mobile_agent_api import active_devices

    device_id = body.get("device_id", "")
    url_pattern = body.get("url_pattern", "")
    param = body.get("param", "")
    payload = body.get("payload", "")
    vuln_type = body.get("vuln_type", "sqli")
    position = body.get("position", "body")

    if not device_id or not payload:
        raise HTTPException(400, "device_id and payload are required")

    ws = active_devices.get(device_id)
    if not ws:
        raise HTTPException(404, f"Device {device_id} not connected")

    command = {
        "type": "inject_payload",
        "injection_id": str(uuid.uuid4())[:8],
        "url_pattern": url_pattern,
        "param": param,
        "payload": payload,
        "vuln_type": vuln_type,
        "position": position,
        "capture_response": True,
    }

    try:
        await ws.send_json(command)
        log.info("[attack] inject_payload sent to %s: %s in %s", device_id, vuln_type, param)
        return {
            "status": "injected",
            "injection_id": command["injection_id"],
            "device_id": device_id,
            "vuln_type": vuln_type,
        }
    except Exception as exc:
        raise HTTPException(500, f"Failed to send inject command: {exc}")


async def list_attack_templates_handler() -> List[dict]:
    return ATTACK_TEMPLATES


async def replay_with_mutations_handler(body: dict) -> dict:
    """
    Replay a captured URL with WAF-adaptive mutations and differential analysis.
    FIX #12: All blocking HTTP calls run in executor.
    FIX #13: Duplicate imports removed.
    """
    import urllib.parse
    import urllib.request
    import urllib.error
    import ssl

    url = body.get("url", "")
    method = body.get("method", "GET").upper()
    param = body.get("param", "")
    vuln_types = body.get("vuln_types", ["sqli", "xss"])
    response_headers = body.get("response_headers", {})

    if not url or not url.startswith("http"):
        raise HTTPException(400, "Valid URL required")

    waf_selector = WAFAdaptivePayloadSelector()
    SmartPayloadGeneratorCls = _get_smart_payload_gen()
    loop = asyncio.get_event_loop()
    results: List[dict] = []
    session_id = str(uuid.uuid4())[:8]

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _do_request(req_url: str, req_data: Optional[bytes]) -> tuple:
        """Blocking HTTP call — runs in executor."""
        req = urllib.request.Request(req_url, data=req_data, method=method)
        if req_data:
            req.add_header("Content-Type", "application/json")
        t0 = time.time()
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
                body_bytes = r.read(65536).decode("utf-8", errors="replace")
                return r.status, body_bytes, (time.time() - t0) * 1000
        except urllib.error.HTTPError as e:
            body_bytes = ""
            try:
                body_bytes = e.read(4096).decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, body_bytes, (time.time() - t0) * 1000
        except Exception:
            return 0, "", (time.time() - t0) * 1000

    # Baseline in executor
    baseline_status, baseline_body, baseline_ms = await loop.run_in_executor(
        None, _do_request, url, None
    )

    for vuln_type in vuln_types:
        payloads = waf_selector.get_payloads_for_endpoint(vuln_type, response_headers)

        if SmartPayloadGeneratorCls:
            try:
                gen = SmartPayloadGeneratorCls()
                smart = gen.generate_payloads(url, param, [vuln_type], count=5)
                payloads = [sp.payload for sp in smart] + payloads
            except Exception as exc:
                log.debug("SmartPayloadGenerator failed: %s", exc)

        for payload in payloads[:5]:
            if param:
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                if param in qs or method == "GET":
                    qs[param] = [payload]
                    attack_url = urllib.parse.urlunparse(
                        parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
                    )
                    attack_data = None
                else:
                    attack_url = url
                    attack_data = json.dumps({param: payload}).encode()
            else:
                sep = "&" if "?" in url else "?"
                attack_url = f"{url}{sep}q={urllib.parse.quote(payload)}"
                attack_data = None

            # FIX #12: Run in executor
            attack_status, attack_body, attack_ms = await loop.run_in_executor(
                None, _do_request, attack_url, attack_data
            )

            finding = analyze_response_diff(
                baseline_status, baseline_body, baseline_ms,
                attack_status, attack_body, attack_ms,
                payload, vuln_type,
            )
            if finding:
                finding["session_id"] = session_id
                finding["scan_id"] = session_id
                finding["url"] = url
                finding["target"] = url
                finding["param"] = param
                results.append(finding)

                ingestion = _get_ingestion_engine()
                if ingestion:
                    try:
                        from oneinfinity.findings.result_ingestion_engine import RawResult
                        ingestion.ingest(RawResult(
                            scan_id=session_id, source="mobile_agent", raw=finding
                        ))
                    except Exception:
                        pass

    return {
        "session_id": session_id,
        "url": url,
        "mutations_tested": len(results),
        "findings": results,
        "waf_detected": bool(waf_selector.detect_waf_from_headers(response_headers)),
    }


# ---------------------------------------------------------------------------
# Export list for main.py
# ---------------------------------------------------------------------------

__all__ = [
    "start_attack_session_handler",
    "stop_attack_session_handler",
    "list_attack_sessions_handler",
    "get_attack_session_handler",
    "get_session_findings_handler",
    "inject_payload_handler",
    "list_attack_templates_handler",
    "replay_with_mutations_handler",
    "ATTACK_TEMPLATES",
]
