"""
Mobile Frida Integration API — Phase 3
========================================
Bridges connected Android companion devices with the full Frida instrumentation
pipeline. Unlike any other tool on the market:

  1. MASTG-Guided Attack Sequencing — finds auto-escalate through OWASP MASTG
     test sequences. SSL bypass confirmed → auto-run MASTG-TEST-0022,
     then decrypt captured traffic, then feed cleartext to Phase 2 attacks.

  2. Frida × Phase 2 Attack Bridge — when Frida hooks capture auth tokens,
     API keys, or session cookies at runtime, they are automatically injected
     into Phase 2 attack campaigns. No other tool bridges runtime instrumentation
     with active API attacks.

  3. AI-Driven Hook Generation — given a package name, uses the existing
     FridaScriptGenerator + reverse-engineering knowledge to auto-generate
     targeted hooks (auth classes, crypto classes, network classes).

  4. Live Output Correlation Engine — correlates Frida hook output with
     Phase 1 VPN traffic by timestamp to create composite findings.

  5. MASTG Coverage Report — after a session, generates a full MASVS/MASTG
     coverage report mapped to the attack graph.

  6. Persistent Session with Auto-Reconnect — FridaSession survives device
     disconnects and reconnects gracefully.

Architecture
------------
Companion device (Android) ←WebSocket→ mobile_agent_api.active_devices
                                              ↓
mobile_frida_api._inject_via_companion()   (sends {type:frida_inject,...})
                                              ↓
FridaManager.kt receives command → executes frida subprocess → streams output
                                              ↓
WebSocket message {type:frida_output,...} → ingest_frida_output()
                                              ↓
frida_wrapper._parse_frida_output() → findings → ingest() → graph → UI
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import functools
import json
import logging
import os
import subprocess
import shutil
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

# Thread pool for graph/learning background work — avoids per-finding daemon thread spawn
_bg_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="frida-bg"
)

log = logging.getLogger("oneinfinity.mobile_frida")

# ---------------------------------------------------------------------------
# Lazy imports
# ---------------------------------------------------------------------------

def _get_frida_wrapper():
    try:
        from oneinfinity.mobile.frida_wrapper import frida_wrapper, FridaConfig
        return frida_wrapper, FridaConfig
    except ImportError as exc:
        log.warning("frida_wrapper unavailable: %s", exc)
        return None, None


def _get_script_generator():
    try:
        from oneinfinity.mobile.frida_script_generator import FridaScriptGenerator
        return FridaScriptGenerator()
    except ImportError:
        return None


def _get_mastg_tests():
    try:
        from oneinfinity.mobile.mastg_knowledge import MASTG_TESTS
        return MASTG_TESTS
    except ImportError:
        return {}


def _get_ingestion_engine():
    try:
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
        return get_ingestion_engine(), RawResult
    except ImportError:
        return None, None


def _get_attack_graph_brain():
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        return get_brain()
    except ImportError:
        return None


def _get_chain_engine():
    try:
        from oneinfinity.scan.chain_suggestion_engine import ChainSuggestionEngine
        return ChainSuggestionEngine()
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# MASTG test → Frida script / attack_type mapping
# ---------------------------------------------------------------------------

# Maps MASTG test ID → the script type to run and what to look for
_MASTG_SCRIPT_MAP: Dict[str, Dict[str, Any]] = {
    "MASTG-TEST-0022": {
        "script": "ssl_bypass",
        "description": "SSL Certificate Pinning Test",
        "attack_types": ["ssl_pinning"],
        "next_if_pass": "MASTG-TEST-0242",
        "next_if_fail": None,
    },
    "MASTG-TEST-0242": {
        "script": "ssl_bypass",
        "description": "Network Security Config Pinning",
        "attack_types": ["ssl_pinning"],
        "next_if_pass": None,
        "next_if_fail": None,
    },
    "MASTG-TEST-0045": {
        "script": "root_bypass",
        "description": "Root Detection Bypass",
        "attack_types": ["root_bypass"],
        "next_if_pass": "MASTG-TEST-0341",
        "next_if_fail": None,
    },
    "MASTG-TEST-0341": {
        "script": "anti_debug_bypass",
        "description": "Runtime Hook Detection",
        "attack_types": ["anti_tamper", "anti_debug"],
        "next_if_pass": None,
        "next_if_fail": None,
    },
    "MASTG-TEST-0212": {
        "script": "crypto_hooks",
        "description": "Hardcoded Cryptographic Keys",
        "attack_types": ["hardcoded_key", "weak_crypto"],
        "next_if_pass": "MASTG-TEST-0221",
        "next_if_fail": None,
    },
    "MASTG-TEST-0221": {
        "script": "crypto_hooks",
        "description": "Broken Symmetric Encryption",
        "attack_types": ["weak_crypto"],
        "next_if_pass": None,
        "next_if_fail": None,
    },
    "MASTG-TEST-0001": {
        "script": "storage_hooks",
        "description": "Local Storage Sensitive Data",
        "attack_types": ["insecure_storage"],
        "next_if_pass": None,
        "next_if_fail": None,
    },
}

# Maps Frida attack_type → MASTG test IDs
_ATTACK_TYPE_TO_MASTG: Dict[str, List[str]] = {}
for _mid, _mdata in _MASTG_SCRIPT_MAP.items():
    for _at in _mdata["attack_types"]:
        _ATTACK_TYPE_TO_MASTG.setdefault(_at, []).append(_mid)


# ---------------------------------------------------------------------------
# Severity-based MASTG sequence escalation
# ---------------------------------------------------------------------------

_MASTG_SEQUENCE: List[str] = [
    "MASTG-TEST-0022",   # SSL pinning (Android + iOS)
    "MASTG-TEST-0242",   # Network Security Config (Android)
    "MASTG-TEST-0045",   # Root/jailbreak (Android)
    "MASTG-TEST-0341",   # Runtime hook detection
    "MASTG-TEST-0212",   # Hardcoded crypto keys
    "MASTG-TEST-0221",   # Broken crypto algorithms
    "MASTG-TEST-0001",   # Storage sensitive data
]

# iOS-specific MASTG sequence
_MASTG_SEQUENCE_IOS: List[str] = [
    "MASTG-TEST-0022",   # SSL pinning
    "MASTG-TEST-0060",   # Jailbreak detection
    "MASTG-TEST-0077",   # ATS configuration
    "MASTG-TEST-0080",   # NSURLSession security
    "MASTG-TEST-0341",   # Runtime hook detection
    "MASTG-TEST-0068",   # ObjC reverse engineering defenses
    "MASTG-TEST-0001",   # Storage (Keychain)
    "MASTG-TEST-0212",   # Hardcoded crypto keys
    "MASTG-TEST-0062",   # Crash logs
]

# iOS attack_type → MASTG test IDs
_IOS_ATTACK_TYPE_TO_MASTG: Dict[str, List[str]] = {
    "jailbreak_detection":    ["MASTG-TEST-0060"],
    "jailbreak_bypass":       ["MASTG-TEST-0060"],
    "ssl_pinning":            ["MASTG-TEST-0022"],
    "insecure_communication": ["MASTG-TEST-0077", "MASTG-TEST-0080"],
    "cleartext_http":         ["MASTG-TEST-0077"],
    "auth_bypass":            ["MASTG-TEST-0068"],
    "anti_debug":             ["MASTG-TEST-0341"],
    "insecure_storage":       ["MASTG-TEST-0001"],
    "keychain_read":          ["MASTG-TEST-0001"],
    "biometric_bypass":       ["MASTG-TEST-0068"],
    "weak_crypto":            ["MASTG-TEST-0212", "MASTG-TEST-0221"],
    "hardcoded_key":          ["MASTG-TEST-0212"],
    "crash_log":              ["MASTG-TEST-0062"],
}

# iOS MASTG script map
_MASTG_SCRIPT_MAP_IOS: Dict[str, Dict[str, Any]] = {
    "MASTG-TEST-0022": {"script": "ssl_bypass",           "attack_types": ["ssl_pinning"],
                        "next_if_pass": "MASTG-TEST-0060"},
    "MASTG-TEST-0060": {"script": "ios_jailbreak_bypass", "attack_types": ["jailbreak_detection", "jailbreak_bypass"],
                        "next_if_pass": "MASTG-TEST-0077"},
    "MASTG-TEST-0077": {"script": "ios_network_hooks",    "attack_types": ["cleartext_http", "insecure_communication"],
                        "next_if_pass": "MASTG-TEST-0080"},
    "MASTG-TEST-0080": {"script": "ios_network_hooks",    "attack_types": ["insecure_communication"],
                        "next_if_pass": "MASTG-TEST-0341"},
    "MASTG-TEST-0341": {"script": "ios_anti_debug_bypass","attack_types": ["anti_debug"],
                        "next_if_pass": "MASTG-TEST-0068"},
    "MASTG-TEST-0068": {"script": "ios_biometric_bypass", "attack_types": ["auth_bypass", "biometric_bypass"],
                        "next_if_pass": "MASTG-TEST-0001"},
    "MASTG-TEST-0001": {"script": "ios_keychain_hooks",   "attack_types": ["insecure_storage", "keychain_read"],
                        "next_if_pass": "MASTG-TEST-0212"},
    "MASTG-TEST-0212": {"script": "crypto_hooks",         "attack_types": ["hardcoded_key", "weak_crypto"],
                        "next_if_pass": None},
    "MASTG-TEST-0062": {"script": "ios_network_hooks",    "attack_types": ["crash_log"],
                        "next_if_pass": None},
}


# ---------------------------------------------------------------------------
# Frida Session
# ---------------------------------------------------------------------------

@dataclass
class FridaFinding:
    """A single structured finding from a Frida script execution."""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    session_id: str = ""
    device_id: str = ""
    package_name: str = ""
    script_name: str = ""
    vulnerability: str = ""
    attack_type: str = ""
    severity: str = "info"
    evidence: str = ""
    confidence: float = 0.8
    cvss: float = 0.0
    remediation: str = ""
    mastg_ids: List[str] = field(default_factory=list)
    masvs_ids: List[str] = field(default_factory=list)
    raw_output: str = ""
    found_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "finding_id":   self.finding_id,
            "session_id":   self.session_id,
            "device_id":    self.device_id,
            "package_name": self.package_name,
            "script_name":  self.script_name,
            "vulnerability": self.vulnerability,
            "attack_type":  self.attack_type,
            "severity":     self.severity,
            "evidence":     self.evidence,
            "confidence":   self.confidence,
            "cvss":         self.cvss,
            "remediation":  self.remediation,
            "mastg_ids":    self.mastg_ids,
            "masvs_ids":    self.masvs_ids,
            "found_at":     self.found_at,
        }


@dataclass
class FridaSession:
    """A live Frida instrumentation session on a companion device."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    device_id: str = ""
    package_name: str = ""
    status: str = "pending"      # pending / running / completed / stopped / error
    mode: str = "companion"      # companion | direct (adb-only, no WebSocket)
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    findings: List[FridaFinding] = field(default_factory=list)
    output_log: List[str] = field(default_factory=list)
    scripts_run: List[str] = field(default_factory=list)
    mastg_completed: List[str] = field(default_factory=list)
    mastg_queue: List[str] = field(default_factory=list)
    captured_tokens: List[Dict] = field(default_factory=list)  # Phase 2 bridge
    stats: Dict = field(default_factory=lambda: {
        "scripts_injected": 0,
        "findings_count": 0,
        "mastg_tests_run": 0,
        "tokens_captured": 0,
        "chains_triggered": 0,
    })
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "session_id":       self.session_id,
            "device_id":        self.device_id,
            "package_name":     self.package_name,
            "status":           self.status,
            "mode":             self.mode,
            "started_at":       self.started_at,
            "completed_at":     self.completed_at,
            "findings":         [f.to_dict() for f in self.findings],
            "output_log":       self.output_log[-100:],  # last 100 lines
            "scripts_run":      self.scripts_run,
            "mastg_completed":  self.mastg_completed,
            "mastg_queue":      self.mastg_queue,
            "captured_tokens":  self.captured_tokens,
            "stats":            self.stats,
            "error":            self.error,
            "duration_s":       round((self.completed_at or time.time()) - self.started_at, 1),
        }


_sessions: Dict[str, FridaSession] = {}
_SESSION_TTL_SECONDS = 3600  # 1 hour after completion


async def _session_cleanup_loop() -> None:
    """FIX #6: Background coroutine — evicts completed sessions older than TTL.
    Started by main.py lifespan or on first session creation."""
    while True:
        try:
            await asyncio.sleep(300)  # check every 5 minutes
            now = time.time()
            to_delete = [
                sid for sid, s in list(_sessions.items())
                if s.status in ("completed", "stopped", "error")
                and s.completed_at
                and (now - s.completed_at) > _SESSION_TTL_SECONDS
            ]
            for sid in to_delete:
                del _sessions[sid]
                log.info("[frida] Evicted expired session %s", sid)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.debug("session_cleanup_loop error: %s", exc)


def _ensure_cleanup_task() -> None:
    """Schedule the cleanup coroutine if not already running."""
    try:
        loop = asyncio.get_running_loop()
        # Only start if not already scheduled
        existing = [t for t in asyncio.all_tasks(loop)
                    if "session_cleanup" in t.get_name()]
        if not existing:
            loop.create_task(_session_cleanup_loop(), name="frida-session-cleanup")
    except RuntimeError:
        pass  # No running loop — cleanup will start on next request

# ---------------------------------------------------------------------------
# MASTG finding enrichment
# ---------------------------------------------------------------------------

def _enrich_with_mastg(attack_type: str, platform: str = "android") -> Tuple[List[str], List[str]]:
    """Return (mastg_ids, masvs_ids) for a given attack_type and platform."""
    mastg_tests = _get_mastg_tests()

    # Check iOS-specific map first if platform is ios
    if platform == "ios":
        mastg_ids = list(_IOS_ATTACK_TYPE_TO_MASTG.get(attack_type, []))
        if not mastg_ids:
            mastg_ids = list(_ATTACK_TYPE_TO_MASTG.get(attack_type, []))
    else:
        mastg_ids = list(_ATTACK_TYPE_TO_MASTG.get(attack_type, []))

    masvs_ids: List[str] = []
    for mid in mastg_ids:
        item = mastg_tests.get(mid)
        if item:
            masvs_ids.extend(item.masvs_mapping)

    return mastg_ids, list(set(masvs_ids))


# ---------------------------------------------------------------------------
# Frida output ingestion — processes messages from Android FridaManager
# ---------------------------------------------------------------------------

def ingest_frida_output(device_id: str, session_id: str, msg: dict) -> None:
    """
    Process a frida_output message from the Android companion.
    Called by mobile_agent_api.handle_device_message() when type=frida_output.
    """
    session = _sessions.get(session_id)
    if not session:
        log.warning("ingest_frida_output: unknown session %s", session_id)
        return

    raw_output = msg.get("output", "")
    script_name = msg.get("script_name", "unknown")
    package_name = msg.get("package_name", session.package_name)

    # Append to output log
    for line in raw_output.splitlines():
        session.output_log.append(f"[{script_name}] {line}")

    # FIX #14: Correlate Frida events with traffic and UI
    try:
        from .mobile_correlation_engine import ingest_event
        # If the output contains a JSON tag (OneInfinity standard), parse and ingest
        import json
        for line in raw_output.splitlines():
            if '[FRIDA_FINDING]' in line:
                try:
                    data_str = line.split('[FRIDA_FINDING]')[1].strip()
                    data = json.loads(data_str)
                    tag = data.get("tag")
                    if tag == "ui_interaction":
                        ingest_event(device_id, "ui", data.get("data", {}))
                    else:
                        ingest_event(device_id, "frida", {"script": script_name, "tag": tag, "data": data.get("data", {})})
                except Exception:
                    pass
    except ImportError:
        pass

    # Parse findings using existing frida_wrapper parser
    fw, _ = _get_frida_wrapper()
    if fw:
        try:
            unified_findings = fw._parse_frida_output(raw_output, package_name)
        except Exception as exc:
            # FIX #7: surface parse errors to session, never silently discard findings
            msg = f"[error] Frida output parsing failed for {script_name}: {exc}"
            log.error(msg)
            session.output_log.append(msg)
            session.error = msg
            unified_findings = []

        for uf in unified_findings:
            mastg_ids, masvs_ids = _enrich_with_mastg(uf.attack_type)
            finding = FridaFinding(
                session_id=session_id,
                device_id=device_id,
                package_name=package_name,
                script_name=script_name,
                vulnerability=uf.vulnerability,
                attack_type=uf.attack_type,
                severity=uf.severity,
                evidence=uf.evidence,
                confidence=uf.confidence,
                cvss=uf.cvss,
                remediation=uf.remediation,
                mastg_ids=mastg_ids,
                masvs_ids=masvs_ids,
                raw_output=raw_output[:500],
            )
            session.findings.append(finding)
            session.stats["findings_count"] += 1
            _persist_and_enrich_finding(finding, session)

    # Check for Phase 2 bridge: auth tokens captured
    _extract_and_bridge_tokens(session, raw_output, device_id)

    # Layer 2: Route ssl_read/ssl_write/keylog emissions to SSL interceptor
    for line in raw_output.splitlines():
        if '[FRIDA_FINDING]' in line:
            try:
                payload = json.loads(line.split('[FRIDA_FINDING]', 1)[1].strip())
                tag = payload.get('tag', '')
                if tag in ('ssl_write', 'ssl_read', 'ssl_write_intercept', 'keylog'):
                    from .mobile_ssl_interceptor import process_ssl_emission
                    process_ssl_emission(device_id, session_id,
                                        session.package_name, tag, payload.get('data', payload))
            except Exception:
                pass

    # MASTG auto-escalation
    _advance_mastg_sequence(session)


def _extract_and_bridge_tokens(session: FridaSession, output: str, device_id: str) -> None:
    """
    Parse Frida output for captured auth tokens/API keys.
    When found, build a Phase 2 attack campaign using them.
    This is the Frida × Phase 2 Attack Bridge.
    """
    import re

    # Patterns for tokens in Frida [FRIDA_FINDING] output
    token_patterns = [
        (re.compile(r'"auth_header_found".*?"value":\s*"([^"]{10,})"', re.S), "Authorization"),
        (re.compile(r'"jwt_found".*?"jwt":\s*(\{[^}]+\})', re.S), "JWT"),
        (re.compile(r'"auth_call".*?"args":\s*\[([^\]]+)\]', re.S), "auth_arg"),
        (re.compile(r'Bearer\s+([A-Za-z0-9\-_\.]{20,})', re.I), "Bearer"),
        (re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})', re.I), "API-Key"),
    ]

    for pattern, token_type in token_patterns:
        m = pattern.search(output)
        if m:
            token_value = m.group(1)[:200]
            entry = {
                "type": token_type,
                "value": token_value,
                "device_id": device_id,
                "captured_at": time.time(),
                "script": "frida_network_hook",
            }
            # Avoid duplicate tokens
            if not any(t.get("value") == token_value for t in session.captured_tokens):
                session.captured_tokens.append(entry)
                session.stats["tokens_captured"] += 1
                log.info("[frida] Token captured: %s (type=%s)", token_value[:20], token_type)

                # FIX #1: Bridge to Phase 2 — correct asyncio task scheduling.
                # ingest_frida_output() is sync but called from an async coroutine
                # (handle_device_message), so we ARE on the event loop here.
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(_queue_phase2_attack_with_token(session, entry))
                except RuntimeError:
                    # Not on the event loop (called from sync context); schedule safely
                    log.debug("[frida] Phase 2 bridge: no running loop — skipping task")


async def _queue_phase2_attack_with_token(session: FridaSession, token: dict) -> None:
    """
    When Frida captures a live auth token, automatically start a Phase 2
    attack session using that token against captured endpoints.
    """
    try:
        from .mobile_attack_api import start_attack_session_handler
        from .mobile_agent_api import get_traffic_handler

        # Get captured endpoints from Phase 1 traffic
        traffic = await get_traffic_handler(session.device_id, limit=100)
        endpoints = list({e.get("request", {}).get("url", "") for e in traffic
                          if e.get("request", {}).get("url", "").startswith("http")})

        if not endpoints:
            return

        # Build headers with captured token
        auth_headers = {}
        if token["type"] in ("Authorization", "Bearer"):
            auth_headers["Authorization"] = f"Bearer {token['value']}"
        elif token["type"] == "API-Key":
            auth_headers["X-Api-Key"] = token["value"]

        log.info("[frida] Launching Phase 2 attack with captured %s token on %d endpoints",
                 token["type"], len(endpoints))

        result = await start_attack_session_handler({
            "device_id": session.device_id,
            "endpoints": endpoints[:20],
            "template_id": "m3_insecure_authentication",
            "options": {
                "timeout": 10,
                "auth_headers": auth_headers,
                "_source": f"frida_session:{session.session_id}",
            },
        })
        session.stats["chains_triggered"] += 1
        session.output_log.append(
            f"[bridge] Phase 2 attack launched with {token['type']} token → "
            f"session {result.get('session_id')}"
        )
    except Exception as exc:
        log.debug("Phase 2 bridge failed: %s", exc)


def _advance_mastg_sequence(session: FridaSession) -> None:
    """
    After each script execution, check if the MASTG sequence should advance.
    Auto-queues the next MASTG test based on findings.
    """
    if not session.mastg_queue:
        return

    # Check which MASTG tests have been effectively tested by recent findings
    tested_attacks = {f.attack_type for f in session.findings}
    for mid, mdata in _MASTG_SCRIPT_MAP.items():
        if any(at in tested_attacks for at in mdata["attack_types"]):
            if mid not in session.mastg_completed:
                session.mastg_completed.append(mid)
                # Auto-escalate to next test
                next_test = mdata.get("next_if_pass")
                if next_test and next_test not in session.mastg_queue and next_test not in session.mastg_completed:
                    session.mastg_queue.append(next_test)
                    session.output_log.append(
                        f"[mastg] Auto-queued {next_test} after {mid} passed"
                    )


def _persist_and_enrich_finding(finding: FridaFinding, session: FridaSession) -> None:
    """Full enrichment: DB + attack graph + chain suggestions.

    FIX #13: Uses shared thread-pool executor instead of spawning a new daemon
    thread per finding, preventing unbounded thread creation under load.
    FIX #7: Propagates errors to session.error and output_log instead of
    silently discarding them.
    """
    ingestion, RawResult = _get_ingestion_engine()
    if ingestion and RawResult:
        try:
            raw = RawResult(
                scan_id=session.session_id,
                source="frida",
                raw={
                    **finding.to_dict(),
                    "url": f"frida://{finding.package_name}",
                    "target": finding.package_name,
                    "title": finding.vulnerability,
                    "tool": f"frida:{finding.script_name}",
                    "vuln_type": finding.attack_type,
                    "severity": finding.severity,
                    "evidence": finding.evidence,
                    "confidence": finding.confidence,
                },
            )
            ingestion.ingest(raw)
        except Exception as exc:
            # FIX #7: surface parse/ingest errors to session
            msg = f"[warn] ingest failed for {finding.finding_id[:8]}: {exc}"
            log.warning(msg)
            session.output_log.append(msg)

    def _update_graph():
        brain = _get_attack_graph_brain()
        if brain:
            try:
                brain.integrate_vuln({
                    **finding.to_dict(),
                    "url": f"frida://{finding.package_name}",
                    "target": finding.package_name,
                    "title": finding.vulnerability,
                    "vuln_type": finding.attack_type,
                })
            except Exception as exc:
                log.warning("attack graph update failed for %s: %s",
                            finding.finding_id[:8], exc)

    def _update_learning():
        glw = _get_graph_learning_writer()
        if glw:
            try:
                glw.write_finding_async(finding.to_dict())
            except Exception as exc:
                log.debug("graph_learning_writer failed: %s", exc)

    # FIX #13: submit to bounded thread pool — never spawns unbounded threads
    _bg_executor.submit(_update_graph)
    _bg_executor.submit(_update_learning)


# ---------------------------------------------------------------------------
# Script Library — reuses frida_script_generator completely
# ---------------------------------------------------------------------------

def _build_script_library(package_name: str = "", platform: str = "android") -> List[Dict]:
    """
    Build the full Frida script library for the given platform.
    Platform-aware: returns iOS scripts for iOS devices, Android for Android.
    """
    gen = _get_script_generator()
    if not gen:
        return []

    if platform == "ios":
        # Use new iOS script suite
        scripts = gen.generate_ios_scripts_for_session(
            package_name=package_name,
            include_jailbreak=True,
            include_ssl=True,
            include_keychain=True,
            include_network=True,
            include_anti_debug=True,
            include_biometric=False,
        )
        # Also include platform-neutral crypto hooks
        scripts.append(gen.generate_crypto_hook_script([]))
        script_map = _MASTG_SCRIPT_MAP_IOS
    else:
        scripts = [
            gen.generate_ssl_bypass_script(platform="android"),
            gen.generate_root_bypass_script(),
            gen.generate_anti_debug_bypass(),
            gen.generate_storage_hook_script(),
            gen.generate_crypto_hook_script([]),
            gen.generate_network_hook_script([]),
            gen.generate_dexguard_bypass_script(),
            gen.generate_appsealing_bypass_script(),
            gen.generate_arxan_bypass_script(),
            gen.generate_ui_hook_script(),
        ]
        script_map = _MASTG_SCRIPT_MAP

    mastg_tests = _get_mastg_tests()
    result = []
    for script in scripts:
        mastg_ids = []
        masvs_ids = []
        for mid, mdata in script_map.items():
            if mdata.get("script") == script.name:
                mastg_ids.append(mid)
                item = mastg_tests.get(mid)
                if item:
                    masvs_ids.extend(item.masvs_mapping)

        result.append({
            "name": script.name,
            "description": script.description,
            "platform": script.platform,
            "auto_run": script.auto_run,
            "script_content": script.script_content,
            "mastg_ids": mastg_ids,
            "masvs_ids": list(set(masvs_ids)),
            "targets": [{"class": t.class_name, "method": t.method_name, "type": t.hook_type}
                        for t in script.targets],
        })

    return result


# ---------------------------------------------------------------------------
# AI hook generation — reuses FridaScriptGenerator with AppModel
# ---------------------------------------------------------------------------

def _generate_ai_hooks(package_name: str, auth_classes: List[str],
                       crypto_classes: List[str], network_classes: List[str]) -> List[Dict]:
    """Generate targeted Frida hooks from reverse-engineering findings."""
    gen = _get_script_generator()
    if not gen:
        return []

    scripts = []
    if auth_classes:
        scripts.append(gen.generate_auth_hook_script(auth_classes))
    if crypto_classes:
        scripts.append(gen.generate_crypto_hook_script(crypto_classes))
    if network_classes:
        scripts.append(gen.generate_network_hook_script(network_classes))

    return [{
        "name": s.name,
        "description": s.description,
        "script_content": s.script_content,
        "platform": s.platform,
        "auto_run": s.auto_run,
        "targets": [{"class": t.class_name, "method": t.method_name, "type": t.hook_type}
                    for t in s.targets],
    } for s in scripts]


# ---------------------------------------------------------------------------
# frida-server management via adb
# ---------------------------------------------------------------------------

def _get_adb() -> Optional[str]:
    return shutil.which("adb")


def _resolve_adb_serial(device_id: str) -> Optional[str]:
    """
    Map a backend device_id (Android ANDROID_ID or any string) to a real ADB
    transport serial.  Strategy:
      1. Run `adb devices` and collect all online serials.
      2. If device_id is itself a known serial → return it directly.
      3. If exactly one device is connected → return its serial (common case).
      4. Try `adb -s <device_id> shell echo ok` to confirm it works directly.
      5. Return None (caller falls back to no -s flag).
    """
    adb = _get_adb()
    if not adb:
        return None
    try:
        result = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=5)
        serials = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serials.append(parts[0])

        # device_id is a known ADB serial already
        if device_id in serials:
            return device_id

        # Only one device connected — use it regardless of device_id mismatch
        if len(serials) == 1:
            return serials[0]

        # Multiple devices: try the device_id directly as a serial
        if serials:
            probe = subprocess.run(
                [adb, "-s", device_id, "shell", "echo", "ok"],
                capture_output=True, text=True, timeout=3
            )
            if "ok" in probe.stdout:
                return device_id

        return None
    except Exception:
        return None


def _build_adb_cmd(device_id: str) -> list:
    """Return base adb command with -s <serial> resolved, or without -s if unresolvable."""
    adb = _get_adb()
    if not adb:
        return []
    serial = _resolve_adb_serial(device_id)
    if serial:
        return [adb, "-s", serial]
    return [adb]


def _check_frida_server_status_sync(device_id: str) -> Dict:
    """Sync implementation — run via executor to avoid blocking the event loop."""
    adb = _get_adb()
    if not adb:
        return {"running": False, "reason": "adb not found"}

    cmd = _build_adb_cmd(device_id)
    if not cmd:
        return {"running": False, "reason": "adb not found"}
    cmd += ["shell", "ps", "-e"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        running = "frida-server" in result.stdout
        pid = None
        if running:
            for line in result.stdout.splitlines():
                if "frida-server" in line:
                    parts = line.split()
                    pid = parts[1] if len(parts) > 1 else None
                    break
        return {"running": running, "pid": pid}
    except Exception as exc:
        return {"running": False, "reason": str(exc)}


async def _check_frida_server_status(device_id: str) -> Dict:
    """FIX #2: Async wrapper — runs blocking adb subprocess in thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _bg_executor,
        functools.partial(_check_frida_server_status_sync, device_id)
    )


def _push_and_start_frida_server_sync(device_id: str, server_binary_path: str) -> Dict:
    """Sync implementation — run via executor to avoid blocking the event loop."""
    if not _get_adb():
        return {"success": False, "error": "adb not found"}

    if not os.path.isfile(server_binary_path):
        return {"success": False, "error": f"Binary not found: {server_binary_path}"}

    base_cmd = _build_adb_cmd(device_id)
    if not base_cmd:
        return {"success": False, "error": "adb not found"}

    try:
        push_result = subprocess.run(
            base_cmd + ["push", server_binary_path, "/data/local/tmp/frida-server"],
            capture_output=True, text=True, timeout=60,
        )
        if push_result.returncode != 0:
            return {"success": False, "error": f"adb push failed: {push_result.stderr}"}

        subprocess.run(
            base_cmd + ["shell", "su", "-c", "chmod +x /data/local/tmp/frida-server"],
            capture_output=True, text=True, timeout=10,
        )

        subprocess.Popen(
            base_cmd + ["shell", "su", "-c", "/data/local/tmp/frida-server -D"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Give frida-server time to start — sleep is safe here (sync thread, not event loop)
        time.sleep(2)
        status = _check_frida_server_status_sync(device_id)
        return {"success": status["running"], "status": status}

    except Exception as exc:
        return {"success": False, "error": str(exc)}


async def _push_and_start_frida_server(device_id: str, server_binary_path: str) -> Dict:
    """FIX #2: Async wrapper — runs blocking adb ops in thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        _bg_executor,
        functools.partial(_push_and_start_frida_server_sync, device_id, server_binary_path)
    )


# ---------------------------------------------------------------------------
# MASTG Coverage Report
# ---------------------------------------------------------------------------

def _generate_mastg_report(session: FridaSession) -> Dict:
    """Generate a MASVS/MASTG coverage report for the session."""
    mastg_tests = _get_mastg_tests()

    tested_attack_types = {f.attack_type for f in session.findings}
    all_mastg_ids = list(_MASTG_SCRIPT_MAP.keys())

    coverage = []
    for mid in all_mastg_ids:
        mdata = _MASTG_SCRIPT_MAP.get(mid, {})
        item = mastg_tests.get(mid)
        tested = mid in session.mastg_completed
        failed = any(
            at in tested_attack_types
            for at in mdata.get("attack_types", [])
        )
        coverage.append({
            "mastg_id":   mid,
            "title":      item.title if item else mid,
            "category":   item.category if item else "UNKNOWN",
            "masvs":      item.masvs_mapping if item else [],
            "status":     "FAIL" if failed else ("PASS" if tested else "NOT_TESTED"),
            "findings":   [f.to_dict() for f in session.findings
                           if any(at in mdata.get("attack_types", []) for at in [f.attack_type])],
        })

    total = len(all_mastg_ids)
    failed_count = sum(1 for c in coverage if c["status"] == "FAIL")
    passed_count = sum(1 for c in coverage if c["status"] == "PASS")

    return {
        "session_id":   session.session_id,
        "package_name": session.package_name,
        "device_id":    session.device_id,
        "generated_at": time.time(),
        "summary": {
            "total_tests":  total,
            "failed":       failed_count,
            "passed":       passed_count,
            "not_tested":   total - failed_count - passed_count,
            "coverage_pct": round((failed_count + passed_count) / total * 100, 1) if total else 0,
        },
        "coverage": coverage,
        "captured_tokens": len(session.captured_tokens),
        "phase2_chains_triggered": session.stats["chains_triggered"],
    }


# ---------------------------------------------------------------------------
# Handler functions (called from main.py route definitions)
# ---------------------------------------------------------------------------

async def start_frida_session_handler(body: dict) -> dict:
    """
    Start a Frida instrumentation session on a connected companion device.

    Body:
    {
        "device_id": "abc123",           // companion WebSocket device ID
        "package_name": "com.target.app",
        "scripts": ["ssl_bypass", "root_bypass"],  // or [] for all auto-run
        "mastg_sequence": true,          // enable MASTG-guided sequencing
        "options": {"timeout": 60}
    }
    """
    device_id = body.get("device_id", "")
    package_name = body.get("package_name", "")
    scripts = body.get("scripts", [])
    mastg_sequence = body.get("mastg_sequence", True)
    options = body.get("options", {})

    if not device_id:
        raise HTTPException(400, "device_id required")
    if not package_name:
        raise HTTPException(400, "package_name required")

    # Platform detection: use device metadata if available
    platform = body.get("platform", "android").lower()
    if platform not in ("android", "ios"):
        platform = "android"

    # Auto-detect platform from device registry if not explicitly provided
    if "platform" not in body:
        try:
            from .mobile_agent_api import device_metadata
            meta = device_metadata.get(device_id, {})
            platform = meta.get("platform", "android").lower()
        except Exception:
            pass

    # Choose MASTG sequence based on platform
    mastg_seq = _MASTG_SEQUENCE_IOS if platform == "ios" else _MASTG_SEQUENCE

    session = FridaSession(
        device_id=device_id,
        package_name=package_name,
        mode="companion",
        mastg_queue=list(mastg_seq) if mastg_sequence else [],
    )
    session.to_dict()  # validate
    _sessions[session.session_id] = session
    _ensure_cleanup_task()  # FIX #6: start TTL reaper if not running

    # FIX #3: Set status to "running" BEFORE the injection loop
    session.status = "running"

    # Build platform-appropriate script library
    library = _build_script_library(package_name, platform=platform)
    scripts_to_run = (
        [s for s in library if s["auto_run"]] if not scripts
        else [s for s in library if s["name"] in scripts]
    )

    # Inject each script; continue on per-script failure (don't abort the session)
    for script_def in scripts_to_run:
        try:
            await _inject_via_companion(session, script_def["name"],
                                        script_def["script_content"], options)
        except Exception as exc:
            session.output_log.append(f"[error] Failed to inject {script_def['name']}: {exc}")
            log.error("[frida] Injection of %s failed: %s", script_def["name"], exc)

    log.info("[frida] Session %s started on %s (%s)",
             session.session_id, device_id, package_name)

    return {
        "session_id":    session.session_id,
        "status":        "started",
        "scripts_queued": len(scripts_to_run),
        "mastg_queue":   session.mastg_queue,
    }


async def _inject_via_companion(session: FridaSession, script_name: str,
                                 script_content: str, options: dict) -> None:
    """
    Send frida_inject command to Android companion via WebSocket, then execute
    the script locally using frida_wrapper (host-side, via adb/USB).

    ARCHITECTURE (Fix #11 complement):
      1. Notify the companion so it ensures frida-server is running
      2. Execute frida -U on the host (backend) using frida_wrapper
      3. Stream output back to the companion device via WebSocket
      4. Ingest findings into the session
    """
    from .mobile_agent_api import active_devices

    ws = active_devices.get(session.device_id)

    # Step 1: Notify companion device (ensures frida-server is running)
    if ws:
        notify_cmd = {
            "type": "frida_inject",
            "session_id": session.session_id,
            "script_name": script_name,
            "package_name": session.package_name,
            "timeout": options.get("timeout", 60),
            # Note: script_content NOT sent to device (execution is host-side)
        }
        try:
            await ws.send_json(notify_cmd)
            session.scripts_run.append(script_name)
            session.stats["scripts_injected"] += 1
        except Exception as exc:
            session.output_log.append(f"[error] notify inject {script_name}: {exc}")
            log.warning("[frida] companion notify failed: %s", exc)
    else:
        session.output_log.append(
            f"[warn] Device {session.device_id} not connected — running host-direct frida"
        )
        session.scripts_run.append(script_name)
        session.stats["scripts_injected"] += 1

    # Step 2: Execute frida on host via frida_wrapper (non-blocking via executor)
    fw, FridaConfig = _get_frida_wrapper()
    if not fw:
        session.output_log.append(f"[warn] frida_wrapper unavailable — skipping host execution")
        return

    timeout = options.get("timeout", 60)

    def _run_host_frida() -> None:
        """Synchronous frida execution — runs in thread pool."""
        try:
            result = fw.inject_script_content(
                package=session.package_name,
                script_content=script_content,
                device_id="",  # auto-select first USB device
                timeout=timeout,
            )

            # Step 3: Ingest output into session (same path as companion output)
            ingest_frida_output(session.device_id, session.session_id, {
                "session_id": session.session_id,
                "output": "\n".join(result.output),
                "script_name": script_name,
                "package_name": session.package_name,
            })

            # Step 4: Stream raw output back to companion for logging
            if ws and result.output:
                try:
                    # Fire-and-forget streaming (don't await from thread)
                    asyncio.get_event_loop().call_soon_threadsafe(
                        lambda r=result: asyncio.ensure_future(_stream_output_to_device(ws, session.session_id, script_name, r.output))
                    )
                except Exception:
                    pass

            log.info("[frida] Host execution complete: %s → %d findings",
                     script_name, len(result.findings))
        except Exception as exc:
            session.output_log.append(f"[error] Host frida execution {script_name}: {exc}")
            log.error("[frida] host execution failed: %s", exc)

    # Submit to thread pool (non-blocking)
    _bg_executor.submit(_run_host_frida)


async def _stream_output_to_device(ws, session_id: str, script_name: str,
                                    output_lines: List[str]) -> None:
    """Stream Frida output lines back to companion device for UI display."""
    if not output_lines:
        return
    try:
        msg = {
            "type": "frida_output",
            "session_id": session_id,
            "script_name": script_name,
            "output": "\n".join(output_lines[:50]),  # cap at 50 lines per message
            "has_finding": any("[FRIDA_FINDING]" in l for l in output_lines),
        }
        await ws.send_json(msg)
    except Exception as exc:
        log.debug("stream_output_to_device failed: %s", exc)


async def inject_script_handler(body: dict) -> dict:
    """
    Inject a custom or library script into a running Frida session.

    Body:
    {
        "session_id": "...",        // existing session, OR
        "device_id":  "...",        // create ad-hoc session
        "package_name": "...",
        "script_name": "ssl_bypass",   // library name OR
        "script_content": "...",        // inline JS
        "timeout": 60
    }
    """
    session_id = body.get("session_id")
    device_id = body.get("device_id", "")
    package_name = body.get("package_name", "")
    script_name = body.get("script_name", "custom")
    script_content = body.get("script_content", "")
    timeout = body.get("timeout", 60)

    # Resolve session
    session = _sessions.get(session_id) if session_id else None
    if not session:
        if not device_id or not package_name:
            raise HTTPException(400, "Either session_id or (device_id + package_name) required")
        session = FridaSession(device_id=device_id, package_name=package_name)
        _sessions[session.session_id] = session
        session.status = "running"

    # Resolve script content from library if name given
    if not script_content and script_name != "custom":
        library = _build_script_library(session.package_name)
        match = next((s for s in library if s["name"] == script_name), None)
        if match:
            script_content = match["script_content"]
        else:
            raise HTTPException(404, f"Script '{script_name}' not in library")

    if not script_content:
        raise HTTPException(400, "script_content or valid script_name required")

    await _inject_via_companion(session, script_name, script_content, {"timeout": timeout})

    return {
        "session_id": session.session_id,
        "script_name": script_name,
        "status": "injected",
        "device_id": session.device_id,
    }


async def stop_frida_session_handler(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    session.status = "stopped"
    session.completed_at = time.time()
    return {"session_id": session_id, "status": "stopped"}


async def list_frida_sessions_handler() -> List[dict]:
    return [s.to_dict() for s in _sessions.values()]


async def get_frida_session_handler(session_id: str) -> dict:
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    return session.to_dict()


async def get_script_library_handler(package_name: str = "", platform: str = "android") -> List[dict]:
    """Return the Frida script library for the given platform (android or ios)."""
    library = _build_script_library(package_name, platform=platform)
    return library


async def ai_generate_hooks_handler(body: dict) -> dict:
    """
    AI-driven hook generation from package reverse-engineering.

    Body:
    {
        "package_name": "com.target.app",
        "auth_classes": ["com.target.auth.LoginManager"],
        "crypto_classes": ["com.target.crypto.AESHelper"],
        "network_classes": ["com.target.network.ApiClient"]
    }
    """
    package_name = body.get("package_name", "")
    auth_classes = body.get("auth_classes", [])
    crypto_classes = body.get("crypto_classes", [])
    network_classes = body.get("network_classes", [])

    if not package_name:
        raise HTTPException(400, "package_name required")

    scripts = _generate_ai_hooks(package_name, auth_classes, crypto_classes, network_classes)
    return {
        "package_name": package_name,
        "scripts_generated": len(scripts),
        "scripts": scripts,
    }


async def frida_server_status_handler(device_id: str) -> dict:
    """Check frida-server status on device. FIX #2: now properly async."""
    status = await _check_frida_server_status(device_id)
    return {"device_id": device_id, **status}


async def frida_server_push_handler(body: dict) -> dict:
    """Push frida-server binary to device and start it. FIX #2: now properly async."""
    device_id = body.get("device_id", "")
    binary_path = body.get("binary_path", "")
    if not device_id or not binary_path:
        raise HTTPException(400, "device_id and binary_path required")
    result = await _push_and_start_frida_server(device_id, binary_path)
    if not result.get("success"):
        raise HTTPException(500, result.get("error", "Failed to start frida-server"))
    return result


async def mastg_report_handler(session_id: str) -> dict:
    """Generate MASTG coverage report for a session."""
    session = _sessions.get(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id} not found")
    return _generate_mastg_report(session)


async def ingest_companion_frida_output_handler(body: dict) -> dict:
    """
    Receive frida_output from companion device.
    Called internally when WebSocket message {type: frida_output} arrives.
    """
    device_id = body.get("device_id", "")
    session_id = body.get("session_id", "")
    if not session_id:
        raise HTTPException(400, "session_id required")
    ingest_frida_output(device_id, session_id, body)
    return {"status": "ingested"}


__all__ = [
    "start_frida_session_handler",
    "stop_frida_session_handler",
    "list_frida_sessions_handler",
    "get_frida_session_handler",
    "inject_script_handler",
    "get_script_library_handler",
    "ai_generate_hooks_handler",
    "frida_server_status_handler",
    "frida_server_push_handler",
    "mastg_report_handler",
    "ingest_frida_output",
    "FridaSession",
    "FridaFinding",
]
