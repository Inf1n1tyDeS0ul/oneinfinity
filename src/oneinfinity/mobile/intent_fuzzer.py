"""
intent_fuzzer.py — Android Intent fuzzing engine.

Enumerates exported Activities, Services, and BroadcastReceivers and
batters each with malformed, injected, and oversized extras to surface:
  - android_intent_injection (SQL/JS/shell in string extras)
  - exported_component_abuse (unprotected exported components)

All findings conform to the OneInfinity finding schema with
  tool='intent_fuzzer', target=<package>.
"""
from __future__ import annotations

import asyncio
import logging
import re
import shlex
import subprocess
from typing import Any, Dict, List, Optional

log = logging.getLogger("oi.intent_fuzzer")

# ---------------------------------------------------------------------------
# Malicious extras payloads
# ---------------------------------------------------------------------------

_STRING_PAYLOADS: List[str] = [
    "",                                        # null/empty
    "' OR '1'='1",                             # SQL injection
    "\" OR \"1\"=\"1",                         # SQL injection double-quote
    "'; DROP TABLE users; --",                 # SQL injection destructive
    "<script>alert(1)</script>",               # XSS / JS injection
    "javascript:alert(1)",                     # URI scheme injection
    "content://com.android.contacts/contacts", # content URI traversal
    "file:///data/data/",                      # file URI traversal
    "A" * 4096,                                # oversized string (buffer edge)
    "A" * 65536,                               # oversized string (large)
    "\x00\x01\x02\x03\xff",                    # binary/null bytes
    "../../../etc/passwd",                     # path traversal
    "$(id)",                                   # shell command injection
    "`id`",                                    # backtick shell injection
    "intent:#Intent;action=android.intent.action.VIEW;end",  # nested intent
]

_INT_PAYLOADS: List[int] = [0, -1, 2**31 - 1, -(2**31), 2**63 - 1]

_URI_PAYLOADS: List[str] = [
    "file:///etc/passwd",
    "file:///data/data/",
    "content://com.android.contacts/contacts/1",
    "content://com.android.providers.settings/system",
    "jar:file:///data/local/tmp/evil.jar!/",
    "javascript:void(0)",
]

_COMPONENT_RE = re.compile(
    r"^\s+([a-zA-Z][a-zA-Z0-9._/]+)\s+filter.*?(?:exported|public)=true",
    re.IGNORECASE,
)
_ACTIVITY_BLOCK_RE = re.compile(r"Activity Resolver Table:", re.IGNORECASE)
_SERVICE_BLOCK_RE  = re.compile(r"Service Resolver Table:", re.IGNORECASE)
_RECEIVER_BLOCK_RE = re.compile(r"Receiver Resolver Table:", re.IGNORECASE)

# Simple parser for `dumpsys package <pkg>` output
_PKG_SECTION_RE = re.compile(
    r"(Activity|Service|Receiver) #\d+:\s*\n"
    r".*?name=([\w\.]+/[\w\.]+).*?exported=(true|false)",
    re.S,
)


def _run(cmd: str, timeout: int = 10) -> str:
    """Run a shell command via subprocess; return stdout (empty on error)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,  # noqa: S602 — intentional for adb shell commands
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except Exception as exc:
        log.debug("_run error: %s", exc)
        return ""


def _adb(serial: str, command: str, timeout: int = 10) -> str:
    """Execute an adb shell command on the given device serial."""
    return _run(f"adb -s {shlex.quote(serial)} shell {command}", timeout=timeout)


def _make_finding(
    vuln_type: str,
    severity: str,
    evidence: str,
    component: str,
    package: str,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    finding: Dict[str, Any] = {
        "vuln_type": vuln_type,
        "severity": severity,
        "evidence": evidence,
        "component": component,
        "tool": "intent_fuzzer",
        "target": package,
    }
    if extra:
        finding.update(extra)
    return finding


# ---------------------------------------------------------------------------
# Main fuzzer class
# ---------------------------------------------------------------------------

class AndroidIntentFuzzer:
    """
    Automated Android Intent fuzzer.

    Enumerate all exported components of *package* on *device_serial*, then
    batter each with malformed/injected extras to find intent-injection and
    exported-component-abuse vulnerabilities.
    """

    def __init__(self, device_serial: str, package: str) -> None:
        self.serial  = device_serial
        self.package = package

    # ------------------------------------------------------------------
    # Component enumeration
    # ------------------------------------------------------------------

    def enumerate_exported_components(self) -> Dict[str, List[str]]:
        """
        Parse `adb shell dumpsys package <pkg>` output to find all components
        with exported=true.

        Returns:
            {
                "activities":  ["com.example/.MainActivity", …],
                "services":    ["com.example/.MyService", …],
                "receivers":   ["com.example/.MyReceiver", …],
            }
        """
        out = _adb(self.serial, f"dumpsys package {shlex.quote(self.package)}", timeout=20)
        result: Dict[str, List[str]] = {"activities": [], "services": [], "receivers": []}

        current_type: Optional[str] = None
        comp_name: Optional[str] = None
        is_exported = False

        for line in out.splitlines():
            stripped = line.strip()

            # Detect component class sections
            if stripped.startswith("Activity #") or stripped.startswith("ActivityInfo#"):
                current_type = "activities"
                comp_name = None
                is_exported = False
            elif stripped.startswith("Service #") or stripped.startswith("ServiceInfo#"):
                current_type = "services"
                comp_name = None
                is_exported = False
            elif stripped.startswith("Receiver #") or stripped.startswith("ReceiverInfo#"):
                current_type = "receivers"
                comp_name = None
                is_exported = False

            # Extract name
            name_match = re.search(r"name=([\w\.]+/[\w\.$]+)", stripped)
            if name_match and current_type:
                comp_name = name_match.group(1)

            # Check exported flag
            if "exported=true" in stripped.lower():
                is_exported = True

            # Commit when we have both
            if comp_name and is_exported and current_type:
                # Normalise to fully-qualified if needed
                fq = comp_name
                if "/" not in fq:
                    fq = f"{self.package}/{comp_name}"
                if fq not in result[current_type]:
                    result[current_type].append(fq)
                comp_name = None
                is_exported = False

        log.info(
            "enumerate_exported_components: pkg=%s acts=%d svcs=%d recvs=%d",
            self.package,
            len(result["activities"]),
            len(result["services"]),
            len(result["receivers"]),
        )
        return result

    # ------------------------------------------------------------------
    # Activity fuzzing
    # ------------------------------------------------------------------

    async def fuzz_activity(
        self,
        component: str,
        extras: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fuzz an exported Activity with malicious extras.

        Tests: null intent, oversized extras, SQL injection in string extras,
        URI scheme injection, and int overflow.
        """
        findings: List[Dict[str, Any]] = []

        # First: bare start (no extras) to confirm activity exported unprotected
        bare_cmd = f"am start -n {shlex.quote(component)} --user 0 2>&1"
        bare_out = _adb(self.serial, bare_cmd, timeout=8)
        if "Error" not in bare_out and "Exception" not in bare_out and "SecurityException" not in bare_out:
            findings.append(_make_finding(
                vuln_type="exported_component_abuse",
                severity="HIGH",
                evidence=f"Activity launched without permission: {bare_out[:200]}",
                component=component,
                package=self.package,
            ))

        # Merge custom extras + fuzz payloads
        test_extras = dict(extras or {})

        # String injection payloads
        for payload in _STRING_PAYLOADS:
            escaped = shlex.quote(payload)
            cmd = (
                f"am start -n {shlex.quote(component)} "
                f"--es fuzz_key {escaped} "
                f"--es url {escaped} "
                f"--es data {escaped} --user 0 2>&1"
            )
            out = _adb(self.serial, cmd, timeout=8)
            if _is_crash(out):
                findings.append(_make_finding(
                    vuln_type="android_intent_injection",
                    severity="CRITICAL",
                    evidence=f"Crash on string extra payload={payload[:80]!r}: {out[:300]}",
                    component=component,
                    package=self.package,
                    extra={"payload": payload[:80]},
                ))
            elif _is_injection_reflection(out, payload):
                findings.append(_make_finding(
                    vuln_type="android_intent_injection",
                    severity="HIGH",
                    evidence=f"Payload reflected in output payload={payload[:80]!r}: {out[:200]}",
                    component=component,
                    package=self.package,
                    extra={"payload": payload[:80]},
                ))

        # URI scheme payloads via data flag
        for uri in _URI_PAYLOADS:
            cmd = f"am start -n {shlex.quote(component)} -d {shlex.quote(uri)} --user 0 2>&1"
            out = _adb(self.serial, cmd, timeout=8)
            if _is_crash(out):
                findings.append(_make_finding(
                    vuln_type="android_intent_injection",
                    severity="CRITICAL",
                    evidence=f"Crash on URI payload={uri!r}: {out[:300]}",
                    component=component,
                    package=self.package,
                    extra={"uri": uri},
                ))

        # Integer overflow extras
        for val in _INT_PAYLOADS:
            cmd = (
                f"am start -n {shlex.quote(component)} "
                f"--ei int_val {val} --user 0 2>&1"
            )
            out = _adb(self.serial, cmd, timeout=8)
            if _is_crash(out):
                findings.append(_make_finding(
                    vuln_type="android_intent_injection",
                    severity="HIGH",
                    evidence=f"Crash on int extra val={val}: {out[:200]}",
                    component=component,
                    package=self.package,
                    extra={"int_val": val},
                ))

        await asyncio.sleep(0)  # yield to event loop between components
        return findings

    # ------------------------------------------------------------------
    # Service fuzzing
    # ------------------------------------------------------------------

    async def fuzz_service(self, component: str) -> List[Dict[str, Any]]:
        """
        Fuzz an exported Service with injection payloads via am startservice.
        """
        findings: List[Dict[str, Any]] = []

        bare_cmd = f"am startservice -n {shlex.quote(component)} --user 0 2>&1"
        bare_out = _adb(self.serial, bare_cmd, timeout=8)
        if "Error" not in bare_out and "SecurityException" not in bare_out:
            findings.append(_make_finding(
                vuln_type="exported_component_abuse",
                severity="HIGH",
                evidence=f"Service started without permission: {bare_out[:200]}",
                component=component,
                package=self.package,
            ))

        for payload in _STRING_PAYLOADS[:8]:  # subset for services
            escaped = shlex.quote(payload)
            cmd = (
                f"am startservice -n {shlex.quote(component)} "
                f"--es cmd {escaped} "
                f"--es action {escaped} --user 0 2>&1"
            )
            out = _adb(self.serial, cmd, timeout=8)
            if _is_crash(out):
                findings.append(_make_finding(
                    vuln_type="android_intent_injection",
                    severity="CRITICAL",
                    evidence=f"Service crash on payload={payload[:60]!r}: {out[:300]}",
                    component=component,
                    package=self.package,
                    extra={"payload": payload[:60]},
                ))

        await asyncio.sleep(0)
        return findings

    # ------------------------------------------------------------------
    # Broadcast fuzzing
    # ------------------------------------------------------------------

    async def fuzz_broadcast(self, component: str) -> List[Dict[str, Any]]:
        """
        Fuzz an exported BroadcastReceiver with malicious action/data via am broadcast.
        """
        findings: List[Dict[str, Any]] = []

        # Derive a plausible action from component name
        pkg_part = component.split("/")[0]
        action_base = f"{pkg_part}.action"

        for payload in _STRING_PAYLOADS[:8]:
            escaped = shlex.quote(payload)
            cmd = (
                f"am broadcast -n {shlex.quote(component)} "
                f"-a {shlex.quote(action_base)} "
                f"--es data {escaped} "
                f"--es extra1 {escaped} --user 0 2>&1"
            )
            out = _adb(self.serial, cmd, timeout=8)
            if "Broadcast completed" in out or "result=0" in out:
                if _is_crash(out):
                    findings.append(_make_finding(
                        vuln_type="android_intent_injection",
                        severity="CRITICAL",
                        evidence=f"Broadcast crash payload={payload[:60]!r}: {out[:300]}",
                        component=component,
                        package=self.package,
                        extra={"payload": payload[:60]},
                    ))
                elif not findings:
                    # Bare broadcast succeeded — exported unprotected
                    findings.append(_make_finding(
                        vuln_type="exported_component_abuse",
                        severity="MEDIUM",
                        evidence=f"Broadcast receiver accepts unauthenticated broadcasts: {out[:200]}",
                        component=component,
                        package=self.package,
                    ))

        # URI injection via broadcast data
        for uri in _URI_PAYLOADS[:3]:
            cmd = (
                f"am broadcast -n {shlex.quote(component)} "
                f"-d {shlex.quote(uri)} --user 0 2>&1"
            )
            out = _adb(self.serial, cmd, timeout=8)
            if _is_crash(out):
                findings.append(_make_finding(
                    vuln_type="android_intent_injection",
                    severity="HIGH",
                    evidence=f"Broadcast crash on URI={uri!r}: {out[:200]}",
                    component=component,
                    package=self.package,
                    extra={"uri": uri},
                ))

        await asyncio.sleep(0)
        return findings

    # ------------------------------------------------------------------
    # Full automated scan
    # ------------------------------------------------------------------

    async def scan(self) -> List[Dict[str, Any]]:
        """
        Full automated intent fuzz of all exported components for *package*.

        Returns list of findings (may be empty if device unreachable or
        no vulnerabilities found).
        """
        log.info("IntentFuzzer.scan starting package=%s serial=%s", self.package, self.serial)
        components = self.enumerate_exported_components()
        findings: List[Dict[str, Any]] = []

        # Activities
        for comp in components.get("activities", []):
            try:
                findings.extend(await self.fuzz_activity(comp))
            except Exception as exc:
                log.warning("fuzz_activity(%s) error: %s", comp, exc)

        # Services
        for comp in components.get("services", []):
            try:
                findings.extend(await self.fuzz_service(comp))
            except Exception as exc:
                log.warning("fuzz_service(%s) error: %s", comp, exc)

        # Receivers
        for comp in components.get("receivers", []):
            try:
                findings.extend(await self.fuzz_broadcast(comp))
            except Exception as exc:
                log.warning("fuzz_broadcast(%s) error: %s", comp, exc)

        log.info(
            "IntentFuzzer.scan done package=%s findings=%d",
            self.package,
            len(findings),
        )
        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_crash(output: str) -> bool:
    """Detect crash/ANR/exception indicators in adb am output."""
    crash_signals = (
        "FATAL EXCEPTION",
        "java.lang.NullPointerException",
        "java.lang.RuntimeException",
        "Process: ",  # logcat crash header often includes "Process: " + pkg
        "SIGSEGV",
        "ANR",
        "has crashed",
        "NullPointer",
        "ArrayIndexOutOfBounds",
        "StackOverflow",
        "OutOfMemory",
    )
    lo = output.lower()
    return any(s.lower() in lo for s in crash_signals)


def _is_injection_reflection(output: str, payload: str) -> bool:
    """Check if a dangerous payload appears verbatim in output (reflection)."""
    dangerous = ("' or", "\" or", "<script", "$(id)", "`id`", "drop table")
    pl = payload.lower()
    return any(d in pl for d in dangerous) and payload[:30].lower() in output.lower()
