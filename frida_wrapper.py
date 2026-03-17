"""
Frida Wrapper
=============
Execute Frida scripts against Android/iOS targets.
Handles device enumeration, process listing, script injection, and
structured output parsing.

Architecture
------------
* ``FridaWrapper.inject_script()`` writes a temporary script (if content is
  provided), then spawns ``frida … -l <script>`` as a subprocess.
* Scripts signal findings back to the host by printing lines prefixed with
  ``[FRIDA_FINDING]`` followed by a JSON object.
* The wrapper also heuristically detects SSL-pinning, root-bypass, and other
  common patterns from free-form Frida output.

Usage::

    from frida_wrapper import frida_wrapper

    result = frida_wrapper.inject_script(
        package="com.example.app",
        script_path="/path/to/ssl_bypass.js",
        device_id="emulator-5554",
        timeout=90,
    )
    for f in result.findings:
        print(f.severity, f.vulnerability)

Script convention
-----------------
Frida scripts emit structured findings by calling::

    console.log("[FRIDA_FINDING] " + JSON.stringify({
        vulnerability: "SSL Pinning Bypass",
        severity:      "high",
        evidence:      "OkHttpClient.checkServerTrusted bypassed",
        attack_type:   "ssl_pinning",
        confidence:    0.9
    }));
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mobile_tool_registry import UnifiedFinding, tool_registry

log = logging.getLogger("oneinfinity.mobile.frida")

# ──────────────────────────────────────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FridaConfig:
    """Runtime configuration for the Frida wrapper."""

    device_id: str = ""
    """ADB serial / Frida USB device ID.  Empty string = auto-select first device."""

    host: str = ""
    """Remote Frida server hostname or IP (for TCP-mode frida-server)."""

    port: int = 27042
    """TCP port on which frida-server listens (default 27042)."""

    timeout: int = 60
    """Default script execution timeout in seconds."""

    runtime: str = "v8"
    """Frida JS runtime: 'v8' (default) or 'qjs'."""

    frida_server_path: str = "/data/local/tmp/frida-server"
    """Path of frida-server on the Android device."""


# ──────────────────────────────────────────────────────────────────────────────
#  Result types
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FridaResult:
    """Structured result from a Frida script injection."""

    package: str
    """Target application package / bundle identifier."""

    script_name: str
    """Name or path of the injected script."""

    output: List[str] = field(default_factory=list)
    """Raw output lines from the script (console.log / console.error)."""

    findings: List[UnifiedFinding] = field(default_factory=list)
    """Structured findings extracted from [FRIDA_FINDING] markers."""

    error: str = ""
    """Error message if injection or execution failed."""

    duration: float = 0.0
    """Wall-clock execution time in seconds."""

    def to_dict(self) -> dict:
        return {
            "package":     self.package,
            "script_name": self.script_name,
            "output":      self.output,
            "findings":    [f.to_dict() for f in self.findings],
            "error":       self.error,
            "duration":    self.duration,
        }

    def __repr__(self) -> str:
        return (
            f"<FridaResult pkg={self.package!r} findings={len(self.findings)} "
            f"error={bool(self.error)}>"
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Heuristic patterns
# ──────────────────────────────────────────────────────────────────────────────

# Patterns matched against Frida output lines to synthesise findings when a
# script does not emit explicit [FRIDA_FINDING] markers.

_HEURISTIC_PATTERNS: List[Tuple[str, str, str, str, float, float]] = [
    # (regex_pattern, vulnerability, attack_type, severity, confidence, cvss)
    (
        r"(?i)ssl\s*pin(?:ning)?\s*(?:bypass|detach|disabled|removed|hooked)",
        "SSL Pinning Bypassed",
        "ssl_pinning",
        "high", 0.85, 7.5,
    ),
    (
        r"(?i)certificate\s+pinning\s+(?:bypass|disabled|removed)",
        "Certificate Pinning Disabled",
        "ssl_pinning",
        "high", 0.85, 7.5,
    ),
    (
        r"(?i)root\s+(?:detection|check)\s+(?:bypass|disabled|hooked|removed)",
        "Root Detection Bypassed",
        "root_bypass",
        "medium", 0.80, 5.3,
    ),
    (
        r"(?i)emulator\s+detection\s+(?:bypass|disabled|hooked)",
        "Emulator Detection Bypassed",
        "emulator_detection",
        "medium", 0.75, 4.3,
    ),
    (
        r"(?i)biometric\s+(?:bypass|disabled|hooked)",
        "Biometric Authentication Bypassed",
        "auth_bypass",
        "critical", 0.80, 9.1,
    ),
    (
        r"(?i)(?:DES|3DES|TripleDES|RC4|MD5)\s*(?:cipher|encrypt|hash)",
        "Weak Cryptography Detected at Runtime",
        "weak_crypto",
        "high", 0.85, 7.0,
    ),
    (
        r"(?i)ECB\s*mode",
        "Insecure Block Cipher Mode (ECB) at Runtime",
        "weak_crypto",
        "high", 0.90, 7.3,
    ),
    (
        r"(?i)(?:hardcoded|plaintext)\s+(?:key|secret|password|token)",
        "Hardcoded Credential Detected at Runtime",
        "hardcoded_secret",
        "critical", 0.80, 9.0,
    ),
    (
        r"(?i)Log\.[dev]\s*\([\"'](?:password|token|secret|key)",
        "Sensitive Data in Logcat",
        "insecure_logging",
        "medium", 0.75, 5.0,
    ),
    (
        r"(?i)WebView.*setJavaScript.*true",
        "WebView JavaScript Enabled",
        "webview_misconfiguration",
        "medium", 0.70, 5.3,
    ),
    (
        r"(?i)addJavascriptInterface",
        "WebView addJavascriptInterface Detected",
        "webview_misconfiguration",
        "high", 0.85, 8.8,
    ),
    (
        r"(?i)MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",
        "World-Readable/Writable File Created",
        "insecure_storage",
        "high", 0.90, 6.5,
    ),
    (
        r"(?i)SharedPreferences.*(?:password|token|secret|key|credential)",
        "Sensitive Data in SharedPreferences",
        "insecure_storage",
        "medium", 0.75, 5.5,
    ),
    (
        r"(?i)SQLiteDatabase.*rawQuery.*\+",
        "Potential SQL Injection (SQLiteDatabase)",
        "sql_injection",
        "high", 0.70, 8.1,
    ),
    (
        r"(?i)http://(?!localhost|127\.0\.0\.1)",
        "Cleartext HTTP Traffic Detected at Runtime",
        "insecure_transport",
        "medium", 0.80, 5.9,
    ),
]

# Pre-compile patterns for performance
_COMPILED_HEURISTICS = [
    (re.compile(p), vuln, attack, sev, conf, cvss)
    for p, vuln, attack, sev, conf, cvss in _HEURISTIC_PATTERNS
]


# ──────────────────────────────────────────────────────────────────────────────
#  Wrapper
# ──────────────────────────────────────────────────────────────────────────────

class FridaWrapper:
    """
    Subprocess-based wrapper around the Frida CLI toolchain.

    All methods degrade gracefully when Frida binaries are not installed —
    they log a warning and return empty results rather than raising.
    """

    def __init__(self, config: Optional[FridaConfig] = None) -> None:
        self.config = config or FridaConfig()
        self._frida_bin: Optional[str] = self._get_frida_binary()
        self._frida_ps_bin: Optional[str] = self._get_frida_ps_binary()

        if not self._frida_bin:
            log.warning(
                "Frida binary not found. Dynamic analysis will be unavailable. "
                "Install with: pip install frida-tools"
            )

    # ── Binary discovery ──────────────────────────────────────────────────────

    def _get_frida_binary(self) -> Optional[str]:
        """Locate the ``frida`` binary via the tool registry."""
        t = tool_registry.get_tool("frida")
        if t and t.is_available() and t.binary_path:
            return t.binary_path
        # Manual fallback
        return shutil.which("frida")

    def _get_frida_ps_binary(self) -> Optional[str]:
        """Locate the ``frida-ps`` binary via the tool registry."""
        t = tool_registry.get_tool("frida-ps")
        if t and t.is_available() and t.binary_path:
            return t.binary_path
        return shutil.which("frida-ps")

    # ── Device / process enumeration ──────────────────────────────────────────

    def _list_devices(self) -> List[dict]:
        """
        Enumerate Frida-connected devices.

        Tries ``frida-ls-devices --json`` first (newer Frida); falls back to
        parsing the plain-text output of ``frida-ls-devices``.

        Returns
        -------
        List of ``{"id": ..., "name": ..., "type": ...}`` dicts.
        """
        if not self._frida_bin:
            log.warning("_list_devices: frida not available.")
            return []

        frida_ls = shutil.which("frida-ls-devices") or self._frida_bin

        # ── Try JSON output (Frida ≥ 12) ─────────────────────────────────────
        try:
            result = subprocess.run(
                [frida_ls, "--json"] if "ls-devices" in frida_ls else [self._frida_bin, "ls-devices", "--json"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout.strip())
                if isinstance(data, list):
                    devices = []
                    for d in data:
                        devices.append({
                            "id":   d.get("id", ""),
                            "name": d.get("name", d.get("id", "")),
                            "type": d.get("type", "unknown"),
                        })
                    log.debug("Enumerated %d Frida devices (JSON mode)", len(devices))
                    return devices
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        except Exception as exc:  # noqa: BLE001
            log.debug("frida-ls-devices JSON failed: %s", exc)

        # ── Fall back to frida-ps -D (parses table output) ───────────────────
        try:
            result = subprocess.run(
                [self._frida_ps_bin or self._frida_bin, "-D"],
                capture_output=True, text=True, timeout=10,
            )
            devices: List[dict] = []
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and not line.startswith("Id"):
                    devices.append({
                        "id":   parts[0],
                        "name": " ".join(parts[1:]),
                        "type": "usb" if "emulator" not in parts[0].lower() else "emulator",
                    })
            log.debug("Enumerated %d Frida devices (text mode)", len(devices))
            return devices
        except Exception as exc:  # noqa: BLE001
            log.debug("frida-ps -D failed: %s", exc)
            return []

    def _list_processes(self, device_id: str = "") -> List[dict]:
        """
        List running processes on a Frida-connected device.

        Parameters
        ----------
        device_id:
            ADB serial or Frida device ID.  Empty = use USB device.

        Returns
        -------
        List of ``{"pid": int, "name": str, "identifier": str}`` dicts.
        """
        if not self._frida_ps_bin:
            log.warning("_list_processes: frida-ps not found.")
            return []

        cmd = [self._frida_ps_bin]
        if device_id:
            cmd += ["-D", device_id]
        else:
            cmd += ["-U"]
        cmd += ["-a"]

        # Try --json flag first
        try:
            result = subprocess.run(
                cmd + ["--json"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout.strip())
                if isinstance(data, list):
                    procs = []
                    for p in data:
                        procs.append({
                            "pid":        int(p.get("pid", 0)),
                            "name":       p.get("name", ""),
                            "identifier": p.get("identifier", p.get("name", "")),
                        })
                    log.debug("Listed %d processes (JSON mode)", len(procs))
                    return procs
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass
        except Exception as exc:  # noqa: BLE001
            log.debug("frida-ps JSON failed: %s", exc)

        # Text-mode fallback
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            procs = []
            for line in result.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0].isdigit():
                    procs.append({
                        "pid":        int(parts[0]),
                        "name":       parts[1],
                        "identifier": parts[1],
                    })
            log.debug("Listed %d processes (text mode)", len(procs))
            return procs
        except Exception as exc:  # noqa: BLE001
            log.debug("frida-ps text mode failed: %s", exc)
            return []

    # ── Script injection ──────────────────────────────────────────────────────

    def inject_script(
        self,
        package: str,
        script_path: str,
        device_id: str = "",
        timeout: int = 60,
    ) -> FridaResult:
        """
        Inject a Frida script into a running (or spawned) application.

        Parameters
        ----------
        package:
            Android package name or iOS bundle ID (e.g. ``com.example.app``).
        script_path:
            Path to the ``.js`` script file to inject.
        device_id:
            ADB serial / Frida device ID.  Empty = auto-select USB device.
        timeout:
            Maximum execution time in seconds.

        Returns
        -------
        ``FridaResult`` with ``output``, ``findings``, ``error``, ``duration``.

        The script is spawned with ``-f`` (spawn mode) so it can hook early
        initialisation code.  Pass ``--no-pause`` to resume automatically.
        """
        result = FridaResult(package=package, script_name=script_path)

        if not self._frida_bin:
            result.error = (
                "Frida binary not found. "
                "Install with: pip install frida-tools"
            )
            log.warning("inject_script: %s", result.error)
            return result

        if not os.path.isfile(script_path):
            result.error = f"Script file not found: {script_path}"
            log.error("inject_script: %s", result.error)
            return result

        # Build the command
        cmd = [self._frida_bin]
        if device_id:
            cmd += ["-D", device_id]
        else:
            cmd += ["-U"]

        # Use spawn mode (-f) so we can hook app startup
        cmd += ["-f", package, "-l", script_path, "--no-pause", f"--runtime={self.config.runtime}"]

        # Add host/port if TCP mode is configured
        if self.config.host:
            cmd += ["-H", f"{self.config.host}:{self.config.port}"]

        log.info("Injecting Frida script into %s (timeout=%ds) …", package, timeout)
        log.debug("Frida cmd: %s", " ".join(cmd))

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            result.duration = time.monotonic() - start

            combined_output = proc.stdout + proc.stderr
            result.output = combined_output.splitlines()

            if proc.returncode not in (0, 1):
                # rc=1 is common on normal exit from Frida (script finished)
                stderr_snippet = (proc.stderr or "")[:300]
                if stderr_snippet:
                    result.error = f"Frida exited with code {proc.returncode}: {stderr_snippet}"
                    log.warning(result.error)

            result.findings = self._parse_frida_output(combined_output, package)
            log.info(
                "Frida injection complete: %d findings, %.1fs, rc=%d",
                len(result.findings), result.duration, proc.returncode,
            )

        except subprocess.TimeoutExpired:
            result.duration = time.monotonic() - start
            result.error = (
                f"Frida script timed out after {timeout}s. "
                "The app may still be running; consider increasing timeout."
            )
            log.warning(result.error)

        except FileNotFoundError:
            result.error = f"Frida binary not found at runtime: {self._frida_bin}"
            log.error(result.error)

        except Exception as exc:  # noqa: BLE001
            result.error = f"Frida injection error: {exc}"
            log.exception(result.error)

        return result

    def inject_script_content(
        self,
        package: str,
        script_content: str,
        device_id: str = "",
        timeout: int = 60,
    ) -> FridaResult:
        """
        Inject an inline script string into an application.

        The content is written to a secure temporary file, passed to Frida,
        then cleaned up automatically.

        Parameters
        ----------
        package:
            Target application package / bundle ID.
        script_content:
            JavaScript source code to inject.
        device_id:
            Frida device ID.  Empty = USB device.
        timeout:
            Maximum execution time in seconds.

        Returns
        -------
        ``FridaResult`` (same as ``inject_script``).
        """
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".js",
            prefix="oneinfinity_frida_",
            delete=False,
        ) as tmp:
            tmp.write(script_content)
            tmp_path = tmp.name

        log.debug("Wrote inline script to temp file: %s", tmp_path)
        try:
            result = self.inject_script(
                package=package,
                script_path=tmp_path,
                device_id=device_id,
                timeout=timeout,
            )
            result.script_name = "<inline>"
            return result
        finally:
            try:
                os.unlink(tmp_path)
                log.debug("Cleaned up temp script: %s", tmp_path)
            except OSError as exc:
                log.debug("Could not delete temp script %s: %s", tmp_path, exc)

    # ── Output parsing ────────────────────────────────────────────────────────

    def _parse_frida_output(
        self,
        output: str,
        package: str,
    ) -> List[UnifiedFinding]:
        """
        Parse Frida process output and extract structured findings.

        Two strategies are employed in order:

        1. **Explicit markers** — lines containing ``[FRIDA_FINDING]`` followed
           by a JSON object are parsed directly.  This is the recommended way
           for Frida scripts to report findings.

        2. **Heuristic patterns** — the entire output is scanned for patterns
           that suggest common mobile security issues (SSL pinning bypass,
           root bypass, weak crypto, etc.).  These produce lower-confidence
           findings.

        Parameters
        ----------
        output:
            Combined stdout + stderr from the Frida subprocess.
        package:
            Application identifier for the ``target`` field.

        Returns
        -------
        Deduplicated list of UnifiedFinding objects.
        """
        findings: List[UnifiedFinding] = []
        seen_vulns: set = set()

        # ── Strategy 1: explicit [FRIDA_FINDING] markers ───────────────────
        for line in output.splitlines():
            marker_idx = line.find("[FRIDA_FINDING]")
            if marker_idx == -1:
                continue
            json_part = line[marker_idx + len("[FRIDA_FINDING]"):].strip()
            if not json_part:
                continue
            try:
                data = json.loads(json_part)
                if not isinstance(data, dict):
                    continue
                sev = UnifiedFinding.normalise_severity(str(data.get("severity", "info")))
                vuln = str(data.get("vulnerability", data.get("title", "Frida Finding")))
                attack_type = str(data.get("attack_type", data.get("type", vuln)))
                evidence = str(data.get("evidence", data.get("detail", json_part)))[:500]
                confidence = float(data.get("confidence", 0.80))
                cvss = float(data.get("cvss", _sev_to_cvss_frida(sev)))
                remediation = str(data.get("remediation", data.get("fix", "")))

                dedup_key = (vuln.lower(), attack_type.lower())
                if dedup_key in seen_vulns:
                    continue
                seen_vulns.add(dedup_key)

                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability=vuln,
                    attack_type=attack_type,
                    tool="frida",
                    severity=sev,
                    evidence=evidence,
                    payload=str(data.get("payload", ""))[:300],
                    confidence=confidence,
                    cvss=cvss,
                    remediation=remediation,
                    tags=["frida", "dynamic", attack_type],
                ))
            except (json.JSONDecodeError, ValueError, KeyError) as exc:
                log.debug("Could not parse FRIDA_FINDING JSON: %s — %s", json_part[:80], exc)

        # ── Strategy 2: heuristic scan ────────────────────────────────────────
        for regex, vuln, attack, sev, conf, cvss in _COMPILED_HEURISTICS:
            match = regex.search(output)
            if not match:
                continue
            dedup_key = (vuln.lower(), attack.lower())
            if dedup_key in seen_vulns:
                continue
            seen_vulns.add(dedup_key)

            # Extract the surrounding line for evidence
            start = max(0, match.start() - 40)
            end   = min(len(output), match.end() + 40)
            evidence = output[start:end].replace("\n", " ").strip()

            findings.append(UnifiedFinding(
                target=package,
                vulnerability=vuln,
                attack_type=attack,
                tool="frida",
                severity=sev,
                evidence=evidence[:400],
                confidence=conf,
                cvss=cvss,
                remediation=_FRIDA_REMEDIATIONS.get(attack, ""),
                tags=["frida", "dynamic", "heuristic", attack],
            ))

        log.debug(
            "_parse_frida_output: %d findings from %d output lines (pkg=%s)",
            len(findings), len(output.splitlines()), package,
        )
        return findings

    # ── Utility methods ───────────────────────────────────────────────────────

    def check_frida_server(self, device_id: str = "") -> bool:
        """
        Verify that a frida-server is running and accessible on the device.

        Parameters
        ----------
        device_id:
            Device identifier.  Empty = USB device.

        Returns
        -------
        True if processes could be listed (frida-server is responsive).
        """
        try:
            procs = self._list_processes(device_id=device_id)
            return len(procs) > 0
        except Exception:  # noqa: BLE001
            return False

    def get_running_apps(self, device_id: str = "") -> List[str]:
        """
        Return the package names of all currently running applications.

        Parameters
        ----------
        device_id:
            Device identifier.  Empty = USB device.

        Returns
        -------
        List of package/bundle identifier strings.
        """
        procs = self._list_processes(device_id=device_id)
        apps: List[str] = []
        for p in procs:
            ident = p.get("identifier", "")
            name  = p.get("name", "")
            # Filter obvious system processes (no dot in identifier)
            candidate = ident or name
            if "." in candidate:
                apps.append(candidate)
        # Deduplicate while preserving order
        seen: set = set()
        unique_apps: List[str] = []
        for a in apps:
            if a not in seen:
                seen.add(a)
                unique_apps.append(a)
        return unique_apps

    def __repr__(self) -> str:   # pragma: no cover
        status = "available" if self._frida_bin else "unavailable"
        return f"<FridaWrapper frida={status} config={self.config!r}>"


# ──────────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _sev_to_cvss_frida(severity: str) -> float:
    return {
        "critical": 9.5,
        "high":     7.5,
        "medium":   5.0,
        "low":      3.0,
        "info":     0.0,
    }.get(severity, 0.0)


#: Attack-type → boilerplate remediation text used by heuristic findings.
_FRIDA_REMEDIATIONS: Dict[str, str] = {
    "ssl_pinning": (
        "Implement robust SSL/TLS certificate pinning using a multi-layer approach: "
        "OkHttp CertificatePinner + TrustKit + Android Network Security Config. "
        "Do not rely solely on a single pinning mechanism."
    ),
    "root_bypass": (
        "Use a combination of root-detection libraries (RootBeer, SafetyNet/Play Integrity API) "
        "and native checks. Obfuscate detection logic to resist Frida hooks."
    ),
    "emulator_detection": (
        "Implement multi-signal emulator detection (hardware fingerprints, sensor data, "
        "QEMU traces). Tie detection to business-logic restrictions, not just UI warnings."
    ),
    "auth_bypass": (
        "Biometric / auth checks must be performed server-side using cryptographic "
        "challenge-response.  Client-side checks alone are bypassable."
    ),
    "weak_crypto": (
        "Replace DES, 3DES, RC4, and MD5 with AES-256-GCM for encryption and "
        "SHA-256/SHA-3 for hashing. Use Android Keystore for key management."
    ),
    "hardcoded_secret": (
        "Remove all hardcoded credentials from the application binary. "
        "Use server-side secrets management and fetch credentials at runtime "
        "over a pinned TLS channel."
    ),
    "insecure_logging": (
        "Strip all Log.d/Log.v calls in release builds using ProGuard/R8 rules. "
        "Never log passwords, tokens, or PII."
    ),
    "webview_misconfiguration": (
        "Disable JavaScript in WebViews that do not require it. "
        "If JavaScript is needed, restrict origins via setAllowFileAccess(false) "
        "and avoid addJavascriptInterface unless unavoidable."
    ),
    "insecure_storage": (
        "Use EncryptedSharedPreferences / Android Keystore rather than plain "
        "SharedPreferences for sensitive data. Never use MODE_WORLD_READABLE files."
    ),
    "sql_injection": (
        "Always use parameterised queries or Room DAO annotations. "
        "Never concatenate user input into SQL strings."
    ),
    "insecure_transport": (
        "Enforce HTTPS for all network calls. Set usesCleartextTraffic=false "
        "in network_security_config.xml."
    ),
}


# ──────────────────────────────────────────────────────────────────────────────
#  Module-level singleton
# ──────────────────────────────────────────────────────────────────────────────

#: Global singleton.  Import as:
#:     ``from frida_wrapper import frida_wrapper``
frida_wrapper: FridaWrapper = FridaWrapper()
