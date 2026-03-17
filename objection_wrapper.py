"""
Objection Wrapper
=================
Runtime exploration and manipulation of mobile apps using Objection.
Objection is powered by Frida and provides high-level mobile app analysis.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from mobile_tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.objection")

_TOOL = "objection"


@dataclass
class ObjectionConfig:
    device_id: str = ""
    timeout: int = 120


class ObjectionWrapper:
    """High-level Objection runtime analysis wrapper."""

    def __init__(self, config: ObjectionConfig = None) -> None:
        self.config = config or ObjectionConfig()
        self._objection_path: Optional[str] = self._find_objection()

    # ------------------------------------------------------------------ internals

    def _find_objection(self) -> Optional[str]:
        """Locate the objection binary on PATH."""
        path = shutil.which("objection")
        if path:
            logger.debug("Found objection at %s", path)
            return path
        logger.warning("objection not found on PATH — dynamic analysis will be limited")
        return None

    def _run_objection_command(
        self,
        package: str,
        command: str,
        device_id: str = "",
        timeout: int = 30,
    ) -> Tuple[str, str]:
        """
        Run a single objection startup-command against *package*.

        Builds:
          objection [-N] [-h host] explore --startup-command "{command}" -- -U -f {package}

        Returns (stdout, stderr).
        """
        if not self._objection_path:
            return "", "objection not available"

        cmd: List[str] = [self._objection_path]

        # Network device: device_id like "192.168.1.5:5555" → use -N -h <host>
        effective_device = device_id or self.config.device_id
        if effective_device and ":" in effective_device and not effective_device.startswith("emulator-"):
            host_only = effective_device.split(":")[0]
            cmd += ["-N", "-h", host_only]

        cmd += [
            "explore",
            "--startup-command", command,
            "--",
            "-U",
            "-f", package,
        ]

        logger.debug("Running objection: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.warning("objection command timed out after %ds: %s", timeout, command)
            return "", f"timeout after {timeout}s"
        except FileNotFoundError:
            return "", "objection binary not found"
        except Exception as exc:
            logger.error("objection error: %s", exc)
            return "", str(exc)

    def _make_finding(
        self,
        package: str,
        vulnerability: str,
        attack_type: str,
        severity: str,
        evidence: str = "",
        remediation: str = "",
        cvss: float = 0.0,
    ) -> UnifiedFinding:
        return UnifiedFinding(
            target=package,
            vulnerability=vulnerability,
            attack_type=attack_type,
            tool=_TOOL,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            cvss=cvss,
        )

    # ------------------------------------------------------------------ public API

    def bypass_ssl_pinning(self, package: str, device_id: str = "") -> bool:
        """
        Attempt to disable SSL pinning via objection.
        Returns True if objection reported a successful bypass.
        """
        stdout, stderr = self._run_objection_command(
            package,
            "android sslpinning disable",
            device_id=device_id,
            timeout=self.config.timeout,
        )
        combined = (stdout + stderr).lower()
        if not combined.strip():
            return False
        indicators = ["ssl pinning disabled", "sslpinning", "pinning bypass", "disabled"]
        error_indicators = ["error", "exception", "failed", "not found"]
        has_positive = any(ind in combined for ind in indicators)
        has_error = any(e in combined for e in error_indicators) and "ssl" not in combined
        return has_positive and not has_error

    def bypass_root_detection(self, package: str, device_id: str = "") -> bool:
        """
        Attempt to disable root detection via objection.
        Returns True if bypass appears successful.
        """
        stdout, stderr = self._run_objection_command(
            package,
            "android root disable",
            device_id=device_id,
            timeout=self.config.timeout,
        )
        combined = (stdout + stderr).lower()
        if not combined.strip():
            return False
        indicators = ["root disabled", "root detection disabled", "com.scottyab.rootbeer", "disabled"]
        return any(ind in combined for ind in indicators)

    def list_activities(self, package: str, device_id: str = "") -> List[str]:
        """Return list of activity class names declared by the package."""
        stdout, _stderr = self._run_objection_command(
            package,
            "android hooking list activities",
            device_id=device_id,
        )
        activities: List[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line and "." in line and not line.startswith("[") and not line.startswith("("):
                if not any(kw in line.lower() for kw in ("objection", "frida", "agent", "---")):
                    activities.append(line)
        logger.debug("Found %d activities for %s", len(activities), package)
        return activities

    def list_services(self, package: str, device_id: str = "") -> List[str]:
        """Return list of service class names declared by the package."""
        stdout, _stderr = self._run_objection_command(
            package,
            "android hooking list services",
            device_id=device_id,
        )
        services: List[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line and "." in line and not line.startswith("[") and not line.startswith("("):
                if not any(kw in line.lower() for kw in ("objection", "frida", "agent", "---")):
                    services.append(line)
        return services

    def dump_keystore(self, package: str, device_id: str = "") -> List[dict]:
        """
        List entries in the Android Keystore accessible to *package*.
        Returns list of dicts with keys: alias, type, accessible.
        """
        stdout, _stderr = self._run_objection_command(
            package,
            "android keystore list",
            device_id=device_id,
        )
        entries: List[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or "alias" in line.lower():
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                entries.append({
                    "alias": parts[0],
                    "type": parts[1] if len(parts) > 1 else "",
                    "accessible": parts[2].lower() == "true" if len(parts) > 2 else False,
                })
            elif line:
                entries.append({"alias": line, "type": "unknown", "accessible": False})
        return entries

    def list_shared_prefs(self, package: str, device_id: str = "") -> List[dict]:
        """
        List SharedPreferences files and their key-value entries.
        Returns list of dicts with keys: file, key, value.
        """
        stdout, _stderr = self._run_objection_command(
            package,
            "android preferences list",
            device_id=device_id,
        )
        prefs: List[dict] = []
        current_file = ""
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("sharedpreferences:") or (line.endswith(".xml") and "/" not in line):
                current_file = line.split(":", 1)[-1].strip()
            elif "=" in line:
                key, _, value = line.partition("=")
                prefs.append({"file": current_file, "key": key.strip(), "value": value.strip()})
            elif "|" in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 2:
                    prefs.append({
                        "file": current_file,
                        "key": parts[0],
                        "value": parts[1] if len(parts) > 1 else "",
                    })
        return prefs

    def dump_cookies(self, package: str, device_id: str = "") -> List[dict]:
        """
        Dump HTTP cookies stored by the app (WebView / OkHttp cookie jar).
        Returns list of dicts with keys: name, value, domain, secure, httpOnly.
        """
        stdout, _stderr = self._run_objection_command(
            package,
            "android cookies get",
            device_id=device_id,
        )
        cookies: List[dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or "name" in line.lower():
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                cookies.append({
                    "name": parts[0],
                    "value": parts[1] if len(parts) > 1 else "",
                    "domain": parts[2] if len(parts) > 2 else "",
                    "secure": parts[3].lower() == "true" if len(parts) > 3 else False,
                    "httpOnly": parts[4].lower() == "true" if len(parts) > 4 else False,
                })
        return cookies

    def list_sqlite_databases(self, package: str, device_id: str = "") -> List[str]:
        """Return list of SQLite database file paths used by the app."""
        stdout, _stderr = self._run_objection_command(
            package,
            "android sqlite databases",
            device_id=device_id,
        )
        databases: List[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line and (".db" in line or "sqlite" in line.lower()):
                clean = re.sub(r"^\[[^\]]+\]\s*", "", line)
                if clean:
                    databases.append(clean)
        return databases

    # ------------------------------------------------------------------ analysis

    def analyze_runtime(self, package: str, device_id: str = "") -> List[UnifiedFinding]:
        """
        Aggregate results from bypass checks, keystore, prefs, and cookies into
        UnifiedFinding objects.

        Severity mapping:
          - Insecure SharedPreferences (plaintext sensitive values) → MEDIUM
          - Cleartext cookies (secure=False for sensitive cookies)   → HIGH
          - Accessible Keystore entries                              → HIGH
        """
        if not self._objection_path:
            return [
                UnifiedFinding(
                    target=package,
                    vulnerability="Objection not available — runtime analysis skipped",
                    attack_type="tool_missing",
                    tool=_TOOL,
                    severity="info",
                    remediation="Install objection (pip install objection) to enable runtime analysis.",
                )
            ]

        findings: List[UnifiedFinding] = []

        # ── SSL Pinning ────────────────────────────────────────────────────────
        ssl_bypassed = self.bypass_ssl_pinning(package, device_id=device_id)
        if ssl_bypassed:
            findings.append(self._make_finding(
                package=package,
                vulnerability="SSL Pinning Bypassed via Objection",
                attack_type="ssl_pinning_bypass",
                severity="medium",
                evidence="objection 'android sslpinning disable' succeeded",
                remediation=(
                    "Implement stronger pinning (e.g. TrustKit or native pinning) "
                    "and detect hooking frameworks at runtime."
                ),
                cvss=5.9,
            ))

        # ── Root Detection ─────────────────────────────────────────────────────
        root_bypassed = self.bypass_root_detection(package, device_id=device_id)
        if root_bypassed:
            findings.append(self._make_finding(
                package=package,
                vulnerability="Root Detection Bypassed via Objection",
                attack_type="root_detection_bypass",
                severity="medium",
                evidence="objection 'android root disable' succeeded",
                remediation=(
                    "Use multiple independent detection methods and obfuscate detection logic. "
                    "Consider using the SafetyNet/Play Integrity API."
                ),
                cvss=5.3,
            ))

        # ── Keystore ──────────────────────────────────────────────────────────
        keystore_entries = self.dump_keystore(package, device_id=device_id)
        accessible = [e for e in keystore_entries if e.get("accessible")]
        if accessible:
            aliases = ", ".join(e["alias"] for e in accessible[:10])
            findings.append(self._make_finding(
                package=package,
                vulnerability="Android Keystore Entries Accessible Without Authentication",
                attack_type="insecure_keystore",
                severity="high",
                evidence=f"Accessible aliases: {aliases}",
                remediation=(
                    "Use KeyGenParameterSpec.Builder.setUserAuthenticationRequired(true) "
                    "and setUserAuthenticationValidityDurationSeconds(-1) for sensitive keys."
                ),
                cvss=7.1,
            ))

        # ── SharedPreferences ─────────────────────────────────────────────────
        prefs = self.list_shared_prefs(package, device_id=device_id)
        sensitive_pref_re = re.compile(
            r"(password|passwd|token|secret|key|auth|credential|pin\b|ssn|dob|cc_|credit)",
            re.IGNORECASE,
        )
        insecure_prefs = [
            p for p in prefs
            if sensitive_pref_re.search(p.get("key", "")) and p.get("value")
        ]
        if insecure_prefs:
            sample = "; ".join(
                f"{p['file']}:{p['key']}={p['value'][:20]}" for p in insecure_prefs[:5]
            )
            findings.append(self._make_finding(
                package=package,
                vulnerability="Sensitive Data Stored in Plaintext SharedPreferences",
                attack_type="insecure_storage_sharedprefs",
                severity="medium",
                evidence=sample,
                remediation=(
                    "Use EncryptedSharedPreferences from the Jetpack Security library, "
                    "or Android Keystore-backed encryption for sensitive values."
                ),
                cvss=5.5,
            ))

        # ── Cookies ───────────────────────────────────────────────────────────
        cookies = self.dump_cookies(package, device_id=device_id)
        session_cookie_re = re.compile(
            r"(session|auth|token|jwt|access|refresh|user_id)", re.IGNORECASE
        )
        cleartext_cookies = [
            c for c in cookies
            if session_cookie_re.search(c.get("name", "")) and not c.get("secure", True)
        ]
        if cleartext_cookies:
            sample = "; ".join(
                f"{c['name']}@{c.get('domain', '?')}" for c in cleartext_cookies[:5]
            )
            findings.append(self._make_finding(
                package=package,
                vulnerability="Session/Auth Cookies Missing Secure Flag",
                attack_type="insecure_cookie",
                severity="high",
                evidence=sample,
                remediation=(
                    "Set the Secure and HttpOnly flags on all authentication cookies. "
                    "Use HTTPS exclusively and configure HSTS."
                ),
                cvss=7.4,
            ))

        logger.info("analyze_runtime(%s): %d findings", package, len(findings))
        return findings


# Module-level singleton
objection_wrapper = ObjectionWrapper()
