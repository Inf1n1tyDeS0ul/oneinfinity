"""
Drozer Wrapper
==============
Android component security testing using Drozer.
Tests exported activities, content providers, broadcast receivers, and services.
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from oneinfinity.mobile.tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.drozer")

_TOOL = "drozer"


@dataclass
class DrozerConfig:
    host: str = "127.0.0.1"
    port: int = 31415
    timeout: int = 60


class DrozerWrapper:
    """Drozer-based Android component security tester."""

    def __init__(self, config: DrozerConfig = None) -> None:
        self.config = config or DrozerConfig()
        self._drozer_path: Optional[str] = self._find_drozer()

    # ------------------------------------------------------------------ internals

    def _find_drozer(self) -> Optional[str]:
        """Locate the drozer binary on PATH."""
        path = shutil.which("drozer")
        if path:
            logger.debug("Found drozer at %s", path)
            return path
        logger.warning("drozer not found on PATH — component testing unavailable")
        return None

    def _is_drozer_running(self) -> bool:
        """Check if the drozer agent is accepting connections on host:port."""
        try:
            with socket.create_connection(
                (self.config.host, self.config.port), timeout=2
            ):
                return True
        except (OSError, ConnectionRefusedError, socket.timeout):
            return False

    def _run_drozer_command(
        self,
        command: str,
        timeout: int = 60,
    ) -> Tuple[str, str]:
        """
        Execute a drozer console command via:
          drozer console connect --server {host}:{port} --cmd "{command}"

        Returns (stdout, stderr).
        """
        if not self._drozer_path:
            return "", "drozer not available"

        cmd = [
            self._drozer_path,
            "console", "connect",
            "--server", f"{self.config.host}:{self.config.port}",
            "--cmd", command,
        ]

        logger.debug("Running drozer: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.warning("drozer command timed out (%ds): %s", timeout, command)
            return "", f"timeout after {timeout}s"
        except FileNotFoundError:
            return "", "drozer binary not found"
        except Exception as exc:
            logger.error("drozer error: %s", exc)
            return "", str(exc)

    def _check_available(self) -> Optional[UnifiedFinding]:
        """Return a tool_missing UnifiedFinding if drozer cannot be used, else None."""
        if not self._drozer_path:
            return UnifiedFinding(
                target="",
                vulnerability="Drozer not installed — component testing skipped",
                attack_type="tool_missing",
                tool=_TOOL,
                severity="info",
                remediation="Install drozer (pip install drozer) to enable Android component testing.",
            )
        if not self._is_drozer_running():
            return UnifiedFinding(
                target="",
                vulnerability="Drozer agent not running — component testing skipped",
                attack_type="tool_unavailable",
                tool=_TOOL,
                severity="info",
                remediation=(
                    f"Drozer agent not accepting connections at "
                    f"{self.config.host}:{self.config.port}. "
                    "Start the drozer agent app on the device and run "
                    "'adb forward tcp:31415 tcp:31415'."
                ),
            )
        return None

    def _make_finding(
        self,
        package: str,
        vulnerability: str,
        attack_type: str,
        severity: str,
        evidence: str = "",
        remediation: str = "",
        location: str = "",
        cvss: float = 0.0,
    ) -> UnifiedFinding:
        f = UnifiedFinding(
            target=package,
            vulnerability=vulnerability,
            attack_type=attack_type,
            tool=_TOOL,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            cvss=cvss,
        )
        f.file_path = location
        return f

    # ------------------------------------------------------------------ attack surface

    def get_attack_surface(self, package: str) -> dict:
        """
        Run drozer app.package.attacksurface and parse the result.

        Returns:
            {
                "activities": int,
                "services": int,
                "broadcast_receivers": int,
                "content_providers": int,
                "is_debuggable": bool,
            }
        """
        surface: Dict = {
            "activities": 0,
            "services": 0,
            "broadcast_receivers": 0,
            "content_providers": 0,
            "is_debuggable": False,
        }

        stdout, stderr = self._run_drozer_command(
            f"run app.package.attacksurface {package}",
            timeout=self.config.timeout,
        )

        if not stdout:
            logger.debug("attacksurface returned no output: %s", stderr)
            return surface

        for line in stdout.splitlines():
            line = line.strip().lower()
            m = re.search(r"(\d+)\s+(.+)", line)
            if m:
                count = int(m.group(1))
                label = m.group(2)
                if "activity" in label:
                    surface["activities"] = count
                elif "service" in label:
                    surface["services"] = count
                elif "broadcast" in label or "receiver" in label:
                    surface["broadcast_receivers"] = count
                elif "content provider" in label or "provider" in label:
                    surface["content_providers"] = count
            if "debuggable" in line:
                surface["is_debuggable"] = "true" in line or "yes" in line

        return surface

    # ------------------------------------------------------------------ activities

    def get_exported_activities(self, package: str) -> List[str]:
        """Return list of exported activity class names for *package*."""
        stdout, _stderr = self._run_drozer_command(
            f"run app.activity.info -a {package}",
            timeout=self.config.timeout,
        )
        activities: List[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if (
                line
                and "." in line
                and not line.startswith("[")
                and not line.lower().startswith("package")
                and not line.lower().startswith("permission")
                and not line.lower().startswith("activity")
                and not line.startswith("-")
            ):
                activities.append(line)
        return activities

    def test_exported_activities(self, package: str) -> List[UnifiedFinding]:
        """
        Attempt to start each exported activity without credentials.
        If an activity starts without an auth gate → HIGH finding.
        """
        unavail = self._check_available()
        if unavail:
            return [unavail]

        activities = self.get_exported_activities(package)
        if not activities:
            return []

        findings: List[UnifiedFinding] = []

        for activity in activities:
            stdout, stderr = self._run_drozer_command(
                f"run app.activity.start --component {package} {activity}",
                timeout=30,
            )
            combined = (stdout + stderr).lower()
            started = (
                "error" not in combined
                and "denied" not in combined
                and "permission" not in combined
                and "securityexception" not in combined
            ) or "starting: intent" in combined

            if started:
                findings.append(self._make_finding(
                    package=package,
                    vulnerability=f"Exported Activity Accessible Without Authentication: {activity}",
                    attack_type="exported_activity_bypass",
                    severity="high",
                    evidence=stdout[:200],
                    remediation=(
                        "Set android:exported=\"false\" unless external access is required. "
                        "If external access is needed, enforce android:permission."
                    ),
                    location=activity,
                    cvss=7.5,
                ))

        return findings

    # ------------------------------------------------------------------ content providers

    def get_content_providers(self, package: str) -> List[str]:
        """Return list of content provider authority URIs for *package*."""
        stdout, _stderr = self._run_drozer_command(
            f"run app.provider.info -a {package}",
            timeout=self.config.timeout,
        )
        providers: List[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("Authority:"):
                authority = line.split(":", 1)[1].strip()
                providers.append(f"content://{authority}")
            elif "content://" in line:
                m = re.search(r"content://[^\s\"']+", line)
                if m:
                    providers.append(m.group(0))
        return list(set(providers))

    def test_content_providers(self, package: str) -> List[UnifiedFinding]:
        """
        Test all content providers for:
          - Unauthorised data read (CRITICAL)
          - SQL injection via projection clause (CRITICAL)
        """
        unavail = self._check_available()
        if unavail:
            return [unavail]

        providers = self.get_content_providers(package)
        if not providers:
            providers = [f"content://{package}"]

        findings: List[UnifiedFinding] = []

        for uri in providers:
            # ── Unauthenticated read ─────────────────────────────────────────
            stdout_q, stderr_q = self._run_drozer_command(
                f"run app.provider.query {uri}",
                timeout=30,
            )
            if (
                stdout_q
                and "error" not in stdout_q.lower()
                and "exception" not in stdout_q.lower()
                and stdout_q.strip()
            ):
                findings.append(self._make_finding(
                    package=package,
                    vulnerability=f"Content Provider Exposes Data Without Authentication: {uri}",
                    attack_type="content_provider_exposure",
                    severity="critical",
                    evidence=stdout_q[:300],
                    remediation=(
                        "Protect content providers with android:readPermission and "
                        "android:writePermission. Set android:exported=\"false\" "
                        "unless external access is required."
                    ),
                    location=uri,
                    cvss=9.1,
                ))

            # ── SQL Injection via projection ─────────────────────────────────
            sqli_payload = "* FROM sqlite_master--"
            stdout_sqli, stderr_sqli = self._run_drozer_command(
                f"run app.provider.query {uri} --projection \"{sqli_payload}\"",
                timeout=30,
            )
            combined_sqli = stdout_sqli + stderr_sqli
            sqli_positive = (
                "sqlite_master" in combined_sqli.lower()
                or (
                    "table" in combined_sqli.lower()
                    and "name" in combined_sqli.lower()
                    and "type" in combined_sqli.lower()
                )
            ) and "error" not in combined_sqli.lower()[:50]

            if sqli_positive:
                findings.append(self._make_finding(
                    package=package,
                    vulnerability=f"SQL Injection in Content Provider: {uri}",
                    attack_type="content_provider_sqli",
                    severity="critical",
                    evidence=combined_sqli[:300],
                    remediation=(
                        "Use parameterised queries in ContentProvider.query(). "
                        "Validate and whitelist projection columns. "
                        "Never concatenate user-supplied strings into SQL clauses."
                    ),
                    location=uri,
                    cvss=9.8,
                ))

        return findings

    # ------------------------------------------------------------------ broadcast receivers

    def test_broadcast_receivers(self, package: str) -> List[UnifiedFinding]:
        """
        Test exported broadcast receivers for unauthorised intent handling.
        """
        unavail = self._check_available()
        if unavail:
            return [unavail]

        stdout, _stderr = self._run_drozer_command(
            f"run app.broadcast.info -a {package}",
            timeout=self.config.timeout,
        )
        receivers: List[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if (
                line
                and "." in line
                and not line.startswith("[")
                and not line.lower().startswith("permission")
            ):
                receivers.append(line)

        findings: List[UnifiedFinding] = []

        for receiver in receivers:
            stdout_send, stderr_send = self._run_drozer_command(
                f"run app.broadcast.send --component {package} {receiver} "
                "--action android.intent.action.MAIN",
                timeout=20,
            )
            combined = (stdout_send + stderr_send).lower()
            accepted = (
                "error" not in combined
                and "denied" not in combined
                and "permission" not in combined
                and "securityexception" not in combined
            ) and (stdout_send.strip() or "sending" in combined)

            if accepted:
                findings.append(self._make_finding(
                    package=package,
                    vulnerability=(
                        f"Exported Broadcast Receiver Accepts Unauthorised Intents: {receiver}"
                    ),
                    attack_type="exported_broadcast_receiver",
                    severity="medium",
                    evidence=stdout_send[:200],
                    remediation=(
                        "Protect exported receivers with android:permission. "
                        "Validate all incoming intent extras. "
                        "Use LocalBroadcastManager for internal broadcasts."
                    ),
                    location=receiver,
                    cvss=5.3,
                ))

        return findings

    # ------------------------------------------------------------------ IPC

    def test_ipc_vulnerabilities(self, package: str) -> List[UnifiedFinding]:
        """
        Comprehensive IPC security test:
          - Exported service enumeration and unauthorised binding
          - Deep link / URI handler testing
          - Intent structure analysis
        """
        unavail = self._check_available()
        if unavail:
            return [unavail]

        findings: List[UnifiedFinding] = []

        # ── Exported services ─────────────────────────────────────────────────
        svc_stdout, _svc_stderr = self._run_drozer_command(
            f"run app.service.info -a {package}",
            timeout=self.config.timeout,
        )
        services: List[str] = []
        for line in svc_stdout.splitlines():
            line = line.strip()
            if (
                line
                and "." in line
                and not line.startswith("[")
                and not line.lower().startswith("permission")
            ):
                services.append(line)

        for service in services:
            start_out, start_err = self._run_drozer_command(
                f"run app.service.start --component {package} {service}",
                timeout=20,
            )
            combined = (start_out + start_err).lower()
            if (
                "error" not in combined
                and "denied" not in combined
                and "permission" not in combined
                and "securityexception" not in combined
            ):
                findings.append(self._make_finding(
                    package=package,
                    vulnerability=f"Exported Service Startable Without Permission: {service}",
                    attack_type="exported_service_unprotected",
                    severity="high",
                    evidence=start_out[:200],
                    remediation=(
                        "Set android:exported=\"false\" for internal services. "
                        "For externally accessible services, require a signature-level permission."
                    ),
                    location=service,
                    cvss=7.5,
                ))

        # ── Deep links from manifest ──────────────────────────────────────────
        manifest_stdout, _manifest_stderr = self._run_drozer_command(
            f"run app.package.manifest {package}",
            timeout=self.config.timeout,
        )
        deep_links: List[str] = []
        for m in re.finditer(r'android:scheme="([^"]+)"', manifest_stdout):
            scheme = m.group(1)
            if scheme not in ("http", "https"):
                deep_links.append(f"{scheme}://test")

        for deep_link in deep_links[:5]:
            dl_out, dl_err = self._run_drozer_command(
                f"run app.activity.start --action android.intent.action.VIEW "
                f"--data-uri {deep_link}",
                timeout=20,
            )
            combined = (dl_out + dl_err).lower()
            if (
                "error" not in combined
                and "exception" not in combined
                and dl_out.strip()
            ):
                findings.append(self._make_finding(
                    package=package,
                    vulnerability=f"Deep Link Handler Accepts Arbitrary URI: {deep_link}",
                    attack_type="deep_link_injection",
                    severity="medium",
                    evidence=dl_out[:200],
                    remediation=(
                        "Validate all URI parameters before processing. "
                        "Use App Links (HTTPS) instead of custom URI schemes where possible. "
                        "Implement strict URI allowlisting."
                    ),
                    location=deep_link,
                    cvss=5.4,
                ))

        return findings

    # ------------------------------------------------------------------ full audit

    def full_audit(self, package: str) -> List[UnifiedFinding]:
        """
        Run all component security tests and return deduplicated findings.
        """
        unavail = self._check_available()
        if unavail:
            return [unavail]

        all_findings: List[UnifiedFinding] = []

        # Attack surface summary
        surface = self.get_attack_surface(package)
        summary = UnifiedFinding(
            target=package,
            vulnerability=f"Attack Surface Summary for {package}",
            attack_type="attack_surface_summary",
            tool=_TOOL,
            severity="info",
            evidence=(
                f"Exported components: "
                f"{surface['activities']} activities, "
                f"{surface['services']} services, "
                f"{surface['broadcast_receivers']} receivers, "
                f"{surface['content_providers']} providers. "
                f"Debuggable: {surface['is_debuggable']}."
            ),
        )
        all_findings.append(summary)

        if surface.get("is_debuggable"):
            all_findings.append(self._make_finding(
                package=package,
                vulnerability="Application is Debuggable (android:debuggable=true)",
                attack_type="debuggable_application",
                severity="high",
                evidence="android:debuggable=true detected via drozer attack surface scan",
                remediation=(
                    "Remove android:debuggable or set it to false in release builds. "
                    "Ensure build system does not override this in release variants."
                ),
                cvss=7.8,
            ))

        # Run all test suites
        for test_fn in (
            self.test_exported_activities,
            self.test_content_providers,
            self.test_broadcast_receivers,
            self.test_ipc_vulnerabilities,
        ):
            try:
                results = test_fn(package)
                all_findings.extend(results)
            except Exception as exc:
                logger.warning("drozer test %s failed: %s", test_fn.__name__, exc)

        # Deduplicate by (attack_type, location, target)
        seen: set = set()
        deduped: List[UnifiedFinding] = []
        for f in all_findings:
            key = (f.attack_type, getattr(f, "file_path", ""), f.target)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info("full_audit(%s): %d unique findings", package, len(deduped))
        return deduped


# Module-level singleton
drozer_wrapper = DrozerWrapper()
