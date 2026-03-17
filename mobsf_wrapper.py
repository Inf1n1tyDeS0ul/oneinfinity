"""
MobSF Wrapper
=============
Interface to Mobile Security Framework (MobSF).
Supports both REST API mode (if MobSF server is running) and a graceful
degradation path when the server is unavailable.

Architecture
------------
* If a MobSF server is reachable at ``config.api_url`` the wrapper uses the
  REST API: upload → scan → report_json.
* When the server is down ``scan_file()`` logs a warning and returns an empty
  list (CLI mode placeholder — production deployments should run MobSF as a
  service).

MobSF REST API reference: https://mobsf.github.io/Mobile-Security-Framework-MobSF/

Usage::

    from mobsf_wrapper import mobsf_wrapper

    findings = mobsf_wrapper.scan_file("/path/to/app.apk")
    for f in findings:
        print(f.severity, f.vulnerability)
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from mobile_tool_registry import UnifiedFinding, tool_registry

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

log = logging.getLogger("oneinfinity.mobile.mobsf")


# ──────────────────────────────────────────────────────────────────────────────
#  Configuration
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class MobSFConfig:
    """Runtime configuration for the MobSF wrapper."""

    api_url: str = "http://localhost:8008"
    """Base URL of the MobSF REST API server."""

    api_key: str = ""
    """MobSF REST API key — visible on the MobSF dashboard under REST API."""

    timeout: int = 300
    """HTTP request timeout in seconds (default 5 min for large APKs)."""

    verify_ssl: bool = True
    """Set False when the MobSF server uses a self-signed certificate."""

    def __post_init__(self) -> None:
        # Strip trailing slash for consistent URL construction
        self.api_url = self.api_url.rstrip("/")
        # Allow API key to come from environment if not set explicitly
        if not self.api_key:
            self.api_key = os.environ.get("MOBSF_API_KEY", "")


# ──────────────────────────────────────────────────────────────────────────────
#  Severity / CVSS mapping tables
# ──────────────────────────────────────────────────────────────────────────────

# MobSF permission status → severity
_PERM_SEVERITY: Dict[str, str] = {
    "dangerous": "high",
    "normal":    "info",
    "signature": "info",
    "unknown":   "low",
}

# MobSF code-analysis finding severity strings
_CODE_SEV: Dict[str, str] = {
    "high":   "high",
    "medium": "medium",
    "info":   "info",
    "warning": "medium",
    "error":  "high",
}

# Dangerous Android permissions warrant specific remediation advice
_DANGEROUS_PERM_REMEDIATION: Dict[str, str] = {
    "android.permission.READ_CONTACTS":
        "Request READ_CONTACTS only when actively needed; explain usage to the user.",
    "android.permission.CAMERA":
        "Request CAMERA at runtime and only for features that genuinely require it.",
    "android.permission.RECORD_AUDIO":
        "Request RECORD_AUDIO at runtime; never record in the background without clear disclosure.",
    "android.permission.ACCESS_FINE_LOCATION":
        "Prefer ACCESS_COARSE_LOCATION unless precise location is strictly necessary.",
    "android.permission.READ_EXTERNAL_STORAGE":
        "Target API 33+ scoped-storage APIs to avoid broad external-storage access.",
    "android.permission.WRITE_EXTERNAL_STORAGE":
        "Use app-specific directories (getExternalFilesDir) instead of WRITE_EXTERNAL_STORAGE.",
    "android.permission.READ_SMS":
        "SMS access is high-risk; justify to Google Play and request at runtime only.",
    "android.permission.SEND_SMS":
        "SEND_SMS can incur charges; require explicit user confirmation for each message.",
    "android.permission.PROCESS_OUTGOING_CALLS":
        "Deprecated in API 29; use CallScreeningService instead.",
    "android.permission.READ_CALL_LOG":
        "READ_CALL_LOG is restricted; requires a Privacy Policy and Play Store declaration.",
}

_GENERIC_DANGEROUS_PERM_REMEDIATION = (
    "Audit whether this dangerous permission is strictly required. "
    "If it is, request it at runtime with a clear user-facing rationale "
    "and implement graceful degradation when denied."
)


# ──────────────────────────────────────────────────────────────────────────────
#  Wrapper
# ──────────────────────────────────────────────────────────────────────────────

class MobSFWrapper:
    """
    High-level interface to Mobile Security Framework (MobSF).

    All public methods return ``List[UnifiedFinding]`` so results slot directly
    into the shared mobile security pipeline.
    """

    def __init__(self, config: Optional[MobSFConfig] = None) -> None:
        self.config = config or MobSFConfig()
        self._session: Optional[object] = None   # requests.Session, typed as Any

        if not _REQUESTS_AVAILABLE:
            log.warning(
                "MobSFWrapper: 'requests' library not installed. "
                "Install with: pip install requests"
            )
        else:
            import requests
            session = requests.Session()
            session.headers.update({"Authorization": self.config.api_key})
            if self.config.api_key:
                session.headers["Authorization"] = self.config.api_key
            self._session = session

    # ── Server probe ──────────────────────────────────────────────────────────

    def _is_server_running(self) -> bool:
        """
        Return True if the MobSF server is reachable.

        Performs a lightweight GET /api/v1/version — the lightest endpoint
        that requires no authentication.
        """
        if not _REQUESTS_AVAILABLE or self._session is None:
            return False
        try:
            import requests
            url = f"{self.config.api_url}/api/v1/version"
            resp = self._session.get(url, timeout=5, verify=self.config.verify_ssl)
            return resp.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    # ── Upload + scan ─────────────────────────────────────────────────────────

    def upload_and_scan(self, file_path: str) -> dict:
        """
        Upload an APK/IPA/AAB to MobSF and trigger static analysis.

        Parameters
        ----------
        file_path:
            Absolute path to the mobile app binary.

        Returns
        -------
        Dict with at least ``{"hash": "<scan_hash>", "file_name": "..."}``
        from MobSF, or ``{}`` on failure.

        Falls back to ``_cli_scan()`` mode when the server is unreachable.
        """
        if not self._is_server_running():
            log.warning(
                "MobSF server not reachable at %s; falling back to CLI mode.",
                self.config.api_url,
            )
            return {}

        import requests

        file_path = os.path.abspath(file_path)
        if not os.path.isfile(file_path):
            log.error("upload_and_scan: file not found: %s", file_path)
            return {}

        file_name = os.path.basename(file_path)
        log.info("Uploading %s to MobSF …", file_name)

        # ── Upload ────────────────────────────────────────────────────────────
        try:
            with open(file_path, "rb") as fh:
                upload_resp = self._session.post(
                    f"{self.config.api_url}/api/v1/upload",
                    files={"file": (file_name, fh, "application/octet-stream")},
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                )
            upload_resp.raise_for_status()
            upload_data = upload_resp.json()
        except requests.RequestException as exc:
            log.error("MobSF upload failed: %s", exc)
            return {}
        except ValueError as exc:
            log.error("MobSF upload response not JSON: %s", exc)
            return {}

        scan_hash = upload_data.get("hash")
        if not scan_hash:
            log.error("MobSF upload response missing 'hash': %s", upload_data)
            return {}

        log.info("Upload successful, scan_hash=%s", scan_hash)

        # ── Scan ──────────────────────────────────────────────────────────────
        try:
            scan_resp = self._session.post(
                f"{self.config.api_url}/api/v1/scan",
                data={"scan_type": upload_data.get("scan_type", "apk"), "hash": scan_hash},
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
            scan_resp.raise_for_status()
            scan_data = scan_resp.json()
        except requests.RequestException as exc:
            log.error("MobSF scan request failed: %s", exc)
            return upload_data   # return upload data so caller has scan_hash

        log.info("Scan triggered for hash=%s", scan_hash)
        return {**upload_data, **scan_data}

    # ── Report retrieval ──────────────────────────────────────────────────────

    def get_report(self, scan_hash: str) -> dict:
        """
        Retrieve the full JSON report for a completed scan.

        Parameters
        ----------
        scan_hash:
            Hash returned by ``upload_and_scan``.

        Returns
        -------
        Full MobSF report dict, or ``{}`` on error.
        """
        if not _REQUESTS_AVAILABLE or self._session is None:
            log.error("get_report: requests not available.")
            return {}
        if not self._is_server_running():
            log.warning("MobSF server not reachable; cannot retrieve report.")
            return {}

        import requests

        try:
            resp = self._session.post(
                f"{self.config.api_url}/api/v1/report_json",
                data={"hash": scan_hash},
                headers={"Authorization": self.config.api_key},
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            log.error("get_report failed for hash=%s: %s", scan_hash, exc)
            return {}
        except ValueError as exc:
            log.error("get_report: non-JSON response for hash=%s: %s", scan_hash, exc)
            return {}

    # ── Finding parsers ───────────────────────────────────────────────────────

    def get_static_findings(self, scan_hash: str) -> List[UnifiedFinding]:
        """
        Extract static-analysis findings from a completed MobSF scan.

        Parses the following report sections:
        - Permissions (dangerous → HIGH)
        - Manifest analysis (security misconfigurations)
        - Code analysis (insecure API calls, crypto, logging)
        - Binary analysis (stripped symbols, NX, RELRO)
        - File analysis (world-readable files, path traversal)

        Parameters
        ----------
        scan_hash:
            MobSF scan identifier.

        Returns
        -------
        Combined list of UnifiedFinding objects.
        """
        report = self.get_report(scan_hash)
        if not report:
            return []

        findings: List[UnifiedFinding] = []

        package = report.get("package_name", "") or report.get("app_name", "")

        # ── Permissions ───────────────────────────────────────────────────────
        perms = report.get("permissions", {})
        if isinstance(perms, dict):
            findings.extend(self._parse_permissions(
                [{"name": k, **v} if isinstance(v, dict) else {"name": k, "status": str(v)}
                 for k, v in perms.items()],
                package=package,
            ))
        elif isinstance(perms, list):
            findings.extend(self._parse_permissions(perms, package=package))

        # ── Manifest ──────────────────────────────────────────────────────────
        manifest = report.get("manifest_analysis", {})
        if isinstance(manifest, dict):
            findings.extend(self._parse_manifest(manifest, package=package))
        elif isinstance(manifest, list):
            findings.extend(self._parse_manifest({"findings": manifest}, package=package))

        # ── Code analysis ─────────────────────────────────────────────────────
        code = report.get("code_analysis", {})
        if code:
            findings.extend(self._parse_code_analysis(code, package=package))

        # ── Binary analysis ───────────────────────────────────────────────────
        binary = report.get("binary_analysis", [])
        if isinstance(binary, list):
            for item in binary:
                if not isinstance(item, dict):
                    continue
                sev = item.get("severity", item.get("level", "info"))
                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability=item.get("issue", item.get("title", "Binary analysis finding")),
                    attack_type="binary_analysis",
                    tool="mobsf",
                    severity=sev,
                    evidence=item.get("description", item.get("detail", "")),
                    remediation=item.get("recommendation", ""),
                    confidence=0.85,
                    cvss=_sev_to_cvss(sev),
                    tags=["mobsf", "binary", "static"],
                ))

        # ── File analysis ─────────────────────────────────────────────────────
        file_analysis = report.get("file_analysis", [])
        if isinstance(file_analysis, list):
            for item in file_analysis:
                if not isinstance(item, dict):
                    continue
                sev = item.get("severity", "low")
                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability=item.get("issue", item.get("title", "File analysis finding")),
                    attack_type="file_analysis",
                    tool="mobsf",
                    severity=sev,
                    file_path=item.get("file", ""),
                    evidence=item.get("description", ""),
                    remediation=item.get("recommendation", ""),
                    confidence=0.75,
                    cvss=_sev_to_cvss(sev),
                    tags=["mobsf", "file", "static"],
                ))

        log.info(
            "get_static_findings: extracted %d findings for hash=%s",
            len(findings), scan_hash,
        )
        return findings

    def get_dynamic_findings(self, scan_hash: str) -> List[UnifiedFinding]:
        """
        Extract dynamic-analysis findings from a completed MobSF scan.

        Parses: network_security, api_monitor, and exported_activities sections.

        Parameters
        ----------
        scan_hash:
            MobSF scan identifier.

        Returns
        -------
        List of UnifiedFinding objects from dynamic analysis.
        """
        report = self.get_report(scan_hash)
        if not report:
            return []

        findings: List[UnifiedFinding] = []
        package = report.get("package_name", "") or report.get("app_name", "")

        # ── Network security (cleartext, certificate errors) ──────────────────
        net_sec = report.get("network_security", {})
        if isinstance(net_sec, dict):
            for issue_name, detail in net_sec.items():
                if not detail:
                    continue
                desc = detail if isinstance(detail, str) else json.dumps(detail)
                sev = "medium" if "cleartext" in issue_name.lower() else "info"
                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability=f"Network Security: {issue_name.replace('_', ' ').title()}",
                    attack_type="network_security",
                    tool="mobsf",
                    severity=sev,
                    evidence=desc[:500],
                    remediation=(
                        "Enforce HTTPS with certificate pinning and a strict "
                        "network_security_config.xml."
                    ),
                    confidence=0.80,
                    cvss=_sev_to_cvss(sev),
                    tags=["mobsf", "dynamic", "network"],
                ))

        # ── API monitor (runtime calls) ───────────────────────────────────────
        api_monitor = report.get("appsec", {}).get("api_monitor", [])
        if not api_monitor:
            api_monitor = report.get("api_monitor", [])
        for call in api_monitor[:50]:   # cap to avoid flooding
            if not isinstance(call, dict):
                continue
            sev = call.get("severity", "info")
            findings.append(UnifiedFinding(
                target=package,
                vulnerability=f"Runtime API Call: {call.get('api', call.get('class', 'unknown'))}",
                attack_type="api_monitor",
                tool="mobsf",
                severity=sev,
                evidence=json.dumps(call)[:500],
                confidence=0.70,
                cvss=_sev_to_cvss(sev),
                tags=["mobsf", "dynamic", "api_monitor"],
            ))

        # ── Exported activities accessed during dynamic test ──────────────────
        exported = report.get("exported_activities", [])
        if isinstance(exported, list):
            for activity in exported:
                activity_str = activity if isinstance(activity, str) else json.dumps(activity)
                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability="Exported Activity Accessible Without Permission",
                    attack_type="exported_component",
                    tool="mobsf",
                    severity="medium",
                    evidence=activity_str[:300],
                    remediation=(
                        "Add android:exported=\"false\" or protect with a custom permission."
                    ),
                    confidence=0.80,
                    cvss=5.3,
                    tags=["mobsf", "dynamic", "exported_activity"],
                ))

        log.info(
            "get_dynamic_findings: extracted %d findings for hash=%s",
            len(findings), scan_hash,
        )
        return findings

    # ── Section parsers ───────────────────────────────────────────────────────

    def _parse_permissions(
        self,
        perms: list,
        package: str = "",
    ) -> List[UnifiedFinding]:
        """
        Parse MobSF permission entries.

        Dangerous permissions produce HIGH-severity findings.
        Normal/signature permissions produce INFO-level entries.

        Parameters
        ----------
        perms:
            List of dicts, each with at minimum a ``name`` key and optionally
            a ``status`` / ``description`` / ``reason`` key.
        package:
            Package name for the ``target`` field.
        """
        findings: List[UnifiedFinding] = []

        for perm in perms:
            if not isinstance(perm, dict):
                continue

            perm_name = (
                perm.get("name")
                or perm.get("permission")
                or perm.get("Permission")
                or ""
            )
            if not perm_name:
                continue

            status = str(
                perm.get("status")
                or perm.get("type")
                or perm.get("protection_level")
                or "unknown"
            ).lower()

            sev = _PERM_SEVERITY.get(status, "info")

            description = (
                perm.get("description")
                or perm.get("reason")
                or f"Permission {perm_name} declared with status '{status}'."
            )

            remediation = _DANGEROUS_PERM_REMEDIATION.get(
                perm_name, _GENERIC_DANGEROUS_PERM_REMEDIATION
            )

            if sev in ("high", "critical"):
                confidence = 0.90
                cvss = 7.5
            else:
                confidence = 0.70
                cvss = 0.0

            findings.append(UnifiedFinding(
                target=package,
                vulnerability=f"Dangerous Permission: {perm_name}",
                attack_type="dangerous_permission",
                tool="mobsf",
                severity=sev,
                evidence=str(description)[:500],
                remediation=remediation,
                confidence=confidence,
                cvss=cvss,
                tags=["mobsf", "permissions", "android", status],
            ))

        return findings

    def _parse_code_analysis(
        self,
        code: dict,
        package: str = "",
    ) -> List[UnifiedFinding]:
        """
        Parse MobSF code analysis findings.

        MobSF returns code analysis as either:
        * A dict keyed by finding-type → list of matches, or
        * A list of finding dicts (newer API versions).

        Each finding maps to a ``UnifiedFinding`` with file and line info.
        """
        findings: List[UnifiedFinding] = []

        # Newer MobSF: list of dicts with title/description/severity/files
        if isinstance(code, list):
            for item in code:
                if not isinstance(item, dict):
                    continue
                sev = _CODE_SEV.get(str(item.get("severity", "info")).lower(), "info")
                files = item.get("files", [])
                file_path = ""
                line_no = 0
                if files and isinstance(files, list):
                    first = files[0]
                    if isinstance(first, dict):
                        file_path = first.get("file_path", "")
                        line_no = int(first.get("match_lines", [0])[0] or 0) if first.get("match_lines") else 0
                    else:
                        file_path = str(first)

                findings.append(UnifiedFinding(
                    target=package,
                    vulnerability=item.get("title", "Code Analysis Finding"),
                    attack_type="code_analysis",
                    tool="mobsf",
                    severity=sev,
                    file_path=file_path,
                    line_number=line_no,
                    evidence=item.get("description", "")[:500],
                    remediation=item.get("recommendation", item.get("fix", ""))[:300],
                    confidence=0.85,
                    cvss=_sev_to_cvss(sev),
                    tags=["mobsf", "code_analysis", "static"],
                ))
            return findings

        # Older MobSF: dict keyed by category
        if isinstance(code, dict):
            for category, items in code.items():
                if not isinstance(items, (list, dict)):
                    continue
                item_list = items if isinstance(items, list) else [items]
                for item in item_list:
                    if not isinstance(item, dict):
                        continue
                    sev_raw = item.get("level", item.get("severity", "info"))
                    sev = _CODE_SEV.get(str(sev_raw).lower(), "info")

                    # File / line info
                    file_path = item.get("filename", item.get("file", ""))
                    line_no = 0
                    raw_lines = item.get("lines", item.get("match_lines", ""))
                    if raw_lines:
                        try:
                            first_line = str(raw_lines).split(",")[0].strip()
                            line_no = int(first_line) if first_line.isdigit() else 0
                        except (ValueError, IndexError):
                            pass

                    findings.append(UnifiedFinding(
                        target=package,
                        vulnerability=item.get("title", f"Code Issue: {category}"),
                        attack_type=f"code_analysis_{category}",
                        tool="mobsf",
                        severity=sev,
                        file_path=str(file_path),
                        line_number=line_no,
                        evidence=item.get("match", item.get("description", ""))[:500],
                        remediation=item.get("fix", item.get("recommendation", ""))[:300],
                        confidence=0.80,
                        cvss=_sev_to_cvss(sev),
                        tags=["mobsf", "code_analysis", "static", str(category)],
                    ))

        return findings

    def _parse_manifest(
        self,
        manifest: dict,
        package: str = "",
    ) -> List[UnifiedFinding]:
        """
        Parse MobSF manifest-analysis findings.

        Extracts issues such as:
        - debuggable=true
        - allowBackup=true
        - exported components without permissions
        - cleartext traffic allowed
        - custom permissions with dangerous protection level
        """
        findings: List[UnifiedFinding] = []

        # MobSF returns manifest issues under various keys depending on version
        issue_list = (
            manifest.get("manifest_findings")
            or manifest.get("findings")
            or manifest.get("issues")
            or []
        )
        if not issue_list and isinstance(manifest, dict):
            # Flatten top-level dict values that look like issue lists
            for v in manifest.values():
                if isinstance(v, list):
                    issue_list = v
                    break

        for item in issue_list:
            if not isinstance(item, dict):
                continue
            sev_raw = item.get("severity", item.get("level", "info"))
            sev = UnifiedFinding.normalise_severity(str(sev_raw))

            title = (
                item.get("title")
                or item.get("issue")
                or item.get("description", "")[:80]
                or "Manifest Security Issue"
            )
            description = item.get("description", item.get("detail", ""))

            # Enhance severity for well-known high-impact manifest issues
            title_lower = title.lower()
            if "debuggable" in title_lower:
                sev = "high"
                remediation = (
                    "Remove android:debuggable=\"true\" from production builds. "
                    "Enable only in debug build variants via BuildConfig."
                )
                cvss = 7.4
            elif "allowbackup" in title_lower or "allow backup" in title_lower:
                sev = "medium"
                remediation = (
                    "Set android:allowBackup=\"false\" to prevent device backups "
                    "exposing sensitive data."
                )
                cvss = 5.5
            elif "cleartext" in title_lower:
                sev = "high"
                remediation = (
                    "Set android:usesCleartextTraffic=\"false\" or enforce "
                    "network_security_config.xml with cleartextTrafficPermitted=\"false\"."
                )
                cvss = 7.5
            else:
                remediation = item.get("recommendation", item.get("fix", ""))
                cvss = _sev_to_cvss(sev)

            findings.append(UnifiedFinding(
                target=package,
                vulnerability=title,
                attack_type="manifest_analysis",
                tool="mobsf",
                severity=sev,
                evidence=str(description)[:500],
                remediation=remediation,
                confidence=0.90,
                cvss=cvss,
                tags=["mobsf", "manifest", "android", "static"],
            ))

        return findings

    # ── High-level scan entry point ───────────────────────────────────────────

    def scan_file(self, file_path: str) -> List[UnifiedFinding]:
        """
        Perform a full MobSF analysis on a mobile app binary.

        Workflow: upload → scan → wait for results → parse static findings.
        Dynamic findings are included if the report contains them (requires
        a previously run dynamic analysis session in MobSF).

        Parameters
        ----------
        file_path:
            Absolute path to APK, IPA, or AAB file.

        Returns
        -------
        Combined list of static + dynamic UnifiedFinding objects.
        On server unavailability, delegates to ``_cli_scan()`` and returns [].
        """
        if not self._is_server_running():
            log.warning(
                "MobSF server at %s is not running. "
                "Start it with: mobile-security-framework-mobsf --start 1",
                self.config.api_url,
            )
            return self._cli_scan(file_path)

        scan_data = self.upload_and_scan(file_path)
        scan_hash = scan_data.get("hash")
        if not scan_hash:
            log.error("scan_file: no scan hash returned from MobSF for %s", file_path)
            return []

        log.info("Waiting for MobSF scan to complete (hash=%s) …", scan_hash)
        # MobSF performs static analysis synchronously during upload+scan,
        # so the report is usually immediately available.  Give it a short
        # delay for very large apps.
        time.sleep(2)

        findings: List[UnifiedFinding] = []
        findings.extend(self.get_static_findings(scan_hash))
        findings.extend(self.get_dynamic_findings(scan_hash))

        log.info(
            "scan_file complete: %d total findings for %s",
            len(findings), file_path,
        )
        return findings

    def _cli_scan(self, file_path: str) -> List[UnifiedFinding]:
        """
        Fallback path when MobSF server is unavailable.

        In a production environment you would launch a headless MobSF container
        here.  For now this method logs a clear warning and returns an empty
        list so the pipeline degrades gracefully rather than crashing.

        Parameters
        ----------
        file_path:
            Path to the mobile app binary (for log context).
        """
        log.warning(
            "MobSF CLI mode: server unavailable at %s. "
            "To enable full analysis, start MobSF with:\n"
            "    pip install mobsf && mobsf\n"
            "or use Docker:\n"
            "    docker run -it -p 8008:8008 opensecurity/mobile-security-framework-mobsf\n"
            "Skipping MobSF analysis for: %s",
            self.config.api_url,
            file_path,
        )
        return []


# ──────────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _sev_to_cvss(severity: str) -> float:
    """Map severity label to a default CVSS base score."""
    return {
        "critical": 9.5,
        "high":     7.5,
        "medium":   5.0,
        "low":      3.0,
        "info":     0.0,
    }.get(UnifiedFinding.normalise_severity(severity), 0.0)


# ──────────────────────────────────────────────────────────────────────────────
#  Module-level singleton
# ──────────────────────────────────────────────────────────────────────────────

#: Drop-in singleton — import as:
#:     ``from mobsf_wrapper import mobsf_wrapper``
mobsf_wrapper: MobSFWrapper = MobSFWrapper()
