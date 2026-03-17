"""
Android Component Security Testing
=====================================
Tests Android application components for security vulnerabilities.
Uses Drozer for automated component exploitation testing.
Covers: Activities, Services, Broadcast Receivers, Content Providers.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

try:
    from drozer_wrapper import drozer_wrapper
except ImportError:
    drozer_wrapper = None  # type: ignore

from mobile_tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.android_component_testing")

# Android XML namespace
_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_ANS = f"{{{_ANDROID_NS}}}"

# Dangerous permissions that indicate the component is sensitive
_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_SMS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
}

# Implicit intents with sensitive patterns
_SENSITIVE_ACTIONS = {
    "android.intent.action.VIEW",
    "android.intent.action.SEND",
    "android.intent.action.SENDTO",
    "android.intent.action.CALL",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ComponentTestConfig:
    use_drozer: bool = True
    static_fallback: bool = True
    device_id: str = ""
    timeout: int = 60


@dataclass
class ComponentTestResult:
    package_name: str
    activities_tested: List[str] = field(default_factory=list)
    services_tested: List[str] = field(default_factory=list)
    receivers_tested: List[str] = field(default_factory=list)
    providers_tested: List[str] = field(default_factory=list)
    ipc_tests: List[Dict] = field(default_factory=list)
    findings: List[UnifiedFinding] = field(default_factory=list)
    drozer_available: bool = False
    static_only: bool = True

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "activities_tested": self.activities_tested,
            "services_tested": self.services_tested,
            "receivers_tested": self.receivers_tested,
            "providers_tested": self.providers_tested,
            "ipc_tests": self.ipc_tests,
            "findings": [f.to_dict() for f in self.findings],
            "drozer_available": self.drozer_available,
            "static_only": self.static_only,
        }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class AndroidComponentTester:
    """
    Tests Android app components (Activities, Services, Receivers, Providers)
    for security vulnerabilities using Drozer (dynamic) and static manifest analysis.
    """

    def __init__(self, config: ComponentTestConfig = None) -> None:
        self.config = config or ComponentTestConfig()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def test_app(
        self,
        package_name: str,
        extracted_dir: str = "",
        device_id: str = "",
    ) -> ComponentTestResult:
        """
        Run component security testing.
        Attempts Drozer dynamic testing first; falls back to static manifest analysis.
        """
        result = ComponentTestResult(package_name=package_name)
        effective_device = device_id or self.config.device_id

        # Phase 1: static analysis (always run — provides component inventory)
        manifest_path = self._find_manifest(extracted_dir)
        components = {}
        if manifest_path:
            components = self.parse_manifest_components(manifest_path)
            result.activities_tested = components.get("activities", [])
            result.services_tested = components.get("services", [])
            result.receivers_tested = components.get("receivers", [])
            result.providers_tested = components.get("providers", [])

            static_findings = self._static_component_analysis(package_name, extracted_dir)
            result.findings.extend(static_findings)

        # Phase 2: IPC vulnerability checks
        if extracted_dir:
            ipc_findings = self._check_ipc_vulnerabilities(package_name, extracted_dir)
            result.findings.extend(ipc_findings)

        # Phase 3: drozer dynamic testing
        if self.config.use_drozer and drozer_wrapper is not None and effective_device:
            try:
                drozer_avail = drozer_wrapper.is_available() if hasattr(drozer_wrapper, "is_available") else True
                if drozer_avail:
                    result.drozer_available = True
                    result.static_only = False
                    drozer_findings = self._drozer_dynamic_testing(package_name, effective_device)
                    result.findings.extend(drozer_findings)
            except Exception as exc:
                logger.warning("Drozer dynamic testing failed: %s — using static results only", exc)

        # Phase 4: targeted activity/provider tests (static-based)
        if components:
            activities = components.get("activities", [])
            services = components.get("services", [])
            receivers = components.get("receivers", [])
            providers = components.get("providers", [])

            result.findings.extend(self._test_activity_hijacking(package_name, activities))
            result.findings.extend(self._test_intent_redirection(package_name, activities))
            result.findings.extend(self._test_content_provider_sqli(package_name, providers))
            result.findings.extend(self._test_broadcast_sniffing(package_name, receivers))

        # Deduplicate
        result.findings = self._dedup_findings(result.findings)

        logger.info(
            "Component testing for %s: %d findings (%s)",
            package_name,
            len(result.findings),
            "dynamic+static" if result.drozer_available else "static only",
        )
        return result

    # ------------------------------------------------------------------
    # Static manifest analysis
    # ------------------------------------------------------------------

    def _static_component_analysis(
        self, package_name: str, extracted_dir: str
    ) -> List[UnifiedFinding]:
        """Parse AndroidManifest.xml and flag insecure component configurations."""
        findings: List[UnifiedFinding] = []
        manifest_path = self._find_manifest(extracted_dir)
        if not manifest_path:
            return findings

        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except ET.ParseError as exc:
            logger.debug("ET.ParseError on %s: %s — trying aapt fallback", manifest_path, exc)
            return self._static_analysis_aapt_fallback(package_name, manifest_path)

        # ── Application-level flags ────────────────────────────────
        app_el = root.find("application")
        if app_el is not None:
            # android:debuggable
            if app_el.get(f"{_ANS}debuggable", "false").lower() == "true":
                findings.append(UnifiedFinding(
                    title="Application Debuggable Flag Enabled",
                    severity="high",
                    finding_type="debug_enabled",
                    tool="android_component_tester",
                    package=package_name,
                    description=(
                        "The android:debuggable=true flag is set in AndroidManifest.xml. "
                        "Attackers can attach a debugger, extract memory, and bypass security controls."
                    ),
                    evidence='android:debuggable="true" in <application>',
                    recommendation="Remove android:debuggable or set it to false for release builds. Use BuildConfig.DEBUG conditionally in code.",
                    cwe="CWE-489",
                    cvss_score=7.1,
                    location=manifest_path,
                ))

            # android:allowBackup
            if app_el.get(f"{_ANS}allowBackup", "true").lower() == "true":
                findings.append(UnifiedFinding(
                    title="Application Backup Allowed (allowBackup=true)",
                    severity="medium",
                    finding_type="backup_allowed",
                    tool="android_component_tester",
                    package=package_name,
                    description=(
                        "android:allowBackup=true allows ADB backup of the application's data directory. "
                        "Sensitive data including credentials and tokens may be extracted via `adb backup`."
                    ),
                    evidence='android:allowBackup="true" (default) in <application>',
                    recommendation='Set android:allowBackup="false" or define a backup rule that excludes sensitive files.',
                    cwe="CWE-530",
                    cvss_score=4.3,
                    location=manifest_path,
                ))

            # android:usesCleartextTraffic
            if app_el.get(f"{_ANS}usesCleartextTraffic", "false").lower() == "true":
                findings.append(UnifiedFinding(
                    title="Cleartext Traffic Permitted (usesCleartextTraffic=true)",
                    severity="high",
                    finding_type="cleartext_traffic",
                    tool="android_component_tester",
                    package=package_name,
                    description=(
                        "The application permits cleartext HTTP traffic. "
                        "Data transmitted over HTTP is susceptible to MITM interception."
                    ),
                    evidence='android:usesCleartextTraffic="true" in <application>',
                    recommendation='Set android:usesCleartextTraffic="false" and configure network-security-config.xml.',
                    cwe="CWE-319",
                    cvss_score=6.5,
                    location=manifest_path,
                ))

        # ── Per-component checks ───────────────────────────────────
        component_defs = {
            "activity": ("Activity", "activity_exposed", "high", "CWE-926"),
            "service": ("Service", "service_exposed", "high", "CWE-926"),
            "receiver": ("BroadcastReceiver", "receiver_exposed", "medium", "CWE-926"),
            "provider": ("ContentProvider", "provider_exposed", "critical", "CWE-926"),
        }

        for tag, (label, finding_type, severity, cwe) in component_defs.items():
            for comp_el in root.iter(tag):
                comp_name = comp_el.get(f"{_ANS}name", "")
                exported_raw = comp_el.get(f"{_ANS}exported", None)
                permission = comp_el.get(f"{_ANS}permission", "")

                # Determine exported status
                if exported_raw is not None:
                    exported = exported_raw.lower() == "true"
                else:
                    # Implicitly exported if intent-filter present
                    exported = len(list(comp_el.iter("intent-filter"))) > 0

                if not exported:
                    continue

                has_intent_filter = len(list(comp_el.iter("intent-filter"))) > 0

                # Provider always critical if exported
                if tag == "provider":
                    effective_severity = "critical" if not permission else "medium"
                    findings.append(UnifiedFinding(
                        title=f"Exported ContentProvider: {comp_name}",
                        severity=effective_severity,
                        finding_type=finding_type,
                        tool="android_component_tester",
                        package=package_name,
                        description=(
                            f"ContentProvider '{comp_name}' is exported "
                            f"{'without a permission requirement' if not permission else f'with permission: {permission}'}. "
                            "Exported providers may leak data or be vulnerable to SQL injection via content URIs."
                        ),
                        evidence=f"android:exported=true, permission={permission or 'none'}, component={comp_name}",
                        recommendation=(
                            "Set android:exported=false if external access is not required. "
                            "If export is required, add android:permission and sanitize all query parameters."
                        ),
                        cwe=cwe,
                        cvss_score=9.0 if not permission else 5.5,
                        location=f"{manifest_path} ({comp_name})",
                    ))

                    # Check readPermission / writePermission separately
                    read_perm = comp_el.get(f"{_ANS}readPermission", "")
                    write_perm = comp_el.get(f"{_ANS}writePermission", "")
                    if not read_perm and not write_perm and not permission:
                        findings.append(UnifiedFinding(
                            title=f"ContentProvider Without Read/Write Permissions: {comp_name}",
                            severity="critical",
                            finding_type="provider_no_permissions",
                            tool="android_component_tester",
                            package=package_name,
                            description=(
                                f"Exported ContentProvider '{comp_name}' has no readPermission or writePermission. "
                                "Any app can read from or write to this provider."
                            ),
                            evidence=f"Component: {comp_name}",
                            recommendation="Add android:readPermission and android:writePermission with appropriate protection level.",
                            cwe="CWE-284",
                            cvss_score=9.5,
                            location=f"{manifest_path} ({comp_name})",
                        ))

                elif tag == "activity":
                    if not permission:
                        findings.append(UnifiedFinding(
                            title=f"Exported Activity Without Permission: {comp_name}",
                            severity="high",
                            finding_type=finding_type,
                            tool="android_component_tester",
                            package=package_name,
                            description=(
                                f"Activity '{comp_name}' is exported without requiring any permission. "
                                "Any external app can launch this activity, potentially bypassing authentication."
                            ),
                            evidence=f"android:exported=true, no android:permission, component={comp_name}",
                            recommendation="Add android:permission, or set android:exported=false if not needed externally.",
                            cwe=cwe,
                            cvss_score=7.5,
                            location=f"{manifest_path} ({comp_name})",
                        ))

                    # Deep link risk
                    for intent_filter in comp_el.iter("intent-filter"):
                        for data_el in intent_filter.iter("data"):
                            scheme = data_el.get(f"{_ANS}scheme", "")
                            if scheme and scheme not in ("http", "https", "content"):
                                findings.append(UnifiedFinding(
                                    title=f"Activity Accepts Deep Link Without Validation: {comp_name}",
                                    severity="medium",
                                    finding_type="deep_link_risk",
                                    tool="android_component_tester",
                                    package=package_name,
                                    description=(
                                        f"Activity '{comp_name}' handles deep links with scheme '{scheme}'. "
                                        "Unvalidated deep link parameters may lead to open redirects or intent injection."
                                    ),
                                    evidence=f"scheme={scheme}, component={comp_name}",
                                    recommendation="Validate and sanitize all URI parameters received from deep links.",
                                    cwe="CWE-601",
                                    cvss_score=5.3,
                                    location=f"{manifest_path} ({comp_name})",
                                ))

                elif tag == "service":
                    if not permission:
                        findings.append(UnifiedFinding(
                            title=f"Exported Service Without Permission: {comp_name}",
                            severity="high",
                            finding_type=finding_type,
                            tool="android_component_tester",
                            package=package_name,
                            description=(
                                f"Service '{comp_name}' is exported without requiring any permission. "
                                "External apps can bind to or start this service, potentially triggering sensitive operations."
                            ),
                            evidence=f"android:exported=true, no android:permission, component={comp_name}",
                            recommendation="Add android:permission or set android:exported=false.",
                            cwe=cwe,
                            cvss_score=7.0,
                            location=f"{manifest_path} ({comp_name})",
                        ))

                elif tag == "receiver":
                    if has_intent_filter:
                        effective_sev = "medium"
                        findings.append(UnifiedFinding(
                            title=f"Exported BroadcastReceiver: {comp_name}",
                            severity=effective_sev,
                            finding_type=finding_type,
                            tool="android_component_tester",
                            package=package_name,
                            description=(
                                f"BroadcastReceiver '{comp_name}' is exported. "
                                "External apps can send broadcasts to this receiver, "
                                "potentially triggering unintended behaviour."
                            ),
                            evidence=f"android:exported=true, component={comp_name}",
                            recommendation=(
                                "Add android:permission to restrict who can send broadcasts. "
                                "Use LocalBroadcastManager for internal broadcasts."
                            ),
                            cwe=cwe,
                            cvss_score=4.3,
                            location=f"{manifest_path} ({comp_name})",
                        ))

        # ── Implicit intents with sensitive data ───────────────────
        for activity_el in root.iter("activity"):
            comp_name = activity_el.get(f"{_ANS}name", "")
            for intent_filter in activity_el.iter("intent-filter"):
                for action in intent_filter.iter("action"):
                    action_name = action.get(f"{_ANS}name", "")
                    if action_name in _SENSITIVE_ACTIONS:
                        findings.append(UnifiedFinding(
                            title=f"Activity Handles Sensitive Implicit Intent: {comp_name}",
                            severity="medium",
                            finding_type="intent_redirection",
                            tool="android_component_tester",
                            package=package_name,
                            description=(
                                f"Activity '{comp_name}' registers for implicit intent '{action_name}'. "
                                "Malicious apps can intercept such intents if multiple apps handle them (intent hijacking)."
                            ),
                            evidence=f"action={action_name}, component={comp_name}",
                            recommendation="Use explicit intents where possible; verify intent sender identity for sensitive actions.",
                            cwe="CWE-927",
                            cvss_score=4.0,
                            location=f"{manifest_path} ({comp_name})",
                        ))

        return findings

    # ------------------------------------------------------------------
    # Static analysis fallback using aapt
    # ------------------------------------------------------------------

    def _static_analysis_aapt_fallback(
        self, package_name: str, manifest_path: str
    ) -> List[UnifiedFinding]:
        """Fallback static analysis using aapt dump when XML parsing fails (binary XML)."""
        findings: List[UnifiedFinding] = []
        aapt = self._find_aapt()
        if not aapt:
            return findings

        try:
            result = subprocess.run(
                [aapt, "dump", "xmltree", manifest_path],
                capture_output=True, text=True, timeout=30,
            )
            text = result.stdout

            # Check debuggable
            if 'android:debuggable' in text and '0xffffffff' in text:
                findings.append(UnifiedFinding(
                    title="Application Debuggable Flag Enabled (aapt)",
                    severity="high",
                    finding_type="debug_enabled",
                    tool="android_component_tester",
                    package=package_name,
                    description="android:debuggable=true detected via aapt dump.",
                    recommendation="Remove android:debuggable for release builds.",
                    cwe="CWE-489",
                    cvss_score=7.1,
                    location=manifest_path,
                ))

            # Exported components
            exported_comp_re = re.compile(
                r'E:\s+(activity|service|receiver|provider).*?\n(?:.*?\n)*?.*?android:exported.*?0xffffffff',
                re.MULTILINE,
            )
            for m in exported_comp_re.finditer(text):
                comp_type = m.group(1)
                severity = "critical" if comp_type == "provider" else "high" if comp_type in ("activity", "service") else "medium"
                findings.append(UnifiedFinding(
                    title=f"Exported {comp_type.capitalize()} Detected (aapt fallback)",
                    severity=severity,
                    finding_type=f"{comp_type}_exposed",
                    tool="android_component_tester",
                    package=package_name,
                    description=f"Exported {comp_type} detected via aapt manifest dump. Verify permissions.",
                    recommendation="Review exported flag and add appropriate permission requirement.",
                    cwe="CWE-926",
                    location=manifest_path,
                ))
        except Exception as exc:
            logger.debug("aapt fallback failed: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Drozer dynamic testing
    # ------------------------------------------------------------------

    def _drozer_dynamic_testing(
        self, package_name: str, device_id: str
    ) -> List[UnifiedFinding]:
        """Run Drozer full audit and convert results to UnifiedFinding objects."""
        findings: List[UnifiedFinding] = []
        dw = drozer_wrapper

        try:
            raw_results = dw.full_audit(package_name=package_name, device_id=device_id)
            if isinstance(raw_results, list):
                for item in raw_results:
                    if isinstance(item, UnifiedFinding):
                        findings.append(item)
                    elif isinstance(item, dict):
                        findings.append(UnifiedFinding.from_dict(item))
            elif hasattr(raw_results, "findings"):
                for f in raw_results.findings:
                    if isinstance(f, UnifiedFinding):
                        findings.append(f)
            logger.info("Drozer found %d findings for %s", len(findings), package_name)
        except AttributeError:
            logger.debug("drozer_wrapper.full_audit not available")
        except Exception as exc:
            logger.warning("Drozer full_audit error: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Activity hijacking test
    # ------------------------------------------------------------------

    def _test_activity_hijacking(
        self, package_name: str, activities: List[str]
    ) -> List[UnifiedFinding]:
        """
        Check exported activities for missing authentication checks — potential activity hijacking.
        This is a static heuristic based on activity name patterns.
        """
        findings: List[UnifiedFinding] = []
        sensitive_patterns = re.compile(
            r"(main|home|dashboard|payment|checkout|transfer|profile|settings|admin|login|auth)",
            re.I,
        )

        for activity in activities:
            if sensitive_patterns.search(activity):
                findings.append(UnifiedFinding(
                    title=f"Potential Activity Hijacking Risk: {activity.split('.')[-1]}",
                    severity="medium",
                    finding_type="activity_hijacking",
                    tool="android_component_tester",
                    package=package_name,
                    description=(
                        f"Activity '{activity}' has a sensitive name pattern and may be exported. "
                        "If launchable by external apps without authentication, it could be hijacked."
                    ),
                    evidence=f"Activity: {activity}",
                    recommendation=(
                        "Verify android:exported=false for sensitive activities. "
                        "Add authentication state checks in onCreate/onResume."
                    ),
                    cwe="CWE-926",
                    cvss_score=6.3,
                    location=activity,
                ))

        return findings

    # ------------------------------------------------------------------
    # ContentProvider SQL injection test
    # ------------------------------------------------------------------

    def _test_content_provider_sqli(
        self, package_name: str, providers: List[str]
    ) -> List[UnifiedFinding]:
        """Flag exported ContentProviders as potential SQL injection targets."""
        findings: List[UnifiedFinding] = []

        for provider in providers:
            findings.append(UnifiedFinding(
                title=f"ContentProvider SQL Injection Test Required: {provider.split('.')[-1]}",
                severity="high",
                finding_type="content_provider_sqli",
                tool="android_component_tester",
                package=package_name,
                description=(
                    f"ContentProvider '{provider}' is exported and its query() method may be vulnerable "
                    "to SQL injection via crafted content URI selection arguments."
                ),
                evidence=f"Provider: {provider}",
                recommendation=(
                    "Use parameterized queries (SQLiteQueryBuilder with strict mode). "
                    "Validate and sanitize all selection and selectionArgs parameters. "
                    "Test with: adb shell content query --uri content://<authority>/... "
                    "--where \"1=1 OR 1=1\"."
                ),
                cwe="CWE-89",
                cvss_score=7.8,
                location=provider,
            ))

        return findings

    # ------------------------------------------------------------------
    # Intent redirection test
    # ------------------------------------------------------------------

    def _test_intent_redirection(
        self, package_name: str, activities: List[str]
    ) -> List[UnifiedFinding]:
        """
        Identify activities that may accept ACTION_VIEW or custom scheme intents without validation.
        """
        findings: List[UnifiedFinding] = []
        view_patterns = re.compile(
            r"(webview|browser|deeplink|redirect|link|open|viewer|display)", re.I
        )

        for activity in activities:
            if view_patterns.search(activity):
                findings.append(UnifiedFinding(
                    title=f"Potential Intent Redirection: {activity.split('.')[-1]}",
                    severity="medium",
                    finding_type="intent_redirection",
                    tool="android_component_tester",
                    package=package_name,
                    description=(
                        f"Activity '{activity}' likely handles URL/deep link intents. "
                        "If ACTION_VIEW or custom-scheme intents are accepted without URL validation, "
                        "an attacker can redirect the app to malicious content or internal endpoints."
                    ),
                    evidence=f"Activity name pattern match: {activity}",
                    recommendation=(
                        "Validate all URLs received via Intent.getData(). "
                        "Maintain an allowlist of trusted hosts/schemes. "
                        "Use parseUri() with Intent.URI_INTENT_SCHEME flag carefully."
                    ),
                    cwe="CWE-601",
                    cvss_score=5.4,
                    location=activity,
                ))

        return findings

    # ------------------------------------------------------------------
    # Broadcast receiver sniffing test
    # ------------------------------------------------------------------

    def _test_broadcast_sniffing(
        self, package_name: str, receivers: List[str]
    ) -> List[UnifiedFinding]:
        """Flag exported receivers that may receive sensitive broadcast data."""
        findings: List[UnifiedFinding] = []
        sensitive_re = re.compile(
            r"(sms|call|payment|auth|token|secret|credential|password|pin)", re.I
        )

        for receiver in receivers:
            if sensitive_re.search(receiver):
                findings.append(UnifiedFinding(
                    title=f"Sensitive BroadcastReceiver Exposed: {receiver.split('.')[-1]}",
                    severity="medium",
                    finding_type="broadcast_sniffing",
                    tool="android_component_tester",
                    package=package_name,
                    description=(
                        f"BroadcastReceiver '{receiver}' handles potentially sensitive broadcast events. "
                        "If exported without permission, malicious apps can send forged broadcasts or "
                        "eavesdrop on sensitive data passed in Intent extras."
                    ),
                    evidence=f"Receiver: {receiver}",
                    recommendation=(
                        "Use LocalBroadcastManager for internal broadcasts. "
                        "Add android:permission to restrict external senders. "
                        "Validate and sanitize all Intent extras in onReceive()."
                    ),
                    cwe="CWE-925",
                    cvss_score=4.5,
                    location=receiver,
                ))

        return findings

    # ------------------------------------------------------------------
    # IPC vulnerability checks
    # ------------------------------------------------------------------

    def _check_ipc_vulnerabilities(
        self, package_name: str, extracted_dir: str
    ) -> List[UnifiedFinding]:
        """
        Check AIDL interfaces, Messenger services, and Binder without permission checks.
        """
        findings: List[UnifiedFinding] = []
        if not extracted_dir or not os.path.isdir(extracted_dir):
            return findings

        root_path = Path(extracted_dir)

        # ── AIDL interfaces ───────────────────────────────────────
        aidl_files = list(root_path.rglob("*.aidl")) + list(root_path.rglob("I*.java"))
        for fpath in aidl_files:
            try:
                text = fpath.read_text(errors="replace", encoding="utf-8")
            except Exception:
                continue

            # Look for AIDL interface definitions without enforceCallingPermission
            if "interface I" in text or ".aidl" in str(fpath):
                if "enforceCallingPermission" not in text and "checkCallingPermission" not in text:
                    rel = str(fpath.relative_to(root_path)) if root_path in fpath.parents else str(fpath)
                    findings.append(UnifiedFinding(
                        title=f"AIDL Interface Without Permission Check: {fpath.name}",
                        severity="high",
                        finding_type="aidl_no_permission",
                        tool="android_component_tester",
                        package=package_name,
                        description=(
                            f"AIDL interface '{fpath.name}' does not call enforceCallingPermission() "
                            "or checkCallingPermission(). Any app with a reference to this Binder can "
                            "invoke privileged IPC operations."
                        ),
                        evidence=f"File: {rel}",
                        recommendation=(
                            "Call context.enforceCallingPermission() at the start of each service method. "
                            "Use checkCallingOrSelfPermission() for internal/external callers."
                        ),
                        cwe="CWE-284",
                        cvss_score=7.2,
                        location=rel,
                    ))

        # ── Messenger IPC ─────────────────────────────────────────
        _messenger_pat = re.compile(r'new Messenger\s*\(', re.I)
        for fpath in root_path.rglob("*.java"):
            try:
                text = fpath.read_text(errors="replace", encoding="utf-8")
            except Exception:
                continue
            if _messenger_pat.search(text) and "checkCallingPermission" not in text:
                rel = str(fpath.relative_to(root_path)) if root_path in fpath.parents else str(fpath)
                findings.append(UnifiedFinding(
                    title=f"Messenger IPC Without Permission Check: {fpath.name}",
                    severity="medium",
                    finding_type="messenger_no_permission",
                    tool="android_component_tester",
                    package=package_name,
                    description=(
                        f"Messenger-based IPC in '{fpath.name}' does not verify caller identity. "
                        "Any app can send Messages to this Handler."
                    ),
                    evidence=f"File: {rel} — new Messenger() without permission check",
                    recommendation="Validate the sender's UID in handleMessage() using Binder.getCallingUid().",
                    cwe="CWE-284",
                    cvss_score=4.8,
                    location=rel,
                ))
                break  # one finding per file

        # ── Kotlin files ──────────────────────────────────────────
        for fpath in root_path.rglob("*.kt"):
            try:
                text = fpath.read_text(errors="replace", encoding="utf-8")
            except Exception:
                continue
            if "Messenger(" in text and "checkCallingPermission" not in text:
                rel = str(fpath.relative_to(root_path)) if root_path in fpath.parents else str(fpath)
                findings.append(UnifiedFinding(
                    title=f"Messenger IPC Without Permission Check: {fpath.name}",
                    severity="medium",
                    finding_type="messenger_no_permission",
                    tool="android_component_tester",
                    package=package_name,
                    description=f"Messenger IPC in '{fpath.name}' without caller permission verification.",
                    evidence=f"File: {rel}",
                    recommendation="Validate caller UID in handleMessage() via Binder.getCallingUid().",
                    cwe="CWE-284",
                    cvss_score=4.8,
                    location=rel,
                ))

        # ── Binder onTransact without checkPermission ─────────────
        _binder_pat = re.compile(r'onTransact\s*\(', re.I)
        for fpath in list(root_path.rglob("*.java")) + list(root_path.rglob("*.kt")):
            try:
                text = fpath.read_text(errors="replace", encoding="utf-8")
            except Exception:
                continue
            if _binder_pat.search(text) and "checkCallingPermission" not in text and "enforceCallingPermission" not in text:
                rel = str(fpath.relative_to(root_path)) if root_path in fpath.parents else str(fpath)
                findings.append(UnifiedFinding(
                    title=f"Binder onTransact Without Permission Enforcement: {fpath.name}",
                    severity="high",
                    finding_type="binder_no_permission",
                    tool="android_component_tester",
                    package=package_name,
                    description=(
                        f"Custom Binder in '{fpath.name}' overrides onTransact() without permission checks. "
                        "Clients can invoke arbitrary transactions."
                    ),
                    evidence=f"File: {rel}",
                    recommendation="Call enforceCallingPermission() at the top of onTransact() for privileged transactions.",
                    cwe="CWE-284",
                    cvss_score=7.0,
                    location=rel,
                ))

        return self._dedup_findings(findings)

    # ------------------------------------------------------------------
    # Manifest component parser
    # ------------------------------------------------------------------

    def parse_manifest_components(self, manifest_path: str) -> Dict:
        """
        Parse AndroidManifest.xml and return a dict:
        {activities: [], services: [], receivers: [], providers: [], permissions: []}
        """
        result: Dict = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "permissions": [],
        }

        # Try standard ET parse
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except ET.ParseError:
            # Binary XML — try aapt
            return self._parse_manifest_aapt(manifest_path)

        package = root.get("package", "")

        def _resolve_name(name: str) -> str:
            """Resolve relative component names to full class names."""
            if name.startswith("."):
                return package + name
            if "." not in name:
                return f"{package}.{name}"
            return name

        for activity in root.iter("activity"):
            name = activity.get(f"{_ANS}name", "")
            if name:
                result["activities"].append(_resolve_name(name))

        for service in root.iter("service"):
            name = service.get(f"{_ANS}name", "")
            if name:
                result["services"].append(_resolve_name(name))

        for receiver in root.iter("receiver"):
            name = receiver.get(f"{_ANS}name", "")
            if name:
                result["receivers"].append(_resolve_name(name))

        for provider in root.iter("provider"):
            name = provider.get(f"{_ANS}name", "")
            if name:
                result["providers"].append(_resolve_name(name))

        for uses_perm in root.iter("uses-permission"):
            perm = uses_perm.get(f"{_ANS}name", "")
            if perm:
                result["permissions"].append(perm)

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_manifest(self, extracted_dir: str) -> Optional[str]:
        """Locate AndroidManifest.xml inside extracted_dir."""
        if not extracted_dir or not os.path.isdir(extracted_dir):
            return None

        for root_dir, _, files in os.walk(extracted_dir):
            if "AndroidManifest.xml" in files:
                return os.path.join(root_dir, "AndroidManifest.xml")
        return None

    def _find_aapt(self) -> Optional[str]:
        """Locate aapt or aapt2 binary."""
        for name in ("aapt", "aapt2"):
            path = subprocess.run(
                ["which", name], capture_output=True, text=True
            ).stdout.strip()
            if path:
                return path
        return None

    def _parse_manifest_aapt(self, manifest_path: str) -> Dict:
        """Use aapt dump to extract component names when binary XML is present."""
        result: Dict = {
            "activities": [], "services": [], "receivers": [],
            "providers": [], "permissions": [],
        }
        aapt = self._find_aapt()
        if not aapt:
            return result

        try:
            proc = subprocess.run(
                [aapt, "dump", "xmltree", manifest_path],
                capture_output=True, text=True, timeout=30,
            )
            text = proc.stdout

            # Extract component names from aapt xmltree output
            _name_re = re.compile(r'A:\s+android:name\(0x[0-9a-f]+\)="([^"]+)"')
            _section_re = re.compile(r'E:\s+(activity|service|receiver|provider|uses-permission)\b')

            current_section = None
            for line in text.splitlines():
                sec_m = _section_re.search(line)
                if sec_m:
                    current_section = sec_m.group(1)

                name_m = _name_re.search(line)
                if name_m and current_section:
                    name = name_m.group(1)
                    if current_section == "activity":
                        result["activities"].append(name)
                    elif current_section == "service":
                        result["services"].append(name)
                    elif current_section == "receiver":
                        result["receivers"].append(name)
                    elif current_section == "provider":
                        result["providers"].append(name)
                    elif current_section == "uses-permission":
                        result["permissions"].append(name)
                    current_section = None  # reset after consuming name

        except Exception as exc:
            logger.debug("aapt manifest parse failed: %s", exc)

        return result

    def _dedup_findings(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        seen: set = set()
        out: List[UnifiedFinding] = []
        for f in findings:
            key = (f.finding_type, f.title, f.location)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out


# Module-level singleton
android_component_tester = AndroidComponentTester()
