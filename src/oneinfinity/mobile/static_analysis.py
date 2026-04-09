"""
Mobile Static Analysis Engine
==============================
Comprehensive static analysis using APKTool, JADX, and MobSF.
Orchestrates decompilation and source-level vulnerability detection,
permission analysis, component security, and network config review.

Usage::

    from oneinfinity.mobile_static_analysis import mobile_static_analyzer

    result = mobile_static_analyzer.analyze(
        app_id="com.example.app",
        file_path="/path/to/app.apk",
        extracted_dir="/path/to/extraction/dir",
    )
    for finding in result.all_findings:
        print(finding.severity, finding.vulnerability)
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.mobile.static_analysis")

# ── Optional dependencies ────────────────────────────────────────────────────

try:
    from oneinfinity.apktool_wrapper import apktool_wrapper, ApktoolResult
    _HAS_APKTOOL = True
except ImportError:
    apktool_wrapper = None  # type: ignore
    ApktoolResult = None    # type: ignore
    _HAS_APKTOOL = False
    log.debug("apktool_wrapper not available")

try:
    from oneinfinity.jadx_wrapper import jadx_wrapper, JadxResult
    _HAS_JADX = True
except ImportError:
    jadx_wrapper = None  # type: ignore
    JadxResult = None    # type: ignore
    _HAS_JADX = False
    log.debug("jadx_wrapper not available")

try:
    from oneinfinity.mobile.tool_registry import UnifiedFinding
except ImportError:
    @dataclass  # type: ignore
    class UnifiedFinding:  # type: ignore
        target: str = ""
        vulnerability: str = ""
        attack_type: str = ""
        tool: str = ""
        severity: str = "info"
        evidence: str = ""
        file_path: str = ""
        line_number: int = 0
        payload: str = ""
        confidence: float = 0.5
        cvss: float = 0.0
        remediation: str = ""
        tags: List[str] = field(default_factory=list)

        def to_dict(self) -> dict:
            return vars(self)

# ── Dangerous permission catalogue ───────────────────────────────────────────

#: Maps permission name → (severity, description, cvss)
DANGEROUS_PERMISSIONS: Dict[str, tuple] = {
    "android.permission.CAMERA":
        ("medium", "Access to device camera — user content recording risk", 5.5),
    "android.permission.RECORD_AUDIO":
        ("high", "Access to microphone — audio surveillance risk", 7.0),
    "android.permission.ACCESS_FINE_LOCATION":
        ("high", "Precise GPS location tracking", 7.0),
    "android.permission.ACCESS_COARSE_LOCATION":
        ("medium", "Approximate location access", 5.0),
    "android.permission.READ_CONTACTS":
        ("high", "Read all device contacts", 7.0),
    "android.permission.WRITE_CONTACTS":
        ("high", "Modify or delete all contacts", 7.0),
    "android.permission.READ_SMS":
        ("critical", "Read all SMS messages including OTPs/2FA codes", 9.0),
    "android.permission.SEND_SMS":
        ("high", "Send SMS (may incur charges; can be used for fraud)", 7.5),
    "android.permission.RECEIVE_SMS":
        ("high", "Intercept all incoming SMS messages", 7.5),
    "android.permission.READ_CALL_LOG":
        ("high", "Access complete call history", 7.0),
    "android.permission.WRITE_CALL_LOG":
        ("medium", "Modify or delete call history", 5.0),
    "android.permission.PROCESS_OUTGOING_CALLS":
        ("critical", "Intercept and redirect outgoing phone calls", 9.0),
    "android.permission.WRITE_EXTERNAL_STORAGE":
        ("medium", "Write to world-readable external storage", 5.5),
    "android.permission.READ_EXTERNAL_STORAGE":
        ("medium", "Read all files on external storage", 5.5),
    "android.permission.GET_ACCOUNTS":
        ("medium", "Enumerate all device accounts (email, social)", 5.0),
    "android.permission.USE_BIOMETRIC":
        ("medium", "Use biometric authentication — integrity risk if bypassed", 5.0),
    "android.permission.USE_FINGERPRINT":
        ("medium", "Fingerprint access (deprecated in API 28+)", 5.0),
    "android.permission.READ_PHONE_STATE":
        ("medium", "Read IMEI, IMSI, and phone state — device fingerprinting", 5.5),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        ("critical", "Full accessibility service — used by spyware/overlay attacks", 9.5),
    "android.permission.SYSTEM_ALERT_WINDOW":
        ("high", "Draw over other apps — clickjacking / overlay attack vector", 7.5),
    "android.permission.REQUEST_INSTALL_PACKAGES":
        ("high", "Install arbitrary APK packages without user consent", 8.0),
    "android.permission.CHANGE_NETWORK_STATE":
        ("low", "Modify network connectivity settings", 3.0),
    "android.permission.RECEIVE_BOOT_COMPLETED":
        ("medium", "Auto-start on device boot — persistence mechanism", 5.0),
    "android.permission.FOREGROUND_SERVICE":
        ("low", "Run persistent foreground service", 3.0),
    "android.permission.MANAGE_EXTERNAL_STORAGE":
        ("high", "Full access to all external storage (Android 11+)", 7.5),
    "android.permission.READ_MEDIA_IMAGES":
        ("medium", "Read all images from media store", 5.0),
    "android.permission.READ_MEDIA_VIDEO":
        ("medium", "Read all video files from media store", 5.0),
    "android.permission.READ_MEDIA_AUDIO":
        ("medium", "Read all audio files from media store", 5.0),
    "android.permission.POST_NOTIFICATIONS":
        ("low", "Send push notifications", 2.0),
    "android.permission.SCHEDULE_EXACT_ALARM":
        ("low", "Schedule exact alarms (potential for battery drain)", 2.0),
}

# ── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class StaticAnalysisConfig:
    """Configuration for the static analysis engine."""
    use_apktool: bool = True
    use_jadx: bool = True
    use_mobsf: bool = False          # reserved for future MobSF integration
    output_dir: str = ""
    max_smali_files: int = 2000      # cap for large apps
    max_java_files: int = 1000


@dataclass
class StaticAnalysisResult:
    """Aggregated output from a full static analysis run."""

    app_id: str
    platform: str = "android"

    # Raw decompilation metadata
    apktool_result: Optional[dict] = None
    jadx_result: Optional[dict] = None

    # Per-category findings (as dicts so they serialise to JSON cleanly)
    manifest_findings: List[dict] = field(default_factory=list)
    permission_findings: List[dict] = field(default_factory=list)
    component_findings: List[dict] = field(default_factory=list)
    code_findings: List[dict] = field(default_factory=list)
    crypto_findings: List[dict] = field(default_factory=list)
    network_config_findings: List[dict] = field(default_factory=list)

    # All findings combined
    all_findings: List[dict] = field(default_factory=list)

    # High-level summary
    summary: dict = field(default_factory=dict)
    obfuscation_detected: bool = False
    decompile_success: bool = False
    analysis_time: float = 0.0

    def to_dict(self) -> dict:
        return vars(self)


# ── Analysis engine ───────────────────────────────────────────────────────────


class MobileStaticAnalyzer:
    """
    Orchestrates static analysis of an Android APK using APKTool and JADX.

    Analysis phases
    ---------------
    1. Decompile with APKTool (smali + decoded manifest + resources)
    2. Decompile with JADX (Java source)
    3. Manifest checks (debuggable, backup, cleartext traffic)
    4. Permission analysis (dangerous permission catalogue)
    5. Component security (exported without permissions)
    6. Code-level vulnerability scan (via JADX patterns)
    7. Network security config review
    8. Obfuscation detection

    All findings are normalised to ``UnifiedFinding`` objects and then
    serialised to dicts for the aggregated ``StaticAnalysisResult``.
    """

    def __init__(self, config: StaticAnalysisConfig = None) -> None:
        self.config = config or StaticAnalysisConfig()

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(
        self,
        app_id: str,
        file_path: str,
        extracted_dir: str,
    ) -> StaticAnalysisResult:
        """
        Run a full static analysis on an APK.

        Parameters
        ----------
        app_id:
            Unique identifier for the app (package name or user-assigned ID).
        file_path:
            Absolute path to the APK file to analyse.
        extracted_dir:
            Directory where the app was previously extracted / uploaded.
            Used as a base for APKTool / JADX output directories and for
            locating supplementary files (network_security_config.xml, etc.).

        Returns
        -------
        A ``StaticAnalysisResult`` with all findings populated.
        """
        result = StaticAnalysisResult(app_id=app_id)
        t0 = time.monotonic()

        if not os.path.isfile(file_path):
            log.warning("analyze: APK not found at %s", file_path)
            result.summary = {"error": f"File not found: {file_path}", "total": 0}
            return result

        out_base = self.config.output_dir or extracted_dir
        apktool_out = os.path.join(out_base, "apktool_out")
        jadx_out = os.path.join(out_base, "jadx_src")

        # ── Phase 1: APKTool decompilation ────────────────────────────────────
        apk_res = None
        if self.config.use_apktool and _HAS_APKTOOL and apktool_wrapper is not None:
            try:
                log.info("Running APKTool on %s", os.path.basename(file_path))
                apk_res = apktool_wrapper.decompile(file_path, apktool_out)
                result.apktool_result = apk_res.to_dict() if hasattr(apk_res, "to_dict") else vars(apk_res)
                if apk_res.success:
                    result.decompile_success = True
                    log.info(
                        "APKTool: %d smali dirs, manifest=%s",
                        len(apk_res.smali_dirs), bool(apk_res.manifest_path),
                    )
            except Exception as exc:
                log.warning("APKTool decompile error: %s", exc)

        # ── Phase 2: JADX decompilation ───────────────────────────────────────
        jadx_res = None
        if self.config.use_jadx and _HAS_JADX and jadx_wrapper is not None:
            try:
                log.info("Running JADX on %s", os.path.basename(file_path))
                jadx_res = jadx_wrapper.decompile(file_path, jadx_out)
                result.jadx_result = jadx_res.to_dict() if hasattr(jadx_res, "to_dict") else vars(jadx_res)
                if jadx_res.success:
                    result.decompile_success = True
                    log.info("JADX: %d Java files", jadx_res.java_files)
            except Exception as exc:
                log.warning("JADX decompile error: %s", exc)

        # ── Phase 3: Manifest checks ──────────────────────────────────────────
        if apk_res and apk_res.success:
            manifest_text = self._get_manifest_text(apk_res, extracted_dir)
            if manifest_text:
                result.manifest_findings = self._finding_list(
                    self._check_manifest_flags(app_id, manifest_text, apk_res)
                )
                result.permission_findings = self._finding_list(
                    self._analyze_permissions(app_id, manifest_text)
                )
                result.component_findings = self._finding_list(
                    self._analyze_components(app_id, manifest_text)
                )
            else:
                log.warning("analyze: could not read AndroidManifest.xml for %s", app_id)
        else:
            # Fallback: try to find manifest in extracted_dir directly
            manifest_text = self._find_manifest_in_dir(extracted_dir)
            if manifest_text:
                result.manifest_findings = self._finding_list(
                    self._check_manifest_flags(app_id, manifest_text)
                )
                result.permission_findings = self._finding_list(
                    self._analyze_permissions(app_id, manifest_text)
                )
                result.component_findings = self._finding_list(
                    self._analyze_components(app_id, manifest_text)
                )

        # ── Phase 4: Code vulnerability scan ─────────────────────────────────
        if jadx_res and jadx_res.success and _HAS_JADX and jadx_wrapper is not None:
            try:
                code_vulns = jadx_wrapper.analyze_for_vulns(jadx_res)
                result.code_findings = self._finding_list(code_vulns)
                result.obfuscation_detected = self._detect_obfuscation(jadx_res)
            except Exception as exc:
                log.warning("JADX vulnerability analysis error: %s", exc)

        elif apk_res and apk_res.success and _HAS_APKTOOL and apktool_wrapper is not None:
            # Smali-level analysis as fallback when JADX is not available
            try:
                smali_vulns = apktool_wrapper.analyze_for_vulns(apk_res)
                result.code_findings = self._finding_list(smali_vulns)
            except Exception as exc:
                log.warning("APKTool vulnerability analysis error: %s", exc)

        # ── Phase 5: Network security config ─────────────────────────────────
        result.network_config_findings = self._finding_list(
            self._analyze_network_security_config(app_id, extracted_dir, apktool_out)
        )

        # ── Phase 6: Aggregate ────────────────────────────────────────────────
        all_f: List[dict] = (
            result.manifest_findings
            + result.permission_findings
            + result.component_findings
            + result.code_findings
            + result.network_config_findings
        )
        result.all_findings = all_f
        result.analysis_time = time.monotonic() - t0
        result.summary = self._build_summary(result)

        log.info(
            "Static analysis complete for %s: %d findings in %.1fs",
            app_id, len(all_f), result.analysis_time,
        )
        return result

    # ── Manifest helpers ──────────────────────────────────────────────────────

    def _get_manifest_text(
        self,
        apk_res: Any,
        extracted_dir: str,
    ) -> Optional[str]:
        """Read AndroidManifest.xml from an APKTool result or the extracted dir."""
        if _HAS_APKTOOL and apktool_wrapper is not None:
            try:
                text = apktool_wrapper.get_manifest(apk_res)
                if text:
                    return text
            except Exception:
                pass
        return self._find_manifest_in_dir(extracted_dir)

    def _find_manifest_in_dir(self, directory: str) -> Optional[str]:
        """Search for a text-format AndroidManifest.xml in common locations."""
        search_paths = [
            Path(directory) / "AndroidManifest.xml",
            Path(directory) / "apktool_out" / "AndroidManifest.xml",
            Path(directory) / "extracted" / "AndroidManifest.xml",
        ]
        for p in search_paths:
            if p.is_file():
                try:
                    raw = p.read_bytes()
                    # Binary AXML starts with 0x03 0x00 — skip those
                    if len(raw) >= 2 and raw[0] == 0x03 and raw[1] == 0x00:
                        continue
                    return p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass
        return None

    # ── Manifest flag checks ──────────────────────────────────────────────────

    _MANIFEST_RULES = [
        # (pattern, vuln_name, attack_type, severity, confidence, cvss, remediation)
        (
            re.compile(r'android:debuggable\s*=\s*["\']true["\']', re.I),
            "Application Debuggable Flag Set",
            "misconfiguration", "high", 0.97, 7.4,
            (
                "Remove android:debuggable=\"true\" from the production manifest or "
                "restrict it to debug build variants. Debuggable apps allow arbitrary "
                "code injection via JDWP and adb."
            ),
        ),
        (
            re.compile(r'android:allowBackup\s*=\s*["\']true["\']', re.I),
            "ADB Backup Allowed (allowBackup=true)",
            "insecure_backup", "medium", 0.92, 5.5,
            (
                "Set android:allowBackup=\"false\" or restrict backup scope with "
                "android:fullBackupContent / android:dataExtractionRules "
                "to prevent sensitive data leakage via adb backup."
            ),
        ),
        (
            re.compile(r'android:usesCleartextTraffic\s*=\s*["\']true["\']', re.I),
            "Cleartext Traffic Explicitly Permitted",
            "insecure_transport", "high", 0.97, 7.5,
            (
                "Set android:usesCleartextTraffic=\"false\" and configure "
                "network_security_config.xml to enforce HTTPS for all connections."
            ),
        ),
        (
            re.compile(r'android:testOnly\s*=\s*["\']true["\']', re.I),
            "Test-Only Application Flag Set",
            "misconfiguration", "medium", 0.90, 4.3,
            "Remove android:testOnly=\"true\" before production release.",
        ),
        (
            re.compile(r'android:protectionLevel\s*=\s*["\'](?:normal|dangerous)["\']', re.I),
            "Custom Permission with Weak Protection Level",
            "permission_misconfiguration", "low", 0.70, 3.5,
            (
                "Use android:protectionLevel=\"signature\" for custom permissions "
                "that protect sensitive components."
            ),
        ),
    ]

    def _check_manifest_flags(
        self,
        target: str,
        manifest_text: str,
        apk_res: Any = None,
    ) -> List[UnifiedFinding]:
        """Apply manifest flag security rules and return findings."""
        findings: List[UnifiedFinding] = []
        file_path = ""
        if apk_res and hasattr(apk_res, "manifest_path"):
            file_path = apk_res.manifest_path or ""

        for regex, vuln, attack, sev, conf, cvss, rem in self._MANIFEST_RULES:
            m = regex.search(manifest_text)
            if m:
                findings.append(UnifiedFinding(
                    target=target,
                    vulnerability=vuln,
                    attack_type=attack,
                    tool="apktool",
                    severity=sev,
                    file_path=file_path or "AndroidManifest.xml",
                    line_number=manifest_text[:m.start()].count("\n") + 1,
                    evidence=m.group(0)[:200],
                    confidence=conf,
                    cvss=cvss,
                    remediation=rem,
                    tags=["manifest", "static", "android", attack],
                ))
        return findings

    # ── Permission analysis ───────────────────────────────────────────────────

    def _analyze_permissions(
        self,
        target: str,
        manifest_text: str,
    ) -> List[UnifiedFinding]:
        """Extract and evaluate permission declarations from the manifest."""
        findings: List[UnifiedFinding] = []
        seen_perms: set = set()

        perm_pattern = re.compile(
            r'<uses-permission[^>]+android:name=["\']([^"\']+)["\']', re.I
        )
        for m in perm_pattern.finditer(manifest_text):
            perm = m.group(1)
            if perm in seen_perms:
                continue
            seen_perms.add(perm)

            if perm not in DANGEROUS_PERMISSIONS:
                continue

            sev, desc, cvss = DANGEROUS_PERMISSIONS[perm]
            short = perm.replace("android.permission.", "")
            findings.append(UnifiedFinding(
                target=target,
                vulnerability=f"Dangerous Permission Requested: {short}",
                attack_type="dangerous_permission",
                tool="apktool",
                severity=sev,
                file_path="AndroidManifest.xml",
                line_number=manifest_text[:m.start()].count("\n") + 1,
                evidence=f"{perm}: {desc}",
                confidence=0.95,
                cvss=cvss,
                remediation=(
                    f"Evaluate whether {short} is strictly necessary. "
                    "Request permissions at runtime and explain the reason. "
                    "Remove unused permissions before release."
                ),
                tags=["manifest", "permission", "android", "static"],
            ))

        log.debug("Permission analysis: %d dangerous permissions found", len(findings))
        return findings

    # ── Component security ────────────────────────────────────────────────────

    def _analyze_components(
        self,
        target: str,
        manifest_text: str,
    ) -> List[UnifiedFinding]:
        """
        Detect exported Android components that lack permission protection.

        Checks:
        - <activity> exported="true" without android:permission
        - <service> exported="true" without android:permission
        - <receiver> exported="true" without android:permission
        - <provider> exported="true" without android:readPermission / android:writePermission
        """
        findings: List[UnifiedFinding] = []

        # Component-type → (severity, cvss, remediation hint)
        COMPONENT_META = {
            "activity":  ("high",     7.0, "Add android:permission to the <activity> or set android:exported=false"),
            "service":   ("high",     7.5, "Add android:permission to the <service> or set android:exported=false"),
            "receiver":  ("medium",   5.5, "Add android:permission to the <receiver> or set android:exported=false"),
            "provider":  ("critical", 8.5, "Add android:readPermission and android:writePermission to the <provider> or set android:exported=false"),
        }

        for tag, (sev, cvss, rem_hint) in COMPONENT_META.items():
            # Match opening tags for the component type that have exported=true
            pattern = re.compile(
                rf'<{tag}[^>]+android:exported\s*=\s*["\']true["\'][^>]*(?:/>|>)',
                re.I | re.DOTALL,
            )
            for m in pattern.finditer(manifest_text):
                tag_body = m.group(0)

                # Extract component name
                name_m = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', tag_body)
                comp_name = name_m.group(1) if name_m else "(unknown)"
                short_name = comp_name.split(".")[-1]

                # Skip if protected by an android:permission attribute
                if "android:permission" in tag_body:
                    continue

                # For providers also check read/writePermission
                if tag == "provider" and (
                    "android:readPermission" in tag_body
                    or "android:writePermission" in tag_body
                ):
                    continue

                line_no = manifest_text[:m.start()].count("\n") + 1
                label = tag.capitalize()

                findings.append(UnifiedFinding(
                    target=target,
                    vulnerability=f"Exported {label} Without Permission: {short_name}",
                    attack_type="exported_component",
                    tool="apktool",
                    severity=sev,
                    file_path="AndroidManifest.xml",
                    line_number=line_no,
                    evidence=(
                        f"<{tag} android:name=\"{comp_name}\" android:exported=\"true\"> "
                        "has no permission restriction"
                    ),
                    confidence=0.93,
                    cvss=cvss,
                    remediation=rem_hint,
                    tags=["manifest", "component", "android", "static", f"exported_{tag}"],
                ))

        log.debug("Component analysis: %d exported-component findings", len(findings))
        return findings

    # ── Network security config ───────────────────────────────────────────────

    def _analyze_network_security_config(
        self,
        target: str,
        extracted_dir: str,
        apktool_out: str,
    ) -> List[UnifiedFinding]:
        """
        Inspect network_security_config.xml for dangerous allowances:

        - cleartextTrafficPermitted=true
        - Trusting user-installed CAs in production
        - Debug overrides left in production
        """
        findings: List[UnifiedFinding] = []

        # Candidate locations for the NSC file
        nsc_candidates = [
            Path(apktool_out) / "res" / "xml" / "network_security_config.xml",
            Path(extracted_dir) / "res" / "xml" / "network_security_config.xml",
            Path(extracted_dir) / "apktool_out" / "res" / "xml" / "network_security_config.xml",
        ]

        nsc_content: Optional[str] = None
        nsc_path: Optional[str] = None
        for p in nsc_candidates:
            if p.is_file():
                try:
                    nsc_content = p.read_text(encoding="utf-8", errors="replace")
                    nsc_path = str(p)
                    break
                except OSError:
                    pass

        if nsc_content is None:
            log.debug("network_security_config.xml not found — skipping NSC analysis")
            return findings

        log.debug("Analysing network_security_config.xml at %s", nsc_path)

        # Rule: cleartextTrafficPermitted=true
        if re.search(r'cleartextTrafficPermitted\s*=\s*["\']true["\']', nsc_content, re.I):
            findings.append(UnifiedFinding(
                target=target,
                vulnerability="Network Security Config Permits Cleartext Traffic",
                attack_type="cleartext_traffic",
                tool="static_analysis",
                severity="high",
                file_path=nsc_path or "network_security_config.xml",
                line_number=0,
                evidence='cleartextTrafficPermitted="true" found in network_security_config.xml',
                confidence=0.99,
                cvss=7.5,
                remediation=(
                    'Set cleartextTrafficPermitted="false" globally in network_security_config.xml. '
                    "Allow cleartext only for specific debug domains if absolutely required."
                ),
                tags=["manifest", "network", "static", "cleartext"],
            ))

        # Rule: user CA trust in a non-debug context
        if (
            re.search(r'<certificates\s+src=["\']user["\']', nsc_content, re.I)
            and "<debug-overrides>" not in nsc_content
        ):
            findings.append(UnifiedFinding(
                target=target,
                vulnerability="App Trusts User-Installed Certificate Authorities",
                attack_type="certificate_trust",
                tool="static_analysis",
                severity="medium",
                file_path=nsc_path or "network_security_config.xml",
                line_number=0,
                evidence='<certificates src="user"> found outside <debug-overrides>',
                confidence=0.90,
                cvss=6.5,
                remediation=(
                    "Remove user CA trust from the base-config or domain-config. "
                    "User-trusted CAs allow MITM attacks when a malicious cert is installed."
                ),
                tags=["manifest", "network", "static", "certificate"],
            ))

        # Rule: debug-overrides present (check that it's not shipped in production)
        if "<debug-overrides>" in nsc_content:
            findings.append(UnifiedFinding(
                target=target,
                vulnerability="Network Security Config Contains Debug Overrides",
                attack_type="debug_config",
                tool="static_analysis",
                severity="medium",
                file_path=nsc_path or "network_security_config.xml",
                line_number=0,
                evidence="<debug-overrides> block found in network_security_config.xml",
                confidence=0.80,
                cvss=5.0,
                remediation=(
                    "Debug overrides are only safe if the app is signed with a debug key. "
                    "Verify that production builds cannot enter debug-overrides mode."
                ),
                tags=["manifest", "network", "static", "debug"],
            ))

        # Rule: certificate pinning not configured
        if "<pin-set>" not in nsc_content and "<pin " not in nsc_content:
            findings.append(UnifiedFinding(
                target=target,
                vulnerability="Certificate Pinning Not Configured",
                attack_type="missing_certificate_pinning",
                tool="static_analysis",
                severity="medium",
                file_path=nsc_path or "network_security_config.xml",
                line_number=0,
                evidence="No <pin-set> or <pin> elements found in network_security_config.xml",
                confidence=0.75,
                cvss=5.9,
                remediation=(
                    "Implement certificate pinning via <pin-set> in network_security_config.xml "
                    "for all sensitive API domains. Use backup pins and a pin rotation strategy."
                ),
                tags=["manifest", "network", "static", "pinning"],
            ))

        return findings

    # ── Obfuscation detection ─────────────────────────────────────────────────

    def _detect_obfuscation(self, jadx_res: Any) -> bool:
        """
        Heuristic: if >40% of class names are 1–2 characters long,
        the app is likely obfuscated with ProGuard/R8.
        """
        if jadx_res is None or not hasattr(jadx_res, "source_dir") or not jadx_res.source_dir:
            return False
        try:
            java_files = list(Path(jadx_res.source_dir).rglob("*.java"))[:200]
            if not java_files:
                return False
            obfuscated = sum(1 for f in java_files if len(f.stem) <= 2)
            return obfuscated > len(java_files) * 0.4
        except Exception:
            return False

    # ── Utility helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _finding_list(findings: List[Any]) -> List[dict]:
        """Convert a list of UnifiedFinding (or dicts) to a list of plain dicts."""
        result: List[dict] = []
        for f in findings:
            if isinstance(f, dict):
                result.append(f)
            elif hasattr(f, "to_dict"):
                result.append(f.to_dict())
            else:
                try:
                    result.append(vars(f))
                except TypeError:
                    pass
        return result

    def _build_summary(self, result: StaticAnalysisResult) -> dict:
        """Build a high-level summary of the analysis results."""
        by_severity: Dict[str, int] = {}
        for f in result.all_findings:
            sev = f.get("severity", "info") if isinstance(f, dict) else "info"
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total": len(result.all_findings),
            "by_severity": by_severity,
            "decompile_success": result.decompile_success,
            "obfuscation_detected": result.obfuscation_detected,
            "analysis_time_seconds": round(result.analysis_time, 2),
            "manifest_findings": len(result.manifest_findings),
            "permission_findings": len(result.permission_findings),
            "component_findings": len(result.component_findings),
            "code_findings": len(result.code_findings),
            "network_config_findings": len(result.network_config_findings),
        }


# ── Module-level singleton ────────────────────────────────────────────────────

#: Global singleton.  Import as:
#:     ``from mobile_static_analysis import mobile_static_analyzer``
mobile_static_analyzer: MobileStaticAnalyzer = MobileStaticAnalyzer()
