"""
Mobile Static Analyzer — AndroidManifest.xml parsing, permission analysis,
exported component detection, hardcoded URL/secret extraction, smali/jadx integration.
"""

import re
import os
import json
import shutil
import logging
import subprocess
import zipfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

# Android namespace
ANDROID_NS = "http://schemas.android.com/apk/res/android"

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.GET_ACCOUNTS", "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT", "android.permission.BODY_SENSORS",
}

CLEARTEXT_KEYWORDS = [
    "http://", "ftp://", "mongodb://", "redis://", "mysql://", "postgres://",
]

HARDCODED_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
    (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^\'"]{8,})["\']', "Secret/Password"),
    (r'(?i)(token|access[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'sk-[A-Za-z0-9]{48}', "OpenAI Key"),
    (r'AIza[0-9A-Za-z_\-]{35}', "Google API Key"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub PAT"),
    (r'(?i)firebase.*["\']([A-Za-z0-9_\-]{20,})["\']', "Firebase Key"),
]

URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')

COMPILED_SECRET_PATTERNS = [(re.compile(p), label) for p, label in HARDCODED_SECRET_PATTERNS]


@dataclass
class ComponentInfo:
    name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool = False
    intent_filters: list = field(default_factory=list)
    permissions: list = field(default_factory=list)
    deep_links: list = field(default_factory=list)


@dataclass
class StaticAnalysisResult:
    app_id: str
    package_name: str = ""
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: list = field(default_factory=list)
    dangerous_permissions: list = field(default_factory=list)
    components: list = field(default_factory=list)
    exported_components: list = field(default_factory=list)
    deep_links: list = field(default_factory=list)
    hardcoded_urls: list = field(default_factory=list)
    hardcoded_secrets: list = field(default_factory=list)
    cleartext_traffic: bool = False
    backup_allowed: bool = False
    debuggable: bool = False
    network_security_config: bool = False
    vulnerabilities: list = field(default_factory=list)
    raw_manifest: str = ""
    tool_used: str = ""

    def to_dict(self):
        return {
            "app_id": self.app_id,
            "package_name": self.package_name,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "permissions": self.permissions,
            "dangerous_permissions": self.dangerous_permissions,
            "components": [c.__dict__ for c in self.components],
            "exported_components": [c.__dict__ for c in self.exported_components],
            "deep_links": self.deep_links,
            "hardcoded_urls": self.hardcoded_urls,
            "hardcoded_secrets": self.hardcoded_secrets,
            "cleartext_traffic": self.cleartext_traffic,
            "backup_allowed": self.backup_allowed,
            "debuggable": self.debuggable,
            "network_security_config": self.network_security_config,
            "vulnerabilities": self.vulnerabilities,
            "tool_used": self.tool_used,
        }


class MobileStaticAnalyzer:

    def analyze(self, app_id: str, apk_path: str, extracted_dir: str) -> StaticAnalysisResult:
        result = StaticAnalysisResult(app_id=app_id)
        ext = Path(apk_path).suffix.lower()

        if ext == ".apk":
            self._analyze_apk(result, apk_path, extracted_dir)
        elif ext in (".ipa", ".zip"):
            self._analyze_ipa(result, apk_path, extracted_dir)
        else:
            result.vulnerabilities.append({
                "type": "unknown_format",
                "severity": "info",
                "detail": f"Unknown file extension: {ext}",
            })

        return result

    # ── APK ──────────────────────────────────────────────────────────────────

    def _analyze_apk(self, result: StaticAnalysisResult, apk_path: str, extracted_dir: str):
        manifest_xml = self._get_manifest_apktool(apk_path, extracted_dir)
        if manifest_xml:
            self._parse_manifest(result, manifest_xml)
            result.tool_used = "apktool"
        else:
            # fallback: string extraction from binary
            self._parse_manifest_strings(result, apk_path)
            result.tool_used = "strings"

        # Source code analysis
        self._scan_source_directory(result, extracted_dir)

        # jadx decompile if available
        if shutil.which("jadx"):
            jadx_dir = Path(extracted_dir) / "jadx_src"
            self._run_jadx(apk_path, str(jadx_dir))
            self._scan_source_directory(result, str(jadx_dir))

        self._generate_vuln_findings(result)

    def _get_manifest_apktool(self, apk_path: str, extracted_dir: str) -> Optional[str]:
        if not shutil.which("apktool"):
            # Try to extract AndroidManifest.xml from ZIP and parse as binary
            return self._extract_manifest_from_zip(apk_path, extracted_dir)

        out_dir = Path(extracted_dir) / "apktool_out"
        try:
            subprocess.run(
                ["apktool", "d", "-f", "-o", str(out_dir), apk_path],
                capture_output=True, text=True, timeout=120
            )
            manifest_path = out_dir / "AndroidManifest.xml"
            if manifest_path.exists():
                return manifest_path.read_text(errors="replace")
        except Exception as e:
            logger.warning(f"apktool failed: {e}")
        return None

    def _extract_manifest_from_zip(self, apk_path: str, extracted_dir: str) -> Optional[str]:
        """Try to find already-extracted manifest or extract raw bytes."""
        # Check if it was already extracted (skip binary AXML — starts with 0x03 0x00)
        for candidate in [
            Path(extracted_dir) / "AndroidManifest.xml",
            Path(extracted_dir) / "apktool_out" / "AndroidManifest.xml",
        ]:
            if candidate.exists():
                raw = candidate.read_bytes()
                # Binary AXML magic: first 2 bytes are 0x03 0x00
                if len(raw) > 2 and raw[0] == 0x03 and raw[1] == 0x00:
                    continue  # skip binary, fall through to androguard
                return candidate.read_text(errors="replace")

        # Try aapt2
        if shutil.which("aapt2"):
            try:
                r = subprocess.run(
                    ["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", apk_path],
                    capture_output=True, text=True, timeout=30
                )
                if r.returncode == 0:
                    return r.stdout
            except Exception:
                pass

        # Try aapt
        if shutil.which("aapt"):
            try:
                r = subprocess.run(
                    ["aapt", "dump", "xmltree", apk_path, "AndroidManifest.xml"],
                    capture_output=True, text=True, timeout=30
                )
                if r.returncode == 0:
                    return r.stdout
            except Exception:
                pass

        # Try androguard (pure Python APK parser — no native tools needed)
        try:
            import logging as _logging
            _logging.disable(_logging.CRITICAL)
            from androguard.core.apk import APK as _APK
            _apk = _APK(apk_path)
            lines = [
                f"package: {_apk.get_package()}",
                f"versionName: {_apk.get_androidversion_name()}",
                f"versionCode: {_apk.get_androidversion_code()}",
                f"minSdkVersion: {_apk.get_min_sdk_version()}",
                f"targetSdkVersion: {_apk.get_target_sdk_version()}",
                "permissions:",
            ]
            for p in _apk.get_permissions():
                lines.append(f"  uses-permission: {p}")
            lines.append("activities:")
            for a in _apk.get_activities():
                exported = bool(_apk.get_intent_filters("activity", a))
                lines.append(f"  activity name={a} exported={exported}")
            lines.append("services:")
            for s in _apk.get_services():
                lines.append(f"  service name={s}")
            lines.append("receivers:")
            for rv in _apk.get_receivers():
                lines.append(f"  receiver name={rv}")
            _logging.disable(_logging.NOTSET)
            return "\n".join(lines)
        except Exception:
            pass

        return None

    def _parse_manifest(self, result: StaticAnalysisResult, xml_text: str):
        """Parse decoded AndroidManifest.xml (aapt tree or apktool XML)."""
        result.raw_manifest = xml_text[:5000]

        # If it looks like standard XML, parse with ElementTree
        if xml_text.strip().startswith("<?xml") or xml_text.strip().startswith("<manifest"):
            self._parse_manifest_xml(result, xml_text)
        elif xml_text.strip().startswith("package:"):
            # androguard plain-text format
            self._parse_manifest_androguard(result, xml_text)
        else:
            # aapt dump tree format — extract with regex
            self._parse_manifest_aapt_tree(result, xml_text)

    def _parse_manifest_xml(self, result: StaticAnalysisResult, xml_text: str):
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            logger.warning(f"Manifest XML parse error: {e}")
            self._parse_manifest_strings_from_text(result, xml_text)
            return

        ns = ANDROID_NS
        result.package_name = root.get("package", "")
        result.min_sdk = int(root.find(f"uses-sdk[@{{{ns}}}minSdkVersion]") is not None and
                              root.find(f"uses-sdk").get(f"{{{ns}}}minSdkVersion", "0") or "0")

        sdk_el = root.find("uses-sdk")
        if sdk_el is not None:
            result.min_sdk = int(sdk_el.get(f"{{{ns}}}minSdkVersion", "0") or "0")
            result.target_sdk = int(sdk_el.get(f"{{{ns}}}targetSdkVersion", "0") or "0")

        for perm in root.findall("uses-permission"):
            name = perm.get(f"{{{ns}}}name", "")
            if name:
                result.permissions.append(name)
                if name in DANGEROUS_PERMISSIONS:
                    result.dangerous_permissions.append(name)

        app_el = root.find("application")
        if app_el is not None:
            result.debuggable = app_el.get(f"{{{ns}}}debuggable", "false").lower() == "true"
            result.backup_allowed = app_el.get(f"{{{ns}}}allowBackup", "true").lower() == "true"
            result.cleartext_traffic = app_el.get(f"{{{ns}}}usesCleartextTraffic", "false").lower() == "true"
            nsc = app_el.get(f"{{{ns}}}networkSecurityConfig")
            result.network_security_config = nsc is not None

            for comp_tag in ["activity", "service", "receiver", "provider"]:
                for el in app_el.findall(f".//{comp_tag}"):
                    name = el.get(f"{{{ns}}}name", "")
                    exported_val = el.get(f"{{{ns}}}exported", "")
                    intent_filters = el.findall("intent-filter")
                    # exported is True if explicitly set or has intent-filters (for activities/receivers)
                    exported = (
                        exported_val.lower() == "true" or
                        (exported_val == "" and comp_tag in ("activity", "receiver") and len(intent_filters) > 0)
                    )
                    comp = ComponentInfo(
                        name=name,
                        component_type=comp_tag,
                        exported=exported,
                    )
                    # Deep links
                    for ifilter in intent_filters:
                        action = ifilter.find(f"action[@{{{ns}}}name='android.intent.action.VIEW']")
                        if action is not None:
                            for data in ifilter.findall("data"):
                                scheme = data.get(f"{{{ns}}}scheme", "")
                                host = data.get(f"{{{ns}}}host", "")
                                path = data.get(f"{{{ns}}}path", "")
                                if scheme:
                                    deep_link = f"{scheme}://{host}{path}"
                                    comp.deep_links.append(deep_link)
                                    result.deep_links.append(deep_link)
                        comp.intent_filters.append({
                            "actions": [a.get(f"{{{ns}}}name", "") for a in ifilter.findall("action")],
                            "categories": [c.get(f"{{{ns}}}name", "") for c in ifilter.findall("category")],
                        })

                    perm_attr = el.get(f"{{{ns}}}permission", "")
                    if perm_attr:
                        comp.permissions.append(perm_attr)

                    result.components.append(comp)
                    if comp.exported:
                        result.exported_components.append(comp)

    def _parse_manifest_androguard(self, result: StaticAnalysisResult, text: str):
        """Parse our androguard plain-text format."""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                result.package_name = line.split(":", 1)[1].strip()
            elif line.startswith("minSdkVersion:"):
                try:
                    result.min_sdk = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("targetSdkVersion:"):
                try:
                    result.target_sdk = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif "uses-permission:" in line:
                perm = line.split("uses-permission:", 1)[1].strip()
                result.permissions.append(perm)
                perm_short = perm.replace("android.permission.", "")
                if perm_short in DANGEROUS_PERMISSIONS or perm in DANGEROUS_PERMISSIONS:
                    result.dangerous_permissions.append(perm_short)
            elif "activity name=" in line:
                m = re.search(r"name=([^\s]+)", line)
                exported = "exported=True" in line
                if m:
                    comp = ComponentInfo(name=m.group(1), component_type="activity", exported=exported)
                    result.components.append(comp)
                    if exported:
                        result.exported_components.append(comp)
            elif "service name=" in line:
                m = re.search(r"name=([^\s]+)", line)
                if m:
                    result.components.append(ComponentInfo(name=m.group(1), component_type="service", exported=False))
            elif "receiver name=" in line:
                m = re.search(r"name=([^\s]+)", line)
                if m:
                    result.components.append(ComponentInfo(name=m.group(1), component_type="receiver", exported=False))

    def _parse_manifest_aapt_tree(self, result: StaticAnalysisResult, tree_text: str):
        """Parse aapt dump xmltree output."""
        pkg_m = re.search(r'package=\(0x[0-9a-f]+\)\s*"([^"]+)"', tree_text)
        if pkg_m:
            result.package_name = pkg_m.group(1)

        for m in re.finditer(r'uses-permission.*?name=\(0x[0-9a-f]+\)\s*"([^"]+)"', tree_text):
            perm = m.group(1)
            result.permissions.append(perm)
            if perm in DANGEROUS_PERMISSIONS:
                result.dangerous_permissions.append(perm)

        result.debuggable = bool(re.search(r'debuggable.*?=\(.*?\)\s*"?true"?', tree_text, re.I))
        result.backup_allowed = not bool(re.search(r'allowBackup.*?=\(.*?\)\s*"?false"?', tree_text, re.I))
        result.cleartext_traffic = bool(re.search(r'usesCleartextTraffic.*?=\(.*?\)\s*"?true"?', tree_text, re.I))

    def _parse_manifest_strings_from_text(self, result: StaticAnalysisResult, text: str):
        """Extract info from manifest text using regex when XML parse fails."""
        for m in re.finditer(r'android:name="(android\.permission\.[^"]+)"', text):
            perm = m.group(1)
            result.permissions.append(perm)
            if perm in DANGEROUS_PERMISSIONS:
                result.dangerous_permissions.append(perm)
        for m in re.finditer(r'package="([^"]+)"', text):
            result.package_name = m.group(1)
            break
        result.debuggable = 'android:debuggable="true"' in text
        result.backup_allowed = 'android:allowBackup="false"' not in text
        result.cleartext_traffic = 'android:usesCleartextTraffic="true"' in text

    def _parse_manifest_strings(self, result: StaticAnalysisResult, apk_path: str):
        """Last resort: extract strings from binary APK."""
        try:
            with zipfile.ZipFile(apk_path, 'r') as z:
                if "AndroidManifest.xml" in z.namelist():
                    raw = z.read("AndroidManifest.xml").decode("utf-8", errors="replace")
                    self._parse_manifest_strings_from_text(result, raw)
        except Exception:
            pass

    def _run_jadx(self, apk_path: str, out_dir: str):
        try:
            subprocess.run(
                ["jadx", "-d", out_dir, "--no-res", apk_path],
                capture_output=True, timeout=180
            )
        except Exception as e:
            logger.debug(f"jadx failed: {e}")

    # ── IPA ──────────────────────────────────────────────────────────────────

    def _analyze_ipa(self, result: StaticAnalysisResult, ipa_path: str, extracted_dir: str):
        result.tool_used = "plistlib"
        plist_path = self._find_info_plist(extracted_dir)
        if plist_path:
            self._parse_info_plist(result, plist_path)
        self._scan_source_directory(result, extracted_dir)
        self._generate_vuln_findings(result)

    def _find_info_plist(self, extracted_dir: str) -> Optional[str]:
        for root_dir, _, files in os.walk(extracted_dir):
            for f in files:
                if f == "Info.plist":
                    return os.path.join(root_dir, f)
        return None

    def _parse_info_plist(self, result: StaticAnalysisResult, plist_path: str):
        try:
            import plistlib
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
            result.package_name = plist.get("CFBundleIdentifier", "")
            # Check for insecure transport
            ats = plist.get("NSAppTransportSecurity", {})
            allows_arbitrary = ats.get("NSAllowsArbitraryLoads", False)
            result.cleartext_traffic = allows_arbitrary
            # Permissions
            perm_keys = [k for k in plist if k.startswith("NS") and "UsageDescription" in k]
            result.permissions = perm_keys
            # Deep links
            url_types = plist.get("CFBundleURLTypes", [])
            for ut in url_types:
                for scheme in ut.get("CFBundleURLSchemes", []):
                    result.deep_links.append(f"{scheme}://")
        except Exception as e:
            logger.warning(f"plist parse error: {e}")

    # ── Source scanning ───────────────────────────────────────────────────────

    def _scan_source_directory(self, result: StaticAnalysisResult, src_dir: str):
        if not os.path.isdir(src_dir):
            return

        text_exts = {".java", ".kt", ".smali", ".xml", ".json", ".js", ".ts", ".properties", ".gradle", ".yaml", ".yml", ".swift", ".m", ".h"}
        seen_urls = set(result.hardcoded_urls)
        seen_secrets = set()

        for root_dir, dirs, files in os.walk(src_dir):
            # Skip large binary dirs
            dirs[:] = [d for d in dirs if d not in {"__pycache__", "node_modules", ".git"}]
            for fname in files:
                fpath = os.path.join(root_dir, fname)
                if Path(fname).suffix.lower() not in text_exts:
                    continue
                try:
                    text = Path(fpath).read_text(errors="replace", encoding="utf-8")
                except Exception:
                    continue

                rel_path = os.path.relpath(fpath, src_dir)

                # URLs
                for m in URL_PATTERN.finditer(text):
                    url = m.group(0)
                    if url not in seen_urls and len(url) < 300:
                        seen_urls.add(url)
                        result.hardcoded_urls.append({"url": url, "file": rel_path})
                        for kw in CLEARTEXT_KEYWORDS:
                            if url.startswith(kw):
                                result.cleartext_traffic = True

                # IPs
                for m in IP_PATTERN.finditer(text):
                    ip = m.group(0)
                    # Skip local/loopback
                    if not ip.startswith(("127.", "10.", "192.168.", "0.0.0.0", "255.")):
                        entry = f"IP:{ip} in {rel_path}"
                        if entry not in seen_urls:
                            seen_urls.add(entry)
                            result.hardcoded_urls.append({"url": ip, "file": rel_path, "type": "ip"})

                # Secrets
                for pattern, label in COMPILED_SECRET_PATTERNS:
                    for m in pattern.finditer(text):
                        key = f"{label}:{m.group(0)[:40]}"
                        if key not in seen_secrets:
                            seen_secrets.add(key)
                            result.hardcoded_secrets.append({
                                "type": label,
                                "value": m.group(0)[:80],
                                "file": rel_path,
                                "line": text[:m.start()].count("\n") + 1,
                            })

    # ── Vulnerability generation ──────────────────────────────────────────────

    def _generate_vuln_findings(self, result: StaticAnalysisResult):
        vulns = result.vulnerabilities

        if result.debuggable:
            vulns.append({"type": "debuggable_app", "severity": "high",
                "detail": "Application has android:debuggable=true — allows ADB debugging and memory inspection"})

        if result.backup_allowed:
            vulns.append({"type": "backup_enabled", "severity": "medium",
                "detail": "android:allowBackup=true — app data can be extracted via ADB backup"})

        if result.cleartext_traffic:
            vulns.append({"type": "cleartext_traffic", "severity": "high",
                "detail": "Application allows cleartext (HTTP) traffic — sensitive data may be transmitted unencrypted"})

        for perm in result.dangerous_permissions:
            vulns.append({"type": "dangerous_permission", "severity": "medium",
                "detail": f"Dangerous permission: {perm}"})

        for comp in result.exported_components:
            sev = "high" if comp.component_type in ("activity", "provider") else "medium"
            vulns.append({"type": "exported_component", "severity": sev,
                "detail": f"Exported {comp.component_type}: {comp.name}",
                "component": comp.name, "component_type": comp.component_type})

        if result.hardcoded_secrets:
            for s in result.hardcoded_secrets:
                vulns.append({"type": "hardcoded_secret", "severity": "critical",
                    "detail": f"Hardcoded {s['type']} found in {s['file']}",
                    "file": s["file"], "value_preview": s["value"][:40]})

        if result.min_sdk > 0 and result.min_sdk < 21:
            vulns.append({"type": "low_min_sdk", "severity": "info",
                "detail": f"minSdkVersion={result.min_sdk} supports very old Android versions with known vulnerabilities"})

        if not result.network_security_config and result.target_sdk < 28:
            vulns.append({"type": "no_network_security_config", "severity": "medium",
                "detail": "No network_security_config defined — app may trust user-installed CAs"})


mobile_static_analyzer = MobileStaticAnalyzer()
