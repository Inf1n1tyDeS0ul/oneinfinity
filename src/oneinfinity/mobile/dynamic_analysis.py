"""
Mobile Dynamic Analysis Engine
================================
Runtime analysis using Frida, Objection, and RMS.
Manages device connectivity, script injection, and runtime monitoring.
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
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("oneinfinity.mobile.dynamic_analysis")

# ---------------------------------------------------------------------------
# Optional wrapper imports — all fail-safe so the module is always importable
# ---------------------------------------------------------------------------
try:
    from oneinfinity.frida_wrapper import frida_wrapper
except ImportError:
    frida_wrapper = None  # type: ignore

try:
    from oneinfinity.objection_wrapper import objection_wrapper
except ImportError:
    objection_wrapper = None  # type: ignore

try:
    from oneinfinity.rms_wrapper import rms_wrapper
except ImportError:
    rms_wrapper = None  # type: ignore

try:
    from oneinfinity.frida_script_generator import frida_script_generator
except ImportError:
    frida_script_generator = None  # type: ignore

from oneinfinity.mobile.tool_registry import UnifiedFinding

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DynamicAnalysisConfig:
    device_id: str = ""
    package_name: str = ""
    enable_frida: bool = True
    enable_objection: bool = True
    enable_rms: bool = False
    bypass_ssl: bool = True
    bypass_root: bool = True
    monitor_network: bool = True
    monitor_crypto: bool = True
    monitor_storage: bool = True
    timeout: int = 120


@dataclass
class DynamicAnalysisResult:
    app_id: str
    package_name: str
    device_id: str = ""
    runtime_findings: List[Dict] = field(default_factory=list)
    network_traffic: List[Dict] = field(default_factory=list)
    crypto_operations: List[Dict] = field(default_factory=list)
    storage_operations: List[Dict] = field(default_factory=list)
    frida_script_results: List[Dict] = field(default_factory=list)
    ssl_bypassed: bool = False
    root_bypassed: bool = False
    all_findings: List[UnifiedFinding] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "app_id": self.app_id,
            "package_name": self.package_name,
            "device_id": self.device_id,
            "runtime_findings": self.runtime_findings,
            "network_traffic": self.network_traffic,
            "crypto_operations": self.crypto_operations,
            "storage_operations": self.storage_operations,
            "frida_script_results": self.frida_script_results,
            "ssl_bypassed": self.ssl_bypassed,
            "root_bypassed": self.root_bypassed,
            "all_findings": [f.to_dict() for f in self.all_findings],
            "duration": self.duration,
        }


# ---------------------------------------------------------------------------
# Built-in Frida scripts (used when frida_script_generator is unavailable)
# ---------------------------------------------------------------------------

_FRIDA_SSL_BYPASS = """
Java.perform(function() {
    // Generic TrustManager bypass
    try {
        var TrustManager = Java.registerClass({
            name: 'com.bypass.TrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
            send({type:'ssl_bypass', message:'SSLContext.init overridden'});
        };
    } catch(e) { send({type:'error', message:'TrustManager: ' + e}); }

    // OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(host, certs) {
                send({type:'ssl_bypass', message:'OkHttp pinning bypassed for: ' + host});
            };
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
            .implementation = function(host, certs) {
                send({type:'ssl_bypass', message:'OkHttp pinning (cert[]) bypassed for: ' + host});
            };
    } catch(e) {}

    // TrustKit
    try {
        var OkHostnameVerifier = Java.use(
            'com.datatheorem.android.trustkit.pinning.OkHostnameVerifier'
        );
        OkHostnameVerifier.verify
            .overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function(h, s) { return true; };
    } catch(e) {}

    send({type:'status', message:'SSL pinning bypass loaded'});
});
"""

_FRIDA_ROOT_BYPASS = """
Java.perform(function() {
    var SU_PATHS = [
        '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
        '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
        '/system/bin/failsafe/su', '/data/local/su'
    ];
    // Spoof File.exists for su paths
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function() {
            var p = this.getAbsolutePath();
            if (SU_PATHS.indexOf(p) >= 0) {
                send({type:'root_bypass', message:'Blocked File.exists: ' + p});
                return false;
            }
            return this.exists();
        };
    } catch(e) {}

    // Block Runtime.exec('su')
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
            if (cmd === 'su' || cmd.indexOf('su ') === 0) {
                send({type:'root_bypass', message:'Blocked Runtime.exec su'});
                throw Java.use('java.io.IOException').$new('Permission denied');
            }
            return this.exec(cmd);
        };
    } catch(e) {}

    // Bypass RootBeer
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            send({type:'root_bypass', message:'RootBeer.isRooted bypassed'});
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
    } catch(e) {}

    send({type:'status', message:'Root detection bypass loaded'});
});
"""

_FRIDA_NETWORK_HOOK = """
Java.perform(function() {
    // Hook java.net.URL.openConnection
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function() {
            send({type:'network', url:this.toString(), method:'openConnection'});
            return this.openConnection();
        };
    } catch(e) {}

    // OkHttp3 Request.Builder.url(String)
    try {
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.url.overload('java.lang.String').implementation = function(url) {
            send({type:'network', url:url, method:'okhttp3'});
            return this.url(url);
        };
    } catch(e) {}

    // HttpsURLConnection
    try {
        var HttpsURLConn = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConn.connect.implementation = function() {
            send({type:'network', url:this.getURL().toString(), method:'https_connect'});
            return this.connect();
        };
    } catch(e) {}

    send({type:'status', message:'Network hooks loaded'});
});
"""

_FRIDA_CRYPTO_HOOK = """
Java.perform(function() {
    // Cipher.getInstance
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
            send({type:'crypto', algorithm:algo, operation:'Cipher.getInstance'});
            return this.getInstance(algo);
        };
    } catch(e) {}

    // MessageDigest.getInstance
    try {
        var MD = Java.use('java.security.MessageDigest');
        MD.getInstance.overload('java.lang.String').implementation = function(algo) {
            send({type:'crypto', algorithm:algo, operation:'MessageDigest.getInstance'});
            return this.getInstance(algo);
        };
    } catch(e) {}

    // KeyGenerator.getInstance
    try {
        var KG = Java.use('javax.crypto.KeyGenerator');
        KG.getInstance.overload('java.lang.String').implementation = function(algo) {
            send({type:'crypto', algorithm:algo, operation:'KeyGenerator.getInstance'});
            return this.getInstance(algo);
        };
    } catch(e) {}

    send({type:'status', message:'Crypto hooks loaded'});
});
"""

_FRIDA_STORAGE_HOOK = """
Java.perform(function() {
    // SharedPreferences.edit -> putString for sensitive keys
    try {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Editor.putString.implementation = function(key, value) {
            var SENSITIVE = ['password','token','secret','key','auth','pin','ssn'];
            for (var i = 0; i < SENSITIVE.length; i++) {
                if (key.toLowerCase().indexOf(SENSITIVE[i]) >= 0) {
                    send({type:'storage', key:key, value_length:value ? value.length : 0,
                          storage:'SharedPreferences'});
                    break;
                }
            }
            return this.putString(key, value);
        };
    } catch(e) {}

    // File write: FileOutputStream
    try {
        var FOS = Java.use('java.io.FileOutputStream');
        FOS.$init.overload('java.lang.String').implementation = function(path) {
            send({type:'file_write', path:path});
            return this.$init(path);
        };
    } catch(e) {}

    send({type:'status', message:'Storage hooks loaded'});
});
"""

_BUILTIN_SCRIPTS = {
    "ssl_bypass": _FRIDA_SSL_BYPASS,
    "root_bypass": _FRIDA_ROOT_BYPASS,
    "network_hook": _FRIDA_NETWORK_HOOK,
    "crypto_hook": _FRIDA_CRYPTO_HOOK,
    "storage_hook": _FRIDA_STORAGE_HOOK,
}

# Weak crypto algorithms that should be flagged
_WEAK_ALGOS = {"DES", "3DES", "RC4", "RC2", "MD5", "SHA1", "ECB", "BLOWFISH"}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class MobileDynamicAnalyzer:
    """
    Orchestrates dynamic analysis of mobile apps using Frida, Objection, and RMS.
    Falls back gracefully when no device is connected.
    """

    def __init__(self, config: DynamicAnalysisConfig = None) -> None:
        self.config = config or DynamicAnalysisConfig()
        self._adb_path: Optional[str] = shutil.which("adb")
        self._frida_path: Optional[str] = shutil.which("frida")

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        app_id: str,
        package_name: str,
        extracted_dir: str = "",
        device_id: str = "",
        app_model: Any = None,
    ) -> DynamicAnalysisResult:
        """
        Main orchestrator for dynamic analysis.

        Steps:
        1. Check device connectivity (adb/frida)
        2. Generate Frida scripts from app_model (or use built-ins)
        3. Run Frida scripts
        4. Run Objection analysis
        5. Run RMS if enabled
        6. Aggregate all findings

        Returns gracefully if no device is connected.
        """
        start = time.monotonic()
        result = DynamicAnalysisResult(app_id=app_id, package_name=package_name)

        # Resolve device
        effective_device = device_id or self.config.device_id
        if not effective_device:
            devices = self.get_adb_devices()
            effective_device = devices[0]["serial"] if devices else ""

        result.device_id = effective_device

        # Check device connectivity
        if not self._check_device(effective_device):
            logger.warning(
                "No connected device for dynamic analysis of %s — running simulation only.", package_name
            )
            self._simulate_without_device(result)
            result.duration = time.monotonic() - start
            return result

        # Resolve package name
        if not package_name:
            package_name = self._get_package_name(app_id, extracted_dir)
        result.package_name = package_name

        # Generate or use built-in Frida scripts
        scripts = self._collect_scripts(app_model)

        # Phase 1: Frida
        if self.config.enable_frida and self._frida_path:
            try:
                self._run_frida_phase(result, scripts, package_name, effective_device)
            except Exception as exc:
                logger.error("Frida phase error: %s", exc)
                result.runtime_findings.append({"error": str(exc), "phase": "frida"})

        # Phase 2: Objection
        if self.config.enable_objection and objection_wrapper is not None:
            try:
                self._run_objection_phase(result, package_name, effective_device)
            except Exception as exc:
                logger.error("Objection phase error: %s", exc)
                result.runtime_findings.append({"error": str(exc), "phase": "objection"})

        # Phase 3: RMS
        if self.config.enable_rms and rms_wrapper is not None:
            try:
                self._run_rms_phase(result, package_name, effective_device)
            except Exception as exc:
                logger.error("RMS phase error: %s", exc)

        # Analyse collected data into UnifiedFindings
        self._synthesize_findings(result)

        result.duration = time.monotonic() - start
        logger.info(
            "Dynamic analysis complete for %s: %d findings in %.1fs",
            package_name, len(result.all_findings), result.duration,
        )
        return result

    # ------------------------------------------------------------------
    # Device check
    # ------------------------------------------------------------------

    def _check_device(self, device_id: str) -> bool:
        """Return True if a connected ADB device is available (and Frida server if needed)."""
        if not self._adb_path:
            logger.debug("adb not found on PATH")
            return False

        devices = self.get_adb_devices()
        if not devices:
            return False

        if device_id:
            return any(d["serial"] == device_id for d in devices)
        return True

    # ------------------------------------------------------------------
    # Package resolution
    # ------------------------------------------------------------------

    def _get_package_name(self, app_id: str, extracted_dir: str) -> str:
        """Try to derive package name from app_id or AndroidManifest.xml."""
        if app_id and "." in app_id and not os.sep in app_id:
            return app_id

        if extracted_dir and os.path.isdir(extracted_dir):
            from pathlib import Path
            for manifest in Path(extracted_dir).rglob("AndroidManifest.xml"):
                try:
                    from xml.etree import ElementTree as ET
                    tree = ET.parse(str(manifest))
                    pkg = tree.getroot().get("package", "")
                    if pkg:
                        return pkg
                except Exception:
                    pass
        return app_id

    # ------------------------------------------------------------------
    # Script collection
    # ------------------------------------------------------------------

    def _collect_scripts(self, app_model: Any) -> List[Tuple[str, str]]:
        """
        Build list of (name, js_code) Frida scripts to inject.
        Uses frida_script_generator if available; otherwise falls back to built-ins.
        """
        scripts: List[Tuple[str, str]] = []

        if frida_script_generator is not None and app_model is not None:
            try:
                generated = frida_script_generator.generate(app_model)
                if isinstance(generated, list):
                    for item in generated:
                        if isinstance(item, tuple) and len(item) == 2:
                            scripts.append(item)
                        elif isinstance(item, dict):
                            scripts.append((item.get("name", "generated"), item.get("code", "")))
            except Exception as exc:
                logger.debug("frida_script_generator failed: %s — using built-ins", exc)

        # Always include built-in scripts as baseline
        if self.config.bypass_ssl:
            scripts.append(("ssl_bypass", _FRIDA_SSL_BYPASS))
        if self.config.bypass_root:
            scripts.append(("root_bypass", _FRIDA_ROOT_BYPASS))
        if self.config.monitor_network:
            scripts.append(("network_hook", _FRIDA_NETWORK_HOOK))
        if self.config.monitor_crypto:
            scripts.append(("crypto_hook", _FRIDA_CRYPTO_HOOK))
        if self.config.monitor_storage:
            scripts.append(("storage_hook", _FRIDA_STORAGE_HOOK))

        return scripts

    # ------------------------------------------------------------------
    # Frida phase
    # ------------------------------------------------------------------

    def _run_frida_phase(
        self,
        result: DynamicAnalysisResult,
        scripts: List[Tuple[str, str]],
        package: str,
        device_id: str,
    ) -> None:
        """Inject and run each Frida script; aggregate output into result."""

        # Try frida_wrapper first
        if frida_wrapper is not None:
            for name, js_code in scripts:
                try:
                    frida_result = frida_wrapper.inject_script_content(
                        package_name=package,
                        script_content=js_code,
                        device_id=device_id,
                        timeout=min(self.config.timeout, 30),
                    )
                    parsed = self._parse_frida_result(name, frida_result)
                    result.frida_script_results.append(parsed)
                    self._aggregate_frida_findings(result, name, parsed)
                except Exception as exc:
                    logger.debug("frida_wrapper.inject_script_content failed for %s: %s", name, exc)
                    # Fall back to subprocess frida
                    self._run_frida_subprocess(result, name, js_code, package, device_id)
        else:
            # Use subprocess frida directly
            for name, js_code in scripts:
                self._run_frida_subprocess(result, name, js_code, package, device_id)

    def _run_frida_subprocess(
        self,
        result: DynamicAnalysisResult,
        name: str,
        js_code: str,
        package: str,
        device_id: str,
    ) -> None:
        """Run a Frida script via subprocess frida CLI."""
        if not self._frida_path:
            return

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
                f.write(js_code)
                script_path = f.name

            cmd = [self._frida_path, "-U", "-f", package, "-l", script_path, "--no-pause"]
            if device_id and ":" in device_id:
                cmd = [self._frida_path, "-H", device_id, "-f", package, "-l", script_path, "--no-pause"]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=min(self.config.timeout, 25),
            )
            os.unlink(script_path)

            output = proc.stdout + proc.stderr
            parsed = self._parse_frida_text_output(name, output)
            result.frida_script_results.append(parsed)
            self._aggregate_frida_findings(result, name, parsed)

        except subprocess.TimeoutExpired:
            logger.debug("Frida script %s timed out", name)
        except FileNotFoundError:
            logger.debug("frida binary not found")
        except Exception as exc:
            logger.debug("Frida subprocess error (%s): %s", name, exc)
        finally:
            try:
                if "script_path" in locals() and os.path.exists(script_path):
                    os.unlink(script_path)
            except Exception:
                pass

    def _parse_frida_result(self, script_name: str, frida_result: Any) -> Dict:
        """Parse FridaResult object (from frida_wrapper) into a plain dict."""
        if frida_result is None:
            return {"script": script_name, "messages": [], "error": "no result"}

        if hasattr(frida_result, "messages"):
            return {
                "script": script_name,
                "messages": list(frida_result.messages or []),
                "error": getattr(frida_result, "error", None),
            }

        # Already a dict
        if isinstance(frida_result, dict):
            frida_result["script"] = script_name
            return frida_result

        return {"script": script_name, "raw": str(frida_result)}

    def _parse_frida_text_output(self, script_name: str, output: str) -> Dict:
        """Parse raw Frida CLI text output into structured dict."""
        messages: List[Dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Try JSON messages sent via send()
            if "{" in line and "}" in line:
                start = line.find("{")
                try:
                    msg = json.loads(line[start:])
                    messages.append(msg)
                    continue
                except json.JSONDecodeError:
                    pass
            messages.append({"raw": line})
        return {"script": script_name, "messages": messages, "raw_output": output[:2000]}

    def _aggregate_frida_findings(
        self, result: DynamicAnalysisResult, script_name: str, parsed: Dict
    ) -> None:
        """Aggregate structured Frida messages into result data structures."""
        for msg in parsed.get("messages", []):
            if not isinstance(msg, dict):
                continue
            msg_type = msg.get("type", "")

            if msg_type == "ssl_bypass":
                result.ssl_bypassed = True
                result.runtime_findings.append({
                    "type": "ssl_pinning_bypass",
                    "message": msg.get("message", ""),
                    "tool": "frida",
                })

            elif msg_type == "root_bypass":
                result.root_bypassed = True
                result.runtime_findings.append({
                    "type": "root_detection_bypass",
                    "message": msg.get("message", ""),
                    "tool": "frida",
                })

            elif msg_type == "network":
                result.network_traffic.append({
                    "url": msg.get("url", ""),
                    "method": msg.get("method", ""),
                    "tool": "frida_network_hook",
                })

            elif msg_type in ("network_response",):
                result.network_traffic.append({
                    "url": msg.get("url", ""),
                    "status": msg.get("status", ""),
                    "tool": "frida_network_hook",
                })

            elif msg_type == "crypto":
                result.crypto_operations.append({
                    "algorithm": msg.get("algorithm", ""),
                    "operation": msg.get("operation", ""),
                    "tool": "frida_crypto_hook",
                })

            elif msg_type == "storage":
                result.storage_operations.append({
                    "key": msg.get("key", ""),
                    "storage": msg.get("storage", ""),
                    "value_length": msg.get("value_length", 0),
                    "tool": "frida_storage_hook",
                })

            elif msg_type == "file_write":
                result.storage_operations.append({
                    "path": msg.get("path", ""),
                    "storage": "FileOutputStream",
                    "tool": "frida_storage_hook",
                })

    # ------------------------------------------------------------------
    # Objection phase
    # ------------------------------------------------------------------

    def _run_objection_phase(
        self,
        result: DynamicAnalysisResult,
        package: str,
        device_id: str,
    ) -> None:
        """Run Objection-based analysis and integrate findings."""
        ow = objection_wrapper

        # Runtime analysis (SSL bypass, root bypass, keystore, prefs, cookies)
        try:
            findings: List[UnifiedFinding] = ow.analyze_runtime(package, device_id=device_id)
            result.all_findings.extend(findings)

            # Propagate bypass status
            for f in findings:
                if f.finding_type == "ssl_pinning_bypass":
                    result.ssl_bypassed = True
                elif f.finding_type == "root_detection_bypass":
                    result.root_bypassed = True
        except Exception as exc:
            logger.debug("objection.analyze_runtime: %s", exc)

        # Dump keystore
        try:
            keystore = ow.dump_keystore(package, device_id=device_id)
            for entry in keystore:
                result.storage_operations.append({
                    "storage": "AndroidKeystore",
                    "alias": entry.get("alias", ""),
                    "accessible": entry.get("accessible", False),
                    "type": entry.get("type", ""),
                })
        except Exception as exc:
            logger.debug("objection.dump_keystore: %s", exc)

        # List shared prefs
        try:
            prefs = ow.list_shared_prefs(package, device_id=device_id)
            _sensitive = re.compile(
                r"(password|passwd|token|secret|key|auth|credential|pin)", re.I
            )
            for pref in prefs:
                if _sensitive.search(pref.get("key", "")):
                    result.storage_operations.append({
                        "storage": "SharedPreferences",
                        "file": pref.get("file", ""),
                        "key": pref.get("key", ""),
                        "sensitive": True,
                    })
        except Exception as exc:
            logger.debug("objection.list_shared_prefs: %s", exc)

    # ------------------------------------------------------------------
    # RMS phase
    # ------------------------------------------------------------------

    def _run_rms_phase(
        self,
        result: DynamicAnalysisResult,
        package: str,
        device_id: str,
    ) -> None:
        """Run RMS (Runtime Mobile Security) analysis."""
        rw = rms_wrapper
        if rw is None:
            return

        try:
            rms_result = rw.run_full_analysis(package_name=package, device_id=device_id)
            if isinstance(rms_result, dict):
                result.runtime_findings.extend(rms_result.get("findings", []))
                result.network_traffic.extend(rms_result.get("network", []))
                result.crypto_operations.extend(rms_result.get("crypto", []))
            logger.debug("RMS analysis complete for %s", package)
        except Exception as exc:
            logger.warning("RMS analysis failed for %s: %s", package, exc)

    # ------------------------------------------------------------------
    # Simulation (no device)
    # ------------------------------------------------------------------

    def _simulate_without_device(self, result: DynamicAnalysisResult) -> None:
        """
        When no device is connected, generate informational/theoretical findings
        based on static knowledge of common mobile vulnerabilities.
        """
        result.all_findings.append(UnifiedFinding(
            title="Dynamic Analysis Requires Connected Device",
            severity="info",
            finding_type="no_device",
            tool="mobile_dynamic_analyzer",
            package=result.package_name,
            description=(
                "No Android device or emulator was detected. "
                "Dynamic analysis (Frida hooks, SSL bypass, runtime behavior) was skipped. "
                "Connect a device via ADB or start an emulator to enable full dynamic analysis."
            ),
            recommendation=(
                "1. Connect a physical device with USB debugging enabled, OR\n"
                "2. Start an Android emulator: `emulator -avd <AVD_NAME>`\n"
                "3. Ensure frida-server is running on the device: `adb shell /data/local/tmp/frida-server &`\n"
                "4. Re-run dynamic analysis."
            ),
        ))

        # Theoretical findings based on common mobile patterns
        theoretical_findings = [
            UnifiedFinding(
                title="[Theoretical] SSL Certificate Pinning May Be Bypassable",
                severity="medium",
                finding_type="ssl_pinning_theoretical",
                tool="mobile_dynamic_analyzer",
                package=result.package_name,
                description=(
                    "Without dynamic analysis, it is unknown whether SSL pinning is implemented. "
                    "Many apps implement weak or bypassable pinning. "
                    "Connect a device and run Frida SSL bypass scripts to verify."
                ),
                recommendation="Implement certificate pinning using network-security-config.xml or TrustKit.",
                cwe="CWE-295",
            ),
            UnifiedFinding(
                title="[Theoretical] Root/Jailbreak Detection Status Unknown",
                severity="info",
                finding_type="root_detection_theoretical",
                tool="mobile_dynamic_analyzer",
                package=result.package_name,
                description=(
                    "Root detection capability could not be verified without a connected device. "
                    "Apps without root detection run unmodified on compromised devices."
                ),
                recommendation="Implement multi-layered root detection and anti-tampering controls.",
                cwe="CWE-693",
            ),
            UnifiedFinding(
                title="[Theoretical] Runtime Crypto Strength Unverified",
                severity="info",
                finding_type="crypto_unverified_theoretical",
                tool="mobile_dynamic_analyzer",
                package=result.package_name,
                description=(
                    "Cryptographic operations could not be monitored at runtime. "
                    "Static analysis may miss dynamically constructed weak algorithms."
                ),
                recommendation="Instrument the app with Frida crypto hooks to verify algorithm strength at runtime.",
                cwe="CWE-327",
            ),
        ]
        result.all_findings.extend(theoretical_findings)
        logger.info("Generated %d theoretical findings (no device)", len(theoretical_findings))

    # ------------------------------------------------------------------
    # Synthesize findings from collected runtime data
    # ------------------------------------------------------------------

    def _synthesize_findings(self, result: DynamicAnalysisResult) -> None:
        """Convert raw runtime observations into UnifiedFinding objects."""

        # SSL bypass
        if result.ssl_bypassed:
            result.all_findings.append(UnifiedFinding(
                title="SSL Certificate Pinning Successfully Bypassed",
                severity="high",
                finding_type="ssl_pinning_bypass",
                tool="frida/objection",
                package=result.package_name,
                description=(
                    "Certificate pinning was bypassed at runtime using Frida/Objection. "
                    "An attacker with a rooted device can intercept all HTTPS traffic."
                ),
                recommendation=(
                    "Strengthen pinning implementation; detect Frida/Magisk presence; "
                    "use multi-level pinning (leaf + intermediate + root)."
                ),
                cwe="CWE-295",
                cvss_score=7.5,
            ))

        # Root bypass
        if result.root_bypassed:
            result.all_findings.append(UnifiedFinding(
                title="Root/Jailbreak Detection Bypassed",
                severity="medium",
                finding_type="root_detection_bypass",
                tool="frida/objection",
                package=result.package_name,
                description=(
                    "Root/jailbreak detection was successfully bypassed. "
                    "Tampered devices can execute the app without restriction."
                ),
                recommendation="Use multiple independent detection mechanisms; obfuscate detection logic; use SafetyNet/Play Integrity API.",
                cwe="CWE-693",
                cvss_score=5.5,
            ))

        # Weak crypto
        seen_weak: set = set()
        for op in result.crypto_operations:
            algo = op.get("algorithm", "").upper()
            for weak in _WEAK_ALGOS:
                if weak in algo and algo not in seen_weak:
                    seen_weak.add(algo)
                    result.all_findings.append(UnifiedFinding(
                        title=f"Weak Cryptographic Algorithm Detected: {algo}",
                        severity="medium",
                        finding_type="weak_crypto",
                        tool="frida_crypto_hook",
                        package=result.package_name,
                        description=f"Runtime monitoring detected use of weak algorithm: {algo}.",
                        evidence=f"Operation: {op.get('operation', '?')}",
                        recommendation=f"Replace {algo} with AES-256-GCM (symmetric) or RSA-2048/ECDSA-256 (asymmetric).",
                        cwe="CWE-327",
                        cvss_score=4.3,
                    ))

        # Cleartext network
        seen_cleartext: set = set()
        for req in result.network_traffic:
            url = req.get("url", "")
            if url.startswith("http://") and url not in seen_cleartext:
                seen_cleartext.add(url)
                result.all_findings.append(UnifiedFinding(
                    title="Cleartext HTTP Traffic Detected at Runtime",
                    severity="high",
                    finding_type="cleartext_network",
                    tool="frida_network_hook",
                    package=result.package_name,
                    description=f"Unencrypted HTTP request observed: {url[:120]}",
                    evidence=f"URL: {url}",
                    recommendation="Migrate all endpoints to HTTPS; set android:usesCleartextTraffic=false.",
                    cwe="CWE-319",
                    cvss_score=6.5,
                ))

        # Sensitive storage
        sensitive_prefs = [s for s in result.storage_operations
                           if s.get("sensitive") and s.get("storage") == "SharedPreferences"]
        if sensitive_prefs:
            sample = "; ".join(s.get("key", "?") for s in sensitive_prefs[:5])
            result.all_findings.append(UnifiedFinding(
                title="Sensitive Data Written to SharedPreferences at Runtime",
                severity="medium",
                finding_type="insecure_storage_sharedprefs",
                tool="frida_storage_hook",
                package=result.package_name,
                description="Runtime monitoring detected sensitive keys being written to SharedPreferences in plaintext.",
                evidence=f"Keys observed: {sample}",
                recommendation="Use EncryptedSharedPreferences (Jetpack Security) for sensitive values.",
                cwe="CWE-312",
                cvss_score=5.3,
            ))

    # ------------------------------------------------------------------
    # ADB utilities
    # ------------------------------------------------------------------

    def get_adb_devices(self) -> List[Dict]:
        """Return list of connected ADB devices as dicts with 'serial' and 'type' keys."""
        if not self._adb_path:
            return []

        try:
            result = subprocess.run(
                [self._adb_path, "devices"],
                capture_output=True, text=True, timeout=10,
            )
        except Exception as exc:
            logger.debug("adb devices error: %s", exc)
            return []

        devices: List[Dict] = []
        for line in result.stdout.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                serial, state = parts[0].strip(), parts[1].strip()
                if state == "device":
                    dev_type = "emulator" if serial.startswith("emulator-") else "physical"
                    devices.append({"serial": serial, "type": dev_type, "state": state})
        return devices

    def launch_app(self, package: str, device_id: str = "") -> bool:
        """Launch an installed app via `adb shell monkey`. Returns True on success."""
        if not self._adb_path:
            return False

        cmd = [self._adb_path]
        if device_id:
            cmd += ["-s", device_id]
        cmd += ["shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0
        except Exception as exc:
            logger.debug("launch_app error: %s", exc)
            return False

    def get_logcat(
        self,
        package: str,
        device_id: str = "",
        duration: int = 30,
    ) -> List[str]:
        """
        Capture logcat output for *package* for up to *duration* seconds.
        Returns list of log lines.
        """
        if not self._adb_path:
            return []

        # Get PID first
        pid = self._get_pid(package, device_id)

        cmd = [self._adb_path]
        if device_id:
            cmd += ["-s", device_id]
        cmd += ["logcat", "-d", "-v", "brief", "*:W"]
        if pid:
            cmd += ["--pid", pid]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
            return result.stdout.splitlines()
        except subprocess.TimeoutExpired:
            return []
        except Exception as exc:
            logger.debug("get_logcat error: %s", exc)
            return []

    def _get_pid(self, package: str, device_id: str) -> str:
        """Return PID string for package, or empty string."""
        if not self._adb_path:
            return ""

        cmd = [self._adb_path]
        if device_id:
            cmd += ["-s", device_id]
        cmd += ["shell", "pidof", package]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.stdout.strip().split()[0] if result.stdout.strip() else ""
        except Exception:
            return ""


# Module-level singleton
mobile_dynamic_analyzer = MobileDynamicAnalyzer()
