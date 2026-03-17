"""
Mobile Dynamic Analyzer — Frida/Objection integration, ADB emulator control,
SSL pinning detection, runtime behavior analysis, network traffic capture.
"""

import re
import os
import json
import shutil
import asyncio
import logging
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DynamicFinding:
    finding_type: str
    severity: str
    detail: str
    evidence: str = ""
    tool: str = ""

    def to_dict(self):
        return self.__dict__.copy()


@dataclass
class DynamicAnalysisResult:
    app_id: str
    package_name: str
    device_id: str = ""
    frida_available: bool = False
    adb_available: bool = False
    ssl_pinning_detected: bool = False
    ssl_pinning_bypassed: bool = False
    root_detection_detected: bool = False
    root_detection_bypassed: bool = False
    emulator_detection_detected: bool = False
    runtime_permissions: list = field(default_factory=list)
    network_requests: list = field(default_factory=list)
    crypto_operations: list = field(default_factory=list)
    file_operations: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    logcat_output: str = ""
    frida_hooks_output: str = ""
    errors: list = field(default_factory=list)

    def to_dict(self):
        return {
            "app_id": self.app_id,
            "package_name": self.package_name,
            "device_id": self.device_id,
            "frida_available": self.frida_available,
            "adb_available": self.adb_available,
            "ssl_pinning_detected": self.ssl_pinning_detected,
            "ssl_pinning_bypassed": self.ssl_pinning_bypassed,
            "root_detection_detected": self.root_detection_detected,
            "root_detection_bypassed": self.root_detection_bypassed,
            "emulator_detection_detected": self.emulator_detection_detected,
            "runtime_permissions": self.runtime_permissions,
            "network_requests": self.network_requests,
            "crypto_operations": self.crypto_operations,
            "file_operations": self.file_operations,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


# Frida scripts
FRIDA_SSL_BYPASS_SCRIPT = """
Java.perform(function() {
    // Bypass TrustManager
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
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
            this.init(km, [TrustManager.$new()], sr);
            send({type: 'ssl_bypass', message: 'SSLContext.init overridden'});
        };

    // Bypass OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(h, c) {
            send({type: 'ssl_bypass', message: 'OkHttp cert pinning bypassed for: ' + h});
        };
    } catch(e) {}

    // Bypass TrustKit
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(h, s) {
            return true;
        };
    } catch(e) {}

    send({type: 'status', message: 'SSL pinning bypass loaded'});
});
"""

FRIDA_ROOT_BYPASS_SCRIPT = """
Java.perform(function() {
    // Bypass RootBeer / common root checks
    var paths = ['/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
                 '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su'];
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        for (var i = 0; i < paths.length; i++) {
            if (name === paths[i]) {
                send({type: 'root_bypass', message: 'Blocked File.exists for: ' + name});
                return false;
            }
        }
        return this.exists();
    };

    // Runtime.exec su
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd === 'su' || cmd.indexOf('su ') >= 0) {
            send({type: 'root_bypass', message: 'Blocked Runtime.exec su'});
            throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.exec(cmd);
    };
    send({type: 'status', message: 'Root detection bypass loaded'});
});
"""

FRIDA_NETWORK_HOOK_SCRIPT = """
Java.perform(function() {
    // Hook URL.openConnection
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        send({type: 'network', url: this.toString(), method: 'openConnection'});
        return this.openConnection();
    };

    // Hook OkHttp
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.url.overload('java.lang.String').implementation = function(url) {
            send({type: 'network', url: url, method: 'okhttp'});
            return this.url(url);
        };
    } catch(e) {}

    // Hook HttpURLConnection
    try {
        var HttpURLConn = Java.use('java.net.HttpURLConnection');
        HttpURLConn.getResponseCode.implementation = function() {
            send({type: 'network_response', url: this.getURL().toString(), status: this.getResponseCode()});
            return this.getResponseCode();
        };
    } catch(e) {}

    send({type: 'status', message: 'Network hooks loaded'});
});
"""

FRIDA_CRYPTO_HOOK_SCRIPT = """
Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
        send({type: 'crypto', algorithm: algo, operation: 'getInstance'});
        return this.getInstance(algo);
    };

    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
        send({type: 'crypto', algorithm: algo, operation: 'digest'});
        return this.getInstance(algo);
    };

    send({type: 'status', message: 'Crypto hooks loaded'});
});
"""


class MobileDynamicAnalyzer:

    def __init__(self):
        self.adb = shutil.which("adb")
        self.frida = shutil.which("frida")
        self.objection = shutil.which("objection")

    def analyze(self, app_id: str, package_name: str, apk_path: str = None,
                device_id: str = None, timeout: int = 60) -> DynamicAnalysisResult:
        result = DynamicAnalysisResult(app_id=app_id, package_name=package_name)
        result.adb_available = bool(self.adb)
        result.frida_available = bool(self.frida)

        if not self.adb:
            result.errors.append("adb not found — install Android SDK platform-tools")
            result.findings.append(DynamicFinding(
                finding_type="tool_missing", severity="info",
                detail="Dynamic analysis skipped: adb not available",
                tool="adb"
            ))
            return result

        # Get device
        device_id = device_id or self._get_device()
        if not device_id:
            result.errors.append("No Android device/emulator connected")
            result.findings.append(DynamicFinding(
                finding_type="no_device", severity="info",
                detail="No Android device found. Connect a device or start an emulator.",
                tool="adb"
            ))
            return result

        result.device_id = device_id

        # Install APK if provided
        if apk_path and os.path.exists(apk_path):
            self._install_apk(apk_path, device_id, result)

        # Check if app is installed
        if not self._is_installed(package_name, device_id):
            result.errors.append(f"Package {package_name} not installed on device")
            return result

        # Launch app
        self._launch_app(package_name, device_id, result)
        time.sleep(3)  # Give app time to start

        # Logcat analysis
        self._collect_logcat(package_name, device_id, result, timeout=min(timeout, 30))

        # Frida-based analysis
        if self.frida:
            self._run_frida_analysis(package_name, device_id, result, timeout=timeout)
        elif self.objection:
            self._run_objection_analysis(package_name, device_id, result)

        # Static dynamic checks (permissions granted at runtime)
        self._check_runtime_permissions(package_name, device_id, result)

        # Generate findings from collected data
        self._analyze_results(result)

        return result

    def _get_device(self) -> Optional[str]:
        try:
            r = subprocess.run([self.adb, "devices"], capture_output=True, text=True, timeout=10)
            for line in r.stdout.split("\n")[1:]:
                if "\tdevice" in line:
                    return line.split("\t")[0].strip()
        except Exception:
            pass
        return None

    def _is_installed(self, package: str, device_id: str) -> bool:
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "shell", "pm", "list", "packages", package],
                capture_output=True, text=True, timeout=10
            )
            return f"package:{package}" in r.stdout
        except Exception:
            return False

    def _install_apk(self, apk_path: str, device_id: str, result: DynamicAnalysisResult):
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "install", "-r", apk_path],
                capture_output=True, text=True, timeout=120
            )
            if r.returncode != 0:
                result.errors.append(f"APK install failed: {r.stderr[:200]}")
        except Exception as e:
            result.errors.append(f"APK install error: {e}")

    def _launch_app(self, package: str, device_id: str, result: DynamicAnalysisResult):
        try:
            subprocess.run(
                [self.adb, "-s", device_id, "shell", "monkey", "-p", package,
                 "-c", "android.intent.category.LAUNCHER", "1"],
                capture_output=True, timeout=15
            )
        except Exception as e:
            result.errors.append(f"App launch error: {e}")

    def _collect_logcat(self, package: str, device_id: str, result: DynamicAnalysisResult, timeout: int = 30):
        try:
            # Get PID
            pid_r = subprocess.run(
                [self.adb, "-s", device_id, "shell", "pidof", package],
                capture_output=True, text=True, timeout=5
            )
            pid = pid_r.stdout.strip()

            cmd = [self.adb, "-s", device_id, "logcat", "-d"]
            if pid:
                cmd += ["--pid", pid]
            cmd += ["-v", "brief", "*:W"]

            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            result.logcat_output = r.stdout[:10000]

            # Analyze logcat for sensitive data
            self._analyze_logcat(result)
        except Exception as e:
            result.errors.append(f"Logcat error: {e}")

    def _analyze_logcat(self, result: DynamicAnalysisResult):
        log = result.logcat_output
        patterns = [
            (r'password[=:]\s*\S+', "Password in logcat", "critical"),
            (r'token[=:]\s*[A-Za-z0-9_\-\.]{20,}', "Token in logcat", "high"),
            (r'Authorization:\s*Bearer\s+\S+', "Bearer token in logcat", "high"),
            (r'https?://[a-zA-Z0-9\-\.]+/[^\s]+', "URL in logcat", "info"),
            (r'ssl error', "SSL error logged", "medium"),
            (r'Certificate.*invalid', "Certificate error logged", "medium"),
            (r'javax\.net\.ssl.*Exception', "SSL Exception", "medium"),
        ]
        for pat, label, sev in patterns:
            for m in re.finditer(pat, log, re.I):
                result.findings.append(DynamicFinding(
                    finding_type="logcat_leak", severity=sev,
                    detail=label, evidence=m.group(0)[:100], tool="logcat"
                ))
                break  # One finding per type

    def _run_frida_analysis(self, package: str, device_id: str, result: DynamicAnalysisResult, timeout: int = 60):
        """Run Frida hooks and collect output."""
        scripts = [
            ("ssl_bypass", FRIDA_SSL_BYPASS_SCRIPT),
            ("root_bypass", FRIDA_ROOT_BYPASS_SCRIPT),
            ("network_hook", FRIDA_NETWORK_HOOK_SCRIPT),
            ("crypto_hook", FRIDA_CRYPTO_HOOK_SCRIPT),
        ]

        combined_output = []
        for script_name, script_code in scripts:
            output = self._run_frida_script(package, device_id, script_code, timeout=min(timeout, 20))
            if output:
                combined_output.append(f"=== {script_name} ===\n{output}")
                self._parse_frida_output(script_name, output, result)

        result.frida_hooks_output = "\n".join(combined_output)[:5000]

    def _run_frida_script(self, package: str, device_id: str, script: str, timeout: int = 20) -> str:
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script)
                script_path = f.name

            cmd = [self.frida, "-U", "-f", package, "-l", script_path, "--no-pause", "--runtime=v8"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            os.unlink(script_path)
            return r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            return f"Script timed out after {timeout}s"
        except Exception as e:
            return f"Frida error: {e}"

    def _parse_frida_output(self, script_name: str, output: str, result: DynamicAnalysisResult):
        try:
            for line in output.split("\n"):
                if not line.strip():
                    continue
                # Try JSON messages
                if "{" in line and "}" in line:
                    start = line.find("{")
                    try:
                        msg = json.loads(line[start:])
                        msg_type = msg.get("type", "")
                        if msg_type == "ssl_bypass":
                            result.ssl_pinning_detected = True
                            result.ssl_pinning_bypassed = True
                        elif msg_type == "root_bypass":
                            result.root_detection_detected = True
                            result.root_detection_bypassed = True
                        elif msg_type == "network":
                            result.network_requests.append(msg)
                        elif msg_type == "crypto":
                            result.crypto_operations.append(msg)
                    except json.JSONDecodeError:
                        pass

                # Text-based detection
                if "ssl" in line.lower() and ("pin" in line.lower() or "bypass" in line.lower()):
                    result.ssl_pinning_detected = True
                if "error" in line.lower() and "ssl" in line.lower():
                    result.ssl_pinning_detected = True
        except Exception:
            pass

    def _run_objection_analysis(self, package: str, device_id: str, result: DynamicAnalysisResult):
        """Run objection for basic analysis when frida-python is not directly available."""
        try:
            # Check SSL pinning
            r = subprocess.run(
                [self.objection, "--gadget", package, "explore", "--startup-command",
                 "android sslpinning disable"],
                capture_output=True, text=True, timeout=30
            )
            if "ssl" in r.stdout.lower() or "pin" in r.stdout.lower():
                result.ssl_pinning_detected = True
                result.ssl_pinning_bypassed = "disabled" in r.stdout.lower()
        except Exception as e:
            result.errors.append(f"Objection error: {e}")

    def _check_runtime_permissions(self, package: str, device_id: str, result: DynamicAnalysisResult):
        try:
            r = subprocess.run(
                [self.adb, "-s", device_id, "shell", "dumpsys", "package", package],
                capture_output=True, text=True, timeout=15
            )
            output = r.stdout
            for m in re.finditer(r'(android\.permission\.\w+):\s*granted=true', output):
                result.runtime_permissions.append(m.group(1))
        except Exception as e:
            result.errors.append(f"Permission check error: {e}")

    def _analyze_results(self, result: DynamicAnalysisResult):
        if result.ssl_pinning_detected and not result.ssl_pinning_bypassed:
            result.findings.append(DynamicFinding(
                finding_type="ssl_pinning", severity="info",
                detail="SSL/Certificate pinning detected but not bypassed — manual bypass may be needed",
                tool="frida"
            ))
        elif result.ssl_pinning_detected and result.ssl_pinning_bypassed:
            result.findings.append(DynamicFinding(
                finding_type="ssl_pinning_bypassed", severity="medium",
                detail="SSL pinning successfully bypassed — MITM traffic interception is possible",
                tool="frida"
            ))

        if result.root_detection_detected:
            result.findings.append(DynamicFinding(
                finding_type="root_detection", severity="info",
                detail=f"Root/jailbreak detection {'bypassed' if result.root_detection_bypassed else 'detected'}",
                tool="frida"
            ))

        # Weak crypto
        weak_algos = {"DES", "RC4", "MD5", "SHA1", "ECB"}
        for op in result.crypto_operations:
            algo = op.get("algorithm", "")
            if any(w in algo.upper() for w in weak_algos):
                result.findings.append(DynamicFinding(
                    finding_type="weak_crypto", severity="medium",
                    detail=f"Weak cryptographic algorithm detected: {algo}",
                    tool="frida"
                ))

        # Cleartext network
        for req in result.network_requests:
            url = req.get("url", "")
            if url.startswith("http://"):
                result.findings.append(DynamicFinding(
                    finding_type="cleartext_network", severity="high",
                    detail=f"Cleartext HTTP request detected: {url[:100]}",
                    evidence=url, tool="frida"
                ))


mobile_dynamic_analyzer = MobileDynamicAnalyzer()
