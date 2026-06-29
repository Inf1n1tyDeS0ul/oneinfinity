"""
Deep Link Fuzzer
================
Extracts deep links from manifest and performs fuzzing via ADB (Android).
Identifies vulnerabilities like Open Redirect, XSS via Deep Link, and DoS.
"""

import logging
import subprocess
import time
from typing import List, Dict, Optional
from oneinfinity.mobile.tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.deep_link_fuzzer")

class DeepLinkFuzzer:
    """
    Fuzzes Android Deep Links by launching them via ADB and monitoring for crashes or anomalies.
    """

    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id
        # Common fuzzing payloads for different vulnerability classes
        self.payloads = {
            "xss": [
                "<script>alert(1)</script>",
                "javascript:alert(1)",
                "\"'><img src=x onerror=alert(1)>",
            ],
            "open_redirect": [
                "https://evil.com",
                "//evil.com",
                "javascript:alert(1)",
            ],
            "sql_injection": [
                "' OR 1=1 --",
                "admin'--",
                "1' SLEEP(5) --",
            ],
            "path_traversal": [
                "../../../../etc/passwd",
                "/sdcard/DCIM/Camera/test.jpg",
                "file:///etc/passwd",
            ],
            "dos": [
                "A" * 5000,
                "%n" * 100,
                "0" * 1000,
            ]
        }

    def fuzz(self, package_name: str, deep_links: List[str]) -> List[UnifiedFinding]:
        """
        Perform fuzzing on a list of deep links for a given package.
        """
        if not self.device_id:
            logger.warning("[deep_link_fuzzer] No device ID provided. Skipping fuzzing.")
            return []

        if not deep_links:
            logger.info("[deep_link_fuzzer] No deep links found to fuzz.")
            return []

        findings: List[UnifiedFinding] = []
        logger.info(f"[deep_link_fuzzer] Starting fuzzing for {package_name} on {self.device_id}")

        for link in deep_links:
            # Handle different deep link formats (scheme://host or just scheme)
            base_link = link
            if "?" in link:
                base_link = link.split("?")[0]

            for attack_type, payloads in self.payloads.items():
                for payload in payloads:
                    # Test both as a parameter 'q' and 'url'
                    for param in ["q", "url", "redirect", "path", "id"]:
                        fuzzed_link = f"{base_link}?{param}={payload}"
                        
                        logger.debug(f"[deep_link_fuzzer] Testing: {fuzzed_link}")
                        success, output = self._launch_deep_link(fuzzed_link)
                        
                        # Wait a bit for the app to process the intent
                        time.sleep(1)
                        
                        if self._check_for_crash(package_name):
                            findings.append(UnifiedFinding(
                                target=package_name,
                                vulnerability="Deep Link Denial of Service (Crash)",
                                attack_type="dos",
                                tool="deep_link_fuzzer",
                                severity="medium",
                                evidence=f"App crashed when launching fuzzed deep link: {fuzzed_link}",
                                payload=payload,
                                confidence=0.8,
                                remediation="Validate all input parameters from deep links before processing. Use try-catch blocks."
                            ))
                            # If it crashed, we might need to restart or skip further fuzzing for this link
                            self._clear_app_data(package_name) # Try to recover
                            time.sleep(2)
                            break # Move to next attack type
                        
                        # Check logs for suspicious patterns
                        if self._check_logs_for_anomalies(payload):
                            findings.append(UnifiedFinding(
                                target=package_name,
                                vulnerability=f"Potential {attack_type.upper()} via Deep Link",
                                attack_type=attack_type,
                                tool="deep_link_fuzzer",
                                severity="high" if attack_type in ["xss", "sql_injection"] else "medium",
                                evidence=f"Suspicious activity detected in logs after launching: {fuzzed_link}",
                                payload=payload,
                                confidence=0.6,
                                remediation=f"Sanitize and validate deep link parameter '{param}' to prevent {attack_type}."
                            ))

        return findings

    def _launch_deep_link(self, link: str) -> (bool, str):
        """Launch a deep link via ADB."""
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(["shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", f"'{link}'"])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "ADB command timed out"
        except Exception as e:
            return False, str(e)

    def _check_for_crash(self, package_name: str) -> bool:
        """Check if the app has crashed or stopped responding."""
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(["shell", "pidof", package_name])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            # If pidof returns nothing, the app is not running
            if not result.stdout.strip():
                # Check logcat for recent FATAL EXCEPTIONs related to the package
                crash_cmd = ["adb"]
                if self.device_id:
                    crash_cmd.extend(["-s", self.device_id])
                crash_cmd.extend(["logcat", "-d", "*:E"])
                log_res = subprocess.run(crash_cmd, capture_output=True, text=True)
                if "FATAL EXCEPTION" in log_res.stdout and package_name in log_res.stdout:
                    return True
            return False
        except Exception:
            return False

    def _check_logs_for_anomalies(self, payload: str) -> bool:
        """Check logcat for the presence of the payload or error indicators."""
        # This is a very basic check. In reality, you'd look for SQL errors, 
        # JavaScript execution logs (if WebView), or file access errors.
        return False # Placeholder for more advanced log analysis

    def _clear_app_data(self, package_name: str):
        """Recover from a crash by clearing app data (optional/aggressive) or just stopping it."""
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(["shell", "am", "force-stop", package_name])
        subprocess.run(cmd, capture_output=True)

def mobile_deep_link_fuzzer(device_id: Optional[str] = None):
    return DeepLinkFuzzer(device_id=device_id)
