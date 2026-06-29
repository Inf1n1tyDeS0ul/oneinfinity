"""
APKleaks Wrapper — Scanning APK file for URIs, endpoints and secrets.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional
from .tool_registry import tool_registry, UnifiedFinding
from oneinfinity.core.path_resolver import get_tool_binary as _get_tb

logger = logging.getLogger(__name__)

_VENV_APKLEAKS = _get_tb('apkleaks') or 'apkleaks'

# APKleaks category → (vuln_type, severity)
_CATEGORY_SEVERITY: Dict[str, tuple] = {
    "AWS":              ("secret_exposure", "critical"),
    "google_api":       ("secret_exposure", "high"),
    "firebase":         ("secret_exposure", "high"),
    "secret":           ("secret_exposure", "high"),
    "api_key":          ("secret_exposure", "high"),
    "password":         ("secret_exposure", "high"),
    "token":            ("secret_exposure", "high"),
    "private_key":      ("secret_exposure", "critical"),
    "certificate":      ("secret_exposure", "high"),
    "endpoint":         ("url_disclosure", "medium"),
    "url":              ("url_disclosure", "low"),
    "ip":               ("url_disclosure", "low"),
    "email":            ("info_disclosure", "low"),
}


def _find_apkleaks_bin() -> str:
    """Locate apkleaks binary: venv → registry → PATH."""
    if os.path.isfile(_VENV_APKLEAKS) and os.access(_VENV_APKLEAKS, os.X_OK):
        return _VENV_APKLEAKS
    t = tool_registry.get_tool("apkleaks")
    if t and t.is_available() and t.binary_path:
        return t.binary_path
    import shutil
    found = shutil.which("apkleaks")
    if found:
        return found
    return "apkleaks"  # let subprocess fail with a clear error


class APKleaksWrapper:
    """Wrapper for APKleaks CLI."""

    def __init__(self):
        self.tool_name = "apkleaks"
        self._bin = _find_apkleaks_bin()

    def analyze(self, apk_path: str, output_dir: Optional[str] = None) -> List[UnifiedFinding]:
        """Run apkleaks on the given APK and return normalised UnifiedFinding list."""
        if not os.path.exists(apk_path):
            logger.error("APK file not found: %s", apk_path)
            return []

        out_file = None
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            out_file = os.path.join(output_dir, f"apkleaks_{Path(apk_path).stem}.json")

        cmd = [self._bin, "-f", apk_path, "--json"]
        if out_file:
            cmd.extend(["-o", out_file])

        logger.info("Running apkleaks: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # Large APKs can take 3-5 min for JADX decompilation
            )
            rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            logger.error("apkleaks timed out for %s", apk_path)
            return []
        except FileNotFoundError:
            logger.error("apkleaks binary not found at %s", self._bin)
            return []

        findings: List[UnifiedFinding] = []
        raw_data: dict = {}

        try:
            if out_file and os.path.exists(out_file):
                raw_data = json.loads(Path(out_file).read_text())
            else:
                json_start = stdout.find('{')
                if json_start != -1:
                    raw_data = json.loads(stdout[json_start:])
        except (json.JSONDecodeError, ValueError) as e:
            logger.error("Failed to parse apkleaks output: %s", e)

        for category, items in raw_data.items():
            if not isinstance(items, list):
                continue
            cat_lower = category.lower()
            # Determine severity and vuln_type from category
            vuln_type, severity = ("secret_exposure", "high")
            for key, (vt, sev) in _CATEGORY_SEVERITY.items():
                if key in cat_lower:
                    vuln_type, severity = vt, sev
                    break
            # Escalate to critical for private keys and AWS credentials
            if any(k in cat_lower for k in ("private_key", "aws", "rsa", "pem")):
                severity = "critical"

            for item in items:
                evidence = str(item)
                findings.append(UnifiedFinding(
                    target=Path(apk_path).name,
                    vulnerability=f"APKleaks: {category}",
                    attack_type=vuln_type,
                    tool="apkleaks",
                    severity=severity,
                    evidence=evidence[:500],
                    remediation=(
                        "Remove hardcoded secrets from the APK. "
                        "Use Android Keystore or environment-based secret injection. "
                        "Rotate any exposed credentials immediately."
                    ),
                    confidence=0.80,
                    cvss=9.0 if severity == "critical" else 7.5 if severity == "high" else 5.0,
                    tags=["apkleaks", vuln_type, "static"],
                ))

        logger.info("apkleaks: %d findings from %s", len(findings), apk_path)
        return findings


def run_apkleaks(apk_path: str, output_dir: Optional[str] = None) -> List[UnifiedFinding]:
    """
    Convenience function: scan an APK with apkleaks and return findings.

    Parameters
    ----------
    apk_path:
        Path to the APK file to analyse.
    output_dir:
        Optional directory to write the JSON report.  Uses a temp path if omitted.

    Returns
    -------
    List of UnifiedFinding with vuln_type='secret_exposure'/'url_disclosure',
    severity='high'/'critical', evidence=matched_string.
    """
    wrapper = APKleaksWrapper()
    return wrapper.analyze(apk_path, output_dir)


mobile_apkleaks = APKleaksWrapper()
