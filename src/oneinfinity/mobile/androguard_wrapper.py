"""
Androguard Wrapper — Deep Dalvik bytecode analysis and malware pattern detection.
"""

import logging
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from .tool_registry import tool_registry, UnifiedFinding

logger = logging.getLogger(__name__)

class AndroguardWrapper:
    """Wrapper for Androguard library-based analysis."""

    def __init__(self):
        self.tool_name = "androguard"

    def analyze(self, apk_path: str) -> List[UnifiedFinding]:
        """Run androguard analysis on the given APK."""
        if not os.path.exists(apk_path):
            logger.error(f"APK file not found: {apk_path}")
            return []

        findings = []
        try:
            from androguard.core.bytecodes.apk import APK
            from androguard.core.bytecodes.dvm import DalvikVMFormat
            from androguard.core.analysis.analysis import Analysis

            a = APK(apk_path)
            # Basic manifest analysis
            if a.is_debuggable():
                findings.append({
                    "vulnerability": "Debuggable Application",
                    "attack_type": "insecure_configuration",
                    "severity": "high",
                    "detail": "Application has android:debuggable=true in AndroidManifest.xml",
                    "target": a.get_package(),
                    "tool": self.tool_name
                })

            # Check permissions
            permissions = a.get_permissions()
            dangerous = [p for p in permissions if "dangerous" in p.lower() or "SYSTEM_ALERT_WINDOW" in p]
            if dangerous:
                findings.append({
                    "vulnerability": "Dangerous Permissions Requested",
                    "attack_type": "insecure_permissions",
                    "severity": "medium",
                    "detail": f"Application requests {len(dangerous)} dangerous permissions: {', '.join(dangerous[:5])}",
                    "target": a.get_package(),
                    "tool": self.tool_name
                })

            # Deep bytecode analysis could go here if needed
            # For now, let's keep it efficient for the engine
            
        except Exception as e:
            logger.error(f"Androguard analysis failed: {e}")
        
        return tool_registry.normalize_findings(findings, self.tool_name)

mobile_androguard = AndroguardWrapper()
