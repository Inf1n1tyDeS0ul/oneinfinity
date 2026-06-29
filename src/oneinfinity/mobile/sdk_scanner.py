from __future__ import annotations
import os
import logging
from typing import List
from oneinfinity.mobile.tool_registry import UnifiedFinding

logger = logging.getLogger(__name__)

# Mock vulnerability database for MVP
VULNERABLE_SDKS = [
    {
        "id": "okhttp3",
        "pattern": "com/squareup/okhttp3",
        "vulnerability": "Vulnerable SDK: OkHttp (pre-3.12.0)",
        "description": "Detected OkHttp SDK version with known TLS/SSL vulnerabilities. Older versions (pre-3.12.0) are prone to MITM and lack modern security defaults.",
        "severity": "medium",
        "attack_type": "vulnerable_sdk",
        "remediation": "Update OkHttp to version 3.12.0 or higher. For full TLS 1.3 support, upgrade to 4.x."
    },
    {
        "id": "retrofit2",
        "pattern": "com/squareup/retrofit2",
        "vulnerability": "Vulnerable SDK: Retrofit",
        "description": "Detected Retrofit SDK. Ensure it is not using an outdated version with known vulnerabilities.",
        "severity": "low",
        "attack_type": "vulnerable_sdk",
        "remediation": "Update Retrofit to the latest stable version."
    },
    {
        "id": "fastjson",
        "pattern": "com/alibaba/fastjson",
        "vulnerability": "Vulnerable SDK: Alibaba Fastjson",
        "description": "Detected Fastjson. Older versions have critical deserialization vulnerabilities that allow RCE.",
        "severity": "high",
        "attack_type": "rce_deserialization",
        "remediation": "Update Fastjson to >= 1.2.83 or switch to Jackson/Gson."
    }
]

class SDKScanner:
    """
    Scans mobile app extracted contents for vulnerable SDKs based on file patterns.
    """
    def __init__(self, extracted_dir: str):
        self.extracted_dir = extracted_dir

    def scan(self) -> List[UnifiedFinding]:
        findings = []
        if not self.extracted_dir or not os.path.exists(self.extracted_dir):
            logger.warning(f"SDKScanner: Extracted directory does not exist: {self.extracted_dir}")
            return findings

        # Basic pattern matching on directory structure (smali files)
        # In a real tool, we might parse build.gradle or pom.xml if available,
        # but for decompiled APKs, directory paths in smali/ are the best signal.
        
        found_patterns = set()
        
        for root, dirs, files in os.walk(self.extracted_dir):
            # Normalise path to use forward slashes for pattern matching
            rel_path = os.path.relpath(root, self.extracted_dir).replace(os.sep, "/")
            
            for sdk in VULNERABLE_SDKS:
                if sdk["pattern"] in rel_path:
                    if sdk["id"] not in found_patterns:
                        findings.append(UnifiedFinding(
                            target="mobile_app",
                            vulnerability=sdk["vulnerability"],
                            attack_type=sdk["attack_type"],
                            tool="sdk_scanner",
                            severity=sdk["severity"],
                            evidence=f"Detected pattern '{sdk['pattern']}' in {rel_path}",
                            file_path=rel_path,
                            remediation=sdk["remediation"],
                            confidence=0.8
                        ))
                        found_patterns.add(sdk["id"])
        
        logger.info(f"SDKScanner: Found {len(findings)} vulnerable SDKs")
        return findings

def scan_extracted_dir(extracted_dir: str, app_id: str = "") -> List[UnifiedFinding]:
    """Helper function for MobileSecurityEngine integration."""
    scanner = SDKScanner(extracted_dir)
    return scanner.scan()
