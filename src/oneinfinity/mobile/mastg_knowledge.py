"""
OWASP MASTG Knowledge Base & Mapping
=====================================
Centralised registry of OWASP MASTG tests, techniques, and MASVS mapping.
Used to enrich security findings and provide context-aware remediations.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class MASTGItem:
    id: str
    title: str
    category: str
    masvs_mapping: List[str]
    description: str
    remediation: str

# ── MASTG Test Registry ───────────────────────────────────────────────────────

MASTG_TESTS: Dict[str, MASTGItem] = {
    "MASTG-TEST-0001": MASTGItem(
        id="MASTG-TEST-0001",
        title="Testing Local Storage for Sensitive Data",
        category="STORAGE",
        masvs_mapping=["MASVS-STORAGE-1", "MASVS-STORAGE-2"],
        description="Verifies if sensitive data is stored in plain text in local files, databases, or preferences.",
        remediation="Use Android Keystore or iOS Keychain to encrypt sensitive local data. Avoid storing PII whenever possible."
    ),
    "MASTG-TEST-0012": MASTGItem(
        id="MASTG-TEST-0012",
        title="Testing for Insecure IPC",
        category="PLATFORM",
        masvs_mapping=["MASVS-PLATFORM-1"],
        description="Checks if exported components (Activities, Services, etc.) can be accessed by malicious apps.",
        remediation="Set android:exported='false' for internal components. Use custom permissions for cross-app communication."
    ),
    "MASTG-TEST-0030": MASTGItem(
        id="MASTG-TEST-0030",
        title="Testing for Vulnerable Implementation of PendingIntent",
        category="PLATFORM",
        masvs_mapping=["MASVS-PLATFORM-1"],
        description="Identifies use of mutable PendingIntents which can be hijacked to execute actions with the app's permissions.",
        remediation="Always use PendingIntent.FLAG_IMMUTABLE when creating PendingIntents unless mutability is explicitly required."
    ),
    "MASTG-TEST-0022": MASTGItem(
        id="MASTG-TEST-0022",
        title="Testing Custom Certificate Stores and Certificate Pinning",
        category="NETWORK",
        masvs_mapping=["MASVS-NETWORK-2"],
        description="Validates the implementation of certificate pinning to prevent MITM attacks.",
        remediation="Implement pinning using Network Security Configuration (Android) or URLSessionTrustManagement (iOS)."
    ),
    "MASTG-TEST-0242": MASTGItem(
        id="MASTG-TEST-0242",
        title="Missing Certificate Pinning in Network Security Configuration",
        category="NETWORK",
        masvs_mapping=["MASVS-NETWORK-2"],
        description="Specific check for missing <pin-set> in Android 7.0+ XML configuration.",
        remediation="Add a <pin-set> entry for your API domains in res/xml/network_security_config.xml."
    ),
    "MASTG-TEST-0212": MASTGItem(
        id="MASTG-TEST-0212",
        title="Use of Hardcoded Cryptographic Keys",
        category="CRYPTO",
        masvs_mapping=["MASVS-CRYPTO-1"],
        description="Detects static encryption keys embedded in code or binaries.",
        remediation="Never hardcode keys. Use the Android Keystore System or iOS Keychain to generate and store keys securely."
    ),
    "MASTG-TEST-0221": MASTGItem(
        id="MASTG-TEST-0221",
        title="Broken Symmetric Encryption Algorithms",
        category="CRYPTO",
        masvs_mapping=["MASVS-CRYPTO-2"],
        description="Checks for the use of insecure or deprecated algorithms like DES, 3DES, or AES-ECB.",
        remediation="Use AES-GCM or AES-CBC with a secure random IV. Avoid ECB mode."
    ),
    "MASTG-TEST-0045": MASTGItem(
        id="MASTG-TEST-0045",
        title="Testing Root Detection",
        category="RESILIENCE",
        masvs_mapping=["MASVS-RESILIENCE-1"],
        description="Verifies if the app detects a rooted environment and takes protective measures.",
        remediation="Implement multiple root detection checks (file checks, package checks, property checks) using a library like RootBeer."
    ),
    "MASTG-TEST-0341": MASTGItem(
        id="MASTG-TEST-0341",
        title="Testing Runtime Hook Detection",
        category="RESILIENCE",
        masvs_mapping=["MASVS-RESILIENCE-2"],
        description="Checks if the app detects instrumentation frameworks like Frida or Xposed.",
        remediation="Use native-level checks to detect debugger presence, frida-server ports, or suspicious named pipes."
    ),

    # ── iOS-Specific Tests ────────────────────────────────────────────────────

    "MASTG-TEST-0060": MASTGItem(
        id="MASTG-TEST-0060",
        title="Testing for Jailbreak Detection on iOS",
        category="RESILIENCE",
        masvs_mapping=["MASVS-RESILIENCE-1"],
        description=(
            "Verifies if the iOS app implements jailbreak detection and responds "
            "appropriately. Tests include checking for Cydia.app, Substrate, SBSettings, "
            "fork() sandbox escape, and suspicious dyld image list entries."
        ),
        remediation=(
            "Implement multi-layered jailbreak detection: file existence checks "
            "(Cydia.app, MobileSubstrate), canOpenURL for cydia://, fork() return value, "
            "dyld image list scan. Combine with app integrity check via DeviceCheck/AppAttest. "
            "Do NOT rely on a single check — use at least 5 independent signals."
        )
    ),
    "MASTG-TEST-0062": MASTGItem(
        id="MASTG-TEST-0062",
        title="Testing for Sensitive Data in Crash Logs on iOS",
        category="STORAGE",
        masvs_mapping=["MASVS-STORAGE-3"],
        description=(
            "Checks if sensitive data (passwords, tokens, PII) is written to iOS crash "
            "reports or device logs. Crash reporters like Firebase Crashlytics may "
            "capture stack frames containing sensitive values."
        ),
        remediation=(
            "Enable NSPrivacyTrackingDomains in PrivacyInfo.xcprivacy. "
            "Sanitize NSException userInfo dictionaries before throwing. "
            "Never log authentication tokens — use NSLog only in DEBUG builds. "
            "Configure crash reporting to redact sensitive keys."
        )
    ),
    "MASTG-TEST-0068": MASTGItem(
        id="MASTG-TEST-0068",
        title="Testing Objective-C Reverse Engineering Defenses on iOS",
        category="RESILIENCE",
        masvs_mapping=["MASVS-RESILIENCE-3"],
        description=(
            "Checks if the app implements anti-reversing controls for Objective-C: "
            "class name obfuscation, method swizzling detection, dylib injection detection, "
            "and biometric authentication binding to Keychain. "
            "ObjC runtime is inherently reflective — class names and selectors are visible."
        ),
        remediation=(
            "Move sensitive logic to C/C++ or Swift non-ObjC code. "
            "Use class_replaceMethod to detect swizzling. "
            "Obfuscate class names with a tool like obfuscator-llvm. "
            "Bind Keychain items to biometric authentication using SecAccessControlCreateWithFlags "
            "with kSecAccessControlBiometryCurrentSet."
        )
    ),
    "MASTG-TEST-0077": MASTGItem(
        id="MASTG-TEST-0077",
        title="Testing for App Transport Security (ATS) Configuration",
        category="NETWORK",
        masvs_mapping=["MASVS-NETWORK-1"],
        description=(
            "Verifies the iOS App Transport Security configuration in Info.plist. "
            "ATS enforces HTTPS for all connections by default (iOS 9+). "
            "Tests check for NSAllowsArbitraryLoads=YES, NSExceptionDomains with "
            "NSTemporaryExceptionAllowsInsecureHTTPLoads, or NSRequiresCertificateTransparency=NO."
        ),
        remediation=(
            "Remove NSAllowsArbitraryLoads from Info.plist. "
            "Each NSExceptionDomain must have a documented business justification. "
            "Enable NSRequiresCertificateTransparency=YES for all domains. "
            "Target iOS 15+ — all ATS exemptions require App Store review justification."
        )
    ),
    "MASTG-TEST-0080": MASTGItem(
        id="MASTG-TEST-0080",
        title="Testing for Insecure NSURLSession Implementation",
        category="NETWORK",
        masvs_mapping=["MASVS-NETWORK-2"],
        description=(
            "Checks if the app configures NSURLSession securely: validates that "
            "NSURLSessionDelegate.didReceiveChallenge does not accept all certificates, "
            "verifies certificate pinning via pinnedCertificates, and checks that "
            "TLSMinimumSupportedProtocolVersion is TLS 1.2 or higher."
        ),
        remediation=(
            "Never implement URLSession:didReceiveChallenge:completionHandler: accepting "
            "SecTrustEvaluate results blindly. Use certificate pinning via "
            "NSURLSessionConfiguration.pinnedCertificates. "
            "Set TLSMinimumSupportedProtocolVersion to TLS 1.2 at minimum. "
            "Use TrustKit or iOS native pinning for defense in depth."
        )
    ),
}

# ── Enrichment Helper ─────────────────────────────────────────────────────────

def enrich_finding(finding: dict) -> dict:
    """Add MASTG context to a finding based on its type or tags."""
    ftype = finding.get("type", "").lower()
    tags = finding.get("tags", [])
    
    # Mapping logic
    mapping = None
    if "pendingintent" in ftype or "pending_intent" in ftype:
        mapping = MASTG_TESTS["MASTG-TEST-0030"]
    elif "exported" in ftype and "component" in tags:
        mapping = MASTG_TESTS["MASTG-TEST-0012"]
    elif "cleartext" in ftype:
        mapping = MASTG_TESTS["MASTG-TEST-0242"]
    elif "pinning" in ftype and "missing" in ftype:
        mapping = MASTG_TESTS["MASTG-TEST-0242"]
    elif "hardcoded" in ftype and "key" in ftype:
        mapping = MASTG_TESTS["MASTG-TEST-0212"]
    elif "crypto" in tags and ("ecb" in ftype or "des" in ftype):
        mapping = MASTG_TESTS["MASTG-TEST-0221"]
    elif "root" in tags and "detection" in ftype:
        mapping = MASTG_TESTS["MASTG-TEST-0045"]

    # iOS-specific enrichments
    if not mapping:
        if "jailbreak" in ftype or "cydia" in ftype:
            mapping = MASTG_TESTS.get("MASTG-TEST-0060")
        elif "ats" in ftype or "nsurlsession" in ftype or "nsallowsarbitraryloads" in ftype:
            mapping = MASTG_TESTS.get("MASTG-TEST-0077")
        elif "nsurlsession" in ftype or "certificate" in ftype and "ios" in tags:
            mapping = MASTG_TESTS.get("MASTG-TEST-0080")
        elif "biometric" in ftype or "touchid" in ftype or "faceid" in ftype or "lacontext" in ftype:
            mapping = MASTG_TESTS.get("MASTG-TEST-0068")
        elif "crash" in ftype and "log" in ftype:
            mapping = MASTG_TESTS.get("MASTG-TEST-0062")
        elif "keychain" in ftype or "secitem" in ftype:
            mapping = MASTG_TESTS.get("MASTG-TEST-0001")
        elif "insecure_storage" in ftype and "ios" in tags:
            mapping = MASTG_TESTS.get("MASTG-TEST-0001")

    if mapping:
        finding["mastg_id"] = mapping.id
        finding["masvs"] = mapping.masvs_mapping
        finding["remediation"] = finding.get("remediation") or mapping.remediation
        finding["description"] = (
            finding.get("detail", "")
            + f"\n\nOWASP MASTG {mapping.id}: {mapping.description}"
        )

    return finding
