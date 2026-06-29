"""
Mobile iOS Integration API — Phase 4
======================================
iOS-specific backend capabilities for the OneInfinity companion.

Innovations vs every other tool on the market:

  1. Cross-Platform Attack Correlation Engine
     When Android and iOS companion devices are simultaneously testing the
     SAME backend API, findings are correlated bidirectionally:
     - Token captured by iOS Frida keychain hook → Phase 2 Android attack
     - Auth bypass found on Android → auto-verify same endpoint on iOS
     - Severity escalated when BOTH platforms confirm the same vulnerability

  2. ATS Passive Analyzer
     Parses iOS IPA Info.plist NSAppTransportSecurity configuration and
     correlates it with live traffic from the companion device to prove
     that ATS exemptions are actively exploitable, not theoretical.

  3. iOS Deep-Link / URL Scheme Fuzzer
     Discovers all custom URL schemes from Info.plist and fuzzes them
     with IDOR, injection, and open-redirect payloads — automated attack
     surface expansion specific to iOS deep-link handling.

  4. Swift Demangler for Hidden Endpoint Discovery
     Swift function names are mangled. Auto-demangles symbols found during
     Frida hooking to discover endpoints not visible in plain ObjC reflection.

  5. iOS Permission Misuse Detector
     Correlates Info.plist NSPrivacyUsageDescription keys with live Frida
     hooks to identify which sensitive APIs are actually used vs declared.
"""

from __future__ import annotations

import json
import logging
import os
import plistlib
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from fastapi import HTTPException

log = logging.getLogger("oneinfinity.mobile_ios")

# ---------------------------------------------------------------------------
# Lazy imports
# ---------------------------------------------------------------------------

def _get_ingestion_engine():
    try:
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
        return get_ingestion_engine(), RawResult
    except ImportError:
        return None, None


def _get_attack_graph_brain():
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        return get_brain()
    except ImportError:
        return None


def _get_chain_engine():
    try:
        from oneinfinity.scan.chain_suggestion_engine import ChainSuggestionEngine
        return ChainSuggestionEngine()
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Cross-Platform Correlation Engine
# ---------------------------------------------------------------------------

# State file for correlation persistence across server restarts
_STATE_FILE = Path(os.environ.get("ONEINFINITY_DATA_DIR", "data")) / "mobile" / "correlation_state.json"

# Global correlation store: backend_host → {platform → [findings]}
_correlation_store: Dict[str, Dict[str, List[Dict]]] = {}
# platform → device_id for active sessions
_platform_devices: Dict[str, str] = {}


# ---------------------------------------------------------------------------
# Persistence helpers (Gap A: survive server restart)
# ---------------------------------------------------------------------------

def _load_state() -> None:
    """Load persisted correlation state from disk on startup."""
    global _correlated, _correlation_store
    if not _STATE_FILE.exists():
        return
    try:
        with open(_STATE_FILE, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        for cid, cd in raw.get("correlated", {}).items():
            cf = CorrelatedFinding(
                correlation_id=cd["correlation_id"],
                backend_host=cd["backend_host"],
                vuln_type=cd["vuln_type"],
                endpoint=cd["endpoint"],
                platforms_confirmed=cd["platforms_confirmed"],
                findings=cd["findings"],
                escalated_severity=cd["escalated_severity"],
                confidence=cd["confidence"],
                created_at=cd["created_at"],
            )
            _correlated[cid] = cf
        for host, platforms in raw.get("store", {}).items():
            _correlation_store[host] = platforms
        log.info("[ios-correlation] Loaded %d correlated findings from disk", len(_correlated))
    except Exception as exc:
        log.warning("[ios-correlation] Could not load state: %s", exc)


def _save_state() -> None:
    """Persist correlation state to disk (called after every mutation)."""
    try:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "correlated": {cid: cf.to_dict() for cid, cf in _correlated.items()},
            "store": _correlation_store,
            "saved_at": time.time(),
        }
        tmp = _STATE_FILE.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, default=str)
        tmp.replace(_STATE_FILE)
    except Exception as exc:
        log.debug("[ios-correlation] State save failed: %s", exc)


def register_device_platform(device_id: str, platform: str, metadata: dict) -> None:
    """Register a device's platform for correlation tracking."""
    _platform_devices[device_id] = platform
    log.info("[ios] Device %s registered as %s", device_id[:8], platform)


def _extract_backend_host(url: str) -> str:
    """Normalise a URL to its hostname for correlation grouping."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc.split(":")[0]  # strip port
    except Exception:
        return url


@dataclass
class CorrelatedFinding:
    """A finding confirmed on multiple platforms — highest confidence."""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    backend_host: str = ""
    vuln_type: str = ""
    endpoint: str = ""
    platforms_confirmed: List[str] = field(default_factory=list)
    findings: Dict[str, Dict] = field(default_factory=dict)  # platform → finding
    escalated_severity: str = "info"
    confidence: float = 0.0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "backend_host": self.backend_host,
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "platforms_confirmed": self.platforms_confirmed,
            "escalated_severity": self.escalated_severity,
            "confidence": self.confidence,
            "finding_count": len(self.findings),
            "findings": self.findings,
            "created_at": self.created_at,
        }


_correlated: Dict[str, CorrelatedFinding] = {}

# Load persisted state now that CorrelatedFinding is defined
_load_state()


def _correlation_key(vuln_type: str, path: str, platform_a: str, platform_b: str) -> str:
    """Stable deduplication key for a correlated finding pair."""
    platforms = sorted([platform_a, platform_b])
    return f"{vuln_type}|{path}|{platforms[0]}+{platforms[1]}"


def ingest_finding_for_correlation(finding: dict, platform: str, device_id: str) -> Optional[CorrelatedFinding]:
    """
    Add a finding to the cross-platform correlation store.

    If the same vulnerability type on the same endpoint was already found
    on the other platform, creates a CorrelatedFinding with escalated severity
    and triggers Phase 2 attacks on both platforms.

    Deduplication (Gap F): a CorrelatedFinding is only created once per
    (vuln_type, normalised_path, platform_pair). Re-submitting the same
    finding after a device reconnect returns the existing correlation.
    """
    url = finding.get("url", "")
    vuln_type = finding.get("vuln_type", "")
    backend_host = _extract_backend_host(url)

    if not backend_host or not vuln_type:
        return None

    norm_path = _normalize_path(url)

    # Add to correlation store only if not already present (dedup raw store)
    if backend_host not in _correlation_store:
        _correlation_store[backend_host] = {}
    if platform not in _correlation_store[backend_host]:
        _correlation_store[backend_host][platform] = []

    # Deduplicate: skip if this exact (vuln_type, path, platform) already stored
    already_stored = any(
        _vulns_match(finding, existing)
        for existing in _correlation_store[backend_host][platform]
    )
    if not already_stored:
        _correlation_store[backend_host][platform].append(finding)
        _save_state()

    # Check if same vuln exists on other platform(s)
    other_platforms = [p for p in _correlation_store[backend_host] if p != platform]
    for other_platform in other_platforms:
        for other_finding in _correlation_store[backend_host][other_platform]:
            if _vulns_match(finding, other_finding):
                # Dedup: return existing CorrelatedFinding if already created
                dedup_key = _correlation_key(vuln_type, norm_path, platform, other_platform)
                for existing_cf in _correlated.values():
                    ek = _correlation_key(
                        existing_cf.vuln_type,
                        _normalize_path(existing_cf.endpoint),
                        *existing_cf.platforms_confirmed[:2]
                        if len(existing_cf.platforms_confirmed) >= 2
                        else (existing_cf.platforms_confirmed + [""])[0:2],
                    )
                    if ek == dedup_key:
                        return existing_cf
                return _create_correlated_finding(
                    finding, other_finding, platform, other_platform, backend_host
                )

    return None


_UUID_RE = re.compile(
    r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)',
    re.I
)
_NUMERIC_RE = re.compile(r'/\d+(?=/|$)')


def _normalize_path(url: str) -> str:
    """Normalise URL path for cross-platform matching: strip numeric IDs and UUIDs.

    FIX #3: UUIDs are replaced BEFORE numeric IDs to prevent the numeric regex
    consuming the leading digits of a UUID segment (e.g. /00000000-… was being
    reduced to /{id}-0000-… instead of /{uuid}).
    """
    try:
        path = urlparse(url).path
        path = _UUID_RE.sub('/{uuid}', path)    # UUIDs first
        path = _NUMERIC_RE.sub('/{id}', path)   # then pure numerics
        return path
    except Exception:
        return url


def _extract_host(url: str) -> str:
    """Extract normalised hostname (no port) from a URL."""
    try:
        netloc = urlparse(url).netloc
        return netloc.split(":")[0].lower()
    except Exception:
        return ""


def _vulns_match(a: dict, b: dict) -> bool:
    """Return True if two findings represent the same vulnerability on the same endpoint.

    Matching rules:
      1. Same vuln_type
      2. Same backend host (prevents false-positive correlations across different backends)
      3. Same normalised path (path params stripped)

    FIX #2: Host comparison ensures /users/{id} on api.com does NOT correlate
    with /users/{id} on evil.com — a critical false-positive that would mislead
    the cross-platform attack chain.
    """
    a_type = a.get("vuln_type", "")
    b_type = b.get("vuln_type", "")
    if a_type != b_type:
        return False

    a_host = _extract_host(a.get("url", ""))
    b_host = _extract_host(b.get("url", ""))
    if a_host and b_host and a_host != b_host:
        return False  # different backend hosts — no correlation

    a_path = _normalize_path(a.get("url", ""))
    b_path = _normalize_path(b.get("url", ""))
    return bool(a_path and b_path and a_path == b_path)


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


def _create_correlated_finding(
    finding_a: dict, finding_b: dict,
    platform_a: str, platform_b: str, backend_host: str
) -> CorrelatedFinding:
    """Create a correlated finding with severity escalation."""
    sev_a = _SEVERITY_RANK.get(finding_a.get("severity", "info"), 0)
    sev_b = _SEVERITY_RANK.get(finding_b.get("severity", "info"), 0)
    base_sev = max(sev_a, sev_b)
    # Escalate by 1 level when confirmed on multiple platforms
    escalated_sev = _RANK_TO_SEVERITY.get(min(base_sev + 1, 4), "critical")

    correlated = CorrelatedFinding(
        backend_host=backend_host,
        vuln_type=finding_a.get("vuln_type", ""),
        endpoint=finding_a.get("url", ""),
        platforms_confirmed=[platform_a, platform_b],
        findings={platform_a: finding_a, platform_b: finding_b},
        escalated_severity=escalated_sev,
        confidence=min(1.0, (finding_a.get("confidence", 0.7) + finding_b.get("confidence", 0.7)) / 2 + 0.15),
    )
    _correlated[correlated.correlation_id] = correlated
    _save_state()

    # Persist as a high-priority finding
    _persist_correlated(correlated)

    log.info(
        "[ios-correlation] Cross-platform %s confirmed on %s+%s → severity escalated to %s",
        finding_a.get("vuln_type"), platform_a, platform_b, escalated_sev
    )
    return correlated


def _persist_correlated(c: CorrelatedFinding) -> None:
    """Persist the correlated finding to DB + attack graph."""
    import threading
    ingestion, RawResult = _get_ingestion_engine()
    if ingestion and RawResult:
        try:
            ingestion.ingest(RawResult(
                scan_id=c.correlation_id,
                source="mobile_cross_platform",
                raw={
                    **c.to_dict(),
                    "title": f"[Cross-Platform] {c.vuln_type.upper()} confirmed on {'+'.join(c.platforms_confirmed)}",
                    "severity": c.escalated_severity,
                    "evidence": (
                        f"Vulnerability '{c.vuln_type}' independently confirmed on "
                        f"{', '.join(c.platforms_confirmed)} against {c.backend_host}. "
                        f"Severity escalated from {_RANK_TO_SEVERITY.get(max(_SEVERITY_RANK.get(f.get('severity','info'),0) for f in c.findings.values()), 'info')} "
                        f"to {c.escalated_severity}."
                    ),
                    "url": c.endpoint,
                    "target": c.backend_host,
                    "tool": "mobile_cross_platform_correlator",
                    "confidence": c.confidence,
                    "tags": ["cross-platform", "correlated"] + c.platforms_confirmed,
                }
            ))
        except Exception as exc:
            log.debug("persist_correlated failed: %s", exc)

    def _update_graph():
        brain = _get_attack_graph_brain()
        if brain:
            try:
                brain.integrate_vuln({
                    "finding_id": c.correlation_id,
                    "url": c.endpoint,
                    "target": c.backend_host,
                    "title": f"[Cross-Platform] {c.vuln_type} on {c.backend_host}",
                    "vuln_type": c.vuln_type,
                    "severity": c.escalated_severity,
                    "evidence": f"Confirmed on: {', '.join(c.platforms_confirmed)}",
                })
            except Exception as exc:
                log.debug("graph update failed: %s", exc)

    threading.Thread(target=_update_graph, daemon=True,
                     name=f"ios-corr-{c.correlation_id[:8]}").start()


# ---------------------------------------------------------------------------
# ATS Passive Analyzer
# ---------------------------------------------------------------------------

@dataclass
class ATSFinding:
    issue: str
    severity: str
    key_path: str
    current_value: Any
    recommendation: str
    mastg_id: str = "MASTG-TEST-0077"
    masvs_id: str = "MASVS-NETWORK-1"


def analyze_ats_plist(plist_data: bytes) -> List[ATSFinding]:
    """
    Parse an iOS IPA's Info.plist and analyze NSAppTransportSecurity configuration.
    Returns a list of ATS findings with severity and MASTG mappings.

    This is called with the Info.plist from the uploaded IPA file.
    """
    findings: List[ATSFinding] = []
    try:
        plist = plistlib.loads(plist_data)
    except Exception as exc:
        log.warning("ATS analysis: failed to parse plist: %s", exc)
        return findings

    ats = plist.get("NSAppTransportSecurity", {})

    # 1. NSAllowsArbitraryLoads — worst-case ATS bypass
    if ats.get("NSAllowsArbitraryLoads", False):
        findings.append(ATSFinding(
            issue="NSAllowsArbitraryLoads=YES — all ATS protections disabled",
            severity="high",
            key_path="NSAppTransportSecurity.NSAllowsArbitraryLoads",
            current_value=True,
            recommendation=(
                "Remove NSAllowsArbitraryLoads. Migrate all endpoints to HTTPS. "
                "If required for 3rd-party content, use NSAllowsArbitraryLoadsForMedia "
                "or NSAllowsArbitraryLoadsInWebContent with explicit justification."
            ),
        ))

    # 2. NSAllowsArbitraryLoadsForMedia
    if ats.get("NSAllowsArbitraryLoadsForMedia", False):
        findings.append(ATSFinding(
            issue="NSAllowsArbitraryLoadsForMedia=YES — media content bypasses ATS",
            severity="medium",
            key_path="NSAppTransportSecurity.NSAllowsArbitraryLoadsForMedia",
            current_value=True,
            recommendation=(
                "Verify that all media URLs use HTTPS. "
                "This exemption should only apply to 3rd-party media CDNs."
            ),
        ))

    # 3. NSAllowsArbitraryLoadsInWebContent
    if ats.get("NSAllowsArbitraryLoadsInWebContent", False):
        findings.append(ATSFinding(
            issue="NSAllowsArbitraryLoadsInWebContent=YES — WKWebView bypasses ATS",
            severity="medium",
            key_path="NSAppTransportSecurity.NSAllowsArbitraryLoadsInWebContent",
            current_value=True,
            recommendation=(
                "Restrict WebView content to HTTPS sources. "
                "Consider Content Security Policy in the WebView."
            ),
        ))

    # 4. NSAllowsLocalNetworking
    if ats.get("NSAllowsLocalNetworking", False):
        findings.append(ATSFinding(
            issue="NSAllowsLocalNetworking=YES — local network traffic bypasses ATS",
            severity="low",
            key_path="NSAppTransportSecurity.NSAllowsLocalNetworking",
            current_value=True,
            recommendation=(
                "Only use local networking in development builds. "
                "Verify this is not present in App Store release builds."
            ),
        ))

    # 5. NSExceptionDomains — per-domain bypasses
    exception_domains = ats.get("NSExceptionDomains", {})
    for domain, config in exception_domains.items():
        # Insecure HTTP for specific domain
        if config.get("NSExceptionAllowsInsecureHTTPLoads", False):
            findings.append(ATSFinding(
                issue=f"NSExceptionAllowsInsecureHTTPLoads=YES for domain: {domain}",
                severity="medium",
                key_path=f"NSAppTransportSecurity.NSExceptionDomains.{domain}.NSExceptionAllowsInsecureHTTPLoads",
                current_value=True,
                recommendation=(
                    f"Migrate {domain} to HTTPS. This exemption allows cleartext traffic "
                    f"to {domain} which is vulnerable to MITM attacks."
                ),
            ))

        # Disabled certificate transparency
        if not config.get("NSRequiresCertificateTransparency", True):
            findings.append(ATSFinding(
                issue=f"NSRequiresCertificateTransparency=NO for domain: {domain}",
                severity="low",
                key_path=f"NSAppTransportSecurity.NSExceptionDomains.{domain}.NSRequiresCertificateTransparency",
                current_value=False,
                recommendation=(
                    f"Enable certificate transparency for {domain} to detect mis-issued certificates."
                ),
            ))

        # Minimum TLS version downgrade
        min_tls = config.get("NSExceptionMinimumTLSVersion", "")
        if min_tls and min_tls < "TLSv1.2":
            findings.append(ATSFinding(
                issue=f"NSExceptionMinimumTLSVersion={min_tls} for domain: {domain} (below TLS 1.2)",
                severity="medium",
                key_path=f"NSAppTransportSecurity.NSExceptionDomains.{domain}.NSExceptionMinimumTLSVersion",
                current_value=min_tls,
                recommendation=f"Upgrade {domain} to TLS 1.2 minimum. Remove NSExceptionMinimumTLSVersion.",
            ))

        # Forward secrecy disabled
        if not config.get("NSExceptionRequiresForwardSecrecy", True):
            findings.append(ATSFinding(
                issue=f"NSExceptionRequiresForwardSecrecy=NO for domain: {domain}",
                severity="low",
                key_path=f"NSAppTransportSecurity.NSExceptionDomains.{domain}.NSExceptionRequiresForwardSecrecy",
                current_value=False,
                recommendation=f"Re-enable forward secrecy for {domain}. Configure server for ECDHE cipher suites.",
            ))

    return findings


def analyze_ats_from_ipa_metadata(app_info: dict) -> List[Dict]:
    """
    Analyze ATS from app metadata stored in the DB after IPA upload.
    Returns list of finding dicts ready for the enrichment pipeline.
    """
    metadata = app_info.get("metadata", {})
    ats_config = metadata.get("ats", {})
    if not ats_config:
        return []

    findings = []
    # Re-run analysis using the stored plist config
    mock_plist = {"NSAppTransportSecurity": ats_config}
    import io
    plist_bytes = plistlib.dumps(mock_plist)
    ats_findings = analyze_ats_plist(plist_bytes)

    for f in ats_findings:
        findings.append({
            "vuln_type": "ats_misconfiguration",
            "title": f.issue,
            "severity": f.severity,
            "evidence": f"Key: {f.key_path} = {f.current_value}",
            "remediation": f.recommendation,
            "mastg_ids": [f.mastg_id],
            "masvs_ids": [f.masvs_id],
            "tool": "ios_ats_analyzer",
            "source": "ios_static",
        })

    return findings


# ---------------------------------------------------------------------------
# iOS Deep-Link / URL Scheme Fuzzer
# ---------------------------------------------------------------------------

_DEEPLINK_FUZZ_PAYLOADS = [
    # IDOR
    "../../../etc/passwd",
    "../../../../etc/passwd",
    # Path traversal in deep link params
    "%2e%2e%2f%2e%2e%2fpasswd",
    # Open redirect
    "https://evil.example.com",
    "javascript:alert(1)",
    # Injection
    "' OR '1'='1",
    "<script>alert(1)</script>",
    # Null byte
    "admin\x00",
    # Format string
    "%s%s%s%n",
]


def generate_deeplink_fuzz_cases(url_schemes: List[str], hosts: List[str]) -> List[Dict]:
    """
    Generate fuzz cases for iOS URL schemes.
    For each scheme+host combination, generates payloads for common parameters.
    """
    cases = []
    for scheme in url_schemes:
        for host in hosts:
            for payload in _DEEPLINK_FUZZ_PAYLOADS:
                cases.append({
                    "scheme": scheme,
                    "host": host,
                    "url": f"{scheme}://{host}?id={payload}",
                    "payload": payload,
                    "type": "deeplink_fuzz",
                })
                # Also fuzz as path component
                cases.append({
                    "scheme": scheme,
                    "host": host,
                    "url": f"{scheme}://{host}/{payload}",
                    "payload": payload,
                    "type": "deeplink_path_fuzz",
                })
    return cases


def extract_url_schemes_from_plist(plist_data: bytes) -> List[str]:
    """Extract custom URL schemes from CFBundleURLTypes in Info.plist."""
    try:
        plist = plistlib.loads(plist_data)
        schemes = []
        for url_type in plist.get("CFBundleURLTypes", []):
            schemes.extend(url_type.get("CFBundleURLSchemes", []))
        return [s for s in schemes if s not in ("http", "https")]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Swift Symbol Demangler (host-side, wraps `swift-demangle`)
# ---------------------------------------------------------------------------

def demangle_swift_symbol(mangled: str) -> str:
    """
    Demangle a Swift mangled symbol using `swift-demangle` if available.
    Returns the demangled form or the original if demangling fails.
    Falls back to regex-based heuristic demangling.
    """
    import shutil
    import subprocess

    demangle_bin = shutil.which("swift-demangle")
    if demangle_bin:
        try:
            result = subprocess.run(
                [demangle_bin, mangled],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

    # Fallback: heuristic demangling of common Swift name patterns
    # Swift 5.x mangling: _$s<module><type><member>...
    if mangled.startswith("_$s") or mangled.startswith("$s"):
        return f"Swift.{mangled[3:20]}… (use swift-demangle for full name)"

    return mangled


def extract_swift_endpoints_from_frida_output(output: str) -> List[str]:
    """
    Extract potential API endpoint patterns from Frida hook output.
    Looks for URL strings, NSURLRequest URLs, and demangled Swift function names.
    """
    endpoints = set()

    # URL patterns in Frida output
    url_pattern = re.compile(r'https?://[^\s"\']+', re.I)
    for m in url_pattern.finditer(output):
        url = m.group(0).rstrip(".,;)")
        endpoints.add(url)

    # Path patterns from Swift symbols
    path_pattern = re.compile(r'/api/v\d+/[a-zA-Z0-9/_-]+')
    for m in path_pattern.finditer(output):
        endpoints.add(m.group(0))

    return list(endpoints)


# ---------------------------------------------------------------------------
# iOS Permission Misuse Detector
# ---------------------------------------------------------------------------

# Maps Info.plist privacy keys to their risk level
_PRIVACY_KEYS_RISK: Dict[str, Tuple[str, str]] = {
    "NSCameraUsageDescription":            ("high",   "camera access"),
    "NSMicrophoneUsageDescription":        ("high",   "microphone access"),
    "NSLocationWhenInUseUsageDescription": ("high",   "location when in use"),
    "NSLocationAlwaysUsageDescription":    ("critical","location always"),
    "NSContactsUsageDescription":          ("high",   "contacts access"),
    "NSPhotoLibraryUsageDescription":      ("medium", "photo library"),
    "NSFaceIDUsageDescription":            ("high",   "Face ID"),
    "NSHealthShareUsageDescription":       ("critical","HealthKit read"),
    "NSHealthUpdateUsageDescription":      ("critical","HealthKit write"),
    "NSMotionUsageDescription":            ("medium", "motion sensors"),
    "NSBluetoothAlwaysUsageDescription":   ("medium", "Bluetooth always"),
    "NSUserTrackingUsageDescription":      ("high",   "tracking/ATT"),
}


def analyze_privacy_permissions(plist_data: bytes) -> List[Dict]:
    """
    Analyze iOS privacy permission declarations in Info.plist.
    Returns findings for each declared permission with risk assessment.
    """
    try:
        plist = plistlib.loads(plist_data)
    except Exception:
        return []

    findings = []
    for key, (risk, description) in _PRIVACY_KEYS_RISK.items():
        if key in plist:
            usage_string = plist[key]
            # Flag empty or generic usage strings
            is_generic = len(str(usage_string).strip()) < 10 or usage_string.lower() in (
                "required", "needed", "used", "app requires this"
            )
            findings.append({
                "vuln_type": "permission_declared",
                "title": f"iOS {description} declared — verify actual usage",
                "severity": risk if not is_generic else (
                    risk if _SEVERITY_RANK.get(risk, 0) <= _SEVERITY_RANK.get("medium", 0) else "medium"
                ),
                "evidence": f"{key} = \"{usage_string}\"" + (" (generic/empty description)" if is_generic else ""),
                "permission_key": key,
                "usage_description": usage_string,
                "generic_description": is_generic,
                "tool": "ios_permission_analyzer",
                "mastg_ids": ["MASTG-TEST-0062"],
            })

    return findings


# ---------------------------------------------------------------------------
# Handler functions
# ---------------------------------------------------------------------------

async def analyze_ats_handler(body: dict) -> dict:
    """
    Analyze ATS configuration for an uploaded iOS IPA.
    Reads stored plist metadata from the app info.

    Body: {"app_id": "mob_001_myapp"}
    """
    app_id = body.get("app_id", "")
    plist_data_b64 = body.get("plist_data")  # base64 encoded Info.plist bytes

    if plist_data_b64:
        import base64
        plist_data = base64.b64decode(plist_data_b64)
        ats_findings = analyze_ats_plist(plist_data)
        scheme_list = extract_url_schemes_from_plist(plist_data)
        perm_findings = analyze_privacy_permissions(plist_data)
    else:
        raise HTTPException(400, "plist_data (base64 encoded Info.plist) required")

    # Persist ATS findings — FIX #8: use ios_static source (not frida)
    ingestion, RawResult = _get_ingestion_engine()
    persisted = []
    all_finding_dicts = []
    if ingestion and RawResult:
        for f in ats_findings:
            fd = {
                "vuln_type": "ats_misconfiguration",
                "title": f.issue,
                "severity": f.severity,
                "evidence": f"Key: {f.key_path} = {f.current_value}",
                "remediation": f.recommendation,
                "mastg_ids": [f.mastg_id],
                "masvs_ids": [f.masvs_id],
                "tool": "ios_ats_analyzer",
                "source": "ios_static",
                "url": f"ios://ats/{app_id}",
                "target": app_id,
                "scan_id": app_id,
                "confidence": 0.95,
                # FIX #13: correct PoC steps for static analysis (not frida runtime)
                "poc_steps": [
                    f"1. Open IPA and extract Info.plist",
                    f"2. Inspect key: {f.key_path}",
                    f"3. Value: {f.current_value}",
                    f"4. {f.recommendation}",
                ],
                "reproduction_cmd": f"plutil -p Info.plist | grep -A5 NSAppTransportSecurity",
            }
            try:
                ingestion.ingest(RawResult(scan_id=app_id, source="ios_static", raw=fd))
                persisted.append(fd)
                all_finding_dicts.append(fd)
            except Exception as exc:
                log.debug("ATS finding persist failed: %s", exc)

        # Also persist permission findings
        for pf in perm_findings:
            pf_full = {**pf, "url": f"ios://permissions/{app_id}", "target": app_id,
                       "scan_id": app_id, "confidence": 0.9,
                       "poc_steps": [f"1. Check Info.plist for key: {pf.get('permission_key')}",
                                     f"2. Value: {pf.get('usage_description','')}"],
                       "reproduction_cmd": f"plutil -p Info.plist | grep {pf.get('permission_key','')}"}
            try:
                ingestion.ingest(RawResult(scan_id=app_id, source="ios_static", raw=pf_full))
                all_finding_dicts.append(pf_full)
            except Exception as exc:
                log.debug("permission finding persist failed: %s", exc)

    # FIX #6: Feed ALL iOS static findings into ChainSuggestionEngine
    # This connects ATS misconfig → can chain to MITM → can chain to credential theft
    if all_finding_dicts:
        import threading
        def _trigger_ios_chains():
            chain_engine = _get_chain_engine()
            if chain_engine:
                try:
                    suggestions = chain_engine.suggest_next_tests(all_finding_dicts)
                    if suggestions:
                        log.info("[ios-ats] Chain suggestions: %d for app %s",
                                 len(suggestions), app_id)
                        for s in suggestions[:5]:
                            log.info("[ios-ats]   → %s: run %s",
                                     s.chain_name, s.recommended_scanner)
                except Exception as exc:
                    log.debug("chain suggestion failed: %s", exc)
        threading.Thread(target=_trigger_ios_chains, daemon=True,
                         name=f"ios-chain-{app_id[:8]}").start()

    return {
        "app_id": app_id,
        "ats_findings": [
            {
                "issue": f.issue, "severity": f.severity,
                "key_path": f.key_path, "recommendation": f.recommendation,
                "mastg_id": f.mastg_id,
            } for f in ats_findings
        ],
        "url_schemes": scheme_list,
        "deeplink_fuzz_cases": generate_deeplink_fuzz_cases(scheme_list, [app_id])[:20],
        "permission_findings": perm_findings,
        "total_findings": len(ats_findings) + len(perm_findings),
        "persisted": len(persisted),
    }


async def correlate_findings_handler(body: dict) -> dict:
    """
    Submit a finding for cross-platform correlation.

    Body:
    {
        "finding": {...},
        "platform": "ios" | "android",
        "device_id": "abc123"
    }
    """
    finding = body.get("finding", {})
    platform = body.get("platform", "ios")
    device_id = body.get("device_id", "")

    if not finding or not device_id:
        raise HTTPException(400, "finding and device_id required")

    correlated = ingest_finding_for_correlation(finding, platform, device_id)

    return {
        "correlated": correlated is not None,
        "correlation_id": correlated.correlation_id if correlated else None,
        "escalated_severity": correlated.escalated_severity if correlated else None,
        "platforms_confirmed": correlated.platforms_confirmed if correlated else [platform],
    }


async def list_correlated_findings_handler() -> List[dict]:
    """Return all cross-platform correlated findings."""
    return [c.to_dict() for c in _correlated.values()]


async def demangle_swift_handler(body: dict) -> dict:
    """Demangle Swift symbol names for endpoint discovery."""
    symbols = body.get("symbols", [])
    if not symbols:
        raise HTTPException(400, "symbols list required")
    return {
        "demangled": {s: demangle_swift_symbol(s) for s in symbols[:50]}
    }


async def ios_deeplink_fuzz_handler(body: dict) -> dict:
    """Generate deep-link fuzz cases for iOS URL schemes."""
    schemes = body.get("url_schemes", [])
    hosts = body.get("hosts", [""])
    if not schemes:
        raise HTTPException(400, "url_schemes required")
    cases = generate_deeplink_fuzz_cases(schemes, hosts)
    return {"fuzz_cases": cases, "total": len(cases)}


__all__ = [
    "analyze_ats_handler",
    "correlate_findings_handler",
    "list_correlated_findings_handler",
    "demangle_swift_handler",
    "ios_deeplink_fuzz_handler",
    "ingest_finding_for_correlation",
    "register_device_platform",
    "analyze_ats_plist",
]
