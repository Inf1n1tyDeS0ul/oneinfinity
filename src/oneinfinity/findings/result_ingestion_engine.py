"""
result_ingestion_engine.py — Fixes the tool→output→parser→database→graph→UI result chain.

Every tool result (nuclei, dalfox, sqlmap, subfinder, httpx, etc.) must flow through here.
No silent failures — every error is logged with the source.

Storage: PostgreSQL (hard requirement).
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

import oneinfinity.infra.path_manager as path_manager

log = logging.getLogger("oneinfinity.result_ingestion")


def _require_pg():
    """Return DBManager in PG mode, or raise if unavailable."""
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            return mgr
    except Exception as exc:
        raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
    raise RuntimeError(
        "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
    )


def _get_graph_learning_writer():
    """Lazy import to avoid circular import at module load."""
    try:
        from oneinfinity.learning.graph_learning_writer import get_graph_learning_writer
        return get_graph_learning_writer()
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class RawResult:
    scan_id: str
    source: str  # "nuclei", "dalfox", "sqlmap", "subfinder", "httpx", etc.
    raw: dict    # raw tool output as dict
    timestamp: float = field(default_factory=time.time)


@dataclass
class NormalizedFinding:
    scan_id: str
    target: str
    title: str
    severity: str         # critical/high/medium/low/info
    vuln_type: str
    evidence: str
    tool: str
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    payload: str = ""
    url: str = ""
    confidence: float = 0.8
    cvss: float = 0.0
    status: str = "new"   # new/confirmed/false_positive
    # source_type classifies the evidence quality:
    #   "tool"       — confirmed by a security tool (nuclei, dalfox, sqlmap, etc.)
    #   "simulated"  — result of a simulation engine (workflow sim, Monte Carlo)
    #   "ai_theory"  — AI-generated theory not yet confirmed by a tool
    #   "manual"     — manually added finding
    source_type: str = "tool"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    raw: dict = field(default_factory=dict)
    poc_steps: list = field(default_factory=list)     # ordered PoC reproduction steps
    reproduction_cmd: str = ""                         # exact CLI command to reproduce
    # Phase 0: Verified Finding Architecture — three-tier confidence system
    # Set by finding_judge.py after judge evaluation; None until judged.
    confirmed_tier: Optional[str] = None  # CONFIRMED | INFERRED | CANDIDATE | None
    discovered_by: list = field(default_factory=list)  # model IDs that found this

    def to_dict(self) -> dict:
        return {
            "finding_id":       self.finding_id,
            "scan_id":          self.scan_id,
            "target":           self.target,
            "title":            self.title,
            "severity":         self.severity,
            "vuln_type":        self.vuln_type,
            "evidence":         self.evidence,
            "payload":          self.payload,
            "url":              self.url,
            "tool":             self.tool,
            "confidence":       self.confidence,
            "cvss":             self.cvss,
            "status":           self.status,
            "source_type":      self.source_type,
            "created_at":       self.created_at,
            "raw":              self.raw,
            "poc_steps":        self.poc_steps,
            "reproduction_cmd": self.reproduction_cmd,
            "confirmed_tier":   self.confirmed_tier,
            "discovered_by":    self.discovered_by,
        }

    def safe_raw_json(self) -> str:
        """Return finding.raw as JSON, coercing any non-serializable values to str."""
        try:
            return json.dumps(self.raw, default=str)
        except Exception:
            return "{}"


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _parse_nuclei(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse a nuclei JSONL result dict into a NormalizedFinding."""
    try:
        template_id = raw.get("template-id") or raw.get("template_id")
        if not template_id:
            raise ValueError("nuclei finding missing template_id/template-id")
        title = raw.get("name") or template_id or "nuclei-finding"
        severity = (raw.get("info", {}).get("severity") or raw.get("severity") or "info").lower()
        matched_at = raw.get("matched-at") or raw.get("matched_at") or ""
        url = matched_at or raw.get("host") or raw.get("url") or ""
        vuln_type = raw.get("type") or template_id or "nuclei"
        target = raw.get("host") or url
        evidence = raw.get("extracted-results", "")
        if isinstance(evidence, list):
            evidence = "; ".join(str(e) for e in evidence)
        evidence = evidence or raw.get("matcher-name", "") or ""
        # CVSS from severity
        cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        cvss = cvss_map.get(severity, 0.0)
        return NormalizedFinding(
            scan_id=scan_id,
            target=target,
            title=str(title),
            severity=severity,
            vuln_type=str(vuln_type),
            evidence=str(evidence),
            tool=f"nuclei:{template_id}",
            url=str(url),
            confidence=0.85,
            cvss=cvss,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_nuclei failed: %s | raw=%s", exc, raw)
        return None


def _parse_dalfox(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse a dalfox result dict.
    dalfox outputs: {"type":"V","poc":"...","param":"...","evidence":"..."}
    """
    try:
        poc = raw.get("poc") or raw.get("PoC") or ""
        param = raw.get("param") or raw.get("parameter") or ""
        evidence = raw.get("evidence") or raw.get("message") or poc
        url = raw.get("url") or raw.get("URL") or poc.split("?")[0] if poc else ""
        target = url.split("/")[2] if url.startswith("http") else url
        result_type = raw.get("type") or raw.get("Type") or "V"
        severity = "high" if result_type in ("V", "G") else "medium"
        title = "Reflected XSS" if result_type == "V" else "Potential XSS"
        return NormalizedFinding(
            scan_id=scan_id,
            target=target,
            title=title,
            severity=severity,
            vuln_type="xss",
            evidence=str(evidence),
            payload=str(poc),
            url=str(url),
            tool="dalfox",
            confidence=0.9 if result_type == "V" else 0.6,
            cvss=8.0 if severity == "high" else 5.0,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_dalfox failed: %s | raw=%s", exc, raw)
        return None


def _parse_sqlmap(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse a sqlmap result dict."""
    try:
        url = raw.get("url") or raw.get("target") or ""
        target = url.split("/")[2] if url.startswith("http") else url
        param = raw.get("parameter") or raw.get("param") or ""
        technique = raw.get("technique") or raw.get("type") or "SQL Injection"
        dbms = raw.get("dbms") or raw.get("backend") or ""
        evidence = raw.get("payload") or raw.get("evidence") or ""
        payload = raw.get("payload") or ""
        title = f"SQL Injection ({technique})" if technique else "SQL Injection"
        if dbms:
            title += f" [{dbms}]"
        return NormalizedFinding(
            scan_id=scan_id,
            target=target,
            title=title,
            severity="high",
            vuln_type="sqli",
            evidence=str(evidence),
            payload=str(payload),
            url=str(url),
            tool="sqlmap",
            confidence=0.95,
            cvss=8.8,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_sqlmap failed: %s | raw=%s", exc, raw)
        return None


def _parse_subfinder(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse a subfinder result dict. Subdomains are info-severity 'subdomain-discovered' findings."""
    try:
        subdomain = raw.get("host") or raw.get("subdomain") or raw.get("value") or ""
        if not subdomain:
            # plain string passed as dict key
            subdomain = next(iter(raw.values()), "")
        target = subdomain
        return NormalizedFinding(
            scan_id=scan_id,
            target=target,
            title=f"Subdomain Discovered: {subdomain}",
            severity="info",
            vuln_type="subdomain-discovered",
            evidence=f"Subdomain: {subdomain}",
            url=f"https://{subdomain}",
            tool="subfinder",
            confidence=0.9,
            cvss=0.0,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_subfinder failed: %s | raw=%s", exc, raw)
        return None


def _parse_httpx(raw: dict, scan_id: str) -> Optional[NormalizedFinding]:
    """Parse an httpx result dict. Live hosts are info-severity 'live-host' findings."""
    try:
        url = raw.get("url") or raw.get("input") or ""
        host = raw.get("host") or (url.split("/")[2] if url.startswith("http") else url)
        status_code = raw.get("status-code") or raw.get("status_code") or 0
        title_text = raw.get("title") or raw.get("webserver") or ""
        tech = raw.get("tech") or raw.get("technologies") or []
        if isinstance(tech, list):
            tech = ", ".join(tech)
        evidence = f"status={status_code} title={title_text} tech={tech}"
        return NormalizedFinding(
            scan_id=scan_id,
            target=host,
            title=f"Live Host: {host}",
            severity="info",
            vuln_type="live-host",
            evidence=evidence,
            url=str(url),
            tool="httpx",
            confidence=1.0,
            cvss=0.0,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_httpx failed: %s | raw=%s", exc, raw)
        return None


# ---------------------------------------------------------------------------
# Canonical vuln_type normalization — maps raw scanner tags → Vuln.* strings
# so the capmap correctly counts coverage across all 63 vulnerability classes.
# ---------------------------------------------------------------------------

_CANONICAL_VULN_MAP: dict = {
    # SQL Injection
    "sqli": "SQL Injection", "sqli_potential": "SQL Injection",
    "sqli_blind": "SQL Injection", "sqli_time": "SQL Injection",
    "sqli_error": "SQL Injection", "sql_injection": "SQL Injection",
    "sql injection": "SQL Injection",
    # XSS
    "xss": "Cross-Site Scripting (XSS)", "reflected_xss": "Cross-Site Scripting (XSS)",
    "stored_xss": "Cross-Site Scripting (XSS)", "blind_xss": "Cross-Site Scripting (XSS)",
    "cross-site scripting": "Cross-Site Scripting (XSS)",
    "dom_xss": "DOM-based XSS", "dom-based xss": "DOM-based XSS",
    # SSRF
    "ssrf": "Server-Side Request Forgery (SSRF)", "ssrf_internal": "Server-Side Request Forgery (SSRF)",
    "ssrf_cloud": "Server-Side Request Forgery (SSRF)", "pdf_ssrf": "Server-Side Request Forgery (SSRF)",
    "blind_ssrf": "Server-Side Request Forgery (SSRF)",
    # IDOR/BOLA
    "idor": "Insecure Direct Object Reference (IDOR)", "bola": "Insecure Direct Object Reference (IDOR)",
    "idor_access": "Insecure Direct Object Reference (IDOR)",
    # CORS
    "cors_misconfiguration": "CORS Misconfiguration", "cors": "CORS Misconfiguration",
    "cors_origin_reflected": "CORS Misconfiguration",
    # CRLF
    "crlf": "CRLF Injection", "crlf_injection": "CRLF Injection",
    "http header injection": "CRLF Injection",
    # Command / Code injection
    "cmd_injection": "OS Command Injection", "rce": "OS Command Injection",
    "os_command_injection": "OS Command Injection", "command injection": "OS Command Injection",
    "code_injection": "Code Injection", "eval_injection": "Code Injection via eval",
    # Redirect / SSTI / XXE / LFI
    "open_redirect": "Open Redirect", "redirect": "Open Redirect",
    "ssti": "Server-Side Template Injection (SSTI)",
    "xxe": "XML External Entity (XXE)",
    "lfi": "Local File Inclusion (LFI)", "path_traversal": "Local File Inclusion (LFI)",
    "file_read": "Local File Inclusion (LFI)",
    # Subdomain / Files
    "subdomain_takeover": "Subdomain Takeover",
    "backup_files": "Backup/Archive File Exposed", "backup_file_exposed": "Backup/Archive File Exposed",
    "exposed_file": "Exposed Sensitive Files", "sensitive_file": "Exposed Sensitive Files",
    "source_disclosure": "Exposed Sensitive Files",
    # Misconfig / Headers
    "misconfig": "Security Misconfiguration", "misconfiguration": "Security Misconfiguration",
    "missing_security_headers": "Missing Security Headers", "missing_headers": "Missing Security Headers",
    # Info disclosure
    "info_leak": "Information Disclosure", "information_disclosure": "Information Disclosure",
    "sensitive_data_disclosure": "Information Disclosure",
    "SENSITIVE_DATA_DISCLOSURE": "Information Disclosure",
    # Auth
    "default_credentials": "Default Credentials", "default_creds": "Default Credentials",
    "credential_spray_hit": "Default Credentials",
    "broken_auth": "Broken Authentication", "auth_bypass": "Broken Authentication",
    "session_replay_access": "Broken Authentication", "session_replay": "Broken Authentication",
    "session_not_invalidated": "Broken Authentication",
    # JWT
    "jwt_vulnerability": "JWT Vulnerability", "jwt_attack": "JWT Vulnerability",
    "jwt_none_alg": "JWT Vulnerability", "jwt_weak_secret": "JWT Vulnerability",
    "jwt_kid_injection": "JWT Vulnerability",
    # Secrets
    "secret_exposure": "Secret / Credential Exposure", "secret": "Secret / Credential Exposure",
    "credential_exposure": "Secret / Credential Exposure",
    "hardcoded_password": "Secret / Credential Exposure",
    "hardcoded_credential": "Secret / Credential Exposure",
    "js_hardcoded_credential": "Secret / Credential Exposure",
    "mqtt_credential_exposure": "Secret / Credential Exposure",
    "hardcoded_mqtt_password": "Secret / Credential Exposure",
    "client_side_secret": "Secret / Credential Exposure",
    "exposed_mqtt_credentials": "Secret / Credential Exposure",
    # Cloud / Network
    "cloud_misconfig": "Cloud Storage Misconfiguration", "s3_misconfig": "Cloud Storage Misconfiguration",
    "open_port": "Exposed Network Service", "lateral_open_port": "Exposed Network Service",
    "outdated_software": "Outdated Software / Known CVE", "cve": "Outdated Software / Known CVE",
    # HTTP attacks
    "hpp": "HTTP Parameter Pollution", "http_parameter_pollution": "HTTP Parameter Pollution",
    "host_header_injection": "Host Header Injection", "host_header": "Host Header Injection",
    "cache_poisoning": "Cache Poisoning", "cache_deception": "Cache Poisoning",
    "undocumented_api": "Undocumented API Endpoint",
    # Vuln classes
    "deserialization": "Insecure Deserialization", "insecure_deserialization": "Insecure Deserialization",
    "race_condition": "Race Condition",
    "file_upload_bypass": "Insecure File Upload", "file_upload": "Insecure File Upload",
    "oauth_flaw": "OAuth/OIDC Vulnerability", "oauth_pkce_downgrade": "OAuth/OIDC Vulnerability",
    "oauth_missing_state": "OAuth/OIDC Vulnerability", "oauth": "OAuth/OIDC Vulnerability",
    "prototype_pollution": "Prototype Pollution",
    "websocket_vuln": "WebSocket Security Issue", "websocket": "WebSocket Security Issue",
    "mfa_bypass": "MFA/2FA Bypass", "otp_bypass": "MFA/2FA Bypass", "2fa_bypass": "MFA/2FA Bypass",
    "rate_limit_bypass": "Missing Rate Limiting", "no_rate_limiting": "Missing Rate Limiting",
    "missing_rate_limiting": "Missing Rate Limiting",
    "pii_exposure": "PII Exposure in API Response", "pii_leak": "PII Exposure in API Response",
    "payment_tampering": "Payment/Price Tampering", "price_manipulation": "Payment/Price Tampering",
    "clickjacking": "Clickjacking",
    "source_map_exposure": "Exposed JavaScript Source Map",
    "weak_tls": "Weak TLS Configuration", "tls_cert_issue": "TLS Certificate Issue",
    "insecure_cookie_attributes": "Insecure Cookie Attributes",
    "missing_httponly": "Insecure Cookie Attributes", "missing_secure_flag": "Insecure Cookie Attributes",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "missing_csrf_protection": "Cross-Site Request Forgery (CSRF)",
    "Missing CSRF Protection": "Cross-Site Request Forgery (CSRF)",
    "session_fixation": "Session Fixation",
    "session_timeout": "Missing Session Timeout", "missing_session_timeout": "Missing Session Timeout",
    "account_enumeration": "Account Enumeration via Timing",
    "account_enum_timing": "Account Enumeration via Timing",
    "weak_password_policy": "Weak Password Policy",
    "saml_vulnerability": "SAML Assertion Vulnerability", "saml_wrapping": "SAML Assertion Vulnerability",
    "ldap_injection": "LDAP Injection",
    "mail_header_injection": "Mail Header Injection",
    "csv_injection": "CSV Injection",
    "postmessage_hijacking": "postMessage Hijacking Risk",
    "web_storage": "Sensitive Data in Web Storage",
    "insecure_rng": "Insecure Random Number Generation",
    "weak_crypto": "Weak Encryption Algorithm", "weak_encryption": "Weak Encryption Algorithm",
    "padding_oracle": "Padding Oracle",
    "service_worker_scope_abuse": "Service Worker Abuse Risk",
    "service_worker_abuse": "Service Worker Abuse Risk",
    "webrtc_leak": "WebRTC IP Leakage",
    "grpc_exposed": "gRPC/SOAP Endpoint Exposed",
    # GraphQL → nearest canonical
    "graphql_circular_fragment_no_error": "Security Misconfiguration",
    "graphql_null_coercion": "Security Misconfiguration",
    "graphql_introspection": "Undocumented API Endpoint",
}


def _canonicalize_vuln_type(vuln_type: str) -> str:
    """Map a raw scanner vuln_type string to the canonical Vuln.* value.
    Returns the canonical string if a mapping exists, else the original."""
    if not vuln_type:
        return vuln_type
    # Exact match first (case-sensitive)
    if vuln_type in _CANONICAL_VULN_MAP:
        return _CANONICAL_VULN_MAP[vuln_type]
    # Case-insensitive match
    vl = vuln_type.lower()
    if vl in _CANONICAL_VULN_MAP:
        return _CANONICAL_VULN_MAP[vl]
    # Prefix/substring fallback for families of tags
    if (vl.startswith("js_secret") or "password_in_js" in vl or "api_key" in vl
            or "aws_secret" in vl or "hardcoded" in vl or "mqtt_cred" in vl
            or "client_side_secret" in vl):
        return "Secret / Credential Exposure"
    if "cors" in vl:
        return "CORS Misconfiguration"
    if "sqli" in vl or ("sql" in vl and "injection" in vl):
        return "SQL Injection"
    if "dom" in vl and "xss" in vl:
        return "DOM-based XSS"
    if "xss" in vl:
        return "Cross-Site Scripting (XSS)"
    if "ssrf" in vl:
        return "Server-Side Request Forgery (SSRF)"
    if "idor" in vl or "bola" in vl:
        return "Insecure Direct Object Reference (IDOR)"
    if "session_replay" in vl or "session replay" in vl:
        return "Broken Authentication"
    if "oauth" in vl:
        return "OAuth/OIDC Vulnerability"
    if "mfa" in vl or "otp" in vl or "2fa" in vl:
        return "MFA/2FA Bypass"
    if "file_upload" in vl or "upload_bypass" in vl:
        return "Insecure File Upload"
    if "jwt" in vl:
        return "JWT Vulnerability"
    if "rate_limit" in vl or "ratelimit" in vl:
        return "Missing Rate Limiting"
    if "prototype" in vl:
        return "Prototype Pollution"
    if "crlf" in vl:
        return "CRLF Injection"
    if "csrf" in vl:
        return "Cross-Site Request Forgery (CSRF)"
    if "deserialization" in vl:
        return "Insecure Deserialization"
    if "race_condition" in vl or "race condition" in vl:
        return "Race Condition"
    if "service_worker" in vl:
        return "Service Worker Abuse Risk"
    if "webrtc" in vl:
        return "WebRTC IP Leakage"
    if "grpc" in vl or "soap" in vl:
        return "gRPC/SOAP Endpoint Exposed"
    return vuln_type  # no mapping found — keep original


def _parse_generic(raw: dict, scan_id: str, source: str) -> Optional[NormalizedFinding]:
    """Fallback parser using raw.get fields."""
    try:
        title = (
            raw.get("title")
            or raw.get("name")
            or raw.get("type")
            or raw.get("vuln_type")
            or f"{source}-finding"
        )
        severity = (raw.get("severity") or raw.get("risk") or "info").lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "info"
        target = (
            raw.get("target")
            or raw.get("host")
            or raw.get("url")
            or raw.get("domain")
            or ""
        )
        url = raw.get("url") or raw.get("matched-at") or ""
        evidence = (
            raw.get("evidence")
            or raw.get("output")
            or raw.get("details")
            or raw.get("description")
            or ""
        )
        if isinstance(evidence, (dict, list)):
            evidence = json.dumps(evidence)
        vuln_type = (
            raw.get("vuln_type")
            or raw.get("type")
            or raw.get("category")
            or source
        )
        # Normalize vuln_type to canonical Vuln.* string so capmap coverage
        # correctly counts against the 63-class catalogue.
        vuln_type = _canonicalize_vuln_type(str(vuln_type))
        payload = raw.get("payload") or raw.get("poc") or ""
        cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        cvss = float(raw.get("cvss") or raw.get("cvss_score") or cvss_map.get(severity, 0.0))
        # Cap confidence for unconfirmed 'potential' findings — they need validation
        raw_vt = str(raw.get('vuln_type', '') or raw.get('type', '') or '')
        conf = float(raw.get('confidence', 0.7))
        if 'potential' in raw_vt.lower() or 'tentative' in raw_vt.lower():
            conf = min(conf, 0.65)  # below _INFERRED_MIN; forces sync-validation path
        return NormalizedFinding(
            scan_id=scan_id,
            target=str(target),
            title=str(title),
            severity=severity,
            vuln_type=str(vuln_type),
            evidence=str(evidence),
            payload=str(payload),
            url=str(url),
            tool=source,
            confidence=conf,
            cvss=cvss,
            raw=raw,
        )
    except Exception as exc:
        log.error("_parse_generic failed (source=%s): %s | raw=%s", source, exc, raw)
        return None


# ---------------------------------------------------------------------------
# ResultIngestionEngine
# ---------------------------------------------------------------------------

_PARSER_MAP: dict[str, Callable[[dict, str], Optional[NormalizedFinding]]] = {
    "nuclei": _parse_nuclei,
    "dalfox": _parse_dalfox,
    "sqlmap": _parse_sqlmap,
    "subfinder": _parse_subfinder,
    "httpx": _parse_httpx,
}


class ResultIngestionEngine:
    """Central funnel for all tool results → PostgreSQL → attack graph → UI broadcast."""

    def __init__(self) -> None:
        self._broadcast_cb: Optional[Callable[[dict], None]] = None

    def _init_db(self) -> None:
        """No-op: PG schema is managed by DBManager._ensure_schema(). Kept for backwards compatibility."""
        pass

    def set_broadcast_callback(self, cb: Callable[[dict], None]) -> None:
        """Register a callback(finding_dict) called for each new finding."""
        self._broadcast_cb = cb

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # Phase E: vuln types that trigger synchronous pre-store validation (low FP, fast probe)
    # cors_origin_reflected / cors_misconfiguration added: CORS is fast to re-probe (one OPTIONS
    # request) and has a high FP rate from tools that flag permissive-but-intentional wildcard
    # CORS policies as vulnerabilities without checking ACAC.
    _SYNC_VALIDATE_TYPES = frozenset({
        # canonical names (post _canonicalize_vuln_type) — must match AFTER normalization
        "Cross-Site Scripting (XSS)",
        "SQL Injection",
        "Server-Side Template Injection (SSTI)",
        "Local File Inclusion (LFI)",
        "Open Redirect",
        "XML External Entity (XXE)",
        "CORS Misconfiguration",
    })
    # Async validation (fire-and-forget; too slow/risky to block ingest)
    _ASYNC_VALIDATE_TYPES = frozenset({
        "Server-Side Request Forgery (SSRF)",
        "OS Command Injection",
        "Broken Authentication",
        "Insecure Direct Object Reference (IDOR)",
    })

    def _normalize_url_for_dedup(self, url: str, vuln_type: str) -> str:
        """Path-template normalization for semantic dedup (MLR2).
        /api/v1/users/123 → /api/v1/users/{id}
        /api/v1/users/abc-def-ghi → /api/v1/users/{uuid}
        Prevents storing N findings for the same injection point tested on N IDs.
        """
        import re as _re
        try:
            from urllib.parse import urlparse, urlencode, parse_qs
            p = urlparse(url)
            # Normalize path segments
            path = _re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', p.path)
            path = _re.sub(r'/[0-9a-fA-F]{24,}', '/{hex}', path)
            path = _re.sub(r'/\d+', '/{id}', path)
            # Normalize query param values (keep keys, replace values)
            params = parse_qs(p.query)
            norm_params = {k: ["{val}"] for k in params}
            norm_query = urlencode(norm_params, doseq=True) if norm_params else ""
            return f"{p.scheme}://{p.netloc}{path}?{norm_query}" if norm_query else f"{p.scheme}://{p.netloc}{path}"
        except Exception:
            return url

    # ── URL sanitization helper ──────────────────────────────────────────────
    @staticmethod
    def _sanitize_url(url: str, scan_target: str) -> str:
        """Fix malformed agent-generated URLs and return the canonical form.

        Agents sometimes build URLs by string-concatenating a scan target that
        already has a scheme with a path, producing garbage like:
          ://vulnbank.org/login          (missing scheme)
          ://://vulnbank.org/login       (double garbage)
          ://://://                      (fully garbled)

        Root cause: code like  f"{scheme}://{target}{path}"  where `scheme`
        was already '' (empty) because target had no detected scheme.

        Fix strategy:
          1. Strip leading '://' repetitions.
          2. If result has no scheme, prepend the scheme from scan_target.
          3. If still no valid host, return the original (let dedup handle it).
        """
        if not url:
            return url
        import re as _re
        # Strip leading '://' garbage (1 or more times)
        cleaned = _re.sub(r'^(://)+', '', url)
        if not cleaned:
            # URL was purely '://' noise — use scan_target as the canonical URL
            return scan_target if scan_target else url
        # If it now looks like a valid URL, return it
        if cleaned.startswith(('http://', 'https://')):
            return cleaned
        # No scheme — prepend from scan_target
        try:
            from urllib.parse import urlparse as _up
            scheme = _up(scan_target).scheme or 'https'
            # Generic: prepend scheme to any string that looks like host/path.
            # Condition: cleaned contains a dot (hostname) or a slash (path) after stripping.
            if '.' in cleaned or '/' in cleaned:
                return f"{scheme}://{cleaned}"
        except Exception:
            pass
        return url

    @staticmethod
    def _is_in_scope(url: str, scan_target: str) -> bool:
        """Return True if `url` belongs to the same host/domain as scan_target.

        A finding is in-scope when:
          - url is empty/None (network-level finding with no specific URL)
          - url host ends with the scan target's registered domain
          - url host IS the scan target host exactly
          - url is localhost / 127.x (internal probe targets are in-scope)

        Off-scope = url points to a completely different domain
        (e.g. sandbox.gimmeit.net.au when scanning vulnbank.org).
        Off-scope findings are NEVER false-positived; they are CANDIDATE-capped
        so a human reviewer can investigate cross-origin issues separately.
        """
        if not url:
            return True   # no URL = network-level finding; always in-scope
        try:
            from urllib.parse import urlparse as _up
            raw_host = _up(url).netloc.split(':')[0]
            if raw_host.startswith('www.'): raw_host = raw_host[4:]
            if raw_host.startswith('m.'): raw_host = raw_host[2:]
            host = raw_host
            if not host:
                return True
            if host in ('localhost', '127.0.0.1', '::1'):
                # When scan target has an explicit port, require the finding URL
                # to use the same port — prevents cross-service contamination
                # (e.g. DVWA:8888 scan should not absorb JuiceShop:9090 findings).
                target_port = _up(scan_target).port
                url_port = _up(url).port
                if target_port and url_port and target_port != url_port:
                    return False
                return True
            raw_target = _up(scan_target).netloc.split(':')[0]
            if raw_target.startswith('www.'): raw_target = raw_target[4:]
            if raw_target.startswith('m.'): raw_target = raw_target[2:]
            target_host = raw_target
            if not target_host:
                # scan_target has no scheme — try as plain host
                plain = scan_target.split('/')[0]
                if plain.startswith('www.'): plain = plain[4:]
                if plain.startswith('m.'): plain = plain[2:]
                target_host = plain
            if not target_host:
                return True   # unknown target — don't filter
            # Match: exact or subdomain
            return host == target_host or host.endswith('.' + target_host)
        except Exception:
            return True   # on parse error, let it through

    def ingest(self, result: RawResult, confidence_threshold: float = 0.5) -> Optional[NormalizedFinding]:
        """Parse → validate → semantic-dedup → filter → store → graph → broadcast.
        Phase E: FindingValidationEngine pre-filter + AI confidence rescoring.
        """
        try:
            finding = self._parse(result)
        except Exception as exc:
            log.error("ingest: parse error [source=%s scan=%s]: %s", result.source, result.scan_id, exc)
            return None

        if finding is None:
            return None

        # Skip empty ghost findings — no vuln_type AND no url = useless stub
        _vt = (finding.vuln_type or "").strip()
        _url = (finding.url or "").strip()
        if not _vt and not _url:
            log.debug("ingest: skipping empty finding stub (no vuln_type, no url) target=%s",
                      finding.target)
            return None
        # Drop URL-less chain suggestion stubs from ExploitChainEngine.
        # These are speculative attack paths, not confirmed findings. They have no
        # real URL and pollute the findings list with :// rows.
        _ev = (finding.evidence or "").strip()
        if not _url and "Chain detected by ExploitChainEngine" in _ev:
            log.debug("ingest: dropping URL-less chain suggestion stub [%s]", _vt)
            return None

        # Fix malformed agent-generated URLs (e.g. ://vulnbank.org/login)
        # Root cause: agents concatenate empty scheme + target + path.
        # Must happen before dedup so the fixed URL is what gets stored/deduped.
        if _url.startswith('://') or _url == '://':
            fixed = self._sanitize_url(
                _url,
                finding.target or
                (result.raw.get("target") if isinstance(result.raw, dict) else None) or
                ""
            )
            if fixed != _url:
                log.debug("ingest: fixed malformed URL [%s] → [%s]", _url, fixed)
                finding.url = fixed
            # Drop finding if URL is still malformed after sanitization
            if not finding.url or finding.url in ("://", "://://") or finding.url.startswith("://"):
                log.debug("ingest: dropped unfixable malformed URL [%s] vuln_type=%s", _url, _vt)
                return None

        # Mark whether this finding's URL is in-scope for the scan target.
        # Off-scope findings (e.g. sandbox.gimmeit.net.au when scanning vulnbank.org)
        # are allowed through — they may be valid cross-origin issues — but the judge
        # must not promote them past CANDIDATE without explicit confirmation.
        # We tag the finding so the judge thread can use this signal.
        _scan_target = finding.target or ""
        finding._off_scope = not self._is_in_scope(finding.url, _scan_target)  # type: ignore[attr-defined]
        if finding._off_scope:  # type: ignore[attr-defined]
            log.info(
                "ingest: off-scope URL [%s @ %s] (scan target=%s) — capping at CANDIDATE",
                finding.vuln_type, finding.url, _scan_target,
            )
            # Hard-cap confidence so heuristic judge can't auto-promote to CONFIRMED/INFERRED.
            # The LLM judge will still run and may upgrade if evidence is conclusive.
            finding.confidence = min(finding.confidence, 0.59)  # below _INFERRED_MIN (0.60)

        # 1. Confidence Filtering (Noise Reduction)
        if finding.confidence < confidence_threshold:
            log.info("ingest: suppressing low-confidence finding (%.2f < %.2f) [%s]",
                     finding.confidence, confidence_threshold, finding.vuln_type)
            return None

        # Phase E-1: Synchronous validation for fast-probe vuln types (OR2/RTL2)
        # Blocks ingest only for types where re-probe is <500ms and FP rate is high.
        if finding.vuln_type in self._SYNC_VALIDATE_TYPES:
            try:
                from oneinfinity.findings.finding_validation_engine import FindingValidationEngine
                vr = FindingValidationEngine().validate(
                    finding.url, finding.vuln_type, finding.payload
                )
                if not vr.validated:
                    log.info("ingest: validation failed → false_positive suppressed [%s @ %s]",
                             finding.vuln_type, finding.url)
                    finding.status = "false_positive"
                    return None   # do not store confirmed FPs
                # Boost confidence on validated finding
                finding.confidence = max(finding.confidence, min(0.95, vr.confidence))
                finding.status = "confirmed"
                log.debug("ingest: validated [%s] confidence → %.2f", finding.vuln_type, finding.confidence)
            except Exception as _ve:
                log.debug("ingest: sync validation error (fail-open): %s", _ve)
                # Fail-open: let finding through if validator errors (PE2/RTL2 TP preservation)

        # Phase E-2: Async validation for slow/risky types (fire-and-forget, non-blocking)
        elif finding.vuln_type in self._ASYNC_VALIDATE_TYPES and finding.confidence >= 0.7:
            import threading as _threading
            _f_copy = finding  # closure capture
            def _async_validate():
                try:
                    from oneinfinity.findings.finding_validation_engine import FindingValidationEngine
                    vr = FindingValidationEngine().validate(
                        _f_copy.url, _f_copy.vuln_type, _f_copy.payload
                    )
                    if vr.validated:
                        _f_copy.confidence = max(_f_copy.confidence, min(0.95, vr.confidence))
                        _f_copy.status = "confirmed"
                    else:
                        _f_copy.status = "needs_review"
                    log.debug("ingest async-validate: [%s] → %s (%.2f)",
                              _f_copy.vuln_type, _f_copy.status, _f_copy.confidence)
                except Exception as _ae:
                    log.debug("ingest: async validation error: %s", _ae)
            _threading.Thread(target=_async_validate, daemon=True,
                               name=f"async-val-{finding.finding_id[:8]}").start()

        # Phase E-3: Path-template semantic dedup (MLR2)
        # Normalize URL before DB dedup to catch same-injection-point findings
        # that differ only in path parameter values.
        normalized_url = self._normalize_url_for_dedup(finding.url, finding.vuln_type)
        if normalized_url != finding.url:
            log.debug("ingest: normalized URL for dedup [%s] %s → %s",
                      finding.vuln_type, finding.url, normalized_url)
            finding.url = normalized_url

        # 2. Check-then-store (dedup by scan_id+vuln_type+normalized_url)
        # Falls back to a local JSONL file when PostgreSQL is unavailable.
        stored = False
        _pg_err: Optional[Exception] = None
        try:
            stored = self._check_and_store(finding)
        except RuntimeError as exc:
            _pg_err = exc
            log.warning("ingest: PG unavailable (%s) — writing to local fallback", exc)
            try:
                from pathlib import Path as _Path
                fallback_dir = _Path.home() / ".oneinfinity" / finding.scan_id
                fallback_dir.mkdir(parents=True, exist_ok=True)
                fallback_path = fallback_dir / "findings_fallback.jsonl"
                with fallback_path.open("a", encoding="utf-8") as _fh:
                    _fh.write(json.dumps(finding.to_dict()) + "\n")
                log.info("ingest: finding written to fallback [%s]", fallback_path)
                stored = True
            except Exception as fb_exc:
                log.error("ingest: fallback write failed: %s", fb_exc)
                return None
        except Exception as exc:
            log.error("ingest: DB write failed: %s", exc)
            return None

        if not stored:
            log.debug("ingest: duplicate skipped [%s @ %s]", finding.vuln_type, finding.url)
            return None

        self._broadcast(finding)           # fire immediately — UI gets the event

        # Fire learning graph update (async, non-blocking, non-fatal)
        _glw = _get_graph_learning_writer()
        if _glw is not None:
            _glw.write_finding_async(finding.to_dict())

        import threading
        threading.Thread(
            target=self._update_graph,
            args=(finding,),
            daemon=True,
            name=f"graph-update-{finding.finding_id[:8]}",
        ).start()

        # Phase 0 — Verified Finding Architecture: LLM judge (non-blocking)
        # Runs after DB write so the finding_id is guaranteed to exist.
        # Uses evaluate_and_persist() which writes confirmed_tier + judge_verdict back.
        # Daemon thread — never blocks the scan pipeline; failure is logged, not fatal.
        _finding_dict = finding.to_dict()
        threading.Thread(
            target=self._run_judge,
            args=(_finding_dict,),
            daemon=True,
            name=f"judge-{finding.finding_id[:8]}",
        ).start()
        return finding

    def _check_and_store(self, finding: NormalizedFinding) -> bool:
        """Atomically check for duplicate and store if new via PostgreSQL."""
        return _require_pg().sync_check_and_save_finding(finding.to_dict())

    def ingest_batch(self, results: List[RawResult]) -> List[NormalizedFinding]:
        """Ingest a list of RawResults; returns list of successfully parsed findings."""
        findings: List[NormalizedFinding] = []
        for result in results:
            f = self.ingest(result)
            if f is not None:
                findings.append(f)
        return findings

    def ingest_recon_asset(
        self,
        scan_id: str,
        asset_type: str,
        value: str,
        metadata: Optional[dict] = None,
    ) -> None:
        """Store a recon asset (subdomain, endpoint, service, technology)."""
        if metadata is None:
            metadata = {}
        asset_id = str(uuid.uuid4())[:12]
        _require_pg().sync_save_recon_asset(asset_id, scan_id, asset_type, value, metadata)

    def store_raw_findings(self, findings: List[dict]) -> int:
        """Store raw findings before validation."""
        return _require_pg().sync_store_raw_findings(findings)

    def persist_finding(self, finding: dict) -> None:
        """Persist an already-normalised finding dict to the findings table."""
        nf = NormalizedFinding(
            finding_id  = finding.get("finding_id") or finding.get("id") or str(uuid.uuid4())[:12],
            scan_id     = finding.get("scan_id", ""),
            target      = finding.get("target", ""),
            title       = finding.get("title", ""),
            severity    = finding.get("severity", "info"),
            vuln_type   = finding.get("vuln_type") or finding.get("attack_type", ""),
            evidence    = finding.get("evidence", ""),
            payload     = finding.get("payload", ""),
            url         = finding.get("url", ""),
            tool        = finding.get("tool", ""),
            confidence  = float(finding.get("confidence", 0.8)),
            cvss        = float(finding.get("cvss", 0.0)),
            status      = finding.get("status", "new"),
            created_at  = finding.get("created_at", datetime.utcnow().isoformat()),
            raw         = finding,
        )
        self._store_finding(nf)
        self._broadcast(nf)

    def get_findings(
        self,
        scan_id: str = None,
        target: str = None,
        severity: str = None,
    ) -> List[dict]:
        """Query findings with optional filters. Falls back to local scan files when Postgres unavailable."""
        try:
            return _require_pg().sync_get_findings(scan_id=scan_id, target=target, severity=severity)
        except Exception:
            pass
        # Local fallback: read unified_findings.json from the scan output directory
        return self._get_findings_local(scan_id=scan_id, target=target, severity=severity)

    def _get_findings_local(self, scan_id=None, target=None, severity=None) -> List[dict]:
        from pathlib import Path as _Path
        base = _Path.home() / ".oneinfinity"
        results: List[dict] = []
        scan_dirs = [base / scan_id] if scan_id else sorted(base.iterdir()) if base.exists() else []
        for d in scan_dirs:
            if not d.is_dir():
                continue
            # --- unified_findings.json (JSON array / dict) ---
            for fname in ("unified_findings.json", "full_scan/unified_findings.json"):
                fpath = d / fname
                if not fpath.exists():
                    continue
                try:
                    data = json.loads(fpath.read_text())
                    items = data if isinstance(data, list) else data.get("findings", [])
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        if target and item.get("target", "") != target:
                            continue
                        if severity and item.get("severity", "").lower() != severity.lower():
                            continue
                        results.append(item)
                except Exception:
                    pass
            # --- findings_fallback.jsonl (one JSON object per line) ---
            fallback_path = d / "findings_fallback.jsonl"
            if fallback_path.exists():
                try:
                    for line in fallback_path.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except Exception:
                            continue
                        if not isinstance(item, dict):
                            continue
                        if target and item.get("target", "") != target:
                            continue
                        if severity and item.get("severity", "").lower() != severity.lower():
                            continue
                        results.append(item)
                except Exception:
                    pass
        return results

    def delete_findings_for_scan(self, scan_id: str) -> int:
        """Delete all findings for the given scan_id. Returns the count deleted."""
        return _require_pg().sync_delete_findings_for_scan(scan_id)

    def get_recon_assets(
        self,
        scan_id: str = None,
        asset_type: str = None,
    ) -> List[dict]:
        """Query recon assets with optional filters."""
        return _require_pg().sync_get_recon_assets(scan_id=scan_id, asset_type=asset_type)

    def finding_count(self, scan_id: str) -> int:
        """Return number of findings for a given scan_id."""
        return _require_pg().sync_finding_count(scan_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse(self, result: RawResult) -> Optional[NormalizedFinding]:
        source = (result.source or "").lower()
        parser = _PARSER_MAP.get(source)
        if parser:
            return parser(result.raw, result.scan_id)
        return _parse_generic(result.raw, result.scan_id, source)

    def _store_finding(self, finding: NormalizedFinding) -> None:
        """Unconditionally persist a finding (used by persist_finding, no dup check)."""
        _require_pg().sync_save_finding(finding.to_dict())

    def _update_graph(self, finding: NormalizedFinding) -> None:
        """Push finding into AttackGraphBrain as a VULNERABILITY node."""
        try:
            from oneinfinity.intelligence.attack_graph_brain import get_brain
            get_brain().integrate_vuln(finding.to_dict())
        except Exception as exc:
            log.error("_update_graph: graph update failed [finding=%s]: %s",
                      finding.finding_id, exc)

    def _broadcast(self, finding: NormalizedFinding) -> None:
        if self._broadcast_cb is None:
            return
        try:
            self._broadcast_cb(finding.to_dict())
        except Exception as exc:
            log.error("_broadcast: callback raised [finding=%s]: %s",
                      finding.finding_id, exc)

    def _run_judge(self, finding_dict: dict) -> None:
        """
        Run the LLM judge for a persisted finding (called from daemon thread).

        Writes confirmed_tier + judge_verdict back to postgres via
        evaluate_and_persist(). Never raises — all errors are logged.
        Safe to run concurrently with other judge threads.
        """
        try:
            from oneinfinity.findings.finding_judge import get_judge
            get_judge().evaluate_and_persist(finding_dict)
        except Exception as exc:
            log.warning("_run_judge: judge failed [finding=%s]: %s",
                        finding_dict.get("finding_id", "?"), exc)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[ResultIngestionEngine] = None
_engine_lock = threading.Lock()


def get_ingestion_engine() -> ResultIngestionEngine:
    """Return the module-level ResultIngestionEngine singleton (created on first call)."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = ResultIngestionEngine()
    return _engine
