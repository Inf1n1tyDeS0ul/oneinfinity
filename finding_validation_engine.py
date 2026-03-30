"""
Finding Validation Engine — Verify discovered vulnerabilities before reporting.
Uses payload reflection, HTTP probing, response analysis, and diff comparison.
"""

import re
import json
import time
import logging
import urllib.request
import urllib.parse
import urllib.error
import ssl
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Compiled evidence patterns
EVIDENCE_PATTERNS = {
    "sqli": [
        re.compile(r"SQL syntax|mysql_fetch|ORA-\d+|SQLSTATE|syntax error|unclosed quotation|sqlite3\.OperationalError|pg_query|Microsoft OLE DB|ODBC SQL Server", re.I),
        re.compile(r"Warning:.*mysql|Warning:.*pdo|Warning:.*sqlite|Warning:.*pg_", re.I),
    ],
    "xss": [
        re.compile(r"<script[^>]*>alert|onerror\s*=\s*alert|onload\s*=\s*alert", re.I),
        re.compile(r"OI_[A-Z]{8}"),  # Canary pattern
        re.compile(r"<svg\s+onload|<img\s+src=x\s+onerror"),
    ],
    "ssrf": [
        re.compile(r"ami-id|instance-id|availability-zone|169\.254\.169\.254|iam/security-credentials", re.I),
        re.compile(r"root:x:0:0|/bin/bash|/sbin/nologin"),
        re.compile(r"metadata\.google\.internal|computeMetadata"),
    ],
    "lfi": [
        re.compile(r"root:x:0:0|daemon:x:|bin:x:|sys:x:"),
        re.compile(r"\[boot loader\]|\[operating systems\]"),  # win.ini
        re.compile(r"PHP Fatal error|include\(\)|failed to open stream"),
    ],
    "ssti": [
        re.compile(r"\b49\b"),  # 7*7 = 49
        re.compile(r"uid=\d+|www-data|root"),
        re.compile(r"TemplateNotFound|jinja2\.|freemarker\."),
    ],
    "cmdi": [
        re.compile(r"uid=\d+\(\w+\)\s+gid=\d+"),  # id command output
        re.compile(r"root:x:0:0"),                  # /etc/passwd
        re.compile(r"total \d+\ndrwx"),             # ls output
    ],
    "open_redirect": [
        re.compile(r"evil\.oneinfinity\.test"),
        re.compile(r"Location:\s*https?://evil"),
    ],
    "xxe": [
        re.compile(r"root:x:0:0|daemon:x:"),
        re.compile(r"ami-id|instance-id"),
    ],
    "auth_bypass": [
        re.compile(r"dashboard|welcome|logged.?in|admin panel|success", re.I),
        re.compile(r'"token"\s*:|"access_token"\s*:|"session"\s*:'),
    ],
    "idor": [
        re.compile(r'"email"\s*:|"username"\s*:|"password"\s*:|"phone"\s*:', re.I),
        re.compile(r'"user_id"\s*:|"account"\s*:', re.I),
    ],
}

TIME_BASED_TYPES = {"sqli_time", "cmdi_time"}
TIMING_THRESHOLD_S = 6.0


@dataclass
class ValidationResult:
    validated: bool = False
    vuln_type: str = ""
    url: str = ""
    payload: str = ""
    evidence: str = ""
    evidence_type: str = ""
    response_status: int = 0
    response_body_snippet: str = ""
    duration_ms: float = 0.0
    confidence: float = 0.0  # 0.0 - 1.0
    flags: list = field(default_factory=list)
    poc_steps: list = field(default_factory=list)
    error: str = ""
    retry_count: int = 0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class FindingValidationEngine:
    """Verify vulnerabilities using targeted HTTP probes and response analysis."""

    def __init__(self, timeout: int = 15, max_retries: int = 2):
        self.timeout = timeout
        self.max_retries = max_retries
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE
        self._baseline_cache: OrderedDict = OrderedDict()
        self._baseline_cache_limit = 128

    # ── Public Interface ──────────────────────────────────────────────────────

    def validate(self, finding: dict) -> ValidationResult:
        """Main validation entry point. Returns ValidationResult."""
        url = finding.get("url", "")
        vuln_type = finding.get("vuln_type", finding.get("type", "unknown")).lower().replace("-", "_")
        payload = finding.get("payload", "")
        param = finding.get("param", "q")
        method = finding.get("method", "GET")

        result = ValidationResult(vuln_type=vuln_type, url=url, payload=payload)

        for attempt in range(self.max_retries + 1):
            result.retry_count = attempt
            try:
                validated = self._dispatch(result, finding, url, vuln_type, payload, param, method)
                if validated:
                    result.validated = True
                    break
            except Exception as e:
                result.error = str(e)[:200]
                logger.debug(f"Validation attempt {attempt} error: {e}")
                time.sleep(1)

        return result

    def validate_batch(self, findings: list) -> list:
        return [self.validate(f) for f in findings]

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def _get_dispatch(self) -> dict:
        """Return the full dispatch mapping of vuln_type → validator method."""
        return {
            "sqli": self._validate_sqli,
            "sql_injection": self._validate_sqli,
            "xss": self._validate_xss,
            "cross_site_scripting": self._validate_xss,
            "ssrf": self._validate_ssrf,
            "lfi": self._validate_lfi,
            "local_file_inclusion": self._validate_lfi,
            "ssti": self._validate_ssti,
            "cmdi": self._validate_cmdi,
            "cmd_injection": self._validate_cmdi,
            "open_redirect": self._validate_open_redirect,
            "auth_bypass": self._validate_auth_bypass,
            "idor": self._validate_idor,
            "xxe": self._validate_xxe,
            "http_request_smuggling": self._validate_passthrough,
            # OWASP gap checks
            "csrf":                  self.validate_csrf,
            "missing_csrf":          self.validate_csrf,
            "cookie_attributes":     self.validate_cookie_attrs,
            "insecure_cookie":       self.validate_cookie_attrs,
            "session_fixation":      self.validate_session_fixation,
            "ldap_injection":        self.validate_ldap_injection,
            "weak_tls":              self.validate_weak_tls,
            "ssrf_oob":              self.validate_ssrf_oob,
            "padding_oracle":        self.validate_padding_oracle,
            "account_enumeration":   self.validate_account_enumeration,
        }

    def _dispatch(self, result: ValidationResult, finding: dict, url: str,
                  vuln_type: str, payload: str, param: str, method: str) -> bool:
        dispatch = self._get_dispatch()
        fn = dispatch.get(vuln_type, self._validate_generic)
        return fn(result, finding, url, payload, param, method)

    # ── Type-Specific Validators ──────────────────────────────────────────────

    def _validate_sqli(self, result: ValidationResult, finding: dict,
                       url: str, payload: str, param: str, method: str) -> bool:
        from exploit_generator import SQLI_PAYLOADS
        baseline = self._baseline(url, method, param)
        # Try each category
        for category, payloads in SQLI_PAYLOADS.items():
            for p in payloads[:2]:
                resp = self._send(url, method, param, p)
                if not resp:
                    continue
                result.response_status = resp["status"]
                result.duration_ms = resp["duration_ms"]
                body = resp["body"]

                # Time-based detection — must exceed baseline by threshold (not just absolute value)
                if category == "blind_time":
                    _baseline_ms = (baseline or {}).get("duration_ms", 0.0)
                    _delta_ms = resp["duration_ms"] - _baseline_ms
                    if _delta_ms >= TIMING_THRESHOLD_S * 1000:
                        result.evidence = (
                            f"Time-based SQLi: {resp['duration_ms']:.0f}ms "
                            f"(baseline {_baseline_ms:.0f}ms, delta {_delta_ms:.0f}ms)"
                        )
                        result.evidence_type = "timing"
                        result.confidence = 0.85
                        result.payload = p
                        result.flags.append("time_based_sqli")
                        self._build_poc(result, url, param, p, method)
                        return True

                # Error-based detection
                for pat in EVIDENCE_PATTERNS["sqli"]:
                    # Suppress if baseline contains same SQL error (likely generic error page)
                    if baseline and pat.search(baseline.get("body", "")):
                        continue
                    m = pat.search(body)
                    if m:
                        result.evidence = m.group(0)[:200]
                        result.evidence_type = "error_message"
                        result.confidence = 0.95
                        result.payload = p
                        result.response_body_snippet = body[:500]
                        result.flags.append("sql_error_disclosure")
                        self._build_poc(result, url, param, p, method)
                        return True
        return False

    def _validate_xss(self, result: ValidationResult, finding: dict,
                      url: str, payload: str, param: str, method: str) -> bool:
        import random, string
        from exploit_generator import XSS_PAYLOADS

        canary = "OIXSS" + "".join(random.choices(string.ascii_uppercase, k=6))
        test_payload = f"<script>alert('{canary}')</script>"

        resp = self._send(url, method, param, test_payload)
        if resp and canary in resp["body"]:
            if not self._content_type_is_html(resp.get("headers", {})):
                return False
            result.evidence = f"Canary reflected: {canary}"
            result.evidence_type = "reflection"
            result.confidence = 0.98
            result.payload = test_payload
            result.response_status = resp["status"]
            result.response_body_snippet = resp["body"][:300]
            result.flags.append("xss_reflected")
            self._build_poc(result, url, param, test_payload, method)
            return True

        # Try standard payloads
        for p in XSS_PAYLOADS["reflected"][:4]:
            resp = self._send(url, method, param, p)
            if not resp:
                continue
            body = resp["body"]
            if not self._content_type_is_html(resp.get("headers", {})):
                continue
            for pat in EVIDENCE_PATTERNS["xss"]:
                if pat.search(body):
                    result.evidence = f"XSS payload reflected in response"
                    result.evidence_type = "reflection"
                    result.confidence = 0.9
                    result.payload = p
                    result.response_status = resp["status"]
                    result.response_body_snippet = body[:300]
                    result.flags.append("xss_reflected")
                    self._build_poc(result, url, param, p, method)
                    return True
        return False

    def _validate_ssrf(self, result: ValidationResult, finding: dict,
                       url: str, payload: str, param: str, method: str) -> bool:
        from exploit_generator import SSRF_PAYLOADS
        baseline = self._baseline(url, method, param)

        for variant, targets in SSRF_PAYLOADS.items():
            for target_url in targets[:2]:
                resp = self._send(url, method, param, target_url)
                if not resp:
                    continue
                body = resp["body"]
                for pat in EVIDENCE_PATTERNS["ssrf"]:
                    if baseline and pat.search(baseline.get("body", "")):
                        continue
                    m = pat.search(body)
                    if m:
                        result.evidence = f"SSRF confirmed: {m.group(0)[:100]}"
                        result.evidence_type = "internal_access"
                        result.confidence = 0.95
                        result.payload = target_url
                        result.response_status = resp["status"]
                        result.response_body_snippet = body[:400]
                        result.flags.append(f"ssrf_{variant}")
                        self._build_poc(result, url, param, target_url, method)
                        return True
        return False

    def _validate_lfi(self, result: ValidationResult, finding: dict,
                      url: str, payload: str, param: str, method: str) -> bool:
        from exploit_generator import LFI_PAYLOADS
        baseline = self._baseline(url, method, param)
        for p in LFI_PAYLOADS[:6]:
            resp = self._send(url, method, param, p)
            if not resp:
                continue
            body = resp["body"]
            for pat in EVIDENCE_PATTERNS["lfi"]:
                if baseline and pat.search(baseline.get("body", "")):
                    continue
                m = pat.search(body)
                if m:
                    result.evidence = f"LFI confirmed: {m.group(0)[:100]}"
                    result.evidence_type = "file_content"
                    result.confidence = 0.96
                    result.payload = p
                    result.response_status = resp["status"]
                    result.response_body_snippet = body[:400]
                    result.flags.append("lfi_file_read")
                    self._build_poc(result, url, param, p, method)
                    return True
        return False

    def _validate_ssti(self, result: ValidationResult, finding: dict,
                       url: str, payload: str, param: str, method: str) -> bool:
        baseline = self._baseline(url, method, param)
        baseline_body = (baseline or {}).get("body", "")
        # Send probe payloads and check for 49 (7*7)
        for p in ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}"]:
            resp = self._send(url, method, param, p)
            if resp and "49" in resp["body"] and "49" not in baseline_body:
                result.evidence = "SSTI: 7*7=49 evaluated"
                result.evidence_type = "code_execution"
                result.confidence = 0.97
                result.payload = p
                result.response_status = resp["status"]
                result.response_body_snippet = resp["body"][:300]
                result.flags.append("ssti_rce_risk")
                self._build_poc(result, url, param, p, method)
                return True
        return False

    def _validate_cmdi(self, result: ValidationResult, finding: dict,
                       url: str, payload: str, param: str, method: str) -> bool:
        from exploit_generator import CMDI_PAYLOADS
        baseline = self._baseline(url, method, param)
        for p in CMDI_PAYLOADS[:5]:
            resp = self._send(url, method, param, p)
            if not resp:
                continue
            body = resp["body"]
            for pat in EVIDENCE_PATTERNS["cmdi"]:
                if baseline and pat.search(baseline.get("body", "")):
                    continue
                m = pat.search(body)
                if m:
                    result.evidence = f"CMDi: {m.group(0)[:100]}"
                    result.evidence_type = "command_output"
                    result.confidence = 0.98
                    result.payload = p
                    result.response_status = resp["status"]
                    result.response_body_snippet = body[:400]
                    result.flags.append("remote_code_execution")
                    self._build_poc(result, url, param, p, method)
                    return True
        return False

    def _validate_open_redirect(self, result: ValidationResult, finding: dict,
                                 url: str, payload: str, param: str, method: str) -> bool:
        evil = "https://evil.oneinfinity.test"
        resp = self._send(url, method, param, evil, follow_redirects=False)
        if resp:
            location = resp.get("headers", {}).get("Location", "")
            if resp.get("status", 0) in (301, 302, 303, 307, 308) and evil in location:
                result.evidence = f"Open redirect to {evil}"
                result.evidence_type = "redirect"
                result.confidence = 0.92
                result.payload = evil
                result.response_status = resp["status"]
                result.flags.append("open_redirect")
                self._build_poc(result, url, param, evil, method)
                return True
        return False

    def _validate_auth_bypass(self, result: ValidationResult, finding: dict,
                               url: str, payload: str, param: str, method: str) -> bool:
        from exploit_generator import AUTH_BYPASS_PAYLOADS
        # Try header-based bypass
        for header_dict in AUTH_BYPASS_PAYLOADS["header_bypass"][:4]:
            resp = self._send_with_headers(url, header_dict)
            if resp and resp["status"] in (200, 302):
                body = resp["body"]
                for pat in EVIDENCE_PATTERNS["auth_bypass"]:
                    m = pat.search(body)
                    if m:
                        result.evidence = f"Auth bypass via header: {header_dict}"
                        result.evidence_type = "access_granted"
                        result.confidence = 0.85
                        result.payload = json.dumps(header_dict)
                        result.response_status = resp["status"]
                        result.flags.append("authentication_bypass")
                        self._build_poc(result, url, param, str(header_dict), method)
                        return True
        return False

    def _validate_idor(self, result: ValidationResult, finding: dict,
                       url: str, payload: str, param: str, method: str) -> bool:
        # Compare response for own ID vs other IDs
        own_id = finding.get("user_id", "1")
        other_id = "2" if own_id == "1" else "1"

        resp_own = self._send(url, method, param, own_id)
        resp_other = self._send(url, method, param, other_id)

        if resp_own and resp_other:
            if resp_other["status"] == 200 and len(resp_other["body"]) > 50:
                for pat in EVIDENCE_PATTERNS["idor"]:
                    if pat.search(resp_other["body"]):
                        result.evidence = f"IDOR: accessed resource for ID={other_id}"
                        result.evidence_type = "unauthorized_access"
                        result.confidence = 0.88
                        result.payload = other_id
                        result.response_status = resp_other["status"]
                        result.response_body_snippet = resp_other["body"][:300]
                        result.flags.append("idor_horizontal")
                        self._build_poc(result, url, param, other_id, method)
                        return True
        return False

    def _validate_xxe(self, result: ValidationResult, finding: dict,
                      url: str, payload: str, param: str, method: str) -> bool:
        from exploit_generator import SQLI_PAYLOADS  # reuse send mechanism
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        resp = self._send(url, "POST", param, xxe_payload,
                          content_type="application/xml")
        if resp:
            body = resp["body"]
            for pat in EVIDENCE_PATTERNS["xxe"]:
                m = pat.search(body)
                if m:
                    result.evidence = f"XXE: {m.group(0)[:100]}"
                    result.evidence_type = "file_content"
                    result.confidence = 0.97
                    result.payload = xxe_payload
                    result.response_status = resp["status"]
                    result.flags.append("xxe_file_read")
                    self._build_poc(result, url, param, xxe_payload, "POST")
                    return True
        return False

    def _validate_passthrough(self, result: ValidationResult, finding: dict,
                              url: str, payload: str, param: str, method: str) -> bool:
        """Pass through tool-validated findings that can't be re-probed (e.g. timing-based)."""
        original_confidence = float(finding.get("confidence", 0) or 0)
        if original_confidence >= 0.5:
            result.confidence = original_confidence
            result.evidence = finding.get("evidence", "")[:200]
            result.evidence_type = "passthrough"
            result.flags.append("tool_validated_passthrough")
            return True
        return False

    # ── OWASP Gap Check Validators ────────────────────────────────────────────

    def validate_csrf(self, result: ValidationResult, finding: dict,
                      url: str, payload: str, param: str, method: str) -> bool:
        """Re-validate CSRF: replay POST without token, expect non-403."""
        from modules.owasp_gap_checks import check_csrf
        r = check_csrf(url, finding.get("response_body", ""),
                       finding.get("response_headers", {}), method)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "csrf_active"
            result.confidence = r.confidence
            result.flags.append("csrf_active_confirmed")
            self._build_poc(result, url, param, "POST without CSRF token", method)
            return True
        return False

    def validate_cookie_attrs(self, result: ValidationResult, finding: dict,
                               url: str, payload: str, param: str, method: str) -> bool:
        from modules.owasp_gap_checks import check_cookie_attributes
        headers = finding.get("response_headers", {})
        r = check_cookie_attributes(url, headers)
        if r.passive_finding and r.confidence >= 0.7:
            result.evidence = r.evidence
            result.evidence_type = "cookie_attribute"
            result.confidence = r.confidence
            result.flags.append("insecure_cookie")
            return True
        return False

    def validate_session_fixation(self, result: ValidationResult, finding: dict,
                                   url: str, payload: str, param: str, method: str) -> bool:
        pre = finding.get("pre_login_session_id", "")
        post = finding.get("post_login_session_id", "")
        from modules.owasp_gap_checks import check_session_fixation
        r = check_session_fixation(pre, post, url)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "session_fixation"
            result.confidence = r.confidence
            result.flags.append("session_fixation")
            return True
        return False

    def validate_ldap_injection(self, result: ValidationResult, finding: dict,
                                 url: str, payload: str, param: str, method: str) -> bool:
        from modules.owasp_gap_checks import check_ldap_injection
        r = check_ldap_injection(url, param, method)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "ldap_injection"
            result.confidence = r.confidence
            result.flags.append("ldap_injection_confirmed")
            self._build_poc(result, url, param, payload, method)
            return True
        return False

    def validate_weak_tls(self, result: ValidationResult, finding: dict,
                           url: str, payload: str, param: str, method: str) -> bool:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or 443
        from modules.owasp_gap_checks import check_weak_tls
        r = check_weak_tls(host, port)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "weak_tls"
            result.confidence = r.confidence
            result.flags.append("weak_tls_accepted")
            return True
        return False

    def validate_ssrf_oob(self, result: ValidationResult, finding: dict,
                           url: str, payload: str, param: str, method: str) -> bool:
        """SSRF: only confirm if OOB callback flag is explicitly set."""
        oob_received = finding.get("oob_callback_received", False)
        if oob_received:
            result.evidence = finding.get("evidence", "SSRF confirmed via OOB callback")
            result.evidence_type = "oob_callback"
            result.confidence = 0.95
            result.flags.append("ssrf_oob_confirmed")
            self._build_poc(result, url, param, payload, method)
            return True
        # Downgrade without OOB
        result.confidence = 0.35
        result.flags.append("ssrf_unconfirmed_no_oob")
        return False

    def validate_padding_oracle(self, result: ValidationResult, finding: dict,
                                 url: str, payload: str, param: str, method: str) -> bool:
        cookie_name = finding.get("cookie_name", "")
        cookie_value = finding.get("cookie_value", "")
        from modules.owasp_gap_checks import check_padding_oracle
        r = check_padding_oracle(url, cookie_name, cookie_value)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "padding_oracle"
            result.confidence = r.confidence
            result.flags.append("padding_oracle_confirmed")
            return True
        return False

    def validate_account_enumeration(self, result: ValidationResult, finding: dict,
                                      url: str, payload: str, param: str, method: str) -> bool:
        valid_user = finding.get("valid_username", "admin")
        invalid_user = finding.get("invalid_username", "nonexistent_oi_test_user_xyz")
        from modules.owasp_gap_checks import check_account_enumeration_timing
        r = check_account_enumeration_timing(url, valid_user, invalid_user)
        if r.active_confirmed:
            result.evidence = r.evidence
            result.evidence_type = "timing_enumeration"
            result.confidence = r.confidence
            result.flags.append("account_enumeration_timing")
            return True
        return False

    def _validate_generic(self, result: ValidationResult, finding: dict,
                          url: str, payload: str, param: str, method: str) -> bool:
        """Generic validation: send original payload, check evidence string."""
        evidence_str = finding.get("evidence", "")
        resp = self._send(url, method, param, payload)
        baseline = self._baseline(url, method, param)
        if baseline and evidence_str and evidence_str.lower() in baseline.get("body", "").lower():
            return False
        if resp and evidence_str and evidence_str.lower() in resp["body"].lower():
            result.evidence = f"Evidence found: {evidence_str[:100]}"
            result.evidence_type = "generic"
            result.confidence = 0.7
            result.payload = payload
            result.response_status = resp["status"]
            result.flags.append("generic_validation")
            return True
        # No evidence to validate — preserve original tool confidence rather than leaving 0.0
        result.confidence = float(finding.get("confidence", 0) or 0)
        return False

    def _baseline(self, url: str, method: str, param: str) -> Optional[dict]:
        """Send a benign request for baseline comparison to reduce false positives."""
        key = (url, method.upper(), param)
        if key in self._baseline_cache:
            self._baseline_cache.move_to_end(key)
            return self._baseline_cache[key]
        # Use empty payload to avoid unintended effects
        resp = self._send(url, method, param, "")
        # LRU eviction
        if resp is not None:
            self._baseline_cache[key] = resp
            self._baseline_cache.move_to_end(key)
            if len(self._baseline_cache) > self._baseline_cache_limit:
                self._baseline_cache.popitem(last=False)
        return resp

    @staticmethod
    def _content_type_is_html(headers: dict) -> bool:
        ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        return "text/html" in ct or "application/xhtml+xml" in ct

    # ── HTTP Helpers ──────────────────────────────────────────────────────────

    def _send(self, url: str, method: str, param: str, payload: str,
              follow_redirects: bool = True, content_type: str = None,
              retries: int = 2) -> Optional[dict]:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)

        for attempt in range(retries + 1):
            t0 = time.time()
            try:
                if method.upper() == "GET":
                    qs = parse_qs(parsed.query)
                    qs[param] = [payload]
                    new_query = urlencode(qs, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    req = urllib.request.Request(new_url, method="GET")
                else:
                    body_data = urlencode({param: payload}).encode()
                    req = urllib.request.Request(url, data=body_data, method=method.upper())
                    req.add_header("Content-Type", content_type or "application/x-www-form-urlencoded")

                req.add_header("User-Agent", "Mozilla/5.0 (compatible; SecurityBot/1.0)")

                opener = urllib.request.build_opener()
                if not follow_redirects:
                    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
                    opener.handlers = [h for h in opener.handlers if not isinstance(h, urllib.request.HTTPRedirectHandler)]

                with opener.open(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                    duration = (time.time() - t0) * 1000
                    body = resp.read(65536).decode("utf-8", errors="replace")
                    return {
                        "status": resp.status,
                        "body": body,
                        "headers": dict(resp.headers),
                        "duration_ms": duration,
                    }
            except urllib.error.HTTPError as e:
                duration = (time.time() - t0) * 1000
                try:
                    body = e.read(65536).decode("utf-8", errors="replace")
                except Exception:
                    body = ""
                return {"status": e.code, "body": body, "headers": {}, "duration_ms": duration}
            except urllib.error.URLError as e:
                logger.debug(f"HTTP send URLError (attempt {attempt + 1}): {e}")
                time.sleep(0.2 * (attempt + 1))
                continue
            except Exception as e:
                logger.debug(f"HTTP send error (attempt {attempt + 1}): {e}")
                time.sleep(0.2 * (attempt + 1))
                continue
        return None

    def _send_with_headers(self, url: str, headers: dict, retries: int = 2) -> Optional[dict]:
        for attempt in range(retries + 1):
            try:
                t0 = time.time()
                req = urllib.request.Request(url)
                for k, v in headers.items():
                    req.add_header(k, v)
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                    duration = (time.time() - t0) * 1000
                    body = resp.read(32768).decode("utf-8", errors="replace")
                    return {"status": resp.status, "body": body, "headers": dict(resp.headers), "duration_ms": duration}
            except urllib.error.HTTPError as e:
                return {"status": e.code, "body": "", "headers": {}, "duration_ms": 0}
            except urllib.error.URLError as e:
                logger.debug(f"HTTP header send URLError (attempt {attempt + 1}): {e}")
                time.sleep(0.2 * (attempt + 1))
                continue
            except Exception as e:
                logger.debug(f"HTTP header send error (attempt {attempt + 1}): {e}")
                time.sleep(0.2 * (attempt + 1))
                continue
        return None

    def _build_poc(self, result: ValidationResult, url: str, param: str, payload: str, method: str):
        encoded = urllib.parse.quote(payload)
        if method.upper() == "GET":
            result.poc_steps = [
                f"1. Navigate to: {url}",
                f"2. Set parameter '{param}' to: {payload}",
                f"3. Request URL: {url}{'?' if '?' not in url else '&'}{param}={encoded}",
                f"4. Observe evidence: {result.evidence}",
            ]
        else:
            result.poc_steps = [
                f"1. Send {method} request to: {url}",
                f"2. Set body parameter '{param}' to: {payload}",
                f"3. Observe response: {result.evidence}",
            ]


finding_validation_engine = FindingValidationEngine()
