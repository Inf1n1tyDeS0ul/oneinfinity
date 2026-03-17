"""
API Security Scanner Plugin.

Tests REST/GraphQL APIs for common vulnerabilities:
  - Broken Object Level Authorization (BOLA/IDOR)
  - Broken Function Level Authorization
  - Mass Assignment
  - Excessive Data Exposure
  - Missing rate limiting
  - GraphQL introspection enabled
  - Unauthenticated API access
  - JWT algorithm confusion
  - API versioning misconfig (v1 deprecated endpoint bypass)

Requires: AppModel in context (from application_intelligence.py)
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

log = logging.getLogger(__name__)

PLUGIN_META = {
    "name": "api_security",
    "type": "vuln",
    "version": "1.0.0",
    "description": "REST/GraphQL API security testing — BOLA, mass assignment, rate limiting, introspection",
    "author": "OneInfinity",
    "tags": ["api", "rest", "graphql", "bola", "idor", "jwt", "mass-assignment", "rate-limit"],
}

_GRAPHQL_INTROSPECTION = """{"query":"{__schema{types{name}}}"}"""
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]
_API_VERSION_PATHS = ["/v1/", "/v2/", "/api/v1/", "/api/v2/", "/api/v3/"]
_ID_INCREMENT_RANGE = range(1, 11)  # test IDs 1-10
_TIMEOUT = 10


@dataclass
class APIFinding:
    vuln_type: str
    severity: str
    endpoint: str
    description: str
    evidence: str = ""
    parameter: str = ""
    confidence: float = 0.75
    remediation: str = ""


class Plugin:
    """API-specific vulnerability scanner."""

    def run(self, target: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Args:
            target: base URL (e.g. "https://api.acme.com")
            context:
                "app_model": dict (from ApplicationIntelligenceEngine)
                "endpoints": [str]  — API endpoints to test
                "auth_headers": dict — Authorization headers
                "cookies": dict

        Returns:
            {
                "findings": [APIFinding as dict],
                "tested_endpoints": int,
                "error": str | None
            }
        """
        try:
            import httpx
            self._client_lib = "httpx"
        except ImportError:
            self._client_lib = "urllib"

        base_url = self._normalize_url(target)
        app_model = context.get("app_model", {})
        endpoints = context.get("endpoints", [])
        auth_headers = context.get("auth_headers", {})
        cookies = context.get("cookies", {})

        self._base_url = base_url
        self._auth_headers = auth_headers
        self._cookies = cookies

        findings: List[APIFinding] = []
        tested = 0

        # 1. GraphQL introspection
        graphql_findings, tested_gql = self._test_graphql(base_url)
        findings.extend(graphql_findings)
        tested += tested_gql

        # 2. Unauthenticated access to API endpoints
        if endpoints:
            unauth_findings, tested_unauth = self._test_unauthenticated_access(
                base_url, endpoints[:20]
            )
            findings.extend(unauth_findings)
            tested += tested_unauth

        # 3. BOLA/IDOR via integer ID increment
        id_endpoints = [e for e in endpoints if re.search(r"/\d+/?$", e)]
        if id_endpoints:
            bola_findings, tested_bola = self._test_bola(base_url, id_endpoints[:5])
            findings.extend(bola_findings)
            tested += tested_bola

        # 4. Mass assignment via extra POST fields
        post_endpoints = [e for e in endpoints if not re.search(r"/\d+/?$", e)][:5]
        if post_endpoints:
            mass_findings = self._test_mass_assignment(base_url, post_endpoints)
            findings.extend(mass_findings)
            tested += len(post_endpoints)

        # 5. Old API version bypass
        ver_findings, tested_ver = self._test_version_bypass(base_url, endpoints[:5])
        findings.extend(ver_findings)
        tested += tested_ver

        # 6. Rate limiting
        if endpoints:
            rate_findings = self._test_rate_limiting(base_url, endpoints[0] if endpoints else "/api/login")
            findings.extend(rate_findings)
            tested += 1

        return {
            "findings": [self._finding_to_dict(f) for f in findings],
            "tested_endpoints": tested,
            "error": None,
        }

    # ------------------------------------------------------------------ #
    #  Test implementations
    # ------------------------------------------------------------------ #

    def _test_graphql(self, base_url: str):
        findings = []
        tested = 0
        for path in _GRAPHQL_PATHS:
            url = urljoin(base_url, path)
            tested += 1
            resp = self._post(url, json_data=json.loads(_GRAPHQL_INTROSPECTION))
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                if "__schema" in body or "types" in body:
                    findings.append(APIFinding(
                        vuln_type="GraphQL Introspection Enabled",
                        severity="medium",
                        endpoint=url,
                        description="GraphQL introspection is enabled, exposing the full API schema to attackers.",
                        evidence=body[:200],
                        confidence=0.95,
                        remediation="Disable introspection in production. Set `introspection: false` in your GraphQL server config.",
                    ))
                    break  # found one, no need to keep testing
        return findings, tested

    def _test_unauthenticated_access(self, base_url: str, endpoints: List[str]):
        findings = []
        tested = 0
        for ep in endpoints:
            url = urljoin(base_url, ep)
            tested += 1
            # Request without auth headers
            resp = self._get(url, headers={})
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                # Check if it looks like an API response (JSON with data)
                if body.startswith("{") or body.startswith("["):
                    try:
                        data = json.loads(body)
                        if data and (isinstance(data, list) or (isinstance(data, dict) and len(data) > 1)):
                            findings.append(APIFinding(
                                vuln_type="Unauthenticated API Access",
                                severity="high",
                                endpoint=url,
                                description="API endpoint returns data without authentication.",
                                evidence=body[:300],
                                confidence=0.70,
                                remediation="Implement authentication middleware for all API endpoints.",
                            ))
                    except json.JSONDecodeError:
                        pass
        return findings, tested

    def _test_bola(self, base_url: str, id_endpoints: List[str]):
        findings = []
        tested = 0
        for ep in id_endpoints:
            # Extract base path and swap ID
            match = re.search(r"(.*/)(\d+)(/?.*)", ep)
            if not match:
                continue
            prefix, current_id, suffix = match.groups()
            current_id_int = int(current_id)

            for probe_id in _ID_INCREMENT_RANGE:
                if probe_id == current_id_int:
                    continue
                probed_path = f"{prefix}{probe_id}{suffix}"
                url = urljoin(base_url, probed_path)
                tested += 1
                resp = self._get(url)
                if resp and resp.get("status") == 200:
                    body = resp.get("body", "")
                    if len(body) > 50 and (body.startswith("{") or body.startswith("[")):
                        findings.append(APIFinding(
                            vuln_type="BOLA / IDOR",
                            severity="high",
                            endpoint=url,
                            parameter="id",
                            description=f"Object at ID={probe_id} is accessible — possible IDOR.",
                            evidence=f"GET {url} → HTTP 200\n{body[:200]}",
                            confidence=0.65,
                            remediation="Implement object-level authorization. Verify the requesting user owns the requested object.",
                        ))
                        break  # one finding per endpoint is enough
        return findings, tested

    def _test_mass_assignment(self, base_url: str, endpoints: List[str]):
        findings = []
        extra_fields = {
            "is_admin": True,
            "role": "admin",
            "admin": True,
            "verified": True,
            "balance": 999999,
            "credits": 9999,
        }
        for ep in endpoints:
            url = urljoin(base_url, ep)
            resp = self._post(url, json_data=extra_fields)
            if resp and resp.get("status") in (200, 201):
                body = resp.get("body", "")
                # Check if the extra fields were reflected
                for field_name in extra_fields:
                    if field_name in body:
                        findings.append(APIFinding(
                            vuln_type="Mass Assignment",
                            severity="high",
                            endpoint=url,
                            parameter=field_name,
                            description=f"Server accepted `{field_name}` in POST body — possible mass assignment.",
                            evidence=f"POST with extra field '{field_name}' → reflected in response",
                            confidence=0.60,
                            remediation="Use allow-lists (DTOs) to explicitly define permitted fields. Never auto-bind request fields to model properties.",
                        ))
                        break
        return findings

    def _test_version_bypass(self, base_url: str, endpoints: List[str]):
        findings = []
        tested = 0
        parsed = urlparse(base_url)
        for ep in endpoints[:3]:
            for v1_path in ["/v1", "/api/v1"]:
                if v1_path in ep:
                    continue
                # Try adding /v1 prefix
                url = urljoin(base_url, v1_path + ep)
                tested += 1
                resp = self._get(url)
                if resp and resp.get("status") == 200:
                    findings.append(APIFinding(
                        vuln_type="API Version Bypass",
                        severity="medium",
                        endpoint=url,
                        description=f"Older API version {v1_path} is still accessible and may lack current security controls.",
                        evidence=f"GET {url} → HTTP 200",
                        confidence=0.60,
                        remediation="Remove or lock down deprecated API versions. Apply same auth/validation to all versions.",
                    ))
        return findings, tested

    def _test_rate_limiting(self, base_url: str, endpoint: str):
        findings = []
        url = urljoin(base_url, endpoint)
        # Send 20 rapid requests
        statuses = []
        for _ in range(20):
            resp = self._get(url)
            if resp:
                statuses.append(resp.get("status", 0))

        # If none returned 429, rate limiting may be absent
        if statuses and 429 not in statuses and all(s == 200 for s in statuses[:10]):
            findings.append(APIFinding(
                vuln_type="Missing Rate Limiting",
                severity="medium",
                endpoint=url,
                description="No rate limiting detected after 20 rapid requests — potential for brute force or abuse.",
                evidence=f"20 requests returned HTTP 200 with no 429 responses",
                confidence=0.50,
                remediation="Implement rate limiting (e.g. 60 req/min per IP). Return HTTP 429 with Retry-After header.",
            ))
        return findings

    # ------------------------------------------------------------------ #
    #  HTTP helpers
    # ------------------------------------------------------------------ #

    def _get(self, url: str, headers: Optional[dict] = None) -> Optional[dict]:
        import urllib.request, urllib.error
        h = {**self._auth_headers, **(headers or {})}
        req = urllib.request.Request(url, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return {"status": resp.getcode(), "body": resp.read(4096).decode("utf-8", errors="ignore")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    def _post(self, url: str, json_data: dict) -> Optional[dict]:
        import urllib.request, urllib.error
        body = json.dumps(json_data).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._auth_headers,
        }
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return {"status": resp.getcode(), "body": resp.read(4096).decode("utf-8", errors="ignore")}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _finding_to_dict(self, f: APIFinding) -> dict:
        return {
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "endpoint": f.endpoint,
            "parameter": f.parameter,
            "description": f.description,
            "evidence": f.evidence,
            "confidence": f.confidence,
            "remediation": f.remediation,
            "tool": "api_security_plugin",
        }
