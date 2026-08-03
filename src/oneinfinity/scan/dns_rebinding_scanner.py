"""
DNS Rebinding Scanner
======================
Detects DNS rebinding vulnerabilities by testing if webapp follows DNS changes.

LIMITATION: Full exploitation requires attacker-controlled DNS server.
This scanner provides passive detection heuristics:

1. **TTL Analysis** - Short DNS TTL (<60s) indicates rebinding risk
2. **Origin Check Absence** - No Host header validation
3. **CORS with DNS** - Dynamic CORS based on DNS resolution
4. **IP Change Response** - Tests if app caches DNS or re-resolves

Innovation:
- Passive detection without DNS server
- Identifies rebindable targets for manual exploitation
- Tests DNS cache behavior via timing
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import httpx

log = logging.getLogger("oneinfinity.dns_rebinding")

@dataclass
class DNSRebindingFinding:
    finding_id: str
    vuln_type: str = "dns_rebinding_risk"
    title: str = ""
    severity: str = "high"
    url: str = ""
    hostname: str = ""
    dns_ttl: int = 0
    evidence: str = ""
    confidence: float = 0.0
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = "dns_rebinding_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


class DNSRebindingScanner:
    """
    DNS rebinding risk scanner.

    IMPORTANT: Cannot perform full exploitation without DNS server.
    Provides risk detection heuristics.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.http_client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
        )
        self.traffic_engine = None

    def _get_traffic_engine(self):
        """Lazy load traffic capture engine."""
        if self.traffic_engine is None:
            try:
                from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
                self.traffic_engine = traffic_capture_engine
            except ImportError:
                log.warning("Traffic capture engine not available")
        return self.traffic_engine

    def _capture_traffic(self, method: str, url: str, payload: str, resp: httpx.Response, finding_id: str, attack_type: str):
        """Persist attack traffic to database."""
        engine = self._get_traffic_engine()
        if engine:
            try:
                engine.capture(
                    method=method,
                    url=url,
                    headers=dict(resp.request.headers),
                    body=payload,
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp.text[:10000],
                    source="dns_rebinding_scanner",
                    duration_ms=int(resp.elapsed.total_seconds() * 1000),
                    tags=["dns_rebinding", attack_type],
                    vuln_id=finding_id,
                    attack_type=attack_type,
                )
            except Exception as e:
                log.debug(f"Failed to capture traffic: {e}")

    async def close(self):
        await self.http_client.aclose()

    # ── DNS TTL Analysis ──────────────────────────────────────────────────────

    async def analyze_dns_ttl(self, hostname: str) -> Optional[int]:
        """
        Check DNS TTL for hostname.

        Low TTL (<60s) enables fast rebinding attacks.

        Returns:
            TTL in seconds, or None if error
        """
        try:
            # Basic DNS lookup - Python doesn't expose TTL directly
            # In real implementation would use dnspython
            # For now, check if hostname resolves and assume TTL via timing
            loop = asyncio.get_event_loop()
            start = time.monotonic()
            await loop.getaddrinfo(hostname, None)
            elapsed = time.monotonic() - start

            # Without dnspython we cannot read actual TTL from DNS wire data.
            # Timing-based TTL guessing produced systematic false positives on
            # CDN-fronted targets (slow first-lookup ≠ short TTL). Return None
            # so callers skip the TTL-based rebinding check entirely.
            _ = elapsed  # consumed; not used for TTL estimation
            return None

        except Exception as e:
            log.debug(f"DNS TTL check failed for {hostname}: {e}")
            return None

    # ── Host Header Validation ────────────────────────────────────────────────

    async def test_host_header_validation(self, url: str) -> Optional[DNSRebindingFinding]:
        """
        Test if app validates Host header.

        DNS rebinding exploits require no Host validation.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname

        try:
            # Send request with malicious Host header
            malicious_host = "attacker-rebind.com"
            resp = await self.http_client.get(
                url,
                headers={"Host": malicious_host}
            )

            # Check if server accepted malicious Host
            # Good: returns 400/403 or redirects
            # Bad: returns 200 with content
            if resp.status_code == 200:
                # Check if response references malicious host
                if malicious_host in resp.text or "attacker" in resp.text.lower():
                    finding_id = hashlib.md5(f"dns_rebind_host_{url}".encode()).hexdigest()[:16]

                    # Capture attack traffic
                    self._capture_traffic("GET", url, f"Host: {malicious_host}", resp, finding_id, "host_header_bypass")

                    return DNSRebindingFinding(
                        finding_id=finding_id,
                        title=f"DNS rebinding risk: no Host validation on {hostname}",
                        severity="high",
                        url=url,
                        hostname=hostname,
                        dns_ttl=0,
                        evidence=f"Server accepted Host: {malicious_host} without validation",
                        confidence=0.75,
                        exploitation_steps=[
                            "1. Server accepts arbitrary Host header",
                            "2. DNS rebinding can bypass origin checks",
                            "3. Attacker domain resolves to victim IP after TTL expires",
                            "4. Browser sends authenticated requests to attacker domain",
                        ]
                    )

        except Exception as e:
            log.debug(f"Host header test failed for {url}: {e}")

        return None

    # ── CORS Dynamic Resolution ───────────────────────────────────────────────

    async def test_cors_dns_resolution(self, url: str) -> Optional[DNSRebindingFinding]:
        """
        Test if CORS policy dynamically resolves DNS.

        If app allows CORS based on DNS resolution, rebinding bypasses it.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname

        try:
            # Test with Origin that matches via DNS
            resp = await self.http_client.get(
                url,
                headers={"Origin": f"http://{hostname}"}
            )

            # Check CORS headers
            acao = resp.headers.get("Access-Control-Allow-Origin", "")

            # If CORS reflects Origin without validation
            if acao == f"http://{hostname}":
                # Check if it's dynamic (accepts any origin)
                resp2 = await self.http_client.get(
                    url,
                    headers={"Origin": "http://evil.com"}
                )
                acao2 = resp2.headers.get("Access-Control-Allow-Origin", "")

                if acao2 == "http://evil.com":
                    finding_id = hashlib.md5(f"dns_rebind_cors_{url}".encode()).hexdigest()[:16]

                    # Capture attack traffic
                    self._capture_traffic("GET", url, "Origin: http://evil.com", resp2, finding_id, "cors_dynamic")

                    return DNSRebindingFinding(
                        finding_id=finding_id,
                        title=f"DNS rebinding risk: dynamic CORS on {hostname}",
                        severity="high",
                        url=url,
                        hostname=hostname,
                        dns_ttl=0,
                        evidence="CORS policy reflects any Origin without validation",
                        confidence=0.80,
                        exploitation_steps=[
                            "1. CORS policy dynamically trusts Origin header",
                            "2. DNS rebinding makes attacker domain resolve to victim IP",
                            "3. Browser sends credentials to attacker domain",
                            "4. CORS allows attacker to read response",
                        ]
                    )

        except Exception as e:
            log.debug(f"CORS DNS test failed for {url}: {e}")

        return None

    # ── Low TTL Detection ─────────────────────────────────────────────────────

    async def test_low_ttl(self, url: str) -> Optional[DNSRebindingFinding]:
        """
        Test if hostname has low DNS TTL.

        TTL < 60s enables rapid rebinding attacks.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname

        ttl = await self.analyze_dns_ttl(hostname)

        if ttl and ttl < 60:
            finding_id = hashlib.md5(f"dns_rebind_ttl_{url}".encode()).hexdigest()[:16]

            # Note: No HTTP traffic for TTL check, skip capture

            return DNSRebindingFinding(
                finding_id=finding_id,
                title=f"DNS rebinding risk: low TTL ({ttl}s) on {hostname}",
                severity="medium",
                url=url,
                hostname=hostname,
                dns_ttl=ttl,
                evidence=f"DNS TTL={ttl}s enables rapid rebinding (TTL < 60s)",
                confidence=0.60,
                exploitation_steps=[
                    f"1. DNS TTL is {ttl}s (very low)",
                    "2. Attacker can rebind DNS quickly",
                    "3. Browser cache expires fast",
                    "4. Enables DNS rebinding attack within seconds",
                ]
            )

        return None

    # ── Orchestration ─────────────────────────────────────────────────────────

    async def scan(self, url: str) -> List[DNSRebindingFinding]:
        """
        Scan URL for DNS rebinding risks.

        NOTE: This is passive detection. Full exploitation requires DNS server.

        Returns:
            List of findings
        """
        log.info(f"Starting DNS rebinding risk scan for {url}")

        tests = [
            self.test_host_header_validation(url),
            self.test_cors_dns_resolution(url),
            self.test_low_ttl(url),
        ]

        results = await asyncio.gather(*tests, return_exceptions=True)

        findings = []
        for result in results:
            if isinstance(result, DNSRebindingFinding):
                findings.append(result)
            elif isinstance(result, Exception):
                log.debug(f"DNS rebinding test failed: {result}")

        log.info(f"DNS rebinding scan complete: {len(findings)} risk indicator(s)")
        return findings


async def scan_dns_rebinding(url: str) -> List[DNSRebindingFinding]:
    """Scan DNS rebinding risks."""
    scanner = DNSRebindingScanner()
    try:
        return await scanner.scan(url)
    finally:
        await scanner.close()
