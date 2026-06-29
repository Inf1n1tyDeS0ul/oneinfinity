"""
Host Header Scanner
===================
Detects host header injection and related attack classes.

Detects:
1. **Host Header Injection** — X-Forwarded-Host / X-Host / Forwarded / X-Original-URL
   injection with OOB domain; reflection in body or Location header.
2. **Password Reset Poisoning** — malicious host injected into password-reset flows to
   intercept reset links sent by e-mail.
3. **Cache Poisoning via Host** — unkeyed host header variants that corrupt shared caches.
4. **Routing Bypass** — internal hostnames / loopback addresses in Host header to bypass
   access controls or reach admin interfaces.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from oneinfinity.scan import scan_verify as _scan_verify

log = logging.getLogger("oneinfinity.host_header_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# Payloads and constants
# ─────────────────────────────────────────────────────────────────────────────

# Headers used for Host header injection (in addition to the canonical Host)
_INJECTION_HEADERS: List[str] = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",          # RFC 7239: Forwarded: host=evil.com
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
]

# Default OOB callback domain used when none is supplied
_DEFAULT_OOB_DOMAIN = "oob.oneinfinity.io"

# Password-reset endpoint patterns (case-insensitive path matching)
_RESET_PATTERNS: re.Pattern = re.compile(
    r"/(password[_\-]?reset|reset[_\-]?password|forgot[_\-]?password"
    r"|account/recover|auth/recover|users/password)",
    re.IGNORECASE,
)

# Internal routing bypass hostnames injected into the Host header itself
_ROUTING_BYPASS_HOSTS: List[str] = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "internal",
    "internal.company.com",
    "corp.internal",
    "admin.internal",
    "10.0.0.1",
    "192.168.1.1",
    "169.254.169.254",   # cloud metadata
]

# Indicators in response body that confirm reflection of injected value
_REFLECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"oob\.oneinfinity\.io", re.IGNORECASE),
    re.compile(r"x-forwarded-host\s*:", re.IGNORECASE),
]

# Cache-poisoning probe via additional unkeyed host variants
_CACHE_POISON_HEADERS: List[str] = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "Pragma",             # some caches key on Pragma; injecting a host variant here is a red herring — kept for completeness
]

# ─────────────────────────────────────────────────────────────────────────────
# Data Model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HostHeaderFinding:
    """A confirmed or suspected host header vulnerability."""
    finding_id: str
    vuln_type: str          # host_injection | password_reset_poisoning | cache_poisoning | routing_bypass
    url: str
    injected_header: str
    injected_value: str
    evidence: str
    severity: str           # critical | high | medium | low | info
    confidence: float       # 0.0 – 1.0
    tool: str = "host_header_scanner"
    source_type: str = "active"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "injected_header": self.injected_header,
            "injected_value": self.injected_value,
            "evidence": self.evidence,
            "severity": self.severity,
            "confidence": self.confidence,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class HostHeaderScanner:
    """
    Detect host-header-based vulnerabilities across a set of endpoints.

    Workflow
    --------
    1. For each endpoint, send requests with injected host header variants.
    2. Detect reflection of the OOB domain in the response body or Location header.
    3. Detect password-reset-path endpoints and apply dedicated poisoning probes.
    4. Detect cache-poisoning by comparing responses with and without injected headers.
    5. Detect routing bypass by replacing the Host header with internal hostnames.
    """

    def __init__(
        self,
        target: str,
        oob_domain: Optional[str] = None,
        timeout: int = 10,
        cookies: Optional[Dict[str, str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.target = target
        self.oob_domain = oob_domain or _DEFAULT_OOB_DOMAIN
        self.timeout = timeout
        self._base_cookies: Dict[str, str] = cookies or {}
        self._extra_headers: Dict[str, str] = extra_headers or {}
        self._client: Optional[httpx.AsyncClient] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=_scan_verify(),
                follow_redirects=False,   # We want to see Location headers directly
                cookies=self._base_cookies,
                headers=self._extra_headers,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ── Public API ─────────────────────────────────────────────────────────────

    async def scan(
        self,
        target: str,
        endpoints: List[str],
    ) -> List[HostHeaderFinding]:
        """
        Scan *endpoints* for host header vulnerabilities.

        Parameters
        ----------
        target:
            Base target domain / URL (used for context only; actual requests go to
            the individual endpoint URLs).
        endpoints:
            Fully-qualified URLs to test.

        Returns
        -------
        List[HostHeaderFinding]
        """
        if not endpoints:
            endpoints = [target]

        findings: List[HostHeaderFinding] = []
        client = await self._get_client()

        tasks = []
        for endpoint in endpoints:
            tasks.append(self._scan_endpoint(client, endpoint))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                log.debug("Host header scan raised: %s", result)
                continue
            if isinstance(result, list):
                findings.extend(result)

        return findings

    # ── Per-endpoint dispatcher ───────────────────────────────────────────────

    async def _scan_endpoint(
        self, client: httpx.AsyncClient, url: str
    ) -> List[HostHeaderFinding]:
        findings: List[HostHeaderFinding] = []

        parsed = urlparse(url)
        original_host = parsed.netloc or self.target

        # Determine if this endpoint looks like a password-reset flow
        is_reset = bool(_RESET_PATTERNS.search(parsed.path or ""))

        tests: List[asyncio.coroutine] = [
            self._test_header_injection(client, url, original_host),
            self._test_cache_poisoning(client, url, original_host),
            self._test_routing_bypass(client, url, original_host),
        ]
        if is_reset:
            tests.append(self._test_password_reset_poisoning(client, url, original_host))

        results = await asyncio.gather(*tests, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                log.debug("Host header sub-test raised: %s", r)
                continue
            if isinstance(r, list):
                findings.extend(r)

        return findings

    # ── Test 1: Host header injection ─────────────────────────────────────────

    async def _test_header_injection(
        self,
        client: httpx.AsyncClient,
        url: str,
        original_host: str,
    ) -> List[HostHeaderFinding]:
        """
        Inject each auxiliary header with the OOB domain and check whether
        the injected value is reflected in the response body or Location header.
        """
        findings: List[HostHeaderFinding] = []
        oob_value = self.oob_domain

        for header_name in _INJECTION_HEADERS:
            if header_name == "Forwarded":
                injected_value = f"host={oob_value}"
            else:
                injected_value = oob_value

            try:
                headers = {header_name: injected_value}
                resp = await client.get(url, headers=headers)
            except Exception as exc:
                log.debug("Header injection request failed (%s %s): %s", header_name, url, exc)
                continue

            evidence = self._check_reflection(resp, oob_value)
            if evidence:
                findings.append(HostHeaderFinding(
                    finding_id=_make_id("hhi", url, header_name),
                    vuln_type="host_injection",
                    url=url,
                    injected_header=header_name,
                    injected_value=injected_value,
                    evidence=evidence,
                    severity="high",
                    confidence=0.85,
                ))

        return findings

    # ── Test 2: Password reset poisoning ──────────────────────────────────────

    async def _test_password_reset_poisoning(
        self,
        client: httpx.AsyncClient,
        url: str,
        original_host: str,
    ) -> List[HostHeaderFinding]:
        """
        For password-reset endpoints, inject the OOB domain as the Host header
        (and common override headers). If the server reflects the injected host
        in the response (e.g., constructs a reset link), it is vulnerable.
        """
        findings: List[HostHeaderFinding] = []
        oob_value = self.oob_domain

        probe_headers_list: List[Tuple[str, str]] = [
            ("Host", oob_value),
            ("X-Forwarded-Host", oob_value),
            ("X-Forwarded-Host", f"{oob_value}:443"),
        ]

        for header_name, injected_value in probe_headers_list:
            try:
                if header_name == "Host":
                    # httpx allows overriding Host only via the headers mapping
                    resp = await client.post(
                        url,
                        headers={"Host": injected_value},
                        data={"email": "security_test@example.com"},
                    )
                else:
                    resp = await client.post(
                        url,
                        headers={header_name: injected_value},
                        data={"email": "security_test@example.com"},
                    )
            except Exception as exc:
                log.debug("Reset poisoning request failed (%s): %s", url, exc)
                continue

            evidence = self._check_reflection(resp, oob_value)
            # Also flag 200/202 on a reset endpoint with injected Host as medium confidence
            if not evidence and resp.status_code in (200, 202):
                evidence = (
                    f"Server accepted POST to reset endpoint with injected {header_name}={injected_value!r} "
                    f"(HTTP {resp.status_code}); manual verification required"
                )
                confidence = 0.45
                severity = "high"
            elif evidence:
                confidence = 0.90
                severity = "critical"
            else:
                continue

            findings.append(HostHeaderFinding(
                finding_id=_make_id("pwreset", url, header_name),
                vuln_type="password_reset_poisoning",
                url=url,
                injected_header=header_name,
                injected_value=injected_value,
                evidence=evidence,
                severity=severity,
                confidence=confidence,
            ))

        return findings

    # ── Test 3: Cache poisoning ───────────────────────────────────────────────

    async def _test_cache_poisoning(
        self,
        client: httpx.AsyncClient,
        url: str,
        original_host: str,
    ) -> List[HostHeaderFinding]:
        """
        Detect responses where an injected (unkeyed) Host variant is reflected
        in the body — a prerequisite for cache poisoning.

        Heuristic:
        - Fetch the baseline response.
        - Inject the OOB domain in X-Forwarded-Host; compare whether a unique
          probe token appears in the poisoned response but not in the baseline.
        """
        findings: List[HostHeaderFinding] = []
        probe_token = f"oob-cache-{uuid.uuid4().hex[:8]}.{self.oob_domain}"

        # Baseline (no injection)
        try:
            baseline_resp = await client.get(url)
        except Exception as exc:
            log.debug("Cache poisoning baseline failed (%s): %s", url, exc)
            return findings

        baseline_body = baseline_resp.text

        for header_name in ("X-Forwarded-Host", "X-Host"):
            try:
                poisoned_resp = await client.get(url, headers={header_name: probe_token})
            except Exception as exc:
                log.debug("Cache poisoning probe failed (%s %s): %s", header_name, url, exc)
                continue

            poisoned_body = poisoned_resp.text

            # Reflected in poisoned but not baseline → genuine unkeyed reflection
            token_root = probe_token.split(".")[0]  # oob-cache-<hex>
            if (
                token_root in poisoned_body
                and token_root not in baseline_body
            ):
                findings.append(HostHeaderFinding(
                    finding_id=_make_id("cache_poison", url, header_name),
                    vuln_type="cache_poisoning",
                    url=url,
                    injected_header=header_name,
                    injected_value=probe_token,
                    evidence=(
                        f"Probe token '{token_root}' reflected in response body only when "
                        f"{header_name} is set; response length {len(poisoned_body)} vs baseline {len(baseline_body)}"
                    ),
                    severity="high",
                    confidence=0.80,
                ))

            # Also check for reflection in cache-related response headers
            cache_headers = dict(poisoned_resp.headers)
            for h_val in cache_headers.values():
                if token_root in h_val:
                    findings.append(HostHeaderFinding(
                        finding_id=_make_id("cache_header", url, header_name),
                        vuln_type="cache_poisoning",
                        url=url,
                        injected_header=header_name,
                        injected_value=probe_token,
                        evidence=f"Probe token reflected in response header value: {h_val[:120]}",
                        severity="high",
                        confidence=0.75,
                    ))
                    break

        return findings

    # ── Test 4: Routing bypass ─────────────────────────────────────────────────

    async def _test_routing_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        original_host: str,
    ) -> List[HostHeaderFinding]:
        """
        Replace the Host header with internal addresses and watch for
        successful responses that differ from the expected rejection (403/404).
        """
        findings: List[HostHeaderFinding] = []

        # Baseline status
        try:
            baseline_resp = await client.get(url)
            baseline_status = baseline_resp.status_code
        except Exception as exc:
            log.debug("Routing bypass baseline failed (%s): %s", url, exc)
            return findings

        for bypass_host in _ROUTING_BYPASS_HOSTS:
            try:
                resp = await client.get(url, headers={"Host": bypass_host})
            except Exception as exc:
                log.debug("Routing bypass request failed (Host=%s, %s): %s", bypass_host, url, exc)
                continue

            # If injecting an internal host causes a 200 where baseline was 403/401/404,
            # that is a strong indicator of routing bypass.
            is_bypass = (
                resp.status_code == 200
                and baseline_status in (401, 403, 404)
            )
            # Or if the response reveals internal service indicators
            internal_indicators = [
                "admin", "dashboard", "redis_version", "PONG",
                "Welcome to nginx", "Apache Tomcat", "Internal Server",
            ]
            body_snippet = resp.text[:1000]
            indicator_hit = any(ind.lower() in body_snippet.lower() for ind in internal_indicators)

            if is_bypass or (resp.status_code == 200 and indicator_hit and bypass_host not in (original_host,)):
                evidence_parts = [
                    f"Host: {bypass_host!r} → HTTP {resp.status_code} (baseline: {baseline_status})"
                ]
                if indicator_hit:
                    evidence_parts.append(f"internal service indicator in response: {body_snippet[:200]!r}")
                findings.append(HostHeaderFinding(
                    finding_id=_make_id("routing_bypass", url, bypass_host),
                    vuln_type="routing_bypass",
                    url=url,
                    injected_header="Host",
                    injected_value=bypass_host,
                    evidence="; ".join(evidence_parts),
                    severity="critical" if is_bypass else "high",
                    confidence=0.75 if is_bypass else 0.60,
                ))

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _check_reflection(
        self, resp: httpx.Response, value: str
    ) -> Optional[str]:
        """
        Return a human-readable evidence string if *value* is reflected in the
        response body or Location / Link headers, or None if not found.
        """
        # Body reflection
        if value in resp.text:
            snippet = _extract_snippet(resp.text, value)
            return f"Injected value '{value}' reflected in response body: …{snippet}…"

        # Location / Link header reflection
        for header in ("location", "link", "refresh", "content-location"):
            hval = resp.headers.get(header, "")
            if value in hval:
                return f"Injected value '{value}' found in {header!r} response header: {hval[:200]}"

        return None


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _make_id(vuln_prefix: str, url: str, discriminator: str) -> str:
    """Generate a stable, short finding id."""
    import hashlib
    raw = f"{vuln_prefix}:{url}:{discriminator}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _extract_snippet(text: str, needle: str, context: int = 60) -> str:
    """Return up to *context* characters surrounding *needle* in *text*."""
    idx = text.find(needle)
    if idx == -1:
        return ""
    start = max(0, idx - context)
    end = min(len(text), idx + len(needle) + context)
    return text[start:end]


# ─────────────────────────────────────────────────────────────────────────────
# Factory / convenience
# ─────────────────────────────────────────────────────────────────────────────

def get_scanner(
    target: str,
    oob_domain: Optional[str] = None,
    timeout: int = 10,
    cookies: Optional[Dict[str, str]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> HostHeaderScanner:
    """Return a configured :class:`HostHeaderScanner` for *target*."""
    return HostHeaderScanner(
        target=target,
        oob_domain=oob_domain,
        timeout=timeout,
        cookies=cookies,
        extra_headers=extra_headers,
    )


async def scan_host_header(
    target: str,
    endpoints: Optional[List[str]] = None,
    oob_domain: Optional[str] = None,
    traffic_limit: int = 200,
    cookies: Optional[Dict[str, str]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> List[HostHeaderFinding]:
    """
    Convenience coroutine — create a scanner, run it, close it, return findings.

    Parameters
    ----------
    target:
        Base target URL or domain.
    endpoints:
        Optional pre-computed list of URLs to test.  If omitted, only *target*
        itself is tested.
    oob_domain:
        Out-of-band callback domain (e.g. from Burp Collaborator / interactsh).
        Defaults to ``oob.oneinfinity.io``.
    traffic_limit:
        Not used directly; reserved for future traffic-capture integration.
    cookies, extra_headers:
        Session context (e.g. from an authenticated auth_manager).
    """
    scanner = get_scanner(
        target=target,
        oob_domain=oob_domain,
        cookies=cookies,
        extra_headers=extra_headers,
    )
    try:
        return await scanner.scan(target, endpoints or [target])
    finally:
        await scanner.close()
