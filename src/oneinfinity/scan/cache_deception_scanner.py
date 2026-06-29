"""
Cache Deception Scanner
=======================
Detects Web Cache Deception, Cache Poisoning, CDN key-normalisation attacks,
and Vary-header bypass vulnerabilities.

Innovation:
1. **Web Cache Deception (WCD)** — Appends static-file suffixes (.css, .js, .png,
   .ico) to authenticated endpoints and confirms whether an unauthenticated client
   receives cached, auth-gated content (CPDoS / WCD).
2. **Cache Poisoning** — Injects unkeyed headers (X-Forwarded-Host,
   X-Original-URL, X-Rewrite-URL, X-Forwarded-Scheme) and checks whether the
   injected value appears in a subsequent unauthenticated response.
3. **CDN Cache-Key Normalisation** — Tests path-traversal via cache keys:
   ``/api/user/..%2F..%2Fadmin`` may normalise to ``/api/admin`` in the CDN
   key while routing to an admin handler on the origin.
4. **Vary-Header Bypass** — Flags responses containing auth-dependent content
   where the server omits or under-scopes the ``Vary`` header.

No other scanner in this suite combines all four attack vectors.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, urljoin, urlparse, urlunparse

import httpx

log = logging.getLogger("oneinfinity.cache_deception_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# TLS helper
# ─────────────────────────────────────────────────────────────────────────────


def _scan_verify() -> bool:
    """Return TLS verify flag for scan clients (mirrors differential_scanner pattern)."""
    return os.environ.get("ONEINFINITY_STRICT_TLS", "").strip() in ("1", "true", "yes")


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Static-file suffixes used for Web Cache Deception probes
_WCD_SUFFIXES: List[str] = [
    ".css",
    ".js",
    ".png",
    ".ico",
    ".jpg",
    ".gif",
    ".woff2",
    "/style.css",
    "/script.js",
    "/favicon.ico",
]

# Unkeyed headers used for Cache Poisoning probes
_POISON_HEADERS: List[Dict[str, str]] = [
    {"X-Forwarded-Host": "evil.oneinfinity-probe.com"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Proto": "http"},
    {"X-Host": "evil.oneinfinity-probe.com"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"Forwarded": "host=evil.oneinfinity-probe.com"},
]

# CDN cache-key normalisation traversal payloads (appended to path)
_CDN_TRAVERSAL_PAYLOADS: List[Tuple[str, str]] = [
    # (path_suffix_to_append, label)
    ("/..%2Fadmin",       "dot-dot-slash-admin"),
    ("/..%2F..%2Fadmin",  "double-dot-slash-admin"),
    ("/%2e%2e/admin",     "encoded-dotdot-admin"),
    ("/%252e%252e/admin", "double-encoded-dotdot"),
    ("/./",               "dot-slash-normalise"),
    ("//",                "double-slash-normalise"),
    ("/;/",               "semicolon-path-param"),
]

# Headers whose presence is required when auth-dependent content is served
_REQUIRED_VARY_HEADERS: Set[str] = {
    "cookie",
    "authorization",
    "accept-encoding",
}

# Patterns that hint at authenticated content in a response body
_AUTH_CONTENT_PATTERNS: List[re.Pattern] = [
    re.compile(r'"user(?:name|_id|Id)"', re.I),
    re.compile(r'"email"\s*:\s*"[^@"]{1,64}@[^"]{1,64}"', re.I),
    re.compile(r'"(?:auth|access)_?token"\s*:', re.I),
    re.compile(r'"(?:is_)?admin"\s*:\s*true', re.I),
    re.compile(r'"role"\s*:\s*"(?:admin|superuser|root)"', re.I),
    re.compile(r'"(?:session|csrf)_?(?:token|key)"\s*:', re.I),
    re.compile(r'"(?:api_?key|apikey)"\s*:\s*"[A-Za-z0-9_\-]{16,}"', re.I),
]

# ─────────────────────────────────────────────────────────────────────────────
# Data Model
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CacheDeceptionFinding:
    """Finding emitted by CacheDeceptionScanner."""
    finding_id: str
    vuln_type: str                          # wcd | cache_poisoning | cdn_normalisation | vary_bypass
    url: str                                # original endpoint under test
    test_url: str                           # exact URL (or header combo) used to trigger the finding
    evidence: str                           # human-readable explanation
    severity: str = "high"                  # critical | high | medium | low | info
    confidence: float = 0.0                 # 0.0 – 1.0
    cache_header_value: str = ""            # raw Cache-Control / Age / X-Cache value observed
    tool: str = "cache_deception_scanner"
    source_type: str = "active"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "test_url": self.test_url,
            "evidence": self.evidence,
            "severity": self.severity,
            "confidence": self.confidence,
            "cache_header_value": self.cache_header_value,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _finding_id(key: str) -> str:
    return hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()[:16]


def _is_cached(headers: httpx.Headers) -> Tuple[bool, str]:
    """
    Determine whether a response was served from cache.

    Returns (is_cached, raw_cache_header_value).
    """
    # Explicit CDN HIT markers
    x_cache = headers.get("x-cache", "").lower()
    if "hit" in x_cache:
        return True, headers.get("x-cache", "")

    cf_cache = headers.get("cf-cache-status", "").lower()
    if cf_cache == "hit":
        return True, headers.get("cf-cache-status", "")

    # Age header > 0 means the response was reused from cache
    age = headers.get("age", "0")
    try:
        if int(age) > 0:
            raw = f"Age: {age}"
            cc = headers.get("cache-control", "")
            if cc:
                raw = f"{raw}, Cache-Control: {cc}"
            return True, raw
    except ValueError:
        pass

    # Cache-Control lacking no-store/no-cache + max-age > 0
    cc = headers.get("cache-control", "").lower()
    if cc and "no-store" not in cc and "private" not in cc and "max-age=0" not in cc:
        if re.search(r"max-age\s*=\s*[1-9]", cc) or "public" in cc:
            return True, headers.get("cache-control", "")

    return False, headers.get("cache-control", headers.get("x-cache", ""))


def _looks_authenticated(body: str) -> bool:
    """Return True if body contains patterns typical of authenticated responses."""
    for pat in _AUTH_CONTENT_PATTERNS:
        if pat.search(body):
            return True
    return False


def _append_suffix(url: str, suffix: str) -> str:
    """Append a static-file suffix to *url*, preserving any query string."""
    parsed = urlparse(url)
    new_path = parsed.path.rstrip("/") + suffix
    return urlunparse(parsed._replace(path=new_path))


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────


class CacheDeceptionScanner:
    """
    Web Cache Deception, Cache Poisoning, CDN normalisation, and Vary-bypass scanner.

    Workflow
    --------
    1. For each endpoint, run Web Cache Deception probes (unauthenticated suffix requests).
    2. Run Cache Poisoning probes with unkeyed header injection.
    3. Run CDN cache-key normalisation path-traversal probes.
    4. Inspect Vary headers for auth-dependent content exposure.
    """

    def __init__(self, timeout: int = 12):
        self.timeout = timeout
        # Two independent clients: one carries auth cookies/headers (set later),
        # one is always anonymous to simulate a different user / edge-node.
        self._authed_client: Optional[httpx.AsyncClient] = None
        self._anon_client: httpx.AsyncClient = httpx.AsyncClient(
            timeout=timeout,
            verify=_scan_verify(),
            follow_redirects=False,
        )
        self._tested: Set[str] = set()

    def _build_authed_client(self, auth_headers: Dict[str, str]) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.timeout,
            verify=_scan_verify(),
            follow_redirects=False,
            headers=auth_headers,
        )

    async def close(self) -> None:
        """Release HTTP clients."""
        await self._anon_client.aclose()
        if self._authed_client is not None:
            await self._authed_client.aclose()

    # ── 1. Web Cache Deception ────────────────────────────────────────────────

    async def test_web_cache_deception(
        self,
        url: str,
        auth_headers: Dict[str, str],
    ) -> Optional[CacheDeceptionFinding]:
        """
        WCD probe: append static suffix, fetch authenticated, then fetch
        unauthenticated and check if cached auth content is returned.
        """
        if self._authed_client is None:
            self._authed_client = self._build_authed_client(auth_headers)

        for suffix in _WCD_SUFFIXES:
            test_url = _append_suffix(url, suffix)
            dedup_key = f"wcd:{test_url}"
            if dedup_key in self._tested:
                continue
            self._tested.add(dedup_key)

            try:
                # Step 1 — authenticated prime request (warms CDN cache with auth body)
                auth_resp = await self._authed_client.get(test_url)
                if auth_resp.status_code not in (200, 206):
                    continue

                # Must be cacheable for the attack to work
                auth_cached, auth_cache_raw = _is_cached(auth_resp.headers)

                # Step 2 — anonymous request (different client, no auth)
                await asyncio.sleep(0.3)  # small delay to let CDN settle
                anon_resp = await self._anon_client.get(test_url)

                anon_cached, anon_cache_raw = _is_cached(anon_resp.headers)
                anon_body = anon_resp.text

                # Positive: anonymous got a cached response AND body looks authenticated
                if anon_resp.status_code == 200 and anon_cached and _looks_authenticated(anon_body):
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"wcd:{url}:{suffix}"),
                        vuln_type="web_cache_deception",
                        url=url,
                        test_url=test_url,
                        evidence=(
                            f"Appended '{suffix}' to {url}. Authenticated prime returned "
                            f"HTTP {auth_resp.status_code}; unauthenticated repeat returned "
                            f"HTTP {anon_resp.status_code} with cached auth-dependent content. "
                            f"Cache header: {anon_cache_raw}"
                        ),
                        severity="critical",
                        confidence=0.90,
                        cache_header_value=anon_cache_raw,
                    )

                # Weaker signal: response is the same size as the authenticated response
                # and is served from cache — still suspicious
                if (anon_resp.status_code == 200
                        and anon_cached
                        and abs(len(anon_body) - len(auth_resp.text)) < 50
                        and len(anon_body) > 200):
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"wcd_size:{url}:{suffix}"),
                        vuln_type="web_cache_deception",
                        url=url,
                        test_url=test_url,
                        evidence=(
                            f"Appended '{suffix}' to {url}. Unauthenticated request received "
                            f"cached response (size {len(anon_body)}) matching the authenticated "
                            f"response (size {len(auth_resp.text)}). Possible WCD. "
                            f"Cache header: {anon_cache_raw}"
                        ),
                        severity="high",
                        confidence=0.65,
                        cache_header_value=anon_cache_raw,
                    )

            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                log.debug("WCD probe failed for %s%s: %s", url, suffix, exc)

        return None

    # ── 2. Cache Poisoning ────────────────────────────────────────────────────

    async def test_cache_poisoning(
        self,
        url: str,
    ) -> Optional[CacheDeceptionFinding]:
        """
        Cache Poisoning probe: inject unkeyed headers; check if injected value
        is reflected in a subsequent unauthenticated response from cache.
        """
        for header_dict in _POISON_HEADERS:
            header_name, injected_value = next(iter(header_dict.items()))
            dedup_key = f"poison:{url}:{header_name}"
            if dedup_key in self._tested:
                continue
            self._tested.add(dedup_key)

            try:
                # Request 1 — poison the cache with the injected header
                poison_resp = await self._anon_client.get(url, headers=header_dict)

                # Request 2 — clean anonymous request (no injected header)
                await asyncio.sleep(0.2)
                clean_resp = await self._anon_client.get(url)

                clean_body = clean_resp.text
                clean_cached, cache_raw = _is_cached(clean_resp.headers)

                # Positive: injected value appears in the clean (non-poisoned) response
                if clean_cached and injected_value.lower() in clean_body.lower():
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"poison:{url}:{header_name}"),
                        vuln_type="cache_poisoning",
                        url=url,
                        test_url=url,
                        evidence=(
                            f"Injected header '{header_name}: {injected_value}' in request to {url}. "
                            f"Subsequent clean request received a cached response containing the "
                            f"injected value '{injected_value}'. "
                            f"Cache header: {cache_raw}"
                        ),
                        severity="critical",
                        confidence=0.92,
                        cache_header_value=cache_raw,
                    )

                # Weaker signal: injected header is reflected in the poison response itself
                # (server echoes it back unescaped) and the response is cacheable
                if injected_value.lower() in poison_resp.text.lower():
                    poison_cached, poison_cache_raw = _is_cached(poison_resp.headers)
                    if poison_cached:
                        return CacheDeceptionFinding(
                            finding_id=_finding_id(f"poison_reflected:{url}:{header_name}"),
                            vuln_type="cache_poisoning",
                            url=url,
                            test_url=url,
                            evidence=(
                                f"Injected header '{header_name}: {injected_value}' was reflected "
                                f"in a cacheable response from {url}. Other clients may receive "
                                f"the poisoned response. "
                                f"Cache header: {poison_cache_raw}"
                            ),
                            severity="high",
                            confidence=0.80,
                            cache_header_value=poison_cache_raw,
                        )

            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                log.debug("Cache poisoning probe failed for %s [%s]: %s", url, header_name, exc)

        return None

    # ── 5. X-Forwarded-Host Cache Poisoning ──────────────────────────────────

    async def test_host_header_cache_poison(
        self,
        url: str,
    ) -> Optional[CacheDeceptionFinding]:
        """
        X-Forwarded-Host cache poisoning probe.

        Injects X-Forwarded-Host with a benign sentinel and then an XSS payload.
        If the injected value is reflected in a cached response, the endpoint is
        vulnerable to cache poisoning; when the XSS payload is reflected unescaped
        the severity is upgraded to cache_poison_xss (critical).
        """
        _SENTINEL = "cache-probe-8675309.evil.com"
        _XSS_HOST = 'evil.com/"><script>alert(1)</script>'

        for injected_host, label in ((_SENTINEL, "sentinel"), (_XSS_HOST, "xss")):
            dedup_key = f"host_poison:{url}:{label}"
            if dedup_key in self._tested:
                continue
            self._tested.add(dedup_key)

            headers = {"X-Forwarded-Host": injected_host}
            try:
                # Prime: request with injected host header to seed the cache
                prime_resp = await self._anon_client.get(url, headers=headers)
                prime_cached, prime_cache_raw = _is_cached(prime_resp.headers)
                prime_body = prime_resp.text

                # Verify: clean request — should return poisoned cached copy
                await asyncio.sleep(0.25)
                clean_resp = await self._anon_client.get(url)
                clean_cached, clean_cache_raw = _is_cached(clean_resp.headers)
                clean_body = clean_resp.text

                # Check direct reflection in the prime response (server echoes host)
                reflected_prime = injected_host.lower() in prime_body.lower()
                # Check reflection served from cache to clean client
                reflected_clean = injected_host.lower() in clean_body.lower()

                if reflected_prime and prime_cached and label == "xss":
                    # XSS payload reflected in a cacheable response — highest severity
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"host_xss:{url}"),
                        vuln_type="cache_poison_xss",
                        url=url,
                        test_url=url,
                        evidence=(
                            f"X-Forwarded-Host XSS payload '{injected_host}' reflected in "
                            f"cacheable response from {url} (HTTP {prime_resp.status_code}). "
                            f"Payload appears unescaped in response body — cache poisoning "
                            f"combined with XSS. Cache header: {prime_cache_raw}"
                        ),
                        severity="critical",
                        confidence=0.93,
                        cache_header_value=prime_cache_raw,
                    )

                if reflected_clean and clean_cached:
                    # Sentinel reflected in clean cached response — confirmed poisoning
                    vuln = "cache_poison_xss" if label == "xss" else "cache_poisoning"
                    sev = "critical"
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"host_poison_clean:{url}:{label}"),
                        vuln_type=vuln,
                        url=url,
                        test_url=url,
                        evidence=(
                            f"X-Forwarded-Host: '{injected_host}' injected at {url}. "
                            f"Subsequent clean request received cached response containing "
                            f"the injected host value — cache poisoning confirmed. "
                            f"Cache header: {clean_cache_raw}"
                        ),
                        severity=sev,
                        confidence=0.95,
                        cache_header_value=clean_cache_raw,
                    )

                if reflected_prime and prime_cached:
                    # Reflected in poisoned response itself (weaker — may poison other users)
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"host_poison_prime:{url}:{label}"),
                        vuln_type="cache_poisoning",
                        url=url,
                        test_url=url,
                        evidence=(
                            f"X-Forwarded-Host: '{injected_host}' reflected in cacheable "
                            f"prime response from {url} (HTTP {prime_resp.status_code}). "
                            f"Other users fetching from cache may receive the poisoned copy. "
                            f"Cache header: {prime_cache_raw}"
                        ),
                        severity="high",
                        confidence=0.80,
                        cache_header_value=prime_cache_raw,
                    )

            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                log.debug("Host-header cache poison probe failed for %s [%s]: %s", url, label, exc)

        return None

    # ── 6. Path-Based Cache Poisoning (Fat GET / Parameter Cloaking) ─────────

    async def test_path_cache_poison(
        self,
        url: str,
    ) -> Optional[CacheDeceptionFinding]:
        """
        Fat GET / parameter cloaking via X-Original-URL and X-Rewrite-URL.

        Sends a normal GET with an X-Original-URL header pointing at a privileged
        path (e.g. /admin).  If the origin routes on the header rather than the
        request-line path, and the CDN caches on the request-line key, subsequent
        unauthenticated requests for the original URL will receive the admin response.
        """
        _CLOAK_PATHS = [
            "/admin", "/admin/", "/.env", "/config", "/api/admin",
            "/actuator", "/debug", "/_internal",
        ]
        _CLOAK_HEADERS = ["X-Original-URL", "X-Rewrite-URL", "X-Override-URL"]

        parsed = urlparse(url)

        for cloak_header in _CLOAK_HEADERS:
            for admin_path in _CLOAK_PATHS:
                dedup_key = f"path_cloak:{url}:{cloak_header}:{admin_path}"
                if dedup_key in self._tested:
                    continue
                self._tested.add(dedup_key)

                try:
                    inject_headers = {cloak_header: admin_path}
                    prime_resp = await self._anon_client.get(url, headers=inject_headers)

                    # A 200 on an admin path when the request-line has a normal path
                    # indicates the server is routing on the override header
                    if prime_resp.status_code != 200:
                        continue

                    prime_cached, prime_cache_raw = _is_cached(prime_resp.headers)
                    prime_body = prime_resp.text

                    # Check if the body contains admin-looking content
                    admin_indicators = ["admin", "dashboard", "configuration", "debug", "actuator"]
                    body_lower = prime_body.lower()
                    has_admin_content = any(ind in body_lower for ind in admin_indicators)

                    # Verify — clean request should return the cached admin response
                    await asyncio.sleep(0.25)
                    clean_resp = await self._anon_client.get(url)
                    clean_cached, clean_cache_raw = _is_cached(clean_resp.headers)
                    clean_body = clean_resp.text
                    clean_has_admin = any(ind in clean_body.lower() for ind in admin_indicators)

                    if prime_cached and clean_cached and clean_has_admin:
                        return CacheDeceptionFinding(
                            finding_id=_finding_id(f"path_cloak_confirmed:{url}:{cloak_header}"),
                            vuln_type="cache_poison_path_cloaking",
                            url=url,
                            test_url=url,
                            evidence=(
                                f"Parameter cloaking confirmed: {cloak_header}: {admin_path} "
                                f"injected at {url} served admin-like content (cached). "
                                f"Subsequent clean request also returned cached admin content. "
                                f"Cache header: {clean_cache_raw}"
                            ),
                            severity="critical",
                            confidence=0.88,
                            cache_header_value=clean_cache_raw,
                        )

                    if prime_cached and has_admin_content:
                        return CacheDeceptionFinding(
                            finding_id=_finding_id(f"path_cloak_prime:{url}:{cloak_header}:{admin_path}"),
                            vuln_type="cache_poison_path_cloaking",
                            url=url,
                            test_url=url,
                            evidence=(
                                f"Parameter cloaking suspected: {cloak_header}: {admin_path} "
                                f"caused {url} to return admin-like cached content "
                                f"(HTTP {prime_resp.status_code}). "
                                f"Cache header: {prime_cache_raw}"
                            ),
                            severity="high",
                            confidence=0.75,
                            cache_header_value=prime_cache_raw,
                        )

                except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                    log.debug(
                        "Path cache poison probe failed for %s [%s:%s]: %s",
                        url, cloak_header, admin_path, exc,
                    )

        return None

    # ── 7. Response Header Injection via X-Forwarded-Port ────────────────────

    async def test_response_header_injection(
        self,
        url: str,
    ) -> Optional[CacheDeceptionFinding]:
        """
        Response header injection via X-Forwarded-Port in an HTTPS context.

        If the server reflects X-Forwarded-Port into a Location or Content-Location
        header (e.g. when generating redirect URLs), an attacker can force HTTP
        downgrade redirects: ``https://example.com`` → ``http://example.com`` by
        injecting ``X-Forwarded-Port: 80``.  When that redirect is cached, all
        subsequent visitors are downgraded to plaintext HTTP.
        """
        _PORT_PAYLOADS: List[Tuple[str, str]] = [
            ("80", "http_downgrade"),
            ("8080", "proxy_redirect"),
            ("443\r\nX-Injected: rhi-probe", "crlf_injection"),
        ]

        parsed = urlparse(url)
        is_https = parsed.scheme.lower() == "https"

        for port_val, label in _PORT_PAYLOADS:
            dedup_key = f"rhi:{url}:{label}"
            if dedup_key in self._tested:
                continue
            self._tested.add(dedup_key)

            inject_headers = {"X-Forwarded-Port": port_val}
            try:
                resp = await self._anon_client.get(url, headers=inject_headers)
                body = resp.text
                resp_headers_raw = "\r\n".join(
                    f"{k}: {v}" for k, v in resp.headers.items()
                )
                cached, cache_raw = _is_cached(resp.headers)

                # CRLF injection: injected header name appears in response
                if label == "crlf_injection" and "x-injected" in resp_headers_raw.lower():
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"rhi_crlf:{url}"),
                        vuln_type="response_header_injection",
                        url=url,
                        test_url=url,
                        evidence=(
                            f"CRLF injection via X-Forwarded-Port at {url}: injected header "
                            f"'X-Injected: rhi-probe' appeared in HTTP response. "
                            f"Cache header: {cache_raw}"
                        ),
                        severity="critical",
                        confidence=0.95,
                        cache_header_value=cache_raw,
                    )

                # HTTP downgrade: 3xx redirect from HTTPS → HTTP (port 80 injected)
                if label == "http_downgrade" and is_https and resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("location", "")
                    if location.startswith("http://"):
                        return CacheDeceptionFinding(
                            finding_id=_finding_id(f"rhi_downgrade:{url}"),
                            vuln_type="response_header_injection",
                            url=url,
                            test_url=url,
                            evidence=(
                                f"HTTP downgrade via X-Forwarded-Port: 80 at {url} "
                                f"(HTTP {resp.status_code}). "
                                f"Location header: '{location}' — redirect to plaintext HTTP. "
                                + ("Response is cached — all users affected. " if cached else "")
                                + f"Cache header: {cache_raw}"
                            ),
                            severity="critical" if cached else "high",
                            confidence=0.90 if cached else 0.75,
                            cache_header_value=cache_raw,
                        )

                # Weak signal: port value reflected in response body or headers
                if port_val in body or port_val in resp_headers_raw:
                    if cached:
                        return CacheDeceptionFinding(
                            finding_id=_finding_id(f"rhi_reflected:{url}:{label}"),
                            vuln_type="response_header_injection",
                            url=url,
                            test_url=url,
                            evidence=(
                                f"X-Forwarded-Port: '{port_val}' reflected in cached response "
                                f"from {url} (HTTP {resp.status_code}). Server may generate "
                                f"URLs/redirects using attacker-controlled port value. "
                                f"Cache header: {cache_raw}"
                            ),
                            severity="high",
                            confidence=0.72,
                            cache_header_value=cache_raw,
                        )

            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                log.debug("Response header injection probe failed for %s [%s]: %s", url, label, exc)

        return None

    # ── 3. CDN Cache-Key Normalisation ───────────────────────────────────────

    async def test_cdn_normalisation(
        self,
        url: str,
        auth_headers: Dict[str, str],
    ) -> Optional[CacheDeceptionFinding]:
        """
        CDN cache-key normalisation probe: path traversal may collapse to a
        privileged path in the CDN key while routing correctly on origin.
        """
        if self._authed_client is None:
            self._authed_client = self._build_authed_client(auth_headers)

        parsed = urlparse(url)
        base_path = parsed.path.rstrip("/")

        for suffix, label in _CDN_TRAVERSAL_PAYLOADS:
            traversal_path = base_path + suffix
            test_url = urlunparse(parsed._replace(path=traversal_path))
            dedup_key = f"cdn:{test_url}"
            if dedup_key in self._tested:
                continue
            self._tested.add(dedup_key)

            try:
                # Authenticated traversal request — may warm admin page in cache
                auth_resp = await self._authed_client.get(test_url)

                # Check if a different status was returned vs. the original path
                orig_resp = await self._anon_client.get(url)
                trav_resp = await self._anon_client.get(test_url)

                _, cache_raw = _is_cached(trav_resp.headers)
                trav_cached, _ = _is_cached(trav_resp.headers)

                # Positive: traversal path returns a different (higher-priv) response
                # while the cache says it's a hit — indicates key normalisation
                if (trav_resp.status_code != orig_resp.status_code
                        and trav_resp.status_code == 200
                        and trav_cached):
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"cdn:{url}:{label}"),
                        vuln_type="cdn_normalisation",
                        url=url,
                        test_url=test_url,
                        evidence=(
                            f"CDN cache-key normalisation suspected at {url}. "
                            f"Traversal suffix '{suffix}' ({label}) yielded HTTP "
                            f"{trav_resp.status_code} while direct path yielded "
                            f"{orig_resp.status_code}. Response served from cache. "
                            f"Cache header: {cache_raw}"
                        ),
                        severity="high",
                        confidence=0.75,
                        cache_header_value=cache_raw,
                    )

                # Also flag if both 200 but traversal body contains auth-looking content
                # that the original path does not
                if (trav_resp.status_code == 200
                        and trav_cached
                        and _looks_authenticated(trav_resp.text)
                        and not _looks_authenticated(orig_resp.text)):
                    return CacheDeceptionFinding(
                        finding_id=_finding_id(f"cdn_auth:{url}:{label}"),
                        vuln_type="cdn_normalisation",
                        url=url,
                        test_url=test_url,
                        evidence=(
                            f"CDN normalisation at {url}: traversal path '{suffix}' "
                            f"returned cached response containing auth-gated content "
                            f"absent from the canonical path. "
                            f"Cache header: {cache_raw}"
                        ),
                        severity="critical",
                        confidence=0.85,
                        cache_header_value=cache_raw,
                    )

            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                log.debug("CDN normalisation probe failed for %s [%s]: %s", url, label, exc)

        return None

    # ── 4. Vary Header Bypass ─────────────────────────────────────────────────

    async def test_vary_bypass(
        self,
        url: str,
        auth_headers: Dict[str, str],
    ) -> Optional[CacheDeceptionFinding]:
        """
        Vary-bypass probe: check whether the server omits or under-scopes the
        ``Vary`` header on responses that contain auth-dependent data.
        """
        if self._authed_client is None:
            self._authed_client = self._build_authed_client(auth_headers)

        dedup_key = f"vary:{url}"
        if dedup_key in self._tested:
            return None
        self._tested.add(dedup_key)

        try:
            auth_resp = await self._authed_client.get(url)
            if auth_resp.status_code != 200:
                return None

            body = auth_resp.text
            vary = auth_resp.headers.get("vary", "").lower()
            cc = auth_resp.headers.get("cache-control", "").lower()

            # Not cacheable — skip
            if "no-store" in cc or "private" in cc:
                return None

            is_auth_content = _looks_authenticated(body)
            has_auth_vary = any(h in vary for h in ("cookie", "authorization"))

            if is_auth_content and not has_auth_vary:
                _, cache_raw = _is_cached(auth_resp.headers)
                missing = []
                if "cookie" not in vary and auth_headers.get("Cookie"):
                    missing.append("Cookie")
                if "authorization" not in vary and auth_headers.get("Authorization"):
                    missing.append("Authorization")
                if not missing:
                    # No explicit auth header used — infer from content
                    missing = ["Cookie/Authorization"]

                return CacheDeceptionFinding(
                    finding_id=_finding_id(f"vary:{url}"),
                    vuln_type="vary_bypass",
                    url=url,
                    test_url=url,
                    evidence=(
                        f"Endpoint {url} returned auth-dependent content "
                        f"(HTTP {auth_resp.status_code}) but Vary header is "
                        f"'{vary or '(absent)'}' — missing: {', '.join(missing)}. "
                        f"Cacheable responses without Vary: {', '.join(missing)} risk "
                        f"serving authenticated data to other users. "
                        f"Cache-Control: {cc or '(absent)'}"
                    ),
                    severity="high",
                    confidence=0.80,
                    cache_header_value=cache_raw,
                )

        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            log.debug("Vary bypass probe failed for %s: %s", url, exc)

        return None

    # ── Top-level scan ────────────────────────────────────────────────────────

    async def scan(
        self,
        target: str,
        endpoints: List[str],
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[CacheDeceptionFinding]:
        """
        Run all cache-deception checks against the provided endpoints.

        Parameters
        ----------
        target:
            Base URL of the target (used for logging and discovery fallback).
        endpoints:
            List of absolute URLs to test. If empty, the scanner falls back to
            traffic-capture discovery.
        auth_headers:
            HTTP headers that grant authenticated access (e.g. Cookie, Authorization).
            If omitted, WCD / CDN / Vary tests are skipped (they require auth context).

        Returns
        -------
        List[CacheDeceptionFinding]
        """
        _auth = auth_headers or {}

        if not endpoints:
            endpoints = await self._discover_endpoints(target)

        if not endpoints:
            log.info("cache_deception_scanner: no endpoints to test for %s", target)
            return []

        log.info(
            "cache_deception_scanner: testing %d endpoints against %s",
            len(endpoints), target,
        )

        findings: List[CacheDeceptionFinding] = []

        for url in endpoints[:50]:  # cap to avoid runaway scan time
            tasks = [
                self.test_cache_poisoning(url),
                self.test_host_header_cache_poison(url),
                self.test_path_cache_poison(url),
                self.test_response_header_injection(url),
            ]
            if _auth:
                tasks += [
                    self.test_web_cache_deception(url, _auth),
                    self.test_cdn_normalisation(url, _auth),
                    self.test_vary_bypass(url, _auth),
                ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, CacheDeceptionFinding):
                    findings.append(r)
                elif isinstance(r, Exception):
                    log.debug("cache_deception_scanner probe exception: %s", r)

        log.info(
            "cache_deception_scanner: complete — %d finding(s) for %s",
            len(findings), target,
        )
        return findings

    # ── Endpoint Discovery ────────────────────────────────────────────────────

    async def _discover_endpoints(self, target: str) -> List[str]:
        """Pull endpoints from traffic capture engine (mirrors cors_scanner pattern)."""
        try:
            from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
        except ImportError:
            log.warning("cache_deception_scanner: traffic capture engine unavailable")
            return []

        endpoints: Set[str] = set()
        try:
            requests = traffic_capture_engine.list(target=target, limit=500)
        except Exception as exc:
            log.error("cache_deception_scanner: traffic capture failed: %s", exc)
            return []

        for req in requests:
            req_dict = req.to_json() if hasattr(req, "to_json") else req
            url = req_dict.get("url", "")
            if url:
                endpoints.add(url.split("?")[0])

        log.info("cache_deception_scanner: discovered %d endpoints from traffic", len(endpoints))
        return list(endpoints)


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────


def get_scanner(timeout: int = 12) -> CacheDeceptionScanner:
    """Return a fresh CacheDeceptionScanner instance."""
    return CacheDeceptionScanner(timeout=timeout)
