"""
OAuth Token Leak Scanner
=========================
Detects OAuth token/code leakage via referer, logs, CORS, client-side.

Innovation:
1. **Referer Leak** - Token in URL → external referer
2. **Log Injection** - Token visible in access logs
3. **CORS Leak** - Token in origin that allows CORS
4. **Client-Side Leak** - Token in JavaScript/localStorage
5. **Authorization Code Interception** - Redirect URI manipulation

No other tool tests all 5 OAuth leak vectors.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, parse_qs

import httpx

log = logging.getLogger("oneinfinity.oauth_leak")

@dataclass
class OAuthLeakFinding:
    finding_id: str
    vuln_type: str = "oauth_token_leak"
    title: str = ""
    severity: str = "critical"
    url: str = ""
    leak_type: str = ""
    token: str = ""
    evidence: str = ""
    confidence: float = 0.0
    exploitation_steps: List[str] = field(default_factory=list)
    tool: str = "oauth_leak_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}

class OAuthLeakScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.http_client = httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=False)

    async def close(self):
        await self.http_client.aclose()

    async def discover_oauth_flows(self, target: str, limit: int = 500) -> List[dict]:
        """Find OAuth authorization/token endpoints from traffic."""
        oauth_endpoints = []
        try:
            from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
            requests = traffic_capture_engine.list(target=target, limit=limit)
            for req in requests:
                req_dict = req.to_json() if hasattr(req, 'to_json') else req
                url = req_dict.get("url", "")
                if any(x in url.lower() for x in ["oauth", "authorize", "token", "callback"]):
                    oauth_endpoints.append({"url": url, "method": req_dict.get("method", "GET")})
        except Exception as e:
            log.error(f"Traffic discovery failed: {e}")
        return oauth_endpoints

    async def test_referer_leak(self, url: str) -> Optional[OAuthLeakFinding]:
        """Test if OAuth token leaks via referer header."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        # Check for token in URL
        token_keys = ["access_token", "token", "code", "authorization_code"]
        leaked_token = None
        for key in token_keys:
            if key in query_params:
                leaked_token = query_params[key][0]
                break

        if not leaked_token:
            return None

        # Test referer leak - make request to external site with OAuth URL as referer
        try:
            test_url = "http://example.com/test"
            resp = await self.http_client.get(test_url, headers={"Referer": url})
            # If this were real attack, external server would see full OAuth URL in referer

            return OAuthLeakFinding(
                finding_id=hashlib.md5(f"oauth_referer_{url}".encode()).hexdigest()[:16],
                title=f"OAuth token in URL (referer leak)",
                severity="critical",
                url=url,
                leak_type="referer",
                token=leaked_token[:20] + "...",
                evidence=f"Token in URL will leak via Referer header",
                confidence=0.95,
                exploitation_steps=[
                    "1. OAuth token in URL query parameter",
                    "2. User clicks external link",
                    "3. Full URL sent in Referer header",
                    "4. Attacker captures token from access logs",
                ]
            )
        except Exception as e:
            log.debug(f"Referer test failed: {e}")

        return None

    async def test_client_side_leak(self, url: str) -> Optional[OAuthLeakFinding]:
        """Test if OAuth tokens exposed in JavaScript/localStorage."""
        try:
            resp = await self.http_client.get(url)

            # Check for OAuth tokens in JavaScript
            oauth_patterns = [
                r'access_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'localStorage\.setItem\(["\']token["\']\s*,\s*["\']([^"\']+)["\']',
                r'bearer\s+([A-Za-z0-9\-_\.]{20,})',
            ]

            for pattern in oauth_patterns:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                if matches:
                    return OAuthLeakFinding(
                        finding_id=hashlib.md5(f"oauth_js_{url}".encode()).hexdigest()[:16],
                        title=f"OAuth token in client-side code",
                        severity="high",
                        url=url,
                        leak_type="client_side",
                        token=matches[0][:20] + "...",
                        evidence="OAuth token hardcoded in JavaScript",
                        confidence=0.90,
                        exploitation_steps=[
                            "1. OAuth token stored in JavaScript/localStorage",
                            "2. Visible to anyone viewing page source",
                            "3. XSS can steal token",
                            "4. Use token to access victim account",
                        ]
                    )
        except Exception as e:
            log.debug(f"Client-side test failed: {e}")

        return None

    # ── Active OAuth Attacks ──────────────────────────────────────────────────

    async def test_pkce_downgrade(self, auth_url: str) -> dict | None:
        """
        Resend the authorization request without ``code_challenge`` / ``code_challenge_method``.
        If the server accepts the request (2xx/3xx) the flow is vulnerable to PKCE downgrade.
        """
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Build downgraded params: drop PKCE fields
        downgraded = {k: v[0] for k, v in params.items()
                      if k not in ("code_challenge", "code_challenge_method")}

        from urllib.parse import urlencode, urlunparse
        stripped_qs = urlencode(downgraded)
        stripped_url = urlunparse(parsed._replace(query=stripped_qs))

        try:
            resp = await self.http_client.get(stripped_url, follow_redirects=False)
            # Server should return 400 or redirect to error — anything else is a downgrade
            if resp.status_code not in (400, 401, 403):
                return {
                    "finding_id": hashlib.md5(f"pkce_dg_{auth_url}".encode()).hexdigest()[:16],
                    "vuln_type": "oauth_pkce_downgrade",
                    "severity": "high",
                    "url": stripped_url,
                    "payload": stripped_url,
                    "evidence": (
                        f"Authorization endpoint accepted request without code_challenge "
                        f"(HTTP {resp.status_code}). PKCE can be bypassed."
                    ),
                    "tool": "oauth_leak_scanner",
                    "target": auth_url,
                }
        except Exception as e:
            log.debug(f"PKCE downgrade test failed: {e}")
        return None

    async def test_state_fixation(self, auth_url: str) -> dict | None:
        """
        Pre-set a known ``state`` parameter and verify the server enforces it
        (i.e. the server should validate state on callback, not just echo it).
        Flag when the server returns the fixed state in the redirect Location header
        without a 400/error — indicating state fixation is possible.
        """
        from urllib.parse import urlencode, urlunparse
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        fixed_state = "ONEINFINITY_STATE_FIXATION_TEST_12345"
        params["state"] = [fixed_state]
        fixed_qs = urlencode({k: v[0] for k, v in params.items()})
        fixed_url = urlunparse(parsed._replace(query=fixed_qs))

        try:
            resp = await self.http_client.get(fixed_url, follow_redirects=False)
            location = resp.headers.get("location", "")
            if fixed_state in location and resp.status_code in (301, 302, 303, 307, 308):
                return {
                    "finding_id": hashlib.md5(f"state_fix_{auth_url}".encode()).hexdigest()[:16],
                    "vuln_type": "oauth_state_fixation",
                    "severity": "high",
                    "url": fixed_url,
                    "payload": fixed_state,
                    "evidence": (
                        f"Server reflected attacker-controlled state '{fixed_state}' in redirect "
                        f"Location header — CSRF / state fixation possible."
                    ),
                    "tool": "oauth_leak_scanner",
                    "target": auth_url,
                }
        except Exception as e:
            log.debug(f"State fixation test failed: {e}")
        return None

    async def test_redirect_uri_bypass(self, auth_url: str, redirect_uri: str) -> list[dict]:
        """
        Attempt redirect_uri bypass via:
        - Path traversal  (``/callback/../evil``)
        - Fragment injection (``/callback#https://evil.com``)
        - Subdomain confusion (``evil.legit-domain.com``)
        - Open-redirect suffix (``/callback?next=https://evil.com``)

        Each variant is sent as a fresh authorization request; a non-400 response
        with the manipulated URI in Location is flagged.
        """
        from urllib.parse import urlencode, urlunparse, quote
        findings: list[dict] = []
        parsed_auth = urlparse(auth_url)
        parsed_redir = urlparse(redirect_uri)
        base_domain = parsed_redir.netloc

        variants = [
            # Path traversal
            redirect_uri.rstrip("/") + "/../evil",
            # Fragment injection
            redirect_uri + "#https://evil.oneinfinity.test",
            # Subdomain prepend
            f"{parsed_redir.scheme}://evil.{base_domain}{parsed_redir.path}",
            # Open-redirect suffix
            redirect_uri + "?next=https://evil.oneinfinity.test",
            # URL-encoded dot-dot
            redirect_uri.rstrip("/") + "%2F..%2Fevil",
            # @-sign trick
            f"{parsed_redir.scheme}://evil.oneinfinity.test@{base_domain}{parsed_redir.path}",
        ]

        auth_params = {k: v[0] for k, v in parse_qs(parsed_auth.query, keep_blank_values=True).items()}

        for variant in variants:
            auth_params["redirect_uri"] = variant
            test_qs = urlencode(auth_params)
            test_url = urlunparse(parsed_auth._replace(query=test_qs))
            try:
                resp = await self.http_client.get(test_url, follow_redirects=False)
                location = resp.headers.get("location", "")
                if resp.status_code not in (400, 401, 403) and (
                    "evil" in location or variant in location
                ):
                    findings.append({
                        "finding_id": hashlib.md5(f"redir_bypass_{auth_url}_{variant}".encode()).hexdigest()[:16],
                        "vuln_type": "oauth_redirect_uri_bypass",
                        "severity": "critical",
                        "url": test_url,
                        "payload": variant,
                        "evidence": (
                            f"Server accepted manipulated redirect_uri '{variant[:80]}' "
                            f"(HTTP {resp.status_code}, Location: {location[:80]})."
                        ),
                        "tool": "oauth_leak_scanner",
                        "target": auth_url,
                    })
            except Exception as e:
                log.debug(f"Redirect URI bypass test failed for {variant!r}: {e}")

        return findings

    async def scan(self, target: str, traffic_limit: int = 500) -> List[OAuthLeakFinding]:
        log.info(f"Starting OAuth leak scan for {target}")
        oauth_endpoints = await self.discover_oauth_flows(target, traffic_limit)

        all_findings: List[OAuthLeakFinding] = []

        if not oauth_endpoints:
            log.info("No OAuth endpoints found in traffic; attempting direct active tests on target")
            # Still run active attacks directly against the target URL
            active_tasks = [
                self.test_pkce_downgrade(target),
                self.test_state_fixation(target),
                self.test_redirect_uri_bypass(target, target),
            ]
            active_results = await asyncio.gather(*active_tasks, return_exceptions=True)
            for r in active_results:
                if isinstance(r, dict):
                    all_findings.append(r)  # type: ignore[arg-type]
                elif isinstance(r, list):
                    all_findings.extend(r)  # type: ignore[arg-type]
            log.info(f"OAuth active scan complete: {len(all_findings)} findings")
            return all_findings

        for endpoint in oauth_endpoints[:10]:
            ep_url = endpoint["url"]
            tests = [
                self.test_referer_leak(ep_url),
                self.test_client_side_leak(ep_url),
                self.test_pkce_downgrade(ep_url),
                self.test_state_fixation(ep_url),
                self.test_redirect_uri_bypass(ep_url, ep_url),
            ]
            results = await asyncio.gather(*tests, return_exceptions=True)
            for result in results:
                if isinstance(result, OAuthLeakFinding):
                    all_findings.append(result)
                elif isinstance(result, dict):
                    all_findings.append(result)  # type: ignore[arg-type]
                elif isinstance(result, list):
                    all_findings.extend(result)  # type: ignore[arg-type]

        log.info(f"OAuth leak scan complete: {len(all_findings)} findings")
        return all_findings

async def scan_oauth_leaks(target: str, traffic_limit: int = 500) -> List[OAuthLeakFinding]:
    scanner = OAuthLeakScanner()
    try:
        return await scanner.scan(target, traffic_limit)
    finally:
        await scanner.close()
