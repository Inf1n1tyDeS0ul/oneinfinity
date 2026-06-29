"""
CAPTCHA & 2FA Bypass Testing Engine
====================================
Automated bypass technique testing for CAPTCHA and 2FA endpoints.

Integrates with:
  - traffic_capture_engine.py (pattern detection)
  - traffic_replay_engine.py (bulk replay)

Innovation: Pattern-based bypass discovery + automated solver fallback.
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

import httpx

from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine, CapturedRequest

log = logging.getLogger("oneinfinity.captcha_bypass")

# ─────────────────────────────────────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────────────────────────────────────

_CAPTCHA_INDICATORS = [
    re.compile(r'captcha|recaptcha|hcaptcha|turnstile', re.I),
    re.compile(r'g-recaptcha-response', re.I),
    re.compile(r'cf-turnstile-response', re.I),
]

_2FA_INDICATORS = [
    re.compile(r'2fa|mfa|otp|totp|verify|code', re.I),
    re.compile(r'/verify|/2fa|/mfa|/otp', re.I),
]


@dataclass
class BypassAttempt:
    """Single bypass attempt result"""
    technique: str = ""
    successful: bool = False
    status_code: int = 0
    response_body: str = ""
    evidence: str = ""


@dataclass
class BypassFinding:
    """CAPTCHA/2FA bypass vulnerability"""
    finding_id: str = field(default_factory=lambda: f"BYPASS-{uuid.uuid4().hex[:8].upper()}")
    vuln_type: str = ""  # "captcha_bypass" or "2fa_bypass"
    title: str = ""
    severity: str = "high"
    url: str = ""
    bypass_technique: str = ""
    evidence: str = ""
    payload: str = ""
    confidence: float = 0.0
    attempts: List[BypassAttempt] = field(default_factory=list)
    tool: str = "captcha_bypass_engine"
    source_type: str = "tool"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != 'attempts'}


class CaptchaBypassEngine:
    """
    CAPTCHA and 2FA bypass testing engine.

    Bypass techniques:
    1. Parameter removal (remove captcha param entirely)
    2. Null/empty value (captcha="" or null)
    3. Token reuse (use old/expired token)
    4. HTTP method change (POST → GET)
    5. Case manipulation (Captcha vs captcha)
    6. Direct endpoint access (skip captcha page)
    """

    def __init__(self):
        pass

    async def test_captcha_bypass(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        original_params: Dict[str, str],
    ) -> List[BypassFinding]:
        """Test various CAPTCHA bypass techniques"""
        findings = []

        # Identify captcha parameter
        captcha_param = self._find_captcha_param(original_params, body)
        if not captcha_param:
            log.debug(f"No CAPTCHA parameter found in {url}")
            return findings

        log.info(f"Testing CAPTCHA bypass on {url}, param={captcha_param}")

        attempts = []

        # Technique 1: Remove parameter entirely
        attempt = await self._test_param_removal(
            url, method, headers, body, captcha_param
        )
        attempts.append(attempt)

        # Technique 2: Empty/null value
        attempt = await self._test_null_value(
            url, method, headers, body, captcha_param
        )
        attempts.append(attempt)

        # Technique 3: Reuse old token (if available)
        old_token = self._get_old_captcha_token(url)
        if old_token:
            attempt = await self._test_token_reuse(
                url, method, headers, body, captcha_param, old_token
            )
            attempts.append(attempt)

        # Technique 4: HTTP method change
        if method == "POST":
            attempt = await self._test_method_change(
                url, "GET", headers, original_params
            )
            attempts.append(attempt)

        # Analyze attempts
        successful_attempts = [a for a in attempts if a.successful]

        if successful_attempts:
            finding = BypassFinding(
                vuln_type="captcha_bypass",
                title="CAPTCHA Bypass Detected",
                severity="high",
                url=url,
                bypass_technique=successful_attempts[0].technique,
                evidence=successful_attempts[0].evidence,
                payload=f"Bypassed via {successful_attempts[0].technique}",
                confidence=0.90,
                attempts=attempts,
            )
            findings.append(finding)

        return findings

    async def test_2fa_bypass(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        original_params: Dict[str, str],
        session_cookies: Optional[str] = None,
    ) -> List[BypassFinding]:
        """Test 2FA bypass techniques"""
        findings = []

        log.info(f"Testing 2FA bypass on {url}")

        attempts = []

        # Technique 1: Direct access (skip 2FA page)
        if session_cookies:
            attempt = await self._test_direct_access(
                url.replace('/verify', '/dashboard'),
                headers,
                session_cookies,
            )
            attempts.append(attempt)

        # Technique 2: Missing 2FA param
        code_param = self._find_2fa_param(original_params, body)
        if code_param:
            attempt = await self._test_param_removal(
                url, method, headers, body, code_param
            )
            attempts.append(attempt)

        # Technique 3: Response manipulation test (send invalid code, check response)
        attempt = await self._test_response_manipulation(
            url, method, headers, body
        )
        attempts.append(attempt)

        successful_attempts = [a for a in attempts if a.successful]

        if successful_attempts:
            finding = BypassFinding(
                vuln_type="2fa_bypass",
                title="2FA Bypass Detected",
                severity="critical",
                url=url,
                bypass_technique=successful_attempts[0].technique,
                evidence=successful_attempts[0].evidence,
                payload=f"Bypassed via {successful_attempts[0].technique}",
                confidence=0.85,
                attempts=attempts,
            )
            findings.append(finding)

        return findings

    # ── Bypass Techniques ─────────────────────────────────────────────────────

    async def _test_param_removal(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        param_name: str,
    ) -> BypassAttempt:
        """Test bypass by removing parameter"""
        try:
            # Remove param from body
            modified_body = self._remove_param(body, param_name)

            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=modified_body.encode('utf-8') if modified_body else None,
                )

                # Success if 200/201 and doesn't contain error markers
                successful = (
                    resp.status_code in (200, 201, 302) and
                    not self._contains_error(resp.text)
                )

                return BypassAttempt(
                    technique="parameter_removal",
                    successful=successful,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                    evidence=f"Removed {param_name} param, got HTTP {resp.status_code}"
                )

        except Exception as exc:
            return BypassAttempt(
                technique="parameter_removal",
                successful=False,
                evidence=f"Failed: {exc}"
            )

    async def _test_null_value(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        param_name: str,
    ) -> BypassAttempt:
        """Test bypass with null/empty value"""
        try:
            modified_body = self._set_param_value(body, param_name, "")

            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=modified_body.encode('utf-8') if modified_body else None,
                )

                successful = (
                    resp.status_code in (200, 201, 302) and
                    not self._contains_error(resp.text)
                )

                return BypassAttempt(
                    technique="null_value",
                    successful=successful,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                    evidence=f"Set {param_name}='', got HTTP {resp.status_code}"
                )

        except Exception as exc:
            return BypassAttempt(
                technique="null_value",
                successful=False,
                evidence=f"Failed: {exc}"
            )

    async def _test_token_reuse(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        param_name: str,
        old_token: str,
    ) -> BypassAttempt:
        """Test reusing old/expired token"""
        try:
            modified_body = self._set_param_value(body, param_name, old_token)

            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=modified_body.encode('utf-8') if modified_body else None,
                )

                successful = (
                    resp.status_code in (200, 201, 302) and
                    not self._contains_error(resp.text)
                )

                return BypassAttempt(
                    technique="token_reuse",
                    successful=successful,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                    evidence=f"Reused old token, got HTTP {resp.status_code}"
                )

        except Exception as exc:
            return BypassAttempt(
                technique="token_reuse",
                successful=False,
                evidence=f"Failed: {exc}"
            )

    async def _test_method_change(
        self,
        url: str,
        new_method: str,
        headers: Dict[str, str],
        params: Dict[str, str],
    ) -> BypassAttempt:
        """Test changing HTTP method"""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.request(
                    method=new_method,
                    url=url,
                    headers=headers,
                    params=params,
                )

                successful = (
                    resp.status_code in (200, 201, 302) and
                    not self._contains_error(resp.text)
                )

                return BypassAttempt(
                    technique="method_change",
                    successful=successful,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                    evidence=f"Changed method to {new_method}, got HTTP {resp.status_code}"
                )

        except Exception as exc:
            return BypassAttempt(
                technique="method_change",
                successful=False,
                evidence=f"Failed: {exc}"
            )

    async def _test_direct_access(
        self,
        protected_url: str,
        headers: Dict[str, str],
        session_cookies: str,
    ) -> BypassAttempt:
        """Test direct access to protected resource (skip 2FA)"""
        try:
            headers_with_cookies = {**headers, 'Cookie': session_cookies}

            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.get(
                    protected_url,
                    headers=headers_with_cookies,
                    follow_redirects=False,
                )

                # Success if not redirected to login/2FA
                successful = (
                    resp.status_code == 200 and
                    '/login' not in resp.text.lower() and
                    '/verify' not in resp.text.lower()
                )

                return BypassAttempt(
                    technique="direct_access",
                    successful=successful,
                    status_code=resp.status_code,
                    response_body=resp.text[:500],
                    evidence=f"Direct access to {protected_url}, got HTTP {resp.status_code}"
                )

        except Exception as exc:
            return BypassAttempt(
                technique="direct_access",
                successful=False,
                evidence=f"Failed: {exc}"
            )

    async def _test_response_manipulation(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
    ) -> BypassAttempt:
        """Test if response can be manipulated (returns parseable JSON)"""
        try:
            # Send invalid code
            modified_body = self._set_param_value(body, 'code', '000000')

            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=modified_body.encode('utf-8') if modified_body else None,
                )

                # Check if response is JSON with success/valid field
                try:
                    import json
                    data = json.loads(resp.text)
                    has_success_field = any(
                        k in data for k in ['success', 'valid', 'verified', 'status']
                    )

                    if has_success_field and resp.status_code == 200:
                        return BypassAttempt(
                            technique="response_manipulation",
                            successful=True,
                            status_code=resp.status_code,
                            response_body=resp.text[:500],
                            evidence="Response contains parseable success field - client-side validation risk"
                        )

                except (json.JSONDecodeError, KeyError):
                    pass

                return BypassAttempt(
                    technique="response_manipulation",
                    successful=False,
                    status_code=resp.status_code,
                    evidence="Response not manipulable"
                )

        except Exception as exc:
            return BypassAttempt(
                technique="response_manipulation",
                successful=False,
                evidence=f"Failed: {exc}"
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _find_captcha_param(self, params: Dict[str, str], body: str) -> Optional[str]:
        """Find CAPTCHA parameter name"""
        all_text = str(params) + body

        for pattern in _CAPTCHA_INDICATORS:
            match = pattern.search(all_text)
            if match:
                # Extract param name
                param_pattern = re.compile(r'["\']?(\w*captcha\w*)["\']?\s*[:=]', re.I)
                param_match = param_pattern.search(all_text)
                if param_match:
                    return param_match.group(1)

        return None

    def _find_2fa_param(self, params: Dict[str, str], body: str) -> Optional[str]:
        """Find 2FA/OTP parameter name"""
        common_names = ['code', 'otp', 'token', 'totp', 'verify_code', '2fa_code']

        # Check params
        for name in common_names:
            if name in params:
                return name

        # Check body
        for name in common_names:
            if name in body.lower():
                return name

        return None

    def _remove_param(self, body: str, param_name: str) -> str:
        """Remove parameter from JSON or form-encoded body"""
        # Try JSON
        try:
            import json
            data = json.loads(body)
            if isinstance(data, dict) and param_name in data:
                del data[param_name]
                return json.dumps(data)
        except (json.JSONDecodeError, KeyError):
            pass

        # Try form-encoded
        import urllib.parse
        try:
            params = urllib.parse.parse_qs(body)
            if param_name in params:
                del params[param_name]
                return urllib.parse.urlencode(params, doseq=True)
        except Exception:
            pass

        return body

    def _set_param_value(self, body: str, param_name: str, value: str) -> str:
        """Set parameter value in body"""
        # Try JSON
        try:
            import json
            data = json.loads(body)
            if isinstance(data, dict):
                data[param_name] = value
                return json.dumps(data)
        except json.JSONDecodeError:
            pass

        # Try form-encoded
        import urllib.parse
        try:
            params = urllib.parse.parse_qs(body)
            params[param_name] = [value]
            return urllib.parse.urlencode(params, doseq=True)
        except Exception:
            pass

        return body

    def _contains_error(self, response: str) -> bool:
        """Check if response contains error indicators"""
        error_markers = ['error', 'invalid', 'incorrect', 'failed', 'denied']
        response_lower = response.lower()
        return any(marker in response_lower for marker in error_markers)

    def _get_old_captcha_token(self, url: str) -> Optional[str]:
        """Get old CAPTCHA token from traffic history"""
        # Query traffic DB for previous successful requests to same URL
        domain = urlparse(url).netloc
        historical_requests = traffic_capture_engine.list(
            target=domain,
            status_code=200,
            limit=10,
        )

        for req in historical_requests:
            # Look for captcha tokens in body
            for pattern in _CAPTCHA_INDICATORS:
                match = pattern.search(req.body)
                if match:
                    # Extract token value
                    token_pattern = re.compile(r'["\']([A-Za-z0-9_\-\.]{20,})["\']')
                    token_match = token_pattern.search(req.body)
                    if token_match:
                        return token_match.group(1)

        return None

    # ── Automated Detection ───────────────────────────────────────────────────

    async def scan_captured_traffic(self, limit: int = 100) -> List[BypassFinding]:
        """
        Automatically detect and test CAPTCHA/2FA endpoints in captured traffic.
        """
        findings = []

        # Get all POST requests
        candidates = traffic_capture_engine.list(
            method="POST",
            status_min=200,
            status_max=299,
            limit=limit,
        )

        for req in candidates:
            # Check if endpoint looks like CAPTCHA/2FA
            is_captcha = any(pattern.search(req.url + req.body) for pattern in _CAPTCHA_INDICATORS)
            is_2fa = any(pattern.search(req.url + req.body) for pattern in _2FA_INDICATORS)

            if is_captcha:
                results = await self.test_captcha_bypass(
                    url=req.url,
                    method=req.method,
                    headers=req.headers,
                    body=req.body,
                    original_params=parse_qs(req.body),
                )
                findings.extend(results)

            elif is_2fa:
                results = await self.test_2fa_bypass(
                    url=req.url,
                    method=req.method,
                    headers=req.headers,
                    body=req.body,
                    original_params=parse_qs(req.body),
                )
                findings.extend(results)

        return findings


captcha_bypass_engine = CaptchaBypassEngine()
