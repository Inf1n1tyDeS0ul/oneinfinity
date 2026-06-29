"""
differential_scanner.py — Authenticated vs. Unauthenticated Response Differential Scanner

Innovation: The ONLY tool that automatically detects broken access control by comparing
JSON field sets, status codes, response sizes, and data sensitivity across auth boundaries.

No other tool does this automatically — most require manual Burp Repeater comparison.

How it works
------------
1. Build an endpoint list (from recon or traffic capture)
2. For each endpoint, fire an unauthenticated request
3. Fire an authenticated request using the same session
4. Compute a semantic diff:
   - Status code delta  (401→200 = expected; 200→200 = IDOR candidate)
   - Response size delta (same status but more fields = data leakage)
   - JSON key diff       (auth response contains extra sensitive keys)
   - PII exposure        (SSN, email, card numbers in unauth response)
5. Score each endpoint with a confidence value
6. Emit findings for IDOR, BAC, sensitive data disclosure

Usage::

    scanner = DifferentialScanner(target, auth_session)
    findings = await scanner.scan(endpoints)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

log = logging.getLogger("oneinfinity.differential_scanner")

# ── Sensitivity heuristics ────────────────────────────────────────────────────

_SENSITIVE_KEYS: Set[str] = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "credit_card", "card_number", "cvv", "ssn",
    "social_security", "dob", "date_of_birth", "bank_account",
    "routing_number", "tax_id", "passport", "license_number",
    "phone", "mobile", "address", "salary", "income", "balance",
    "account_number", "pin", "otp", "mfa_secret", "auth_token",
    "refresh_token", "access_token", "session_id", "cookie",
    "admin", "is_admin", "role", "permissions", "acl",
    "email", "user_id", "uuid", "internal_id",
}

_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),             # SSN
    re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),         # Visa card
    re.compile(r"\b5[1-5][0-9]{14}\b"),                 # Mastercard
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),  # Email
    re.compile(r"\b\d{3}\s?\d{3}\s?\d{4}\b"),           # Phone
    re.compile(r'"password"\s*:\s*"[^"]+"', re.I),
    re.compile(r'(api_key|secret|token)\s*[:=]\s*["\']?\w{16,}', re.I),
]


# ── Finding model ─────────────────────────────────────────────────────────────

@dataclass
class DiffFinding:
    vuln_type: str          # IDOR | BAC | SENSITIVE_DATA_DISCLOSURE | UNAUTH_ACCESS
    title: str
    severity: str           # critical | high | medium | low
    url: str
    method: str
    evidence: str
    unauth_status: int
    auth_status: int
    confidence: float
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    tool: str = "differential_scanner"
    source_type: str = "differential"
    extra_fields: List[str] = field(default_factory=list)   # keys exposed without auth

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ── Scanner ───────────────────────────────────────────────────────────────────

class DifferentialScanner:
    """
    Compares authenticated vs unauthenticated responses to detect:
    - IDOR / Broken Object-Level Auth (BOLA)
    - Broken Function-Level Auth (BFLA)
    - Sensitive data disclosure to unauthenticated callers
    - Partial auth bypass (same data, different response size)
    """

    def __init__(
        self,
        target: str,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> None:
        self.target = target
        self.auth_headers = auth_headers or {}
        self.auth_cookies = auth_cookies or {}
        self.timeout = timeout
        self._tested: Set[str] = set()

    async def scan(
        self,
        endpoints: List[str],
        methods: Optional[List[str]] = None,
        concurrency: int = 5,
    ) -> List[DiffFinding]:
        """
        Scan a list of endpoints and return differential findings.

        Parameters
        ----------
        endpoints : list[str]
            Absolute URLs to test. Relative paths are resolved against self.target.
        methods : list[str], optional
            HTTP methods to test. Defaults to ["GET"].
        concurrency : int
            Max parallel requests.
        """
        methods = methods or ["GET"]
        sem = asyncio.Semaphore(concurrency)
        tasks = []
        for url in endpoints:
            if not url.startswith("http"):
                url = urljoin(self.target, url)
            for method in methods:
                key = f"{method}:{url}"
                if key not in self._tested:
                    self._tested.add(key)
                    tasks.append(self._diff_endpoint(url, method, sem))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[DiffFinding] = []
        for r in results:
            if isinstance(r, DiffFinding):
                findings.append(r)
            elif isinstance(r, list):
                findings.extend(r)
        return findings

    # ── Core diff logic ───────────────────────────────────────────────────────

    async def _diff_endpoint(
        self, url: str, method: str, sem: asyncio.Semaphore
    ) -> Optional[DiffFinding]:
        async with sem:
            try:
                import httpx
                async with httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=False,
                    # scan_verify() — False by default, True in STRICT_TLS mode
                    verify=_scan_verify(),
                ) as client:
                    # Unauthenticated request — bare, no cookies, no auth headers
                    unauth_resp = await client.request(method, url)
                    # Authenticated request
                    auth_resp = await client.request(
                        method, url,
                        headers=self.auth_headers,
                        cookies=self.auth_cookies,
                    )

                return self._analyze_pair(url, method, unauth_resp, auth_resp)

            except Exception as exc:
                log.debug("diff_endpoint %s %s failed: %s", method, url, exc)
                return None

    def _analyze_pair(
        self, url: str, method: str,
        unauth, auth
    ) -> Optional[DiffFinding]:
        """
        Compare an unauth/auth response pair and return a finding if suspicious.
        """
        unauth_status = unauth.status_code
        auth_status   = auth.status_code

        # ── Scenario 1: Both return 200 — potential IDOR / BAC ───────────────
        if unauth_status == 200 and auth_status == 200:
            return self._compare_200_pair(url, method, unauth, auth)

        # ── Scenario 2: Unauth returns data (200/206) but should require auth ─
        if unauth_status in (200, 206) and auth_status in (401, 403):
            # Auth system inverted — unauthenticated gets MORE than authenticated?
            # Unusual but happens with misconfigured middleware.
            return DiffFinding(
                vuln_type="UNAUTH_ACCESS",
                title=f"Endpoint returns data without authentication: {_short(url)}",
                severity="high",
                url=url,
                method=method,
                evidence=(
                    f"Unauthenticated status: {unauth_status} "
                    f"({len(unauth.content)} bytes)\n"
                    f"Authenticated status: {auth_status}\n"
                    "Endpoint serves data without credentials."
                ),
                unauth_status=unauth_status,
                auth_status=auth_status,
                confidence=0.80,
            )

        # ── Scenario 3: Unauth returns 200 but auth returns 200 with MORE data ─
        # Already handled in _compare_200_pair.

        # ── Scenario 4: Sensitive data in unauth 4xx body ────────────────────
        if unauth_status in (401, 403):
            pii = _find_pii(unauth.text)
            if pii:
                return DiffFinding(
                    vuln_type="SENSITIVE_DATA_DISCLOSURE",
                    title=f"PII/sensitive data in {unauth_status} response: {_short(url)}",
                    severity="medium",
                    url=url,
                    method=method,
                    evidence=f"PII found in {unauth_status} response body: {pii[:200]}",
                    unauth_status=unauth_status,
                    auth_status=auth_status,
                    confidence=0.70,
                )

        return None

    def _compare_200_pair(
        self, url: str, method: str, unauth, auth
    ) -> Optional[DiffFinding]:
        """
        Both responses are 200. Semantic diff to detect data leakage.
        """
        unauth_text = unauth.text
        auth_text   = auth.text
        unauth_size = len(unauth.content)
        auth_size   = len(auth.content)

        # ── PII in unauthenticated response ───────────────────────────────────
        pii = _find_pii(unauth_text)
        if pii:
            return DiffFinding(
                vuln_type="SENSITIVE_DATA_DISCLOSURE",
                title=f"PII exposed without authentication: {_short(url)}",
                severity="high",
                url=url,
                method=method,
                evidence=f"Matched PII patterns in unauthenticated response:\n{pii[:300]}",
                unauth_status=200,
                auth_status=200,
                confidence=0.85,
            )

        # ── JSON key differential ─────────────────────────────────────────────
        unauth_keys = _extract_json_keys(unauth_text)
        auth_keys   = _extract_json_keys(auth_text)

        if unauth_keys and auth_keys:
            # Keys present in auth but NOT in unauth — not a problem
            # Keys present in UNAUTH but NOT in auth — potential IDOR (more data without auth)
            extra_in_unauth = unauth_keys - auth_keys
            sensitive_unauth = extra_in_unauth & {k.lower() for k in _SENSITIVE_KEYS}

            # Keys in auth response are the baseline
            sensitive_in_unauth_baseline = {
                k for k in unauth_keys
                if k.lower() in _SENSITIVE_KEYS
            }

            if sensitive_in_unauth_baseline:
                return DiffFinding(
                    vuln_type="SENSITIVE_DATA_DISCLOSURE",
                    title=f"Sensitive JSON fields exposed without auth: {_short(url)}",
                    severity="high",
                    url=url,
                    method=method,
                    evidence=(
                        f"Sensitive fields in unauthenticated response: "
                        f"{sorted(sensitive_in_unauth_baseline)}\n"
                        f"Unauthenticated response size: {unauth_size} bytes"
                    ),
                    unauth_status=200,
                    auth_status=200,
                    confidence=0.80,
                    extra_fields=sorted(sensitive_in_unauth_baseline),
                )

            # Significantly more data without auth than with auth (size anomaly)
            if unauth_size > auth_size * 1.5 and unauth_size > 500:
                return DiffFinding(
                    vuln_type="IDOR",
                    title=f"Unauthenticated response significantly larger than authenticated: {_short(url)}",
                    severity="medium",
                    url=url,
                    method=method,
                    evidence=(
                        f"Unauth: {unauth_size} bytes | Auth: {auth_size} bytes\n"
                        f"Size ratio: {unauth_size/max(auth_size,1):.1f}x\n"
                        f"Extra keys (unauth only): {sorted(extra_in_unauth)[:10]}"
                    ),
                    unauth_status=200,
                    auth_status=200,
                    confidence=0.60,
                    extra_fields=sorted(extra_in_unauth)[:10],
                )

        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_json_keys(text: str) -> Set[str]:
    """Flatten all string keys from a JSON response."""
    try:
        data = json.loads(text)
    except Exception:
        return set()

    keys: Set[str] = set()

    def _recurse(obj: Any, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.add(str(k).lower())
                _recurse(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:5]:  # limit list expansion
                _recurse(item, depth + 1)

    _recurse(data)
    return keys


def _find_pii(text: str) -> str:
    """Return first PII match found in text, or empty string."""
    for pat in _PII_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return ""


def _short(url: str, max_len: int = 60) -> str:
    return url if len(url) <= max_len else url[:max_len] + "…"


def _scan_verify() -> bool:
    """Return TLS verify flag for scan clients."""
    import os
    return os.environ.get("ONEINFINITY_STRICT_TLS", "").strip() in ("1", "true", "yes")


# ── Convenience builder ───────────────────────────────────────────────────────

def build_scanner(
    target: str,
    auth_context=None,
    timeout: int = 10,
) -> DifferentialScanner:
    """
    Build a DifferentialScanner from an AuthSessionContext or raw headers/cookies.

    Parameters
    ----------
    auth_context : AuthSessionContext | dict | None
        If AuthSessionContext, extracts headers and cookies automatically.
        If dict, used directly as headers.
    """
    if auth_context is None:
        return DifferentialScanner(target, timeout=timeout)

    if hasattr(auth_context, "headers") and hasattr(auth_context, "cookies"):
        return DifferentialScanner(
            target,
            auth_headers=dict(auth_context.headers or {}),
            auth_cookies=dict(auth_context.cookies or {}),
            timeout=timeout,
        )

    if isinstance(auth_context, dict):
        return DifferentialScanner(target, auth_headers=auth_context, timeout=timeout)

    return DifferentialScanner(target, timeout=timeout)
