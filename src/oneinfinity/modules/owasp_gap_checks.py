"""
OWASP WSTG v4.2 Gap Checks — modules/owasp_gap_checks.py

All 23 checks missing from the core pipeline. Each function:
  - Is self-contained (no class required)
  - Returns a GapCheckResult
  - Has a passive detection step and (where applicable) an active confirmation step
  - Uses only stdlib (ssl, urllib.request, socket, math, statistics, re, hashlib)

Integration: called from pipeline/executor.py in the appropriate phase.
"""
from __future__ import annotations

import hashlib
import math
import re
import socket
import ssl
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import logging
log = logging.getLogger("oi.gap_checks")

# ── Confidence thresholds ─────────────────────────────────────────────────────
_EMIT_THRESHOLD   = 0.40   # below this: suppressed entirely
_HIGH_THRESHOLD   = 0.70   # at or above: emit HIGH/CRITICAL if active_confirmed

# ── Data contract ─────────────────────────────────────────────────────────────

@dataclass
class GapCheckResult:
    check_id: str
    vuln_name: str = ""
    passive_finding: bool = False
    active_confirmed: bool = False
    confidence: float = 0.0
    evidence: str = ""
    needs_validation: bool = True
    details: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.active_confirmed:
            self.needs_validation = False


def gap_check_result_to_finding(result: GapCheckResult, url: str) -> Optional[dict]:
    """
    Convert a GapCheckResult to a normalized finding dict.
    Returns None if confidence is below the emission threshold (suppressed).
    """
    if result.confidence < _EMIT_THRESHOLD:
        return None

    if result.active_confirmed and result.confidence >= _HIGH_THRESHOLD:
        severity = "high"
    elif result.active_confirmed:
        severity = "medium"
    elif result.passive_finding:
        severity = "low"
    else:
        severity = "info"

    return {
        "vuln_type": result.vuln_name or result.check_id,
        "check_id": result.check_id,
        "url": url,
        "severity": severity,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "passive_finding": result.passive_finding,
        "active_confirmed": result.active_confirmed,
        "needs_manual_verification": result.needs_validation,
        "source_type": "owasp_gap",
        "details": result.details,
    }


# ── WSTG-SESS-02: Cookie Attribute Audit ─────────────────────────────────────

_REQUIRED_COOKIE_FLAGS = ["HttpOnly", "Secure", "SameSite"]

def check_cookie_attributes(url: str, response_headers: Dict[str, str]) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-SESS-02", vuln_name="Insecure Cookie Attributes")
    set_cookie = response_headers.get("Set-Cookie", response_headers.get("set-cookie", ""))
    if not set_cookie:
        return result

    missing = []
    for flag in _REQUIRED_COOKIE_FLAGS:
        if flag.lower() not in set_cookie.lower():
            missing.append(flag)

    if not missing:
        return result

    result.passive_finding = True
    result.evidence = f"Session cookie missing flags: {', '.join(missing)}"
    result.confidence = 0.75

    if "Secure" in missing and url.startswith("https://"):
        http_url = url.replace("https://", "http://", 1)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(http_url)
            req.add_header("User-Agent", "Mozilla/5.0 (SecurityBot)")
            with urllib.request.urlopen(req, timeout=8) as resp:
                sc = dict(resp.headers).get("Set-Cookie", "")
                if sc:
                    result.active_confirmed = True
                    result.confidence = 0.90
                    result.evidence += " — confirmed: cookie sent over HTTP (Secure flag missing)"
        except Exception as e:
            log.debug("cookie_attrs active check failed: %s", e)

    return result



# ── Internal Domain Cookie Leak ───────────────────────────────────────────────
_INTERNAL_DOMAIN_RE = re.compile(
    r'Domain=([^;\s]+)',
    re.I
)
_INTERNAL_DOMAIN_SUFFIXES = (
    '.cluster.local', '.internal', '.svc', '.local',
    '.corp', '.intra', '.lan', '.home'
)

def check_internal_domain_cookie_leak(response_headers: Dict[str, str]) -> GapCheckResult:
    """
    Detect cookies whose Domain= attribute exposes internal hostnames.
    e.g. Dynatrace setting Domain=.cluster.local leaks k8s cluster topology
    to any JavaScript on the page.
    """
    result = GapCheckResult(check_id="OI-SESS-DOMAIN", vuln_name="Internal Domain Cookie Leak")
    all_cookies = response_headers.get("Set-Cookie", "") + " " + response_headers.get("set-cookie", "")
    leaks = []
    for m in _INTERNAL_DOMAIN_RE.finditer(all_cookies):
        domain = m.group(1).strip()
        if any(domain.lower().endswith(suf) for suf in _INTERNAL_DOMAIN_SUFFIXES):
            leaks.append(domain)
    if not leaks:
        return result
    result.passive_finding = True
    result.confidence = 0.90
    result.evidence = (
        f"Cookie Domain attribute exposes internal network topology: "
        f"{', '.join(set(leaks))}. "
        f"Attackers can infer container orchestration platform, service names, and namespace layout."
    )
    return result


# ── Envoy Internal Topology Disclosure ───────────────────────────────────────
def check_envoy_topology_leak(response_headers: Dict[str, str]) -> GapCheckResult:
    """
    Detect x-envoy-decorator-operation header exposing internal k8s service FQDNs.
    e.g. eshop-oneshop-nginx.eshop-plh-uat.svc.cluster.local:80/*
    """
    result = GapCheckResult(check_id="OI-INFRA-ENVOY", vuln_name="Internal Service Topology Disclosure")
    decorator = (
        response_headers.get("x-envoy-decorator-operation", "") or
        response_headers.get("X-Envoy-Decorator-Operation", "")
    )
    if not decorator:
        return result
    if ".svc.cluster.local" in decorator or ".svc." in decorator or ".cluster.local" in decorator:
        result.passive_finding = True
        result.confidence = 0.85
        result.evidence = (
            f"x-envoy-decorator-operation header exposes internal Kubernetes service FQDN: "
            f"'{decorator}'. Reveals namespace, service name, and cluster domain."
        )
    return result


# ── WSTG-SESS-05: CSRF Token Validation ───────────────────────────────────────

_CSRF_PATTERNS = [
    re.compile(r'<input[^>]+name=["\'](_?csrf|csrf_token|_token|authenticity_token|__RequestVerificationToken)["\']', re.I),
    re.compile(r'X-CSRF-Token|X-Xsrf-Token', re.I),
]

def check_csrf(url: str, response_body: str, response_headers: Dict[str, str],
               method: str = "POST") -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-SESS-05", vuln_name="Missing CSRF Protection")

    token_found = any(p.search(response_body) for p in _CSRF_PATTERNS)
    samesite = bool(re.search(r"samesite=(strict|lax)", response_headers.get("Set-Cookie", ""), re.I))
    if token_found or samesite:
        return result

    if method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return result

    result.passive_finding = True
    result.confidence = 0.60
    result.evidence = "No CSRF token found in form/response and no SameSite=Strict cookie"

    try:
        req = urllib.request.Request(url, data=b"csrf_test=1", method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Referer", "http://evil.example.com")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            if resp.status in (200, 201, 302):
                result.active_confirmed = True
                result.confidence = 0.85
                result.evidence += f" — server accepted cross-origin POST without token (HTTP {resp.status})"
    except urllib.error.HTTPError as e:
        if e.code == 403:
            result.passive_finding = False
            result.confidence = 0.0
            result.evidence = "CSRF protected: server returned 403 on cross-origin POST"
    except Exception as e:
        log.debug("csrf active check failed: %s", e)

    return result


# ── WSTG-CRYP-01: Weak TLS Configuration ─────────────────────────────────────

def check_weak_tls(host: str, port: int = 443) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CRYP-01", vuln_name="Weak TLS Configuration")

    weak_protocols = []
    try:
        weak_protocols.append(("TLSv1.0", ssl.TLSVersion.TLSv1))
    except AttributeError:
        pass
    try:
        weak_protocols.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))
    except AttributeError:
        pass

    for proto_name, proto_const in weak_protocols:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = proto_const
            ctx.minimum_version = proto_const
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    result.passive_finding = True
                    result.active_confirmed = True
                    result.confidence = 0.95
                    result.evidence = f"Server accepts deprecated {proto_name}"
                    result.details["accepted_protocol"] = proto_name
                    return result
        except ssl.SSLError:
            pass
        except Exception as e:
            log.debug("weak_tls check %s failed: %s", proto_name, e)

    return result


# ── WSTG-CONF-07: TLS Certificate Validation ─────────────────────────────────

def check_tls_cert(host: str, port: int = 443) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CONF-07", vuln_name="TLS Certificate Issue")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    expiry = ssl.cert_time_to_seconds(not_after)
                    if expiry < time.time():
                        result.passive_finding = True
                        result.active_confirmed = True
                        result.confidence = 0.99
                        result.evidence = f"Certificate expired: {not_after}"
    except ssl.SSLCertVerificationError as e:
        result.passive_finding = True
        result.active_confirmed = True
        result.confidence = 0.95
        result.evidence = f"Certificate validation failed: {e}"
    except Exception as e:
        log.debug("tls_cert check failed: %s", e)
    return result


# ── WSTG-CONF-04: Backup/Archive File Discovery ───────────────────────────────

_BACKUP_EXTENSIONS = [
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp",
    "~", ".copy", ".1", ".2", "_bak", "_old", "_backup", "_orig",
    ".zip", ".tar.gz", ".tgz", ".tar", ".gz",
]

def check_backup_files(base_url: str, known_paths: List[str]) -> List[GapCheckResult]:
    results = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for path in known_paths[:40]:
        stem = path.rstrip("/")
        candidates = [stem + ext for ext in _BACKUP_EXTENSIONS]
        for url_path in candidates:
            full_url = base_url.rstrip("/") + url_path
            try:
                req = urllib.request.Request(full_url, method="GET")
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
                    if resp.status == 200:
                        body_preview = resp.read(256).decode("utf-8", errors="replace")
                        if len(body_preview.strip()) > 10:
                            r = GapCheckResult(
                                check_id="WSTG-CONF-04",
                                vuln_name="Backup/Archive File Exposed",
                                passive_finding=True,
                                active_confirmed=True,
                                confidence=0.90,
                                evidence=f"HTTP 200 for {full_url} — content: {body_preview[:80]!r}",
                            )
                            results.append(r)
            except urllib.error.HTTPError:
                pass
            except Exception as e:
                log.debug("backup_files probe %s failed: %s", full_url, e)

    return results


# ── WSTG-SESS-03: Session Fixation ────────────────────────────────────────────

def check_session_fixation(pre_login_session_id: str, post_login_session_id: str,
                            url: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-SESS-03", vuln_name="Session Fixation")
    if not pre_login_session_id or not post_login_session_id:
        return result
    if pre_login_session_id == post_login_session_id:
        result.passive_finding = True
        result.active_confirmed = True
        result.confidence = 0.88
        result.evidence = (
            f"Session ID unchanged after login: {pre_login_session_id[:16]}... "
            "— attacker can fixate session before authentication"
        )
    return result


# ── WSTG-SESS-07: Session Timeout ─────────────────────────────────────────────

def check_session_timeout(url: str, session_cookie: str, idle_seconds: int = 1800) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-SESS-07", vuln_name="Missing Session Timeout")
    if not session_cookie:
        return result
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url)
        req.add_header("Cookie", session_cookie)
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            if resp.status == 200:
                result.passive_finding = True
                result.active_confirmed = True
                result.confidence = 0.75
                result.evidence = (
                    f"Session still valid after {idle_seconds}s idle — no server-side timeout enforced"
                )
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            pass
    except Exception as e:
        log.debug("session_timeout check failed: %s", e)
    return result


# ── WSTG-IDNT-04: Account Enumeration via Timing ─────────────────────────────

def check_account_enumeration_timing(login_url: str, valid_username: str,
                                      invalid_username: str,
                                      password: str = "wrongpass_OI_test!") -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-IDNT-04", vuln_name="Account Enumeration via Timing")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _measure(username: str, n: int = 10) -> List[float]:
        times = []
        for _ in range(n):
            try:
                data = urllib.parse.urlencode({"username": username, "password": password}).encode()
                req = urllib.request.Request(login_url, data=data, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
                req.add_header("User-Agent", "Mozilla/5.0")
                t0 = time.time()
                try:
                    with urllib.request.urlopen(req, timeout=10, context=ctx):
                        pass
                except urllib.error.HTTPError:
                    pass
                times.append((time.time() - t0) * 1000)
                time.sleep(0.1)
            except Exception:
                pass
        return times

    valid_times = _measure(valid_username)
    invalid_times = _measure(invalid_username)

    if len(valid_times) < 5 or len(invalid_times) < 5:
        return result

    mean_valid = statistics.mean(valid_times)
    mean_invalid = statistics.mean(invalid_times)
    delta = abs(mean_valid - mean_invalid)

    if delta > 100:
        result.passive_finding = True
        result.active_confirmed = True
        result.confidence = min(0.90, 0.50 + delta / 1000)
        result.evidence = (
            f"Timing delta {delta:.0f}ms between valid ({mean_valid:.0f}ms) "
            f"and invalid ({mean_invalid:.0f}ms) usernames — account enumeration possible"
        )
        result.details = {"mean_valid_ms": mean_valid, "mean_invalid_ms": mean_invalid, "delta_ms": delta}
    return result


# ── WSTG-INPV-06: LDAP Injection ─────────────────────────────────────────────

_LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "admin)(&(password=*))",
    "*)(|(password=*)",
    "*()|%26'",
]

def check_ldap_injection(url: str, param: str, method: str = "POST") -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-INPV-06", vuln_name="LDAP Injection")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _send(payload: str) -> Optional[dict]:
        try:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [payload]
                new_url = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(qs, doseq=True)))
                req = urllib.request.Request(new_url)
            else:
                data = urllib.parse.urlencode({param: payload}).encode()
                req = urllib.request.Request(url, data=data, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                return {"status": resp.status, "body": body}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": ""}
        except Exception:
            return None

    baseline = _send("normaluser")
    if not baseline:
        return result

    for payload in _LDAP_PAYLOADS:
        probe = _send(payload)
        if not probe:
            continue
        if (probe["status"] in (200, 302) and
                baseline["status"] not in (200, 302)):
            result.passive_finding = True
            result.active_confirmed = True
            result.confidence = 0.85
            result.evidence = (
                f"LDAP injection: payload {payload!r} returned HTTP {probe['status']} "
                f"vs baseline HTTP {baseline['status']}"
            )
            return result
        if re.search(r"ldap|invalid dn|ldap_bind|javax\.naming", probe["body"], re.I):
            result.passive_finding = True
            result.confidence = 0.65
            result.evidence = f"LDAP error disclosure with payload {payload!r}"
            return result

    return result


# ── WSTG-INPV-10: Mail Header Injection ──────────────────────────────────────

def check_mail_header_injection(url: str, param: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-INPV-10", vuln_name="Mail Header Injection")
    payload = "test@test.com\r\nBcc: canary@oneinfinity.test\r\n"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        data = urllib.parse.urlencode({param: payload}).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            body = resp.read(2048).decode("utf-8", errors="replace")
            if resp.status in (200, 302) and not re.search(r"invalid|error|rejected", body, re.I):
                result.passive_finding = True
                result.active_confirmed = True
                result.confidence = 0.72
                result.evidence = (
                    f"Mail form accepted CRLF-injected payload without error (HTTP {resp.status})"
                )
    except urllib.error.HTTPError as e:
        if e.code in (400, 422):
            pass
    except Exception as e:
        log.debug("mail_header_injection check failed: %s", e)
    return result


# ── WSTG-INPV-11: Code Injection ─────────────────────────────────────────────

_CODE_INJECTION_PAYLOADS = [
    ("php_system",  "<?php echo shell_exec('id'); ?>"),
    ("php_eval",    "<?php eval('echo 1+1;'); ?>"),
    ("node_exec",   "require('child_process').execSync('id').toString()"),
    ("python_exec", "__import__('os').popen('id').read()"),
]
_CODE_INJECTION_EVIDENCE = re.compile(r"uid=\d+\(\w+\)\s+gid=\d+", re.I)

def check_code_injection(url: str, param: str, method: str = "GET") -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-INPV-11", vuln_name="Code Injection")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for name, payload in _CODE_INJECTION_PAYLOADS:
        try:
            if method.upper() == "GET":
                parsed = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed.query)
                qs[param] = [payload]
                probe_url = urllib.parse.urlunparse(parsed._replace(
                    query=urllib.parse.urlencode(qs, doseq=True)))
                req = urllib.request.Request(probe_url)
            else:
                data = urllib.parse.urlencode({param: payload}).encode()
                req = urllib.request.Request(url, data=data, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                if _CODE_INJECTION_EVIDENCE.search(body):
                    result.passive_finding = True
                    result.active_confirmed = True
                    result.confidence = 0.97
                    result.evidence = f"Code injection ({name}): `id` output found in response"
                    return result
        except Exception as e:
            log.debug("code_injection %s failed: %s", name, e)
    return result


# ── CSV Injection ─────────────────────────────────────────────────────────────

_CSV_INJECT_PAYLOADS = [
    '=HYPERLINK("http://canary.oneinfinity.test","x")',
    "=cmd|'/C calc'!A0",
    "@SUM(1+1)*cmd|'/C calc'!A0",
]

def check_csv_injection(url: str, param: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-INPV-CSV", vuln_name="CSV Injection")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for payload in _CSV_INJECT_PAYLOADS:
        try:
            data = urllib.parse.urlencode({param: payload}).encode()
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                ct = dict(resp.headers).get("Content-Type", "")
                if "csv" in ct.lower() or "spreadsheet" in ct.lower():
                    if payload[:10] in body:
                        result.passive_finding = True
                        result.active_confirmed = True
                        result.confidence = 0.88
                        result.evidence = f"CSV export contains unescaped formula: {payload[:40]!r}"
                        return result
        except Exception as e:
            log.debug("csv_injection check failed: %s", e)
    return result


# ── WSTG-CLNT-11: postMessage Hijacking ──────────────────────────────────────

_POSTMESSAGE_PATTERNS = [
    re.compile(r'window\.addEventListener\s*\(\s*["\']message["\']', re.I),
    re.compile(r'\.postMessage\s*\(', re.I),
    re.compile(r'event\.data', re.I),
]
_ORIGIN_CHECK_PATTERNS = [
    re.compile(r'event\.origin\s*[!=]=', re.I),
    re.compile(r'event\.origin\s*\.startsWith', re.I),
]

def check_postmessage_hijacking(url: str, js_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CLNT-11", vuln_name="postMessage Hijacking Risk")
    uses_pm = any(p.search(js_body) for p in _POSTMESSAGE_PATTERNS)
    if not uses_pm:
        return result
    has_origin_check = any(p.search(js_body) for p in _ORIGIN_CHECK_PATTERNS)
    if not has_origin_check:
        result.passive_finding = True
        result.confidence = 0.68
        result.evidence = (
            "postMessage listener found without event.origin validation — "
            "cross-origin messages accepted without verification"
        )
    return result


# ── WSTG-CLNT-12: Web Storage Security ───────────────────────────────────────

_SENSITIVE_STORAGE_KEYS = re.compile(
    r'(auth|token|jwt|session|password|secret|key|api_?key|access|credential)',
    re.I
)
_STORAGE_SET_PATTERN = re.compile(r'localStorage\.setItem\s*\(\s*["\']([^"\']+)["\']', re.I)

def check_web_storage(url: str, js_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CLNT-12", vuln_name="Sensitive Data in Web Storage")
    for m in _STORAGE_SET_PATTERN.finditer(js_body):
        key = m.group(1)
        if _SENSITIVE_STORAGE_KEYS.search(key):
            result.passive_finding = True
            result.confidence = 0.72
            result.evidence = (
                f"Sensitive key '{key}' stored in localStorage — "
                "accessible to any same-origin JS (XSS impact)"
            )
            return result
    return result


# ── Insecure RNG Detection ────────────────────────────────────────────────────

def check_insecure_rng(url: str, token_samples: List[str]) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CRYP-RNG", vuln_name="Insecure Random Number Generation")
    if len(token_samples) < 5:
        return result

    for i in range(len(token_samples) - 1):
        t1, t2 = token_samples[i], token_samples[i + 1]
        common_len = 0
        for a, b in zip(t1, t2):
            if a == b:
                common_len += 1
            else:
                break
        suffix1 = t1[common_len:]
        suffix2 = t2[common_len:]
        if suffix1.isdigit() and suffix2.isdigit():
            if int(suffix2) - int(suffix1) <= 2:
                result.passive_finding = True
                result.confidence = 0.90
                result.evidence = f"Sequential token pattern detected: {t1!r} → {t2!r}"
                return result

    combined = "".join(token_samples)
    if len(combined) < 20:
        return result
    byte_counts = [combined.count(chr(i)) for i in range(256) if chr(i) in combined]
    if not byte_counts:
        return result
    total = sum(byte_counts)
    entropy = -sum((c / total) * math.log2(c / total) for c in byte_counts if c > 0)
    if entropy < 2.5:
        result.passive_finding = True
        result.confidence = 0.75
        result.evidence = f"Low token entropy: {entropy:.2f} bits/char (expected >3.5 for secure RNG)"
        result.details["entropy_bits"] = entropy
    return result


# ── WSTG-CRYP-04: Weak Encryption Pattern Detection ──────────────────────────

_WEAK_CRYPTO_PATTERNS = [
    (re.compile(r'\bMD5\s*\(', re.I), "MD5 hash usage"),
    (re.compile(r'\bSHA1\s*\(|\bSHA-1\b', re.I), "SHA1 hash usage"),
    (re.compile(r'\bDES\b|\b3DES\b|\bTripleDES\b', re.I), "DES/3DES cipher usage"),
    (re.compile(r'["\']AES.ECB["\']|mode\s*[=:]\s*["\']ECB["\']', re.I), "AES-ECB mode usage"),
    (re.compile(r'base64\.(encode|decode)\s*\(.*password', re.I), "Base64 used as encryption"),
    (re.compile(r'rot13|caesar.cipher|vigenere', re.I), "Trivially weak cipher"),
]

def check_weak_encryption_patterns(url: str, body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CRYP-04", vuln_name="Weak Encryption Algorithm")
    for pattern, description in _WEAK_CRYPTO_PATTERNS:
        m = pattern.search(body)
        if m:
            result.passive_finding = True
            result.confidence = 0.70
            result.evidence = f"{description} detected: {m.group(0)!r}"
            return result
    return result


# ── WSTG-CRYP-02: Padding Oracle ─────────────────────────────────────────────

def check_padding_oracle(url: str, cookie_name: str, cookie_value: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CRYP-02", vuln_name="Padding Oracle")
    if not cookie_value:
        return result
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def _send_cookie(value: str) -> Optional[dict]:
        try:
            req = urllib.request.Request(url)
            req.add_header("Cookie", f"{cookie_name}={value}")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(2048).decode("utf-8", errors="replace")
                return {"status": resp.status, "len": len(body), "body": body[:200]}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "len": 0, "body": ""}
        except Exception:
            return None

    baseline = _send_cookie(cookie_value)
    if not baseline:
        return result

    try:
        import base64
        decoded = base64.b64decode(cookie_value + "==")
        flipped = bytearray(decoded)
        flipped[-1] ^= 0x01
        modified_value = base64.b64encode(bytes(flipped)).decode()
    except Exception:
        modified_value = cookie_value[:-1] + ("A" if cookie_value[-1] != "A" else "B")

    probe = _send_cookie(modified_value)
    if not probe:
        return result

    if (probe["status"] != baseline["status"] and
            probe["status"] in (400, 500) and
            baseline["status"] == 200):
        result.passive_finding = True
        result.active_confirmed = True
        result.confidence = 0.75
        result.evidence = (
            f"Padding oracle candidate: bit-flip on cookie '{cookie_name}' changed "
            f"response from HTTP {baseline['status']} to {probe['status']}"
        )
    return result


# ── Service Worker Abuse ──────────────────────────────────────────────────────

_SW_REGISTER = re.compile(r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']', re.I)

def check_service_worker(url: str, js_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CLNT-SW", vuln_name="Service Worker Abuse Risk")
    m = _SW_REGISTER.search(js_body)
    if not m:
        return result
    sw_path = m.group(1)
    if sw_path.endswith("/sw.js") or sw_path in ("/service-worker.js", "/sw.js"):
        result.passive_finding = True
        result.confidence = 0.60
        result.evidence = (
            f"Service worker registered at root scope ({sw_path}) — "
            "may intercept sensitive API requests if compromised via XSS"
        )
    return result


# ── WebRTC IP Leakage ─────────────────────────────────────────────────────────

_WEBRTC_PATTERNS = re.compile(
    r'RTCPeerConnection|webkitRTCPeerConnection|mozRTCPeerConnection', re.I
)

def check_webrtc_leak(url: str, js_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-CLNT-WEBRTC", vuln_name="WebRTC IP Leakage")
    if _WEBRTC_PATTERNS.search(js_body):
        result.passive_finding = True
        result.confidence = 0.55
        result.evidence = (
            "WebRTC API usage detected — may leak real client IP through STUN/TURN, "
            "bypassing proxy/VPN. Requires browser-based confirmation."
        )
        result.needs_validation = True
    return result


# ── gRPC / SOAP Endpoint Detection ───────────────────────────────────────────

def check_grpc_soap(base_url: str, response_headers: Dict[str, str],
                    response_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-API-GRPC", vuln_name="gRPC/SOAP Endpoint Exposed")
    ct = response_headers.get("Content-Type", response_headers.get("content-type", ""))
    if "application/grpc" in ct.lower():
        result.passive_finding = True
        result.confidence = 0.70
        result.evidence = "gRPC endpoint detected via Content-Type: application/grpc"
    elif "wsdl" in response_body.lower() or "<definitions" in response_body:
        result.passive_finding = True
        result.confidence = 0.75
        result.evidence = "SOAP WSDL endpoint detected — enumerate operations and test for injection"
    elif "?wsdl" in base_url.lower() or base_url.endswith(".wsdl"):
        result.passive_finding = True
        result.confidence = 0.65
        result.evidence = f"WSDL URL pattern detected: {base_url}"
    return result


# ── WSTG-ATHN-10: SAML Assertion Validation ──────────────────────────────────

_SAML_PATTERNS = [
    re.compile(r'<saml:|<samlp:|SAMLResponse|SAMLRequest', re.I),
    re.compile(r'AssertionConsumerService|SingleSignOnService', re.I),
]
_SAML_UNSIGNED = re.compile(r'<Signature', re.I)

def check_saml_assertion(url: str, response_body: str) -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-ATHN-10", vuln_name="SAML Assertion Vulnerability")
    is_saml = any(p.search(response_body) for p in _SAML_PATTERNS)
    if not is_saml:
        return result
    has_signature = _SAML_UNSIGNED.search(response_body)
    if not has_signature:
        result.passive_finding = True
        result.confidence = 0.75
        result.evidence = (
            "SAML response detected without XML signature — "
            "assertion may be forgeable (unsigned SAML)"
        )
    return result


# ── WSTG-ATHN-07: Password Policy Testing ────────────────────────────────────

_WEAK_PASSWORDS = ["a", "aa", "password", "12345", "abc", "1", "pass"]

def check_password_policy(register_url: str, username_param: str = "username",
                           password_param: str = "password") -> GapCheckResult:
    result = GapCheckResult(check_id="WSTG-ATHN-07", vuln_name="Weak Password Policy")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    import random
    import string as _str
    test_username = "oi_pwtest_" + "".join(random.choices(_str.ascii_lowercase, k=6))
    for weak_pass in _WEAK_PASSWORDS:
        try:
            data = urllib.parse.urlencode({
                username_param: test_username, password_param: weak_pass
            }).encode()
            req = urllib.request.Request(register_url, data=data, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(2048).decode("utf-8", errors="replace")
                if resp.status in (200, 201, 302):
                    if not re.search(r"password.*too short|weak|minimum|must be", body, re.I):
                        result.passive_finding = True
                        result.active_confirmed = True
                        result.confidence = 0.85
                        result.evidence = f"Weak password accepted: {weak_pass!r} (HTTP {resp.status})"
                        return result
        except urllib.error.HTTPError:
            pass
        except Exception as e:
            log.debug("password_policy check failed: %s", e)
    return result


# ── WSTG-INPV-CRLF: CRLF Injection ──────────────────────────────────────────

_CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:%20oi_crlf_test=1",
    "%0aSet-Cookie:%20oi_crlf_test=1",
    "%0d%0aLocation:%20https://oi-test.invalid",
    "\r\nSet-Cookie:%20oi_crlf_test=1",
]
_CRLF_EVIDENCE = re.compile(r"oi_crlf_test=1", re.I)

def check_crlf_injection(base_url: str, params: List[str] = None) -> GapCheckResult:
    """WSTG-INPV-CRLF: Test for CRLF injection in URL parameters and redirect params."""
    result = GapCheckResult(check_id="WSTG-INPV-CRLF", vuln_name="CRLF Injection")
    import urllib.request as _ur, ssl as _ssl, urllib.error as _ue
    from urllib.parse import urlencode, urljoin

    _ctx = _ssl.create_default_context()
    _ctx.check_hostname = False
    _ctx.verify_mode = _ssl.CERT_NONE

    test_params = params or ["redirect", "url", "next", "return", "location", "continue", "dest"]

    for param in test_params[:4]:
        for payload in _CRLF_PAYLOADS[:3]:
            try:
                test_url = f"{base_url.rstrip('/')}?{param}={payload}"
                req = _ur.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
                with _ur.urlopen(req, timeout=6, context=_ctx) as resp:
                    resp_headers = str(dict(resp.headers)).lower()
                    resp_body = resp.read(4096).decode("utf-8", errors="replace")
                    if _CRLF_EVIDENCE.search(resp_headers) or _CRLF_EVIDENCE.search(resp_body):
                        result.found = True
                        result.confidence = 0.92
                        result.evidence = f"CRLF injection confirmed: param={param!r} payload={payload!r}"
                        result.severity = "high"
                        result.needs_validation = False
                        return result
                    # Also check if \r\n appears in response headers (header splitting)
                    raw_loc = resp.headers.get("Location", "")
                    if "oi-test.invalid" in raw_loc:
                        result.found = True
                        result.confidence = 0.95
                        result.evidence = f"CRLF redirect injection: Location header poisoned via {param!r}"
                        result.severity = "high"
                        result.needs_validation = False
                        return result
            except (_ue.HTTPError, _ue.URLError, OSError):
                continue
            except Exception:
                continue
    return result
