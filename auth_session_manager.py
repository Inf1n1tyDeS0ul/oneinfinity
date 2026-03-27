"""
auth_session_manager.py — Authentication & Session Management Engine for OneInfinity

Manages multi-role authenticated sessions and provides utilities for:
  - Building pre-authenticated requests.Session objects
  - Probing targets for login endpoints
  - Attempting login with provided credentials
  - Comparing responses across multiple role sessions (IDOR / access-control testing)
  - Injecting session state into scanner kwargs

Usage::

    mgr = AuthSessionManager(
        target="https://example.com",
        cookies={"session": "abc123"},
        headers={"Authorization": "Bearer token"},
    )
    session = mgr.get_session()
    resp = session.get("https://example.com/api/profile")

    mgr.add_role("admin", token="admin-jwt-token")
    mgr.add_role("user", cookies={"session": "user-session-id"})
    diff = mgr.compare_responses("https://example.com/api/admin/users")
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("oi.auth_session_manager")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/auth/login",
    "/api/login",
    "/api/auth",
    "/api/signin",
    "/api/v1/login",
    "/api/v1/auth",
    "/user/login",
    "/account/login",
    "/auth",
    "/admin/login",
    "/wp-login.php",
    "/auth/token",
    "/oauth/token",
    "/session",
]

_SUCCESS_INDICATORS = (
    "token",
    "access_token",
    "session",
    "jwt",
    "auth",
    "dashboard",
    "welcome",
    "success",
    "logged_in",
    "logged-in",
)

_DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_session(
    cookies: Optional[dict],
    headers: Optional[dict],
    token: Optional[str],
) -> requests.Session:
    """Create and configure a requests.Session with the given credentials."""
    sess = requests.Session()
    sess.verify = False
    if cookies:
        sess.cookies.update(cookies)
    merged_headers = {
        "User-Agent": "OneInfinity-AuthManager/1.0",
        "Accept": "application/json, text/html, */*",
    }
    if headers:
        merged_headers.update(headers)
    if token:
        # Support "Bearer <token>" or raw token; detect by presence of space
        if " " in token:
            merged_headers["Authorization"] = token
        else:
            merged_headers["Authorization"] = f"Bearer {token}"
    sess.headers.update(merged_headers)
    return sess


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class AuthSessionManager:
    """
    Session and authentication management engine.

    Parameters
    ----------
    target : str
        Base URL of the target application.
    cookies : dict | None
        Session cookies to attach to the default session.
    headers : dict | None
        Custom HTTP headers (e.g. API key headers) for the default session.
    token : str | None
        Bearer / JWT token to attach as an Authorization header.
    """

    def __init__(
        self,
        target: str,
        cookies: Optional[dict] = None,
        headers: Optional[dict] = None,
        token: Optional[str] = None,
    ) -> None:
        self.target = target.rstrip("/")
        self._default_cookies = cookies or {}
        self._default_headers = headers or {}
        self._default_token = token
        # Named role sessions: role_name -> requests.Session
        self._role_sessions: Dict[str, requests.Session] = {}

    # ------------------------------------------------------------------ #
    # Session access
    # ------------------------------------------------------------------ #

    def get_session(self) -> requests.Session:
        """
        Return a pre-configured requests.Session for the default (primary) identity.

        A fresh session is built on every call so callers can safely mutate it.
        """
        return _build_session(
            cookies=self._default_cookies,
            headers=self._default_headers,
            token=self._default_token,
        )

    def add_role(
        self,
        role_name: str,
        cookies: Optional[dict] = None,
        headers: Optional[dict] = None,
        token: Optional[str] = None,
    ) -> None:
        """
        Register a named session for a specific role (e.g. "admin", "user", "guest").

        Parameters
        ----------
        role_name : str
            Logical role label.
        cookies : dict | None
            Session cookies for this role.
        headers : dict | None
            Custom request headers for this role.
        token : str | None
            Bearer token for this role.
        """
        self._role_sessions[role_name] = _build_session(
            cookies=cookies, headers=headers, token=token
        )
        log.info("Role '%s' registered", role_name)

    def get_role_session(self, role_name: str) -> requests.Session:
        """
        Return the requests.Session for a named role.

        Raises
        ------
        KeyError
            If *role_name* was not previously registered via :meth:`add_role`.
        """
        if role_name not in self._role_sessions:
            raise KeyError(f"Role '{role_name}' not registered. Call add_role() first.")
        return self._role_sessions[role_name]

    # ------------------------------------------------------------------ #
    # Login endpoint detection
    # ------------------------------------------------------------------ #

    def detect_login_form(self) -> Optional[str]:
        """
        Probe the target for common login endpoint paths.

        Returns the first URL that returned a 200/401/403 status, or None
        if no login endpoint was found.
        """
        probe_session = requests.Session()
        probe_session.verify = False
        probe_session.headers["User-Agent"] = "OneInfinity-AuthManager/1.0"

        for path in _LOGIN_PATHS:
            url = urljoin(self.target + "/", path.lstrip("/"))
            try:
                resp = probe_session.get(url, timeout=_DEFAULT_TIMEOUT, allow_redirects=True)
                if resp.status_code in (200, 401, 403):
                    log.info("Login endpoint candidate: %s (HTTP %d)", url, resp.status_code)
                    return url
            except requests.RequestException as exc:
                log.debug("Login probe failed for %s: %s", url, exc)
        return None

    # ------------------------------------------------------------------ #
    # CSRF token detection
    # ------------------------------------------------------------------ #

    def extract_csrf_token(self, response: requests.Response) -> Optional[str]:
        """
        Extract a CSRF token from an HTTP response.

        Checks (in order):
          1. Response headers: ``X-CSRF-Token``, ``X-CSRFToken``, ``csrf-token``
          2. HTML ``<meta name="csrf-token">`` tag
          3. HTML ``<input type="hidden" name="*csrf*">`` field
          4. JSON body key ``csrfToken`` / ``csrf_token`` / ``_csrf``

        Parameters
        ----------
        response : requests.Response
            The response object from a GET to the login page.

        Returns
        -------
        str | None
            The extracted token value, or None if not found.
        """
        # 1. Response headers
        for header_name in ("X-CSRF-Token", "X-CSRFToken", "csrf-token", "x-csrf-token"):
            value = response.headers.get(header_name)
            if value:
                log.debug("CSRF token found in header '%s'", header_name)
                return value

        body = response.text

        # 2. <meta name="csrf-token" content="...">
        meta_match = re.search(
            r'<meta[^>]+name=["\'](?:csrf[-_]token|_csrf)["\'][^>]+content=["\']([^"\']+)["\']',
            body,
            re.IGNORECASE,
        )
        if meta_match:
            log.debug("CSRF token found in meta tag")
            return meta_match.group(1)

        # Also handle reversed attribute order: content=... name=...
        meta_match2 = re.search(
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\'](?:csrf[-_]token|_csrf)["\']',
            body,
            re.IGNORECASE,
        )
        if meta_match2:
            log.debug("CSRF token found in meta tag (reversed attrs)")
            return meta_match2.group(1)

        # 3. <input type="hidden" name="*csrf*" value="...">
        input_match = re.search(
            r'<input[^>]+name=["\']([^"\']*csrf[^"\']*)["\'][^>]+value=["\']([^"\']+)["\']',
            body,
            re.IGNORECASE,
        )
        if input_match:
            log.debug("CSRF token found in hidden input '%s'", input_match.group(1))
            return input_match.group(2)

        # Also reversed: value=... name=...
        input_match2 = re.search(
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']([^"\']*csrf[^"\']*)["\']',
            body,
            re.IGNORECASE,
        )
        if input_match2:
            log.debug("CSRF token found in hidden input (reversed attrs)")
            return input_match2.group(1)

        # 4. JSON body
        try:
            json_body = response.json()
            for key in ("csrfToken", "csrf_token", "_csrf", "csrf", "token"):
                if key in json_body:
                    log.debug("CSRF token found in JSON body key '%s'", key)
                    return str(json_body[key])
        except (ValueError, AttributeError):
            pass

        return None

    def get_csrf_token(self, url: str) -> Optional[str]:
        """
        GET *url* and extract a CSRF token from the response.

        Returns the token string, or None if not found.
        """
        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = "OneInfinity-AuthManager/1.0"
        try:
            resp = session.get(url, timeout=_DEFAULT_TIMEOUT, allow_redirects=True)
            token = self.extract_csrf_token(resp)
            if token:
                log.info("CSRF token extracted from %s", url)
            return token
        except requests.RequestException as exc:
            log.debug("get_csrf_token failed for %s: %s", url, exc)
            return None

    def _extract_form_fields(self, html: str) -> Dict[str, str]:
        """
        Parse an HTML login form and return field name→value pairs for all
        hidden and visible input fields.

        Provides better form detection than hardcoded field names.
        """
        fields: Dict[str, str] = {}
        # Match <input ...> tags
        for m in re.finditer(r'<input([^>]*)>', html, re.IGNORECASE):
            attrs_str = m.group(1)
            # Extract name and value attributes
            name_m = re.search(r'name=["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
            value_m = re.search(r'value=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
            if name_m:
                name = name_m.group(1)
                value = value_m.group(1) if value_m else ""
                fields[name] = value
        return fields

    # ------------------------------------------------------------------ #
    # Login
    # ------------------------------------------------------------------ #

    def attempt_login(
        self,
        url: str,
        username: str,
        password: str,
    ) -> Optional[requests.Session]:
        """
        POST credentials to *url* and return an authenticated session if
        the response indicates success.

        Tries JSON body first (``{"username": ..., "password": ...}``),
        then falls back to form-encoded body.

        Parameters
        ----------
        url : str
            Full login endpoint URL.
        username : str
        password : str

        Returns
        -------
        requests.Session | None
            Authenticated session on success, None otherwise.
        """
        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = "OneInfinity-AuthManager/1.0"

        # Fetch the login page to extract CSRF token and form fields
        csrf_token: Optional[str] = None
        form_fields: Dict[str, str] = {}
        try:
            get_resp = session.get(url, timeout=_DEFAULT_TIMEOUT, allow_redirects=True)
            csrf_token = self.extract_csrf_token(get_resp)
            form_fields = self._extract_form_fields(get_resp.text)
            if csrf_token:
                log.debug("CSRF token extracted for login: %s…", csrf_token[:12])
        except requests.RequestException as exc:
            log.debug("Could not fetch login page for CSRF extraction: %s", exc)

        # Detect actual username/password field names from the form
        username_field = "username"
        password_field = "password"
        for fname in form_fields:
            flower = fname.lower()
            if flower in ("email", "user", "username", "login", "usr"):
                username_field = fname
            elif flower in ("password", "passwd", "pass", "pwd"):
                password_field = fname

        # Build form data including any hidden fields (CSRF, tokens, etc.)
        base_form = dict(form_fields)  # includes hidden fields like csrf
        base_form[username_field] = username
        base_form[password_field] = password

        # If CSRF token was found in a response header/meta but not in form, add common field names
        if csrf_token and not any(
            "csrf" in k.lower() for k in base_form
        ):
            base_form["_csrf"] = csrf_token
            base_form["csrfToken"] = csrf_token

        credential_pairs = [
            # JSON body with detected field names
            {
                "content_type": "application/json",
                "body_json": {username_field: username, "password": password},
                "body_form": None,
            },
            # Form-encoded body with all detected fields (includes hidden CSRF fields)
            {
                "content_type": "application/x-www-form-urlencoded",
                "body_json": None,
                "body_form": base_form,
            },
            # email field variant
            {
                "content_type": "application/json",
                "body_json": {"email": username, "password": password},
                "body_form": None,
            },
            # Standard username + password form fallback
            {
                "content_type": "application/x-www-form-urlencoded",
                "body_json": None,
                "body_form": {"username": username, "password": password},
            },
        ]

        for variant in credential_pairs:
            try:
                if variant["body_json"] is not None:
                    resp = session.post(
                        url,
                        json=variant["body_json"],
                        timeout=_DEFAULT_TIMEOUT,
                    )
                else:
                    resp = session.post(
                        url,
                        data=variant["body_form"],
                        timeout=_DEFAULT_TIMEOUT,
                    )

                if resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if any(ind in body_lower for ind in _SUCCESS_INDICATORS):
                        log.info(
                            "Login succeeded for user '%s' at %s (HTTP 200)",
                            username, url,
                        )
                        # Absorb any Set-Cookie headers
                        return session

                    # Also check for token in JSON response
                    try:
                        data = resp.json()
                        for key in ("token", "access_token", "jwt", "auth_token", "sessionToken"):
                            if key in data:
                                token_val = data[key]
                                session.headers["Authorization"] = f"Bearer {token_val}"
                                log.info(
                                    "Login succeeded for user '%s' at %s — token extracted",
                                    username, url,
                                )
                                return session
                    except ValueError:
                        pass

            except requests.RequestException as exc:
                log.debug("Login attempt failed (url=%s, user=%s): %s", url, username, exc)

        log.debug("Login failed for user '%s' at %s", username, url)
        return None

    # ------------------------------------------------------------------ #
    # Role-based response comparison
    # ------------------------------------------------------------------ #

    def compare_responses(
        self,
        url: str,
        method: str = "GET",
        data: Optional[dict] = None,
    ) -> dict:
        """
        Issue the same request from every registered role session (plus the
        default session) and return a structured comparison dict.

        Useful for detecting IDOR and broken access-control: if two different
        roles receive the same privileged data, access control is broken.

        Parameters
        ----------
        url : str
            Endpoint to probe.
        method : str
            HTTP method: ``"GET"`` (default) or ``"POST"``.
        data : dict | None
            Request body for POST requests.

        Returns
        -------
        dict
            Keyed by role name (``"__default__"`` for the primary session).
            Each value: ``{status_code, body_snippet, content_length, headers}``.
        """
        results: dict = {}

        all_sessions: Dict[str, requests.Session] = {
            "__default__": self.get_session(),
            **self._role_sessions,
        }

        for role, sess in all_sessions.items():
            try:
                if method.upper() == "POST":
                    resp = sess.post(url, json=data, timeout=_DEFAULT_TIMEOUT)
                else:
                    resp = sess.get(url, timeout=_DEFAULT_TIMEOUT)

                results[role] = {
                    "status_code": resp.status_code,
                    "body_snippet": resp.text[:500],
                    "content_length": len(resp.content),
                    "headers": dict(resp.headers),
                }
            except requests.RequestException as exc:
                results[role] = {
                    "status_code": -1,
                    "body_snippet": "",
                    "content_length": 0,
                    "headers": {},
                    "error": str(exc),
                }
                log.debug("compare_responses error for role '%s' at %s: %s", role, url, exc)

        # Annotate differences
        status_codes = {r: v["status_code"] for r, v in results.items()}
        content_lengths = {r: v["content_length"] for r, v in results.items()}
        unique_statuses = set(status_codes.values()) - {-1}
        unique_lengths = set(content_lengths.values())

        results["__meta__"] = {
            "url": url,
            "method": method.upper(),
            "status_codes": status_codes,
            "content_lengths": content_lengths,
            "status_divergence": len(unique_statuses) > 1,
            "length_divergence": len(unique_lengths) > 1,
        }
        log.info(
            "compare_responses %s — status divergence=%s, length divergence=%s",
            url,
            results["__meta__"]["status_divergence"],
            results["__meta__"]["length_divergence"],
        )
        return results

    def idor_diff(
        self,
        url: str,
        role_a: str = "__default__",
        role_b: str = "user",
        method: str = "GET",
        data: Optional[dict] = None,
    ) -> dict:
        """
        Compare the same endpoint response between two specific roles and
        return a structured diff highlighting potential IDOR.

        Parameters
        ----------
        url : str
            Endpoint to probe.
        role_a : str
            First role name. Use ``"__default__"`` for the primary session.
        role_b : str
            Second role name (must be registered via :meth:`add_role`).
        method : str
            HTTP method (``"GET"`` or ``"POST"``).
        data : dict | None
            Request body for POST requests.

        Returns
        -------
        dict
            Keys: ``url``, ``role_a``, ``role_b``, ``status_match``,
            ``length_diff``, ``content_overlap``, ``idor_suspected``,
            ``details``.
        """
        all_sessions: Dict[str, requests.Session] = {
            "__default__": self.get_session(),
            **self._role_sessions,
        }

        def _fetch(sess: requests.Session) -> dict:
            try:
                if method.upper() == "POST":
                    resp = sess.post(url, json=data, timeout=_DEFAULT_TIMEOUT)
                else:
                    resp = sess.get(url, timeout=_DEFAULT_TIMEOUT)
                return {
                    "status": resp.status_code,
                    "body": resp.text,
                    "length": len(resp.content),
                    "error": None,
                }
            except requests.RequestException as exc:
                return {"status": -1, "body": "", "length": 0, "error": str(exc)}

        sess_a = all_sessions.get(role_a)
        sess_b = all_sessions.get(role_b)

        if sess_a is None:
            return {"error": f"Role '{role_a}' not found"}
        if sess_b is None:
            return {"error": f"Role '{role_b}' not found — call add_role() first"}

        result_a = _fetch(sess_a)
        result_b = _fetch(sess_b)

        # Compute a rough token-level overlap score (0–1)
        tokens_a = set(result_a["body"].split())
        tokens_b = set(result_b["body"].split())
        overlap = (
            len(tokens_a & tokens_b) / max(len(tokens_a | tokens_b), 1)
            if (tokens_a or tokens_b) else 0.0
        )

        status_match = result_a["status"] == result_b["status"]
        length_diff = abs(result_a["length"] - result_b["length"])

        # IDOR suspected when both return 200 with highly similar content
        idor_suspected = (
            result_a["status"] == 200
            and result_b["status"] == 200
            and overlap > 0.80
            and result_a["body"] != result_b["body"]
        )

        result = {
            "url": url,
            "role_a": role_a,
            "role_b": role_b,
            "status_match": status_match,
            "status_a": result_a["status"],
            "status_b": result_b["status"],
            "length_diff": length_diff,
            "content_overlap": round(overlap, 3),
            "idor_suspected": idor_suspected,
            "details": {
                role_a: {"status": result_a["status"], "length": result_a["length"]},
                role_b: {"status": result_b["status"], "length": result_b["length"]},
            },
        }

        if idor_suspected:
            log.warning(
                "IDOR suspected at %s between roles '%s' and '%s' "
                "(overlap=%.2f, len_diff=%d)",
                url, role_a, role_b, overlap, length_diff,
            )
        return result

    # ------------------------------------------------------------------ #
    # Scanner integration
    # ------------------------------------------------------------------ #

    def apply_to_scanner(self, scanner_kwargs: dict) -> dict:
        """
        Inject the default session's cookies and headers into *scanner_kwargs*
        so that scanner engines receive authenticated request parameters.

        Merges with any existing ``cookies`` / ``headers`` keys in
        *scanner_kwargs* (existing values are NOT overwritten).

        Parameters
        ----------
        scanner_kwargs : dict
            Keyword argument dict destined for a scanner engine constructor
            or ``run()`` call.

        Returns
        -------
        dict
            Updated copy of *scanner_kwargs* with session credentials merged in.
        """
        updated = dict(scanner_kwargs)

        # Merge cookies
        existing_cookies = dict(updated.get("cookies") or {})
        existing_cookies.update(self._default_cookies)
        updated["cookies"] = existing_cookies

        # Merge headers
        existing_headers = dict(updated.get("headers") or {})
        default_headers = dict(self._default_headers)
        if self._default_token:
            if " " in self._default_token:
                default_headers["Authorization"] = self._default_token
            else:
                default_headers["Authorization"] = f"Bearer {self._default_token}"
        # Existing scanner headers take precedence
        merged_headers = {**default_headers, **existing_headers}
        updated["headers"] = merged_headers

        log.debug(
            "apply_to_scanner: injected %d cookies, %d headers",
            len(existing_cookies),
            len(merged_headers),
        )
        return updated


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(description="Auth & Session Manager")
    parser.add_argument("target", help="Base URL (e.g. https://example.com)")
    parser.add_argument("--token", default=None, help="Bearer token for default session")
    parser.add_argument("--cookie", default=None, help="session=value cookie string")
    parser.add_argument("--username", default=None, help="Username to attempt login with")
    parser.add_argument("--password", default=None, help="Password to attempt login with")
    parser.add_argument("--compare-url", default=None, help="URL to compare across roles")
    args = parser.parse_args()

    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()

    mgr = AuthSessionManager(
        target=args.target,
        cookies=cookies or None,
        token=args.token,
    )

    login_url = mgr.detect_login_form()
    print(f"[+] Login endpoint: {login_url}")

    if args.username and args.password and login_url:
        sess = mgr.attempt_login(login_url, args.username, args.password)
        if sess:
            print(f"[+] Login succeeded for {args.username}")
        else:
            print(f"[-] Login failed for {args.username}")

    if args.compare_url:
        diff = mgr.compare_responses(args.compare_url)
        print(f"\n[+] Response comparison for {args.compare_url}:")
        print(json.dumps(diff["__meta__"], indent=2))
