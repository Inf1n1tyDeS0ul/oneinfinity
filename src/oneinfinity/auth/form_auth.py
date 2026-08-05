"""
form_auth.py — Standard HTTP form/JSON authentication for lab and app targets.
Supports: session-cookie apps (DVWA, WebGoat), JSON API apps (Juice Shop), Basic Auth.
"""
from __future__ import annotations
import json
import urllib.request as _ur
import urllib.parse as _up
import urllib.error as _ue
import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class FormAuthConfig:
    """Configuration for standard HTTP form/API authentication."""
    login_url: str
    username: str
    password: str
    username_field: str = "username"      # POST form field name
    password_field: str = "password"      # POST form field name
    auth_type: str = "form"               # form | json | basic
    success_pattern: str = ""             # regex in response body to confirm login
    token_field: str = ""                 # JSON field name for auth token in response
    extra_fields: dict = field(default_factory=dict)  # additional POST fields


@dataclass
class FormAuthResult:
    success: bool
    session_cookie: str = ""
    auth_header: str = ""
    token: str = ""
    error: str = ""


def authenticate(config: FormAuthConfig) -> FormAuthResult:
    """
    Perform HTTP form/JSON/Basic authentication and return session cookie or token.
    """
    try:
        if config.auth_type == "basic":
            import base64
            creds = base64.b64encode(f"{config.username}:{config.password}".encode()).decode()
            return FormAuthResult(success=True, auth_header=f"Basic {creds}")

        if config.auth_type == "json":
            return _json_auth(config)

        # Default: HTML form POST
        return _form_post_auth(config)

    except Exception as exc:
        log.warning("FormAuth failed: %s", exc)
        return FormAuthResult(success=False, error=str(exc))


def _form_post_auth(config: FormAuthConfig) -> FormAuthResult:
    """Standard HTML form POST authentication."""
    import http.cookiejar as _cj, urllib.request as _ur2

    cj = _cj.CookieJar()
    opener = _ur2.build_opener(_ur2.HTTPCookieProcessor(cj))

    # E7: GET login page first — extract CSRF hidden fields + pre-auth cookies
    _hidden_fields: dict = {}
    try:
        import re as _re_h
        _pre_req = _ur2.Request(config.login_url, headers={"User-Agent": "oneinfinity/1.0"})
        _pre_resp = opener.open(_pre_req, timeout=10)
        _pre_body = _pre_resp.read(32768).decode("utf-8", errors="replace")
        # Extract hidden <input> fields (CSRF nonces, user_token, etc.)
        _inp_pat = _re_h.compile(r"<input([^>]*)>", _re_h.IGNORECASE)
        _attr_pat = _re_h.compile(r"""([\w-]+)=['"](.*?)['"]""", _re_h.IGNORECASE)
        for _inp in _inp_pat.findall(_pre_body):
            _attrs = dict(_attr_pat.findall(_inp))
            if _attrs.get("type", "").lower() == "hidden" and "name" in _attrs:
                _hidden_fields[_attrs["name"]] = _attrs.get("value", "")
    except Exception:
        pass  # best-effort

    # Merge: live hidden fields fill blanks, explicit extra_fields override
    _merged_extra = dict(_hidden_fields)
    _merged_extra.update({k: v for k, v in config.extra_fields.items() if v != ""})

    post_data = {
        config.username_field: config.username,
        config.password_field: config.password,
        **_merged_extra,
    }
    encoded = _up.urlencode(post_data).encode()
    req = _ur2.Request(
        config.login_url, data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "oneinfinity/1.0"},
    )
    resp = opener.open(req, timeout=10)

    # Extract cookies
    cookie_str = "; ".join(f"{c.name}={c.value}" for c in cj)

    if not cookie_str:
        return FormAuthResult(success=False, error="No session cookie received")

    # Check success pattern if provided
    if config.success_pattern:
        import re
        body = resp.read(8192).decode("utf-8", errors="replace")
        if not re.search(config.success_pattern, body, re.IGNORECASE):
            return FormAuthResult(success=False, error="Success pattern not found in response")

    log.info("FormAuth: form POST auth successful for %s", config.login_url)
    return FormAuthResult(success=True, session_cookie=cookie_str)

def _json_auth(config: FormAuthConfig) -> FormAuthResult:
    """JSON body POST authentication (Juice Shop, modern APIs)."""
    payload = json.dumps({
        config.username_field: config.username,
        config.password_field: config.password,
        **config.extra_fields,
    }).encode()
    req = _ur.Request(
        config.login_url, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "oneinfinity/1.0"},
    )
    try:
        resp = _ur.urlopen(req, timeout=10)
        body = resp.read(65536).decode("utf-8", errors="replace")
        data = json.loads(body)

        # Extract token from response
        token = ""
        if config.token_field:
            token = str(data.get(config.token_field, ""))
        else:
            # Common token field names
            for field_name in ("token", "access_token", "accessToken", "jwt", "authentication"):
                val = data.get(field_name) or (data.get("data", {}) or {}).get(field_name, "")
                if val:
                    token = str(val)
                    break

        if token:
            log.info("FormAuth: JSON auth successful, got token for %s", config.login_url)
            return FormAuthResult(success=True, token=token, auth_header=f"Bearer {token}")

        return FormAuthResult(success=False, error="No token in JSON response")
    except _ue.HTTPError as he:
        return FormAuthResult(success=False, error=f"HTTP {he.code}")


# ── Known app profiles for auto-detection ─────────────────────────────────────
KNOWN_APP_AUTH = {
    "dvwa": FormAuthConfig(
        login_url="{base}/login.php",
        username="admin", password="password",
        username_field="username", password_field="password",
        extra_fields={"Login": "Login", "user_token": ""},  # DVWA needs user_token from CSRF
        auth_type="form",
    ),
    "juice_shop": FormAuthConfig(
        login_url="{base}/rest/user/login",
        username="admin@juice-sh.op", password="admin123",
        username_field="email", password_field="password",
        auth_type="json", token_field="token",
    ),
    "webgoat": FormAuthConfig(
        login_url="{base}/WebGoat/login",
        username="guest", password="guest",
        username_field="username", password_field="password",
        auth_type="form",
    ),
}


def auth_from_scan_config(scan_config: dict, base_url: str) -> Optional[FormAuthResult]:
    """
    Try to authenticate using scan config fields.
    scan_config may contain:
      form_auth_url, form_auth_username, form_auth_password,
      form_auth_type (form|json|basic), form_auth_username_field, form_auth_password_field
    """
    login_url = scan_config.get("form_auth_url", "")
    username  = scan_config.get("form_auth_username", "")
    password  = scan_config.get("form_auth_password", "")
    if not (login_url and username and password):
        return None

    # Resolve relative login URLs
    if not login_url.startswith("http"):
        login_url = base_url.rstrip("/") + "/" + login_url.lstrip("/")

    cfg = FormAuthConfig(
        login_url=login_url,
        username=username,
        password=password,
        username_field=scan_config.get("form_auth_username_field", "username"),
        password_field=scan_config.get("form_auth_password_field", "password"),
        auth_type=scan_config.get("form_auth_type", "form"),
        token_field=scan_config.get("form_auth_token_field", ""),
    )
    result = authenticate(cfg)
    log.info("FormAuth result: success=%s error=%s", result.success, result.error)
    return result
