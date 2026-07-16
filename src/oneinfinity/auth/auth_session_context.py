from __future__ import annotations
import logging
import time
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from oneinfinity.auth.session_manager import LoginSession
    from oneinfinity.auth.session_replay import SessionReplay

log = logging.getLogger(__name__)

_EXPIRY_KEYWORDS = {"/login", "/signin", "/auth/", "/session/new", "/logout"}


class AuthSessionContext:
    def __init__(self, session: "LoginSession") -> None:
        self._session = session

    def inject_requests(self, s) -> None:
        """Inject cookies + auth headers into a requests.Session."""
        try:
            for c in self._session.cookies:
                if c.get("name") and c.get("value"):
                    s.cookies.set(c["name"], c["value"], domain=c.get("domain", ""))
            for k, v in self._session.auth_headers.items():
                s.headers[k] = v
        except Exception as exc:
            log.debug("inject_requests failed: %s", exc)

    def inject_httpx(self, client) -> None:
        """Inject cookies + auth headers into an httpx.Client."""
        try:
            for c in self._session.cookies:
                if c.get("name") and c.get("value"):
                    client.cookies.set(c["name"], c["value"])
            for k, v in self._session.auth_headers.items():
                client.headers[k] = v
        except Exception as exc:
            log.debug("inject_httpx failed: %s", exc)

    def inject_playwright(self, context) -> None:
        """Inject cookies into a Playwright BrowserContext."""
        try:
            pw_cookies = []
            for c in self._session.cookies:
                if c.get("name") and c.get("value"):
                    pw_cookies.append({
                        "name": c["name"],
                        "value": c["value"],
                        "domain": c.get("domain", "") or "",
                        "path": c.get("path", "/"),
                    })
            if pw_cookies:
                context.add_cookies(pw_cookies)
                # NOTE: for localStorage-based auth (Cognito/Amplify), cookies alone are
                # insufficient. Call inject_localstorage(page) on each page after navigation.
            auth_headers = dict(self._session.auth_headers)
            if auth_headers:
                def _add_headers(route, request):
                    headers = {**request.headers, **auth_headers}
                    route.continue_(headers=headers)
                context.route("**/*", _add_headers)
        except Exception as exc:
            log.debug("inject_playwright failed: %s", exc)

    async def inject_localstorage(self, page) -> None:
        """
        Inject localStorage keys into a Playwright page after navigation.

        Must be called AFTER page.goto() because localStorage is origin-scoped —
        it is cleared when navigating to a new origin. Call sequence:
          1. await page.goto(url)
          2. await auth_context.inject_localstorage(page)
          3. await page.reload()  # reload so JS app reads the injected tokens

        Used for Cognito SPAs that store idToken/accessToken in localStorage
        rather than cookies (e.g. SpendAble, AWS Amplify apps).
        """
        try:
            ls = getattr(self._session, "local_storage", {}) or {}
            if not ls:
                return
            for key, value in ls.items():
                if key and value:
                    safe_value = str(value).replace("'", "\'").replace("\\", "\\\\")
                    await page.evaluate(f"localStorage.setItem('{key}', '{safe_value}')")
            log.debug("inject_localstorage: set %d keys", len(ls))
        except Exception as exc:
            log.debug("inject_localstorage failed (non-fatal): %s", exc)

    def inject_subprocess_env(self, env: dict) -> dict:
        """Add COOKIE and AUTH_HEADER env vars for CLI tool subprocesses."""
        cookie_str = "; ".join(
            f"{c['name']}={c['value']}" for c in self._session.cookies if c.get("name")
        )
        auth_header = next(iter(self._session.auth_headers.values()), "")
        result = dict(env)
        result["COOKIE"] = cookie_str
        result["AUTH_HEADER"] = auth_header
        return result

    def is_session_expired(self, response) -> bool:
        status = getattr(response, "status_code", None) or getattr(response, "status", None)
        if status in (401, 403):
            return True
        if status in (301, 302, 303, 307, 308):
            url = str(getattr(response, "url", "") or getattr(response, "headers", {}).get("location", ""))
            if any(kw in url.lower() for kw in _EXPIRY_KEYWORDS):
                return True
        return False

    def refresh(self, replay: Optional["SessionReplay"] = None) -> bool:
        """Re-authenticate via HAR replay. Returns True on success."""
        if replay is None:
            from oneinfinity.auth.session_replay import SessionReplay
            replay = SessionReplay()
        self._session.expiry_detected_at = time.time()
        success = replay.replay(self._session)
        if success:
            log.info("AuthSessionContext: session refreshed via HAR replay")
        else:
            log.warning("AuthSessionContext: session refresh failed — manual re-auth needed")
        return success

    def to_auth_config(self) -> dict:
        """Return {session_cookie, bearer_token, auth_header} for existing pipeline."""
        return self._session.to_auth_config()

    @property
    def session(self) -> "LoginSession":
        return self._session
