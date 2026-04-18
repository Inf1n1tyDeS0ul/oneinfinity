from __future__ import annotations
import html.parser
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

log = logging.getLogger(__name__)

USERNAME_NAMES = {"username", "user", "email", "login", "user_name", "userid", "uname", "identifier"}
PASSWORD_NAMES = {"password", "pass", "passwd", "pwd", "secret", "passphrase"}


@dataclass
class LoginFormResult:
    has_login_form: bool
    login_url: str = ""
    username_field: str = ""
    password_field: str = ""
    form_action: str = ""
    form_method: str = "POST"


class _FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._current = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "fields": [],
            }
        elif tag == "input" and self._current is not None:
            self._current["fields"].append({
                "type": (a.get("type") or "text").lower(),
                "name": (a.get("name") or "").lower(),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


class LoginFormDetector:
    def detect(self, target_url: str) -> LoginFormResult:
        try:
            html_body, status, _ = self._fetch(target_url)
        except Exception as exc:
            log.debug("LoginFormDetector: fetch failed for %s — %s", target_url, exc)
            return LoginFormResult(has_login_form=False)

        parser = _FormParser()
        try:
            parser.feed(html_body)
        except Exception:
            pass

        for form in parser.forms:
            pw_field = next((f["name"] for f in form["fields"] if f["type"] == "password" and f["name"]), None)
            if not pw_field:
                continue
            user_field = next(
                (f["name"] for f in form["fields"] if f["name"] in USERNAME_NAMES),
                None,
            )
            if not user_field:
                user_field = next(
                    (f["name"] for f in form["fields"]
                     if f["type"] in ("text", "email") and f["name"] and f["name"] != pw_field),
                    "",
                )
            action = form["action"]
            return LoginFormResult(
                has_login_form=True,
                login_url=target_url,
                username_field=user_field or "",
                password_field=pw_field,
                form_action=action or target_url,
                form_method=form["method"],
            )

        return LoginFormResult(has_login_form=False, login_url=target_url)

    def _fetch(self, url: str, timeout: int = 10) -> tuple[str, int, dict]:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status, dict(resp.headers)
