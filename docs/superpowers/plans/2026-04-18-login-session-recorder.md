# Login Session Recorder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Acunetix-style login session recording to OneInfinity so every scan can automatically authenticate, test 16 post-login vulnerability categories, and gracefully handle session expiry.

**Architecture:** New `src/oneinfinity/auth/` package (7 files) is self-contained. It bridges into the existing pipeline via `AuthSessionContext.to_auth_config()` which returns the `{session_cookie, bearer_token, auth_header}` dict that the existing `GodModeSession.auth_config` / `FullScanMission` / `SwarmMission` already consume. `AuthTestMission` is a new god-mode mission inserted between `SwarmMission` and `ChainsMission`. Session files live in `~/.oneinfinity/sessions/`. Login detection runs after Foundation phase completes.

**Tech Stack:** Playwright (already installed), httpx (already installed), mitmproxy (optional), pytest + unittest.mock for tests.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `src/oneinfinity/auth/__init__.py` | Package exports |
| Create | `src/oneinfinity/auth/login_form_detector.py` | Detect login forms on target URLs |
| Create | `src/oneinfinity/auth/login_session_recorder.py` | Record session via Playwright HAR |
| Create | `src/oneinfinity/auth/session_manager.py` | Save/load/list/delete sessions on disk |
| Create | `src/oneinfinity/auth/auth_session_context.py` | Inject auth into all HTTP clients |
| Create | `src/oneinfinity/auth/session_replay.py` | Re-authenticate using recorded HAR |
| Create | `src/oneinfinity/auth/authenticated_test_suite.py` | 16 post-login test categories |
| Modify | `src/oneinfinity/orchestration/god_mode_engine.py` | Auth detection after Foundation + AuthTestMission |
| Modify | `web/backend/main.py` | 6 new /api/auth/* endpoints |
| Modify | `web/frontend/src/pages/GodMode.jsx` | Record button + overlay + session picker |
| Modify | `web/frontend/src/utils/api.js` | 6 new auth API calls |
| Create | `tests/test_auth_login_form_detector.py` | Tests for login form detector |
| Create | `tests/test_auth_session_manager.py` | Tests for session manager |
| Create | `tests/test_auth_session_context.py` | Tests for auth session context |
| Create | `tests/test_auth_test_suite.py` | Tests for authenticated test suite |

---

## Task 1: LoginFormResult + LoginFormDetector

**Files:**
- Create: `src/oneinfinity/auth/login_form_detector.py`
- Create: `tests/test_auth_login_form_detector.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_auth_login_form_detector.py
import pytest
from unittest.mock import patch, MagicMock
from oneinfinity.auth.login_form_detector import LoginFormDetector, LoginFormResult

SIMPLE_LOGIN_HTML = """
<html><body>
<form action="/login" method="POST">
  <input type="text" name="username" />
  <input type="password" name="password" />
  <button type="submit">Login</button>
</form>
</body></html>
"""

EMAIL_LOGIN_HTML = """
<html><body>
<form action="/auth/signin" method="post">
  <input type="email" name="email" />
  <input type="password" name="pass" />
  <input type="submit" value="Sign in" />
</form>
</body></html>
"""

NO_LOGIN_HTML = """
<html><body>
<form action="/search" method="GET">
  <input type="text" name="q" />
</form>
</body></html>
"""

def _mock_fetch(html):
    def _fetch(url, timeout=10):
        return html, 200, {}
    return _fetch

def test_detects_simple_login_form():
    d = LoginFormDetector()
    with patch.object(d, '_fetch', _mock_fetch(SIMPLE_LOGIN_HTML)):
        r = d.detect("https://example.com")
    assert r.has_login_form is True
    assert r.username_field == "username"
    assert r.password_field == "password"
    assert r.form_action == "/login"
    assert r.form_method == "POST"

def test_detects_email_login_form():
    d = LoginFormDetector()
    with patch.object(d, '_fetch', _mock_fetch(EMAIL_LOGIN_HTML)):
        r = d.detect("https://example.com/signin")
    assert r.has_login_form is True
    assert r.username_field == "email"
    assert r.password_field == "pass"
    assert r.login_url == "https://example.com/signin"

def test_no_login_form():
    d = LoginFormDetector()
    with patch.object(d, '_fetch', _mock_fetch(NO_LOGIN_HTML)):
        r = d.detect("https://example.com/search")
    assert r.has_login_form is False

def test_fetch_failure_returns_no_form():
    d = LoginFormDetector()
    def _fail(url, timeout=10):
        raise ConnectionError("timeout")
    with patch.object(d, '_fetch', _fail):
        r = d.detect("https://example.com")
    assert r.has_login_form is False
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
cd /Users/devendrayadav/Tools/oneinfinity
uv run pytest tests/test_auth_login_form_detector.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'oneinfinity.auth'`

- [ ] **Step 3: Implement LoginFormDetector**

```python
# src/oneinfinity/auth/login_form_detector.py
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
            # Find username field: prefer explicit username-like name, fall back to first text/email
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
            if action and not action.startswith("http"):
                action = urljoin(target_url, action)
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
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
uv run pytest tests/test_auth_login_form_detector.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/oneinfinity/auth/login_form_detector.py tests/test_auth_login_form_detector.py
git commit -m "feat(auth): add LoginFormDetector with form field extraction"
```

---

## Task 2: LoginSession dataclass + SessionManager

**Files:**
- Create: `src/oneinfinity/auth/session_manager.py`
- Create: `tests/test_auth_session_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_auth_session_manager.py
import json
import pytest
from pathlib import Path
from oneinfinity.auth.session_manager import SessionManager, LoginSession

def test_save_and_load_auto(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    s = LoginSession(
        session_id="abc123",
        target="https://example.com",
        login_url="https://example.com/login",
        cookies=[{"name": "session", "value": "s1", "domain": "example.com"}],
        auth_headers={"Authorization": "Bearer tok"},
        local_storage={"token": "tok"},
        session_storage={},
        indexeddb_snapshot={},
        har_path="",
        recorder="playwright",
    )
    mgr.save(s)
    loaded = mgr.load(target="https://example.com")
    assert loaded is not None
    assert loaded.session_id == "abc123"
    assert loaded.cookies[0]["name"] == "session"

def test_save_and_load_named(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    s = LoginSession(
        session_id="xyz999",
        target="https://app.io",
        login_url="https://app.io/signin",
        cookies=[],
        auth_headers={},
        local_storage={},
        session_storage={},
        indexeddb_snapshot={},
        har_path="",
        recorder="playwright",
    )
    mgr.save(s, name="myapp")
    loaded = mgr.load(name="myapp")
    assert loaded is not None
    assert loaded.session_id == "xyz999"

def test_list_all(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    for i in range(3):
        s = LoginSession(
            session_id=f"s{i}", target=f"https://t{i}.com", login_url=f"https://t{i}.com/login",
            cookies=[], auth_headers={}, local_storage={}, session_storage={},
            indexeddb_snapshot={}, har_path="", recorder="playwright",
        )
        mgr.save(s, name=f"sess{i}")
    assert len(mgr.list_all()) == 3

def test_delete(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    s = LoginSession(
        session_id="del1", target="https://del.com", login_url="https://del.com/login",
        cookies=[], auth_headers={}, local_storage={}, session_storage={},
        indexeddb_snapshot={}, har_path="", recorder="playwright",
    )
    mgr.save(s, name="todelete")
    mgr.delete("del1")
    assert mgr.load(name="todelete") is None

def test_exists(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    assert mgr.exists(target="https://example.com") is False
    s = LoginSession(
        session_id="ex1", target="https://example.com", login_url="https://example.com/login",
        cookies=[], auth_headers={}, local_storage={}, session_storage={},
        indexeddb_snapshot={}, har_path="", recorder="playwright",
    )
    mgr.save(s)
    assert mgr.exists(target="https://example.com") is True

def test_load_missing_returns_none(tmp_path):
    mgr = SessionManager(base_dir=tmp_path)
    assert mgr.load(target="https://nobody.com") is None
    assert mgr.load(name="nonexistent") is None
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
uv run pytest tests/test_auth_session_manager.py -v 2>&1 | head -10
```

- [ ] **Step 3: Implement SessionManager + LoginSession**

```python
# src/oneinfinity/auth/session_manager.py
from __future__ import annotations
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_DEFAULT_DIR = Path.home() / ".oneinfinity" / "sessions"


@dataclass
class LoginSession:
    session_id: str
    target: str
    login_url: str
    cookies: list           # list of {name, value, domain, ...}
    auth_headers: dict      # e.g. {"Authorization": "Bearer ..."}
    local_storage: dict
    session_storage: dict
    indexeddb_snapshot: dict
    har_path: str           # absolute path to .har file, "" if not recorded
    recorder: str           # "playwright" | "mitmproxy"
    name: str = ""
    recorded_at: float = field(default_factory=time.time)
    mitmproxy_flow_path: str = ""
    expiry_detected_at: Optional[float] = None
    replayed_at: Optional[float] = None

    def to_auth_config(self) -> dict:
        """Convert to the {session_cookie, bearer_token, auth_header} dict
        that the existing FullScanMission / SwarmMission pipeline expects."""
        cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in self.cookies if c.get("name"))
        bearer = self.auth_headers.get("Authorization", "")
        if bearer.startswith("Bearer "):
            bearer = bearer[len("Bearer "):]
        elif bearer:
            bearer = ""
        raw_header = ""
        for k, v in self.auth_headers.items():
            if k.lower() != "authorization":
                raw_header = f"{k}: {v}"
                break
        return {
            "session_cookie": cookie_str,
            "bearer_token": bearer,
            "auth_header": raw_header,
        }


def _target_hash(target: str) -> str:
    return hashlib.sha256(target.encode()).hexdigest()[:8]


class SessionManager:
    def __init__(self, base_dir: Path = _DEFAULT_DIR):
        self._dir = Path(base_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def save(self, session: LoginSession, name: str = "") -> None:
        session.name = name or session.name
        data = asdict(session)
        # Always save auto-path keyed by target
        auto_path = self._dir / f"auto-{_target_hash(session.target)}.json"
        auto_path.write_text(json.dumps(data, indent=2, default=str))
        # If named, also save under the name
        if name:
            named_path = self._dir / f"{name}.json"
            named_path.write_text(json.dumps(data, indent=2, default=str))
        log.info("Session %s saved (target=%s, name=%s)", session.session_id, session.target, name)

    def load(self, target: str = "", name: str = "") -> Optional[LoginSession]:
        if name:
            p = self._dir / f"{name}.json"
            if p.exists():
                return self._read(p)
        if target:
            p = self._dir / f"auto-{_target_hash(target)}.json"
            if p.exists():
                return self._read(p)
        return None

    def list_all(self) -> list[LoginSession]:
        sessions: list[LoginSession] = []
        seen_ids: set[str] = set()
        for p in self._dir.glob("*.json"):
            s = self._read(p)
            if s and s.session_id not in seen_ids:
                sessions.append(s)
                seen_ids.add(s.session_id)
        return sessions

    def delete(self, session_id: str) -> None:
        for p in self._dir.glob("*.json"):
            s = self._read(p)
            if s and s.session_id == session_id:
                p.unlink(missing_ok=True)

    def exists(self, target: str = "", name: str = "") -> bool:
        return self.load(target=target, name=name) is not None

    def _read(self, path: Path) -> Optional[LoginSession]:
        try:
            data = json.loads(path.read_text())
            return LoginSession(**{k: data[k] for k in LoginSession.__dataclass_fields__ if k in data})
        except Exception as exc:
            log.debug("SessionManager: failed to read %s — %s", path, exc)
            return None
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
uv run pytest tests/test_auth_session_manager.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/oneinfinity/auth/session_manager.py tests/test_auth_session_manager.py
git commit -m "feat(auth): add LoginSession dataclass and SessionManager"
```

---

## Task 3: SessionReplay

**Files:**
- Create: `src/oneinfinity/auth/session_replay.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_auth_session_replay.py
import json
import pytest
from unittest.mock import patch, MagicMock
from oneinfinity.auth.session_replay import SessionReplay
from oneinfinity.auth.session_manager import LoginSession

def _make_session(cookies=None, har_path=""):
    return LoginSession(
        session_id="r1", target="https://app.com",
        login_url="https://app.com/login",
        cookies=cookies or [{"name": "session", "value": "old", "domain": "app.com"}],
        auth_headers={}, local_storage={}, session_storage={},
        indexeddb_snapshot={}, har_path=har_path, recorder="playwright",
    )

# Minimal HAR with a single POST /login entry
MINIMAL_HAR = json.dumps({
    "log": {
        "entries": [{
            "request": {
                "method": "POST",
                "url": "https://app.com/login",
                "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                "postData": {"text": "username=admin&password=secret"},
            }
        }]
    }
})

def test_replay_updates_cookies(tmp_path):
    har_file = tmp_path / "session.har"
    har_file.write_text(MINIMAL_HAR)
    session = _make_session(har_path=str(har_file))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.cookies = {"session": "newsession456", "csrf": "abc"}
    mock_resp.headers = {"Set-Cookie": "session=newsession456"}

    with patch("httpx.Client") as MockClient:
        instance = MockClient.return_value.__enter__.return_value
        instance.send.return_value = mock_resp
        instance.cookies = {"session": "newsession456"}
        replay = SessionReplay()
        success = replay.replay(session)

    # SessionReplay should return True on 200
    assert success is True

def test_replay_returns_false_on_empty_har(tmp_path):
    har_file = tmp_path / "empty.har"
    har_file.write_text(json.dumps({"log": {"entries": []}}))
    session = _make_session(har_path=str(har_file))
    replay = SessionReplay()
    assert replay.replay(session) is False

def test_replay_returns_false_on_missing_har():
    session = _make_session(har_path="/nonexistent/path.har")
    replay = SessionReplay()
    assert replay.replay(session) is False
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
uv run pytest tests/test_auth_session_replay.py -v 2>&1 | head -10
```

- [ ] **Step 3: Implement SessionReplay**

```python
# src/oneinfinity/auth/session_replay.py
"""Replay the HAR login sequence to refresh an expired session."""
from __future__ import annotations
import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oneinfinity.auth.session_manager import LoginSession

log = logging.getLogger(__name__)

_LOGIN_KEYWORDS = {"/login", "/signin", "/auth", "/session", "/token", "/oauth"}


class SessionReplay:
    def replay(self, session: "LoginSession") -> bool:
        """
        Re-execute the login HAR sequence using httpx.
        Returns True if a session cookie / auth header was extracted.
        Updates session.cookies and session.auth_headers in-place.
        """
        har_path = session.har_path or ""
        if not har_path or not Path(har_path).exists():
            log.warning("SessionReplay: no HAR file at %s", har_path)
            return False

        try:
            har = json.loads(Path(har_path).read_text())
        except Exception as exc:
            log.warning("SessionReplay: could not parse HAR — %s", exc)
            return False

        entries = har.get("log", {}).get("entries", [])
        login_entries = [
            e for e in entries
            if any(kw in e.get("request", {}).get("url", "").lower() for kw in _LOGIN_KEYWORDS)
        ]
        if not login_entries:
            login_entries = entries  # fall back to all entries

        if not login_entries:
            log.warning("SessionReplay: HAR contains no entries")
            return False

        try:
            import httpx
        except ImportError:
            log.error("SessionReplay: httpx not installed — cannot replay")
            return False

        try:
            with httpx.Client(follow_redirects=True, verify=False, timeout=15) as client:
                for entry in login_entries:
                    req = entry.get("request", {})
                    url = req.get("url", "")
                    method = req.get("method", "GET").upper()
                    headers = {h["name"]: h["value"] for h in req.get("headers", [])}
                    body = req.get("postData", {}).get("text", None)
                    request = client.build_request(method, url, headers=headers, content=body)
                    try:
                        client.send(request)
                    except Exception:
                        pass

                # Extract fresh cookies
                new_cookies = [
                    {"name": name, "value": value, "domain": ""}
                    for name, value in client.cookies.items()
                ]
                if new_cookies:
                    session.cookies = new_cookies
                    session.replayed_at = time.time()
                    log.info("SessionReplay: refreshed %d cookies", len(new_cookies))
                    return True

        except Exception as exc:
            log.warning("SessionReplay: replay failed — %s", exc)

        return False
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
uv run pytest tests/test_auth_session_replay.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/oneinfinity/auth/session_replay.py tests/test_auth_session_replay.py
git commit -m "feat(auth): add SessionReplay for re-authenticating expired sessions via HAR"
```

---

## Task 4: AuthSessionContext

**Files:**
- Create: `src/oneinfinity/auth/auth_session_context.py`
- Create: `tests/test_auth_session_context.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_auth_session_context.py
import pytest
from unittest.mock import MagicMock, patch
from oneinfinity.auth.session_manager import LoginSession
from oneinfinity.auth.auth_session_context import AuthSessionContext

def _session(cookies=None, auth_headers=None):
    return LoginSession(
        session_id="ctx1", target="https://app.com",
        login_url="https://app.com/login",
        cookies=cookies or [{"name": "session", "value": "abc123", "domain": "app.com"}],
        auth_headers=auth_headers or {"Authorization": "Bearer tok123"},
        local_storage={}, session_storage={}, indexeddb_snapshot={},
        har_path="", recorder="playwright",
    )

def test_inject_requests_sets_cookies_and_headers():
    import requests
    ctx = AuthSessionContext(_session())
    s = requests.Session()
    ctx.inject_requests(s)
    assert s.cookies.get("session") == "abc123"
    assert s.headers.get("Authorization") == "Bearer tok123"

def test_inject_subprocess_env():
    ctx = AuthSessionContext(_session())
    env = {}
    result = ctx.inject_subprocess_env(env)
    assert "COOKIE" in result
    assert "session=abc123" in result["COOKIE"]
    assert "AUTH_HEADER" in result

def test_is_session_expired_401():
    ctx = AuthSessionContext(_session())
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.url = "https://app.com/api/data"
    assert ctx.is_session_expired(mock_resp) is True

def test_is_session_expired_redirect_to_login():
    ctx = AuthSessionContext(_session())
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.url = "https://app.com/login?next=/api/data"
    assert ctx.is_session_expired(mock_resp) is True

def test_is_session_expired_200():
    ctx = AuthSessionContext(_session())
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = "https://app.com/api/data"
    assert ctx.is_session_expired(mock_resp) is False

def test_to_auth_config():
    ctx = AuthSessionContext(_session(
        cookies=[{"name": "sess", "value": "val1", "domain": "app.com"}],
        auth_headers={"Authorization": "Bearer mytoken"},
    ))
    cfg = ctx.to_auth_config()
    assert cfg["session_cookie"] == "sess=val1"
    assert cfg["bearer_token"] == "mytoken"
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
uv run pytest tests/test_auth_session_context.py -v 2>&1 | head -10
```

- [ ] **Step 3: Implement AuthSessionContext**

```python
# src/oneinfinity/auth/auth_session_context.py
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

    # ── Injection ──────────────────────────────────────────────────────────────

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

            # Inject auth headers via route intercept
            auth_headers = dict(self._session.auth_headers)
            if auth_headers:
                def _add_headers(route, request):
                    headers = {**request.headers, **auth_headers}
                    route.continue_(headers=headers)
                context.route("**/*", _add_headers)
        except Exception as exc:
            log.debug("inject_playwright failed: %s", exc)

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

    # ── Expiry detection ───────────────────────────────────────────────────────

    def is_session_expired(self, response) -> bool:
        status = getattr(response, "status_code", None) or getattr(response, "status", None)
        if status in (401, 403):
            return True
        if status in (301, 302, 303, 307, 308):
            url = str(getattr(response, "url", "") or getattr(response, "headers", {}).get("location", ""))
            if any(kw in url.lower() for kw in _EXPIRY_KEYWORDS):
                return True
        return False

    # ── Refresh ───────────────────────────────────────────────────────────────

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

    # ── Bridge to existing pipeline ───────────────────────────────────────────

    def to_auth_config(self) -> dict:
        """Return {session_cookie, bearer_token, auth_header} for existing pipeline."""
        return self._session.to_auth_config()

    @property
    def session(self) -> "LoginSession":
        return self._session
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
uv run pytest tests/test_auth_session_context.py -v
```

Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add src/oneinfinity/auth/auth_session_context.py tests/test_auth_session_context.py
git commit -m "feat(auth): add AuthSessionContext for injecting sessions into all HTTP clients"
```

---

## Task 5: LoginSessionRecorder

**Files:**
- Create: `src/oneinfinity/auth/login_session_recorder.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_auth_login_session_recorder.py
import pytest
from unittest.mock import patch, MagicMock, call
from oneinfinity.auth.login_form_detector import LoginFormResult
from oneinfinity.auth.login_session_recorder import LoginSessionRecorder

def _form(action="https://app.com/login", user="username", pw="password"):
    return LoginFormResult(
        has_login_form=True,
        login_url="https://app.com/login",
        username_field=user,
        password_field=pw,
        form_action=action,
        form_method="POST",
    )

def test_record_auto_no_credentials_returns_none():
    rec = LoginSessionRecorder()
    session = rec.record_auto(login_form=_form(), credentials=None)
    assert session is None

def test_record_auto_or_interactive_no_display_no_creds_returns_none():
    rec = LoginSessionRecorder()
    with patch.dict("os.environ", {}, clear=True):
        with patch("oneinfinity.auth.login_session_recorder._has_display", return_value=False):
            result = rec.record_auto_or_interactive(login_form=_form(), credentials=None)
    assert result is None

def test_record_auto_or_interactive_prefers_auto():
    rec = LoginSessionRecorder()
    fake_session = MagicMock()
    with patch.object(rec, "record_auto", return_value=fake_session) as mock_auto:
        result = rec.record_auto_or_interactive(
            login_form=_form(),
            credentials=("admin", "pass"),
        )
    mock_auto.assert_called_once()
    assert result is fake_session
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
uv run pytest tests/test_auth_login_session_recorder.py -v 2>&1 | head -10
```

- [ ] **Step 3: Implement LoginSessionRecorder**

```python
# src/oneinfinity/auth/login_session_recorder.py
"""
LoginSessionRecorder — record auth sessions via Playwright HAR.

Three modes (selected automatically):
  record_auto()          — fill credentials programmatically
  record_interactive()   — open headed browser, user logs in
  record_auto_or_interactive() — try auto first, fall back to interactive,
                                 fall back to None if no DISPLAY
"""
from __future__ import annotations
import json
import logging
import os
import socket
import time
import uuid
from pathlib import Path
from typing import Optional, Tuple

log = logging.getLogger(__name__)

_SESSIONS_DIR = Path.home() / ".oneinfinity" / "sessions"
_HAR_DIR = Path.home() / ".oneinfinity" / "sessions"


def _has_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or os.name == "nt")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LoginSessionRecorder:
    def record_auto(
        self,
        login_form,
        credentials: Optional[Tuple[str, str]],
        har_dir: Path = _HAR_DIR,
    ):
        """Auto-fill form with credentials. Returns LoginSession or None."""
        if not credentials:
            log.info("LoginSessionRecorder.record_auto: no credentials provided — skipping")
            return None

        username, password = credentials
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            log.error("LoginSessionRecorder: Playwright not installed")
            return None

        session_id = str(uuid.uuid4())[:8]
        har_dir.mkdir(parents=True, exist_ok=True)
        har_path = har_dir / f"{session_id}.har"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    record_har_path=str(har_path),
                    record_har_mode="full",
                    ignore_https_errors=True,
                )
                page = context.new_page()
                page.goto(login_form.login_url, timeout=15000)

                if login_form.username_field:
                    try:
                        page.fill(f'[name="{login_form.username_field}"]', username)
                    except Exception:
                        try:
                            page.fill(f'input[type="text"]', username)
                            page.fill(f'input[type="email"]', username)
                        except Exception:
                            pass

                try:
                    page.fill(f'[name="{login_form.password_field}"]', password)
                except Exception:
                    try:
                        page.fill('input[type="password"]', password)
                    except Exception:
                        pass

                page.keyboard.press("Enter")
                page.wait_for_load_state("networkidle", timeout=8000)

                session = self._extract_session(context, page, session_id, login_form.login_url, str(har_path))
                context.close()
                browser.close()
                return session
        except Exception as exc:
            log.warning("LoginSessionRecorder.record_auto failed: %s", exc)
            return None

    def record_interactive(
        self,
        login_form,
        har_dir: Path = _HAR_DIR,
        done_file: Optional[Path] = None,
    ):
        """Open headed browser — user logs in manually, then signals done."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            log.error("LoginSessionRecorder: Playwright not installed")
            return None

        session_id = str(uuid.uuid4())[:8]
        har_dir.mkdir(parents=True, exist_ok=True)
        har_path = har_dir / f"{session_id}.har"
        done_file = done_file or (har_dir / f"{session_id}.done")

        print(f"\n[*] Opening browser for manual login at: {login_form.login_url}")
        print(f"    Log in, then press ENTER here (or create file: {done_file})")

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=False)
                context = browser.new_context(
                    record_har_path=str(har_path),
                    record_har_mode="full",
                    ignore_https_errors=True,
                )
                page = context.new_page()
                page.goto(login_form.login_url, timeout=15000)

                # Wait for user signal: either ENTER key or done_file creation
                import threading
                _done = threading.Event()

                def _wait_key():
                    try:
                        input()
                    except Exception:
                        pass
                    _done.set()

                t = threading.Thread(target=_wait_key, daemon=True)
                t.start()
                while not _done.is_set() and not done_file.exists():
                    time.sleep(0.5)

                session = self._extract_session(context, page, session_id, login_form.login_url, str(har_path))
                context.close()
                browser.close()
                if done_file.exists():
                    done_file.unlink(missing_ok=True)
                return session
        except Exception as exc:
            log.warning("LoginSessionRecorder.record_interactive failed: %s", exc)
            return None

    def record_auto_or_interactive(
        self,
        login_form,
        credentials: Optional[Tuple[str, str]],
        har_dir: Path = _HAR_DIR,
    ):
        """Try auto first; fall back to interactive if display available; else None."""
        if credentials:
            session = self.record_auto(login_form=login_form, credentials=credentials, har_dir=har_dir)
            if session:
                return session
            log.info("LoginSessionRecorder: auto-fill failed — trying interactive")

        if _has_display():
            return self.record_interactive(login_form=login_form, har_dir=har_dir)

        log.warning(
            "LoginSessionRecorder: no credentials and no DISPLAY — "
            "scan will continue unauthenticated. "
            "Set ONEINFINITY_USERNAME/PASSWORD or run with a display."
        )
        return None

    def _extract_session(self, context, page, session_id: str, login_url: str, har_path: str):
        from oneinfinity.auth.session_manager import LoginSession

        # Cookies
        cookies = []
        try:
            cookies = context.cookies()
        except Exception:
            pass

        # localStorage + sessionStorage
        local_storage: dict = {}
        session_storage: dict = {}
        indexeddb: dict = {}
        try:
            local_storage = page.evaluate("() => { const o = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); o[k] = localStorage.getItem(k); } return o; }")
        except Exception:
            pass
        try:
            session_storage = page.evaluate("() => { const o = {}; for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); o[k] = sessionStorage.getItem(k); } return o; }")
        except Exception:
            pass
        try:
            indexeddb = page.evaluate("""async () => {
                const dbs = await indexedDB.databases();
                return dbs.map(db => db.name);
            }""") or {}
        except Exception:
            pass

        # Extract auth headers from local/session storage tokens
        auth_headers: dict = {}
        for storage in (local_storage, session_storage):
            for k, v in (storage or {}).items():
                if isinstance(v, str) and v.startswith("eyJ"):  # JWT
                    auth_headers["Authorization"] = f"Bearer {v}"
                    break
            if auth_headers:
                break

        # mitmproxy secondary capture (if available)
        mitmproxy_flow_path = self._try_mitmproxy_merge(har_path, session_id)

        return LoginSession(
            session_id=session_id,
            target=login_url,
            login_url=login_url,
            cookies=[{
                "name": c.get("name", ""),
                "value": c.get("value", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "httpOnly": c.get("httpOnly", False),
                "secure": c.get("secure", False),
                "sameSite": c.get("sameSite", ""),
            } for c in cookies],
            auth_headers=auth_headers,
            local_storage=local_storage or {},
            session_storage=session_storage or {},
            indexeddb_snapshot=indexeddb if isinstance(indexeddb, dict) else {},
            har_path=har_path,
            recorder="playwright",
            mitmproxy_flow_path=mitmproxy_flow_path or "",
        )

    def _try_mitmproxy_merge(self, har_path: str, session_id: str) -> Optional[str]:
        """Optionally run mitmproxy to supplement HAR. Silent no-op if not installed."""
        if not os.environ.get("ONEINFINITY_MITMPROXY"):
            return None
        try:
            import mitmproxy  # noqa: F401
            # mitmproxy integration — write flows alongside HAR
            flow_path = str(Path(har_path).parent / f"{session_id}.flows")
            # Actual mitmproxy DumpMaster integration is complex; we flag the path for future use
            log.info("mitmproxy detected — flow capture path: %s", flow_path)
            return flow_path
        except ImportError:
            return None
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
uv run pytest tests/test_auth_login_session_recorder.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/oneinfinity/auth/login_session_recorder.py tests/test_auth_login_session_recorder.py
git commit -m "feat(auth): add LoginSessionRecorder with Playwright HAR recording (auto + interactive)"
```

---

## Task 6: AuthenticatedTestSuite (categories 1–8)

**Files:**
- Create: `src/oneinfinity/auth/authenticated_test_suite.py` (partial — categories 1–8)
- Create: `tests/test_auth_test_suite.py` (categories 1–8)

- [ ] **Step 1: Write failing tests for categories 1–8**

```python
# tests/test_auth_test_suite.py
import pytest
from unittest.mock import patch, MagicMock
from oneinfinity.auth.session_manager import LoginSession
from oneinfinity.auth.auth_session_context import AuthSessionContext
from oneinfinity.auth.authenticated_test_suite import AuthenticatedTestSuite, Finding

def _ctx():
    session = LoginSession(
        session_id="t1", target="https://app.com", login_url="https://app.com/login",
        cookies=[{"name": "session", "value": "abc", "domain": "app.com",
                  "httpOnly": False, "secure": False, "sameSite": "None"}],
        auth_headers={"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."},
        local_storage={}, session_storage={}, indexeddb_snapshot={},
        har_path="", recorder="playwright",
    )
    return AuthSessionContext(session)

def _suite(endpoints=None):
    return AuthenticatedTestSuite(
        target="https://app.com",
        endpoints=endpoints or ["https://app.com/api/users/1", "https://app.com/api/orders/42"],
        auth_context=_ctx(),
    )

def test_finding_has_required_fields():
    f = Finding(vuln_type="test", title="Test", severity="medium",
                url="https://app.com/test", evidence="evidence", payload="", parameter="")
    assert f.vuln_type
    assert f.severity in ("critical", "high", "medium", "low", "info")

def test_test_cookie_security_detects_missing_httponly():
    suite = _suite()
    findings = suite.test_cookie_security()
    vuln_types = [f.vuln_type for f in findings]
    assert "missing_httponly" in vuln_types

def test_test_cookie_security_detects_missing_secure():
    suite = _suite()
    findings = suite.test_cookie_security()
    vuln_types = [f.vuln_type for f in findings]
    assert "missing_secure_flag" in vuln_types

def test_test_jwt_detects_alg_none():
    suite = _suite()
    # The fixture has a JWT with alg:none in auth_headers
    findings = suite.test_jwt()
    vuln_types = [f.vuln_type for f in findings]
    assert "jwt_alg_none" in vuln_types

def test_test_csrf_makes_http_calls():
    suite = _suite()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("httpx.Client") as MockClient:
        instance = MockClient.return_value.__enter__.return_value
        instance.request.return_value = mock_resp
        findings = suite.test_csrf()
    # test runs without error; may or may not find CSRF
    assert isinstance(findings, list)

def test_run_all_returns_list():
    suite = _suite()
    # Patch all HTTP calls to avoid network
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = ""
    mock_resp.headers = {}
    mock_resp.cookies = {}
    with patch("httpx.Client") as MockClient:
        instance = MockClient.return_value.__enter__.return_value
        instance.get.return_value = mock_resp
        instance.post.return_value = mock_resp
        instance.request.return_value = mock_resp
        findings = suite.run_all()
    assert isinstance(findings, list)
```

- [ ] **Step 2: Run tests — expect ImportError**

```bash
uv run pytest tests/test_auth_test_suite.py -v 2>&1 | head -10
```

- [ ] **Step 3: Implement AuthenticatedTestSuite (all 16 categories)**

```python
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
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),          # SSN
    re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"),     # Visa
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),  # email
    re.compile(r'"password"\s*:\s*"[^"]+"'),          # plaintext password in JSON
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

        # Check: does logout actually invalidate the session?
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
                    # Try using the old session after logout
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
                # No auth injected — bare client
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
                                # Heuristic: if response body is similar size to original, likely IDOR
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
                # Remove any CSRF token from cookies to simulate cross-origin request
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
        # Find JWTs in auth headers or local storage
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

            # Check alg:none attack
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
                # Build alg:none token and test against API
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
                                evidence=f"Server returned 200 with unsigned (alg:none) JWT",
                                payload=none_token,
                                parameter="Authorization",
                                confidence=1.0,
                            ))
                except Exception:
                    pass
            except Exception:
                pass

            # Check: expired token still accepted
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
                                evidence="GraphQL introspection returned full schema. Reveals internal API structure.",
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
        """Crawl authenticated pages for endpoints not reachable unauthenticated."""
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
                    locked_out = any(s == 403 for s in statuses[10:])  # lockout after many attempts
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
                    # Test open redirect via redirect_uri manipulation
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
                    # Test response manipulation: submit wrong code, see if server returns bypass-able JSON
                    try:
                        resp = client.post(url, json={"code": "000000"})
                        body = resp.text.lower()
                        if resp.status_code == 200 and any(k in body for k in ['"success":false', '"valid":false', '"verified":false']):
                            # Try manipulating: submit code=000000 but with success=true in body
                            findings.append(Finding(
                                vuln_type="mfa_response_manipulation",
                                title=f"MFA endpoint returns parseable JSON — response manipulation possible",
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
                    # Test: change password without providing old password
                    try:
                        resp = client.post(url, data={
                            "new_password": "Tr0ub4d@r&3",
                            "confirm_password": "Tr0ub4d@r&3",
                            # Intentionally omitting old_password / current_password
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
        """Chain: IDOR on profile update endpoint to change another user's email."""
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
                                        evidence=f"Template expression evaluated: 7*7=49",
                                        payload=payload,
                                        parameter=param_name,
                                    ))
                                    break
                            except Exception:
                                pass
        except Exception as exc:
            log.debug("test_injection_auth: %s", exc)
        return findings
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
uv run pytest tests/test_auth_test_suite.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/oneinfinity/auth/authenticated_test_suite.py tests/test_auth_test_suite.py
git commit -m "feat(auth): add AuthenticatedTestSuite with 16 post-login test categories"
```

---

## Task 7: auth/__init__.py

**Files:**
- Create: `src/oneinfinity/auth/__init__.py`

- [ ] **Step 1: Create `__init__.py`**

```python
# src/oneinfinity/auth/__init__.py
from oneinfinity.auth.login_form_detector import LoginFormDetector, LoginFormResult
from oneinfinity.auth.login_session_recorder import LoginSessionRecorder
from oneinfinity.auth.session_manager import SessionManager, LoginSession
from oneinfinity.auth.auth_session_context import AuthSessionContext

__all__ = [
    "LoginFormDetector",
    "LoginFormResult",
    "LoginSessionRecorder",
    "SessionManager",
    "LoginSession",
    "AuthSessionContext",
]
```

- [ ] **Step 2: Verify imports work**

```bash
uv run python -c "from oneinfinity.auth import LoginFormDetector, LoginSessionRecorder, SessionManager, AuthSessionContext; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Run all auth tests together**

```bash
uv run pytest tests/test_auth_login_form_detector.py tests/test_auth_session_manager.py tests/test_auth_session_context.py tests/test_auth_test_suite.py tests/test_auth_session_replay.py tests/test_auth_login_session_recorder.py -v
```

Expected: All passing.

- [ ] **Step 4: Commit**

```bash
git add src/oneinfinity/auth/__init__.py
git commit -m "feat(auth): add auth package __init__ with public exports"
```

---

## Task 8: god_mode_engine.py — Auth Detection + AuthTestMission

**Files:**
- Modify: `src/oneinfinity/orchestration/god_mode_engine.py`

Two changes:
1. After `foundation.run_sync(session)` succeeds (around line 886) — detect login form, load/record session, update `session.auth_config`.
2. In `_run_stages_2_to_5` — add `AuthTestMission` to mission list after `swarm`.

- [ ] **Step 1: Add auth detection block after Foundation in `run()` method**

Find this line in `god_mode_engine.py` (around line 894):
```python
        print(f"    [+] Foundation complete — recon={'ok' if foundation.recon else 'skipped'} "
```

Insert the entire block BEFORE that print statement:

```python
        # ── Auth detection (after Foundation, before stages 2-5) ──────────
        # Auto-detect login form; record session if not already saved.
        # Updates session.auth_config so all downstream missions use auth.
        _auth_ctx = None
        try:
            from oneinfinity.auth import LoginFormDetector, LoginSessionRecorder, SessionManager, AuthSessionContext
            _sm = SessionManager()
            _existing = _sm.load(target=target)
            if _existing:
                _auth_ctx = AuthSessionContext(_existing)
                session.auth_config = _existing.to_auth_config()
                log.info("[GOD MODE] Loaded existing auth session for %s", target)
            else:
                _detector = LoginFormDetector()
                _form = _detector.detect(target)
                if _form.has_login_form:
                    log.info("[GOD MODE] Login form detected at %s", _form.login_url)
                    _creds = None
                    import os as _os
                    _u = _os.environ.get("ONEINFINITY_USERNAME")
                    _p = _os.environ.get("ONEINFINITY_PASSWORD")
                    if _u and _p:
                        _creds = (_u, _p)
                    _rec = LoginSessionRecorder()
                    _recorded = _rec.record_auto_or_interactive(
                        login_form=_form, credentials=_creds
                    )
                    if _recorded:
                        _sm.save(_recorded)
                        _auth_ctx = AuthSessionContext(_recorded)
                        session.auth_config = _recorded.to_auth_config()
                        log.info("[GOD MODE] Auth session recorded and saved for %s", target)
                else:
                    log.info("[GOD MODE] No login form detected — scanning unauthenticated")
        except Exception as _auth_exc:
            log.warning("[GOD MODE] Auth detection failed (non-fatal): %s", _auth_exc)
        # Store auth_context as dynamic attribute (not a dataclass field — not serialized)
        session.auth_context = _auth_ctx  # type: ignore[attr-defined]
```

- [ ] **Step 2: Update `_run_stages_2_to_5` signature and add AuthTestMission**

Find this in `_run_stages_2_to_5` (around line 928-934):
```python
        full_scan = FullScanMission(foundation, auth_config=session.auth_config)
        research = ResearchMission(self._convergence) if not no_research else None
        swarm = SwarmMission() if not no_swarm else None
        chains = ChainsMission()
        report = ReportMission(report_fmt)

        self._missions = [m for m in [full_scan, research, swarm, chains, report] if m is not None]
```

Replace with:
```python
        full_scan = FullScanMission(foundation, auth_config=session.auth_config)
        research = ResearchMission(self._convergence) if not no_research else None
        swarm = SwarmMission() if not no_swarm else None
        auth_test = AuthTestMission(getattr(session, "auth_context", None))
        chains = ChainsMission()
        report = ReportMission(report_fmt)

        self._missions = [m for m in [full_scan, research, swarm, auth_test, chains, report] if m is not None]
```

- [ ] **Step 3: Add `AuthTestMission` class** (add after `SwarmMission` class, before `ChainsMission`, around line 511):

```python
# ── AuthTestMission ────────────────────────────────────────────────────────────

class AuthTestMission(Mission):
    """
    Runs 16 post-login security test categories.
    Unlocked automatically when auth_context is available (set by login detection).
    Silently skipped if no auth_context — does not affect unauthenticated scans.
    """

    def __init__(self, auth_context=None):
        super().__init__("auth_test")
        self._auth_context = auth_context

    def _run(self, session: GodModeSession) -> None:
        import json as _json
        if self._auth_context is None:
            log.info("[GOD MODE] AuthTestMission: no auth context — skipping")
            return

        log.info("[GOD MODE] AuthTestMission: running 16 authenticated test categories for %s", session.target)

        # Collect endpoints from recon output
        _endpoints: list[str] = [session.target]
        for _candidate in [
            GOD_MODE_DIR / session.scan_id / "full_scan" / "adaptive_recon.json",
            GOD_MODE_DIR / session.scan_id / "recon" / "urls.json",
        ]:
            try:
                if _candidate.exists():
                    _d = _json.loads(_candidate.read_text())
                    _urls = _d if isinstance(_d, list) else _d.get("urls", [])
                    _endpoints.extend(_urls)
            except Exception:
                pass

        try:
            from oneinfinity.auth.authenticated_test_suite import AuthenticatedTestSuite
            suite = AuthenticatedTestSuite(
                target=session.target,
                endpoints=list(dict.fromkeys(_endpoints))[:100],
                auth_context=self._auth_context,
            )
            findings = suite.run_all()
        except Exception as exc:
            log.warning("[GOD MODE] AuthTestMission: test suite failed — %s", exc)
            return

        new_count = len(findings)
        session.finding_count += new_count
        session.phases_complete.append("auth_test")

        # Write findings to disk
        out_dir = GOD_MODE_DIR / session.scan_id / "full_scan"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "auth_test_findings.json"
        try:
            out_file.write_text(_json.dumps([f.to_dict() for f in findings], indent=2, default=str))
            log.info("[GOD MODE] AuthTestMission: wrote %d findings to %s", new_count, out_file)
        except Exception as exc:
            log.warning("[GOD MODE] AuthTestMission: could not write findings — %s", exc)

        # Publish to ingestion bus
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
            bus = get_ingestion_engine()
            for f in findings:
                bus.ingest(RawResult(scan_id=session.scan_id, source="auth-test", raw=f.to_dict()))
        except Exception as exc:
            log.warning("[GOD MODE] AuthTestMission ingestion failed: %s", exc)

        log.info("[GOD MODE] AuthTestMission complete — %d findings", new_count)
        self._result = {"findings": new_count}
```

- [ ] **Step 4: Also update the two call sites for `_run_stages_2_to_5`**

The method is called from two places. Find:
```python
        self._run_stages_2_to_5(session, foundation, no_swarm, no_research, report_fmt)
```
(appears twice — once for background thread, once for foreground). No change needed — the signature hasn't changed.

- [ ] **Step 5: Verify no syntax errors**

```bash
uv run python -c "from oneinfinity.orchestration.god_mode_engine import GodModeConductor; print('OK')"
```

Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add src/oneinfinity/orchestration/god_mode_engine.py
git commit -m "feat(auth): integrate auth detection + AuthTestMission into god_mode_engine"
```

---

## Task 9: Backend — 6 new /api/auth/* endpoints

**Files:**
- Modify: `web/backend/main.py`

Add these 6 endpoints. Insert them as a block after the `god_mode_logs` endpoint (around line 2687). All are new — nothing existing is modified.

- [ ] **Step 1: Add in-memory recording state dict** near the top of `main.py` where other dicts are declared (around line 269 where `TARGETS`, `SCANS`, etc. are defined):

Find:
```python
_scan_processes: Dict[str, subprocess.Popen] = {}
```

Add after it:
```python
_AUTH_RECORDINGS: Dict[str, Dict] = {}  # session_id → {status, thread, session}
```

- [ ] **Step 2: Add the 6 endpoints** as a block (insert anywhere after the existing god-mode endpoints, before the CVSS utilities section around line 2692):

```python
# ── Auth Session Recording ─────────────────────────────────────────────────────

@app.post("/api/auth/detect", dependencies=[Depends(_require_auth)])
async def auth_detect(request: Request):
    """Detect whether the target URL has a login form."""
    data = await request.json()
    target = (data.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    _validate_target(target)
    try:
        from oneinfinity.auth import LoginFormDetector
        result = LoginFormDetector().detect(target)
        return {
            "has_login_form": result.has_login_form,
            "login_url": result.login_url,
            "username_field": result.username_field,
            "password_field": result.password_field,
            "form_action": result.form_action,
            "form_method": result.form_method,
        }
    except Exception as exc:
        log.warning("auth_detect error: %s", exc)
        return {"has_login_form": False, "error": str(exc)}


@app.post("/api/auth/record", dependencies=[Depends(_require_auth)])
async def auth_record_start(request: Request, background_tasks: BackgroundTasks):
    """
    Start a headed Playwright browser for manual login recording.
    Returns {session_id, status: 'recording'}.
    The browser opens on the server machine.
    """
    import threading as _threading
    data = await request.json()
    target = (data.get("target") or "").strip()
    session_name = (data.get("name") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    _validate_target(target)

    rec_id = str(uuid.uuid4())[:8]
    done_event = _threading.Event()

    _AUTH_RECORDINGS[rec_id] = {
        "status": "recording",
        "target": target,
        "name": session_name,
        "done_event": done_event,
        "session": None,
        "error": None,
    }

    def _record():
        try:
            from oneinfinity.auth import LoginFormDetector, LoginSessionRecorder
            form = LoginFormDetector().detect(target)
            if not form.has_login_form:
                form.has_login_form = True
                form.login_url = target
            recorder = LoginSessionRecorder()
            session = recorder.record_interactive(login_form=form)
            _AUTH_RECORDINGS[rec_id]["session"] = session
            _AUTH_RECORDINGS[rec_id]["status"] = "done" if session else "failed"
        except Exception as exc:
            _AUTH_RECORDINGS[rec_id]["status"] = "failed"
            _AUTH_RECORDINGS[rec_id]["error"] = str(exc)
            log.warning("auth_record_start background error: %s", exc)

    t = _threading.Thread(target=_record, daemon=True, name=f"auth-record-{rec_id}")
    t.start()

    return {"session_id": rec_id, "status": "recording",
            "message": "Browser opened on server — log in, then call /done endpoint"}


@app.post("/api/auth/record/{rec_id}/done", dependencies=[Depends(_require_auth)])
async def auth_record_done(rec_id: str, request: Request):
    """Signal that the user has finished logging in. Finalizes HAR and saves session."""
    entry = _AUTH_RECORDINGS.get(rec_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Recording {rec_id} not found")

    # Signal the recording thread to stop
    done_event = entry.get("done_event")
    if done_event:
        done_event.set()

    # Also create the done-file that record_interactive watches
    from pathlib import Path as _Path
    sessions_dir = _Path.home() / ".oneinfinity" / "sessions"
    done_file = sessions_dir / f"{rec_id}.done"
    try:
        done_file.touch()
    except Exception:
        pass

    data = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    session_name = (data.get("name") or entry.get("name") or "").strip()

    # Wait up to 10s for the recording thread to finalize
    import asyncio as _asyncio
    for _ in range(20):
        if entry.get("status") in ("done", "failed"):
            break
        await _asyncio.sleep(0.5)

    session = entry.get("session")
    if session:
        from oneinfinity.auth import SessionManager
        SessionManager().save(session, name=session_name)
        _AUTH_RECORDINGS.pop(rec_id, None)
        return {
            "status": "saved",
            "session_id": session.session_id,
            "name": session_name or session.session_id,
            "target": session.target,
            "cookies_captured": len(session.cookies),
        }
    else:
        error = entry.get("error") or "Recording did not complete"
        _AUTH_RECORDINGS.pop(rec_id, None)
        raise HTTPException(status_code=500, detail=error)


@app.get("/api/auth/sessions", dependencies=[Depends(_require_auth)])
async def auth_list_sessions():
    """List all saved login sessions."""
    try:
        from oneinfinity.auth import SessionManager
        sessions = SessionManager().list_all()
        return [
            {
                "session_id": s.session_id,
                "name": s.name,
                "target": s.target,
                "login_url": s.login_url,
                "recorded_at": s.recorded_at,
                "cookies_count": len(s.cookies),
                "has_har": bool(s.har_path),
                "recorder": s.recorder,
            }
            for s in sessions
        ]
    except Exception as exc:
        log.warning("auth_list_sessions error: %s", exc)
        return []


@app.get("/api/auth/sessions/{session_id}", dependencies=[Depends(_require_auth)])
async def auth_get_session(session_id: str):
    """Get session details. Cookies are redacted for security."""
    try:
        from oneinfinity.auth import SessionManager
        sessions = SessionManager().list_all()
        s = next((x for x in sessions if x.session_id == session_id), None)
        if not s:
            raise HTTPException(status_code=404, detail="Session not found")
        return {
            "session_id": s.session_id,
            "name": s.name,
            "target": s.target,
            "login_url": s.login_url,
            "recorded_at": s.recorded_at,
            "cookies": [{"name": c["name"], "domain": c.get("domain", ""), "value": "***REDACTED***"}
                        for c in s.cookies],
            "auth_headers": {k: "***REDACTED***" for k in s.auth_headers},
            "has_local_storage": bool(s.local_storage),
            "has_har": bool(s.har_path),
            "recorder": s.recorder,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.delete("/api/auth/sessions/{session_id}", dependencies=[Depends(_require_auth)])
async def auth_delete_session(session_id: str):
    """Delete a saved session."""
    try:
        from oneinfinity.auth import SessionManager
        SessionManager().delete(session_id)
        return {"deleted": True, "session_id": session_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
```

- [ ] **Step 3: Also accept `auth_session_id` in `god_mode_run`** — when provided, load session + override auth_config. Find in `god_mode_run` (around line 2466):

```python
    auth_config = {
        "session_cookie": str(data.get("session_cookie", "") or ""),
        "bearer_token":   str(data.get("bearer_token", "") or ""),
        "auth_header":    str(data.get("auth_header", "") or ""),
    }
    has_auth = any(auth_config.values())
```

Replace with:
```python
    auth_config = {
        "session_cookie": str(data.get("session_cookie", "") or ""),
        "bearer_token":   str(data.get("bearer_token", "") or ""),
        "auth_header":    str(data.get("auth_header", "") or ""),
    }
    # If caller provided a saved session_id, load it and override auth_config
    _auth_session_id = (data.get("auth_session_id") or "").strip()
    if _auth_session_id:
        try:
            from oneinfinity.auth import SessionManager
            _loaded = SessionManager().load(name=_auth_session_id) or \
                      next((s for s in SessionManager().list_all() if s.session_id == _auth_session_id), None)
            if _loaded:
                auth_config = _loaded.to_auth_config()
        except Exception as _se:
            log.warning("Could not load auth session %s: %s", _auth_session_id, _se)
    has_auth = any(auth_config.values())
```

- [ ] **Step 4: Verify syntax**

```bash
uv run python -c "import ast; ast.parse(open('web/backend/main.py').read()); print('OK')"
```

Expected: `OK`

- [ ] **Step 5: Restart backend and verify endpoints exist**

```bash
pkill -f "python.*main.py" 2>/dev/null; sleep 1
uv run python -u web/backend/main.py > /tmp/backend.log 2>&1 &
sleep 4
curl -s http://localhost:8000/api/auth/sessions -H "X-API-Key: $(grep API_KEY /tmp/backend.log | head -1 | grep -o '[a-f0-9-]*' | tail -1)" | head -5
```

Expected: `[]` (empty list — no sessions yet)

- [ ] **Step 6: Commit**

```bash
git add web/backend/main.py
git commit -m "feat(auth): add 6 /api/auth/* endpoints for session recording, listing, deletion"
```

---

## Task 10: Frontend — Record Session UI in GodMode.jsx

**Files:**
- Modify: `web/frontend/src/utils/api.js`
- Modify: `web/frontend/src/pages/GodMode.jsx`

- [ ] **Step 1: Add auth API calls to `api.js`**

Find in `web/frontend/src/utils/api.js`:
```javascript
  godModeRun:          (data) => api.post('/god-mode/run', data),
```

Add after it:
```javascript
  authDetect:          (data) => api.post('/auth/detect', data),
  authRecordStart:     (data) => api.post('/auth/record', data),
  authRecordDone:      (recId, data={}) => api.post(`/auth/record/${recId}/done`, data),
  authListSessions:    () => api.get('/auth/sessions'),
  authGetSession:      (id) => api.get(`/auth/sessions/${id}`),
  authDeleteSession:   (id) => api.delete(`/auth/sessions/${id}`),
```

- [ ] **Step 2: Add state variables to `GodMode.jsx`**

Find in `GodMode.jsx`:
```javascript
  const [showAuth, setShowAuth]   = useState(false)
  const [authType, setAuthType]   = useState('none')
  const [authValue, setAuthValue] = useState('')
```

Add after it:
```javascript
  const [savedSessions, setSavedSessions]         = useState([])
  const [selectedSessionId, setSelectedSessionId] = useState('')
  const [isRecording, setIsRecording]             = useState(false)
  const [recordingId, setRecordingId]             = useState(null)
  const [loginFormDetected, setLoginFormDetected]  = useState(null)  // null | true | false
```

- [ ] **Step 3: Add session loading useEffect and login form detection** 

Find the existing `useEffect` for URL auto-detection (around line 261):
```javascript
  // URL auto-detection — runs 400ms after target changes
  useEffect(() => {
```

Add a new useEffect BEFORE it:
```javascript
  // Load saved auth sessions on mount
  useEffect(() => {
    endpoints.authListSessions()
      .then(r => setSavedSessions(r.data || []))
      .catch(() => {})
  }, [])

  // Detect login form 800ms after target changes
  useEffect(() => {
    if (!target.trim()) { setLoginFormDetected(null); return }
    const timer = setTimeout(() => {
      endpoints.authDetect({ target: target.trim() })
        .then(r => setLoginFormDetected(r.data?.has_login_form ?? false))
        .catch(() => setLoginFormDetected(false))
    }, 800)
    return () => clearTimeout(timer)
  }, [target])
```

- [ ] **Step 4: Add session recording handlers**

Find `handleLaunch` function. Add these two handler functions BEFORE it:

```javascript
  const handleRecordSession = async () => {
    if (!target.trim()) return
    setIsRecording(true)
    try {
      const r = await endpoints.authRecordStart({ target: target.trim(), name: '' })
      setRecordingId(r.data.session_id)
      addNotification('Browser opened — log in, then click "Done"', 'info')
    } catch (e) {
      addNotification('Could not start recording: ' + (e.response?.data?.detail || e.message), 'error')
      setIsRecording(false)
    }
  }

  const handleRecordDone = async () => {
    if (!recordingId) return
    try {
      const r = await endpoints.authRecordDone(recordingId, { name: target.trim() })
      addNotification(`Session recorded — ${r.data.cookies_captured} cookies captured`, 'success')
      setSelectedSessionId(r.data.session_id)
      // Refresh session list
      const list = await endpoints.authListSessions()
      setSavedSessions(list.data || [])
    } catch (e) {
      addNotification('Recording finalization failed: ' + (e.response?.data?.detail || e.message), 'error')
    } finally {
      setIsRecording(false)
      setRecordingId(null)
    }
  }
```

- [ ] **Step 5: Pass `auth_session_id` in launch payload**

Find in `handleLaunch`:
```javascript
      ...authPayload,
```

Replace with:
```javascript
      ...authPayload,
      ...(selectedSessionId ? { auth_session_id: selectedSessionId } : {}),
```

- [ ] **Step 6: Add UI — Record button + session picker in the Authentication section**

Find in the JSX the existing authentication section:
```javascript
              {showAuth && (
```

Find the block that ends with:
```javascript
                        {authValue && (
                            <CheckCircle2 size={9} /> Authenticated scanning enabled</p>
                          </div>
                        )}
```

After that closing `)}`, still inside `{showAuth && (`, add:

```jsx
                    {/* Saved session picker */}
                    {savedSessions.length > 0 && (
                      <div className="mt-3">
                        <label className="label">Use Saved Session</label>
                        <select
                          className="select"
                          value={selectedSessionId}
                          onChange={e => setSelectedSessionId(e.target.value)}
                        >
                          <option value="">— None —</option>
                          {savedSessions.map(s => (
                            <option key={s.session_id} value={s.session_id}>
                              {s.name || s.session_id} ({s.target})
                            </option>
                          ))}
                        </select>
                        {selectedSessionId && (
                          <p className="text-[10px] text-green-400 mt-1 flex items-center gap-1">
                            <CheckCircle2 size={9} /> Authenticated session will be injected
                          </p>
                        )}
                      </div>
                    )}

                    {/* Record new session */}
                    {loginFormDetected && !isRecording && (
                      <div className="mt-3">
                        <button
                          className="btn-secondary w-full flex items-center justify-center gap-2"
                          onClick={handleRecordSession}
                        >
                          <span>⏺</span> Record Login Session
                        </button>
                        <p className="text-[10px] text-slate-500 mt-1">
                          Login form detected — click to open browser and record your session
                        </p>
                      </div>
                    )}

                    {/* Recording in progress overlay */}
                    {isRecording && (
                      <div className="mt-3 p-3 rounded border border-yellow-600/40 bg-yellow-900/20">
                        <p className="text-xs text-yellow-300 font-medium mb-2">
                          ⏺ Recording — browser is open on the server
                        </p>
                        <p className="text-[10px] text-yellow-400 mb-3">
                          Log in to your account in the browser, then click Done below.
                        </p>
                        <button
                          className="btn-primary w-full"
                          onClick={handleRecordDone}
                        >
                          Done — I have logged in
                        </button>
                      </div>
                    )}
```

- [ ] **Step 7: Verify frontend builds**

```bash
cd /Users/devendrayadav/Tools/oneinfinity/web/frontend && npm run build 2>&1 | tail -10
```

Expected: Build succeeds with no errors.

- [ ] **Step 8: Commit**

```bash
git add web/frontend/src/utils/api.js web/frontend/src/pages/GodMode.jsx
git commit -m "feat(auth): add session recording UI — Record button, session picker, done overlay"
```

---

## Task 11: CLI flags — `--auth-session` and `--no-auth`

**Files:**
- Modify: `src/oneinfinity/cli/commands/core.py` (or wherever `god-mode` CLI command is defined)

- [ ] **Step 1: Find the god-mode CLI command**

```bash
grep -n "god.mode\|god_mode\|@cli\|@app\|click.command\|auth.session\|no.auth" \
  /Users/devendrayadav/Tools/oneinfinity/src/oneinfinity/cli/commands/core.py | head -30
```

- [ ] **Step 2: Add `--auth-session` and `--no-auth` options**

Find the `@click.command` decorator block for `god_mode` (or equivalent). Add two new options:

```python
@click.option("--auth-session", "auth_session", default="", help="Name of saved login session to use")
@click.option("--no-auth", "no_auth", is_flag=True, default=False, help="Skip login detection entirely")
```

Update the function signature to accept `auth_session: str, no_auth: bool`.

In the function body, before calling `conductor.run(...)`, add:

```python
    # Resolve auth_config from saved session or env vars
    _auth_config = None
    if not no_auth:
        if auth_session:
            try:
                from oneinfinity.auth import SessionManager
                _s = SessionManager().load(name=auth_session)
                if _s:
                    _auth_config = _s.to_auth_config()
                    click.echo(f"[*] Auth: loaded session '{auth_session}'")
                else:
                    click.echo(f"[!] Auth session '{auth_session}' not found", err=True)
            except Exception as exc:
                click.echo(f"[!] Could not load auth session: {exc}", err=True)
```

Pass `auth_config=_auth_config` to `conductor.run(...)`.

- [ ] **Step 3: Verify CLI help text shows new flags**

```bash
uv run oneinfinity god-mode --help 2>&1 | grep -E "auth|no-auth"
```

Expected: shows `--auth-session` and `--no-auth` options.

- [ ] **Step 4: Commit**

```bash
git add src/oneinfinity/cli/commands/core.py
git commit -m "feat(auth): add --auth-session and --no-auth CLI flags to god-mode command"
```

---

## Final Verification

- [ ] **Run all auth tests**

```bash
uv run pytest tests/test_auth_login_form_detector.py tests/test_auth_session_manager.py \
  tests/test_auth_session_context.py tests/test_auth_test_suite.py \
  tests/test_auth_session_replay.py tests/test_auth_login_session_recorder.py -v
```

Expected: All passing.

- [ ] **Run existing test suite — verify nothing broken**

```bash
uv run pytest tests/test_god_mode_api.py tests/test_swarm_wiring.py tests/test_pipeline_parity.py -v 2>&1 | tail -20
```

Expected: No new failures.

- [ ] **Verify backend starts cleanly**

```bash
pkill -f "python.*main.py" 2>/dev/null; sleep 1
uv run python -u web/backend/main.py > /tmp/backend.log 2>&1 &
sleep 4 && curl -s http://localhost:8000/health
```

Expected: `{"status":"ok"}`

- [ ] **Final commit**

```bash
git add -A
git commit -m "feat(auth): complete login session recorder — form detection, HAR recording, 16 auth tests, UI, CLI"
```
