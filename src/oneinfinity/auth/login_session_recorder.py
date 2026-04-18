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
                            page.fill('input[type="text"]', username)
                            page.fill('input[type="email"]', username)
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

        cookies = []
        try:
            cookies = context.cookies()
        except Exception:
            pass

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

        auth_headers: dict = {}
        for storage in (local_storage, session_storage):
            for k, v in (storage or {}).items():
                if isinstance(v, str) and v.startswith("eyJ"):  # JWT
                    auth_headers["Authorization"] = f"Bearer {v}"
                    break
            if auth_headers:
                break

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
            flow_path = str(Path(har_path).parent / f"{session_id}.flows")
            log.info("mitmproxy detected — flow capture path: %s", flow_path)
            return flow_path
        except ImportError:
            return None
