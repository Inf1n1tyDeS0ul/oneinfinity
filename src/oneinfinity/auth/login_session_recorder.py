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
        """Auto-fill form with credentials. SPA-aware: waits for JS render, tries multiple selectors.
        Returns LoginSession or None."""
        if not credentials:
            log.info("LoginSessionRecorder.record_auto: no credentials provided — skipping")
            return None

        username, password = credentials
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        except ImportError:
            log.error("LoginSessionRecorder: Playwright not installed")
            return None

        session_id = str(uuid.uuid4())[:8]
        har_dir.mkdir(parents=True, exist_ok=True)
        har_path = har_dir / f"{session_id}.har"

        _EMAIL_SELECTORS = [
            f'[name="{login_form.username_field}"]' if login_form.username_field else None,
            'input[type="email"]', 'input[name="email"]', 'input[name="username"]',
            'input[type="text"][name*="user"]', 'input[type="text"][name*="email"]',
            'input[placeholder*="email" i]', 'input[placeholder*="username" i]',
            'input[autocomplete="email"]', 'input[autocomplete="username"]',
            'input[id*="email" i]', 'input[id*="user" i]', 'input[type="text"]',
        ]
        _PASS_SELECTORS = [
            f'[name="{login_form.password_field}"]' if login_form.password_field else None,
            'input[type="password"]', 'input[name="password"]',
            'input[id*="pass" i]', 'input[placeholder*="password" i]',
        ]
        _SUBMIT_SELECTORS = [
            'button[type="submit"]', 'input[type="submit"]',
            'button:has-text("Sign in")', 'button:has-text("Log in")',
            'button:has-text("Login")', 'button:has-text("Continue")',
            'button:has-text("Next")', '[data-testid*="submit"]',
            '[data-testid*="login"]', '[data-testid*="sign"]',
        ]

        def _fill(page, selectors, value, field_name):
            for sel in (s for s in selectors if s):
                try:
                    el = page.locator(sel).first
                    if el.count() > 0:
                        el.click(timeout=2000)
                        el.fill(value, timeout=2000)
                        log.info("record_auto: filled %s with selector '%s'", field_name, sel)
                        return sel
                except Exception:
                    continue
            log.warning("record_auto: could not fill %s", field_name)
            return None

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    record_har_path=str(har_path),
                    record_har_mode="full",
                    ignore_https_errors=True,
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                )
                page = context.new_page()
                try:
                    page.goto(login_form.login_url, timeout=30000, wait_until="networkidle")
                except PWTimeout:
                    page.goto(login_form.login_url, timeout=30000, wait_until="domcontentloaded")
                    time.sleep(2)  # SPA render time

                time.sleep(1)  # Extra wait for React to mount
                _fill(page, _EMAIL_SELECTORS, username, "username/email")
                _fill(page, _PASS_SELECTORS, password, "password")

                submitted = False
                for sel in _SUBMIT_SELECTORS:
                    try:
                        el = page.locator(sel).first
                        if el.count() > 0:
                            el.click(timeout=4000)
                            submitted = True
                            break
                    except Exception:
                        continue
                if not submitted:
                    try:
                        page.locator('input[type="password"]').first.press("Enter", timeout=2000)
                    except Exception:
                        page.keyboard.press("Enter")

                try:
                    page.wait_for_load_state("networkidle", timeout=15000)
                except Exception:
                    time.sleep(3)

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
        cancel_file: Optional[Path] = None,
        on_session=None,
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

        print(f"\n[DEBUG] record_interactive: session_id={session_id}")
        print(f"[DEBUG] done_file={done_file}")
        print(f"[DEBUG] cancel_file={cancel_file}")
        print(f"\n[*] Opening browser for manual login at: {login_form.login_url}")
        print(f"    Log in, then press ENTER here (or create file: {done_file})")

        # Clean up any stale cancel file before launching so it doesn't fire immediately.
        if cancel_file and cancel_file.exists():
            try:
                cancel_file.unlink(missing_ok=True)
            except Exception:
                pass

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=False)
                context = browser.new_context(
                    record_har_path=str(har_path),
                    record_har_mode="full",
                    ignore_https_errors=True,
                )
                page = context.new_page()
                try:
                    page.goto(login_form.login_url, timeout=60000, wait_until="domcontentloaded")
                except Exception as exc:
                    log.warning("LoginSessionRecorder: goto timeout/error (browser still open, navigate manually): %s", exc)
                    try:
                        page.goto("about:blank")
                    except Exception:
                        pass

                # Wait for done_file (created by /api/auth/record/{id}/done endpoint).
                # Max 10 minutes; stdin is not used — server context has no terminal.
                print(f"[DEBUG] browser launched, waiting for done_file: {done_file}")
                deadline = time.time() + 600
                while not done_file.exists() and time.time() < deadline:
                    if cancel_file and cancel_file.exists():
                        log.info("LoginSessionRecorder: cancel signal received — closing browser")
                        cancel_file.unlink(missing_ok=True)
                        try:
                            context.close()
                        except Exception:
                            pass
                        try:
                            browser.close()
                        except Exception:
                            pass
                        return None
                    time.sleep(0.5)

                log.info("LoginSessionRecorder: done signal received — waiting for page to settle")
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

                # Detect if still on login page — wait up to 30s for post-login redirect.
                _login_indicators = ("/login", "/signin", "/sign-in", "/auth/login",
                                     "/account/login", "/user/login", "returnTo", "redirect")
                _extra_deadline = time.time() + 30
                while time.time() < _extra_deadline:
                    current_url = page.url
                    if not any(ind in current_url for ind in _login_indicators):
                        break
                    log.info("LoginSessionRecorder: still on login page (%s) — waiting for redirect...", current_url)
                    try:
                        page.wait_for_url(
                            lambda u: not any(ind in u for ind in _login_indicators),
                            timeout=3000,
                        )
                        break
                    except Exception:
                        pass

                current_url = page.url
                on_login_page = any(ind in current_url for ind in _login_indicators)
                log.info("LoginSessionRecorder: final page url: %s (on_login_page=%s)", current_url, on_login_page)

                session = self._extract_session(context, page, session_id, login_form.login_url, str(har_path))
                log.info("LoginSessionRecorder: session extracted: cookies=%d on_login_page=%s",
                         len(session.cookies) if session else 0, on_login_page)

                # Tag session with warning if captured on login page
                if session and on_login_page:
                    session.warning = "Captured on login page — authentication may not be complete. Re-record after fully logging in."
                elif session:
                    session.warning = ""

                # Signal session immediately — before slow browser teardown.
                if on_session:
                    try:
                        on_session(session)
                    except Exception:
                        pass
                if done_file.exists():
                    done_file.unlink(missing_ok=True)
                context.close()
                browser.close()
                return session
        except Exception as exc:
            log.warning("LoginSessionRecorder.record_interactive failed: %s", exc)
            raise

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
            log.info("_extract_session: captured %d cookies from context", len(cookies))
        except Exception as e:
            log.warning("_extract_session: cookies() failed: %s", e)

        # Use the active page (last page in context, most likely post-login)
        try:
            pages = context.pages
            if pages:
                page = pages[-1]
        except Exception:
            pass

        local_storage: dict = {}
        session_storage: dict = {}
        indexeddb: dict = {}
        try:
            local_storage = page.evaluate("() => { const o = {}; for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); o[k] = localStorage.getItem(k); } return o; }")
            log.info("_extract_session: local_storage keys=%d", len(local_storage))
        except Exception as e:
            log.warning("_extract_session: localStorage eval failed: %s", e)
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
