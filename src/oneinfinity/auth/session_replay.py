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
