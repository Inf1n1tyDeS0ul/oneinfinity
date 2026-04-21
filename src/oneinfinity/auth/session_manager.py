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
    warning: str = ""  # non-empty if session captured in a suspicious state

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
    return hashlib.sha256(target.encode()).hexdigest()[:16]


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
        # If named, sanitize to a safe filename (strip URL schemes, replace path separators)
        if name:
            import re as _re
            safe_name = _re.sub(r"[^\w\-.]", "_", name)[:128]
            named_path = self._dir / f"{safe_name}.json"
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
            log.warning("SessionManager: failed to read %s — %s", path, exc)
            return None
