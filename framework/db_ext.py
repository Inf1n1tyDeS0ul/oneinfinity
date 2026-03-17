"""Extended findings DB — adds scan_sessions, recon_assets, surface_items, vuln_candidates."""

import json
import sqlite3
from modules.findings import FindingsDB

EXT_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT,
    auth_type     TEXT,
    auth_ref      TEXT,
    phase_reached INTEGER DEFAULT 0,
    status        TEXT DEFAULT 'running',
    started_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at  DATETIME
);

CREATE TABLE IF NOT EXISTS recon_assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER,
    asset_type   TEXT,
    value        TEXT NOT NULL,
    source       TEXT,
    status_code  INTEGER,
    tech_stack   TEXT,
    is_in_scope  INTEGER DEFAULT 1,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS surface_items (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER,
    item_type    TEXT,
    host         TEXT,
    value        TEXT,
    method       TEXT,
    extra        TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vuln_candidates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER,
    vuln_type    TEXT,
    host         TEXT,
    endpoint     TEXT,
    parameter    TEXT,
    method       TEXT,
    payload      TEXT,
    evidence     TEXT,
    confidence   TEXT,
    validated    INTEGER DEFAULT 0,
    finding_id   INTEGER,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


class ExtendedDB(FindingsDB):
    def __init__(self, db_path: str):
        super().__init__(db_path)
        self.conn.executescript(EXT_SCHEMA)
        self.conn.commit()

    # ── Sessions ──────────────────────────────────────────────────────────────

    def new_session(self, target: str, auth_type: str, auth_ref: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scan_sessions (target, auth_type, auth_ref) VALUES (?,?,?)",
            (target, auth_type, auth_ref),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_session(self, session_id: int, **kwargs):
        if not kwargs:
            return
        sets = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [session_id]
        self.conn.execute(f"UPDATE scan_sessions SET {sets} WHERE id=?", vals)
        self.conn.commit()

    def get_session(self, session_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM scan_sessions WHERE id=?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def last_session(self, target: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM scan_sessions WHERE target=? ORDER BY id DESC LIMIT 1",
            (target,),
        ).fetchone()
        return dict(row) if row else None

    # ── Recon assets ──────────────────────────────────────────────────────────

    def save_asset(self, session_id: int, asset_type: str, value: str,
                   source: str = None, status_code: int = None,
                   tech_stack: str = None, is_in_scope: int = 1):
        self.conn.execute(
            "INSERT INTO recon_assets "
            "(session_id, asset_type, value, source, status_code, tech_stack, is_in_scope) "
            "VALUES (?,?,?,?,?,?,?)",
            (session_id, asset_type, value, source, status_code, tech_stack, is_in_scope),
        )
        self.conn.commit()

    def get_assets(self, session_id: int, asset_type: str = None) -> list[dict]:
        q = "SELECT * FROM recon_assets WHERE session_id=?"
        params: list = [session_id]
        if asset_type:
            q += " AND asset_type=?"
            params.append(asset_type)
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    # ── Surface items ─────────────────────────────────────────────────────────

    def save_surface_item(self, session_id: int, item_type: str, host: str,
                          value: str, method: str = None, extra: dict = None):
        self.conn.execute(
            "INSERT INTO surface_items (session_id, item_type, host, value, method, extra) "
            "VALUES (?,?,?,?,?,?)",
            (session_id, item_type, host, value, method,
             json.dumps(extra) if extra else None),
        )
        self.conn.commit()

    def get_surface(self, session_id: int, item_type: str = None) -> list[dict]:
        q = "SELECT * FROM surface_items WHERE session_id=?"
        params: list = [session_id]
        if item_type:
            q += " AND item_type=?"
            params.append(item_type)
        rows = self.conn.execute(q, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("extra"):
                try:
                    d["extra"] = json.loads(d["extra"])
                except Exception:
                    pass
            result.append(d)
        return result

    # ── Vuln candidates ───────────────────────────────────────────────────────

    def save_candidate(self, session_id: int, vuln_type: str, host: str,
                       endpoint: str, parameter: str = None, method: str = "GET",
                       payload: str = None, evidence: str = None,
                       confidence: str = "medium") -> int:
        cur = self.conn.execute(
            "INSERT INTO vuln_candidates "
            "(session_id, vuln_type, host, endpoint, parameter, method, payload, evidence, confidence) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (session_id, vuln_type, host, endpoint, parameter, method,
             payload, evidence, confidence),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_candidates(self, session_id: int, validated: int = None) -> list[dict]:
        q = "SELECT * FROM vuln_candidates WHERE session_id=?"
        params: list = [session_id]
        if validated is not None:
            q += " AND validated=?"
            params.append(validated)
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def confirm_candidate(self, candidate_id: int, finding_id: int):
        self.conn.execute(
            "UPDATE vuln_candidates SET validated=1, finding_id=? WHERE id=?",
            (finding_id, candidate_id),
        )
        self.conn.commit()
