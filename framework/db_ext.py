"""Extended findings DB — adds scan_sessions, fw_recon_assets, surface_items, vuln_candidates.

Storage: PG-first (via DBManager generic helpers) with SQLite fallback.
Note: FindingsDB no longer owns a SQLite connection (it delegates to ResultIngestionEngine),
so ExtendedDB manages its own SQLite connection for the fallback path.
"""

import json
import logging
import sqlite3
from pathlib import Path
from modules.findings import FindingsDB

log = logging.getLogger("oneinfinity.db_ext")

# SQLite DDL (fallback only) — uses local table names
_SQLITE_DDL = """
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

CREATE TABLE IF NOT EXISTS fw_recon_assets (
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
        pg = self._pg()
        if pg is not None:
            self._conn = None  # PG mode — no SQLite connection needed
        else:
            p = Path(db_path).expanduser()
            p.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(p), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_SQLITE_DDL)
            self._conn.commit()

    # ── PG helper ─────────────────────────────────────────────────────────────

    def _pg(self):
        """Return DBManager if running in PG/distributed mode, else None."""
        try:
            from core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            return mgr if mgr and mgr.mode in ("distributed", "postgres") else None
        except Exception:
            return None

    # ── Sessions ──────────────────────────────────────────────────────────────

    def new_session(self, target: str, auth_type: str, auth_ref: str) -> int:
        pg = self._pg()
        if pg is not None:
            try:
                rows = pg.sync_pg_execute_read(
                    "INSERT INTO scan_sessions (target, auth_type, auth_ref) "
                    "VALUES (%s, %s, %s) RETURNING id",
                    (target, auth_type, auth_ref),
                )
                return rows[0]["id"] if rows else -1
            except Exception as exc:
                log.warning("PG new_session failed, falling back to SQLite: %s", exc)
        cur = self._conn.execute(
            "INSERT INTO scan_sessions (target, auth_type, auth_ref) VALUES (?,?,?)",
            (target, auth_type, auth_ref),
        )
        self._conn.commit()
        return cur.lastrowid

    def update_session(self, session_id: int, **kwargs):
        if not kwargs:
            return
        pg = self._pg()
        if pg is not None:
            try:
                sets = ", ".join(f"{k}=%s" for k in kwargs)
                vals = tuple(kwargs.values()) + (session_id,)
                pg.sync_pg_execute_write(
                    f"UPDATE scan_sessions SET {sets} WHERE id=%s", vals
                )
                return
            except Exception as exc:
                log.warning("PG update_session failed, falling back to SQLite: %s", exc)
        sets = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [session_id]
        self._conn.execute(f"UPDATE scan_sessions SET {sets} WHERE id=?", vals)
        self._conn.commit()

    def get_session(self, session_id: int) -> dict | None:
        pg = self._pg()
        if pg is not None:
            try:
                rows = pg.sync_pg_execute_read(
                    "SELECT * FROM scan_sessions WHERE id=%s", (session_id,)
                )
                return rows[0] if rows else None
            except Exception as exc:
                log.warning("PG get_session failed, falling back to SQLite: %s", exc)
        row = self._conn.execute(
            "SELECT * FROM scan_sessions WHERE id=?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def last_session(self, target: str) -> dict | None:
        pg = self._pg()
        if pg is not None:
            try:
                rows = pg.sync_pg_execute_read(
                    "SELECT * FROM scan_sessions WHERE target=%s ORDER BY id DESC LIMIT 1",
                    (target,),
                )
                return rows[0] if rows else None
            except Exception as exc:
                log.warning("PG last_session failed, falling back to SQLite: %s", exc)
        row = self._conn.execute(
            "SELECT * FROM scan_sessions WHERE target=? ORDER BY id DESC LIMIT 1",
            (target,),
        ).fetchone()
        return dict(row) if row else None

    # ── Recon assets ──────────────────────────────────────────────────────────

    def save_asset(self, session_id: int, asset_type: str, value: str,
                   source: str = None, status_code: int = None,
                   tech_stack: str = None, is_in_scope: int = 1):
        pg = self._pg()
        if pg is not None:
            try:
                pg.sync_pg_execute_write(
                    "INSERT INTO fw_recon_assets "
                    "(session_id, asset_type, value, source, status_code, tech_stack, is_in_scope) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (session_id, asset_type, value, source, status_code, tech_stack, is_in_scope),
                )
                return
            except Exception as exc:
                log.warning("PG save_asset failed, falling back to SQLite: %s", exc)
        self._conn.execute(
            "INSERT INTO fw_recon_assets "
            "(session_id, asset_type, value, source, status_code, tech_stack, is_in_scope) "
            "VALUES (?,?,?,?,?,?,?)",
            (session_id, asset_type, value, source, status_code, tech_stack, is_in_scope),
        )
        self._conn.commit()

    def get_assets(self, session_id: int, asset_type: str = None) -> list[dict]:
        pg = self._pg()
        if pg is not None:
            try:
                if asset_type:
                    return pg.sync_pg_execute_read(
                        "SELECT * FROM fw_recon_assets WHERE session_id=%s AND asset_type=%s",
                        (session_id, asset_type),
                    )
                return pg.sync_pg_execute_read(
                    "SELECT * FROM fw_recon_assets WHERE session_id=%s", (session_id,)
                )
            except Exception as exc:
                log.warning("PG get_assets failed, falling back to SQLite: %s", exc)
        q = "SELECT * FROM fw_recon_assets WHERE session_id=?"
        params: list = [session_id]
        if asset_type:
            q += " AND asset_type=?"
            params.append(asset_type)
        return [dict(r) for r in self._conn.execute(q, params).fetchall()]

    # ── Surface items ─────────────────────────────────────────────────────────

    def save_surface_item(self, session_id: int, item_type: str, host: str,
                          value: str, method: str = None, extra: dict = None):
        pg = self._pg()
        if pg is not None:
            try:
                pg.sync_pg_execute_write(
                    "INSERT INTO surface_items (session_id, item_type, host, value, method, extra) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (session_id, item_type, host, value, method,
                     json.dumps(extra) if extra else None),
                )
                return
            except Exception as exc:
                log.warning("PG save_surface_item failed, falling back to SQLite: %s", exc)
        self._conn.execute(
            "INSERT INTO surface_items (session_id, item_type, host, value, method, extra) "
            "VALUES (?,?,?,?,?,?)",
            (session_id, item_type, host, value, method,
             json.dumps(extra) if extra else None),
        )
        self._conn.commit()

    def get_surface(self, session_id: int, item_type: str = None) -> list[dict]:
        pg = self._pg()
        if pg is not None:
            try:
                if item_type:
                    rows = pg.sync_pg_execute_read(
                        "SELECT * FROM surface_items WHERE session_id=%s AND item_type=%s",
                        (session_id, item_type),
                    )
                else:
                    rows = pg.sync_pg_execute_read(
                        "SELECT * FROM surface_items WHERE session_id=%s", (session_id,)
                    )
                # extra is already a dict from JSONB in PG
                return rows
            except Exception as exc:
                log.warning("PG get_surface failed, falling back to SQLite: %s", exc)
        q = "SELECT * FROM surface_items WHERE session_id=?"
        params: list = [session_id]
        if item_type:
            q += " AND item_type=?"
            params.append(item_type)
        result = []
        for r in self._conn.execute(q, params).fetchall():
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
        pg = self._pg()
        if pg is not None:
            try:
                rows = pg.sync_pg_execute_read(
                    "INSERT INTO vuln_candidates "
                    "(session_id, vuln_type, host, endpoint, parameter, method, payload, evidence, confidence) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (session_id, vuln_type, host, endpoint, parameter, method,
                     payload, evidence, confidence),
                )
                return rows[0]["id"] if rows else -1
            except Exception as exc:
                log.warning("PG save_candidate failed, falling back to SQLite: %s", exc)
        cur = self._conn.execute(
            "INSERT INTO vuln_candidates "
            "(session_id, vuln_type, host, endpoint, parameter, method, payload, evidence, confidence) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (session_id, vuln_type, host, endpoint, parameter, method,
             payload, evidence, confidence),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_candidates(self, session_id: int, validated: int = None) -> list[dict]:
        pg = self._pg()
        if pg is not None:
            try:
                if validated is not None:
                    return pg.sync_pg_execute_read(
                        "SELECT * FROM vuln_candidates WHERE session_id=%s AND validated=%s",
                        (session_id, validated),
                    )
                return pg.sync_pg_execute_read(
                    "SELECT * FROM vuln_candidates WHERE session_id=%s", (session_id,)
                )
            except Exception as exc:
                log.warning("PG get_candidates failed, falling back to SQLite: %s", exc)
        q = "SELECT * FROM vuln_candidates WHERE session_id=?"
        params: list = [session_id]
        if validated is not None:
            q += " AND validated=?"
            params.append(validated)
        return [dict(r) for r in self._conn.execute(q, params).fetchall()]

    def confirm_candidate(self, candidate_id: int, finding_id: int):
        pg = self._pg()
        if pg is not None:
            try:
                pg.sync_pg_execute_write(
                    "UPDATE vuln_candidates SET validated=1, finding_id=%s WHERE id=%s",
                    (finding_id, candidate_id),
                )
                return
            except Exception as exc:
                log.warning("PG confirm_candidate failed, falling back to SQLite: %s", exc)
        self._conn.execute(
            "UPDATE vuln_candidates SET validated=1, finding_id=? WHERE id=?",
            (finding_id, candidate_id),
        )
        self._conn.commit()
