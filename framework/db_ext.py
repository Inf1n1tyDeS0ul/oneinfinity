"""Extended findings DB — adds scan_sessions, fw_recon_assets, surface_items, vuln_candidates.

Storage: PostgreSQL via DBManager generic helpers (hard requirement).
"""

import json
import logging
from modules.findings import FindingsDB

log = logging.getLogger("oneinfinity.db_ext")


def _require_pg():
    """Return DBManager in PG mode, or raise if unavailable."""
    try:
        from core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            return mgr
    except Exception as exc:
        raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
    raise RuntimeError(
        "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
    )


class ExtendedDB(FindingsDB):
    def __init__(self, db_path: str):
        super().__init__(db_path)
        self._db_path = db_path

    # ── Sessions ──────────────────────────────────────────────────────────────

    def new_session(self, target: str, auth_type: str, auth_ref: str) -> int:
        rows = _require_pg().sync_pg_execute_read(
            "INSERT INTO scan_sessions (target, auth_type, auth_ref) "
            "VALUES (%s, %s, %s) RETURNING id",
            (target, auth_type, auth_ref),
        )
        return rows[0]["id"] if rows else -1

    def update_session(self, session_id: int, **kwargs):
        if not kwargs:
            return
        sets = ", ".join(f"{k}=%s" for k in kwargs)
        vals = tuple(kwargs.values()) + (session_id,)
        _require_pg().sync_pg_execute_write(
            f"UPDATE scan_sessions SET {sets} WHERE id=%s", vals
        )

    def get_session(self, session_id: int) -> dict | None:
        rows = _require_pg().sync_pg_execute_read(
            "SELECT * FROM scan_sessions WHERE id=%s", (session_id,)
        )
        return rows[0] if rows else None

    def last_session(self, target: str) -> dict | None:
        rows = _require_pg().sync_pg_execute_read(
            "SELECT * FROM scan_sessions WHERE target=%s ORDER BY id DESC LIMIT 1",
            (target,),
        )
        return rows[0] if rows else None

    # ── Recon assets ──────────────────────────────────────────────────────────

    def save_asset(self, session_id: int, asset_type: str, value: str,
                   source: str = None, status_code: int = None,
                   tech_stack: str = None, is_in_scope: int = 1):
        _require_pg().sync_pg_execute_write(
            "INSERT INTO fw_recon_assets "
            "(session_id, asset_type, value, source, status_code, tech_stack, is_in_scope) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (session_id, asset_type, value, source, status_code, tech_stack, is_in_scope),
        )

    def get_assets(self, session_id: int, asset_type: str = None) -> list[dict]:
        if asset_type:
            return _require_pg().sync_pg_execute_read(
                "SELECT * FROM fw_recon_assets WHERE session_id=%s AND asset_type=%s",
                (session_id, asset_type),
            )
        return _require_pg().sync_pg_execute_read(
            "SELECT * FROM fw_recon_assets WHERE session_id=%s", (session_id,)
        )

    # ── Surface items ─────────────────────────────────────────────────────────

    def save_surface_item(self, session_id: int, item_type: str, host: str,
                          value: str, method: str = None, extra: dict = None):
        _require_pg().sync_pg_execute_write(
            "INSERT INTO surface_items (session_id, item_type, host, value, method, extra) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (session_id, item_type, host, value, method,
             json.dumps(extra) if extra else None),
        )

    def get_surface(self, session_id: int, item_type: str = None) -> list[dict]:
        if item_type:
            return _require_pg().sync_pg_execute_read(
                "SELECT * FROM surface_items WHERE session_id=%s AND item_type=%s",
                (session_id, item_type),
            )
        return _require_pg().sync_pg_execute_read(
            "SELECT * FROM surface_items WHERE session_id=%s", (session_id,)
        )

    # ── Vuln candidates ───────────────────────────────────────────────────────

    def save_candidate(self, session_id: int, vuln_type: str, host: str,
                       endpoint: str, parameter: str = None, method: str = "GET",
                       payload: str = None, evidence: str = None,
                       confidence: str = "medium") -> int:
        rows = _require_pg().sync_pg_execute_read(
            "INSERT INTO vuln_candidates "
            "(session_id, vuln_type, host, endpoint, parameter, method, payload, evidence, confidence) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (session_id, vuln_type, host, endpoint, parameter, method,
             payload, evidence, confidence),
        )
        return rows[0]["id"] if rows else -1

    def get_candidates(self, session_id: int, validated: int = None) -> list[dict]:
        if validated is not None:
            return _require_pg().sync_pg_execute_read(
                "SELECT * FROM vuln_candidates WHERE session_id=%s AND validated=%s",
                (session_id, validated),
            )
        return _require_pg().sync_pg_execute_read(
            "SELECT * FROM vuln_candidates WHERE session_id=%s", (session_id,)
        )

    def confirm_candidate(self, candidate_id: int, finding_id: int):
        _require_pg().sync_pg_execute_write(
            "UPDATE vuln_candidates SET validated=1, finding_id=%s WHERE id=%s",
            (finding_id, candidate_id),
        )
