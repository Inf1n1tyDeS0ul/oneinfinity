"""
core/pg_client.py — psycopg3 connection management for async (FastAPI) and sync (CLI).

Async pool: used by FastAPI/web backend (fully async)
Sync conn:  used by CLI (synchronous, loop.run_until_complete wrapper)

Environment:
    POSTGRES_URL — e.g. postgresql://user:pass@localhost:5432/oneinfinity
                   or   postgresql://user:pass@rds.amazonaws.com/oneinfinity?sslmode=require
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Optional

log = logging.getLogger("oneinfinity.pg_client")

_async_pool: Optional[object] = None
_sync_conn: Optional[object] = None
_pool_lock = threading.Lock()
_conn_lock = threading.Lock()


async def get_async_pool() -> Optional[object]:
    """Return async psycopg3 connection pool, or None if Postgres unavailable."""
    global _async_pool
    if _async_pool is not None:
        # Return existing pool only if it's still open
        try:
            if not _async_pool.closed:
                return _async_pool
        except Exception:
            return _async_pool
        # Pool is closed — clear it and recreate below
        _async_pool = None
    url = os.environ.get("POSTGRES_URL", "").strip()
    if not url:
        return None
    # Acquire with timeout to avoid deadlock: threading.Lock held across await
    # causes concurrent callers to block forever without it.
    acquired = _pool_lock.acquire(timeout=10)
    if not acquired:
        return _async_pool  # may be None if init is still in progress
    try:
        if _async_pool is not None:
            # Post-lock double-check: also guard against a closed pool
            try:
                if not _async_pool.closed:
                    return _async_pool
            except Exception:
                return _async_pool
            _async_pool = None
        try:
            from psycopg_pool import AsyncConnectionPool
            pool = AsyncConnectionPool(
                conninfo=url,
                min_size=2,
                max_size=10,
                open=False,
                timeout=5.0,
                reconnect_timeout=0,
                max_idle=300,
            )
            await pool.open(wait=True, timeout=8)
            _async_pool = pool
            log.info("PostgreSQL async pool connected: %s", _safe_url(url))
            return _async_pool
        except Exception as exc:
            log.warning(
                "FALLBACK TRIGGERED: PostgreSQL connection failed (%s) — Postgres unavailable", exc
            )
            return None
    finally:
        _pool_lock.release()


def get_sync_conn() -> Optional[object]:
    """Return sync psycopg3 connection for CLI use, or None if unavailable."""
    global _sync_conn
    if _sync_conn is not None:
        try:
            _sync_conn.execute("SELECT 1")
            return _sync_conn
        except Exception:
            _sync_conn = None

    url = os.environ.get("POSTGRES_URL", "").strip()
    if not url:
        return None
    with _conn_lock:
        if _sync_conn is not None:
            return _sync_conn
        try:
            import psycopg
            _sync_conn = psycopg.connect(url, autocommit=False)
            log.info("PostgreSQL sync connection established: %s", _safe_url(url))
            return _sync_conn
        except Exception as exc:
            log.warning(
                "FALLBACK TRIGGERED: PostgreSQL connection failed (%s) — Postgres unavailable", exc
            )
            return None


async def close_pg() -> None:
    """Close both async pool and sync connection."""
    global _async_pool, _sync_conn
    if _async_pool is not None:
        try:
            await _async_pool.close()
        except Exception:
            pass
        _async_pool = None
    if _sync_conn is not None:
        try:
            _sync_conn.close()
        except Exception:
            pass
        _sync_conn = None


def _safe_url(url: str) -> str:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
        db = p.path or ""
        return f"postgresql://{host}{port}{db}"
    except Exception:
        return "postgresql://***"


# ── Council Run helpers ────────────────────────────────────────────────────────
# These are module-level async functions matching the existing pattern in this
# file (no class — the module IS the client).

_COUNCIL_RUN_COLS = (
    "surface_profile",
    "exploit_plan",
    "exploit_trace",
    "mutation_report",
    "post_exploit_report",
    "validated_finding",
    "overall_success",
    "objective_artifact",
    "finding_count",
    "completed_at",
)


async def upsert_council_run(scan_id: str, target: str, **kwargs) -> int:
    """INSERT council_runs row or UPDATE on duplicate scan_id.

    Returns the row id.
    """
    import json

    pool = await get_async_pool()
    if pool is None:
        log.debug("upsert_council_run: Postgres unavailable — skipping")
        return -1

    # Build optional field assignments
    extra_cols = [c for c in _COUNCIL_RUN_COLS if c in kwargs]
    _json_cols = {"surface_profile", "exploit_plan", "exploit_trace",
                  "mutation_report", "post_exploit_report", "validated_finding",
                  "reproduction_steps"}

    def _serialise(col: str, val: object) -> object:
        if col in _json_cols and val is not None and not isinstance(val, str):
            return json.dumps(val)
        return val

    values: list = [scan_id, target] + [_serialise(c, kwargs[c]) for c in extra_cols]
    placeholders = ", ".join(f"${i + 3}" for i in range(len(extra_cols)))
    col_list = ", ".join(extra_cols)

    if extra_cols:
        update_clause = ", ".join(f"{c} = EXCLUDED.{c}" for c in extra_cols)
        sql = (
            f"INSERT INTO council_runs (scan_id, target, {col_list}) "
            f"VALUES ($1, $2, {placeholders}) "
            f"ON CONFLICT (scan_id) DO UPDATE SET {update_clause} "
            f"RETURNING id"
        )
    else:
        sql = (
            "INSERT INTO council_runs (scan_id, target) VALUES ($1, $2) "
            "ON CONFLICT (scan_id) DO UPDATE SET scan_id = EXCLUDED.scan_id "
            "RETURNING id"
        )

    try:
        async with pool.connection() as conn:
            row = await conn.fetchrow(sql, *values)
            return row["id"] if row else -1
    except Exception as exc:
        log.warning("upsert_council_run failed: %s", exc)
        return -1


async def update_council_run(run_id: int, **kwargs) -> None:
    """UPDATE council_runs SET <kwargs fields> WHERE id = run_id."""
    import json

    if not kwargs:
        return
    pool = await get_async_pool()
    if pool is None:
        return

    _json_cols = {"surface_profile", "exploit_plan", "exploit_trace",
                  "mutation_report", "post_exploit_report", "validated_finding"}

    def _serialise(col: str, val: object) -> object:
        if col in _json_cols and val is not None and not isinstance(val, str):
            return json.dumps(val)
        return val

    cols = list(kwargs.keys())
    vals = [_serialise(c, kwargs[c]) for c in cols] + [run_id]
    set_clause = ", ".join(f"{c} = ${i + 1}" for i, c in enumerate(cols))
    sql = f"UPDATE council_runs SET {set_clause} WHERE id = ${len(vals)}"

    try:
        async with pool.connection() as conn:
            await conn.execute(sql, *vals)
    except Exception as exc:
        log.warning("update_council_run failed: %s", exc)


async def insert_council_finding(council_run_id: int, scan_id: str, finding: dict) -> int:
    """INSERT a row into council_findings, returns new row id."""
    import json


    pool = await get_async_pool()
    if pool is None:
        return -1

    _json_cols = {"reproduction_steps"}
    cols = ["council_run_id", "scan_id"] + [k for k in finding]
    placeholders = ", ".join(f"${i + 1}" for i in range(len(cols)))
    values: list = [council_run_id, scan_id]
    for k, v in finding.items():
        if k in _json_cols and v is not None and not isinstance(v, str):
            values.append(json.dumps(v))
        else:
            values.append(v)

    col_list = ", ".join(cols)
    sql = f"INSERT INTO council_findings ({col_list}) VALUES ({placeholders}) RETURNING id"

    try:
        async with pool.connection() as conn:
            row = await conn.fetchrow(sql, *values)
            return row["id"] if row else -1
    except Exception as exc:
        log.warning("insert_council_finding failed: %s", exc)
        return -1


async def get_council_run(scan_id: str) -> "dict | None":
    """SELECT council_runs WHERE scan_id = scan_id, returns dict or None."""
    pool = await get_async_pool()
    if pool is None:
        return None

    sql = "SELECT * FROM council_runs WHERE scan_id = $1 ORDER BY id DESC LIMIT 1"
    try:
        async with pool.connection() as conn:
            row = await conn.fetchrow(sql, scan_id)
            return dict(row) if row else None
    except Exception as exc:
        log.warning("get_council_run failed: %s", exc)
        return None


async def get_council_findings(scan_id: str) -> "list[dict]":
    """SELECT council_findings WHERE scan_id = scan_id, returns list of dicts."""
    pool = await get_async_pool()
    if pool is None:
        return []

    sql = "SELECT * FROM council_findings WHERE scan_id = $1 ORDER BY id ASC"
    try:
        async with pool.connection() as conn:
            rows = await conn.fetch(sql, scan_id)
            return [dict(r) for r in rows]
    except Exception as exc:
        log.warning("get_council_findings failed: %s", exc)
        return []


async def save_council_run(
    scan_id: str,
    target: str,
    surface_profile: dict,
    exploit_plan: dict,
    exploit_trace: dict,
    overall_success: bool,
    findings_count: int,
) -> bool:
    """Persist an AICouncilMission run to the council_runs table. Returns True on success."""
    pool = await get_async_pool()
    if pool is None:
        return False
    try:
        import json as _json
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO council_runs
                    (scan_id, target, surface_profile, exploit_plan, exploit_trace,
                     overall_success, findings_count, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s, NOW())
                ON CONFLICT (scan_id) DO UPDATE SET
                    surface_profile = EXCLUDED.surface_profile,
                    exploit_plan    = EXCLUDED.exploit_plan,
                    exploit_trace   = EXCLUDED.exploit_trace,
                    overall_success = EXCLUDED.overall_success,
                    findings_count  = EXCLUDED.findings_count
                """,
                (
                    scan_id, target,
                    _json.dumps(surface_profile),
                    _json.dumps(exploit_plan),
                    _json.dumps(exploit_trace),
                    overall_success,
                    findings_count,
                ),
            )
        return True
    except Exception as exc:
        log.warning("save_council_run failed: %s", exc)
        return False


async def store_recon_findings(
    scan_id: str,
    target: str,
    finding_type: str,
    findings: list,
) -> int:
    """
    Persist recon findings (secrets, endpoints, credentials) to recon_findings table.
    Creates the table if it does not yet exist.
    Returns the number of rows inserted.
    """
    import json as _json

    pool = await get_async_pool()
    if pool is None:
        log.debug("store_recon_findings: Postgres unavailable — skipping")
        return 0

    try:
        async with pool.connection() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS recon_findings (
                    id          SERIAL PRIMARY KEY,
                    scan_id     TEXT NOT NULL,
                    target      TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    data        JSONB,
                    created_at  TIMESTAMPTZ DEFAULT NOW()
                )
                """
            )
            count = 0
            for f in findings:
                data_str = _json.dumps(f) if not isinstance(f, str) else f
                await conn.execute(
                    "INSERT INTO recon_findings (scan_id, target, finding_type, data) "
                    "VALUES ($1, $2, $3, $4)",
                    scan_id, target, finding_type, data_str,
                )
                count += 1
            return count
    except Exception as exc:
        log.warning("store_recon_findings failed: %s", exc)
        return 0
