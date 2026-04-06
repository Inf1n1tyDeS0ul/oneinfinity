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
        return _async_pool
    url = os.environ.get("POSTGRES_URL", "").strip()
    if not url:
        return None
    with _pool_lock:
        if _async_pool is not None:
            return _async_pool
        try:
            from psycopg_pool import AsyncConnectionPool
            pool = AsyncConnectionPool(
                conninfo=url,
                min_size=2,
                max_size=10,
                open=False,
            )
            await pool.open()
            _async_pool = pool
            log.info("PostgreSQL async pool connected: %s", _safe_url(url))
            return _async_pool
        except Exception as exc:
            log.warning(
                "FALLBACK TRIGGERED: PostgreSQL connection failed (%s) — Postgres unavailable", exc
            )
            return None


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
