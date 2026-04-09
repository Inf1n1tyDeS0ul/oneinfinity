"""
Recon Cache — PostgreSQL-backed TTL cache for reconnaissance data.

Avoids re-running expensive tools (subfinder, katana, etc.) within the
same session or across sessions within the TTL window.

All operations go to the shared PostgreSQL ``recon_cache`` table
(defined in db/schema.sql). PostgreSQL is a hard requirement.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Optional

log = logging.getLogger(__name__)

# Default TTLs in seconds
DEFAULT_TTLS: dict[str, int] = {
    "subfinder":   6 * 3600,    # 6h — subdomain lists change slowly
    "httpx":       1 * 3600,    # 1h — liveness can change
    "katana":      2 * 3600,    # 2h — crawl results
    "waybackurls": 12 * 3600,   # 12h — historical, very stable
    "gauplus":     12 * 3600,
    "dnsx":        6 * 3600,
    "naabu":       1 * 3600,
    "nuclei":      30 * 60,     # 30m — findings can change after fixes
    "dalfox":      30 * 60,
    "sqlmap":      30 * 60,
    "default":     1 * 3600,
}


def _cache_key(tool: str, target: str, extra: str = "") -> str:
    raw = f"{tool}::{target}::{extra}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _require_pg():
    """Return DBManager in PG mode, or raise if unavailable."""
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            return mgr
    except Exception as exc:
        raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
    raise RuntimeError(
        "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
    )


class ReconCache:
    """PostgreSQL-backed TTL cache. PostgreSQL is a hard requirement."""

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def get(self, tool: str, target: str, extra: str = "") -> Optional[Any]:
        """Return cached data or None if missing/expired."""
        key = _cache_key(tool, target, extra)
        now = time.time()
        pg = _require_pg()
        rows = pg.sync_pg_execute_read(
            "SELECT data FROM recon_cache WHERE cache_key = %s AND expires_at > %s",
            (key, now),
        )
        if not rows:
            return None
        raw = rows[0]["data"]
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw

    def set(
        self,
        tool: str,
        target: str,
        data: Any,
        extra: str = "",
        ttl: Optional[int] = None,
    ) -> None:
        """Store data with a TTL (seconds). Uses DEFAULT_TTLS[tool] if ttl not given."""
        if ttl is None:
            ttl = DEFAULT_TTLS.get(tool, DEFAULT_TTLS["default"])
        key = _cache_key(tool, target, extra)
        now = time.time()
        serialised = json.dumps(data)
        _require_pg().sync_pg_execute_write(
            """
            INSERT INTO recon_cache
              (cache_key, tool, target, extra, data, created_at, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cache_key) DO UPDATE SET
              data       = EXCLUDED.data,
              expires_at = EXCLUDED.expires_at,
              created_at = EXCLUDED.created_at
            """,
            (key, tool, target, extra, serialised, now, now + ttl),
        )
        log.debug("Cached %s/%s (TTL %ds)", tool, target, ttl)

    def invalidate(self, tool: str, target: str, extra: str = "") -> None:
        """Force-remove a cache entry."""
        key = _cache_key(tool, target, extra)
        _require_pg().sync_pg_execute_write(
            "DELETE FROM recon_cache WHERE cache_key = %s", (key,)
        )

    def invalidate_target(self, target: str) -> int:
        """Remove all cache entries for a target. Returns rows deleted."""
        return _require_pg().sync_pg_execute_write(
            "DELETE FROM recon_cache WHERE target = %s", (target,)
        )

    def invalidate_tool(self, tool: str, target: str) -> int:
        """Remove all cache entries for a (tool, target) pair."""
        return _require_pg().sync_pg_execute_write(
            "DELETE FROM recon_cache WHERE tool = %s AND target = %s",
            (tool, target),
        )

    def sweep_expired(self) -> int:
        """Delete all expired entries. Returns rows deleted."""
        return _require_pg().sync_pg_execute_write(
            "DELETE FROM recon_cache WHERE expires_at < %s", (time.time(),)
        )

    def clear_expired(self) -> int:
        """Alias for sweep_expired()."""
        return self.sweep_expired()

    def stats(self) -> dict:
        pg = _require_pg()
        rows_total   = pg.sync_pg_execute_read("SELECT COUNT(*) AS cnt FROM recon_cache", ())
        rows_expired = pg.sync_pg_execute_read(
            "SELECT COUNT(*) AS cnt FROM recon_cache WHERE expires_at < %s",
            (time.time(),),
        )
        rows_by_tool = pg.sync_pg_execute_read(
            "SELECT tool, COUNT(*) AS cnt FROM recon_cache GROUP BY tool", ()
        )
        return {
            "total":   rows_total[0]["cnt"] if rows_total else 0,
            "expired": rows_expired[0]["cnt"] if rows_expired else 0,
            "by_tool": {r["tool"]: r["cnt"] for r in rows_by_tool},
        }

    def clear_all(self) -> None:
        _require_pg().sync_pg_execute_write("DELETE FROM recon_cache", ())

    # ------------------------------------------------------------------ #
    #  Context manager
    # ------------------------------------------------------------------ #

    def cached(self, tool: str, target: str, ttl: Optional[int] = None, extra: str = ""):
        """
        Context manager for caching function results.

        Usage:
            with cache.cached("subfinder", "target.com") as hit:
                if hit.hit is None:
                    result = run_tool()
                    hit.store(result)
        """
        return _CacheContext(self, tool, target, extra, ttl)


class _CacheContext:
    """Context manager returned by cache.cached()."""

    def __init__(self, cache: ReconCache, tool, target, extra, ttl):
        self._cache = cache
        self._tool = tool
        self._target = target
        self._extra = extra
        self._ttl = ttl
        self.hit: Optional[Any] = None

    def __enter__(self):
        self.hit = self._cache.get(self._tool, self._target, self._extra)
        return self

    def store(self, data: Any) -> None:
        self._cache.set(self._tool, self._target, data, self._extra, self._ttl)
        self.hit = data

    def __exit__(self, *args):
        pass


# Global singleton
recon_cache = ReconCache()
