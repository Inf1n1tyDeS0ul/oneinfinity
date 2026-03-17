"""
Recon Cache — SQLite-backed TTL cache for reconnaissance data.

Avoids re-running expensive tools (subfinder, katana, etc.) within the
same session or across sessions within the TTL window.

Usage:
    cache = ReconCache()
    data = cache.get("subfinder", "target.com")
    if data is None:
        data = run_subfinder("target.com")
        cache.set("subfinder", "target.com", data, ttl=3600)
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

from path_manager import recon_cache_db_path

_DB_PATH = recon_cache_db_path()

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


class ReconCache:
    """Thread-safe SQLite cache with per-tool TTL support."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    # ------------------------------------------------------------------ #
    #  Connection (per-thread)
    # ------------------------------------------------------------------ #

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self) -> None:
        conn = self._conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS recon_cache (
                cache_key   TEXT PRIMARY KEY,
                tool        TEXT NOT NULL,
                target      TEXT NOT NULL,
                extra       TEXT DEFAULT '',
                data        TEXT NOT NULL,
                created_at  REAL NOT NULL,
                expires_at  REAL NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_target ON recon_cache(tool, target)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON recon_cache(expires_at)")
        conn.commit()

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def get(self, tool: str, target: str, extra: str = "") -> Optional[Any]:
        """Return cached data or None if missing/expired."""
        key = _cache_key(tool, target, extra)
        row = self._conn().execute(
            "SELECT data, expires_at FROM recon_cache WHERE cache_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        if time.time() > row["expires_at"]:
            self._conn().execute("DELETE FROM recon_cache WHERE cache_key = ?", (key,))
            self._conn().commit()
            log.debug("Cache expired: %s/%s", tool, target)
            return None
        try:
            return json.loads(row["data"])
        except json.JSONDecodeError:
            return row["data"]

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
        self._conn().execute(
            """
            INSERT OR REPLACE INTO recon_cache
              (cache_key, tool, target, extra, data, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (key, tool, target, extra, json.dumps(data), now, now + ttl),
        )
        self._conn().commit()
        log.debug("Cached %s/%s (TTL %ds)", tool, target, ttl)

    def invalidate(self, tool: str, target: str, extra: str = "") -> None:
        """Force-remove a cache entry."""
        key = _cache_key(tool, target, extra)
        self._conn().execute("DELETE FROM recon_cache WHERE cache_key = ?", (key,))
        self._conn().commit()

    def invalidate_target(self, target: str) -> int:
        """Remove all cache entries for a target. Returns rows deleted."""
        cur = self._conn().execute(
            "DELETE FROM recon_cache WHERE target = ?", (target,)
        )
        self._conn().commit()
        return cur.rowcount

    def invalidate_tool(self, tool: str, target: str) -> int:
        """Remove all cache entries for a (tool, target) pair."""
        cur = self._conn().execute(
            "DELETE FROM recon_cache WHERE tool = ? AND target = ?", (tool, target)
        )
        self._conn().commit()
        return cur.rowcount

    def sweep_expired(self) -> int:
        """Delete all expired entries. Returns rows deleted."""
        cur = self._conn().execute(
            "DELETE FROM recon_cache WHERE expires_at < ?", (time.time(),)
        )
        self._conn().commit()
        return cur.rowcount

    def stats(self) -> dict:
        conn = self._conn()
        total = conn.execute("SELECT COUNT(*) FROM recon_cache").fetchone()[0]
        expired = conn.execute(
            "SELECT COUNT(*) FROM recon_cache WHERE expires_at < ?", (time.time(),)
        ).fetchone()[0]
        by_tool = {}
        for row in conn.execute(
            "SELECT tool, COUNT(*) as cnt FROM recon_cache GROUP BY tool"
        ).fetchall():
            by_tool[row["tool"]] = row["cnt"]
        return {"total": total, "expired": expired, "by_tool": by_tool}

    def clear_all(self) -> None:
        self._conn().execute("DELETE FROM recon_cache")
        self._conn().commit()

    # ------------------------------------------------------------------ #
    #  Context manager
    # ------------------------------------------------------------------ #

    def cached(self, tool: str, target: str, ttl: Optional[int] = None, extra: str = ""):
        """
        Decorator / callable wrapper for caching function results.

        Usage:
            with cache.cached("subfinder", "target.com") as hit:
                if hit is None:
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
