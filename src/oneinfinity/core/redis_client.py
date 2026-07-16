"""
core/redis_client.py — Redis connection pool with graceful fallback.

Returns None when REDIS_URL is unset or Redis is unreachable.
Callers must handle None: if get_redis() is None, use local fallback.

Environment:
    REDIS_URL — e.g. redis://localhost:47294/0 or rediss://user:pass@host:6380/0
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Optional

log = logging.getLogger("oneinfinity.redis_client")

_pool: Optional[object] = None
_client: Optional[object] = None
_lock: threading.Lock = threading.Lock()


def get_redis() -> Optional["redis.Redis"]:
    """Return a Redis client, or None if Redis is unavailable."""
    global _pool, _client
    if _client is not None:      # fast path, no lock
        return _client
    with _lock:
        if _client is not None:  # re-check inside lock
            return _client
        redis_url = os.environ.get("REDIS_URL", "").strip()
        if not redis_url:
            return None
        try:
            import redis
            _pool = redis.ConnectionPool.from_url(
                redis_url,
                max_connections=20,
                socket_connect_timeout=3,
                socket_timeout=5,
                decode_responses=True,
            )
            _client = redis.Redis(connection_pool=_pool)
            _client.ping()
            log.info("Redis connected: %s", _safe_url(redis_url))
            return _client
        except Exception as exc:
            log.warning(
                "FALLBACK TRIGGERED: Redis connection failed (%s) — falling back to in-memory", exc
            )
            if _pool is not None:
                try:
                    _pool.disconnect()
                except Exception:
                    pass
            _client = None
            _pool = None
            return None


def close_redis() -> None:
    """Disconnect and reset the module-level Redis client."""
    global _pool, _client
    if _pool is not None:
        try:
            _pool.disconnect()
        except Exception:
            pass
    _pool = None
    _client = None


def _safe_url(url: str) -> str:
    """Strip credentials from Redis URL for logging."""
    try:
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url)
        return urlunparse(p._replace(netloc=p.hostname + (f":{p.port}" if p.port else "")))
    except Exception:
        return "redis://***"
