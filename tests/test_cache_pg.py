# tests/test_cache_pg.py
"""
Tests for ReconCache PG-first path.

All tests mock DBManager so no real Postgres connection is needed.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pg_mgr(read_return=None):
    """Return a mock DBManager that looks like PG mode."""
    mgr = MagicMock()
    mgr.mode = "postgres"
    mgr.sync_pg_execute_write.return_value = 1
    mgr.sync_pg_execute_read.return_value = read_return if read_return is not None else []
    return mgr


def _cache_with_pg(mgr, tmp_path: Path):
    """
    Build a ReconCache wired to the given mock mgr.

    We patch get_db_manager_sync so _pg() returns our mock, and also
    supply a tmp_path so the SQLite fallback doesn't write to the real
    location (even though it won't be used in PG mode).
    """
    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
    return cache


# ---------------------------------------------------------------------------
# Test 1 — set() calls sync_pg_execute_write with SQL containing 'recon_cache'
# ---------------------------------------------------------------------------

def test_set_calls_pg_execute_write(tmp_path):
    mgr = _make_pg_mgr()

    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
        cache.set("subfinder", "target.com", ["sub1.target.com"], ttl=3600)

    mgr.sync_pg_execute_write.assert_called_once()
    call_args = mgr.sync_pg_execute_write.call_args
    sql = call_args[0][0]  # first positional arg
    assert "recon_cache" in sql, f"SQL should mention recon_cache, got: {sql}"
    # Verify ON CONFLICT upsert pattern
    assert "ON CONFLICT" in sql or "INSERT" in sql


def test_set_pg_params_contain_tool_target_data(tmp_path):
    """set() must pass correct column values to PG."""
    mgr = _make_pg_mgr()

    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
        cache.set("httpx", "example.org", {"alive": True}, extra="port443", ttl=60)

    params = mgr.sync_pg_execute_write.call_args[0][1]
    # params order: cache_key, tool, target, extra, data, created_at, expires_at
    assert "httpx" in params
    assert "example.org" in params
    assert "port443" in params
    assert json.dumps({"alive": True}) in params


# ---------------------------------------------------------------------------
# Test 2 — get() calls sync_pg_execute_read
# ---------------------------------------------------------------------------

def test_get_calls_pg_execute_read_cache_miss(tmp_path):
    """get() must call sync_pg_execute_read and return None on a miss."""
    mgr = _make_pg_mgr(read_return=[])

    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
        result = cache.get("subfinder", "target.com")

    mgr.sync_pg_execute_read.assert_called_once()
    assert result is None


def test_get_calls_pg_execute_read_cache_hit(tmp_path):
    """get() must deserialise the data field returned by PG."""
    payload = ["sub1.target.com", "sub2.target.com"]
    mgr = _make_pg_mgr(read_return=[{"data": json.dumps(payload)}])

    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
        result = cache.get("subfinder", "target.com")

    mgr.sync_pg_execute_read.assert_called_once()
    assert result == payload


def test_get_pg_sql_filters_by_cache_key_and_expires_at(tmp_path):
    """The SELECT sent to PG must filter on cache_key and expires_at."""
    mgr = _make_pg_mgr(read_return=[])

    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
        cache.get("nuclei", "victim.io")

    sql, params = mgr.sync_pg_execute_read.call_args[0]
    assert "cache_key" in sql
    assert "expires_at" in sql
    assert len(params) == 2  # key + now


# ---------------------------------------------------------------------------
# Test 3 — clear_expired() calls sync_pg_execute_write
# ---------------------------------------------------------------------------

def test_clear_expired_calls_pg_execute_write(tmp_path):
    mgr = _make_pg_mgr()

    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
        cache.clear_expired()

    mgr.sync_pg_execute_write.assert_called_once()
    sql, params = mgr.sync_pg_execute_write.call_args[0]
    assert "recon_cache" in sql
    assert "expires_at" in sql
    # Params must contain a numeric timestamp
    assert len(params) == 1
    assert isinstance(params[0], float)


def test_sweep_expired_is_same_as_clear_expired(tmp_path):
    """sweep_expired() and clear_expired() must both hit PG."""
    mgr = _make_pg_mgr()

    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
        cache.sweep_expired()

    mgr.sync_pg_execute_write.assert_called_once()


# ---------------------------------------------------------------------------
# Test 4 — invalidate() uses PG path
# ---------------------------------------------------------------------------

def test_invalidate_calls_pg_execute_write(tmp_path):
    mgr = _make_pg_mgr()

    with patch("core.cache.ReconCache._pg", return_value=mgr):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "test_cache.db")
        cache.invalidate("nuclei", "victim.io")

    mgr.sync_pg_execute_write.assert_called_once()
    sql, params = mgr.sync_pg_execute_write.call_args[0]
    assert "recon_cache" in sql
    assert "cache_key" in sql


# ---------------------------------------------------------------------------
# Test 5 — SQLite fallback when _pg() returns None
# ---------------------------------------------------------------------------

def test_set_falls_back_to_sqlite_when_no_pg(tmp_path):
    """When _pg() returns None, set() must write to the SQLite file."""
    with patch("core.cache.ReconCache._pg", return_value=None):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "fallback.db")
        cache.set("dalfox", "site.io", {"xss": True}, ttl=120)

    # Verify the SQLite file was created and contains the record
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "fallback.db"))
    rows = conn.execute("SELECT tool, target FROM recon_cache").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == "dalfox"
    assert rows[0][1] == "site.io"


def test_get_falls_back_to_sqlite_when_no_pg(tmp_path):
    """When _pg() returns None, get() must read from SQLite."""
    with patch("core.cache.ReconCache._pg", return_value=None):
        from core.cache import ReconCache
        cache = ReconCache(db_path=tmp_path / "fallback.db")
        cache.set("katana", "site.io", ["/path1", "/path2"], ttl=120)
        result = cache.get("katana", "site.io")

    assert result == ["/path1", "/path2"]
