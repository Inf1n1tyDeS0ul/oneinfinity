# tests/test_db_manager_recon_raw.py
"""Unit tests for new DBManager methods: check_and_save_finding, recon_assets, raw_findings."""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def pg_mgr_with_execute(execute_return=None):
    """Return a DBManager in postgres mode with a controllable mock connection."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"

    mock_result = MagicMock()
    mock_result.fetchone = AsyncMock(return_value=execute_return)
    mock_result.rowcount = 1

    async def _aiter():
        return
        yield  # make it an async generator

    mock_result.__aiter__ = lambda self=mock_result: _aiter()

    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value=mock_result)
    mock_conn.commit = AsyncMock()

    mock_pool = MagicMock()
    mock_pool.connection.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.connection.return_value.__aexit__ = AsyncMock(return_value=False)

    mgr._pg_pool = mock_pool
    return mgr, mock_conn, mock_result


# ── check_and_save_finding ───────────────────────────────────────────────────

def test_check_and_save_new_finding_returns_true():
    """When PG returns a row, finding is new — return True."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute(execute_return=("finding-abc",))
    finding = {
        "finding_id": "abc123", "scan_id": "scan1", "target": "example.com",
        "title": "XSS", "severity": "high", "vuln_type": "xss",
        "url": "https://example.com/q", "tool": "dalfox",
        "confidence": 0.9, "cvss": 8.0, "status": "new", "source_type": "tool",
    }
    result = mgr.sync_check_and_save_finding(finding)
    assert result is True


def test_check_and_save_duplicate_returns_false():
    """When PG returns no row (ON CONFLICT DO NOTHING), finding is duplicate — return False."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute(execute_return=None)
    finding = {
        "finding_id": "abc123", "scan_id": "scan1",
        "vuln_type": "xss", "url": "https://example.com/q",
    }
    result = mgr.sync_check_and_save_finding(finding)
    assert result is False


def test_check_and_save_sqlite_mode_stores_and_returns_true():
    """In sqlite mode, check_and_save_finding uses SQLite dedup and returns True for new."""
    import core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_conn_ctx = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None  # no duplicate found
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock(return_value=mock_cursor)
    mock_conn_ctx.commit = MagicMock()

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        finding = {
            "finding_id": "abc123", "scan_id": "scan1", "target": "example.com",
            "title": "XSS", "severity": "high", "vuln_type": "xss",
            "url": "https://example.com/q", "tool": "dalfox",
            "confidence": 0.9, "cvss": 8.0, "status": "new", "source_type": "tool",
            "created_at": "2026-04-07T00:00:00",
        }
        result = mgr.sync_check_and_save_finding(finding)
    assert result is True
