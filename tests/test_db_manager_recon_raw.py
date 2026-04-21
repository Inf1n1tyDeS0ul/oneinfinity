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
    import oneinfinity.core.db_manager as dm
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
    import oneinfinity.core.db_manager as dm
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


# ── save_recon_asset ──────────────────────────────────────────────────────────

def test_save_recon_asset_issues_pg_insert():
    """save_recon_asset in PG mode executes INSERT with correct args."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute()
    mgr.sync_save_recon_asset("asset1", "scan1", "subdomain", "sub.example.com", {"ip": "1.2.3.4"})
    mock_conn.execute.assert_called_once()
    sql, params = mock_conn.execute.call_args[0]
    assert "INSERT INTO recon_assets" in sql
    assert params[0] == "asset1"
    assert params[1] == "scan1"
    assert params[2] == "subdomain"
    assert params[3] == "sub.example.com"
    assert json.loads(params[4]) == {"ip": "1.2.3.4"}


def test_save_recon_asset_sqlite_mode():
    """save_recon_asset in sqlite mode writes to SQLite."""
    import oneinfinity.core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock()
    mock_conn_ctx.commit = MagicMock()

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        mgr.sync_save_recon_asset("a1", "s1", "endpoint", "/api/v1", {})
    mock_conn_ctx.execute.assert_called()


# ── get_recon_assets ──────────────────────────────────────────────────────────

def test_get_recon_assets_pg_mode_returns_list():
    """get_recon_assets in PG mode returns parsed list."""
    import oneinfinity.core.db_manager as dm
    import json
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"

    rows = [
        ("asset1", "scan1", "subdomain", "sub.example.com", json.dumps({"ip": "1.2.3.4"}), "2026-04-07T00:00:00"),
    ]

    async def fake_execute(sql, params=None):
        cursor = MagicMock()
        async def _aiter():
            for r in rows:
                yield r
        cursor.__aiter__ = lambda self=cursor: _aiter()
        return cursor

    mock_conn = AsyncMock()
    mock_conn.execute = fake_execute
    mock_pool = MagicMock()
    mock_pool.connection.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.connection.return_value.__aexit__ = AsyncMock(return_value=False)
    mgr._pg_pool = mock_pool

    result = mgr.sync_get_recon_assets(scan_id="scan1")
    assert len(result) == 1
    assert result[0]["asset_id"] == "asset1"
    assert result[0]["metadata"] == {"ip": "1.2.3.4"}


def test_get_recon_assets_sqlite_mode_returns_list():
    """get_recon_assets in sqlite mode returns parsed list from SQLite."""
    import oneinfinity.core.db_manager as dm
    from unittest.mock import patch, MagicMock
    import sqlite3
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.fetchall = MagicMock(return_value=[])
    mock_conn_ctx.row_factory = None

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        result = mgr.sync_get_recon_assets(scan_id="scan1")
    assert isinstance(result, list)


# ── store_raw_findings ────────────────────────────────────────────────────────

def test_store_raw_findings_pg_mode_returns_count():
    """store_raw_findings inserts each finding and returns count."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute()
    findings = [
        {"tool": "nuclei", "vuln_type": "xss", "url": "https://example.com"},
        {"tool": "dalfox", "vuln_type": "xss", "url": "https://example.com/q"},
    ]
    count = mgr.sync_store_raw_findings(findings)
    assert count == 2
    assert mock_conn.execute.call_count == 2


def test_store_raw_findings_sqlite_mode_returns_count():
    """store_raw_findings in sqlite mode inserts and returns count."""
    import oneinfinity.core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock()
    mock_conn_ctx.commit = MagicMock()

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        count = mgr.sync_store_raw_findings([{"tool": "nuclei"}, {"tool": "sqlmap"}])
    assert count == 2


# ── delete_findings_for_scan ─────────────────────────────────────────────────

def test_delete_findings_for_scan_pg_mode_returns_rowcount():
    """delete_findings_for_scan returns number of rows deleted."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute()
    mock_result.rowcount = 5
    mock_conn.execute = AsyncMock(return_value=mock_result)

    count = mgr.sync_delete_findings_for_scan("scan1")
    assert count == 5
    mock_conn.execute.assert_called_once()
    sql, params = mock_conn.execute.call_args[0]
    assert "DELETE FROM findings" in sql
    assert params == ("scan1",)


def test_delete_findings_for_scan_sqlite_mode():
    """delete_findings_for_scan in sqlite mode deletes and returns rowcount."""
    import oneinfinity.core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_cursor = MagicMock()
    mock_cursor.rowcount = 3
    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock(return_value=mock_cursor)
    mock_conn_ctx.commit = MagicMock()

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        count = mgr.sync_delete_findings_for_scan("scan1")
    assert count == 3


# ── finding_count ─────────────────────────────────────────────────────────────

def test_finding_count_pg_mode_returns_int():
    """finding_count returns integer count from PG."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute(execute_return=(7,))
    count = mgr.sync_finding_count("scan1")
    assert count == 7
    mock_conn.execute.assert_called_once()
    sql, params = mock_conn.execute.call_args[0]
    assert "COUNT(*)" in sql
    assert params == ("scan1",)


def test_finding_count_sqlite_mode():
    """finding_count in sqlite mode returns count."""
    import oneinfinity.core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (4,)
    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock(return_value=mock_cursor)

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        count = mgr.sync_finding_count("scan1")
    assert count == 4
