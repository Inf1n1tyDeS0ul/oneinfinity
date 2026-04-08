# tests/test_db_ext_pg.py
"""Tests verifying ExtendedDB routes writes/reads through DBManager in PG mode."""
import sys
import os
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _make_pg_mgr(read_results=None):
    mgr = MagicMock()
    mgr.mode = "postgres"
    mgr.sync_pg_execute_write = MagicMock(return_value=1)
    mgr.sync_pg_execute_read = MagicMock(return_value=read_results or [{"id": 1}])
    return mgr


def _make_db(tmp_path, pg_mgr=None):
    from framework.db_ext import ExtendedDB
    mock_mgr = pg_mgr or _make_pg_mgr()
    with patch("framework.db_ext.ExtendedDB._pg", return_value=mock_mgr):
        db = ExtendedDB(str(tmp_path / "ext.db"))
    return db, mock_mgr


# ── scan_sessions ─────────────────────────────────────────────────────────────

def test_new_session_calls_pg_execute_read_returning(tmp_path):
    """new_session() must use RETURNING id via sync_pg_execute_read."""
    db, mock_mgr = _make_db(tmp_path)

    with patch.object(db, "_pg", return_value=mock_mgr):
        sid = db.new_session("http://example.com", "bearer", "token-ref")

    assert mock_mgr.sync_pg_execute_read.called
    sql = mock_mgr.sync_pg_execute_read.call_args[0][0]
    assert "scan_sessions" in sql, f"Expected scan_sessions in SQL: {sql!r}"
    assert "RETURNING" in sql.upper()
    assert sid == 1


def test_update_session_calls_pg_execute_write(tmp_path):
    """update_session() must call sync_pg_execute_write with UPDATE scan_sessions SQL."""
    db, mock_mgr = _make_db(tmp_path)

    with patch.object(db, "_pg", return_value=mock_mgr):
        db.update_session(1, status="completed", phase_reached=3)

    assert mock_mgr.sync_pg_execute_write.called
    sql = mock_mgr.sync_pg_execute_write.call_args[0][0]
    assert "scan_sessions" in sql
    assert "UPDATE" in sql.upper()


# ── fw_recon_assets ───────────────────────────────────────────────────────────

def test_save_asset_calls_pg_execute_write(tmp_path):
    """save_asset() must call sync_pg_execute_write with fw_recon_assets SQL."""
    db, mock_mgr = _make_db(tmp_path)

    with patch.object(db, "_pg", return_value=mock_mgr):
        db.save_asset(1, "url", "http://target.com/admin", source="recon")

    assert mock_mgr.sync_pg_execute_write.called
    sql = mock_mgr.sync_pg_execute_write.call_args[0][0]
    assert "fw_recon_assets" in sql, f"Expected fw_recon_assets in SQL: {sql!r}"


def test_get_assets_calls_pg_execute_read(tmp_path):
    """get_assets() must call sync_pg_execute_read with fw_recon_assets SQL."""
    db, mock_mgr = _make_db(tmp_path, _make_pg_mgr(read_results=[]))

    with patch.object(db, "_pg", return_value=mock_mgr):
        db.get_assets(1, asset_type="url")

    assert mock_mgr.sync_pg_execute_read.called
    sql = mock_mgr.sync_pg_execute_read.call_args[0][0]
    assert "fw_recon_assets" in sql


# ── surface_items ─────────────────────────────────────────────────────────────

def test_save_surface_item_calls_pg_execute_write(tmp_path):
    """save_surface_item() must call sync_pg_execute_write with surface_items SQL."""
    db, mock_mgr = _make_db(tmp_path)

    with patch.object(db, "_pg", return_value=mock_mgr):
        db.save_surface_item(1, "endpoint", "example.com", "/api/v1/users", method="GET")

    assert mock_mgr.sync_pg_execute_write.called
    sql = mock_mgr.sync_pg_execute_write.call_args[0][0]
    assert "surface_items" in sql


# ── vuln_candidates ───────────────────────────────────────────────────────────

def test_save_candidate_calls_pg_execute_read_returning(tmp_path):
    """save_candidate() must use RETURNING id via sync_pg_execute_read."""
    db, mock_mgr = _make_db(tmp_path)

    with patch.object(db, "_pg", return_value=mock_mgr):
        cid = db.save_candidate(1, "sqli", "example.com", "/login", parameter="username")

    assert mock_mgr.sync_pg_execute_read.called
    sql = mock_mgr.sync_pg_execute_read.call_args[0][0]
    assert "vuln_candidates" in sql
    assert "RETURNING" in sql.upper()
    assert cid == 1


def test_confirm_candidate_calls_pg_execute_write(tmp_path):
    """confirm_candidate() must call sync_pg_execute_write with UPDATE vuln_candidates SQL."""
    db, mock_mgr = _make_db(tmp_path)

    with patch.object(db, "_pg", return_value=mock_mgr):
        db.confirm_candidate(42, 7)

    assert mock_mgr.sync_pg_execute_write.called
    sql = mock_mgr.sync_pg_execute_write.call_args[0][0]
    assert "vuln_candidates" in sql
    assert "UPDATE" in sql.upper()


# ── SQLite fallback ───────────────────────────────────────────────────────────

def test_new_session_falls_back_to_sqlite_when_pg_none(tmp_path):
    """When _pg() returns None, new_session() should write to SQLite."""
    from framework.db_ext import ExtendedDB
    with patch("framework.db_ext.ExtendedDB._pg", return_value=None):
        db = ExtendedDB(str(tmp_path / "ext.db"))
        sid = db.new_session("http://localhost", "none", "")
    assert isinstance(sid, int) and sid > 0

    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "ext.db"))
    count = conn.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]
    conn.close()
    assert count == 1
