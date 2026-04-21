# tests/test_db_manager_targets.py
"""Tests for DBManager target methods."""
import asyncio
import datetime
import pytest
from unittest.mock import AsyncMock, MagicMock


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def sqlite_mgr():
    import oneinfinity.core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"
    return mgr


def pg_mgr_with_mock_pool(rows_for_select=None):
    import oneinfinity.core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"

    _row_list = list(rows_for_select or [])

    async def fake_execute(sql, params=None):
        cursor = MagicMock()
        if _row_list and "SELECT" in sql:
            async def _aiter():
                for r in _row_list:
                    yield r
            cursor.__aiter__ = lambda self=cursor: _aiter()
        else:
            async def _empty():
                return
                yield
            cursor.__aiter__ = lambda self=cursor: _empty()
        return cursor

    mock_conn = AsyncMock()
    mock_conn.execute = fake_execute
    mock_conn.commit = AsyncMock()

    mock_pool = MagicMock()
    mock_pool.connection.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.connection.return_value.__aexit__ = AsyncMock(return_value=False)

    mgr._pg_pool = mock_pool
    return mgr, mock_conn


# Mode guard tests

def test_save_target_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.save_target({"target_id": "t1", "target_value": "example.com"}))


def test_list_targets_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.list_targets())


def test_get_target_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.get_target("t1"))


def test_delete_target_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.delete_target("t1"))


def test_update_target_status_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.update_target_status("t1", "scanning"))


def test_update_target_vuln_count_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.update_target_vuln_count("t1", 5))


# Shape and behavior tests

def test_target_row_to_dict_returns_aliases():
    import oneinfinity.core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"
    now = datetime.datetime.now()
    row = ("t1", "example.com", "web", "Example", "hackerone",
           [], "pending", now, None, 0, {})
    d = mgr._target_row_to_dict(row)
    assert d["id"] == "t1"
    assert d["domain"] == "example.com"
    assert d["created_at"] == now.isoformat()
    assert isinstance(d["scope"], list)
    assert isinstance(d["severity_counts"], dict)


def test_list_targets_returns_list_in_pg_mode():
    import datetime as dt
    now = dt.datetime.now()
    row = ("t2", "target.com", "web", "Target", "hackerone",
           [], "pending", now, None, 0, {})
    mgr, _ = pg_mgr_with_mock_pool(rows_for_select=[row])
    result = run(mgr.list_targets())
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["target_id"] == "t2"
    assert result[0]["id"] == "t2"
    assert result[0]["domain"] == "target.com"


def test_get_target_returns_none_for_empty_result():
    mgr, _ = pg_mgr_with_mock_pool(rows_for_select=[])
    result = run(mgr.get_target("nonexistent"))
    assert result is None


def test_delete_target_returns_true_on_success():
    mgr, _ = pg_mgr_with_mock_pool()
    result = run(mgr.delete_target("t1"))
    assert result is True


def test_save_target_in_pg_mode_returns_dict():
    """save_target in postgres mode must return a dict with target_id and aliases."""
    import datetime as dt
    now = dt.datetime.now()
    # The save_target implementation calls get_target after inserting,
    # so we need to return a row from the SELECT as well.
    row = ("t3", "new.com", "web", "New", "hackerone", [], "pending", now, None, 0, {})

    call_count = [0]

    async def fake_execute(sql, params=None):
        cursor = MagicMock()
        if "SELECT" in sql:
            async def _aiter():
                yield row
            cursor.__aiter__ = lambda self=cursor: _aiter()
        else:
            async def _empty():
                return
                yield
            cursor.__aiter__ = lambda self=cursor: _empty()
        return cursor

    import oneinfinity.core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"

    mock_conn = AsyncMock()
    mock_conn.execute = fake_execute
    mock_conn.commit = AsyncMock()
    mock_pool = MagicMock()
    mock_pool.connection.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.connection.return_value.__aexit__ = AsyncMock(return_value=False)
    mgr._pg_pool = mock_pool

    result = run(mgr.save_target({"target_id": "t3", "target_value": "new.com"}))
    assert result["target_id"] == "t3"
    assert result["id"] == "t3"
    assert result["domain"] == "new.com"


def test_update_target_status_does_not_raise_in_pg_mode():
    """update_target_status must not raise when in postgres mode."""
    mgr, mock_conn = pg_mgr_with_mock_pool()
    run(mgr.update_target_status("t1", "scanning", "2026-04-07T12:00:00"))
    # commit is an AsyncMock and is always called after a successful execute
    assert mock_conn.commit.called


def test_update_target_vuln_count_does_not_raise_in_pg_mode():
    """update_target_vuln_count must not raise when in postgres mode."""
    mgr, mock_conn = pg_mgr_with_mock_pool()
    run(mgr.update_target_vuln_count("t1", 7))
    assert mock_conn.commit.called
