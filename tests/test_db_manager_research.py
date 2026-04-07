# tests/test_db_manager_research.py
"""Tests for DBManager research persistence methods."""
import asyncio
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
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"
    return mgr


def pg_mgr(rows=None):
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"

    _rows = list(rows or [])

    async def fake_execute(sql, params=None):
        cursor = MagicMock()
        if _rows and "SELECT" in sql.upper():
            async def _aiter():
                for r in _rows:
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


# ── Mode guard tests ──────────────────────────────────────────────────────────

def test_save_research_session_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_research_session({"session_id": "s1", "target": "t.com"}))


def test_get_research_session_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_research_session("s1"))


def test_list_research_sessions_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.list_research_sessions())


def test_save_research_theory_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_research_theory({"theory_id": "t1", "session_id": "s1",
                                       "target": "t.com", "vuln_type": "xss"}))


def test_update_research_theory_status_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.update_research_theory_status("t1", "confirmed", 1.0))


def test_save_test_outcome_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_test_outcome({"session_id": "s1", "target": "t.com", "vuln_type": "sqli"}))


def test_save_research_discovery_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_research_discovery({"report_id": "r1", "session_id": "s1",
                                          "target": "t.com", "vuln_type": "xss"}))


def test_list_research_discoveries_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.list_research_discoveries())


def test_upsert_cross_target_pattern_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.upsert_cross_target_pattern({"vuln_type": "xss",
                                              "endpoint_pattern": "/api/{id}"}))


def test_get_cross_target_patterns_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_cross_target_patterns())


# ── Postgres mock tests ───────────────────────────────────────────────────────

def test_save_research_session_pg():
    mgr, conn = pg_mgr()
    run(mgr.save_research_session({"session_id": "s1", "target": "t.com"}))
    assert conn.commit.called


def test_get_research_session_returns_none_when_not_found():
    mgr, _ = pg_mgr(rows=[])
    result = run(mgr.get_research_session("missing"))
    assert result is None


def test_get_research_session_returns_dict_when_found():
    row = {"session_id": "s1", "target": "t.com", "status": "running"}
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.get_research_session("s1"))
    assert result["session_id"] == "s1"
    assert result["target"] == "t.com"


def test_list_research_sessions_returns_empty_list():
    mgr, _ = pg_mgr(rows=[])
    result = run(mgr.list_research_sessions())
    assert result == []


def test_list_research_sessions_with_target_filter():
    row = {"session_id": "s1", "target": "t.com"}
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.list_research_sessions(target="t.com"))
    assert len(result) == 1
    assert result[0]["target"] == "t.com"


def test_save_research_theory_pg():
    mgr, conn = pg_mgr()
    run(mgr.save_research_theory({
        "theory_id": "th1", "session_id": "s1", "target": "t.com",
        "vuln_type": "xss", "endpoint": "/search",
    }))
    assert conn.commit.called


def test_update_research_theory_status_pg():
    mgr, conn = pg_mgr()
    run(mgr.update_research_theory_status("th1", "confirmed", 1234.0))
    assert conn.commit.called


def test_save_test_outcome_pg():
    mgr, conn = pg_mgr()
    run(mgr.save_test_outcome({
        "session_id": "s1", "target": "t.com", "vuln_type": "sqli",
        "endpoint": "/api", "payload": "' OR 1=1",
    }))
    assert conn.commit.called


def test_save_research_discovery_pg():
    mgr, conn = pg_mgr()
    run(mgr.save_research_discovery({
        "report_id": "r1", "session_id": "s1", "target": "t.com",
        "vuln_type": "xss", "title": "Stored XSS", "steps": ["step1"],
    }))
    assert conn.commit.called


def test_list_research_discoveries_pg():
    row = {"report_id": "r1", "session_id": "s1", "vuln_type": "xss",
           "target": "t.com", "steps": ["step1"]}
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.list_research_discoveries())
    assert len(result) == 1
    assert result[0]["report_id"] == "r1"


def test_upsert_cross_target_pattern_pg():
    mgr, conn = pg_mgr()
    run(mgr.upsert_cross_target_pattern({
        "vuln_type": "xss", "endpoint_pattern": "/api/{id}",
        "parameter_pattern": "q",
    }))
    assert conn.commit.called


def test_get_cross_target_patterns_pg():
    row = {"vuln_type": "xss", "endpoint_pattern": "/api/{id}", "success_count": 3}
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.get_cross_target_patterns(min_count=2))
    assert len(result) == 1
    assert result[0]["success_count"] == 3
