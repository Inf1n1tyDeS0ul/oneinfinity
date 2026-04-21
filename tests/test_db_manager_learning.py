# tests/test_db_manager_learning.py
"""Tests for DBManager learning persistence methods."""
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
    import oneinfinity.core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"
    return mgr


def pg_mgr(rows=None):
    import oneinfinity.core.db_manager as dm
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

def test_save_learning_session_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_learning_session({"session_id": "s1", "target": "t.com"}))


def test_list_learning_sessions_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.list_learning_sessions())


def test_save_learning_finding_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_learning_finding({"session_id": "s1", "target": "t.com", "vuln_type": "sqli"}))


def test_record_tool_run_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.record_tool_run({"tool_name": "nuclei", "vuln_type": "xss"}))


def test_get_best_tool_for_vuln_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_best_tool_for_vuln("xss"))


def test_upsert_target_profile_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.upsert_target_profile({"domain": "t.com"}))


def test_get_target_profile_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_target_profile("t.com"))


def test_upsert_pattern_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.upsert_pattern({"tech_stack_key": "wordpress", "vuln_type": "sqli"}))


def test_get_patterns_for_tech_stack_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_patterns_for_tech_stack("wordpress"))


def test_get_learning_stats_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_learning_stats())


def test_list_tool_performance_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.list_tool_performance())


# ── Postgres behavior tests ───────────────────────────────────────────────────

def test_save_learning_session_commits_in_pg_mode():
    mgr, mock_conn = pg_mgr()
    run(mgr.save_learning_session({
        "session_id": "s1", "target": "t.com", "started_at": 1.0,
        "finished_at": None, "phases": [], "total_findings": 0,
        "tools_used": [], "notes": "",
    }))
    assert mock_conn.commit.called


def test_save_learning_finding_commits_in_pg_mode():
    mgr, mock_conn = pg_mgr()
    run(mgr.save_learning_finding({
        "session_id": "s1", "target": "t.com", "vuln_type": "sqli",
        "severity": "high", "cvss_score": 7.5, "endpoint": "/login",
        "parameter": "id", "source_tool": "sqlmap",
        "confirmed": 1, "chain_id": "", "discovered_at": 1.0,
    }))
    assert mock_conn.commit.called


def test_record_tool_run_commits_in_pg_mode():
    mgr, mock_conn = pg_mgr()
    run(mgr.record_tool_run({
        "tool_name": "nuclei", "vuln_type": "xss", "target_type": "web",
        "runs_success": 1, "findings_total": 3, "avg_duration_s": 5.0,
        "last_updated": 1.0,
    }))
    assert mock_conn.commit.called


def test_get_best_tool_for_vuln_returns_list_in_pg_mode():
    row = MagicMock()
    row.__getitem__ = lambda self, i: ["nuclei", 10, 8, 25, 3.0][i]
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.get_best_tool_for_vuln("xss", top_n=1))
    assert isinstance(result, list)


def test_list_learning_sessions_returns_list_in_pg_mode():
    row = MagicMock()
    row.__iter__ = MagicMock(return_value=iter([]))
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.list_learning_sessions())
    assert isinstance(result, list)


def test_list_tool_performance_returns_list_in_pg_mode():
    mgr, _ = pg_mgr(rows=[])
    result = run(mgr.list_tool_performance())
    assert isinstance(result, list)
