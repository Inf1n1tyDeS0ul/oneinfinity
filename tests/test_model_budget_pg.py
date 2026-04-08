# tests/test_model_budget_pg.py
"""
Tests for ModelBudgetManager PG-first migration.
Verifies that PG mode routes writes/reads through DBManager helpers.
"""
import sys
import os
import time
from unittest.mock import MagicMock, patch

# Ensure the repo root is on sys.path so model_budget_manager can be imported
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _make_pg_mgr(write_results=None, read_results=None):
    """Create a mock DBManager that looks like it's in postgres mode."""
    mgr = MagicMock()
    mgr.mode = "postgres"
    mgr.sync_pg_execute_write = MagicMock(return_value=write_results or 1)
    mgr.sync_pg_execute_read = MagicMock(return_value=read_results or [])
    return mgr


def _make_budget_manager_pg(mock_mgr, tmp_path):
    """Instantiate ModelBudgetManager with PG mock injected."""
    from model_budget_manager import ModelBudgetManager
    with patch(
        "model_budget_manager.ModelBudgetManager._pg",
        return_value=mock_mgr,
    ):
        bm = ModelBudgetManager(db_path=tmp_path / "model_usage.db")
    return bm


# ── Test 1: record() calls sync_pg_execute_write with model_usage SQL ──────────

def test_record_calls_pg_execute_write(tmp_path):
    """record() must call sync_pg_execute_write with SQL targeting model_usage."""
    mock_mgr = _make_pg_mgr()

    with patch(
        "model_budget_manager.ModelBudgetManager._pg",
        return_value=mock_mgr,
    ):
        from model_budget_manager import ModelBudgetManager
        bm = ModelBudgetManager(db_path=tmp_path / "model_usage.db")

        # Call record
        bm.record(
            model_id="gpt-4o",
            provider="openai",
            task_id="task-001",
            task_category="RECON",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.001,
            duration_ms=250.0,
            escalation=True,
        )

    assert mock_mgr.sync_pg_execute_write.called, \
        "sync_pg_execute_write should have been called"

    call_args = mock_mgr.sync_pg_execute_write.call_args
    sql = call_args[0][0]  # first positional arg is the SQL string
    assert "model_usage" in sql, \
        f"SQL should target model_usage table, got: {sql!r}"

    params = call_args[0][1]
    # escalation must be a Python bool (True/False), not integer
    assert params[8] is True, \
        f"escalation param should be Python bool True, got {params[8]!r}"


# ── Test 2: _refresh_cache() calls sync_pg_execute_read in PG mode ────────────

def test_refresh_cache_calls_pg_execute_read(tmp_path):
    """_refresh_cache() must call sync_pg_execute_read in PG mode."""
    mock_mgr = _make_pg_mgr(read_results=[])

    with patch(
        "model_budget_manager.ModelBudgetManager._pg",
        return_value=mock_mgr,
    ):
        from model_budget_manager import ModelBudgetManager
        bm = ModelBudgetManager(db_path=tmp_path / "model_usage.db")

        # _refresh_cache is called during __init__; reset call count then call again
        mock_mgr.sync_pg_execute_read.reset_mock()
        bm._refresh_cache()

    assert mock_mgr.sync_pg_execute_read.called, \
        "sync_pg_execute_read should have been called by _refresh_cache"

    # Verify at least one call targets model_usage
    calls = mock_mgr.sync_pg_execute_read.call_args_list
    sqls = [c[0][0] for c in calls]
    assert any("model_usage" in s for s in sqls), \
        f"At least one read should target model_usage, got: {sqls}"


# ── Test 3: record() passes bool escalation in PG mode ────────────────────────

def test_record_escalation_bool_in_pg_mode(tmp_path):
    """In PG mode, escalation must be sent as Python bool, not int."""
    mock_mgr = _make_pg_mgr()

    with patch(
        "model_budget_manager.ModelBudgetManager._pg",
        return_value=mock_mgr,
    ):
        from model_budget_manager import ModelBudgetManager
        bm = ModelBudgetManager(db_path=tmp_path / "model_usage.db")

        bm.record(
            model_id="claude-3-haiku",
            provider="anthropic",
            task_id="task-002",
            task_category="EXPLOIT",
            input_tokens=200,
            output_tokens=80,
            cost_usd=0.0005,
            escalation=False,
        )

    call_args = mock_mgr.sync_pg_execute_write.call_args
    params = call_args[0][1]
    escalation_val = params[8]
    assert isinstance(escalation_val, bool), \
        f"escalation must be Python bool, got {type(escalation_val)}: {escalation_val!r}"
    assert escalation_val is False


# ── Test 4: SQLite fallback when PG unavailable ────────────────────────────────

def test_record_falls_back_to_sqlite_when_no_pg(tmp_path):
    """When _pg() returns None, record() should write to SQLite without error."""
    with patch(
        "model_budget_manager.ModelBudgetManager._pg",
        return_value=None,
    ):
        from model_budget_manager import ModelBudgetManager
        bm = ModelBudgetManager(db_path=tmp_path / "model_usage.db")

        # Should not raise
        bm.record(
            model_id="gpt-3.5-turbo",
            provider="openai",
            task_id="task-003",
            task_category="GENERAL",
            input_tokens=50,
            output_tokens=20,
            cost_usd=0.00005,
        )

    # Verify it actually wrote to SQLite
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "model_usage.db"))
    count = conn.execute("SELECT COUNT(*) FROM model_usage").fetchone()[0]
    conn.close()
    assert count == 1, f"Expected 1 row in SQLite, got {count}"
