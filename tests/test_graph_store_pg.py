"""
tests/test_graph_store_pg.py — Unit tests for PG-first SQLiteStore migration.

Mocks DBManager so no real PG connection is needed.
"""
import sys
import json
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, "/home/devendra-yadav/oneinfinity")

from attack_graph_core.graph_store import SQLiteStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mgr(mode="postgres"):
    """Return a mock DBManager in the given mode."""
    mgr = MagicMock()
    mgr.mode = mode
    mgr.sync_pg_execute_write.return_value = 1
    mgr.sync_pg_execute_read.return_value = []
    return mgr


def _make_node(node_id="node-1"):
    return {
        "id": node_id,
        "node_type": "vulnerability",
        "label": "Test Node",
        "properties": {"cvss": 9.8},
        "severity": "critical",
        "risk_score": 9.8,
        "exploitable": True,
        "validated": False,
        "discovered_at": str(time.time()),
        "updated_at": str(time.time()),
        "source": "scanner",
        "tags": ["rce"],
    }


# ---------------------------------------------------------------------------
# Test 1: save_node calls sync_pg_execute_write with graph_nodes SQL
# ---------------------------------------------------------------------------

def test_save_node_uses_pg_and_targets_graph_nodes():
    """save_node in PG mode must call sync_pg_execute_write with graph_nodes SQL."""
    mgr = _make_mgr(mode="postgres")
    store = SQLiteStore(db_path="/tmp/test_graph.db")

    with patch.object(SQLiteStore, "_get_pg", return_value=(mgr, True)):
        store.save_node(_make_node("n1"))

    assert mgr.sync_pg_execute_write.called, "sync_pg_execute_write should have been called"
    call_sql = mgr.sync_pg_execute_write.call_args[0][0]
    assert "graph_nodes" in call_sql, (
        f"Expected 'graph_nodes' in SQL, got: {call_sql!r}"
    )
    assert "ON CONFLICT" in call_sql, (
        f"Expected upsert ON CONFLICT clause, got: {call_sql!r}"
    )
    # Must NOT use SQLite '?' placeholders
    assert "?" not in call_sql, f"SQL should use %s placeholders, not '?': {call_sql!r}"


# ---------------------------------------------------------------------------
# Test 2: get_all_nodes (load_all_nodes) calls sync_pg_execute_read
# ---------------------------------------------------------------------------

def test_load_all_nodes_uses_pg_execute_read():
    """load_all_nodes in PG mode must delegate to sync_pg_execute_read."""
    mgr = _make_mgr(mode="distributed")
    store = SQLiteStore(db_path="/tmp/test_graph.db")

    with patch.object(SQLiteStore, "_get_pg", return_value=(mgr, True)):
        result = store.load_all_nodes()

    assert mgr.sync_pg_execute_read.called, "sync_pg_execute_read should have been called"
    call_sql = mgr.sync_pg_execute_read.call_args[0][0]
    assert "graph_nodes" in call_sql, (
        f"Expected 'graph_nodes' in SQL, got: {call_sql!r}"
    )
    assert result == [], "Empty PG result should return empty list"


def test_load_all_nodes_with_node_type_filter():
    """load_all_nodes(node_type=...) must pass node_type as a PG parameter."""
    mgr = _make_mgr(mode="postgres")
    store = SQLiteStore(db_path="/tmp/test_graph.db")

    with patch.object(SQLiteStore, "_get_pg", return_value=(mgr, True)):
        store.load_all_nodes(node_type="vulnerability")

    assert mgr.sync_pg_execute_read.called
    call_args = mgr.sync_pg_execute_read.call_args[0]
    sql, params = call_args[0], call_args[1]
    assert "graph_nodes" in sql
    assert "node_type" in sql
    assert "vulnerability" in params, (
        f"node_type filter param missing from {params!r}"
    )


# ---------------------------------------------------------------------------
# Test 3: SQLite fallback — no PG write is made when mode is sqlite
# ---------------------------------------------------------------------------

def test_save_node_sqlite_fallback_does_not_call_pg(tmp_path):
    """When not in PG mode, save_node must use SQLite and not call sync_pg_execute_write."""
    mgr = _make_mgr(mode="sqlite")
    store = SQLiteStore(db_path=str(tmp_path / "graph.db"))

    # Initialize the SQLite connection (PG not available)
    with patch.object(SQLiteStore, "_get_pg", return_value=(None, False)):
        store.initialize()

    with patch.object(SQLiteStore, "_get_pg", return_value=(None, False)):
        store.save_node(_make_node("n-sqlite"))

    # mgr was never returned as active, so it should never have been called
    mgr.sync_pg_execute_write.assert_not_called()
