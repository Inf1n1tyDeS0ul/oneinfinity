"""
tests/test_graph_store_pg.py — Unit tests for PG-backed SQLiteStore.

Mocks DBManager so no real PG connection is needed.
"""
import sys
import json
import time
from unittest.mock import MagicMock, patch


from oneinfinity.attack_graph_core.graph_store import SQLiteStore


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
    """save_node must call sync_pg_execute_write with graph_nodes SQL."""
    mgr = _make_mgr(mode="postgres")
    store = SQLiteStore(db_path="/tmp/test_graph.db")

    with patch.object(SQLiteStore, "_get_pg", return_value=mgr):
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
    """load_all_nodes must delegate to sync_pg_execute_read."""
    mgr = _make_mgr(mode="distributed")
    store = SQLiteStore(db_path="/tmp/test_graph.db")

    with patch.object(SQLiteStore, "_get_pg", return_value=mgr):
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

    with patch.object(SQLiteStore, "_get_pg", return_value=mgr):
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
# Test 3: save_node raises RuntimeError when PG unavailable
# ---------------------------------------------------------------------------

def test_save_node_raises_when_pg_unavailable():
    """save_node must raise RuntimeError when PostgreSQL is unavailable."""
    store = SQLiteStore(db_path="/tmp/test_graph.db")

    with patch.object(SQLiteStore, "_get_pg", side_effect=RuntimeError("PostgreSQL is required")):
        try:
            store.save_node(_make_node("n-no-pg"))
            assert False, "Expected RuntimeError to be raised"
        except RuntimeError as exc:
            assert "PostgreSQL" in str(exc)
