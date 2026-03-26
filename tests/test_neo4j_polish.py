import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock, patch, call


def _make_neo4j_engine(connected=True):
    """Build Neo4jEngine with a fully-mocked driver (no real Neo4j needed)."""
    from core.neo4j_engine import Neo4jEngine
    eng = Neo4jEngine.__new__(Neo4jEngine)
    eng._uri = "bolt://localhost:7687"
    eng._auth = ("neo4j", "test")
    eng._database = "neo4j"
    eng._connected = connected
    mock_driver = MagicMock()
    eng._driver = mock_driver if connected else None
    return eng, mock_driver


def test_bootstrap_schema_runs_all_three_statements():
    """bootstrap_schema must issue CONSTRAINT + 2 INDEX statements."""
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    eng.bootstrap_schema()

    calls = [str(c) for c in mock_sess.run.call_args_list]
    assert any("CONSTRAINT" in c and "IF NOT EXISTS" in c for c in calls), "CONSTRAINT IF NOT EXISTS missing"
    assert any("INDEX" in c and "n.type" in c and "IF NOT EXISTS" in c for c in calls), "node type INDEX IF NOT EXISTS missing"
    assert any("INDEX" in c and "r.type" in c and "IF NOT EXISTS" in c for c in calls), "rel type INDEX IF NOT EXISTS missing"


def test_bootstrap_schema_noop_when_disconnected():
    """bootstrap_schema must be safe to call when driver is None."""
    eng, mock_driver = _make_neo4j_engine(connected=False)
    eng.bootstrap_schema()  # should not raise
    assert mock_driver.session.call_count == 0, "session must not be called when disconnected"


# ---------------------------------------------------------------------------
# Task 3 — safe path query with timeout
# ---------------------------------------------------------------------------

def test_find_path_node_ids_safe_respects_depth_cap():
    """find_path_node_ids_safe must cap depth at path_max_depth from config."""
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    mock_sess.run.return_value = []
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    with patch("core.graph_config.load_graph_config", return_value={"neo4j": {"path_max_depth": 8, "max_path_query_ms": 5000}}):
        eng.find_path_node_ids_safe("a", "b", max_depth=999)

    cypher_str = mock_sess.run.call_args_list[0][0][0]
    assert "[*1..8]" in cypher_str, f"depth not clamped to 8: {cypher_str}"


def test_find_path_node_ids_safe_noop_when_disconnected():
    """Returns empty list when driver is None."""
    eng, _ = _make_neo4j_engine(connected=False)
    result = eng.find_path_node_ids_safe("x", "y")
    assert result == []


# ---------------------------------------------------------------------------
# Task 4 — count_nodes, count_edges, get_status
# ---------------------------------------------------------------------------

def test_count_nodes_returns_int():
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    mock_sess.run.return_value = [{"n": 42}]
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    result = eng.count_nodes()
    assert result == 42


def test_count_edges_returns_int():
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    mock_sess.run.return_value = [{"e": 17}]
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    result = eng.count_edges()
    assert result == 17


def test_count_nodes_returns_zero_when_disconnected():
    eng, _ = _make_neo4j_engine(connected=False)
    assert eng.count_nodes() == 0


def test_get_status_structure():
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    mock_sess.run.return_value = [{"n": 5}]
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    status = eng.get_status()
    assert "connected" in status
    assert "node_count" in status
    assert "edge_count" in status
    assert "last_sync_ts" in status


# ---------------------------------------------------------------------------
# Task 5 — compare_inmemory_vs_neo4j
# ---------------------------------------------------------------------------

def test_compare_inmemory_vs_neo4j_match():
    """Returns True when in-memory counts match Neo4j counts."""
    from core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j

    mock_store = MagicMock()
    mock_store.get_graph_stats.return_value = {"total_nodes": 10, "total_edges": 5}

    mock_engine = MagicMock()
    mock_engine.connected = True
    mock_engine.count_nodes.return_value = 10
    mock_engine.count_edges.return_value = 5

    result = compare_inmemory_vs_neo4j(mock_store, neo4j_engine=mock_engine)
    assert result["match"] is True
    assert result["inmem_nodes"] == 10
    assert result["neo4j_nodes"] == 10


def test_compare_inmemory_vs_neo4j_mismatch():
    """Returns False with delta when counts differ."""
    from core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j

    mock_store = MagicMock()
    mock_store.get_graph_stats.return_value = {"total_nodes": 10, "total_edges": 5}

    mock_engine = MagicMock()
    mock_engine.connected = True
    mock_engine.count_nodes.return_value = 8
    mock_engine.count_edges.return_value = 5

    result = compare_inmemory_vs_neo4j(mock_store, neo4j_engine=mock_engine)
    assert result["match"] is False
    assert result["node_delta"] == 2


def test_compare_inmemory_vs_neo4j_no_neo4j():
    """Returns neo4j_connected=False when Neo4j unavailable."""
    from core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j

    mock_store = MagicMock()
    mock_store.get_graph_stats.return_value = {"total_nodes": 3, "total_edges": 1}

    result = compare_inmemory_vs_neo4j(mock_store, neo4j_engine=None)
    assert result["neo4j_connected"] is False
