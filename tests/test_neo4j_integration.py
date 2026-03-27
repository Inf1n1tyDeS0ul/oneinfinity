"""Neo4j optional backend: GraphStore sync + hybrid path hook (mocked driver)."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock

from attack_graph_core.graph_engine import AttackGraphEngine, NodeType, EdgeType
from attack_graph_core.graph_store import GraphStore
from attack_graph_core.graph_query_engine import GraphQueryEngine


def test_graph_store_sync_backend_called():
    backend = MagicMock()
    store = GraphStore(db_path=":memory:", use_memory=True, sync_backend=backend)
    store.initialize()

    n = {
        "id": "n1", "node_type": "target", "label": "t.com",
        "properties": {}, "discovered_at": "0", "updated_at": "0",
    }
    store.save_node(n)
    backend.on_node_saved.assert_called_once()

    e = {
        "id": "e1", "source_id": "n1", "target_id": "n1",
        "edge_type": "hosts", "label": "", "properties": {},
        "created_at": "0",
    }
    store.save_edge(e)
    assert backend.on_edge_saved.call_count >= 1


def test_hybrid_dfs_falls_back_when_no_neo4j():
    eng = AttackGraphEngine()
    a, _ = eng.get_or_create_node(NodeType.TARGET, "a.com", properties={})
    b, _ = eng.get_or_create_node(NodeType.URL, "https://a.com/x", properties={})
    eng.add_edge(a.id, b.id, EdgeType.HAS_ENDPOINT, label="e")
    q = GraphQueryEngine(engine=eng)
    paths = q.dfs_paths(a.id, b.id, max_depth=10)
    assert paths and len(paths[0]) >= 2


def test_neo4j_engine_batches_rows():
    from core import neo4j_engine as ne
    if not ne.neo4j_driver_available():
        pytest.skip("neo4j package not installed")
    from core.neo4j_engine import Neo4jEngine, node_to_neo_row

    eng = Neo4jEngine("bolt://127.0.0.1:1", "neo4j", "invalid-password-for-test")
    mock_drv = MagicMock()
    eng._driver = mock_drv
    eng._connected = True
    mock_sess = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value = mock_sess
    mock_ctx.__exit__.return_value = None
    mock_drv.session.return_value = mock_ctx

    eng.merge_nodes_batch([
        node_to_neo_row({"id": "x", "node_type": "target", "label": "x", "properties": {}}),
    ])
    mock_sess.execute_write.assert_called_once()


def test_publish_chain_feedback_no_crash():
    from core.graph_neo4j_bootstrap import publish_chain_feedback_neo4j

    publish_chain_feedback_neo4j("c1", False, target="t", vuln_type="sqli")
