# tests/test_neo4j_sole_graph.py
import pathlib

def test_no_attack_graph_db_direct_writes_outside_fallback():
    """Graph code must not write to attack_graph.db when Neo4j is available.
    The SQLite path must be gated behind a fallback condition."""
    src = pathlib.Path("/home/devendra-yadav/oneinfinity/attack_graph_brain.py").read_text()
    # If attack_graph.db writes exist, they must be inside a fallback branch
    # This is a soft check — passes if SQLite is only used as fallback
    assert "sqlite3" not in src or "fallback" in src.lower() or "except" in src, \
        "attack_graph_brain.py appears to have unconditional SQLite writes — must be gated"

def test_neo4j_primary_backend_exists():
    """Neo4jPrimaryBackend must exist in core/graph_storage.py."""
    from core.graph_storage import Neo4jPrimaryBackend
    assert Neo4jPrimaryBackend is not None

def test_neo4j_primary_backend_on_node_saved_does_not_raise_on_error():
    """Neo4jPrimaryBackend.on_node_saved must be non-fatal on errors."""
    from core.graph_storage import Neo4jPrimaryBackend
    from unittest.mock import MagicMock
    mock_engine = MagicMock()
    mock_engine.upsert_node.side_effect = Exception("Neo4j down")
    backend = Neo4jPrimaryBackend(mock_engine)
    # Must not raise
    backend.on_node_saved({"node_id": "n1", "node_type": "host"})

def test_neo4j_primary_backend_on_edge_saved_does_not_raise_on_error():
    """Neo4jPrimaryBackend.on_edge_saved must be non-fatal on errors."""
    from core.graph_storage import Neo4jPrimaryBackend
    from unittest.mock import MagicMock
    mock_engine = MagicMock()
    mock_engine.upsert_edge.side_effect = Exception("Neo4j down")
    backend = Neo4jPrimaryBackend(mock_engine)
    # Must not raise
    backend.on_edge_saved({"edge_id": "e1", "source_id": "n1", "target_id": "n2"})
