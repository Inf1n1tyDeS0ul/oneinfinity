# tests/test_neo4j_queries.py
from unittest.mock import MagicMock, patch

def test_neo4j_engine_find_paths_returns_list():
    """find_paths_node_ids must return a list (empty or populated)."""
    from oneinfinity.core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None  # simulate unavailable
    result = engine.find_paths_node_ids("node-A", "node-B", max_depth=4)
    assert isinstance(result, list)

def test_neo4j_engine_upsert_node_does_not_raise_when_driver_none():
    """upsert_node must not raise when Neo4j is unavailable."""
    from oneinfinity.core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None
    engine.upsert_node({"node_id": "n1", "node_type": "host", "label": "example.com"})

def test_neo4j_engine_ping_returns_false_when_unavailable():
    """ping() must return False (not raise) when Neo4j is down."""
    from oneinfinity.core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None
    assert engine.ping() is False

def test_neo4j_engine_upsert_edge_does_not_raise_when_driver_none():
    """upsert_edge must not raise when Neo4j is unavailable."""
    from oneinfinity.core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None
    engine.upsert_edge({"edge_id": "e1", "source_id": "n1", "target_id": "n2"})

def test_neo4j_engine_delete_node_does_not_raise_when_driver_none():
    """delete_node must not raise when Neo4j is unavailable."""
    from oneinfinity.core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None
    engine.delete_node("n1")

def test_neo4j_engine_delete_edge_does_not_raise_when_driver_none():
    """delete_edge must not raise when Neo4j is unavailable."""
    from oneinfinity.core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None
    engine.delete_edge("e1")
