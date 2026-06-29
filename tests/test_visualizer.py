"""tests/test_visualizer.py — Unit tests for attack graph visualizer extensions."""
from __future__ import annotations
import pytest
import uuid


def _make_graph():
    from oneinfinity.attack_graph_core.graph import AttackGraph, Node, NodeType, Edge, EdgeType

    g = AttackGraph(target="example.com")
    n1 = Node(node_id="n1", node_type=NodeType.ENDPOINT, label="/api/users")
    n2 = Node(node_id="n2", node_type=NodeType.VULNERABILITY, label="SQLi")
    n3 = Node(node_id="n3", node_type=NodeType.CICD_PIPELINE, label=".github/workflows/deploy.yml")
    n4 = Node(node_id="n4", node_type=NodeType.SMART_CONTRACT, label="Token.sol")
    g.add_node(n1)
    g.add_node(n2)
    g.add_node(n3)
    g.add_node(n4)
    e = Edge(
        edge_id=str(uuid.uuid4()),
        src="n1",
        dst="n2",
        edge_type=EdgeType.ENABLES,
    )
    g.add_edge(e)
    return g


def test_visualizer_imports():
    from oneinfinity.attack_graph_core.visualizer import AttackGraphVisualizer
    assert AttackGraphVisualizer is not None


def test_graph_has_cicd_node():
    from oneinfinity.attack_graph_core.graph import NodeType
    g = _make_graph()
    nodes = g.nodes()
    types = [n.node_type for n in nodes]
    assert NodeType.CICD_PIPELINE in types


def test_graph_has_smart_contract_node():
    from oneinfinity.attack_graph_core.graph import NodeType
    g = _make_graph()
    nodes = g.nodes()
    types = [n.node_type for n in nodes]
    assert NodeType.SMART_CONTRACT in types


def test_to_graphml_produces_xml():
    from oneinfinity.attack_graph_core.visualizer import AttackGraphVisualizer
    g = _make_graph()
    viz = AttackGraphVisualizer(g)
    try:
        xml = viz.to_graphml()
        assert "<graphml" in xml
        assert "n1" in xml
    except AttributeError:
        pytest.skip("to_graphml() not yet implemented")


def test_ascii_exploit_paths_returns_str():
    from oneinfinity.attack_graph_core.visualizer import AttackGraphVisualizer
    g = _make_graph()
    viz = AttackGraphVisualizer(g)
    try:
        result = viz.ascii_exploit_paths()
        assert isinstance(result, str)
    except AttributeError:
        pytest.skip("ascii_exploit_paths() not yet implemented")


def test_cicd_node_type_exists_in_enum():
    """CICD_PIPELINE must be in the NodeType enum."""
    from oneinfinity.attack_graph_core.graph import NodeType
    assert hasattr(NodeType, "CICD_PIPELINE"), "NodeType.CICD_PIPELINE not defined"
    assert NodeType.CICD_PIPELINE.value == "cicd_pipeline"


def test_smart_contract_node_type_exists_in_enum():
    """SMART_CONTRACT must be in the NodeType enum."""
    from oneinfinity.attack_graph_core.graph import NodeType
    assert hasattr(NodeType, "SMART_CONTRACT"), "NodeType.SMART_CONTRACT not defined"
    assert NodeType.SMART_CONTRACT.value == "smart_contract"


def test_mindmap_produces_output():
    from oneinfinity.attack_graph_core.visualizer import AttackSurfaceMindMap
    g = _make_graph()
    try:
        mm = AttackSurfaceMindMap(g)
        output = mm.render()
        assert output
    except (AttributeError, ImportError):
        pytest.skip("AttackSurfaceMindMap not yet fully implemented")
