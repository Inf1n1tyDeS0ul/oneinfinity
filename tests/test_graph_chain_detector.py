"""
Tests for graph chain detector.
"""
import pytest
from oneinfinity.attack_graph_core.graph import AttackGraph, Node, Edge, NodeType, EdgeType
from oneinfinity.attack_graph_core.graph_chain_detector import (
    GraphChainDetector,
    ChainNode,
    AttackChain,
)


@pytest.fixture
def simple_graph():
    """Create simple test graph with chain: IDOR -> SQLi -> RCE."""
    g = AttackGraph("test.com")

    # Add nodes
    idor_node = Node(
        node_id="vuln_idor_1",
        node_type=NodeType.VULNERABILITY,
        label="IDOR",
        severity="medium",
        properties={"vuln_type": "idor", "confidence": 0.8, "cvss_score": 5.0},
    )
    g.add_node(idor_node)

    sqli_node = Node(
        node_id="vuln_sqli_1",
        node_type=NodeType.VULNERABILITY,
        label="SQLi",
        severity="high",
        properties={"vuln_type": "sqli", "confidence": 0.9, "cvss_score": 8.0},
    )
    g.add_node(sqli_node)

    rce_node = Node(
        node_id="vuln_rce_1",
        node_type=NodeType.VULNERABILITY,
        label="RCE",
        severity="critical",
        properties={"vuln_type": "command_injection", "confidence": 0.85, "cvss_score": 9.5},
    )
    g.add_node(rce_node)

    # Add edges
    edge1 = Edge(
        edge_id="e1",
        src="vuln_idor_1",
        dst="vuln_sqli_1",
        edge_type=EdgeType.ENABLES,
        properties={"confidence": 0.75},
    )
    g.add_edge(edge1)

    edge2 = Edge(
        edge_id="e2",
        src="vuln_sqli_1",
        dst="vuln_rce_1",
        edge_type=EdgeType.ENABLES,
        properties={"confidence": 0.8},
    )
    g.add_edge(edge2)

    return g


@pytest.fixture
def complex_graph():
    """Create complex graph with multiple paths."""
    g = AttackGraph("test.com")

    # Entry nodes
    xss = Node("vuln_xss", NodeType.VULNERABILITY, "XSS", severity="low", properties={"vuln_type": "xss", "confidence": 0.7, "cvss_score": 3.0})
    info = Node("vuln_info", NodeType.VULNERABILITY, "Info Leak", severity="low", properties={"vuln_type": "info_leak", "confidence": 0.9, "cvss_score": 2.0})

    # Mid nodes
    idor = Node("vuln_idor", NodeType.VULNERABILITY, "IDOR", severity="medium", properties={"vuln_type": "idor", "confidence": 0.8, "cvss_score": 5.0})
    sqli = Node("vuln_sqli", NodeType.VULNERABILITY, "SQLi", severity="high", properties={"vuln_type": "sqli", "confidence": 0.9, "cvss_score": 8.0})

    # Target nodes
    rce = Node("vuln_rce", NodeType.VULNERABILITY, "RCE", severity="critical", properties={"vuln_type": "command_injection", "confidence": 0.85, "cvss_score": 9.5})
    auth_bypass = Node("vuln_auth", NodeType.VULNERABILITY, "Auth Bypass", severity="high", properties={"vuln_type": "auth_bypass", "confidence": 0.8, "cvss_score": 7.5})

    for node in [xss, info, idor, sqli, rce, auth_bypass]:
        g.add_node(node)

    # Edges - multiple paths to objectives
    edges = [
        Edge("e1", "vuln_xss", "vuln_idor", EdgeType.ENABLES, properties={"confidence": 0.7}),
        Edge("e2", "vuln_info", "vuln_idor", EdgeType.ENABLES, properties={"confidence": 0.8}),
        Edge("e3", "vuln_idor", "vuln_sqli", EdgeType.ENABLES, properties={"confidence": 0.75}),
        Edge("e4", "vuln_sqli", "vuln_rce", EdgeType.ENABLES, properties={"confidence": 0.8}),
        Edge("e5", "vuln_info", "vuln_auth", EdgeType.ENABLES, properties={"confidence": 0.85}),
        Edge("e6", "vuln_idor", "vuln_auth", EdgeType.ENABLES, properties={"confidence": 0.7}),
    ]

    for edge in edges:
        g.add_edge(edge)

    return g


def test_detector_initialization(simple_graph):
    """Test detector initializes with graph."""
    detector = GraphChainDetector(simple_graph)
    assert detector.graph == simple_graph
    assert detector.chains == []


def test_detect_chains_simple(simple_graph):
    """Test chain detection in simple linear graph."""
    detector = GraphChainDetector(simple_graph)
    chains = detector.detect_chains(objectives=["rce"])

    assert len(chains) > 0
    chain = chains[0]
    assert chain.objective == "rce"
    assert chain.length == 3
    assert chain.nodes[0].node_id == "vuln_idor_1"
    assert chain.nodes[-1].node_id == "vuln_rce_1"


def test_detect_chains_multiple_objectives(complex_graph):
    """Test detection of chains to multiple objectives."""
    detector = GraphChainDetector(complex_graph)
    chains = detector.detect_chains(objectives=["rce", "ato"])

    # Should find chains to both RCE and ATO (auth bypass)
    rce_chains = [c for c in chains if c.objective == "rce"]
    ato_chains = [c for c in chains if c.objective == "ato"]

    assert len(rce_chains) > 0
    assert len(ato_chains) > 0


def test_confidence_pruning():
    """Test that low-confidence edges are pruned."""
    g = AttackGraph("test.com")

    n1 = Node("n1", NodeType.VULNERABILITY, "Entry", severity="low", properties={"vuln_type": "info_leak", "confidence": 0.8, "cvss_score": 2.0})
    n2 = Node("n2", NodeType.VULNERABILITY, "Mid", severity="medium", properties={"vuln_type": "idor", "confidence": 0.5, "cvss_score": 5.0})
    n3 = Node("n3", NodeType.VULNERABILITY, "Target", severity="high", properties={"vuln_type": "command_injection", "confidence": 0.9, "cvss_score": 9.0})

    g.add_node(n1)
    g.add_node(n2)
    g.add_node(n3)

    # Low confidence edge should be pruned
    low_edge = Edge("e1", "n1", "n2", EdgeType.ENABLES, properties={"confidence": 0.3})
    high_edge = Edge("e2", "n2", "n3", EdgeType.ENABLES, properties={"confidence": 0.9})

    g.add_edge(low_edge)
    g.add_edge(high_edge)

    detector = GraphChainDetector(g)
    chains = detector.detect_chains(objectives=["rce"])

    # Should find no chains due to low confidence edge
    assert len(chains) == 0


def test_max_chain_length():
    """Test that chains exceeding max length are not detected."""
    g = AttackGraph("test.com")

    # Create chain with 6 nodes (exceeds MAX_CHAIN_LENGTH=5)
    nodes = []
    for i in range(6):
        n = Node(
            f"n{i}",
            NodeType.VULNERABILITY,
            f"Vuln{i}",
            severity="medium" if i > 0 else "low",  # First node is entry
            properties={
                "vuln_type": "command_injection" if i == 5 else "idor",
                "confidence": 0.8,
                "cvss_score": 5.0,
            },
        )
        g.add_node(n)
        nodes.append(n)

    # Connect nodes in chain
    for i in range(5):
        edge = Edge(f"e{i}", f"n{i}", f"n{i+1}", EdgeType.ENABLES, properties={"confidence": 0.8})
        g.add_edge(edge)

    detector = GraphChainDetector(g)
    chains = detector.detect_chains(objectives=["rce"])

    # Should find chains, but none exceeding MAX_CHAIN_LENGTH=5
    for chain in chains:
        assert chain.length <= GraphChainDetector.MAX_CHAIN_LENGTH


def test_cvss_escalation_scoring(simple_graph):
    """Test CVSS escalation is calculated correctly."""
    detector = GraphChainDetector(simple_graph)
    chains = detector.detect_chains(objectives=["rce"])

    assert len(chains) > 0
    chain = chains[0]

    # CVSS escalation should be 9.5 - 5.0 = 4.5
    assert chain.cvss_escalation == pytest.approx(4.5, abs=0.1)


def test_exploitability_scoring(simple_graph):
    """Test exploitability score is calculated."""
    detector = GraphChainDetector(simple_graph)
    chains = detector.detect_chains(objectives=["rce"])

    assert len(chains) > 0
    chain = chains[0]

    # Exploitability should be between 0 and 1
    assert 0.0 <= chain.exploitability_score <= 1.0


def test_get_chains_by_objective(complex_graph):
    """Test filtering chains by objective."""
    detector = GraphChainDetector(complex_graph)
    detector.detect_chains(objectives=["rce", "ato"])

    rce_chains = detector.get_chains_by_objective("rce")
    ato_chains = detector.get_chains_by_objective("ato")

    assert all(c.objective == "rce" for c in rce_chains)
    assert all(c.objective == "ato" for c in ato_chains)


def test_get_high_risk_chains(complex_graph):
    """Test filtering high-risk chains."""
    detector = GraphChainDetector(complex_graph)
    detector.detect_chains(objectives=["rce", "ato"])

    high_risk = detector.get_high_risk_chains(threshold=0.5)

    assert all(c.exploitability_score >= 0.5 for c in high_risk)


def test_chain_to_dict(simple_graph):
    """Test chain serialization to dict."""
    detector = GraphChainDetector(simple_graph)
    chains = detector.detect_chains(objectives=["rce"])

    assert len(chains) > 0
    chain = chains[0]
    chain_dict = chain.to_dict()

    assert "chain_id" in chain_dict
    assert "nodes" in chain_dict
    assert "edges" in chain_dict
    assert "confidence" in chain_dict
    assert "cvss_escalation" in chain_dict
    assert "exploitability" in chain_dict
    assert chain_dict["objective"] == "rce"
    assert chain_dict["length"] == 3


def test_deduplication(complex_graph):
    """Test that duplicate chains are removed."""
    detector = GraphChainDetector(complex_graph)
    chains = detector.detect_chains(objectives=["rce"])

    # Check no duplicate node sequences
    seen_sequences = set()
    for chain in chains:
        node_seq = tuple(n.node_id for n in chain.nodes)
        assert node_seq not in seen_sequences
        seen_sequences.add(node_seq)
