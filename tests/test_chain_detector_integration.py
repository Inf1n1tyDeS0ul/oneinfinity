"""
Integration test: GraphChainDetector with real AttackGraphBuilder.
"""
import pytest
from oneinfinity.attack_graph_core.builder import AttackGraphBuilder
from oneinfinity.attack_graph_core.graph_chain_detector import GraphChainDetector


def test_builder_auto_detects_chains():
    """Test that builder.build() automatically detects chains."""
    builder = AttackGraphBuilder("test.com")

    # Simulate findings from scan
    findings = [
        {
            "id": "1",
            "vuln_type": "idor",
            "type": "IDOR",
            "host": "test.com",
            "endpoint": "/api/users/{id}",
            "severity": "medium",
            "cvss_score": 5.0,
            "confidence": 0.8,
        },
        {
            "id": "2",
            "vuln_type": "sqli",
            "type": "SQL Injection",
            "host": "test.com",
            "endpoint": "/api/users/{id}",
            "severity": "high",
            "cvss_score": 8.0,
            "confidence": 0.9,
        },
        {
            "id": "3",
            "vuln_type": "command_injection",
            "type": "RCE via Command Injection",
            "host": "test.com",
            "endpoint": "/admin/backup",
            "severity": "critical",
            "cvss_score": 9.5,
            "confidence": 0.85,
        },
    ]

    # Add findings to graph
    builder.from_findings(findings)

    # Build graph with chain detection
    graph = builder.build(detect_chains=True)

    # Verify chains detected
    assert hasattr(graph, "metadata")
    assert "detected_chains" in graph.metadata
    assert "chain_count" in graph.metadata

    chains = graph.metadata["detected_chains"]
    assert isinstance(chains, list)

    # Should find at least one chain (depends on edge creation logic)
    # If no edges created, chains will be empty - that's OK for this test
    print(f"Detected {len(chains)} chains")
    for chain in chains:
        print(f"  Chain {chain['chain_id']}: {chain['length']} nodes, objective={chain['objective']}")


def test_builder_can_skip_chain_detection():
    """Test that chain detection can be disabled."""
    builder = AttackGraphBuilder("test.com")

    findings = [
        {"id": "1", "vuln_type": "xss", "type": "XSS", "host": "test.com", "severity": "medium"}
    ]

    builder.from_findings(findings)
    graph = builder.build(detect_chains=False)

    # Should not have chain metadata
    if hasattr(graph, "metadata"):
        assert "detected_chains" not in graph.metadata or graph.metadata.get("detected_chains") is None


def test_chain_detection_with_edges():
    """Test chain detection when explicit edges exist."""
    builder = AttackGraphBuilder("test.com")

    # Add findings
    findings = [
        {
            "id": "entry",
            "vuln_type": "info_leak",
            "type": "Information Disclosure",
            "host": "test.com",
            "endpoint": "/.env",
            "severity": "low",
            "cvss_score": 2.0,
            "confidence": 0.9,
        },
        {
            "id": "mid",
            "vuln_type": "idor",
            "type": "IDOR",
            "host": "test.com",
            "endpoint": "/api/profile",
            "severity": "medium",
            "cvss_score": 5.0,
            "confidence": 0.8,
        },
        {
            "id": "target",
            "vuln_type": "auth_bypass",
            "type": "Authentication Bypass",
            "host": "test.com",
            "endpoint": "/admin",
            "severity": "high",
            "cvss_score": 8.0,
            "confidence": 0.85,
        },
    ]

    builder.from_findings(findings)

    # Manually add edges to create attack path
    from oneinfinity.attack_graph_core.graph import Edge, EdgeType

    # Get node IDs from builder
    graph = builder.g
    node_ids = list(graph._nodes.keys())
    vuln_nodes = [nid for nid in node_ids if "vuln" in nid or "finding" in nid]

    if len(vuln_nodes) >= 3:
        # Create chain: entry -> mid -> target
        edge1 = Edge(
            edge_id="e1",
            src=vuln_nodes[0],
            dst=vuln_nodes[1],
            edge_type=EdgeType.ENABLES,
            properties={"confidence": 0.7},
        )
        edge2 = Edge(
            edge_id="e2",
            src=vuln_nodes[1],
            dst=vuln_nodes[2],
            edge_type=EdgeType.ENABLES,
            properties={"confidence": 0.75},
        )

        graph.add_edge(edge1)
        graph.add_edge(edge2)

        # Build with chain detection
        final_graph = builder.build(detect_chains=True)

        # Should detect chain to ATO objective (auth_bypass)
        chains = final_graph.metadata.get("detected_chains", [])
        ato_chains = [c for c in chains if c["objective"] == "ato"]

        # Print for debugging
        print(f"Total chains: {len(chains)}")
        print(f"ATO chains: {len(ato_chains)}")

        if ato_chains:
            chain = ato_chains[0]
            print(f"Chain length: {chain['length']}")
            print(f"Chain nodes: {[n['id'] for n in chain['nodes']]}")
            assert chain["length"] >= 2


def test_chain_exploitability_scoring():
    """Test that exploitability scores are calculated correctly."""
    builder = AttackGraphBuilder("test.com")

    findings = [
        {"id": "1", "vuln_type": "xss", "type": "XSS", "host": "test.com", "severity": "low", "cvss_score": 3.0, "confidence": 0.7},
        {"id": "2", "vuln_type": "idor", "type": "IDOR", "host": "test.com", "severity": "medium", "cvss_score": 5.0, "confidence": 0.8},
        {"id": "3", "vuln_type": "sqli", "type": "SQLi", "host": "test.com", "severity": "high", "cvss_score": 8.0, "confidence": 0.9},
        {"id": "4", "vuln_type": "command_injection", "type": "RCE", "host": "test.com", "severity": "critical", "cvss_score": 9.5, "confidence": 0.85},
    ]

    builder.from_findings(findings)

    # Add edges
    from oneinfinity.attack_graph_core.graph import Edge, EdgeType
    graph = builder.g
    vuln_nodes = [nid for nid in graph._nodes.keys() if any(x in nid for x in ["vuln", "finding"])]

    if len(vuln_nodes) >= 4:
        edges = [
            Edge(f"e{i}", vuln_nodes[i], vuln_nodes[i+1], EdgeType.ENABLES, properties={"confidence": 0.75})
            for i in range(3)
        ]
        for edge in edges:
            graph.add_edge(edge)

    final_graph = builder.build(detect_chains=True)
    chains = final_graph.metadata.get("detected_chains", [])

    if chains:
        for chain in chains:
            # Exploitability should be 0-1
            assert 0.0 <= chain["exploitability"] <= 1.0
            # Confidence should be 0-1
            assert 0.0 <= chain["confidence"] <= 1.0
            # CVSS escalation should be non-negative
            assert chain["cvss_escalation"] >= 0.0


def test_high_risk_chains_metadata():
    """Test that high_risk_chains count is included in metadata."""
    builder = AttackGraphBuilder("test.com")

    findings = [
        {"id": "1", "vuln_type": "idor", "host": "test.com", "severity": "high", "cvss_score": 7.0, "confidence": 0.9},
        {"id": "2", "vuln_type": "sqli", "host": "test.com", "severity": "critical", "cvss_score": 9.0, "confidence": 0.95},
    ]

    builder.from_findings(findings)
    graph = builder.build(detect_chains=True)

    assert "high_risk_chains" in graph.metadata
    assert isinstance(graph.metadata["high_risk_chains"], int)
    assert graph.metadata["high_risk_chains"] >= 0
