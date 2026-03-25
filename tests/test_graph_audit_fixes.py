"""Regression tests for graph audit remediation (2026-03-25)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from attack_graph_core.graph_engine import AttackGraphEngine, NodeType, EdgeType
from attack_graph_core.exploit_chain_engine import ExploitChainEngine


# ── helpers ────────────────────────────────────────────────────────────────

def fresh_engine():
    """Return a new in-memory AttackGraphEngine (no SQLite)."""
    return AttackGraphEngine()


# ── C1 tests ───────────────────────────────────────────────────────────────

class TestExploitChainEngineGraphValidation:

    def test_no_chain_when_nodes_disconnected(self):
        """CRITICAL: keyword match alone must NOT produce a chain."""
        engine = fresh_engine()
        # Add two isolated vuln nodes — no edge between them
        v1, _ = engine.get_or_create_node(
            NodeType.VULNERABILITY, "idor@a",
            properties={"vuln_type": "idor"}, severity="high",
        )
        v2, _ = engine.get_or_create_node(
            NodeType.VULNERABILITY, "bac@b",
            properties={"vuln_type": "bac"}, severity="high",
        )
        chain_eng = ExploitChainEngine(engine=engine)
        chains = chain_eng.detect_chains()
        assert chains == [], (
            f"Expected 0 chains from disconnected nodes, got {len(chains)}: "
            + ", ".join(c.name for c in chains)
        )

    def test_chain_produced_when_nodes_connected(self):
        """Chain IS allowed when a real graph edge connects the matched nodes."""
        engine = fresh_engine()
        v1, _ = engine.get_or_create_node(
            NodeType.VULNERABILITY, "idor@endpoint_a",
            properties={"vuln_type": "idor"}, severity="high",
        )
        v2, _ = engine.get_or_create_node(
            NodeType.VULNERABILITY, "bac@endpoint_b",
            properties={"vuln_type": "bac"}, severity="high",
        )
        # Wire a real edge
        engine.add_edge(v1.id, v2.id, EdgeType.LEADS_TO, label="idor enables bac")
        chain_eng = ExploitChainEngine(engine=engine)
        chains = chain_eng.detect_chains()
        names = [c.name for c in chains]
        assert any("idor" in n.lower() or "privilege" in n.lower() for n in names), (
            f"Expected IDOR→Privilege chain, got: {names}"
        )

    def test_single_step_chain_never_requires_path(self):
        """A single-keyword chain (only one node needed) should still match."""
        engine = fresh_engine()
        engine.get_or_create_node(
            NodeType.VULNERABILITY, "ssrf@target",
            properties={"vuln_type": "ssrf"}, severity="critical",
        )
        chain_eng = ExploitChainEngine(engine=engine)
        chains = chain_eng.detect_chains()
        ssrf_chains = [c for c in chains if "ssrf" in c.name.lower()]
        assert ssrf_chains, "Single-step SSRF chain should be found"
