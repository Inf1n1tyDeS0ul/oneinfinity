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


# ── C2 tests ───────────────────────────────────────────────────────────────

from attack_graph_core.graph_updater import GraphUpdater


class TestCanonicalEdgeTypes:

    def _make(self):
        engine = fresh_engine()
        return engine, GraphUpdater(engine=engine)

    def test_add_url_emits_has_endpoint(self):
        """add_url must wire parent→URL with HAS_ENDPOINT, not EXPOSES."""
        engine, updater = self._make()
        updater.add_target("example.com")
        updater.add_url("https://example.com/api/users", "example.com")

        target_id = engine._label_index.get((NodeType.TARGET, "example.com"))
        url_id = engine._label_index.get((NodeType.URL, "https://example.com/api/users"))
        assert target_id and url_id

        edges = engine.get_edges_from(target_id)
        edge_types = {e.edge_type for e in edges if e.target_id == url_id}
        assert EdgeType.HAS_ENDPOINT in edge_types, (
            f"Expected HAS_ENDPOINT, got: {edge_types}"
        )
        assert EdgeType.EXPOSES not in edge_types, (
            "EXPOSES must not appear for target→URL relationship"
        )

    def test_add_api_endpoint_emits_has_endpoint(self):
        """add_api_endpoint must wire parent→API_ENDPOINT with HAS_ENDPOINT."""
        engine, updater = self._make()
        updater.add_target("example.com")
        updater.add_api_endpoint("/api/v1/users", "GET", "https://example.com")

        target_id = engine._label_index.get((NodeType.TARGET, "example.com"))
        ep_id = engine._label_index.get(
            (NodeType.API_ENDPOINT, "GET https://example.com/api/v1/users")
        )
        assert target_id and ep_id

        edges = engine.get_edges_from(target_id)
        edge_types = {e.edge_type for e in edges if e.target_id == ep_id}
        assert EdgeType.HAS_ENDPOINT in edge_types, (
            f"Expected HAS_ENDPOINT, got: {edge_types}"
        )

    def test_add_parameter_emits_has_param(self):
        """add_parameter must wire URL→Parameter with HAS_PARAM, not EXPOSES."""
        engine, updater = self._make()
        updater.add_target("example.com")
        updater.add_url("https://example.com/search", "example.com")
        updater.add_parameter("q", "https://example.com/search")

        url_id = engine._label_index.get((NodeType.URL, "https://example.com/search"))
        param_id = engine._label_index.get(
            (NodeType.PARAMETER, "https://example.com/search?q")
        )
        assert url_id and param_id

        edges = engine.get_edges_from(url_id)
        edge_types = {e.edge_type for e in edges if e.target_id == param_id}
        assert EdgeType.HAS_PARAM in edge_types, (
            f"Expected HAS_PARAM, got: {edge_types}"
        )
        assert EdgeType.EXPOSES not in edge_types, (
            "EXPOSES must not appear for url→parameter relationship"
        )

    def test_path_validator_accepts_graph_updater_paths(self):
        """Paths built via graph_updater must pass GraphPathValidator strict mode."""
        from core.graph_path_validator import GraphPathValidator
        engine, updater = self._make()
        updater.add_target("example.com")
        updater.add_url("https://example.com/login", "example.com")
        updater.add_parameter("username", "https://example.com/login")
        vuln = updater.add_vulnerability(
            "sqli", "https://example.com/login", parameter="username",
            severity="critical", tool="test",
        )

        target_id = engine._label_index.get((NodeType.TARGET, "example.com"))
        target_node = engine.get_node(target_id)
        url_id = engine._label_index.get((NodeType.URL, "https://example.com/login"))
        url_node = engine.get_node(url_id)
        param_id = engine._label_index.get(
            (NodeType.PARAMETER, "https://example.com/login?username")
        )
        param_node = engine.get_node(param_id)
        vuln_node = engine.get_node(vuln.id)

        path = [target_node, url_node, param_node, vuln_node]
        validator = GraphPathValidator(engine=engine, strict=True)
        result = validator.validate(path)
        assert result.is_valid, f"Path validator rejected path: {result.reason}"
