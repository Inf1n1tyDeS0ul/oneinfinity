"""
tests/test_neo4j_readiness.py
Neo4j Readiness Validation — 8-phase automated pass/fail gate.

Run as pytest:   pytest tests/test_neo4j_readiness.py -v
Run standalone:  python3 tests/test_neo4j_readiness.py
"""
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock

from attack_graph_core.graph_engine import AttackGraphEngine, NodeType, EdgeType
from attack_graph_core.graph_updater import GraphUpdater
from attack_graph_core.graph_query_engine import GraphQueryEngine
from attack_graph_core.exploit_chain_engine import ExploitChainEngine as InnerChainEngine
from attack_graph_core.graph_store import GraphStore
from attack_graph_brain import AttackGraphBrain
from core.token_execution_engine import TokenExecutionEngine


# ---------------------------------------------------------------------------
# Inline graph metric helpers (no such methods exist on AttackGraphEngine)
# ---------------------------------------------------------------------------

def _connected_components(engine) -> int:
    """BFS over undirected projection. Returns number of connected components."""
    visited, components = set(), 0
    for start_id in engine._nodes:
        if start_id in visited:
            continue
        queue = [start_id]
        while queue:
            nid = queue.pop(0)
            if nid in visited:
                continue
            visited.add(nid)
            for e in engine.get_edges_from(nid):
                queue.append(e.target_id)
            for e in engine.get_edges_to(nid):
                queue.append(e.source_id)
        components += 1
    return components


def _avg_degree(engine) -> float:
    """Average degree (in + out) per node."""
    n = len(engine._nodes)
    return (2 * len(engine._edges)) / n if n else 0.0


# ---------------------------------------------------------------------------
# Session fixture — builds vulnbank.org simulation graph once for all phases
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sim_graph():
    """
    Build a realistic vulnbank.org simulation graph.
    Returned dict: {"engine": engine, "updater": updater, "brain": brain,
                    "vuln_sqli": node, "vuln_bypass": node, "vuln_rce": node}

    Graph contents:
    - Target: vulnbank.org + subdomain api.vulnbank.org
    - URLs: /login, /api/users, /api/admin/transfer (HAS_ENDPOINT via graph_updater)
    - Parameters: username, password on /login; user_id on /api/users (HAS_PARAM)
    - Vulnerabilities:
        sqli (on user_id) --LEADS_TO--> auth_bypass --LEADS_TO--> command_execution
        vuln_type keywords match "SQLi -> Auth Bypass -> Full Compromise" CHAIN_DEFINITION
    - TOKEN node (JWT) with ISSUES_TOKEN from login_flow and AUTH_FOR to api endpoints
    - SESSION node with AUTH_FOR to /login
    - CALLS edge: /login -> /api/users (via integrate_api_relationships)
    """
    engine = AttackGraphEngine()  # in-memory, no SQLite

    # Inject engine into brain (bypasses lazy get_engine() which hits global singleton)
    brain = AttackGraphBrain()
    brain._engine = engine

    updater = GraphUpdater(engine=engine)

    # --- Structural graph ---
    updater.add_target("vulnbank.org")
    brain.integrate_node("SUBDOMAIN", "api.vulnbank.org", "vulnbank.org")

    updater.add_url("https://vulnbank.org/login", "vulnbank.org")
    updater.add_url("https://api.vulnbank.org/users", "api.vulnbank.org")
    updater.add_url("https://api.vulnbank.org/admin/transfer", "api.vulnbank.org")

    updater.add_parameter("username", "https://vulnbank.org/login")
    updater.add_parameter("password", "https://vulnbank.org/login")
    updater.add_parameter("user_id", "https://api.vulnbank.org/users")

    # --- 3-hop vulnerability chain ---
    # vuln_type values MUST match keywords in a CHAIN_DEFINITIONS vuln_sequence.
    # Pattern "SQLi -> Auth Bypass -> Full Compromise" uses ["sqli", "auth_bypass"].
    # command_execution is the terminal impact node.
    vuln_sqli = updater.add_vulnerability(
        "sqli", "https://api.vulnbank.org/users",
        parameter="user_id", severity="critical", tool="test",
    )
    vuln_bypass, _ = engine.get_or_create_node(
        NodeType.VULNERABILITY, "auth_bypass@api",
        properties={"vuln_type": "auth_bypass"}, severity="high",
    )
    vuln_rce, _ = engine.get_or_create_node(
        NodeType.VULNERABILITY, "command_execution@api",
        properties={"vuln_type": "command_execution"}, severity="critical",
    )
    engine.add_edge(vuln_sqli.id, vuln_bypass.id, EdgeType.LEADS_TO,
                    label="sqli enables auth bypass")
    engine.add_edge(vuln_bypass.id, vuln_rce.id, EdgeType.LEADS_TO,
                    label="auth bypass enables rce")

    # --- Token and session ---
    brain.integrate_token(
        "eyJhbGciOiJIUzI1NiJ9.vulnbank.sig",
        "jwt", "login_flow", "vulnbank.org",
    )
    brain.integrate_session("sess_vb123", "vulnbank.org",
                             auth_endpoint="https://vulnbank.org/login")

    # --- CALLS edge via API relationship discovery ---
    brain.integrate_api_relationships(
        "https://vulnbank.org/login",
        '{"fetch": "https://api.vulnbank.org/users"}',
        {},
        "vulnbank.org",
    )

    return {
        "engine": engine,
        "updater": updater,
        "brain": brain,
        "vuln_sqli": vuln_sqli,
        "vuln_bypass": vuln_bypass,
        "vuln_rce": vuln_rce,
    }


# ---------------------------------------------------------------------------
# Phase 1 — Deep Chaining
# ---------------------------------------------------------------------------

class TestPhase1DeepChaining:

    def test_dfs_finds_3hop_path(self, sim_graph):
        """dfs_paths must return a path of >=3 nodes from sqli to command_execution."""
        engine = sim_graph["engine"]
        sqli_id = sim_graph["vuln_sqli"].id
        rce_id = sim_graph["vuln_rce"].id

        query = GraphQueryEngine(engine=engine)
        paths = query.dfs_paths(sqli_id, rce_id, max_depth=6)

        assert len(paths) >= 1, "No DFS path found between sqli and rce nodes"
        assert len(paths[0]) >= 3, (
            f"Expected path length >=3, got {len(paths[0])}: {paths[0]}"
        )

    def test_chain_engine_detects_connected_chain(self, sim_graph):
        """Inner ExploitChainEngine must detect a chain when LEADS_TO edges connect nodes."""
        engine = sim_graph["engine"]
        chains = InnerChainEngine(engine=engine).detect_chains()
        assert len(chains) >= 1, (
            "Expected >=1 chain from connected vuln nodes, got 0"
        )

    def test_chain_engine_rejects_isolated_nodes(self):
        """C1 regression: isolated vuln nodes with matching keywords must produce 0 chains."""
        isolated = AttackGraphEngine()
        isolated.get_or_create_node(
            NodeType.VULNERABILITY, "sqli@isolated",
            properties={"vuln_type": "sqli"}, severity="high",
        )
        isolated.get_or_create_node(
            NodeType.VULNERABILITY, "auth_bypass@isolated",
            properties={"vuln_type": "auth_bypass"}, severity="high",
        )
        # No edges between them
        chains = InnerChainEngine(engine=isolated).detect_chains()
        assert chains == [], (
            f"C1 regression: got {len(chains)} chains from disconnected nodes"
        )
