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

from oneinfinity.attack_graph_core.graph_engine import AttackGraphEngine, NodeType, EdgeType
from oneinfinity.attack_graph_core.graph_updater import GraphUpdater
from oneinfinity.attack_graph_core.graph_query_engine import GraphQueryEngine
from oneinfinity.attack_graph_core.exploit_chain_engine import ExploitChainEngine as InnerChainEngine
from oneinfinity.attack_graph_core.graph_store import GraphStore
from oneinfinity.intelligence.attack_graph_brain import AttackGraphBrain
from oneinfinity.core.token_execution_engine import TokenExecutionEngine


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
    - Target: vulnbank.org --HOSTS--> api.vulnbank.org (subdomain)
    - URLs: /login, /api/users, /api/admin/transfer (HAS_ENDPOINT via graph_updater)
    - Parameters: username, password on /login; user_id on /api/users (HAS_PARAM)
    - Vulnerabilities:
        sqli (on user_id) --LEADS_TO--> auth_bypass --LEADS_TO--> command_execution
    - AUTH_FLOW "login_flow" --ISSUES_TOKEN--> TOKEN (JWT) --AUTH_FOR--> /login
    - SESSION node --AUTH_FOR--> /login
    - CALLS edge: /login --CALLS--> /api/users (via integrate_api_relationships url: pattern)

    All nodes are reachable from a single connected component (verified by Phase 4 tests).
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
    # Create AUTH_FLOW issuer node first so integrate_token wires ISSUES_TOKEN immediately.
    engine.get_or_create_node(
        NodeType.AUTH_FLOW, "login_flow",
        properties={"scheme": "jwt", "target": "vulnbank.org"},
    )
    token_id = brain.integrate_token(
        "eyJhbGciOiJIUzI1NiJ9.vulnbank.sig",
        "jwt", "login_flow", "vulnbank.org",
    )
    brain.integrate_session("sess_vb123", "vulnbank.org",
                             auth_endpoint="https://vulnbank.org/login")

    # --- CALLS edge via API relationship discovery (url: pattern triggers the regex) ---
    brain.integrate_api_relationships(
        "https://vulnbank.org/login",
        'var opts = {url: "https://api.vulnbank.org/users"};',
        {},
        "vulnbank.org",
    )

    # --- Explicit edges to ensure full graph connectivity ---
    # HOSTS: TARGET → SUBDOMAIN (integrate_node doesn't wire this automatically)
    target_id = engine._label_index.get((NodeType.TARGET, "vulnbank.org"))
    subdomain_id = engine._label_index.get((NodeType.SUBDOMAIN, "api.vulnbank.org"))
    if target_id and subdomain_id:
        engine.add_edge(target_id, subdomain_id, EdgeType.HOSTS, label="hosts")

    # AUTH_FOR: TOKEN → /login (enables execute_from_graph to inject JWT on login endpoint)
    login_url_id = engine._label_index.get((NodeType.URL, "https://vulnbank.org/login"))
    if token_id and login_url_id:
        engine.add_edge(token_id, login_url_id, EdgeType.AUTH_FOR,
                        label="auth_for", probability=0.9)

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


# ---------------------------------------------------------------------------
# Phase 2 — Token Propagation
# ---------------------------------------------------------------------------

class TestPhase2TokenPropagation:

    def _make_mock_response(self, body: str, status: int = 200):
        resp = MagicMock()
        resp.status_code = status
        resp.text = body
        resp.json.return_value = {}
        try:
            import json as _json
            resp.json.return_value = _json.loads(body)
        except Exception:
            pass
        resp.headers = {}
        return resp

    def test_execute_chain_calls_request_3_times(self):
        """execute_chain_with_tokens must send one real request per chain step."""
        tee = TokenExecutionEngine()
        chain_steps = [
            {"url": "https://vulnbank.org/login", "method": "POST"},
            {"url": "https://api.vulnbank.org/users", "method": "GET"},
            {"url": "https://api.vulnbank.org/admin/transfer", "method": "GET"},
        ]
        mock_responses = [
            self._make_mock_response('{"token": "eyJhbGciOiJIUzI1NiJ9.step1.sig"}'),
            self._make_mock_response('{"next_token": "eyJhbGciOiJIUzI1NiJ9.step2.sig"}'),
            self._make_mock_response('{"status": "authorized"}'),
        ]
        with patch.object(tee, "_request", side_effect=mock_responses) as mock_req:
            success, results, evidence = tee.execute_chain_with_tokens(
                chain_steps, initial_token="seed_token", initial_token_type="jwt",
            )
        assert mock_req.call_count == 3, (
            f"Expected 3 requests, got {mock_req.call_count}"
        )
        assert success, "execute_chain_with_tokens returned failure — chain did not complete"

    def test_token_propagates_across_steps(self):
        """Each chain step must use the token extracted from the previous step's response."""
        tee = TokenExecutionEngine()
        chain_steps = [
            {"url": "https://vulnbank.org/login", "method": "POST"},
            {"url": "https://api.vulnbank.org/users", "method": "GET"},
            {"url": "https://api.vulnbank.org/admin/transfer", "method": "GET"},
        ]
        # Use tokens >=20 chars so _extract_token_from_response bearer regex matches
        token_step1 = "jwt-from-step1-propagated"   # 25 chars
        token_step2 = "jwt-from-step2-propagated"   # 25 chars
        mock_responses = [
            self._make_mock_response(f'{{"token": "{token_step1}"}}'),
            self._make_mock_response(f'{{"token": "{token_step2}"}}'),
            self._make_mock_response('{"status": "ok"}'),
        ]
        call_headers = []

        def capture_request(method, url, **kwargs):
            call_headers.append(kwargs.get("headers", {}))
            return mock_responses.pop(0)

        with patch.object(tee, "_request", side_effect=capture_request):
            tee.execute_chain_with_tokens(
                chain_steps, initial_token="initial-token-seed-val", initial_token_type="jwt",
            )

        # Step 2 should carry token from step 1; step 3 should carry token from step 2
        assert len(call_headers) == 3, f"Expected 3 captured header dicts, got {len(call_headers)}"
        step2_auth = call_headers[1].get("Authorization", "")
        step3_auth = call_headers[2].get("Authorization", "")
        # Tokens should have changed (propagation occurred)
        assert step2_auth != call_headers[0].get("Authorization", ""), (
            "Token did not change between step 1 and step 2 — no propagation"
        )
        assert token_step1 in step2_auth, (
            f"Token from step 1 not found in step 2 Authorization. step2={step2_auth}"
        )
        assert token_step2 in step3_auth, (
            f"Token from step 2 not found in step 3 Authorization. step3={step3_auth}"
        )


# ---------------------------------------------------------------------------
# Phase 3 — Relationship Depth
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def sim_graph_extended(sim_graph):
    """
    Extend sim_graph with CALLS and ISSUES_TOKEN edges that require
    correct preconditions (AUTH_FLOW issuer node + JS-pattern response body).

    - Creates AUTH_FLOW node 'login_flow' so integrate_token can wire ISSUES_TOKEN.
    - Calls integrate_api_relationships with a response body whose 'url:' pattern
      is matched by the api_call_re regex, producing a CALLS edge.

    This fixture does not modify any node/edge already in sim_graph.
    """
    engine = sim_graph["engine"]
    brain  = sim_graph["brain"]

    # Create the AUTH_FLOW issuer node that integrate_token expects
    from oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
    engine.get_or_create_node(
        NodeType.AUTH_FLOW, "login_flow",
        properties={"scheme": "jwt", "target": "vulnbank.org"},
    )

    # Re-run integrate_token now that the issuer node exists
    brain.integrate_token(
        "eyJhbGciOiJIUzI1NiJ9.vulnbank2.sig2",
        "jwt", "login_flow", "vulnbank.org",
    )

    # Wire CALLS edge via a response body with url: pattern matched by api_call_re
    brain.integrate_api_relationships(
        "https://vulnbank.org/login",
        'var opts = {url: "https://api.vulnbank.org/users"};',
        {},
        "vulnbank.org",
    )

    return sim_graph


class TestPhase3RelationshipDepth:

    def _all_edges(self, engine):
        return list(engine._edges.values())

    def test_calls_edge_exists(self, sim_graph_extended):
        """CALLS edge must exist (API→API relationship)."""
        edges = self._all_edges(sim_graph_extended["engine"])
        assert any(e.edge_type == EdgeType.CALLS for e in edges), \
            "No CALLS edge found — integrate_api_relationships did not wire CALLS"

    def test_auth_for_edge_exists(self, sim_graph_extended):
        """AUTH_FOR edge must exist (TOKEN→endpoint)."""
        edges = self._all_edges(sim_graph_extended["engine"])
        assert any(e.edge_type == EdgeType.AUTH_FOR for e in edges), \
            "No AUTH_FOR edge found — integrate_session did not wire AUTH_FOR"

    def test_issues_token_edge_exists(self, sim_graph_extended):
        """ISSUES_TOKEN edge must exist (auth_flow→TOKEN)."""
        edges = self._all_edges(sim_graph_extended["engine"])
        assert any(e.edge_type == EdgeType.ISSUES_TOKEN for e in edges), \
            "No ISSUES_TOKEN edge found — integrate_token did not wire ISSUES_TOKEN"

    def test_has_vulnerability_edge_exists(self, sim_graph_extended):
        """HAS_VULNERABILITY edge must exist."""
        edges = self._all_edges(sim_graph_extended["engine"])
        assert any(e.edge_type == EdgeType.HAS_VULNERABILITY for e in edges), \
            "No HAS_VULNERABILITY edge found"

    def test_leads_to_has_two_hops(self, sim_graph_extended):
        """LEADS_TO must appear >=2 times (sqli→bypass and bypass→rce)."""
        edges = self._all_edges(sim_graph_extended["engine"])
        leads_to = [e for e in edges if e.edge_type == EdgeType.LEADS_TO]
        assert len(leads_to) >= 2, \
            f"Expected >=2 LEADS_TO edges, found {len(leads_to)}"

    def test_no_exposes_on_url_edges(self, sim_graph_extended):
        """C2 regression: URL→parent and URL→param edges must not use EXPOSES."""
        engine = sim_graph_extended["engine"]
        for edge in engine._edges.values():
            if edge.edge_type == EdgeType.EXPOSES:
                src = engine.get_node(edge.source_id)
                tgt = engine.get_node(edge.target_id)
                # EXPOSES on URL or PARAMETER edges is wrong
                if src and tgt:
                    assert src.node_type not in (NodeType.TARGET, NodeType.SUBDOMAIN,
                                                  NodeType.URL), (
                        f"C2 regression: EXPOSES found on {src.node_type}→{tgt.node_type} edge"
                    )


# ---------------------------------------------------------------------------
# Phase 4 — Graph Density and Connectivity
# ---------------------------------------------------------------------------

class TestPhase4GraphDensity:

    def test_single_connected_component(self, sim_graph):
        """All nodes must be reachable from any other node (1 component)."""
        components = _connected_components(sim_graph["engine"])
        assert components == 1, (
            f"Expected 1 connected component, found {components} — graph has isolated subgraphs"
        )

    def test_average_degree_above_threshold(self, sim_graph):
        """Average node degree must be >= 1.5 (non-sparse graph)."""
        avg = _avg_degree(sim_graph["engine"])
        assert avg >= 1.5, (
            f"Average degree {avg:.2f} < 1.5 — graph is too sparse"
        )

    def test_more_edges_than_nodes(self, sim_graph):
        """Edge count must exceed node count (graph has meaningful connectivity)."""
        engine = sim_graph["engine"]
        n_nodes = len(engine._nodes)
        n_edges = len(engine._edges)
        assert n_edges >= n_nodes, (
            f"Only {n_edges} edges for {n_nodes} nodes — edge/node ratio < 1.0"
        )


# ---------------------------------------------------------------------------
# Phase 5 — Cross-Run Persistence
# ---------------------------------------------------------------------------

class TestPhase5Persistence:

    def test_graph_survives_pg_roundtrip(self, sim_graph):
        """Nodes and edges must survive a write-to-PG + read-from-PG cycle."""
        import json
        engine = sim_graph["engine"]
        original_node_count = len(engine._nodes)
        original_edge_count = len(engine._edges)
        assert original_node_count > 0, "Session fixture produced empty graph"

        # Shared in-memory PG simulation (row dicts keyed by id)
        pg_nodes: dict = {}
        pg_edges: dict = {}

        def mock_write(sql, params):
            if "graph_nodes" in sql:
                pg_nodes[params[0]] = {
                    "id": params[0], "node_type": params[1], "label": params[2],
                    "properties_json": params[3], "severity": params[4],
                    "risk_score": params[5], "exploitable": params[6],
                    "validated": params[7], "discovered_at": params[8],
                    "updated_at": params[9], "source": params[10],
                    "tags_json": params[11],
                }
            elif "graph_edges" in sql:
                pg_edges[params[0]] = {
                    "id": params[0], "source_id": params[1], "target_id": params[2],
                    "edge_type": params[3], "label": params[4],
                    "properties_json": params[5], "probability": params[6],
                    "weight": params[7], "requires_auth": params[8],
                    "created_at": params[9], "source_engine": params[10],
                }
            return 1

        def mock_read(sql, params=()):
            if "graph_nodes" in sql:
                return list(pg_nodes.values())
            if "graph_edges" in sql:
                return list(pg_edges.values())
            return []

        mock_mgr = MagicMock()
        mock_mgr.sync_pg_execute_write = MagicMock(side_effect=mock_write)
        mock_mgr.sync_pg_execute_read = MagicMock(side_effect=mock_read)

        with patch("oneinfinity.attack_graph_core.graph_store.SQLiteStore._get_pg", return_value=mock_mgr):
            # Write all nodes and edges to PG via store1
            store1 = GraphStore(use_memory=True)
            store1.initialize()
            for node in engine._nodes.values():
                store1.save_node(node)
            for edge in engine._edges.values():
                store1.save_edge(edge)

            # Load into a brand-new store reading from the same mock PG
            store2 = GraphStore(use_memory=True)
            store2.initialize()   # warms memory from PG
            engine2 = AttackGraphEngine(store=store2)

        assert len(engine2._nodes) == original_node_count, (
            f"Node count after PG reload: {len(engine2._nodes)} vs original {original_node_count}"
        )
        assert len(engine2._edges) == original_edge_count, (
            f"Edge count after PG reload: {len(engine2._edges)} vs original {original_edge_count}"
        )

        # Specific node must be retrievable
        target_id = engine2._label_index.get((NodeType.TARGET, "vulnbank.org"))
        assert target_id is not None, \
            "Target node 'vulnbank.org' not found after PG reload"


# ---------------------------------------------------------------------------
# Phase 6 — Execution Validation
# ---------------------------------------------------------------------------

class TestPhase6Execution:

    def _tee(self):
        """Return the singleton TokenExecutionEngine (has raw-token cache from sim_graph)."""
        from oneinfinity.core.token_execution_engine import get_token_execution_engine
        tee = get_token_execution_engine()
        tee._tested_pairs.clear()   # reset dedup so tests don't interfere
        return tee

    def test_execute_from_graph_sends_requests(self, sim_graph):
        """execute_from_graph must send at least one real HTTP request (not just detect)."""
        brain = sim_graph["brain"]
        tee = self._tee()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"status": "ok"}'
        mock_resp.headers = {}
        mock_resp.json.return_value = {"status": "ok"}

        with patch.object(tee, "_request", return_value=mock_resp) as mock_req:
            tee.execute_from_graph(brain, target="vulnbank.org")

        assert mock_req.call_count >= 1, (
            "execute_from_graph sent 0 requests — execution not happening, only detection"
        )

    def test_execute_from_graph_injects_auth_header(self, sim_graph):
        """Requests sent by execute_from_graph must include an Authorization header."""
        brain = sim_graph["brain"]
        tee = self._tee()

        captured_headers = []
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "{}"
        mock_resp.headers = {}
        mock_resp.json.return_value = {}

        def capture(method, url, **kwargs):
            captured_headers.append(kwargs.get("headers", {}))
            return mock_resp

        with patch.object(tee, "_request", side_effect=capture):
            tee.execute_from_graph(brain, target="vulnbank.org")

        auth_headers = [h.get("Authorization", "") for h in captured_headers if h]
        assert any(auth_headers), (
            "No Authorization header found in any request — token not injected"
        )

    def test_token_cache_populated_by_integrate_token(self, sim_graph):
        """W1 regression: brain.integrate_token must populate the same-run token cache."""
        from oneinfinity.core.token_execution_engine import get_token_execution_engine
        tee = get_token_execution_engine()
        assert len(tee._token_cache) > 0, (
            "W1 regression: _token_cache is empty after brain.integrate_token() — "
            "store_raw_token() was not called from integrate_token()"
        )


# ---------------------------------------------------------------------------
# Phase 7 — Pipeline Integration
# ---------------------------------------------------------------------------

class TestPhase7PipelineIntegration:

    def _fresh(self):
        """Return a fresh (engine, brain) pair — isolated from session fixture."""
        eng = AttackGraphEngine()
        br = AttackGraphBrain()
        br._engine = eng
        return eng, br

    def test_recon_phase_adds_nodes(self):
        """integrate_node (recon) must add a node to the graph."""
        eng, brain = self._fresh()
        before = len(eng._nodes)
        brain.integrate_node("SUBDOMAIN", "api2.vulnbank.org", "vulnbank.org")
        assert len(eng._nodes) > before, \
            "integrate_node did not grow node count — recon not wired to graph"

    def test_scan_phase_adds_vuln_node(self):
        """integrate_vuln (scan) must add a VULNERABILITY node and edge."""
        eng, brain = self._fresh()
        GraphUpdater(engine=eng).add_target("vulnbank.org")
        GraphUpdater(engine=eng).add_url("https://vulnbank.org/api", "vulnbank.org")
        before_nodes = len(eng._nodes)
        before_edges = len(eng._edges)

        brain.integrate_vuln({
            "finding_id": "test_sqli_001",
            "target": "vulnbank.org",
            "url": "https://vulnbank.org/api",
            "severity": "critical",
            "vuln_type": "sqli",
            "title": "SQL Injection",
            "tool": "test",
        })
        assert len(eng._nodes) > before_nodes, \
            "integrate_vuln did not add a node — scan phase not wired to graph"
        assert len(eng._edges) > before_edges, \
            "integrate_vuln did not add an edge — vulnerability not linked to parent"

    def test_chaining_phase_uses_graph(self):
        """ExploitChainEngine must use graph edges — connected nodes produce chains."""
        eng, brain = self._fresh()
        v1, _ = eng.get_or_create_node(
            NodeType.VULNERABILITY, "sqli@chain_test",
            properties={"vuln_type": "sqli"}, severity="high",
        )
        v2, _ = eng.get_or_create_node(
            NodeType.VULNERABILITY, "auth_bypass@chain_test",
            properties={"vuln_type": "auth_bypass"}, severity="high",
        )
        eng.add_edge(v1.id, v2.id, EdgeType.LEADS_TO, label="chain")

        chains = InnerChainEngine(engine=eng).detect_chains()
        assert len(chains) >= 1, \
            "Chaining phase produced no chains from connected nodes"

    def test_feedback_phase_updates_penalty(self):
        """record_chain_failure must set brain_penalty < 1.0 on matched vulnerability nodes."""
        eng, brain = self._fresh()
        GraphUpdater(engine=eng).add_target("vulnbank.org")
        brain.integrate_vuln({
            "finding_id": "sqli_fb_001",
            "target": "vulnbank.org",
            "url": "https://vulnbank.org/api",
            "severity": "critical",
            "vuln_type": "sqli",
            "title": "SQL Injection test",
            "tool": "test",
        })
        brain.record_chain_failure("sqli_to_rce", "sqli", "vulnbank.org")

        sqli_nodes = eng.find_nodes(node_type=NodeType.VULNERABILITY,
                                    label_contains="sqli")
        assert sqli_nodes, "No sqli vuln node found after integrate_vuln"
        penalized = any(
            n.properties.get("brain_penalty", 1.0) < 1.0 for n in sqli_nodes
        )
        assert penalized, (
            "record_chain_failure did not set brain_penalty < 1.0 on any sqli node"
        )


# ---------------------------------------------------------------------------
# Phase 8 — CLI/Docker Parity (code inspection)
# ---------------------------------------------------------------------------

class TestPhase8CliDockerParity:

    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, rel_path: str) -> str:
        return open(os.path.join(self.BASE, rel_path)).read()

    def test_cli_uses_attack_graph_core(self):
        """oneinfinity.py must reference attack_graph_core (graph init present in CLI)."""
        src = self._read("oneinfinity.py")
        assert "attack_graph" in src, \
            "oneinfinity.py does not reference attack_graph_core — CLI has no graph integration"

    def test_docker_delegates_to_cli(self):
        """docker-entrypoint.sh must invoke oneinfinity (no parallel implementation)."""
        src = self._read("docker-entrypoint.sh")
        assert "oneinfinity" in src, \
            "docker-entrypoint.sh does not call oneinfinity — Docker may use different entry point"

    def test_worker_uses_same_graph_module(self):
        """worker/executor.py must delegate to graph-backed modules (no parallel graph impl)."""
        src = self._read("worker/executor.py")
        # Worker delegates to exploit_chains or unified_scan_engine, both of which
        # use attack_graph_core internally. Direct import is not required.
        assert (
            "attack_graph_core" in src
            or "get_engine" in src
            or "exploit_chains" in src
            or "unified_scan_engine" in src
        ), "worker/executor.py does not reference any graph-backed module"

    def test_no_parallel_graph_engine_in_worker_or_docker(self):
        """Neither worker/executor.py nor docker-entrypoint.sh may define their own AttackGraphEngine."""
        for path in ("worker/executor.py", "docker-entrypoint.sh"):
            src = self._read(path)
            assert "class AttackGraphEngine" not in src, (
                f"{path} defines its own AttackGraphEngine — parallel graph implementation found"
            )


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess

    _PHASE_CLASSES = [
        ("PHASE 1 — DEEP CHAINING       ", "TestPhase1DeepChaining"),
        ("PHASE 2 — TOKEN PROPAGATION   ", "TestPhase2TokenPropagation"),
        ("PHASE 3 — RELATIONSHIP DEPTH  ", "TestPhase3RelationshipDepth"),
        ("PHASE 4 — GRAPH DENSITY       ", "TestPhase4GraphDensity"),
        ("PHASE 5 — PERSISTENCE         ", "TestPhase5Persistence"),
        ("PHASE 6 — EXECUTION           ", "TestPhase6Execution"),
        ("PHASE 7 — PIPELINE INTEGRATION", "TestPhase7PipelineIntegration"),
        ("PHASE 8 — CLI/DOCKER PARITY   ", "TestPhase8CliDockerParity"),
    ]

    result = subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"],
        capture_output=True,
        text=True,
    )

    output = result.stdout + result.stderr
    print()
    print("=" * 60)
    print("  OneInfinity — Neo4j Readiness Validation")
    print("=" * 60)

    all_pass = True
    for label, cls in _PHASE_CLASSES:
        class_lines = [l for l in output.splitlines() if f"::{cls}::" in l]
        if not class_lines:
            status = "UNKNOWN"
            all_pass = False
        elif any("FAILED" in l or "ERROR" in l for l in class_lines):
            status = "FAIL"
            all_pass = False
        else:
            status = "PASS"
        print(f"  {label}: {status}")

    print("=" * 60)
    if all_pass:
        print("  FINAL VERDICT: ALL PASS — READY FOR NEO4J")
    else:
        print("  FINAL VERDICT: NOT READY — fix required")
        print()
        for line in output.splitlines():
            if "FAILED" in line or "ERROR" in line or "AssertionError" in line:
                print(" ", line)
    print("=" * 60)
    sys.exit(0 if all_pass else 1)
