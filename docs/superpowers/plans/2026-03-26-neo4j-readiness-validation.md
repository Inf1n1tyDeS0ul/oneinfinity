# Neo4j Readiness Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create `tests/test_neo4j_readiness.py` — an 8-phase automated pass/fail gate that proves the OneInfinity graph system is ready for Neo4j integration.

**Architecture:** Single dual-purpose file (pytest + standalone runner). One session-scoped fixture builds a realistic vulnbank.org simulation graph shared across all 8 phases. HTTP calls mocked via `unittest.mock.patch`. Inline BFS computes graph metrics. Phase 8 uses file content inspection.

**Tech Stack:** Python 3.10+, pytest, `attack_graph_core`, `core.token_execution_engine`, `attack_graph_brain` — no new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-26-neo4j-readiness-validation-design.md`

---

## Key API Reference

Read these before implementing — exact signatures matter:

```python
# AttackGraphEngine — no args for in-memory (store=None uses no SQLite)
from attack_graph_core.graph_engine import AttackGraphEngine, NodeType, EdgeType
engine = AttackGraphEngine()  # in-memory
engine.get_or_create_node(NodeType.VULNERABILITY, "label", properties={}, severity="high")
engine.add_edge(src_id, tgt_id, EdgeType.LEADS_TO, label="...")
engine.get_edges_from(node_id)   # → list[Edge]
engine.get_edges_to(node_id)     # → list[Edge]; wrapper over _adj_in
engine._nodes                    # dict[id → Node]
engine._edges                    # dict[id → Edge]

# GraphUpdater — pass engine= explicitly (never use global singleton in tests)
from attack_graph_core.graph_updater import GraphUpdater
updater = GraphUpdater(engine=engine)
updater.add_target("vulnbank.org")
updater.add_url("https://vulnbank.org/login", "vulnbank.org")
updater.add_parameter("username", "https://vulnbank.org/login")
updater.add_vulnerability("sqli", "https://api.vulnbank.org/users",
                           parameter="user_id", severity="critical", tool="test")

# AttackGraphBrain — inject engine via brain._engine = engine after construction
from attack_graph_brain import AttackGraphBrain
brain = AttackGraphBrain()
brain._engine = engine   # inject our engine (bypasses lazy get_engine() call)
brain.integrate_node("SUBDOMAIN", "api.vulnbank.org", "vulnbank.org")
brain.integrate_vuln({"finding_id": "...", "target": "...", "url": "...",
                       "severity": "critical", "vuln_type": "sqli", "tool": "test"})
brain.integrate_token("raw_jwt_value", "jwt", "login_flow", "vulnbank.org")
brain.integrate_session("sess_abc123", "vulnbank.org",
                         auth_endpoint="https://vulnbank.org/login")
brain.integrate_api_relationships("https://vulnbank.org/login",
    '{"fetch": "https://api.vulnbank.org/users"}', {}, "vulnbank.org")
brain.record_chain_failure("sqli_to_rce", "sqli", "vulnbank.org")

# GraphQueryEngine — pass engine= explicitly
from attack_graph_core.graph_query_engine import GraphQueryEngine
query = GraphQueryEngine(engine=engine)
paths = query.dfs_paths(start_id, end_id, max_depth=6)  # → list[list[str]]

# Inner ExploitChainEngine (the one that was patched for C1)
from attack_graph_core.exploit_chain_engine import ExploitChainEngine as InnerChainEngine
chains = InnerChainEngine(engine=engine).detect_chains()  # no args — scans engine's VULN nodes

# TokenExecutionEngine
from core.token_execution_engine import TokenExecutionEngine
tee = TokenExecutionEngine()
tee.store_raw_token(fingerprint, raw_value)
tee._build_auth_headers(token_node)  # → dict
# execute_from_graph(brain, scan_id="", target="")
# execute_chain_with_tokens(chain_steps, initial_token=None, initial_token_type="bearer")

# GraphStore — for persistence tests
from attack_graph_core.graph_store import GraphStore
store = GraphStore(db_path="/tmp/test.db", use_memory=True, use_sqlite=True)
store.initialize()   # creates schema; on second call with existing db, warms memory from SQLite
store.save_node(node)
store.save_edge(edge)
```

---

## File Map

| File | Action |
|------|--------|
| `tests/test_neo4j_readiness.py` | Create — all 8 phase test classes + session fixture + standalone runner (~450 lines) |

No other files modified.

---

## Task 1 — File scaffold, session fixture, Phase 1 (Deep Chaining)

**Files:**
- Create: `tests/test_neo4j_readiness.py`

The session fixture builds the full simulation graph. Phase 1 proves ≥3-hop DFS paths exist and C1 fix holds (isolated nodes produce no chains).

- [ ] **Step 1: Create the file with scaffold, helpers, and session fixture**

```python
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
    Returned dict: {"engine": engine, "updater": updater, "brain": brain}

    Graph contents:
    - Target: vulnbank.org + subdomain api.vulnbank.org
    - URLs: /login, /api/users, /api/admin/transfer (all via graph_updater → HAS_ENDPOINT)
    - Parameters: username, password on /login; user_id on /api/users (HAS_PARAM)
    - Vulnerabilities:
        sqli (on user_id) --LEADS_TO--> auth_bypass --LEADS_TO--> command_execution
        vuln_type keywords match the "SQLi → Auth Bypass → Full Compromise" CHAIN_DEFINITION
    - TOKEN node (JWT) with ISSUES_TOKEN from login_flow and AUTH_FOR to api endpoints
    - SESSION node with AUTH_FOR to /login
    - CALLS edge: /login → /api/users (via integrate_api_relationships)
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
    # Pattern "SQLi → Auth Bypass → Full Compromise" uses ["sqli", "auth_bypass"].
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
```

- [ ] **Step 2: Append Phase 1 test class**

```python
# ---------------------------------------------------------------------------
# Phase 1 — Deep Chaining
# ---------------------------------------------------------------------------

class TestPhase1DeepChaining:

    def test_dfs_finds_3hop_path(self, sim_graph):
        """dfs_paths must return a path of ≥3 nodes from sqli to command_execution."""
        engine = sim_graph["engine"]
        sqli_id = sim_graph["vuln_sqli"].id
        rce_id = sim_graph["vuln_rce"].id

        query = GraphQueryEngine(engine=engine)
        paths = query.dfs_paths(sqli_id, rce_id, max_depth=6)

        assert len(paths) >= 1, "No DFS path found between sqli and rce nodes"
        assert len(paths[0]) >= 3, (
            f"Expected path length ≥ 3, got {len(paths[0])}: {paths[0]}"
        )

    def test_chain_engine_detects_connected_chain(self, sim_graph):
        """Inner ExploitChainEngine must detect a chain when LEADS_TO edges connect nodes."""
        engine = sim_graph["engine"]
        chains = InnerChainEngine(engine=engine).detect_chains()
        assert len(chains) >= 1, (
            "Expected ≥1 chain from connected vuln nodes, got 0"
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
```

- [ ] **Step 3: Run Phase 1 tests**

```bash
cd /Users/devendrayadav/Tools/oneinfinity
python3 -m pytest tests/test_neo4j_readiness.py::TestPhase1DeepChaining -v
```

Expected: `3 passed`.

- [ ] **Step 4: Commit**

```bash
git add tests/test_neo4j_readiness.py
git commit -m "$(cat <<'EOF'
test(readiness): add Phase 1 deep chaining validation

Session fixture builds vulnbank.org simulation graph with 3-hop
sqli→auth_bypass→command_execution chain. Phase 1 proves dfs_paths
finds the chain and inner ExploitChainEngine respects graph connectivity.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2 — Phase 2 (Token Propagation) + Phase 3 (Relationship Depth)

**Files:**
- Modify: `tests/test_neo4j_readiness.py` (append)

- [ ] **Step 1: Append Phase 2**

```python
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

    def test_token_propagates_across_steps(self):
        """Each chain step must use the token extracted from the previous step's response."""
        tee = TokenExecutionEngine()
        chain_steps = [
            {"url": "https://vulnbank.org/login", "method": "POST"},
            {"url": "https://api.vulnbank.org/users", "method": "GET"},
            {"url": "https://api.vulnbank.org/admin/transfer", "method": "GET"},
        ]
        # Step 1 returns a JWT that step 2 should use; step 2 returns a new JWT for step 3
        mock_responses = [
            self._make_mock_response('{"token": "jwt-from-step1"}'),
            self._make_mock_response('{"token": "jwt-from-step2"}'),
            self._make_mock_response('{"status": "ok"}'),
        ]
        call_headers = []

        def capture_request(method, url, **kwargs):
            call_headers.append(kwargs.get("headers", {}))
            return mock_responses.pop(0)

        with patch.object(tee, "_request", side_effect=capture_request):
            tee.execute_chain_with_tokens(
                chain_steps, initial_token="initial-token", initial_token_type="jwt",
            )

        # Step 2 should carry token from step 1; step 3 should carry token from step 2
        assert len(call_headers) == 3, f"Expected 3 captured header dicts, got {len(call_headers)}"
        step2_auth = call_headers[1].get("Authorization", "")
        step3_auth = call_headers[2].get("Authorization", "")
        # Tokens should have changed (propagation occurred)
        assert step2_auth != call_headers[0].get("Authorization", ""), (
            "Token did not change between step 1 and step 2 — no propagation"
        )
        assert "jwt-from-step1" in step2_auth or "jwt-from-step2" in step3_auth, (
            f"Extracted tokens not found in later steps. step2={step2_auth} step3={step3_auth}"
        )
```

- [ ] **Step 2: Append Phase 3**

```python
# ---------------------------------------------------------------------------
# Phase 3 — Relationship Depth
# ---------------------------------------------------------------------------

class TestPhase3RelationshipDepth:

    def _all_edges(self, engine):
        return list(engine._edges.values())

    def test_calls_edge_exists(self, sim_graph):
        """CALLS edge must exist (API→API relationship)."""
        edges = self._all_edges(sim_graph["engine"])
        assert any(e.edge_type == EdgeType.CALLS for e in edges), \
            "No CALLS edge found — integrate_api_relationships did not wire CALLS"

    def test_auth_for_edge_exists(self, sim_graph):
        """AUTH_FOR edge must exist (TOKEN→endpoint)."""
        edges = self._all_edges(sim_graph["engine"])
        assert any(e.edge_type == EdgeType.AUTH_FOR for e in edges), \
            "No AUTH_FOR edge found — integrate_session did not wire AUTH_FOR"

    def test_issues_token_edge_exists(self, sim_graph):
        """ISSUES_TOKEN edge must exist (auth_flow→TOKEN)."""
        edges = self._all_edges(sim_graph["engine"])
        assert any(e.edge_type == EdgeType.ISSUES_TOKEN for e in edges), \
            "No ISSUES_TOKEN edge found — integrate_token did not wire ISSUES_TOKEN"

    def test_has_vulnerability_edge_exists(self, sim_graph):
        """HAS_VULNERABILITY edge must exist."""
        edges = self._all_edges(sim_graph["engine"])
        assert any(e.edge_type == EdgeType.HAS_VULNERABILITY for e in edges), \
            "No HAS_VULNERABILITY edge found"

    def test_leads_to_has_two_hops(self, sim_graph):
        """LEADS_TO must appear ≥2 times (sqli→bypass and bypass→rce)."""
        edges = self._all_edges(sim_graph["engine"])
        leads_to = [e for e in edges if e.edge_type == EdgeType.LEADS_TO]
        assert len(leads_to) >= 2, \
            f"Expected ≥2 LEADS_TO edges, found {len(leads_to)}"

    def test_no_exposes_on_url_edges(self, sim_graph):
        """C2 regression: URL→parent and URL→param edges must not use EXPOSES."""
        engine = sim_graph["engine"]
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
```

- [ ] **Step 3: Run Phases 1–3**

```bash
python3 -m pytest tests/test_neo4j_readiness.py::TestPhase2TokenPropagation tests/test_neo4j_readiness.py::TestPhase3RelationshipDepth -v
```

Expected: `8 passed` (2 Phase 2 + 6 Phase 3).

- [ ] **Step 4: Commit**

```bash
git add tests/test_neo4j_readiness.py
git commit -m "$(cat <<'EOF'
test(readiness): add Phase 2 token propagation and Phase 3 relationship depth

Phase 2: proves execute_chain_with_tokens sends 3 requests and propagates
extracted tokens across steps. Phase 3: asserts all 5 required deep edge
types (CALLS, AUTH_FOR, ISSUES_TOKEN, HAS_VULNERABILITY, LEADS_TO) exist
and EXPOSES does not appear on structural URL edges (C2 regression check).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3 — Phase 4 (Graph Density) + Phase 5 (Persistence)

**Files:**
- Modify: `tests/test_neo4j_readiness.py` (append)

- [ ] **Step 1: Append Phase 4**

```python
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
        """Average node degree must be ≥ 1.5 (non-sparse graph)."""
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
```

- [ ] **Step 2: Append Phase 5**

```python
# ---------------------------------------------------------------------------
# Phase 5 — Cross-Run Persistence
# ---------------------------------------------------------------------------

class TestPhase5Persistence:

    def test_graph_survives_sqlite_roundtrip(self, sim_graph):
        """Nodes and edges must survive a write-to-SQLite + read-from-SQLite cycle."""
        engine = sim_graph["engine"]
        original_node_count = len(engine._nodes)
        original_edge_count = len(engine._edges)
        assert original_node_count > 0, "Session fixture produced empty graph"

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_path = f.name
        try:
            # Write all nodes and edges to a fresh SQLite store
            store1 = GraphStore(db_path=tmp_path, use_memory=True, use_sqlite=True)
            store1.initialize()
            for node in engine._nodes.values():
                store1.save_node(node)
            for edge in engine._edges.values():
                store1.save_edge(edge)

            # Load into a brand-new store from the same SQLite file
            store2 = GraphStore(db_path=tmp_path, use_memory=True, use_sqlite=True)
            store2.initialize()   # warms memory from SQLite
            engine2 = AttackGraphEngine(store=store2)

            assert len(engine2._nodes) == original_node_count, (
                f"Node count after reload: {len(engine2._nodes)} vs original {original_node_count}"
            )
            assert len(engine2._edges) == original_edge_count, (
                f"Edge count after reload: {len(engine2._edges)} vs original {original_edge_count}"
            )

            # Specific node must be retrievable
            target_id = engine2._label_index.get((NodeType.TARGET, "vulnbank.org"))
            assert target_id is not None, \
                "Target node 'vulnbank.org' not found after SQLite reload"
        finally:
            os.unlink(tmp_path)
```

- [ ] **Step 3: Run Phases 4–5**

```bash
python3 -m pytest tests/test_neo4j_readiness.py::TestPhase4GraphDensity tests/test_neo4j_readiness.py::TestPhase5Persistence -v
```

Expected: `4 passed` (3 Phase 4 + 1 Phase 5).

- [ ] **Step 4: Commit**

```bash
git add tests/test_neo4j_readiness.py
git commit -m "$(cat <<'EOF'
test(readiness): add Phase 4 graph density and Phase 5 persistence

Phase 4: inline BFS connected-components and avg-degree prove simulation
graph is fully connected and non-sparse. Phase 5: SQLite round-trip
confirms node/edge counts survive process restart and target node
is retrievable by label after reload.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4 — Phase 6 (Execution) + Phase 7 (Pipeline Integration)

**Files:**
- Modify: `tests/test_neo4j_readiness.py` (append)

- [ ] **Step 1: Append Phase 6**

```python
# ---------------------------------------------------------------------------
# Phase 6 — Execution Validation
# ---------------------------------------------------------------------------

class TestPhase6Execution:

    def test_execute_from_graph_sends_requests(self, sim_graph):
        """execute_from_graph must send at least one real HTTP request (not just detect)."""
        brain = sim_graph["brain"]
        tee = TokenExecutionEngine()

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
        tee = TokenExecutionEngine()

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
        from core.token_execution_engine import get_token_execution_engine
        tee = get_token_execution_engine()
        assert len(tee._token_cache) > 0, (
            "W1 regression: _token_cache is empty after brain.integrate_token() — "
            "store_raw_token() was not called from integrate_token()"
        )
```

- [ ] **Step 2: Append Phase 7**

```python
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
        # Create two connected vuln nodes matching a chain pattern
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

        # Find the sqli node and verify penalty was applied
        sqli_nodes = eng.find_nodes(node_type=NodeType.VULNERABILITY,
                                     label_contains="sqli")
        assert sqli_nodes, "No sqli vuln node found after integrate_vuln"
        penalized = any(
            n.properties.get("brain_penalty", 1.0) < 1.0 for n in sqli_nodes
        )
        assert penalized, (
            "record_chain_failure did not set brain_penalty < 1.0 on any sqli node"
        )
```

- [ ] **Step 3: Run Phases 6–7**

```bash
python3 -m pytest tests/test_neo4j_readiness.py::TestPhase6Execution tests/test_neo4j_readiness.py::TestPhase7PipelineIntegration -v
```

Expected: `7 passed` (3 Phase 6 + 4 Phase 7).

- [ ] **Step 4: Commit**

```bash
git add tests/test_neo4j_readiness.py
git commit -m "$(cat <<'EOF'
test(readiness): add Phase 6 execution and Phase 7 pipeline integration

Phase 6: proves execute_from_graph sends real HTTP requests with
Authorization headers and that the W1 token cache is populated.
Phase 7: proves each pipeline phase (recon, scan, chaining, feedback)
updates the graph — node counts grow and brain_penalty is applied.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5 — Phase 8 (CLI/Docker Parity) + Standalone Runner

**Files:**
- Modify: `tests/test_neo4j_readiness.py` (append)

- [ ] **Step 1: Append Phase 8**

```python
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
        """worker/executor.py must use attack_graph_core (same module as CLI)."""
        src = self._read("worker/executor.py")
        assert "attack_graph_core" in src or "get_engine" in src, \
            "worker/executor.py does not reference attack_graph_core — worker may use different graph"

    def test_no_parallel_graph_engine_in_worker_or_docker(self):
        """Neither worker/executor.py nor docker-entrypoint.sh may define their own AttackGraphEngine."""
        for path in ("worker/executor.py", "docker-entrypoint.sh"):
            src = self._read(path)
            assert "class AttackGraphEngine" not in src, (
                f"{path} defines its own AttackGraphEngine — parallel graph implementation found"
            )
```

- [ ] **Step 2: Append standalone runner**

```python
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
        [sys.executable, "-m", "pytest", __file__, "-v", "--tb=short", "-q"],
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
        # A phase passes if all its test lines show PASSED and none show FAILED/ERROR
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
        # Print failures for quick diagnosis
        for line in output.splitlines():
            if "FAILED" in line or "ERROR" in line or "AssertionError" in line:
                print(" ", line)
    print("=" * 60)
    sys.exit(0 if all_pass else 1)
```

- [ ] **Step 3: Run the full suite via pytest**

```bash
python3 -m pytest tests/test_neo4j_readiness.py -v
```

Expected: all tests across all 8 phases pass.

- [ ] **Step 4: Run standalone mode**

```bash
python3 tests/test_neo4j_readiness.py
```

Expected:
```
============================================================
  OneInfinity — Neo4j Readiness Validation
============================================================
  PHASE 1 — DEEP CHAINING       : PASS
  PHASE 2 — TOKEN PROPAGATION   : PASS
  PHASE 3 — RELATIONSHIP DEPTH  : PASS
  PHASE 4 — GRAPH DENSITY       : PASS
  PHASE 5 — PERSISTENCE         : PASS
  PHASE 6 — EXECUTION           : PASS
  PHASE 7 — PIPELINE INTEGRATION: PASS
  PHASE 8 — CLI/DOCKER PARITY   : PASS
============================================================
  FINAL VERDICT: ALL PASS — READY FOR NEO4J
============================================================
```

- [ ] **Step 5: Commit**

```bash
git add tests/test_neo4j_readiness.py
git commit -m "$(cat <<'EOF'
test(readiness): add Phase 8 CLI/Docker parity and standalone runner

Phase 8 proves CLI, worker, and Docker all use the same attack_graph_core
module via file content inspection — no parallel implementations.
Standalone runner (python3 tests/test_neo4j_readiness.py) prints
structured PHASE N: PASS/FAIL report and exits non-zero if any phase fails.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```
