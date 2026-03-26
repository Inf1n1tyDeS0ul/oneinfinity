# OneInfinity — Neo4j Readiness Validation Design
**Date:** 2026-03-26
**Status:** Approved for implementation
**Scope:** Final pass/fail gate before Neo4j integration

---

## Overview

This spec defines an automated, self-contained pytest test suite that validates the OneInfinity graph system is production-ready for Neo4j integration. The suite proves — not assumes — that the system is deep, execution-capable, token-propagating, relationship-rich, and persistent across runs.

The three blockers from the 2026-03-25 pre-Neo4j audit (C1 phantom chains, C2 wrong edge types, W1 token cache) have been fixed. This validation suite confirms those fixes hold under realistic conditions and exercises the broader system capabilities required before migrating to Neo4j.

---

## Deliverable

**File:** `tests/test_neo4j_readiness.py`

A single file with two modes of operation:

1. **Pytest mode:** `pytest tests/test_neo4j_readiness.py -v` — standard exit code 0 = ready, non-zero = not ready. CI-compatible.

2. **Standalone mode:** `python3 tests/test_neo4j_readiness.py` — prints structured audit report:

```
PHASE 1 — DEEP CHAINING:        PASS
PHASE 2 — TOKEN PROPAGATION:    PASS
PHASE 3 — RELATIONSHIP DEPTH:   PASS
PHASE 4 — GRAPH DENSITY:        PASS
PHASE 5 — PERSISTENCE:          PASS
PHASE 6 — EXECUTION:            PASS
PHASE 7 — PIPELINE INTEGRATION: PASS
PHASE 8 — CLI/DOCKER PARITY:    PASS

FINAL VERDICT: ALL PASS — READY FOR NEO4J
```

---

## Architecture

### Session Fixture

A single `@pytest.fixture(scope="session")` named `sim_graph` builds one realistic vulnbank.org simulation graph used by all 8 phases. The fixture:

1. Creates a fresh in-memory `AttackGraphEngine` (no SQLite — isolation)
2. Uses `GraphUpdater` to wire canonical edges (HAS_ENDPOINT, HAS_PARAM)
3. Uses `AttackGraphBrain` to wire deep relationships (CALLS, AUTH_FOR, ISSUES_TOKEN)
4. Creates a 3-hop vulnerability chain with real `LEADS_TO` edges
5. Returns `{"engine": engine, "updater": updater, "brain": brain}`

**Simulation graph contents:**
- Target: `vulnbank.org` + subdomain `api.vulnbank.org`
- URLs: `/login`, `/api/users`, `/api/admin/transfer`
- Parameters: `username`, `password` on `/login`; `user_id` on `/api/users`
- Vulnerabilities: `sqli` on `user_id` → `auth_bypass` (intermediate, `vuln_type="auth_bypass"`) → `command_execution` (3-hop chain via LEADS_TO). **Note:** `vuln_type` values must match keywords in a `CHAIN_DEFINITIONS` pattern's `vuln_sequence`. The "SQLi → Auth Bypass → Full Compromise" pattern uses `["sqli", "auth_bypass"]` — use these exact keywords so `_find_vuln_sequence` keyword-matches and `_path_exists` graph-validates.
- Token: JWT extracted from login, stored as TOKEN node via `brain.integrate_token()`
- Session: SESSION node wired via `brain.integrate_session()`
- CALLS edge: `/login` → `/api/users` (discovered via `brain.integrate_api_relationships()`)
- AUTH_FOR edges: TOKEN node → protected API endpoints

### HTTP Mocking

Phases 2 and 6 require HTTP execution. Mock via `unittest.mock.patch("core.token_execution_engine.TokenExecutionEngine._request")` — no network calls. Mock responses:
- POST `/login` → 200 with `{"token": "eyJhbGciOiJIUzI1NiJ9.step1.sig"}`
- GET `/api/users` → 200 with `{"users": [...], "next_token": "eyJhbGciOiJIUzI1NiJ9.step2.sig"}`
- GET `/api/admin/transfer` → 200 with `{"status": "authorized"}`

### Inline Graph Metrics (Phase 4)

No existing methods in `AttackGraphEngine` or `GraphQueryEngine` compute connectivity or density. Compute inline in the test:

```python
def _connected_components(engine) -> int:
    """BFS over undirected projection. Returns component count."""
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
    """Average degree (in+out) per node."""
    n = len(engine._nodes)
    return (2 * len(engine._edges)) / n if n else 0.0
```

`get_edges_to()` already exists in `AttackGraphEngine` as a wrapper over `_adj_in` — no changes to `graph_engine.py` needed.

---

## Phase Specifications

### Phase 1 — Deep Chaining

**Goal:** Prove the system supports multi-hop attack chains of ≥3 steps.

**Test:** Using the session graph, call `GraphQueryEngine.dfs_paths(sqli_node_id, rce_node_id, max_depth=6)`. Assert at least one path is returned and its length is ≥ 3 nodes.

Also verify C1 fix holds using `attack_graph_core.exploit_chain_engine.ExploitChainEngine` (the inner engine that was patched). Call `detect_chains()` with no arguments — the method fetches all VULNERABILITY nodes directly from `self.engine` internally. Run two scenarios:

1. **Connected graph** (session engine): call `ExploitChainEngine(engine=session_engine).detect_chains()` — assert ≥1 chain returned (sqli→file_write→rce LEADS_TO path exists)
2. **Isolated nodes** (fresh engine with 2 unconnected vuln nodes, same `vuln_type` keywords but no edges): call `ExploitChainEngine(engine=isolated_engine).detect_chains()` — assert 0 chains returned (C1 regression check)

**Pass criteria:**
- `len(dfs_paths(sqli, rce)) >= 1`
- `len(path[0]) >= 3`
- `detect_chains()` on connected graph returns ≥1 chain
- `detect_chains()` on isolated graph returns 0 chains (C1 fix holds)

**Fail criteria:**
- No path found between sqli and rce nodes
- Chains detected from isolated nodes with no LEADS_TO edges (C1 regression)

---

### Phase 2 — Token Propagation

**Goal:** Prove tokens flow across multiple chain steps via `execute_chain_with_tokens()`.

**Test:** Build a 3-step chain description:
```python
chain_steps = [
    {"url": "https://vulnbank.org/login", "method": "POST", "name": "login"},
    {"url": "https://api.vulnbank.org/users", "method": "GET", "name": "get_users"},
    {"url": "https://api.vulnbank.org/admin/transfer", "method": "GET", "name": "admin"},
]
```
Mock `_request` to return step-appropriate responses. Call `tee.execute_chain_with_tokens(chain_steps, initial_token="seed_token")`. Assert:
- `_request` called 3 times
- Step 2's request included the token extracted from step 1's response
- Step 3's request included the token extracted from step 2's response

**Pass criteria:**
- `_request.call_count == 3`
- Authorization headers differ across calls (token updated at each step)
- Final result status is success

**Fail criteria:**
- Same token used in all 3 requests (no propagation)
- `_request` called fewer than 3 times (chain aborted early)

---

### Phase 3 — Relationship Depth

**Goal:** Prove the graph contains rich multi-type relationships beyond structural edges.

**Test:** After session fixture runs, query the simulation engine for each required edge type and assert at least one edge of that type exists:

| Edge type | Required count |
|-----------|---------------|
| `CALLS` | ≥ 1 |
| `AUTH_FOR` | ≥ 1 |
| `ISSUES_TOKEN` | ≥ 1 |
| `HAS_VULNERABILITY` | ≥ 1 |
| `LEADS_TO` | ≥ 2 (two hops in the chain) |

Also assert `EXPOSES` does NOT appear on any URL→parent or URL→parameter edge (C2 regression check).

**Pass criteria:** All 5 edge types present with required counts; no EXPOSES on structural edges.

**Fail criteria:** Any required edge type absent; EXPOSES found on URL/parameter edges.

---

### Phase 4 — Graph Density and Connectivity

**Goal:** Prove the simulation graph is connected and non-sparse.

**Test:** Run inline metrics on the session graph:
- `components = _connected_components(engine)` — assert `== 1` (all nodes reachable)
- `avg_deg = _avg_degree(engine)` — assert `>= 1.5`
- `edge_ratio = len(engine._edges) / len(engine._nodes)` — assert `>= 1.0`

**Pass criteria:**
- 1 connected component
- Average degree ≥ 1.5
- More edges than nodes

**Fail criteria:**
- Multiple disconnected components
- Sparse graph (avg degree < 1.5)
- Fewer edges than nodes

---

### Phase 5 — Cross-Run Persistence

**Goal:** Prove graph data survives process restart via SQLite.

**Test:** Write the simulation graph to a temporary SQLite file using `GraphStore`. Instantiate a new `AttackGraphEngine` pointed at that file. Assert:
- Node count in new engine matches original
- Edge count in new engine matches original
- A specific node (e.g., `vulnbank.org` target) is retrievable by label

Use `tempfile.NamedTemporaryFile` for the SQLite path; clean up after test.

**Pass criteria:**
- `new_engine.node_count == original_engine.node_count`
- `new_engine.edge_count == original_engine.edge_count`
- Target node retrievable by label

**Fail criteria:**
- Node/edge counts differ after reload
- Specific node not found in reloaded engine

---

### Phase 6 — Execution Validation

**Goal:** Prove chains are executed (real requests sent) not just detected.

**Test:** Patch `TokenExecutionEngine._request`. Call `tee.execute_from_graph(brain, target="vulnbank.org")` — the first argument is the `AttackGraphBrain` instance from the session fixture (not the raw engine; the method calls `brain._get_engine()` internally). This method loads TOKEN/SESSION nodes from the graph and follows AUTH_FOR edges to find endpoints to test. Assert:
- `_request` was called at least once (requests actually sent)
- The call included an `Authorization` header (token injected from graph node or same-run cache)
- Result list is non-empty (endpoints were tested)

Also verify `store_raw_token()` was called by `brain.integrate_token()` by checking the engine's `_token_cache` is populated after fixture setup.

**Pass criteria:**
- `_request.call_count >= 1`
- Authorization header present in at least one request
- `tee._token_cache` is non-empty (W1 fix active)

**Fail criteria:**
- No requests sent (execution skipped)
- No Authorization header (token not injected)
- `_token_cache` empty (W1 regression)

---

### Phase 7 — Pipeline Integration

**Goal:** Prove the graph is updated at every major pipeline phase.

**Test:** On a fresh engine (not the session fixture — we need to observe incremental growth), call each pipeline phase in sequence and assert graph size increases:

1. **Recon:** `brain.integrate_node("SUBDOMAIN", "api2.vulnbank.org", "vulnbank.org")` → assert node count increased
2. **Scan:** `brain.integrate_vuln(...)` → assert node + edge count increased
3. **Chaining:** `ExploitChainEngine(engine=fresh).detect_chains()` after adding connected vulns → assert chains returned
4. **Feedback:** `brain.record_chain_failure("sqli_to_rce", "sqli", "vulnbank.org")` → assert the penalized node's `properties["brain_penalty"] < 1.0` (the method searches for nodes by `label_contains="sqli"` and applies a 0.7 penalty multiplier)

**Pass criteria:**
- Node count grows after each of steps 1–3
- `node.properties.get("brain_penalty", 1.0) < 1.0` on the penalized node after step 4

**Fail criteria:**
- Graph size does not change after a pipeline phase
- Feedback does not update node properties

---

### Phase 8 — CLI/Docker Parity

**Goal:** Prove both CLI and Docker paths use identical graph logic (code inspection — no Docker required).

**Test:** Read source files and assert:

1. `oneinfinity.py` imports or invokes `attack_graph_core` (graph initialization is present in CLI)
2. `docker-entrypoint.sh` invokes `oneinfinity` (Docker delegates to same CLI entry point, not a parallel implementation)
3. `worker/executor.py` references `attack_graph_core` or `get_engine` (worker uses same graph module as CLI)
4. Neither `worker/executor.py` nor `docker-entrypoint.sh` define their own graph engine class (no parallel implementations)

**Pass criteria:** All 4 assertions pass via string/regex inspection of file contents.

**Fail criteria:** Docker or worker uses a different graph initialization path.

---

## Pass/Fail Gate

All 8 phases must pass. There is no partial credit.

In standalone mode, the script exits with code 0 (READY) only if all 8 phases pass. Any failure prints `FINAL VERDICT: NOT READY — fix required` and exits non-zero.

In pytest mode, a single test failure causes the suite to fail.

---

## What This Suite Does NOT Test

- Live HTTP scanning against vulnbank.org (no external network calls)
- Docker container build or runtime consistency (Phase 8 is code inspection only)
- Neo4j Cypher queries or schema (Neo4j is not yet installed)
- SQLmap, ffuf, or nuclei tool output (not installed in dev environment)
- The `graph_query_engine.find_ssrf_to_cloud_chains()` W2 issue (out of scope)

---

## Files

| File | Action |
|------|--------|
| `tests/test_neo4j_readiness.py` | Create — all 8 phases + session fixture + standalone runner |
| `attack_graph_core/graph_engine.py` | No changes needed — `get_edges_to()` already exists |
