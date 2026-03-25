# Graph Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the three blockers identified in the pre-Neo4j graph audit so the system is fully graph-native and ready for Neo4j migration.

**Architecture:** Three independent fixes applied in priority order: (1) add graph-path validation to the inner exploit chain engine so chains require real graph connectivity; (2) replace `EXPOSES` with canonical `HAS_ENDPOINT`/`HAS_PARAM` edge types in `graph_updater.py` and remove the direct `HAS_ENDPOINT` call in `unified_scan_engine.py` so all URL/parameter wiring goes through one consistent path; (3) add a same-run in-process token cache to `TokenExecutionEngine` so cross-phase token replay works without persisting raw secrets to SQLite.

**Tech Stack:** Python 3.10+, pytest, `attack_graph_core` (internal), no new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-25-graph-audit-design.md`

---

## File Map

| File | Action | What changes |
|------|--------|-------------|
| `attack_graph_core/exploit_chain_engine.py` | Modify | `_find_vuln_sequence` gains graph-path validation after keyword match |
| `attack_graph_core/graph_updater.py` | Modify | `add_url`, `add_api_endpoint`, `add_parameter` emit canonical edge types |
| `unified_scan_engine.py` | Modify | Remove direct `EdgeType.HAS_ENDPOINT` call at line 800; delegate to `graph_updater.add_url()` |
| `core/token_execution_engine.py` | Modify | Add class-level `_token_cache` dict; `store_raw_token()` populates it; `_build_auth_headers()` falls back to cache |
| `tests/test_graph_audit_fixes.py` | Create | All regression tests for the three fixes |

---

## Task 1 — C1: Graph-path validation in inner ExploitChainEngine

**Files:**
- Modify: `attack_graph_core/exploit_chain_engine.py:258-288`
- Test: `tests/test_graph_audit_fixes.py`

The problem is in `_find_vuln_sequence()`: it returns keyword-matched nodes with no check that any graph edge connects them. The fix adds a post-match graph-path check using `GraphQueryEngine.dfs_paths()`. If no path exists between consecutive matched nodes, the chain is rejected.

- [ ] **Step 1: Write the failing test**

Create `tests/test_graph_audit_fixes.py`:

```python
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
```

- [ ] **Step 2: Run test — confirm C1 failure**

```bash
cd /Users/devendrayadav/Tools/oneinfinity
python3 -m pytest tests/test_graph_audit_fixes.py::TestExploitChainEngineGraphValidation::test_no_chain_when_nodes_disconnected -v
```

Expected output: `FAILED` — the current code produces a chain from disconnected nodes.

- [ ] **Step 3: Add `_path_exists` helper and update `_find_vuln_sequence`**

In `attack_graph_core/exploit_chain_engine.py`, make two changes:

**3a.** Add import at top of file (after existing imports):

```python
from .graph_query_engine import GraphQueryEngine
```

**3b.** Add `_path_exists` helper method to `ExploitChainEngine` class (insert after `_derive_prerequisites`, before the global singleton line):

```python
def _path_exists(self, from_node, to_node, max_depth: int = 6) -> bool:
    """Return True if a real graph path connects from_node to to_node."""
    query = GraphQueryEngine(engine=self.engine)
    paths = query.dfs_paths(from_node.id, to_node.id, max_depth=max_depth)
    return len(paths) > 0
```

**3c.** Replace the body of `_find_vuln_sequence` (lines 258-288) with the version that adds path validation between consecutive matched nodes:

```python
def _find_vuln_sequence(self, vuln_sequence: list, all_vulns: list) -> list:
    """
    For each keyword in vuln_sequence, find a matching vulnerability node.
    Returns the matched node list in sequence order, or [] if any keyword
    cannot be matched OR if consecutive matched nodes have no graph path
    connecting them.
    """
    if not vuln_sequence:
        return []

    matched = []
    used_ids = set()

    for keyword in vuln_sequence:
        kw = keyword.lower()
        found = None

        for vnode in all_vulns:
            if vnode.id in used_ids:
                continue
            vuln_type = vnode.properties.get("vuln_type", "").lower()
            label = vnode.label.lower()
            if kw in vuln_type or kw in label:
                found = vnode
                used_ids.add(vnode.id)
                break

        if found is None:
            return []

        # Validate graph connectivity between this node and the previous one.
        # Single-step chains (len==0 so far) skip this check.
        if matched and not self._path_exists(matched[-1], found):
            logger.debug(
                "_find_vuln_sequence: no graph path %s → %s; rejecting chain",
                matched[-1].label[:40], found.label[:40],
            )
            return []

        matched.append(found)

    return matched
```

- [ ] **Step 4: Run all three C1 tests**

```bash
python3 -m pytest tests/test_graph_audit_fixes.py::TestExploitChainEngineGraphValidation -v
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add attack_graph_core/exploit_chain_engine.py tests/test_graph_audit_fixes.py
git commit -m "fix(graph): require real graph path in ExploitChainEngine._find_vuln_sequence

Keyword-matched vulnerability nodes that have no graph connectivity
no longer produce chains. Added _path_exists() using GraphQueryEngine.dfs_paths().
Fixes C1 from pre-Neo4j graph audit."
```

---

## Task 2 — C2: Canonical edge types in `graph_updater.py`

**Files:**
- Modify: `attack_graph_core/graph_updater.py` — `add_url`, `add_api_endpoint`, `add_parameter`
- Test: `tests/test_graph_audit_fixes.py` (append new class)

Three methods use `EdgeType.EXPOSES` where canonical types are required.
`add_url` and `add_api_endpoint` → `HAS_ENDPOINT`.
`add_parameter` → `HAS_PARAM`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_graph_audit_fixes.py`:

```python
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
```

- [ ] **Step 2: Run tests — confirm failure**

```bash
python3 -m pytest tests/test_graph_audit_fixes.py::TestCanonicalEdgeTypes -v
```

Expected: `4 FAILED` — all emit `EXPOSES` currently.

- [ ] **Step 3: Fix `add_url` in `graph_updater.py`**

In `attack_graph_core/graph_updater.py`, inside `add_url`, replace:

```python
        self.engine.add_edge(
            parent_node.id,
            url_node.id,
            EdgeType.EXPOSES,
            label="exposes",
            source_engine="crawler",
        )
```

with:

```python
        self.engine.add_edge(
            parent_node.id,
            url_node.id,
            EdgeType.HAS_ENDPOINT,
            label="has_endpoint",
            source_engine="crawler",
        )
```

- [ ] **Step 4: Fix `add_api_endpoint` in `graph_updater.py`**

Inside `add_api_endpoint`, replace:

```python
                self.engine.add_edge(
                    pid, api_node.id, EdgeType.EXPOSES,
                    label="exposes_api",
                    source_engine="api_discovery",
                )
```

with:

```python
                self.engine.add_edge(
                    pid, api_node.id, EdgeType.HAS_ENDPOINT,
                    label="has_endpoint",
                    source_engine="api_discovery",
                )
```

- [ ] **Step 5: Fix `add_parameter` in `graph_updater.py`**

Inside `add_parameter`, replace:

```python
        if url_node_id:
            self.engine.add_edge(
                url_node_id,
                param_node.id,
                EdgeType.EXPOSES,
                label="has_parameter",
                source_engine="parameter_discovery",
            )
```

with:

```python
        if url_node_id:
            self.engine.add_edge(
                url_node_id,
                param_node.id,
                EdgeType.HAS_PARAM,
                label="has_param",
                source_engine="parameter_discovery",
            )
```

- [ ] **Step 6: Run C2 tests**

```bash
python3 -m pytest tests/test_graph_audit_fixes.py::TestCanonicalEdgeTypes -v
```

Expected: `4 passed`.

- [ ] **Step 7: Remove duplicate `HAS_ENDPOINT` in `unified_scan_engine.py`**

`unified_scan_engine.py:800` emits `HAS_ENDPOINT` directly, bypassing `graph_updater`, creating an inconsistent dual code path. Now that `graph_updater.add_url()` emits `HAS_ENDPOINT` correctly, the direct call is replaced. Use `GraphUpdater(engine=eng)` — not the module-level singleton — to guarantee both paths operate on the same engine instance that `brain` is tracking.

In `unified_scan_engine.py`, find the block around line 784-803:

```python
        urls = getattr(intel, "all_urls", []) or []
        for url in urls[:500]:   # cap to avoid graph bloat
            try:
                url_node_id = brain.integrate_node(
                    "URL", url, session.target, properties={"url": url}
                )
                if eng is not None and url_node_id:
                    # Wire URL to its closest parent (subdomain or root target)
                    parent_id = None
                    for sub, sid in sub_index.items():
                        if sub in url:
                            parent_id = sid
                            break
                    if parent_id is None:
                        parent_id = target_node_id
                    if parent_id:
                        eng.add_edge(parent_id, url_node_id, EdgeType.HAS_ENDPOINT,
                                     label="has_endpoint", probability=1.0)
            except Exception as exc:
                log.debug("graph_update: failed to integrate url %s: %s", url, exc)
```

Replace with:

```python
        from urllib.parse import urlparse as _urlparse
        from attack_graph_core.graph_updater import GraphUpdater as _GU
        # GraphUpdater.add_url creates-or-retrieves the URL node and wires
        # HAS_ENDPOINT. Note: brain.integrate_node() is no longer called here
        # because add_url covers both node creation and edge wiring in one step.
        # If brain.integrate_node has separate side effects needed (scoring,
        # session tracking), call brain.integrate_node first, then add_url.
        _local_updater = _GU(engine=eng)   # same engine instance brain uses
        urls = getattr(intel, "all_urls", []) or []
        for url in urls[:500]:   # cap to avoid graph bloat
            try:
                parsed = _urlparse(url)
                parent_domain = parsed.netloc or session.target
                _local_updater.add_url(url, parent_domain)
            except Exception as exc:
                log.debug("graph_update: failed to integrate url %s: %s", url, exc)
```

- [ ] **Step 8: Run full C2 test suite + smoke test**

```bash
python3 -m pytest tests/test_graph_audit_fixes.py::TestCanonicalEdgeTypes -v
```

Expected: `4 passed` still.

- [ ] **Step 9: Commit**

```bash
git add attack_graph_core/graph_updater.py unified_scan_engine.py tests/test_graph_audit_fixes.py
git commit -m "fix(graph): emit canonical HAS_ENDPOINT and HAS_PARAM edge types

graph_updater.add_url/add_api_endpoint now emit HAS_ENDPOINT instead of EXPOSES.
graph_updater.add_parameter now emits HAS_PARAM instead of EXPOSES.
unified_scan_engine delegates URL wiring to graph_updater to remove the
duplicate direct HAS_ENDPOINT call at line 800.
GraphPathValidator strict-mode paths built via graph_updater now pass.
Fixes C2 from pre-Neo4j graph audit."
```

---

## Task 3 — W1: Same-run token cache for cross-phase token replay

**Files:**
- Modify: `core/token_execution_engine.py`
- Test: `tests/test_graph_audit_fixes.py` (append new class)

`_build_auth_headers()` silently returns `{}` when `raw_token` is absent from node properties because `attack_graph_brain.integrate_token()` only stores a SHA256 fingerprint (by design, to avoid persisting secrets). The fix adds an in-process class-level cache (`TokenExecutionEngine._token_cache`) keyed by fingerprint. The brain (or any caller) can register a raw token once per run via `store_raw_token(fingerprint, raw_value)`, and `_build_auth_headers()` falls back to the cache before returning empty.

This approach avoids storing raw secrets in SQLite while making same-run cross-phase injection work.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_graph_audit_fixes.py`:

```python
# ── W1 tests ───────────────────────────────────────────────────────────────

from core.token_execution_engine import TokenExecutionEngine


class TestTokenCache:

    def _make_token_node(self, engine, fp="abc123", token_type="jwt"):
        node, _ = engine.get_or_create_node(
            NodeType.TOKEN, f"{token_type}:{fp}",
            properties={"token_type": token_type, "fingerprint": fp, "target": "t.com"},
        )
        return node

    def test_build_auth_headers_returns_empty_without_raw(self):
        """Baseline: no raw_token in props AND no cache → empty headers."""
        engine = fresh_engine()
        node = self._make_token_node(engine)
        tee = TokenExecutionEngine()
        headers = tee._build_auth_headers(node)
        assert headers == {}, f"Expected empty headers, got {headers}"

    def test_store_and_retrieve_raw_token(self):
        """store_raw_token populates the cache; _build_auth_headers uses it."""
        engine = fresh_engine()
        node = self._make_token_node(engine, fp="deadbeef", token_type="jwt")
        raw = "eyJhbGciOiJIUzI1NiJ9.payload.sig"

        tee = TokenExecutionEngine()
        tee.store_raw_token("deadbeef", raw)
        headers = tee._build_auth_headers(node)

        assert "Authorization" in headers, f"Expected Authorization header, got {headers}"
        assert raw in headers["Authorization"], (
            f"Raw token not injected: {headers}"
        )

    def test_cache_is_instance_level(self):
        """Two separate TokenExecutionEngine instances do not share cache."""
        tee1 = TokenExecutionEngine()
        tee2 = TokenExecutionEngine()
        tee1.store_raw_token("fp1", "raw-value-1")
        engine = fresh_engine()
        node = self._make_token_node(engine, fp="fp1", token_type="bearer")
        # tee2 has no cache entry for fp1
        headers = tee2._build_auth_headers(node)
        assert headers == {}, "Cache must not bleed across instances"

    def test_node_raw_token_property_takes_precedence(self):
        """If raw_token is on the node, it wins over the cache."""
        engine = fresh_engine()
        node, _ = engine.get_or_create_node(
            NodeType.TOKEN, "jwt:fp99",
            properties={"token_type": "jwt", "fingerprint": "fp99",
                        "raw_token": "node-level-value"},
        )
        tee = TokenExecutionEngine()
        tee.store_raw_token("fp99", "cache-level-value")
        headers = tee._build_auth_headers(node)
        assert "node-level-value" in headers.get("Authorization", ""), (
            "Node-level raw_token must take precedence over cache"
        )
```

- [ ] **Step 2: Run tests — confirm W1 failure**

```bash
python3 -m pytest tests/test_graph_audit_fixes.py::TestTokenCache -v
```

Expected: `test_store_and_retrieve_raw_token FAILED` (method doesn't exist yet).

- [ ] **Step 3: Add `_token_cache` and `store_raw_token` to `TokenExecutionEngine`**

In `core/token_execution_engine.py`, inside the `TokenExecutionEngine` class:

**3a.** In `__init__`, add cache initialisation after the existing `self._tested_pairs` line:

```python
        # Same-run token cache: fingerprint → raw_token value
        # Populated by store_raw_token(); never persisted to SQLite.
        self._token_cache: dict = {}
```

**3b.** Add `store_raw_token` as a new public method (insert after `__init__`, before `_get_session`):

```python
    def store_raw_token(self, fingerprint: str, raw_value: str) -> None:
        """
        Register a raw token value for the given fingerprint.
        Called by the scan pipeline after token extraction so that
        _build_auth_headers can inject it into subsequent requests
        within the same run — without persisting secrets to SQLite.
        """
        self._token_cache[fingerprint] = raw_value
```

**3c.** Update `_build_auth_headers` to fall back to cache (replace the method):

```python
    def _build_auth_headers(self, token_node) -> dict:
        """Construct HTTP headers for a TOKEN or SESSION node."""
        token_type = token_node.properties.get("token_type", "")
        # Prefer raw_token on the node; fall back to the same-run cache.
        raw_token = token_node.properties.get("raw_token", "")
        if not raw_token:
            fp = token_node.properties.get("fingerprint", "")
            raw_token = self._token_cache.get(fp, "")
        if not raw_token:
            return {}

        headers: dict = {}
        if token_type in ("jwt", "bearer", "oauth"):
            headers["Authorization"] = f"Bearer {raw_token}"
        elif token_type == "api_key":
            headers["X-Api-Key"] = raw_token
            headers["Authorization"] = f"ApiKey {raw_token}"
        elif token_type in ("session_cookie",):
            headers["Cookie"] = f"session={raw_token}"
        else:
            headers["Authorization"] = f"Token {raw_token}"
        return headers
```

- [ ] **Step 4: Run all W1 tests**

```bash
python3 -m pytest tests/test_graph_audit_fixes.py::TestTokenCache -v
```

Expected: `4 passed`.

- [ ] **Step 5: Run the entire test file**

```bash
python3 -m pytest tests/test_graph_audit_fixes.py -v
```

Expected: all tests pass (`TestExploitChainEngineGraphValidation`, `TestCanonicalEdgeTypes`, `TestTokenCache`).

- [ ] **Step 6: Commit**

```bash
git add core/token_execution_engine.py tests/test_graph_audit_fixes.py
git commit -m "fix(tokens): add same-run token cache to TokenExecutionEngine

store_raw_token(fingerprint, value) registers raw token values in an
instance-level dict. _build_auth_headers falls back to this cache when
raw_token is absent from graph node properties, enabling cross-phase
token replay within a scan run without persisting secrets to SQLite.
Fixes W1 from pre-Neo4j graph audit."
```

---

## Task 4 — Regression verification

**Files:**
- Test: `tests/test_graph_audit_fixes.py`

Run the full test suite and confirm no pre-existing tests are broken by the edge-type rename.

- [ ] **Step 1: Run all project tests**

```bash
python3 -m pytest tests/ -v 2>&1 | tail -30
```

Pay attention to any test that asserts `EdgeType.EXPOSES` on URL or parameter edges — those would now be broken by the Task 2 change and should be updated to `HAS_ENDPOINT` / `HAS_PARAM`.

- [ ] **Step 2: If failures found, update affected tests**

For any test that breaks because it expected `EXPOSES` for a URL→parent or URL→param edge, update the assertion to the canonical type. Do not change any test that expects `EXPOSES` for technology or other non-URL/param relationships (those are still correct).

- [ ] **Step 3: Verify audit pass conditions**

Run the live audit verification script:

```bash
python3 - <<'EOF'
import sys
sys.path.insert(0, '.')
import attack_graph_core.graph_engine as ge
ge._global_engine = None

from attack_graph_core.graph_engine import AttackGraphEngine, NodeType, EdgeType
from attack_graph_core.graph_updater import GraphUpdater
from attack_graph_core.exploit_chain_engine import ExploitChainEngine
from core.graph_path_validator import GraphPathValidator
from core.token_execution_engine import TokenExecutionEngine

engine = AttackGraphEngine()
updater = GraphUpdater(engine=engine)

# C1 check
v1, _ = engine.get_or_create_node(NodeType.VULNERABILITY, "idor@a", properties={"vuln_type": "idor"})
v2, _ = engine.get_or_create_node(NodeType.VULNERABILITY, "bac@b", properties={"vuln_type": "bac"})
chains = ExploitChainEngine(engine=engine).detect_chains()
c1_pass = len(chains) == 0
print(f"C1 (no phantom chains): {'PASS' if c1_pass else 'FAIL'} — {len(chains)} chains from disconnected nodes")

# C2 check
engine2 = AttackGraphEngine()
updater2 = GraphUpdater(engine=engine2)
updater2.add_target("t.com")
updater2.add_url("https://t.com/api", "t.com")
updater2.add_parameter("id", "https://t.com/api")
t_id = engine2._label_index.get((NodeType.TARGET, "t.com"))
u_id = engine2._label_index.get((NodeType.URL, "https://t.com/api"))
p_id = engine2._label_index.get((NodeType.PARAMETER, "https://t.com/api?id"))
has_ep = any(e.edge_type == EdgeType.HAS_ENDPOINT for e in engine2.get_edges_from(t_id) if e.target_id == u_id)
has_pm = any(e.edge_type == EdgeType.HAS_PARAM for e in engine2.get_edges_from(u_id) if e.target_id == p_id)
c2_pass = has_ep and has_pm
print(f"C2 (canonical edges): {'PASS' if c2_pass else 'FAIL'} — HAS_ENDPOINT={has_ep} HAS_PARAM={has_pm}")

# W1 check
tee = TokenExecutionEngine()
tee.store_raw_token("fp1", "raw-value")
n, _ = engine2.get_or_create_node(NodeType.TOKEN, "jwt:fp1", properties={"token_type": "jwt", "fingerprint": "fp1"})
headers = tee._build_auth_headers(n)
w1_pass = "raw-value" in headers.get("Authorization", "")
print(f"W1 (token cache): {'PASS' if w1_pass else 'FAIL'} — headers={headers}")

overall = all([c1_pass, c2_pass, w1_pass])
print(f"\nOverall: {'ALL PASS — ready for Neo4j' if overall else 'FAILURES REMAIN'}")
EOF
```

Expected output:
```
C1 (no phantom chains): PASS — 0 chains from disconnected nodes
C2 (canonical edges): PASS — HAS_ENDPOINT=True HAS_PARAM=True
W1 (token cache): PASS — headers={'Authorization': 'Bearer raw-value'}

Overall: ALL PASS — ready for Neo4j
```

- [ ] **Step 4: Final commit**

```bash
git add tests/
git commit -m "test: add regression verification for graph audit remediation

All three audit blockers confirmed fixed:
C1 — phantom chains eliminated
C2 — canonical edge types enforced
W1 — cross-phase token cache works"
```

---

## What is NOT in this plan

- Neo4j integration (blocked on these fixes; planned separately)
- Changes to `exploit_chains/engine.py` (already correct, untouched)
- Changes to BFS/DFS traversal logic (already correct, untouched)
- Changes to the SQLite persistence layer (already correct, untouched)
- Encrypting raw tokens at rest — W1 uses an in-process cache; if encrypted persistence is later required, that is a separate security decision
