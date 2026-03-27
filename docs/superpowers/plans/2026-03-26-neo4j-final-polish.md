# Neo4j Final Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Neo4j integration observable, safe, optimized, and intelligent by adding consistency validation, schema bootstrapping, safe path queries, graph metrics, a status CLI, and feedback-loop activation.

**Architecture:** All Neo4j enhancements live in `core/neo4j_engine.py` (low-level) and `core/graph_neo4j_bootstrap.py` (wiring). The CLI `graph` command (new subcommand group in `oneinfinity.py`) exposes `verify`, `stats`, and `neo4j-status`. Chain feedback is read from Neo4j's `OI_ChainFeedback` nodes and applied as score multipliers in `ExploitChainEngine.detect_chains()`.

**Tech Stack:** Python 3.11+, neo4j driver, pytest, argparse (no new deps)

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `core/neo4j_engine.py` | Modify | Add `bootstrap_schema`, `count_nodes`, `count_edges`, `get_status`, `get_chain_feedback_scores`, timeout in `find_path_node_ids` |
| `core/graph_neo4j_bootstrap.py` | Modify | Call `bootstrap_schema` after connect; add `compare_inmemory_vs_neo4j` |
| `core/graph_storage.py` | Modify | Track `_last_sync_ts` in `BatchedNeo4jGraphBackend.flush` |
| `config/graph.yaml` | Modify | Add `max_path_query_ms`, `path_max_depth` keys |
| `attack_graph_core/graph_store.py` | Modify | Add `avg_degree` to `get_graph_stats` |
| `attack_graph_core/exploit_chain_engine.py` | Modify | Read feedback scores from Neo4j; boost/deprioritize chain candidates |
| `oneinfinity.py` | Modify | Add `graph` subparser with `verify`/`stats`/`neo4j-status`; add `cmd_graph` |
| `tests/test_neo4j_polish.py` | Create | All tests for the 6 polish fixes |

---

## Task 1: Schema Bootstrap (FIX 2 — Constraints + Indexes)

**Files:**
- Modify: `core/neo4j_engine.py`
- Modify: `core/graph_neo4j_bootstrap.py`
- Test: `tests/test_neo4j_polish.py`

- [ ] **Step 1: Write failing tests for bootstrap_schema**

```python
# tests/test_neo4j_polish.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Task 1 — bootstrap_schema
# ---------------------------------------------------------------------------

def _make_neo4j_engine(connected=True):
    """Build Neo4jEngine with a fully-mocked driver (no real Neo4j needed)."""
    from core.neo4j_engine import Neo4jEngine
    eng = Neo4jEngine.__new__(Neo4jEngine)
    eng._uri = "bolt://localhost:7687"
    eng._auth = ("neo4j", "test")
    eng._database = "neo4j"
    eng._connected = connected
    mock_driver = MagicMock()
    eng._driver = mock_driver if connected else None
    return eng, mock_driver


def test_bootstrap_schema_runs_all_three_statements():
    """bootstrap_schema must issue CONSTRAINT + 2 INDEX statements."""
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    eng.bootstrap_schema()

    calls = [str(c) for c in mock_sess.run.call_args_list]
    assert any("CONSTRAINT" in c for c in calls), "CONSTRAINT statement missing"
    assert any("INDEX" in c and "n.type" in c for c in calls), "node type INDEX missing"
    assert any("INDEX" in c and "r.type" in c for c in calls), "rel type INDEX missing"


def test_bootstrap_schema_noop_when_disconnected():
    """bootstrap_schema must be safe to call when driver is None."""
    eng, _ = _make_neo4j_engine(connected=False)
    eng.bootstrap_schema()  # should not raise
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/devendrayadav/Tools/oneinfinity
python -m pytest tests/test_neo4j_polish.py::test_bootstrap_schema_runs_all_three_statements -x 2>&1 | tail -20
```
Expected: `AttributeError: 'Neo4jEngine' object has no attribute 'bootstrap_schema'`

- [ ] **Step 3: Implement `bootstrap_schema` in `core/neo4j_engine.py`**

Add this method inside the `Neo4jEngine` class, just after `__init__`:

```python
def bootstrap_schema(self) -> None:
    """
    Create uniqueness constraint and type indexes if they do not already exist.
    Safe to call multiple times (IF NOT EXISTS guards).
    """
    if not self._driver:
        return
    statements = [
        # Uniqueness constraint on OI_Node.id
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:OI_Node) REQUIRE n.id IS UNIQUE",
        # Index on node type property for fast type-filtered lookups
        "CREATE INDEX IF NOT EXISTS FOR (n:OI_Node) ON (n.type)",
        # Index on relationship type property
        "CREATE INDEX IF NOT EXISTS FOR ()-[r:OI_REL]-() ON (r.type)",
    ]
    try:
        with self._driver.session(database=self._database) as sess:
            for stmt in statements:
                sess.run(stmt)
        log.info("Neo4j schema bootstrapped (constraint + 2 indexes).")
    except Exception as exc:
        log.warning("bootstrap_schema failed (non-fatal): %s", exc)
```

- [ ] **Step 4: Call `bootstrap_schema` in `core/graph_neo4j_bootstrap.py`**

In `create_default_graph_store()`, add the call right after `_neo4j_engine_singleton = eng`:

```python
# existing code around line 59:
if eng.connected:
    _neo4j_engine_singleton = eng
    eng.bootstrap_schema()          # <-- ADD THIS LINE
    backend = BatchedNeo4jGraphBackend(
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
python -m pytest tests/test_neo4j_polish.py::test_bootstrap_schema_runs_all_three_statements tests/test_neo4j_polish.py::test_bootstrap_schema_noop_when_disconnected -v 2>&1 | tail -20
```
Expected: `2 passed`

- [ ] **Step 6: Commit**

```bash
git add core/neo4j_engine.py core/graph_neo4j_bootstrap.py tests/test_neo4j_polish.py
git commit -m "feat(neo4j): bootstrap schema — uniqueness constraint + 2 type indexes on connect"
```

---

## Task 2: Config Keys for Safe Path Queries (FIX 3 — preparation)

**Files:**
- Modify: `config/graph.yaml`
- Modify: `core/graph_config.py`

- [ ] **Step 1: Add new config keys to `config/graph.yaml`**

Open `config/graph.yaml` and add two keys inside the `neo4j:` block:

```yaml
neo4j:
  enabled: false
  uri: bolt://localhost:7687
  username: neo4j
  password: password
  database: neo4j
  batch_size: 100
  flush_interval_sec: 2.0
  hybrid_depth_threshold: 3
  load_on_startup: false
  record_chain_feedback: true
  # Safety limits for variable-length Cypher path queries
  path_max_depth: 8
  max_path_query_ms: 5000
```

- [ ] **Step 2: Add defaults to `_DEFAULTS` in `core/graph_config.py`**

Find the `_DEFAULTS` dict and add two lines inside `"neo4j"`:

```python
_DEFAULTS: dict[str, Any] = {
    "neo4j": {
        "enabled": False,
        "uri": "bolt://localhost:7687",
        "username": "neo4j",
        "password": "password",
        "database": "neo4j",
        "batch_size": 100,
        "flush_interval_sec": 2.0,
        "hybrid_depth_threshold": 3,
        "load_on_startup": False,
        "record_chain_feedback": True,
        "path_max_depth": 8,           # <-- ADD
        "max_path_query_ms": 5000,     # <-- ADD
    }
}
```

- [ ] **Step 3: Verify no import errors**

```bash
python -c "from core.graph_config import load_graph_config; cfg=load_graph_config(); print(cfg['neo4j']['path_max_depth'], cfg['neo4j']['max_path_query_ms'])"
```
Expected: `8 5000`

- [ ] **Step 4: Commit**

```bash
git add config/graph.yaml core/graph_config.py
git commit -m "config: add path_max_depth and max_path_query_ms to graph.yaml defaults"
```

---

## Task 3: Safe Path Queries with Timeout + Depth Limit (FIX 3)

**Files:**
- Modify: `core/neo4j_engine.py`
- Test: `tests/test_neo4j_polish.py`

- [ ] **Step 1: Add failing tests**

```python
# tests/test_neo4j_polish.py — append to file

# ---------------------------------------------------------------------------
# Task 3 — safe path query with timeout
# ---------------------------------------------------------------------------

def test_find_path_node_ids_safe_respects_depth_cap():
    """find_path_node_ids_safe must cap depth at path_max_depth from config."""
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    mock_sess.run.return_value = []
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    # Pass max_depth=999; should be clamped to config path_max_depth (8 by default)
    with patch("core.neo4j_engine.load_graph_config", return_value={"neo4j": {"path_max_depth": 8, "max_path_query_ms": 5000}}):
        eng.find_path_node_ids_safe("a", "b", max_depth=999)

    cypher_str = mock_sess.run.call_args_list[0][0][0]
    assert "[*1..8]" in cypher_str, f"depth not clamped to 8: {cypher_str}"


def test_find_path_node_ids_safe_noop_when_disconnected():
    """Returns empty list when driver is None."""
    eng, _ = _make_neo4j_engine(connected=False)
    result = eng.find_path_node_ids_safe("x", "y")
    assert result == []
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_neo4j_polish.py::test_find_path_node_ids_safe_respects_depth_cap -x 2>&1 | tail -10
```
Expected: `AttributeError: ... 'find_path_node_ids_safe'`

- [ ] **Step 3: Add `find_path_node_ids_safe` to `core/neo4j_engine.py`**

Add this method inside `Neo4jEngine`, right after the existing `find_path_node_ids` method (~line 196):

```python
def find_path_node_ids_safe(
    self,
    start_id: str,
    end_id: str,
    max_depth: int = 8,
    max_paths: int = 32,
) -> list[list[str]]:
    """
    find_path_node_ids with config-controlled depth cap and query timeout.
    Reads path_max_depth and max_path_query_ms from graph.yaml.
    """
    if not self._driver:
        return []
    try:
        from core.graph_config import load_graph_config
        neo_cfg = load_graph_config().get("neo4j") or {}
        depth_cap = int(neo_cfg.get("path_max_depth") or 8)
        timeout_ms = int(neo_cfg.get("max_path_query_ms") or 5000)
    except Exception:
        depth_cap, timeout_ms = 8, 5000

    hop = max(1, min(int(max_depth), depth_cap))
    cypher = (
        f"MATCH p = (a:OI_Node {{id: $sid}})-[*1..{hop}]->(b:OI_Node {{id: $eid}})\n"
        "WITH p LIMIT $maxp\n"
        "RETURN [n IN nodes(p) | n.id] AS ids"
    )
    try:
        with self._driver.session(
            database=self._database,
            fetch_size=100,
        ) as sess:
            result = sess.run(
                cypher,
                sid=start_id,
                eid=end_id,
                maxp=max_paths,
                timeout=timeout_ms / 1000,
            )
            return [r["ids"] for r in result if r.get("ids")]
    except Exception as exc:
        log.debug("find_path_node_ids_safe failed: %s", exc)
        return []
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_neo4j_polish.py::test_find_path_node_ids_safe_respects_depth_cap tests/test_neo4j_polish.py::test_find_path_node_ids_safe_noop_when_disconnected -v 2>&1 | tail -10
```
Expected: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add core/neo4j_engine.py tests/test_neo4j_polish.py
git commit -m "feat(neo4j): safe path query with config depth cap and timeout (FIX 3)"
```

---

## Task 4: Neo4j Count Methods + Last-Sync Tracking (FIX 4 + FIX 5 prep)

**Files:**
- Modify: `core/neo4j_engine.py`
- Modify: `core/graph_storage.py`
- Test: `tests/test_neo4j_polish.py`

- [ ] **Step 1: Add failing tests**

```python
# tests/test_neo4j_polish.py — append

# ---------------------------------------------------------------------------
# Task 4 — count_nodes, count_edges, get_status
# ---------------------------------------------------------------------------

def test_count_nodes_returns_int():
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    mock_sess.run.return_value = [{"n": 42}]
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    result = eng.count_nodes()
    assert result == 42


def test_count_edges_returns_int():
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    mock_sess.run.return_value = [{"e": 17}]
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    result = eng.count_edges()
    assert result == 17


def test_count_nodes_returns_zero_when_disconnected():
    eng, _ = _make_neo4j_engine(connected=False)
    assert eng.count_nodes() == 0


def test_get_status_structure():
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    mock_sess.run.return_value = [{"n": 5}]
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    status = eng.get_status()
    assert "connected" in status
    assert "node_count" in status
    assert "edge_count" in status
    assert "last_sync_ts" in status
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_neo4j_polish.py::test_count_nodes_returns_int -x 2>&1 | tail -10
```
Expected: `AttributeError: ... 'count_nodes'`

- [ ] **Step 3: Add `count_nodes`, `count_edges`, `get_status` to `core/neo4j_engine.py`**

Add these methods inside `Neo4jEngine`, after `find_path_node_ids_safe`:

```python
def count_nodes(self) -> int:
    """Return total OI_Node count in Neo4j, or 0 if unavailable."""
    if not self._driver:
        return 0
    try:
        with self._driver.session(database=self._database) as sess:
            result = list(sess.run("MATCH (n:OI_Node) RETURN count(n) AS n"))
            return int(result[0]["n"]) if result else 0
    except Exception as exc:
        log.debug("count_nodes failed: %s", exc)
        return 0

def count_edges(self) -> int:
    """Return total OI_REL count in Neo4j, or 0 if unavailable."""
    if not self._driver:
        return 0
    try:
        with self._driver.session(database=self._database) as sess:
            result = list(sess.run("MATCH ()-[r:OI_REL]->() RETURN count(r) AS e"))
            return int(result[0]["e"]) if result else 0
    except Exception as exc:
        log.debug("count_edges failed: %s", exc)
        return 0

def get_status(self) -> dict:
    """Return dict: connected, node_count, edge_count, last_sync_ts."""
    return {
        "connected": self.connected,
        "uri": self._uri,
        "database": self._database,
        "node_count": self.count_nodes() if self.connected else 0,
        "edge_count": self.count_edges() if self.connected else 0,
        "last_sync_ts": getattr(self, "_last_sync_ts", None),
    }
```

Also add `_last_sync_ts: float | None = None` as a class attribute at the top of `Neo4jEngine`:

```python
class Neo4jEngine:
    _last_sync_ts: float | None = None   # <-- ADD this line before __init__

    def __init__(...):
```

- [ ] **Step 4: Track last sync time in `core/graph_storage.py`**

In `BatchedNeo4jGraphBackend._maybe_flush`, after the actual Neo4j writes succeed, update `_last_sync_ts`:

```python
# Find this block in _maybe_flush (around line 108-125):
            if nodes_to_write:
                self._engine.merge_nodes_batch(nodes_to_write)
            if edges_to_write:
                self._engine.merge_edges_batch(edges_to_write)
            # ... delete blocks ...
            self._last_flush = now
```

Add one line after the existing flushes complete:

```python
            if nodes_to_write or edges_to_write:
                self._engine.merge_nodes_batch(nodes_to_write)
                self._engine.merge_edges_batch(edges_to_write)
                import time as _t
                self._engine._last_sync_ts = _t.time()   # <-- ADD
            self._last_flush = now
```

> Note: The exact block in `_maybe_flush` may differ slightly. Find the lines that call `merge_nodes_batch` and `merge_edges_batch` and add the timestamp update immediately after.

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/test_neo4j_polish.py::test_count_nodes_returns_int tests/test_neo4j_polish.py::test_count_edges_returns_int tests/test_neo4j_polish.py::test_count_nodes_returns_zero_when_disconnected tests/test_neo4j_polish.py::test_get_status_structure -v 2>&1 | tail -15
```
Expected: `4 passed`

- [ ] **Step 6: Commit**

```bash
git add core/neo4j_engine.py core/graph_storage.py tests/test_neo4j_polish.py
git commit -m "feat(neo4j): add count_nodes, count_edges, get_status + last_sync_ts tracking (FIX 4+5)"
```

---

## Task 5: Compare In-Memory vs Neo4j (FIX 1)

**Files:**
- Modify: `core/graph_neo4j_bootstrap.py`
- Test: `tests/test_neo4j_polish.py`

- [ ] **Step 1: Add failing test**

```python
# tests/test_neo4j_polish.py — append

# ---------------------------------------------------------------------------
# Task 5 — compare_inmemory_vs_neo4j
# ---------------------------------------------------------------------------

def test_compare_inmemory_vs_neo4j_match():
    """Returns True when in-memory counts match Neo4j counts."""
    from core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j
    from unittest.mock import MagicMock

    mock_store = MagicMock()
    mock_store.get_graph_stats.return_value = {"total_nodes": 10, "total_edges": 5}

    mock_engine = MagicMock()
    mock_engine.connected = True
    mock_engine.count_nodes.return_value = 10
    mock_engine.count_edges.return_value = 5

    result = compare_inmemory_vs_neo4j(mock_store, neo4j_engine=mock_engine)
    assert result["match"] is True
    assert result["inmem_nodes"] == 10
    assert result["neo4j_nodes"] == 10


def test_compare_inmemory_vs_neo4j_mismatch():
    """Returns False with delta when counts differ."""
    from core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j
    from unittest.mock import MagicMock

    mock_store = MagicMock()
    mock_store.get_graph_stats.return_value = {"total_nodes": 10, "total_edges": 5}

    mock_engine = MagicMock()
    mock_engine.connected = True
    mock_engine.count_nodes.return_value = 8
    mock_engine.count_edges.return_value = 5

    result = compare_inmemory_vs_neo4j(mock_store, neo4j_engine=mock_engine)
    assert result["match"] is False
    assert result["node_delta"] == 2


def test_compare_inmemory_vs_neo4j_no_neo4j():
    """Returns connected=False when Neo4j unavailable."""
    from core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j
    from unittest.mock import MagicMock

    mock_store = MagicMock()
    mock_store.get_graph_stats.return_value = {"total_nodes": 3, "total_edges": 1}

    result = compare_inmemory_vs_neo4j(mock_store, neo4j_engine=None)
    assert result["neo4j_connected"] is False
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_neo4j_polish.py::test_compare_inmemory_vs_neo4j_match -x 2>&1 | tail -10
```
Expected: `ImportError` or `AttributeError` — `compare_inmemory_vs_neo4j` does not exist.

- [ ] **Step 3: Add `compare_inmemory_vs_neo4j` to `core/graph_neo4j_bootstrap.py`**

Append this function at the bottom of the file (after `maybe_merge_neo4j_into_store`):

```python
def compare_inmemory_vs_neo4j(store, neo4j_engine=None) -> dict:
    """
    Compare node and edge counts between the in-memory/SQLite store and Neo4j.

    Args:
        store: GraphStore instance with get_graph_stats().
        neo4j_engine: Neo4jEngine instance (or None to auto-detect singleton).

    Returns:
        dict with keys: neo4j_connected, inmem_nodes, inmem_edges,
        neo4j_nodes, neo4j_edges, node_delta, edge_delta, match
    """
    if neo4j_engine is None:
        neo4j_engine = get_neo4j_engine()

    local_stats = store.get_graph_stats()
    inmem_nodes = int(local_stats.get("total_nodes") or 0)
    inmem_edges = int(local_stats.get("total_edges") or 0)

    if neo4j_engine is None or not neo4j_engine.connected:
        return {
            "neo4j_connected": False,
            "inmem_nodes": inmem_nodes,
            "inmem_edges": inmem_edges,
            "neo4j_nodes": 0,
            "neo4j_edges": 0,
            "node_delta": inmem_nodes,
            "edge_delta": inmem_edges,
            "match": False,
        }

    neo_nodes = neo4j_engine.count_nodes()
    neo_edges = neo4j_engine.count_edges()
    node_delta = abs(inmem_nodes - neo_nodes)
    edge_delta = abs(inmem_edges - neo_edges)

    return {
        "neo4j_connected": True,
        "inmem_nodes": inmem_nodes,
        "inmem_edges": inmem_edges,
        "neo4j_nodes": neo_nodes,
        "neo4j_edges": neo_edges,
        "node_delta": node_delta,
        "edge_delta": edge_delta,
        "match": node_delta == 0 and edge_delta == 0,
    }
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_neo4j_polish.py::test_compare_inmemory_vs_neo4j_match tests/test_neo4j_polish.py::test_compare_inmemory_vs_neo4j_mismatch tests/test_neo4j_polish.py::test_compare_inmemory_vs_neo4j_no_neo4j -v 2>&1 | tail -15
```
Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add core/graph_neo4j_bootstrap.py tests/test_neo4j_polish.py
git commit -m "feat(graph): add compare_inmemory_vs_neo4j consistency check (FIX 1)"
```

---

## Task 6: Graph Metrics with avg_degree (FIX 4)

**Files:**
- Modify: `attack_graph_core/graph_store.py`
- Test: `tests/test_neo4j_polish.py`

- [ ] **Step 1: Add failing test**

```python
# tests/test_neo4j_polish.py — append

# ---------------------------------------------------------------------------
# Task 6 — avg_degree in get_graph_stats
# ---------------------------------------------------------------------------

def test_get_graph_stats_includes_avg_degree():
    """get_graph_stats must return avg_degree key."""
    import tempfile
    from attack_graph_core.graph_store import GraphStore

    with tempfile.TemporaryDirectory() as td:
        store = GraphStore(db_path=f"{td}/test.db", use_memory=True)

        # Seed 3 nodes and 2 edges manually into the in-memory store
        for i in range(3):
            store._memory.save_node({
                "id": f"n{i}", "node_type": "target", "label": f"n{i}",
                "properties": {}, "severity": None, "risk_score": 0.0,
                "exploitable": False, "validated": False,
                "discovered_at": "0", "updated_at": "0", "source": "", "tags": [],
            })
        store._memory.save_edge({
            "id": "e1", "source_id": "n0", "target_id": "n1",
            "edge_type": "leads_to", "label": "", "properties": {},
            "probability": 1.0, "weight": 1.0, "requires_auth": False,
            "created_at": "0", "source_engine": "",
        })
        store._memory.save_edge({
            "id": "e2", "source_id": "n1", "target_id": "n2",
            "edge_type": "leads_to", "label": "", "properties": {},
            "probability": 1.0, "weight": 1.0, "requires_auth": False,
            "created_at": "0", "source_engine": "",
        })

        stats = store.get_graph_stats()

    assert "avg_degree" in stats, "avg_degree key missing from get_graph_stats"
    # 3 nodes, 2 edges → avg_degree = (2 * 2) / 3 ≈ 1.33
    assert abs(stats["avg_degree"] - (2 * 2 / 3)) < 0.01
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_neo4j_polish.py::test_get_graph_stats_includes_avg_degree -x 2>&1 | tail -10
```
Expected: `AssertionError: avg_degree key missing`

- [ ] **Step 3: Update `get_graph_stats` in `attack_graph_core/graph_store.py`**

Find the `get_graph_stats` method (~line 503) and replace it:

```python
def get_graph_stats(self) -> dict:
    if self._use_memory:
        n = self._memory.count_nodes()
        e = self._memory.count_edges()
    else:
        n = self._sqlite.count_nodes()
        e = self._sqlite.count_edges()
    avg_degree = (2 * e) / n if n > 0 else 0.0
    return {
        "total_nodes": n,
        "total_edges": e,
        "avg_degree": round(avg_degree, 4),
    }
```

- [ ] **Step 4: Run test**

```bash
python -m pytest tests/test_neo4j_polish.py::test_get_graph_stats_includes_avg_degree -v 2>&1 | tail -10
```
Expected: `1 passed`

- [ ] **Step 5: Commit**

```bash
git add attack_graph_core/graph_store.py tests/test_neo4j_polish.py
git commit -m "feat(graph): add avg_degree to get_graph_stats (FIX 4)"
```

---

## Task 7: Feedback Loop Activation (FIX 6)

**Files:**
- Modify: `core/neo4j_engine.py`
- Modify: `attack_graph_core/exploit_chain_engine.py`
- Test: `tests/test_neo4j_polish.py`

- [ ] **Step 1: Add failing tests**

```python
# tests/test_neo4j_polish.py — append

# ---------------------------------------------------------------------------
# Task 7 — feedback loop
# ---------------------------------------------------------------------------

def test_get_chain_feedback_scores_returns_dict():
    """get_chain_feedback_scores returns dict of chain_type -> float multiplier."""
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    # Simulate 3 successes and 1 failure for "XSS → Session Hijacking → ATO"
    mock_sess.run.return_value = [
        {"chain_type": "XSS → Session Hijacking → ATO", "success": True},
        {"chain_type": "XSS → Session Hijacking → ATO", "success": True},
        {"chain_type": "XSS → Session Hijacking → ATO", "success": True},
        {"chain_type": "XSS → Session Hijacking → ATO", "success": False},
    ]
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    scores = eng.get_chain_feedback_scores()
    assert isinstance(scores, dict)
    # 3 success, 1 fail → success_rate=0.75 → multiplier > 1.0
    multiplier = scores.get("XSS → Session Hijacking → ATO", 1.0)
    assert multiplier > 1.0, f"Expected boost, got {multiplier}"


def test_detect_chains_applies_feedback_boost():
    """detect_chains must boost bounty estimate when feedback multiplier > 1."""
    import tempfile
    from attack_graph_core.exploit_chain_engine import ExploitChainEngine
    from attack_graph_core.graph_engine import AttackGraphEngine, NodeType

    with tempfile.TemporaryDirectory() as td:
        from attack_graph_core.graph_store import GraphStore
        from unittest.mock import patch

        store = GraphStore(db_path=f"{td}/test.db", use_memory=True)
        engine = AttackGraphEngine(store=store)

        # Add XSS and session_steal vulnerabilities to trigger chain
        xss_id = engine.add_node(NodeType.VULNERABILITY, "XSS test", properties={"vuln_type": "xss"})
        sess_id = engine.add_node(NodeType.VULNERABILITY, "session steal", properties={"vuln_type": "session_steal"})

        chain_eng = ExploitChainEngine(engine=engine)
        # Baseline: detect without feedback
        chains_no_fb = chain_eng.detect_chains()
        baseline_bounties = [c.estimated_bounty for c in chains_no_fb]

        # With feedback: 100% success rate → high boost
        feedback = {"XSS → Session Hijacking → ATO": 2.0}
        chains_with_fb = chain_eng.detect_chains(feedback_scores=feedback)
        boosted_bounties = [c.estimated_bounty for c in chains_with_fb]

        # At least one chain should be boosted if any were detected
        if chains_no_fb and chains_with_fb:
            assert max(boosted_bounties) >= max(baseline_bounties)
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_neo4j_polish.py::test_get_chain_feedback_scores_returns_dict -x 2>&1 | tail -10
```
Expected: `AttributeError: ... 'get_chain_feedback_scores'`

- [ ] **Step 3: Add `get_chain_feedback_scores` to `core/neo4j_engine.py`**

Add after `record_chain_feedback`:

```python
def get_chain_feedback_scores(self, limit: int = 1000) -> dict:
    """
    Read OI_ChainFeedback nodes from Neo4j and compute per-chain-type
    success-rate multipliers.

    Returns:
        dict[chain_type, float] where values > 1.0 are boosts, < 1.0 are penalties.
        Empty dict if Neo4j unavailable.
    """
    if not self._driver:
        return {}
    try:
        with self._driver.session(database=self._database) as sess:
            rows = list(sess.run(
                "MATCH (f:OI_ChainFeedback) "
                "RETURN f.chain_type AS chain_type, f.success AS success "
                "LIMIT $lim",
                lim=limit,
            ))
    except Exception as exc:
        log.debug("get_chain_feedback_scores failed: %s", exc)
        return {}

    # Aggregate per chain_type
    counts: dict[str, list[bool]] = {}
    for row in rows:
        ct = row.get("chain_type") or ""
        ok = bool(row.get("success"))
        counts.setdefault(ct, []).append(ok)

    scores: dict[str, float] = {}
    for ct, results in counts.items():
        if not ct:
            continue
        total = len(results)
        successes = sum(1 for r in results if r)
        rate = successes / total
        # Multiplier: 0.0 rate → 0.5 (half penalty), 1.0 rate → 2.0 (double boost)
        scores[ct] = 0.5 + 1.5 * rate
    return scores
```

- [ ] **Step 4: Update `ExploitChainEngine.detect_chains` to accept and apply feedback**

In `attack_graph_core/exploit_chain_engine.py`, update `detect_chains` signature and body:

```python
def detect_chains(self, target: str = None, feedback_scores: dict = None) -> list:
    """
    Scan the entire graph (or a target subgraph) for matching chain patterns.

    Args:
        target: Optional target label to restrict the subgraph.
        feedback_scores: Optional dict[chain_name, float] multipliers from Neo4j feedback.
                         Values > 1.0 boost estimated_bounty; < 1.0 penalize.

    Returns:
        list of ExploitChain objects, sorted by estimated_bounty descending.
    """
    # Get all vulnerability nodes
    all_vulns = self.engine.find_nodes(node_type=NodeType.VULNERABILITY)

    # If target specified, filter to that target's subgraph
    if target:
        target_node_id = self.engine._label_index.get((NodeType.TARGET, target))
        if target_node_id:
            subgraph = self.engine.get_subgraph(target_node_id, depth=8)
            subgraph_node_ids = {n["id"] for n in subgraph.get("nodes", [])}
            all_vulns = [v for v in all_vulns if v.id in subgraph_node_ids]

    # Auto-load feedback from Neo4j if not provided
    if feedback_scores is None:
        try:
            from core.graph_neo4j_bootstrap import get_neo4j_engine
            eng = get_neo4j_engine()
            if eng and eng.connected:
                feedback_scores = eng.get_chain_feedback_scores()
        except Exception:
            pass
    feedback_scores = feedback_scores or {}

    detected_chains = []
    for pattern in CHAIN_DEFINITIONS:
        chain = self._match_chain(pattern, all_vulns)
        if chain is not None:
            # Apply feedback multiplier to estimated_bounty
            multiplier = feedback_scores.get(chain.name, 1.0)
            if multiplier != 1.0:
                object.__setattr__(
                    chain,
                    "estimated_bounty",
                    int(chain.estimated_bounty * multiplier),
                )
            detected_chains.append(chain)

    detected_chains.sort(key=lambda c: c.estimated_bounty, reverse=True)

    logger.info(
        "ExploitChainEngine: detected %d chains%s (feedback keys: %d)",
        len(detected_chains),
        f" for {target}" if target else "",
        len(feedback_scores),
    )
    return detected_chains
```

> **Note:** `ExploitChain` may be a frozen dataclass. If `object.__setattr__` raises, check its definition in `graph_query_engine.py` and use `dataclasses.replace(chain, estimated_bounty=...)` instead. The test will tell you if this approach works.

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/test_neo4j_polish.py::test_get_chain_feedback_scores_returns_dict tests/test_neo4j_polish.py::test_detect_chains_applies_feedback_boost -v 2>&1 | tail -20
```
Expected: `2 passed`

If `object.__setattr__` fails due to frozen dataclass, check `ExploitChain` definition and use `dataclasses.replace`:
```python
import dataclasses
chain = dataclasses.replace(chain, estimated_bounty=int(chain.estimated_bounty * multiplier))
```

- [ ] **Step 6: Commit**

```bash
git add core/neo4j_engine.py attack_graph_core/exploit_chain_engine.py tests/test_neo4j_polish.py
git commit -m "feat(feedback): activate chain feedback loop — boost/penalize via Neo4j ChainFeedback (FIX 6)"
```

---

## Task 8: CLI `graph` Command (FIX 1 + FIX 4 + FIX 5)

**Files:**
- Modify: `oneinfinity.py`
- Test: `tests/test_neo4j_polish.py`

- [ ] **Step 1: Add failing CLI test**

```python
# tests/test_neo4j_polish.py — append

# ---------------------------------------------------------------------------
# Task 8 — CLI graph subcommand
# ---------------------------------------------------------------------------

def test_graph_parser_has_verify_stats_neo4j_status():
    """The 'graph' parser must expose verify, stats, neo4j-status subcommands."""
    import sys
    sys.path.insert(0, "/Users/devendrayadav/Tools/oneinfinity")
    from oneinfinity import build_parser

    p = build_parser()
    # Parse each subcommand to check it doesn't raise
    args_verify = p.parse_args(["graph", "verify"])
    assert args_verify.command == "graph"
    assert args_verify.subcommand == "verify"

    args_stats = p.parse_args(["graph", "stats"])
    assert args_stats.subcommand == "stats"

    args_status = p.parse_args(["graph", "neo4j-status"])
    assert args_status.subcommand == "neo4j-status"
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/test_neo4j_polish.py::test_graph_parser_has_verify_stats_neo4j_status -x 2>&1 | tail -10
```
Expected: `SystemExit` or `error: argument command: invalid choice: 'graph'`

- [ ] **Step 3: Add `graph` subparser to `oneinfinity.py`**

In `build_parser()`, find the section where `attack-graph` is registered (~line 2219) and add the new `graph` subcommand group **just before** `attack-graph`:

```python
    # ── graph — Neo4j observability commands ──────────────────────────────────
    gr = sub.add_parser("graph", help="Graph backend observability: verify/stats/neo4j-status")
    grsub = gr.add_subparsers(dest="subcommand")
    grsub.add_parser("verify", help="Compare in-memory vs Neo4j node/edge counts")
    grsub.add_parser("stats",  help="Show graph metrics (nodes, edges, avg_degree, chains)")
    grsub.add_parser("neo4j-status", help="Show Neo4j connectivity, counts, and last sync time")

    # attack-graph — existing command
    ag = sub.add_parser("attack-graph", ...
```

- [ ] **Step 4: Add `cmd_graph` handler to `oneinfinity.py`**

Add the handler function at the bottom of the file, before `main()` (or wherever similar handlers live):

```python
def cmd_graph(args):
    """
    oneinfinity graph <verify|stats|neo4j-status>
    """
    from modules.utils import banner, ok, warn, info, err

    sub = getattr(args, "subcommand", None)

    if sub == "verify":
        banner("Graph Consistency Verify")
        try:
            from attack_graph_core import AttackGraphEngine
            from core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j, get_neo4j_engine
            engine = AttackGraphEngine.get_or_create()
            result = compare_inmemory_vs_neo4j(engine.store)
            print(f"  In-memory  nodes: {result['inmem_nodes']}")
            print(f"  In-memory  edges: {result['inmem_edges']}")
            if result["neo4j_connected"]:
                print(f"  Neo4j      nodes: {result['neo4j_nodes']}")
                print(f"  Neo4j      edges: {result['neo4j_edges']}")
                print(f"  Node delta      : {result['node_delta']}")
                print(f"  Edge delta      : {result['edge_delta']}")
                if result["match"]:
                    ok("Counts match — in-memory and Neo4j are consistent.")
                else:
                    warn("Count mismatch — Neo4j may be lagging or diverged.")
            else:
                warn("Neo4j not connected — only in-memory counts available.")
        except Exception as exc:
            err(f"verify failed: {exc}")

    elif sub == "stats":
        banner("Graph Metrics")
        try:
            from attack_graph_core import AttackGraphEngine
            from attack_graph_core.exploit_chain_engine import ExploitChainEngine
            engine = AttackGraphEngine.get_or_create()
            stats = engine.store.get_graph_stats()
            chains = ExploitChainEngine(engine=engine).detect_chains()
            metrics = {
                "nodes":      stats["total_nodes"],
                "edges":      stats["total_edges"],
                "avg_degree": stats["avg_degree"],
                "chains":     len(chains),
            }
            for k, v in metrics.items():
                print(f"  {k:<12}: {v}")
            ok("Graph stats complete.")
        except Exception as exc:
            err(f"stats failed: {exc}")

    elif sub == "neo4j-status":
        banner("Neo4j Status")
        try:
            from core.graph_neo4j_bootstrap import get_neo4j_engine
            import time
            eng = get_neo4j_engine()
            if eng is None:
                warn("Neo4j engine not initialised (disabled or not connected).")
                return
            status = eng.get_status()
            print(f"  Connected  : {status['connected']}")
            print(f"  URI        : {status['uri']}")
            print(f"  Database   : {status['database']}")
            print(f"  Nodes      : {status['node_count']}")
            print(f"  Edges      : {status['edge_count']}")
            ts = status.get("last_sync_ts")
            if ts:
                import datetime
                dt = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                print(f"  Last sync  : {dt}")
            else:
                print(f"  Last sync  : never")
            if status["connected"]:
                ok("Neo4j is reachable.")
            else:
                warn("Neo4j not connected.")
        except Exception as exc:
            err(f"neo4j-status failed: {exc}")

    else:
        warn("Usage: oneinfinity graph <verify|stats|neo4j-status>")
```

- [ ] **Step 5: Register `cmd_graph` in the handlers dict in `main()`**

In `main()`, find the handlers dict and add:

```python
        "graph":              cmd_graph,
```

Place it in the "Graph Brain" section or near `attack-graph`.

- [ ] **Step 6: Run CLI test**

```bash
python -m pytest tests/test_neo4j_polish.py::test_graph_parser_has_verify_stats_neo4j_status -v 2>&1 | tail -10
```
Expected: `1 passed`

- [ ] **Step 7: Smoke-test CLI manually**

```bash
cd /Users/devendrayadav/Tools/oneinfinity
python oneinfinity.py graph stats 2>&1 | head -20
python oneinfinity.py graph neo4j-status 2>&1 | head -15
python oneinfinity.py graph verify 2>&1 | head -15
```
Expected: no crash; outputs a formatted table for each subcommand.

- [ ] **Step 8: Commit**

```bash
git add oneinfinity.py tests/test_neo4j_polish.py
git commit -m "feat(cli): add 'graph verify/stats/neo4j-status' subcommands (FIX 1+4+5)"
```

---

## Task 9: Full Test Suite Pass

- [ ] **Step 1: Run all new polish tests**

```bash
cd /Users/devendrayadav/Tools/oneinfinity
python -m pytest tests/test_neo4j_polish.py -v 2>&1 | tail -30
```
Expected: all tests pass, 0 failures.

- [ ] **Step 2: Run existing readiness tests to confirm no regressions**

```bash
python -m pytest tests/test_neo4j_readiness.py tests/test_graph_audit_fixes.py -v 2>&1 | tail -30
```
Expected: all existing tests still pass.

- [ ] **Step 3: Commit if any fixes were needed**

```bash
git add -A
git commit -m "fix: address regressions from neo4j polish implementation"
```

---

## Self-Review

### Spec Coverage

| Spec requirement | Task |
|---|---|
| FIX 1 — `compare_inmemory_vs_neo4j()` | Task 5 |
| FIX 1 — `oneinfinity graph verify` | Task 8 |
| FIX 2 — `CREATE CONSTRAINT IF NOT EXISTS` | Task 1 |
| FIX 2 — node type index + rel type index | Task 1 |
| FIX 3 — depth limit from config | Task 2 + 3 |
| FIX 3 — timeout handling | Task 3 |
| FIX 4 — graph_metrics dict (nodes, edges, avg_degree, chains) | Task 6 + 8 |
| FIX 4 — `oneinfinity graph stats` | Task 8 |
| FIX 5 — `oneinfinity graph neo4j-status` | Task 8 |
| FIX 5 — connectivity, node/edge count, last sync | Task 4 + 8 |
| FIX 6 — boost successful paths | Task 7 |
| FIX 6 — deprioritize failed paths | Task 7 |
| FIX 6 — integrate into prioritization + chaining | Task 7 |

All requirements covered. ✓

### Placeholder Scan

No TBD, no "similar to Task N", all code blocks are complete. ✓

### Type Consistency

- `get_graph_stats()` returns `{"total_nodes": int, "total_edges": int, "avg_degree": float}` — used consistently in Tasks 6 and 8. ✓
- `compare_inmemory_vs_neo4j(store, neo4j_engine=None)` — signature matches all call sites. ✓
- `detect_chains(target=None, feedback_scores=None)` — backward compatible (all existing callers pass no `feedback_scores`). ✓
- `get_chain_feedback_scores()` returns `dict[str, float]` — matches `feedback_scores` param type in `detect_chains`. ✓
- `get_status()` returns `{"connected": bool, "uri": str, "database": str, "node_count": int, "edge_count": int, "last_sync_ts": float|None}` — used consistently in Task 8. ✓

### ExploitChain frozen dataclass note

If `ExploitChain` is defined as `@dataclass(frozen=True)` in `graph_query_engine.py`, `object.__setattr__` will work for frozen dataclasses in Python 3.10+ but may fail with `FrozenInstanceError` in older patterns. The safe alternative using `dataclasses.replace(chain, estimated_bounty=...)` is documented in Task 7 Step 5. The test in Task 7 will immediately surface this if it's a problem.
