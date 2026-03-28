# OneInfinity System Repair & Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 4 confirmed graph bugs and wire 3 integration gaps in the OneInfinity framework so findings flow end-to-end from scan → graph → learning, and `research` starts with real recon data.

**Architecture:** Incremental — 4 tiers executed sequentially. Each tier validates with `doctor --quick` before moving to the next. No new files, no new CLI commands. All changes are surgical edits to existing files.

**Tech Stack:** Python 3.11, Neo4j (bolt:7687), SQLite WAL, `attack_graph_core`, `result_ingestion_engine`, `learning/adaptive_planner.py`

---

## File Map

| File | Change |
|------|--------|
| `oneinfinity.py` | T1: commit existing diff; T2-B1: init engine before neo4j-status check; T3-G1/G4: post-pipeline graph+learn; T3-G3: publish findings after agents run |
| `core/neo4j_engine.py` | T2-B4: add `OI_ChainFeedback` constraint to `bootstrap_schema()` |
| `core/graph_neo4j_bootstrap.py` | T2-B2: add `backfill_neo4j_from_store()` called after store creation |
| `research_mode_controller.py` | T3-G2: run `AdaptiveReconEngine` on iteration 0 and seed `analyze_application_structure()` |
| `agents/coordinator.py` | T3-G3: add `get_all_findings()` public method |

---

## Tier 1 — Commit Working-Tree Fixes

### Task 1: Commit all 8 modified files

**Files:**
- Modify: `oneinfinity.py`, `config/graph.yaml`, `modules/pipeline.py`, `modules/tool_wrappers.py`, `web/backend/main.py`, `Dockerfile`, `web/frontend/src/hooks/useWebSocket.js`, `web/frontend/src/utils/api.js`

- [ ] **Step 1: Verify the diff is clean**

```bash
git diff --stat HEAD
```

Expected output: 8 files modified, no unexpected files.

- [ ] **Step 2: Run doctor to confirm baseline health**

```bash
python3 oneinfinity.py doctor --quick
```

Expected: `Health Score: 10.0 / 10.0`

- [ ] **Step 3: Stage and commit**

```bash
git add oneinfinity.py config/graph.yaml modules/pipeline.py modules/tool_wrappers.py \
  web/backend/main.py Dockerfile \
  web/frontend/src/hooks/useWebSocket.js web/frontend/src/utils/api.js
git commit -m "fix: commit working-tree fixes (graph store attr, neo4j config, pipeline checkpoints, retry logic, web auth)"
```

- [ ] **Step 4: Confirm doctor still passes**

```bash
python3 oneinfinity.py doctor --quick
```

Expected: `Health Score: 10.0 / 10.0` — if it drops, stop and diagnose before continuing.

---

## Tier 2 — Graph Bug Fixes

### Task 2: B4 — Add `OI_ChainFeedback` constraint to Neo4j schema

**Files:**
- Modify: `core/neo4j_engine.py` lines ~72–76 (`bootstrap_schema`)

- [ ] **Step 1: Read the current bootstrap_schema method**

Open `core/neo4j_engine.py` and find `bootstrap_schema()` (around line 65). It currently has 3 statements:

```python
statements = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:OI_Node) REQUIRE n.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (n:OI_Node) ON (n.type)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[r:OI_REL]-() ON (r.type)",
]
```

- [ ] **Step 2: Add the OI_ChainFeedback index**

Edit `core/neo4j_engine.py`. Replace the `statements` list with:

```python
statements = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:OI_Node) REQUIRE n.id IS UNIQUE",
    "CREATE INDEX IF NOT EXISTS FOR (n:OI_Node) ON (n.type)",
    "CREATE INDEX IF NOT EXISTS FOR ()-[r:OI_REL]-() ON (r.type)",
    # Silence GqlStatusObject warnings for chain feedback queries
    "CREATE INDEX IF NOT EXISTS FOR (f:OI_ChainFeedback) ON (f.chain_type)",
]
```

- [ ] **Step 3: Verify the change**

```bash
python3 -c "
from core.neo4j_engine import Neo4jEngine
import inspect
print(inspect.getsource(Neo4jEngine.bootstrap_schema))
" 2>&1 | grep -A 10 "statements ="
```

Expected: 4-element list including `OI_ChainFeedback`.

- [ ] **Step 4: Commit**

```bash
git add core/neo4j_engine.py
git commit -m "fix(graph): bootstrap OI_ChainFeedback index to silence schema warnings (B4)"
```

---

### Task 3: B2 — Backfill existing in-memory nodes to Neo4j on startup

**Files:**
- Modify: `core/graph_neo4j_bootstrap.py` — add `_backfill_nodes_to_neo4j()` and call it from `create_default_graph_store()`

The 190 in-memory nodes pre-date Neo4j being enabled. The `BatchedNeo4jGraphBackend` only pushes nodes via `on_node_saved()`, which fires when `GraphStore.save_node()` is called. Existing nodes were saved when Neo4j was disabled, so they were never sent. The fix: after the store is created with a live backend, iterate all existing nodes and push them.

- [ ] **Step 1: Add the backfill helper at the bottom of `create_default_graph_store()`**

Open `core/graph_neo4j_bootstrap.py`. Find `create_default_graph_store()`. It ends with:

```python
store = GraphStore(db_path=db, use_memory=True, sync_backend=backend)
return store, cfg
```

Replace that with:

```python
store = GraphStore(db_path=db, use_memory=True, sync_backend=backend)
if backend is not None:
    _backfill_nodes_to_neo4j(store, backend)
return store, cfg
```

Then add the helper function immediately before `create_default_graph_store()`:

```python
def _backfill_nodes_to_neo4j(store, backend) -> None:
    """Push any nodes already in the local store into Neo4j (one-time catch-up on startup)."""
    try:
        all_nodes = store.load_all_nodes()
        if not all_nodes:
            return
        for node_dict in all_nodes:
            backend.on_node_saved(node_dict)
        backend.flush()
        log.info("Neo4j backfill: pushed %d existing nodes to Neo4j.", len(all_nodes))
    except Exception as exc:
        log.warning("Neo4j backfill failed (non-fatal): %s", exc)
```

- [ ] **Step 2: Verify `GraphStore` has `load_all_nodes()`**

```bash
python3 -c "
from attack_graph_core.graph_store import GraphStore
import inspect
print(inspect.getsource(GraphStore.load_all_nodes))
" 2>&1 | head -10
```

Expected: method exists, returns list of node dicts.

- [ ] **Step 3: Smoke test backfill**

```bash
python3 -c "
from attack_graph_core.graph_engine import get_engine
engine = get_engine()
from core.graph_neo4j_bootstrap import get_neo4j_engine
neo = get_neo4j_engine()
if neo:
    print('Neo4j connected:', neo.connected)
    print('Neo4j node count:', neo.count_nodes())
else:
    print('Neo4j not connected')
" 2>&1
```

Expected: `Neo4j connected: True`, node count > 0.

- [ ] **Step 4: Commit**

```bash
git add core/graph_neo4j_bootstrap.py
git commit -m "fix(graph): backfill existing in-memory nodes to Neo4j on startup (B2)"
```

---

### Task 4: B1 — Fix `graph neo4j-status` always showing "not initialised"

**Files:**
- Modify: `oneinfinity.py` — `cmd_graph` function, `neo4j-status` branch (around line 1212)

The singleton `_neo4j_engine_singleton` is only populated inside `create_default_graph_store()`, which is called lazily by `get_engine()`. The `neo4j-status` branch calls `get_neo4j_engine()` directly, before `get_engine()` has been called, so the singleton is always `None`.

- [ ] **Step 1: Find the neo4j-status branch**

Open `oneinfinity.py`. Find `elif sub == "neo4j-status":` (around line 1212). It currently starts with:

```python
elif sub == "neo4j-status":
    banner("Neo4j Status")
    try:
        from core.graph_neo4j_bootstrap import get_neo4j_engine
        eng = get_neo4j_engine()
```

- [ ] **Step 2: Add engine init before singleton lookup**

Replace those lines with:

```python
elif sub == "neo4j-status":
    banner("Neo4j Status")
    try:
        from attack_graph_core.graph_engine import get_engine as _init_graph
        _init_graph()   # side-effect: populates _neo4j_engine_singleton
        from core.graph_neo4j_bootstrap import get_neo4j_engine
        eng = get_neo4j_engine()
```

- [ ] **Step 3: Validate**

```bash
python3 oneinfinity.py graph neo4j-status 2>&1
```

Expected: shows `Connected`, `URI`, `Database`, `Nodes`, `Edges` — NOT "not initialised".

- [ ] **Step 4: Commit**

```bash
git add oneinfinity.py
git commit -m "fix(graph): initialise graph engine before checking neo4j-status singleton (B1)"
```

---

### Task 5: Tier 2 validation gate

- [ ] **Step 1: Run all graph commands**

```bash
python3 oneinfinity.py graph neo4j-status 2>&1
python3 oneinfinity.py graph verify 2>&1
python3 oneinfinity.py graph stats 2>&1
```

Expected:
- `neo4j-status`: Connected=True, Nodes > 0
- `verify`: Neo4j nodes > 0, node delta shrinking toward 0
- `stats`: No `GqlStatusObject`/`OI_ChainFeedback` warnings in stderr

- [ ] **Step 2: Doctor health check**

```bash
python3 oneinfinity.py doctor --quick
```

Expected: `Health Score: 10.0 / 10.0`

If doctor drops below 10.0 — **stop here, diagnose, fix before continuing to Tier 3.**

---

## Tier 3 — Integration Gap Wiring

### Task 6: G1 + G4 — `full-scan` hands findings to graph and learning system

**Files:**
- Modify: `oneinfinity.py` — `cmd_full_scan()` (around line 3380–3395)

`run_canonical_pipeline()` returns a `PipelineResult` with `.findings` (list of dicts) and `.phases_run` (list of `PhaseResult`). After it returns, neither the graph nor the learning system are updated. Fix: call `AttackGraphBrain.integrate_vuln()` for each finding, and `LearningSystem.record_result()` with a duck-typed task result.

- [ ] **Step 1: Find the post-pipeline location in `cmd_full_scan`**

Open `oneinfinity.py`. Find `cmd_full_scan()` (around line 3303). Find the `except` block after `run_canonical_pipeline()`:

```python
    except Exception as e:
        err(f"Pipeline failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)

    print()

    # Summary table
```

- [ ] **Step 2: Insert graph + learning handoff after the pipeline result, before the summary table**

Add this block immediately after `result = run_canonical_pipeline(...)` succeeds (after the except block, before `print()`):

```python
    # ── Post-pipeline: graph ingestion ────────────────────────────────────
    try:
        from attack_graph_brain import get_brain
        _brain = get_brain()
        _ingested = 0
        for _f in result.findings:
            _brain.integrate_vuln(_f)
            _ingested += 1
        if _ingested:
            info(f"Graph: ingested {_ingested} finding(s) from full-scan")
    except Exception as _ge:
        warn(f"Graph ingestion skipped: {_ge}")

    # ── Post-pipeline: learning system update ─────────────────────────────
    try:
        import types as _types
        from learning import LearningSystem as _LS
        # phase names (subdomain_enum, http_probe, vuln_scan …) serve as tool proxies
        _tools_used = list(result.phases.keys()) if result.phases else []
        _task_result = _types.SimpleNamespace(
            findings=result.findings,
            tools_used=_tools_used,
            target=target,
            success=(result.status == "completed"),
            duration=result.elapsed_s,
        )
        _ls = _LS()
        _ls.record_result(_task_result)
        _ls.close()
        info("Learning system updated from full-scan results")
    except Exception as _le:
        warn(f"Learning update skipped: {_le}")
```

- [ ] **Step 3: Verify the attribute names**

```bash
python3 -c "
from pipeline.executor import PipelineResult, PhaseResult
print('PipelineResult fields:', list(PipelineResult.__dataclass_fields__.keys()))
print('PhaseResult fields:', list(PhaseResult.__dataclass_fields__.keys()))
" 2>&1
```

Expected: `findings`, `status`, `elapsed_s`, `phases` in `PipelineResult`; `name`, `status`, `findings`, `meta` in `PhaseResult`.

- [ ] **Step 4: Commit**

```bash
git add oneinfinity.py
git commit -m "feat(pipeline): full-scan now ingests findings into graph and updates learning system (G1+G4)"
```

---

### Task 7: G2 — `research` seeds `analyze_application_structure()` with adaptive-recon data

**Files:**
- Modify: `research_mode_controller.py` — `ResearchModeController._run_iteration()` (around line 830)

`_run_iteration()` currently opens with Phase 1 which calls `self._app_engine.analyze_application_structure()` with no arguments, causing it to load from disk. On iteration 0 the disk may be empty. Fix: on the first iteration only, run `AdaptiveReconEngine` and pass its results directly into `analyze_application_structure()`.

- [ ] **Step 1: Find Phase 1 in `_run_iteration()`**

Open `research_mode_controller.py`. Find `_run_iteration()` (around line 830). Phase 1 block:

```python
        # ── Phase 1: Application Analysis ─────────────────────────────────────
        self._log("Phase 1: Application structure analysis...")
        from application_intelligence import ApplicationIntelligenceEngine
        self._app_engine = ApplicationIntelligenceEngine(
            self.target, str(self.output_dir)
        )
        app_model = self._app_engine.analyze_application_structure()
```

- [ ] **Step 2: Add adaptive-recon seed on iteration 0**

Replace Phase 1 block with:

```python
        # ── Phase 1: Application Analysis ─────────────────────────────────────
        self._log("Phase 1: Application structure analysis...")
        from application_intelligence import ApplicationIntelligenceEngine
        self._app_engine = ApplicationIntelligenceEngine(
            self.target, str(self.output_dir)
        )

        # On the first iteration seed the AppModel with real recon data
        _seed_urls: list[str] | None = None
        _seed_hosts: list[dict] | None = None
        _seed_tech: dict | None = None
        if self._session.iteration == 1:
            try:
                self._log("Phase 0: Adaptive recon (first iteration only)...")
                from adaptive_recon_engine import AdaptiveReconEngine
                _recon = AdaptiveReconEngine(
                    self.target,
                    depth="quick",
                    output_dir=str(self.output_dir),
                ).run()
                _seed_urls  = _recon.all_urls or None
                _seed_hosts = _recon.alive_hosts or None
                _seed_tech  = {"tech_stack": _recon.tech_profile.raw_tech} if _recon.tech_profile.raw_tech else None
                self._log(
                    f"  Recon: {len(_recon.subdomains)} subdomains, "
                    f"{len(_recon.all_urls)} URLs, "
                    f"tech: {_recon.tech_profile.raw_tech[:3]}"
                )
            except Exception as _re:
                self._log(f"  Adaptive recon skipped: {_re}")

        app_model = self._app_engine.analyze_application_structure(
            urls=_seed_urls,
            alive_hosts=_seed_hosts,
            tech_profile=_seed_tech,
        )
```

Note: `self._session.iteration` starts at 0 and is incremented by `run_research()` before calling `_run_iteration()`. Check which value it holds at first call:

- [ ] **Step 3: Verify the iteration counter value on first call**

```bash
python3 -c "
import inspect, research_mode_controller
src = inspect.getsource(research_mode_controller.ResearchModeController.run_research)
# Find iteration increment pattern
for i, line in enumerate(src.splitlines()):
    if 'iteration' in line.lower():
        print(i, line)
" 2>&1
```

Expected: shows where `_session.iteration` is incremented. Adjust the `== 1` check above to `== 0` if the counter hasn't been incremented yet when `_run_iteration()` is first called.

- [ ] **Step 4: Commit**

```bash
git add research_mode_controller.py
git commit -m "feat(research): seed analyze_application_structure with adaptive-recon data on first iteration (G2)"
```

---

### Task 8: G3 — `agents run` publishes findings to shared endpoint bus

**Files:**
- Modify: `agents/coordinator.py` — add `get_all_findings()` public method
- Modify: `oneinfinity.py` — `cmd_agents`, after `coord.run_pentest()` returns

- [ ] **Step 1: Add `get_all_findings()` to `AgentCoordinator`**

Open `agents/coordinator.py`. Find `findings_summary()` (around line 396). Add the following method immediately after it:

```python
    def get_all_findings(self) -> list:
        """Return all findings from all completed agent tasks."""
        with self._lock:
            return [f for r in self._results for f in r.findings]
```

- [ ] **Step 2: Publish findings in `cmd_agents` after `run_pentest()`**

Open `oneinfinity.py`. Find `cmd_agents()` (around line 1306). The call is:

```python
        results = coord.run_pentest(
            target=target,
            output_dir=output_dir,
            platform=platform,
            phases=phases,
            timeout=timeout,
        )

        coord.shutdown()

        section("Pentest Complete")
```

Insert after `coord.shutdown()` and before `section("Pentest Complete")`:

```python
        # ── Publish agent findings to shared endpoint bus ─────────────────────
        try:
            from result_ingestion_engine import get_ingestion_engine, RawResult
            import uuid as _uuid
            _bus = get_ingestion_engine()
            _sid = str(_uuid.uuid4())[:8]
            for _f in coord.get_all_findings():
                _bus.ingest(RawResult(
                    scan_id=_sid,
                    source="agents-run",
                    raw=_f,
                ))
            info(f"Endpoint bus: published {len(coord.get_all_findings())} findings from agents run")
        except Exception as _be:
            warn(f"Endpoint bus publish skipped: {_be}")
```

- [ ] **Step 3: Verify `RawResult` import path**

```bash
python3 -c "from result_ingestion_engine import RawResult, get_ingestion_engine; print('OK')"
```

Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add agents/coordinator.py oneinfinity.py
git commit -m "feat(agents): publish agent findings to shared endpoint bus after run (G3)"
```

---

### Task 9: Tier 3 validation gate

- [ ] **Step 1: Doctor check**

```bash
python3 oneinfinity.py doctor --quick
```

Expected: `Health Score: 10.0 / 10.0`

- [ ] **Step 2: Verify G1/G4 wiring compiles**

```bash
python3 -c "
import ast, sys
with open('oneinfinity.py') as f:
    src = f.read()
ast.parse(src)
print('oneinfinity.py: syntax OK')
" 2>&1
```

- [ ] **Step 3: Verify G2 wiring compiles**

```bash
python3 -c "
import ast
with open('research_mode_controller.py') as f:
    src = f.read()
ast.parse(src)
print('research_mode_controller.py: syntax OK')
" 2>&1
```

- [ ] **Step 4: Verify G3 compiles**

```bash
python3 -c "
import ast
with open('agents/coordinator.py') as f:
    src = f.read()
ast.parse(src)
print('agents/coordinator.py: syntax OK')
from agents.coordinator import AgentCoordinator
print('get_all_findings exists:', hasattr(AgentCoordinator, 'get_all_findings'))
" 2>&1
```

Expected: `syntax OK` and `get_all_findings exists: True`

If doctor drops below 10.0 — **stop here, diagnose before continuing to Tier 4.**

---

## Tier 4 — Unused Command Validation

### Task 10: Validate `simulate-attacks`, `simulate-workflow`, `benchmark`

**Files:**
- Conditionally modify: `oneinfinity.py` or the underlying engine files, only if a command crashes on import or runtime.

- [ ] **Step 1: Test `simulate-attacks`**

```bash
python3 oneinfinity.py simulate-attacks --help 2>&1
python3 oneinfinity.py simulate-attacks example.com --top 3 2>&1 | head -30
```

Expected: `--help` shows usage; dry run prints attack paths. If import error: find the failing import in `cmd_simulate_attacks()` and fix it.

- [ ] **Step 2: Test `simulate-workflow`**

```bash
python3 oneinfinity.py simulate-workflow --help 2>&1
python3 oneinfinity.py simulate-workflow example.com 2>&1 | head -30
```

Expected: `--help` shows usage; run shows workflow simulation output. If import error: fix it.

- [ ] **Step 3: Test `benchmark`**

```bash
python3 oneinfinity.py benchmark --help 2>&1
python3 oneinfinity.py benchmark 2>&1 | head -30
```

Expected: `--help` shows usage; run prints benchmark comparison. If import error: fix it.

- [ ] **Step 4: If any command crashes, fix only the failing import or missing attribute**

Pattern for an import error like `ImportError: cannot import name 'Foo' from 'bar'`:
1. Open the module (`bar.py`)
2. Check if `Foo` was renamed or removed
3. Either restore the export or update the import in `cmd_simulate_*` / `cmd_benchmark`
4. Re-run the command to confirm exit 0

- [ ] **Step 5: Commit any fixes (only if there were crashes)**

```bash
git add <changed files>
git commit -m "fix: resolve import errors in simulate-attacks/simulate-workflow/benchmark (T4)"
```

---

### Task 11: Final validation — full system

- [ ] **Step 1: Doctor**

```bash
python3 oneinfinity.py doctor --quick
```

Expected: `Health Score: 10.0 / 10.0`

- [ ] **Step 2: Graph full check**

```bash
python3 oneinfinity.py graph neo4j-status 2>&1
python3 oneinfinity.py graph verify 2>&1
python3 oneinfinity.py graph stats 2>&1
```

Expected:
- `neo4j-status`: Connected=True, URI, Database, Nodes > 0
- `verify`: Neo4j nodes > 0, no "not initialised"
- `stats`: No `GqlStatusObject`/`OI_ChainFeedback` schema warnings

- [ ] **Step 3: Toolcheck**

```bash
python3 oneinfinity.py toolcheck 2>&1 | tail -5
```

Expected: `43/44 tools available`

- [ ] **Step 4: Syntax check all modified files**

```bash
python3 -c "
import ast
files = [
    'oneinfinity.py',
    'core/neo4j_engine.py',
    'core/graph_neo4j_bootstrap.py',
    'research_mode_controller.py',
    'agents/coordinator.py',
]
for f in files:
    with open(f) as fh:
        ast.parse(fh.read())
    print(f'OK: {f}')
" 2>&1
```

Expected: `OK` for every file.

---

## Quick Reference: All Commands Used

```bash
# Health checks (run after every tier)
python3 oneinfinity.py doctor --quick

# Graph validation (Tier 2+)
python3 oneinfinity.py graph neo4j-status
python3 oneinfinity.py graph verify
python3 oneinfinity.py graph stats

# Unused command smoke tests (Tier 4)
python3 oneinfinity.py simulate-attacks example.com --top 3
python3 oneinfinity.py simulate-workflow example.com
python3 oneinfinity.py benchmark

# Syntax check
python3 -m py_compile <file.py>
```
