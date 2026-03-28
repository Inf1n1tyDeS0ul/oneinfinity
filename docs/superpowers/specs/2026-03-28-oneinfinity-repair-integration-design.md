# OneInfinity — System Repair & Integration Design
**Date:** 2026-03-28
**Approach:** Option A — Commit fixes first, then fill gaps incrementally
**Scope:** Bug fixes + pipeline integration; no new CLI commands, no CLI restructuring

---

## Context

As of 2026-03-28 the system is at 10.0/10.0 doctor health with 34 passing tests and 43/44 tools installed. Eight files of valid fixes are uncommitted in the working tree. Four real bugs exist in the graph subsystem. Five integration gaps exist where pipeline stages don't hand off data to each other.

---

## Audit Summary

### Confirmed Bugs

| ID | Description | Location |
|----|-------------|----------|
| B1 | `graph neo4j-status` always shows "not initialised" — singleton not populated before check | `oneinfinity.py:cmd_graph` |
| B2 | 190 in-memory nodes never written to Neo4j despite bolt:7687 being open and enabled | `core/graph_neo4j_bootstrap.py` + `graph_store` |
| B3 | 0 edges in attack graph — `ResultIngestionEngine` adds nodes but never calls `add_edge()` | `result_ingestion_engine.py` |
| B4 | `OI_ChainFeedback` label missing from Neo4j schema — spews warnings on every `graph stats` | `core/neo4j_engine.py:bootstrap_schema` |
| B5 | 8 working-tree files with valid fixes are uncommitted | All uncommitted diffs |

### Already Working (no changes needed)

- Doctor 10.0/10.0, 34 unit tests pass
- 43/44 tools installed (`pyrit` only missing — non-critical)
- Full capmap coverage: XSS, SQLi, SSRF, IDOR, RCE, LFI, SSTI, etc.
- `research` already chains: analyze-app → theorize → test → detect → report
- `agents run` already connects attack graph + learning system
- All tools funnel through `ResultIngestionEngine` (shared findings bus)

### Integration Gaps

| ID | Description |
|----|-------------|
| G1 | `full-scan` findings never handed off to graph or learning system after pipeline completes |
| G2 | `research` loop starts cold — no `adaptive-recon` step before `analyze_application()` |
| G3 | `agents`, `swarm-scan`, `ai-*` don't share discovered endpoints in real-time |
| G4 | `learn` never called from `full-scan` — learning system only updated by manual invocation |
| G5 | Unused commands (`simulate-attacks`, `simulate-workflow`, `benchmark`) never validated for runtime errors |

---

## Architecture

### Execution Tiers (sequential — each validated before the next)

```
Tier 1  →  Commit working-tree fixes
Tier 2  →  Fix graph bugs (B1–B4)
Tier 3  →  Wire integration gaps (G1, G2, G4, G3)
Tier 4  →  Validate unused commands
```

No new CLI commands. No new modules. No changes to doctor, dedup, scorer, or chain engine.

---

## Tier 1 — Commit Working-Tree Fixes

**What:** Commit all 8 modified files as-is. They are already correct.

**Files:**
- `oneinfinity.py` — `engine.store` → `engine._store` (2 occurrences in `cmd_graph`)
- `config/graph.yaml` — `enabled: false` → `enabled: true`, password updated
- `modules/pipeline.py` — phase precondition checks + output validation checkpoints
- `modules/tool_wrappers.py` — retry logic with exponential backoff, `normalize_finding()`, `~/.local/bin` added to PATH
- `web/backend/main.py` — `_validate_target()` input sanitization, lifespan handler, `/api/scans/{id}/stop` auth guard, `/api/auth-token` localhost-only endpoint
- `Dockerfile` — (inspect and commit)
- `web/frontend/src/hooks/useWebSocket.js` — (inspect and commit)
- `web/frontend/src/utils/api.js` — (inspect and commit)

**Validation:** `doctor --quick` still returns 10.0/10.0.

---

## Tier 2 — Graph Bug Fixes

### B1: `neo4j-status` singleton initialization

**File:** `oneinfinity.py` — `cmd_graph`, `neo4j-status` branch
**Fix:** Call `get_engine()` before `get_neo4j_engine()` so `create_default_graph_store()` runs and populates the singleton.

```
# Before checking singleton:
from attack_graph_core.graph_engine import get_engine as _init_engine
_init_engine()   # populates _neo4j_engine_singleton as side-effect
eng = get_neo4j_engine()
```

### B2: In-memory nodes not synced to Neo4j

**File:** `core/graph_neo4j_bootstrap.py` — `create_default_graph_store()`
**Fix:** After `GraphStore` is constructed with the batched backend, call `store.flush_sync_backend()` once to push any nodes already loaded from SQLite into Neo4j. This is a one-time catch-up flush on startup.

**Additional:** Verify `GraphStore.save_node()` calls `_sync_backend.write_node()` — if this path is missing, add it. The backend exists but the call chain must be confirmed.

### B3: 0 edges — no `add_edge()` calls in ingestion

**File:** `result_ingestion_engine.py` — `_ingest_to_graph()` (or equivalent graph write method)
**Fix:** After creating a vulnerability node, create a `HAS_VULNERABILITY` edge from the parent endpoint/URL node:

```python
# After adding vuln node:
if endpoint_node_id:
    engine.add_edge(
        src=endpoint_node_id,
        dst=vuln_node_id,
        edge_type=EdgeType.HAS_VULNERABILITY,
        properties={"source": tool_name}
    )
```

Similarly, when adding a URL node under a subdomain, add a `HAS_ENDPOINT` edge. Follow the `EdgeType` enum in `attack_graph_core/graph_engine.py` for all canonical edge types.

### B4: `OI_ChainFeedback` schema not bootstrapped

**File:** `core/neo4j_engine.py` — `bootstrap_schema()`
**Fix:** Add a constraint (or index) for `OI_ChainFeedback.chain_type` alongside existing constraints so the label is recognized by Neo4j before any feedback query runs.

**Validation after Tier 2:**
- `graph neo4j-status` → shows connected, URI, node/edge counts
- `graph verify` → Neo4j node count > 0, delta shrinks toward 0
- `graph stats` → no OI_ChainFeedback warnings in stderr

---

## Tier 3 — Integration Gap Wiring

### G2: `research` starts with `adaptive-recon`

**File:** `research_mode_controller.py` — `ResearchModeController.run()` (or `main_cli`)
**Fix:** Before the first `analyze_application()` call (iteration 0 only), invoke `adaptive_recon_engine` to produce a recon profile and pass it into the AppModel builder.

```python
# iteration == 0 only:
from adaptive_recon_engine import AdaptiveReconEngine
recon = AdaptiveReconEngine(target).run()
# pass recon.tech_stack, recon.api_endpoints into analyze_application()
```

Subsequent iterations skip this step (recon data is cached in the AppModel).

### G1 + G4: `full-scan` → graph ingestion + learning

**File:** `oneinfinity.py` — `cmd_full_scan`, after `run_canonical_pipeline()` returns
**Fix:** Two sequential calls after pipeline result is available:

```python
# 1. Ingest findings into graph
try:
    from result_ingestion_engine import get_ingestion_engine
    for finding in result.findings:
        get_ingestion_engine().ingest(finding, source="full-scan")
    info(f"Ingested {len(result.findings)} findings into graph")
except Exception as e:
    warn(f"Graph ingestion skipped: {e}")

# 2. Record in learning system
try:
    from learning import LearningSystem
    ls = LearningSystem()
    ls.record_scan_result(target, result.findings, tools_used=result.tools_run)
    ls.close()
    info("Learning system updated")
except Exception as e:
    warn(f"Learning update skipped: {e}")
```

### G3: Shared endpoint bus — `agents` → `swarm-scan` / `ai-*`

**Files:** `agents/coordinator.py` + `oneinfinity.py:cmd_agents`

**Step 1 — Add `get_all_findings()` to `AgentCoordinator`:**
`findings_summary()` already assembles `all_findings` from `self._results`. Add a thin public method alongside it:
```python
def get_all_findings(self) -> list:
    with self._lock:
        return [f for r in self._results for f in r.findings]
```

**Step 2 — Publish to ingestion engine in `cmd_agents` after `run_pentest()`:**
```python
try:
    from result_ingestion_engine import get_ingestion_engine
    for f in coord.get_all_findings():
        get_ingestion_engine().ingest(f, source="agents-run")
except Exception as e:
    warn(f"Ingestion bus publish skipped: {e}")
```

`swarm-scan` and `ai-*` already call `get_ingestion_engine().get_findings()` for their target lists — no changes needed on their side once findings are published to the bus.

---

## Tier 4 — Unused Command Validation

**Commands to validate:** `simulate-attacks`, `simulate-workflow`, `benchmark`

**Method:** Run each against a known safe dummy target (e.g., `example.com`) with `--help` first, then a dry/offline invocation. Confirm exit code 0 and no import errors.

**Action if crash:** Fix the import or runtime error only. Do not wire into any pipeline — these stay standalone.

**No pipeline integration** for these commands. They are diagnostic/simulation tools, not execution stages.

---

## Error Handling

All new integration calls (graph ingestion, learning system) follow the existing pattern used in `agents run`:
- Wrapped in `try/except Exception`
- On failure: `warn()` message logged, scan continues
- Never let integration failures abort the primary pipeline

Graph operations (Neo4j writes, edge creation) degrade gracefully:
- If Neo4j is unreachable, in-memory store still works
- `flush_sync_backend()` is always safe to call even with no backend

---

## Validation Gates

| After | Run | Pass criteria |
|-------|-----|---------------|
| Tier 1 | `doctor --quick` | 10.0/10.0, no regressions |
| Tier 2 | `graph neo4j-status`, `graph verify`, `graph stats` | Connected, nodes > 0, no schema warnings |
| Tier 3 | `research <target> --yes`, `full-scan <target>` (dry) | Research shows recon step; full-scan shows graph+learn steps |
| Tier 4 | `simulate-attacks <target>`, `simulate-workflow <target>`, `benchmark` | Exit 0, no import errors |

If `doctor` drops below 10.0 at any tier: stop, diagnose, fix before continuing.

---

## Scope Limits

- No new CLI commands
- No changes to: `doctor`, `dedup`, `core/deduplicator.py`, `scorer`, `exploit_chains`
- No changes to `modules/workflow.py` or `unified_scan_engine.py` internals
- No new test files — existing 34-test suite + doctor are the validation gate
