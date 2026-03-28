# OneInfinity — Enforcement Layer Design
**Date:** 2026-03-28
**Approach:** Option A — Enforcement Coordinator Module (`enforcement_controller.py`)
**Scope:** 5 enforcement requirements; no new CLI commands, no changes to doctor internals, dedup, scorer, or chain engine

---

## Context

As of 2026-03-28 the repair and integration cycle (Tiers 1–4) is complete. Five enforcement requirements have been identified to harden the system:

1. **Capmap-driven execution** — If any vulnerability class is not covered, trigger the required module
2. **Validation pipeline** — No finding accepted without active HTTP validation (replay-request + replay-attack) + dedup
3. **Recursive scanning** — New endpoints → re-run fuzz+vuln-scan; new auth → re-run IDOR+privilege; new vuln → re-run attack-graph+chains
4. **Module execution enforcement** — simulate-attacks, research, swarm, ai-* compliance tracked and reported
5. **Shared intelligence** — All modules that produce findings must publish via `ResultIngestionEngine`

---

## Existing Infrastructure (No Duplication)

| Need | Existing Component |
|------|--------------------|
| Vulnerability class registry | `modules/capability_map.py` — `CapabilityMap.tools_for_vuln(vuln_class)` |
| HTTP finding validation | `finding_validation_engine.py` — `FindingValidationEngine.validate()` |
| Deduplication | `core/deduplicator.py` — `Deduplicator.filter_new()` |
| Finding ingestion | `result_ingestion_engine.py` — `ResultIngestionEngine.ingest()` |
| Event pub/sub | `event_bus.py` — `get_bus().on(event_type, handler)` |
| Replay commands | `finding_replay_engine.py` — generates curl/nuclei/python per finding |
| Tool execution | `modules/tool_wrappers.py` — `run_tool()` |

All enforcement methods delegate to these existing components. `enforcement_controller.py` contains no validation logic of its own.

---

## Architecture

### New File

**`enforcement_controller.py`** — Single class, singleton accessor, five methods:

```
EnforcementController
├── _modules_run: set[str]                                ← instance state, persists on singleton
├── check_capmap_coverage(scan_id, findings) → CoverageReport
├── validate_findings(raw_findings) → list[dict]          ← HTTP probe via FindingValidationEngine
├── start_recursive_watch(scan_id, depth=0)               ← subscribes to event_bus
├── register_module(module_name: str)                     ← called by each cmd_* at entry
├── check_module_compliance() → ComplianceReport          ← reads _modules_run
└── audit_ingestion_compliance() → list[str]              ← static analysis for doctor

get_enforcement_controller() → EnforcementController singleton
```

### Wiring Points (existing files, minimal edits)

| File | Change |
|------|--------|
| `oneinfinity.py:cmd_full_scan()` | Call all 5 methods: validate findings pre-ingestion, capmap check post-pipeline, recursive watch during, `check_module_compliance()` after |
| `oneinfinity.py:cmd_agents()` | Call `register_module("agents")` + `validate_findings()` |
| `oneinfinity.py:cmd_swarm_scan()` | Call `register_module("swarm-scan")` + `validate_findings()` |
| `oneinfinity.py:cmd_research()` | Call `register_module("research")` |
| `oneinfinity.py:cmd_simulate_attacks()` | Call `register_module("simulate-attacks")` |
| `oneinfinity.py:cmd_ai_redteam()` / `cmd_ai_agent_test()` | Call `register_module("ai-redteam")` |
| `oneinfinity.py:cmd_doctor()` | Call `audit_ingestion_compliance()` to extend health check |
| `config/graph.yaml` | Add `enforcement:` block |

No changes to: `ResultIngestionEngine`, `pipeline.py`, `deduplicator.py`, `finding_validation_engine.py`, `capability_map.py`, `event_bus.py`, doctor internals, scorer, chain engine.

### Configuration

New `enforcement:` block in `config/graph.yaml`:

```yaml
enforcement:
  enabled: true
  validation_pipeline: true        # req 2: HTTP-probe all findings before storage
  capmap_enforcement: true         # req 1: trigger tools for uncovered vuln classes
  max_recursion_depth: 2           # req 3: recursive scan depth cap
  max_recursive_items: 100         # req 3: total new items cap across all recursive passes
  module_compliance: warn          # req 4: warn | block | disabled
  ingestion_audit: true            # req 5: flag non-compliant cmds in doctor
```

---

## Component Design

### Requirement 1 — Capmap Coverage Enforcement

```
findings → extract unique vuln_types
         → CapabilityMap.all_vuln_classes() - vuln_types_found = uncovered_set
         → for each uncovered:
               tools = CapabilityMap.tools_for_vuln(vuln_class)
               pick first available (installed) tool
               if capmap_enforcement: tool_wrappers.run_tool(tool, target)
         → return CoverageReport(covered=set, uncovered=set, triggered=list)
```

Called once after `run_canonical_pipeline()` completes in `cmd_full_scan()`.

### Requirement 2 — Validation Pipeline

```
raw_findings: list[dict]
  → for each finding:
        result = FindingValidationEngine(timeout=15, max_retries=2).validate(finding)
        if result.validated and result.confidence >= threshold:
            keep
        else:
            log.info("Dropped finding: %s (%s)", finding.get("url"), result.error)
            discard
  → validated_findings = Deduplicator.filter_new(kept)
  → for each survivor: ResultIngestionEngine.ingest(RawResult(...))
  → return validated_findings
```

`validate_findings()` is called **before** any ingestion call. Raw findings from all sources (tool_wrappers, agents, swarm) pass through this gate.

If target is unreachable (all findings time out): log single `warn()`, fall through with original findings. Enforcement never hangs a scan.

### Requirement 3 — Recursive Scanning

Recursion state is per `scan_id`:

```python
@dataclass
class RecursionState:
    scan_id: str
    depth: int = 0
    item_count: int = 0
    max_depth: int = 2
    max_items: int = 100
```

Event bus subscriptions (created by `start_recursive_watch(scan_id)`):

```
event_bus.on(NEW_ENDPOINT) →
    if state.depth < max_depth and state.item_count < max_items:
        state.item_count += 1
        trigger fuzz + vuln-scan on new endpoint URL
        state.depth += 1  (for findings produced by this sub-scan)

event_bus.on(NEW_API) →
    if within limits:
        trigger IDOR + privilege escalation tests

event_bus.on(NEW_VULNERABILITY) →
    # depth not incremented — graph/chain update is not a new scan pass
    trigger attack_graph_brain.integrate_vuln(finding)
    trigger exploit_chains evaluation
```

Subscriptions are unregistered via `event_bus.off()` when `scan_id` completes or item cap is hit.

### Requirement 4 — Module Compliance

```python
REQUIRED_MODULES = {"simulate-attacks", "research", "swarm-scan", "ai-redteam"}

# Each cmd_* calls this at entry to register itself on the singleton
def register_module(self, module_name: str) -> None:
    self._modules_run.add(module_name)

def check_module_compliance(self) -> ComplianceReport:
    missing = REQUIRED_MODULES - self._modules_run
    if not missing:
        return ComplianceReport(status="ok", missing=set())
    mode = cfg.get("enforcement", {}).get("module_compliance", "warn")
    if mode == "warn":
        warn(f"Modules not run this session: {', '.join(sorted(missing))}")
    elif mode == "block":
        raise EnforcementError(f"Required modules skipped: {missing}")
    return ComplianceReport(status=mode, missing=missing)
```

`EnforcementController` maintains `_modules_run: set[str]` on the singleton instance. Each cmd_* calls `get_enforcement_controller().register_module("simulate-attacks")` (etc.) at its entry point. `cmd_full_scan()` calls `check_module_compliance()` at the end to evaluate the full session's coverage.

### Requirement 5 — Ingestion Audit (Doctor Extension)

Static analysis at `doctor --quick` time:

```
Parse oneinfinity.py → find all cmd_* functions
For each cmd_*:
    does it call run_tool() or produce findings[]?  → "produces findings"
    does it call get_ingestion_engine()?             → "compliant"
non_compliant = produces_findings - compliant
doctor deducts 0.1 per non-compliant command, capped at -1.0 total
```

This is a static check — it does not instrument runtime calls. It flags commands that structurally bypass the ingestion bus.

---

## Data Structures

```python
@dataclass
class CoverageReport:
    covered: set[str]       # vuln classes found in findings
    uncovered: set[str]     # vuln classes in capmap but not found
    triggered: list[str]    # tools triggered for uncovered classes

@dataclass
class ComplianceReport:
    status: str             # "ok" | "warn" | "block"
    missing: set[str]       # required modules not run
```

---

## Error Handling

All enforcement failures are non-fatal except `module_compliance: block` (explicit user config):

```python
# validate_findings — timeout/unreachable target
try:
    validated = controller.validate_findings(raw_findings)
except Exception as e:
    warn(f"Enforcement validation skipped: {e}")
    validated = raw_findings   # fall through with original findings

# check_capmap_coverage — tool trigger failure
# → log warning per failed tool, return partial CoverageReport, continue

# start_recursive_watch — event bus subscription failure
# → warn once, skip recursive watch, continue

# check_module_compliance: warn mode
# → warn(), return ComplianceReport, continue

# check_module_compliance: block mode
# → raise EnforcementError — this is the ONE intentional hard stop

# audit_ingestion_compliance (doctor)
# → parse error → return [] (no deduction), warn in doctor output
```

`FindingValidationEngine` already has 15s timeout + 2 retries. Individual finding timeouts drop that finding, not the batch.

---

## Validation Gates

| After | Run | Pass criteria |
|-------|-----|---------------|
| Implementation | `doctor --quick` | 10.0/10.0 (minus ingestion audit deductions if any) |
| Implementation | `full-scan <target>` | Enforcement log lines visible; no crash |
| Implementation | `graph stats` | No new warnings |
| Implementation | `graph neo4j-status` | Still connected |

---

## Scope Limits

- No new CLI commands
- No changes to: `ResultIngestionEngine`, `pipeline.py`, `deduplicator.py`, `finding_validation_engine.py`, `capability_map.py`, `event_bus.py`, doctor internals, scorer, chain engine
- No new test files — existing 34-test suite + doctor are the validation gate
- `enforcement_controller.py` is the only new file
