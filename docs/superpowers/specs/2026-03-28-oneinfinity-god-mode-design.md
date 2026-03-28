# OneInfinity — GOD MODE Design
**Date:** 2026-03-28
**Approach:** Option C — Conductor + Event-Driven Missions (`god_mode_engine.py`)
**Scope:** New `god-mode` CLI command + orchestration engine; no changes to existing pipeline, enforcement, or engine internals

---

## Context

As of 2026-03-28 the OneInfinity enforcement layer is complete. The system has ~89 CLI commands, a 10-phase canonical pipeline (`full_scan`), an iterative research loop (`research`), a swarm intelligence engine, a graph brain, and an adaptive recon engine. No single command sequences all of these together in an intelligent, adaptive flow.

**GOD MODE** is the master orchestration layer: a single command that sequences every capability in an adaptive cascade, runs until convergence (or a configurable limit), and produces a complete report with zero manual intervention.

---

## Existing Infrastructure (No Duplication)

| Need | Existing Component |
|------|--------------------|
| 10-phase canonical pipeline | `pipeline/canonical.py` + `run_canonical_pipeline()` |
| Iterative research loop | `research_mode_controller.py` — `ResearchModeController.run()` |
| Parallel swarm agents | `swarm_intelligence_engine.py` — 8 specialized agents |
| Adaptive recon | `adaptive_recon_engine.py` — `AdaptiveReconEngine.run()` |
| Event pub/sub | `event_bus.py` — `get_bus().on(event_type, handler)` |
| Finding ingestion | `result_ingestion_engine.py` — `ResultIngestionEngine.ingest()` |
| Chain analysis | `exploit_chains` engine |
| Doctor health check | `DoctorOrchestrator` |
| Report generation | `report` engine |
| Learning system | `LearningSystem` |
| Capmap coverage | `modules/capability_map.py` |

GOD MODE delegates entirely to these components. `god_mode_engine.py` contains no validation, scanning, or analysis logic of its own.

---

## Architecture

### New File

**`god_mode_engine.py`** — Single module containing all GOD MODE logic:

```
GodModeConductor
├── session: GodModeSession
├── missions: list[Mission]
├── convergence: ConvergenceChecker
├── state_file: GodModeStateFile
├── run(target, opts) → GodModeSession
├── stop(scan_id)
├── status(scan_id) → dict
└── _convergence_loop()           ← checks termination conditions every 30s

GodModeSession (dataclass)
├── scan_id: str
├── target: str
├── start_time: float
├── max_time_sec: int             ← default 7200 (2h)
├── max_findings: int             ← default 100
├── phases_complete: list[str]
├── finding_count: int
├── missions: dict[str, str]      ← name → status
└── terminated_by: str            ← "convergence"|"time"|"cap"|"stop"|"error"

Mission (abstract base)
├── name: str
├── status: str                   ← "pending"|"running"|"done"|"failed"
├── start(session)
├── stop()
├── is_done() → bool
└── result() → dict

Concrete missions:
├── FoundationMission             ← doctor + adaptive-recon + analyze-app
├── FullScanMission               ← run_canonical_pipeline() in daemon thread
├── ResearchMission               ← ResearchModeController.run() in daemon thread
├── SwarmMission                  ← swarm_intelligence_engine in daemon thread
├── ChainsMission                 ← exploit chains on accumulated findings
└── ReportMission                 ← validation → dedup → capmap → report → learn

ConvergenceChecker
├── research_iters_with_no_new: int
└── is_converged(capmap_coverage) → bool   ← 2 empty iters + 100% class coverage

GodModeStateFile
├── path: Path                    ← ~/.oneinfinity/god-mode-<scan_id>.json
├── write(session)
└── read(scan_id) → dict

get_god_mode_conductor() → GodModeConductor singleton
```

### Wiring Points (existing files, minimal edits)

| File | Change |
|------|--------|
| `oneinfinity.py` | Add `cmd_god_mode()` — thin CLI shell, ~30 lines |

No changes to: `pipeline/`, `enforcement_controller.py`, `event_bus.py`, `research_mode_controller.py`, `swarm_intelligence_engine.py`, `adaptive_recon_engine.py`, or any engine internals.

---

## CLI Surface

```
oneinfinity god-mode <target>                    # foreground (blocks until done)
oneinfinity god-mode <target> --background       # foreground through Stage 1, then detach
oneinfinity god-mode <target> --max-time 4h      # time cap (default: 2h)
oneinfinity god-mode <target> --max-findings 50  # finding cap (default: 100)
oneinfinity god-mode status [scan-id]            # read state file
oneinfinity god-mode logs [--follow]             # tail log file
oneinfinity god-mode stop [scan-id]              # write sentinel → finalize
```

`--background` detaches after `FoundationMission` completes (Stage 1). The parent process prints:
```
[+] GOD MODE running in background. Session: gm-a3f2b1
    Status: oneinfinity god-mode status gm-a3f2b1
    Logs:   oneinfinity god-mode logs --follow
    Stop:   oneinfinity god-mode stop gm-a3f2b1
```

---

## Phase Orchestration — Adaptive Cascade

### Stage 1 — Foundation (blocking)

`FoundationMission` runs three steps sequentially:

1. `doctor --quick` — if health < 10.0, abort with diagnosis
2. `AdaptiveReconEngine(target, depth="deep").run()` — builds tech profile + endpoint map
3. `AnalyzeAppEngine(target, recon=recon_result).run()` — builds parameter map + role model

Output of Stage 1 is passed into Stage 2 as seed data. Foundation failures on recon/analyze are non-fatal (warn + continue with less intel). Only doctor failure hard-aborts.

After Stage 1: if `--background`, detach. Otherwise continue in foreground.

### Stage 2 — Main Thread Launch

`FullScanMission` starts in a daemon thread, calling `run_canonical_pipeline(target, seed=foundation_intel)`. The recon seed from Stage 1 pre-populates phases 1-2 of the canonical pipeline (skips cold start).

`ResearchMission` and `SwarmMission` are created but held in `pending` state — waiting for event bus signals.

### Stage 3 — Event-Driven Mission Unlocking

`GodModeConductor` subscribes to the existing event bus at startup:

```
NEW_VULNERABILITY fired ≥ 3 times  →  start ResearchMission
NEW_ENDPOINT fired ≥ 10 times      →  start SwarmMission
ResearchMission iteration 2+ done  →  start ChainsMission
```

All missions run concurrently in daemon threads. Their findings flow back into the event bus, which can trigger further unlocks (recursive). The conductor caps recursive depth at 2 (reuses `max_recursion_depth` from `config/graph.yaml:enforcement`).

### Stage 4 — Convergence Loop

Conductor's main thread runs a loop checking every 30 seconds:

```python
while True:
    sleep(30)
    if _stop_sentinel_exists(session.scan_id):
        reason = "stop"; break
    if time.time() - session.start_time >= session.max_time_sec:
        reason = "time"; break
    if session.finding_count >= session.max_findings:
        reason = "cap"; break
    if convergence.is_converged(capmap_coverage()):
        reason = "convergence"; break
```

`ConvergenceChecker.is_converged()` returns `True` when:
- Last 2 research iterations each produced 0 new unique findings, **and**
- `CapabilityMap` shows all vuln classes covered in current findings

### Stage 5 — Finalization (always runs)

Regardless of which condition triggered, `ReportMission` runs:
1. `FindingValidationEngine.validate()` on all accumulated findings
2. `Deduplicator.filter_new()` deduplication pass
3. `capmap` coverage report
4. `benchmark` coverage vs industry tools
5. `report` generation (findings + chain report)
6. `learn` — persist successful payloads + attack patterns

---

## Data Persistence

### State File: `~/.oneinfinity/god-mode-<scan_id>.json`

```json
{
  "scan_id": "gm-a3f2b1",
  "target": "example.com",
  "start_time": 1743120000.0,
  "elapsed_seconds": 3612,
  "max_time_sec": 7200,
  "max_findings": 100,
  "phases_complete": ["foundation", "full_scan", "research"],
  "missions": {
    "foundation": "done",
    "full_scan": "done",
    "research": "running",
    "swarm": "done",
    "chains": "pending",
    "report": "pending"
  },
  "finding_count": 23,
  "terminated_by": null
}
```

Written after every mission state change. `god-mode status` reads this file — no running process required. Survives crashes.

### Log File: `~/.oneinfinity/logs/god-mode-<scan_id>.log`

Structured text log. `god-mode logs --follow` tails this file using `tail -f`. Foreground mode also streams to stdout.

### Stop Sentinel: `~/.oneinfinity/god-mode-<scan_id>.stop`

Created by `god-mode stop`. Convergence loop detects it within 30s and triggers finalization.

---

## Mission Design

### FoundationMission

```python
def _run(self):
    # Step 1: doctor
    from doctor_orchestrator import DoctorOrchestrator
    report = asyncio.run(DoctorOrchestrator().run(quick=True))
    if report.score < 10.0:
        raise FoundationError(f"Doctor score {report.score} — fix before GOD MODE")

    # Step 2: adaptive recon
    try:
        from adaptive_recon_engine import AdaptiveReconEngine
        self.recon = AdaptiveReconEngine(self.target, depth="deep").run()
    except Exception as e:
        log.warning("Recon failed (non-fatal): %s", e)
        self.recon = None

    # Step 3: analyze app
    try:
        from app_analysis_engine import AnalyzeAppEngine
        self.app_model = AnalyzeAppEngine(self.target, recon=self.recon).run()
    except Exception as e:
        log.warning("App analysis failed (non-fatal): %s", e)
        self.app_model = None
```

### FullScanMission

Calls `run_canonical_pipeline(target, seed_recon=foundation.recon, seed_app=foundation.app_model)`. Wrapped in `try/except` — pipeline failure marks mission FAILED but does not stop conductor.

### ResearchMission

Calls `ResearchModeController(target, max_iterations=5, auto_confirm=True).run()`. Each completed iteration increments `ConvergenceChecker.research_iters_with_no_new` if finding delta is 0.

### SwarmMission

Calls the swarm intelligence engine with all 8 specialized agents. Findings published to `ResultIngestionEngine`.

### ChainsMission

Reads accumulated findings from `ResultIngestionEngine.get_findings()` and runs exploit chain detection. Triggered after ResearchMission iteration 2+ completes.

### ReportMission

Sequential finalization: validate → dedup → capmap → benchmark → report → learn. Each step is independently try/except wrapped.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| `doctor --quick` < 10.0 | Hard abort with diagnosis message |
| Recon/analyze-app failure | Warn + continue (GOD MODE starts with less intel) |
| FullScanMission exception | Warn, mark FAILED, ReportMission still runs |
| ResearchMission exception | Warn, mark FAILED, ConvergenceChecker treats as converged |
| SwarmMission exception | Warn, mark FAILED, continue |
| ChainsMission exception | Warn, mark FAILED, report partial chains |
| ReportMission sub-step failure | Log each sub-step independently, best-effort |
| Background detach failure | Fall back to foreground mode, warn user |
| State file write failure | Log warning, continue in-memory |

All mission failures are non-fatal except `FoundationMission` doctor check. This is the one intentional hard stop.

---

## Configuration

GOD MODE reads/writes to existing `~/.oneinfinity/` directory. No new config files. Options are CLI flags with sane defaults:

| Flag | Default | Description |
|------|---------|-------------|
| `--max-time` | `2h` | Time cap (accepts `30m`, `2h`, `4h`) |
| `--max-findings` | `100` | Finding cap |
| `--background` | off | Detach after Stage 1 |
| `--no-swarm` | off | Skip SwarmMission (lighter mode) |
| `--no-research` | off | Skip ResearchMission (faster mode) |
| `--report-fmt` | `markdown` | Report format (`markdown`, `json`, `html`) |

---

## Validation Gates

| After | Run | Pass criteria |
|-------|-----|---------------|
| Implementation | `python3 -c "from god_mode_engine import get_god_mode_conductor; print('ok')"` | No import error |
| Implementation | `oneinfinity god-mode --help` | Help text displays |
| Implementation | `doctor --quick` | Still 10.0/10.0 |
| Implementation | `oneinfinity god-mode status nonexistent-id` | Graceful "session not found" message |

Full integration test (`god-mode <live-target>`) is out of scope for implementation validation — use a known-safe target manually.

---

## Scope Limits

- One new file: `god_mode_engine.py`
- One modified file: `oneinfinity.py` (add `cmd_god_mode`, ~30 lines)
- No changes to: `pipeline/`, `enforcement_controller.py`, `event_bus.py`, any existing engine
- No new test files — import check + doctor + help text are the validation gate
