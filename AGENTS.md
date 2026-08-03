<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST

- **Exploring code**: `semantic_search_nodes` or `query_graph` instead of Grep
- **Understanding impact**: `get_impact_radius` instead of manually tracing imports
- **Code review**: `detect_changes` + `get_review_context` instead of reading entire files
- **Finding relationships**: `query_graph` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview` + `list_communities`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools

| Tool | Use when |
|------|----------|
| `detect_changes` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context` | Need source snippets for review — token-efficient |
| `get_impact_radius` | Understanding blast radius of a change |
| `get_affected_flows` | Finding which execution paths are impacted |
| `query_graph` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes` | Finding functions/classes by name or keyword |
| `get_architecture_overview` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow

1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes` for code review.
3. Use `get_affected_flows` to understand impact.
4. Use `query_graph` pattern="tests_for" to check coverage.


---

## Single-Process Architecture (Hard Rule)

**This system runs as ONE Python process.**
The entry point is `web/backend/main.py` — a FastAPI app served by uvicorn.
All background service loops live inside `_lifespan()` as supervised asyncio tasks,
or are launched as FastAPI `BackgroundTasks` for per-request work.
No exceptions.

### Never

- Add a new `python ...` entry point to `scripts/start-native.sh` or `scripts/worker-entrypoint.sh`
- Add a new Python **service** container to `docker-compose.yml` / `docker-compose.distributed.yml`
- Call `asyncio.run()` inside any coroutine that runs inside the FastAPI process
  (it creates a nested event loop and breaks uvicorn's loop)
- Call `asyncio.run()` inside any module under `src/oneinfinity/` that is imported by
  `web/backend/main.py` — bridge synchronous callers with `loop.run_in_executor()` instead
- Spawn `multiprocessing.Process` or `os.fork()` from inside a service loop
- Use `subprocess.Popen` for anything other than **external CLI tools**
  (nuclei, nmap, frida, jadx, ffuf) — never for Python logic

### Always — the only correct pattern for a new background loop

```python
# Step 1 — add to your service module, e.g. src/oneinfinity/services/my_service.py
import asyncio, logging
log = logging.getLogger("oneinfinity.my_service")

async def my_service_loop() -> None:
    """Gateway entry point — registered in _lifespan()."""
    while True:
        try:
            await do_work()
        except asyncio.CancelledError:
            raise          # propagate — enables clean shutdown
        except Exception as exc:
            log.error("my_service_loop error", exc_info=exc)
        await asyncio.sleep(INTERVAL_SEC)


# Step 2 — register in web/backend/main.py _lifespan()
# Add import at top of _lifespan():
from oneinfinity.services.my_service import my_service_loop as _my_service_loop

# Inside _lifespan(), after existing startup work:
_bg_tasks: list[asyncio.Task] = []
_bg_tasks.append(asyncio.create_task(_my_service_loop(), name="my_service"))

# Inside the finally / teardown block of _lifespan():
for _t in _bg_tasks:
    _t.cancel()
    try:
        await _t
    except asyncio.CancelledError:
        pass
```

This gives you free restart-with-backoff (wrap the outer loop), graceful shutdown on
`CancelledError`, and observability at `GET /api/health`. No extra infrastructure required.

### Correct pattern for per-request background work

All scan launchers, god_mode runs, mobile analysis jobs, and AI campaign runners
already use `BackgroundTasks.add_task()` — keep this pattern:

```python
@app.post("/api/scan/launch")
async def launch_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {"status": "running", ...}
    background_tasks.add_task(_run_scan_via_engine, scan_id, req.target, req.scan_type)
    return {"scan_id": scan_id}
```

**Do not** call `asyncio.create_task()` directly from endpoint handlers — FastAPI's
`BackgroundTasks` lifecycle is correctly tied to the request/response cycle.

### Known legacy violations — fix on touch, never introduce new ones

The following files contain `asyncio.run()` calls that pre-date this rule.
They are safe only because they run inside synchronous BackgroundTask threads
(FastAPI runs sync background functions via `anyio`'s thread pool, which is separate
from the uvicorn event loop — a new event loop per thread is correct there).
When touching these files, choose the migration path based on context:

- **Outer function is `async def`** → replace `asyncio.run(coro)` with `await coro`
- **Outer function is `def` (sync)** → replace with `loop.run_until_complete(coro)` where
  `loop = asyncio.new_event_loop()`, or restructure the caller to be `async def`
- **Sync wrapper pattern** → use `asyncio.get_event_loop().run_in_executor(None, sync_fn)`

| File | Line(s) | Outer function type | Migration path |
|---|---|---|---|
| `src/oneinfinity/pipeline/executor.py` | 1492, 2203, 2256, 3006 | `def` (sync) | restructure caller → `async def`, then `await coro` |
| `src/oneinfinity/intelligence/intelligence_engine.py` | 118 | sync wrapper | `run_in_executor` |
| `src/oneinfinity/swarm/swarm_intelligence_engine.py` | 3921 | sync | new loop or restructure |
| `src/oneinfinity/swarm/agent_execution_fabric.py` | 591 | sync | new loop or restructure |
| `src/oneinfinity/framework/surface.py` | 221, 271 | sync | new loop or restructure |
| `src/oneinfinity/framework/recon_engine.py` | 233 | sync | new loop or restructure |
| `src/oneinfinity/recon/adaptive_recon_engine.py` | 1265, 1271 | sync | new loop or restructure |

**Note — coverage gap:** `src/oneinfinity/scan/` currently has 6 pre-existing `asyncio.run()`
calls and is not in the hygiene script's strict check list (adding it would require first
allowlisting all 6 existing violations). Treat `scan/` the same as the table above:
safe if in a sync context, fix on touch, never add new ones.

`subprocess.Popen` in `mobile/android_studio_integration.py` and
`mobile/mitmproxy_wrapper.py` is acceptable — these spawn genuine external processes
(Android Studio, mitmproxy). Document the PID and ensure cleanup on shutdown.

### Check before every PR or session-end

```bash
bash scripts/check_process_hygiene.sh   # must exit 0
```

---

## Development Workflow — Maker / Checker / Verifier / Approver

**Every non-trivial change to oneinfinity requires four roles.**
The agent that wrote the code cannot verify it. No exceptions.

> **Triggers** — use this workflow whenever you:
> add a new scan module, new agent, new background loop, new API endpoint, new scan type,
> change the findings schema, change `_lifespan()`, change the VULNERABILITIES/SCANS dicts,
> update any file in the DENYLIST, or make any change that touches more than 2 files.
> Single-file cosmetic edits (comments, docstrings, log messages) are exempt.

---

### Role 1 — Maker (Implementer)

**Who:** The agent performing the development task.

**Responsibility:** Write the code. Do not run quality gates. Do not self-verify.

**Must produce before handing off:**
```
MAKER HANDOFF
─────────────
Files changed:   <list every file touched, with path>
Files created:   <list every new file>
What changed:    <1-3 sentences — what the code does, not how>
Expected effect: <what a passing test would look like>
DENYLIST touched: YES / NO  (if YES, human approval required before Checker runs)
```

**Never:** mark the task done, run gates, or call the change verified.

---

### Role 2 — Checker (Mechanical Gates)

**Who:** A separate `sonic` subagent — fast, mechanical, no interpretation.

**Responsibility:** Run all four quality gates. Report exact output. Do not interpret results.

**Dispatch pattern:**
```python
# In the orchestrating agent:
checker = task(agent="sonic", task="""
CHECKER ROLE — run every gate exactly as written, report raw output.

## Gate 1 — Compilation
cd /home/ubuntu/oneinfinity
venv/bin/python -m compileall src/oneinfinity/ web/backend/ -q
Report: exit code + any error lines.

## Gate 2 — Import Health
cd /home/ubuntu/oneinfinity && venv/bin/python -c "
import sys; sys.path.insert(0,'src'); sys.path.insert(0,'web/backend')
from oneinfinity.core.db_manager import get_db_manager
from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
from oneinfinity.orchestration.god_mode_engine import GodModeSession
from oneinfinity.scan.unified_scan_engine import UnifiedScanEngine
from oneinfinity.agents.scan_agent import ScanAgent
from oneinfinity.agents.exploit_agent import ExploitAgent
from oneinfinity.infra.llm_provider import LLMProviderFactory
from oneinfinity.attack_graph_core.risk_analyzer import RiskAnalyzer
print('imports: OK')
"
Report: exit code + any import errors.

## Gate 3 — Backend Health
curl -s -o /dev/null -w "HTTP %{http_code}" http://localhost:3000/health
curl -s http://localhost:3000/api/health
Report: HTTP status code + raw JSON.

## Gate 4 — Process Hygiene
cd /home/ubuntu/oneinfinity && bash scripts/check_process_hygiene.sh
Report: full output + exit code.

## Output format (required):
GATE 1 COMPILE:  PASS|FAIL  — <evidence>
GATE 2 IMPORTS:  PASS|FAIL  — <evidence>
GATE 3 HEALTH:   PASS|FAIL  — <evidence>
GATE 4 HYGIENE:  PASS|FAIL  — <evidence>
CHECKER VERDICT: PASS|FAIL
""")
```

**Checker PASS criteria:** all four gates exit 0, HTTP 200, hygiene script clean.
Any single gate failure = FAIL. No partial credit.

---

### Role 3 — Verifier (Adversarial Reviewer)

**Who:** A separate `reviewer` subagent — runs in parallel with Checker. Different context, adversarial mindset.

**Responsibility:** Find every reason the change could fail, break production, introduce a bug,
or silently degrade quality. Assume the Maker made a mistake until proven otherwise.

**Dispatch pattern:**
```python
# Spawned in the same task() batch as Checker — parallel, independent:
verifier = task(agent="reviewer", task="""
VERIFIER ROLE — adversarial code review. Your job is to find failures, not confirm success.

## Context
Files changed: <paste Maker handoff here>

## Your checklist — check every item, report evidence for each

ARCHITECTURE
[ ] Does any new code call asyncio.run() inside an async def? (= nested event loop, crash)
[ ] Does any new code call asyncio.run() in a module imported by web/backend/main.py
    outside of a BackgroundTask thread? (= blocks uvicorn event loop)
[ ] Does any new code add a new Python entry point (new process)?
[ ] Does any new code add subprocess.Popen for Python logic (not an external CLI tool)?

SCHEMA & CONTRACTS
[ ] Does it change the shape of findings dicts stored in VULNERABILITIES{}?
    If yes: does every consumer of VULNERABILITIES still work?
[ ] Does it change what get_findings() returns from result_ingestion_engine.py?
[ ] Does it add columns/keys to the postgres findings table without a migration?
[ ] Does it change the scan status state machine (running/completed/stopped/failed)?

CORRECTNESS
[ ] Are all claimed file:line numbers accurate? (stale references mislead future developers)
[ ] Are all code examples in the change syntactically valid Python/bash?
[ ] Does any migration advice produce a SyntaxError if followed literally?
[ ] Does it introduce any hardcoded secrets, credentials, or IP addresses?

COVERAGE GAPS
[ ] Does it add a new module that should be imported in Gate 2 but isn't?
[ ] Does it add a new DENYLIST file that isn't listed in the DENYLIST?
[ ] Does it add new asyncio.run() patterns the hygiene script won't catch?

## Output format (required):
ROLE: Verifier

ISSUES:
[CRITICAL] <issue> — <file:line evidence>
[HIGH]     <issue> — <file:line evidence>
[MEDIUM]   <issue> — <file:line evidence>
[LOW]      <issue> — <file:line evidence>
NONE       (if no issues found)

FALSE NEGATIVES (violations the hygiene script will miss): <list or NONE>
FALSE POSITIVES (legitimate code wrongly flagged): <list or NONE>

VERIFIER VERDICT: PASS | PASS_WITH_NOTES | FAIL
""")
```

**Verifier FAIL criteria:** any CRITICAL or HIGH issue = FAIL. MEDIUM/LOW = PASS_WITH_NOTES.

---

### Role 4 — Approver (Final Decision)

**Who:** The orchestrating agent (Main) — runs after both Checker and Verifier complete.

**Responsibility:** Read both reports. Apply fixes for any CRITICAL/HIGH issues.
Re-run gates after fixes. Issue final verdict with evidence.

**Decision matrix:**

| Checker | Verifier | Approver action |
|---|---|---|
| PASS | PASS | ✅ **APPROVED** — merge |
| PASS | PASS_WITH_NOTES | ✅ **APPROVED** — document notes, merge |
| PASS | FAIL | 🔴 **BLOCK** — fix CRITICAL/HIGH issues, re-run full pipeline |
| FAIL | any | 🔴 **BLOCK** — fix gate failures first, re-run full pipeline |
| FAIL | FAIL | 🔴 **BLOCK** — fix all, re-run full pipeline |

**Approver output (required before any "done" claim):**
```
APPROVER VERDICT
────────────────
Checker:  PASS | FAIL
Verifier: PASS | PASS_WITH_NOTES | FAIL

Issues fixed:
  [HIGH] <issue> → <fix applied at file:line>

Issues deferred (LOW/MEDIUM, documented):
  [MEDIUM] <issue> → tracked in AGENTS.md known-violations table

Final gates re-run: YES | NO (required if any fix was applied)

FINAL VERDICT: APPROVED | BLOCKED
```

**Never let an Approver approve without Checker evidence. Never self-approve.**

---

### Parallel Dispatch Template

Spawn Checker and Verifier simultaneously. Wait for both before running Approver.

```python
# Orchestrating agent — copy this pattern for every development task
from task import task  # hub task tool

# 1. Maker work is already done — produce handoff doc

# 2. Spawn Checker + Verifier in parallel (one task() call, two items)
results = task(
    context="oneinfinity EC2: 172.31.2.127, key: ~/.ssh/oneinfinity_sync, "
            "repo: /home/ubuntu/oneinfinity, venv: venv/bin/python",
    tasks=[
        {"agent": "sonic",    "name": "Checker",  "task": CHECKER_PROMPT},
        {"agent": "reviewer", "name": "Verifier", "task": VERIFIER_PROMPT},
    ]
)

# 3. Wait for both, then run Approver inline
# (Approver = orchestrating agent reads both outputs and makes decision)
```

---

### DENYLIST — never modify without explicit human approval

If the Maker handoff says "DENYLIST touched: YES", **stop**. Get human approval before
Checker or Verifier run. These files control production state:

```
web/backend/main.py:_lifespan             # startup sequence — breaks all background tasks
web/backend/main.py:VULNERABILITIES       # in-memory findings store — shape is API contract
web/backend/main.py:SCANS                 # in-memory scan store — shape is API contract
src/oneinfinity/findings/result_ingestion_engine.py:get_findings   # findings query contract
src/oneinfinity/core/db_manager.py                                  # postgres connection pool
docker-compose.yml                                                   # service topology
scripts/start-native.sh                                              # process entry points
scripts/check_process_hygiene.sh                                     # the hygiene gate itself
```

---

### Quick Reference — what each role does

```
MAKER     → writes code, produces handoff doc, never self-verifies
CHECKER   → runs 4 mechanical gates, reports raw output, sonic agent
VERIFIER  → adversarial review, finds bugs the maker missed, reviewer agent
APPROVER  → reads both, fixes CRITICAL/HIGH, issues final verdict, orchestrator

Parallel: Checker + Verifier run simultaneously (same task() batch)
Serial:   Approver runs only after both complete

Gate summary:
  G1 compile  → venv/bin/python -m compileall src/ web/backend/ -q
  G2 imports  → python -c "from ... import ...; print('OK')"
  G3 health   → curl http://localhost:3000/health → HTTP 200
  G4 hygiene  → bash scripts/check_process_hygiene.sh → exit 0
```
---

## Quality Gates

No traditional test suite. All four gates must pass before any PR or session-end claim of "done."
Run from the repo root (`/home/ubuntu/oneinfinity` on EC2, local repo on laptop).

### Gate 1 — Compilation

```bash
cd /home/ubuntu/oneinfinity
venv/bin/python -m compileall src/oneinfinity/ web/backend/ -q
echo "Gate 1 exit: $?"   # must be 0
```

Catches syntax errors, malformed f-strings, bad indentation across the entire Python surface.

### Gate 2 — Import Health

```bash
cd /home/ubuntu/oneinfinity
venv/bin/python -c "
import sys
sys.path.insert(0, 'src')
sys.path.insert(0, 'web/backend')

from oneinfinity.core.db_manager import get_db_manager
from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
from oneinfinity.orchestration.god_mode_engine import GodModeSession
from oneinfinity.scan.unified_scan_engine import UnifiedScanEngine
from oneinfinity.agents.scan_agent import ScanAgent
from oneinfinity.agents.exploit_agent import ExploitAgent
from oneinfinity.infra.llm_provider import LLMProviderFactory
from oneinfinity.attack_graph_core.risk_analyzer import RiskAnalyzer
print('All core imports: OK')
"
```

Catches import-time errors, missing `__init__` exports, circular imports introduced by new modules.

### Gate 3 — Backend Health

```bash
# Backend must already be running (PID from nohup)
curl -s -o /dev/null -w "HTTP %{http_code}" http://localhost:3000/health
# Must return: HTTP 200

curl -s http://localhost:3000/api/health | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('status') == 'ok' or 'ok' in str(d).lower(), f'Unhealthy: {d}'
print('Gate 3: OK')
"
```

Confirms the FastAPI process is alive and the event loop is healthy after your change.
Restart the backend first if you changed `web/backend/main.py`:

```bash
pkill -f 'python.*main.py'
sleep 3
cd /home/ubuntu/oneinfinity
nohup venv/bin/python -B web/backend/main.py >> logs/backend.log 2>&1 &
sleep 8
curl -s -o /dev/null -w "HTTP %{http_code}" http://localhost:3000/health
```

### Gate 4 — Process Hygiene

```bash
bash scripts/check_process_hygiene.sh   # must exit 0
```

The script checks:
- No new `asyncio.run()` calls introduced in modules under `src/oneinfinity/` since last commit
- No new Python entry points added to `scripts/start-native.sh`
- No new `python` service containers added to `docker-compose.yml`
- No new `subprocess.Popen` outside of the approved mobile tool wrappers

Script source: `scripts/check_process_hygiene.sh` (see below).

### Running all four gates in one pass

```bash
cd /home/ubuntu/oneinfinity && \
  venv/bin/python -m compileall src/oneinfinity/ web/backend/ -q && echo "Gate 1: OK" && \
  venv/bin/python -c "
import sys; sys.path.insert(0,'src'); sys.path.insert(0,'web/backend')
from oneinfinity.core.db_manager import get_db_manager
from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
from oneinfinity.orchestration.god_mode_engine import GodModeSession
from oneinfinity.scan.unified_scan_engine import UnifiedScanEngine
from oneinfinity.agents.scan_agent import ScanAgent
from oneinfinity.agents.exploit_agent import ExploitAgent
from oneinfinity.infra.llm_provider import LLMProviderFactory
from oneinfinity.attack_graph_core.risk_analyzer import RiskAnalyzer
print('Gate 2: OK')
" && \
  curl -sf http://localhost:3000/health > /dev/null && echo "Gate 3: OK" && \
  bash scripts/check_process_hygiene.sh && echo "Gate 4: OK" && \
  echo "=== ALL GATES PASSED ==="
```