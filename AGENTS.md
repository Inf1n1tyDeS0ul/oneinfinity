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

GOD MODE INTEGRITY
[ ] Does new scan logic bypass god_mode_engine.py and run only through a standalone endpoint?
    (= God Mode blind spot — CRITICAL if scan findings are not reachable via God Mode)
[ ] Does new finding logic break the chain: god_mode_engine → result_ingestion_engine → postgres → API?
[ ] Does any LLM call in scan context bypass offensive_router.py / model_orchestrator.py?

FULL-STACK SYNC
[ ] Does it add a new API endpoint without updating the frontend API client?
[ ] Does it add a new finding field without a postgres migration AND frontend update?
[ ] Does it change a response shape without updating all frontend consumers?
[ ] Does it affect Redis keys or Neo4j schema without documenting the change?

DUPLICATE FEATURES
[ ] Does this add a function/module that duplicates existing scan, agent, or orchestration code?
[ ] Does this add a new API route that is semantically identical to an existing route?
[ ] Does this add a new frontend component when an existing component could be parameterized?
[ ] Does this add a new finding vuln_type that duplicates an existing type in VULNERABILITIES{}?

OVER-ENGINEERING
[ ] Does it introduce a new abstraction (base class, factory, registry, manager) with only one use?
[ ] Does it add async wrappers around sync code with no concurrency benefit?

ROOT CAUSE
[ ] Does it add a try/except or guard that masks a bug instead of fixing the root cause?
    (= deferred bug, label [HIGH])
[ ] Does it suppress an error log without explaining why the error is safe to ignore?

STABILITY CONTRACT
[ ] After this change, do all existing API endpoints still return correct responses?
[ ] After this change, does the God Mode scan still complete successfully?
[ ] Is any existing finding in postgres at risk of being lost or becoming inaccessible?
[ ] Does it leave any service (frontend/backend/postgres/redis/neo4j) in an inconsistent state?

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

## Engineering Principles & Full-Stack Coherence (Hard Rules)

These rules apply to **every change** — feature, fix, refactor, or documentation.
They are not guidelines; they are non-negotiable constraints enforced at Verifier time.

---

### God Mode is the Primary Scan — Everything Orbits It

God Mode (`orchestration/god_mode_engine.py`, launched at `POST /api/god-mode/start`) is the
**canonical scan path** for oneinfinity. Every scan capability that exists must be reachable
through God Mode. Every new scan module, agent, or finding type **must** integrate with God Mode
first. Standalone endpoints are secondary wrappers, never the source of truth.

Rules:
- New scan logic → wire it into `GodModeSession` before exposing a standalone endpoint.
- New finding type → confirm it surfaces in `/api/god-mode/{scan_id}/findings`.
- New LLM call in scan context → route through `offensive_router.py` / `model_orchestrator.py`.
- Never create a parallel scan pipeline that bypasses `god_mode_engine.py`.
- God Mode findings flow: `god_mode_engine` → `result_ingestion_engine.get_findings()` →
  postgres → API → frontend. Break this chain and findings are lost.

---

### Full-Stack Service Sync — All Services Must Move Together

oneinfinity has five runtime services. A feature is not done until **all affected services
reflect the change consistently**. Partial deployments that leave services out of sync
are production bugs.

```
Service         Role                                    Change trigger
──────────────  ──────────────────────────────────────  ──────────────────────────────────────
Backend         FastAPI, scan engine, findings API      Always — every feature touches this
Frontend        React UI (web/frontend/)                Any new endpoint, finding type, or UX
PostgreSQL       Findings, scan history, state          Schema change, new column, new table
Redis           Session cache, rate limits, scan state  New caching layer, session change
Neo4j           Attack graph, asset relationships       New node type, new relationship type
```

**Before shipping any feature**, answer each question:

| Question | If YES → action required |
|---|---|
| New API endpoint? | Add to frontend API client; update UI if user-visible |
| New finding field? | Migrate postgres schema; update frontend finding card |
| New scan module? | Wire into God Mode; verify findings appear in dashboard |
| New session/state key? | Update Redis key schema; document TTL |
| New graph relationship? | Add Neo4j migration; update attack graph queries |
| Changed response shape? | Update all frontend consumers; re-run Gate 2 imports |

**Sync verification** — after any feature that touches ≥2 services, the Checker must
confirm each service reflects the change:

```bash
# Backend health
curl -s http://localhost:3000/health

# Postgres — confirm schema/data reflects change
psql -U oneinfinity -c "\d findings"    # or relevant table

# Redis — confirm no stale keys from old schema
redis-cli keys "oneinfinity:*" | head -20

# Neo4j — confirm graph is populated if attack-graph change was made
cypher-shell -u neo4j "MATCH (n) RETURN labels(n), count(n) LIMIT 10"

# Frontend — confirm UI renders without console errors (check browser devtools)
curl -sf http://localhost:3001/ > /dev/null && echo "Frontend: UP"
```

---

### UI-First Discovery — Reuse Before Building

Before writing a single line of frontend code for a new feature, search for existing
UI capabilities. One duplicate component or redundant page is tech debt that outlasts
the sprint that created it.

**Mandatory discovery steps** (Maker must complete before writing new UI):

1. Search `web/frontend/src/` for components, pages, hooks, or utilities that cover
   the needed capability:
   ```bash
   # Find existing components by keyword
   grep -r "keyword" web/frontend/src/components/ --include="*.tsx" -l
   grep -r "keyword" web/frontend/src/pages/ --include="*.tsx" -l
   ```
2. Check existing API hooks in `web/frontend/src/hooks/` or `web/frontend/src/api/` —
   an API client method may already exist.
3. Check the existing findings display (`FindingCard`, `FindingsList`, `VulnTable`, or
   equivalent) — new finding types must render through existing cards with new data,
   not a new card component.
4. Only if no reusable capability exists: build new. Document why reuse was not possible
   in the Maker handoff.

**Prohibited UI patterns:**
- A second scan status panel when one already exists
- A second findings list when `FindingsList` can be parameterized
- A duplicate API hook for the same endpoint
- A new page that duplicates an existing page with minor label differences
- Hardcoded mock/stub data in a component when a real API endpoint exists

---

### Root-Cause Mandate — Fix the Source, Never the Symptom

When a bug is found:
1. Identify the **root cause** — the earliest point in the call chain where the invariant breaks.
2. Fix it there, not in a downstream guard or a try/except that swallows the error.
3. Remove any symptom-masking code added before the root cause was understood.

**Prohibited symptom fixes:**
```python
# WRONG — hides a schema mismatch:
try:
    return finding["confirmed_tier"]
except KeyError:
    return "UNKNOWN"

# RIGHT — fix the schema so the key is always present, or migrate existing rows.
```
```python
# WRONG — masks a stale-cache bug:
if findings_from_cache != findings_from_db:
    return findings_from_db   # silently drops cache

# RIGHT — find why cache diverged; fix the write path that failed to invalidate.
```

The Verifier must call out any change that **adds a guard without removing the root cause**.
Label it `[HIGH]` — it is always a deferred bug, not a fix.

---

### No Duplicate Features

Before adding any capability, search the codebase for existing implementations:

```bash
# Use the code-review-graph MCP first:
# semantic_search_nodes("XSS scanner")  →  finds existing XSS detection code
# query_graph(pattern="callers_of", node="scan_for_xss")

# Fallback grep:
grep -r "xss\|cross.site" src/oneinfinity/ --include="*.py" -l
```

Duplicate feature checklist (Verifier enforces):
- [ ] Does a function with the same purpose already exist in `scan/`, `agents/`, or
      `orchestration/`? If yes → extend it, don't create a parallel one.
- [ ] Does an API endpoint with the same semantic already exist in `main.py`? If yes →
      reuse it with new parameters rather than adding a new route.
- [ ] Does a finding type with the same `vuln_type` string already exist in
      `main.py:VULNERABILITIES` or the postgres schema? If yes → reuse the type.
- [ ] Would this feature be reachable via God Mode after this change? If not → incomplete.

---

### No Over-Engineering

Every abstraction must earn its place. The cost of a wrong abstraction is higher than the
cost of a small amount of repetition.

**Signs of over-engineering (Verifier flags as [MEDIUM] or [HIGH]):**
- A new base class or ABC with only one subclass
- A factory function that unconditionally returns one concrete type
- A config dataclass for a value that will never change
- A "manager" or "registry" class wrapping a dict that is simpler to use directly
- Async wrappers around sync code that gains nothing from being async
- A plugin system for a use-case that has two fixed variants

Rule of three: abstract only when the same pattern appears in three or more concrete places.
Until then, keep it inline and readable.

---

### Enhancement Mindset — Always Look for Improvement

Every code touch is an opportunity. When reading existing code to implement a change,
note — and act on — improvements that are safe to make in the same commit:

- A stale comment that no longer matches the code → delete or correct it.
- A raw `print()` in a module that has a `log` → replace with `log.debug()`.
- An `except Exception: pass` that silently swallows errors → add `log.error(..., exc_info=True)`.
- A hardcoded string that appears twice → extract to a module constant.
- A God Mode result that is computed but never surfaced in the API response → wire it up.
- A finding that reaches postgres but is never displayed on the frontend → fix the display.

**Scope constraint:** enhancements must be in the same file or directly adjacent module.
Do not chase enhancement rabbits across unrelated files in a single commit — open a
separate task for those.

**Enhancement in Verifier scope:** the Verifier should note `[LOW] Enhancement opportunity`
items even when they are not blockers. The Approver decides whether to include them in the
current commit or defer.

---

### Non-Negotiable Stability Contract

Every change must leave the system in a state where:

1. **All existing API endpoints still return correct responses.** Run Gate 3 after every
   backend change. If an endpoint's shape changes, all callers must be updated in the
   same commit — never leave a consumer broken.
2. **All existing findings in postgres remain accessible.** The `get_findings()` contract
   in `result_ingestion_engine.py` must not change shape without a migration.
3. **God Mode scan completes successfully on a known target.** If your change touches
   `god_mode_engine.py` or any module it imports, trigger a test scan and confirm
   findings are returned.
4. **Frontend renders without runtime errors.** After any frontend change, open the
   dashboard and confirm no uncaught JS exceptions in the browser console.
5. **No finding is lost.** If you change how findings are written or read, verify the count
   before and after your change is identical (or intentionally changed and documented).

These are not acceptance criteria for a PR — they are baseline hygiene. A change that
fails any of them is not done; it is broken.


## Code Sync — Local ↔ GitHub ↔ EC2 (Hard Rule)

**GitHub is the single source of truth.**
Local and EC2 must both be at the same commit as `origin/main`
before starting any session and after ending any session.
Never leave uncommitted working changes on EC2 overnight.

### Topology

```
  Local (macOS)                   EC2 (172.31.2.127)
  /Users/devendra.yadav/          /home/ubuntu/
  oneinfinity/                    oneinfinity/
       │                               │
       │  git push / git pull          │  git push / git pull
       │                               │
       └──────────── GitHub ───────────┘
              Inf1n1tyDeS0ul/oneinfinity
              branch: main (only branch for active work)

  EC2 remote config:
    fetch:  https://github.com/Inf1n1tyDeS0ul/oneinfinity.git
    push:   git@github-oneinfinity:Inf1n1tyDeS0ul/oneinfinity.git

  EC2 post-commit hook auto-pushes to GitHub on every commit.
  Local pushes via HTTPS (token auth).
```

### Start-of-session checklist (always run first)

```bash
# On whichever machine you are about to develop on:
cd /home/ubuntu/oneinfinity   # or local equivalent
git fetch origin
git status                    # must be clean — no uncommitted changes
git log --oneline HEAD..origin/main   # must be empty (nothing to pull)
git pull origin main --rebase         # pull if behind
```

If `git status` shows modified files: **commit them first** (see commit rules below).
Never develop on top of uncommitted changes.

### End-of-session checklist (always run before closing)

```bash
# 1. Run all 4 quality gates
bash scripts/check_process_hygiene.sh

# 2. Commit everything — no WIP commits, no "misc" messages
git add -A
git commit -m "<type>(<scope>): <what changed and why>"

# 3. Push to GitHub
git push origin main

# 4. Pull on the other machine
#    If you worked on Local → pull on EC2:
ssh -i ~/.ssh/oneinfinity_sync ubuntu@172.31.2.127 \
  "cd /home/ubuntu/oneinfinity && git pull origin main --rebase"

#    If you worked on EC2 → pull on Local:
cd /Users/devendra.yadav/oneinfinity && git pull origin main --rebase

# 5. If web/backend/main.py changed — restart backend on EC2
ssh -i ~/.ssh/oneinfinity_sync ubuntu@172.31.2.127 \
  "pkill -f 'python.*main.py'; sleep 3;
   cd /home/ubuntu/oneinfinity;
   nohup venv/bin/python -B web/backend/main.py >> logs/backend.log 2>&1 &
   sleep 8 && curl -sf http://localhost:3000/health > /dev/null && echo 'backend: UP'"
```

### One-command sync (use `scripts/sync.sh`)

```bash
# From local — commits staged changes, pushes, pulls on EC2, restarts if needed:
bash scripts/sync.sh "feat(scan): add new IDOR detection module"

# From EC2 — commits staged changes, pushes to GitHub:
bash scripts/sync.sh "fix(scanner): headless browser timeout fix"
```

### Commit message format

```
<type>(<scope>): <imperative description, ≤72 chars>

type:  feat | fix | chore | docs | refactor | perf | test
scope: scan | agent | api | mobile | ai | infra | db | frontend | docs

Examples:
  feat(scan): add GraphQL batching attack to graphql_scan_engine
  fix(agent): exploit_agent pool crash on empty findings list
  chore(infra): add src/nim/bin/ to .gitignore
  docs(agents): add 4-role development workflow to AGENTS.md
```

### Never

- Push without all 4 quality gates passing
- Push directly to a branch other than `main` without a PR review
- Leave EC2 with uncommitted changes at end of session
- Merge commit on pull — always `--rebase`
- Force-push to `main` (`git push --force`) — ask human first
- Commit secrets, `.env` files, scan output JSON, or binary build artifacts

### Conflict resolution

EC2 and Local diverge only when both machines commit to `main` without syncing.
Resolution is always: **rebase, never merge**.

```bash
# Machine that is behind:
git fetch origin
git rebase origin/main        # replay your commits on top of remote
# Fix any conflicts, then:
git rebase --continue
git push origin main
```

If a rebase is blocked by an untracked file conflicting with a remote commit:
```bash
git rebase --abort
# Remove or commit the blocking file, then retry rebase
```

### What is never committed (enforced by .gitignore)

```
.env  .env.*          # secrets — use .env.example for templates
venv/  node_modules/  # dependency trees — pip/npm install on each machine
logs/  *.log          # runtime output — lives only on the running machine
.oneinfinity/         # scan state, findings cache — machine-local runtime data
god-mode-*.json       # scan session state — not code
unified_findings.json # findings JSON — stored in postgres, not git
*.db  *.sqlite        # databases — not code
data/                 # binary/large data — not code
src/nim/bin/          # compiled binaries — build on target machine
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
from oneinfinity.findings.finding_judge import get_judge
from oneinfinity.orchestration.god_mode_engine import GodModeSession
from oneinfinity.orchestration.offensive_router import get_model_for_task
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
from oneinfinity.findings.finding_judge import get_judge
from oneinfinity.orchestration.god_mode_engine import GodModeSession
from oneinfinity.orchestration.offensive_router import get_model_for_task
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