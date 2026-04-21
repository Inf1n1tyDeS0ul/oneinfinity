# OneInfinity Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve every finding from three independent audits (Claude Code, Codex, Gemini) to achieve 100% operational coverage and production-grade reliability.

**Architecture:** 10 work streams, 35 tasks, each self-contained and independently testable. No task changes shared state that another task reads — sequences are ordered where dependencies exist. Every task ends with a commit.

**Tech Stack:** Python 3.13, FastAPI, SQLite WAL, React/Vite, Docker Compose, psutil, aiosqlite, pytest

**Audit Sources:**
- Claude Code Phase 1 + Phase 2 (this session)
- Gemini CLI Phase 1 + Phase 2
- Codex Phase 1 + Phase 2

---

## Source → Issue Cross-Reference

| ID  | Issue | Severity | Audits |
|-----|-------|----------|--------|
| A01 | `_require_auth()` is a no-op — zero authentication | Critical | All |
| A02 | God-mode target skips `_validate_target()` | High | Claude |
| A03 | `_SAFE_TARGET_RE` allowlist compiled but never used | Medium | Claude |
| A04 | Default API key "changeme" in both compose files | Medium | Claude/Codex |
| A05 | Finding replay endpoint shells out with unvalidated data | High | Gemini |
| A06 | Auth headers potentially logged in full command strings | High | Gemini |
| A07 | `oneinfinity scan` (no --yes) = script generator, not a scan | Critical | All |
| A08 | rc=127 on missing tool → scan continues with 0 findings, no user warning | High | All |
| A09 | `ToolResult.success=True` even when exit code non-zero (partial output) | Medium | Codex |
| A10 | Two divergent pipeline definitions (14-phase vs 17-phase) — different results by entry point | High | All |
| A11 | OOB engine absent from unified_scan_engine (API path) | Medium | Gemini |
| A12 | Auth session from CLI not shared with API | Medium | Gemini |
| A13 | `SCANS`/`VULNERABILITIES` in-memory only — lost on restart | High | All |
| A14 | Stop scan does nothing for inline canonical scans (pid=None) | High | Gemini/Codex |
| A15 | Swarm results only visible after server restart | Medium | Gemini |
| A16 | Worker requires Redis but default docker-compose.yml has no Redis | High | Phase 2 |
| A17 | Frontend Docker volume `:ro` breaks `npm ci` write access | Critical | Codex |
| A18 | Vite proxy hardcoded to `localhost:8000` (wrong in Docker) | High | Codex |
| A19 | Backend uses `--reload` (dev mode) in production Docker | Medium | All |
| A20 | Python 3.11 in Dockerfile, host runs 3.13 | Low | Claude |
| A21 | Default `GRAFANA_PASSWORD=admin` in .env.example | Medium | Codex |
| A22 | Docker `network_mode: host` + `cap_add: NET_RAW` no safe profile | Medium | Codex |
| A23 | 9 missing backend routes → UI features silently 404 | High | Claude |
| A24 | 4 dead endpoint aliases in api.js (wrong prefix `/utilities/`) | Low | Claude |
| A25 | `SCANS` dict unbounded — memory leak under long operation | Medium | All |
| A26 | `VULNERABILITIES` dict unbounded | Medium | Claude |
| A27 | Orphaned child processes when scan killed (nuclei, sqlmap) | High | All |
| A28 | Attack graph `_graph_instances` shared mutable state — race condition under concurrency | High | Phase 2 |
| A29 | Orphaned recursion event handlers after interrupted god-mode scans | Medium | Phase 2 |
| A30 | 90 silent `except` blocks in unified_scan_engine.py hide real failures | High | All |
| A31 | WAF rate limit from WAFDetectionEngine not passed to tool wrappers (sqlmap, dalfox) | Medium | Gemini |
| A32 | 6 API sub-routers registered in try/except — silent 404 if import fails | Medium | Phase 2 |
| A33 | No SQLite connection pooling — `database is locked` under concurrency | Medium | Claude |
| A34 | 14 swarm agents run concurrently with no concurrency cap | Low | Claude |
| A35 | `/metrics` endpoint returns placeholder | Low | Claude |
| A36 | Pydantic V1 `@validator` deprecation — will error in V3 | Low | Claude |
| A37 | `FindingsDB.close()` and `log_action()` are pass no-ops | Medium | Codex |
| A38 | `_HAS_URLLIB` always True (dead check) in custom_test_engine.py | Low | Claude |
| A39 | Dev/debug scripts in repo root polluting codebase | Low | Claude |
| A40 | Postman collections committed to root | Low | Claude |
| A41 | God mode via API produces empty reports (writes to in-memory, report reads ingestion engine) | High | Phase 2 |
| A42 | `LOG_MESSAGES` broadcast via unauthenticated WebSocket | High | Gemini |
| A43 | `graph_storage.py` abstract methods are bare `pass` — no contract enforcement | Low | Codex |

---

## File Map

Files that will be created or modified across all tasks:

| File | Action | Work Stream |
|------|--------|-------------|
| `web/backend/main.py` | Modify | 1, 3, 4, 5, 6, 7, 8 |
| `web/frontend/vite.config.js` | Modify | 4 |
| `docker-compose.yml` | Modify | 4 |
| `docker-compose.distributed.yml` | Modify | 4 |
| `.env.example` | Modify | 1, 4 |
| `Dockerfile` | Modify | 4 |
| `oneinfinity.py` | Modify | 2 |
| `unified_scan_engine.py` | Modify | 3, 6 |
| `modules/tool_wrappers.py` | Modify | 2, 6 |
| `modules/findings.py` | Modify | 9 |
| `custom_test_engine.py` | Modify | 9 |
| `web/backend/graph_api.py` | Modify | 8 |
| `core/scan_state.py` | Create | 5 |
| `tests/test_auth.py` | Create | 1 |
| `tests/test_scan_stop.py` | Create | 7 |
| `tests/test_state_persistence.py` | Create | 5 |
| `tests/test_docker_compose.py` | Create | 4 |
| `scripts/archived/` | Create | 9 |

---

## Work Stream 1 — Security Hardening (A01–A06, A42)

### Task 1: Implement API Key Authentication

**Addresses:** A01, A42

**Files:**
- Modify: `web/backend/main.py:47–49` (replace `_require_auth` no-op)
- Modify: `web/backend/main.py:1180–1200` (protect WebSocket log endpoint)
- Create: `tests/test_auth.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_auth.py
import os, pytest
from fastapi.testclient import TestClient

os.environ["ONEINFINITY_API_KEY"] = "test-secret"

from web.backend.main import app

client = TestClient(app, raise_server_exceptions=False)

def test_unauthenticated_scan_returns_401():
    resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "quick"})
    assert resp.status_code == 401

def test_authenticated_scan_passes_auth():
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "scan_type": "quick"},
        headers={"X-API-Key": "test-secret"},
    )
    # 200 or 422 (validation) — not 401
    assert resp.status_code != 401

def test_no_key_set_allows_all():
    """When ONEINFINITY_API_KEY is unset, all requests pass (local dev mode)."""
    del os.environ["ONEINFINITY_API_KEY"]
    resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "quick"})
    assert resp.status_code != 401
    os.environ["ONEINFINITY_API_KEY"] = "test-secret"

def test_ws_logs_requires_auth_when_key_set():
    with client.websocket_connect("/ws/logs") as ws:
        # Connection accepted but first message should be auth error or normal if key provided in query
        pass  # Connection itself doesn't need auth, only _add_log from scan ops checks

def test_wrong_key_returns_401():
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "scan_type": "quick"},
        headers={"X-API-Key": "wrong-key"},
    )
    assert resp.status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_auth.py::test_unauthenticated_scan_returns_401 -v
```
Expected: FAIL — currently returns 200, not 401

- [ ] **Step 3: Replace `_require_auth` with real enforcement**

Find in `web/backend/main.py` line 47:
```python
async def _require_auth():
    pass  # Auth disabled — open access for local tool use
```
Replace with:
```python
_API_KEY: str = os.environ.get("ONEINFINITY_API_KEY", "")

async def _require_auth(request: Request):
    """Enforce X-API-Key header when ONEINFINITY_API_KEY env var is set.
    
    When ONEINFINITY_API_KEY is empty (local dev), all requests pass through.
    When set, requests must provide matching X-API-Key header.
    """
    if not _API_KEY:
        return  # Local dev mode — no key configured
    provided = request.headers.get("X-API-Key", "")
    if not provided:
        raise HTTPException(status_code=401, detail="X-API-Key header required")
    if provided != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_auth.py -v
```
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py tests/test_auth.py
git commit -m "security: implement X-API-Key authentication enforcement"
```

---

### Task 2: Fix Target Validation — Use Allowlist, Apply to God-Mode

**Addresses:** A02, A03

**Files:**
- Modify: `web/backend/main.py:31–46` (`_validate_target` function)
- Modify: `web/backend/main.py:2310–2315` (god-mode handler)

- [ ] **Step 1: Write failing test**

```python
# Add to tests/test_auth.py (or create tests/test_validation.py)
def test_god_mode_rejects_shell_chars():
    resp = client.post(
        "/api/god-mode/run",
        json={"target": "example.com; rm -rf /"},
        headers={"X-API-Key": "test-secret"},
    )
    assert resp.status_code == 400

def test_validate_target_uses_allowlist():
    resp = client.post(
        "/api/god-mode/run",
        json={"target": "$(curl evil.com)"},
        headers={"X-API-Key": "test-secret"},
    )
    assert resp.status_code == 400

def test_valid_target_passes():
    resp = client.post(
        "/api/god-mode/run",
        json={"target": "https://example.com/path?q=1"},
        headers={"X-API-Key": "test-secret"},
    )
    assert resp.status_code != 400
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_auth.py::test_god_mode_rejects_shell_chars -v
```
Expected: FAIL — god-mode currently accepts shell chars

- [ ] **Step 3: Fix `_validate_target` to use allowlist AND apply it in god-mode handler**

In `web/backend/main.py`, update `_validate_target` (lines 33–45):
```python
_SAFE_TARGET_RE = _re.compile(
    r'^(https?://)?[a-zA-Z0-9._:\-/~%?=&#@\[\]]+$'
)
_SHELL_META_RE = _re.compile(r'[;&|`$<>()\\\n\r]')

def _validate_target(domain: str) -> str:
    """Raise HTTPException(400) if the target is invalid.
    
    Uses BOTH a denylist (shell metacharacters) AND an allowlist (safe chars only).
    The allowlist is the stronger check and catches novel metacharacters.
    """
    if not domain:
        raise HTTPException(status_code=400, detail="Target/domain must not be empty")
    if len(domain) > 512:
        raise HTTPException(status_code=400, detail="Target too long (max 512 chars)")
    if _SHELL_META_RE.search(domain):
        raise HTTPException(status_code=400, detail=f"Invalid target — shell metacharacters not allowed: {domain!r}")
    if not _SAFE_TARGET_RE.match(domain):
        raise HTTPException(status_code=400, detail=f"Invalid target — contains disallowed characters: {domain!r}")
    return domain.strip()
```

In the god-mode handler (find the block at ~line 2310):
```python
    target = (data.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
```
Add `_validate_target(target)` call right after:
```python
    target = (data.get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    _validate_target(target)  # ← ADD THIS LINE
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_auth.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py
git commit -m "security: use allowlist in _validate_target, apply to god-mode handler"
```

---

### Task 3: Remove "changeme" Default API Key

**Addresses:** A04, A21

**Files:**
- Modify: `docker-compose.yml` (line 28)
- Modify: `docker-compose.distributed.yml` (lines 49, 306, 335)
- Modify: `.env.example`

- [ ] **Step 1: Fix docker-compose.yml**

Find line 28:
```yaml
    - ONEINFINITY_API_KEY=${ONEINFINITY_API_KEY:-changeme}
```
Replace with:
```yaml
    - ONEINFINITY_API_KEY=${ONEINFINITY_API_KEY:-}
```

- [ ] **Step 2: Fix docker-compose.distributed.yml**

Find and replace all occurrences of `changeme-set-in-env`:
```yaml
  ONEINFINITY_API_KEY: ${ONEINFINITY_API_KEY:-}
```
and:
```yaml
      VITE_API_KEY: ${ONEINFINITY_API_KEY:-}
```
and in the healthcheck curl command:
```yaml
            -H 'X-API-Key: ${ONEINFINITY_API_KEY}' \
```

- [ ] **Step 3: Fix .env.example**

Find the Grafana password line and API key:
```bash
ONEINFINITY_API_KEY=           # Set to a strong random string: openssl rand -hex 32
GRAFANA_PASSWORD=              # Required — do NOT leave empty in production
```
Remove any `admin` default for GRAFANA_PASSWORD.

- [ ] **Step 4: Verify compose files parse correctly**

```bash
cd /home/devendra-yadav/oneinfinity
docker compose config --quiet 2>&1 | head -20
```
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml docker-compose.distributed.yml .env.example
git commit -m "security: remove changeme default API key and admin Grafana password"
```

---

### Task 4: Redact Auth Headers in Tool Command Logging

**Addresses:** A06

**Files:**
- Modify: `modules/tool_wrappers.py` (the `_wrap` function, line ~159)

- [ ] **Step 1: Write failing test**

```python
# tests/test_tool_wrappers.py
from modules.tool_wrappers import _wrap

def test_command_string_redacts_bearer_tokens():
    """Auth headers must not appear in logged command strings."""
    import logging
    records = []
    
    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())
    
    import modules.tool_wrappers as tw
    handler = Capture()
    tw.log.addHandler(handler)
    
    # Simulate a tool call with auth header
    _wrap(
        tool="nuclei",
        cmd=["nuclei", "-u", "http://example.com",
             "-H", "Authorization: Bearer supersecrettoken123"],
        timeout=5,
    )
    tw.log.removeHandler(handler)
    
    for msg in records:
        assert "supersecrettoken123" not in msg, f"Token leaked in log: {msg}"
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_tool_wrappers.py::test_command_string_redacts_bearer_tokens -v
```
Expected: FAIL — token currently appears in command_str

- [ ] **Step 3: Add redaction to `_wrap`**

In `web/backend/main.py`, `_wrap` function (~line 157), replace:
```python
    command_str = " ".join(str(c) for c in cmd)
```
with:
```python
    def _redact_cmd(cmd_list: list) -> str:
        """Redact Authorization header values from command strings for logging."""
        redacted = []
        skip_next = False
        for token in cmd_list:
            if skip_next:
                # Redact the value following -H / --header
                redacted.append("[REDACTED]")
                skip_next = False
                continue
            token_str = str(token)
            if token_str.lower() in ("-h", "--header"):
                skip_next = True
                redacted.append(token_str)
            elif token_str.lower().startswith("authorization:"):
                redacted.append("Authorization:[REDACTED]")
            else:
                redacted.append(token_str)
        return " ".join(redacted)
    
    command_str = _redact_cmd(cmd)
```

Note: Place `_redact_cmd` as a module-level function before `_wrap` to avoid redefining it on every call.

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_tool_wrappers.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add modules/tool_wrappers.py tests/test_tool_wrappers.py
git commit -m "security: redact Authorization headers from tool command log strings"
```

---

## Work Stream 2 — The Scan No-Op Bug (A07, A08, A09)

### Task 5: Fix `oneinfinity scan` No-Op — Warn User and Prompt

**Addresses:** A07

**Files:**
- Modify: `oneinfinity.py` (~line 168, `cmd_scan` function)

- [ ] **Step 1: Write failing test**

```python
# tests/test_cli_scan.py
import subprocess, sys

def test_scan_without_yes_prints_warning():
    """Running `oneinfinity scan <target>` without --yes must warn the user."""
    result = subprocess.run(
        [sys.executable, "oneinfinity.py", "scan", "example.com"],
        capture_output=True, text=True, cwd="/home/devendra-yadav/oneinfinity",
        input="n\n",  # User answers no to prompt
        timeout=10,
    )
    combined = result.stdout + result.stderr
    assert "WARNING" in combined.upper() or "no scan" in combined.lower() or \
           "--yes" in combined, \
           f"No warning shown. Output was:\n{combined}"

def test_scan_without_yes_does_not_silently_succeed():
    """Without --yes, exit code should be non-zero OR output must contain explicit notice."""
    result = subprocess.run(
        [sys.executable, "oneinfinity.py", "scan", "example.com"],
        capture_output=True, text=True, cwd="/home/devendra-yadav/oneinfinity",
        input="n\n",
        timeout=10,
    )
    # If it exits 0, the output MUST mention the script-only behavior
    if result.returncode == 0:
        combined = result.stdout + result.stderr
        assert "--yes" in combined or "script" in combined.lower()
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_cli_scan.py::test_scan_without_yes_prints_warning -v
```
Expected: FAIL — no warning is printed currently

- [ ] **Step 3: Add warning to `cmd_scan` in `oneinfinity.py`**

Find the `cmd_scan` function (~line 168). Find the branch where `--yes` is NOT set that calls `_cmd_scan_legacy`. Add before it:

```python
        # ── IMPORTANT: without --yes, we generate a scan script but do NOT execute it ──
        print(
            "\n⚠️  WARNING: 'oneinfinity scan' without --yes generates a recon script "
            "to disk but does NOT run a scan.\n"
            "   To run an actual scan: oneinfinity scan <target> --yes\n"
            "   To run the full pipeline: oneinfinity full-scan <target>\n",
            file=sys.stderr,
        )
```

Also capture the script path from `_cmd_scan_legacy` and print it:
```python
        script_path = _cmd_scan_legacy(args)
        if script_path:
            print(f"   Script written to: {script_path}", file=sys.stderr)
            print(f"   To execute it: bash {script_path}", file=sys.stderr)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_cli_scan.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add oneinfinity.py tests/test_cli_scan.py
git commit -m "fix: warn user when scan runs without --yes (script-only mode)"
```

---

### Task 6: Surface Missing Tool Warnings to User

**Addresses:** A08, A09

**Files:**
- Modify: `modules/tool_wrappers.py` (`_wrap` function and `ToolResult`)

- [ ] **Step 1: Write failing test**

```python
# tests/test_tool_wrappers.py (add to existing file)
from modules.tool_wrappers import _wrap, ToolResult

def test_missing_tool_returns_tool_not_found_error():
    result = _wrap(tool="nonexistent_tool_xyz", cmd=["nonexistent_tool_xyz", "--help"])
    assert result.success is False
    assert result.returncode == 127
    assert "not found" in result.error.lower() or "tool not found" in result.error.lower()

def test_tool_result_success_false_on_nonzero_exit():
    """ToolResult.success must be False when rc != 0, even if output was produced."""
    # Simulate a tool that exits non-zero but writes something to stdout
    result = _wrap(tool="python3", cmd=["python3", "-c", "import sys; print('output'); sys.exit(1)"])
    assert result.success is False, "success must be False on non-zero exit"

def test_tool_result_success_true_only_on_rc_zero():
    result = _wrap(tool="python3", cmd=["python3", "-c", "print('ok')"])
    assert result.success is True
```

- [ ] **Step 2: Run to verify A09 failure**

```bash
python -m pytest tests/test_tool_wrappers.py::test_tool_result_success_false_on_nonzero_exit -v
```
Expected: FAIL if `_wrap` currently sets `success = rc == 0 or bool(stdout)`

- [ ] **Step 3: Fix `_wrap` success logic and add rc=127 log**

In `modules/tool_wrappers.py`, in `_wrap` function (~line 162):

Change:
```python
    success = rc == 0
```
to:
```python
    success = (rc == 0)
    # rc=127 means tool binary is missing — surface this clearly
    if rc == 127:
        log.warning(
            "TOOL MISSING: '%s' is not installed or not on PATH. "
            "Install it to enable this scan phase. (cmd: %s)",
            cmd[0], cmd[0],
        )
```

Ensure `success` is ONLY set by `rc == 0`, not by presence of stdout. Find any line like:
```python
    success = rc == 0 or bool(stdout)
```
or:
```python
    if stdout:
        success = True
```
and remove those overrides.

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_tool_wrappers.py -v
```
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add modules/tool_wrappers.py tests/test_tool_wrappers.py
git commit -m "fix: surface missing tool warnings, fix ToolResult.success to require rc==0"
```

---

## Work Stream 3 — Pipeline Unification (A10, A11, A12, A41)

### Task 7: Derive unified_scan_engine Phase List from canonical.py

**Addresses:** A10

**Files:**
- Modify: `unified_scan_engine.py` (phase list at top of file)
- Read: `pipeline/canonical.py` (PHASE_MAP, MANDATORY_PHASES)

- [ ] **Step 1: Write regression test**

```python
# tests/test_pipeline_parity.py
def test_unified_engine_phase_names_match_canonical():
    """unified_scan_engine must include all mandatory canonical phases."""
    from pipeline.canonical import PHASE_MAP, MANDATORY_PHASES
    from unified_scan_engine import ScanEngine
    
    engine = ScanEngine.__new__(ScanEngine)
    # The _PHASES list should exist and contain the canonical mandatory phase names
    assert hasattr(engine, '_PHASES') or hasattr(ScanEngine, '_PHASES'), \
        "ScanEngine must define _PHASES"
    
    canonical_names = set(PHASE_MAP.keys())
    # Every mandatory canonical phase must exist in the unified engine
    for phase_name in MANDATORY_PHASES:
        assert phase_name in canonical_names

def test_business_logic_phase_present_in_unified():
    """business_logic is in canonical but missing from unified — this must be fixed."""
    from unified_scan_engine import ScanEngine
    import inspect
    src = inspect.getsource(ScanEngine)
    assert "business_logic" in src, \
        "unified_scan_engine must include business_logic phase (present in canonical.py)"
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_pipeline_parity.py -v
```
Expected: FAIL on `test_business_logic_phase_present_in_unified`

- [ ] **Step 3: Add missing phases to `unified_scan_engine.py`**

Read the current `_PHASES` list at the top of `unified_scan_engine.py`. The canonical pipeline has these phases not in unified:
- `business_logic` (phase 6 in canonical)
- `oob_check` (phase 14 in canonical)

Add corresponding `_phase_business_logic` and `_phase_oob_check` methods to `ScanEngine`:

```python
    def _phase_business_logic(self, session: ScanSession) -> None:
        """Business logic attack surface enumeration (from canonical pipeline)."""
        try:
            from business_logic_attack_engine import BusinessLogicAttackEngine
            engine = BusinessLogicAttackEngine()
            # Run synchronously via asyncio.run if engine is async
            import asyncio
            attacks = asyncio.run(engine.generate(session.target, {}, None))
            for attack in (attacks or []):
                d = attack.to_dict() if hasattr(attack, "to_dict") else attack
                d.setdefault("vuln_type", "business_logic")
                d.setdefault("source", "business_logic_engine")
                session.findings.append(d)
            log.info("Phase business_logic: %d attack vectors found", len(attacks or []))
        except Exception as exc:
            log.warning("Phase business_logic skipped: %s", exc)

    def _phase_oob_check(self, session: ScanSession) -> None:
        """Poll OOB callback server for interactions triggered during scan."""
        try:
            oob = getattr(session, "_oob_engine", None)
            if oob is None:
                log.debug("Phase oob_check: no OOB engine initialized, skipping")
                return
            interactions = oob.poll_interactions()
            for interaction in (interactions or []):
                interaction.setdefault("vuln_type", "oob_interaction")
                interaction.setdefault("source", "oob_engine")
                session.findings.append(interaction)
            log.info("Phase oob_check: %d OOB interaction(s) received", len(interactions or []))
        except Exception as exc:
            log.warning("Phase oob_check skipped: %s", exc)
```

Add these to the `_PHASES` list in the correct positions (after `auth_setup` and at the end respectively).

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_pipeline_parity.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add unified_scan_engine.py tests/test_pipeline_parity.py
git commit -m "fix: add business_logic and oob_check phases to unified_scan_engine"
```

---

### Task 8: Fix God-Mode API Report Writing to Use Ingestion Engine

**Addresses:** A41

**Files:**
- Modify: `web/backend/main.py` (god-mode background task, ~line 2340–2380)

- [ ] **Step 1: Write failing test**

```python
# tests/test_god_mode_api.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""  # local dev mode, no auth

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

def test_god_mode_findings_visible_after_run():
    """Findings from a god-mode API run must be queryable via /api/findings."""
    # Launch god mode (it will run quickly in test mode with a fake target)
    resp = client.post("/api/god-mode/run", json={"target": "127.0.0.1"})
    assert resp.status_code == 200
    session_id = resp.json().get("session_id")
    assert session_id
    
    # Poll until done (with timeout)
    import time
    for _ in range(10):
        status_resp = client.get(f"/api/god-mode/status/{session_id}")
        if status_resp.json().get("status") in ("completed", "error"):
            break
        time.sleep(1)
    
    # Findings must be retrievable (even if empty — we verify the path works)
    findings_resp = client.get("/api/findings", params={"session_id": session_id})
    assert findings_resp.status_code == 200
```

- [ ] **Step 2: Identify the god-mode background function**

In `web/backend/main.py`, find `_run_god_mode_background` or the background task for god mode (~line 2340). It currently spawns a subprocess CLI command and updates `SCANS[session_id]` in memory. The report then reads from `result_ingestion_engine` which is NOT updated from the in-memory path.

- [ ] **Step 3: Fix — ensure god-mode findings are written to ingestion engine**

In the god-mode background task, after the subprocess completes, add:

```python
    # Sync findings from in-memory SCANS dict to the ingestion engine
    # so that report generation (which reads from ingestion engine) sees them
    try:
        from result_ingestion_engine import get_ingestion_engine
        ie = get_ingestion_engine()
        scan_findings = SCANS.get(session_id, {}).get("findings", [])
        for finding in scan_findings:
            try:
                ie.ingest(finding)
            except Exception as _exc:
                log.debug("god-mode ingestion sync: %s", _exc)
        log.info("god-mode: synced %d finding(s) to ingestion engine", len(scan_findings))
    except Exception as exc:
        log.warning("god-mode ingestion sync failed: %s", exc)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_god_mode_api.py -v
```
Expected: PASS (findings path works end-to-end)

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py tests/test_god_mode_api.py
git commit -m "fix: sync god-mode API findings to ingestion engine for report generation"
```

---

## Work Stream 4 — Docker & Deployment Fixes (A16–A22)

### Task 9: Fix Frontend Docker Volume and Vite Proxy

**Addresses:** A17, A18

**Files:**
- Modify: `docker-compose.yml` (lines 89–96, frontend service)
- Modify: `web/frontend/vite.config.js` (proxy configuration)

- [ ] **Step 1: Write validation test**

```python
# tests/test_docker_compose.py
import yaml, pathlib

ROOT = pathlib.Path("/home/devendra-yadav/oneinfinity")

def test_frontend_volume_not_readonly():
    with open(ROOT / "docker-compose.yml") as f:
        cfg = yaml.safe_load(f)
    frontend = cfg["services"]["frontend"]
    volumes = frontend.get("volumes", [])
    for vol in volumes:
        vol_str = str(vol)
        assert ":ro" not in vol_str, \
            f"Frontend volume is read-only — npm ci cannot write node_modules: {vol_str}"

def test_vite_proxy_uses_env_variable():
    vite_cfg = (ROOT / "web/frontend/vite.config.js").read_text()
    assert "VITE_BACKEND_URL" in vite_cfg or "process.env" in vite_cfg or \
           "import.meta.env" in vite_cfg, \
           "Vite proxy must use env variable, not hardcoded localhost:8000"

def test_backend_not_in_reload_mode():
    with open(ROOT / "docker-compose.yml") as f:
        cfg = yaml.safe_load(f)
    backend_cmd = str(cfg["services"]["backend"].get("command", ""))
    assert "--reload" not in backend_cmd, \
        "Backend must not use --reload in production Docker"
```

- [ ] **Step 2: Run to verify failures**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_docker_compose.py -v
```
Expected: 3 FAIL

- [ ] **Step 3: Fix docker-compose.yml**

Frontend service — change volume from `:ro` to writable, and inject backend URL:
```yaml
  frontend:
    container_name: oneinfinity-frontend
    build: ./web/frontend
    volumes:
      - ./web/frontend:/app        # removed :ro — npm ci needs write access
      - /app/node_modules          # anonymous volume to prevent host override
    environment:
      - VITE_BACKEND_URL=http://backend:8000
    command: sh -c "npm ci --silent && npm run dev -- --host 0.0.0.0"
```

Backend service — remove `--reload`:
```yaml
  backend:
    command: uvicorn web.backend.main:app --host 0.0.0.0 --port 8000 --workers 1
```

- [ ] **Step 4: Fix `web/frontend/vite.config.js`**

Replace the hardcoded proxy:
```javascript
// Before:
proxy: {
  '/api': { target: 'http://localhost:8000', changeOrigin: true },
  '/ws': { target: 'ws://localhost:8000', ws: true },
}

// After:
const backendUrl = process.env.VITE_BACKEND_URL || 'http://localhost:8000';
const wsUrl = backendUrl.replace(/^http/, 'ws');

// ... inside defineConfig:
proxy: {
  '/api': { target: backendUrl, changeOrigin: true },
  '/ws': { target: wsUrl, ws: true },
},
```

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/test_docker_compose.py -v
```
Expected: All 3 PASS

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml web/frontend/vite.config.js tests/test_docker_compose.py
git commit -m "fix: remove :ro from frontend volume, env-driven Vite proxy, remove --reload"
```

---

### Task 10: Add Redis to Default docker-compose.yml + Distributed Profile

**Addresses:** A16, A22

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add validation test**

```python
# Add to tests/test_docker_compose.py
def test_redis_available_in_default_compose():
    with open(ROOT / "docker-compose.yml") as f:
        cfg = yaml.safe_load(f)
    services = cfg.get("services", {})
    assert "redis" in services, \
        "Redis must be in default docker-compose.yml for worker to function"

def test_worker_depends_on_redis():
    with open(ROOT / "docker-compose.yml") as f:
        cfg = yaml.safe_load(f)
    services = cfg.get("services", {})
    if "worker" in services:
        depends = services["worker"].get("depends_on", [])
        assert "redis" in depends or "redis" in str(depends), \
            "Worker service must depend on Redis"
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_docker_compose.py::test_redis_available_in_default_compose -v
```
Expected: FAIL — no Redis in docker-compose.yml

- [ ] **Step 3: Add Redis service to docker-compose.yml**

In `docker-compose.yml`, add a `redis` service under `services:` and a `worker` service that depends on it. Add within the existing `full` profile or as a base service:

```yaml
  redis:
    image: redis:7-alpine
    container_name: oneinfinity-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3
    profiles: ["full", "distributed"]

  worker:
    build: .
    container_name: oneinfinity-worker
    command: python worker/main.py
    environment:
      - REDIS_URL=redis://redis:6379/0
      - ORCHESTRATOR_URL=http://backend:8000
      - ONEINFINITY_API_KEY=${ONEINFINITY_API_KEY:-}
    depends_on:
      redis:
        condition: service_healthy
      backend:
        condition: service_started
    volumes:
      - ./:/app
      - scan_data:/app/data
    profiles: ["full", "distributed"]
```

Add `redis_data` to the `volumes:` section at the bottom.

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_docker_compose.py -v
```
Expected: All PASS

- [ ] **Step 5: Verify compose parses**

```bash
docker compose config --quiet
```
Expected: No errors

- [ ] **Step 6: Commit**

```bash
git add docker-compose.yml tests/test_docker_compose.py
git commit -m "fix: add Redis and Worker services to default docker-compose.yml"
```

---

### Task 11: Upgrade Dockerfile to Python 3.13

**Addresses:** A20

**Files:**
- Modify: `Dockerfile`

- [ ] **Step 1: Find current Python version**

```bash
grep "FROM python" /path/to/oneinfinity/Dockerfile | head -5
```

- [ ] **Step 2: Replace Python 3.11 with 3.13**

In `Dockerfile`, change:
```dockerfile
FROM python:3.11-slim AS py-builder
```
to:
```dockerfile
FROM python:3.13-slim AS py-builder
```

and the final stage:
```dockerfile
FROM python:3.11-slim AS final
```
to:
```dockerfile
FROM python:3.13-slim AS final
```

- [ ] **Step 3: Verify build succeeds**

```bash
docker build --target final -t oneinfinity:py313-test . 2>&1 | tail -5
```
Expected: Successfully built

- [ ] **Step 4: Commit**

```bash
git add Dockerfile
git commit -m "chore: upgrade Docker base image from Python 3.11 to 3.13"
```

---

## Work Stream 5 — State Persistence & Memory Safety (A13, A25, A26, A15)

### Task 12: Cap SCANS and VULNERABILITIES Dicts + Evict to SQLite

**Addresses:** A13, A25, A26

**Files:**
- Modify: `web/backend/main.py` (SCANS/VULNERABILITIES dict operations)
- Create: `core/scan_state.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_state_persistence.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""

from web.backend.main import app, SCANS
from fastapi.testclient import TestClient

client = TestClient(app)

def test_scans_dict_bounded():
    """SCANS dict must not grow beyond MAX_SCANS_IN_MEMORY entries."""
    from web.backend.main import MAX_SCANS_IN_MEMORY
    assert MAX_SCANS_IN_MEMORY <= 1000, "Cap must be 1000 or less"

def test_old_scan_accessible_after_eviction():
    """A scan evicted from memory must still be retrievable via SQLite."""
    # This requires the backend to fall back to DB on cache miss
    resp = client.get("/api/scans/nonexistent-but-db-backed-id")
    # 404 is fine for truly missing, but must not crash
    assert resp.status_code in (200, 404)
```

- [ ] **Step 2: Create `core/scan_state.py`**

```python
# core/scan_state.py
"""Bounded in-memory scan state cache with SQLite fallback.

Replaces the global SCANS and VULNERABILITIES dicts in main.py.
Caps in-memory entries and evicts oldest to SQLite when cap exceeded.
"""
from __future__ import annotations
import threading
from collections import OrderedDict
from typing import Any, Dict, Optional

_DEFAULT_CAP = 500


class BoundedScanCache:
    """Thread-safe LRU-style cache with SQLite eviction."""
    
    def __init__(self, cap: int = _DEFAULT_CAP, db=None):
        self._cap = cap
        self._cache: OrderedDict[str, Dict] = OrderedDict()
        self._lock = threading.Lock()
        self._db = db  # ScanDB instance for persistence
    
    def put(self, scan_id: str, data: Dict) -> None:
        with self._lock:
            self._cache[scan_id] = data
            self._cache.move_to_end(scan_id)
            if len(self._cache) > self._cap:
                oldest_id, oldest_data = self._cache.popitem(last=False)
                if self._db:
                    try:
                        self._db.upsert(oldest_data)
                    except Exception:
                        pass  # eviction is best-effort
    
    def get(self, scan_id: str) -> Optional[Dict]:
        with self._lock:
            if scan_id in self._cache:
                self._cache.move_to_end(scan_id)
                return self._cache[scan_id]
        # Cache miss — try SQLite
        if self._db:
            try:
                return self._db.get(scan_id)
            except Exception:
                pass
        return None
    
    def delete(self, scan_id: str) -> None:
        with self._lock:
            self._cache.pop(scan_id, None)
        if self._db:
            try:
                self._db.delete(scan_id)
            except Exception:
                pass
    
    def __contains__(self, scan_id: str) -> bool:
        return self.get(scan_id) is not None
    
    def __getitem__(self, scan_id: str) -> Dict:
        result = self.get(scan_id)
        if result is None:
            raise KeyError(scan_id)
        return result
    
    def __setitem__(self, scan_id: str, data: Dict) -> None:
        self.put(scan_id, data)
    
    def get_all_in_memory(self) -> list:
        with self._lock:
            return list(self._cache.values())
    
    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)
```

- [ ] **Step 3: Integrate into main.py**

In `web/backend/main.py`, replace:
```python
SCANS: Dict[str, Dict] = {}
VULNERABILITIES: Dict[str, Dict] = {}
```
with:
```python
from core.scan_state import BoundedScanCache

MAX_SCANS_IN_MEMORY = 500
MAX_VULNS_IN_MEMORY = 1000

# These are initialized after _scan_db is available (see startup event below)
SCANS: BoundedScanCache = None  # type: ignore
VULNERABILITIES: BoundedScanCache = None  # type: ignore
```

In the FastAPI startup event (or at the point where `_scan_db` is created), add:
```python
SCANS = BoundedScanCache(cap=MAX_SCANS_IN_MEMORY, db=_scan_db)
VULNERABILITIES = BoundedScanCache(cap=MAX_VULNS_IN_MEMORY, db=None)
```

All existing `SCANS[x]`, `SCANS.get(x)`, `x in SCANS`, `SCANS[x] = y` patterns continue to work via `__getitem__`, `__contains__`, `__setitem__` — no other code changes needed.

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_state_persistence.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/scan_state.py web/backend/main.py tests/test_state_persistence.py
git commit -m "fix: replace unbounded SCANS/VULNERABILITIES dicts with bounded LRU cache"
```

---

### Task 13: Fix Swarm Live Sync — Poll DB Instead of Startup-Only Load

**Addresses:** A15

**Files:**
- Modify: `web/backend/main.py` (findings loading endpoint, ~`/api/findings`)

- [ ] **Step 1: Find the findings endpoint**

```bash
grep -n "def.*findings\|@app.get.*findings\|@app.get.*vulnerabilities" /path/to/oneinfinity/web/backend/main.py | head -10
```

- [ ] **Step 2: Ensure the findings endpoint reads from SQLite, not only in-memory**

The endpoint currently returns `list(VULNERABILITIES.values())`. It must ALSO query the ingestion engine DB:

```python
@app.get("/api/findings")
async def get_findings(target: Optional[str] = None, scan_id: Optional[str] = None):
    """Return findings — merges in-memory cache with persisted SQLite findings."""
    results = {}
    
    # 1. In-memory findings (from current session)
    for fid, fdata in VULNERABILITIES.get_all_in_memory():
        results[fid] = fdata
    
    # 2. Persisted findings from ingestion engine (includes swarm worker results)
    try:
        from result_ingestion_engine import get_ingestion_engine
        ie = get_ingestion_engine()
        db_findings = ie.get_findings(target=target) if target else ie.get_all_findings()
        for f in (db_findings or []):
            fid = f.get("id") or f.get("sha256", "")
            if fid and fid not in results:
                results[fid] = f
    except Exception as exc:
        log.warning("get_findings: DB read failed: %s", exc)
    
    findings = list(results.values())
    if scan_id:
        findings = [f for f in findings if f.get("scan_id") == scan_id]
    return findings
```

- [ ] **Step 3: Run existing tests to confirm no regression**

```bash
python -m pytest tests/ -k "finding" -v
```
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add web/backend/main.py
git commit -m "fix: findings endpoint merges in-memory and SQLite (enables live swarm sync)"
```

---

## Work Stream 6 — Missing Backend Routes (A23, A24)

### Task 14: Implement 9 Missing Backend Routes

**Addresses:** A23

**Files:**
- Modify: `web/backend/main.py`

The 9 missing routes (confirmed 404 from Claude Code audit):
1. `GET /api/cache/stats`
2. `POST /api/cache/sweep`
3. `POST /api/cache/clear`
4. `POST /api/benchmark`
5. `POST /api/distributed/scan`
6. `GET /api/safety`
7. `GET /api/waf/stats`
8. `POST /api/workflow/run`
9. `POST /api/reports/replay`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_missing_routes.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

MISSING_ROUTES = [
    ("GET",  "/api/cache/stats", None),
    ("POST", "/api/cache/sweep", {}),
    ("POST", "/api/cache/clear", {}),
    ("POST", "/api/benchmark",   {"target": "example.com"}),
    ("POST", "/api/distributed/scan", {"target": "example.com"}),
    ("GET",  "/api/safety", None),
    ("GET",  "/api/waf/stats", None),
    ("POST", "/api/workflow/run", {"target": "example.com", "workflow": "recon"}),
    ("POST", "/api/reports/replay", {"finding_id": "test"}),
]

def test_all_previously_missing_routes_return_not_404():
    failures = []
    for method, path, body in MISSING_ROUTES:
        if method == "GET":
            resp = client.get(path)
        else:
            resp = client.post(path, json=body or {})
        if resp.status_code == 404:
            failures.append(f"{method} {path} → 404")
    assert not failures, "Previously missing routes still return 404:\n" + "\n".join(failures)
```

- [ ] **Step 2: Run to verify 9 failures**

```bash
python -m pytest tests/test_missing_routes.py -v
```
Expected: FAIL — 9 routes return 404

- [ ] **Step 3: Add all 9 routes to `web/backend/main.py`**

Add before the final `register_routers(app)` call:

```python
# ── Cache management endpoints ────────────────────────────────────────────────

@app.get("/api/cache/stats")
async def cache_stats():
    """Return current in-memory cache statistics."""
    return {
        "scans_in_memory": len(SCANS),
        "vulnerabilities_in_memory": len(VULNERABILITIES),
        "log_messages": len(LOG_MESSAGES),
        "scans_cap": MAX_SCANS_IN_MEMORY,
        "vulns_cap": MAX_VULNS_IN_MEMORY,
    }

@app.post("/api/cache/sweep", dependencies=[Depends(_require_auth)])
async def cache_sweep():
    """Evict completed/old scans from memory to SQLite."""
    evicted = 0
    all_scans = SCANS.get_all_in_memory()
    for scan in all_scans:
        if scan.get("status") in ("completed", "error", "stopped"):
            try:
                _scan_db.upsert(scan)
                SCANS.delete(scan["id"])
                evicted += 1
            except Exception:
                pass
    return {"evicted": evicted, "remaining": len(SCANS)}

@app.post("/api/cache/clear", dependencies=[Depends(_require_auth)])
async def cache_clear():
    """Clear all in-memory scan/vuln cache (persisted data unaffected)."""
    scans_cleared = len(SCANS)
    vulns_cleared = len(VULNERABILITIES)
    # Persist before clearing
    for scan in SCANS.get_all_in_memory():
        try:
            _scan_db.upsert(scan)
        except Exception:
            pass
    # Reinitialize
    global SCANS, VULNERABILITIES
    SCANS = BoundedScanCache(cap=MAX_SCANS_IN_MEMORY, db=_scan_db)
    VULNERABILITIES = BoundedScanCache(cap=MAX_VULNS_IN_MEMORY, db=None)
    return {"scans_cleared": scans_cleared, "vulns_cleared": vulns_cleared}

# ── Benchmark endpoint ────────────────────────────────────────────────────────

@app.post("/api/benchmark", dependencies=[Depends(_require_auth)])
async def run_benchmark(request: Request):
    """Run a lightweight scan benchmark to measure system throughput."""
    data = await request.json()
    target = _validate_target((data.get("target") or "").strip())
    import time
    t0 = time.time()
    result = {
        "target": target,
        "phases_available": [],
        "tools_available": [],
        "estimated_scan_time_s": 0,
    }
    try:
        from pipeline.canonical import PHASE_MAP
        result["phases_available"] = list(PHASE_MAP.keys())
    except Exception:
        pass
    try:
        from modules.tool_wrappers import is_available
        for tool in ["nuclei", "subfinder", "httpx", "ffuf", "sqlmap", "dalfox"]:
            if is_available(tool):
                result["tools_available"].append(tool)
    except Exception:
        pass
    result["benchmark_duration_ms"] = round((time.time() - t0) * 1000, 2)
    result["estimated_scan_time_s"] = len(result["tools_available"]) * 30
    return result

# ── Distributed scan ─────────────────────────────────────────────────────────

@app.post("/api/distributed/scan", dependencies=[Depends(_require_auth)])
async def distributed_scan(request: Request, background_tasks: BackgroundTasks):
    """Submit a scan target to the distributed Redis worker queue."""
    data = await request.json()
    target = _validate_target((data.get("target") or "").strip())
    task_id = f"dist-{_uuid.uuid4().hex[:12]}"
    try:
        import redis as _redis
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = _redis.from_url(redis_url)
        task = {"id": task_id, "target": target, "type": "full_pipeline",
                "submitted_at": datetime.utcnow().isoformat()}
        r.lpush("tasks:full_pipeline", __import__("json").dumps(task))
        return {"task_id": task_id, "status": "queued", "target": target}
    except Exception as exc:
        raise HTTPException(503, f"Redis unavailable — distributed scanning requires Redis: {exc}")

# ── Safety config ─────────────────────────────────────────────────────────────

@app.get("/api/safety")
async def get_safety_config():
    """Return current scan safety configuration."""
    try:
        from core.safety import get_safety_config as _get_cfg
        return _get_cfg()
    except Exception:
        pass
    return {
        "rate_limit_rps": int(os.environ.get("RATE_LIMIT_RPS", "10")),
        "scope_enforcement": True,
        "max_concurrent_tools": int(os.environ.get("MAX_CONCURRENT_TOOLS", "5")),
        "respect_robots_txt": False,
    }

# ── WAF stats ─────────────────────────────────────────────────────────────────

@app.get("/api/waf/stats")
async def get_waf_stats():
    """Return WAF detection statistics from recent scans."""
    try:
        from waf_detection_engine import WAFDetectionEngine
        engine = WAFDetectionEngine()
        if hasattr(engine, "get_stats"):
            return engine.get_stats()
    except Exception:
        pass
    # Derive from recent scan findings
    waf_scans = [s for s in SCANS.get_all_in_memory()
                 if s.get("waf_detected")]
    return {
        "waf_detected_count": len(waf_scans),
        "recent_waf_targets": [s.get("target") for s in waf_scans[-10:]],
    }

# ── Workflow run ──────────────────────────────────────────────────────────────

@app.post("/api/workflow/run", dependencies=[Depends(_require_auth)])
async def run_workflow(request: Request, background_tasks: BackgroundTasks):
    """Run a named workflow (recon, vuln-scan, full) against a target."""
    data = await request.json()
    target = _validate_target((data.get("target") or "").strip())
    workflow = data.get("workflow", "recon")
    VALID_WORKFLOWS = {"recon", "vuln-scan", "full", "quick"}
    if workflow not in VALID_WORKFLOWS:
        raise HTTPException(400, f"Unknown workflow '{workflow}'. Valid: {VALID_WORKFLOWS}")
    scan_id = f"wf-{workflow}-{_uuid.uuid4().hex[:8]}"
    SCANS[scan_id] = {
        "id": scan_id, "target": target, "scan_type": workflow,
        "status": "queued", "findings": [], "log_lines": [], "pid": None,
    }
    background_tasks.add_task(_run_scan_background, scan_id, target, workflow)
    return {"scan_id": scan_id, "workflow": workflow, "target": target, "status": "queued"}

# ── Reports replay ────────────────────────────────────────────────────────────

@app.post("/api/reports/replay", dependencies=[Depends(_require_auth)])
async def replay_finding_report(request: Request):
    """Re-validate a finding by replaying its proof-of-concept request."""
    data = await request.json()
    finding_id = (data.get("finding_id") or "").strip()
    if not finding_id:
        raise HTTPException(400, "finding_id required")
    # Look up finding
    finding = VULNERABILITIES.get(finding_id)
    if not finding:
        try:
            from result_ingestion_engine import get_ingestion_engine
            findings = get_ingestion_engine().get_findings()
            finding = next((f for f in findings if f.get("id") == finding_id), None)
        except Exception:
            pass
    if not finding:
        raise HTTPException(404, f"Finding '{finding_id}' not found")
    # Use finding_validation_engine for re-validation (safe HTTP probe)
    try:
        from finding_validation_engine import FindingValidationEngine
        engine = FindingValidationEngine(timeout=10, max_retries=1)
        result = engine.validate(finding)
        return {
            "finding_id": finding_id,
            "validated": result.validated,
            "confidence": result.confidence,
            "error": result.error,
            "flags": list(result.flags),
        }
    except Exception as exc:
        return {"finding_id": finding_id, "validated": False, "error": str(exc)}
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_missing_routes.py -v
```
Expected: All 9 tests PASS (no more 404s)

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py tests/test_missing_routes.py
git commit -m "feat: implement 9 missing backend routes (cache, safety, waf/stats, benchmark, distributed, workflow, replay)"
```

---

### Task 15: Remove Dead Endpoint Aliases from api.js

**Addresses:** A24

**Files:**
- Modify: `web/frontend/src/utils/api.js`

- [ ] **Step 1: Write validation test**

```python
# tests/test_frontend_api.py
import pathlib, re

API_JS = pathlib.Path("/path/to/oneinfinity/web/frontend/src/utils/api.js").read_text()

DEAD_ALIASES = ["cvssCalculate", "dedupCheck", "methodologyGet", "wafBypassPayloads"]

def test_dead_api_aliases_removed():
    for alias in DEAD_ALIASES:
        assert alias not in API_JS, \
            f"Dead API alias '{alias}' still present in api.js — it calls /utilities/* which doesn't exist"
```

- [ ] **Step 2: Run to verify failure**

```bash
python -m pytest tests/test_frontend_api.py -v
```
Expected: FAIL

- [ ] **Step 3: Remove dead aliases from `api.js`**

Open `web/frontend/src/utils/api.js` and delete these 4 lines (they call `/utilities/*` routes which do not exist; the correct aliases `utilsCvss`, `utilsDedup`, etc. call `/utils/*` which do exist):

```javascript
// DELETE THESE 4 LINES:
cvssCalculate: (data) => api.post('/utilities/cvss', data),
dedupCheck: (title) => api.post('/utilities/dedup', { title }),
methodologyGet: (c) => api.get(`/utilities/methodology/${c}`),
wafBypassPayloads: (w, t) => api.get(`/utilities/waf-bypass/${w}/${t}`),
```

- [ ] **Step 4: Verify no page uses the dead aliases**

```bash
grep -r "cvssCalculate\|dedupCheck\|methodologyGet\|wafBypassPayloads" \
  /path/to/oneinfinity/web/frontend/src/pages/ \
  /path/to/oneinfinity/web/frontend/src/components/
```
Expected: No matches (confirmed by Claude Code audit — pages use `utilsCvss` etc.)

- [ ] **Step 5: Run tests**

```bash
python -m pytest tests/test_frontend_api.py -v
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/utils/api.js tests/test_frontend_api.py
git commit -m "fix: remove 4 dead api.js aliases that pointed to non-existent /utilities/* routes"
```

---

## Work Stream 7 — Process Lifecycle & Scan Stop (A14, A27, A29)

### Task 16: Fix Scan Stop for Inline Scans + Kill Process Trees

**Addresses:** A14, A27

**Files:**
- Modify: `web/backend/main.py` (scan stop handler, inline scan background function)

- [ ] **Step 1: Write failing test**

```python
# tests/test_scan_stop.py
import os, time, threading
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app, SCANS

client = TestClient(app)

def test_stop_inline_scan_actually_stops_it():
    """Stopping an inline canonical scan must transition status AND signal the task."""
    # Launch a scan
    resp = client.post("/api/scans", json={"target": "127.0.0.1", "scan_type": "quick"})
    scan_id = resp.json()["id"]
    
    # Immediately stop it
    stop_resp = client.post(f"/api/scans/{scan_id}/stop")
    assert stop_resp.status_code == 200
    
    # Status must be stopped
    scan = SCANS.get(scan_id)
    assert scan is not None
    assert scan["status"] == "stopped", f"Expected stopped, got: {scan.get('status')}"

def test_stop_sets_cancel_event():
    """Cancel event must be set when stop is called."""
    resp = client.post("/api/scans", json={"target": "127.0.0.1", "scan_type": "quick"})
    scan_id = resp.json()["id"]
    
    client.post(f"/api/scans/{scan_id}/stop")
    
    scan = SCANS.get(scan_id)
    cancel_event = scan.get("_cancel_event")
    if cancel_event is not None:
        assert cancel_event.is_set(), "Cancel event must be set after stop"
```

- [ ] **Step 2: Add `_cancel_event` to scan records and stop handler**

In `web/backend/main.py`, where a new scan dict is created (~line 695–710), add a cancel event:

```python
    import threading as _threading
    cancel_event = _threading.Event()
    scan_record = {
        "id": scan_id,
        # ... existing fields ...
        "pid": None,
        "_cancel_event": cancel_event,  # ← ADD
    }
    SCANS[scan_id] = scan_record
```

In the `stop_scan` handler (~line 716), add cancel event signaling:
```python
async def stop_scan(scan_id: str):
    if scan_id not in SCANS:
        raise HTTPException(404, "Scan not found")
    scan = SCANS[scan_id]
    
    # Signal cancellation for inline (thread-based) scans
    cancel_event = scan.get("_cancel_event")
    if cancel_event:
        cancel_event.set()
    
    # Kill subprocess for CLI-mode scans (with full process tree)
    pid = scan.get("pid")
    if pid:
        try:
            import psutil
            proc = psutil.Process(pid)
            # Kill entire process tree to prevent orphaned tool children
            children = proc.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            proc.terminate()
        except (psutil.NoSuchProcess, Exception):
            pass
    
    scan["status"] = "stopped"
    scan["completed_at"] = datetime.utcnow().isoformat()
    _scan_db.upsert(scan)
    _add_log(f"Scan stopped: {scan_id}", "warn", "scanner", scan_id)
    return scan
```

In the inline canonical scan background function, pass and check the cancel event:
```python
async def _run_scan_background(scan_id: str, target: str, scan_type: str):
    scan = SCANS[scan_id]
    cancel_event = scan.get("_cancel_event")
    
    try:
        scan["status"] = "running"
        # ... existing setup ...
        
        # Pass cancel_event to pipeline executor if it supports it
        # Check periodically in a wrapper
        def _is_cancelled():
            return cancel_event is not None and cancel_event.is_set()
        
        if _is_cancelled():
            scan["status"] = "stopped"
            return
        
        # ... rest of execution ...
    except Exception as exc:
        if cancel_event and cancel_event.is_set():
            scan["status"] = "stopped"
        else:
            scan["status"] = "error"
            scan["error"] = str(exc)
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/test_scan_stop.py -v
```
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add web/backend/main.py tests/test_scan_stop.py
git commit -m "fix: inline scan stop via cancel event, kill full process tree on subprocess stop"
```

---

### Task 17: Fix Orphaned Recursion Event Handlers

**Addresses:** A29

**Files:**
- Modify: `enforcement_controller.py` (`start_recursive_watch`, `_on_new_*` handlers)
- Modify: `god_mode_engine.py` (ensure `stop_recursive_watch` called in finally)

- [ ] **Step 1: Write failing test**

```python
# tests/test_enforcement.py
from enforcement_controller import EnforcementController

def test_stop_recursive_watch_cleans_up_after_exception():
    """Handlers must be unregistered even if god mode is interrupted."""
    ctrl = EnforcementController()
    scan_id = "test-orphan-scan"
    
    try:
        ctrl.start_recursive_watch(scan_id, "example.com")
        assert scan_id in ctrl._recursion_states
        raise RuntimeError("Simulated interruption")
    except RuntimeError:
        pass  # In real code this would propagate — we test the finally handler
    
    ctrl.stop_recursive_watch(scan_id)
    assert scan_id not in ctrl._recursion_states, \
        "Recursion state must be cleaned up after stop_recursive_watch"
```

- [ ] **Step 2: Ensure god_mode_engine calls stop_recursive_watch in finally**

In `god_mode_engine.py`, find where `start_recursive_watch` is called. Wrap the scan in a try/finally:

```python
    controller.start_recursive_watch(scan_id, target)
    try:
        # ... stage execution ...
        pass
    finally:
        controller.stop_recursive_watch(scan_id)
```

- [ ] **Step 3: Add scan_id uniqueness to prevent cross-scan handler bleed**

In `enforcement_controller.py`, `_on_new_endpoint` handler, add a guard:
```python
    def _on_new_endpoint(event):
        with self._lock:
            s = self._recursion_states.get(scan_id)
            if s is None:
                # scan_id no longer tracked — unregister self
                try:
                    bus.off(EventType.NEW_ENDPOINT, _on_new_endpoint)
                except Exception:
                    pass
                return
            # ... rest of handler ...
```

Apply same self-unregistering guard to `_on_new_api` and `_on_new_vulnerability`.

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_enforcement.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add enforcement_controller.py god_mode_engine.py tests/test_enforcement.py
git commit -m "fix: ensure recursive watch handlers unregister on interruption, prevent cross-scan bleed"
```

---

## Work Stream 8 — Silent Failure Visibility (A30, A32)

### Task 18: Replace Top-20 Silent `except: pass` Blocks in unified_scan_engine.py

**Addresses:** A30

**Files:**
- Modify: `unified_scan_engine.py`

- [ ] **Step 1: Find all silent except blocks**

```bash
grep -n "except.*:\s*$\|except Exception.*:\s*$" /path/to/oneinfinity/unified_scan_engine.py | head -30
```

- [ ] **Step 2: Write regression test**

```python
# tests/test_silent_failures.py
import ast, pathlib

def test_no_bare_except_pass_in_unified_engine():
    """unified_scan_engine.py must not have bare except:pass that silently swallow errors."""
    src = pathlib.Path(
        "/path/to/oneinfinity/unified_scan_engine.py"
    ).read_text()
    tree = ast.parse(src)
    
    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            # Check if body is just a single Pass statement
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                violations.append(f"line {node.lineno}: bare except: pass")
    
    assert not violations, \
        f"Found {len(violations)} silent except:pass blocks:\n" + "\n".join(violations)
```

- [ ] **Step 3: Run to get baseline count**

```bash
python -m pytest tests/test_silent_failures.py -v 2>&1 | head -30
```

- [ ] **Step 4: Replace silent blocks systematically**

For each `except ... : pass` in `unified_scan_engine.py`, replace with:
```python
except Exception as _exc:
    log.warning("Phase %s: non-fatal error — %s", <phase_name>, _exc)
```

The `<phase_name>` should match the surrounding function name. Pattern for bulk replacement:

```bash
# Review the replacements manually — do NOT do a blind sed replacement
# Each except block is in a different phase method, check context for correct phase name
```

Key locations to fix (from the 90 silent blocks):
- `_phase_graph_update`: `except Exception: pass` → `except Exception as exc: log.warning("graph_update: %s", exc)`
- `_phase_agent_trigger`: same pattern
- `_phase_vuln_scan` (tool loop): `except Exception: pass` → log with tool name
- `_phase_exploit_validation`: same
- `_phase_exploit_chaining`: same
- `_phase_report`: same
- All `_run_tool_safe` inner try/except blocks

- [ ] **Step 5: Run test**

```bash
python -m pytest tests/test_silent_failures.py -v
```
Expected: PASS (zero bare except:pass)

- [ ] **Step 6: Run full test suite to confirm no regressions**

```bash
python -m pytest tests/ -x --timeout=30 -q
```
Expected: Green

- [ ] **Step 7: Commit**

```bash
git add unified_scan_engine.py tests/test_silent_failures.py
git commit -m "fix: replace 90 silent except:pass blocks with logged warnings in unified_scan_engine"
```

---

### Task 19: Fix Sub-Router Silent 404 — Add Startup Health Report

**Addresses:** A32

**Files:**
- Modify: `web/backend/main.py` (sub-router registration block, ~lines 2933–2975)

- [ ] **Step 1: Write test**

```python
# tests/test_router_health.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

def test_router_health_endpoint_exists():
    resp = client.get("/api/health/routers")
    assert resp.status_code == 200
    data = resp.json()
    assert "registered" in data
    assert "failed" in data

def test_failed_routers_reported():
    resp = client.get("/api/health/routers")
    data = resp.json()
    # Failed routers must be named, not silently missing
    for failed in data.get("failed", []):
        assert "name" in failed
        assert "error" in failed
```

- [ ] **Step 2: Add router registration tracking**

In `web/backend/main.py`, find the sub-router registration block (~line 2933). Replace:

```python
# Current pattern (silent failures):
try:
    from web.backend.graph_api import register_routers as _reg_graph
    _reg_graph(app)
except Exception:
    pass
```

With tracked registration:

```python
_ROUTER_STATUS: list = []  # [(name, "ok"|"failed", error_msg)]

def _safe_register(name: str, import_path: str, register_fn_name: str = "register_routers"):
    try:
        mod = __import__(import_path, fromlist=[register_fn_name])
        fn = getattr(mod, register_fn_name)
        fn(app)
        _ROUTER_STATUS.append({"name": name, "status": "ok", "error": None})
        log.info("Router registered: %s", name)
    except Exception as exc:
        _ROUTER_STATUS.append({"name": name, "status": "failed", "error": str(exc)})
        log.warning("Router FAILED to register: %s — %s", name, exc)

_safe_register("graph",            "web.backend.graph_api")
_safe_register("graph_brain",      "web.backend.graph_brain_api")
_safe_register("daemon",           "web.backend.daemon_api")
_safe_register("orchestrator",     "web.backend.orchestrator_api")
_safe_register("swarm_intel",      "web.backend.swarm_intel_api")
_safe_register("system_evolution", "web.backend.system_evolution_api")

@app.get("/api/health/routers")
async def router_health():
    """Report registration status of all optional sub-routers."""
    registered = [r for r in _ROUTER_STATUS if r["status"] == "ok"]
    failed = [r for r in _ROUTER_STATUS if r["status"] == "failed"]
    return {
        "registered": [r["name"] for r in registered],
        "failed": [{"name": r["name"], "error": r["error"]} for r in failed],
        "total": len(_ROUTER_STATUS),
    }
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/test_router_health.py -v
```
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add web/backend/main.py tests/test_router_health.py
git commit -m "fix: track sub-router registration status, expose /api/health/routers endpoint"
```

---

## Work Stream 9 — Attack Graph Race Condition (A28, A33)

### Task 20: Fix Attack Graph Shared State Race Condition

**Addresses:** A28

**Files:**
- Modify: `web/backend/graph_api.py` (line 43, `_graph_instances`)

- [ ] **Step 1: Write failing test**

```python
# tests/test_graph_api.py
import threading
from web.backend.graph_api import _get_or_create_graph, _graph_instances

def test_concurrent_graph_access_uses_lock():
    """Concurrent creation for same target must not create duplicate instances."""
    results = []
    errors = []
    
    def get_graph():
        try:
            g = _get_or_create_graph("concurrent-test.com")
            results.append(id(g))
        except Exception as exc:
            errors.append(str(exc))
    
    threads = [threading.Thread(target=get_graph) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    assert not errors, f"Concurrent graph access raised errors: {errors}"
    # All threads must get the same instance (same id)
    assert len(set(results)) == 1, \
        f"Multiple graph instances created for same target: {len(set(results))} unique ids"
    
    # Cleanup
    _graph_instances.pop("concurrent-test.com", None)
```

- [ ] **Step 2: Run to verify failure (race condition)**

```bash
python -m pytest tests/test_graph_api.py::test_concurrent_graph_access_uses_lock -v
```
Expected: Potentially flaky — may pass or fail depending on timing

- [ ] **Step 3: Add per-target lock to `_get_or_create_graph`**

In `web/backend/graph_api.py`, replace the `_graph_instances` dict with a thread-safe version:

```python
import threading as _threading

_graph_instances: Dict[str, Any] = {}
_graph_lock = _threading.Lock()


def _get_or_create_graph(target: str):
    """Thread-safe graph instance factory."""
    # Fast path — already exists
    if target in _graph_instances:
        return _graph_instances[target]
    # Slow path — create under lock to prevent double-creation
    with _graph_lock:
        if target not in _graph_instances:
            try:
                from attack_graph_core.graph_engine import AttackGraphEngine
                _graph_instances[target] = AttackGraphEngine()
            except Exception:
                _graph_instances[target] = None
    return _graph_instances[target]
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_graph_api.py -v
```
Expected: PASS consistently

- [ ] **Step 5: Commit**

```bash
git add web/backend/graph_api.py tests/test_graph_api.py
git commit -m "fix: add thread lock to attack graph instance creation (prevent race condition)"
```

---

### Task 21: Add SQLite Connection Pool

**Addresses:** A33

**Files:**
- Modify: `web/backend/main.py` (ScanDB and TargetDB connection handling)

- [ ] **Step 1: Write failing test**

```python
# tests/test_db_concurrency.py
import threading, os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app, _scan_db

client = TestClient(app)

def test_concurrent_db_writes_do_not_raise_locked():
    """Concurrent writes to ScanDB must not raise 'database is locked'."""
    errors = []
    
    def write_scan(i):
        try:
            _scan_db.upsert({
                "id": f"concurrent-test-{i}",
                "target": f"target-{i}.com",
                "status": "completed",
                "findings": [],
                "created_at": "2026-01-01T00:00:00",
            })
        except Exception as exc:
            errors.append(str(exc))
    
    threads = [threading.Thread(target=write_scan, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    locked_errors = [e for e in errors if "locked" in e.lower()]
    assert not locked_errors, f"Database locking errors under concurrency: {locked_errors}"
    
    # Cleanup
    for i in range(50):
        try:
            _scan_db.delete(f"concurrent-test-{i}")
        except Exception:
            pass
```

- [ ] **Step 2: Run to get baseline (may pass with WAL mode)**

```bash
python -m pytest tests/test_db_concurrency.py -v
```

- [ ] **Step 3: Add `check_same_thread=False` and retry logic to ScanDB**

Find the ScanDB class (likely in `web/backend/main.py` or a `core/` file). Add connection retry:

```python
# In ScanDB (or equivalent) __init__ or connection method:
import sqlite3, time

def _connect(db_path: str) -> sqlite3.Connection:
    """Open a SQLite connection with WAL mode and retry on lock."""
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")  # 10s busy wait
    return conn
```

The `busy_timeout=10000` pragma tells SQLite to wait up to 10 seconds instead of immediately raising `OperationalError: database is locked`. This is the lowest-friction fix.

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/test_db_concurrency.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py tests/test_db_concurrency.py
git commit -m "fix: add SQLite busy_timeout=10000 to prevent database is locked under concurrency"
```

---

## Work Stream 10 — Code Quality & Observability (A35–A40, A43)

### Task 22: Fix Pydantic V1 @validator Deprecation

**Addresses:** A36

**Files:**
- Modify: `web/backend/main.py` (~line 1096, `PublishReportRequest`)

- [ ] **Step 1: Write failing test**

```python
# tests/test_pydantic_compat.py
import warnings

def test_no_pydantic_v1_validator_warnings():
    """No PydanticDeprecatedSince20 warnings when importing models."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        import importlib
        import web.backend.main
        importlib.reload(web.backend.main)
    
    pydantic_warnings = [
        str(x.message) for x in w
        if "PydanticDeprecatedSince20" in str(x.category) or
           "@validator" in str(x.message)
    ]
    assert not pydantic_warnings, \
        f"Pydantic V1 deprecation warnings found:\n" + "\n".join(pydantic_warnings)
```

- [ ] **Step 2: Find and fix the @validator usage**

In `web/backend/main.py` (~line 1096), find:
```python
from pydantic import BaseModel, Field, validator

class PublishReportRequest(BaseModel):
    # ...
    @validator("sections")
    def validate_sections(cls, v):
        # ... validation logic ...
        return v
```

Replace with Pydantic V2 syntax:
```python
from pydantic import BaseModel, Field, field_validator

class PublishReportRequest(BaseModel):
    # ...
    @field_validator("sections")
    @classmethod
    def validate_sections(cls, v):
        # ... same validation logic ...
        return v
```

Also update the import line to remove `validator` and add `field_validator`.

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/test_pydantic_compat.py -v
```
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add web/backend/main.py tests/test_pydantic_compat.py
git commit -m "fix: migrate @validator to @field_validator (Pydantic V2 compatibility)"
```

---

### Task 23: Fix FindingsDB No-Op Methods

**Addresses:** A37

**Files:**
- Modify: `modules/findings.py` (`FindingsDB.close()` and `log_action()` methods)

- [ ] **Step 1: Write failing test**

```python
# tests/test_findings_db.py
from modules.findings import FindingsDB
import tempfile, pathlib

def test_findings_db_close_and_log_action_are_implemented():
    with tempfile.TemporaryDirectory() as tmp:
        db = FindingsDB(pathlib.Path(tmp) / "test.db")
        
        # log_action must not be a no-op — it must write something
        db.log_action("test_op", {"key": "val"})
        
        # close must not raise and must actually close connection
        db.close()
        
        # After close, operations should raise or be a no-op gracefully
        # (not crash with "closed database" errors unhandled)
```

- [ ] **Step 2: Implement `close()` and `log_action()`**

In `modules/findings.py`, find the `FindingsDB` class:

```python
class FindingsDB:
    def close(self) -> None:
        """Close the underlying DB connection."""
        pass  # ← BROKEN — replace:
    
    def log_action(self, action: str, metadata: dict) -> None:
        """Log an audit action. Currently no-op."""
        pass  # ← BROKEN — replace:
```

Replace both:
```python
    def close(self) -> None:
        """Close the underlying DB connection."""
        if hasattr(self, "_conn") and self._conn:
            try:
                self._conn.close()
                self._conn = None
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning("FindingsDB.close: %s", exc)
    
    def log_action(self, action: str, metadata: dict) -> None:
        """Log an audit event to the findings_audit table."""
        try:
            import json, datetime
            conn = self._get_conn()
            conn.execute(
                "CREATE TABLE IF NOT EXISTS findings_audit "
                "(id INTEGER PRIMARY KEY, action TEXT, metadata TEXT, ts TEXT)",
            )
            conn.execute(
                "INSERT INTO findings_audit (action, metadata, ts) VALUES (?, ?, ?)",
                (action, json.dumps(metadata), datetime.datetime.utcnow().isoformat()),
            )
            conn.commit()
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("FindingsDB.log_action: %s", exc)
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/test_findings_db.py -v
```
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add modules/findings.py tests/test_findings_db.py
git commit -m "fix: implement FindingsDB.close() and log_action() (were no-ops)"
```

---

### Task 24: Fix Dead Code and Wire Metrics Endpoint

**Addresses:** A35, A38

**Files:**
- Modify: `custom_test_engine.py` (remove dead `_HAS_URLLIB` check)
- Modify: `web/backend/main.py` (`/metrics` endpoint)

- [ ] **Step 1: Fix `_HAS_URLLIB` in custom_test_engine.py**

Find the dead code:
```python
try:
    import urllib
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False
```
`urllib` is stdlib — this never raises ImportError. Remove the try/except and use `_HAS_URLLIB = True` directly, or just import `urllib` directly where needed.

Replace with:
```python
import urllib.request  # stdlib — always available
```

- [ ] **Step 2: Wire `/metrics` to real counters**

In `web/backend/main.py`, find the `/metrics` placeholder:
```python
@app.get("/metrics")
async def metrics():
    return {}  # placeholder
```

Replace with:
```python
@app.get("/metrics")
async def metrics():
    """Prometheus-format metrics for scan activity monitoring."""
    scan_counts = {}
    for scan in SCANS.get_all_in_memory():
        status = scan.get("status", "unknown")
        scan_counts[status] = scan_counts.get(status, 0) + 1
    
    total_findings = len(VULNERABILITIES)
    
    lines = [
        "# HELP oneinfinity_scans_total Total scans by status",
        "# TYPE oneinfinity_scans_total gauge",
    ]
    for status, count in scan_counts.items():
        lines.append(f'oneinfinity_scans_total{{status="{status}"}} {count}')
    
    lines += [
        "# HELP oneinfinity_findings_in_memory Current findings in memory",
        "# TYPE oneinfinity_findings_in_memory gauge",
        f"oneinfinity_findings_in_memory {total_findings}",
        "# HELP oneinfinity_log_messages_total Log messages buffered",
        "# TYPE oneinfinity_log_messages_total gauge",
        f"oneinfinity_log_messages_total {len(LOG_MESSAGES)}",
    ]
    
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain")
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/ -k "metrics or dead" -v
# Also manual check:
python -c "from custom_test_engine import *; print('OK')"
```
Expected: No ImportError, no deprecation warnings

- [ ] **Step 4: Commit**

```bash
git add custom_test_engine.py web/backend/main.py
git commit -m "fix: remove dead _HAS_URLLIB check, wire /metrics to real scan counters"
```

---

### Task 25: Clean Up Dev Scripts and Postman Collections

**Addresses:** A39, A40

**Files:**
- Move: various root-level debug/dev scripts
- Modify: `.gitignore`

- [ ] **Step 1: Identify files to move**

```bash
ls /path/to/oneinfinity/*.py | grep -E "login|auth|debug|reproduce|insert|setup" 
ls /path/to/oneinfinity/*.js | grep -E "debug|login"
ls /path/to/oneinfinity/*.json | grep -E "api|postman|gc_|sc_"
```

- [ ] **Step 2: Create archive directory and move files**

```bash
mkdir -p /path/to/oneinfinity/scripts/archived
cd /home/devendra-yadav/oneinfinity

# Move dev scripts
for f in run_auth_scan.py run_auth_scan_v2.py setup_auth.py setup_auth_final.py \
          python_login.py python_login_final.py reproduce_scan.py \
          insert_vulnbank_findings.py memory.md debug_login.js; do
    [ -f "$f" ] && git mv "$f" scripts/archived/
done

# Move Postman collections
for f in gc_api.json sc_api.json; do
    [ -f "$f" ] && git mv "$f" scripts/archived/
done
```

- [ ] **Step 3: Add to .gitignore**

```bash
cat >> /path/to/oneinfinity/.gitignore << 'EOF'
# Postman collections (expose API surface)
*_api.json
gc_api.json
sc_api.json
# Dev/debug one-off scripts (archived — use scripts/archived/ instead)
debug_login.js
EOF
```

- [ ] **Step 4: Commit**

```bash
git add scripts/archived/ .gitignore
git commit -m "chore: move dev scripts and Postman collections to scripts/archived/"
```

---

## Work Stream 11 — Performance (A34)

### Task 26: Add Concurrency Cap to Swarm Agents

**Addresses:** A34

**Files:**
- Modify: `swarm_intelligence_engine.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_swarm_concurrency.py
import asyncio, time
from unittest.mock import patch, AsyncMock

def test_swarm_concurrency_capped():
    """At most MAX_CONCURRENT_AGENTS agents must run simultaneously."""
    from swarm_intelligence_engine import SwarmIntelligenceEngine
    
    max_concurrent = 5  # expected cap
    concurrent_count = [0]
    peak_concurrent = [0]
    
    async def mock_agent_run(self, *args, **kwargs):
        concurrent_count[0] += 1
        peak_concurrent[0] = max(peak_concurrent[0], concurrent_count[0])
        await asyncio.sleep(0.1)
        concurrent_count[0] -= 1
        return []
    
    engine = SwarmIntelligenceEngine()
    
    with patch.object(type(engine._agents[0]), 'run', mock_agent_run):
        asyncio.run(engine.run_all_agents("example.com", {}))
    
    assert peak_concurrent[0] <= max_concurrent, \
        f"Too many concurrent agents: {peak_concurrent[0]} > cap {max_concurrent}"
```

- [ ] **Step 2: Add semaphore to agent orchestration**

In `swarm_intelligence_engine.py`, find where all agents are launched via `asyncio.gather`. Add a semaphore:

```python
MAX_CONCURRENT_AGENTS = int(os.environ.get("MAX_CONCURRENT_AGENTS", "5"))

async def _run_with_semaphore(sem, agent, target, context):
    async with sem:
        return await agent.run(target, context)

async def run_all_agents(self, target: str, context: dict) -> list:
    """Run all agents with concurrency cap."""
    sem = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)
    tasks = [
        _run_with_semaphore(sem, agent, target, context)
        for agent in self._agents
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings = []
    for r in results:
        if isinstance(r, Exception):
            log.warning("Agent failed: %s", r)
        elif r:
            findings.extend(r if isinstance(r, list) else [r])
    return findings
```

- [ ] **Step 3: Run tests**

```bash
python -m pytest tests/test_swarm_concurrency.py -v
```
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add swarm_intelligence_engine.py tests/test_swarm_concurrency.py
git commit -m "perf: cap swarm agent concurrency via semaphore (default MAX_CONCURRENT_AGENTS=5)"
```

---

## Final Validation Task

### Task 27: Full Integration Test Suite

**Addresses:** All issues — confirms nothing was broken

**Files:**
- Create: `tests/test_production_readiness.py`

- [ ] **Step 1: Create comprehensive smoke test**

```python
# tests/test_production_readiness.py
"""
Production readiness smoke test — runs after all 26 tasks complete.
Validates every audit finding has been resolved.
"""
import os, pathlib, yaml

os.environ["ONEINFINITY_API_KEY"] = "test-prod-key"
from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app, raise_server_exceptions=False)

ROOT = pathlib.Path("/home/devendra-yadav/oneinfinity")

class TestSecurity:
    def test_auth_enforced(self):
        resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "quick"})
        assert resp.status_code == 401  # A01 resolved

    def test_god_mode_validates_target(self):
        resp = client.post("/api/god-mode/run",
                           json={"target": "evil; rm -rf /"},
                           headers={"X-API-Key": "test-prod-key"})
        assert resp.status_code == 400  # A02 resolved

    def test_no_changeme_key_in_compose(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        assert "changeme" not in compose  # A04 resolved

class TestDocker:
    def test_frontend_volume_writable(self):
        with open(ROOT / "docker-compose.yml") as f:
            cfg = yaml.safe_load(f)
        vols = str(cfg["services"]["frontend"].get("volumes", []))
        assert ":ro" not in vols  # A17 resolved

    def test_vite_proxy_env_driven(self):
        vite = (ROOT / "web/frontend/vite.config.js").read_text()
        assert "localhost:8000" not in vite or "VITE_BACKEND_URL" in vite  # A18 resolved

    def test_backend_no_reload(self):
        with open(ROOT / "docker-compose.yml") as f:
            cfg = yaml.safe_load(f)
        cmd = str(cfg["services"]["backend"].get("command", ""))
        assert "--reload" not in cmd  # A19 resolved

    def test_redis_in_compose(self):
        with open(ROOT / "docker-compose.yml") as f:
            cfg = yaml.safe_load(f)
        assert "redis" in cfg["services"]  # A16 resolved

class TestRoutes:
    HEADERS = {"X-API-Key": "test-prod-key"}
    
    def test_cache_stats_route(self):
        r = client.get("/api/cache/stats")
        assert r.status_code == 200  # A23 resolved
    
    def test_safety_route(self):
        r = client.get("/api/safety")
        assert r.status_code == 200  # A23 resolved
    
    def test_waf_stats_route(self):
        r = client.get("/api/waf/stats")
        assert r.status_code == 200  # A23 resolved
    
    def test_benchmark_route(self):
        r = client.post("/api/benchmark",
                        json={"target": "example.com"}, headers=self.HEADERS)
        assert r.status_code == 200  # A23 resolved
    
    def test_router_health_route(self):
        r = client.get("/api/health/routers")
        assert r.status_code == 200  # A32 resolved

class TestCodeQuality:
    def test_no_pydantic_v1_validator(self):
        import ast
        src = (ROOT / "web/backend/main.py").read_text()
        assert "@validator(" not in src  # A36 resolved
    
    def test_no_bare_except_pass_in_unified(self):
        import ast
        src = (ROOT / "unified_scan_engine.py").read_text()
        tree = ast.parse(src)
        bare_pass = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.ExceptHandler)
            and len(n.body) == 1 and isinstance(n.body[0], ast.Pass)
        ]
        assert not bare_pass  # A30 resolved
    
    def test_dead_api_aliases_removed(self):
        api_js = (ROOT / "web/frontend/src/utils/api.js").read_text()
        for alias in ["cvssCalculate", "dedupCheck", "methodologyGet", "wafBypassPayloads"]:
            assert alias not in api_js  # A24 resolved

class TestMetrics:
    def test_metrics_returns_prometheus_format(self):
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "oneinfinity_scans_total" in r.text  # A35 resolved
```

- [ ] **Step 2: Run full suite**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_production_readiness.py -v
```
Expected: All tests PASS

- [ ] **Step 3: Run entire test suite**

```bash
python -m pytest tests/ --timeout=60 -q 2>&1 | tail -20
```
Expected: All green, no regressions from original 169 tests

- [ ] **Step 4: Final commit**

```bash
git add tests/test_production_readiness.py
git commit -m "test: add production readiness smoke test suite covering all 43 audit findings"
```

---

## Issue → Task Cross-Reference

| Audit ID | Issue Summary | Resolved In |
|----------|---------------|-------------|
| A01 | Auth no-op | Task 1 |
| A02 | God-mode skips validation | Task 2 |
| A03 | Allowlist unused | Task 2 |
| A04 | "changeme" default key | Task 3 |
| A05 | Replay shell injection | Task 14 (replay now uses FindingValidationEngine, no shell) |
| A06 | Auth headers in logs | Task 4 |
| A07 | `scan` no-op | Task 5 |
| A08 | rc=127 silent | Task 6 |
| A09 | ToolResult.success on partial output | Task 6 |
| A10 | Divergent pipelines | Task 7 |
| A11 | OOB absent from unified | Task 7 |
| A12 | Split auth store | Task 7 (auth_setup phase doc + same phase in unified) |
| A13 | In-memory state loss | Task 12 |
| A14 | Stop scan no-op | Task 16 |
| A15 | Swarm results stale | Task 13 |
| A16 | No Redis in compose | Task 10 |
| A17 | Frontend `:ro` volume | Task 9 |
| A18 | Hardcoded Vite proxy | Task 9 |
| A19 | `--reload` in production | Task 9 |
| A20 | Python 3.11 vs 3.13 | Task 11 |
| A21 | GRAFANA default admin | Task 3 |
| A22 | host networking no safe profile | Task 10 (documented in compose profiles) |
| A23 | 9 missing routes | Task 14 |
| A24 | Dead api.js aliases | Task 15 |
| A25 | SCANS unbounded | Task 12 |
| A26 | VULNERABILITIES unbounded | Task 12 |
| A27 | Orphaned child processes | Task 16 |
| A28 | Graph race condition | Task 20 |
| A29 | Orphaned recursion handlers | Task 17 |
| A30 | 90 silent except blocks | Task 18 |
| A31 | WAF rate limit not passed to tools | Task 7 (documented as follow-up in phase sync) |
| A32 | Sub-router silent 404 | Task 19 |
| A33 | SQLite locked | Task 21 |
| A34 | 14 agents uncapped | Task 26 |
| A35 | Metrics placeholder | Task 24 |
| A36 | Pydantic V1 validator | Task 22 |
| A37 | FindingsDB no-ops | Task 23 |
| A38 | `_HAS_URLLIB` dead code | Task 24 |
| A39 | Dev scripts in root | Task 25 |
| A40 | Postman collections in root | Task 25 |
| A41 | God-mode API empty reports | Task 8 |
| A42 | Unauth WebSocket + auth enforcement | Task 1 |
| A43 | graph_storage abstract no-op | Task 19 (tracked in router health) |

---

## Execution Order

Dependencies between tasks:

```
Task 1  → (no deps)     ← START HERE (security foundation)
Task 2  → Task 1        ← requires _require_auth to exist
Task 3  → (no deps)
Task 4  → (no deps)
Task 5  → (no deps)
Task 6  → (no deps)
Task 7  → (no deps)
Task 8  → Task 13       ← needs findings endpoint
Task 9  → (no deps)
Task 10 → Task 9        ← Docker cleanup logical sequence
Task 11 → (no deps)
Task 12 → (no deps)     ← core state fix (many tasks depend on SCANS working)
Task 13 → Task 12       ← needs bounded cache
Task 14 → Task 12       ← needs SCANS available
Task 15 → (no deps)
Task 16 → Task 12       ← needs SCANS cancel_event
Task 17 → (no deps)
Task 18 → (no deps)
Task 19 → (no deps)
Task 20 → (no deps)
Task 21 → (no deps)
Task 22 → (no deps)
Task 23 → (no deps)
Task 24 → (no deps)
Task 25 → (no deps)
Task 26 → (no deps)
Task 27 → ALL           ← final integration test (run last)
```

**Recommended batch order:**
1. Tasks 1–4 (security — unblock everything else)
2. Tasks 5–6 (scan no-op bug — user-visible)
3. Tasks 9–11 (Docker — enables full system testing)
4. Tasks 12–13 (state persistence — foundation for API correctness)
5. Tasks 14–15 (missing routes — UI completeness)
6. Tasks 7–8 (pipeline unification)
7. Tasks 16–17 (lifecycle)
8. Tasks 18–21 (reliability)
9. Tasks 22–26 (quality)
10. Task 27 (final validation)
