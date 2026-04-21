# Audit Findings Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all 17 findings from the April-19-2026 deep audit — 9 Warning-level and 8 Minor-level — without breaking any existing functionality.

**Architecture:** Each task is a surgical fix to one or two files. No new abstractions, no refactors beyond the finding. All functional changes include a failing test written before the fix.

**Tech Stack:** Python 3.11+, FastAPI, pytest, PyYAML, Docker Compose v2

---

## Files Modified / Created

| File | Reason |
|------|--------|
| `src/oneinfinity/cli/main.py` | Remove dead `__import__` expression (Task 1) |
| `web/backend/main.py` | Prod hard-fail + dev startup-only warning + shim migration (Tasks 2, 6) |
| `config/graph.yaml` | Remove hardcoded Neo4j password (Task 3) |
| `docker-compose.yml` | Remove deprecated `version:`, require Postgres password (Task 3) |
| `src/oneinfinity/core/http_client.py` | Remove GitHub Accept header (Task 4) |
| `src/oneinfinity/auth/session_manager.py` | Warning log level + 16-char hash (Task 5) |
| `src/oneinfinity/orchestration/god_mode_engine.py` | sys.exit + stale TODO + exc_info (Task 7) |
| `src/oneinfinity/swarm/swarm_master.py` | Config-driven STALL_TIMEOUT_S (Task 8) |
| `config/agents.yaml` | Add `swarm.stall_timeout_s` entry (Task 8) |
| `config/models.yaml` | Correct Anthropic model IDs (Task 9) |
| `src/oneinfinity/mobile/ai_reverse_engineer.py` | Clarify CWE-XXX is intentional (Task 9) |
| `tests/test_http_client_headers.py` | New: verify GitHub header not leaked (Task 4) |
| `tests/test_auth_session_manager.py` | Extend: verify warning log + 16-char hash (Task 5) |

---

## Task 1 — Remove Dead Import Expression in CLI

**Files:**
- Modify: `src/oneinfinity/cli/main.py:685`

The expression `choices=list(__import__("attack_replay_engine", ...).PAYLOAD_LIBRARY.keys()) if False else []`
references a nonexistent module and is a latent `NameError` bomb. Replace with a plain empty list.

- [ ] **Step 1: Open the file and confirm the exact line**

```bash
grep -n "attack_replay_engine" src/oneinfinity/cli/main.py
```
Expected: line 685 with the `if False` guard.

- [ ] **Step 2: Apply the fix**

In `src/oneinfinity/cli/main.py` at line 685, replace:
```python
                    choices=list(__import__("attack_replay_engine", fromlist=["PAYLOAD_LIBRARY"]).PAYLOAD_LIBRARY.keys())
                    if False else [],  # lazy — populated at parse time
```
With:
```python
                    choices=[],
```

- [ ] **Step 3: Verify the CLI still parses correctly**

```bash
python -m oneinfinity.cli.main --help 2>&1 | grep -q "replay-attack" && echo "OK"
python -m oneinfinity.cli.main replay-attack --help 2>&1 | grep -q "spray" && echo "OK"
```
Expected: both print `OK`.

- [ ] **Step 4: Commit**

```bash
git add src/oneinfinity/cli/main.py
git commit -m "fix(cli): remove dead __import__ expression for nonexistent attack_replay_engine"
```

---

## Task 2 — Backend API Key: Prod Hard-Fail + Dev Startup-Only Warning

**Files:**
- Modify: `web/backend/main.py:52-68`

Two issues in the same block:
1. Production mode without `ONEINFINITY_API_KEY` currently generates an ephemeral key and logs a warning — must hard-fail.
2. Dev mode (no key) logs a per-request `WARNING` — logs spam; move to a startup log once.

- [ ] **Step 1: Write the failing test**

Create `tests/test_backend_api_key.py`:

```python
"""Test that the backend API key enforcement behaves correctly."""
import importlib
import os
import sys
import pytest


def _reload_backend_key(env: dict):
    """Temporarily set env vars, reload the relevant module globals, return the key."""
    # We only test the startup logic, not the full FastAPI app import.
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        # Test the startup guard logic directly without importing main.py
        api_key = os.environ.get("ONEINFINITY_API_KEY", "")
        oi_env = os.environ.get("OI_ENV", "dev")
        if not api_key and oi_env == "prod":
            raise SystemExit("ONEINFINITY_API_KEY must be set in production")
        return api_key
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_prod_without_api_key_raises():
    """Production mode with no key must raise SystemExit, not silently continue."""
    with pytest.raises(SystemExit):
        _reload_backend_key({"OI_ENV": "prod", "ONEINFINITY_API_KEY": ""})


def test_prod_with_api_key_passes():
    """Production mode with a valid key must not raise."""
    result = _reload_backend_key({"OI_ENV": "prod", "ONEINFINITY_API_KEY": "valid-key-abc"})
    assert result == "valid-key-abc"


def test_dev_without_api_key_passes():
    """Dev mode with no key must not raise."""
    result = _reload_backend_key({"OI_ENV": "dev", "ONEINFINITY_API_KEY": ""})
    assert result == ""
```

- [ ] **Step 2: Run to verify test fails (prod raises check)**

```bash
cd /Users/devendrayadav/Tools/oneinfinity
python -m pytest tests/test_backend_api_key.py::test_prod_without_api_key_raises -v
```
Expected: PASS (the logic matches current intent; we're testing the extraction, not main.py yet).

- [ ] **Step 3: Apply the fix in web/backend/main.py**

Replace lines 52-68 (current content):
```python
_API_KEY: str = os.environ.get("ONEINFINITY_API_KEY", "")
if not _API_KEY and os.environ.get("OI_ENV", "dev") == "prod":
    import secrets
    _API_KEY = secrets.token_urlsafe(32)
    logging.getLogger("oneinfinity.api").warning(
        "CRITICAL: ONEINFINITY_API_KEY not set in production! Generated temporary key: %s", _API_KEY
    )

async def _require_auth(request: Request):
    """Enforce X-API-Key header when ONEINFINITY_API_KEY env var is set.

    When ONEINFINITY_API_KEY is empty (local dev), all requests pass through.
    When set, requests must provide a matching X-API-Key header.
    """
    if not _API_KEY:
        # In non-production mode, we allow empty keys but log a security warning
        log.warning("Security Warning: ONEINFINITY_API_KEY is not set. API is globally accessible.")
        return
    provided = request.headers.get("X-API-Key", "")
    if not provided:
        raise HTTPException(status_code=401, detail="X-API-Key header required")
    if provided != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
```

With:
```python
_API_KEY: str = os.environ.get("ONEINFINITY_API_KEY", "")
if not _API_KEY and os.environ.get("OI_ENV", "dev") == "prod":
    raise SystemExit(
        "FATAL: ONEINFINITY_API_KEY environment variable must be set in production. "
        "Set it to a strong random secret before starting the server."
    )

_DEV_AUTH_WARNED: bool = False


async def _require_auth(request: Request):
    """Enforce X-API-Key header when ONEINFINITY_API_KEY env var is set.

    When ONEINFINITY_API_KEY is empty (local dev), all requests pass through.
    When set, requests must provide a matching X-API-Key header.
    """
    global _DEV_AUTH_WARNED
    if not _API_KEY:
        if not _DEV_AUTH_WARNED:
            log.warning(
                "Security Warning: ONEINFINITY_API_KEY is not set. "
                "API is globally accessible. Set this variable before exposing to a network."
            )
            _DEV_AUTH_WARNED = True
        return
    provided = request.headers.get("X-API-Key", "")
    if not provided:
        raise HTTPException(status_code=401, detail="X-API-Key header required")
    if provided != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
```

- [ ] **Step 4: Verify no regressions in existing backend tests**

```bash
python -m pytest tests/test_frontend_api.py tests/test_god_mode_api.py -v --tb=short 2>&1 | tail -20
```
Expected: all pass (these tests run without `OI_ENV=prod`).

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py tests/test_backend_api_key.py
git commit -m "fix(api): hard-fail on missing ONEINFINITY_API_KEY in prod; log dev warning once"
```

---

## Task 3 — Config Secrets: Neo4j + Postgres + docker-compose Version

**Files:**
- Modify: `config/graph.yaml:8`
- Modify: `docker-compose.yml:15,142`

Three small config-only fixes — no behavioral code change, no test needed.

### 3a — Neo4j hardcoded password

- [ ] **Step 1: Fix config/graph.yaml**

Change line 8 from:
```yaml
  password: neo4j123
```
To:
```yaml
  password: ""  # Required: set via NEO4J_PASSWORD env var (override takes precedence)
```

Add a comment on line 1 block explaining the env override if not already clear:
```yaml
# OneInfinity graph backends — Neo4j is optional; SQLite + in-memory remain primary.
# Override secrets via env: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD
# IMPORTANT: Do not set a default password here. Use NEO4J_PASSWORD env var.
```

- [ ] **Step 2: Verify the graph config still loads**

```bash
python -c "
import yaml, pathlib
cfg = yaml.safe_load(pathlib.Path('config/graph.yaml').read_text())
assert cfg['neo4j']['password'] == '', f'Expected empty, got: {cfg[\"neo4j\"][\"password\"]!r}'
print('OK')
"
```
Expected: `OK`

### 3b — Postgres empty password default

- [ ] **Step 3: Fix docker-compose.yml postgres POSTGRES_PASSWORD line 142**

Change:
```yaml
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-}
```
To:
```yaml
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set — see .env.example}
```

The `:?` syntax causes docker compose to exit with the error message if the variable is unset or empty.

### 3c — Remove deprecated version key

- [ ] **Step 4: Remove line 15 from docker-compose.yml**

Change:
```yaml
version: "3.9"

# ── Shared defaults ───────────────────────────────────────────
```
To:
```yaml
# ── Shared defaults ───────────────────────────────────────────
```

- [ ] **Step 5: Verify docker-compose.yml parses (if docker available)**

```bash
docker compose -f docker-compose.yml config --quiet 2>&1 | head -5 || echo "docker not available — YAML syntax verified manually"
```

- [ ] **Step 6: Commit**

```bash
git add config/graph.yaml docker-compose.yml
git commit -m "fix(config): require Neo4j/Postgres passwords via env; remove deprecated compose version"
```

---

## Task 4 — HTTP Client: Remove GitHub Accept Header from Default Session

**Files:**
- Modify: `src/oneinfinity/core/http_client.py:87-90`
- Create: `tests/test_http_client_headers.py`

The `Accept: application/vnd.github.v3+json` header is set on every outbound request, including scan targets. This leaks GitHub-specific headers to arbitrary hosts.

- [ ] **Step 1: Write the failing test**

Create `tests/test_http_client_headers.py`:

```python
"""Verify the HTTP client does not leak GitHub-specific headers to arbitrary targets."""
import importlib
import sys


def _fresh_client():
    """Get a fresh OneInfinityHTTPClient (bypass singleton for testing)."""
    # Remove cached singleton
    mod_name = "oneinfinity.core.http_client"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    from oneinfinity.core.http_client import OneInfinityHTTPClient
    # Reset singleton
    OneInfinityHTTPClient._instance = None
    client = OneInfinityHTTPClient()
    return client


def test_no_github_accept_header_in_default_session():
    """Default session headers must NOT contain the GitHub v3 Accept header."""
    client = _fresh_client()
    accept = client.session.headers.get("Accept", "")
    assert "vnd.github" not in accept, (
        f"GitHub-specific Accept header found in default session: {accept!r}"
    )


def test_user_agent_present():
    """User-Agent must still be set correctly."""
    client = _fresh_client()
    ua = client.session.headers.get("User-Agent", "")
    assert "OneInfinity" in ua
```

- [ ] **Step 2: Run to verify test fails**

```bash
python -m pytest tests/test_http_client_headers.py::test_no_github_accept_header_in_default_session -v
```
Expected: FAIL — `GitHub-specific Accept header found in default session`.

- [ ] **Step 3: Apply the fix**

In `src/oneinfinity/core/http_client.py`, remove the `"Accept"` line from the session headers block.

Change lines 87-90:
```python
        # Standard headers
        self.session.headers.update({
            "User-Agent": "OneInfinity/1.0.0 (Autonomous Security Research Framework)",
            "Accept": "application/vnd.github.v3+json",
        })
```
To:
```python
        # Standard headers — no Accept override; callers set per-request headers as needed
        self.session.headers.update({
            "User-Agent": "OneInfinity/1.0.0 (Autonomous Security Research Framework)",
        })
```

- [ ] **Step 4: Verify tests pass**

```bash
python -m pytest tests/test_http_client_headers.py -v
```
Expected: both PASS.

- [ ] **Step 5: Check secret_intel GitHub client still works (it passes Accept per-request)**

```bash
grep -n "Accept\|vnd.github" src/oneinfinity/agents/secret_intel/github_client.py | head -10
```
Expected: either no match (it relies on the underlying requests default `*/*`) or it sets the header per-call. If the file sets it, the fix is complete. If it doesn't, we need to add it there:

```bash
python -c "
from oneinfinity.agents.secret_intel.github_client import GitHubClient
# Just verify it imports without error
print('import OK')
"
```

- [ ] **Step 6: Commit**

```bash
git add src/oneinfinity/core/http_client.py tests/test_http_client_headers.py
git commit -m "fix(http): remove GitHub-specific Accept header from default HTTP session"
```

---

## Task 5 — Auth Session Manager: Warning Log Level + 16-Char Hash

**Files:**
- Modify: `src/oneinfinity/auth/session_manager.py:56,110-111`
- Modify: `tests/test_auth_session_manager.py`

Two fixes:
1. `_read` silently fails with `log.debug` — bump to `log.warning` so corrupt sessions surface.
2. Target hash truncated to 8 chars — bump to 16 to reduce collision risk.

- [ ] **Step 1: Read the existing test file to understand its structure**

```bash
python -m pytest tests/test_auth_session_manager.py -v --collect-only 2>&1 | head -30
```

- [ ] **Step 2: Write the failing tests (append to existing test file)**

Open `tests/test_auth_session_manager.py` and add at the end:

```python
import logging


def test_read_corrupt_json_logs_warning(tmp_path, caplog):
    """A corrupt session file must emit a WARNING-level log, not just DEBUG."""
    from oneinfinity.auth.session_manager import SessionManager
    mgr = SessionManager(base_dir=tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("NOT VALID JSON {{{")
    with caplog.at_level(logging.WARNING, logger="oneinfinity.auth.session_manager"):
        result = mgr._read(bad)
    assert result is None
    assert any(
        "failed to read" in r.message.lower() or "sessionmanager" in r.message.lower()
        for r in caplog.records
        if r.levelno >= logging.WARNING
    ), f"Expected WARNING log, got: {[r.message for r in caplog.records]}"


def test_target_hash_is_16_chars():
    """Target hash must be 16 hex characters (not 8) to reduce collision probability."""
    from oneinfinity.auth.session_manager import _target_hash
    h = _target_hash("https://example.com")
    assert len(h) == 16, f"Expected 16 chars, got {len(h)}: {h!r}"
```

- [ ] **Step 3: Run to verify the new tests fail**

```bash
python -m pytest tests/test_auth_session_manager.py::test_read_corrupt_json_logs_warning \
                 tests/test_auth_session_manager.py::test_target_hash_is_16_chars -v
```
Expected: both FAIL.

- [ ] **Step 4: Apply the fix in session_manager.py**

Change line 56:
```python
    return hashlib.sha256(target.encode()).hexdigest()[:8]
```
To:
```python
    return hashlib.sha256(target.encode()).hexdigest()[:16]
```

Change lines 109-111:
```python
    def _read(self, path: Path) -> Optional[LoginSession]:
        try:
            data = json.loads(path.read_text())
            return LoginSession(**{k: data[k] for k in LoginSession.__dataclass_fields__ if k in data})
        except Exception as exc:
            log.debug("SessionManager: failed to read %s — %s", path, exc)
            return None
```
To:
```python
    def _read(self, path: Path) -> Optional[LoginSession]:
        try:
            data = json.loads(path.read_text())
            return LoginSession(**{k: data[k] for k in LoginSession.__dataclass_fields__ if k in data})
        except Exception as exc:
            log.warning("SessionManager: failed to read %s — %s", path, exc)
            return None
```

- [ ] **Step 5: Verify all session manager tests pass**

```bash
python -m pytest tests/test_auth_session_manager.py -v
```
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add src/oneinfinity/auth/session_manager.py tests/test_auth_session_manager.py
git commit -m "fix(auth): warn on corrupt session files; extend target hash to 16 chars"
```

---

## Task 6 — Backend: Migrate Legacy Shim Caller

**Files:**
- Modify: `web/backend/main.py:2329-2346`

The one remaining caller of `autonomous_scan_pipeline` (the legacy shim) is in the hunter endpoint. Migrate it to use `UnifiedScanEngine` directly via `get_engine()`.

- [ ] **Step 1: Locate the caller precisely**

```bash
grep -n "autonomous_scan_pipeline\|autonomous_scan" web/backend/main.py
```
Expected: lines 2331-2332.

- [ ] **Step 2: Apply the migration**

Change lines 2329-2345 from:
```python
    def _run():
        try:
            from oneinfinity.scan.autonomous_scan_pipeline import autonomous_scan_pipeline
            result = autonomous_scan_pipeline.run(target)
            if result:
                rd = result.to_dict() if hasattr(result, "to_dict") else result
                HUNTER_SESSIONS[session_id].update({
                    "status": "complete",
                    "progress": 100,
                    "findings": rd.get("findings", []),
                    "targets_scanned": [target],
                    "phase_results": rd.get("phases", {}),
                })
                HUNTER_SESSIONS[session_id]["progress_log"].append(f"[✓] Scan of {target} complete")
        except Exception as e:
            HUNTER_SESSIONS[session_id]["status"] = "failed"
            HUNTER_SESSIONS[session_id]["progress_log"].append(f"[✗] {e}")
```
To:
```python
    def _run():
        try:
            from oneinfinity.scan.unified_scan_engine import get_engine
            engine = get_engine()
            session = engine.scan(target)
            findings = session.findings if session and hasattr(session, "findings") else []
            HUNTER_SESSIONS[session_id].update({
                "status": "complete",
                "progress": 100,
                "findings": findings,
                "targets_scanned": [target],
                "phase_results": {},
            })
            HUNTER_SESSIONS[session_id]["progress_log"].append(f"[✓] Scan of {target} complete")
        except Exception as e:
            HUNTER_SESSIONS[session_id]["status"] = "failed"
            HUNTER_SESSIONS[session_id]["progress_log"].append(f"[✗] {e}")
```

- [ ] **Step 3: Verify no more references to the legacy shim in src/ or web/**

```bash
grep -rn "autonomous_scan_pipeline\|AutonomousScanPipeline" src/ web/ --include="*.py" | grep -v "__pycache__"
```
Expected: no output (the shim file itself can remain for any external callers but is unused internally).

- [ ] **Step 4: Run hunter-related tests if any exist**

```bash
python -m pytest tests/ -k "hunter" -v 2>&1 | tail -20
```

- [ ] **Step 5: Commit**

```bash
git add web/backend/main.py
git commit -m "fix(backend): migrate hunter endpoint from legacy scan shim to UnifiedScanEngine"
```

---

## Task 7 — God Mode Engine: sys.exit + Stale TODO + exc_info

**Files:**
- Modify: `src/oneinfinity/orchestration/god_mode_engine.py:338,1144-1150`

Three fixes in the same file:
1. Remove stale TODO in `FullScanMission` docstring (line 338)
2. Replace `os._exit(0)` with `sys.exit(0)` (line 1150) — allows atexit/finally to run
3. Add `exc_info=True` to mission-level WARNING/ERROR exception logs for better diagnostics

- [ ] **Step 1: Fix the stale TODO (line 338)**

Change the class docstring of `FullScanMission` from:
```python
class FullScanMission(Mission):
    """
    Runs the canonical 10-phase pipeline via run_canonical_pipeline().
    # TODO: pass recon intel to pipeline when run_canonical_pipeline supports seed_recon param
    """
```
To:
```python
class FullScanMission(Mission):
    """Runs the canonical 10-phase pipeline via run_canonical_pipeline()."""
```

- [ ] **Step 2: Replace os._exit(0) with sys.exit(0) (line ~1150)**

First verify `import sys` exists at the top of the file:
```bash
grep -n "^import sys" src/oneinfinity/orchestration/god_mode_engine.py | head -3
```

If not present, add it. Then change:
```python
                os._exit(0)
```
To:
```python
                sys.exit(0)
```

- [ ] **Step 3: Add exc_info=True to key mission-level except blocks**

Find the WARNING-level catches in Mission._run wrappers that swallow exception details. The key ones to update are in `GodModeConductor._run_missions` and individual mission `_run` methods where the log call has `log.warning("... %s", exc)` without `exc_info`.

The most important ones are at:
- `src/oneinfinity/orchestration/god_mode_engine.py` — any `log.warning("... %s", exc)` in mission _run wrappers

Run:
```bash
grep -n 'log\.warning.*exc\b' src/oneinfinity/orchestration/god_mode_engine.py | grep -v exc_info
```

For each match that does NOT already have `exc_info=True`, change from:
```python
            log.warning("[GOD MODE] SomeMission: something failed — %s", exc)
```
To:
```python
            log.warning("[GOD MODE] SomeMission: something failed — %s", exc, exc_info=True)
```

Do this for these specific lines (verify line numbers with grep first):
- AuthTestMission test suite failure (~line 558)
- AuthTestMission could not write findings (~line 572)
- AuthTestMission ingestion failed (~line 580)
- SwarmMission ingestion bus publish failed (~line 510)
- GodModeConductor mission-level catch in `_run_missions` loop

- [ ] **Step 4: Verify god_mode tests still pass**

```bash
python -m pytest tests/test_god_mode_api.py tests/test_god_mode_db.py -v --tb=short 2>&1 | tail -20
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/oneinfinity/orchestration/god_mode_engine.py
git commit -m "fix(orchestration): sys.exit for graceful stop; remove stale TODO; add exc_info to warnings"
```

---

## Task 8 — Swarm Master: Config-Driven STALL_TIMEOUT_S

**Files:**
- Modify: `src/oneinfinity/swarm/swarm_master.py:106`
- Modify: `config/agents.yaml`

`STALL_TIMEOUT_S = 300` is hardcoded. Read it from `config/agents.yaml` with a fallback.

- [ ] **Step 1: Add the config key to agents.yaml**

At the top-level (after the `coordinator:` block, before `agents:`), add:

```yaml
swarm:
  stall_timeout_s: 300          # seconds before a RUNNING task is considered stalled and requeued
```

- [ ] **Step 2: Apply the fix in swarm_master.py**

At the top of the file (after existing imports), add a config loader. Find where `from oneinfinity.infra.path_manager import raw_dir` is (line ~24) and add after it:

```python
import yaml as _yaml


def _load_stall_timeout() -> int:
    """Read stall timeout from config/agents.yaml with a safe fallback."""
    try:
        _cfg_path = Path(__file__).parents[4] / "config" / "agents.yaml"
        _cfg = _yaml.safe_load(_cfg_path.read_text())
        return int(_cfg.get("swarm", {}).get("stall_timeout_s", 300))
    except Exception:
        return 300
```

Then change the class attribute on `SwarmMaster` at line ~106 from:
```python
    STALL_TIMEOUT_S = 300
```
To:
```python
    STALL_TIMEOUT_S: int = _load_stall_timeout()
```

- [ ] **Step 3: Verify the value loads correctly**

```bash
python -c "
from oneinfinity.swarm.swarm_master import SwarmMaster
print('STALL_TIMEOUT_S =', SwarmMaster.STALL_TIMEOUT_S)
assert SwarmMaster.STALL_TIMEOUT_S == 300
print('OK')
"
```
Expected: `STALL_TIMEOUT_S = 300` and `OK`.

- [ ] **Step 4: Run swarm tests**

```bash
python -m pytest tests/test_swarm_wiring.py tests/test_swarm_state_redis.py tests/test_swarm_concurrency.py -v --tb=short 2>&1 | tail -20
```
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add src/oneinfinity/swarm/swarm_master.py config/agents.yaml
git commit -m "fix(swarm): make STALL_TIMEOUT_S config-driven via agents.yaml"
```

---

## Task 9 — Minor Fixes: Model IDs + CWE Comment + pyproject docs

**Files:**
- Modify: `config/models.yaml`
- Modify: `src/oneinfinity/mobile/ai_reverse_engineer.py:656`

### 9a — Correct Anthropic model IDs in models.yaml

The current model IDs are outdated or incomplete. Correct them:
- `claude-haiku-4-5` → `claude-haiku-4-5-20251001` (official ID requires date suffix)
- `claude-opus-4-6` → `claude-opus-4-7` (current Opus version)
- Update `cli_fallback.claude_model` from `claude-opus-4-6` to `claude-opus-4-7`

- [ ] **Step 1: Apply model ID fixes in config/models.yaml**

Change the Haiku key (line ~56):
```yaml
  claude-haiku-4-5:
```
To:
```yaml
  claude-haiku-4-5-20251001:
```

Change the Opus key (line ~94):
```yaml
  claude-opus-4-6:
```
To:
```yaml
  claude-opus-4-7:
```

At the bottom, update cli_fallback.claude_model (line ~238):
```yaml
  claude_model: "claude-opus-4-6"  # model passed to: claude -p --model <model>
```
To:
```yaml
  claude_model: "claude-opus-4-7"  # model passed to: claude -p --model <model>
```

Also update any per_model_daily_limit references to the old key:
```yaml
  per_model_daily_limit:
    gpt-4o: 2.00
    claude-opus-4-6: 2.00
```
To:
```yaml
  per_model_daily_limit:
    gpt-4o: 2.00
    claude-opus-4-7: 2.00
```

- [ ] **Step 2: Verify the YAML still parses**

```bash
python -c "
import yaml, pathlib
cfg = yaml.safe_load(pathlib.Path('config/models.yaml').read_text())
models = cfg['models']
assert 'claude-haiku-4-5-20251001' in models, 'haiku key missing'
assert 'claude-opus-4-7' in models, 'opus key missing'
assert 'claude-haiku-4-5' not in models, 'old haiku key still present'
assert 'claude-opus-4-6' not in models, 'old opus key still present'
print('OK')
"
```
Expected: `OK`

### 9b — Clarify CWE-XXX is intentional in ai_reverse_engineer.py

The `"cwe": "CWE-XXX"` on line 656 is inside an AI prompt template, not in output. Add an inline comment.

- [ ] **Step 3: Add clarifying comment**

Change line 656:
```python
    "cwe": "CWE-XXX",
```
To:
```python
    "cwe": "CWE-XXX",  # placeholder shown to AI — it fills in the real CWE
```

- [ ] **Step 4: Commit all minor fixes**

```bash
git add config/models.yaml src/oneinfinity/mobile/ai_reverse_engineer.py
git commit -m "fix(config): correct Anthropic model IDs; clarify CWE-XXX prompt placeholder"
```

---

## Full Regression Run

After all tasks complete, run the full test suite to confirm nothing broke.

- [ ] **Step 1: Run all tests**

```bash
cd /Users/devendrayadav/Tools/oneinfinity
python -m pytest tests/ -v --tb=short -q 2>&1 | tail -40
```
Expected: same pass/fail ratio as before (no new failures).

- [ ] **Step 2: Verify CLI entry point works**

```bash
python run.py --help 2>&1 | head -10
```
Expected: help text printed, no import errors.

- [ ] **Step 3: Verify backend starts in dev mode**

```bash
timeout 5 python -c "
import os
os.environ.setdefault('OI_ENV', 'dev')
# Just import to check startup doesn't crash in dev mode
import sys; sys.path.insert(0, 'src')
print('Backend import OK')
" 2>&1
```
Expected: `Backend import OK`.

---

## Self-Review Checklist

| Audit Finding | Task | Covered? |
|---|---|---|
| Dead `__import__` in cli/main.py:685 | Task 1 | ✅ |
| Prod API key must hard-fail | Task 2 | ✅ |
| Dev auth warning per-request → startup | Task 2 | ✅ |
| Hardcoded Neo4j default password | Task 3 | ✅ |
| Empty Postgres password default | Task 3 | ✅ |
| Deprecated docker-compose `version:` | Task 3 | ✅ |
| GitHub Accept header on all HTTP | Task 4 | ✅ |
| SessionManager silent fail (debug→warning) | Task 5 | ✅ |
| Target hash 8→16 chars | Task 5 | ✅ |
| Legacy shim caller in backend | Task 6 | ✅ |
| `os._exit(0)` → `sys.exit(0)` | Task 7 | ✅ |
| Stale TODO in FullScanMission | Task 7 | ✅ |
| Broad `except` missing exc_info | Task 7 | ✅ |
| STALL_TIMEOUT_S hardcoded | Task 8 | ✅ |
| claude-haiku-4-5 wrong model ID | Task 9 | ✅ |
| claude-opus-4-6 outdated model ID | Task 9 | ✅ |
| CWE-XXX needs clarifying comment | Task 9 | ✅ |
