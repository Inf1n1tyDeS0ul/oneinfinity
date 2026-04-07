# Spec: Research Knowledge Base PostgreSQL Migration

**Date:** 2026-04-07
**Status:** Approved

## Problem

`ResearchKnowledgeBase` in `research_mode_controller.py` uses a direct SQLite connection to `~/.oneinfinity/databases/research.db`. It manages 6 tables for autonomous research loop state (sessions, theories, test outcomes, discoveries, patterns, endpoint insights). This bypasses `DBManager` — violating the project rule that all persistence must go through DBManager → PostgreSQL.

## Goal

Remove `ResearchKnowledgeBase` and its SQLite dependency. Route all research persistence through a new `ResearchRepository` backed by DBManager/PostgreSQL. No data migration — start fresh.

## What Is Not Changed

- All research loop logic in `ResearchModeController`, `ResearchSession`, `VulnTheory`, `TestOutcome`, `Discovery`, `AnomDetector`, `PayloadGen` — untouched
- No new API endpoints
- No frontend changes
- `endpoint_insights` table added to schema for completeness but has no active write path (no change to callers)

## Changes

### 1. `db/schema.sql` — 6 new tables

```sql
-- Research Sessions
CREATE TABLE IF NOT EXISTS research_sessions (
    session_id         TEXT PRIMARY KEY,
    target             TEXT NOT NULL,
    output_dir         TEXT NOT NULL DEFAULT '',
    platform           TEXT NOT NULL DEFAULT '',
    started_at         DOUBLE PRECISION,
    ended_at           DOUBLE PRECISION,
    status             TEXT NOT NULL DEFAULT 'running',
    iteration          INTEGER NOT NULL DEFAULT 0,
    theories_generated INTEGER NOT NULL DEFAULT 0,
    tests_executed     INTEGER NOT NULL DEFAULT 0,
    anomalies_found    INTEGER NOT NULL DEFAULT 0,
    confirmed_vulns    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_research_sessions_target ON research_sessions(target);

-- Vulnerability Theories
CREATE TABLE IF NOT EXISTS vuln_theories (
    theory_id   TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    target      TEXT NOT NULL,
    endpoint    TEXT NOT NULL DEFAULT '',
    vuln_type   TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    confidence  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    reasoning   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  DOUBLE PRECISION,
    updated_at  DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_vuln_theories_session ON vuln_theories(session_id);
CREATE INDEX IF NOT EXISTS idx_vuln_theories_target  ON vuln_theories(target);

-- Test Outcomes
CREATE TABLE IF NOT EXISTS test_outcomes (
    id               BIGSERIAL PRIMARY KEY,
    session_id       TEXT NOT NULL,
    theory_id        TEXT,
    target           TEXT NOT NULL,
    endpoint         TEXT NOT NULL DEFAULT '',
    vuln_type        TEXT NOT NULL,
    payload          TEXT NOT NULL DEFAULT '',
    status_code      INTEGER,
    response_size    INTEGER,
    response_time_ms DOUBLE PRECISION,
    anomaly_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    confirmed        INTEGER NOT NULL DEFAULT 0,
    evidence         TEXT NOT NULL DEFAULT '',
    tested_at        DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_test_outcomes_session ON test_outcomes(session_id);
CREATE INDEX IF NOT EXISTS idx_test_outcomes_theory  ON test_outcomes(theory_id);

-- Discoveries (confirmed vulnerabilities)
CREATE TABLE IF NOT EXISTS research_discoveries (
    report_id     TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    target        TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'medium',
    confidence    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    endpoint      TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    impact        TEXT NOT NULL DEFAULT '',
    steps         JSONB NOT NULL DEFAULT '[]',
    poc           TEXT NOT NULL DEFAULT '',
    remediation   TEXT NOT NULL DEFAULT '',
    evidence      TEXT NOT NULL DEFAULT '',
    cvss_score    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    discovered_at DOUBLE PRECISION,
    reported      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_research_discoveries_session ON research_discoveries(session_id);
CREATE INDEX IF NOT EXISTS idx_research_discoveries_target  ON research_discoveries(target);

-- Cross-Target Patterns
CREATE TABLE IF NOT EXISTS cross_target_patterns (
    id                BIGSERIAL PRIMARY KEY,
    vuln_type         TEXT NOT NULL,
    endpoint_pattern  TEXT NOT NULL DEFAULT '',
    parameter_pattern TEXT NOT NULL DEFAULT '',
    success_count     INTEGER NOT NULL DEFAULT 1,
    last_seen         DOUBLE PRECISION,
    notes             TEXT NOT NULL DEFAULT '',
    UNIQUE(vuln_type, endpoint_pattern, parameter_pattern)
);

-- Endpoint Insights (schema present; no active write path)
CREATE TABLE IF NOT EXISTS endpoint_insights (
    id                BIGSERIAL PRIMARY KEY,
    session_id        TEXT NOT NULL,
    target            TEXT NOT NULL,
    endpoint          TEXT NOT NULL DEFAULT '',
    method            TEXT NOT NULL DEFAULT 'GET',
    parameters        JSONB NOT NULL DEFAULT '[]',
    auth_required     INTEGER NOT NULL DEFAULT 0,
    sensitivity_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    tags              JSONB NOT NULL DEFAULT '[]',
    tested_at         DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_endpoint_insights_session ON endpoint_insights(session_id);
```

Note: `research_discoveries` avoids collision with any future global `discoveries` table.

### 2. `core/db_manager.py` — 10 new async methods

New `# ── Research ──` section, inserted before `# ── Sync wrappers for CLI ──`.

All methods raise `RuntimeError("... requires Postgres mode")` when `self.mode not in ("distributed", "postgres")`.

| Method | SQL | Notes |
|---|---|---|
| `save_research_session(data)` | `INSERT ... ON CONFLICT (session_id) DO UPDATE SET ...` | Upsert — covers both start and finish |
| `get_research_session(session_id)` | `SELECT * FROM research_sessions WHERE session_id = %s` | Returns dict or None |
| `list_research_sessions(target=None)` | `SELECT * FROM research_sessions [WHERE target = %s] ORDER BY started_at DESC` | target=None returns all |
| `save_research_theory(data)` | `INSERT ... ON CONFLICT (theory_id) DO NOTHING` | Idempotent |
| `update_research_theory_status(theory_id, status, updated_at)` | `UPDATE vuln_theories SET status = %s, updated_at = %s WHERE theory_id = %s` | |
| `save_test_outcome(data)` | `INSERT INTO test_outcomes ...` | No upsert — every outcome is a new row |
| `save_research_discovery(data)` | `INSERT ... ON CONFLICT (report_id) DO UPDATE SET ...` | Upsert |
| `list_research_discoveries(session_id=None)` | `SELECT * FROM research_discoveries [WHERE session_id = %s]` | session_id=None returns all |
| `upsert_cross_target_pattern(data)` | `INSERT ... ON CONFLICT (vuln_type, endpoint_pattern, parameter_pattern) DO UPDATE SET success_count = success_count + 1, last_seen = %s` | Atomic increment |
| `get_cross_target_patterns(min_count=2)` | `SELECT * FROM cross_target_patterns WHERE success_count >= %s ORDER BY success_count DESC` | |

### 3. `core/research_repository.py` (new file)

```python
class ResearchRepository:
    def __init__(self, db: DBManager) -> None: ...

    async def save_session(self, session_id, target, output_dir="", platform="",
                           started_at=None, status="running", **counts) -> None

    async def finish_session(self, session_id, ended_at, status, **counts) -> None

    async def record_theory(self, theory_id, session_id, target, endpoint,
                            vuln_type, severity, confidence, reasoning) -> None

    async def update_theory_status(self, theory_id, status) -> None

    async def record_test_outcome(self, session_id, theory_id, target, endpoint,
                                  vuln_type, payload, status_code, response_size,
                                  response_time_ms, anomaly_score, confirmed,
                                  evidence, tested_at) -> None

    async def save_discovery(self, report_id, session_id, target, vuln_type,
                             title, severity, confidence, endpoint, description,
                             impact, steps, poc, remediation, evidence,
                             cvss_score, discovered_at) -> None

    async def get_known_patterns(self, min_count=2) -> list

    async def get_session_history(self, target=None) -> list

    async def get_confirmed_discoveries(self, session_id=None) -> list


async def get_research_repo() -> ResearchRepository:
    """Callable dependency — works in FastAPI (Depends) and async CLI (asyncio.run)."""
    return ResearchRepository(await get_db_manager())
```

`finish_session` maps to `save_research_session` (upsert) but makes the intent explicit at the repository layer — mirrors the original `start_session` / `finish_session` distinction.

### 4. `research_mode_controller.py` — delete `ResearchKnowledgeBase`

Delete:
- `ResearchKnowledgeBase` class (~lines 140–422): `DB_PATH`, `_init_schema`, `_conn`, all 10 methods, `close()`
- Import of `sqlite3` (if module-level)

Update `show_research_stats()`:

```python
async def _fetch_research_stats():
    from core.research_repository import get_research_repo
    repo = await get_research_repo()
    sessions = await repo.get_session_history(target=None)
    discoveries = await repo.get_confirmed_discoveries()
    return sessions, discoveries

def show_research_stats():
    import asyncio
    sessions, discoveries = asyncio.run(_fetch_research_stats())
    ...
    # kb.close() removed
```

### 5. `god_mode_engine.py` — wire `ResearchRepository`

```python
# Add import
from core.research_repository import get_research_repo

# In __init__ or startup:
self.kb = await get_research_repo()

# All self.kb.* calls gain await:
await self.kb.save_session(session_id, target, ...)
await self.kb.record_theory(theory_id, ...)
await self.kb.update_theory_status(theory_id, status)
await self.kb.record_test_outcome(...)
await self.kb.save_discovery(report_id, ...)
await self.kb.get_known_patterns(min_count=2)
await self.kb.get_session_history(target)
await self.kb.get_confirmed_discoveries()

# self.kb.close() removed — no connection to close
```

## Data Flow

```
god_mode_engine: await self.kb.save_session(...)
  → ResearchRepository.save_session(...)
    → DBManager.save_research_session(...)
      → INSERT INTO research_sessions (Postgres)

god_mode_engine: await self.kb.record_theory(...)
  → ResearchRepository.record_theory(...)
    → DBManager.save_research_theory(...)
      → INSERT INTO vuln_theories ON CONFLICT DO NOTHING (Postgres)

god_mode_engine: await self.kb.save_discovery(...)
  → ResearchRepository.save_discovery(...)
    → DBManager.save_research_discovery(...)  [upsert]
    → DBManager.upsert_cross_target_pattern(...) [atomic increment]
      → INSERT INTO research_discoveries, cross_target_patterns (Postgres)
```

Note: `save_discovery` in the original also calls `_update_pattern`. `ResearchRepository.save_discovery` must call both `save_research_discovery` and `upsert_cross_target_pattern` — two DBManager calls in sequence.

## File Map

| File | Change |
|---|---|
| `db/schema.sql` | Add 6 research tables |
| `core/db_manager.py` | Add `# ── Research ──` section with 10 new async methods |
| `core/research_repository.py` | New — `ResearchRepository` + `get_research_repo()` |
| `research_mode_controller.py` | Delete `ResearchKnowledgeBase` class; update `show_research_stats()` |
| `god_mode_engine.py` | Import `get_research_repo`; add `await` to all `self.kb.*` calls; remove `self.kb.close()` |

## Testing

| Test file | What it tests |
|---|---|
| `tests/test_db_manager_research.py` | All 10 DBManager research methods (mode guard + postgres mock) |
| `tests/test_research_repository.py` | ResearchRepository delegation to DBManager mock |
| `tests/test_research_kb_removed.py` | Static checks: no `ResearchKnowledgeBase` in controller, no sqlite3 import |
