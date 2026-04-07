# Spec: Learning Knowledge Base PostgreSQL Migration

**Date:** 2026-04-07
**Status:** Approved

## Problem

`KnowledgeBase` in `learning/knowledge_base.py` uses a direct SQLite connection. It manages 5 tables for continuous learning state (scan sessions, findings history, tool performance, target profiles, pattern library). This bypasses `DBManager` — violating the project rule that all persistence must go through DBManager → PostgreSQL.

Additionally, `web/backend/main.py`'s `/api/learning/stats` endpoint creates a `KnowledgeBase` instance and queries `kb._conn` directly with raw SQL against `tool_performance`.

## Goal

Remove `KnowledgeBase` and its SQLite dependency. Route all learning persistence through a new `LearningRepository` backed by DBManager/PostgreSQL. No data migration — start fresh.

## What Is Not Changed

- All learning logic in `unified_scan_engine.py`, `intelligence_daemon.py`, `agent_swarm_coordinator.py`, `swarm_intelligence_engine.py`, `attack_simulation_engine.py` — only the KB instantiation and import lines change
- No new API endpoints
- No frontend changes
- `learning/adaptive_planner.py` — uses `Neo4jKnowledgeBase` (not `KnowledgeBase`), untouched

## Changes

### 1. `db/schema.sql` — 5 new tables

```sql
-- Learning Scan Sessions
CREATE TABLE IF NOT EXISTS learning_scan_sessions (
    session_id       TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    scan_type        TEXT NOT NULL DEFAULT 'full',
    started_at       DOUBLE PRECISION,
    ended_at         DOUBLE PRECISION,
    findings_count   INTEGER NOT NULL DEFAULT 0,
    vulns_confirmed  INTEGER NOT NULL DEFAULT 0,
    duration_seconds DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_learning_scan_sessions_target ON learning_scan_sessions(target);

-- Learning Findings History
CREATE TABLE IF NOT EXISTS learning_findings (
    id          BIGSERIAL PRIMARY KEY,
    session_id  TEXT NOT NULL,
    target      TEXT NOT NULL,
    endpoint    TEXT NOT NULL DEFAULT '',
    vuln_type   TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'medium',
    confidence  DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    payload     TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT '',
    confirmed   INTEGER NOT NULL DEFAULT 0,
    found_at    DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_learning_findings_session ON learning_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_learning_findings_target  ON learning_findings(target);

-- Tool Performance (composite PK — atomic upsert with weighted averages)
CREATE TABLE IF NOT EXISTS tool_performance (
    tool_name        TEXT NOT NULL,
    vuln_type        TEXT NOT NULL DEFAULT '',
    target_type      TEXT NOT NULL DEFAULT '',
    runs_total       INTEGER NOT NULL DEFAULT 0,
    runs_success     INTEGER NOT NULL DEFAULT 0,
    findings_total   INTEGER NOT NULL DEFAULT 0,
    avg_time_seconds DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_run         DOUBLE PRECISION,
    PRIMARY KEY (tool_name, vuln_type, target_type)
);

-- Target Profiles
CREATE TABLE IF NOT EXISTS target_profiles (
    domain        TEXT PRIMARY KEY,
    tech_stack    JSONB NOT NULL DEFAULT '[]',
    open_ports    JSONB NOT NULL DEFAULT '[]',
    waf_detected  TEXT NOT NULL DEFAULT '',
    auth_types    JSONB NOT NULL DEFAULT '[]',
    scan_count    INTEGER NOT NULL DEFAULT 0,
    last_scanned  DOUBLE PRECISION,
    profile_data  JSONB NOT NULL DEFAULT '{}'
);

-- Pattern Library (composite PK — atomic occurrence counter)
CREATE TABLE IF NOT EXISTS pattern_library (
    tech_stack_key   TEXT NOT NULL,
    vuln_type        TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    avg_cvss         DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    best_tool        TEXT NOT NULL DEFAULT '',
    last_seen        DOUBLE PRECISION,
    PRIMARY KEY (tech_stack_key, vuln_type)
);
```

Note: `learning_scan_sessions` and `learning_findings` use a `learning_` prefix to avoid future collision with any global `scan_sessions` or `findings` tables. The other three names are specific enough to be collision-safe.

### 2. `core/db_manager.py` — 12 new async methods

New `# ── Learning ──` section, inserted before `# ── Sync wrappers for CLI ──`.

All methods raise `RuntimeError("... requires Postgres mode")` when `self.mode not in ("distributed", "postgres")`.

| Method | SQL | Notes |
|---|---|---|
| `save_learning_session(data)` | `INSERT ... ON CONFLICT (session_id) DO UPDATE SET ...` | Upsert — covers both start and finish |
| `get_learning_session(session_id)` | `SELECT * FROM learning_scan_sessions WHERE session_id = %s` | Returns dict or None |
| `list_learning_sessions(limit=10)` | `SELECT * FROM learning_scan_sessions ORDER BY started_at DESC LIMIT %s` | |
| `save_learning_finding(data)` | `INSERT INTO learning_findings ...` | Plain insert — every finding is a new row |
| `record_tool_run(data)` | `INSERT ... ON CONFLICT (tool_name, vuln_type, target_type) DO UPDATE SET runs_total+1, runs_success+N, findings_total+N, avg_time_seconds=weighted avg` | Atomic; ON CONFLICT DO UPDATE sees old `runs_total` before incrementing — EMA formula is correct |
| `get_best_tool_for_vuln(vuln_type, target_type)` | `SELECT tool_name ... ORDER BY runs_success::float/NULLIF(runs_total,0) DESC, findings_total DESC LIMIT 1` | Returns tool name string or None |
| `upsert_target_profile(data)` | `INSERT ... ON CONFLICT (domain) DO UPDATE SET ...` | Upsert |
| `get_target_profile(domain)` | `SELECT * FROM target_profiles WHERE domain = %s` | Returns dict or None |
| `upsert_pattern(data)` | `INSERT ... ON CONFLICT (tech_stack_key, vuln_type) DO UPDATE SET occurrence_count+1, avg_cvss=weighted avg` | Atomic increment |
| `get_patterns_for_tech_stack(tech_stack_key)` | `SELECT * FROM pattern_library WHERE tech_stack_key = %s ORDER BY occurrence_count DESC LIMIT 20` | |
| `get_learning_stats()` | 4 subqueries: session count, confirmed findings, unique target count, top 5 vuln types, top 5 tools | Returns same shape as original `stats()` |
| `list_tool_performance()` | `SELECT tool_name, vuln_type, CASE WHEN runs_total > 0 THEN runs_success::float/runs_total ELSE 0 END AS ema, runs_total, findings_total FROM tool_performance ORDER BY findings_total DESC` | Exact query `/api/learning/stats` needs |

### 3. `core/learning_repository.py` (new file)

`LearningRepository` mirrors the original `KnowledgeBase` method names exactly so caller updates are mechanical.

```python
class LearningRepository:
    def __init__(self, db: DBManager) -> None: ...

    # Session lifecycle
    async def start_session(self, session_id, target, scan_type="full") -> None
    async def finish_session(self, session_id, findings_count, vulns_confirmed, duration_seconds=0.0) -> None

    # Findings
    async def record_finding(self, session_id, finding: dict, confirmed: bool) -> None
    async def record_findings_bulk(self, session_id, findings: list, confirmed: bool) -> None  # loops record_finding

    # Tool performance
    async def record_tool_run(self, tool_name, vuln_type="", target_type="",
                              success=True, findings_count=0, time_seconds=0.0) -> None
    async def best_tool_for_vuln(self, vuln_type, target_type="") -> str | None

    # Target profiles
    async def upsert_target_profile(self, target, profile_data: dict) -> None
    async def get_target_profile(self, target) -> dict | None

    # Patterns
    async def upsert_pattern(self, tech_stack: list, pattern_data: dict) -> None
    async def patterns_for_tech_stack(self, tech_stack: list) -> list

    # Analytics
    async def stats(self) -> dict
    async def recent_sessions(self, limit=10) -> list
    async def get_tool_performance_stats(self) -> list

    def close(self) -> None  # no-op — no connection to close

    # Sync wrappers (one per async method, via DBManager._run_sync)
    def start_session_sync(...)
    def finish_session_sync(...)
    def record_finding_sync(...)
    def record_findings_bulk_sync(...)
    def record_tool_run_sync(...)
    def best_tool_for_vuln_sync(...)
    def upsert_target_profile_sync(...)
    def get_target_profile_sync(...)
    def upsert_pattern_sync(...)
    def patterns_for_tech_stack_sync(...)
    def stats_sync(...)
    def recent_sessions_sync(...)
    def get_tool_performance_stats_sync(...)


async def get_learning_repo() -> LearningRepository:
    return LearningRepository(await get_db_manager())

def get_learning_repo_sync() -> LearningRepository:
    return LearningRepository(get_db_manager_sync())
```

### 4. Caller updates — 6 files

| File | Change |
|---|---|
| `unified_scan_engine.py` | Replace `KnowledgeBase()` with `LearningRepository(get_db_manager_sync())`; all method names match — no other changes |
| `intelligence_daemon.py` | Currently creates `KnowledgeBase()` on every event call; refactor to create one `LearningRepository` instance at class init (lazy via `get_learning_repo_sync()`); reuse it in `_learn()` |
| `agent_swarm_coordinator.py` | `_try_load_kb()` creates `KnowledgeBase()` — replace with `LearningRepository(get_db_manager_sync())`; `record_finding` and `record_tool_run` method names match |
| `swarm_intelligence_engine.py` | Same `_try_load_kb()` pattern; same two methods called |
| `attack_simulation_engine.py` | Only calls `best_tool_for_vuln()` — swap import only; no method changes |
| `web/backend/main.py` | Delete `KnowledgeBase(path)` + `kb._conn.execute(...)` block; replace with `repo = get_learning_repo_sync(); rows = repo.get_tool_performance_stats_sync()`; remove `from learning.knowledge_base import KnowledgeBase` and `from path_manager import db_path as _db_path_fn` imports |

After all callers are updated, `learning/knowledge_base.py` is deleted.

### 5. Data Flow

```
unified_scan_engine: self._kb.start_session_sync(session_id, target, scan_type)
  → LearningRepository.start_session(...)
    → DBManager.save_learning_session(...)
      → INSERT INTO learning_scan_sessions ON CONFLICT DO UPDATE (Postgres)

unified_scan_engine: self._kb.record_tool_run_sync(tool_name, vuln_type, ...)
  → LearningRepository.record_tool_run(...)
    → DBManager.record_tool_run(...)
      → INSERT INTO tool_performance ON CONFLICT DO UPDATE (atomic increment + weighted avg)

GET /api/learning/stats
  → repo.get_tool_performance_stats_sync()
    → DBManager.list_tool_performance()
      → SELECT tool_name, vuln_type, ema, runs_total, findings_total (Postgres)
```

## File Map

| File | Change |
|---|---|
| `db/schema.sql` | Add 5 learning tables |
| `core/db_manager.py` | Add `# ── Learning ──` section with 12 async methods |
| `core/learning_repository.py` | New — `LearningRepository` + `get_learning_repo()` + `get_learning_repo_sync()` |
| `unified_scan_engine.py` | Replace `KnowledgeBase` import and instantiation |
| `intelligence_daemon.py` | Replace per-event `KnowledgeBase()` with single repo instance |
| `agent_swarm_coordinator.py` | Update `_try_load_kb()` |
| `swarm_intelligence_engine.py` | Update `_try_load_kb()` |
| `attack_simulation_engine.py` | Swap import only |
| `web/backend/main.py` | Replace raw `_conn` query with `get_tool_performance_stats_sync()` |
| `learning/knowledge_base.py` | Delete |

## Testing

| Test file | What it tests |
|---|---|
| `tests/test_db_manager_learning.py` | All 12 DBManager methods: mode guard (SQLite → RuntimeError) + postgres mock (commit called, SELECT returns correct shape) |
| `tests/test_learning_repository.py` | All async methods + sync wrappers via mocked DBManager; includes `test_finish_session_upserts_with_counts`, `test_record_findings_bulk_calls_save_per_finding`, `test_best_tool_for_vuln_returns_none_when_empty` |
| `tests/test_learning_kb_removed.py` | Static checks: `learning/knowledge_base.py` is gone; no `sqlite3` import in any learning module; no raw `_conn` access in `web/backend/main.py` |
