# Learning Knowledge Base PostgreSQL Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `KnowledgeBase` (SQLite, `learning/knowledge_base.py`) with `LearningRepository` backed by DBManager/PostgreSQL, update all 7 callers, and delete the SQLite class.

**Architecture:** New `core/learning_repository.py` wraps DBManager using the same repository pattern as `core/research_repository.py`. 12 async methods added to `core/db_manager.py`. All callers (synchronous) use `_sync` wrapper methods. `learning/knowledge_base.py` is deleted after all callers are updated.

**Tech Stack:** psycopg3 async pool, PostgreSQL JSONB, `DBManager._run_sync()` for sync callers.

---

## File Map

| File | Change |
|---|---|
| `db/schema.sql` | Append 5 learning tables |
| `core/db_manager.py` | Add `# ── Learning ──` section (~line 947, before `# ── Sync wrappers for CLI ──`) with 12 async methods |
| `core/learning_repository.py` | **New** — `LearningRepository` class + `get_learning_repo()` + `get_learning_repo_sync()` |
| `unified_scan_engine.py` | Replace `KnowledgeBase()` with `get_learning_repo_sync()`; rename 7 call sites to `_sync` methods |
| `intelligence_daemon.py` | Replace per-event `KnowledgeBase()` in `_learn()` with `get_learning_repo_sync()`; rename 2 call sites |
| `learning/pattern_miner.py` | Rename 5 `kb.*` call sites to `kb.*_sync` |
| `agent_swarm_coordinator.py` | Replace `_try_load_kb()` import; rename 2 call sites |
| `swarm_intelligence_engine.py` | Replace `_try_load_kb()` import; rename 3 call sites |
| `attack_simulation_engine.py` | Replace top-level import; rename 1 call site |
| `web/backend/main.py` | Replace raw `_conn.execute` block with `get_learning_repo_sync()` |
| `learning/__init__.py` | Remove `KnowledgeBase` import and `__all__` entry |
| `learning/knowledge_base.py` | **Delete** |

---

## Task 1: Schema — 5 learning tables in db/schema.sql

**Files:**
- Modify: `db/schema.sql` (append after line 217)
- Test: `tests/test_learning_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_learning_schema.py
"""Verify that db/schema.sql contains all 5 learning table definitions."""
from pathlib import Path


def _schema():
    return Path("db/schema.sql").read_text()


def test_learning_scan_sessions_table_present():
    assert "CREATE TABLE IF NOT EXISTS learning_scan_sessions" in _schema()


def test_learning_findings_table_present():
    assert "CREATE TABLE IF NOT EXISTS learning_findings" in _schema()


def test_tool_performance_table_present():
    assert "CREATE TABLE IF NOT EXISTS tool_performance" in _schema()


def test_target_profiles_table_present():
    assert "CREATE TABLE IF NOT EXISTS target_profiles" in _schema()


def test_pattern_library_table_present():
    assert "CREATE TABLE IF NOT EXISTS pattern_library" in _schema()
```

- [ ] **Step 2: Run test to verify it fails**

```
pytest tests/test_learning_schema.py -v
```

Expected: 5 FAILs — `AssertionError`

- [ ] **Step 3: Append the 5 tables to db/schema.sql**

Add at the end of `db/schema.sql`:

```sql
-- ── Learning Scan Sessions ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS learning_scan_sessions (
    session_id      TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    started_at      DOUBLE PRECISION NOT NULL DEFAULT 0,
    finished_at     DOUBLE PRECISION,
    phases          JSONB NOT NULL DEFAULT '[]',
    total_findings  INTEGER NOT NULL DEFAULT 0,
    tools_used      JSONB NOT NULL DEFAULT '[]',
    notes           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_learning_sessions_target ON learning_scan_sessions(target);

-- ── Learning Findings History ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS learning_findings (
    id            BIGSERIAL PRIMARY KEY,
    session_id    TEXT NOT NULL,
    target        TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'info',
    cvss_score    DOUBLE PRECISION,
    endpoint      TEXT NOT NULL DEFAULT '',
    parameter     TEXT NOT NULL DEFAULT '',
    source_tool   TEXT NOT NULL DEFAULT '',
    confirmed     INTEGER NOT NULL DEFAULT 1,
    chain_id      TEXT NOT NULL DEFAULT '',
    discovered_at DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_learning_findings_session ON learning_findings(session_id);
CREATE INDEX IF NOT EXISTS idx_learning_findings_target  ON learning_findings(target);
CREATE INDEX IF NOT EXISTS idx_learning_findings_vuln    ON learning_findings(vuln_type);

-- ── Tool Performance ─────────────────────────────────────────────────────────
-- Composite PK enables atomic ON CONFLICT DO UPDATE for EMA accumulation.
CREATE TABLE IF NOT EXISTS tool_performance (
    tool_name      TEXT NOT NULL,
    vuln_type      TEXT NOT NULL DEFAULT '',
    target_type    TEXT NOT NULL DEFAULT '',
    runs_total     INTEGER NOT NULL DEFAULT 0,
    runs_success   INTEGER NOT NULL DEFAULT 0,
    findings_total INTEGER NOT NULL DEFAULT 0,
    avg_duration_s DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_updated   DOUBLE PRECISION,
    PRIMARY KEY (tool_name, vuln_type, target_type)
);

-- ── Target Profiles ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS target_profiles (
    domain           TEXT PRIMARY KEY,
    tech_stack       JSONB NOT NULL DEFAULT '[]',
    waf_detected     TEXT NOT NULL DEFAULT '',
    scope_notes      TEXT NOT NULL DEFAULT '',
    historical_vulns JSONB NOT NULL DEFAULT '{}',
    last_scanned     DOUBLE PRECISION,
    scan_count       INTEGER NOT NULL DEFAULT 0
);

-- ── Pattern Library ──────────────────────────────────────────────────────────
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

- [ ] **Step 4: Run test to verify it passes**

```
pytest tests/test_learning_schema.py -v
```

Expected: 5 PASSes

- [ ] **Step 5: Commit**

```bash
git add db/schema.sql tests/test_learning_schema.py
git commit -m "feat(schema): add 5 learning tables to PostgreSQL schema"
```

---

## Task 2: DBManager — 12 async learning methods

**Files:**
- Modify: `core/db_manager.py` (insert before `# ── Sync wrappers for CLI ──` at ~line 947)
- Test: `tests/test_db_manager_learning.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_db_manager_learning.py
"""Tests for DBManager learning persistence methods."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def sqlite_mgr():
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"
    return mgr


def pg_mgr(rows=None):
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"
    _rows = list(rows or [])

    async def fake_execute(sql, params=None):
        cursor = MagicMock()
        if _rows and "SELECT" in sql.upper():
            async def _aiter():
                for r in _rows:
                    yield r
            cursor.__aiter__ = lambda self=cursor: _aiter()
        else:
            async def _empty():
                return
                yield
            cursor.__aiter__ = lambda self=cursor: _empty()
        return cursor

    mock_conn = AsyncMock()
    mock_conn.execute = fake_execute
    mock_conn.commit = AsyncMock()
    mock_pool = MagicMock()
    mock_pool.connection.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.connection.return_value.__aexit__ = AsyncMock(return_value=False)
    mgr._pg_pool = mock_pool
    return mgr, mock_conn


# ── Mode guard tests ──────────────────────────────────────────────────────────

def test_save_learning_session_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_learning_session({"session_id": "s1", "target": "t.com"}))


def test_list_learning_sessions_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.list_learning_sessions())


def test_save_learning_finding_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_learning_finding({"session_id": "s1", "target": "t.com", "vuln_type": "sqli"}))


def test_record_tool_run_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.record_tool_run({"tool_name": "nuclei", "vuln_type": "xss"}))


def test_get_best_tool_for_vuln_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_best_tool_for_vuln("xss"))


def test_upsert_target_profile_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.upsert_target_profile({"domain": "t.com"}))


def test_get_target_profile_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_target_profile("t.com"))


def test_upsert_pattern_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.upsert_pattern({"tech_stack_key": "wordpress", "vuln_type": "sqli"}))


def test_get_patterns_for_tech_stack_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_patterns_for_tech_stack("wordpress"))


def test_get_learning_stats_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_learning_stats())


def test_list_tool_performance_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.list_tool_performance())


# ── Postgres behavior tests ───────────────────────────────────────────────────

def test_save_learning_session_commits_in_pg_mode():
    mgr, mock_conn = pg_mgr()
    run(mgr.save_learning_session({
        "session_id": "s1", "target": "t.com", "started_at": 1.0,
        "finished_at": None, "phases": [], "total_findings": 0,
        "tools_used": [], "notes": "",
    }))
    assert mock_conn.commit.called


def test_save_learning_finding_commits_in_pg_mode():
    mgr, mock_conn = pg_mgr()
    run(mgr.save_learning_finding({
        "session_id": "s1", "target": "t.com", "vuln_type": "sqli",
        "severity": "high", "cvss_score": 7.5, "endpoint": "/login",
        "parameter": "id", "source_tool": "sqlmap",
        "confirmed": 1, "chain_id": "", "discovered_at": 1.0,
    }))
    assert mock_conn.commit.called


def test_record_tool_run_commits_in_pg_mode():
    mgr, mock_conn = pg_mgr()
    run(mgr.record_tool_run({
        "tool_name": "nuclei", "vuln_type": "xss", "target_type": "web",
        "runs_success": 1, "findings_total": 3, "avg_duration_s": 5.0,
        "last_updated": 1.0,
    }))
    assert mock_conn.commit.called


def test_get_best_tool_for_vuln_returns_list_in_pg_mode():
    row = MagicMock()
    row.__getitem__ = lambda self, i: ["nuclei", 10, 8, 25, 3.0][i]
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.get_best_tool_for_vuln("xss", top_n=1))
    assert isinstance(result, list)


def test_list_learning_sessions_returns_list_in_pg_mode():
    row = MagicMock()
    row.__iter__ = MagicMock(return_value=iter([]))
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.list_learning_sessions())
    assert isinstance(result, list)


def test_list_tool_performance_returns_list_in_pg_mode():
    mgr, _ = pg_mgr(rows=[])
    result = run(mgr.list_tool_performance())
    assert isinstance(result, list)
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_db_manager_learning.py -v
```

Expected: all FAILs — `AttributeError` (methods don't exist yet)

- [ ] **Step 3: Add the `# ── Learning ──` section to core/db_manager.py**

Insert this block immediately before the line `# ── Sync wrappers for CLI ──` (currently around line 947):

```python
    # ── Learning ──────────────────────────────────────────────────────────────

    async def save_learning_session(self, data: dict) -> None:
        """Upsert a learning scan session.
        
        ON CONFLICT updates only the finish fields (finished_at, total_findings,
        tools_used, notes) — target, started_at, and phases are preserved from
        the original INSERT (start_session call).
        """
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("save_learning_session requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO learning_scan_sessions
                        (session_id, target, started_at, finished_at, phases,
                         total_findings, tools_used, notes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (session_id) DO UPDATE SET
                        finished_at    = EXCLUDED.finished_at,
                        total_findings = EXCLUDED.total_findings,
                        tools_used     = EXCLUDED.tools_used,
                        notes          = EXCLUDED.notes
                    """,
                    (
                        data["session_id"],
                        data.get("target", ""),
                        data.get("started_at", 0.0),
                        data.get("finished_at"),
                        data.get("phases", []),
                        data.get("total_findings", 0),
                        data.get("tools_used", []),
                        data.get("notes", ""),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.save_learning_session failed: %s", exc)
            raise

    async def get_learning_session(self, session_id: str) -> Optional[dict]:
        """Return one learning session row as a dict, or None."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("get_learning_session requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT * FROM learning_scan_sessions WHERE session_id = %s",
                    (session_id,),
                )
                async for row in rows:
                    return dict(row)
            return None
        except Exception as exc:
            log.warning("DBManager.get_learning_session failed: %s", exc)
            return None

    async def list_learning_sessions(self, limit: int = 10) -> list:
        """Return the most recent learning sessions, newest first."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("list_learning_sessions requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT * FROM learning_scan_sessions ORDER BY started_at DESC LIMIT %s",
                    (limit,),
                )
                result = []
                async for row in rows:
                    result.append(dict(row))
                return result
        except Exception as exc:
            log.warning("DBManager.list_learning_sessions failed: %s", exc)
            return []

    async def save_learning_finding(self, data: dict) -> None:
        """Insert one learning finding row (every finding is a new row)."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("save_learning_finding requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO learning_findings
                        (session_id, target, vuln_type, severity, cvss_score,
                         endpoint, parameter, source_tool, confirmed, chain_id,
                         discovered_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        data["session_id"],
                        data.get("target", ""),
                        data.get("vuln_type", "unknown"),
                        data.get("severity", "info"),
                        data.get("cvss_score"),
                        data.get("endpoint", ""),
                        data.get("parameter", ""),
                        data.get("source_tool", ""),
                        data.get("confirmed", 1),
                        data.get("chain_id", ""),
                        data.get("discovered_at", 0.0),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.save_learning_finding failed: %s", exc)
            raise

    async def record_tool_run(self, data: dict) -> None:
        """Atomically upsert tool performance stats with weighted average duration.
        
        ON CONFLICT uses the old runs_total (before +1) for the EMA calculation,
        which is correct because PostgreSQL evaluates the table reference in
        DO UPDATE SET before applying the increment.
        """
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("record_tool_run requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO tool_performance
                        (tool_name, vuln_type, target_type, runs_total, runs_success,
                         findings_total, avg_duration_s, last_updated)
                    VALUES (%s, %s, %s, 1, %s, %s, %s, %s)
                    ON CONFLICT (tool_name, vuln_type, target_type) DO UPDATE SET
                        runs_total     = tool_performance.runs_total + 1,
                        runs_success   = tool_performance.runs_success + EXCLUDED.runs_success,
                        findings_total = tool_performance.findings_total + EXCLUDED.findings_total,
                        avg_duration_s = CASE
                            WHEN EXCLUDED.avg_duration_s > 0
                            THEN (tool_performance.avg_duration_s * tool_performance.runs_total
                                  + EXCLUDED.avg_duration_s)
                                 / (tool_performance.runs_total + 1)
                            ELSE tool_performance.avg_duration_s
                        END,
                        last_updated = EXCLUDED.last_updated
                    """,
                    (
                        data["tool_name"],
                        data.get("vuln_type", ""),
                        data.get("target_type", ""),
                        data.get("runs_success", 0),
                        data.get("findings_total", 0),
                        data.get("avg_duration_s", 0.0),
                        data.get("last_updated"),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.record_tool_run failed: %s", exc)
            raise

    async def get_best_tool_for_vuln(
        self, vuln_type: str, top_n: int = 3
    ) -> list:
        """Return top tools for a vuln_type ordered by findings/run ratio."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("get_best_tool_for_vuln requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    """
                    SELECT tool_name, runs_total, runs_success, findings_total, avg_duration_s
                    FROM tool_performance
                    WHERE vuln_type = %s AND runs_total > 0
                    ORDER BY CAST(findings_total AS FLOAT) / NULLIF(runs_total, 0) DESC
                    LIMIT %s
                    """,
                    (vuln_type, top_n),
                )
                result = []
                async for row in rows:
                    result.append({
                        "tool_name":     row[0],
                        "runs_total":    row[1],
                        "runs_success":  row[2],
                        "findings_total": row[3],
                        "avg_duration_s": row[4],
                    })
                return result
        except Exception as exc:
            log.warning("DBManager.get_best_tool_for_vuln failed: %s", exc)
            return []

    async def upsert_target_profile(self, data: dict) -> None:
        """Upsert a target profile, atomically incrementing scan_count."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("upsert_target_profile requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO target_profiles
                        (domain, tech_stack, waf_detected, scope_notes,
                         historical_vulns, last_scanned, scan_count)
                    VALUES (%s, %s, %s, %s, %s, %s, 1)
                    ON CONFLICT (domain) DO UPDATE SET
                        tech_stack       = EXCLUDED.tech_stack,
                        waf_detected     = EXCLUDED.waf_detected,
                        scope_notes      = EXCLUDED.scope_notes,
                        last_scanned     = EXCLUDED.last_scanned,
                        scan_count       = target_profiles.scan_count + 1
                    """,
                    (
                        data["domain"],
                        data.get("tech_stack", []),
                        data.get("waf_detected", ""),
                        data.get("scope_notes", ""),
                        data.get("historical_vulns", {}),
                        data.get("last_scanned"),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.upsert_target_profile failed: %s", exc)
            raise

    async def get_target_profile(self, domain: str) -> Optional[dict]:
        """Return one target profile row as a dict, or None."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("get_target_profile requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT * FROM target_profiles WHERE domain = %s",
                    (domain,),
                )
                async for row in rows:
                    return dict(row)
            return None
        except Exception as exc:
            log.warning("DBManager.get_target_profile failed: %s", exc)
            return None

    async def upsert_pattern(self, data: dict) -> None:
        """Upsert a vulnerability pattern, atomically incrementing occurrence_count
        and updating the weighted average CVSS score."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("upsert_pattern requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO pattern_library
                        (tech_stack_key, vuln_type, occurrence_count, avg_cvss,
                         best_tool, last_seen)
                    VALUES (%s, %s, 1, %s, %s, %s)
                    ON CONFLICT (tech_stack_key, vuln_type) DO UPDATE SET
                        occurrence_count = pattern_library.occurrence_count + 1,
                        avg_cvss = (
                            pattern_library.avg_cvss * pattern_library.occurrence_count
                            + EXCLUDED.avg_cvss
                        ) / (pattern_library.occurrence_count + 1),
                        best_tool = EXCLUDED.best_tool,
                        last_seen = EXCLUDED.last_seen
                    """,
                    (
                        data["tech_stack_key"],
                        data["vuln_type"],
                        data.get("avg_cvss", 0.0),
                        data.get("best_tool", ""),
                        data.get("last_seen"),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.upsert_pattern failed: %s", exc)
            raise

    async def get_patterns_for_tech_stack(self, tech_stack_key: str) -> list:
        """Return patterns for a tech_stack_key, highest frequency first."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("get_patterns_for_tech_stack requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT * FROM pattern_library WHERE tech_stack_key = %s "
                    "ORDER BY occurrence_count DESC LIMIT 20",
                    (tech_stack_key,),
                )
                result = []
                async for row in rows:
                    result.append(dict(row))
                return result
        except Exception as exc:
            log.warning("DBManager.get_patterns_for_tech_stack failed: %s", exc)
            return []

    async def get_learning_stats(self) -> dict:
        """Return aggregated learning statistics (sessions, findings, targets, top vulns/tools)."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("get_learning_stats requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                cur = await conn.execute(
                    "SELECT COUNT(*) FROM learning_scan_sessions"
                )
                sessions = 0
                async for row in cur:
                    sessions = row[0]

                cur = await conn.execute(
                    "SELECT COUNT(*) FROM learning_findings WHERE confirmed = 1"
                )
                findings = 0
                async for row in cur:
                    findings = row[0]

                cur = await conn.execute(
                    "SELECT COUNT(DISTINCT domain) FROM target_profiles"
                )
                targets = 0
                async for row in cur:
                    targets = row[0]

                cur = await conn.execute(
                    "SELECT vuln_type, COUNT(*) AS cnt FROM learning_findings "
                    "WHERE confirmed = 1 "
                    "GROUP BY vuln_type ORDER BY cnt DESC LIMIT 5"
                )
                top_vulns = []
                async for row in cur:
                    top_vulns.append({"vuln_type": row[0], "count": row[1]})

                cur = await conn.execute(
                    "SELECT tool_name, SUM(findings_total) AS total FROM tool_performance "
                    "GROUP BY tool_name ORDER BY total DESC LIMIT 5"
                )
                top_tools = []
                async for row in cur:
                    top_tools.append({"tool": row[0], "findings": row[1]})

            return {
                "sessions":          sessions,
                "confirmed_findings": findings,
                "unique_targets":    targets,
                "top_vuln_types":    top_vulns,
                "top_tools":         top_tools,
            }
        except Exception as exc:
            log.warning("DBManager.get_learning_stats failed: %s", exc)
            return {
                "sessions": 0, "confirmed_findings": 0, "unique_targets": 0,
                "top_vuln_types": [], "top_tools": [],
            }

    async def list_tool_performance(self) -> list:
        """Return all tool_performance rows with computed EMA (success rate)."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("list_tool_performance requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT tool_name, vuln_type, "
                    "CASE WHEN runs_total > 0 "
                    "     THEN runs_success::float / runs_total "
                    "     ELSE 0.0 END AS ema, "
                    "runs_total, findings_total "
                    "FROM tool_performance ORDER BY findings_total DESC"
                )
                result = []
                async for row in rows:
                    result.append({
                        "tool_name":     row[0],
                        "vuln_type":     row[1],
                        "ema":           row[2],
                        "runs_total":    row[3],
                        "findings_total": row[4],
                    })
                return result
        except Exception as exc:
            log.warning("DBManager.list_tool_performance failed: %s", exc)
            return []
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_db_manager_learning.py -v
```

Expected: all PASSes

- [ ] **Step 5: Run the full test suite to check for regressions**

```
pytest tests/ -x -q
```

Expected: no new failures

- [ ] **Step 6: Commit**

```bash
git add core/db_manager.py tests/test_db_manager_learning.py
git commit -m "feat(db-manager): add 12 async learning persistence methods"
```

---

## Task 3: LearningRepository — new core/learning_repository.py

**Files:**
- Create: `core/learning_repository.py`
- Test: `tests/test_learning_repository.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_learning_repository.py
"""Tests for LearningRepository — verifies delegation to DBManager mock."""
import asyncio
import time
import pytest
from unittest.mock import AsyncMock, MagicMock


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def make_repo():
    """LearningRepository backed by a fully mocked DBManager."""
    from core.learning_repository import LearningRepository
    db = MagicMock()
    db.save_learning_session = AsyncMock()
    db.get_learning_session = AsyncMock(return_value=None)
    db.list_learning_sessions = AsyncMock(return_value=[])
    db.save_learning_finding = AsyncMock()
    db.record_tool_run = AsyncMock()
    db.get_best_tool_for_vuln = AsyncMock(return_value=[])
    db.upsert_target_profile = AsyncMock()
    db.get_target_profile = AsyncMock(return_value=None)
    db.upsert_pattern = AsyncMock()
    db.get_patterns_for_tech_stack = AsyncMock(return_value=[])
    db.get_learning_stats = AsyncMock(return_value={
        "sessions": 0, "confirmed_findings": 0, "unique_targets": 0,
        "top_vuln_types": [], "top_tools": [],
    })
    db.list_tool_performance = AsyncMock(return_value=[])
    return LearningRepository(db), db


# ── start_session / finish_session ───────────────────────────────────────────

def test_start_session_calls_save_with_session_fields():
    repo, db = make_repo()
    run(repo.start_session("s1", "t.com", phases=["recon", "scan"]))
    db.save_learning_session.assert_called_once()
    d = db.save_learning_session.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["target"] == "t.com"
    assert d["phases"] == ["recon", "scan"]
    assert d["finished_at"] is None


def test_finish_session_calls_save_with_finish_fields():
    repo, db = make_repo()
    run(repo.finish_session("s1", total_findings=5, tools_used=["nuclei"]))
    db.save_learning_session.assert_called_once()
    d = db.save_learning_session.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["total_findings"] == 5
    assert d["tools_used"] == ["nuclei"]
    assert d["finished_at"] is not None


# ── record_finding / record_findings_bulk ────────────────────────────────────

def test_record_finding_extracts_fields_from_dict():
    repo, db = make_repo()
    finding = {
        "target": "t.com", "vuln_type": "sqli", "severity": "high",
        "cvss_score": 7.5, "endpoint": "/login", "parameter": "id",
        "source_tool": "sqlmap",
    }
    run(repo.record_finding("s1", finding, confirmed=True))
    db.save_learning_finding.assert_called_once()
    d = db.save_learning_finding.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["vuln_type"] == "sqli"
    assert d["confirmed"] == 1


def test_record_finding_confirmed_false_stores_zero():
    repo, db = make_repo()
    run(repo.record_finding("s1", {"vuln_type": "xss", "target": "t.com"}, confirmed=False))
    d = db.save_learning_finding.call_args[0][0]
    assert d["confirmed"] == 0


def test_record_findings_bulk_calls_save_per_finding():
    repo, db = make_repo()
    findings = [
        {"vuln_type": "xss", "target": "t.com"},
        {"vuln_type": "sqli", "target": "t.com"},
    ]
    run(repo.record_findings_bulk("s1", findings, confirmed=True))
    assert db.save_learning_finding.call_count == 2


# ── record_tool_run / best_tool_for_vuln ─────────────────────────────────────

def test_record_tool_run_passes_duration_s_field():
    repo, db = make_repo()
    run(repo.record_tool_run(
        tool_name="nuclei", vuln_type="xss", target_type="web",
        success=True, findings_count=3, duration_s=4.2,
    ))
    db.record_tool_run.assert_called_once()
    d = db.record_tool_run.call_args[0][0]
    assert d["tool_name"] == "nuclei"
    assert d["avg_duration_s"] == 4.2
    assert d["runs_success"] == 1


def test_record_tool_run_failure_stores_zero_success():
    repo, db = make_repo()
    run(repo.record_tool_run("nuclei", success=False))
    d = db.record_tool_run.call_args[0][0]
    assert d["runs_success"] == 0


def test_best_tool_for_vuln_returns_empty_list_when_no_data():
    repo, db = make_repo()
    result = run(repo.best_tool_for_vuln("xss", top_n=1))
    assert result == []


# ── upsert_target_profile / get_target_profile ───────────────────────────────

def test_upsert_target_profile_passes_domain_and_tech_stack():
    repo, db = make_repo()
    run(repo.upsert_target_profile("t.com", tech_stack=["WordPress", "MySQL"]))
    db.upsert_target_profile.assert_called_once()
    d = db.upsert_target_profile.call_args[0][0]
    assert d["domain"] == "t.com"
    assert "WordPress" in d["tech_stack"]


def test_get_target_profile_returns_none_when_not_found():
    repo, db = make_repo()
    result = run(repo.get_target_profile("missing.com"))
    assert result is None


# ── upsert_pattern / patterns_for_tech_stack ─────────────────────────────────

def test_upsert_pattern_builds_tech_stack_key():
    repo, db = make_repo()
    run(repo.upsert_pattern(["WordPress", "MySQL"], "sqli", cvss=7.0, best_tool="sqlmap"))
    db.upsert_pattern.assert_called_once()
    d = db.upsert_pattern.call_args[0][0]
    # key is sorted, lowercased, comma-joined
    assert d["tech_stack_key"] == "mysql,wordpress"
    assert d["vuln_type"] == "sqli"
    assert d["avg_cvss"] == 7.0


def test_patterns_for_tech_stack_builds_key():
    repo, db = make_repo()
    run(repo.patterns_for_tech_stack(["WordPress", "MySQL"]))
    db.get_patterns_for_tech_stack.assert_called_once_with("mysql,wordpress")


# ── stats / recent_sessions / get_tool_performance_stats ─────────────────────

def test_stats_returns_dict():
    repo, db = make_repo()
    result = run(repo.stats())
    assert "sessions" in result
    assert "confirmed_findings" in result


def test_recent_sessions_passes_limit():
    repo, db = make_repo()
    run(repo.recent_sessions(limit=5))
    db.list_learning_sessions.assert_called_once_with(5)


def test_get_tool_performance_stats_returns_list():
    repo, db = make_repo()
    result = run(repo.get_tool_performance_stats())
    assert result == []


def test_close_is_a_noop():
    repo, db = make_repo()
    repo.close()  # must not raise


# ── Sync wrappers ─────────────────────────────────────────────────────────────

def test_start_session_sync_calls_db():
    repo, db = make_repo()
    repo.start_session_sync("s1", "t.com")
    db.save_learning_session.assert_called_once()


def test_finish_session_sync_calls_db():
    repo, db = make_repo()
    repo.finish_session_sync("s1", total_findings=3)
    db.save_learning_session.assert_called_once()


def test_record_finding_sync_calls_db():
    repo, db = make_repo()
    repo.record_finding_sync("s1", {"vuln_type": "xss", "target": "t.com"})
    db.save_learning_finding.assert_called_once()


def test_record_tool_run_sync_calls_db():
    repo, db = make_repo()
    repo.record_tool_run_sync("nuclei")
    db.record_tool_run.assert_called_once()


def test_best_tool_for_vuln_sync_returns_list():
    repo, db = make_repo()
    result = repo.best_tool_for_vuln_sync("xss")
    assert isinstance(result, list)


def test_get_target_profile_sync_returns_none_for_missing():
    repo, db = make_repo()
    assert repo.get_target_profile_sync("missing.com") is None


def test_get_tool_performance_stats_sync_returns_list():
    repo, db = make_repo()
    assert repo.get_tool_performance_stats_sync() == []
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_learning_repository.py -v
```

Expected: all FAILs — `ModuleNotFoundError: No module named 'core.learning_repository'`

- [ ] **Step 3: Create core/learning_repository.py**

```python
# core/learning_repository.py
"""
LearningRepository — async repository for continuous learning persistence.

All storage routes through DBManager → PostgreSQL.
Sync wrappers (method_sync) allow use from synchronous callers
(unified_scan_engine, intelligence_daemon, pattern_miner, swarm engines).
"""
from __future__ import annotations

import time
from typing import Optional

from core.db_manager import DBManager, get_db_manager, get_db_manager_sync


class LearningRepository:
    def __init__(self, db: DBManager) -> None:
        self._db = db

    # ── Session lifecycle ─────────────────────────────────────────────────────

    async def start_session(
        self, session_id: str, target: str, phases: list = None
    ) -> None:
        """Record the start of a scan session."""
        await self._db.save_learning_session({
            "session_id":     session_id,
            "target":         target,
            "started_at":     time.time(),
            "finished_at":    None,
            "phases":         phases or [],
            "total_findings": 0,
            "tools_used":     [],
            "notes":          "",
        })

    async def finish_session(
        self,
        session_id: str,
        total_findings: int,
        tools_used: list = None,
        notes: str = "",
    ) -> None:
        """Record the end of a scan session (upsert updates only finish fields)."""
        await self._db.save_learning_session({
            "session_id":     session_id,
            "target":         "",       # ignored on conflict — preserved from start
            "started_at":     0.0,      # ignored on conflict
            "finished_at":    time.time(),
            "phases":         [],       # ignored on conflict
            "total_findings": total_findings,
            "tools_used":     tools_used or [],
            "notes":          notes,
        })

    def start_session_sync(
        self, session_id: str, target: str, phases: list = None
    ) -> None:
        DBManager._run_sync(self.start_session(session_id, target, phases))

    def finish_session_sync(
        self,
        session_id: str,
        total_findings: int,
        tools_used: list = None,
        notes: str = "",
    ) -> None:
        DBManager._run_sync(
            self.finish_session(session_id, total_findings, tools_used, notes)
        )

    # ── Findings ──────────────────────────────────────────────────────────────

    async def record_finding(
        self, session_id: str, finding: dict, confirmed: bool = True
    ) -> None:
        """Insert one finding row, extracting fields from the finding dict."""
        await self._db.save_learning_finding({
            "session_id":   session_id,
            "target":       finding.get("target", ""),
            "vuln_type":    finding.get("vuln_type", "unknown"),
            "severity":     finding.get("severity", "info"),
            "cvss_score":   finding.get("cvss_score"),
            "endpoint":     finding.get(
                "matched_at", finding.get("url", finding.get("endpoint", ""))
            ),
            "parameter":    finding.get("parameter", ""),
            "source_tool":  finding.get("source_tool", ""),
            "confirmed":    1 if confirmed else 0,
            "chain_id":     finding.get("chain_id", ""),
            "discovered_at": time.time(),
        })

    async def record_findings_bulk(
        self, session_id: str, findings: list, confirmed: bool = True
    ) -> None:
        """Insert multiple findings, silently skipping failures."""
        for f in findings:
            try:
                await self.record_finding(session_id, f, confirmed)
            except Exception:
                pass

    def record_finding_sync(
        self, session_id: str, finding: dict, confirmed: bool = True
    ) -> None:
        DBManager._run_sync(self.record_finding(session_id, finding, confirmed))

    def record_findings_bulk_sync(
        self, session_id: str, findings: list, confirmed: bool = True
    ) -> None:
        DBManager._run_sync(
            self.record_findings_bulk(session_id, findings, confirmed)
        )

    # ── Tool performance ──────────────────────────────────────────────────────

    async def record_tool_run(
        self,
        tool_name: str,
        vuln_type: str = "",
        target_type: str = "",
        success: bool = True,
        findings_count: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        await self._db.record_tool_run({
            "tool_name":     tool_name,
            "vuln_type":     vuln_type,
            "target_type":   target_type,
            "runs_success":  1 if success else 0,
            "findings_total": findings_count,
            "avg_duration_s": duration_s,
            "last_updated":  time.time(),
        })

    async def best_tool_for_vuln(
        self, vuln_type: str, top_n: int = 3
    ) -> list:
        """Return top tools for vuln_type as list of dicts (tool_name, runs_total, …)."""
        return await self._db.get_best_tool_for_vuln(vuln_type, top_n)

    def record_tool_run_sync(
        self,
        tool_name: str,
        vuln_type: str = "",
        target_type: str = "",
        success: bool = True,
        findings_count: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        DBManager._run_sync(
            self.record_tool_run(
                tool_name, vuln_type, target_type, success, findings_count, duration_s
            )
        )

    def best_tool_for_vuln_sync(
        self, vuln_type: str, top_n: int = 3
    ) -> list:
        return DBManager._run_sync(self.best_tool_for_vuln(vuln_type, top_n))

    # ── Target profiles ───────────────────────────────────────────────────────

    async def upsert_target_profile(
        self,
        domain: str,
        tech_stack: list = None,
        waf: str = "",
        scope_notes: str = "",
    ) -> None:
        await self._db.upsert_target_profile({
            "domain":          domain,
            "tech_stack":      tech_stack or [],
            "waf_detected":    waf,
            "scope_notes":     scope_notes,
            "historical_vulns": {},
            "last_scanned":    time.time(),
        })

    async def get_target_profile(self, domain: str) -> Optional[dict]:
        return await self._db.get_target_profile(domain)

    def upsert_target_profile_sync(
        self,
        domain: str,
        tech_stack: list = None,
        waf: str = "",
        scope_notes: str = "",
    ) -> None:
        DBManager._run_sync(
            self.upsert_target_profile(domain, tech_stack, waf, scope_notes)
        )

    def get_target_profile_sync(self, domain: str) -> Optional[dict]:
        return DBManager._run_sync(self.get_target_profile(domain))

    # ── Pattern library ───────────────────────────────────────────────────────

    async def upsert_pattern(
        self,
        tech_stack: list,
        vuln_type: str,
        cvss: float = 0.0,
        best_tool: str = "",
    ) -> None:
        key = ",".join(sorted(t.lower() for t in tech_stack))
        await self._db.upsert_pattern({
            "tech_stack_key": key,
            "vuln_type":      vuln_type,
            "avg_cvss":       cvss,
            "best_tool":      best_tool,
            "last_seen":      time.time(),
        })

    async def patterns_for_tech_stack(self, tech_stack: list) -> list:
        key = ",".join(sorted(t.lower() for t in tech_stack))
        return await self._db.get_patterns_for_tech_stack(key)

    def upsert_pattern_sync(
        self,
        tech_stack: list,
        vuln_type: str,
        cvss: float = 0.0,
        best_tool: str = "",
    ) -> None:
        DBManager._run_sync(
            self.upsert_pattern(tech_stack, vuln_type, cvss, best_tool)
        )

    def patterns_for_tech_stack_sync(self, tech_stack: list) -> list:
        return DBManager._run_sync(self.patterns_for_tech_stack(tech_stack))

    # ── Analytics ─────────────────────────────────────────────────────────────

    async def stats(self) -> dict:
        return await self._db.get_learning_stats()

    async def recent_sessions(self, limit: int = 10) -> list:
        return await self._db.list_learning_sessions(limit)

    async def get_tool_performance_stats(self) -> list:
        return await self._db.list_tool_performance()

    def stats_sync(self) -> dict:
        return DBManager._run_sync(self.stats())

    def recent_sessions_sync(self, limit: int = 10) -> list:
        return DBManager._run_sync(self.recent_sessions(limit))

    def get_tool_performance_stats_sync(self) -> list:
        return DBManager._run_sync(self.get_tool_performance_stats())

    # ── Compatibility ─────────────────────────────────────────────────────────

    def close(self) -> None:
        """No-op — DBManager owns the connection pool."""
        pass


async def get_learning_repo() -> LearningRepository:
    """Async factory — use with FastAPI Depends or asyncio.run."""
    return LearningRepository(await get_db_manager())


def get_learning_repo_sync() -> LearningRepository:
    """Sync factory — use from synchronous callers."""
    return LearningRepository(get_db_manager_sync())
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_learning_repository.py -v
```

Expected: all PASSes

- [ ] **Step 5: Run the full test suite**

```
pytest tests/ -x -q
```

Expected: no new failures

- [ ] **Step 6: Commit**

```bash
git add core/learning_repository.py tests/test_learning_repository.py
git commit -m "feat(learning-repo): add LearningRepository backed by DBManager/PostgreSQL"
```

---

## Task 4: Update unified_scan_engine.py

**Files:**
- Modify: `unified_scan_engine.py` (~lines 591, 596, 602, 607, 991, 1327, 2290, 2341, 2343)

- [ ] **Step 1: Replace the KnowledgeBase instantiation (line ~591–593)**

Find:
```python
            from learning.knowledge_base import KnowledgeBase
            from urllib.parse import urlparse as _urlparse
            kb = KnowledgeBase()
```

Replace with:
```python
            from core.learning_repository import get_learning_repo_sync
            from urllib.parse import urlparse as _urlparse
            kb = get_learning_repo_sync()
```

- [ ] **Step 2: Rename all synchronous call sites to `_sync` versions**

Find and replace each of the following (they are in separate try/except blocks, not consecutive):

**Line ~596** — start_session call:
```python
            kb.start_session(
```
→
```python
            kb.start_session_sync(
```

**Line ~602** — get_target_profile call:
```python
            prior = kb.get_target_profile(domain)
```
→
```python
            prior = kb.get_target_profile_sync(domain)
```

**Line ~607** — upsert_target_profile call:
```python
            kb.upsert_target_profile(domain, tech_stack=tech_stack)
```
→
```python
            kb.upsert_target_profile_sync(domain, tech_stack=tech_stack)
```

**Line ~991** — best_tool_for_vuln call:
```python
                    best = kb.best_tool_for_vuln(vp.vuln_type, top_n=1)
```
→
```python
                    best = kb.best_tool_for_vuln_sync(vp.vuln_type, top_n=1)
```

**Line ~1327** — record_tool_run call:
```python
                        _kb.record_tool_run(
                            tool_name=tool_name,
                            target_type=session.target_type or "web",
                            success=_tool_success,
                            findings_count=len(_tool_result),
                            duration_s=round(_tool_duration, 2),
                        )
```
→
```python
                        _kb.record_tool_run_sync(
                            tool_name=tool_name,
                            target_type=session.target_type or "web",
                            success=_tool_success,
                            findings_count=len(_tool_result),
                            duration_s=round(_tool_duration, 2),
                        )
```

**Line ~2290** — finish_session call (no findings path):
```python
                    _kb.finish_session(ctx.get("kb_session_id", session.scan_id),
                                       total_findings=0, tools_used=[])
```
→
```python
                    _kb.finish_session_sync(ctx.get("kb_session_id", session.scan_id),
                                            total_findings=0, tools_used=[])
```

**Line ~2341** — record_findings_bulk call:
```python
                    _kb.record_findings_bulk(_kb_sid, findings)
```
→
```python
                    _kb.record_findings_bulk_sync(_kb_sid, findings)
```

**Line ~2343** — finish_session call (with findings):
```python
                    _kb.finish_session(_kb_sid,
                                       total_findings=len(ingested),
                                       tools_used=_tools_used)
```
→
```python
                    _kb.finish_session_sync(_kb_sid,
                                            total_findings=len(ingested),
                                            tools_used=_tools_used)
```

- [ ] **Step 3: Verify no remaining KnowledgeBase references in unified_scan_engine.py**

```bash
grep -n "KnowledgeBase\|\.kb\b" unified_scan_engine.py
```

Expected: no output (or only comments)

- [ ] **Step 4: Run the full test suite**

```
pytest tests/ -x -q
```

Expected: no new failures

- [ ] **Step 5: Commit**

```bash
git add unified_scan_engine.py
git commit -m "feat(unified-scan): replace KnowledgeBase with LearningRepository"
```

---

## Task 5: Update all remaining callers

**Files:**
- Modify: `intelligence_daemon.py` (~lines 738–759)
- Modify: `learning/pattern_miner.py` (lines 81, 105, 120, 123, 144, 147)
- Modify: `agent_swarm_coordinator.py` (~lines 48–57, 436, 441)
- Modify: `swarm_intelligence_engine.py` (~lines 53–57, 416, 436, 441)
- Modify: `attack_simulation_engine.py` (~lines 52–57, 416)
- Modify: `web/backend/main.py` (~lines 2879–2888)
- Modify: `learning/__init__.py` (lines 5, 17)

- [ ] **Step 1: Update intelligence_daemon.py**

Find in `_learn()` method (~line 737–759):
```python
        try:
            from learning.knowledge_base import KnowledgeBase
            kb = KnowledgeBase()
            if event.event_type == EventType.NEW_VULNERABILITY:
                sid = d.get("session_id", f"daemon_{int(time.time())}")
                kb.record_finding(sid, {
                    "vuln_type":   d.get("vuln_type", "unknown"),
                    "severity":    d.get("severity", "info"),
                    "cvss_score":  d.get("cvss", 0.0),
                    "endpoint":    d.get("endpoint", ""),
                    "source_tool": d.get("source", "daemon"),
                    "target":      d.get("target", ""),
                }, confirmed=True)
            elif event.event_type == EventType.EXPLOIT_ATTEMPTED:
                kb.record_tool_run(
                    tool_name=d.get("tool", "exploit_engine"),
                    vuln_type=d.get("vuln_type", ""),
                    target_type="web",
                    success=d.get("success", False),
                    findings_count=1 if d.get("success") else 0,
                    duration_s=d.get("duration_s", 0.0),
                )
        except Exception as exc:
            log.debug("[LearningWorker] KB update failed: %s", exc)
```

Replace with:
```python
        try:
            from core.learning_repository import get_learning_repo_sync
            kb = get_learning_repo_sync()
            if event.event_type == EventType.NEW_VULNERABILITY:
                sid = d.get("session_id", f"daemon_{int(time.time())}")
                kb.record_finding_sync(sid, {
                    "vuln_type":   d.get("vuln_type", "unknown"),
                    "severity":    d.get("severity", "info"),
                    "cvss_score":  d.get("cvss", 0.0),
                    "endpoint":    d.get("endpoint", ""),
                    "source_tool": d.get("source", "daemon"),
                    "target":      d.get("target", ""),
                }, confirmed=True)
            elif event.event_type == EventType.EXPLOIT_ATTEMPTED:
                kb.record_tool_run_sync(
                    tool_name=d.get("tool", "exploit_engine"),
                    vuln_type=d.get("vuln_type", ""),
                    target_type="web",
                    success=d.get("success", False),
                    findings_count=1 if d.get("success") else 0,
                    duration_s=d.get("duration_s", 0.0),
                )
        except Exception as exc:
            log.debug("[LearningWorker] KB update failed: %s", exc)
```

- [ ] **Step 2: Update learning/pattern_miner.py**

All 5 call sites use `self.kb.*`. Add `_sync` suffix to each:

```python
# Line ~81: seed patterns
self.kb.upsert_pattern(tech_stack, vuln_type, cvss=5.0, best_tool=tool)
```
→
```python
self.kb.upsert_pattern_sync(tech_stack, vuln_type, cvss=5.0, best_tool=tool)
```

```python
# Line ~105: record tool performance after learning
self.kb.record_tool_run(
    tool_name=tool_name,
    vuln_type=perf.get("vuln_type", ""),
```
→
```python
self.kb.record_tool_run_sync(
    tool_name=tool_name,
    vuln_type=perf.get("vuln_type", ""),
```

```python
# Line ~120: upsert pattern from findings
self.kb.upsert_pattern(tech, vuln_type, cvss=cvss, best_tool=source)
```
→
```python
self.kb.upsert_pattern_sync(tech, vuln_type, cvss=cvss, best_tool=source)
```

```python
# Line ~123: update target profile
self.kb.upsert_target_profile(target, tech_stack=tech)
```
→
```python
self.kb.upsert_target_profile_sync(target, tech_stack=tech)
```

```python
# Line ~144: get target profile
profile = self.kb.get_target_profile(target)
```
→
```python
profile = self.kb.get_target_profile_sync(target)
```

```python
# Line ~147: get patterns for stack
patterns_raw = self.kb.patterns_for_tech_stack(tech)
```
→
```python
patterns_raw = self.kb.patterns_for_tech_stack_sync(tech)
```

- [ ] **Step 3: Update agent_swarm_coordinator.py**

Replace the top-level try/except import block (~lines 47–57):
```python
try:
    from learning.knowledge_base import KnowledgeBase
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False
    KnowledgeBase = None  # type: ignore
```
→
```python
try:
    from core.learning_repository import get_learning_repo_sync as _get_learning_repo_sync
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False
    _get_learning_repo_sync = None  # type: ignore
```

Replace `_try_load_kb()` body:
```python
    @staticmethod
    def _try_load_kb():
        if not _KB_AVAILABLE:
            return None
        try:
            return KnowledgeBase()
        except Exception:
            return None
```
→
```python
    @staticmethod
    def _try_load_kb():
        if not _KB_AVAILABLE:
            return None
        try:
            return _get_learning_repo_sync()
        except Exception:
            return None
```

In `SwarmAgent.learn_from_results()` or wherever `record_finding` and `record_tool_run` are called on `self.knowledge_base` (~lines 436, 441):
```python
                    self.knowledge_base.record_finding(
```
→
```python
                    self.knowledge_base.record_finding_sync(
```

```python
                    self.knowledge_base.record_tool_run(
```
→
```python
                    self.knowledge_base.record_tool_run_sync(
```

- [ ] **Step 4: Update swarm_intelligence_engine.py**

Replace the top-level try/except import block (~lines 52–57):
```python
try:
    from learning.knowledge_base import KnowledgeBase
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False
    KnowledgeBase = None  # type: ignore
```
→
```python
try:
    from core.learning_repository import get_learning_repo_sync as _get_learning_repo_sync
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False
    _get_learning_repo_sync = None  # type: ignore
```

Replace `_try_load_kb()` (same pattern as above):
```python
        try:
            return KnowledgeBase()
        except Exception:
            return None
```
→
```python
        try:
            return _get_learning_repo_sync()
        except Exception:
            return None
```

Rename all `self.knowledge_base.*` calls in `learn_from_results()` to `_sync` versions:
```python
                    self.knowledge_base.record_finding(
```
→
```python
                    self.knowledge_base.record_finding_sync(
```

```python
                    self.knowledge_base.record_tool_run(
```
→
```python
                    self.knowledge_base.record_tool_run_sync(
```

```python
            tools = self.knowledge_base.best_tool_for_vuln(base_type, top_n=1)
```
→
```python
            tools = self.knowledge_base.best_tool_for_vuln_sync(base_type, top_n=1)
```

- [ ] **Step 5: Update attack_simulation_engine.py**

Replace the top-level try/except import block (~lines 52–57):
```python
try:
    from learning.knowledge_base import KnowledgeBase
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False
```
→
```python
try:
    from core.learning_repository import get_learning_repo_sync as _get_learning_repo_sync
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False
    _get_learning_repo_sync = None  # type: ignore
```

In `_load_kb_rates()` (~line 416), rename the call:
```python
            tools = self.knowledge_base.best_tool_for_vuln(base_type, top_n=1)
```
→
```python
            tools = self.knowledge_base.best_tool_for_vuln_sync(base_type, top_n=1)
```

- [ ] **Step 6: Update web/backend/main.py**

Find in `learning_stats()` function (~lines 2879–2888):
```python
        # Also pull per-agent EMA rates from KnowledgeBase tool_performance table
        from learning.knowledge_base import KnowledgeBase
        from path_manager import db_path as _db_path_fn
        kb = KnowledgeBase(str(_db_path_fn("knowledge_base.db")))
        rows = kb._conn.execute(
            "SELECT tool_name, vuln_type, "
            "CASE WHEN runs_total > 0 THEN CAST(runs_success AS REAL)/runs_total ELSE 0 END as ema, "
            "runs_total, findings_total "
            "FROM tool_performance ORDER BY findings_total DESC"
        ).fetchall()
        kb.close()
        vuln_type_stats: dict = {}
        for tool, vtype, ema, runs, findings in rows:
```

Replace with:
```python
        # Pull per-agent EMA rates from tool_performance via DBManager
        from core.learning_repository import get_learning_repo_sync
        _repo = get_learning_repo_sync()
        perf_rows = _repo.get_tool_performance_stats_sync()
        vuln_type_stats: dict = {}
        for _row in perf_rows:
            tool, vtype, ema, runs, findings = (
                _row["tool_name"], _row["vuln_type"], _row["ema"],
                _row["runs_total"], _row["findings_total"],
            )
```

Also remove the stale `for tool, vtype, ema, runs, findings in rows:` line that follows (it's now replaced by the `for _row in perf_rows:` block above).

- [ ] **Step 7: Update learning/__init__.py**

Find:
```python
from learning.knowledge_base import KnowledgeBase
```
Delete that line.

Find in `__all__`:
```python
    "KnowledgeBase",
```
Delete that line.

- [ ] **Step 8: Verify no remaining KnowledgeBase imports**

```bash
grep -rn "from learning.knowledge_base import\|import KnowledgeBase" \
  intelligence_daemon.py learning/pattern_miner.py \
  agent_swarm_coordinator.py swarm_intelligence_engine.py \
  attack_simulation_engine.py web/backend/main.py learning/__init__.py
```

Expected: no output

- [ ] **Step 9: Run the full test suite**

```
pytest tests/ -x -q
```

Expected: no new failures

- [ ] **Step 10: Commit**

```bash
git add intelligence_daemon.py learning/pattern_miner.py \
        agent_swarm_coordinator.py swarm_intelligence_engine.py \
        attack_simulation_engine.py web/backend/main.py learning/__init__.py
git commit -m "feat(learning): wire LearningRepository into all 7 callers"
```

---

## Task 6: Delete knowledge_base.py + static removal tests

**Files:**
- Delete: `learning/knowledge_base.py`
- Test: `tests/test_learning_kb_removed.py`

- [ ] **Step 1: Write the failing tests** (they must fail before deletion)

```python
# tests/test_learning_kb_removed.py
"""
Static checks: KnowledgeBase and sqlite3 are fully gone from the learning module.
These tests fail before deletion and pass after.
"""
import ast
from pathlib import Path


def test_knowledge_base_file_is_deleted():
    assert not Path("learning/knowledge_base.py").exists(), (
        "learning/knowledge_base.py must be deleted"
    )


def test_learning_init_does_not_import_knowledge_base():
    source = Path("learning/__init__.py").read_text()
    assert "KnowledgeBase" not in source, (
        "learning/__init__.py must not import or export KnowledgeBase"
    )


def test_no_sqlite3_import_in_learning_module():
    """No file under learning/ may import sqlite3."""
    learning_dir = Path("learning")
    for py_file in learning_dir.glob("*.py"):
        source = py_file.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "sqlite3", (
                        f"sqlite3 must not be imported in {py_file}"
                    )
            if isinstance(node, ast.ImportFrom):
                assert node.module != "sqlite3", (
                    f"sqlite3 must not be imported in {py_file}"
                )


def test_no_raw_conn_access_in_main():
    """web/backend/main.py must not use kb._conn (raw SQLite access)."""
    source = Path("web/backend/main.py").read_text()
    assert "kb._conn" not in source, (
        "web/backend/main.py must not access kb._conn directly"
    )
    assert "knowledge_base.py" not in source, (
        "web/backend/main.py must not reference learning/knowledge_base.py"
    )
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_learning_kb_removed.py -v
```

Expected: FAILs — `test_knowledge_base_file_is_deleted` and possibly others

- [ ] **Step 3: Delete learning/knowledge_base.py**

```bash
rm learning/knowledge_base.py
```

- [ ] **Step 4: Run the static tests to verify they pass**

```
pytest tests/test_learning_kb_removed.py -v
```

Expected: all 4 PASSes

- [ ] **Step 5: Run the full test suite**

```
pytest tests/ -x -q
```

Expected: no failures (the deleted file had no tests of its own)

- [ ] **Step 6: Final commit**

```bash
git add tests/test_learning_kb_removed.py
git rm learning/knowledge_base.py
git commit -m "feat(learning): delete KnowledgeBase SQLite class — migration to PostgreSQL complete"
```
