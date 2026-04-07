# Research KB PostgreSQL Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete `ResearchKnowledgeBase` (SQLite) from `research_mode_controller.py` and replace it with `ResearchRepository` backed by DBManager/PostgreSQL.

**Architecture:** `ResearchModeController` gets a `ResearchRepository` synchronously (via `get_db_manager_sync()`) and calls sync wrappers on all 10 call sites. `ResearchRepository` wraps 10 new async `DBManager` methods. All research storage routes through PostgreSQL exclusively.

**Tech Stack:** psycopg3 async pool, `DBManager._run_sync()` sync-wrapper pattern, pytest + `unittest.mock`

---

### Task 1: Add 6 research tables to db/schema.sql

**Files:**
- Modify: `db/schema.sql` (append after the `idx_targets_created_at` index at end of file)

- [ ] **Step 1: Append 6 tables to db/schema.sql**

Append after the last line of `db/schema.sql` (after `CREATE INDEX IF NOT EXISTS idx_targets_created_at ON targets(created_at);`):

```sql

-- ── Research Sessions ────────────────────────────────────────────────────────
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

-- ── Vulnerability Theories ───────────────────────────────────────────────────
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

-- ── Test Outcomes ────────────────────────────────────────────────────────────
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

-- ── Research Discoveries ─────────────────────────────────────────────────────
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

-- ── Cross-Target Patterns ────────────────────────────────────────────────────
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

-- ── Endpoint Insights (schema present; no active write path) ─────────────────
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

- [ ] **Step 2: Verify all 6 tables are present**

```bash
python3 -c "
import re
sql = open('db/schema.sql').read()
tables = re.findall(r'CREATE TABLE IF NOT EXISTS (\w+)', sql)
for t in ['research_sessions','vuln_theories','test_outcomes','research_discoveries','cross_target_patterns','endpoint_insights']:
    assert t in tables, f'Missing table: {t}'
print('All 6 research tables present:', [t for t in tables if 'research' in t or t in ('vuln_theories','test_outcomes','cross_target_patterns','endpoint_insights')])
"
```

Expected: prints all 6 table names.

- [ ] **Step 3: Commit**

```bash
git add db/schema.sql
git commit -m "feat(schema): add 6 research tables to PostgreSQL schema"
```

---

### Task 2: Add 10 DBManager research methods

**Files:**
- Modify: `core/db_manager.py` (insert `# ── Research ──` section before line 648 `# ── Sync wrappers for CLI ──`)
- Create: `tests/test_db_manager_research.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_db_manager_research.py`:

```python
# tests/test_db_manager_research.py
"""Tests for DBManager research persistence methods."""
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

def test_save_research_session_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_research_session({"session_id": "s1", "target": "t.com"}))


def test_get_research_session_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_research_session("s1"))


def test_list_research_sessions_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.list_research_sessions())


def test_save_research_theory_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_research_theory({"theory_id": "t1", "session_id": "s1",
                                       "target": "t.com", "vuln_type": "xss"}))


def test_update_research_theory_status_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.update_research_theory_status("t1", "confirmed", 1.0))


def test_save_test_outcome_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_test_outcome({"session_id": "s1", "target": "t.com", "vuln_type": "sqli"}))


def test_save_research_discovery_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.save_research_discovery({"report_id": "r1", "session_id": "s1",
                                          "target": "t.com", "vuln_type": "xss"}))


def test_list_research_discoveries_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.list_research_discoveries())


def test_upsert_cross_target_pattern_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.upsert_cross_target_pattern({"vuln_type": "xss",
                                              "endpoint_pattern": "/api/{id}"}))


def test_get_cross_target_patterns_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises(RuntimeError, match="requires Postgres mode"):
        run(mgr.get_cross_target_patterns())


# ── Postgres mock tests ───────────────────────────────────────────────────────

def test_save_research_session_pg():
    mgr, conn = pg_mgr()
    run(mgr.save_research_session({"session_id": "s1", "target": "t.com"}))
    assert conn.commit.called


def test_get_research_session_returns_none_when_not_found():
    mgr, _ = pg_mgr(rows=[])
    result = run(mgr.get_research_session("missing"))
    assert result is None


def test_get_research_session_returns_dict_when_found():
    row = {"session_id": "s1", "target": "t.com", "status": "running"}
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.get_research_session("s1"))
    assert result["session_id"] == "s1"
    assert result["target"] == "t.com"


def test_list_research_sessions_returns_empty_list():
    mgr, _ = pg_mgr(rows=[])
    result = run(mgr.list_research_sessions())
    assert result == []


def test_list_research_sessions_with_target_filter():
    row = {"session_id": "s1", "target": "t.com"}
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.list_research_sessions(target="t.com"))
    assert len(result) == 1
    assert result[0]["target"] == "t.com"


def test_save_research_theory_pg():
    mgr, conn = pg_mgr()
    run(mgr.save_research_theory({
        "theory_id": "th1", "session_id": "s1", "target": "t.com",
        "vuln_type": "xss", "endpoint": "/search",
    }))
    assert conn.commit.called


def test_update_research_theory_status_pg():
    mgr, conn = pg_mgr()
    run(mgr.update_research_theory_status("th1", "confirmed", 1234.0))
    assert conn.commit.called


def test_save_test_outcome_pg():
    mgr, conn = pg_mgr()
    run(mgr.save_test_outcome({
        "session_id": "s1", "target": "t.com", "vuln_type": "sqli",
        "endpoint": "/api", "payload": "' OR 1=1",
    }))
    assert conn.commit.called


def test_save_research_discovery_pg():
    mgr, conn = pg_mgr()
    run(mgr.save_research_discovery({
        "report_id": "r1", "session_id": "s1", "target": "t.com",
        "vuln_type": "xss", "title": "Stored XSS", "steps": ["step1"],
    }))
    assert conn.commit.called


def test_list_research_discoveries_pg():
    row = {"report_id": "r1", "session_id": "s1", "vuln_type": "xss",
           "target": "t.com", "steps": ["step1"]}
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.list_research_discoveries())
    assert len(result) == 1
    assert result[0]["report_id"] == "r1"


def test_upsert_cross_target_pattern_pg():
    mgr, conn = pg_mgr()
    run(mgr.upsert_cross_target_pattern({
        "vuln_type": "xss", "endpoint_pattern": "/api/{id}",
        "parameter_pattern": "q",
    }))
    assert conn.commit.called


def test_get_cross_target_patterns_pg():
    row = {"vuln_type": "xss", "endpoint_pattern": "/api/{id}", "success_count": 3}
    mgr, _ = pg_mgr(rows=[row])
    result = run(mgr.get_cross_target_patterns(min_count=2))
    assert len(result) == 1
    assert result[0]["success_count"] == 3
```

- [ ] **Step 2: Run tests, confirm they all fail**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest tests/test_db_manager_research.py -v 2>&1 | head -40
```

Expected: All fail with `AttributeError` (methods don't exist yet).

- [ ] **Step 3: Add the Research section to core/db_manager.py**

Insert the following block immediately before line 648 (`    # ── Sync wrappers for CLI ─────────────────────────────────────────────────`):

```python
    # ── Research ──────────────────────────────────────────────────────────────

    async def save_research_session(self, data: dict) -> None:
        """Upsert a research session row."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("save_research_session requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO research_sessions (
                        session_id, target, output_dir, platform, started_at, ended_at,
                        status, iteration, theories_generated, tests_executed,
                        anomalies_found, confirmed_vulns
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (session_id) DO UPDATE SET
                        target             = EXCLUDED.target,
                        output_dir         = EXCLUDED.output_dir,
                        platform           = EXCLUDED.platform,
                        started_at         = EXCLUDED.started_at,
                        ended_at           = EXCLUDED.ended_at,
                        status             = EXCLUDED.status,
                        iteration          = EXCLUDED.iteration,
                        theories_generated = EXCLUDED.theories_generated,
                        tests_executed     = EXCLUDED.tests_executed,
                        anomalies_found    = EXCLUDED.anomalies_found,
                        confirmed_vulns    = EXCLUDED.confirmed_vulns
                    """,
                    (
                        data["session_id"],
                        data["target"],
                        data.get("output_dir", ""),
                        data.get("platform", ""),
                        data.get("started_at"),
                        data.get("ended_at"),
                        data.get("status", "running"),
                        data.get("iteration", 0),
                        data.get("theories_generated", 0),
                        data.get("tests_executed", 0),
                        data.get("anomalies_found", 0),
                        data.get("confirmed_vulns", 0),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.save_research_session failed: %s", exc)
            raise

    async def get_research_session(self, session_id: str) -> Optional[dict]:
        """Return one research session row as a dict, or None."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("get_research_session requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT * FROM research_sessions WHERE session_id = %s",
                    (session_id,),
                )
                async for row in rows:
                    return dict(row)
            return None
        except Exception as exc:
            log.warning("DBManager.get_research_session failed: %s", exc)
            return None

    async def list_research_sessions(self, target: str = None) -> list:
        """List research sessions, optionally filtered by target."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("list_research_sessions requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                if target:
                    rows = await conn.execute(
                        "SELECT * FROM research_sessions WHERE target = %s "
                        "ORDER BY started_at DESC",
                        (target,),
                    )
                else:
                    rows = await conn.execute(
                        "SELECT * FROM research_sessions ORDER BY started_at DESC"
                    )
                result = []
                async for row in rows:
                    result.append(dict(row))
                return result
        except Exception as exc:
            log.warning("DBManager.list_research_sessions failed: %s", exc)
            return []

    async def save_research_theory(self, data: dict) -> None:
        """Insert a vulnerability theory (idempotent — ON CONFLICT DO NOTHING)."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("save_research_theory requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO vuln_theories (
                        theory_id, session_id, target, endpoint, vuln_type,
                        severity, confidence, reasoning, status, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (theory_id) DO NOTHING
                    """,
                    (
                        data["theory_id"],
                        data["session_id"],
                        data["target"],
                        data.get("endpoint", ""),
                        data["vuln_type"],
                        data.get("severity", "medium"),
                        data.get("confidence", 0.0),
                        data.get("reasoning", ""),
                        data.get("status", "pending"),
                        data.get("created_at"),
                        data.get("updated_at"),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.save_research_theory failed: %s", exc)

    async def update_research_theory_status(
        self, theory_id: str, status: str, updated_at: float
    ) -> None:
        """Update the status and updated_at timestamp of a vulnerability theory."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("update_research_theory_status requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    "UPDATE vuln_theories SET status = %s, updated_at = %s "
                    "WHERE theory_id = %s",
                    (status, updated_at, theory_id),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.update_research_theory_status failed: %s", exc)

    async def save_test_outcome(self, data: dict) -> None:
        """Insert one test outcome row (every outcome is a new row — no upsert)."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("save_test_outcome requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO test_outcomes (
                        session_id, theory_id, target, endpoint, vuln_type, payload,
                        status_code, response_size, response_time_ms, anomaly_score,
                        confirmed, evidence, tested_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        data["session_id"],
                        data.get("theory_id"),
                        data["target"],
                        data.get("endpoint", ""),
                        data["vuln_type"],
                        data.get("payload", ""),
                        data.get("status_code"),
                        data.get("response_size"),
                        data.get("response_time_ms"),
                        data.get("anomaly_score", 0.0),
                        data.get("confirmed", 0),
                        data.get("evidence", ""),
                        data.get("tested_at"),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.save_test_outcome failed: %s", exc)

    async def save_research_discovery(self, data: dict) -> None:
        """Upsert a confirmed vulnerability discovery."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("save_research_discovery requires Postgres mode")
        import json as _json
        try:
            steps = data.get("steps", [])
            if isinstance(steps, str):
                steps = _json.loads(steps)
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO research_discoveries (
                        report_id, session_id, target, vuln_type, title, severity,
                        confidence, endpoint, description, impact, steps, poc,
                        remediation, evidence, cvss_score, discovered_at, reported
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (report_id) DO UPDATE SET
                        title       = EXCLUDED.title,
                        severity    = EXCLUDED.severity,
                        confidence  = EXCLUDED.confidence,
                        description = EXCLUDED.description,
                        impact      = EXCLUDED.impact,
                        steps       = EXCLUDED.steps,
                        poc         = EXCLUDED.poc,
                        remediation = EXCLUDED.remediation,
                        evidence    = EXCLUDED.evidence,
                        cvss_score  = EXCLUDED.cvss_score
                    """,
                    (
                        data["report_id"],
                        data["session_id"],
                        data["target"],
                        data["vuln_type"],
                        data.get("title", ""),
                        data.get("severity", "medium"),
                        data.get("confidence", 0.0),
                        data.get("endpoint", ""),
                        data.get("description", ""),
                        data.get("impact", ""),
                        steps,
                        data.get("poc", ""),
                        data.get("remediation", ""),
                        data.get("evidence", ""),
                        data.get("cvss_score", 0.0),
                        data.get("discovered_at"),
                        data.get("reported", 0),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.save_research_discovery failed: %s", exc)
            raise

    async def list_research_discoveries(self, session_id: str = None) -> list:
        """List confirmed discoveries, optionally filtered by session_id."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("list_research_discoveries requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                if session_id:
                    rows = await conn.execute(
                        "SELECT * FROM research_discoveries WHERE session_id = %s "
                        "ORDER BY discovered_at DESC",
                        (session_id,),
                    )
                else:
                    rows = await conn.execute(
                        "SELECT * FROM research_discoveries ORDER BY discovered_at DESC"
                    )
                result = []
                async for row in rows:
                    result.append(dict(row))
                return result
        except Exception as exc:
            log.warning("DBManager.list_research_discoveries failed: %s", exc)
            return []

    async def upsert_cross_target_pattern(self, data: dict) -> None:
        """Insert or atomically increment success_count for a cross-target pattern."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("upsert_cross_target_pattern requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO cross_target_patterns (
                        vuln_type, endpoint_pattern, parameter_pattern, last_seen
                    ) VALUES (%s, %s, %s, %s)
                    ON CONFLICT (vuln_type, endpoint_pattern, parameter_pattern)
                    DO UPDATE SET
                        success_count = cross_target_patterns.success_count + 1,
                        last_seen     = EXCLUDED.last_seen
                    """,
                    (
                        data["vuln_type"],
                        data.get("endpoint_pattern", ""),
                        data.get("parameter_pattern", ""),
                        data.get("last_seen"),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.upsert_cross_target_pattern failed: %s", exc)

    async def get_cross_target_patterns(self, min_count: int = 2) -> list:
        """Return patterns with success_count >= min_count, ordered by frequency."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("get_cross_target_patterns requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT * FROM cross_target_patterns WHERE success_count >= %s "
                    "ORDER BY success_count DESC",
                    (min_count,),
                )
                result = []
                async for row in rows:
                    result.append(dict(row))
                return result
        except Exception as exc:
            log.warning("DBManager.get_cross_target_patterns failed: %s", exc)
            return []

```

- [ ] **Step 4: Run tests, verify all pass**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest tests/test_db_manager_research.py -v
```

Expected: All 23 tests pass.

- [ ] **Step 5: Verify no regressions in existing DBManager tests**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest \
  tests/test_db_manager.py \
  tests/test_db_manager_targets.py \
  tests/test_db_manager_get_findings_hardened.py \
  -v 2>&1 | tail -15
```

Expected: All pass.

- [ ] **Step 6: Commit**

```bash
git add core/db_manager.py tests/test_db_manager_research.py
git commit -m "feat(db-manager): add 10 async research methods for PostgreSQL"
```

---

### Task 3: Create ResearchRepository

**Files:**
- Create: `core/research_repository.py`
- Create: `tests/test_research_repository.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_research_repository.py`:

```python
# tests/test_research_repository.py
"""Tests for ResearchRepository — verifies delegation to DBManager mock."""
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
    """ResearchRepository backed by a fully mocked DBManager."""
    from core.research_repository import ResearchRepository
    db = MagicMock()
    db.save_research_session = AsyncMock()
    db.list_research_sessions = AsyncMock(return_value=[])
    db.save_research_theory = AsyncMock()
    db.update_research_theory_status = AsyncMock()
    db.save_test_outcome = AsyncMock()
    db.save_research_discovery = AsyncMock()
    db.upsert_cross_target_pattern = AsyncMock()
    db.list_research_discoveries = AsyncMock(return_value=[])
    db.get_cross_target_patterns = AsyncMock(return_value=[])
    return ResearchRepository(db), db


def make_session(session_id="s1", target="t.com", status="running", ended_at=0.0):
    """Minimal ResearchSession stand-in (plain object with the right attributes)."""
    s = MagicMock()
    s.session_id = session_id
    s.target = target
    s.output_dir = "/tmp/out"
    s.platform = "HackerOne"
    s.started_at = time.time()
    s.ended_at = ended_at
    s.status = status
    s.iteration = 1
    s.theories_generated = 2
    s.tests_executed = 5
    s.anomalies_found = 1
    s.confirmed_vulns = 1
    return s


# ── save_session / finish_session ─────────────────────────────────────────────

def test_save_session_calls_db_with_session_fields():
    repo, db = make_repo()
    session = make_session()
    run(repo.save_session(session))
    db.save_research_session.assert_called_once()
    d = db.save_research_session.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["target"] == "t.com"
    assert d["status"] == "running"


def test_finish_session_includes_ended_at():
    repo, db = make_repo()
    session = make_session(status="completed", ended_at=time.time())
    run(repo.finish_session(session))
    db.save_research_session.assert_called_once()
    d = db.save_research_session.call_args[0][0]
    assert d["status"] == "completed"
    assert d["ended_at"] is not None


def test_save_session_sync_works_synchronously():
    repo, db = make_repo()
    session = make_session()
    repo.save_session_sync(session)  # must not raise
    db.save_research_session.assert_called_once()


def test_finish_session_sync_works_synchronously():
    repo, db = make_repo()
    session = make_session(status="aborted", ended_at=time.time())
    repo.finish_session_sync(session)
    db.save_research_session.assert_called_once()


# ── record_theory ─────────────────────────────────────────────────────────────

def test_record_theory_passes_correct_fields():
    repo, db = make_repo()
    run(repo.record_theory("th1", "s1", "t.com", "/api/v1", "xss", "high", 0.9, "reason"))
    db.save_research_theory.assert_called_once()
    d = db.save_research_theory.call_args[0][0]
    assert d["theory_id"] == "th1"
    assert d["vuln_type"] == "xss"
    assert d["confidence"] == 0.9
    assert d["status"] == "pending"
    assert isinstance(d["created_at"], float)


def test_record_theory_sync_works_synchronously():
    repo, db = make_repo()
    repo.record_theory_sync("th1", "s1", "t.com", "/api", "sqli", "critical", 0.95, "why")
    db.save_research_theory.assert_called_once()


# ── update_theory_status ──────────────────────────────────────────────────────

def test_update_theory_status_calls_db_with_timestamp():
    repo, db = make_repo()
    run(repo.update_theory_status("th1", "confirmed"))
    db.update_research_theory_status.assert_called_once()
    args = db.update_research_theory_status.call_args[0]
    assert args[0] == "th1"
    assert args[1] == "confirmed"
    assert isinstance(args[2], float)  # updated_at


def test_update_theory_status_sync_works_synchronously():
    repo, db = make_repo()
    repo.update_theory_status_sync("th1", "rejected")
    db.update_research_theory_status.assert_called_once()


# ── record_test_outcome ───────────────────────────────────────────────────────

def test_record_test_outcome_maps_all_fields():
    repo, db = make_repo()
    run(repo.record_test_outcome(
        "s1", "th1", "t.com", "/api/search", "xss", "<script>",
        200, 1024, 50.0, 0.7, 1, "reflected in body", time.time(),
    ))
    db.save_test_outcome.assert_called_once()
    d = db.save_test_outcome.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["payload"] == "<script>"
    assert d["confirmed"] == 1


def test_record_test_outcome_sync_works_synchronously():
    repo, db = make_repo()
    repo.record_test_outcome_sync(
        "s1", "th1", "t.com", "/login", "sqli", "' OR 1=1",
        500, 256, 200.0, 0.9, 0, "", time.time(),
    )
    db.save_test_outcome.assert_called_once()


# ── save_discovery ────────────────────────────────────────────────────────────

def test_save_discovery_calls_both_db_methods():
    repo, db = make_repo()
    run(repo.save_discovery(
        "r1", "s1", "t.com", "xss", "Reflected XSS", "high", 0.95,
        "/api/v1/search", "desc", "impact", ["step1"], "poc", "fix", "ev",
        7.5, time.time(),
    ))
    db.save_research_discovery.assert_called_once()
    db.upsert_cross_target_pattern.assert_called_once()


def test_save_discovery_normalizes_endpoint_digits_to_id():
    repo, db = make_repo()
    run(repo.save_discovery(
        "r1", "s1", "t.com", "idor", "IDOR", "high", 0.9,
        "/api/v1/users/42/posts/7", "desc", "impact", [],
        "poc", "fix", "evidence", 8.0, time.time(),
    ))
    pattern_data = db.upsert_cross_target_pattern.call_args[0][0]
    assert pattern_data["endpoint_pattern"] == "/api/v1/users/{id}/posts/{id}"
    assert pattern_data["vuln_type"] == "idor"


def test_save_discovery_sync_works_synchronously():
    repo, db = make_repo()
    repo.save_discovery_sync(
        "r1", "s1", "t.com", "xss", "XSS", "medium", 0.8,
        "/search", "desc", "impact", [], "poc", "fix", "ev", 5.0, time.time(),
    )
    db.save_research_discovery.assert_called_once()
    db.upsert_cross_target_pattern.assert_called_once()


# ── get_known_patterns ────────────────────────────────────────────────────────

def test_get_known_patterns_delegates_min_count():
    repo, db = make_repo()
    db.get_cross_target_patterns = AsyncMock(return_value=[{"vuln_type": "xss", "success_count": 3}])
    result = run(repo.get_known_patterns(min_count=2))
    db.get_cross_target_patterns.assert_called_once_with(2)
    assert result[0]["success_count"] == 3


def test_get_known_patterns_sync():
    repo, db = make_repo()
    db.get_cross_target_patterns = AsyncMock(return_value=[{"vuln_type": "sqli"}])
    result = repo.get_known_patterns_sync(min_count=1)
    assert result[0]["vuln_type"] == "sqli"


# ── get_session_history ───────────────────────────────────────────────────────

def test_get_session_history_passes_target_kwarg():
    repo, db = make_repo()
    db.list_research_sessions = AsyncMock(return_value=[{"session_id": "s1"}])
    result = run(repo.get_session_history(target="t.com"))
    db.list_research_sessions.assert_called_once_with(target="t.com")
    assert len(result) == 1


def test_get_session_history_sync():
    repo, db = make_repo()
    db.list_research_sessions = AsyncMock(return_value=[{"session_id": "s2"}])
    result = repo.get_session_history_sync("t.com")
    assert result[0]["session_id"] == "s2"


# ── get_confirmed_discoveries ─────────────────────────────────────────────────

def test_get_confirmed_discoveries_passes_session_id_kwarg():
    repo, db = make_repo()
    db.list_research_discoveries = AsyncMock(return_value=[{"report_id": "r1"}])
    result = run(repo.get_confirmed_discoveries(session_id="s1"))
    db.list_research_discoveries.assert_called_once_with(session_id="s1")
    assert len(result) == 1


def test_get_confirmed_discoveries_sync():
    repo, db = make_repo()
    db.list_research_discoveries = AsyncMock(return_value=[{"report_id": "r9"}])
    result = repo.get_confirmed_discoveries_sync()
    assert result[0]["report_id"] == "r9"
```

- [ ] **Step 2: Run tests, confirm they all fail**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest tests/test_research_repository.py -v 2>&1 | head -20
```

Expected: All fail with `ModuleNotFoundError` (file doesn't exist yet).

- [ ] **Step 3: Create core/research_repository.py**

```python
# core/research_repository.py
"""
ResearchRepository — async repository for research loop persistence.

All storage routes through DBManager → PostgreSQL.
Sync wrappers (method_sync) allow use from synchronous callers (ResearchModeController).
"""
from __future__ import annotations

import re
import time
from typing import Optional

from core.db_manager import DBManager, get_db_manager


class ResearchRepository:
    def __init__(self, db: DBManager) -> None:
        self._db = db

    # ── Session ───────────────────────────────────────────────────────────────

    async def save_session(self, session) -> None:
        """Upsert all fields of a ResearchSession object."""
        await self._db.save_research_session({
            "session_id":         session.session_id,
            "target":             session.target,
            "output_dir":         session.output_dir,
            "platform":           session.platform,
            "started_at":         session.started_at,
            "ended_at":           session.ended_at if session.ended_at else None,
            "status":             session.status,
            "iteration":          session.iteration,
            "theories_generated": session.theories_generated,
            "tests_executed":     session.tests_executed,
            "anomalies_found":    session.anomalies_found,
            "confirmed_vulns":    session.confirmed_vulns,
        })

    async def finish_session(self, session) -> None:
        """Upsert final session state (ended_at and terminal status populated)."""
        await self.save_session(session)

    def save_session_sync(self, session) -> None:
        DBManager._run_sync(self.save_session(session))

    def finish_session_sync(self, session) -> None:
        DBManager._run_sync(self.finish_session(session))

    # ── Theories ──────────────────────────────────────────────────────────────

    async def record_theory(
        self, theory_id: str, session_id: str, target: str, endpoint: str,
        vuln_type: str, severity: str, confidence: float, reasoning: str,
    ) -> None:
        await self._db.save_research_theory({
            "theory_id":  theory_id,
            "session_id": session_id,
            "target":     target,
            "endpoint":   endpoint,
            "vuln_type":  vuln_type,
            "severity":   severity,
            "confidence": confidence,
            "reasoning":  reasoning,
            "status":     "pending",
            "created_at": time.time(),
            "updated_at": 0.0,
        })

    async def update_theory_status(self, theory_id: str, status: str) -> None:
        await self._db.update_research_theory_status(theory_id, status, time.time())

    def record_theory_sync(
        self, theory_id: str, session_id: str, target: str, endpoint: str,
        vuln_type: str, severity: str, confidence: float, reasoning: str,
    ) -> None:
        DBManager._run_sync(self.record_theory(
            theory_id, session_id, target, endpoint,
            vuln_type, severity, confidence, reasoning,
        ))

    def update_theory_status_sync(self, theory_id: str, status: str) -> None:
        DBManager._run_sync(self.update_theory_status(theory_id, status))

    # ── Test Outcomes ─────────────────────────────────────────────────────────

    async def record_test_outcome(
        self,
        session_id: str,
        theory_id: Optional[str],
        target: str,
        endpoint: str,
        vuln_type: str,
        payload: str,
        status_code: Optional[int],
        response_size: Optional[int],
        response_time_ms: Optional[float],
        anomaly_score: float,
        confirmed: int,
        evidence: str,
        tested_at: float,
    ) -> None:
        await self._db.save_test_outcome({
            "session_id":      session_id,
            "theory_id":       theory_id,
            "target":          target,
            "endpoint":        endpoint,
            "vuln_type":       vuln_type,
            "payload":         payload,
            "status_code":     status_code,
            "response_size":   response_size,
            "response_time_ms": response_time_ms,
            "anomaly_score":   anomaly_score,
            "confirmed":       confirmed,
            "evidence":        evidence,
            "tested_at":       tested_at,
        })

    def record_test_outcome_sync(
        self,
        session_id: str,
        theory_id: Optional[str],
        target: str,
        endpoint: str,
        vuln_type: str,
        payload: str,
        status_code: Optional[int],
        response_size: Optional[int],
        response_time_ms: Optional[float],
        anomaly_score: float,
        confirmed: int,
        evidence: str,
        tested_at: float,
    ) -> None:
        DBManager._run_sync(self.record_test_outcome(
            session_id, theory_id, target, endpoint, vuln_type, payload,
            status_code, response_size, response_time_ms,
            anomaly_score, confirmed, evidence, tested_at,
        ))

    # ── Discoveries ───────────────────────────────────────────────────────────

    async def save_discovery(
        self,
        report_id: str,
        session_id: str,
        target: str,
        vuln_type: str,
        title: str,
        severity: str,
        confidence: float,
        endpoint: str,
        description: str,
        impact: str,
        steps: list,
        poc: str,
        remediation: str,
        evidence: str,
        cvss_score: float,
        discovered_at: float,
    ) -> None:
        await self._db.save_research_discovery({
            "report_id":    report_id,
            "session_id":   session_id,
            "target":       target,
            "vuln_type":    vuln_type,
            "title":        title,
            "severity":     severity,
            "confidence":   confidence,
            "endpoint":     endpoint,
            "description":  description,
            "impact":       impact,
            "steps":        steps,
            "poc":          poc,
            "remediation":  remediation,
            "evidence":     evidence,
            "cvss_score":   cvss_score,
            "discovered_at": discovered_at,
            "reported":     0,
        })
        # Replicate original _update_pattern logic: normalise digits → {id}
        endpoint_pattern = re.sub(r"\d+", "{id}", endpoint)
        await self._db.upsert_cross_target_pattern({
            "vuln_type":        vuln_type,
            "endpoint_pattern": endpoint_pattern,
            "parameter_pattern": "",
            "last_seen":        time.time(),
        })

    def save_discovery_sync(
        self,
        report_id: str,
        session_id: str,
        target: str,
        vuln_type: str,
        title: str,
        severity: str,
        confidence: float,
        endpoint: str,
        description: str,
        impact: str,
        steps: list,
        poc: str,
        remediation: str,
        evidence: str,
        cvss_score: float,
        discovered_at: float,
    ) -> None:
        DBManager._run_sync(self.save_discovery(
            report_id, session_id, target, vuln_type, title, severity, confidence,
            endpoint, description, impact, steps, poc, remediation, evidence,
            cvss_score, discovered_at,
        ))

    # ── Queries ───────────────────────────────────────────────────────────────

    async def get_known_patterns(self, min_count: int = 2) -> list:
        return await self._db.get_cross_target_patterns(min_count)

    async def get_session_history(self, target: Optional[str] = None) -> list:
        return await self._db.list_research_sessions(target=target)

    async def get_confirmed_discoveries(
        self, session_id: Optional[str] = None
    ) -> list:
        return await self._db.list_research_discoveries(session_id=session_id)

    def get_known_patterns_sync(self, min_count: int = 2) -> list:
        return DBManager._run_sync(self.get_known_patterns(min_count))

    def get_session_history_sync(self, target: Optional[str] = None) -> list:
        return DBManager._run_sync(self.get_session_history(target))

    def get_confirmed_discoveries_sync(
        self, session_id: Optional[str] = None
    ) -> list:
        return DBManager._run_sync(self.get_confirmed_discoveries(session_id))


async def get_research_repo() -> ResearchRepository:
    """Async factory — use with FastAPI Depends or asyncio.run."""
    return ResearchRepository(await get_db_manager())
```

- [ ] **Step 4: Run tests, verify all pass**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest tests/test_research_repository.py -v
```

Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/research_repository.py tests/test_research_repository.py
git commit -m "feat: add ResearchRepository with async methods and sync wrappers"
```

---

### Task 4: Wire ResearchRepository into ResearchModeController

**Files:**
- Modify: `research_mode_controller.py` (line 758 init + 10 `self._kb.*` call sites)

All `self._kb.*` calls currently use the `ResearchKnowledgeBase` API (composite object params). They must become sync wrapper calls on the new `ResearchRepository`.

- [ ] **Step 1: Replace self._kb initialization at line 758**

In `ResearchModeController.__init__`, find:
```python
        self._kb = ResearchKnowledgeBase()
```
Replace with:
```python
        from core.research_repository import ResearchRepository
        from core.db_manager import get_db_manager_sync
        self._kb = ResearchRepository(get_db_manager_sync())
```

- [ ] **Step 2: Replace line 785 — session start save**

Find (inside `run_research`, just before `self.output_dir.mkdir`):
```python
        self._kb.save_session(self._session)
        self.output_dir.mkdir(parents=True, exist_ok=True)
```
Replace with:
```python
        self._kb.save_session_sync(self._session)
        self.output_dir.mkdir(parents=True, exist_ok=True)
```

- [ ] **Step 3: Replace line 789 — get_session_history**

Find:
```python
        prior = self._kb.get_session_history(self.target)
```
Replace with:
```python
        prior = self._kb.get_session_history_sync(self.target)
```

- [ ] **Step 4: Replace line 794 — get_known_patterns (seed)**

Find:
```python
        patterns = self._kb.get_known_patterns(min_count=1)
```
Replace with:
```python
        patterns = self._kb.get_known_patterns_sync(min_count=1)
```

- [ ] **Step 5: Replace line 809 — per-iteration save (inside while loop)**

Find (inside the while loop, after `self._run_iteration()`):
```python
                self._kb.save_session(self._session)
```
Replace with:
```python
                self._kb.save_session_sync(self._session)
```

- [ ] **Step 6: Replace line 825 — final save in finally block**

Find (inside `finally:` block, before `self._finalize()`):
```python
            self._kb.save_session(self._session)
```
Replace with:
```python
            self._kb.finish_session_sync(self._session)
```

- [ ] **Step 7: Replace line 896 — get_known_patterns (confidence boost)**

Find (inside `_run_iteration`, in Phase 2):
```python
        patterns = self._kb.get_known_patterns()
```
Replace with:
```python
        patterns = self._kb.get_known_patterns_sync()
```

- [ ] **Step 8: Replace line 908 — record_theory**

Find:
```python
            self._kb.record_theory(self._session.session_id, t, self.target)
```
Replace with:
```python
            self._kb.record_theory_sync(
                t.theory_id, self._session.session_id, self.target,
                t.endpoint, t.vuln_type, t.severity, t.confidence, t.reasoning,
            )
```

- [ ] **Step 9: Replace line 945 — record_test_outcome**

Find:
```python
            self._kb.record_test_outcome(self._session.session_id, r, self.target)
```
Replace with:
```python
            self._kb.record_test_outcome_sync(
                self._session.session_id, r.theory_id, self.target,
                r.endpoint, r.vuln_type, r.payload_used,
                r.status_code, r.response_size, r.response_time_ms,
                r.anomaly_score, int(r.confirmed), r.evidence, time.time(),
            )
```

- [ ] **Step 10: Replace line 977 — update_theory_status**

Find:
```python
            self._kb.update_theory_status(theory.theory_id, "confirmed")
```
Replace with:
```python
            self._kb.update_theory_status_sync(theory.theory_id, "confirmed")
```

- [ ] **Step 11: Replace line 991 — save_discovery**

Find:
```python
            self._kb.save_discovery(report)
```
Replace with:
```python
            self._kb.save_discovery_sync(
                report.report_id, report.session_id, report.target, report.vuln_type,
                report.title, report.severity, report.confidence, report.endpoint,
                report.description, report.impact, report.steps_to_reproduce,
                report.proof_of_concept, report.remediation, report.evidence,
                report.cvss_score, report.discovered_at,
            )
```

- [ ] **Step 12: Verify syntax is clean**

```bash
python3 -c "import ast; ast.parse(open('research_mode_controller.py').read()); print('Syntax OK')"
```

Expected: `Syntax OK`

- [ ] **Step 13: Commit**

```bash
git add research_mode_controller.py
git commit -m "feat(research): wire ResearchRepository sync wrappers into ResearchModeController"
```

---

### Task 5: Delete ResearchKnowledgeBase + update show_research_stats()

**Files:**
- Modify: `research_mode_controller.py` (delete lines 139–424, remove `sqlite3` import, rewrite `show_research_stats`)
- Create: `tests/test_research_kb_removed.py`

- [ ] **Step 1: Write the static check test (will fail right now)**

Create `tests/test_research_kb_removed.py`:

```python
# tests/test_research_kb_removed.py
"""
Static checks: ResearchKnowledgeBase and sqlite3 are fully gone from
research_mode_controller.py, and show_research_stats() uses ResearchRepository.
These tests fail before deletion and pass after.
"""
import ast
from pathlib import Path


def _source():
    return Path("research_mode_controller.py").read_text()


def test_no_research_knowledge_base_class():
    source = _source()
    assert "class ResearchKnowledgeBase" not in source, (
        "ResearchKnowledgeBase class must be deleted from research_mode_controller.py"
    )


def test_no_sqlite3_import():
    source = _source()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "sqlite3", \
                    "sqlite3 must not be imported in research_mode_controller.py"
        if isinstance(node, ast.ImportFrom):
            assert node.module != "sqlite3", \
                "sqlite3 must not be imported in research_mode_controller.py"


def test_show_research_stats_uses_get_research_repo():
    source = _source()
    assert "ResearchKnowledgeBase" not in source
    assert "get_research_repo" in source, \
        "show_research_stats must use get_research_repo"
    assert "asyncio.run" in source, \
        "show_research_stats must wrap async fetch in asyncio.run"
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest tests/test_research_kb_removed.py -v 2>&1 | head -30
```

Expected: All 3 tests fail.

- [ ] **Step 3: Delete the ResearchKnowledgeBase class**

In `research_mode_controller.py`, delete everything from line 139 through line 424 (inclusive):
- Line 139: `# ── Knowledge Base ────────────────────────────────────────────────────────────`
- Line 424: blank line after `self._conn = None` that closes the `close()` method

After deletion, the file should flow directly from `DiscoveryReport.to_markdown()` (ends around line 136) to `# ── Report Generator ──` (was at line 425).

- [ ] **Step 4: Remove sqlite3 import**

Find and delete the line at the top of the file:
```python
import sqlite3
```

Then check whether `research_db_path` is still used anywhere other than its import:
```bash
grep -n "research_db_path" research_mode_controller.py
```

If the only occurrence is the import line `from path_manager import research_db_path, resolve_output_dir`, remove `research_db_path` from that import (keep `resolve_output_dir` if it appears elsewhere).

- [ ] **Step 5: Rewrite show_research_stats()**

Find the entire `show_research_stats()` function (currently uses `ResearchKnowledgeBase`). Replace it with:

```python
async def _fetch_research_stats():
    from core.research_repository import get_research_repo
    repo = await get_research_repo()
    sessions = await repo.get_session_history(target=None)
    discoveries = await repo.get_confirmed_discoveries()
    patterns = await repo.get_known_patterns(min_count=1)
    return sessions, discoveries, patterns


def show_research_stats():
    """Print cross-session research statistics from PostgreSQL."""
    import asyncio
    sessions, discoveries, patterns = asyncio.run(_fetch_research_stats())
    from modules.utils import banner, section, ok

    banner("Research Knowledge Base")
    ok(f"Confirmed discoveries: {len(discoveries)}")
    ok(f"Cross-target patterns : {len(patterns)}")
    print()

    if discoveries:
        section("Recent Discoveries")
        for d in discoveries[:10]:
            print(f"  [{d['severity'].upper()}] {d['vuln_type']} — {d['endpoint']}")
            print(f"    {d['target']} (confidence: {d['confidence']:.0%})")
        print()

    if patterns:
        section("High-Value Patterns (cross-target)")
        for p in patterns[:10]:
            print(f"  [{p['success_count']}x] {p['vuln_type']} → {p['endpoint_pattern']}")
    print()
```

- [ ] **Step 6: Verify syntax is clean**

```bash
python3 -c "import ast; ast.parse(open('research_mode_controller.py').read()); print('Syntax OK')"
```

Expected: `Syntax OK`

- [ ] **Step 7: Run static check tests — should now pass**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest tests/test_research_kb_removed.py -v
```

Expected: All 3 tests pass.

- [ ] **Step 8: Commit**

```bash
git add research_mode_controller.py tests/test_research_kb_removed.py
git commit -m "feat(research): delete ResearchKnowledgeBase, rewrite show_research_stats via ResearchRepository"
```

---

### Task 6: Full regression

**Files:** none (verification only)

- [ ] **Step 1: Run all new research tests together**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest \
  tests/test_db_manager_research.py \
  tests/test_research_repository.py \
  tests/test_research_kb_removed.py \
  -v
```

Expected: All pass.

- [ ] **Step 2: Run broader suite to confirm no regressions**

```bash
cd /home/devendra-yadav/oneinfinity && python -m pytest \
  tests/test_db_manager.py \
  tests/test_db_manager_targets.py \
  tests/test_db_manager_get_findings_hardened.py \
  tests/test_db_manager_research.py \
  tests/test_research_repository.py \
  tests/test_research_kb_removed.py \
  -v 2>&1 | tail -20
```

Expected: All pass.

- [ ] **Step 3: Verify research_mode_controller.py imports cleanly**

```bash
python3 -c "import research_mode_controller; print('Import OK')"
```

Expected: `Import OK` (no SQLite-related import errors; DBManager import failure is expected if Postgres isn't configured locally — that's fine, the important thing is no sqlite3 error).
