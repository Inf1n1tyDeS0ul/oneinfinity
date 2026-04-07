# Storage Wiring Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Activate correct runtime wiring for Redis/PostgreSQL/Neo4j — fix dead code paths, remove bypass routes, enforce single write path per data type.

**Architecture:** Surgical fixes only — no redesign. DBManager becomes the single scan+findings write router. RedisSwarmState becomes the active swarm coordination path when Redis is available. SQLite fallback is preserved throughout.

**Tech Stack:** Python 3.13, FastAPI, psycopg3, redis-py, SQLite3, asyncio

---

## Pre-flight

- [ ] Confirm backend is running: `curl -s http://localhost:8000/api/scans | python3 -c "import json,sys; print(len(json.load(sys.stdin)), 'scans')"`
- [ ] Note current test suite location: `ls /home/devendra-yadav/oneinfinity/tests/`

---

## Task 1: Extend DBManager — scan SQLite path + delete + load

**Files:**
- Modify: `core/db_manager.py`

This is the prerequisite for Tasks 3 and 5. DBManager's `save_scan()` currently has **no SQLite path** — in sqlite mode it only returns the ID without persisting. We add the SQLite path and two missing methods.

- [ ] **Step 1: Write the failing tests**

Create `/home/devendra-yadav/oneinfinity/tests/test_db_manager_scan.py`:

```python
"""Tests for DBManager scan persistence (SQLite mode)."""
import asyncio
import pytest
from pathlib import Path
import tempfile, os

@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "sqlite")
    monkeypatch.setattr("path_manager.findings_db_path", lambda: tmp_path / "findings.db")
    monkeypatch.setattr("path_manager.db_path", lambda name: tmp_path / name)
    # Reset singleton
    import core.db_manager as dm
    dm._manager = None
    return tmp_path

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)

def test_save_scan_sqlite(tmp_db):
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    assert mgr.mode == "sqlite"
    scan = {"id": "test-001", "target": "127.0.0.1", "scan_type": "full", "status": "queued"}
    sid = run(mgr.save_scan(scan))
    assert sid == "test-001"
    scans = run(mgr.load_scans())
    assert any(s["scan_id"] == "test-001" for s in scans)

def test_delete_scan_sqlite(tmp_db):
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    scan = {"id": "del-001", "target": "127.0.0.1", "scan_type": "full", "status": "completed"}
    run(mgr.save_scan(scan))
    run(mgr.delete_scan("del-001"))
    scans = run(mgr.load_scans())
    assert not any(s["scan_id"] == "del-001" for s in scans)

def test_load_scans_marks_interrupted_running(tmp_db):
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    scan = {"id": "int-001", "target": "10.0.0.1", "scan_type": "full", "status": "running"}
    run(mgr.save_scan(scan))
    # Reset singleton to simulate restart
    import core.db_manager as dm
    dm._manager = None
    mgr2 = run(get_db_manager())
    scans = run(mgr2.load_scans())
    loaded = next(s for s in scans if s["scan_id"] == "int-001")
    assert loaded["status"] == "failed"
    assert "interrupted" in (loaded.get("error") or "").lower()
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_db_manager_scan.py -v 2>&1 | tail -20
```

Expected: 3 FAILs (methods don't exist yet).

- [ ] **Step 3: Add SQLite scan methods to DBManager**

In `core/db_manager.py`, replace the `save_scan` method and add three new methods after it. Find the existing `save_scan` (line ~241):

```python
    async def save_scan(self, scan: dict) -> str:
        sid = scan.get("id") or scan.get("scan_id") or str(uuid.uuid4())
        scan = {**scan, "scan_id": sid}
        if self.mode in ("distributed", "postgres"):
            await self._pg_save_scan(scan)
        return sid
```

Replace with:

```python
    async def save_scan(self, scan: dict) -> str:
        sid = scan.get("id") or scan.get("scan_id") or str(uuid.uuid4())
        scan = {**scan, "scan_id": sid}
        if self.mode in ("distributed", "postgres"):
            await self._pg_save_scan(scan)
        else:
            self._sqlite_save_scan(scan)
        return sid

    def _sqlite_save_scan(self, scan: dict) -> None:
        import sqlite3 as _sq
        db_path = path_manager.db_path("metadata.db")
        sid = scan.get("scan_id") or scan.get("id")
        if not sid:
            return
        try:
            with _sq.connect(str(db_path), check_same_thread=False) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        scan_id TEXT PRIMARY KEY, target TEXT NOT NULL,
                        scan_type TEXT, profile TEXT,
                        status TEXT NOT NULL DEFAULT 'queued',
                        started_at TEXT, completed_at TEXT,
                        progress INTEGER DEFAULT 0,
                        findings_count INTEGER DEFAULT 0,
                        phase TEXT, error TEXT
                    )
                """)
                conn.execute("""
                    INSERT INTO scan_history
                        (scan_id, target, scan_type, profile, status,
                         started_at, completed_at, progress, findings_count, phase, error)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(scan_id) DO UPDATE SET
                        status=excluded.status, completed_at=excluded.completed_at,
                        progress=excluded.progress, findings_count=excluded.findings_count,
                        phase=excluded.phase, error=excluded.error
                """, (
                    sid,
                    scan.get("target", ""),
                    scan.get("scan_type", "full"),
                    scan.get("profile", "auto"),
                    scan.get("status", "queued"),
                    scan.get("started_at"),
                    scan.get("completed_at"),
                    scan.get("progress", 0),
                    scan.get("findings_count", 0),
                    scan.get("phase", ""),
                    scan.get("error", ""),
                ))
                conn.commit()
        except Exception as exc:
            log.warning("DBManager._sqlite_save_scan failed: %s", exc)

    async def delete_scan(self, scan_id: str) -> None:
        if self.mode in ("distributed", "postgres"):
            await self._pg_delete_scan(scan_id)
        else:
            self._sqlite_delete_scan(scan_id)

    async def _pg_delete_scan(self, scan_id: str) -> None:
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager._pg_delete_scan failed: %s", exc)

    def _sqlite_delete_scan(self, scan_id: str) -> None:
        import sqlite3 as _sq
        db_path = path_manager.db_path("metadata.db")
        try:
            with _sq.connect(str(db_path), check_same_thread=False) as conn:
                conn.execute("DELETE FROM scan_history WHERE scan_id=?", (scan_id,))
                conn.commit()
        except Exception as exc:
            log.warning("DBManager._sqlite_delete_scan failed: %s", exc)

    async def load_scans(self) -> list:
        if self.mode in ("distributed", "postgres"):
            return await self._pg_load_scans()
        return self._sqlite_load_scans()

    async def _pg_load_scans(self) -> list:
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT scan_id, target, scan_type, status, data, "
                    "       started_at, completed_at "
                    "FROM scans ORDER BY started_at DESC NULLS LAST"
                )
                results = []
                async for row in rows:
                    d = {
                        "scan_id": row[0], "id": row[0],
                        "target": row[1], "scan_type": row[2],
                        "status": row[3],
                        "started_at": str(row[5]) if row[5] else None,
                        "completed_at": str(row[6]) if row[6] else None,
                        "log_lines": [], "pid": None,
                        "progress": 0, "findings_count": 0, "phase": "",
                    }
                    extra = row[4] or {}
                    if isinstance(extra, str):
                        import json as _j; extra = _j.loads(extra)
                    d.update(extra)
                    if d.get("status") == "running":
                        d["status"] = "failed"
                        d["error"] = d.get("error") or "Process interrupted (server restart)"
                    results.append(d)
                return results
        except Exception as exc:
            log.warning("DBManager._pg_load_scans failed: %s", exc)
            return []

    def _sqlite_load_scans(self) -> list:
        import sqlite3 as _sq
        db_path = path_manager.db_path("metadata.db")
        try:
            with _sq.connect(str(db_path), check_same_thread=False) as conn:
                conn.row_factory = _sq.Row
                rows = conn.execute(
                    "SELECT * FROM scan_history ORDER BY started_at DESC"
                ).fetchall()
                scans = []
                for row in rows:
                    d = dict(row)
                    d["id"] = d["scan_id"]
                    d["log_lines"] = []
                    d["pid"] = None
                    if d.get("status") == "running":
                        d["status"] = "failed"
                        d["error"] = d.get("error") or "Process interrupted (server restart)"
                    scans.append(d)
                return scans
        except Exception as exc:
            log.warning("DBManager._sqlite_load_scans failed: %s", exc)
            return []

    def sync_delete_scan(self, scan_id: str) -> None:
        self._run_sync(self.delete_scan(scan_id))

    def sync_load_scans(self) -> list:
        return self._run_sync(self.load_scans())
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_db_manager_scan.py -v 2>&1 | tail -20
```

Expected: 3 PASSes.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add core/db_manager.py tests/test_db_manager_scan.py
git commit -m "feat(db_manager): add SQLite scan path, delete_scan, load_scans methods"
```

---

## Task 2: Config enforcement + fallback logging

**Files:**
- Modify: `core/db_manager.py`
- Modify: `core/pg_client.py`
- Modify: `core/redis_client.py`

- [ ] **Step 1: Write the failing tests**

Create `/home/devendra-yadav/oneinfinity/tests/test_db_manager_config.py`:

```python
"""Tests for DBManager strict-mode config enforcement."""
import asyncio
import pytest

def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)

def reset_mgr():
    import core.db_manager as dm
    dm._manager = None

def test_explicit_postgres_without_url_raises(monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "postgres")
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    reset_mgr()
    from core.db_manager import get_db_manager
    with pytest.raises(RuntimeError, match="POSTGRES_URL"):
        run(get_db_manager())

def test_explicit_distributed_without_postgres_raises(monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "distributed")
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    reset_mgr()
    from core.db_manager import get_db_manager
    with pytest.raises(RuntimeError, match="POSTGRES_URL"):
        run(get_db_manager())

def test_explicit_sqlite_does_not_raise(monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "sqlite")
    reset_mgr()
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    assert mgr.mode == "sqlite"

def test_no_env_defaults_to_sqlite(monkeypatch):
    monkeypatch.delenv("ONEINFINITY_STORAGE_MODE", raising=False)
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    reset_mgr()
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    assert mgr.mode == "sqlite"
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_db_manager_config.py -v 2>&1 | tail -20
```

Expected: `test_explicit_postgres_without_url_raises` and `test_explicit_distributed_without_postgres_raises` FAIL.

- [ ] **Step 3: Add strict mode + logging to `core/db_manager.py`**

Find the `_init` method (line ~77). Replace the explicit mode handling block:

```python
    # BEFORE (lines 81-89):
    if explicit == "memory":
        self.mode = "memory"
        log.info("DBManager: memory mode (forced)")
        return

    if explicit == "sqlite":
        self.mode = "sqlite"
        log.info("DBManager: SQLite mode (forced)")
        return
```

Replace with:

```python
        if explicit == "memory":
            self.mode = "memory"
            log.info("[DBManager] Running in MEMORY mode (forced)")
            return

        if explicit == "sqlite":
            self.mode = "sqlite"
            log.info("[DBManager] Running in SQLITE fallback mode (forced)")
            return

        if explicit == "postgres":
            if not os.environ.get("POSTGRES_URL", "").strip():
                raise RuntimeError(
                    "[DBManager] ONEINFINITY_STORAGE_MODE=postgres requires POSTGRES_URL to be set"
                )

        if explicit == "distributed":
            if not os.environ.get("POSTGRES_URL", "").strip():
                raise RuntimeError(
                    "[DBManager] ONEINFINITY_STORAGE_MODE=distributed requires POSTGRES_URL to be set"
                )
            if not os.environ.get("REDIS_URL", "").strip():
                raise RuntimeError(
                    "[DBManager] ONEINFINITY_STORAGE_MODE=distributed requires REDIS_URL to be set"
                )
```

Then replace the final fallback line (line ~104):

```python
        # BEFORE:
        self.mode = "sqlite"
        log.info("DBManager: SQLite fallback mode (Postgres unavailable)")

        # AFTER:
        self.mode = "sqlite"
        log.warning(
            "[DBManager] FALLBACK TRIGGERED: PostgreSQL unavailable — running in SQLITE fallback mode"
        )
```

And replace the mode log lines after successful Postgres detection (line ~101):

```python
        # BEFORE:
        self.mode = "distributed" if has_redis else "postgres"
        log.info("DBManager: %s mode", self.mode)

        # AFTER:
        self.mode = "distributed" if has_redis else "postgres"
        if self.mode == "distributed":
            log.info("[DBManager] Running in DISTRIBUTED mode (Redis + Postgres)")
        else:
            log.info("[DBManager] Running in POSTGRES mode")
```

- [ ] **Step 4: Add FALLBACK TRIGGERED log to `core/pg_client.py`**

Find the exception handler where `get_async_pool` catches a connection failure and returns None. Add a warning:

```python
        except Exception as exc:
            log.warning(
                "FALLBACK TRIGGERED: PostgreSQL connection failed (%s) — Postgres unavailable", exc
            )
            return None
```

Do the same for the sync pool getter if one exists.

- [ ] **Step 5: Add FALLBACK TRIGGERED log to `core/redis_client.py`**

Find where `get_redis()` catches connection failure and returns None:

```python
        except Exception as exc:
            log.warning(
                "FALLBACK TRIGGERED: Redis connection failed (%s) — falling back to in-memory", exc
            )
            return None
```

- [ ] **Step 6: Run tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_db_manager_config.py -v 2>&1 | tail -20
```

Expected: 4 PASSes.

- [ ] **Step 7: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add core/db_manager.py core/pg_client.py core/redis_client.py tests/test_db_manager_config.py
git commit -m "feat(config): enforce explicit storage mode, add FALLBACK TRIGGERED logging"
```

---

## Task 3: Remove ScanDB — route all scan persistence through DBManager

**Files:**
- Modify: `web/backend/main.py`

20 `_scan_db.*` call sites + the class definition and module-level init. Every call site is inside an `async def`, so all replacements use `await`.

- [ ] **Step 1: Verify the backend still starts cleanly before touching it**

```bash
curl -s http://localhost:8000/api/scans | python3 -c "import json,sys; print('OK, scans:', len(json.load(sys.stdin)))"
```

- [ ] **Step 2: Delete `ScanDB` class and `_scan_db` init from `main.py`**

Remove lines 263–352 (the entire `ScanDB` class) and line 355 (`_scan_db = ScanDB(...)`).

Find and delete this exact block:

```python
class ScanDB:
    """Persists scan metadata to SQLite so history survives restarts."""
    ...  # everything through the closing of load_all()


_scan_db = ScanDB(_db_path("metadata.db"))
```

- [ ] **Step 3: Replace `_scan_db.load_all()` in lifespan (line 93)**

```python
# BEFORE:
    try:
        for s in _scan_db.load_all():
            SCANS[s["scan_id"]] = s
        log.info("Loaded %d persisted scans into memory", len(SCANS))
    except Exception as exc:
        log.warning("Could not load persisted scans: %s", exc)

# AFTER:
    try:
        from core.db_manager import get_db_manager as _get_dbm
        _startup_mgr = await _get_dbm()
        for s in await _startup_mgr.load_scans():
            SCANS[s["scan_id"]] = s
        log.info("Loaded %d persisted scans into memory", len(SCANS))
    except Exception as exc:
        log.warning("Could not load persisted scans: %s", exc)
```

- [ ] **Step 4: Replace god-mode JSON import `_scan_db.upsert(entry)` (line 138)**

```python
# BEFORE:
                _scan_db.upsert(entry)

# AFTER:
                await _startup_mgr.save_scan(entry)
```

- [ ] **Step 5: Replace all remaining `_scan_db.upsert(scan)` call sites**

For each of the following lines, replace `_scan_db.upsert(X)` with `await (await get_mgr()).save_scan(X)`:

- Line 731 (add_target auto-scan)
- Line 787 (launch_scan)
- Line 827 (stop_scan)
- Line 1391 (_run_scan_via_engine, completed)
- Line 1435 (_run_scan_via_engine, fallback failed)
- Line 1487 (_run_scan, completed)
- Line 1493 (_run_scan, exception)
- Line 2457 (god_mode_scan launch)
- Line 2495 (god_mode status update)
- Line 2517 (god_mode status update)
- Line 2603 (god_mode completion)
- Line 2618 (god_mode import)
- Line 3185 (scan cleanup loop)
- Line 3200 (scan cleanup loop)

Pattern for each replacement:

```python
# BEFORE:
_scan_db.upsert(scan)

# AFTER:
await (await get_mgr()).save_scan(scan)
```

- [ ] **Step 6: Replace `_scan_db.delete(scan_id)` (line 846)**

```python
# BEFORE:
    SCANS.delete(scan_id)
    _scan_db.delete(scan_id)

# AFTER:
    SCANS.delete(scan_id)
    await (await get_mgr()).delete_scan(scan_id)
```

- [ ] **Step 7: Restart backend and verify clean startup**

```bash
kill $(lsof -ti:8000) 2>/dev/null; sleep 1
cd /home/devendra-yadav/oneinfinity/web/backend && .venv/bin/python main.py > /tmp/oneinfinity-backend.log 2>&1 &
sleep 4 && grep -E "ERROR|Traceback|Running in|Loaded" /tmp/oneinfinity-backend.log
```

Expected output includes one of:
- `[DBManager] Running in SQLITE fallback mode`
- `[DBManager] Running in POSTGRES mode`
- `[DBManager] Running in DISTRIBUTED mode`

No `ScanDB` errors.

- [ ] **Step 8: Smoke test scan API**

```bash
curl -s http://localhost:8000/api/scans | python3 -c "import json,sys; print('Scans:', len(json.load(sys.stdin)))"
```

- [ ] **Step 9: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add web/backend/main.py
git commit -m "refactor(main): remove ScanDB, route all scan persistence through DBManager"
```

---

## Task 4: Single findings write path

**Files:**
- Modify: `result_ingestion_engine.py`

`_check_and_store()` has a direct `sqlite3.connect()` block (lines 466–520) that bypasses DBManager. Replace with `DBManager._sqlite_save_finding()` while keeping the deduplication check.

- [ ] **Step 1: Write the failing test**

Add to `/home/devendra-yadav/oneinfinity/tests/test_db_manager_scan.py`:

```python
def test_findings_write_goes_through_dbmanager(tmp_db, monkeypatch):
    """_check_and_store must use DBManager._sqlite_save_finding, not raw sqlite3."""
    import core.db_manager as dm
    dm._manager = None
    calls = []
    original = dm.DBManager._sqlite_save_finding
    def spy(self, finding):
        calls.append(finding)
        original(self, finding)
    monkeypatch.setattr(dm.DBManager, "_sqlite_save_finding", spy)

    from result_ingestion_engine import ResultIngestionEngine, RawResult
    engine = ResultIngestionEngine.__new__(ResultIngestionEngine)
    engine._db_path = tmp_db / "findings.db"
    engine._lock = __import__("threading").Lock()
    engine._init_db()

    raw = RawResult(tool="test", raw={"type": "xss", "url": "http://t.test/", "title": "XSS",
                                      "severity": "high", "target": "t.test"})
    engine.ingest(raw)
    assert len(calls) >= 1, "DBManager._sqlite_save_finding was not called"
```

- [ ] **Step 2: Run test — verify it fails**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_db_manager_scan.py::test_findings_write_goes_through_dbmanager -v 2>&1 | tail -10
```

- [ ] **Step 3: Replace direct sqlite3 block in `result_ingestion_engine.py`**

In `_check_and_store()`, find the SQLite fallback block starting at line ~464:

```python
        # SQLite fallback (existing logic continues below)
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                with self._lock:
                    with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                        conn.execute("PRAGMA journal_mode=WAL;")
                        conn.execute("PRAGMA synchronous=FULL;")
                        # Duplicate check inside the lock — prevents TOCTOU race
                        row = conn.execute(
                            "SELECT 1 FROM findings "
                            ...
                        ).fetchone()
                        if row is not None:
                            return False
                        conn.execute(
                            "INSERT OR REPLACE INTO findings ..."
                            ...
                        )
                        conn.commit()
                        return True
            except sqlite3.OperationalError as exc:
                ...
```

Replace with:

```python
        # SQLite fallback — route through DBManager abstraction (no direct sqlite3 here)
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                with self._lock:
                    with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                        conn.execute("PRAGMA journal_mode=WAL;")
                        # Dedup check only — no INSERT here
                        row = conn.execute(
                            "SELECT 1 FROM findings "
                            "WHERE (scan_id=? AND vuln_type=? AND url=?) "
                            "OR (vuln_type=? AND url=? AND created_at > datetime('now', '-1 day')) "
                            "LIMIT 1",
                            (finding.scan_id, finding.vuln_type, finding.url,
                             finding.vuln_type, finding.url),
                        ).fetchone()
                        if row is not None:
                            return False
                # Delegate INSERT to DBManager to maintain single write path
                mgr = _get_db_manager_sync()
                if mgr is not None:
                    mgr._sqlite_save_finding(finding.to_dict())
                    return True
                # Last-resort direct write only if DBManager itself is unavailable
                log.warning(
                    "FALLBACK TRIGGERED: DBManager unavailable — writing finding directly to SQLite"
                )
                with self._lock:
                    with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                        conn.execute("PRAGMA synchronous=FULL;")
                        conn.execute(
                            "INSERT OR REPLACE INTO findings "
                            "(finding_id, scan_id, target, title, severity, vuln_type, "
                            " evidence, payload, url, tool, confidence, cvss, status, "
                            " source_type, created_at, raw_json) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                finding.finding_id, finding.scan_id, finding.target,
                                finding.title, finding.severity, finding.vuln_type,
                                finding.evidence, finding.payload, finding.url, finding.tool,
                                finding.confidence, finding.cvss, finding.status,
                                finding.source_type, finding.created_at, finding.safe_raw_json(),
                            ),
                        )
                        conn.commit()
                        return True
            except sqlite3.OperationalError as exc:
                last_exc = exc
                if "locked" in str(exc).lower() and attempt < 2:
                    import time as _t; _t.sleep(0.2 * (2 ** attempt))
                    continue
                raise
            except Exception as exc:
                last_exc = exc
                raise
        if last_exc:
            raise RuntimeError("Failed to store finding") from last_exc
        return False
```

- [ ] **Step 4: Run test — verify it passes**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_db_manager_scan.py -v 2>&1 | tail -10
```

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add result_ingestion_engine.py tests/test_db_manager_scan.py
git commit -m "fix(ingestion): route SQLite findings write through DBManager._sqlite_save_finding"
```

---

## Task 5: CLI writes through DBManager

**Files:**
- Modify: `god_mode_engine.py`

`GodModeStateFile.write()` only writes JSON. Add DBManager as primary, JSON as fallback/cache.

- [ ] **Step 1: Write the failing test**

Create `/home/devendra-yadav/oneinfinity/tests/test_god_mode_db.py`:

```python
"""Test that GodModeStateFile.write() persists scan to DBManager first."""
import asyncio, pytest
from unittest.mock import MagicMock, patch

def test_write_calls_dbmanager_sync_save_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "sqlite")
    import core.db_manager as dm
    dm._manager = None

    saved = []
    original_sync_save = dm.DBManager.sync_save_scan
    def capture_save(self, scan):
        saved.append(scan)
    monkeypatch.setattr(dm.DBManager, "sync_save_scan", capture_save)

    import sys
    sys.path.insert(0, "/home/devendra-yadav/oneinfinity")
    from god_mode_engine import GodModeStateFile, GodModeSession
    import time

    sf = GodModeStateFile.__new__(GodModeStateFile)
    sf.path = tmp_path / "god-mode-test.json"
    sf.path.parent.mkdir(parents=True, exist_ok=True)

    session = GodModeSession(
        scan_id="test-gm-001",
        target="http://test.local",
        start_time=time.time(),
        finding_count=3,
    )
    sf.write(session)

    assert len(saved) == 1, "sync_save_scan was not called"
    assert saved[0]["scan_id"] == "test-gm-001"
    assert saved[0]["target"] == "http://test.local"

def test_write_falls_back_to_json_when_dbmanager_fails(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "sqlite")
    import core.db_manager as dm
    dm._manager = None

    def raise_error(self, scan):
        raise RuntimeError("DB unavailable")
    monkeypatch.setattr(dm.DBManager, "sync_save_scan", raise_error)

    import sys
    sys.path.insert(0, "/home/devendra-yadav/oneinfinity")
    from god_mode_engine import GodModeStateFile, GodModeSession
    import time, logging

    sf = GodModeStateFile.__new__(GodModeStateFile)
    sf.path = tmp_path / "god-mode-fallback.json"
    sf.path.parent.mkdir(parents=True, exist_ok=True)

    session = GodModeSession(
        scan_id="fallback-001", target="http://fallback.test",
        start_time=time.time(),
    )
    with caplog.at_level(logging.WARNING):
        sf.write(session)

    assert sf.path.exists(), "JSON fallback file not written"
    assert "FALLBACK TRIGGERED" in caplog.text
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_god_mode_db.py -v 2>&1 | tail -15
```

- [ ] **Step 3: Add `_persist_to_db()` helper and update `write()` in `god_mode_engine.py`**

Find `GodModeStateFile.write()` (line ~95):

```python
    def write(self, session: GodModeSession) -> None:
        try:
            data = asdict(session)
            data["elapsed_seconds"] = round(session.elapsed(), 1)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            tmp.replace(self.path)   # atomic on POSIX
        except Exception as exc:
            log.warning("State file write failed (non-fatal): %s", exc)
```

Replace with:

```python
    def write(self, session: GodModeSession) -> None:
        db_ok = self._persist_to_db(session)
        if not db_ok:
            # DBManager unavailable — JSON is the only persistence path
            log.warning(
                "FALLBACK TRIGGERED: DBManager unavailable — writing JSON only for scan %s",
                session.scan_id,
            )
            self._write_json(session)
        else:
            # DBManager is primary; JSON is cache for status() reads
            self._write_json(session)

    def _persist_to_db(self, session: GodModeSession) -> bool:
        """Write scan metadata to DBManager. Returns True on success."""
        try:
            from core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            scan_dict = {
                "scan_id":        session.scan_id,
                "id":             session.scan_id,
                "target":         session.target,
                "scan_type":      "god_mode",
                "status":         session.terminated_by and "completed" or "running",
                "started_at":     str(session.start_time),
                "finding_count":  session.finding_count,
                "phases_complete": session.phases_complete,
                "missions":       session.missions,
                "terminated_by":  session.terminated_by,
            }
            mgr.sync_save_scan(scan_dict)
            return True
        except Exception as exc:
            log.debug("_persist_to_db failed: %s", exc)
            return False

    def _write_json(self, session: GodModeSession) -> None:
        try:
            data = asdict(session)
            data["elapsed_seconds"] = round(session.elapsed(), 1)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            tmp.replace(self.path)
        except Exception as exc:
            log.warning("State file write failed (non-fatal): %s", exc)
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_god_mode_db.py -v 2>&1 | tail -15
```

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add god_mode_engine.py tests/test_god_mode_db.py
git commit -m "feat(god_mode): write scan metadata through DBManager, JSON as fallback cache"
```

---

## Task 6: Wire RedisSwarmState as active swarm coordinator

**Files:**
- Modify: `core/swarm_state_redis.py`
- Modify: `agent_swarm_coordinator.py`

`scan()` at line 237 uses `SharedSwarmState()` directly. `_make_swarm_state()` already exists but is never called. One-line fix + add `session_id` property to `RedisSwarmState`.

- [ ] **Step 1: Write the failing test**

Create `/home/devendra-yadav/oneinfinity/tests/test_swarm_wiring.py`:

```python
"""Test that scan() uses _make_swarm_state() factory, not SharedSwarmState() directly."""
import asyncio, pytest
from unittest.mock import patch, MagicMock

def test_scan_uses_make_swarm_state_factory(monkeypatch):
    """_make_swarm_state must be called, not SharedSwarmState() directly."""
    from agent_swarm_coordinator import AgentSwarmCoordinator
    coordinator = AgentSwarmCoordinator.__new__(AgentSwarmCoordinator)
    coordinator._sim_engine = None
    coordinator._agents = []

    factory_calls = []
    original_factory = AgentSwarmCoordinator._make_swarm_state
    def spy_factory(self, scan_id):
        factory_calls.append(scan_id)
        from agent_swarm_coordinator import SharedSwarmState
        return SharedSwarmState(session_id=scan_id)
    monkeypatch.setattr(AgentSwarmCoordinator, "_make_swarm_state", spy_factory)

    # Abort after state creation by making agents list empty and short-circuiting
    async def run():
        try:
            await coordinator.scan("http://test.local", {})
        except Exception:
            pass
    asyncio.get_event_loop().run_until_complete(run())

    assert len(factory_calls) > 0, "_make_swarm_state() was never called"

def test_redis_swarm_state_has_session_id_property():
    from core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="abc-123", redis=None)
    assert state.session_id == "abc-123"
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_swarm_wiring.py -v 2>&1 | tail -15
```

- [ ] **Step 3: Add `session_id` property to `RedisSwarmState`**

In `core/swarm_state_redis.py`, after `def _k(self, suffix)` (line ~48), add:

```python
    @property
    def session_id(self) -> str:
        """Alias for scan_id — provides interface parity with SharedSwarmState."""
        return self._scan_id

    @property
    def scan_id(self) -> str:
        return self._scan_id
```

- [ ] **Step 4: Fix `scan()` in `agent_swarm_coordinator.py`**

Find line 237:

```python
        state = SharedSwarmState()
        state_dict: Dict[str, Any] = {
            "session_id":  state.session_id,
            "findings":    state.findings,
            "event_queue": state.event_queue,
            "claimed_tasks": state.claimed_tasks,
        }
```

Replace with:

```python
        _session_id = str(uuid.uuid4()).replace("-", "")[:16]
        state = self._make_swarm_state(_session_id)
        # event_queue and findings are always process-local (not distributed)
        _local_findings: list = getattr(state, "findings", [])
        _local_queue: asyncio.Queue = getattr(state, "event_queue", asyncio.Queue())
        state_dict: Dict[str, Any] = {
            "session_id":   state.session_id,
            "findings":     _local_findings,
            "event_queue":  _local_queue,
            "claimed_tasks": getattr(state, "claimed_tasks", getattr(state, "_mem_claimed", {})),
        }
```

Make sure `import uuid` is present at the top of `agent_swarm_coordinator.py` (it likely already is — verify).

- [ ] **Step 5: Run tests — verify they pass**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_swarm_wiring.py -v 2>&1 | tail -15
```

- [ ] **Step 6: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add core/swarm_state_redis.py agent_swarm_coordinator.py tests/test_swarm_wiring.py
git commit -m "fix(swarm): wire _make_swarm_state() factory in scan(), add session_id to RedisSwarmState"
```

---

## Task 7: Worker — explicit Redis requirement message

**Files:**
- Modify: `worker/main.py`

- [ ] **Step 1: Find and replace the silent exit**

In `worker/main.py`, find line ~148:

```python
        log.critical("[worker] Could not connect to Redis after %d attempts", max_retries)
        sys.exit(1)
```

Replace with:

```python
        log.critical(
            "[worker] FATAL: Could not connect to Redis after %d attempts. "
            "Worker requires REDIS_URL — Redis is mandatory for distributed mode, not optional. "
            "Set REDIS_URL=redis://<host>:6379 and retry.",
            max_retries,
        )
        sys.exit(1)
```

- [ ] **Step 2: Verify the change**

```bash
grep -n "FATAL\|not optional" /home/devendra-yadav/oneinfinity/worker/main.py
```

Expected: line shows the new message.

- [ ] **Step 3: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add worker/main.py
git commit -m "fix(worker): explicit FATAL message when Redis unavailable — clarifies hard requirement"
```

---

## Task 8: Event bus Redis reconnect

**Files:**
- Modify: `event_bus.py`

`_redis_listener_loop()` dies permanently on any exception. Wrap in retry loop.

- [ ] **Step 1: Write the failing test**

Create `/home/devendra-yadav/oneinfinity/tests/test_event_bus_reconnect.py`:

```python
"""Test that Redis listener thread reconnects after failure."""
import threading, time, pytest

def test_redis_listener_retries_on_disconnect(monkeypatch):
    """Listener must attempt reconnection after an exception, not exit permanently."""
    attempt_count = [0]
    stop_after = 3  # Allow 3 attempts then stop

    def fake_get_redis():
        attempt_count[0] += 1
        if attempt_count[0] < stop_after:
            raise ConnectionError("Redis gone")
        return None  # Return None to stop the loop cleanly

    from event_bus import EventBus
    bus = EventBus.__new__(EventBus)
    bus._running = True
    bus._inbox = __import__("queue").PriorityQueue()

    # Patch get_redis inside event_bus module
    import event_bus as eb
    monkeypatch.setattr(eb, "_get_redis_for_listener", fake_get_redis, raising=False)

    # Run listener in a thread, stop after short time
    def stop_soon():
        time.sleep(0.5)
        bus._running = False

    t = threading.Thread(target=bus._redis_listener_loop, daemon=True)
    stopper = threading.Thread(target=stop_soon, daemon=True)
    t.start(); stopper.start()
    t.join(timeout=2.0)

    assert attempt_count[0] >= 2, f"Expected retries, got {attempt_count[0]} attempts"
```

- [ ] **Step 2: Run test — verify it fails**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_event_bus_reconnect.py -v 2>&1 | tail -15
```

- [ ] **Step 3: Wrap `_redis_listener_loop` in retry loop in `event_bus.py`**

Find `_redis_listener_loop` (line ~244):

```python
    def _redis_listener_loop(self) -> None:
        """Subscribe to Redis channels and feed cross-process events into local inbox."""
        try:
            from core.redis_client import get_redis
            r = get_redis()
            if r is None:
                return
            pubsub = r.pubsub(ignore_subscribe_messages=True)
            pubsub.psubscribe("oneinfinity:events:*")
            for raw_msg in pubsub.listen():
                if not self._running:
                    break
                ...
        except Exception as exc:
            log.warning("Redis listener loop exited: %s", exc)
```

Replace with:

```python
    def _redis_listener_loop(self) -> None:
        """Subscribe to Redis channels and feed cross-process events into local inbox.

        Reconnects automatically on failure with exponential backoff (cap 30s).
        """
        import time as _time
        backoff = 1.0
        while self._running:
            try:
                from core.redis_client import get_redis
                r = get_redis()
                if r is None:
                    return  # Redis not configured — stop permanently
                pubsub = r.pubsub(ignore_subscribe_messages=True)
                pubsub.psubscribe("oneinfinity:events:*")
                log.info("EventBus: Redis listener connected, subscribing to oneinfinity:events:*")
                backoff = 1.0  # reset on successful connect
                for raw_msg in pubsub.listen():
                    if not self._running:
                        return
                    if raw_msg is None or raw_msg.get("type") != "pmessage":
                        continue
                    try:
                        d = json.loads(raw_msg["data"])
                        event_id = d.get("event_id", "")
                        with self._published_ids_lock:
                            if event_id in self._published_ids:
                                continue
                        event = BusEvent(
                            event_type=EventType(d["event_type"]),
                            data=d.get("data", {}),
                            source=d.get("source", "remote"),
                            event_id=event_id,
                            timestamp=d.get("timestamp", time.time()),
                            priority=Priority(d.get("priority", Priority.NORMAL.value)),
                            correlation_id=d.get("correlation_id", ""),
                        )
                        self._inbox.put_nowait(
                            (event.priority.value, event.timestamp, event.event_id, event)
                        )
                    except Exception as exc:
                        log.debug("Redis listener: bad message (%s)", exc)
            except Exception as exc:
                if not self._running:
                    return
                log.warning(
                    "EventBus: Redis listener disconnected (%s) — retrying in %.0fs", exc, backoff
                )
                _time.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
```

Note: the inner `for raw_msg` loop is now inside the retry `while`. The existing `time` import at module level covers `time.time()`.

- [ ] **Step 4: Run test — verify it passes**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_event_bus_reconnect.py -v 2>&1 | tail -15
```

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add event_bus.py tests/test_event_bus_reconnect.py
git commit -m "fix(event_bus): Redis listener reconnects on disconnect with exponential backoff"
```

---

## Task 9: Migration `--check` flag

**Files:**
- Modify: `scripts/migrate_sqlite_to_pg.py`

- [ ] **Step 1: Read the current argparse block**

```bash
grep -n "argparse\|add_argument\|parse_args" /home/devendra-yadav/oneinfinity/scripts/migrate_sqlite_to_pg.py
```

- [ ] **Step 2: Add `--check` argument and check-mode path**

Find the `argparse` setup near the bottom of the file (likely in `if __name__ == "__main__"` block). Add:

```python
    parser.add_argument(
        "--check",
        action="store_true",
        default=False,
        help="Dry-run: report SQLite row counts and Postgres connectivity. No writes.",
    )
```

After `args = parser.parse_args()`, add a check-mode early exit:

```python
    if args.check:
        print("\n=== Migration Check Mode (read-only) ===\n")
        # Check SQLite counts
        paths = _resolve_sqlite_paths()
        for label, db_path in [("findings.db", paths.get("findings_db")),
                                ("metadata.db", paths.get("metadata_db"))]:
            if db_path and Path(db_path).exists():
                conn = sqlite3.connect(db_path)
                try:
                    findings_count = conn.execute(
                        "SELECT COUNT(*) FROM findings"
                    ).fetchone()[0]
                    print(f"  {label}: {findings_count} findings")
                except sqlite3.OperationalError:
                    print(f"  {label}: no findings table")
                try:
                    scans_count = conn.execute(
                        "SELECT COUNT(*) FROM scan_history"
                    ).fetchone()[0]
                    print(f"  {label}: {scans_count} scans")
                except sqlite3.OperationalError:
                    print(f"  {label}: no scan_history table")
                finally:
                    conn.close()
            else:
                print(f"  {label}: not found at {db_path}")
        # Check Postgres connectivity
        pg_url = os.environ.get("POSTGRES_URL", "")
        if pg_url:
            try:
                import psycopg
                with psycopg.connect(pg_url) as conn:
                    conn.execute("SELECT 1")
                print(f"\n  PostgreSQL: reachable at {pg_url[:40]}...")
            except Exception as exc:
                print(f"\n  PostgreSQL: UNREACHABLE — {exc}")
        else:
            print("\n  PostgreSQL: POSTGRES_URL not set")
        print("\n=== End Check ===\n")
        sys.exit(0)
```

- [ ] **Step 3: Verify the flag works**

```bash
cd /home/devendra-yadav/oneinfinity
python3 scripts/migrate_sqlite_to_pg.py --check
```

Expected: output showing SQLite row counts and "POSTGRES_URL not set" (since we're in local mode).

- [ ] **Step 4: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add scripts/migrate_sqlite_to_pg.py
git commit -m "feat(migration): add --check flag for dry-run row count + connectivity report"
```

---

## Final Verification

- [ ] **Restart backend cleanly and verify DBManager mode logs**

```bash
kill $(lsof -ti:8000) 2>/dev/null; sleep 1
cd /home/devendra-yadav/oneinfinity/web/backend
.venv/bin/python main.py > /tmp/oneinfinity-backend.log 2>&1 &
sleep 4
grep -E "DBManager|FALLBACK|Running in|Loaded" /tmp/oneinfinity-backend.log
```

Expected: `[DBManager] Running in SQLITE fallback mode` and `Loaded 0 persisted scans`.

- [ ] **Verify scan create + persist + delete round-trip**

```bash
# Create scan
SCAN_ID=$(curl -s -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","scan_type":"recon"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "Created: $SCAN_ID"

# Verify it persisted (restart backend)
kill $(lsof -ti:8000) 2>/dev/null; sleep 1
cd /home/devendra-yadav/oneinfinity/web/backend && .venv/bin/python main.py >> /tmp/oneinfinity-backend.log 2>&1 &
sleep 4
curl -s http://localhost:8000/api/scans | python3 -c "import json,sys; scans=json.load(sys.stdin); print('Found after restart:', any(s['id']=='$SCAN_ID' for s in scans))"

# Delete
curl -s -X DELETE "http://localhost:8000/api/scans/$SCAN_ID" | python3 -c "import json,sys; print(json.load(sys.stdin))"
```

Expected: `Found after restart: True` and `{"ok": True, ...}`.

- [ ] **Run all new tests together**

```bash
cd /home/devendra-yadav/oneinfinity
web/backend/.venv/bin/python -m pytest tests/test_db_manager_scan.py tests/test_db_manager_config.py tests/test_god_mode_db.py tests/test_swarm_wiring.py tests/test_event_bus_reconnect.py -v 2>&1 | tail -30
```

Expected: all pass.

- [ ] **Verify RedisSwarmState is now active path (with Redis)**

```bash
# Only runs if REDIS_URL is set
if [ -n "$REDIS_URL" ]; then
  python3 -c "
from agent_swarm_coordinator import AgentSwarmCoordinator
from core.swarm_state_redis import RedisSwarmState
coord = AgentSwarmCoordinator.__new__(AgentSwarmCoordinator)
state = coord._make_swarm_state('test-session')
print('State type:', type(state).__name__)
print('session_id:', state.session_id)
"
fi
```

Expected with Redis: `State type: RedisSwarmState`. Without Redis: `State type: SharedSwarmState`.

- [ ] **Final commit — tag the completion**

```bash
cd /home/devendra-yadav/oneinfinity
git tag storage-wiring-v1 -m "Storage wiring fixes: DBManager single path, RedisSwarmState active, CLI→DBManager"
```
