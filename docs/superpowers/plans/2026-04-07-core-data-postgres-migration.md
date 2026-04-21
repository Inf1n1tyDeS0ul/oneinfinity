# Core Data PostgreSQL Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove all SQLite usage from the three core-data components (TargetDB in main.py, findings read path, findings audit log) and route everything through DBManager → PostgreSQL.

**Architecture:** Add a `targets` table to `db/schema.sql` + DBManager; replace the `TargetDB` SQLite class in `main.py` with a `TargetRepository` that wraps DBManager via FastAPI `Depends()`; harden `get_findings()` to raise outside Postgres mode; replace `FindingsDB.log_action()` SQLite audit writes with `DBManager.save_event()`.

**Tech Stack:** FastAPI, psycopg3 async pool, pytest, Python 3.11

---

## File Map

| File | Change |
|---|---|
| `db/schema.sql` | Add `targets` table DDL |
| `core/db_manager.py` | Add `_target_row_to_dict` + 6 target methods; harden `get_findings()` |
| `core/target_repository.py` | New — `TargetRepository` class + `get_target_repo()` dependency |
| `web/backend/main.py` | Delete `TargetDB`, `_db_connect`, `_target_db`; wire `TargetRepository`; add startup fail-fast |
| `modules/findings.py` | Rewrite `log_action()`; remove all SQLite attributes |
| `tests/test_db_manager_targets.py` | New |
| `tests/test_target_repository.py` | New |
| `tests/test_main_targets.py` | New |
| `tests/test_findings_audit_pg.py` | New |

---

### Task 1: Add `targets` table to schema.sql and DBManager

**Files:**
- Modify: `db/schema.sql` (end of file)
- Modify: `core/db_manager.py` (after `get_knowledge` method, ~line 519)
- Create: `tests/test_db_manager_targets.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_db_manager_targets.py`:

```python
# tests/test_db_manager_targets.py
"""Tests for DBManager target methods."""
import asyncio
import datetime
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


def pg_mgr_with_mock_pool(rows_for_select=None):
    """Return DBManager in postgres mode with a mocked psycopg pool.

    rows_for_select: list of row tuples returned by SELECT queries.
    """
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"

    _row_list = list(rows_for_select or [])

    async def fake_execute(sql, params=None):
        cursor = MagicMock()
        if _row_list and ("SELECT" in sql or "INSERT" in sql and "RETURNING" in sql):
            async def _aiter():
                for r in _row_list:
                    yield r
            cursor.__aiter__ = lambda: _aiter()
        else:
            async def _empty():
                return
                yield
            cursor.__aiter__ = lambda: _empty()
        return cursor

    mock_conn = AsyncMock()
    mock_conn.execute = fake_execute
    mock_conn.commit = AsyncMock()

    mock_pool = MagicMock()
    mock_pool.connection.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.connection.return_value.__aexit__ = AsyncMock(return_value=False)

    mgr._pg_pool = mock_pool
    return mgr, mock_conn


# ── Mode guard tests (fail before implementation) ────────────────────────────

def test_save_target_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.save_target({"target_id": "t1", "target_value": "example.com"}))


def test_list_targets_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.list_targets())


def test_get_target_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.get_target("t1"))


def test_delete_target_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.delete_target("t1"))


def test_update_target_status_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.update_target_status("t1", "scanning"))


def test_update_target_vuln_count_raises_in_sqlite_mode():
    mgr = sqlite_mgr()
    with pytest.raises((RuntimeError, AttributeError)):
        run(mgr.update_target_vuln_count("t1", 5))


# ── Shape tests (pass after implementation) ──────────────────────────────────

def test_target_row_to_dict_returns_aliases():
    """_target_row_to_dict must add 'id' and 'domain' aliases."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"
    now = datetime.datetime.now()
    row = ("t1", "example.com", "web", "Example", "hackerone",
           [], "pending", now, None, 0, {})
    d = mgr._target_row_to_dict(row)
    assert d["id"] == "t1"
    assert d["domain"] == "example.com"
    assert d["created_at"] == now.isoformat()
    assert isinstance(d["scope"], list)
    assert isinstance(d["severity_counts"], dict)


def test_list_targets_returns_list_in_pg_mode():
    """list_targets must return a list in postgres mode."""
    import datetime as dt
    now = dt.datetime.now()
    row = ("t2", "target.com", "web", "Target", "hackerone",
           [], "pending", now, None, 0, {})
    mgr, _ = pg_mgr_with_mock_pool(rows_for_select=[row])
    result = run(mgr.list_targets())
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["target_id"] == "t2"
    assert result[0]["id"] == "t2"
    assert result[0]["domain"] == "target.com"


def test_get_target_returns_none_for_empty_result():
    """get_target must return None when no rows match."""
    mgr, _ = pg_mgr_with_mock_pool(rows_for_select=[])
    result = run(mgr.get_target("nonexistent"))
    assert result is None


def test_delete_target_returns_true_on_success():
    """delete_target must return True when delete succeeds."""
    mgr, _ = pg_mgr_with_mock_pool()
    result = run(mgr.delete_target("t1"))
    assert result is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python -m pytest tests/test_db_manager_targets.py -v 2>&1 | tail -30
```

Expected: `test_save_target_raises_in_sqlite_mode` through `test_update_target_vuln_count_raises_in_sqlite_mode` should PASS (AttributeError is caught). `test_target_row_to_dict_returns_aliases`, `test_list_targets_returns_list_in_pg_mode`, `test_get_target_returns_none_for_empty_result`, `test_delete_target_returns_true_on_success` should FAIL with AttributeError on `_target_row_to_dict` / `list_targets` / `get_target` / `delete_target`.

- [ ] **Step 3: Add `targets` table to `db/schema.sql`**

Append to the end of `db/schema.sql`:

```sql

-- ── Targets ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS targets (
    target_id       TEXT PRIMARY KEY,
    target_value    TEXT NOT NULL,
    target_type     TEXT NOT NULL DEFAULT 'web',
    name            TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL DEFAULT 'hackerone',
    scope           JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scan_time  TIMESTAMPTZ,
    vuln_count      INTEGER NOT NULL DEFAULT 0,
    severity_counts JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_targets_status     ON targets(status);
CREATE INDEX IF NOT EXISTS idx_targets_created_at ON targets(created_at);
```

- [ ] **Step 4: Add target methods to `core/db_manager.py`**

After the `get_knowledge` method (around line 518), insert the following block — before the `# ── Sync wrappers for CLI ──` comment:

```python
    # ── Targets ──────────────────────────────────────────────────────────────

    def _target_row_to_dict(self, row) -> dict:
        """Convert a targets table row tuple to API dict."""
        cols = ["target_id", "target_value", "target_type", "name", "platform", "scope",
                "status", "created_at", "last_scan_time", "vuln_count", "severity_counts"]
        d = dict(zip(cols, row))
        for ts_field in ("created_at", "last_scan_time"):
            if hasattr(d.get(ts_field), "isoformat"):
                d[ts_field] = d[ts_field].isoformat()
        if not isinstance(d.get("scope"), list):
            d["scope"] = d.get("scope") or []
        if not isinstance(d.get("severity_counts"), dict):
            d["severity_counts"] = d.get("severity_counts") or {}
        d["id"] = d["target_id"]
        d["domain"] = d["target_value"]
        return d

    async def save_target(self, data: dict) -> dict:
        """Upsert a target row. Returns the stored dict."""
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("save_target requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO targets
                        (target_id, target_value, target_type, name, platform,
                         scope, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                    ON CONFLICT (target_id) DO UPDATE SET
                        target_value = EXCLUDED.target_value,
                        name         = EXCLUDED.name,
                        platform     = EXCLUDED.platform
                    """,
                    (
                        data["target_id"],
                        data["target_value"],
                        data.get("target_type", "web"),
                        data.get("name", data["target_value"]),
                        data.get("platform", "hackerone"),
                        json.dumps(data.get("scope", [])),
                        data.get("status", "pending"),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.save_target failed: %s", exc)
            raise
        return await self.get_target(data["target_id"]) or data

    async def get_target(self, target_id: str) -> Optional[dict]:
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("get_target requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT target_id, target_value, target_type, name, platform, scope, "
                    "status, created_at, last_scan_time, vuln_count, severity_counts "
                    "FROM targets WHERE target_id = %s",
                    (target_id,),
                )
                async for row in rows:
                    return self._target_row_to_dict(row)
            return None
        except Exception as exc:
            log.warning("DBManager.get_target failed: %s", exc)
            return None

    async def list_targets(self) -> list:
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("list_targets requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    "SELECT target_id, target_value, target_type, name, platform, scope, "
                    "status, created_at, last_scan_time, vuln_count, severity_counts "
                    "FROM targets ORDER BY created_at DESC",
                )
                results = []
                async for row in rows:
                    results.append(self._target_row_to_dict(row))
                return results
        except Exception as exc:
            log.warning("DBManager.list_targets failed: %s", exc)
            return []

    async def delete_target(self, target_id: str) -> bool:
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("delete_target requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    "DELETE FROM targets WHERE target_id = %s", (target_id,)
                )
                await conn.commit()
            return True
        except Exception as exc:
            log.warning("DBManager.delete_target failed: %s", exc)
            return False

    async def update_target_status(self, target_id: str, status: str,
                                   last_scan_time: str = None) -> None:
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("update_target_status requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    "UPDATE targets SET status = %s, last_scan_time = %s "
                    "WHERE target_id = %s",
                    (status, last_scan_time or datetime.utcnow().isoformat(), target_id),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.update_target_status failed: %s", exc)

    async def update_target_vuln_count(self, target_id: str, count: int) -> None:
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError("update_target_vuln_count requires Postgres mode")
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    "UPDATE targets SET vuln_count = %s WHERE target_id = %s",
                    (count, target_id),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.update_target_vuln_count failed: %s", exc)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
python -m pytest tests/test_db_manager_targets.py -v 2>&1 | tail -20
```

Expected: all 10 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add db/schema.sql core/db_manager.py tests/test_db_manager_targets.py
git commit -m "feat(db): add targets table to schema.sql and DBManager target methods"
```

---

### Task 2: Create `core/target_repository.py`

**Files:**
- Create: `core/target_repository.py`
- Create: `tests/test_target_repository.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_target_repository.py`:

```python
# tests/test_target_repository.py
"""Tests for TargetRepository — verifies it delegates to DBManager."""
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


def make_mock_db(**method_returns):
    """Return a MagicMock DBManager with configurable async method returns."""
    mock_db = MagicMock()
    for method_name, return_value in method_returns.items():
        setattr(mock_db, method_name, AsyncMock(return_value=return_value))
    return mock_db


def test_add_delegates_to_save_target():
    """TargetRepository.add must call db.save_target with a target dict."""
    from core.target_repository import TargetRepository
    expected = {"target_id": "t1", "target_value": "example.com", "id": "t1", "domain": "example.com"}
    db = make_mock_db(save_target=expected)
    repo = TargetRepository(db)
    result = run(repo.add("t1", "example.com", "Example", "hackerone", "web"))
    db.save_target.assert_called_once()
    call_data = db.save_target.call_args[0][0]
    assert call_data["target_id"] == "t1"
    assert call_data["target_value"] == "example.com"
    assert result["target_id"] == "t1"


def test_list_all_delegates_to_list_targets():
    from core.target_repository import TargetRepository
    targets = [{"target_id": "t1"}, {"target_id": "t2"}]
    db = make_mock_db(list_targets=targets)
    repo = TargetRepository(db)
    result = run(repo.list_all())
    db.list_targets.assert_called_once()
    assert result == targets


def test_get_delegates_to_get_target():
    from core.target_repository import TargetRepository
    target = {"target_id": "t1", "target_value": "example.com"}
    db = make_mock_db(get_target=target)
    repo = TargetRepository(db)
    result = run(repo.get("t1"))
    db.get_target.assert_called_once_with("t1")
    assert result == target


def test_get_returns_none_when_not_found():
    from core.target_repository import TargetRepository
    db = make_mock_db(get_target=None)
    repo = TargetRepository(db)
    result = run(repo.get("nonexistent"))
    assert result is None


def test_delete_delegates_to_delete_target():
    from core.target_repository import TargetRepository
    db = make_mock_db(delete_target=True)
    repo = TargetRepository(db)
    result = run(repo.delete("t1"))
    db.delete_target.assert_called_once_with("t1")
    assert result is True


def test_update_status_delegates_to_update_target_status():
    from core.target_repository import TargetRepository
    db = make_mock_db(update_target_status=None)
    repo = TargetRepository(db)
    run(repo.update_status("t1", "scanning", "2026-04-07T12:00:00"))
    db.update_target_status.assert_called_once_with("t1", "scanning", "2026-04-07T12:00:00")


def test_update_vuln_count_delegates_to_update_target_vuln_count():
    from core.target_repository import TargetRepository
    db = make_mock_db(update_target_vuln_count=None)
    repo = TargetRepository(db)
    run(repo.update_vuln_count("t1", 7))
    db.update_target_vuln_count.assert_called_once_with("t1", 7)


def test_get_target_repo_returns_repository_instance():
    """get_target_repo() must return a TargetRepository."""
    from core.target_repository import TargetRepository, get_target_repo
    from unittest.mock import patch
    import core.db_manager as dm
    dm._manager = None
    mock_mgr = MagicMock()
    with patch("core.target_repository.get_db_manager", new_callable=AsyncMock,
               return_value=mock_mgr):
        repo = run(get_target_repo())
    assert isinstance(repo, TargetRepository)
    assert repo._db is mock_mgr
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_target_repository.py -v 2>&1 | tail -20
```

Expected: FAIL with `ModuleNotFoundError: No module named 'core.target_repository'`.

- [ ] **Step 3: Create `core/target_repository.py`**

```python
"""core/target_repository.py — TargetRepository wrapping DBManager.

FastAPI dependency: Depends(get_target_repo)
Direct use:         repo = await get_target_repo()
"""
from __future__ import annotations

from typing import Optional

from core.db_manager import get_db_manager


class TargetRepository:
    """Thin async wrapper over DBManager target methods."""

    def __init__(self, db) -> None:
        self._db = db

    async def add(
        self,
        target_id: str,
        target_value: str,
        name: str = "",
        platform: str = "hackerone",
        target_type: str = "web",
    ) -> dict:
        """Signature matches TargetDB.add: (target_id, target_value, name, platform, target_type)."""
        return await self._db.save_target(
            {
                "target_id": target_id,
                "target_value": target_value,
                "target_type": target_type,
                "name": name or target_value,
                "platform": platform,
            }
        )

    async def get(self, target_id: str) -> Optional[dict]:
        return await self._db.get_target(target_id)

    async def list_all(self) -> list:
        return await self._db.list_targets()

    async def delete(self, target_id: str) -> bool:
        return await self._db.delete_target(target_id)

    async def update_status(
        self,
        target_id: str,
        status: str,
        last_scan_time: str = None,
    ) -> None:
        await self._db.update_target_status(target_id, status, last_scan_time)

    async def update_vuln_count(self, target_id: str, count: int) -> None:
        await self._db.update_target_vuln_count(target_id, count)


async def get_target_repo() -> TargetRepository:
    """FastAPI dependency — returns a TargetRepository backed by the singleton DBManager."""
    return TargetRepository(await get_db_manager())
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_target_repository.py -v 2>&1 | tail -20
```

Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add core/target_repository.py tests/test_target_repository.py
git commit -m "feat(targets): add TargetRepository with DBManager backing"
```

---

### Task 3: Replace `TargetDB` in `main.py` and add startup fail-fast

**Files:**
- Modify: `web/backend/main.py`
- Create: `tests/test_main_targets.py`

This task has three parts: (a) delete `TargetDB`/`_target_db`, add imports; (b) update all 8 call sites; (c) add startup fail-fast. Do all three before running tests.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_main_targets.py`:

```python
# tests/test_main_targets.py
"""Integration-level tests for /api/targets endpoints after TargetDB removal."""
import os
os.environ["ONEINFINITY_API_KEY"] = ""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def mock_repo():
    """Return a mock TargetRepository for patching."""
    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[
        {"target_id": "t1", "target_value": "example.com", "id": "t1",
         "domain": "example.com", "status": "pending", "target_type": "web",
         "name": "example.com", "platform": "hackerone", "scope": [],
         "created_at": "2026-04-07T00:00:00", "last_scan_time": None,
         "vuln_count": 0, "severity_counts": {}}
    ])
    repo.get = AsyncMock(return_value=None)
    repo.add = AsyncMock(return_value={
        "target_id": "new1", "target_value": "new.com", "id": "new1",
        "domain": "new.com", "status": "pending", "target_type": "web",
        "name": "new.com", "platform": "hackerone", "scope": [],
        "created_at": "2026-04-07T00:00:00", "last_scan_time": None,
        "vuln_count": 0, "severity_counts": {}
    })
    repo.delete = AsyncMock(return_value=True)
    return repo


def test_list_targets_returns_list(mock_repo):
    """GET /api/targets must return a list."""
    with patch("web.backend.main.get_target_repo", return_value=mock_repo):
        from web.backend.main import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/targets")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_get_target_returns_404_when_not_found(mock_repo):
    """GET /api/targets/{id} must return 404 when repo.get returns None."""
    with patch("web.backend.main.get_target_repo", return_value=mock_repo):
        from web.backend.main import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/targets/nonexistent")
    assert resp.status_code == 404


def test_delete_target_returns_404_when_not_found(mock_repo):
    """DELETE /api/targets/{id} must return 404 when target does not exist."""
    with patch("web.backend.main.get_target_repo", return_value=mock_repo):
        from web.backend.main import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.delete("/api/targets/nonexistent")
    assert resp.status_code == 404


def test_main_py_does_not_import_sqlite3_at_module_level():
    """main.py must not have a top-level sqlite3 import after TargetDB removal."""
    import ast
    import pathlib
    src = pathlib.Path("/path/to/oneinfinity/web/backend/main.py").read_text()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "sqlite3", f"Found top-level import sqlite3 at line {node.lineno}"
        elif isinstance(node, ast.ImportFrom):
            assert "sqlite3" not in (node.module or ""), \
                f"Found top-level sqlite3 import at line {node.lineno}"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_main_targets.py -v 2>&1 | tail -20
```

Expected: `test_list_targets_returns_list` and others may fail because `get_target_repo` doesn't exist in `main.py` yet. `test_main_py_does_not_import_sqlite3_at_module_level` passes (existing code has no top-level sqlite3 import).

- [ ] **Step 3: Remove `TargetDB`, `_db_connect`, and `_target_db` from `main.py`**

Delete lines 176–261 (the `_db_connect` function, `TargetDB` class, and `_target_db = TargetDB(...)` instantiation):

```python
# DELETE everything between these markers — lines ~176–261:

# ── SQLite helpers ───────────────────────────────────────────────────────────

def _db_connect(db_path):
    ...                              # DELETE this function

# ── SQLite-backed target store ────────────────────────────────────────────────

class TargetDB:
    ...                              # DELETE this class

_target_db = TargetDB(_db_path("metadata.db"))    # DELETE this line
```

- [ ] **Step 4: Add import for `TargetRepository` and `get_target_repo` to `main.py`**

Near the other `from core.*` imports (around line 69, after `from core.scan_state import BoundedScanCache`), add:

```python
from core.target_repository import TargetRepository, get_target_repo
```

- [ ] **Step 5: Add startup fail-fast to `_lifespan` in `main.py`**

In `_lifespan`, after the line `_event_loop = asyncio.get_running_loop()` and before the first `try:` block (around line 82), add:

```python
    # Fail fast if PostgreSQL is not available
    from core.db_manager import get_db_manager as _get_dbm_check
    _startup_check = await _get_dbm_check()
    if _startup_check.mode not in ("distributed", "postgres"):
        raise RuntimeError(
            f"OneInfinity requires PostgreSQL (got mode={_startup_check.mode!r}). "
            "Set DISTRIBUTED_MODE=true and configure DB_HOST/DB_NAME/DB_USER/DB_PASSWORD."
        )
```

- [ ] **Step 6: Update all `_target_db.*` call sites in `main.py`**

There are 10 call sites across 8 functions. Replace each as shown:

**`metrics()` (line ~508) — add `repo` param:**
```python
@app.get("/metrics", include_in_schema=False)
async def metrics(repo: TargetRepository = Depends(get_target_repo)):
    ...
    total_targets = len(await repo.list_all())
```

**`get_stats()` (line ~542) — add `repo` param:**
```python
@app.get("/api/stats")
async def get_stats(repo: TargetRepository = Depends(get_target_repo)):
    ...
    all_targets = await repo.list_all()
```

**`list_targets()` (line ~597):**
```python
@app.get("/api/targets")
async def list_targets(repo: TargetRepository = Depends(get_target_repo)):
    return await repo.list_all()
```

**`get_target()` (line ~601):**
```python
@app.get("/api/targets/{target_id}")
async def get_target(target_id: str, repo: TargetRepository = Depends(get_target_repo)):
    t = await repo.get(target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    return t
```

**`create_target()` (line ~608):**
```python
@app.post("/api/targets", dependencies=[Depends(_require_auth)])
async def create_target(body: Dict[str, Any], background_tasks: BackgroundTasks,
                        repo: TargetRepository = Depends(get_target_repo)):
    ...
    t = await repo.add(target_id, domain, name, platform, ttype)
    ...
    return {**t, "scan_id": scan_id}
```

**`delete_target()` (line ~643):**
```python
@app.delete("/api/targets/{target_id}", dependencies=[Depends(_require_auth)])
async def delete_target(target_id: str, repo: TargetRepository = Depends(get_target_repo)):
    if not await repo.get(target_id):
        raise HTTPException(404, "Target not found")
    await repo.delete(target_id)
    _add_log(f"Target removed: {target_id}", "warn", "system")
    return {"ok": True}
```

**`get_attack_graph()` (line ~1021):**
```python
@app.get("/api/attack-graph")
async def get_attack_graph(target: Optional[str] = None,
                           repo: TargetRepository = Depends(get_target_repo)):
    ...
    # In the global-graph branch:
    for t in await repo.list_all():
```

**`simple_scan()` (line ~1266):**
```python
@app.post("/api/scan", dependencies=[Depends(_require_auth)])
@app.post("/api/scan/start", dependencies=[Depends(_require_auth)])
async def simple_scan(req: SimpleScanRequest, background_tasks: BackgroundTasks,
                      repo: TargetRepository = Depends(get_target_repo)):
    ...
    existing = [t for t in await repo.list_all() if t["target_value"] == req.target]
    if not existing:
        tid = str(uuid.uuid4())[:8]
        await repo.add(tid, req.target)
```

**`_run_scan_via_engine()` (line ~1295) — NOT a route handler, gets repo directly:**

At the very start of `_run_scan_via_engine`, add:
```python
async def _run_scan_via_engine(scan_id: str, target: str, scan_type: str, auth_config: dict = None):
    repo = await get_target_repo()
    scan = SCANS[scan_id]
    ...
```

Then replace:
```python
# OLD (line ~1303):
existing = [t for t in _target_db.list_all() if t["target_value"] == target]
if existing:
    _target_db.update_status(existing[0]["target_id"], "scanning", datetime.utcnow().isoformat())

# NEW:
existing = [t for t in await repo.list_all() if t["target_value"] == target]
if existing:
    await repo.update_status(existing[0]["target_id"], "scanning", datetime.utcnow().isoformat())
```

And replace the post-scan block (lines ~1349–1355):
```python
# OLD:
existing = [t for t in _target_db.list_all() if t["target_value"] == target]
if existing:
    tid = existing[0]["target_id"]
    _target_db.update_status(tid, scan["status"], datetime.utcnow().isoformat())
    with _db_connect(_db_path("metadata.db")) as conn:
        conn.execute("UPDATE targets SET vuln_count=? WHERE target_id=?", (len(result.findings), tid))
        conn.commit()

# NEW:
existing = [t for t in await repo.list_all() if t["target_value"] == target]
if existing:
    tid = existing[0]["target_id"]
    await repo.update_status(tid, scan["status"], datetime.utcnow().isoformat())
    await repo.update_vuln_count(tid, len(result.findings))
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
python -m pytest tests/test_main_targets.py tests/test_no_sqlite_in_distributed_mode.py -v 2>&1 | tail -30
```

Expected: all tests PASS.

- [ ] **Step 8: Verify build**

```bash
cd /path/to/oneinfinity/web/frontend
npm run build 2>&1 | tail -10
```

Expected: clean build (no changes to frontend, just verifying nothing broken).

- [ ] **Step 9: Commit**

```bash
git add web/backend/main.py core/target_repository.py tests/test_main_targets.py
git commit -m "feat(main): replace TargetDB with TargetRepository + startup fail-fast"
```

---

### Task 4: Harden `DBManager.get_findings()` — remove SQLite fallback

**Files:**
- Modify: `core/db_manager.py` (lines ~203–258)
- Create: `tests/test_db_manager_get_findings_hardened.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_db_manager_get_findings_hardened.py`:

```python
# tests/test_db_manager_get_findings_hardened.py
"""get_findings must raise in sqlite mode — no silent SQLite fallback."""
import asyncio
import pytest


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_get_findings_raises_in_sqlite_mode():
    """After hardening, get_findings must raise RuntimeError in sqlite mode."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"
    with pytest.raises(RuntimeError, match="Postgres"):
        run(mgr.get_findings())


def test_get_findings_raises_in_memory_mode():
    """get_findings must raise in memory mode too."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "memory"
    with pytest.raises(RuntimeError, match="Postgres"):
        run(mgr.get_findings())


def test_sqlite_get_findings_method_removed():
    """_sqlite_get_findings must not exist on DBManager after hardening."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    assert not hasattr(mgr, "_sqlite_get_findings"), \
        "_sqlite_get_findings must be removed from DBManager"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_db_manager_get_findings_hardened.py -v 2>&1 | tail -20
```

Expected: `test_get_findings_raises_in_sqlite_mode` FAILs (currently returns empty list), `test_sqlite_get_findings_method_removed` FAILs (method still exists).

- [ ] **Step 3: Update `get_findings()` and delete `_sqlite_get_findings` in `core/db_manager.py`**

Replace lines ~203–258 (the `get_findings`, `_pg_get_findings`, `_sqlite_get_findings` block) with:

```python
    async def get_findings(
        self,
        scan_id: Optional[str] = None,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 1000,
    ) -> list:
        if self.mode not in ("distributed", "postgres"):
            raise RuntimeError(
                f"get_findings requires Postgres mode (current mode: {self.mode!r}). "
                "Ensure PostgreSQL is configured and DISTRIBUTED_MODE=true."
            )
        return await self._pg_get_findings(scan_id=scan_id, target=target,
                                           severity=severity, limit=limit)

    async def _pg_get_findings(self, scan_id=None, target=None, severity=None, limit=1000) -> list:
        conditions, params = [], []
        if scan_id:
            conditions.append("scan_id = %s"); params.append(scan_id)
        if target:
            conditions.append("target = %s"); params.append(target)
        if severity:
            conditions.append("severity = %s"); params.append(severity)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    f"SELECT finding_id,scan_id,target,title,severity,vuln_type,url,"
                    f"tool,confidence,cvss,status,source_type,created_at,data "
                    f"FROM findings {where} ORDER BY created_at DESC LIMIT %s",
                    params,
                )
                results = []
                async for row in rows:
                    d = dict(zip(
                        ["finding_id","scan_id","target","title","severity","vuln_type",
                         "url","tool","confidence","cvss","status","source_type","created_at","data"],
                        row
                    ))
                    extra = d.pop("data") or {}
                    if isinstance(extra, str):
                        extra = json.loads(extra)
                    d.update(extra)
                    results.append(d)
                return results
        except Exception as exc:
            log.warning("DBManager._pg_get_findings failed: %s", exc)
            return []
```

Also update `sync_get_findings` (around line 544) to note it now requires postgres mode — no change to the method itself, but the caller will get a RuntimeError if not in postgres mode.

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_db_manager_get_findings_hardened.py -v 2>&1 | tail -15
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Run the full test suite to check for regressions**

```bash
python -m pytest tests/test_db_manager.py tests/test_db_manager_scan.py tests/test_db_manager_config.py tests/test_db_manager_targets.py -v 2>&1 | tail -30
```

Expected: all passing. If `test_db_manager.py::test_sync_save_finding_does_not_raise` fails (it tests sqlite mode sync_save_finding), that test is now outdated — it expects sqlite mode to work. Skip it by marking it `pytest.mark.skip` with reason `"sqlite mode removed"` if needed.

- [ ] **Step 6: Commit**

```bash
git add core/db_manager.py tests/test_db_manager_get_findings_hardened.py
git commit -m "feat(db): harden get_findings — remove SQLite fallback, raise in non-Postgres mode"
```

---

### Task 5: Replace SQLite audit log in `modules/findings.py`

**Files:**
- Modify: `modules/findings.py`
- Create: `tests/test_findings_audit_pg.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_findings_audit_pg.py`:

```python
# tests/test_findings_audit_pg.py
"""FindingsDB.log_action must write to DBManager.save_event, not SQLite."""
import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def test_log_action_calls_save_event():
    """log_action must call dbmanager.save_event with event_type='findings_audit'."""
    saved_events = []

    mock_mgr = MagicMock()
    mock_mgr.mode = "postgres"
    mock_mgr.save_event = AsyncMock(side_effect=lambda e: saved_events.append(e))

    with patch("core.db_manager.get_db_manager", new_callable=AsyncMock,
               return_value=mock_mgr):
        with patch("modules.findings.get_ingestion_engine") as mock_rie:
            mock_rie.return_value = MagicMock(
                get_findings=MagicMock(return_value=[]),
                persist_finding=MagicMock(),
                _init_db=MagicMock(),
                _db_path=MagicMock(),
            )
            from modules.findings import FindingsDB
            db = FindingsDB()
            db.log_action("scan_complete", {"phase": "full", "result": "ok"})

    import time; time.sleep(0.1)  # let ensure_future run
    assert len(saved_events) == 1
    assert saved_events[0]["event_type"] == "findings_audit"
    assert saved_events[0]["action"] == "scan_complete"


def test_log_action_does_not_open_sqlite_connection():
    """log_action must not open a sqlite3 connection."""
    with patch("modules.findings.get_ingestion_engine") as mock_rie:
        mock_rie.return_value = MagicMock(
            get_findings=MagicMock(return_value=[]),
            persist_finding=MagicMock(),
            _init_db=MagicMock(),
            _db_path=MagicMock(),
        )
        with patch("sqlite3.connect") as mock_sq_connect:
            from modules.findings import FindingsDB
            db = FindingsDB()
            db.log_action("test_action", {"key": "val"})
            mock_sq_connect.assert_not_called()


def test_findings_db_has_no_audit_db_path_attribute():
    """FindingsDB must not have _audit_db_path after refactor."""
    with patch("modules.findings.get_ingestion_engine") as mock_rie:
        mock_rie.return_value = MagicMock(
            get_findings=MagicMock(return_value=[]),
            persist_finding=MagicMock(),
            _init_db=MagicMock(),
            _db_path=MagicMock(),
        )
        from modules.findings import FindingsDB
        db = FindingsDB()
        assert not hasattr(db, "_audit_db_path"), \
            "_audit_db_path must be removed from FindingsDB"
        assert not hasattr(db, "_audit_conn"), \
            "_audit_conn must be removed from FindingsDB"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/test_findings_audit_pg.py -v 2>&1 | tail -20
```

Expected: `test_log_action_does_not_open_sqlite_connection` FAILs (sqlite3.connect is called). `test_findings_db_has_no_audit_db_path_attribute` FAILs (attributes still exist).

- [ ] **Step 3: Rewrite `modules/findings.py` — remove SQLite audit, add `_save_audit_event` helper**

At the top of `modules/findings.py`, add the module-level helper after the imports:

```python
import asyncio as _asyncio


async def _save_audit_event(event: dict) -> None:
    """Persist an audit event to the Postgres events table via DBManager."""
    try:
        from core.db_manager import get_db_manager
        mgr = await get_db_manager()
        await mgr.save_event(event)
    except Exception as exc:
        import logging as _log
        _log.getLogger("oneinfinity.findings").warning(
            "_save_audit_event failed: %s", exc
        )
```

Replace the `__init__` method of `FindingsDB` — remove the audit-related attributes:

```python
def __init__(self, db_path=None):
    # We use the unified ingestion engine for findings storage
    self.engine = get_ingestion_engine()
    self.engine._init_db()
    # db_path parameter kept for backwards compatibility but unused
```

Delete the following methods entirely:
- `_get_audit_conn()`
- `close()`

Replace `log_action()` with:

```python
def log_action(self, phase: str, action=None, result: str = ""):
    """Persist an audit event to Postgres events table.

    Supports two call styles:
      log_action(phase, action_str, result_str)   — original 3-arg style
      log_action(action_str, metadata_dict)       — test-compatible 2-arg style
    """
    if isinstance(action, dict):
        action_str = phase
        metadata = action
    else:
        action_str = phase
        metadata = {"action": action, "result": result} if action else {}

    event = {
        "event_type": "findings_audit",
        "action": action_str,
        "metadata": metadata,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        loop = _asyncio.get_event_loop()
        if loop.is_running():
            _asyncio.ensure_future(_save_audit_event(event))
        else:
            loop.run_until_complete(_save_audit_event(event))
    except Exception as exc:
        log.warning("FindingsDB.log_action(): failed to dispatch audit event: %s", exc)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/test_findings_audit_pg.py -v 2>&1 | tail -15
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Run existing findings tests to check for regressions**

```bash
python -m pytest tests/test_findings_db.py -v 2>&1 | tail -20
```

Expected: all passing. If any tests call `db.close()`, they will get `AttributeError` — update those tests to remove `db.close()` calls.

- [ ] **Step 6: Run full regression suite**

```bash
python -m pytest tests/test_no_sqlite_in_distributed_mode.py tests/test_target_repository.py tests/test_db_manager_targets.py tests/test_main_targets.py tests/test_db_manager_get_findings_hardened.py tests/test_findings_audit_pg.py tests/test_finding_to_api.py -v 2>&1 | tail -30
```

Expected: all passing.

- [ ] **Step 7: Commit**

```bash
git add modules/findings.py tests/test_findings_audit_pg.py
git commit -m "feat(findings): replace SQLite audit log with DBManager.save_event"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered by |
|---|---|
| `targets` table added to Postgres schema | Task 1 (schema.sql) |
| DBManager: 5 target methods | Task 1 (save, get, list, delete, update_status) |
| DBManager: `update_target_vuln_count` | Task 1 (covers line 1354 in main.py) |
| `TargetRepository` + `get_target_repo` | Task 2 |
| `main.py`: `TargetDB` deleted | Task 3 |
| `main.py`: all 10 `_target_db.*` call sites replaced | Task 3 |
| `main.py`: startup fail-fast on non-Postgres mode | Task 3 |
| `_db_connect` helper deleted | Task 3 |
| `get_findings` raises outside Postgres mode | Task 4 |
| `_sqlite_get_findings` deleted | Task 4 |
| `FindingsDB.log_action` writes to `save_event` | Task 5 |
| `FindingsDB` SQLite attributes removed | Task 5 |
| Start fresh — no data migration | Confirmed — no migration script in any task |
| Refuse to start without Postgres | Task 3 (lifespan fail-fast) |
