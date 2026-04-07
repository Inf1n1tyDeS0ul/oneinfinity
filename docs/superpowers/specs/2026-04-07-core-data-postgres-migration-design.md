# Spec: Core Data PostgreSQL Migration

**Date:** 2026-04-07
**Status:** Approved

## Problem

Three core-data components bypass `DBManager` and write directly to SQLite:

| Component | SQLite usage |
|---|---|
| `web/backend/main.py` — `TargetDB` class | `~/.oneinfinity/databases/targets.db` |
| `result_ingestion_engine.py` — read path | falls back to SQLite via `_sqlite_get_findings` |
| `modules/findings.py` — `FindingsDB.log_action` | `findings_audit` table in SQLite |

This means targets are invisible to Postgres, the findings read path silently returns stale data when Postgres has newer findings, and audit records are stranded in a file nobody reads.

## Goal

All three components store and read exclusively through `DBManager` (PostgreSQL). SQLite is removed from the data path entirely. If Postgres is unavailable at startup, the server refuses to start with a clear error.

## What Is Not Changed

- No data migration — start fresh, existing SQLite files are ignored
- No other SQLite-using components in this spec (intelligence stores, operational stores are separate sub-projects)
- No new API endpoints
- No frontend changes

## Changes

### 1. `core/db_manager.py`

**New `targets` table DDL** added to Postgres init:

```sql
CREATE TABLE IF NOT EXISTS targets (
    target_id      TEXT PRIMARY KEY,
    target_value   TEXT NOT NULL,
    target_type    TEXT NOT NULL DEFAULT 'domain',
    name           TEXT,
    platform       TEXT,
    tags           JSONB DEFAULT '[]',
    status         TEXT NOT NULL DEFAULT 'pending',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scan_time TIMESTAMPTZ,
    scan_count     INTEGER DEFAULT 0,
    metadata       JSONB DEFAULT '{}'
)
```

**5 new async methods:**

| Method | SQL |
|---|---|
| `save_target(data) → dict` | `INSERT ... ON CONFLICT (target_id) DO UPDATE SET ...` |
| `get_target(target_id) → Optional[dict]` | `SELECT * FROM targets WHERE target_id = %s` |
| `list_targets() → list` | `SELECT * FROM targets ORDER BY created_at DESC` |
| `delete_target(target_id) → bool` | `DELETE FROM targets WHERE target_id = %s` |
| `update_target_status(target_id, status, last_scan_time=None)` | `UPDATE targets SET status = %s, last_scan_time = %s WHERE target_id = %s` |

**Read path hardening:** `_sqlite_get_findings` is deleted. `get_findings()` becomes:

```python
async def get_findings(self, ...):
    if self.mode not in ("distributed", "postgres"):
        raise RuntimeError("get_findings requires Postgres mode")
    return await self._pg_get_findings(...)
```

### 2. `core/target_repository.py` (new file)

`TargetRepository` wraps DBManager. Exposed as a FastAPI dependency via `get_target_repo()`.

```python
class TargetRepository:
    def __init__(self, db: DBManager): ...

    async def add(self, target_id, target_value, target_type,
                  name=None, platform=None) -> dict: ...
    async def get(self, target_id: str) -> dict | None: ...
    async def list_all(self) -> list: ...
    async def delete(self, target_id: str) -> bool: ...
    async def update_status(self, target_id, status, last_scan_time=None): ...


async def get_target_repo() -> TargetRepository:
    return TargetRepository(await get_db_manager())
```

### 3. `web/backend/main.py`

- `TargetDB` class (lines ~190–260) is deleted
- Module-level `_target_db = TargetDB(...)` instantiation is deleted
- All 5 route handlers that use `_target_db` are updated to accept
  `repo: TargetRepository = Depends(get_target_repo)` and call `await repo.*`
- `lifespan` startup gains a fail-fast check:

```python
mgr = await get_db_manager()
if mgr.mode not in ("distributed", "postgres"):
    raise RuntimeError(
        f"OneInfinity requires PostgreSQL (got mode={mgr.mode!r}). "
        "Set DISTRIBUTED_MODE=true and configure DB_HOST/DB_NAME/DB_USER/DB_PASSWORD."
    )
```

### 4. `modules/findings.py`

- `_audit_db_path`, `_audit_conn`, `_get_audit_conn()`, `close()` are removed
- `log_action()` is rewritten to call `dbmanager.save_event()` with `event_type="findings_audit"`:

```python
def log_action(self, phase: str, action=None, result: str = ""):
    import asyncio
    from core.db_manager import get_db_manager

    if isinstance(action, dict):
        action_str, metadata = phase, action
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
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(_save_audit_event(event))
        else:
            loop.run_until_complete(_save_audit_event(event))
    except Exception as exc:
        log.warning("FindingsDB.log_action(): failed: %s", exc)
```

`_save_audit_event` is a module-level async helper that calls `(await get_db_manager()).save_event(event)`.

## Data Flow

```
POST /api/targets
  → TargetRepository.add(...)
    → DBManager.save_target(...)
      → INSERT INTO targets (Postgres)

GET /api/targets
  → TargetRepository.list_all()
    → DBManager.list_targets()
      → SELECT * FROM targets (Postgres)

GET /api/vulnerabilities
  → DBManager.get_findings()
    → _pg_get_findings()  [SQLite path deleted]
      → SELECT FROM findings (Postgres)

FindingsDB.log_action("scan_complete", {...})
  → _save_audit_event(event)
    → DBManager.save_event(event)
      → INSERT INTO events (Postgres)
```

## Startup Behaviour

| Condition | Result |
|---|---|
| Postgres available, DISTRIBUTED_MODE=true | Normal startup |
| Postgres unavailable | `RuntimeError` — server exits with clear message |
| DISTRIBUTED_MODE not set | `RuntimeError` — server exits with clear message |

## File Map

| File | Change |
|---|---|
| `core/db_manager.py` | Add targets DDL + 5 methods; delete `_sqlite_get_findings`; harden `get_findings` |
| `core/target_repository.py` | New file — `TargetRepository` + `get_target_repo` dependency |
| `web/backend/main.py` | Delete `TargetDB`; wire `TargetRepository` via `Depends`; add startup fail-fast; update imports |
| `modules/findings.py` | Rewrite `log_action`; remove all SQLite attributes |

## Testing

- `tests/test_target_repository.py` — unit tests for `TargetRepository` against a real Postgres test DB
- `tests/test_db_manager_targets.py` — unit tests for the 5 new DBManager methods
- `tests/test_main_startup_failfast.py` — verify server raises on non-Postgres mode
- Existing `tests/test_finding_to_api.py` — unchanged, continues to pass
