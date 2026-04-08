# PG-Only Migration Design

**Date:** 2026-04-08  
**Goal:** Remove SQLite entirely from all components. PostgreSQL is the only storage backend. If PG is unavailable, raise an error — no silent fallback.

---

## Problem

The current codebase has two patterns:
1. **PG-first with SQLite fallback** — components try PG, fall back to SQLite if unavailable (Group A files)
2. **SQLite-primary** — components never migrated, use raw `sqlite3` directly (Group B files)
3. **DBManager sqlite mode** — the central DBManager has a full SQLite branch

These patterns allow the system to silently degrade to SQLite, masking PG connectivity issues and creating two code paths to maintain.

---

## Design

### Error Contract

Every component that previously fell back to SQLite now raises instead:

```python
raise RuntimeError("PostgreSQL is required but unavailable")
```

Consistent message across all files. Fail-fast, not per-operation where possible.

### Per-file Changes

**Remove from every file:**
- `import sqlite3` (top-level or lazy inside fallback blocks)
- SQLite connection helpers: `_conn`, `_open_db`, `_get_db_conn`, `_connect`, `_db_path` attributes that existed only for SQLite
- `if pg is None: <sqlite block>` → replace with `raise RuntimeError("PostgreSQL is required but unavailable")`
- `_db_path` constructor parameters/attributes used only for SQLite paths

**Keep:**
- All existing `pg_execute_write` / `pg_execute_read` call paths (unchanged)
- All existing PG-path tests (they already pass)

**Update tests:**
- Delete assertions that SQLite fallback succeeds when PG is None
- Add assertion that `RuntimeError` is raised when `pg` is `None`

### DBManager (`core/db_manager.py`) — done last

- Remove the `sqlite` mode entirely (enum value, branch logic, delegate methods)
- Constructor raises `RuntimeError` at init time if PG pool is not connected (fail-fast)
- Remove all `import sqlite3 as _sq` blocks
- Remove delegate methods to `ResultIngestionEngine` SQLite path

---

## Migration Order

### Group A — Strip SQLite fallback (PG path already exists)

| # | File | Change |
|---|------|--------|
| 1 | `ai_security/adversarial_prompt_evolution.py` | Remove sqlite3 import + fallback block |
| 2 | `attack_graph_core/graph_store.py` | Remove SQLiteStore + fallback |
| 3 | `core/cache.py` | Remove sqlite3 import + fallback blocks |
| 4 | `framework/db_ext.py` | Remove sqlite3 import + fallback |
| 5 | `memory_manager.py` | Remove sqlite3 import + fallback |
| 6 | `mobile_upload_manager.py` | Remove sqlite3 import + fallback |
| 7 | `model_budget_manager.py` | Remove sqlite3 import + fallback |
| 8 | `result_ingestion_engine.py` | Remove all sqlite3 paths |
| 9 | `traffic_capture_engine.py` | Remove sqlite3 import + fallback |
| 10 | `gen_report.py` | Remove sqlite3 fallback |

### Group B — Full migration (SQLite was primary)

| # | File | Change |
|---|------|--------|
| 11 | `unified_scan_engine.py` | Replace `_get_db_conn()` with PG calls via DBManager |
| 12 | `attack_graph/builder.py` | Replace direct sqlite3 reads with DBManager PG reads |
| 13 | `event_bus.py` | Replace `self._db` (sqlite3.Connection) with PG calls |
| 14 | `research_mode_controller.py` | Replace `self._conn` (sqlite3.Connection) with PG calls |
| 15 | `web/backend/main.py` | Replace all sqlite3 blocks with PG calls |

### Group C — Central DBManager

| # | File | Change |
|---|------|--------|
| 16 | `core/db_manager.py` | Remove sqlite mode entirely; raise at init if PG unavailable |

---

## Success Criteria

- `import sqlite3` does not appear in any non-test, non-script source file (excluding string literals in regex/frida code)
- All existing PG-path tests continue to pass
- Each component's test asserts `RuntimeError` when PG is None
- `core/db_manager.py` has no sqlite branch
- Doctor runs clean (10.0/10.0)
