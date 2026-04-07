# Storage Wiring Fixes — Design Spec

**Date:** 2026-04-06
**Status:** Approved

---

## Problem

Two independent audits confirmed that Redis, PostgreSQL, and Neo4j are all correctly *coded*
but none are the *active execution path* by default. Specific dead code and bypass paths were
identified. This spec defines the minimal surgical fixes to activate correct runtime wiring
without redesigning any working component.

---

## Scope

Fix exactly the issues verified by audit. No new features. No redesign. SQLite fallback preserved.

---

## Fix Inventory

### Phase 1 — Critical Wiring

**Fix 1 — SwarmState wiring (`agent_swarm_coordinator.py`)**

`scan()` at line 237 instantiates `SharedSwarmState()` directly, bypassing the existing
`_make_swarm_state(scan_id)` factory. One-line fix: replace direct instantiation with factory
call. `_make_swarm_state()` already returns `RedisSwarmState` when Redis is available, falling
back to `SharedSwarmState` otherwise. Add `session_id` property to `RedisSwarmState` so both
types share the same interface for `state_dict` construction.

**Fix 2 — CLI writes through DBManager (`god_mode_engine.py`)**

`GodModeStateFile.write()` currently writes JSON only. DBManager is never called from the CLI.
Add `_persist_to_db(session)` helper that calls `DBManager.sync_save_scan()` with scan metadata.
Behaviour:
- DBManager available → write to DBManager (primary) + write JSON as cache (no warning)
- DBManager unavailable → skip DBManager, write JSON + log `FALLBACK TRIGGERED: DBManager unavailable — writing JSON only`

JSON files remain for the `status()` read path and backward compatibility.

**Fix 3 — Remove ScanDB, route scans through DBManager (`main.py`, `db_manager.py`)**

`ScanDB` always persists to SQLite regardless of storage mode. DBManager has no SQLite path
for `save_scan()` and is missing `delete_scan()` / `load_scans()` methods entirely.

Changes:
1. Add `_sqlite_save_scan()`, `_sqlite_delete_scan()`, `_sqlite_load_scans()` to DBManager
   using the existing `scan_history` table schema from ScanDB
2. Update `save_scan()` to call `_sqlite_save_scan()` in sqlite/memory modes
3. Add `delete_scan(scan_id)` and `load_scans()` async methods to DBManager
4. Add `sync_delete_scan()` sync wrapper
5. Remove `ScanDB` class and `_scan_db` module-level instance from `main.py`
6. Replace all 20 `_scan_db.*` call sites with `await (await get_mgr()).save_scan(scan)` /
   `delete_scan()` / `load_scans()`

**Fix 4 — Single findings write path (`result_ingestion_engine.py`)**

`_check_and_store()` has a direct `sqlite3.connect()` fallback block (lines 466–520) that
bypasses DBManager's `_sqlite_save_finding()`. Replace the direct sqlite3 block with
`self._dbmgr_sqlite_save(finding)` that calls `DBManager._sqlite_save_finding()`.
The duplicate-check logic (TOCTOU guard) must be preserved via `_sqlite_dedup_check()`.

### Phase 2 — Config Enforcement

**Fix 5 — Strict mode + logging (`db_manager.py`)**

When `ONEINFINITY_STORAGE_MODE` is explicitly set:
- `"postgres"` → raise `RuntimeError` if `POSTGRES_URL` not set
- `"distributed"` → raise `RuntimeError` if `POSTGRES_URL` or `REDIS_URL` not set
- `"sqlite"` → proceed without network checks

Always log the active mode at startup:
- `"[DBManager] Running in SQLITE fallback mode"`
- `"[DBManager] Running in POSTGRES mode"`
- `"[DBManager] Running in DISTRIBUTED mode (Redis + Postgres)"`

**Fix 10 — Fallback logging (`db_manager.py`, `pg_client.py`, `redis_client.py`)**

Replace silent exceptions with structured `FALLBACK TRIGGERED` log lines wherever a
backend failure causes a degraded code path.

### Phase 3 — Execution Reliability

**Fix 6 — Worker Redis clarity (`worker/main.py`)**

`sys.exit(1)` after Redis failure is already correct (worker cannot function without Redis).
Replace with explicit message before exit:
```
log.critical("[worker] FATAL: Worker requires REDIS_URL — Redis is mandatory for distributed mode, not optional. Set REDIS_URL and retry.")
sys.exit(1)
```

**Fix 7 — Event bus memory leak (already fixed)**

Verified: both `publish()` and `publish_event()` already trim `_published_ids` at 10,000 →
5,000 entries. No code change needed.

**Fix 8 — Redis pub/sub reconnect (`event_bus.py`)**

`_redis_listener_loop()` exits permanently on any exception. Wrap the inner body in an outer
`while self._running` retry loop with exponential backoff (1s → 2s → 4s, cap 30s). Log each
disconnect and reconnect attempt.

### Phase 4 — Migration

**Fix 9 — Migration `--check` flag (`scripts/migrate_sqlite_to_pg.py`)**

Script exists and is functionally correct. Add `--check` flag that reports SQLite row counts
and Postgres connectivity without writing any data. Add invocation hint at top of file.

---

## Constraints

- SQLite fallback must remain working with no env vars set
- All changes must preserve existing API contracts (endpoints, response shapes)
- No new dependencies
- `ScanDB.load_all()` interrupted-scan recovery logic must be preserved in DBManager

---

## Files Modified

| File | Change |
|---|---|
| `core/db_manager.py` | Add scan SQLite path, delete_scan, load_scans, strict mode, fallback logging |
| `core/swarm_state_redis.py` | Add `session_id` property |
| `core/redis_client.py` | Add FALLBACK TRIGGERED log |
| `core/pg_client.py` | Add FALLBACK TRIGGERED log |
| `agent_swarm_coordinator.py` | Line 237: use `_make_swarm_state()` |
| `god_mode_engine.py` | Add `_persist_to_db()`, update `write()` |
| `web/backend/main.py` | Remove ScanDB, replace 20 call sites |
| `result_ingestion_engine.py` | Route SQLite fallback through DBManager |
| `worker/main.py` | Explicit error message before exit |
| `event_bus.py` | Redis reconnect loop |
| `scripts/migrate_sqlite_to_pg.py` | Add `--check` flag |
