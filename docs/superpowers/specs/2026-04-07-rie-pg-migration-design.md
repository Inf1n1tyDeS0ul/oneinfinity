# Design: ResultIngestionEngine → PostgreSQL Migration

**Date:** 2026-04-07
**Status:** Approved
**Scope:** Migrate all SQLite-only paths in `result_ingestion_engine.py` to PG-first with SQLite fallback, via DBManager.

---

## 1. Architecture

The migration follows the established layered pattern (same as LearningRepository):

```
ResultIngestionEngine (public API — parse, dedup, broadcast)
    │
    ▼
DBManager (PG-first gateway)
    ├── PG path  → psycopg3 pool → PostgreSQL
    └── SQLite fallback → findings.db
```

RIE's public interface is unchanged. Every SQLite-only method gains a "try DBManager first, fall back to SQLite" pattern identical to what `_check_and_store()` and `_store_finding()` already do. DBManager is the single writer/reader for all three tables (`findings`, `recon_assets`, `raw_findings`).

---

## 2. Schema Changes (`db/schema.sql`)

### 2a. Dedup constraint on `findings`

Add a `UNIQUE` constraint on `(scan_id, vuln_type, url)` to enable proper PG dedup:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
    ON findings(scan_id, vuln_type, url);
```

This allows `INSERT ... ON CONFLICT (scan_id, vuln_type, url) DO NOTHING RETURNING finding_id`
to distinguish new findings from duplicates — fixing the current broken PG dedup (which
incorrectly conflicts on `finding_id`, a fresh UUID per finding).

### 2b. New `raw_findings` table

```sql
CREATE TABLE IF NOT EXISTS raw_findings (
    id         BIGSERIAL PRIMARY KEY,
    tool       TEXT NOT NULL DEFAULT '',
    raw_json   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_raw_findings_tool       ON raw_findings(tool);
CREATE INDEX IF NOT EXISTS idx_raw_findings_created_at ON raw_findings(created_at);
```

The `recon_assets` table already exists in schema.sql with a JSONB `data` column — no changes needed.

---

## 3. New DBManager Methods (`core/db_manager.py`)

Five new method pairs (async PG + sync wrapper via existing `_run_sync()`):

| Async method | Sync wrapper | Description |
|---|---|---|
| `save_recon_asset(asset_id, scan_id, asset_type, value, metadata)` | `sync_save_recon_asset(...)` | INSERT into `recon_assets`; metadata in JSONB `data`; ON CONFLICT asset_id DO NOTHING |
| `get_recon_assets(scan_id, asset_type)` | `sync_get_recon_assets(...)` | SELECT from `recon_assets` with optional filters |
| `store_raw_findings(findings_list)` | `sync_store_raw_findings(...)` | Bulk INSERT into `raw_findings`; returns inserted count |
| `delete_findings_for_scan(scan_id)` | `sync_delete_findings_for_scan(...)` | DELETE FROM `findings` WHERE scan_id; returns rowcount |
| `finding_count(scan_id)` | `sync_finding_count(...)` | SELECT COUNT(*) FROM `findings` WHERE scan_id |

Each method follows the pattern: PG path in async method, SQLite fallback mirrors current RIE logic.

### 3a. Fix `_pg_save_finding` dedup

Change from:
```python
INSERT INTO findings (...) VALUES (...) ON CONFLICT (finding_id) DO UPDATE SET ...
```

To:
```python
INSERT INTO findings (...) VALUES (...) ON CONFLICT (scan_id, vuln_type, url) DO NOTHING RETURNING finding_id
```

Update `sync_save_finding` to return `True` if a row was inserted (new finding), `False` if duplicate.

---

## 4. RIE Changes (`result_ingestion_engine.py`)

Seven methods updated:

| Method | Change |
|---|---|
| `_init_db()` | Skip SQLite table creation if DBManager is in postgres/distributed mode. Keep SQLite init for fallback. |
| `_check_and_store()` | Update to handle new `True/False` return from `sync_save_finding`. |
| `_store_finding()` | Update to handle new `True/False` return from `sync_save_finding`. |
| `get_findings()` | Try `mgr.sync_get_findings(scan_id, target, severity)` first; fall back to current SQLite query. |
| `ingest_recon_asset()` | Try `mgr.sync_save_recon_asset(...)` first; fall back to current SQLite insert. |
| `get_recon_assets()` | Try `mgr.sync_get_recon_assets(scan_id, asset_type)` first; fall back to current SQLite query. |
| `store_raw_findings()` | Try `mgr.sync_store_raw_findings(findings)` first; fall back to current SQLite insert. |
| `delete_findings_for_scan()` | Try `mgr.sync_delete_findings_for_scan(scan_id)` first; fall back to current SQLite delete. |
| `finding_count()` | Try `mgr.sync_finding_count(scan_id)` first; fall back to current SQLite COUNT. |

---

## 5. Error Handling & Fallback

- If `POSTGRES_URL` is not set → DBManager stays in `sqlite` mode → all methods go straight to SQLite, no PG code runs.
- If PG is available but a query fails → log `WARNING: ... falling back to SQLite` and execute the SQLite path.
- All PG failures are non-fatal; the SQLite path is always the safety net.
- `store_raw_findings` and `ingest_recon_asset` are fire-and-forget (errors logged, not raised).
- `get_findings`, `get_recon_assets`, `finding_count` return empty list/0 on any error.
- `delete_findings_for_scan` returns 0 on error.

---

## 6. Testing

| File | What it covers |
|---|---|
| `tests/test_rie_pg_migration.py` | Static checks: no bare `sqlite3.connect` calls remain in RIE except inside SQLite fallback branches |
| `tests/test_db_manager_recon_raw.py` | Unit tests for the 5 new DBManager methods (mock PG pool, verify SQL issued) |
| `tests/test_rie_pg_paths.py` | Integration-style: mock DBManager in postgres mode, verify RIE routes all methods through it |

---

## 7. Files Changed

| File | Change |
|---|---|
| `db/schema.sql` | Add dedup index on `findings`; add `raw_findings` table |
| `core/db_manager.py` | Fix `_pg_save_finding` dedup; add 5 new method pairs |
| `result_ingestion_engine.py` | Wire 7 methods to DBManager PG-first paths |
| `tests/test_rie_pg_migration.py` | New static assertion tests |
| `tests/test_db_manager_recon_raw.py` | New DBManager unit tests |
| `tests/test_rie_pg_paths.py` | New RIE routing tests |
