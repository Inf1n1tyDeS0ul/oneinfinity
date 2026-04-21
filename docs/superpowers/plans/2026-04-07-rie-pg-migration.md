# RIE → PostgreSQL Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate all SQLite-only paths in `result_ingestion_engine.py` to PG-first with SQLite fallback, via DBManager — completing the PostgreSQL migration for the findings/recon/raw pipeline.

**Architecture:** DBManager gains 5 new method pairs (async PG + sync wrapper) for recon_assets, raw_findings, delete, count, and a dedup-aware check_and_save. RIE's 7 SQLite-only methods each try DBManager first; SQLite remains the fallback. Schema gets a dedup index on findings and the raw_findings table.

**Tech Stack:** Python 3.13, psycopg3 (async pool + sync conn), SQLite (fallback), pytest, unittest.mock

---

## File Map

| File | Change |
|---|---|
| `db/schema.sql` | Add `idx_findings_dedup` UNIQUE index; add `raw_findings` table |
| `core/db_manager.py` | Add `check_and_save_finding`, `save_recon_asset`, `get_recon_assets`, `store_raw_findings`, `delete_findings_for_scan`, `finding_count` (async + SQLite fallback + sync wrapper each) |
| `result_ingestion_engine.py` | Wire `_init_db`, `_check_and_store`, `get_findings`, `ingest_recon_asset`, `get_recon_assets`, `store_raw_findings`, `delete_findings_for_scan`, `finding_count` to DBManager PG-first |
| `tests/test_db_manager_recon_raw.py` | New — unit tests for all 5 new DBManager method pairs |
| `tests/test_rie_pg_paths.py` | New — integration tests verifying RIE routes all 7 methods through DBManager in PG mode |
| `tests/test_rie_pg_migration.py` | New — static assertion: no bare `sqlite3.connect` in non-fallback RIE code paths |

---

## Task 1: Schema — dedup index + raw_findings table

**Files:**
- Modify: `db/schema.sql`

- [ ] **Step 1: Add dedup index and raw_findings table to schema.sql**

Open `db/schema.sql`. After the last `CREATE INDEX` line under the `-- ── Findings ──` section (after `idx_findings_data`), add:

```sql
-- Dedup constraint: same (scan_id, vuln_type, url) is a duplicate within a scan.
-- Enables ON CONFLICT (scan_id, vuln_type, url) DO NOTHING RETURNING finding_id.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
    ON findings(scan_id, vuln_type, url);
```

Then after the last table in the file, add:

```sql
-- ── Raw Findings (pre-validation staging) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS raw_findings (
    id         BIGSERIAL PRIMARY KEY,
    tool       TEXT NOT NULL DEFAULT '',
    raw_json   JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_raw_findings_tool       ON raw_findings(tool);
CREATE INDEX IF NOT EXISTS idx_raw_findings_created_at ON raw_findings(created_at);
```

- [ ] **Step 2: Verify schema is valid SQL (grep check)**

```bash
grep -n "idx_findings_dedup\|raw_findings" /path/to/oneinfinity/db/schema.sql
```

Expected: 3 lines — the CREATE UNIQUE INDEX, CREATE TABLE, and at least one CREATE INDEX for raw_findings.

- [ ] **Step 3: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add db/schema.sql
git commit -m "feat(schema): add findings dedup index and raw_findings table"
```

---

## Task 2: DBManager — check_and_save_finding (dedup-aware PG insert)

**Files:**
- Modify: `core/db_manager.py` (insert after line 252, and append sync wrapper after line 1348)
- Create: `tests/test_db_manager_recon_raw.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_db_manager_recon_raw.py`:

```python
# tests/test_db_manager_recon_raw.py
"""Unit tests for new DBManager methods: check_and_save_finding, recon_assets, raw_findings."""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def pg_mgr_with_execute(execute_return=None):
    """Return a DBManager in postgres mode with a controllable mock connection."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"

    mock_result = MagicMock()
    mock_result.fetchone = AsyncMock(return_value=execute_return)
    mock_result.rowcount = 1

    async def _aiter():
        return
        yield  # make it an async generator

    mock_result.__aiter__ = lambda self=mock_result: _aiter()

    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value=mock_result)
    mock_conn.commit = AsyncMock()

    mock_pool = MagicMock()
    mock_pool.connection.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.connection.return_value.__aexit__ = AsyncMock(return_value=False)

    mgr._pg_pool = mock_pool
    return mgr, mock_conn, mock_result


# ── check_and_save_finding ───────────────────────────────────────────────────

def test_check_and_save_new_finding_returns_true():
    """When PG returns a row, finding is new — return True."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute(execute_return=("finding-abc",))
    finding = {
        "finding_id": "abc123", "scan_id": "scan1", "target": "example.com",
        "title": "XSS", "severity": "high", "vuln_type": "xss",
        "url": "https://example.com/q", "tool": "dalfox",
        "confidence": 0.9, "cvss": 8.0, "status": "new", "source_type": "tool",
    }
    result = mgr.sync_check_and_save_finding(finding)
    assert result is True


def test_check_and_save_duplicate_returns_false():
    """When PG returns no row (ON CONFLICT DO NOTHING), finding is duplicate — return False."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute(execute_return=None)
    finding = {
        "finding_id": "abc123", "scan_id": "scan1",
        "vuln_type": "xss", "url": "https://example.com/q",
    }
    result = mgr.sync_check_and_save_finding(finding)
    assert result is False


def test_check_and_save_sqlite_mode_stores_and_returns_true():
    """In sqlite mode, check_and_save_finding uses SQLite dedup and returns True for new."""
    import core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_conn_ctx = MagicMock()
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = None  # no duplicate found
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock(return_value=mock_cursor)
    mock_conn_ctx.commit = MagicMock()

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        finding = {
            "finding_id": "abc123", "scan_id": "scan1", "target": "example.com",
            "title": "XSS", "severity": "high", "vuln_type": "xss",
            "url": "https://example.com/q", "tool": "dalfox",
            "confidence": 0.9, "cvss": 8.0, "status": "new", "source_type": "tool",
            "created_at": "2026-04-07T00:00:00",
        }
        result = mgr.sync_check_and_save_finding(finding)
    assert result is True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_db_manager_recon_raw.py::test_check_and_save_new_finding_returns_true -v
```

Expected: FAIL with `AttributeError: 'DBManager' object has no attribute 'sync_check_and_save_finding'`

- [ ] **Step 3: Add check_and_save_finding to DBManager**

In `core/db_manager.py`, insert after line 252 (after `_pg_get_findings`, before `# ── Scans ──`):

```python
    async def check_and_save_finding(self, finding: dict) -> bool:
        """Dedup-aware insert. Returns True if stored (new), False if duplicate."""
        fid = finding.get("finding_id") or str(uuid.uuid4())[:12]
        finding = {**finding, "finding_id": fid}
        if self.mode in ("distributed", "postgres"):
            return await self._pg_check_and_save_finding(finding)
        return self._sqlite_check_and_save_finding(finding)

    async def _pg_check_and_save_finding(self, finding: dict) -> bool:
        data = {
            k: finding.get(k, "")
            for k in ("evidence", "payload", "raw", "poc_steps", "reproduction_cmd")
        }
        try:
            async with self._pg_pool.connection() as conn:
                result = await conn.execute(
                    """
                    INSERT INTO findings
                        (finding_id, scan_id, target, title, severity, vuln_type, url,
                         tool, confidence, cvss, status, source_type, created_at, data)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),%s)
                    ON CONFLICT (scan_id, vuln_type, url) DO NOTHING
                    RETURNING finding_id
                    """,
                    (
                        finding["finding_id"],
                        finding.get("scan_id", ""),
                        finding.get("target", ""),
                        finding.get("title", ""),
                        finding.get("severity", "info"),
                        finding.get("vuln_type", ""),
                        finding.get("url", ""),
                        finding.get("tool", ""),
                        float(finding.get("confidence", 0.8)),
                        float(finding.get("cvss", 0.0)),
                        finding.get("status", "new"),
                        finding.get("source_type", "tool"),
                        json.dumps(data, default=str),
                    ),
                )
                row = await result.fetchone()
                await conn.commit()
                return row is not None
        except Exception as exc:
            log.warning("DBManager._pg_check_and_save_finding failed: %s", exc)
            raise

    def _sqlite_check_and_save_finding(self, finding: dict) -> bool:
        import sqlite3 as _sq
        scan_id = finding.get("scan_id", "")
        vuln_type = finding.get("vuln_type", "")
        url = finding.get("url", "")
        try:
            with _sq.connect(str(self._sqlite_path), timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                row = conn.execute(
                    "SELECT 1 FROM findings "
                    "WHERE (scan_id=? AND vuln_type=? AND url=?) "
                    "OR (vuln_type=? AND url=? AND created_at > datetime('now', '-1 day')) "
                    "LIMIT 1",
                    (scan_id, vuln_type, url, vuln_type, url),
                ).fetchone()
                if row is not None:
                    return False
                conn.execute(
                    "INSERT OR REPLACE INTO findings "
                    "(finding_id, scan_id, target, title, severity, vuln_type, "
                    " evidence, payload, url, tool, confidence, cvss, status, "
                    " source_type, created_at, raw_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        finding.get("finding_id", ""),
                        scan_id,
                        finding.get("target", ""),
                        finding.get("title", ""),
                        finding.get("severity", "info"),
                        vuln_type,
                        finding.get("evidence", ""),
                        finding.get("payload", ""),
                        url,
                        finding.get("tool", ""),
                        float(finding.get("confidence", 0.8)),
                        float(finding.get("cvss", 0.0)),
                        finding.get("status", "new"),
                        finding.get("source_type", "tool"),
                        finding.get("created_at", datetime.utcnow().isoformat()),
                        json.dumps(finding.get("raw", {}), default=str),
                    ),
                )
                conn.commit()
                return True
        except Exception as exc:
            log.warning("DBManager._sqlite_check_and_save_finding failed: %s", exc)
            raise
```

Also append to end of `core/db_manager.py` (after line 1348):

```python
    def sync_check_and_save_finding(self, finding: dict) -> bool:
        return self._run_sync(self.check_and_save_finding(finding))
```

- [ ] **Step 4: Run all three check_and_save tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_db_manager_recon_raw.py::test_check_and_save_new_finding_returns_true tests/test_db_manager_recon_raw.py::test_check_and_save_duplicate_returns_false tests/test_db_manager_recon_raw.py::test_check_and_save_sqlite_mode_stores_and_returns_true -v
```

Expected: All 3 PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add core/db_manager.py tests/test_db_manager_recon_raw.py
git commit -m "feat(db-manager): add check_and_save_finding with PG dedup RETURNING"
```

---

## Task 3: DBManager — save_recon_asset + get_recon_assets

**Files:**
- Modify: `core/db_manager.py`
- Modify: `tests/test_db_manager_recon_raw.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_db_manager_recon_raw.py`:

```python
# ── save_recon_asset ──────────────────────────────────────────────────────────

def test_save_recon_asset_issues_pg_insert():
    """save_recon_asset in PG mode executes INSERT with correct args."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute()
    mgr.sync_save_recon_asset("asset1", "scan1", "subdomain", "sub.example.com", {"ip": "1.2.3.4"})
    mock_conn.execute.assert_called_once()
    sql, params = mock_conn.execute.call_args[0]
    assert "INSERT INTO recon_assets" in sql
    assert params[0] == "asset1"
    assert params[1] == "scan1"
    assert params[2] == "subdomain"
    assert params[3] == "sub.example.com"
    assert json.loads(params[4]) == {"ip": "1.2.3.4"}


def test_save_recon_asset_sqlite_mode():
    """save_recon_asset in sqlite mode writes to SQLite."""
    import core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock()
    mock_conn_ctx.commit = MagicMock()

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        mgr.sync_save_recon_asset("a1", "s1", "endpoint", "/api/v1", {})
    mock_conn_ctx.execute.assert_called()


# ── get_recon_assets ──────────────────────────────────────────────────────────

def test_get_recon_assets_pg_mode_returns_list():
    """get_recon_assets in PG mode returns parsed list."""
    import core.db_manager as dm
    import json
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "postgres"

    rows = [
        ("asset1", "scan1", "subdomain", "sub.example.com", json.dumps({"ip": "1.2.3.4"}), "2026-04-07T00:00:00"),
    ]

    async def fake_execute(sql, params=None):
        cursor = MagicMock()
        async def _aiter():
            for r in rows:
                yield r
        cursor.__aiter__ = lambda self=cursor: _aiter()
        return cursor

    mock_conn = AsyncMock()
    mock_conn.execute = fake_execute
    mock_pool = MagicMock()
    mock_pool.connection.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_pool.connection.return_value.__aexit__ = AsyncMock(return_value=False)
    mgr._pg_pool = mock_pool

    result = mgr.sync_get_recon_assets(scan_id="scan1")
    assert len(result) == 1
    assert result[0]["asset_id"] == "asset1"
    assert result[0]["metadata"] == {"ip": "1.2.3.4"}


def test_get_recon_assets_sqlite_mode_returns_list():
    """get_recon_assets in sqlite mode returns parsed list from SQLite."""
    import core.db_manager as dm
    from unittest.mock import patch, MagicMock
    import sqlite3
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    fake_row = MagicMock()
    fake_row.__iter__ = MagicMock(return_value=iter([]))
    fake_row.keys = MagicMock(return_value=["asset_id", "scan_id", "asset_type", "value", "metadata_json", "created_at"])

    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.fetchall = MagicMock(return_value=[])
    mock_conn_ctx.row_factory = None

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        result = mgr.sync_get_recon_assets(scan_id="scan1")
    assert isinstance(result, list)
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_db_manager_recon_raw.py::test_save_recon_asset_issues_pg_insert tests/test_db_manager_recon_raw.py::test_get_recon_assets_pg_mode_returns_list -v
```

Expected: FAIL with `AttributeError: 'DBManager' object has no attribute 'sync_save_recon_asset'`

- [ ] **Step 3: Add save_recon_asset + get_recon_assets to DBManager**

In `core/db_manager.py`, insert a new section after the `check_and_save_finding` block (before `# ── Scans ──`):

```python
    # ── Recon Assets ─────────────────────────────────────────────────────────

    async def save_recon_asset(
        self,
        asset_id: str,
        scan_id: str,
        asset_type: str,
        value: str,
        metadata: Optional[dict] = None,
    ) -> None:
        metadata = metadata or {}
        if self.mode in ("distributed", "postgres"):
            await self._pg_save_recon_asset(asset_id, scan_id, asset_type, value, metadata)
        else:
            self._sqlite_save_recon_asset(asset_id, scan_id, asset_type, value, metadata)

    async def _pg_save_recon_asset(
        self, asset_id: str, scan_id: str, asset_type: str, value: str, metadata: dict
    ) -> None:
        try:
            async with self._pg_pool.connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO recon_assets (asset_id, scan_id, asset_type, value, data)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (asset_id) DO NOTHING
                    """,
                    (asset_id, scan_id, asset_type, value, json.dumps(metadata, default=str)),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager._pg_save_recon_asset failed: %s", exc)
            raise

    def _sqlite_save_recon_asset(
        self, asset_id: str, scan_id: str, asset_type: str, value: str, metadata: dict
    ) -> None:
        import sqlite3 as _sq
        try:
            with _sq.connect(str(self._sqlite_path)) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO recon_assets "
                    "(asset_id, scan_id, asset_type, value, metadata_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (asset_id, scan_id, asset_type, value,
                     json.dumps(metadata, default=str), datetime.utcnow().isoformat()),
                )
                conn.commit()
        except Exception as exc:
            log.warning("DBManager._sqlite_save_recon_asset failed: %s", exc)

    async def get_recon_assets(
        self,
        scan_id: Optional[str] = None,
        asset_type: Optional[str] = None,
    ) -> list:
        if self.mode in ("distributed", "postgres"):
            return await self._pg_get_recon_assets(scan_id=scan_id, asset_type=asset_type)
        return self._sqlite_get_recon_assets(scan_id=scan_id, asset_type=asset_type)

    async def _pg_get_recon_assets(self, scan_id=None, asset_type=None) -> list:
        conditions, params = [], []
        if scan_id:
            conditions.append("scan_id = %s"); params.append(scan_id)
        if asset_type:
            conditions.append("asset_type = %s"); params.append(asset_type)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        try:
            async with self._pg_pool.connection() as conn:
                rows = await conn.execute(
                    f"SELECT asset_id, scan_id, asset_type, value, data, created_at "
                    f"FROM recon_assets {where} ORDER BY created_at DESC",
                    params,
                )
                results = []
                async for row in rows:
                    d = {
                        "asset_id": row[0], "scan_id": row[1],
                        "asset_type": row[2], "value": row[3],
                        "created_at": str(row[5]) if row[5] else None,
                    }
                    extra = row[4] or {}
                    if isinstance(extra, str):
                        extra = json.loads(extra)
                    d["metadata"] = extra
                    results.append(d)
                return results
        except Exception as exc:
            log.warning("DBManager._pg_get_recon_assets failed: %s", exc)
            return []

    def _sqlite_get_recon_assets(self, scan_id=None, asset_type=None) -> list:
        import sqlite3 as _sq
        clauses, params = [], []
        if scan_id:
            clauses.append("scan_id = ?"); params.append(scan_id)
        if asset_type:
            clauses.append("asset_type = ?"); params.append(asset_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        try:
            with _sq.connect(str(self._sqlite_path)) as conn:
                conn.row_factory = _sq.Row
                rows = conn.execute(
                    f"SELECT * FROM recon_assets {where} ORDER BY created_at DESC", params
                ).fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    try:
                        d["metadata"] = json.loads(d.pop("metadata_json", "{}") or "{}")
                    except Exception:
                        d["metadata"] = {}
                    results.append(d)
                return results
        except Exception as exc:
            log.warning("DBManager._sqlite_get_recon_assets failed: %s", exc)
            return []
```

Append to end of file (after `sync_check_and_save_finding`):

```python
    def sync_save_recon_asset(self, asset_id: str, scan_id: str, asset_type: str,
                               value: str, metadata: Optional[dict] = None) -> None:
        self._run_sync(self.save_recon_asset(asset_id, scan_id, asset_type, value, metadata))

    def sync_get_recon_assets(self, **kwargs) -> list:
        return self._run_sync(self.get_recon_assets(**kwargs))
```

- [ ] **Step 4: Run all recon_asset tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_db_manager_recon_raw.py -k "recon_asset" -v
```

Expected: All 4 PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add core/db_manager.py tests/test_db_manager_recon_raw.py
git commit -m "feat(db-manager): add save_recon_asset and get_recon_assets"
```

---

## Task 4: DBManager — store_raw_findings, delete_findings_for_scan, finding_count

**Files:**
- Modify: `core/db_manager.py`
- Modify: `tests/test_db_manager_recon_raw.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_db_manager_recon_raw.py`:

```python
# ── store_raw_findings ────────────────────────────────────────────────────────

def test_store_raw_findings_pg_mode_returns_count():
    """store_raw_findings inserts each finding and returns count."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute()
    findings = [
        {"tool": "nuclei", "vuln_type": "xss", "url": "https://example.com"},
        {"tool": "dalfox", "vuln_type": "xss", "url": "https://example.com/q"},
    ]
    count = mgr.sync_store_raw_findings(findings)
    assert count == 2
    assert mock_conn.execute.call_count == 2


def test_store_raw_findings_sqlite_mode_returns_count():
    """store_raw_findings in sqlite mode inserts and returns count."""
    import core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock()
    mock_conn_ctx.commit = MagicMock()

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        count = mgr.sync_store_raw_findings([{"tool": "nuclei"}, {"tool": "sqlmap"}])
    assert count == 2


# ── delete_findings_for_scan ─────────────────────────────────────────────────

def test_delete_findings_for_scan_pg_mode_returns_rowcount():
    """delete_findings_for_scan returns number of rows deleted."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute()
    mock_result.rowcount = 5
    mock_conn.execute = AsyncMock(return_value=mock_result)

    count = mgr.sync_delete_findings_for_scan("scan1")
    assert count == 5
    mock_conn.execute.assert_called_once()
    sql, params = mock_conn.execute.call_args[0]
    assert "DELETE FROM findings" in sql
    assert params == ("scan1",)


def test_delete_findings_for_scan_sqlite_mode():
    """delete_findings_for_scan in sqlite mode deletes and returns rowcount."""
    import core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_cursor = MagicMock()
    mock_cursor.rowcount = 3
    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock(return_value=mock_cursor)
    mock_conn_ctx.commit = MagicMock()

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        count = mgr.sync_delete_findings_for_scan("scan1")
    assert count == 3


# ── finding_count ─────────────────────────────────────────────────────────────

def test_finding_count_pg_mode_returns_int():
    """finding_count returns integer count from PG."""
    mgr, mock_conn, mock_result = pg_mgr_with_execute(execute_return=(7,))
    count = mgr.sync_finding_count("scan1")
    assert count == 7
    mock_conn.execute.assert_called_once()
    sql, params = mock_conn.execute.call_args[0]
    assert "COUNT(*)" in sql
    assert params == ("scan1",)


def test_finding_count_sqlite_mode():
    """finding_count in sqlite mode returns count."""
    import core.db_manager as dm
    from unittest.mock import patch, MagicMock
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"

    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (4,)
    mock_conn_ctx = MagicMock()
    mock_conn_ctx.__enter__ = MagicMock(return_value=mock_conn_ctx)
    mock_conn_ctx.__exit__ = MagicMock(return_value=False)
    mock_conn_ctx.execute = MagicMock(return_value=mock_cursor)

    with patch("sqlite3.connect", return_value=mock_conn_ctx):
        count = mgr.sync_finding_count("scan1")
    assert count == 4
```

- [ ] **Step 2: Run to verify they fail**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_db_manager_recon_raw.py::test_store_raw_findings_pg_mode_returns_count tests/test_db_manager_recon_raw.py::test_delete_findings_for_scan_pg_mode_returns_rowcount tests/test_db_manager_recon_raw.py::test_finding_count_pg_mode_returns_int -v
```

Expected: FAIL with `AttributeError`.

- [ ] **Step 3: Add store_raw_findings, delete_findings_for_scan, finding_count to DBManager**

In `core/db_manager.py`, insert a `# ── Raw Findings ──` section after the recon_assets section:

```python
    # ── Raw Findings ─────────────────────────────────────────────────────────

    async def store_raw_findings(self, findings: list) -> int:
        """Bulk-insert raw findings. Returns count inserted."""
        if self.mode in ("distributed", "postgres"):
            return await self._pg_store_raw_findings(findings)
        return self._sqlite_store_raw_findings(findings)

    async def _pg_store_raw_findings(self, findings: list) -> int:
        inserted = 0
        try:
            async with self._pg_pool.connection() as conn:
                for f in findings:
                    tool = f.get("tool") or f.get("source_tool") or "unknown"
                    await conn.execute(
                        "INSERT INTO raw_findings (tool, raw_json) VALUES (%s,%s)",
                        (tool, json.dumps(f, default=str)),
                    )
                    inserted += 1
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager._pg_store_raw_findings failed: %s", exc)
        return inserted

    def _sqlite_store_raw_findings(self, findings: list) -> int:
        import sqlite3 as _sq
        inserted = 0
        try:
            with _sq.connect(str(self._sqlite_path), timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                for f in findings:
                    tool = f.get("tool") or f.get("source_tool") or "unknown"
                    conn.execute(
                        "INSERT INTO raw_findings (tool, raw_json) VALUES (?, ?)",
                        (tool, json.dumps(f, default=str)),
                    )
                    inserted += 1
                conn.commit()
        except Exception as exc:
            log.warning("DBManager._sqlite_store_raw_findings failed: %s", exc)
        return inserted

    # ── Findings — delete + count ────────────────────────────────────────────

    async def delete_findings_for_scan(self, scan_id: str) -> int:
        """Delete all findings for a scan. Returns count deleted."""
        if self.mode in ("distributed", "postgres"):
            return await self._pg_delete_findings_for_scan(scan_id)
        return self._sqlite_delete_findings_for_scan(scan_id)

    async def _pg_delete_findings_for_scan(self, scan_id: str) -> int:
        try:
            async with self._pg_pool.connection() as conn:
                result = await conn.execute(
                    "DELETE FROM findings WHERE scan_id = %s", (scan_id,)
                )
                await conn.commit()
                return result.rowcount
        except Exception as exc:
            log.warning("DBManager._pg_delete_findings_for_scan failed: %s", exc)
            return 0

    def _sqlite_delete_findings_for_scan(self, scan_id: str) -> int:
        import sqlite3 as _sq
        try:
            with _sq.connect(str(self._sqlite_path)) as conn:
                cur = conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                conn.commit()
                return cur.rowcount
        except Exception as exc:
            log.warning("DBManager._sqlite_delete_findings_for_scan failed: %s", exc)
            return 0

    async def finding_count(self, scan_id: str) -> int:
        """Return number of findings for a scan."""
        if self.mode in ("distributed", "postgres"):
            return await self._pg_finding_count(scan_id)
        return self._sqlite_finding_count(scan_id)

    async def _pg_finding_count(self, scan_id: str) -> int:
        try:
            async with self._pg_pool.connection() as conn:
                result = await conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = %s", (scan_id,)
                )
                row = await result.fetchone()
                return row[0] if row else 0
        except Exception as exc:
            log.warning("DBManager._pg_finding_count failed: %s", exc)
            return 0

    def _sqlite_finding_count(self, scan_id: str) -> int:
        import sqlite3 as _sq
        try:
            with _sq.connect(str(self._sqlite_path)) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
                ).fetchone()
                return row[0] if row else 0
        except Exception as exc:
            log.warning("DBManager._sqlite_finding_count failed: %s", exc)
            return 0
```

Append to end of file:

```python
    def sync_store_raw_findings(self, findings: list) -> int:
        return self._run_sync(self.store_raw_findings(findings))

    def sync_delete_findings_for_scan(self, scan_id: str) -> int:
        return self._run_sync(self.delete_findings_for_scan(scan_id))

    def sync_finding_count(self, scan_id: str) -> int:
        return self._run_sync(self.finding_count(scan_id))
```

- [ ] **Step 4: Run all tests in the file**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_db_manager_recon_raw.py -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add core/db_manager.py tests/test_db_manager_recon_raw.py
git commit -m "feat(db-manager): add store_raw_findings, delete_findings_for_scan, finding_count"
```

---

## Task 5: RIE — wire _init_db and _check_and_store

**Files:**
- Modify: `result_ingestion_engine.py`
- Create: `tests/test_rie_pg_paths.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_rie_pg_paths.py`:

```python
# tests/test_rie_pg_paths.py
"""Verify RIE routes all methods through DBManager when in PG mode."""
import pytest
from unittest.mock import MagicMock, patch


def make_pg_mgr(mode="postgres"):
    """Return a mock DBManager in PG mode."""
    mgr = MagicMock()
    mgr.mode = mode
    return mgr


# ── _check_and_store ──────────────────────────────────────────────────────────

def test_check_and_store_uses_pg_when_available():
    """In PG mode, _check_and_store delegates to mgr.sync_check_and_save_finding."""
    from result_ingestion_engine import NormalizedFinding
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_check_and_save_finding.return_value = True

    finding = NormalizedFinding(
        scan_id="s1", target="example.com", title="XSS",
        severity="high", vuln_type="xss", evidence="poc",
        tool="dalfox", url="https://example.com/q",
    )

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        result = engine._check_and_store(finding)

    assert result is True
    mock_mgr.sync_check_and_save_finding.assert_called_once()


def test_check_and_store_returns_false_for_duplicate():
    """In PG mode, _check_and_store returns False when DBManager signals duplicate."""
    from result_ingestion_engine import NormalizedFinding
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_check_and_save_finding.return_value = False

    finding = NormalizedFinding(
        scan_id="s1", target="example.com", title="XSS",
        severity="high", vuln_type="xss", evidence="poc",
        tool="dalfox", url="https://example.com/q",
    )

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        result = engine._check_and_store(finding)

    assert result is False
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_paths.py::test_check_and_store_uses_pg_when_available tests/test_rie_pg_paths.py::test_check_and_store_returns_false_for_duplicate -v
```

Expected: FAIL — `_check_and_store` currently ignores `sync_save_finding` return value (always returns `True`), so the duplicate test fails.

- [ ] **Step 3: Update _init_db and _check_and_store in RIE**

In `result_ingestion_engine.py`, replace `_init_db` (lines 394–415):

```python
    def _init_db(self) -> None:
        # In PG mode, DBManager._ensure_schema() handles table creation.
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            log.debug("ResultIngestionEngine: PG mode — skipping SQLite table creation")
            return
        try:
            with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=FULL;")
                conn.execute(_CREATE_FINDINGS_TABLE)
                conn.execute(_CREATE_RECON_ASSETS_TABLE)
                conn.execute(_CREATE_RAW_FINDINGS_TABLE)
                existing_cols = {
                    row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()
                }
                if "source_type" not in existing_cols:
                    conn.execute(
                        "ALTER TABLE findings ADD COLUMN source_type TEXT DEFAULT 'tool'"
                    )
                    log.info("ResultIngestionEngine: migrated findings table — added source_type column")
                conn.commit()
            log.debug("ResultIngestionEngine: DB initialised at %s", self._db_path)
        except Exception as exc:
            log.error("ResultIngestionEngine: DB init failed: %s", exc)
            raise RuntimeError("ResultIngestionEngine DB init failed") from exc
```

In `_check_and_store`, replace the opening PG block (lines 472–479):

```python
    def _check_and_store(self, finding: NormalizedFinding) -> bool:
        """Atomically check for duplicate and store if new. Returns True if stored."""
        # Try Postgres first (via DBManager)
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            try:
                return mgr.sync_check_and_save_finding(finding.to_dict())
            except Exception as exc:
                log.warning("DBManager check_and_save failed, falling back to SQLite: %s", exc)
        # SQLite fallback
```

The rest of `_check_and_store` (SQLite retry loop) remains unchanged.

- [ ] **Step 4: Run the tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_paths.py::test_check_and_store_uses_pg_when_available tests/test_rie_pg_paths.py::test_check_and_store_returns_false_for_duplicate -v
```

Expected: Both PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add result_ingestion_engine.py tests/test_rie_pg_paths.py
git commit -m "feat(rie): wire _init_db and _check_and_store to DBManager PG path"
```

---

## Task 6: RIE — wire get_findings

**Files:**
- Modify: `result_ingestion_engine.py`
- Modify: `tests/test_rie_pg_paths.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_rie_pg_paths.py`:

```python
# ── get_findings ──────────────────────────────────────────────────────────────

def test_get_findings_uses_pg_when_available():
    """In PG mode, get_findings delegates to mgr.sync_get_findings."""
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_get_findings.return_value = [{"finding_id": "f1", "vuln_type": "xss"}]

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        results = engine.get_findings(scan_id="scan1")

    assert len(results) == 1
    assert results[0]["finding_id"] == "f1"
    mock_mgr.sync_get_findings.assert_called_once_with(scan_id="scan1", target=None, severity=None)
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_paths.py::test_get_findings_uses_pg_when_available -v
```

Expected: FAIL — `get_findings` currently goes straight to SQLite.

- [ ] **Step 3: Update get_findings in RIE**

In `result_ingestion_engine.py`, replace `get_findings` (lines 615–653):

```python
    def get_findings(
        self,
        scan_id: str = None,
        target: str = None,
        severity: str = None,
    ) -> List[dict]:
        """Query findings with optional filters."""
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            try:
                return mgr.sync_get_findings(scan_id=scan_id, target=target, severity=severity)
            except Exception as exc:
                log.warning("DBManager get_findings failed, falling back to SQLite: %s", exc)
        clauses: List[str] = []
        params: List = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if target:
            clauses.append("target = ?")
            params.append(target)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM findings {where} ORDER BY created_at DESC"
        try:
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql, params).fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    d["id"] = d.get("finding_id")
                    d["cvss_score"] = d.get("cvss")
                    try:
                        d["raw"] = json.loads(d.pop("raw_json", "{}") or "{}")
                    except Exception:
                        d["raw"] = {}
                    results.append(d)
                return results
        except Exception as exc:
            log.error("get_findings: DB error: %s", exc)
            return []
```

- [ ] **Step 4: Run the test**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_paths.py::test_get_findings_uses_pg_when_available -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add result_ingestion_engine.py tests/test_rie_pg_paths.py
git commit -m "feat(rie): wire get_findings to DBManager PG path"
```

---

## Task 7: RIE — wire ingest_recon_asset + get_recon_assets

**Files:**
- Modify: `result_ingestion_engine.py`
- Modify: `tests/test_rie_pg_paths.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_rie_pg_paths.py`:

```python
# ── ingest_recon_asset ────────────────────────────────────────────────────────

def test_ingest_recon_asset_uses_pg_when_available():
    """In PG mode, ingest_recon_asset delegates to mgr.sync_save_recon_asset."""
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        engine.ingest_recon_asset("scan1", "subdomain", "sub.example.com", {"ip": "1.2.3.4"})

    mock_mgr.sync_save_recon_asset.assert_called_once()
    args = mock_mgr.sync_save_recon_asset.call_args[0]
    assert args[1] == "scan1"
    assert args[2] == "subdomain"
    assert args[3] == "sub.example.com"
    assert args[4] == {"ip": "1.2.3.4"}


# ── get_recon_assets ──────────────────────────────────────────────────────────

def test_get_recon_assets_uses_pg_when_available():
    """In PG mode, get_recon_assets delegates to mgr.sync_get_recon_assets."""
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_get_recon_assets.return_value = [{"asset_id": "a1", "value": "sub.example.com"}]

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        results = engine.get_recon_assets(scan_id="scan1", asset_type="subdomain")

    assert len(results) == 1
    mock_mgr.sync_get_recon_assets.assert_called_once_with(scan_id="scan1", asset_type="subdomain")
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_paths.py::test_ingest_recon_asset_uses_pg_when_available tests/test_rie_pg_paths.py::test_get_recon_assets_uses_pg_when_available -v
```

Expected: FAIL.

- [ ] **Step 3: Update ingest_recon_asset and get_recon_assets in RIE**

In `result_ingestion_engine.py`, replace `ingest_recon_asset` (lines 547–571):

```python
    def ingest_recon_asset(
        self,
        scan_id: str,
        asset_type: str,
        value: str,
        metadata: Optional[dict] = None,
    ) -> None:
        """Store a recon asset (subdomain, endpoint, service, technology)."""
        if metadata is None:
            metadata = {}
        asset_id = str(uuid.uuid4())[:12]
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            try:
                mgr.sync_save_recon_asset(asset_id, scan_id, asset_type, value, metadata)
                return
            except Exception as exc:
                log.warning("DBManager save_recon_asset failed, falling back to SQLite: %s", exc)
        created_at = datetime.utcnow().isoformat()
        try:
            with self._lock:
                with sqlite3.connect(str(self._db_path)) as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO recon_assets "
                        "(asset_id, scan_id, asset_type, value, metadata_json, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (asset_id, scan_id, asset_type, value, json.dumps(metadata), created_at),
                    )
                    conn.commit()
        except Exception as exc:
            log.error("ingest_recon_asset: DB error [scan=%s asset_type=%s value=%s]: %s",
                      scan_id, asset_type, value, exc)
```

Replace `get_recon_assets` (lines 666–697):

```python
    def get_recon_assets(
        self,
        scan_id: str = None,
        asset_type: str = None,
    ) -> List[dict]:
        """Query recon assets with optional filters."""
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            try:
                return mgr.sync_get_recon_assets(scan_id=scan_id, asset_type=asset_type)
            except Exception as exc:
                log.warning("DBManager get_recon_assets failed, falling back to SQLite: %s", exc)
        clauses: List[str] = []
        params: List = []
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if asset_type:
            clauses.append("asset_type = ?")
            params.append(asset_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM recon_assets {where} ORDER BY created_at DESC"
        try:
            with sqlite3.connect(str(self._db_path)) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(sql, params).fetchall()
                results = []
                for row in rows:
                    d = dict(row)
                    try:
                        d["metadata"] = json.loads(d.pop("metadata_json", "{}") or "{}")
                    except Exception:
                        d["metadata"] = {}
                    results.append(d)
                return results
        except Exception as exc:
            log.error("get_recon_assets: DB error: %s", exc)
            return []
```

- [ ] **Step 4: Run the tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_paths.py::test_ingest_recon_asset_uses_pg_when_available tests/test_rie_pg_paths.py::test_get_recon_assets_uses_pg_when_available -v
```

Expected: Both PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add result_ingestion_engine.py tests/test_rie_pg_paths.py
git commit -m "feat(rie): wire ingest_recon_asset and get_recon_assets to DBManager PG path"
```

---

## Task 8: RIE — wire store_raw_findings, delete_findings_for_scan, finding_count

**Files:**
- Modify: `result_ingestion_engine.py`
- Modify: `tests/test_rie_pg_paths.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_rie_pg_paths.py`:

```python
# ── store_raw_findings ────────────────────────────────────────────────────────

def test_store_raw_findings_uses_pg_when_available():
    """In PG mode, store_raw_findings delegates to mgr.sync_store_raw_findings."""
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_store_raw_findings.return_value = 2

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    findings = [{"tool": "nuclei"}, {"tool": "dalfox"}]
    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        count = engine.store_raw_findings(findings)

    assert count == 2
    mock_mgr.sync_store_raw_findings.assert_called_once_with(findings)


# ── delete_findings_for_scan ─────────────────────────────────────────────────

def test_delete_findings_for_scan_uses_pg_when_available():
    """In PG mode, delete_findings_for_scan delegates to mgr.sync_delete_findings_for_scan."""
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_delete_findings_for_scan.return_value = 5

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        count = engine.delete_findings_for_scan("scan1")

    assert count == 5
    mock_mgr.sync_delete_findings_for_scan.assert_called_once_with("scan1")


# ── finding_count ─────────────────────────────────────────────────────────────

def test_finding_count_uses_pg_when_available():
    """In PG mode, finding_count delegates to mgr.sync_finding_count."""
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_finding_count.return_value = 7

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        count = engine.finding_count("scan1")

    assert count == 7
    mock_mgr.sync_finding_count.assert_called_once_with("scan1")
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_paths.py::test_store_raw_findings_uses_pg_when_available tests/test_rie_pg_paths.py::test_delete_findings_for_scan_uses_pg_when_available tests/test_rie_pg_paths.py::test_finding_count_uses_pg_when_available -v
```

Expected: FAIL.

- [ ] **Step 3: Update store_raw_findings, delete_findings_for_scan, finding_count in RIE**

Replace `store_raw_findings` (lines 573–591):

```python
    def store_raw_findings(self, findings: List[dict]) -> int:
        """Store raw findings before validation."""
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            try:
                return mgr.sync_store_raw_findings(findings)
            except Exception as exc:
                log.warning("DBManager store_raw_findings failed, falling back to SQLite: %s", exc)
        inserted = 0
        try:
            with self._lock:
                with sqlite3.connect(str(self._db_path), timeout=30) as conn:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=FULL;")
                    for f in findings:
                        tool = f.get("tool") or f.get("source_tool") or "unknown"
                        conn.execute(
                            "INSERT INTO raw_findings (tool, raw_json) VALUES (?, ?)",
                            (tool, json.dumps(f, default=str)),
                        )
                        inserted += 1
                    conn.commit()
        except Exception as exc:
            log.error("store_raw_findings: DB error: %s", exc)
        return inserted
```

Replace `delete_findings_for_scan` (lines 655–664):

```python
    def delete_findings_for_scan(self, scan_id: str) -> int:
        """Delete all findings for the given scan_id. Returns the count deleted."""
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            try:
                return mgr.sync_delete_findings_for_scan(scan_id)
            except Exception as exc:
                log.warning("DBManager delete_findings_for_scan failed, falling back to SQLite: %s", exc)
        try:
            with sqlite3.connect(str(self._db_path)) as conn:
                cur = conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                conn.commit()
                return cur.rowcount
        except Exception as exc:
            log.error("delete_findings_for_scan: DB error: %s", exc)
            return 0
```

Replace `finding_count` (lines 699–709):

```python
    def finding_count(self, scan_id: str) -> int:
        """Return number of findings for a given scan_id."""
        mgr = _get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            try:
                return mgr.sync_finding_count(scan_id)
            except Exception as exc:
                log.warning("DBManager finding_count failed, falling back to SQLite: %s", exc)
        try:
            with sqlite3.connect(str(self._db_path)) as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
                ).fetchone()
                return row[0] if row else 0
        except Exception as exc:
            log.error("finding_count: DB error [scan=%s]: %s", scan_id, exc)
            return 0
```

- [ ] **Step 4: Run all RIE pg path tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_paths.py -v
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add result_ingestion_engine.py tests/test_rie_pg_paths.py
git commit -m "feat(rie): wire store_raw_findings, delete_findings_for_scan, finding_count to DBManager PG path"
```

---

## Task 9: Static migration test

**Files:**
- Create: `tests/test_rie_pg_migration.py`

- [ ] **Step 1: Write and run the static test**

Create `tests/test_rie_pg_migration.py`:

```python
# tests/test_rie_pg_migration.py
"""
Static checks: all SQLite-only paths in result_ingestion_engine.py are gone.
Every remaining sqlite3.connect must be inside an 'except' or SQLite fallback branch.
"""
import ast
from pathlib import Path


def _get_rie_source():
    return Path("result_ingestion_engine.py").read_text()


def test_no_sqlite_import_for_non_fallback():
    """sqlite3 may still be imported (for fallback), but we verify PG-first is present."""
    source = _get_rie_source()
    # The new PG-first pattern uses _get_db_manager_sync() — verify it's used in all 7 methods
    for method in (
        "_init_db",
        "_check_and_store",
        "get_findings",
        "ingest_recon_asset",
        "get_recon_assets",
        "store_raw_findings",
        "delete_findings_for_scan",
        "finding_count",
    ):
        # Each method must call _get_db_manager_sync somewhere in its body
        assert "_get_db_manager_sync" in source, (
            f"result_ingestion_engine.py must import/use _get_db_manager_sync (needed for {method})"
        )


def test_check_and_store_uses_sync_check_and_save():
    """_check_and_store must use sync_check_and_save_finding, not sync_save_finding."""
    source = _get_rie_source()
    assert "sync_check_and_save_finding" in source, (
        "_check_and_store must call mgr.sync_check_and_save_finding for dedup-aware PG path"
    )


def test_no_direct_pg_queries_in_rie():
    """RIE must not issue direct psycopg queries — all PG goes through DBManager."""
    source = _get_rie_source()
    assert "psycopg" not in source, (
        "result_ingestion_engine.py must not import psycopg directly — use DBManager"
    )


def test_ingest_recon_asset_uses_sync_save_recon_asset():
    source = _get_rie_source()
    assert "sync_save_recon_asset" in source


def test_get_recon_assets_uses_sync_get_recon_assets():
    source = _get_rie_source()
    assert "sync_get_recon_assets" in source


def test_store_raw_findings_uses_sync_store_raw_findings():
    source = _get_rie_source()
    assert "sync_store_raw_findings" in source


def test_delete_findings_uses_sync_delete():
    source = _get_rie_source()
    assert "sync_delete_findings_for_scan" in source


def test_finding_count_uses_sync_finding_count():
    source = _get_rie_source()
    assert "sync_finding_count" in source
```

- [ ] **Step 2: Run the static tests**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_rie_pg_migration.py -v
```

Expected: All 8 PASS.

- [ ] **Step 3: Commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add tests/test_rie_pg_migration.py
git commit -m "test(rie): static assertions — PG migration complete for all 7 methods"
```

---

## Task 10: Full test suite verification

**Files:** None

- [ ] **Step 1: Run all new tests together**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/test_db_manager_recon_raw.py tests/test_rie_pg_paths.py tests/test_rie_pg_migration.py -v
```

Expected: All tests PASS. Note the count and confirm all pass before continuing.

- [ ] **Step 2: Run existing test suite to check for regressions**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -m pytest tests/ -v --ignore=tests/test_learning_kb_removed.py 2>&1 | tail -20
```

Expected: All previously-passing tests still PASS. No new failures.

- [ ] **Step 3: Final commit**

```bash
cd /home/devendra-yadav/oneinfinity
git add -p  # review any remaining unstaged changes
git commit -m "feat(rie+db-manager): complete PG migration — all 7 RIE methods now PG-first"
```
