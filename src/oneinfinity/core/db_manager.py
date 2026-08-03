"""
core/db_manager.py — Backend-agnostic persistence interface.

Callers never know which backend is active. Mode determined at startup:
    distributed  → Redis + PostgreSQL available
    postgres     → PostgreSQL only (no Redis)
    sqlite       → SQLite fallback (default when Postgres unavailable)
    memory       → In-memory only (last resort)

Usage (FastAPI async):
    mgr = await get_db_manager()
    await mgr.save_finding(finding_dict)

Usage (CLI sync):
    mgr = await get_db_manager()        # or use get_db_manager_sync()
    mgr.sync_save_finding(finding_dict)
"""
from __future__ import annotations

import asyncio
from datetime import datetime
import json
import logging
import os
import threading
import uuid
from pathlib import Path
from typing import Optional

import oneinfinity.infra.path_manager as path_manager

log = logging.getLogger("oneinfinity.db_manager")

_manager: Optional["DBManager"] = None
_manager_lock = threading.Lock()

# ── Persistent DB loop ────────────────────────────────────────────────────────
# A single background thread runs _DB_LOOP indefinitely.
# All sync→async DB calls use run_coroutine_threadsafe() to submit work here.
# This avoids:
#   1. Shared event loop contention ('already running' errors)
#   2. Pool-loop mismatch (pool created in one loop, used in another)
#   3. threading.Lock held across await (deadlocks under concurrent callers)
_DB_LOOP: Optional[asyncio.AbstractEventLoop] = None
_DB_LOOP_THREAD: Optional[threading.Thread] = None
_DB_LOOP_LOCK = threading.Lock()


def _ensure_db_loop() -> asyncio.AbstractEventLoop:
    """Return the singleton DB background loop, starting it if necessary."""
    global _DB_LOOP, _DB_LOOP_THREAD
    if _DB_LOOP is not None and not _DB_LOOP.is_closed():
        return _DB_LOOP
    with _DB_LOOP_LOCK:
        if _DB_LOOP is None or _DB_LOOP.is_closed():
            loop = asyncio.new_event_loop()
            _DB_LOOP = loop
            t = threading.Thread(
                target=loop.run_forever,
                name="oneinfinity-db-loop",
                daemon=True,
            )
            _DB_LOOP_THREAD = t
            t.start()
    return _DB_LOOP


def _submit_to_db_loop(coro, timeout: float = 15.0):
    """Submit a coroutine to the persistent DB loop and wait for the result."""
    loop = _ensure_db_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result(timeout=timeout)


async def get_db_manager() -> "DBManager":
    """Return the singleton DBManager, initialising it on first call."""
    global _manager
    if _manager is not None:
        return _manager
    # Only one coroutine runs here at a time (single DB loop) — lock for safety
    acquired = _manager_lock.acquire(timeout=10)
    if not acquired:
        for _ in range(20):
            await asyncio.sleep(0.1)
            if _manager is not None:
                return _manager
        return _manager
    try:
        if _manager is None:
            _manager = DBManager()
            await _manager._init()
    finally:
        _manager_lock.release()
    return _manager


def get_db_manager_sync() -> "DBManager":
    """
    Sync wrapper: returns the DBManager singleton.
    Fast-path: already initialised → immediate return (no I/O, no locks).
    Slow-path: submits async init to the persistent DB background loop via
    run_coroutine_threadsafe() — safe to call from any thread at any time.
    """
    global _manager
    if _manager is not None:
        return _manager
    try:
        return _submit_to_db_loop(get_db_manager(), timeout=15.0)
    except Exception:
        return _manager  # may be None; callers must handle


class DBManager:
    """
    Backend-agnostic persistence interface.

    In distributed mode: uses psycopg3 async pool for all writes/reads.
    In sqlite mode: delegates to SQLite via the existing ResultIngestionEngine.
    """

    def __init__(self):
        self.mode = "sqlite"  # default until _init() runs
        self._pg_pool = None
        self._sqlite_path: Path = path_manager.findings_db_path()

    async def _pool(self):
        """Return the active PG pool, reconnecting if it was closed."""
        if self._pg_pool is not None:
            try:
                if not self._pg_pool.closed:
                    return self._pg_pool
            except Exception:
                pass
        # Pool is closed or missing — reconnect
        log.warning("[DBManager] PG pool closed — reconnecting")
        try:
            from oneinfinity.core.pg_client import get_async_pool
            new_pool = await get_async_pool()
            if new_pool is not None:
                self._pg_pool = new_pool
                log.info("[DBManager] PG pool reconnected successfully")
        except Exception as _exc:
            log.warning("[DBManager] PG pool reconnect failed: %s", _exc)
        return self._pg_pool

    async def _init(self) -> None:
        """Detect available backends and set mode."""
        explicit = os.environ.get("ONEINFINITY_STORAGE_MODE", "").lower()

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

        # Try PostgreSQL
        from oneinfinity.core.pg_client import get_async_pool
        pool = await get_async_pool()
        if pool is not None:
            self._pg_pool = pool
            # Apply schema
            await self._ensure_schema()
            from oneinfinity.core.redis_client import get_redis
            has_redis = get_redis() is not None
            self.mode = "distributed" if has_redis else "postgres"
            if self.mode == "distributed":
                log.info("[DBManager] Running in DISTRIBUTED mode (Redis + Postgres)")
            else:
                log.info("[DBManager] Running in POSTGRES mode")
            return

        self.mode = "sqlite"
        log.warning(
            "[DBManager] FALLBACK TRIGGERED: PostgreSQL unavailable — running in SQLITE fallback mode"
        )

    async def _ensure_schema(self) -> None:
        """Apply db/schema.sql to Postgres if tables don't exist."""
        schema_path = Path(__file__).resolve().parent.parent.parent.parent / "db" / "schema.sql"
        if not schema_path.exists():
            log.warning("DBManager: schema.sql not found at %s — skipping", schema_path)
            return
        sql = schema_path.read_text()
        try:
            async with (await self._pool()).connection() as conn:
                await conn.execute(sql)
                await conn.commit()
            log.info("DBManager: schema applied")
        except Exception as exc:
            log.warning("DBManager: schema apply failed (%s) — may already exist", exc)

    # ── Findings ──────────────────────────────────────────────────────────────

    async def save_finding(self, finding: dict) -> str:
        """Persist a finding. Returns finding_id."""
        fid = finding.get("finding_id") or str(uuid.uuid4())[:12]
        finding = {**finding, "finding_id": fid}

        if self.mode in ("distributed", "postgres"):
            await self._pg_save_finding(finding)
        else:
            self._sqlite_save_finding(finding)
        return fid

    async def _pg_save_finding(self, finding: dict) -> None:
        data = {
            k: finding.get(k, "")
            for k in ("evidence", "payload", "raw", "poc_steps", "reproduction_cmd")
        }
        try:
            async with (await self._pool()).connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO findings
                        (finding_id, scan_id, target, title, severity, vuln_type, url,
                         tool, confidence, cvss, status, source_type, created_at, data)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),%s)
                    ON CONFLICT (finding_id) DO UPDATE SET
                        status=EXCLUDED.status, data=EXCLUDED.data
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
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager._pg_save_finding failed: %s", exc)
            raise

    def _sqlite_save_finding(self, finding: dict) -> None:
        """Delegate to existing ResultIngestionEngine (SQLite fallback)."""
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            ie = get_ingestion_engine()
            # persist_finding accepts a dict and handles NormalizedFinding construction internally
            ie.persist_finding(finding)
        except Exception as exc:
            log.warning("DBManager._sqlite_save_finding failed: %s", exc)

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
            async with (await self._pool()).connection() as conn:
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
            async with (await self._pool()).connection() as conn:
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
                # SQLite dedup: exact match within scan OR same (vuln_type, url) within 24h.
                # The 24h cross-scan arm is intentionally more conservative than PG
                # (which deduplicates strictly on scan_id+vuln_type+url) to prevent
                # duplicate findings from rapid re-scans in offline/fallback mode.
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
                    "INSERT OR IGNORE INTO findings "
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
            async with (await self._pool()).connection() as conn:
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
            async with (await self._pool()).connection() as conn:
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

    # ── Raw Findings ─────────────────────────────────────────────────────────

    async def store_raw_findings(self, findings: list) -> int:
        """Bulk-insert raw findings. Returns count inserted."""
        if self.mode in ("distributed", "postgres"):
            return await self._pg_store_raw_findings(findings)
        return self._sqlite_store_raw_findings(findings)

    async def _pg_store_raw_findings(self, findings: list) -> int:
        inserted = 0
        try:
            async with (await self._pool()).connection() as conn:
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
            async with (await self._pool()).connection() as conn:
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
            async with (await self._pool()).connection() as conn:
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

    # ── Scans ─────────────────────────────────────────────────────────────────

    async def save_scan(self, scan: dict) -> str:
        sid = scan.get("id") or scan.get("scan_id") or str(uuid.uuid4())
        scan = {**scan, "scan_id": sid}
        if self.mode in ("distributed", "postgres"):
            await self._pg_save_scan(scan)
        else:
            self._sqlite_save_scan(scan)
        return sid

    async def _pg_save_scan(self, scan: dict) -> None:
        data = {k: v for k, v in scan.items()
                if k not in ("id", "scan_id", "target", "scan_type", "status", "created_at", "completed_at")}
        try:
            async with (await self._pool()).connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO scans (scan_id, target, scan_type, status, data)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (scan_id) DO UPDATE SET
                        status=EXCLUDED.status,
                        completed_at=CASE WHEN EXCLUDED.status IN ('completed','error','stopped')
                                     THEN NOW() ELSE scans.completed_at END,
                        data=EXCLUDED.data
                    """,
                    (
                        scan["scan_id"],
                        scan.get("target", ""),
                        scan.get("scan_type", "full"),
                        scan.get("status", "pending"),
                        json.dumps(data, default=str),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager._pg_save_scan failed: %s", exc)
            raise

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
            async with (await self._pool()).connection() as conn:
                await conn.execute("DELETE FROM scans WHERE scan_id = %s", (scan_id,))
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager._pg_delete_scan failed: %s", exc)

    def _sqlite_delete_scan(self, scan_id: str) -> None:
        import sqlite3 as _sq
        db_path = path_manager.db_path("metadata.db")
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
            async with (await self._pool()).connection() as conn:
                rows = await conn.execute(
                    "SELECT scan_id, target, scan_type, status, data, completed_at "
                    "FROM scans ORDER BY created_at DESC"
                )
                results = []
                async for row in rows:
                    d = {
                        "scan_id": row[0], "id": row[0],
                        "target": row[1], "scan_type": row[2],
                        "status": row[3],
                        "completed_at": str(row[5]) if row[5] else None,
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

    # ── Events ────────────────────────────────────────────────────────────────

    async def save_event(self, event: dict) -> None:
        if self.mode not in ("distributed", "postgres"):
            return  # events only persisted in Postgres mode
        try:
            async with (await self._pool()).connection() as conn:
                await conn.execute(
                    """
                    INSERT INTO events (event_id, event_type, scan_id, source, data)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        event.get("event_id", str(uuid.uuid4())),
                        event.get("event_type", "UNKNOWN"),
                        event.get("scan_id") or event.get("correlation_id"),
                        event.get("source", "platform"),
                        json.dumps(event.get("data", {}), default=str),
                    ),
                )
                await conn.commit()
        except Exception as exc:
            log.debug("DBManager.save_event failed: %s", exc)

    # ── Knowledge Base ────────────────────────────────────────────────────────

    async def upsert_knowledge(self, category: str, key: str, data: dict) -> None:
        if self.mode in ("distributed", "postgres"):
            try:
                async with (await self._pool()).connection() as conn:
                    await conn.execute(
                        """
                        INSERT INTO knowledge_base (category, key, data)
                        VALUES (%s,%s,%s)
                        ON CONFLICT (category, key) DO UPDATE SET
                            data=EXCLUDED.data, updated_at=NOW()
                        """,
                        (category, key, json.dumps(data, default=str)),
                    )
                    await conn.commit()
            except Exception as exc:
                log.warning("DBManager.upsert_knowledge failed: %s", exc)

    async def get_knowledge(self, category: str, key: Optional[str] = None) -> list:
        if self.mode not in ("distributed", "postgres"):
            return []
        conditions = ["category = %s"]
        params: list = [category]
        if key:
            conditions.append("key = %s")
            params.append(key)
        try:
            async with (await self._pool()).connection() as conn:
                rows = await conn.execute(
                    f"SELECT key, data FROM knowledge_base WHERE {' AND '.join(conditions)}",
                    params,
                )
                return [{"key": r[0], **json.loads(r[1])} async for r in rows]
        except Exception as exc:
            log.warning("DBManager.get_knowledge failed: %s", exc)
            return []

    # ── Targets ──────────────────────────────────────────────────────────────

    def _target_row_to_dict(self, row) -> dict:
        """Convert a targets table row tuple to API dict."""
        cols = ["target_id", "target_value", "target_type", "name", "platform", "scope",
                "status", "created_at", "last_scan_time", "vuln_count", "severity_counts"]
        d = dict(zip(cols, row))
        for ts_field in ("created_at", "last_scan_time"):
            if hasattr(d.get(ts_field), "isoformat"):
                d[ts_field] = d[ts_field].isoformat()
        if isinstance(d.get("scope"), str):
            d["scope"] = json.loads(d["scope"])
        elif d.get("scope") is None:
            d["scope"] = []
        if isinstance(d.get("severity_counts"), str):
            d["severity_counts"] = json.loads(d["severity_counts"])
        elif d.get("severity_counts") is None:
            d["severity_counts"] = {}
        d["id"] = d["target_id"]
        d["domain"] = d["target_value"]
        return d

    async def save_target(self, data: dict) -> dict:
        """Upsert a target row. Returns the stored dict."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("save_target requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
                        data.get("scope", []),
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
            # Postgres not available
            raise RuntimeError("get_target requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            return []
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("delete_target requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("update_target_status requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("update_target_vuln_count requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
                await conn.execute(
                    "UPDATE targets SET vuln_count = %s WHERE target_id = %s",
                    (count, target_id),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.update_target_vuln_count failed: %s", exc)

    # ── Research ──────────────────────────────────────────────────────────────

    async def save_research_session(self, data: dict) -> None:
        """Upsert a research session row."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("save_research_session requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("get_research_session requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("list_research_sessions requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
                    # psycopg3 Row is a named-tuple; dict() interprets it as an
                    # iterable of values, not key-value pairs, causing a TypeError.
                    # Use _mapping (Mapping view) which dict() accepts correctly.
                    try:
                        result.append(dict(row._mapping))
                    except AttributeError:
                        result.append(dict(zip([d.name for d in rows.description], row)))
                return result
        except Exception as exc:
            log.warning("DBManager.list_research_sessions failed: %s", exc)
            return []

    async def save_research_theory(self, data: dict) -> None:
        """Insert a vulnerability theory (idempotent — ON CONFLICT DO NOTHING)."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("save_research_theory requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            raise

    async def update_research_theory_status(
        self, theory_id: str, status: str, updated_at: float
    ) -> None:
        """Update the status and updated_at timestamp of a vulnerability theory."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("update_research_theory_status requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
                await conn.execute(
                    "UPDATE vuln_theories SET status = %s, updated_at = %s "
                    "WHERE theory_id = %s",
                    (status, updated_at, theory_id),
                )
                await conn.commit()
        except Exception as exc:
            log.warning("DBManager.update_research_theory_status failed: %s", exc)
            raise

    async def save_test_outcome(self, data: dict) -> None:
        """Insert one test outcome row (every outcome is a new row — no upsert)."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("save_test_outcome requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            raise

    async def save_research_discovery(self, data: dict) -> None:
        """Upsert a confirmed vulnerability discovery."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("save_research_discovery requires Postgres mode")
        try:
            steps = data.get("steps", [])
            if isinstance(steps, str):
                steps = json.loads(steps)
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("list_research_discoveries requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("upsert_cross_target_pattern requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            raise

    async def get_cross_target_patterns(self, min_count: int = 2) -> list:
        """Return patterns with success_count >= min_count, ordered by frequency."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("get_cross_target_patterns requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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

    # ── Learning ──────────────────────────────────────────────────────────────

    async def save_learning_session(self, data: dict) -> None:
        """Upsert a learning scan session.

        ON CONFLICT updates only the finish fields (finished_at, total_findings,
        tools_used, notes) — target, started_at, and phases are preserved from
        the original INSERT (start_session call).
        """
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("save_learning_session requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("get_learning_session requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("list_learning_sessions requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("save_learning_finding requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("record_tool_run requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("get_best_tool_for_vuln requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
                        "tool_name":      row[0],
                        "runs_total":     row[1],
                        "runs_success":   row[2],
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
            # Postgres not available
            raise RuntimeError("upsert_target_profile requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("get_target_profile requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("upsert_pattern requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("get_patterns_for_tech_stack requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
            # Postgres not available
            raise RuntimeError("get_learning_stats requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
                "sessions":           sessions,
                "confirmed_findings": findings,
                "unique_targets":     targets,
                "top_vuln_types":     top_vulns,
                "top_tools":          top_tools,
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
            # Postgres not available
            raise RuntimeError("list_tool_performance requires Postgres mode")
        try:
            async with (await self._pool()).connection() as conn:
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
                        "tool_name":      row[0],
                        "vuln_type":      row[1],
                        "ema":            row[2],
                        "runs_total":     row[3],
                        "findings_total": row[4],
                    })
                return result
        except Exception as exc:
            log.warning("DBManager.list_tool_performance failed: %s", exc)
            return []

    # ── Sync wrappers for CLI ─────────────────────────────────────────────────

    @staticmethod
    def _run_sync(coro, timeout: float = 15.0):
        """
        Run a coroutine synchronously via the persistent DB background loop.
        Safe to call from any thread (including asyncio thread-pool threads).
        """
        return _submit_to_db_loop(coro, timeout=timeout)

    def sync_save_finding(self, finding: dict) -> str:
        return self._run_sync(self.save_finding(finding))

    def sync_save_scan(self, scan: dict) -> str:
        try:
            return self._run_sync(self.save_scan(scan))
        except Exception as _exc:
            if "PoolClosed" in type(_exc).__name__ or "PoolClosed" in str(_exc):
                log.warning(
                    "sync_save_scan: pool closed during shutdown — skipping persist for scan %s",
                    scan.get("scan_id", "?"))
                return ""
            raise

    def sync_get_findings(self, **kwargs) -> list:
        return self._run_sync(self.get_findings(**kwargs))

    def sync_check_and_save_finding(self, finding: dict) -> bool:
        return self._run_sync(self.check_and_save_finding(finding))

    # ── Generic PG helpers (for peripheral tables not in main DBManager) ──────

    async def pg_execute_write(self, sql: str, params: tuple = ()) -> int:
        """Execute a write statement against PG. Returns rowcount. Raises if not PG mode."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("pg_execute_write requires Postgres mode")
        async with (await self._pool()).connection() as conn:
            result = await conn.execute(sql, params)
            await conn.commit()
            return result.rowcount

    async def pg_execute_read(self, sql: str, params: tuple = ()) -> list:
        """Execute a SELECT against PG. Returns list of row dicts."""
        if self.mode not in ("distributed", "postgres"):
            # Postgres not available
            raise RuntimeError("pg_execute_read requires Postgres mode")
        async with (await self._pool()).connection() as conn:
            cursor = await conn.execute(sql, params)
            columns = [d[0] for d in cursor.description] if cursor.description else []
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def pg_ensure_tables(self, ddl: str) -> None:
        """Run CREATE TABLE IF NOT EXISTS DDL against PG (schema migration)."""
        if self.mode not in ("distributed", "postgres"):
            return
        async with (await self._pool()).connection() as conn:
            await conn.execute(ddl)
            await conn.commit()

    def sync_pg_execute_write(self, sql: str, params: tuple = ()) -> int:
        return self._run_sync(self.pg_execute_write(sql, params))

    def sync_pg_execute_read(self, sql: str, params: tuple = ()) -> list:
        return self._run_sync(self.pg_execute_read(sql, params))

    def sync_pg_ensure_tables(self, ddl: str) -> None:
        self._run_sync(self.pg_ensure_tables(ddl))

    def sync_save_recon_asset(self, asset_id: str, scan_id: str, asset_type: str,
                               value: str, metadata: Optional[dict] = None) -> None:
        self._run_sync(self.save_recon_asset(asset_id, scan_id, asset_type, value, metadata))

    def sync_get_recon_assets(self, **kwargs) -> list:
        return self._run_sync(self.get_recon_assets(**kwargs))

    def sync_store_raw_findings(self, findings: list) -> int:
        return self._run_sync(self.store_raw_findings(findings))

    def sync_delete_findings_for_scan(self, scan_id: str) -> int:
        return self._run_sync(self.delete_findings_for_scan(scan_id))

    def sync_finding_count(self, scan_id: str) -> int:
        return self._run_sync(self.finding_count(scan_id))
