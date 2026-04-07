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

import path_manager

log = logging.getLogger("oneinfinity.db_manager")

_manager: Optional["DBManager"] = None
_manager_lock = threading.Lock()


async def get_db_manager() -> "DBManager":
    """Return the singleton DBManager, initialising it on first call."""
    global _manager
    if _manager is not None:
        return _manager
    with _manager_lock:
        if _manager is None:
            _manager = DBManager()
            await _manager._init()
    return _manager


def get_db_manager_sync() -> "DBManager":
    """Sync wrapper for CLI — creates a new event loop if needed."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already inside an async context — create a new loop in a thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(asyncio.run, get_db_manager())
                return future.result()
        return loop.run_until_complete(get_db_manager())
    except RuntimeError:
        return asyncio.run(get_db_manager())


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
        from core.pg_client import get_async_pool
        pool = await get_async_pool()
        if pool is not None:
            self._pg_pool = pool
            # Apply schema
            await self._ensure_schema()
            from core.redis_client import get_redis
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
        schema_path = Path(__file__).resolve().parent.parent / "db" / "schema.sql"
        if not schema_path.exists():
            log.warning("DBManager: schema.sql not found at %s — skipping", schema_path)
            return
        sql = schema_path.read_text()
        try:
            async with self._pg_pool.connection() as conn:
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
            async with self._pg_pool.connection() as conn:
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
            from result_ingestion_engine import get_ingestion_engine
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
            async with self._pg_pool.connection() as conn:
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
            async with self._pg_pool.connection() as conn:
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
                async with self._pg_pool.connection() as conn:
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
            async with self._pg_pool.connection() as conn:
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

    # ── Sync wrappers for CLI ─────────────────────────────────────────────────

    @staticmethod
    def _run_sync(coro):
        """Run a coroutine synchronously, creating a new event loop if needed."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    return ex.submit(asyncio.run, coro).result()
            if loop.is_closed():
                raise RuntimeError("loop is closed")
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)

    def sync_save_finding(self, finding: dict) -> str:
        return self._run_sync(self.save_finding(finding))

    def sync_save_scan(self, scan: dict) -> str:
        return self._run_sync(self.save_scan(scan))

    def sync_get_findings(self, **kwargs) -> list:
        return self._run_sync(self.get_findings(**kwargs))
