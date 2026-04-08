"""
Traffic Capture Engine
======================
Captures, stores, and queries all HTTP requests/responses produced by the platform.

Storage: SQLite at ~/.oneinfinity/databases/traffic.db
Schema:  captured_requests table

Features:
  - Store any HTTP request + response pair
  - Query by URL, method, status, source, target domain, date
  - Tag requests with source module (recon, scan, ai_redteam, agent, ...)
  - Export to JSON / CSV / HAR
  - Full-text search over URL and body
  - Real-time broadcast hook (WebSocket integration)
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from path_manager import db_path as db_path_fn

log = logging.getLogger("oneinfinity.traffic")

DB_PATH = db_path_fn("traffic.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CapturedRequest:
    id: str                          = field(default_factory=lambda: str(uuid.uuid4())[:12])
    method: str                      = "GET"
    url: str                         = ""
    headers: Dict[str, str]          = field(default_factory=dict)
    body: str                        = ""
    response_status: int             = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str               = ""
    source: str                      = "unknown"      # recon | scan | ai | agent | manual
    target_domain: str               = ""
    proxied: bool                    = False
    proxy_address: str               = ""
    timestamp: str                   = field(default_factory=lambda: datetime.utcnow().isoformat())
    duration_ms: int                 = 0
    tags: List[str]                  = field(default_factory=list)
    vuln_id: str                     = ""             # linked vulnerability
    attack_type: str                 = ""
    flagged: bool                    = False
    flag_reason: str                 = ""

    def __post_init__(self):
        if not self.target_domain and self.url:
            try:
                self.target_domain = urlparse(self.url).hostname or ""
            except Exception:
                pass

    @property
    def fingerprint(self) -> str:
        """SHA-256 of method+url+body for dedup."""
        raw = f"{self.method}|{self.url}|{self.body}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["headers"] = json.dumps(d["headers"])
        d["response_headers"] = json.dumps(d["response_headers"])
        d["tags"] = json.dumps(d["tags"])
        return d

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "CapturedRequest":
        d = dict(row)
        d["headers"] = json.loads(d.get("headers") or "{}")
        d["response_headers"] = json.loads(d.get("response_headers") or "{}")
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["proxied"] = bool(d.get("proxied", 0))
        d["flagged"] = bool(d.get("flagged", 0))
        return cls(**d)

    def to_json(self) -> Dict:
        """Human-readable JSON representation."""
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "response": {
                "status": self.response_status,
                "headers": self.response_headers,
                "body": self.response_body[:2000],
            },
            "source": self.source,
            "target": self.target_domain,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "proxied": self.proxied,
            "flagged": self.flagged,
            "flag_reason": self.flag_reason,
            "tags": self.tags,
            "vuln_id": self.vuln_id,
            "attack_type": self.attack_type,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  SQLite storage
# ─────────────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS captured_requests (
    id               TEXT PRIMARY KEY,
    method           TEXT NOT NULL,
    url              TEXT NOT NULL,
    headers          TEXT DEFAULT '{}',
    body             TEXT DEFAULT '',
    response_status  INTEGER DEFAULT 0,
    response_headers TEXT DEFAULT '{}',
    response_body    TEXT DEFAULT '',
    source           TEXT DEFAULT 'unknown',
    target_domain    TEXT DEFAULT '',
    proxied          INTEGER DEFAULT 0,
    proxy_address    TEXT DEFAULT '',
    timestamp        TEXT NOT NULL,
    duration_ms      INTEGER DEFAULT 0,
    tags             TEXT DEFAULT '[]',
    vuln_id          TEXT DEFAULT '',
    attack_type      TEXT DEFAULT '',
    flagged          INTEGER DEFAULT 0,
    flag_reason      TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_url           ON captured_requests(url);
CREATE INDEX IF NOT EXISTS idx_target        ON captured_requests(target_domain);
CREATE INDEX IF NOT EXISTS idx_source        ON captured_requests(source);
CREATE INDEX IF NOT EXISTS idx_timestamp     ON captured_requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_status        ON captured_requests(response_status);
CREATE INDEX IF NOT EXISTS idx_flagged       ON captured_requests(flagged);
CREATE INDEX IF NOT EXISTS idx_vuln          ON captured_requests(vuln_id);
"""


def _from_pg_row(row: dict) -> "CapturedRequest":
    """Convert a dict row from PG (sync_pg_execute_read) to a CapturedRequest."""
    d = dict(row)
    d["headers"] = json.loads(d.get("headers") or "{}")
    d["response_headers"] = json.loads(d.get("response_headers") or "{}")
    d["tags"] = json.loads(d.get("tags") or "[]")
    d["proxied"] = bool(d.get("proxied", False))
    d["flagged"] = bool(d.get("flagged", False))
    return CapturedRequest(**d)


class TrafficCaptureEngine:
    """
    Thread-safe traffic capture engine backed by PostgreSQL (when available)
    with SQLite fallback.
    """

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._listeners: List[Callable[[CapturedRequest], None]] = []
        self._init_db()

    # ── PG helper ─────────────────────────────────────────────────────────────

    def _pg(self):
        """Return DBManager if running in PG/distributed mode, else None."""
        try:
            from core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            return mgr if mgr and mgr.mode in ("distributed", "postgres") else None
        except Exception:
            return None

    # ── DB init ───────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        if self._pg() is not None:
            # PG schema already applied by DBManager at startup
            return
        con = self._conn()
        con.executescript(_CREATE_TABLE)
        con.commit()

    def _conn(self) -> sqlite3.Connection:
        if not getattr(self._local, "conn", None):
            self._local.conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    # ── Store / capture ───────────────────────────────────────────────────────

    def store(self, req: CapturedRequest) -> str:
        """Persist a captured request. Returns the request id."""
        mgr = self._pg()
        if mgr is not None:
            d = req.to_dict()
            cols = ", ".join(d.keys())
            placeholders = ", ".join("%s" for _ in d)
            sql = (
                f"INSERT INTO captured_requests ({cols}) VALUES ({placeholders})"
                " ON CONFLICT (id) DO NOTHING"
            )
            try:
                mgr.sync_pg_execute_write(sql, tuple(d.values()))
            except Exception as exc:
                log.warning("TrafficCaptureEngine.store PG failed, falling back to SQLite: %s", exc)
                mgr = None
        if mgr is None:
            d = req.to_dict()
            cols = ", ".join(d.keys())
            placeholders = ", ".join("?" for _ in d)
            sql = f"INSERT OR REPLACE INTO captured_requests ({cols}) VALUES ({placeholders})"
            with self._lock:
                self._conn().execute(sql, list(d.values()))
                self._conn().commit()
        log.debug("Traffic captured: %s %s → %d", req.method, req.url, req.response_status)
        for listener in self._listeners:
            try:
                listener(req)
            except Exception:
                pass
        return req.id

    def capture(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        body: str = "",
        response_status: int = 0,
        response_headers: Optional[Dict] = None,
        response_body: str = "",
        source: str = "manual",
        duration_ms: int = 0,
        tags: Optional[List[str]] = None,
        vuln_id: str = "",
        attack_type: str = "",
        proxied: bool = False,
        proxy_address: str = "",
    ) -> CapturedRequest:
        """Convenience wrapper: build and store a CapturedRequest."""
        req = CapturedRequest(
            method=method.upper(),
            url=url,
            headers=headers or {},
            body=body,
            response_status=response_status,
            response_headers=response_headers or {},
            response_body=response_body,
            source=source,
            duration_ms=duration_ms,
            tags=tags or [],
            vuln_id=vuln_id,
            attack_type=attack_type,
            proxied=proxied,
            proxy_address=proxy_address,
        )
        self.store(req)
        return req

    # ── Query ─────────────────────────────────────────────────────────────────

    def get(self, request_id: str) -> Optional[CapturedRequest]:
        mgr = self._pg()
        if mgr is not None:
            rows = mgr.sync_pg_execute_read(
                "SELECT * FROM captured_requests WHERE id = %s", (request_id,)
            )
            if rows:
                return _from_pg_row(rows[0])
            return None
        row = self._conn().execute(
            "SELECT * FROM captured_requests WHERE id = ?", (request_id,)
        ).fetchone()
        return CapturedRequest.from_row(row) if row else None

    def list(
        self,
        target: Optional[str] = None,
        source: Optional[str] = None,
        method: Optional[str] = None,
        status_code: Optional[int] = None,
        flagged: Optional[bool] = None,
        vuln_id: Optional[str] = None,
        attack_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[CapturedRequest]:
        mgr = self._pg()
        if mgr is not None:
            clauses: List[str] = []
            params: List[Any] = []
            if target:
                clauses.append("target_domain LIKE %s")
                params.append(f"%{target}%")
            if source:
                clauses.append("source = %s")
                params.append(source)
            if method:
                clauses.append("method = %s")
                params.append(method.upper())
            if status_code is not None:
                clauses.append("response_status = %s")
                params.append(status_code)
            if flagged is not None:
                clauses.append("flagged = %s")
                params.append(flagged)
            if vuln_id:
                clauses.append("vuln_id = %s")
                params.append(vuln_id)
            if attack_type:
                clauses.append("attack_type = %s")
                params.append(attack_type)
            if search:
                clauses.append("(url LIKE %s OR body LIKE %s OR response_body LIKE %s)")
                params += [f"%{search}%", f"%{search}%", f"%{search}%"]
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            sql = (
                f"SELECT * FROM captured_requests {where}"
                " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
            )
            rows = mgr.sync_pg_execute_read(sql, tuple(params + [limit, offset]))
            return [_from_pg_row(r) for r in rows]

        # SQLite fallback
        clauses = []
        params = []
        if target:
            clauses.append("target_domain LIKE ?")
            params.append(f"%{target}%")
        if source:
            clauses.append("source = ?")
            params.append(source)
        if method:
            clauses.append("method = ?")
            params.append(method.upper())
        if status_code is not None:
            clauses.append("response_status = ?")
            params.append(status_code)
        if flagged is not None:
            clauses.append("flagged = ?")
            params.append(1 if flagged else 0)
        if vuln_id:
            clauses.append("vuln_id = ?")
            params.append(vuln_id)
        if attack_type:
            clauses.append("attack_type = ?")
            params.append(attack_type)
        if search:
            clauses.append("(url LIKE ? OR body LIKE ? OR response_body LIKE ?)")
            params += [f"%{search}%", f"%{search}%", f"%{search}%"]

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM captured_requests {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        rows = self._conn().execute(sql, params + [limit, offset]).fetchall()
        return [CapturedRequest.from_row(r) for r in rows]

    def count(self, **filters) -> int:
        return len(self.list(**filters, limit=10000))

    def flag(self, request_id: str, reason: str) -> None:
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write(
                "UPDATE captured_requests SET flagged=TRUE, flag_reason=%s WHERE id=%s",
                (reason, request_id),
            )
            return
        with self._lock:
            self._conn().execute(
                "UPDATE captured_requests SET flagged=1, flag_reason=? WHERE id=?",
                (reason, request_id)
            )
            self._conn().commit()

    def link_vuln(self, request_id: str, vuln_id: str, attack_type: str = "") -> None:
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write(
                "UPDATE captured_requests SET vuln_id=%s, attack_type=%s WHERE id=%s",
                (vuln_id, attack_type, request_id),
            )
            return
        with self._lock:
            self._conn().execute(
                "UPDATE captured_requests SET vuln_id=?, attack_type=? WHERE id=?",
                (vuln_id, attack_type, request_id)
            )
            self._conn().commit()

    def delete(self, request_id: str) -> None:
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write(
                "DELETE FROM captured_requests WHERE id=%s", (request_id,)
            )
            return
        with self._lock:
            self._conn().execute("DELETE FROM captured_requests WHERE id=?", (request_id,))
            self._conn().commit()

    def clear(self, target: Optional[str] = None) -> int:
        mgr = self._pg()
        if mgr is not None:
            if target:
                return mgr.sync_pg_execute_write(
                    "DELETE FROM captured_requests WHERE target_domain LIKE %s",
                    (f"%{target}%",),
                )
            return mgr.sync_pg_execute_write("DELETE FROM captured_requests", ())
        with self._lock:
            if target:
                cur = self._conn().execute(
                    "DELETE FROM captured_requests WHERE target_domain LIKE ?",
                    (f"%{target}%",)
                )
            else:
                cur = self._conn().execute("DELETE FROM captured_requests")
            self._conn().commit()
            return cur.rowcount

    def stats(self) -> Dict:
        mgr = self._pg()
        if mgr is not None:
            total_rows = mgr.sync_pg_execute_read(
                "SELECT COUNT(*) AS cnt FROM captured_requests", ()
            )
            total = total_rows[0]["cnt"] if total_rows else 0
            flagged_rows = mgr.sync_pg_execute_read(
                "SELECT COUNT(*) AS cnt FROM captured_requests WHERE flagged=TRUE", ()
            )
            flagged = flagged_rows[0]["cnt"] if flagged_rows else 0
            by_source = {
                r["source"]: r["cnt"]
                for r in mgr.sync_pg_execute_read(
                    "SELECT source, COUNT(*) AS cnt FROM captured_requests GROUP BY source", ()
                )
            }
            by_status = {
                str(r["response_status"]): r["cnt"]
                for r in mgr.sync_pg_execute_read(
                    "SELECT response_status, COUNT(*) AS cnt FROM captured_requests"
                    " GROUP BY response_status ORDER BY cnt DESC LIMIT 10",
                    (),
                )
            }
            return {
                "total": total,
                "flagged": flagged,
                "by_source": by_source,
                "by_status_code": by_status,
            }
        con = self._conn()
        total = con.execute("SELECT COUNT(*) FROM captured_requests").fetchone()[0]
        flagged = con.execute("SELECT COUNT(*) FROM captured_requests WHERE flagged=1").fetchone()[0]
        by_source = {
            row["source"]: row["cnt"]
            for row in con.execute(
                "SELECT source, COUNT(*) as cnt FROM captured_requests GROUP BY source"
            ).fetchall()
        }
        by_status = {
            str(row["response_status"]): row["cnt"]
            for row in con.execute(
                "SELECT response_status, COUNT(*) as cnt FROM captured_requests GROUP BY response_status ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
        }
        return {
            "total": total,
            "flagged": flagged,
            "by_source": by_source,
            "by_status_code": by_status,
        }

    # ── Export ────────────────────────────────────────────────────────────────

    def export_json(self, path: str, **filters) -> str:
        reqs = self.list(**filters, limit=10000)
        out = Path(path)
        out.write_text(json.dumps([r.to_json() for r in reqs], indent=2))
        return str(out)

    def export_csv(self, path: str, **filters) -> str:
        reqs = self.list(**filters, limit=10000)
        out = Path(path)
        if not reqs:
            out.write_text("")
            return str(out)
        fieldnames = ["id", "method", "url", "response_status", "source",
                      "target_domain", "timestamp", "duration_ms", "flagged", "flag_reason",
                      "attack_type", "vuln_id", "proxied"]
        with out.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in reqs:
                w.writerow({k: getattr(r, k) for k in fieldnames})
        return str(out)

    def export_har(self, path: str, **filters) -> str:
        """Export as HTTP Archive (HAR) format — compatible with Burp/DevTools."""
        reqs = self.list(**filters, limit=10000)
        entries = []
        for r in reqs:
            req_headers = [{"name": k, "value": v} for k, v in r.headers.items()]
            resp_headers = [{"name": k, "value": v} for k, v in r.response_headers.items()]
            entries.append({
                "startedDateTime": r.timestamp,
                "time": r.duration_ms,
                "request": {
                    "method": r.method,
                    "url": r.url,
                    "headers": req_headers,
                    "postData": {"text": r.body} if r.body else None,
                },
                "response": {
                    "status": r.response_status,
                    "headers": resp_headers,
                    "content": {"text": r.response_body[:10000], "size": len(r.response_body)},
                },
                "_source": r.source,
                "_flagged": r.flagged,
            })
        har = {"log": {"version": "1.2", "entries": entries}}
        Path(path).write_text(json.dumps(har, indent=2))
        return path

    # ── Real-time listener registration ──────────────────────────────────────

    def add_listener(self, fn: Callable[[CapturedRequest], None]) -> None:
        """Register a callback invoked on every new captured request."""
        self._listeners.append(fn)

    def remove_listener(self, fn: Callable[[CapturedRequest], None]) -> None:
        if fn in self._listeners:
            self._listeners.remove(fn)


# ─────────────────────────────────────────────────────────────────────────────
#  Context manager for timing + automatic capture
# ─────────────────────────────────────────────────────────────────────────────

class RequestCapture:
    """
    Context manager that captures timing and stores the result.

    Usage:
        with RequestCapture("recon", url) as cap:
            status, body, headers = do_http_call()
            cap.finish(status, body, headers)
    """

    def __init__(
        self,
        source: str,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        body: str = "",
        tags: Optional[List[str]] = None,
    ) -> None:
        self._source = source
        self._method = method
        self._url = url
        self._headers = headers or {}
        self._body = body
        self._tags = tags or []
        self._t0 = 0.0
        self.captured: Optional[CapturedRequest] = None

    def __enter__(self) -> "RequestCapture":
        self._t0 = time.time()
        return self

    def finish(
        self,
        status: int,
        body: str,
        resp_headers: Optional[Dict] = None,
        vuln_id: str = "",
        attack_type: str = "",
        proxied: bool = False,
        proxy_address: str = "",
    ) -> CapturedRequest:
        duration = int((time.time() - self._t0) * 1000)
        self.captured = traffic_capture_engine.capture(
            method=self._method,
            url=self._url,
            headers=self._headers,
            body=self._body,
            response_status=status,
            response_headers=resp_headers or {},
            response_body=body,
            source=self._source,
            duration_ms=duration,
            tags=self._tags,
            vuln_id=vuln_id,
            attack_type=attack_type,
            proxied=proxied,
            proxy_address=proxy_address,
        )
        return self.captured

    def __exit__(self, *args) -> None:
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Global singleton
# ─────────────────────────────────────────────────────────────────────────────

traffic_capture_engine = TrafficCaptureEngine()
