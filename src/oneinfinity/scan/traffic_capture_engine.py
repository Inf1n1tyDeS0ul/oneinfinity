"""
Traffic Capture Engine
======================
Captures, stores, and queries all HTTP requests/responses produced by the platform.

Storage: PostgreSQL captured_requests table (hard requirement).

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
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("oneinfinity.traffic")


def _require_pg():
    """Return DBManager in PG mode, or raise if unavailable."""
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if mgr is not None and mgr.mode in ("distributed", "postgres"):
            return mgr
    except Exception as exc:
        raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
    raise RuntimeError(
        "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
    )


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
    source: str                      = "unknown"
    target_domain: str               = ""
    proxied: bool                    = False
    proxy_address: str               = ""
    timestamp: str                   = field(default_factory=lambda: datetime.utcnow().isoformat())
    duration_ms: int                 = 0
    tags: List[str]                  = field(default_factory=list)
    vuln_id: str                     = ""
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
        raw = f"{self.method}|{self.url}|{self.body}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["headers"] = json.dumps(d["headers"])
        d["response_headers"] = json.dumps(d["response_headers"])
        d["tags"] = json.dumps(d["tags"])
        return d

    @classmethod
    def from_row(cls, row: dict) -> "CapturedRequest":
        d = dict(row)
        d["headers"] = json.loads(d.get("headers") or "{}")
        d["response_headers"] = json.loads(d.get("response_headers") or "{}")
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["proxied"] = bool(d.get("proxied", False))
        d["flagged"] = bool(d.get("flagged", False))
        return cls(**d)

    def to_json(self) -> Dict:
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
#  Engine
# ─────────────────────────────────────────────────────────────────────────────

class TrafficCaptureEngine:
    """Traffic capture engine backed by PostgreSQL."""

    def __init__(self) -> None:
        self._listeners: List[Callable[[CapturedRequest], None]] = []

    def _pg(self):
        return _require_pg()

    # ── Store / capture ───────────────────────────────────────────────────────

    def store(self, req: CapturedRequest) -> str:
        """Persist a captured request. Returns the request id."""
        d = req.to_dict()
        cols = ", ".join(d.keys())
        placeholders = ", ".join("%s" for _ in d)
        self._pg().sync_pg_execute_write(
            f"INSERT INTO captured_requests ({cols}) VALUES ({placeholders})"
            " ON CONFLICT (id) DO NOTHING",
            tuple(d.values()),
        )
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
        rows = self._pg().sync_pg_execute_read(
            "SELECT * FROM captured_requests WHERE id = %s", (request_id,)
        )
        return CapturedRequest.from_row(rows[0]) if rows else None

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
        rows = self._pg().sync_pg_execute_read(
            f"SELECT * FROM captured_requests {where}"
            " ORDER BY timestamp DESC LIMIT %s OFFSET %s",
            tuple(params + [limit, offset]),
        )
        return [CapturedRequest.from_row(r) for r in rows]

    def count(self, **filters) -> int:
        return len(self.list(**filters, limit=10000))

    def flag(self, request_id: str, reason: str) -> None:
        self._pg().sync_pg_execute_write(
            "UPDATE captured_requests SET flagged=TRUE, flag_reason=%s WHERE id=%s",
            (reason, request_id),
        )

    def link_vuln(self, request_id: str, vuln_id: str, attack_type: str = "") -> None:
        self._pg().sync_pg_execute_write(
            "UPDATE captured_requests SET vuln_id=%s, attack_type=%s WHERE id=%s",
            (vuln_id, attack_type, request_id),
        )

    def delete(self, request_id: str) -> None:
        self._pg().sync_pg_execute_write(
            "DELETE FROM captured_requests WHERE id=%s", (request_id,)
        )

    def clear(self, target: Optional[str] = None) -> int:
        if target:
            return self._pg().sync_pg_execute_write(
                "DELETE FROM captured_requests WHERE target_domain LIKE %s",
                (f"%{target}%",),
            )
        return self._pg().sync_pg_execute_write("DELETE FROM captured_requests", ())

    def stats(self) -> Dict:
        pg = self._pg()
        total = (pg.sync_pg_execute_read(
            "SELECT COUNT(*) AS cnt FROM captured_requests", ()
        ) or [{"cnt": 0}])[0]["cnt"]
        flagged = (pg.sync_pg_execute_read(
            "SELECT COUNT(*) AS cnt FROM captured_requests WHERE flagged=TRUE", ()
        ) or [{"cnt": 0}])[0]["cnt"]
        by_source = {
            r["source"]: r["cnt"]
            for r in pg.sync_pg_execute_read(
                "SELECT source, COUNT(*) AS cnt FROM captured_requests GROUP BY source", ()
            )
        }
        by_status = {
            str(r["response_status"]): r["cnt"]
            for r in pg.sync_pg_execute_read(
                "SELECT response_status, COUNT(*) AS cnt FROM captured_requests"
                " GROUP BY response_status ORDER BY cnt DESC LIMIT 10",
                (),
            )
        }
        return {"total": total, "flagged": flagged, "by_source": by_source, "by_status_code": by_status}

    # ── Export ────────────────────────────────────────────────────────────────

    def export_json(self, path: str, **filters) -> str:
        reqs = self.list(**filters, limit=10000)
        Path(path).write_text(json.dumps([r.to_json() for r in reqs], indent=2))
        return path

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
        reqs = self.list(**filters, limit=10000)
        entries = []
        for r in reqs:
            entries.append({
                "startedDateTime": r.timestamp,
                "time": r.duration_ms,
                "request": {
                    "method": r.method,
                    "url": r.url,
                    "headers": [{"name": k, "value": v} for k, v in r.headers.items()],
                    "postData": {"text": r.body} if r.body else None,
                },
                "response": {
                    "status": r.response_status,
                    "headers": [{"name": k, "value": v} for k, v in r.response_headers.items()],
                    "content": {"text": r.response_body[:10000], "size": len(r.response_body)},
                },
                "_source": r.source,
                "_flagged": r.flagged,
            })
        Path(path).write_text(json.dumps({"log": {"version": "1.2", "entries": entries}}, indent=2))
        return path

    # ── Real-time listener registration ──────────────────────────────────────

    def add_listener(self, fn: Callable[[CapturedRequest], None]) -> None:
        self._listeners.append(fn)

    def remove_listener(self, fn: Callable[[CapturedRequest], None]) -> None:
        if fn in self._listeners:
            self._listeners.remove(fn)


# ─────────────────────────────────────────────────────────────────────────────
#  Context manager for timing + automatic capture
# ─────────────────────────────────────────────────────────────────────────────

class RequestCapture:
    """Context manager that captures timing and stores the result."""

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
