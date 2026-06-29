"""
Unified Mobile Traffic Store — SQLite-backed, persistent across restarts.

All capture layers (mitmproxy, Frida SSL hook, eBPF, tcpdump, VPN) write here.
Replaces the in-memory list in mobile_agent_api.store_traffic().

Schema:
  id, device_id, timestamp, source, method, url, status_code,
  request_headers, request_body, response_headers, response_body,
  duration_ms, decrypted, modified, session_id
"""

import asyncio
import json
import os
import time
from typing import Optional

import aiosqlite

DB_PATH = os.path.join(os.path.dirname(__file__), "../../db/mobile_traffic.db")

_db: Optional[aiosqlite.Connection] = None
_init_lock = asyncio.Lock()


async def _get_db() -> aiosqlite.Connection:
    global _db
    if _db is not None:
        return _db
    async with _init_lock:
        if _db is not None:
            return _db
        os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
        _db = await aiosqlite.connect(DB_PATH)
        _db.row_factory = aiosqlite.Row
        await _db.execute("PRAGMA journal_mode=WAL")
        await _db.execute("""
            CREATE TABLE IF NOT EXISTS traffic (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id       TEXT NOT NULL,
                timestamp       REAL NOT NULL,
                source          TEXT NOT NULL DEFAULT 'unknown',
                method          TEXT,
                url             TEXT,
                status_code     INTEGER,
                request_headers TEXT,
                request_body    TEXT,
                response_headers TEXT,
                response_body   TEXT,
                duration_ms     INTEGER,
                decrypted       INTEGER NOT NULL DEFAULT 0,
                modified        INTEGER NOT NULL DEFAULT 0,
                session_id      TEXT,
                correlation_chain TEXT
            )
        """)
        # Migration: add correlation_chain column if it doesn't exist
        try:
            await _db.execute("ALTER TABLE traffic ADD COLUMN correlation_chain TEXT")
            await _db.commit()
        except Exception:
            pass # already exists
        await _db.execute("CREATE INDEX IF NOT EXISTS idx_device_ts ON traffic(device_id, timestamp DESC)")
        await _db.execute("CREATE INDEX IF NOT EXISTS idx_url ON traffic(url)")
        await _db.commit()
    return _db


async def store_traffic(
    device_id: str,
    request: dict,
    response: dict,
    source: str = "unknown",
    duration_ms: int = 0,
    decrypted: bool = False,
    modified: bool = False,
    session_id: str = "",
) -> int:
    """Persist a traffic entry. Returns the row id."""
    db = await _get_db()
    method = request.get("method", "")
    url = request.get("url", "")
    status_code = response.get("status_code") if response else None

    req_headers = request.get("headers", {})
    req_body = request.get("body", "")
    resp_headers = response.get("headers", {}) if response else {}
    resp_body = response.get("body", "") if response else ""
    correlation_chain = request.get("correlation_chain")

    async with db.execute("""
        INSERT INTO traffic
          (device_id, timestamp, source, method, url, status_code,
           request_headers, request_body, response_headers, response_body,
           duration_ms, decrypted, modified, session_id, correlation_chain)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        device_id, time.time(), source, method, url, status_code,
        json.dumps(req_headers), str(req_body),
        json.dumps(resp_headers), str(resp_body)[:65536],
        duration_ms, int(decrypted), int(modified), session_id,
        json.dumps(correlation_chain) if correlation_chain else None
    )) as cur:
        row_id = cur.lastrowid
    await db.commit()
    return row_id


async def get_traffic(
    device_id: str,
    limit: int = 100,
    source: Optional[str] = None,
    decrypted_only: bool = False,
    url_contains: Optional[str] = None,
    method: Optional[str] = None,
    offset: int = 0,
) -> list:
    """Fetch traffic with optional filters."""
    db = await _get_db()

    where = ["device_id = ?"]
    params: list = [device_id]

    if source:
        where.append("source = ?")
        params.append(source)
    if decrypted_only:
        where.append("decrypted = 1")
    if url_contains:
        where.append("url LIKE ?")
        params.append(f"%{url_contains}%")
    if method:
        where.append("method = ?")
        params.append(method.upper())

    sql = f"""
        SELECT id, device_id, timestamp, source, method, url, status_code,
               request_headers, request_body, response_headers, response_body,
               duration_ms, decrypted, modified, session_id, correlation_chain
        FROM traffic
        WHERE {' AND '.join(where)}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    params += [limit, offset]

    async with db.execute(sql, params) as cur:
        rows = await cur.fetchall()

    result = []
    for row in rows:
        try:
            req_headers = json.loads(row["request_headers"] or "{}")
        except Exception:
            req_headers = {}
        try:
            resp_headers = json.loads(row["response_headers"] or "{}")
        except Exception:
            resp_headers = {}
        try:
            correlation_chain = json.loads(row["correlation_chain"] or "null")
        except Exception:
            correlation_chain = None

        result.append({
            "id": row["id"],
            "device_id": row["device_id"],
            "timestamp": row["timestamp"],
            "source": row["source"],
            "decrypted": bool(row["decrypted"]),
            "modified": bool(row["modified"]),
            "session_id": row["session_id"],
            "correlation_chain": correlation_chain,
            "request": {
                "method": row["method"],
                "url": row["url"],
                "headers": req_headers,
                "body": row["request_body"] or "",
            },
            "response": {
                "status_code": row["status_code"],
                "headers": resp_headers,
                "body": row["response_body"] or "",
            },
            "duration_ms": row["duration_ms"],
        })

    return result


async def get_traffic_entry(entry_id: int) -> Optional[dict]:
    """Fetch single entry by id."""
    entries = await get_traffic("", limit=1)  # wrong approach
    db = await _get_db()
    async with db.execute("SELECT * FROM traffic WHERE id = ?", (entry_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        return None
    try:
        req_headers = json.loads(row["request_headers"] or "{}")
    except Exception:
        req_headers = {}
    try:
        resp_headers = json.loads(row["response_headers"] or "{}")
    except Exception:
        resp_headers = {}
    return {
        "id": row["id"],
        "device_id": row["device_id"],
        "timestamp": row["timestamp"],
        "source": row["source"],
        "decrypted": bool(row["decrypted"]),
        "modified": bool(row["modified"]),
        "session_id": row["session_id"],
        "request": {
            "method": row["method"],
            "url": row["url"],
            "headers": req_headers,
            "body": row["request_body"] or "",
        },
        "response": {
            "status_code": row["status_code"],
            "headers": resp_headers,
            "body": row["response_body"] or "",
        },
        "duration_ms": row["duration_ms"],
    }


async def clear_traffic(device_id: str) -> int:
    """Delete all traffic for a device. Returns rows deleted."""
    db = await _get_db()
    async with db.execute("DELETE FROM traffic WHERE device_id = ?", (device_id,)) as cur:
        count = cur.rowcount
    await db.commit()
    return count


async def export_har(device_id: str, limit: int = 500) -> dict:
    """Export traffic as RFC-compliant HAR 1.2."""
    entries = await get_traffic(device_id, limit=limit)
    har_entries = []
    for e in entries:
        req = e["request"]
        resp = e["response"]
        har_entries.append({
            "startedDateTime": _ts_to_iso(e["timestamp"]),
            "time": e.get("duration_ms") or 0,
            "request": {
                "method": req.get("method", "GET"),
                "url": req.get("url", ""),
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in (req.get("headers") or {}).items()],
                "queryString": [],
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(req.get("body") or ""),
                "postData": {"mimeType": "application/json", "text": req.get("body", "")} if req.get("body") else None,
            },
            "response": {
                "status": resp.get("status_code") or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in (resp.get("headers") or {}).items()],
                "cookies": [],
                "content": {
                    "size": len(resp.get("body") or ""),
                    "mimeType": (resp.get("headers") or {}).get("content-type", "text/plain"),
                    "text": resp.get("body", ""),
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(resp.get("body") or ""),
            },
            "cache": {},
            "timings": {"send": 0, "wait": e.get("duration_ms") or 0, "receive": 0},
            "_source": e.get("source", "unknown"),
            "_decrypted": e.get("decrypted", False),
        })

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "OneInfinity", "version": "1.0"},
            "entries": har_entries,
        }
    }


def _ts_to_iso(ts: float) -> str:
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
