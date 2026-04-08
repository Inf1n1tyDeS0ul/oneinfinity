"""
memory_manager.py — Persistent Evolution Memory Manager

Stores scan results, successful attack patterns, exploit chains, and learning
insights in a dedicated SQLite database.  Wraps KnowledgeBase for domain
knowledge and adds evolution-specific tables for architecture snapshots,
capability history, and platform insight records.
"""

from __future__ import annotations

import json
import sqlite3
import time
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

from path_manager import db_path as db_path_fn


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AttackPattern:
    id: str = ""
    vuln_type: str = ""
    target_tech: str = ""           # e.g. "wordpress,mysql"
    payload: str = ""
    endpoint_pattern: str = ""      # regex pattern of vulnerable endpoint
    cvss: float = 0.0
    success_rate: float = 0.0       # 0–1
    occurrences: int = 1
    last_seen: float = field(default_factory=time.time)
    agent_source: str = ""          # which agent discovered it
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["meta"] = self.meta
        return d


@dataclass
class ExploitChainRecord:
    id: str = ""
    chain_name: str = ""
    steps: list[str] = field(default_factory=list)   # ordered vuln_type list
    target: str = ""
    cvss_combined: float = 0.0
    confirmed: bool = False
    session_id: str = ""
    discovered_at: float = field(default_factory=time.time)
    description: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["steps"] = self.steps
        return d


@dataclass
class LearningInsight:
    id: str = ""
    category: str = ""          # "tool_perf" | "pattern" | "evasion" | "chain" | "target"
    title: str = ""
    body: str = ""
    confidence: float = 0.5
    source_event: str = ""      # event type that generated this insight
    tags: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["tags"] = self.tags
        return d


@dataclass
class ScanResultSummary:
    session_id: str
    target: str
    started_at: float
    finished_at: float
    phases: list[str]
    total_findings: int
    confirmed_findings: int
    critical_count: int
    high_count: int
    tools_used: list[str]
    new_patterns: int = 0
    new_chains: int = 0
    insights_generated: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attack_patterns (
    id               TEXT PRIMARY KEY,
    vuln_type        TEXT NOT NULL,
    target_tech      TEXT DEFAULT '',
    payload          TEXT DEFAULT '',
    endpoint_pattern TEXT DEFAULT '',
    cvss             REAL DEFAULT 0,
    success_rate     REAL DEFAULT 0,
    occurrences      INTEGER DEFAULT 1,
    last_seen        REAL NOT NULL,
    agent_source     TEXT DEFAULT '',
    meta             TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS exploit_chains (
    id               TEXT PRIMARY KEY,
    chain_name       TEXT NOT NULL,
    steps            TEXT NOT NULL,    -- JSON list
    target           TEXT DEFAULT '',
    cvss_combined    REAL DEFAULT 0,
    confirmed        INTEGER DEFAULT 0,
    session_id       TEXT DEFAULT '',
    discovered_at    REAL NOT NULL,
    description      TEXT DEFAULT '',
    remediation      TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS learning_insights (
    id               TEXT PRIMARY KEY,
    category         TEXT NOT NULL,
    title            TEXT NOT NULL,
    body             TEXT DEFAULT '',
    confidence       REAL DEFAULT 0.5,
    source_event     TEXT DEFAULT '',
    tags             TEXT DEFAULT '[]',
    created_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_summaries (
    session_id       TEXT PRIMARY KEY,
    target           TEXT NOT NULL,
    started_at       REAL NOT NULL,
    finished_at      REAL NOT NULL,
    phases           TEXT DEFAULT '[]',
    total_findings   INTEGER DEFAULT 0,
    confirmed_findings INTEGER DEFAULT 0,
    critical_count   INTEGER DEFAULT 0,
    high_count       INTEGER DEFAULT 0,
    tools_used       TEXT DEFAULT '[]',
    new_patterns     INTEGER DEFAULT 0,
    new_chains       INTEGER DEFAULT 0,
    insights_generated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS capability_snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_at      REAL NOT NULL,
    capabilities     TEXT NOT NULL,    -- JSON list of capability names
    total_count      INTEGER DEFAULT 0,
    delta_from_prev  INTEGER DEFAULT 0,
    trigger_event    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS architecture_changelog (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    changed_at       REAL NOT NULL,
    change_type      TEXT NOT NULL,    -- "section_added" | "component_added" | "diagram_updated" | "metric_updated"
    section          TEXT DEFAULT '',
    summary          TEXT NOT NULL,
    trigger_event    TEXT DEFAULT '',
    meta             TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_patterns_vuln  ON attack_patterns(vuln_type);
CREATE INDEX IF NOT EXISTS idx_patterns_tech  ON attack_patterns(target_tech);
CREATE INDEX IF NOT EXISTS idx_chains_name    ON exploit_chains(chain_name);
CREATE INDEX IF NOT EXISTS idx_insights_cat   ON learning_insights(category);
CREATE INDEX IF NOT EXISTS idx_insights_ts    ON learning_insights(created_at);
"""


# ── Manager ───────────────────────────────────────────────────────────────────

class MemoryManager:
    """
    Central persistent store for the self-evolving architecture system.

    Two persistence layers:
    - evolution.db        — this class (attack patterns, chains, insights, snapshots)
    - knowledge_base.db   — KnowledgeBase (scan sessions, tool performance, targets)

    Thread-safe (uses a threading.Lock for write serialization).
    """

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = db_path_fn("evolution.db")
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # If PostgreSQL is available, skip SQLite connection entirely.
        if self._pg() is not None:
            self._conn = None
            return
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _pg(self):
        """Return DBManager if running in postgres/distributed mode, else None."""
        try:
            from core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            return mgr if mgr and mgr.mode in ("distributed", "postgres") else None
        except Exception:
            return None

    @contextmanager
    def _tx(self):
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ── Attack Patterns ───────────────────────────────────────────────────────

    def upsert_attack_pattern(self, pattern: AttackPattern) -> str:
        """
        Insert or merge an attack pattern.  If a pattern with the same
        (vuln_type, target_tech, payload) exists, increments occurrences and
        updates success_rate with EMA (α=0.3).
        """
        key_hash = _hash(pattern.vuln_type, pattern.target_tech, pattern.payload[:120])
        mgr = self._pg()
        if mgr is not None:
            rows = mgr.sync_pg_execute_read(
                "SELECT id, occurrences, success_rate FROM attack_patterns WHERE id=%s",
                (key_hash,)
            )
            if rows:
                new_sr = 0.7 * rows[0]["success_rate"] + 0.3 * pattern.success_rate
                mgr.sync_pg_execute_write(
                    "UPDATE attack_patterns SET occurrences=occurrences+1, success_rate=%s, "
                    "last_seen=%s, agent_source=%s WHERE id=%s",
                    (new_sr, time.time(), pattern.agent_source, key_hash)
                )
            else:
                mgr.sync_pg_execute_write(
                    "INSERT INTO attack_patterns(id, vuln_type, target_tech, payload, "
                    "endpoint_pattern, cvss, success_rate, occurrences, last_seen, "
                    "agent_source, meta) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT (id) DO NOTHING",
                    (key_hash, pattern.vuln_type, pattern.target_tech, pattern.payload,
                     pattern.endpoint_pattern, pattern.cvss, pattern.success_rate,
                     pattern.occurrences, time.time(), pattern.agent_source,
                     json.dumps(pattern.meta))
                )
            return key_hash
        with self._tx() as conn:
            row = conn.execute(
                "SELECT id, occurrences, success_rate FROM attack_patterns WHERE id=?",
                (key_hash,)
            ).fetchone()
            if row:
                new_sr = 0.7 * row["success_rate"] + 0.3 * pattern.success_rate
                conn.execute(
                    "UPDATE attack_patterns SET occurrences=occurrences+1, success_rate=?, "
                    "last_seen=?, agent_source=? WHERE id=?",
                    (new_sr, time.time(), pattern.agent_source, key_hash)
                )
                return key_hash
            else:
                pid = key_hash
                conn.execute(
                    "INSERT INTO attack_patterns(id, vuln_type, target_tech, payload, "
                    "endpoint_pattern, cvss, success_rate, occurrences, last_seen, "
                    "agent_source, meta) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (pid, pattern.vuln_type, pattern.target_tech, pattern.payload,
                     pattern.endpoint_pattern, pattern.cvss, pattern.success_rate,
                     pattern.occurrences, time.time(), pattern.agent_source,
                     json.dumps(pattern.meta))
                )
                return pid

    def get_patterns(self, vuln_type: str = "", limit: int = 50) -> list[dict]:
        mgr = self._pg()
        if mgr is not None:
            if vuln_type:
                return mgr.sync_pg_execute_read(
                    "SELECT * FROM attack_patterns WHERE vuln_type=%s "
                    "ORDER BY success_rate DESC, occurrences DESC LIMIT %s",
                    (vuln_type, limit)
                )
            return mgr.sync_pg_execute_read(
                "SELECT * FROM attack_patterns ORDER BY last_seen DESC LIMIT %s",
                (limit,)
            )
        if vuln_type:
            rows = self._conn.execute(
                "SELECT * FROM attack_patterns WHERE vuln_type=? "
                "ORDER BY success_rate DESC, occurrences DESC LIMIT ?",
                (vuln_type, limit)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM attack_patterns ORDER BY last_seen DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def top_patterns(self, limit: int = 10) -> list[dict]:
        mgr = self._pg()
        if mgr is not None:
            return mgr.sync_pg_execute_read(
                "SELECT * FROM attack_patterns ORDER BY success_rate DESC, occurrences DESC LIMIT %s",
                (limit,)
            )
        rows = self._conn.execute(
            "SELECT * FROM attack_patterns ORDER BY success_rate DESC, occurrences DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    # ── Exploit Chains ────────────────────────────────────────────────────────

    def store_exploit_chain(self, chain: ExploitChainRecord) -> str:
        cid = chain.id or _hash(chain.chain_name, chain.target, json.dumps(chain.steps))
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write(
                "INSERT INTO exploit_chain_records("
                "id, chain_name, steps, target, cvss_combined, confirmed, "
                "session_id, discovered_at, description, remediation"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (id) DO UPDATE SET "
                "chain_name=EXCLUDED.chain_name, steps=EXCLUDED.steps, "
                "target=EXCLUDED.target, cvss_combined=EXCLUDED.cvss_combined, "
                "confirmed=EXCLUDED.confirmed, session_id=EXCLUDED.session_id, "
                "description=EXCLUDED.description, remediation=EXCLUDED.remediation",
                (cid, chain.chain_name, json.dumps(chain.steps), chain.target,
                 chain.cvss_combined, 1 if chain.confirmed else 0,
                 chain.session_id, chain.discovered_at, chain.description,
                 chain.remediation)
            )
            return cid
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO exploit_chains("
                "id, chain_name, steps, target, cvss_combined, confirmed, "
                "session_id, discovered_at, description, remediation"
                ") VALUES (?,?,?,?,?,?,?,?,?,?)",
                (cid, chain.chain_name, json.dumps(chain.steps), chain.target,
                 chain.cvss_combined, 1 if chain.confirmed else 0,
                 chain.session_id, chain.discovered_at, chain.description,
                 chain.remediation)
            )
        return cid

    def get_chains(self, confirmed_only: bool = False, limit: int = 50) -> list[dict]:
        mgr = self._pg()
        if mgr is not None:
            if confirmed_only:
                rows = mgr.sync_pg_execute_read(
                    "SELECT * FROM exploit_chain_records WHERE confirmed=1 "
                    "ORDER BY discovered_at DESC LIMIT %s",
                    (limit,)
                )
            else:
                rows = mgr.sync_pg_execute_read(
                    "SELECT * FROM exploit_chain_records ORDER BY discovered_at DESC LIMIT %s",
                    (limit,)
                )
            for d in rows:
                if isinstance(d.get("steps"), str):
                    d["steps"] = json.loads(d["steps"] or "[]")
            return rows
        q = "SELECT * FROM exploit_chains"
        params: list = []
        if confirmed_only:
            q += " WHERE confirmed=1"
        q += " ORDER BY discovered_at DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(q, params).fetchall()
        results = []
        for r in rows:
            d = _row_to_dict(r)
            d["steps"] = json.loads(d.get("steps") or "[]")
            results.append(d)
        return results

    # ── Learning Insights ─────────────────────────────────────────────────────

    def store_insight(self, insight: LearningInsight) -> str:
        import uuid as _uuid
        iid = insight.id or str(_uuid.uuid4())
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write(
                "INSERT INTO learning_insights(id, category, title, body, confidence, "
                "source_event, tags, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (id) DO NOTHING",
                (iid, insight.category, insight.title, insight.body, insight.confidence,
                 insight.source_event, json.dumps(insight.tags), insight.created_at)
            )
            return iid
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO learning_insights(id, category, title, body, confidence, "
                "source_event, tags, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (iid, insight.category, insight.title, insight.body, insight.confidence,
                 insight.source_event, json.dumps(insight.tags), insight.created_at)
            )
        return iid

    def get_insights(self, category: str = "", limit: int = 50) -> list[dict]:
        mgr = self._pg()
        if mgr is not None:
            if category:
                rows = mgr.sync_pg_execute_read(
                    "SELECT * FROM learning_insights WHERE category=%s "
                    "ORDER BY created_at DESC LIMIT %s", (category, limit)
                )
            else:
                rows = mgr.sync_pg_execute_read(
                    "SELECT * FROM learning_insights ORDER BY created_at DESC LIMIT %s",
                    (limit,)
                )
            for d in rows:
                if isinstance(d.get("tags"), str):
                    d["tags"] = json.loads(d["tags"] or "[]")
            return rows
        if category:
            rows = self._conn.execute(
                "SELECT * FROM learning_insights WHERE category=? "
                "ORDER BY created_at DESC LIMIT ?", (category, limit)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM learning_insights ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        results = []
        for r in rows:
            d = _row_to_dict(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            results.append(d)
        return results

    def recent_insights(self, hours: int = 24, limit: int = 20) -> list[dict]:
        since = time.time() - hours * 3600
        mgr = self._pg()
        if mgr is not None:
            rows = mgr.sync_pg_execute_read(
                "SELECT * FROM learning_insights WHERE created_at >= %s "
                "ORDER BY created_at DESC LIMIT %s", (since, limit)
            )
            for d in rows:
                if isinstance(d.get("tags"), str):
                    d["tags"] = json.loads(d["tags"] or "[]")
            return rows
        rows = self._conn.execute(
            "SELECT * FROM learning_insights WHERE created_at >= ? "
            "ORDER BY created_at DESC LIMIT ?", (since, limit)
        ).fetchall()
        results = []
        for r in rows:
            d = _row_to_dict(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            results.append(d)
        return results

    # ── Scan Summaries ────────────────────────────────────────────────────────

    def store_scan_summary(self, summary: ScanResultSummary):
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write(
                "INSERT INTO scan_summaries("
                "session_id, target, started_at, finished_at, phases, "
                "total_findings, confirmed_findings, critical_count, high_count, "
                "tools_used, new_patterns, new_chains, insights_generated"
                ") VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (session_id) DO UPDATE SET "
                "finished_at=EXCLUDED.finished_at, total_findings=EXCLUDED.total_findings, "
                "confirmed_findings=EXCLUDED.confirmed_findings, "
                "critical_count=EXCLUDED.critical_count, high_count=EXCLUDED.high_count, "
                "tools_used=EXCLUDED.tools_used, new_patterns=EXCLUDED.new_patterns, "
                "new_chains=EXCLUDED.new_chains, insights_generated=EXCLUDED.insights_generated",
                (summary.session_id, summary.target, summary.started_at,
                 summary.finished_at, json.dumps(summary.phases),
                 summary.total_findings, summary.confirmed_findings,
                 summary.critical_count, summary.high_count,
                 json.dumps(summary.tools_used), summary.new_patterns,
                 summary.new_chains, summary.insights_generated)
            )
            return
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_summaries("
                "session_id, target, started_at, finished_at, phases, "
                "total_findings, confirmed_findings, critical_count, high_count, "
                "tools_used, new_patterns, new_chains, insights_generated"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (summary.session_id, summary.target, summary.started_at,
                 summary.finished_at, json.dumps(summary.phases),
                 summary.total_findings, summary.confirmed_findings,
                 summary.critical_count, summary.high_count,
                 json.dumps(summary.tools_used), summary.new_patterns,
                 summary.new_chains, summary.insights_generated)
            )

    def get_scan_summaries(self, limit: int = 20) -> list[dict]:
        mgr = self._pg()
        if mgr is not None:
            rows = mgr.sync_pg_execute_read(
                "SELECT * FROM scan_summaries ORDER BY finished_at DESC LIMIT %s",
                (limit,)
            )
            for d in rows:
                if isinstance(d.get("phases"), str):
                    d["phases"] = json.loads(d["phases"] or "[]")
                if isinstance(d.get("tools_used"), str):
                    d["tools_used"] = json.loads(d["tools_used"] or "[]")
            return rows
        rows = self._conn.execute(
            "SELECT * FROM scan_summaries ORDER BY finished_at DESC LIMIT ?", (limit,)
        ).fetchall()
        results = []
        for r in rows:
            d = _row_to_dict(r)
            d["phases"] = json.loads(d.get("phases") or "[]")
            d["tools_used"] = json.loads(d.get("tools_used") or "[]")
            results.append(d)
        return results

    # ── Capability Snapshots ──────────────────────────────────────────────────

    def snapshot_capabilities(self, capabilities: list[str], trigger_event: str = "") -> int:
        mgr = self._pg()
        if mgr is not None:
            prev_rows = mgr.sync_pg_execute_read(
                "SELECT total_count FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT 1",
                ()
            )
            prev_count = prev_rows[0]["total_count"] if prev_rows else 0
            delta = len(capabilities) - prev_count
            mgr.sync_pg_execute_write(
                "INSERT INTO capability_snapshots(snapshot_at, capabilities, total_count, "
                "delta_from_prev, trigger_event) VALUES (%s,%s,%s,%s,%s)",
                (time.time(), json.dumps(sorted(capabilities)),
                 len(capabilities), delta, trigger_event)
            )
            # Return approximate id (not available from sync helper, return 0 as placeholder)
            rows = mgr.sync_pg_execute_read(
                "SELECT id FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT 1", ()
            )
            return rows[0]["id"] if rows else 0
        prev = self._conn.execute(
            "SELECT total_count FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT 1"
        ).fetchone()
        prev_count = prev["total_count"] if prev else 0
        delta = len(capabilities) - prev_count
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO capability_snapshots(snapshot_at, capabilities, total_count, "
                "delta_from_prev, trigger_event) VALUES (?,?,?,?,?)",
                (time.time(), json.dumps(sorted(capabilities)),
                 len(capabilities), delta, trigger_event)
            )
        return cur.lastrowid

    def latest_capability_snapshot(self) -> dict | None:
        mgr = self._pg()
        if mgr is not None:
            rows = mgr.sync_pg_execute_read(
                "SELECT * FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT 1", ()
            )
            if not rows:
                return None
            d = rows[0]
            if isinstance(d.get("capabilities"), str):
                d["capabilities"] = json.loads(d["capabilities"] or "[]")
            return d
        row = self._conn.execute(
            "SELECT * FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        d = _row_to_dict(row)
        d["capabilities"] = json.loads(d.get("capabilities") or "[]")
        return d

    def capability_history(self, limit: int = 30) -> list[dict]:
        mgr = self._pg()
        if mgr is not None:
            return mgr.sync_pg_execute_read(
                "SELECT snapshot_at, total_count, delta_from_prev, trigger_event "
                "FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT %s",
                (limit,)
            )
        rows = self._conn.execute(
            "SELECT snapshot_at, total_count, delta_from_prev, trigger_event "
            "FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_dict(r) for r in rows]

    # ── Architecture Changelog ────────────────────────────────────────────────

    def log_architecture_change(self, change_type: str, summary: str,
                                 section: str = "", trigger_event: str = "",
                                 meta: dict | None = None):
        mgr = self._pg()
        if mgr is not None:
            mgr.sync_pg_execute_write(
                "INSERT INTO architecture_changelog(changed_at, change_type, section, "
                "summary, trigger_event, meta) VALUES (%s,%s,%s,%s,%s,%s)",
                (time.time(), change_type, section, summary,
                 trigger_event, json.dumps(meta or {}))
            )
            return
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO architecture_changelog(changed_at, change_type, section, "
                "summary, trigger_event, meta) VALUES (?,?,?,?,?,?)",
                (time.time(), change_type, section, summary,
                 trigger_event, json.dumps(meta or {}))
            )

    def get_architecture_changelog(self, limit: int = 50) -> list[dict]:
        mgr = self._pg()
        if mgr is not None:
            rows = mgr.sync_pg_execute_read(
                "SELECT * FROM architecture_changelog ORDER BY changed_at DESC LIMIT %s",
                (limit,)
            )
            for d in rows:
                if isinstance(d.get("meta"), str):
                    d["meta"] = json.loads(d["meta"] or "{}")
            return rows
        rows = self._conn.execute(
            "SELECT * FROM architecture_changelog ORDER BY changed_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        results = []
        for r in rows:
            d = _row_to_dict(r)
            d["meta"] = json.loads(d.get("meta") or "{}")
            results.append(d)
        return results

    # ── Aggregate stats ───────────────────────────────────────────────────────

    def stats(self) -> dict:
        def _count(table: str, where: str = "") -> int:
            q = f"SELECT COUNT(*) as c FROM {table}"
            if where:
                q += f" WHERE {where}"
            row = self._conn.execute(q).fetchone()
            return row["c"] if row else 0

        return {
            "attack_patterns":      _count("attack_patterns"),
            "exploit_chains":       _count("exploit_chains"),
            "confirmed_chains":     _count("exploit_chains", "confirmed=1"),
            "learning_insights":    _count("learning_insights"),
            "scan_summaries":       _count("scan_summaries"),
            "capability_snapshots": _count("capability_snapshots"),
            "arch_changes":         _count("architecture_changelog"),
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash(*parts: str) -> str:
    import hashlib
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]


def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(zip(row.keys(), tuple(row)))


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: MemoryManager | None = None
_instance_lock = threading.Lock()


def get_memory_manager() -> MemoryManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = MemoryManager()
    return _instance
