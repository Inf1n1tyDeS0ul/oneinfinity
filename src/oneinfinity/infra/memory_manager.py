"""
memory_manager.py — Persistent Evolution Memory Manager

Stores scan results, successful attack patterns, exploit chains, and learning
insights in PostgreSQL (hard requirement).
"""

from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AttackPattern:
    id: str = ""
    vuln_type: str = ""
    target_tech: str = ""
    payload: str = ""
    endpoint_pattern: str = ""
    cvss: float = 0.0
    success_rate: float = 0.0
    occurrences: int = 1
    last_seen: float = field(default_factory=time.time)
    agent_source: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["meta"] = self.meta
        return d


@dataclass
class ExploitChainRecord:
    id: str = ""
    chain_name: str = ""
    steps: list[str] = field(default_factory=list)
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
    category: str = ""
    title: str = ""
    body: str = ""
    confidence: float = 0.5
    source_event: str = ""
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


# ── Manager ───────────────────────────────────────────────────────────────────

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


class MemoryManager:
    """Persistent store for the self-evolving architecture system. PostgreSQL is a hard requirement."""

    # ── Attack Patterns ───────────────────────────────────────────────────────

    def upsert_attack_pattern(self, pattern: AttackPattern) -> str:
        key_hash = _hash(pattern.vuln_type, pattern.target_tech, pattern.payload[:120])
        pg = _require_pg()
        rows = pg.sync_pg_execute_read(
            "SELECT id, occurrences, success_rate FROM attack_patterns WHERE id=%s",
            (key_hash,)
        )
        if rows:
            new_sr = 0.7 * rows[0]["success_rate"] + 0.3 * pattern.success_rate
            pg.sync_pg_execute_write(
                "UPDATE attack_patterns SET occurrences=occurrences+1, success_rate=%s, "
                "last_seen=%s, agent_source=%s WHERE id=%s",
                (new_sr, time.time(), pattern.agent_source, key_hash)
            )
        else:
            pg.sync_pg_execute_write(
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

    def get_patterns(self, vuln_type: str = "", limit: int = 50) -> list[dict]:
        pg = _require_pg()
        if vuln_type:
            return pg.sync_pg_execute_read(
                "SELECT * FROM attack_patterns WHERE vuln_type=%s "
                "ORDER BY success_rate DESC, occurrences DESC LIMIT %s",
                (vuln_type, limit)
            )
        return pg.sync_pg_execute_read(
            "SELECT * FROM attack_patterns ORDER BY last_seen DESC LIMIT %s", (limit,)
        )

    def top_patterns(self, limit: int = 10) -> list[dict]:
        return _require_pg().sync_pg_execute_read(
            "SELECT * FROM attack_patterns ORDER BY success_rate DESC, occurrences DESC LIMIT %s",
            (limit,)
        )

    # ── Exploit Chains ────────────────────────────────────────────────────────

    def store_exploit_chain(self, chain: ExploitChainRecord) -> str:
        cid = chain.id or _hash(chain.chain_name, chain.target, json.dumps(chain.steps))
        _require_pg().sync_pg_execute_write(
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

    def get_chains(self, confirmed_only: bool = False, limit: int = 50) -> list[dict]:
        if confirmed_only:
            rows = _require_pg().sync_pg_execute_read(
                "SELECT * FROM exploit_chain_records WHERE confirmed=1 "
                "ORDER BY discovered_at DESC LIMIT %s", (limit,)
            )
        else:
            rows = _require_pg().sync_pg_execute_read(
                "SELECT * FROM exploit_chain_records ORDER BY discovered_at DESC LIMIT %s",
                (limit,)
            )
        for d in rows:
            if isinstance(d.get("steps"), str):
                d["steps"] = json.loads(d["steps"] or "[]")
        return rows

    # ── Learning Insights ─────────────────────────────────────────────────────

    def store_insight(self, insight: LearningInsight) -> str:
        import uuid as _uuid
        iid = insight.id or str(_uuid.uuid4())
        _require_pg().sync_pg_execute_write(
            "INSERT INTO learning_insights(id, category, title, body, confidence, "
            "source_event, tags, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (id) DO NOTHING",
            (iid, insight.category, insight.title, insight.body, insight.confidence,
             insight.source_event, json.dumps(insight.tags), insight.created_at)
        )
        return iid

    def get_insights(self, category: str = "", limit: int = 50) -> list[dict]:
        if category:
            rows = _require_pg().sync_pg_execute_read(
                "SELECT * FROM learning_insights WHERE category=%s "
                "ORDER BY created_at DESC LIMIT %s", (category, limit)
            )
        else:
            rows = _require_pg().sync_pg_execute_read(
                "SELECT * FROM learning_insights ORDER BY created_at DESC LIMIT %s", (limit,)
            )
        for d in rows:
            if isinstance(d.get("tags"), str):
                d["tags"] = json.loads(d["tags"] or "[]")
        return rows

    def recent_insights(self, hours: int = 24, limit: int = 20) -> list[dict]:
        since = time.time() - hours * 3600
        rows = _require_pg().sync_pg_execute_read(
            "SELECT * FROM learning_insights WHERE created_at >= %s "
            "ORDER BY created_at DESC LIMIT %s", (since, limit)
        )
        for d in rows:
            if isinstance(d.get("tags"), str):
                d["tags"] = json.loads(d["tags"] or "[]")
        return rows

    # ── Scan Summaries ────────────────────────────────────────────────────────

    def store_scan_summary(self, summary: ScanResultSummary):
        _require_pg().sync_pg_execute_write(
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

    def get_scan_summaries(self, limit: int = 20) -> list[dict]:
        rows = _require_pg().sync_pg_execute_read(
            "SELECT * FROM scan_summaries ORDER BY finished_at DESC LIMIT %s", (limit,)
        )
        for d in rows:
            if isinstance(d.get("phases"), str):
                d["phases"] = json.loads(d["phases"] or "[]")
            if isinstance(d.get("tools_used"), str):
                d["tools_used"] = json.loads(d["tools_used"] or "[]")
        return rows

    # ── Capability Snapshots ──────────────────────────────────────────────────

    def snapshot_capabilities(self, capabilities: list[str], trigger_event: str = "") -> int:
        pg = _require_pg()
        prev_rows = pg.sync_pg_execute_read(
            "SELECT total_count FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT 1", ()
        )
        prev_count = prev_rows[0]["total_count"] if prev_rows else 0
        delta = len(capabilities) - prev_count
        pg.sync_pg_execute_write(
            "INSERT INTO capability_snapshots(snapshot_at, capabilities, total_count, "
            "delta_from_prev, trigger_event) VALUES (%s,%s,%s,%s,%s)",
            (time.time(), json.dumps(sorted(capabilities)), len(capabilities), delta, trigger_event)
        )
        rows = pg.sync_pg_execute_read(
            "SELECT id FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT 1", ()
        )
        return rows[0]["id"] if rows else 0

    def latest_capability_snapshot(self) -> dict | None:
        rows = _require_pg().sync_pg_execute_read(
            "SELECT * FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT 1", ()
        )
        if not rows:
            return None
        d = rows[0]
        if isinstance(d.get("capabilities"), str):
            d["capabilities"] = json.loads(d["capabilities"] or "[]")
        return d

    def capability_history(self, limit: int = 30) -> list[dict]:
        return _require_pg().sync_pg_execute_read(
            "SELECT snapshot_at, total_count, delta_from_prev, trigger_event "
            "FROM capability_snapshots ORDER BY snapshot_at DESC LIMIT %s",
            (limit,)
        )

    # ── Architecture Changelog ────────────────────────────────────────────────

    def log_architecture_change(self, change_type: str, summary: str,
                                 section: str = "", trigger_event: str = "",
                                 meta: dict | None = None):
        _require_pg().sync_pg_execute_write(
            "INSERT INTO architecture_changelog(changed_at, change_type, section, "
            "summary, trigger_event, meta) VALUES (%s,%s,%s,%s,%s,%s)",
            (time.time(), change_type, section, summary, trigger_event, json.dumps(meta or {}))
        )

    def get_architecture_changelog(self, limit: int = 50) -> list[dict]:
        rows = _require_pg().sync_pg_execute_read(
            "SELECT * FROM architecture_changelog ORDER BY changed_at DESC LIMIT %s", (limit,)
        )
        for d in rows:
            if isinstance(d.get("meta"), str):
                d["meta"] = json.loads(d["meta"] or "{}")
        return rows

    # ── Aggregate stats ───────────────────────────────────────────────────────

    def stats(self) -> dict:
        pg = _require_pg()

        def _count(table: str, where: str = "") -> int:
            q = f"SELECT COUNT(*) AS c FROM {table}"
            if where:
                q += f" WHERE {where}"
            rows = pg.sync_pg_execute_read(q, ())
            return rows[0]["c"] if rows else 0

        return {
            "attack_patterns":      _count("attack_patterns"),
            "exploit_chains":       _count("exploit_chain_records"),
            "confirmed_chains":     _count("exploit_chain_records", "confirmed=1"),
            "learning_insights":    _count("learning_insights"),
            "scan_summaries":       _count("scan_summaries"),
            "capability_snapshots": _count("capability_snapshots"),
            "arch_changes":         _count("architecture_changelog"),
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash(*parts: str) -> str:
    import hashlib
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]


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
