"""
Knowledge Base — persistent SQLite store for scan history, tool performance,
target profiles, and vulnerability patterns.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from path_manager import db_path as db_path_fn

class KnowledgeBase:
    """
    SQLite-backed knowledge base for the continuous learning system.

    Tables
    ------
    scan_sessions   — one row per completed scan
    findings_history — one row per confirmed finding across all scans
    tool_performance — aggregated success/failure stats per tool per vuln_type
    target_profiles  — cached tech stack, scope, historical summary per domain
    pattern_library  — mined patterns: (tech_stack, vuln_type) correlations
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS scan_sessions (
        session_id      TEXT PRIMARY KEY,
        target          TEXT NOT NULL,
        started_at      REAL NOT NULL,
        finished_at     REAL,
        phases          TEXT,          -- JSON list of phases run
        total_findings  INTEGER DEFAULT 0,
        tools_used      TEXT,          -- JSON list
        notes           TEXT
    );

    CREATE TABLE IF NOT EXISTS findings_history (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id      TEXT REFERENCES scan_sessions(session_id),
        target          TEXT NOT NULL,
        vuln_type       TEXT NOT NULL,
        severity        TEXT NOT NULL,
        cvss_score      REAL,
        endpoint        TEXT,
        parameter       TEXT,
        source_tool     TEXT,
        confirmed       INTEGER DEFAULT 1,  -- 0=FP, 1=confirmed
        chain_id        TEXT,               -- if part of a chain
        discovered_at   REAL NOT NULL DEFAULT (strftime('%s','now'))
    );

    CREATE TABLE IF NOT EXISTS tool_performance (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_name       TEXT NOT NULL,
        vuln_type       TEXT,
        target_type     TEXT,           -- e.g. "api", "web", "cloud"
        runs_total      INTEGER DEFAULT 0,
        runs_success    INTEGER DEFAULT 0,
        findings_total  INTEGER DEFAULT 0,
        avg_duration_s  REAL DEFAULT 0,
        last_updated    REAL
    );

    CREATE TABLE IF NOT EXISTS target_profiles (
        domain          TEXT PRIMARY KEY,
        tech_stack      TEXT,           -- JSON list of detected technologies
        waf_detected    TEXT,
        scope_notes     TEXT,
        historical_vulns TEXT,          -- JSON summary
        last_scanned    REAL,
        scan_count      INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS pattern_library (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        tech_stack_key  TEXT NOT NULL,  -- e.g. "wordpress,mysql"
        vuln_type       TEXT NOT NULL,
        occurrence_count INTEGER DEFAULT 1,
        avg_cvss        REAL,
        best_tool       TEXT,
        last_seen       REAL,
        UNIQUE(tech_stack_key, vuln_type)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_target  ON findings_history(target);
    CREATE INDEX IF NOT EXISTS idx_findings_vuln    ON findings_history(vuln_type);
    CREATE INDEX IF NOT EXISTS idx_tool_perf_name   ON tool_performance(tool_name);
    """

    def __init__(self, db_path: str | Path = str(db_path_fn("knowledge_base.db"))):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(self.SCHEMA)
        self._conn.commit()

    @contextmanager
    def _tx(self):
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ── Session management ────────────────────────────────────────────────────

    def start_session(self, session_id: str, target: str,
                      phases: list[str] | None = None) -> str:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scan_sessions(session_id, target, started_at, phases) "
                "VALUES (?, ?, ?, ?)",
                (session_id, target, time.time(), json.dumps(phases or []))
            )
        return session_id

    def finish_session(self, session_id: str, total_findings: int,
                       tools_used: list[str] | None = None, notes: str = ""):
        with self._tx() as conn:
            conn.execute(
                "UPDATE scan_sessions SET finished_at=?, total_findings=?, tools_used=?, notes=? "
                "WHERE session_id=?",
                (time.time(), total_findings, json.dumps(tools_used or []), notes, session_id)
            )

    # ── Findings recording ────────────────────────────────────────────────────

    def record_finding(self, session_id: str, finding: dict, confirmed: bool = True):
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO findings_history("
                "session_id, target, vuln_type, severity, cvss_score, "
                "endpoint, parameter, source_tool, confirmed, chain_id, discovered_at"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    session_id,
                    finding.get("target", ""),
                    finding.get("vuln_type", "unknown"),
                    finding.get("severity", "info"),
                    finding.get("cvss_score"),
                    finding.get("matched_at", finding.get("url", finding.get("endpoint", ""))),
                    finding.get("parameter", ""),
                    finding.get("source_tool", ""),
                    1 if confirmed else 0,
                    finding.get("chain_id", ""),
                    time.time(),
                )
            )

    def record_findings_bulk(self, session_id: str, findings: list[dict],
                             confirmed: bool = True):
        for f in findings:
            try:
                self.record_finding(session_id, f, confirmed)
            except Exception:
                pass

    # ── Tool performance ──────────────────────────────────────────────────────

    def record_tool_run(self, tool_name: str, vuln_type: str = "",
                        target_type: str = "", success: bool = True,
                        findings_count: int = 0, duration_s: float = 0.0):
        with self._tx() as conn:
            existing = conn.execute(
                "SELECT * FROM tool_performance WHERE tool_name=? AND vuln_type=? AND target_type=?",
                (tool_name, vuln_type, target_type)
            ).fetchone()

            if existing:
                old_n = existing["runs_total"]
                old_avg = existing["avg_duration_s"]
                new_avg = (old_avg * old_n + duration_s) / (old_n + 1)
                conn.execute(
                    "UPDATE tool_performance SET runs_total=runs_total+1, "
                    "runs_success=runs_success+?, findings_total=findings_total+?, "
                    "avg_duration_s=?, last_updated=? "
                    "WHERE tool_name=? AND vuln_type=? AND target_type=?",
                    (1 if success else 0, findings_count, new_avg,
                     time.time(), tool_name, vuln_type, target_type)
                )
            else:
                conn.execute(
                    "INSERT INTO tool_performance("
                    "tool_name, vuln_type, target_type, runs_total, runs_success, "
                    "findings_total, avg_duration_s, last_updated"
                    ") VALUES (?,?,?,1,?,?,?,?)",
                    (tool_name, vuln_type, target_type,
                     1 if success else 0, findings_count, duration_s, time.time())
                )

    def best_tool_for_vuln(self, vuln_type: str, top_n: int = 3) -> list[dict]:
        """Return top tools ordered by findings/run ratio."""
        rows = self._conn.execute(
            "SELECT tool_name, runs_total, runs_success, findings_total, avg_duration_s "
            "FROM tool_performance WHERE vuln_type=? AND runs_total > 0 "
            "ORDER BY CAST(findings_total AS REAL)/runs_total DESC LIMIT ?",
            (vuln_type, top_n)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Target profiles ───────────────────────────────────────────────────────

    def upsert_target_profile(self, domain: str, tech_stack: list[str] | None = None,
                               waf: str = "", scope_notes: str = ""):
        with self._tx() as conn:
            existing = conn.execute(
                "SELECT * FROM target_profiles WHERE domain=?", (domain,)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE target_profiles SET tech_stack=?, waf_detected=?, "
                    "scope_notes=?, last_scanned=?, scan_count=scan_count+1 "
                    "WHERE domain=?",
                    (json.dumps(tech_stack or []), waf, scope_notes, time.time(), domain)
                )
            else:
                conn.execute(
                    "INSERT INTO target_profiles("
                    "domain, tech_stack, waf_detected, scope_notes, last_scanned, scan_count"
                    ") VALUES (?,?,?,?,?,1)",
                    (domain, json.dumps(tech_stack or []), waf, scope_notes, time.time())
                )

    def get_target_profile(self, domain: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM target_profiles WHERE domain=?", (domain,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["tech_stack"] = json.loads(d.get("tech_stack") or "[]")
        d["historical_vulns"] = json.loads(d.get("historical_vulns") or "{}")
        return d

    # ── Pattern library ───────────────────────────────────────────────────────

    def upsert_pattern(self, tech_stack: list[str], vuln_type: str,
                       cvss: float = 0.0, best_tool: str = ""):
        key = ",".join(sorted(t.lower() for t in tech_stack))
        with self._tx() as conn:
            existing = conn.execute(
                "SELECT * FROM pattern_library WHERE tech_stack_key=? AND vuln_type=?",
                (key, vuln_type)
            ).fetchone()
            if existing:
                old_n = existing["occurrence_count"]
                old_avg = existing["avg_cvss"] or 0
                new_avg = (old_avg * old_n + cvss) / (old_n + 1)
                conn.execute(
                    "UPDATE pattern_library SET occurrence_count=occurrence_count+1, "
                    "avg_cvss=?, best_tool=?, last_seen=? "
                    "WHERE tech_stack_key=? AND vuln_type=?",
                    (new_avg, best_tool, time.time(), key, vuln_type)
                )
            else:
                conn.execute(
                    "INSERT INTO pattern_library("
                    "tech_stack_key, vuln_type, occurrence_count, avg_cvss, best_tool, last_seen"
                    ") VALUES (?,?,1,?,?,?)",
                    (key, vuln_type, cvss, best_tool, time.time())
                )

    def patterns_for_tech_stack(self, tech_stack: list[str]) -> list[dict]:
        """Return vulnerability patterns seen with this tech stack, highest frequency first."""
        key = ",".join(sorted(t.lower() for t in tech_stack))
        # Exact match + partial match (any tech in stack)
        rows = self._conn.execute(
            "SELECT * FROM pattern_library WHERE tech_stack_key=? "
            "ORDER BY occurrence_count DESC LIMIT 20",
            (key,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Analytics ─────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        sessions = self._conn.execute("SELECT COUNT(*) FROM scan_sessions").fetchone()[0]
        findings = self._conn.execute("SELECT COUNT(*) FROM findings_history WHERE confirmed=1").fetchone()[0]
        targets = self._conn.execute("SELECT COUNT(DISTINCT domain) FROM target_profiles").fetchone()[0]
        top_vulns = self._conn.execute(
            "SELECT vuln_type, COUNT(*) as cnt FROM findings_history "
            "WHERE confirmed=1 GROUP BY vuln_type ORDER BY cnt DESC LIMIT 5"
        ).fetchall()
        top_tools = self._conn.execute(
            "SELECT tool_name, SUM(findings_total) as total FROM tool_performance "
            "GROUP BY tool_name ORDER BY total DESC LIMIT 5"
        ).fetchall()
        return {
            "sessions": sessions,
            "confirmed_findings": findings,
            "unique_targets": targets,
            "top_vuln_types": [{"vuln_type": r[0], "count": r[1]} for r in top_vulns],
            "top_tools": [{"tool": r[0], "findings": r[1]} for r in top_tools],
        }

    def recent_sessions(self, limit: int = 10) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self):
        self._conn.close()
