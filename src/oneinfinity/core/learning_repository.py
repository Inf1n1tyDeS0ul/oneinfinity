# core/learning_repository.py
"""
LearningRepository — async repository for continuous learning persistence.

All storage routes through DBManager → PostgreSQL.
Sync wrappers (method_sync) allow use from synchronous callers
(unified_scan_engine, intelligence_daemon, pattern_miner, swarm engines).
"""
from __future__ import annotations

import time
from typing import Optional

from oneinfinity.core.db_manager import DBManager, get_db_manager, get_db_manager_sync


class LearningRepository:
    def __init__(self, db: DBManager) -> None:
        self._db = db

    # ── Session lifecycle ─────────────────────────────────────────────────────

    async def start_session(
        self, session_id: str, target: str, phases: list = None
    ) -> None:
        """Record the start of a scan session."""
        await self._db.save_learning_session({
            "session_id":     session_id,
            "target":         target,
            "started_at":     time.time(),
            "finished_at":    None,
            "phases":         phases or [],
            "total_findings": 0,
            "tools_used":     [],
            "notes":          "",
        })

    async def finish_session(
        self,
        session_id: str,
        total_findings: int,
        tools_used: list = None,
        notes: str = "",
    ) -> None:
        """Record the end of a scan session (upsert updates only finish fields)."""
        await self._db.save_learning_session({
            "session_id":     session_id,
            "target":         "",       # ignored on conflict — preserved from start
            "started_at":     0.0,      # ignored on conflict
            "finished_at":    time.time(),
            "phases":         [],       # ignored on conflict
            "total_findings": total_findings,
            "tools_used":     tools_used or [],
            "notes":          notes,
        })

    def start_session_sync(
        self, session_id: str, target: str, phases: list = None
    ) -> None:
        DBManager._run_sync(self.start_session(session_id, target, phases))

    def finish_session_sync(
        self,
        session_id: str,
        total_findings: int,
        tools_used: list = None,
        notes: str = "",
    ) -> None:
        DBManager._run_sync(
            self.finish_session(session_id, total_findings, tools_used, notes)
        )

    # ── Findings ──────────────────────────────────────────────────────────────

    async def record_finding(
        self, session_id: str, finding: dict, confirmed: bool = True
    ) -> None:
        """Insert one finding row, extracting fields from the finding dict."""
        await self._db.save_learning_finding({
            "session_id":   session_id,
            "target":       finding.get("target", ""),
            "vuln_type":    finding.get("vuln_type", "unknown"),
            "severity":     finding.get("severity", "info"),
            "cvss_score":   finding.get("cvss_score"),
            "endpoint":     finding.get(
                "matched_at", finding.get("url", finding.get("endpoint", ""))
            ),
            "parameter":    finding.get("parameter", ""),
            "source_tool":  finding.get("source_tool", ""),
            "confirmed":    1 if confirmed else 0,
            "chain_id":     finding.get("chain_id", ""),
            "discovered_at": time.time(),
        })

    async def record_findings_bulk(
        self, session_id: str, findings: list, confirmed: bool = True
    ) -> None:
        """Insert multiple findings, silently skipping failures."""
        for f in findings:
            try:
                await self.record_finding(session_id, f, confirmed)
            except Exception:
                pass

    def record_finding_sync(
        self, session_id: str, finding: dict, confirmed: bool = True
    ) -> None:
        DBManager._run_sync(self.record_finding(session_id, finding, confirmed))

    def record_findings_bulk_sync(
        self, session_id: str, findings: list, confirmed: bool = True
    ) -> None:
        DBManager._run_sync(
            self.record_findings_bulk(session_id, findings, confirmed)
        )

    # ── Tool performance ──────────────────────────────────────────────────────

    async def record_tool_run(
        self,
        tool_name: str,
        vuln_type: str = "",
        target_type: str = "",
        success: bool = True,
        findings_count: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        await self._db.record_tool_run({
            "tool_name":     tool_name,
            "vuln_type":     vuln_type,
            "target_type":   target_type,
            "runs_success":  1 if success else 0,
            "findings_total": findings_count,
            "avg_duration_s": duration_s,
            "last_updated":  time.time(),
        })

    async def best_tool_for_vuln(
        self, vuln_type: str, top_n: int = 3
    ) -> list:
        """Return top tools for vuln_type as list of dicts (tool_name, runs_total, …)."""
        return await self._db.get_best_tool_for_vuln(vuln_type, top_n)

    def record_tool_run_sync(
        self,
        tool_name: str,
        vuln_type: str = "",
        target_type: str = "",
        success: bool = True,
        findings_count: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        DBManager._run_sync(
            self.record_tool_run(
                tool_name, vuln_type, target_type, success, findings_count, duration_s
            )
        )

    def best_tool_for_vuln_sync(
        self, vuln_type: str, top_n: int = 3
    ) -> list:
        return DBManager._run_sync(self.best_tool_for_vuln(vuln_type, top_n))

    # ── Target profiles ───────────────────────────────────────────────────────

    async def upsert_target_profile(
        self,
        domain: str,
        tech_stack: list = None,
        waf: str = "",
        scope_notes: str = "",
    ) -> None:
        await self._db.upsert_target_profile({
            "domain":          domain,
            "tech_stack":      tech_stack or [],
            "waf_detected":    waf,
            "scope_notes":     scope_notes,
            "historical_vulns": {},
            "last_scanned":    time.time(),
        })

    async def get_target_profile(self, domain: str) -> Optional[dict]:
        return await self._db.get_target_profile(domain)

    def upsert_target_profile_sync(
        self,
        domain: str,
        tech_stack: list = None,
        waf: str = "",
        scope_notes: str = "",
    ) -> None:
        DBManager._run_sync(
            self.upsert_target_profile(domain, tech_stack, waf, scope_notes)
        )

    def get_target_profile_sync(self, domain: str) -> Optional[dict]:
        return DBManager._run_sync(self.get_target_profile(domain))

    # ── Pattern library ───────────────────────────────────────────────────────

    async def upsert_pattern(
        self,
        tech_stack: list,
        vuln_type: str,
        cvss: float = 0.0,
        best_tool: str = "",
    ) -> None:
        key = ",".join(sorted(t.lower() for t in tech_stack))
        await self._db.upsert_pattern({
            "tech_stack_key": key,
            "vuln_type":      vuln_type,
            "avg_cvss":       cvss,
            "best_tool":      best_tool,
            "last_seen":      time.time(),
        })

    async def patterns_for_tech_stack(self, tech_stack: list) -> list:
        key = ",".join(sorted(t.lower() for t in tech_stack))
        return await self._db.get_patterns_for_tech_stack(key)

    def upsert_pattern_sync(
        self,
        tech_stack: list,
        vuln_type: str,
        cvss: float = 0.0,
        best_tool: str = "",
    ) -> None:
        DBManager._run_sync(
            self.upsert_pattern(tech_stack, vuln_type, cvss, best_tool)
        )

    def patterns_for_tech_stack_sync(self, tech_stack: list) -> list:
        return DBManager._run_sync(self.patterns_for_tech_stack(tech_stack))

    # ── Analytics ─────────────────────────────────────────────────────────────

    async def stats(self) -> dict:
        return await self._db.get_learning_stats()

    async def recent_sessions(self, limit: int = 10) -> list:
        return await self._db.list_learning_sessions(limit)

    async def get_tool_performance_stats(self) -> list:
        return await self._db.list_tool_performance()

    def stats_sync(self) -> dict:
        return DBManager._run_sync(self.stats())

    def recent_sessions_sync(self, limit: int = 10) -> list:
        return DBManager._run_sync(self.recent_sessions(limit))

    def get_tool_performance_stats_sync(self) -> list:
        return DBManager._run_sync(self.get_tool_performance_stats())

    # ── Compatibility ─────────────────────────────────────────────────────────

    def close(self) -> None:
        """No-op — DBManager owns the connection pool."""
        pass


async def get_learning_repo() -> LearningRepository:
    """Async factory — use with FastAPI Depends or asyncio.run."""
    return LearningRepository(await get_db_manager())


def get_learning_repo_sync() -> LearningRepository:
    """Sync factory — use from synchronous callers."""
    return LearningRepository(get_db_manager_sync())
