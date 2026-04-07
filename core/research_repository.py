# core/research_repository.py
"""
ResearchRepository — async repository for research loop persistence.

All storage routes through DBManager → PostgreSQL.
Sync wrappers (method_sync) allow use from synchronous callers (ResearchModeController).
"""
from __future__ import annotations

import re
import time
from typing import Optional

from core.db_manager import DBManager, get_db_manager


class ResearchRepository:
    def __init__(self, db: DBManager) -> None:
        self._db = db

    # ── Session ───────────────────────────────────────────────────────────────

    async def save_session(self, session) -> None:
        """Upsert all fields of a ResearchSession object."""
        await self._db.save_research_session({
            "session_id":         session.session_id,
            "target":             session.target,
            "output_dir":         session.output_dir,
            "platform":           session.platform,
            "started_at":         session.started_at,
            "ended_at":           session.ended_at or None,  # 0.0 = "not ended" → store NULL
            "status":             session.status,
            "iteration":          session.iteration,
            "theories_generated": session.theories_generated,
            "tests_executed":     session.tests_executed,
            "anomalies_found":    session.anomalies_found,
            "confirmed_vulns":    session.confirmed_vulns,
        })

    async def finish_session(self, session) -> None:
        """Upsert final session state (ended_at and terminal status populated)."""
        await self.save_session(session)

    def save_session_sync(self, session) -> None:
        DBManager._run_sync(self.save_session(session))

    def finish_session_sync(self, session) -> None:
        DBManager._run_sync(self.finish_session(session))

    # ── Theories ──────────────────────────────────────────────────────────────

    async def record_theory(
        self, theory_id: str, session_id: str, target: str, endpoint: str,
        vuln_type: str, severity: str, confidence: float, reasoning: str,
    ) -> None:
        await self._db.save_research_theory({
            "theory_id":  theory_id,
            "session_id": session_id,
            "target":     target,
            "endpoint":   endpoint,
            "vuln_type":  vuln_type,
            "severity":   severity,
            "confidence": confidence,
            "reasoning":  reasoning,
            "status":     "pending",
            "created_at": time.time(),
            "updated_at": 0.0,
        })

    async def update_theory_status(self, theory_id: str, status: str) -> None:
        await self._db.update_research_theory_status(theory_id, status, time.time())

    def record_theory_sync(
        self, theory_id: str, session_id: str, target: str, endpoint: str,
        vuln_type: str, severity: str, confidence: float, reasoning: str,
    ) -> None:
        DBManager._run_sync(self.record_theory(
            theory_id, session_id, target, endpoint,
            vuln_type, severity, confidence, reasoning,
        ))

    def update_theory_status_sync(self, theory_id: str, status: str) -> None:
        DBManager._run_sync(self.update_theory_status(theory_id, status))

    # ── Test Outcomes ─────────────────────────────────────────────────────────

    async def record_test_outcome(
        self,
        session_id: str,
        theory_id: Optional[str],
        target: str,
        endpoint: str,
        vuln_type: str,
        payload: str,
        status_code: Optional[int],
        response_size: Optional[int],
        response_time_ms: Optional[float],
        anomaly_score: float,
        confirmed: int,
        evidence: str,
        tested_at: float,
    ) -> None:
        await self._db.save_test_outcome({
            "session_id":      session_id,
            "theory_id":       theory_id,
            "target":          target,
            "endpoint":        endpoint,
            "vuln_type":       vuln_type,
            "payload":         payload,
            "status_code":     status_code,
            "response_size":   response_size,
            "response_time_ms": response_time_ms,
            "anomaly_score":   anomaly_score,
            "confirmed":       confirmed,
            "evidence":        evidence,
            "tested_at":       tested_at,
        })

    def record_test_outcome_sync(
        self,
        session_id: str,
        theory_id: Optional[str],
        target: str,
        endpoint: str,
        vuln_type: str,
        payload: str,
        status_code: Optional[int],
        response_size: Optional[int],
        response_time_ms: Optional[float],
        anomaly_score: float,
        confirmed: int,
        evidence: str,
        tested_at: float,
    ) -> None:
        DBManager._run_sync(self.record_test_outcome(
            session_id, theory_id, target, endpoint, vuln_type, payload,
            status_code, response_size, response_time_ms,
            anomaly_score, confirmed, evidence, tested_at,
        ))

    # ── Discoveries ───────────────────────────────────────────────────────────

    async def save_discovery(
        self,
        report_id: str,
        session_id: str,
        target: str,
        vuln_type: str,
        title: str,
        severity: str,
        confidence: float,
        endpoint: str,
        description: str,
        impact: str,
        steps: list,
        poc: str,
        remediation: str,
        evidence: str,
        cvss_score: float,
        discovered_at: float,
    ) -> None:
        await self._db.save_research_discovery({
            "report_id":    report_id,
            "session_id":   session_id,
            "target":       target,
            "vuln_type":    vuln_type,
            "title":        title,
            "severity":     severity,
            "confidence":   confidence,
            "endpoint":     endpoint,
            "description":  description,
            "impact":       impact,
            "steps":        steps,
            "poc":          poc,
            "remediation":  remediation,
            "evidence":     evidence,
            "cvss_score":   cvss_score,
            "discovered_at": discovered_at,
            "reported":     0,
        })
        # Replicate original _update_pattern logic: normalise path-segment digits → {id}
        # Only replace segments that are purely numeric (e.g. /42/ but not /v1/)
        endpoint_pattern = re.sub(r"(?<=/)\d+(?=/|$)", "{id}", endpoint)
        await self._db.upsert_cross_target_pattern({
            "vuln_type":        vuln_type,
            "endpoint_pattern": endpoint_pattern,
            "parameter_pattern": "",
            "last_seen":        time.time(),
        })

    def save_discovery_sync(
        self,
        report_id: str,
        session_id: str,
        target: str,
        vuln_type: str,
        title: str,
        severity: str,
        confidence: float,
        endpoint: str,
        description: str,
        impact: str,
        steps: list,
        poc: str,
        remediation: str,
        evidence: str,
        cvss_score: float,
        discovered_at: float,
    ) -> None:
        DBManager._run_sync(self.save_discovery(
            report_id, session_id, target, vuln_type, title, severity, confidence,
            endpoint, description, impact, steps, poc, remediation, evidence,
            cvss_score, discovered_at,
        ))

    # ── Queries ───────────────────────────────────────────────────────────────

    async def get_known_patterns(self, min_count: int = 2) -> list:
        return await self._db.get_cross_target_patterns(min_count)

    async def get_session_history(self, target: Optional[str] = None) -> list:
        return await self._db.list_research_sessions(target=target)

    async def get_confirmed_discoveries(
        self, session_id: Optional[str] = None
    ) -> list:
        return await self._db.list_research_discoveries(session_id=session_id)

    def get_known_patterns_sync(self, min_count: int = 2) -> list:
        return DBManager._run_sync(self.get_known_patterns(min_count))

    def get_session_history_sync(self, target: Optional[str] = None) -> list:
        return DBManager._run_sync(self.get_session_history(target))

    def get_confirmed_discoveries_sync(
        self, session_id: Optional[str] = None
    ) -> list:
        return DBManager._run_sync(self.get_confirmed_discoveries(session_id))


async def get_research_repo() -> ResearchRepository:
    """Async factory — use with FastAPI Depends or asyncio.run."""
    return ResearchRepository(await get_db_manager())
