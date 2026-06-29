"""
Reactive Effectiveness Store — SQLite persistence for effectiveness reports.

Schema:
  reactive_actions         — per-action records
  reactive_replans         — per-replan-cycle records
  reactive_pivots          — per-pivot-target records
  reactive_scan_summaries  — per-scan effectiveness summary
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, List, Optional

from oneinfinity.scan.reactive_effectiveness import (
    ActionRecord,
    EffectivenessReport,
    PivotRecord,
    ReplanRecord,
    render_full_text_report,
)

log = logging.getLogger("oneinfinity.reactive_effectiveness_store")

_DDL = """
CREATE TABLE IF NOT EXISTS reactive_actions (
    id                 TEXT PRIMARY KEY,
    scan_id            TEXT NOT NULL,
    action_type        TEXT DEFAULT '',
    target             TEXT DEFAULT '',
    trigger_phase      TEXT DEFAULT '',
    trigger_source     TEXT DEFAULT '',
    confidence         REAL DEFAULT 0.0,
    generated_at       REAL DEFAULT 0.0,
    executed           INTEGER DEFAULT 0,
    success            INTEGER DEFAULT 0,
    findings_produced  INTEGER DEFAULT 0,
    validated_findings INTEGER DEFAULT 0,
    cost_s             REAL DEFAULT 0.0,
    fingerprint        TEXT DEFAULT '',
    created_at         REAL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_reactive_actions_scan
    ON reactive_actions(scan_id);

CREATE TABLE IF NOT EXISTS reactive_replans (
    id                           TEXT PRIMARY KEY,
    scan_id                      TEXT NOT NULL,
    cycle                        INTEGER DEFAULT 0,
    trigger_phase                TEXT DEFAULT '',
    original_plan_count          INTEGER DEFAULT 0,
    delta_count                  INTEGER DEFAULT 0,
    actions_executed             INTEGER DEFAULT 0,
    findings_produced            INTEGER DEFAULT 0,
    validated_findings_produced  INTEGER DEFAULT 0,
    triggered_at                 REAL DEFAULT 0.0,
    created_at                   REAL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_reactive_replans_scan
    ON reactive_replans(scan_id);

CREATE TABLE IF NOT EXISTS reactive_pivots (
    id                  TEXT PRIMARY KEY,
    scan_id             TEXT NOT NULL,
    pivot_target        TEXT DEFAULT '',
    source_finding_id   TEXT DEFAULT '',
    generated_at        REAL DEFAULT 0.0,
    scanned             INTEGER DEFAULT 0,
    scanned_at          REAL DEFAULT 0.0,
    httpx_findings      INTEGER DEFAULT 0,
    nuclei_findings     INTEGER DEFAULT 0,
    findings_produced   INTEGER DEFAULT 0,
    validated_findings  INTEGER DEFAULT 0,
    budget_used_s       REAL DEFAULT 0.0,
    created_at          REAL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS idx_reactive_pivots_scan
    ON reactive_pivots(scan_id);

CREATE TABLE IF NOT EXISTS reactive_scan_summaries (
    scan_id                    TEXT PRIMARY KEY,
    target                     TEXT DEFAULT '',
    generated_at               REAL DEFAULT 0.0,

    -- Corpus
    total_findings             INTEGER DEFAULT 0,
    baseline_findings          INTEGER DEFAULT 0,
    reactive_findings          INTEGER DEFAULT 0,
    pivot_findings             INTEGER DEFAULT 0,
    validated_total            INTEGER DEFAULT 0,
    validated_baseline         INTEGER DEFAULT 0,
    validated_reactive         INTEGER DEFAULT 0,

    -- Chains
    total_chains               INTEGER DEFAULT 0,
    baseline_chains            INTEGER DEFAULT 0,
    reactive_chains            INTEGER DEFAULT 0,

    -- Attack surface
    pivot_targets_generated    INTEGER DEFAULT 0,
    pivot_targets_scanned      INTEGER DEFAULT 0,
    new_attack_surface         INTEGER DEFAULT 0,

    -- Coverage
    vuln_classes_baseline      INTEGER DEFAULT 0,
    vuln_classes_reactive      INTEGER DEFAULT 0,
    new_vuln_classes           INTEGER DEFAULT 0,

    -- Planner
    replans_triggered          INTEGER DEFAULT 0,
    actions_generated          INTEGER DEFAULT 0,
    actions_executed           INTEGER DEFAULT 0,
    actions_skipped            INTEGER DEFAULT 0,
    actions_producing_findings INTEGER DEFAULT 0,

    -- Runtime
    reactive_runtime_s         REAL DEFAULT 0.0,
    total_runtime_s            REAL DEFAULT 0.0,

    -- 8 Metrics
    m1_finding_lift_pct        REAL DEFAULT 0.0,
    m2_chain_lift_pct          REAL DEFAULT 0.0,
    m3_ase_yield_pct           REAL DEFAULT 0.0,
    m4_coverage_improvement    REAL DEFAULT 0.0,
    m5_reactive_precision      REAL DEFAULT 0.0,
    m6_planner_precision       REAL DEFAULT 0.0,
    m7_pivot_yield_pct         REAL DEFAULT 0.0,
    m8_cost_efficiency         REAL DEFAULT 0.0,

    -- Threshold pass/fail bitmask (bit N = metric N+1)
    metrics_passed             INTEGER DEFAULT 0,

    -- Determination
    determination              TEXT DEFAULT 'INSUFFICIENT_DATA',
    determination_evidence     JSON DEFAULT '[]',

    -- Full report JSON
    report_json                JSON DEFAULT '{}',

    -- Text report
    report_text                TEXT DEFAULT '',

    created_at                 REAL DEFAULT (unixepoch())
);
"""


class ReactiveEffectivenessStore:
    """SQLite-backed store for reactive effectiveness data."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._ensure_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        try:
            with self._conn() as conn:
                conn.executescript(_DDL)
        except Exception as exc:
            log.warning("ReactiveEffectivenessStore schema init failed: %s", exc)

    # ── Persistence ────────────────────────────────────────────────

    def persist_report(self, report: EffectivenessReport) -> None:
        """Persist a complete effectiveness report to all tables."""
        try:
            self._upsert_summary(report)
        except Exception as exc:
            log.warning("Failed to upsert summary: %s", exc)

        try:
            self._insert_actions(report)
        except Exception as exc:
            log.warning("Failed to insert actions: %s", exc)

        try:
            self._insert_replans(report)
        except Exception as exc:
            log.warning("Failed to insert replans: %s", exc)

        try:
            self._insert_pivots(report)
        except Exception as exc:
            log.warning("Failed to insert pivots: %s", exc)

        log.info(
            "ReactiveEffectivenessStore: persisted report for %s "
            "(determination=%s, metrics_passed=%d/8)",
            report.scan_id, report.determination, report.metrics.metrics_passed,
        )

    def _upsert_summary(self, report: EffectivenessReport) -> None:
        em = report.metrics
        text_report = ""
        try:
            text_report = render_full_text_report(report)
        except Exception:
            pass

        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO reactive_scan_summaries (
                    scan_id, target, generated_at,
                    total_findings, baseline_findings, reactive_findings,
                    pivot_findings, validated_total, validated_baseline, validated_reactive,
                    total_chains, baseline_chains, reactive_chains,
                    pivot_targets_generated, pivot_targets_scanned, new_attack_surface,
                    vuln_classes_baseline, vuln_classes_reactive, new_vuln_classes,
                    replans_triggered, actions_generated, actions_executed,
                    actions_skipped, actions_producing_findings,
                    reactive_runtime_s, total_runtime_s,
                    m1_finding_lift_pct, m2_chain_lift_pct, m3_ase_yield_pct,
                    m4_coverage_improvement, m5_reactive_precision, m6_planner_precision,
                    m7_pivot_yield_pct, m8_cost_efficiency,
                    metrics_passed, determination, determination_evidence,
                    report_json, report_text, created_at
                ) VALUES (
                    ?,?,?,  ?,?,?,  ?,?,?,?,  ?,?,?,  ?,?,?,  ?,?,?,
                    ?,?,?,  ?,?,  ?,?,  ?,?,?,  ?,?,?,  ?,?,  ?,?,?,  ?,?,?
                )""",
                (
                    report.scan_id, report.target, report.generated_at,
                    em.total_findings, em.baseline_findings, em.reactive_findings,
                    em.pivot_findings, em.validated_total, em.validated_baseline, em.validated_reactive,
                    em.total_chains, em.baseline_chains, em.reactive_chains,
                    em.pivot_targets_generated, em.pivot_targets_scanned, em.new_attack_surface,
                    em.vuln_classes_baseline, em.vuln_classes_reactive, em.new_vuln_classes,
                    em.replans_triggered, em.actions_generated, em.actions_executed,
                    em.actions_skipped, em.actions_producing_findings,
                    em.reactive_runtime_s, em.total_runtime_s,
                    em.m1_finding_lift_pct, em.m2_chain_lift_pct, em.m3_ase_yield_pct,
                    em.m4_coverage_improvement, em.m5_reactive_precision, em.m6_planner_precision,
                    em.m7_pivot_yield_pct, em.m8_cost_efficiency,
                    em.metrics_passed, report.determination,
                    json.dumps(report.determination_evidence),
                    report.to_json(), text_report, time.time(),
                ),
            )

    def _insert_actions(self, report: EffectivenessReport) -> None:
        if not report.actions:
            return
        with self._conn() as conn:
            conn.executemany(
                """INSERT OR IGNORE INTO reactive_actions (
                    id, scan_id, action_type, target, trigger_phase, trigger_source,
                    confidence, generated_at, executed, success,
                    findings_produced, validated_findings, cost_s, fingerprint
                ) VALUES (?,?,?,?,?,?, ?,?,?,?, ?,?,?,?)""",
                [
                    (
                        a.action_id, a.scan_id, a.action_type, a.target,
                        a.trigger_phase, a.trigger_source,
                        a.confidence, a.generated_at, int(a.executed), int(a.success),
                        a.findings_produced, a.validated_findings, a.cost_s, a.fingerprint,
                    )
                    for a in report.actions
                ],
            )

    def _insert_replans(self, report: EffectivenessReport) -> None:
        if not report.replans:
            return
        with self._conn() as conn:
            conn.executemany(
                """INSERT OR IGNORE INTO reactive_replans (
                    id, scan_id, cycle, trigger_phase, original_plan_count,
                    delta_count, actions_executed, findings_produced,
                    validated_findings_produced, triggered_at
                ) VALUES (?,?,?,?,?, ?,?,?, ?,?)""",
                [
                    (
                        r.replan_id, r.scan_id, r.cycle, r.trigger_phase,
                        r.original_plan_count, r.delta_count, r.actions_executed,
                        r.findings_produced, r.validated_findings_produced,
                        r.triggered_at,
                    )
                    for r in report.replans
                ],
            )

    def _insert_pivots(self, report: EffectivenessReport) -> None:
        if not report.pivots:
            return
        with self._conn() as conn:
            conn.executemany(
                """INSERT OR IGNORE INTO reactive_pivots (
                    id, scan_id, pivot_target, source_finding_id,
                    generated_at, scanned, scanned_at,
                    httpx_findings, nuclei_findings, findings_produced,
                    validated_findings, budget_used_s
                ) VALUES (?,?,?,?, ?,?,?, ?,?,?, ?,?)""",
                [
                    (
                        p.pivot_id, p.scan_id, p.pivot_target, p.source_finding_id,
                        p.generated_at, int(p.scanned), p.scanned_at,
                        p.httpx_findings, p.nuclei_findings, p.findings_produced,
                        p.validated_findings, p.budget_used_s,
                    )
                    for p in report.pivots
                ],
            )

    # ── Query ──────────────────────────────────────────────────────

    def get_report(self, scan_id: str) -> Optional[dict]:
        """Return the summary row for a scan as a dict."""
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM reactive_scan_summaries WHERE scan_id=?",
                    (scan_id,),
                ).fetchone()
                return dict(row) if row else None
        except Exception as exc:
            log.warning("get_report failed: %s", exc)
            return None

    def get_full_report_json(self, scan_id: str) -> Optional[dict]:
        """Return the full report JSON for a scan."""
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT report_json FROM reactive_scan_summaries WHERE scan_id=?",
                    (scan_id,),
                ).fetchone()
                if row and row["report_json"]:
                    return json.loads(row["report_json"])
                return None
        except Exception as exc:
            log.warning("get_full_report_json failed: %s", exc)
            return None

    def get_text_report(self, scan_id: str) -> Optional[str]:
        """Return the rendered text report for a scan."""
        try:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT report_text FROM reactive_scan_summaries WHERE scan_id=?",
                    (scan_id,),
                ).fetchone()
                return row["report_text"] if row else None
        except Exception as exc:
            log.warning("get_text_report failed: %s", exc)
            return None

    def list_reports(self, limit: int = 20) -> List[dict]:
        """List recent effectiveness reports ordered by generated_at desc."""
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT scan_id, target, generated_at, determination,
                              metrics_passed, reactive_findings, baseline_findings,
                              m1_finding_lift_pct, total_runtime_s
                       FROM reactive_scan_summaries
                       ORDER BY generated_at DESC
                       LIMIT ?""",
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            log.warning("list_reports failed: %s", exc)
            return []

    def get_actions(self, scan_id: str) -> List[dict]:
        """Return action records for a scan."""
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM reactive_actions WHERE scan_id=? ORDER BY generated_at",
                    (scan_id,),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            log.warning("get_actions failed: %s", exc)
            return []

    def get_replans(self, scan_id: str) -> List[dict]:
        """Return replan records for a scan."""
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM reactive_replans WHERE scan_id=? ORDER BY cycle",
                    (scan_id,),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            log.warning("get_replans failed: %s", exc)
            return []

    def get_pivots(self, scan_id: str) -> List[dict]:
        """Return pivot records for a scan."""
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM reactive_pivots WHERE scan_id=? ORDER BY generated_at",
                    (scan_id,),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            log.warning("get_pivots failed: %s", exc)
            return []


# ── Singleton ─────────────────────────────────────────────────────────────────

_store_instance: Optional[ReactiveEffectivenessStore] = None


def get_store() -> ReactiveEffectivenessStore:
    """Return (or create) the global ReactiveEffectivenessStore singleton."""
    global _store_instance
    if _store_instance is None:
        from oneinfinity.infra.path_manager import db_path
        # Use the main findings DB so we benefit from existing connection
        # handling; our tables are isolated by their reactive_* prefix.
        db_file = str(db_path("reactive_effectiveness"))
        _store_instance = ReactiveEffectivenessStore(db_file)
    return _store_instance
