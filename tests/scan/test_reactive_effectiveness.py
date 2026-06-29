"""
Unit tests for the Reactive Effectiveness Program.

Tests all 8 metrics, determination logic, record collection,
dashboard rendering, and store persistence.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest


# ── Minimal stubs so we can import without full OneInfinity stack ─────────────

@dataclass
class _PhaseResult:
    name: str
    meta: dict = field(default_factory=dict)
    start_time: float = 0.0
    end_time: float = 0.0
    status: str = "completed"
    error: str = ""
    findings: list = field(default_factory=list)


class _Session:
    """Minimal ScanSession stub."""
    def __init__(
        self,
        scan_id="test-scan-001",
        target="https://example.com",
        findings=None,
    ):
        self.scan_id    = scan_id
        self.target     = target
        self.findings   = findings or []
        self.status     = "running"
        self.scan_config = {}

        # Phase stubs
        self.phases: Dict[str, _PhaseResult] = {
            "classify": _PhaseResult("classify", start_time=1000.0, end_time=1001.0),
            "recon":    _PhaseResult("recon",    start_time=1001.0, end_time=1030.0,
                                      meta={"urls": 12}),
            "vuln_scan": _PhaseResult("vuln_scan", start_time=1030.0, end_time=1090.0),
            "exploit_validation": _PhaseResult("exploit_validation",
                                                start_time=1090.0, end_time=1120.0),
            "exploit_chaining": _PhaseResult("exploit_chaining",
                                              start_time=1120.0, end_time=1130.0,
                                              meta={"pivots": {
                                                  "targets": ["http://10.0.0.2"],
                                                  "findings": 2,
                                              }}),
            "done": _PhaseResult("done", start_time=1130.0, end_time=1135.0),
        }


def _make_finding(vuln_type="sqli", source="", severity="medium",
                  finding_id="", trigger_phase="", **kw):
    f = {
        "vuln_type":     vuln_type,
        "source":        source,
        "severity":      severity,
        "finding_id":    finding_id,
        "trigger_phase": trigger_phase,
        "url":           "https://example.com/test",
    }
    f.update(kw)
    return f


def _make_baseline_findings(n=10, types=None):
    types = types or ["sqli", "xss", "idor", "ssrf", "cors"]
    findings = []
    for i in range(n):
        findings.append(_make_finding(
            vuln_type=types[i % len(types)],
            source="tool_scan",
            finding_id=f"base-{i}",
        ))
    return findings


def _make_reactive_findings(n=5, types=None):
    types = types or ["xss", "rce", "sqli"]
    findings = []
    for i in range(n):
        findings.append(_make_finding(
            vuln_type=types[i % len(types)],
            source="reactive_exec",
            finding_id=f"react-{i}",
            trigger_phase="vuln_scan",
        ))
    return findings


def _make_pivot_findings(n=3):
    findings = []
    for i in range(n):
        findings.append(_make_finding(
            vuln_type="ssrf",
            source="ssrf_pivot_recon",
            finding_id=f"pivot-{i}",
            pivot_target="http://10.0.0.2",
        ))
    return findings


def _make_tel(
    generated=5, executed=4, skipped=1, replans=2,
    piv_gen=1, piv_exec=1, reactive_findings=5, runtime_s=30.0,
):
    return {
        "reactive_actions_generated":      generated,
        "reactive_actions_executed":       executed,
        "reactive_actions_skipped":        skipped,
        "replans_triggered":               replans,
        "pivots_generated":                piv_gen,
        "pivots_executed":                 piv_exec,
        "reactive_findings_produced":      reactive_findings,
        "total_reactive_runtime_s":        runtime_s,
        "chain_driven_actions_generated":  1,
    }


def _make_ctx(tel=None, validated=None, replanned=None, new_targets=None,
              successful_chains=None, exploit_chains=None, **kw):
    ctx = {
        "_reactive_telemetry":    tel or {},
        "validated_findings":     validated or [],
        "_replan_count":          tel.get("replans_triggered", 0) if tel else 0,
        "_reactive_total_executed": tel.get("reactive_actions_executed", 0) if tel else 0,
        "_reactive_total_runtime_s": tel.get("total_reactive_runtime_s", 0.0) if tel else 0.0,
        "replanned_actions":      replanned or [],
        "new_targets":            new_targets or [],
        "successful_chains":      successful_chains or [],
        "exploit_chains":         exploit_chains or [],
    }
    ctx.update(kw)
    return ctx


# ── Import the module under test ──────────────────────────────────────────────

import sys
sys.path.insert(0, "src")

from oneinfinity.scan.reactive_effectiveness import (
    ActionRecord,
    EffectivenessMetrics,
    EffectivenessReport,
    PivotRecord,
    ReplanRecord,
    _collect_action_records,
    _collect_pivot_records,
    _collect_replan_records,
    _compute_determination,
    _compute_metrics,
    _finding_vuln_class,
    _is_pivot_finding,
    _is_reactive_finding,
    generate_effectiveness_report,
    render_dashboard,
    render_full_text_report,
    render_roi_table,
    LIFT_MATERIAL_PCT,
    CHAIN_LIFT_MATERIAL_PCT,
    ASE_MATERIAL_PCT,
    COVERAGE_MATERIAL_PCT,
    PRECISION_MATERIAL,
    PLANNER_PRECISION_MATERIAL,
    PIVOT_YIELD_MATERIAL_PCT,
    COST_EFFICIENCY_MATERIAL,
    YES_THRESHOLD,
)


# ── Finding Attribution Tests ─────────────────────────────────────────────────

class TestFindingAttribution:

    def test_reactive_source_tag(self):
        assert _is_reactive_finding({"source": "reactive_exec"})
        assert _is_reactive_finding({"source": "ssrf_pivot_recon"})
        assert _is_reactive_finding({"source": "ssrf_pivot_nuclei"})
        assert _is_reactive_finding({"source": "reactive_nuclei"})

    def test_non_reactive_source(self):
        assert not _is_reactive_finding({"source": "dalfox"})
        assert not _is_reactive_finding({"source": "nuclei"})
        assert not _is_reactive_finding({"source": "sqlmap"})
        assert not _is_reactive_finding({})

    def test_trigger_phase_marks_reactive(self):
        assert _is_reactive_finding({"trigger_phase": "vuln_scan"})

    def test_pivot_detection(self):
        assert _is_pivot_finding({"source": "ssrf_pivot_recon"})
        assert _is_pivot_finding({"pivot_target": "http://10.0.0.2"})
        assert not _is_pivot_finding({"source": "reactive_exec"})

    def test_vuln_class_normalisation(self):
        assert _finding_vuln_class({"vuln_type": "sqli"}) == "sqli"
        assert _finding_vuln_class({"vuln_type": "sqli_blind"}) == "sqli"
        assert _finding_vuln_class({"vuln_type": "xss_reflected"}) == "xss"
        assert _finding_vuln_class({"vuln_type": "ssrf_rce_chain"}) == "ssrf"
        assert _finding_vuln_class({"vuln_type": ""}) == "unknown"
        assert _finding_vuln_class({}) == "unknown"


# ── Metric Computation Tests ──────────────────────────────────────────────────

class TestMetricM1FindingLift:
    """M1: Reactive Finding Lift = reactive / baseline × 100"""

    def test_basic_lift_computed(self):
        session  = _Session(findings=_make_baseline_findings(10) + _make_reactive_findings(5))
        tel      = _make_tel(reactive_findings=5, generated=5, executed=4)
        ctx      = _make_ctx(tel=tel)
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        # reactive=5, baseline=10 → 50%
        assert em.m1_finding_lift_pct == pytest.approx(50.0, abs=1.0)

    def test_zero_baseline_no_division_error(self):
        session = _Session(findings=_make_reactive_findings(3))
        tel     = _make_tel(reactive_findings=3, generated=3, executed=3)
        ctx     = _make_ctx(tel=tel)
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m1_finding_lift_pct >= 0.0

    def test_zero_reactive_gives_zero_lift(self):
        session = _Session(findings=_make_baseline_findings(10))
        ctx     = _make_ctx(tel=_make_tel(reactive_findings=0, generated=0, executed=0))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m1_finding_lift_pct == 0.0

    def test_lift_pass_threshold(self):
        session = _Session(findings=_make_baseline_findings(10) + _make_reactive_findings(5))
        ctx     = _make_ctx(tel=_make_tel(reactive_findings=5, generated=5, executed=5))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m1_pass == (em.m1_finding_lift_pct >= LIFT_MATERIAL_PCT)

    def test_tel_count_takes_precedence_over_source_tags(self):
        # tel says 8 reactive but only 3 are tagged in findings
        base = _make_baseline_findings(10)
        react = _make_reactive_findings(3)
        session = _Session(findings=base + react)
        tel = _make_tel(reactive_findings=8, generated=8, executed=8)
        ctx = _make_ctx(tel=tel)
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        # tel_reactive_count (8) > source_tagged (3) → use tel
        assert em.reactive_findings == 8


class TestMetricM2ChainLift:
    """M2: Reactive Chain Lift = reactive_chains / total_chains × 100"""

    def test_all_reactive_chains(self):
        chains = [{"chain_type": "sqli_rce", "source": "reactive"} for _ in range(4)]
        ctx = _make_ctx(tel=_make_tel(), successful_chains=chains)
        session = _Session(findings=_make_baseline_findings(5))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m2_chain_lift_pct == pytest.approx(100.0, abs=1.0)

    def test_no_chains_gives_zero(self):
        ctx = _make_ctx(tel=_make_tel())
        session = _Session()
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m2_chain_lift_pct == 0.0

    def test_mixed_chains(self):
        chains = [
            {"chain_type": "sqli", "source": "baseline"},
            {"chain_type": "xss",  "source": "reactive"},
        ]
        ctx = _make_ctx(tel=_make_tel(), successful_chains=chains)
        session = _Session()
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        # 1 of 2 reactive → 50%
        assert em.m2_chain_lift_pct == pytest.approx(50.0, abs=1.0)
        assert em.total_chains == 2
        assert em.reactive_chains == 1


class TestMetricM3ASEYield:
    """M3: Attack Surface Expansion = new_targets / 1 × 100"""

    def test_new_targets_expand_surface(self):
        ctx = _make_ctx(tel=_make_tel(piv_gen=3), new_targets=["http://a", "http://b", "http://c"])
        session = _Session()
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m3_ase_yield_pct == pytest.approx(300.0, abs=1.0)
        assert em.m3_pass is True

    def test_zero_new_targets_no_expansion(self):
        ctx = _make_ctx(tel=_make_tel(piv_gen=0), new_targets=[])
        session = _Session()
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m3_ase_yield_pct == 0.0
        assert em.m3_pass is False


class TestMetricM4Coverage:
    """M4: Coverage = new_vuln_classes / baseline_classes × 100"""

    def test_new_classes_increase_coverage(self):
        base  = [_make_finding(vuln_type="sqli",  source="tool_scan")]
        react = [_make_finding(vuln_type="rce",   source="reactive_exec"),
                 _make_finding(vuln_type="ssrf",  source="reactive_exec")]
        session = _Session(findings=base + react)
        ctx = _make_ctx(tel=_make_tel(reactive_findings=2))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        # baseline class: {sqli}, reactive adds {rce, ssrf} → 2 new / 1 baseline = 200%
        assert em.m4_coverage_improvement >= 100.0
        assert em.new_vuln_classes >= 1

    def test_same_classes_no_improvement(self):
        base  = [_make_finding(vuln_type="sqli", source="tool_scan")]
        react = [_make_finding(vuln_type="sqli", source="reactive_exec")]
        session = _Session(findings=base + react)
        ctx = _make_ctx(tel=_make_tel(reactive_findings=1))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.new_vuln_classes == 0
        assert em.m4_coverage_improvement == 0.0


class TestMetricM5Precision:
    """M5: Reactive Precision = validated_reactive / reactive_findings"""

    def test_all_validated_gives_100pct(self):
        react = _make_reactive_findings(5)
        validated = list(react)
        session = _Session(findings=react)
        ctx = _make_ctx(
            tel=_make_tel(reactive_findings=5),
            validated=validated,
        )
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        # 5 validated / 5 reactive → 1.0
        assert em.m5_reactive_precision == pytest.approx(1.0, abs=0.1)

    def test_zero_reactive_gives_zero_precision(self):
        session = _Session(findings=_make_baseline_findings(5))
        ctx = _make_ctx(tel=_make_tel(reactive_findings=0, generated=0, executed=0))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m5_reactive_precision == 0.0


class TestMetricM6PlannerPrecision:
    """M6: Planner Precision = actions_producing_findings / executed"""

    def test_productive_actions(self):
        session = _Session(findings=_make_reactive_findings(3))
        tel = _make_tel(generated=5, executed=4, reactive_findings=3)
        ctx = _make_ctx(tel=tel)
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m6_planner_precision > 0.0
        assert 0.0 <= em.m6_planner_precision <= 1.0

    def test_zero_executed_gives_zero_precision(self):
        session = _Session()
        ctx = _make_ctx(tel=_make_tel(generated=5, executed=0, reactive_findings=0))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m6_planner_precision == 0.0


class TestMetricM7PivotYield:
    """M7: Pivot Yield = pivots_with_findings / pivots_scanned × 100"""

    def test_all_pivots_productive(self):
        pivots = [
            PivotRecord("p1", "s", "http://10.0.0.1", scanned=True, findings_produced=2),
            PivotRecord("p2", "s", "http://10.0.0.2", scanned=True, findings_produced=1),
        ]
        tel = _make_tel(piv_gen=2, piv_exec=2)
        session = _Session()
        ctx = _make_ctx(tel=tel)
        em = _compute_metrics(session.scan_id, session, ctx, [], [], pivots)
        assert em.m7_pivot_yield_pct == pytest.approx(100.0, abs=1.0)
        assert em.m7_pass is True

    def test_no_pivots_yields_zero(self):
        session = _Session()
        ctx = _make_ctx(tel=_make_tel(piv_gen=0, piv_exec=0))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        assert em.m7_pivot_yield_pct == 0.0

    def test_half_pivots_productive(self):
        pivots = [
            PivotRecord("p1", "s", "http://10.0.0.1", scanned=True, findings_produced=1),
            PivotRecord("p2", "s", "http://10.0.0.2", scanned=True, findings_produced=0),
        ]
        tel = _make_tel(piv_gen=2, piv_exec=2)
        session = _Session()
        ctx = _make_ctx(tel=tel)
        em = _compute_metrics(session.scan_id, session, ctx, [], [], pivots)
        assert em.m7_pivot_yield_pct == pytest.approx(50.0, abs=1.0)


class TestMetricM8CostEfficiency:
    """M8: Cost Efficiency = validated_reactive / reactive_runtime_s"""

    def test_efficient_reactive(self):
        react = _make_reactive_findings(10)
        session = _Session(findings=_make_baseline_findings(10) + react)
        tel = _make_tel(reactive_findings=10, runtime_s=10.0, generated=10, executed=10)
        ctx = _make_ctx(tel=tel, validated=list(react))
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        # Should have cost_efficiency > 0
        assert em.m8_cost_efficiency >= 0.0

    def test_zero_runtime_gives_zero_efficiency(self):
        session = _Session(findings=_make_reactive_findings(5))
        tel = _make_tel(reactive_findings=5, runtime_s=0.0, generated=5, executed=5)
        ctx = _make_ctx(tel=tel)
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        # runtime=0 → cost efficiency = 0 (guard against division)
        assert em.m8_cost_efficiency == 0.0


# ── Determination Tests ───────────────────────────────────────────────────────

class TestDetermination:

    def _make_passing_em(self):
        """EffectivenessMetrics with all 8 metrics passing."""
        em = EffectivenessMetrics(
            scan_id="test", target="https://x.com",
            total_findings=25, baseline_findings=10, reactive_findings=15,
            pivot_findings=2, validated_total=20, validated_baseline=10,
            validated_reactive=12, total_chains=4, reactive_chains=2,
            new_attack_surface=3, vuln_classes_baseline=3, new_vuln_classes=2,
            replans_triggered=2, actions_generated=8, actions_executed=6,
            actions_skipped=2, actions_producing_findings=4,
            reactive_runtime_s=20.0, total_runtime_s=135.0,
            pivot_targets_generated=3, pivot_targets_scanned=3,
            m1_finding_lift_pct=150.0,  m1_pass=True,
            m2_chain_lift_pct=50.0,     m2_pass=True,
            m3_ase_yield_pct=300.0,     m3_pass=True,
            m4_coverage_improvement=66.0, m4_pass=True,
            m5_reactive_precision=0.8,  m5_pass=True,
            m6_planner_precision=0.67,  m6_pass=True,
            m7_pivot_yield_pct=66.0,    m7_pass=True,
            m8_cost_efficiency=0.6,     m8_pass=True,
        )
        return em

    def test_yes_when_all_pass(self):
        em = self._make_passing_em()
        session = _Session()
        ctx = _make_ctx(tel=_make_tel(generated=8, executed=6))
        det, evid = _compute_determination(em, [], [], [], session, ctx)
        assert det == "YES"
        assert any("VERDICT: YES" in e for e in evid)

    def test_insufficient_data_when_no_reactive(self):
        em = EffectivenessMetrics(scan_id="x", target="y",
                                  actions_generated=0, actions_executed=0,
                                  pivot_targets_generated=0, replans_triggered=0)
        session = _Session()
        ctx = _make_ctx(tel={})
        det, evid = _compute_determination(em, [], [], [], session, ctx)
        assert det == "INSUFFICIENT_DATA"
        assert any("INSUFFICIENT_DATA" in e for e in evid)

    def test_insufficient_data_when_zero_findings(self):
        em = EffectivenessMetrics(scan_id="x", target="y",
                                  total_findings=0,
                                  actions_generated=5, actions_executed=3)
        session = _Session()
        ctx = _make_ctx(tel=_make_tel(generated=5, executed=3))
        det, evid = _compute_determination(em, [], [], [], session, ctx)
        assert det == "INSUFFICIENT_DATA"

    def test_no_when_few_metrics_pass(self):
        em = EffectivenessMetrics(
            scan_id="x", target="y",
            total_findings=10, baseline_findings=10,
            reactive_findings=0, pivot_findings=0,
            actions_generated=2, actions_executed=1,
            m1_finding_lift_pct=0.0, m1_pass=False,
            m2_chain_lift_pct=0.0,   m2_pass=False,
            m3_ase_yield_pct=0.0,    m3_pass=False,
            m4_coverage_improvement=0.0, m4_pass=False,
            m5_reactive_precision=0.0, m5_pass=False,
            m6_planner_precision=0.0, m6_pass=False,
            m7_pivot_yield_pct=0.0,  m7_pass=False,
            m8_cost_efficiency=0.0,  m8_pass=False,
        )
        session = _Session()
        ctx = _make_ctx(tel=_make_tel(generated=2, executed=1))
        det, evid = _compute_determination(em, [], [], [], session, ctx)
        assert det == "NO"
        assert any("VERDICT: NO" in e for e in evid)

    def test_yes_threshold_exactly_met(self):
        """YES when exactly YES_THRESHOLD metrics pass."""
        em = EffectivenessMetrics(
            scan_id="x", target="y",
            total_findings=20, baseline_findings=10, reactive_findings=10,
            actions_generated=5, actions_executed=4,
        )
        # Force exactly YES_THRESHOLD metrics to pass
        metrics_attrs = [
            ("m1_finding_lift_pct", "m1_pass", LIFT_MATERIAL_PCT + 1),
            ("m2_chain_lift_pct",   "m2_pass", CHAIN_LIFT_MATERIAL_PCT + 1),
            ("m3_ase_yield_pct",    "m3_pass", ASE_MATERIAL_PCT + 1),
        ]
        for _, pass_attr, _ in metrics_attrs:
            object.__setattr__(em, pass_attr, True)
        # YES_THRESHOLD = 3, so exactly 3 should give YES
        assert YES_THRESHOLD == 3
        object.__setattr__(em, "m4_pass", False)
        object.__setattr__(em, "m5_pass", False)
        object.__setattr__(em, "m6_pass", False)
        object.__setattr__(em, "m7_pass", False)
        object.__setattr__(em, "m8_pass", False)

        session = _Session()
        ctx = _make_ctx(tel=_make_tel(generated=5, executed=4))
        det, evid = _compute_determination(em, [], [], [], session, ctx)
        assert det == "YES"

    def test_evidence_contains_all_8_metrics(self):
        em = self._make_passing_em()
        session = _Session()
        ctx = _make_ctx(tel=_make_tel(generated=8, executed=6))
        det, evid = _compute_determination(em, [], [], [], session, ctx)
        combined = "\n".join(evid)
        # All metrics should appear in evidence
        for m in ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"]:
            assert m in combined, f"Missing {m} in determination evidence"


# ── Record Collection Tests ───────────────────────────────────────────────────

class TestRecordCollection:

    def test_action_records_from_action_log(self):
        """Action log entries should be read directly."""
        session = _Session()
        ctx = _make_ctx(tel=_make_tel())
        ctx["_ree_action_log"] = [
            {
                "action_id":     "act-001",
                "action_type":   "xss",
                "target":        "https://example.com",
                "trigger_phase": "vuln_scan",
                "trigger_source": "replan",
                "confidence":    0.7,
                "generated_at":  1000.0,
                "executed":      True,
                "success":       True,
                "findings_produced": 2,
                "validated_findings": 1,
                "cost_s":        5.0,
                "fingerprint":   "fp-abc",
            }
        ]
        records = _collect_action_records("test", session, ctx)
        assert len(records) == 1
        r = records[0]
        assert r.action_id == "act-001"
        assert r.action_type == "xss"
        assert r.executed is True
        assert r.findings_produced == 2

    def test_action_records_synthesised_from_replan_meta(self):
        """Without action log, records are synthesised from replan meta."""
        session = _Session()
        session.phases["vuln_scan"] = _PhaseResult(
            "vuln_scan",
            meta={"replans": [{"cycle": 1, "trigger_phase": "vuln_scan",
                               "delta_count": 3, "original_count": 5}]},
        )
        tel = _make_tel(generated=3, executed=3, reactive_findings=2)
        ctx = _make_ctx(tel=tel)
        records = _collect_action_records("test", session, ctx)
        assert len(records) >= 3

    def test_replan_records_from_phase_meta(self):
        """Replan records read from session.phases[*].meta['replans']."""
        session = _Session()
        session.phases["vuln_scan"] = _PhaseResult(
            "vuln_scan",
            meta={"replans": [
                {"cycle": 1, "trigger_phase": "vuln_scan", "delta_count": 4, "original_count": 6},
                {"cycle": 2, "trigger_phase": "vuln_scan", "delta_count": 2, "original_count": 10},
            ]},
        )
        tel = _make_tel(replans=2, generated=6, executed=5, reactive_findings=3)
        ctx = _make_ctx(tel=tel)
        records = _collect_replan_records("test", session, ctx)
        cycles = [r.cycle for r in records]
        assert 1 in cycles
        assert 2 in cycles

    def test_replan_records_synthesised_from_tel(self):
        """When no phase meta, synthesise from telemetry counter."""
        session = _Session()  # no replans in meta
        tel = _make_tel(replans=3, generated=9, executed=7, reactive_findings=4)
        ctx = _make_ctx(tel=tel)
        records = _collect_replan_records("test", session, ctx)
        assert len(records) == 3
        assert all(r.scan_id == "test" for r in records)

    def test_pivot_records_from_phase_meta_dict(self):
        """Pivot records read from exploit_chaining phase meta."""
        session = _Session()
        session.phases["exploit_chaining"] = _PhaseResult(
            "exploit_chaining",
            meta={"pivots": {
                "targets": ["http://10.0.0.2", "http://10.0.0.3"],
                "findings": 4,
            }},
        )
        ctx = _make_ctx(tel=_make_tel(piv_gen=2, piv_exec=2))
        records = _collect_pivot_records("test", session, ctx)
        assert len(records) == 2
        assert all(r.scan_id == "test" for r in records)

    def test_pivot_records_from_new_targets(self):
        """Pivot records synthesised from ctx['new_targets'] when no meta."""
        session = _Session()
        session.phases["exploit_chaining"] = _PhaseResult("exploit_chaining", meta={})
        ctx = _make_ctx(
            tel=_make_tel(piv_gen=2, piv_exec=1),
            new_targets=["http://192.168.1.1", "http://10.0.0.5"],
        )
        records = _collect_pivot_records("test", session, ctx)
        assert len(records) == 2
        assert records[0].scanned is True   # i=0 < piv_exec=1
        assert records[1].scanned is False  # i=1 >= piv_exec=1


# ── Dashboard & Rendering Tests ───────────────────────────────────────────────

class TestRendering:

    def _make_full_report(self):
        em = EffectivenessMetrics(
            scan_id="test-001", target="https://example.com",
            total_findings=20, baseline_findings=12, reactive_findings=8,
            validated_total=15, validated_reactive=5,
            total_chains=3, reactive_chains=2,
            pivot_targets_generated=2, pivot_targets_scanned=2,
            new_attack_surface=2, vuln_classes_baseline=3, new_vuln_classes=1,
            replans_triggered=2, actions_generated=6, actions_executed=5,
            actions_skipped=1, actions_producing_findings=3,
            reactive_runtime_s=25.0, total_runtime_s=120.0,
            m1_finding_lift_pct=66.7, m1_pass=True,
            m2_chain_lift_pct=66.7,   m2_pass=True,
            m3_ase_yield_pct=200.0,   m3_pass=True,
            m4_coverage_improvement=33.3, m4_pass=True,
            m5_reactive_precision=0.625,  m5_pass=True,
            m6_planner_precision=0.6,     m6_pass=True,
            m7_pivot_yield_pct=50.0,      m7_pass=False,
            m8_cost_efficiency=0.2,       m8_pass=True,
        )
        return EffectivenessReport(
            scan_id="test-001",
            target="https://example.com",
            generated_at=time.time(),
            metrics=em,
            determination="YES",
            determination_evidence=[
                "M1 PASS — Reactive Finding Lift: 66.7%",
                "M7 FAIL — Pivot Yield: 50.0%",
                "\nVERDICT: YES — 7/8 metrics pass.",
            ],
        )

    def test_dashboard_renders_without_error(self):
        report = self._make_full_report()
        text = render_dashboard(report)
        assert "REACTIVE EFFECTIVENESS DASHBOARD" in text
        assert "DETERMINATION" in text
        assert "M1" in text and "M8" in text

    def test_dashboard_shows_yes_determination(self):
        report = self._make_full_report()
        text = render_dashboard(report)
        assert "YES" in text or "MATERIALLY" in text

    def test_dashboard_shows_all_8_metrics(self):
        report = self._make_full_report()
        text = render_dashboard(report)
        for m in ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"]:
            assert m in text, f"Metric {m} missing from dashboard"

    def test_roi_table_renders(self):
        from oneinfinity.scan.reactive_effectiveness import render_roi_table
        report = self._make_full_report()
        text = render_roi_table(report)
        assert "REACTIVE ROI METRICS" in text
        assert "Finding ROI" in text

    def test_full_text_report_renders(self):
        report = self._make_full_report()
        text = render_full_text_report(report)
        assert len(text) > 500
        assert "DASHBOARD" in text
        assert "ROI" in text

    def test_report_to_json(self):
        report = self._make_full_report()
        j = json.loads(report.to_json())
        assert j["scan_id"] == "test-001"
        assert j["determination"] == "YES"
        assert "metrics" in j
        assert j["metrics"]["m1_finding_lift_pct"] == pytest.approx(66.7, abs=0.1)


# ── generate_effectiveness_report Integration ─────────────────────────────────

class TestGenerateReport:

    def test_full_generate_with_findings(self):
        """Full integration: generate report from populated session/ctx."""
        base  = _make_baseline_findings(10)
        react = _make_reactive_findings(5)
        piv   = _make_pivot_findings(2)
        session = _Session(
            scan_id="full-test-001",
            findings=base + react + piv,
        )
        session.phases["exploit_chaining"] = _PhaseResult(
            "exploit_chaining",
            meta={"pivots": {"targets": ["http://10.0.0.1"], "findings": 2}},
        )
        session.phases["vuln_scan"] = _PhaseResult(
            "vuln_scan",
            meta={"replans": [{"cycle": 1, "trigger_phase": "vuln_scan",
                               "delta_count": 3, "original_count": 7}]},
        )
        tel = _make_tel(
            generated=5, executed=4, skipped=1, replans=1,
            piv_gen=1, piv_exec=1, reactive_findings=5, runtime_s=25.0,
        )
        ctx = _make_ctx(
            tel=tel,
            validated=base[:8] + react[:3],
            new_targets=["http://10.0.0.1"],
        )

        # Patch out DB persistence
        with patch("oneinfinity.scan.reactive_effectiveness_store.get_store") as mock_store:
            mock_store.return_value.persist_report = MagicMock()
            report = generate_effectiveness_report(session, ctx)

        assert report.scan_id == "full-test-001"
        assert report.target  == "https://example.com"
        assert report.determination in ("YES", "NO", "INSUFFICIENT_DATA")
        assert report.metrics.total_findings == 17
        assert report.metrics.reactive_findings >= 5
        assert report.metrics.baseline_findings >= 0
        assert len(report.replans) >= 1
        assert len(report.pivots) >= 1

    def test_generate_with_no_reactive_gives_insufficient(self):
        """No reactive execution → INSUFFICIENT_DATA."""
        session = _Session(findings=_make_baseline_findings(5))
        ctx = _make_ctx(tel={})

        with patch("oneinfinity.scan.reactive_effectiveness_store.get_store") as mock_store:
            mock_store.return_value.persist_report = MagicMock()
            report = generate_effectiveness_report(session, ctx)

        assert report.determination == "INSUFFICIENT_DATA"

    def test_generate_populates_done_meta(self):
        """Report should be written to done.meta['reactive_effectiveness']."""
        session = _Session(findings=_make_baseline_findings(5) + _make_reactive_findings(3))
        tel = _make_tel(generated=3, executed=3, reactive_findings=3)
        ctx = _make_ctx(tel=tel)

        with patch("oneinfinity.scan.reactive_effectiveness_store.get_store") as mock_store:
            mock_store.return_value.persist_report = MagicMock()
            report = generate_effectiveness_report(session, ctx)

        done = session.phases.get("done")
        if done is not None:
            assert "reactive_effectiveness" in done.meta
            assert "determination" in done.meta["reactive_effectiveness"]


# ── Store Tests ───────────────────────────────────────────────────────────────

class TestReactiveEffectivenessStore:

    def _make_report(self, scan_id="store-test-001"):
        em = EffectivenessMetrics(
            scan_id=scan_id, target="https://example.com",
            total_findings=15, reactive_findings=5, baseline_findings=10,
            m1_finding_lift_pct=50.0, m1_pass=True,
        )
        return EffectivenessReport(
            scan_id=scan_id,
            target="https://example.com",
            generated_at=time.time(),
            metrics=em,
            determination="YES",
            determination_evidence=["VERDICT: YES"],
        )

    def test_persist_and_retrieve(self):
        from oneinfinity.scan.reactive_effectiveness_store import ReactiveEffectivenessStore
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store  = ReactiveEffectivenessStore(db_path)
            report = self._make_report()
            store.persist_report(report)

            row = store.get_report(report.scan_id)
            assert row is not None
            assert row["scan_id"] == report.scan_id
            assert row["determination"] == "YES"
            assert row["m1_finding_lift_pct"] == pytest.approx(50.0, abs=0.1)
        finally:
            os.unlink(db_path)

    def test_list_reports(self):
        from oneinfinity.scan.reactive_effectiveness_store import ReactiveEffectivenessStore
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = ReactiveEffectivenessStore(db_path)
            for i in range(3):
                store.persist_report(self._make_report(f"scan-{i:03d}"))
            rows = store.list_reports()
            assert len(rows) == 3
        finally:
            os.unlink(db_path)

    def test_get_full_report_json(self):
        from oneinfinity.scan.reactive_effectiveness_store import ReactiveEffectivenessStore
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store  = ReactiveEffectivenessStore(db_path)
            report = self._make_report()
            store.persist_report(report)

            data = store.get_full_report_json(report.scan_id)
            assert data is not None
            assert data["scan_id"] == report.scan_id
            assert "metrics" in data
        finally:
            os.unlink(db_path)

    def test_action_records_persisted(self):
        from oneinfinity.scan.reactive_effectiveness_store import ReactiveEffectivenessStore
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = ReactiveEffectivenessStore(db_path)
            report = self._make_report()
            report.actions = [
                ActionRecord("act-1", "store-test-001", "xss", "https://x.com",
                             "vuln_scan", "replan", executed=True, findings_produced=1),
                ActionRecord("act-2", "store-test-001", "sqli", "https://x.com",
                             "vuln_scan", "replan", executed=True, findings_produced=0),
            ]
            store.persist_report(report)
            actions = store.get_actions("store-test-001")
            assert len(actions) == 2
            assert any(a["action_type"] == "xss" for a in actions)
        finally:
            os.unlink(db_path)

    def test_missing_scan_returns_none(self):
        from oneinfinity.scan.reactive_effectiveness_store import ReactiveEffectivenessStore
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            store = ReactiveEffectivenessStore(db_path)
            assert store.get_report("does-not-exist") is None
        finally:
            os.unlink(db_path)


# ── Threshold & Constants Tests ───────────────────────────────────────────────

class TestThresholds:

    def test_yes_threshold_is_3(self):
        """YES requires ≥3 passing metrics."""
        assert YES_THRESHOLD == 3

    def test_all_thresholds_positive(self):
        assert LIFT_MATERIAL_PCT > 0
        assert CHAIN_LIFT_MATERIAL_PCT > 0
        assert ASE_MATERIAL_PCT > 0
        assert COVERAGE_MATERIAL_PCT > 0
        assert 0 < PRECISION_MATERIAL < 1
        assert 0 < PLANNER_PRECISION_MATERIAL < 1
        assert PIVOT_YIELD_MATERIAL_PCT > 0
        assert COST_EFFICIENCY_MATERIAL > 0

    def test_lift_threshold_is_10pct(self):
        assert LIFT_MATERIAL_PCT == 10.0

    def test_precision_threshold_sensible(self):
        # Should be between 20% and 50% for realistic scanning
        assert 0.15 <= PRECISION_MATERIAL <= 0.50


# ── Edge Case Tests ───────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_empty_session_no_exception(self):
        session = _Session(findings=[])
        ctx = _make_ctx(tel={})
        with patch("oneinfinity.scan.reactive_effectiveness_store.get_store") as ms:
            ms.return_value.persist_report = MagicMock()
            report = generate_effectiveness_report(session, ctx)
        assert report is not None
        assert report.determination in ("YES", "NO", "INSUFFICIENT_DATA")

    def test_metrics_stay_in_valid_range(self):
        session = _Session(
            findings=_make_baseline_findings(50) + _make_reactive_findings(100)
        )
        tel = _make_tel(generated=100, executed=90, reactive_findings=100, runtime_s=60.0)
        ctx = _make_ctx(tel=tel)
        em = _compute_metrics(session.scan_id, session, ctx, [], [], [])
        # Precision bounded [0, 1]
        assert 0.0 <= em.m5_reactive_precision <= 1.0
        assert 0.0 <= em.m6_planner_precision <= 1.0
        # Percentages non-negative
        assert em.m1_finding_lift_pct >= 0.0
        assert em.m7_pivot_yield_pct >= 0.0

    def test_pivot_records_list_meta(self):
        """Handle pivot meta as list of dicts (not dict)."""
        session = _Session()
        session.phases["exploit_chaining"] = _PhaseResult(
            "exploit_chaining",
            meta={"pivots": [
                {"target": "http://10.0.0.1", "scanned": True, "httpx_findings": 2, "nuclei_findings": 1},
                {"target": "http://10.0.0.2", "scanned": False},
            ]},
        )
        ctx = _make_ctx(tel=_make_tel(piv_gen=2, piv_exec=1))
        records = _collect_pivot_records("test", session, ctx)
        assert len(records) == 2

    def test_report_json_roundtrip(self):
        em = EffectivenessMetrics(
            scan_id="rt-001", target="https://x.com",
            m1_finding_lift_pct=42.0, m1_pass=True,
        )
        report = EffectivenessReport(
            scan_id="rt-001", target="https://x.com",
            generated_at=1234567890.0, metrics=em,
            determination="YES",
        )
        j = report.to_json()
        d = json.loads(j)
        assert d["scan_id"] == "rt-001"
        assert d["metrics"]["m1_finding_lift_pct"] == pytest.approx(42.0, abs=0.01)
