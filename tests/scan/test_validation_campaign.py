"""
Tests for validation_campaign.py

Covers:
  - Static mode disables reactive execution (scan_config overrides)
  - _compute_aggregate: YES/NO/INSUFFICIENT logic
  - render_campaign_reports: all 9 sections present, no exceptions
  - campaign_to_json: round-trips cleanly
  - _cmd_validate_campaign: argparse wiring
"""
from __future__ import annotations

import sys
import json
import time
import pytest

sys.path.insert(0, "src")

from dataclasses import dataclass, field
from typing import Any, List


# ── Stub EffectivenessReport (mirrors real dataclass) ─────────────────────────

@dataclass
class _EM:
    scan_id: str = "test"
    target: str = "http://localhost"
    computed_at: float = 0.0
    total_findings: int = 10
    baseline_findings: int = 6
    reactive_findings: int = 4
    pivot_findings: int = 1
    validated_total: int = 8
    validated_baseline: int = 5
    validated_reactive: int = 3
    total_chains: int = 3
    baseline_chains: int = 2
    reactive_chains: int = 1
    baseline_targets: int = 1
    pivot_targets_generated: int = 2
    pivot_targets_scanned: int = 2
    new_attack_surface: int = 2
    vuln_classes_baseline: int = 3
    vuln_classes_reactive: int = 5
    new_vuln_classes: int = 2
    replans_triggered: int = 2
    actions_generated: int = 8
    actions_executed: int = 6
    actions_skipped: int = 2
    actions_producing_findings: int = 3
    reactive_runtime_s: float = 45.0
    total_runtime_s: float = 120.0
    m1_finding_lift_pct: float = 66.7
    m2_chain_lift_pct: float = 33.3
    m3_ase_yield_pct: float = 200.0
    m4_coverage_improvement: float = 66.7
    m5_reactive_precision: float = 0.75
    m6_planner_precision: float = 0.50
    m7_pivot_yield_pct: float = 50.0
    m8_cost_efficiency: float = 0.067
    m1_pass: bool = True
    m2_pass: bool = True
    m3_pass: bool = True
    m4_pass: bool = True
    m5_pass: bool = True
    m6_pass: bool = True
    m7_pass: bool = True
    m8_pass: bool = True

    @property
    def metrics_passed(self) -> int:
        return sum([self.m1_pass, self.m2_pass, self.m3_pass, self.m4_pass,
                    self.m5_pass, self.m6_pass, self.m7_pass, self.m8_pass])

    def to_dict(self):
        import dataclasses
        return dataclasses.asdict(self)


@dataclass
class _EffReport:
    scan_id: str = "scan-001"
    target: str = "http://localhost"
    generated_at: float = field(default_factory=time.time)
    metrics: _EM = field(default_factory=_EM)
    actions: list = field(default_factory=list)
    replans: list = field(default_factory=list)
    pivots: list = field(default_factory=list)
    determination: str = "YES"
    determination_evidence: List[str] = field(default_factory=lambda: [
        "M1 PASS — Reactive Finding Lift: 66.7%",
        "VERDICT: YES — 8/8 metrics pass",
    ])
    raw_telemetry: dict = field(default_factory=dict)


def _make_pair(
    name="juice-shop",
    url="http://localhost:3000",
    static_det="NO",
    reactive_det="YES",
    reactive_passed=5,
) -> Any:
    from oneinfinity.scan.validation_campaign import ScanPair
    p = ScanPair(target_name=name, target_url=url)

    s_report = _EffReport(
        scan_id=f"{name}-static",
        determination=static_det,
    )
    s_em = _EM(reactive_findings=0, replans_triggered=0, actions_generated=0,
               actions_executed=0, m1_pass=False, m2_pass=False, m3_pass=False,
               m4_pass=False, m5_pass=False, m6_pass=False, m7_pass=False, m8_pass=False)
    s_report.metrics = s_em

    r_report = _EffReport(
        scan_id=f"{name}-reactive",
        determination=reactive_det,
    )
    r_em = _EM()
    # Override metrics_passed via pass bitmask
    pass_flags = [True] * reactive_passed + [False] * (8 - reactive_passed)
    r_em.m1_pass, r_em.m2_pass, r_em.m3_pass, r_em.m4_pass = pass_flags[0:4]
    r_em.m5_pass, r_em.m6_pass, r_em.m7_pass, r_em.m8_pass = pass_flags[4:8]
    r_report.metrics = r_em

    p.static_report = s_report
    p.reactive_report = r_report
    p.static_scan_id = s_report.scan_id
    p.reactive_scan_id = r_report.scan_id
    return p


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestStaticModeConfig:
    """Static mode scan_config overrides disable all reactive execution."""

    def test_static_overrides_zero_out_reactive(self):
        from oneinfinity.scan.validation_campaign import _STATIC_CONFIG_OVERRIDES
        assert _STATIC_CONFIG_OVERRIDES["reactive_max_actions"]  == 0
        assert _STATIC_CONFIG_OVERRIDES["reactive_max_runtime"]  == 0.0
        assert _STATIC_CONFIG_OVERRIDES["reactive_max_replans"]  == 0
        assert _STATIC_CONFIG_OVERRIDES["reactive_max_decisions"] == 0

    def test_static_overrides_are_applied_to_scan_config(self):
        """Merging static overrides into a base config zeroes all reactive knobs."""
        from oneinfinity.scan.validation_campaign import _STATIC_CONFIG_OVERRIDES
        base = {"timeout": 120, "target_type": "web", "reactive_max_actions": 25}
        merged = dict(base)
        merged.update(_STATIC_CONFIG_OVERRIDES)
        assert merged["reactive_max_actions"]  == 0
        assert merged["reactive_max_runtime"]  == 0.0
        assert merged["reactive_max_replans"]  == 0
        # non-reactive keys are preserved
        assert merged["timeout"] == 120


class TestComputeAggregate:
    """_compute_aggregate logic."""

    def test_majority_yes_gives_yes(self):
        from oneinfinity.scan.validation_campaign import CampaignResult, _compute_aggregate
        result = CampaignResult(campaign_id="test", run_at=time.time())
        result.pairs = [
            _make_pair("t1", reactive_det="YES"),
            _make_pair("t2", reactive_det="YES"),
            _make_pair("t3", reactive_det="NO"),
        ]
        result.targets_completed = 3
        _compute_aggregate(result)
        assert result.campaign_determination == "YES"

    def test_all_no_gives_no(self):
        from oneinfinity.scan.validation_campaign import CampaignResult, _compute_aggregate
        result = CampaignResult(campaign_id="test", run_at=time.time())
        result.pairs = [
            _make_pair("t1", reactive_det="NO"),
            _make_pair("t2", reactive_det="NO"),
        ]
        result.targets_completed = 2
        _compute_aggregate(result)
        assert result.campaign_determination == "NO"

    def test_tie_gives_no(self):
        from oneinfinity.scan.validation_campaign import CampaignResult, _compute_aggregate
        result = CampaignResult(campaign_id="test", run_at=time.time())
        result.pairs = [
            _make_pair("t1", reactive_det="YES"),
            _make_pair("t2", reactive_det="NO"),
        ]
        result.targets_completed = 2
        _compute_aggregate(result)
        # tie: yes_count (1) is not > len/2 (1.0), so NO
        assert result.campaign_determination == "NO"

    def test_all_insufficient_gives_insufficient(self):
        from oneinfinity.scan.validation_campaign import CampaignResult, _compute_aggregate
        result = CampaignResult(campaign_id="test", run_at=time.time())
        result.pairs = [
            _make_pair("t1", reactive_det="INSUFFICIENT_DATA"),
        ]
        result.targets_completed = 1
        _compute_aggregate(result)
        assert result.campaign_determination == "INSUFFICIENT_DATA"

    def test_no_completed_gives_insufficient(self):
        from oneinfinity.scan.validation_campaign import CampaignResult, _compute_aggregate
        result = CampaignResult(campaign_id="test", run_at=time.time())
        result.pairs = []
        result.targets_completed = 0
        _compute_aggregate(result)
        assert result.campaign_determination == "INSUFFICIENT_DATA"

    def test_aggregate_stats_computed(self):
        from oneinfinity.scan.validation_campaign import CampaignResult, _compute_aggregate
        result = CampaignResult(campaign_id="test", run_at=time.time())
        result.pairs = [
            _make_pair("t1", reactive_det="YES", reactive_passed=8),
            _make_pair("t2", reactive_det="YES", reactive_passed=4),
        ]
        result.targets_completed = 2
        _compute_aggregate(result)
        # avg metrics_passed = (8+4)/2 = 6
        assert result.agg_metrics_passed == pytest.approx(6.0, abs=0.1)

    def test_evidence_list_populated(self):
        from oneinfinity.scan.validation_campaign import CampaignResult, _compute_aggregate
        result = CampaignResult(campaign_id="test", run_at=time.time())
        result.pairs = [_make_pair("t1", reactive_det="YES")]
        result.targets_completed = 1
        _compute_aggregate(result)
        assert len(result.campaign_evidence) >= 3
        assert any("Aggregate Finding Lift" in ev for ev in result.campaign_evidence)


class TestRenderCampaignReports:
    """render_campaign_reports produces all 9 sections without raising."""

    def _make_result(self, det="YES") -> Any:
        from oneinfinity.scan.validation_campaign import CampaignResult, _compute_aggregate
        result = CampaignResult(campaign_id="c-test", run_at=time.time())
        result.pairs = [
            _make_pair("juice-shop", reactive_det=det),
            _make_pair("dvwa",       reactive_det=det),
        ]
        result.targets_completed = 2
        result.targets_requested = ["juice-shop", "dvwa"]
        _compute_aggregate(result)
        return result

    def test_all_9_report_headers_present(self):
        from oneinfinity.scan.validation_campaign import render_campaign_reports
        text = render_campaign_reports(self._make_result())
        for i in range(1, 10):
            assert f"REPORT {i}" in text, f"Missing REPORT {i}"

    def test_target_names_appear(self):
        from oneinfinity.scan.validation_campaign import render_campaign_reports
        text = render_campaign_reports(self._make_result())
        assert "juice-shop" in text
        assert "dvwa" in text

    def test_campaign_overview_present(self):
        from oneinfinity.scan.validation_campaign import render_campaign_reports
        text = render_campaign_reports(self._make_result())
        assert "CAMPAIGN OVERVIEW" in text
        assert "CAMPAIGN DETERMINATION" in text

    def test_no_exception_for_all_errors(self):
        """Result with all errored pairs should not raise."""
        from oneinfinity.scan.validation_campaign import (
            CampaignResult, ScanPair, _compute_aggregate, render_campaign_reports
        )
        result = CampaignResult(campaign_id="err-test", run_at=time.time())
        p = ScanPair("target-x", "http://x.example.com",
                     static_error="conn refused", reactive_error="conn refused")
        result.pairs = [p]
        result.targets_requested = ["target-x"]
        result.targets_failed = 1
        _compute_aggregate(result)
        text = render_campaign_reports(result)   # must not raise
        assert "target-x" in text


class TestRenderQualityAnalysis:

    def test_finding_quality_analysis_has_precision(self):
        from oneinfinity.scan.validation_campaign import (
            CampaignResult, _compute_aggregate, render_finding_quality_analysis
        )
        result = CampaignResult(campaign_id="qa-test", run_at=time.time())
        result.pairs = [_make_pair("juice-shop")]
        result.targets_completed = 1
        _compute_aggregate(result)
        text = render_finding_quality_analysis(result)
        assert "True Positive" in text
        assert "False Positive" in text
        assert "Reactive Precision" in text

    def test_chain_quality_analysis_has_chain_lift(self):
        from oneinfinity.scan.validation_campaign import (
            CampaignResult, _compute_aggregate, render_chain_quality_analysis
        )
        result = CampaignResult(campaign_id="cq-test", run_at=time.time())
        result.pairs = [_make_pair("juice-shop")]
        result.targets_completed = 1
        _compute_aggregate(result)
        text = render_chain_quality_analysis(result)
        assert "Reactive" in text
        assert "chain lift" in text.lower()


class TestCampaignToJson:
    """campaign_to_json serializes and round-trips cleanly."""

    def test_json_valid(self):
        from oneinfinity.scan.validation_campaign import (
            CampaignResult, _compute_aggregate, campaign_to_json
        )
        result = CampaignResult(campaign_id="json-test", run_at=time.time())
        result.pairs = [_make_pair("t1")]
        result.targets_completed = 1
        result.targets_requested = ["t1"]
        _compute_aggregate(result)
        j = campaign_to_json(result)
        data = json.loads(j)    # must not raise
        assert data["campaign_id"] == "json-test"
        assert len(data["pairs"]) == 1

    def test_json_contains_aggregate(self):
        from oneinfinity.scan.validation_campaign import (
            CampaignResult, _compute_aggregate, campaign_to_json
        )
        result = CampaignResult(campaign_id="json-agg", run_at=time.time())
        result.pairs = [_make_pair("t1", reactive_det="YES")]
        result.targets_completed = 1
        result.targets_requested = ["t1"]
        _compute_aggregate(result)
        data = json.loads(campaign_to_json(result))
        agg = data["aggregate"]
        assert "finding_lift_pct" in agg
        assert "metrics_passed"   in agg

    def test_json_contains_per_target_metrics(self):
        from oneinfinity.scan.validation_campaign import (
            CampaignResult, _compute_aggregate, campaign_to_json
        )
        result = CampaignResult(campaign_id="json-pair", run_at=time.time())
        result.pairs = [_make_pair("juice-shop")]
        result.targets_completed = 1
        result.targets_requested = ["juice-shop"]
        _compute_aggregate(result)
        data = json.loads(campaign_to_json(result))
        pair = data["pairs"][0]
        assert pair["target_name"] == "juice-shop"
        assert pair["reactive_metrics"] is not None
        assert pair["static_metrics"]   is not None

    def test_json_error_pairs_serialise(self):
        """Pairs with errors (no reports) serialize without raising."""
        from oneinfinity.scan.validation_campaign import (
            CampaignResult, ScanPair, _compute_aggregate, campaign_to_json
        )
        result = CampaignResult(campaign_id="err", run_at=time.time())
        p = ScanPair("t-err", "http://err.example.com",
                     static_error="timeout", reactive_error="timeout")
        result.pairs = [p]
        result.targets_failed = 1
        _compute_aggregate(result)
        data = json.loads(campaign_to_json(result))
        assert data["pairs"][0]["static_metrics"] is None


class TestDefaultTargets:
    """Sanity checks on the built-in target registry."""

    def test_all_required_target_categories_present(self):
        from oneinfinity.scan.validation_campaign import DEFAULT_TARGETS
        # Web apps
        assert "juice-shop"  in DEFAULT_TARGETS
        assert "dvwa"        in DEFAULT_TARGETS
        assert "webgoat"     in DEFAULT_TARGETS
        assert "crapi"       in DEFAULT_TARGETS
        # API targets
        assert "graphql"     in DEFAULT_TARGETS
        assert "jwt-target"  in DEFAULT_TARGETS
        assert "rest-api"    in DEFAULT_TARGETS
        # Pivot targets
        assert "ssrf-lab"    in DEFAULT_TARGETS
        assert "internal-discovery" in DEFAULT_TARGETS

    def test_each_target_has_url_and_config(self):
        from oneinfinity.scan.validation_campaign import DEFAULT_TARGETS
        for name, (url, cfg) in DEFAULT_TARGETS.items():
            assert url.startswith("http"), f"{name}: url must be http(s)"
            assert isinstance(cfg, dict), f"{name}: config must be dict"


class TestScanPairBothComplete:

    def test_both_complete_true_when_both_reports_set(self):
        from oneinfinity.scan.validation_campaign import ScanPair
        p = ScanPair("t", "http://t")
        p.static_report   = object()
        p.reactive_report = object()
        assert p.both_complete is True

    def test_both_complete_false_when_one_missing(self):
        from oneinfinity.scan.validation_campaign import ScanPair
        p = ScanPair("t", "http://t")
        p.static_report = object()
        assert p.both_complete is False
