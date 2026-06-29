"""
Reactive Effectiveness Validation Campaign
==========================================

Runs paired Static/Reactive scans against a configured target set and
produces the 9 comparison reports required by the validation spec:

  1. Static vs Reactive Comparison Table
  2. Finding Lift Report
  3. Chain Lift Report
  4. Coverage Improvement Report
  5. Pivot Yield Report
  6. Planner Precision Report
  7. Cost Efficiency Report
  8. Reactive ROI Report
  9. Final Effectiveness Determination

Methodology:
  - Every target is scanned TWICE: Static mode first, then Reactive mode.
  - The only difference between the two runs is reactive execution.
  - scan_config is identical for both runs except for the reactive-disable knobs.
  - Results are persisted to the effectiveness store and returned as a
    CampaignResult for programmatic use or text rendering.

Usage (Python API):
    from oneinfinity.scan.validation_campaign import run_campaign, render_campaign_reports
    result = run_campaign()        # uses built-in target set
    print(render_campaign_reports(result))

Usage (CLI):
    python -m oneinfinity reactive validate_campaign
    python -m oneinfinity reactive validate_campaign --targets juice-shop dvwa webgoat
    python -m oneinfinity reactive validate_campaign --output campaign_report.txt
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.validation_campaign")


# ── Static mode knobs ──────────────────────────────────────────────────────────
# Setting both to 0 disables ALL reactive execution (replans, actions, pivots).
_STATIC_CONFIG_OVERRIDES: Dict[str, Any] = {
    "reactive_max_actions":  0,
    "reactive_max_runtime":  0.0,
    "reactive_max_replans":  0,
    "reactive_max_decisions": 0,
}

# ── Default target registry ────────────────────────────────────────────────────
# Keys are friendly names; values are (target_url, base_scan_config).
# Operators must update target_url to match their lab environment.
DEFAULT_TARGETS: Dict[str, Tuple[str, Dict[str, Any]]] = {
    # Web Applications
    "juice-shop": (
        "http://localhost:3000",
        {"target_type": "web", "timeout": 120},
    ),
    "dvwa": (
        "http://localhost:80",
        {
            "target_type": "web",
            "cookies": {"PHPSESSID": "", "security": "low"},
            "timeout": 120,
        },
    ),
    "webgoat": (
        "http://localhost:8080/WebGoat",
        {"target_type": "web", "timeout": 120},
    ),
    "crapi": (
        "http://localhost:8888",
        {"target_type": "web", "timeout": 120},
    ),
    # API Targets
    "graphql": (
        "http://localhost:4000/graphql",
        {"target_type": "api", "api_type": "graphql", "timeout": 90},
    ),
    "jwt-target": (
        "http://localhost:9000",
        {"target_type": "api", "api_type": "jwt", "timeout": 90},
    ),
    "rest-api": (
        "http://localhost:7000",
        {"target_type": "api", "api_type": "rest", "timeout": 90},
    ),
    # Pivot Targets
    "ssrf-lab": (
        "http://localhost:5000",
        {"target_type": "web", "ssrf_enabled": True, "timeout": 120},
    ),
    "internal-discovery": (
        "http://localhost:6000",
        {"target_type": "web", "ssrf_enabled": True, "timeout": 120},
    ),
}


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class ScanPair:
    """A matched (static, reactive) scan pair for one target."""
    target_name:  str
    target_url:   str
    static_scan_id:   str = ""
    reactive_scan_id: str = ""
    static_report:    Optional[Any] = None   # EffectivenessReport
    reactive_report:  Optional[Any] = None   # EffectivenessReport
    static_error:     str = ""
    reactive_error:   str = ""
    static_runtime_s:   float = 0.0
    reactive_runtime_s: float = 0.0

    @property
    def both_complete(self) -> bool:
        return bool(self.static_report and self.reactive_report)


@dataclass
class CampaignResult:
    """Complete campaign result: all target pairs + aggregate stats."""
    campaign_id:  str
    run_at:       float
    pairs:        List[ScanPair] = field(default_factory=list)
    targets_requested: List[str] = field(default_factory=list)
    targets_completed: int = 0
    targets_failed:    int = 0

    # Aggregate: averaged across targets that completed both modes
    agg_static_findings:   float = 0.0
    agg_reactive_findings: float = 0.0
    agg_finding_lift_pct:  float = 0.0
    agg_chain_lift_pct:    float = 0.0
    agg_coverage_pct:      float = 0.0
    agg_planner_precision: float = 0.0
    agg_pivot_yield_pct:   float = 0.0
    agg_cost_efficiency:   float = 0.0
    agg_metrics_passed:    float = 0.0  # avg metrics passing per scan

    # Cross-campaign verdict
    campaign_determination: str = "INSUFFICIENT_DATA"
    campaign_evidence:      List[str] = field(default_factory=list)


# ── Core runner ────────────────────────────────────────────────────────────────

def _run_single_scan(
    target_url: str,
    base_config: Dict[str, Any],
    reactive_enabled: bool,
    label: str,
) -> Tuple[Optional[Any], Optional[Any], str]:
    """
    Execute one scan.  Returns (session, effectiveness_report, error_str).

    Reactive is disabled by merging _STATIC_CONFIG_OVERRIDES when
    reactive_enabled=False.  No other config difference.
    """
    scan_config = dict(base_config)
    if not reactive_enabled:
        scan_config.update(_STATIC_CONFIG_OVERRIDES)

    mode = "REACTIVE" if reactive_enabled else "STATIC"
    log.info("[Campaign] %s scan starting: target=%s label=%s", mode, target_url, label)

    try:
        from oneinfinity.scan.unified_scan_engine import run_unified_scan
        session = run_unified_scan(target=target_url, scan_config=scan_config)
    except Exception as exc:
        err = f"{mode} scan failed for {label}: {exc}"
        log.error("[Campaign] %s", err)
        return None, None, err

    # The report is generated automatically in _phase_done and persisted to the store.
    # Retrieve it from the store (it has the rendered text ready).
    report = None
    try:
        from oneinfinity.scan.reactive_effectiveness_store import get_store
        scan_id = getattr(session, "scan_id", None)
        if scan_id:
            store = get_store()
            report_dict = store.get_full_report_json(scan_id)
            if report_dict:
                report = _dict_to_report(report_dict)
    except Exception as exc:
        log.warning("[Campaign] Could not retrieve report from store: %s", exc)

    # If store retrieval failed, generate report directly from session
    if report is None:
        try:
            from oneinfinity.scan.reactive_effectiveness import generate_effectiveness_report
            ctx = getattr(session, "_ctx", {}) or {}
            report = generate_effectiveness_report(session, ctx)
        except Exception as exc:
            log.warning("[Campaign] Inline report generation failed: %s", exc)

    log.info(
        "[Campaign] %s scan done: label=%s findings=%d",
        mode, label, len(getattr(session, "findings", [])),
    )
    return session, report, ""


def run_campaign(
    target_names: Optional[List[str]] = None,
    extra_targets: Optional[Dict[str, Tuple[str, Dict[str, Any]]]] = None,
    timeout_per_scan_s: float = 600.0,
) -> CampaignResult:
    """
    Run the full Static vs Reactive validation campaign.

    Args:
        target_names: subset of DEFAULT_TARGETS keys to run; None = all.
        extra_targets: additional {name: (url, config)} entries beyond defaults.
        timeout_per_scan_s: wall-clock cap per individual scan (not enforced
            here — passed to scan_config as 'timeout' if not already set).

    Returns:
        CampaignResult with all pairs populated and aggregate stats computed.
    """
    campaign_id = f"campaign-{uuid.uuid4().hex[:8]}"
    log.info("[Campaign] Starting campaign %s", campaign_id)

    # Build target registry
    registry: Dict[str, Tuple[str, Dict[str, Any]]] = dict(DEFAULT_TARGETS)
    if extra_targets:
        registry.update(extra_targets)

    if target_names:
        unknown = [n for n in target_names if n not in registry]
        if unknown:
            log.warning("[Campaign] Unknown target names (skipped): %s", unknown)
        names = [n for n in target_names if n in registry]
    else:
        names = list(registry.keys())

    result = CampaignResult(
        campaign_id=campaign_id,
        run_at=time.time(),
        targets_requested=names,
    )

    for name in names:
        url, base_cfg = registry[name]
        # Ensure a minimum timeout is set
        cfg = dict(base_cfg)
        cfg.setdefault("timeout", int(timeout_per_scan_s))

        pair = ScanPair(target_name=name, target_url=url)

        # ── Static scan ────────────────────────────────────────────────────
        t0 = time.time()
        static_session, static_report, static_err = _run_single_scan(
            url, cfg, reactive_enabled=False, label=f"{name}/static"
        )
        pair.static_runtime_s = time.time() - t0
        if static_err:
            pair.static_error = static_err
        else:
            pair.static_report = static_report
            pair.static_scan_id = getattr(static_session, "scan_id", "")

        # ── Reactive scan ──────────────────────────────────────────────────
        t0 = time.time()
        reactive_session, reactive_report, reactive_err = _run_single_scan(
            url, cfg, reactive_enabled=True, label=f"{name}/reactive"
        )
        pair.reactive_runtime_s = time.time() - t0
        if reactive_err:
            pair.reactive_error = reactive_err
        else:
            pair.reactive_report = reactive_report
            pair.reactive_scan_id = getattr(reactive_session, "scan_id", "")

        result.pairs.append(pair)
        if pair.both_complete:
            result.targets_completed += 1
        else:
            result.targets_failed += 1

    _compute_aggregate(result)
    log.info(
        "[Campaign] Done: id=%s completed=%d failed=%d determination=%s",
        campaign_id, result.targets_completed, result.targets_failed,
        result.campaign_determination,
    )
    return result


def _compute_aggregate(result: CampaignResult) -> None:
    """Compute aggregate stats and cross-campaign determination from pairs."""
    completed = [p for p in result.pairs if p.both_complete]
    if not completed:
        result.campaign_determination = "INSUFFICIENT_DATA"
        result.campaign_evidence = [
            "INSUFFICIENT_DATA: No target pairs completed both Static and Reactive scans."
        ]
        return

    def _avg(attr: str, obj_attr: str) -> float:
        vals = []
        for p in completed:
            r = getattr(p, attr)
            if r is not None:
                v = getattr(r.metrics, obj_attr, 0.0)
                vals.append(float(v))
        return sum(vals) / len(vals) if vals else 0.0

    # Static baseline aggregates (from static_report.metrics)
    static_findings_vals  = []
    reactive_findings_vals = []
    lift_vals    = []
    chain_vals   = []
    cov_vals     = []
    plan_vals    = []
    pivot_vals   = []
    cost_vals    = []
    passed_vals  = []

    for p in completed:
        sm = p.static_report.metrics
        rm = p.reactive_report.metrics
        static_findings_vals.append(float(sm.total_findings))
        reactive_findings_vals.append(float(rm.reactive_findings))
        lift_vals.append(rm.m1_finding_lift_pct)
        chain_vals.append(rm.m2_chain_lift_pct)
        cov_vals.append(rm.m4_coverage_improvement)
        plan_vals.append(rm.m6_planner_precision * 100)
        pivot_vals.append(rm.m7_pivot_yield_pct)
        cost_vals.append(rm.m8_cost_efficiency)
        passed_vals.append(float(rm.metrics_passed))

    def _mean(v: list) -> float:
        return sum(v) / len(v) if v else 0.0

    result.agg_static_findings   = _mean(static_findings_vals)
    result.agg_reactive_findings = _mean(reactive_findings_vals)
    result.agg_finding_lift_pct  = _mean(lift_vals)
    result.agg_chain_lift_pct    = _mean(chain_vals)
    result.agg_coverage_pct      = _mean(cov_vals)
    result.agg_planner_precision = _mean(plan_vals)
    result.agg_pivot_yield_pct   = _mean(pivot_vals)
    result.agg_cost_efficiency   = _mean(cost_vals)
    result.agg_metrics_passed    = _mean(passed_vals)

    # Per-target YES/NO counts
    yes_count = sum(
        1 for p in completed
        if p.reactive_report.determination == "YES"
    )
    no_count  = sum(
        1 for p in completed
        if p.reactive_report.determination == "NO"
    )
    insuf_count = len(completed) - yes_count - no_count

    evidence: List[str] = []

    # Criterion: majority of completed targets return YES
    if yes_count > len(completed) / 2:
        result.campaign_determination = "YES"
        evidence.append(
            f"CAMPAIGN VERDICT: YES — {yes_count}/{len(completed)} targets returned "
            f"YES determination (majority threshold met)."
        )
    elif no_count >= len(completed):
        result.campaign_determination = "NO"
        evidence.append(
            f"CAMPAIGN VERDICT: NO — all {no_count}/{len(completed)} targets returned "
            f"NO determination."
        )
    elif insuf_count == len(completed):
        result.campaign_determination = "INSUFFICIENT_DATA"
        evidence.append(
            f"CAMPAIGN VERDICT: INSUFFICIENT_DATA — all {len(completed)} targets "
            f"returned INSUFFICIENT_DATA (reactive execution may not have triggered)."
        )
    else:
        result.campaign_determination = "NO"
        evidence.append(
            f"CAMPAIGN VERDICT: NO — only {yes_count}/{len(completed)} targets met "
            f"the YES threshold (majority not reached; {no_count} NO, {insuf_count} INSUFFICIENT)."
        )

    # Evidence from aggregates
    evidence.append(
        f"Aggregate Finding Lift: {result.agg_finding_lift_pct:.1f}% across {len(completed)} targets "
        f"(static avg {result.agg_static_findings:.1f} → reactive avg +{result.agg_reactive_findings:.1f})."
    )
    evidence.append(
        f"Aggregate Chain Lift: {result.agg_chain_lift_pct:.1f}% | "
        f"Coverage Improvement: {result.agg_coverage_pct:.1f}%."
    )
    evidence.append(
        f"Aggregate Planner Precision: {result.agg_planner_precision:.1f}% | "
        f"Pivot Yield: {result.agg_pivot_yield_pct:.1f}%."
    )
    evidence.append(
        f"Aggregate Cost Efficiency: {result.agg_cost_efficiency:.4f} validated findings/s."
    )
    evidence.append(
        f"Average metrics passed per reactive scan: {result.agg_metrics_passed:.1f}/8."
    )

    result.campaign_evidence = evidence


# ── Report rendering ───────────────────────────────────────────────────────────

def render_campaign_reports(result: CampaignResult) -> str:
    """Render all 9 campaign comparison reports as a single text block."""
    sections: List[str] = []
    _H  = "═" * 80
    _h2 = "─" * 80

    def _sec(title: str, body: str) -> None:
        sections.append(_H)
        sections.append(f"  {title}")
        sections.append(_H)
        sections.append(body)
        sections.append("")

    # ── Campaign header ────────────────────────────────────────────────────────
    import datetime as _dt
    ts = _dt.datetime.fromtimestamp(result.run_at).strftime("%Y-%m-%d %H:%M:%S")
    header_lines = [
        f"  REACTIVE EFFECTIVENESS VALIDATION CAMPAIGN",
        f"  Campaign ID : {result.campaign_id}",
        f"  Run at      : {ts}",
        f"  Targets     : {', '.join(result.targets_requested) or '(none)'}",
        f"  Completed   : {result.targets_completed}/{len(result.targets_requested)}",
        f"  Failed      : {result.targets_failed}",
        f"  Determination: {result.campaign_determination}",
    ]
    _sec("CAMPAIGN OVERVIEW", "\n".join(header_lines))

    # ── Report 1: Static vs Reactive Comparison Table ─────────────────────────
    r1_lines = [
        f"  {'Target':<22}  {'Static Findings':>16}  {'Reactive Findings':>18}  "
        f"{'Lift %':>8}  {'Determination':>18}",
        "  " + _h2[2:],
    ]
    for p in result.pairs:
        sf  = p.static_report.metrics.total_findings   if p.static_report   else "ERR"
        rf  = p.reactive_report.metrics.reactive_findings if p.reactive_report else "ERR"
        lft = f"{p.reactive_report.metrics.m1_finding_lift_pct:.1f}%" if p.reactive_report else "N/A"
        det = p.reactive_report.determination if p.reactive_report else "ERROR"
        r1_lines.append(
            f"  {p.target_name:<22}  {str(sf):>16}  {str(rf):>18}  {lft:>8}  {det:>18}"
        )
    r1_lines.extend([
        "  " + _h2[2:],
        f"  AGGREGATE{'':13}  {result.agg_static_findings:>16.1f}  "
        f"{result.agg_reactive_findings:>18.1f}  "
        f"{result.agg_finding_lift_pct:>7.1f}%  "
        f"{result.campaign_determination:>18}",
    ])
    _sec("REPORT 1 — Static vs Reactive Comparison Table", "\n".join(r1_lines))

    # ── Report 2: Finding Lift ─────────────────────────────────────────────────
    r2_lines = [
        f"  {'Target':<22}  {'Baseline':>10}  {'Reactive':>10}  "
        f"{'Validated React.':>18}  {'Lift %':>8}  {'Pass':>6}",
        "  " + _h2[2:],
    ]
    for p in result.pairs:
        if not p.reactive_report:
            r2_lines.append(f"  {p.target_name:<22}  {'ERROR':>10}")
            continue
        em = p.reactive_report.metrics
        r2_lines.append(
            f"  {p.target_name:<22}  {em.baseline_findings:>10}  {em.reactive_findings:>10}  "
            f"{em.validated_reactive:>18}  {em.m1_finding_lift_pct:>7.1f}%  "
            f"{'YES' if em.m1_pass else 'NO':>6}"
        )
    _sec("REPORT 2 — Reactive Finding Lift Report", "\n".join(r2_lines))

    # ── Report 3: Chain Lift ───────────────────────────────────────────────────
    r3_lines = [
        f"  {'Target':<22}  {'Total Chains':>13}  {'Baseline Chains':>16}  "
        f"{'Reactive Chains':>16}  {'Lift %':>8}  {'Pass':>6}",
        "  " + _h2[2:],
    ]
    for p in result.pairs:
        if not p.reactive_report:
            r3_lines.append(f"  {p.target_name:<22}  {'ERROR':>13}")
            continue
        em = p.reactive_report.metrics
        r3_lines.append(
            f"  {p.target_name:<22}  {em.total_chains:>13}  {em.baseline_chains:>16}  "
            f"{em.reactive_chains:>16}  {em.m2_chain_lift_pct:>7.1f}%  "
            f"{'YES' if em.m2_pass else 'NO':>6}"
        )
    _sec("REPORT 3 — Reactive Chain Lift Report", "\n".join(r3_lines))

    # ── Report 4: Coverage Improvement ────────────────────────────────────────
    r4_lines = [
        f"  {'Target':<22}  {'Baseline Classes':>17}  {'Reactive Classes':>17}  "
        f"{'New Classes':>12}  {'Impr %':>8}  {'Pass':>6}",
        "  " + _h2[2:],
    ]
    for p in result.pairs:
        if not p.reactive_report:
            r4_lines.append(f"  {p.target_name:<22}  {'ERROR':>17}")
            continue
        em = p.reactive_report.metrics
        r4_lines.append(
            f"  {p.target_name:<22}  {em.vuln_classes_baseline:>17}  "
            f"{em.vuln_classes_reactive:>17}  {em.new_vuln_classes:>12}  "
            f"{em.m4_coverage_improvement:>7.1f}%  {'YES' if em.m4_pass else 'NO':>6}"
        )
    _sec("REPORT 4 — Coverage Improvement Report", "\n".join(r4_lines))

    # ── Report 5: Pivot Yield ─────────────────────────────────────────────────
    r5_lines = [
        f"  {'Target':<22}  {'Pivots Gen.':>12}  {'Pivots Scan.':>13}  "
        f"{'Pivot Findings':>15}  {'Yield %':>8}  {'Pass':>6}",
        "  " + _h2[2:],
    ]
    for p in result.pairs:
        if not p.reactive_report:
            r5_lines.append(f"  {p.target_name:<22}  {'ERROR':>12}")
            continue
        em = p.reactive_report.metrics
        r5_lines.append(
            f"  {p.target_name:<22}  {em.pivot_targets_generated:>12}  "
            f"{em.pivot_targets_scanned:>13}  {em.pivot_findings:>15}  "
            f"{em.m7_pivot_yield_pct:>7.1f}%  {'YES' if em.m7_pass else 'NO':>6}"
        )
    _sec("REPORT 5 — Pivot Yield Report", "\n".join(r5_lines))

    # ── Report 6: Planner Precision ───────────────────────────────────────────
    r6_lines = [
        f"  {'Target':<22}  {'Replans':>8}  {'Generated':>10}  "
        f"{'Executed':>10}  {'Productive':>11}  {'Precision %':>12}  {'Pass':>6}",
        "  " + _h2[2:],
    ]
    for p in result.pairs:
        if not p.reactive_report:
            r6_lines.append(f"  {p.target_name:<22}  {'ERROR':>8}")
            continue
        em = p.reactive_report.metrics
        r6_lines.append(
            f"  {p.target_name:<22}  {em.replans_triggered:>8}  "
            f"{em.actions_generated:>10}  {em.actions_executed:>10}  "
            f"{em.actions_producing_findings:>11}  "
            f"{em.m6_planner_precision*100:>11.1f}%  "
            f"{'YES' if em.m6_pass else 'NO':>6}"
        )
    _sec("REPORT 6 — Planner Precision Report", "\n".join(r6_lines))

    # ── Report 7: Cost Efficiency ─────────────────────────────────────────────
    r7_lines = [
        f"  {'Target':<22}  {'React. Runtime(s)':>18}  {'Total Runtime(s)':>17}  "
        f"{'Val.React.':>11}  {'Efficiency':>12}  {'Pass':>6}",
        "  " + _h2[2:],
    ]
    for p in result.pairs:
        if not p.reactive_report:
            r7_lines.append(f"  {p.target_name:<22}  {'ERROR':>18}")
            continue
        em = p.reactive_report.metrics
        r7_lines.append(
            f"  {p.target_name:<22}  {em.reactive_runtime_s:>18.1f}  "
            f"{em.total_runtime_s:>17.1f}  {em.validated_reactive:>11}  "
            f"{em.m8_cost_efficiency:>12.4f}  "
            f"{'YES' if em.m8_pass else 'NO':>6}"
        )
    r7_lines.append(
        f"  {'AGGREGATE':<22}  {result.agg_cost_efficiency:>67.4f}"
    )
    _sec("REPORT 7 — Cost Efficiency Report", "\n".join(r7_lines))

    # ── Report 8: Reactive ROI ────────────────────────────────────────────────
    r8_lines = []
    for p in result.pairs:
        if not p.reactive_report:
            r8_lines.append(f"  {p.target_name}: ERROR — {p.reactive_error or p.static_error}")
            continue
        from oneinfinity.scan.reactive_effectiveness import render_roi_table
        r8_lines.append(f"  Target: {p.target_name}  ({p.target_url})")
        roi_text = render_roi_table(p.reactive_report)
        for line in roi_text.splitlines():
            r8_lines.append("  " + line)
        r8_lines.append("")
    _sec("REPORT 8 — Reactive ROI Report", "\n".join(r8_lines))

    # ── Report 9: Final Effectiveness Determination ───────────────────────────
    r9_lines = [
        f"  CAMPAIGN DETERMINATION: {result.campaign_determination}",
        "",
        "  Evidence:",
    ]
    for ev in result.campaign_evidence:
        r9_lines.append(f"    {ev}")
    r9_lines.append("")
    r9_lines.append("  Per-Target Determinations:")
    r9_lines.append(f"  {'Target':<22}  {'Static Findings':>16}  {'Determination':>16}  "
                    f"{'Metrics Passed':>15}  {'Finding Lift':>13}")
    r9_lines.append("  " + _h2[2:])
    for p in result.pairs:
        det = p.reactive_report.determination if p.reactive_report else "ERROR"
        sf  = p.static_report.metrics.total_findings if p.static_report else "N/A"
        mp  = p.reactive_report.metrics.metrics_passed if p.reactive_report else "N/A"
        lft = (f"{p.reactive_report.metrics.m1_finding_lift_pct:.1f}%"
               if p.reactive_report else "N/A")
        r9_lines.append(
            f"  {p.target_name:<22}  {str(sf):>16}  {det:>16}  {str(mp):>15}  {lft:>13}"
        )
    r9_lines.extend([
        "",
        "  Detailed Per-Target Determination Evidence:",
    ])
    for p in result.pairs:
        if p.reactive_report:
            r9_lines.append(f"  ── {p.target_name} ──")
            for ev in p.reactive_report.determination_evidence:
                r9_lines.append(f"    {ev}")
            r9_lines.append("")
    _sec("REPORT 9 — Final Effectiveness Determination", "\n".join(r9_lines))

    return "\n".join(sections)


def render_finding_quality_analysis(result: CampaignResult) -> str:
    """
    Finding Quality Analysis: classify reactive-only findings by TP/FP/Dup/Info.

    Classification is derived from the finding's confidence and validation status
    as recorded in the effectiveness store — no new validation logic.
    """
    lines = ["═" * 80, "  FINDING QUALITY ANALYSIS (Reactive-Only Findings)", "═" * 80]
    for p in result.pairs:
        if not p.reactive_report:
            continue
        em = p.reactive_report.metrics
        lines.append(f"  Target: {p.target_name}")
        lines.append(f"  {'Classification':<18}  {'Count':>8}  {'Notes'}")
        lines.append("  " + "─" * 60)
        tp  = em.validated_reactive
        tot = em.reactive_findings
        fp  = max(0, tot - tp)
        lines.append(f"  {'True Positive':<18}  {tp:>8}  (validated by finding_validation_engine)")
        lines.append(f"  {'False Positive':<18}  {fp:>8}  (not validated; may be over-estimate)")
        lines.append(f"  {'Duplicate':<18}  {'--':>8}  (dedup handled by fingerprint in engine)")
        lines.append(f"  {'Informational':<18}  {'--':>8}  (severity=info not separately tracked)")
        prec = em.m5_reactive_precision * 100
        lines.append(f"  Reactive Precision (TP rate): {prec:.1f}%  "
                     f"({'PASS' if em.m5_pass else 'FAIL'})")
        lines.append("")
    return "\n".join(lines)


def render_chain_quality_analysis(result: CampaignResult) -> str:
    """
    Chain Quality Analysis: reactive-only chains classified by exploitability.

    Exploitability is determined from the chain records stored in the
    effectiveness report.  The engine already rejects heuristic-only and
    impossible chains during _phase_exploit_chaining.
    """
    lines = ["═" * 80, "  CHAIN QUALITY ANALYSIS (Reactive-Only Chains)", "═" * 80]
    for p in result.pairs:
        if not p.reactive_report:
            continue
        em = p.reactive_report.metrics
        lines.append(f"  Target: {p.target_name}")
        lines.append(
            f"  Total chains: {em.total_chains}  "
            f"Baseline: {em.baseline_chains}  "
            f"Reactive: {em.reactive_chains}"
        )
        lines.append(f"  Reactive chain lift: {em.m2_chain_lift_pct:.1f}%  "
                     f"({'PASS' if em.m2_pass else 'FAIL'})")
        lines.append("  Note: Chains are pre-filtered by exploit_chain_engine — "
                     "impossible/heuristic-only chains are excluded at ingestion.")
        lines.append("")
    return "\n".join(lines)


# ── dict → EffectivenessReport reconstruction ─────────────────────────────────

def _dict_to_report(data: dict) -> Any:
    """Reconstruct EffectivenessReport from store JSON."""
    from oneinfinity.scan.reactive_effectiveness import (
        EffectivenessReport, EffectivenessMetrics,
        ActionRecord, ReplanRecord, PivotRecord,
    )
    m_data = data.get("metrics", {})
    metrics = EffectivenessMetrics(**{
        k: v for k, v in m_data.items()
        if k in EffectivenessMetrics.__dataclass_fields__
    }) if m_data else EffectivenessMetrics(
        scan_id=data.get("scan_id", ""),
        target=data.get("target", ""),
    )

    def _load_actions(lst):
        out = []
        for d in (lst or []):
            try:
                out.append(ActionRecord(**{
                    k: v for k, v in d.items()
                    if k in ActionRecord.__dataclass_fields__
                }))
            except Exception:
                pass
        return out

    def _load_replans(lst):
        out = []
        for d in (lst or []):
            try:
                from oneinfinity.scan.reactive_effectiveness import ReplanRecord
                out.append(ReplanRecord(**{
                    k: v for k, v in d.items()
                    if k in ReplanRecord.__dataclass_fields__
                }))
            except Exception:
                pass
        return out

    def _load_pivots(lst):
        out = []
        for d in (lst or []):
            try:
                from oneinfinity.scan.reactive_effectiveness import PivotRecord
                out.append(PivotRecord(**{
                    k: v for k, v in d.items()
                    if k in PivotRecord.__dataclass_fields__
                }))
            except Exception:
                pass
        return out

    return EffectivenessReport(
        scan_id=data.get("scan_id", ""),
        target=data.get("target", ""),
        generated_at=float(data.get("generated_at", 0.0)),
        metrics=metrics,
        actions=_load_actions(data.get("actions", [])),
        replans=_load_replans(data.get("replans", [])),
        pivots=_load_pivots(data.get("pivots", [])),
        determination=data.get("determination", "INSUFFICIENT_DATA"),
        determination_evidence=list(data.get("determination_evidence", [])),
        raw_telemetry=dict(data.get("raw_telemetry", {})),
    )


# ── Serialization ──────────────────────────────────────────────────────────────

def campaign_to_json(result: CampaignResult) -> str:
    """Serialize CampaignResult to JSON (scan pairs include metric dicts)."""
    pairs_out = []
    for p in result.pairs:
        pairs_out.append({
            "target_name":        p.target_name,
            "target_url":         p.target_url,
            "static_scan_id":     p.static_scan_id,
            "reactive_scan_id":   p.reactive_scan_id,
            "static_error":       p.static_error,
            "reactive_error":     p.reactive_error,
            "static_runtime_s":   p.static_runtime_s,
            "reactive_runtime_s": p.reactive_runtime_s,
            "static_metrics":  p.static_report.metrics.to_dict()   if p.static_report   else None,
            "reactive_metrics": p.reactive_report.metrics.to_dict() if p.reactive_report else None,
            "static_determination":   (p.static_report.determination   if p.static_report   else None),
            "reactive_determination": (p.reactive_report.determination if p.reactive_report else None),
        })

    out = {
        "campaign_id":             result.campaign_id,
        "run_at":                  result.run_at,
        "targets_requested":       result.targets_requested,
        "targets_completed":       result.targets_completed,
        "targets_failed":          result.targets_failed,
        "campaign_determination":  result.campaign_determination,
        "campaign_evidence":       result.campaign_evidence,
        "aggregate": {
            "static_findings":   result.agg_static_findings,
            "reactive_findings": result.agg_reactive_findings,
            "finding_lift_pct":  result.agg_finding_lift_pct,
            "chain_lift_pct":    result.agg_chain_lift_pct,
            "coverage_pct":      result.agg_coverage_pct,
            "planner_precision": result.agg_planner_precision,
            "pivot_yield_pct":   result.agg_pivot_yield_pct,
            "cost_efficiency":   result.agg_cost_efficiency,
            "metrics_passed":    result.agg_metrics_passed,
        },
        "pairs": pairs_out,
    }
    return json.dumps(out, indent=2, default=str)
