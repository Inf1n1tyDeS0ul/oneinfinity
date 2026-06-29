"""
CLI command handlers for Reactive Effectiveness Program.

Commands:
  oneinfinity reactive report <scan_id>     — show full effectiveness report
  oneinfinity reactive dashboard <scan_id>  — show dashboard only
  oneinfinity reactive list                 — list all effectiveness reports
  oneinfinity reactive roi <scan_id>        — ROI metrics table
  oneinfinity reactive determination <scan_id> — show final YES/NO verdict

Usage (after a scan completes):
  python -m oneinfinity reactive report <scan_id>
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Optional

log = logging.getLogger(__name__)


def _get_store():
    from oneinfinity.scan.reactive_effectiveness_store import get_store
    return get_store()


def cmd_reactive(args):
    """Entry point dispatched by argparse."""
    sub = getattr(args, "subcommand", None) or "help"

    if sub == "report":
        return _cmd_report(args)
    elif sub == "dashboard":
        return _cmd_dashboard(args)
    elif sub == "list":
        return _cmd_list(args)
    elif sub == "roi":
        return _cmd_roi(args)
    elif sub == "determination":
        return _cmd_determination(args)
    elif sub == "json":
        return _cmd_json(args)
    elif sub == "run":
        return _cmd_run(args)
    elif sub == "validate_campaign":
        return _cmd_validate_campaign(args)
    else:
        print("Usage: oneinfinity reactive <report|dashboard|list|roi|determination|json|run|validate_campaign>")
        print("  report <scan_id>         Full effectiveness report")
        print("  dashboard <scan_id>      Dashboard only")
        print("  list                     List all reports")
        print("  roi <scan_id>            ROI metrics table")
        print("  determination <scan_id>  Final YES/NO verdict with evidence")
        print("  json <scan_id>           Full report as JSON")
        print("  run <target>             Run a scan and show effectiveness report")
        print("  validate_campaign        Run Static vs Reactive validation campaign")


def _require_scan_id(args) -> Optional[str]:
    scan_id = getattr(args, "scan_id", None)
    if not scan_id:
        print("ERROR: scan_id required.", file=sys.stderr)
        sys.exit(1)
    return scan_id


def _cmd_report(args):
    """Show full effectiveness report for a scan."""
    scan_id = _require_scan_id(args)
    store   = _get_store()

    # Try text report first (fastest)
    text = store.get_text_report(scan_id)
    if text:
        print(text)
        return

    # Try to reconstruct from JSON
    data = store.get_full_report_json(scan_id)
    if data:
        _print_report_from_dict(data)
        return

    print(f"No effectiveness report found for scan_id: {scan_id}", file=sys.stderr)
    print("Run a scan first — the report is generated automatically at scan completion.",
          file=sys.stderr)
    sys.exit(1)


def _cmd_dashboard(args):
    """Show dashboard section only."""
    scan_id = _require_scan_id(args)
    store   = _get_store()

    data = store.get_full_report_json(scan_id)
    if not data:
        print(f"No report for {scan_id}", file=sys.stderr)
        sys.exit(1)

    try:
        from oneinfinity.scan.reactive_effectiveness import (
            EffectivenessReport, EffectivenessMetrics, render_dashboard,
        )
        report = _dict_to_report(data)
        print(render_dashboard(report))
    except Exception as exc:
        log.debug("Dashboard render failed, falling back to text: %s", exc)
        text = store.get_text_report(scan_id)
        if text:
            # Print first section up to ROI table
            print(text.split("┌─ REACTIVE ROI")[0])
        else:
            print(f"Dashboard unavailable for {scan_id}")


def _cmd_list(args):
    """List all effectiveness reports."""
    store   = _get_store()
    reports = store.list_reports(limit=getattr(args, "limit", 50))

    if not reports:
        print("No effectiveness reports found.")
        print("Reports are generated automatically when scans complete.")
        return

    # Header
    w = 80
    print("─" * w)
    print(f"{'SCAN ID':<38}  {'TARGET':<20}  {'DET':>4}  {'M':>2}  {'LIFT':>7}")
    print("─" * w)
    for r in reports:
        det = {
            "YES":              "YES",
            "NO":               "NO ",
            "INSUFFICIENT_DATA": "INS",
        }.get(str(r.get("determination", "")), "???")
        target_short = str(r.get("target", ""))[:20]
        scan_short   = str(r.get("scan_id", ""))[:38]
        passed       = int(r.get("metrics_passed", 0))
        lift         = float(r.get("m1_finding_lift_pct", 0.0))
        print(f"{scan_short:<38}  {target_short:<20}  {det:>4}  {passed:>2}  {lift:>6.1f}%")
    print("─" * w)
    print(f"Total: {len(reports)} report(s)")


def _cmd_roi(args):
    """Show ROI metrics table."""
    scan_id = _require_scan_id(args)
    store   = _get_store()
    data = store.get_full_report_json(scan_id)
    if not data:
        print(f"No report for {scan_id}", file=sys.stderr)
        sys.exit(1)
    try:
        from oneinfinity.scan.reactive_effectiveness import render_roi_table
        report = _dict_to_report(data)
        print(render_roi_table(report))
    except Exception as exc:
        print(f"ROI table error: {exc}", file=sys.stderr)
        sys.exit(1)


def _cmd_determination(args):
    """Show final YES/NO determination with evidence."""
    scan_id = _require_scan_id(args)
    store   = _get_store()
    data = store.get_full_report_json(scan_id)
    if not data:
        print(f"No report for {scan_id}", file=sys.stderr)
        sys.exit(1)

    det  = data.get("determination", "UNKNOWN")
    evid = data.get("determination_evidence", [])
    m    = data.get("metrics", {})

    print("=" * 70)
    print(f"REACTIVE EFFECTIVENESS DETERMINATION")
    print(f"Scan: {scan_id}")
    print(f"Target: {data.get('target', '')}")
    print("=" * 70)
    print(f"\nVERDICT: {det}\n")
    print(f"Metrics passed: {m.get('metrics_passed', '?')}/8\n")
    print("EVIDENCE:")
    print("-" * 70)
    for line in evid:
        # Word-wrap
        for chunk in _wrap(line, 68):
            print(f"  {chunk}")
    print("=" * 70)


def _cmd_json(args):
    """Output full report as JSON."""
    scan_id = _require_scan_id(args)
    store   = _get_store()
    data = store.get_full_report_json(scan_id)
    if not data:
        print(f"No report for {scan_id}", file=sys.stderr)
        sys.exit(1)
    output = json.dumps(data, indent=2, default=str)
    if getattr(args, "output", None):
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Written to {args.output}")
    else:
        print(output)


def _cmd_run(args):
    """Run a fresh scan against a target and display effectiveness report."""
    target = getattr(args, "target", None)
    if not target:
        print("ERROR: target required for 'run'.", file=sys.stderr)
        sys.exit(1)

    print(f"Starting scan of {target} with reactive effectiveness measurement...")
    print("The report will be generated automatically when the scan completes.")
    print()

    try:
        from oneinfinity.scan.unified_scan_engine import run_unified_scan
        result = run_unified_scan(target)
        scan_id = getattr(result, "scan_id", None)
        if scan_id:
            print(f"\nScan complete: {scan_id}")
            print("Fetching effectiveness report...\n")
            import time; time.sleep(0.5)  # brief wait for DB write
            store = _get_store()
            text  = store.get_text_report(scan_id)
            if text:
                print(text)
            else:
                print("Report not yet available. Run:")
                print(f"  oneinfinity reactive report {scan_id}")
        else:
            print("Scan complete. Run 'oneinfinity reactive list' to see the report.")
    except Exception as exc:
        print(f"Scan error: {exc}", file=sys.stderr)
        sys.exit(1)


def _cmd_validate_campaign(args):
    """Run Static vs Reactive validation campaign and produce all 9 comparison reports."""
    target_names  = getattr(args, "targets",     None)   or None
    output_file   = getattr(args, "output",      None)
    emit_json     = getattr(args, "json",        False)
    json_out_file = getattr(args, "json_output", None)
    timeout_s     = getattr(args, "timeout",     600.0)

    from oneinfinity.scan.validation_campaign import (
        run_campaign,
        render_campaign_reports,
        render_finding_quality_analysis,
        render_chain_quality_analysis,
        campaign_to_json,
        DEFAULT_TARGETS,
    )

    targets_avail = list(DEFAULT_TARGETS.keys())
    if target_names:
        unknown = [n for n in target_names if n not in DEFAULT_TARGETS]
        if unknown:
            print(f"WARNING: unknown target names (skipped): {unknown}", file=sys.stderr)
        targets_to_run = [n for n in target_names if n in DEFAULT_TARGETS]
        if not targets_to_run:
            print("ERROR: no valid targets. Available:", ", ".join(targets_avail), file=sys.stderr)
            sys.exit(1)
    else:
        targets_to_run = None   # all

    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║       REACTIVE EFFECTIVENESS VALIDATION CAMPAIGN                 ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    if targets_to_run:
        print(f"Targets: {', '.join(targets_to_run)}")
    else:
        print(f"Targets: all ({', '.join(targets_avail)})")
    print(f"Methodology: each target scanned TWICE — Static mode then Reactive mode.")
    print(f"Only reactive execution differs between the two runs.")
    print()

    try:
        result = run_campaign(target_names=targets_to_run, timeout_per_scan_s=timeout_s)
    except Exception as exc:
        print(f"Campaign error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Assemble full report text
    report_text = "\n".join([
        render_campaign_reports(result),
        render_finding_quality_analysis(result),
        render_chain_quality_analysis(result),
    ])

    # Output text report
    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(report_text)
            print(f"Campaign report written to: {output_file}")
        except OSError as exc:
            print(f"ERROR writing {output_file}: {exc}", file=sys.stderr)
            print(report_text)
    else:
        print(report_text)

    # JSON output
    if emit_json or json_out_file:
        j = campaign_to_json(result)
        if json_out_file:
            try:
                with open(json_out_file, "w", encoding="utf-8") as fh:
                    fh.write(j)
                print(f"Campaign JSON written to: {json_out_file}")
            except OSError as exc:
                print(f"ERROR writing {json_out_file}: {exc}", file=sys.stderr)
        if emit_json and not json_out_file:
            print(j)

    # Exit code: 0 = YES, 1 = NO or INSUFFICIENT_DATA
    if result.campaign_determination == "YES":
        sys.exit(0)
    else:
        sys.exit(1)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _wrap(text: str, width: int) -> list:
    """Simple word wrapper."""
    words = text.split()
    lines = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            if current:
                lines.append(current)
            current = word
        else:
            current = (current + " " + word).strip()
    if current:
        lines.append(current)
    return lines or [""]


def _dict_to_report(data: dict):
    """Reconstruct EffectivenessReport from dict (for rendering)."""
    from oneinfinity.scan.reactive_effectiveness import (
        ActionRecord, EffectivenessMetrics, EffectivenessReport,
        PivotRecord, ReplanRecord,
    )

    m_dict = data.get("metrics", {})
    metrics = EffectivenessMetrics(**{
        k: m_dict.get(k, v)
        for k, v in EffectivenessMetrics.__dataclass_fields__.items()
    }) if hasattr(EffectivenessMetrics, "__dataclass_fields__") else EffectivenessMetrics(
        scan_id=data.get("scan_id", ""),
        target=data.get("target", ""),
    )

    return EffectivenessReport(
        scan_id=data.get("scan_id", ""),
        target=data.get("target", ""),
        generated_at=float(data.get("generated_at", 0.0)),
        metrics=metrics,
        actions=[],
        replans=[],
        pivots=[],
        determination=data.get("determination", "INSUFFICIENT_DATA"),
        determination_evidence=data.get("determination_evidence", []),
        raw_telemetry=data.get("raw_telemetry", {}),
    )


def _print_report_from_dict(data: dict):
    """Print report from dict when rendered text is unavailable."""
    try:
        from oneinfinity.scan.reactive_effectiveness import render_full_text_report
        report = _dict_to_report(data)
        print(render_full_text_report(report))
    except Exception as exc:
        # Last resort: print key metrics
        m = data.get("metrics", {})
        print(f"Scan: {data.get('scan_id')}")
        print(f"Target: {data.get('target')}")
        print(f"Determination: {data.get('determination')}")
        print(f"Metrics passed: {m.get('metrics_passed', '?')}/8")
        print(f"Finding lift: {m.get('m1_finding_lift_pct', 0):.1f}%")
        print(f"Reactive findings: {m.get('reactive_findings', 0)}")
        print(f"Baseline findings: {m.get('baseline_findings', 0)}")
        for ev in data.get("determination_evidence", []):
            print(f"  {ev}")


def register(subparsers):
    """Register 'reactive' command with argparse."""
    p = subparsers.add_parser(
        "reactive",
        help="Reactive Effectiveness Program — measure and report reactive scan impact",
    )
    sub = p.add_subparsers(dest="subcommand")

    # report
    p_report = sub.add_parser("report", help="Full effectiveness report for a scan")
    p_report.add_argument("scan_id", help="Scan ID to report on")

    # dashboard
    p_dash = sub.add_parser("dashboard", help="Effectiveness dashboard (summary view)")
    p_dash.add_argument("scan_id", help="Scan ID")

    # list
    p_list = sub.add_parser("list", help="List all effectiveness reports")
    p_list.add_argument("--limit", type=int, default=50, help="Max rows")

    # roi
    p_roi = sub.add_parser("roi", help="ROI metrics table")
    p_roi.add_argument("scan_id", help="Scan ID")

    # determination
    p_det = sub.add_parser("determination", help="Final YES/NO verdict with evidence")
    p_det.add_argument("scan_id", help="Scan ID")

    # json
    p_json = sub.add_parser("json", help="Full report as JSON")
    p_json.add_argument("scan_id", help="Scan ID")
    p_json.add_argument("--output", "-o", help="Write to file instead of stdout")

    # run
    p_run = sub.add_parser("run", help="Scan a target and show effectiveness report")
    p_run.add_argument("target", help="Target URL or domain")

    # validate_campaign
    p_vc = sub.add_parser(
        "validate_campaign",
        help="Run Static vs Reactive validation campaign and produce all 9 comparison reports",
    )
    p_vc.add_argument(
        "--targets", "-t", nargs="*", metavar="NAME",
        help="Target names to include (default: all built-in targets)",
    )
    p_vc.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write full report to FILE instead of stdout",
    )
    p_vc.add_argument(
        "--json", action="store_true",
        help="Also emit campaign JSON alongside the text report",
    )
    p_vc.add_argument(
        "--json-output", metavar="FILE",
        help="Write campaign JSON to FILE",
    )
    p_vc.add_argument(
        "--timeout", type=float, default=600.0,
        help="Per-scan wall-clock timeout in seconds (default: 600)",
    )

    p.set_defaults(func=cmd_reactive)
    return p
