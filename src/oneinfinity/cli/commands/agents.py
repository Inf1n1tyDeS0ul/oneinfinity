"""
CLI command handlers for agents domain.
Each public function is cmd_* (handler) or register() (argparse setup).
"""
from __future__ import annotations
import sys
import os
import asyncio
import logging
from pathlib import Path
from oneinfinity.cli._helpers import (
    CLI_COMMAND, WORKSPACE_DIRNAME, LEGACY_WORKSPACE_DIRNAME,
    get_workspace_root, find_program_dir, get_program_dir,
)

log = logging.getLogger(__name__)

def cmd_run(args):
    """Autonomous framework: run all phases for a target."""
    from oneinfinity.modules.utils import banner, info, warn, err
    from oneinfinity.scan.unified_scan_engine import get_engine

    banner(f"Starting Unified Scan: {args.target}")

    engine = get_engine()

    def on_progress(phase, pct, msg):
        info(f"[{pct}%] {phase}: {msg}")

    try:
        session = engine.scan(args.target, on_progress=on_progress)
        if session.status == "failed":
            err(f"Scan failed.")
        else:
            info(f"Scan completed. Found {len(session.findings)} findings.")
    except Exception as exc:
        err(f"Scan failed: {exc}")


def cmd_agents(args):
    """
    oneinfinity agents run <target> — launch the full multi-agent autonomous pentest.
    """
    from oneinfinity.modules.utils import banner, section, ok, warn, err, info

    subcommand = args.subcommand

    if subcommand == "run":
        target = args.target
        output_dir = args.output or "recon"
        platform = args.platform or "HackerOne"
        phases = args.phases.split(",") if args.phases else None
        timeout = args.timeout or 3600

        banner(f"Multi-Agent Autonomous Pentest — {target}")
        warn("Active scanning will be performed against the target.")
        warn("Unauthorised testing is illegal. Confirm written authorisation.")
        print()
        if getattr(args, "yes", False):
            ans = "yes"
        else:
            ans = input("  [?] Do you have written authorisation to pentest this target? (yes/no): ").strip().lower()
        if ans != "yes":
            print("  Aborted. Obtain written authorisation before scanning.")
            return
        print()

        # ── Enforcement: register module ─────────────────────────────────────
        try:
            from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
            _get_ec().register_module("agents")
        except Exception:
            pass

        # Initialize subsystems
        attack_graph = None
        if not args.no_graph:
            from oneinfinity.attack_graph_core import AttackGraph
            attack_graph = AttackGraph(target)

        learning_system = None
        if not args.no_learn:
            try:
                from oneinfinity.learning import LearningSystem
                learning_system = LearningSystem()
                info("Learning system: active")
                plan = learning_system.plan_for(target)
                notes = plan.rationale or plan.insight.notes
                if notes:
                    section("Adaptive Planner Insights")
                    for note in notes:
                        print(f"  → {note}")
                    print()
            except Exception as e:
                warn(f"Learning system unavailable: {e}")

        from oneinfinity.agents import build_coordinator
        coord = build_coordinator(
            attack_graph=attack_graph,
            learning_system=learning_system,
        )
        coord.start()

        info(f"Agents started: {list(coord._agents.keys())}")
        print()

        results = coord.run_pentest(
            target=target,
            output_dir=output_dir,
            platform=platform,
            phases=phases,
            timeout=timeout,
        )

        coord.shutdown()

        # ── Publish agent findings to shared endpoint bus ─────────────────────
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
            import uuid as _uuid
            _bus = get_ingestion_engine()
            _sid = str(_uuid.uuid4())[:8]
            _all_findings = coord.get_all_findings()
            for _f in _all_findings:
                _bus.ingest(RawResult(
                    scan_id=_sid,
                    source="agents-run",
                    raw=_f,
                ))
            info(f"Endpoint bus: published {len(_all_findings)} findings from agents run")
        except Exception as _be:
            warn(f"Endpoint bus publish skipped: {_be}")

        section("Pentest Complete")
        summary = coord.findings_summary()
        ok(f"Tasks completed: {summary['tasks_completed']}")
        ok(f"Total findings:  {summary['total_findings']}")
        if summary["by_severity"]:
            for sev, count in sorted(summary["by_severity"].items()):
                print(f"  {sev.upper():<10} {count}")
        ok(f"Tools used: {', '.join(summary['tools_used'])}")

        # Save attack graph if built
        if attack_graph:
            from pathlib import Path
            from oneinfinity.attack_graph_core import AttackGraphAnalyzer, AttackGraphVisualizer
            graph_path = str(Path(output_dir) / target / "attack_graph.json")
            attack_graph.save(graph_path)
            ok(f"Attack graph: {graph_path}")
            viz = AttackGraphVisualizer(attack_graph)
            viz.print_full()

        # Persist to learning system
        if learning_system:
            learning_system.close()

        print()

    elif subcommand == "status":
        info("No active agent session.")
        print("  Use: oneinfinity agents run <domain>")
        print()

    else:
        err(f"Unknown subcommand: {subcommand}")
        print("  Usage: oneinfinity agents run <domain> [options]")




def register(subparsers):
    """Register agents commands with the CLI argument parser."""
    sub = subparsers
    ru = sub.add_parser("run", help="Autonomous framework: recon → exploit → report")
    ru.add_argument("target", help="Target domain to test")
    ru.add_argument("--auth", choices=["bugbounty", "contract", "owner", "scope_yaml"],
                    default=None,
                    help="Authorization type (default: auto-detect from scope.yaml)")
    ru.add_argument("--url", metavar="PROGRAM_URL",
                    help="Bug bounty program URL (required for --auth bugbounty)")
    ru.add_argument("--contract", metavar="FILE",
                    help="Contract file path (required for --auth contract)")
    ru.add_argument("--phase", metavar="RANGE",
                    help="Phases to run, e.g. 1-4, 2, 3-6 (default: 1-6)")
    ru.add_argument("--resume", action="store_true",
                    help="Resume from last completed phase")
    ru.add_argument("--rate", type=int, metavar="N",
                    help="Override rate limit (requests/min, default: 30)")
    ru.add_argument("--oob", metavar="URL",
                    help="Out-of-band callback URL for SSRF/blind XSS validation")
    ru.add_argument("--no-validate", dest="no_validate", action="store_true",
                    help="Skip Phase 5 (discovery only)")
    ru.add_argument("--report-only", dest="report_only", action="store_true",
                    help="Run Phase 6 only (generate reports from existing findings)")

    pa = sub.add_parser("agents", help="Multi-agent autonomous pentesting system")
    pasub = pa.add_subparsers(dest="subcommand")
    par = pasub.add_parser("run", help="Launch full autonomous pentest")
    par.add_argument("target", help="Target domain")
    par.add_argument("--output", "-o", metavar="DIR",
                     help="Base output directory (default: ~/.oneinfinity/raw/)")
    par.add_argument("--platform", choices=["HackerOne", "Bugcrowd", "generic"],
                     help="Bug bounty platform (default: HackerOne)")
    par.add_argument("--phases", metavar="LIST",
                     help="Comma-separated phases: recon,scan,exploit,validate,report")
    par.add_argument("--timeout", type=int, metavar="SEC",
                     help="Max total time in seconds (default: 3600)")
    par.add_argument("--no-graph",  dest="no_graph",  action="store_true",
                     help="Disable attack graph construction")
    par.add_argument("--no-learn",  dest="no_learn",  action="store_true",
                     help="Disable continuous learning system")
    par.add_argument("--yes", "-y", action="store_true",
                     help="Skip authorisation confirmation prompt")
    pasub.add_parser("status", help="Show status of running agents")


