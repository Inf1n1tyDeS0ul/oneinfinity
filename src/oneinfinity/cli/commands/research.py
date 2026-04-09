"""
CLI command handlers for research domain.
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

def cmd_research(args):
    """
    oneinfinity research <target> — autonomous vulnerability research mode.
    Runs the full research loop: analyze → theorize → test → detect → report.

    Examples:
      oneinfinity research target.com --yes          — run research loop
      oneinfinity research --stats                   — show research KB statistics
    """
    try:
        from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("research")
    except Exception:
        pass
    if getattr(args, "stats", False):
        # Route to stats display instead of running the loop
        from oneinfinity.research_mode_controller import show_research_stats
        show_research_stats()
        return
    from oneinfinity.research_mode_controller import main_cli
    main_cli(args)


def cmd_learn(args):
    """
    oneinfinity learn stats — show learning system statistics.
    oneinfinity learn plan <target> — show adaptive plan for a domain.
    """
    from oneinfinity.modules.utils import banner, section, ok, warn, info

    subcommand = args.subcommand

    try:
        from oneinfinity.learning import LearningSystem
        ls = LearningSystem()
    except Exception as e:
        warn(f"Learning system error: {e}")
        return

    if subcommand == "stats":
        banner("Continuous Learning System")
        ls.show_stats()

    elif subcommand == "plan":
        target = args.target
        tech = args.tech.split(",") if args.tech else None
        banner(f"Adaptive Scan Plan — {target}")
        plan = ls.plan_for(target, tech_stack=tech, quick=args.quick)
        from oneinfinity.learning import AdaptivePlanner
        planner = AdaptivePlanner(ls.kb)
        print(planner.describe_plan(plan))
        print()

    elif subcommand == "show":
        # Alias for stats
        banner("Continuous Learning System")
        ls.show_stats()

    elif subcommand == "backfill":
        from oneinfinity.learning.backfill import main as backfill_main
        backfill_main()

    else:
        warn(f"Unknown subcommand: {subcommand}")
        print("  Usage: oneinfinity learn stats")
        print("         oneinfinity learn plan <target> [--tech php,mysql] [--quick]")
        print("         oneinfinity learn backfill")

    ls.close()


def cmd_profile(args):
    """oneinfinity profile list|show|run — scan profile management."""
    from oneinfinity.core.scan_profiles import list_profiles, get_profile, PROFILES
    subcommand = getattr(args, "subcommand", None)

    if subcommand == "list" or subcommand is None:
        print(list_profiles())
        return

    if subcommand == "show":
        try:
            p = get_profile(args.name)
        except KeyError as e:
            print(f"[!] {e}")
            return
        print(f"\nProfile: {p.name}")
        print(f"  {p.description}")
        print(f"\n  Recon   : subdomains={p.recon_subdomains}, urls={p.recon_urls}, ports={p.recon_ports}, max_sub={p.max_subdomains}")
        print(f"  Scan    : nuclei={p.nuclei_enabled}({p.nuclei_severity}), dalfox={p.dalfox_enabled}, sqlmap={p.sqlmap_enabled}")
        print(f"  Research: mode={p.research_mode}, iterations={p.research_iterations}")
        print(f"  Workers : {p.max_workers} | Rate: {p.nuclei_rate_limit}/s")
        print(f"  Formats : {', '.join(p.report_formats)}")
        return

    if subcommand == "run":
        try:
            profile = get_profile(args.profile_name)
        except KeyError as e:
            print(f"[!] {e}")
            return
        print(f"\n[*] Running {profile.name} profile on {args.domain}")
        print(f"[*] {profile.description}")

        if not getattr(args, "yes", False):
            confirm = input(f"\n[!] Start {profile.name} scan against {args.domain}? [y/N] ").strip().lower()
            if confirm != "y":
                print("[-] Aborted.")
                return

        output_dir = getattr(args, "output", None) or "recon"
        platform = getattr(args, "platform", "hackerone")

        if profile.research_mode:
            # Route to research mode
            import types
            fake_args = types.SimpleNamespace(
                domain=args.domain,
                yes=True,
                output=output_dir,
                platform=platform,
                iterations=profile.research_iterations,
                confidence=profile.research_confidence_threshold,
                stats=False,
                mode="passive",
                timeout=profile.scan_timeout,
            )
            from oneinfinity.research_mode_controller import main_cli
            main_cli(fake_args)
        else:
            # Route to standard agents run
            import types
            fake_args = types.SimpleNamespace(
                subcommand="run",
                domain=args.domain,
                yes=True,
                output=output_dir,
                platform=platform,
                phases=None,
                timeout=profile.scan_timeout,
                no_learn=False,
            )
            cmd_agents(fake_args)




def register(subparsers):
    """Register research commands with the CLI argument parser."""
    sub = subparsers
    pr2 = sub.add_parser("research",
                          help="Autonomous vulnerability research mode (analyze→theorize→test→report)")
    pr2.add_argument("target", nargs="?", default="",
                     help="Target domain (omit to use --stats)")
    pr2.add_argument("--output", "-o", metavar="DIR",
                     help="Output directory (default: ~/.oneinfinity/raw/<target>)")
    pr2.add_argument("--platform", choices=["HackerOne", "Bugcrowd", "generic"],
                     default="HackerOne", help="Bug bounty platform")
    pr2.add_argument("--iterations", type=int, default=3, metavar="N",
                     help="Max research loop iterations (default: 3)")
    pr2.add_argument("--timeout", type=int, default=3600, metavar="SEC",
                     help="Max total time in seconds (default: 3600)")
    pr2.add_argument("--active", action="store_true",
                     help="Enable active (destructive) tests (default: passive only)")
    pr2.add_argument("--oob", metavar="URL", help="OOB callback URL")
    pr2.add_argument("--no-graph",  dest="no_graph",  action="store_true",
                     help="Disable attack graph integration")
    pr2.add_argument("--no-learn",  dest="no_learn",  action="store_true",
                     help="Disable continuous learning system")
    pr2.add_argument("--yes", "-y", action="store_true",
                     help="Skip authorization confirmation prompt")
    pr2.add_argument("--min-confidence", dest="min_confidence", type=float,
                     default=0.60, metavar="F",
                     help="Minimum theory confidence to test (default: 0.60)")
    pr2.add_argument("--stats", action="store_true",
                     help="Show research knowledge base statistics instead of running")

    pl2 = sub.add_parser("learn", help="Continuous learning system")
    pl2sub = pl2.add_subparsers(dest="subcommand")
    pl2sub.add_parser("stats", help="Show learning statistics")
    pl2sub.add_parser("show",  help="Show learning statistics (alias for stats)")
    ll = pl2sub.add_parser("plan", help="Show adaptive scan plan for a domain")
    ll.add_argument("target", help="Target domain")
    ll.add_argument("--tech", metavar="LIST",
                    help="Comma-separated tech stack (e.g. wordpress,mysql,nginx)")
    ll.add_argument("--quick", action="store_true",
                    help="Quick mode: skip recon, focus on known vuln types")
    pl2sub.add_parser("backfill", help="Backfill Neo4j learning graph from existing PG findings (idempotent)")

    sp_cmd = sub.add_parser("profile", help="Scan profiles: quick/deep/research/swarm/stealth")
    sp_sub = sp_cmd.add_subparsers(dest="subcommand")
    sp_list = sp_sub.add_parser("list", help="List all available scan profiles")
    sp_show = sp_sub.add_parser("show", help="Show profile details")
    sp_show.add_argument("name", help="Profile name")
    sp_run = sp_sub.add_parser("run", help="Run a full scan with a named profile")
    sp_run.add_argument("domain", help="Target domain")
    sp_run.add_argument("profile_name", metavar="profile",
                        choices=["quick", "deep", "research", "swarm", "stealth"],
                        help="Profile: quick | deep | research | swarm | stealth")
    sp_run.add_argument("--yes", "-y", action="store_true", help="Skip authorization prompt")
    sp_run.add_argument("--output", "-o", metavar="DIR", help="Output directory")
    sp_run.add_argument("--platform", default="hackerone",
                        choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"],
                        help="Bug bounty platform")


