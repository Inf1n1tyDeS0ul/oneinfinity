"""
CLI command handlers for analysis domain.
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

def cmd_analyze(args):
    d = get_program_dir()
    recon_dir = str(d / "recon")
    os.makedirs(recon_dir, exist_ok=True)

    from oneinfinity.modules.scope import ScopeManager
    sm = ScopeManager(str(d))
    if sm.exists():
        sm.load()

    subcommand = args.subcommand

    if subcommand == "subdomains":
        from oneinfinity.modules.analyzer import analyze_subdomains
        analyze_subdomains(args.file[0], output_dir=recon_dir)

    elif subcommand == "responses":
        from oneinfinity.modules.analyzer import analyze_responses
        analyze_responses(args.file[0], output_dir=recon_dir)

    elif subcommand == "js":
        from oneinfinity.modules.analyzer import analyze_js
        analyze_js(args.file, output_dir=recon_dir)

    elif subcommand == "nuclei":
        from oneinfinity.modules.analyzer import analyze_nuclei
        analyze_nuclei(args.file[0], output_dir=recon_dir)

    else:
        from oneinfinity.modules.utils import err
        err(f"Unknown analyze subcommand: {subcommand}")
        err("Use: subdomains | responses | js | nuclei")
        sys.exit(1)


def cmd_org_intel(args):
    from oneinfinity.recon.org_intel_mapper import OrgDomainMapper
    token = args.github_token or ""
    if not token and args.github_token_file:
        try:
            token = Path(args.github_token_file).read_text().strip().splitlines()[0]
        except Exception:
            token = ""

    mapper = OrgDomainMapper()
    res = mapper.map_org(
        args.org,
        github_token=token or None,
        max_repos=args.max_repos,
    )

    # Persist as recon assets (best-effort)
    try:
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
        eng = get_ingestion_engine()
        scan_id = f"org-intel:{res.org}"
        for d in res.domains:
            eng.ingest_recon_asset(scan_id, "org_domain", d, {"org": res.org, "source": "github"})
    except Exception:
        pass

    out = res.to_json()
    print(out)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")


def cmd_plan(args):
    d = get_program_dir()
    from oneinfinity.modules.scope import ScopeManager
    sm = ScopeManager(str(d))
    sm.load()
    sm.validate()
    from oneinfinity.modules.planner import HuntPlanner
    planner = HuntPlanner(str(d))
    planner.generate()


def cmd_analyze_app(args):
    """
    oneinfinity analyze-app <target> — build a structured application model.
    Maps auth flows, API structure, user roles, and sensitive endpoints.
    """
    from oneinfinity.application_intelligence import main_cli
    main_cli(args)


def cmd_generate_theories(args):
    """
    oneinfinity generate-theories <target> — generate vulnerability theories from app model.
    Analyzes AppModel and outputs prioritized vulnerability theories with reasoning.
    """
    from oneinfinity.vulnerability_theory_engine import main_cli
    main_cli(args)


def cmd_run_custom_tests(args):
    """
    oneinfinity run-custom-tests <target> — design and execute custom attack tests.
    Generates test cases from theories and executes them against the target.
    """
    from oneinfinity.custom_test_engine import main_cli
    main_cli(args)


def cmd_capmap(args):
    """oneinfinity capmap — print the full tool capability map and vulnerability coverage matrix."""
    from oneinfinity.modules.utils import banner, section, ok, warn, info, bold
    from oneinfinity.modules.capability_map import CapabilityMap, CAPABILITIES, Vuln
    from oneinfinity.modules.tool_wrappers import is_available

    if args.vuln:
        # Show all tools that detect a specific vuln class
        # Find the matching vuln constant
        vuln_map = {k.lower().replace(" ", "_").replace("(","").replace(")","").replace("/","_"):
                    v for k, v in vars(Vuln).items() if isinstance(v, str)}
        query = args.vuln.lower().replace("-","_").replace(" ","_")
        matched_vuln = None
        for key, val in vuln_map.items():
            if query in key or query in val.lower():
                matched_vuln = val
                break
        if not matched_vuln:
            warn(f"No vuln class matching '{args.vuln}'")
            print(f"  Known classes: {', '.join(sorted(vuln_map.keys()))}")
            return
        banner(f"Tools for: {matched_vuln}")
        tools = CapabilityMap.tools_for_vuln(matched_vuln)
        for tool_name, confidence in tools:
            cap = CAPABILITIES[tool_name]
            avail = "✓" if is_available(tool_name) else "✗"
            print(f"  {avail} [{confidence:<6}] {tool_name:<18} — {cap.description[:60]}")
        return

    if args.tool:
        # Show full capability entry for one tool
        cap = CapabilityMap.get(args.tool)
        if not cap:
            warn(f"Unknown tool: {args.tool}")
            return
        avail = "INSTALLED" if is_available(args.tool) else "NOT INSTALLED"
        banner(f"{cap.name}  [{avail}]")
        print(f"  Category    : {cap.category}")
        print(f"  Description : {cap.description}")
        print()
        print(f"  Detects:")
        for vuln in cap.detects:
            conf = cap.confidence.get(vuln, "low")
            print(f"    [{conf:<6}] {vuln}")
        print()
        print(f"  Inputs:")
        for inp in cap.inputs:
            req = "required" if inp.required else "optional"
            print(f"    {inp.name:<16} ({inp.type}, {req}) — {inp.description}")
        print()
        print(f"  Outputs:")
        for out in cap.outputs:
            print(f"    {out.name:<20} ({out.type}) — {out.description}")
        print()
        print(f"  Prerequisites: {', '.join(cap.requires_phase) or 'none'}")
        print(f"  Feeds into  : {', '.join(cap.feeds_into) or 'none'}")
        print(f"  Duration    : ~{cap.typical_duration_sec}s")
        print(f"  Noise level : {cap.noise_level}")
        print(f"  Passive     : {cap.passive}")
        print(f"  Needs root  : {cap.needs_root}")
        if cap.notes:
            print()
            print(f"  Notes: {cap.notes}")
        print()
        return

    # Default: print full coverage matrix
    banner("Tool Capability Map — Vulnerability Coverage Matrix")
    CapabilityMap.print_coverage_matrix()

    section("Tool Summary by Category")
    from itertools import groupby
    tools_by_cat: dict[str, list] = {}
    for name, cap in sorted(CAPABILITIES.items()):
        tools_by_cat.setdefault(cap.category, []).append((name, cap))
    for cat, tools in sorted(tools_by_cat.items()):
        print(f"\n  {bold(cat.upper())}")
        for name, cap in tools:
            avail = "✓" if is_available(name) else "✗"
            dur = f"{cap.typical_duration_sec}s"
            noise = cap.noise_level[0].upper()  # L/M/H
            passive_mark = "P" if cap.passive else " "
            detects_count = len(cap.detects)
            print(f"    {avail} {passive_mark} {name:<20} [{noise}] ~{dur:<6} "
                  f"detects:{detects_count} — {cap.description[:50]}")
    print()
    print("  Legend: ✓=installed  ✗=missing  P=passive  [L/M/H]=noise level")
    print()
    print("  Options:")
    print("    oneinfinity capmap --tool <name>     — detailed tool profile")
    print("    oneinfinity capmap --vuln xss        — tools that detect XSS")
    print("    oneinfinity capmap --vuln sqli       — tools that detect SQLi")
    print()


def cmd_adaptive_recon(args):
    """
    oneinfinity adaptive-recon <target> — adaptive recon intelligence.
    Detects tech stack, maps API endpoints, extracts JS endpoints,
    enumerates cloud assets, and generates a prioritized attack strategy.
    """
    from oneinfinity.recon.adaptive_recon_engine import main_cli
    main_cli(args)


def cmd_zero_day(args):
    """
    oneinfinity zero-day <target> — run zero-day anomaly detection engine.
    Probes the target for unusual behaviors, data leakage, and access control flips.
    """
    from oneinfinity.attack.zero_day_engine import main_cli
    main_cli(args)




def register(subparsers):
    """Register analysis commands with the CLI argument parser."""
    sub = subparsers
    a = sub.add_parser("analyze", help="Analyze recon data files")
    a.add_argument("subcommand", choices=["subdomains","responses","js","nuclei"])
    a.add_argument("file", nargs="+", help="Input file(s)")

    oi = sub.add_parser("org-intel", help="Map GitHub org to likely domains (metadata-based)")
    oi.add_argument("org", help="GitHub org name or https://github.com/<org>")
    oi.add_argument("--github-token", help="GitHub token (optional, higher rate limits)")
    oi.add_argument("--github-token-file", help="File containing GitHub token")
    oi.add_argument("--max-repos", type=int, default=200, help="Max repos to scan (default: 200)")
    oi.add_argument("--output", "-o", metavar="FILE", help="Write JSON to file")

    sub.add_parser("plan", help="Generate prioritized hunt plan from recon data")

    aap = sub.add_parser("analyze-app",
                          help="Build structured application model from recon data")
    aap.add_argument("target", help="Target domain")
    aap.add_argument("--output", "-o", metavar="DIR",
                     help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")

    gt = sub.add_parser("generate-theories",
                         help="Generate vulnerability theories from app model")
    gt.add_argument("target", help="Target domain")
    gt.add_argument("--output", "-o", metavar="DIR",
                    help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")

    rct = sub.add_parser("run-custom-tests",
                          help="Design and execute custom attack tests from theories")
    rct.add_argument("target", help="Target domain")
    rct.add_argument("--output", "-o", metavar="DIR",
                     help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")
    rct.add_argument("--min-severity", dest="min_severity",
                     choices=["critical", "high", "medium", "low"], default="medium",
                     help="Minimum severity to test (default: medium)")
    rct.add_argument("--passive", action="store_true", default=True,
                     help="Passive (non-destructive) tests only (default: True)")
    rct.add_argument("--oob", metavar="URL", help="OOB callback URL for SSRF/blind detection")
    rct.add_argument("--rate", type=float, default=1.0, metavar="SEC",
                     help="Seconds between requests (default: 1.0)")

    pcm = sub.add_parser("capmap",
                          help="Show tool capability map and vulnerability coverage matrix")
    pcm.add_argument("--tool", metavar="NAME", help="Show full profile for one tool")
    pcm.add_argument("--vuln", metavar="CLASS",
                     help="Show tools that detect a vuln class (e.g. xss, sqli, ssrf)")

    ar = sub.add_parser("adaptive-recon",
                         help="Adaptive recon intelligence: tech detect, API map, JS endpoints, cloud assets")
    ar.add_argument("target", help="Target domain")
    ar.add_argument("--output", "-o", metavar="DIR",
                    help="Output directory (default: ~/.oneinfinity/raw/<target>)")
    ar.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard",
                    help="Recon depth (default: standard)")
    ar.add_argument("--json", action="store_true",
                    help="Print structured JSON output after report")
    ar.add_argument("--no-graph", dest="no_graph", action="store_true",
                    help="Disable attack graph integration")

    zd = sub.add_parser("zero-day",
                         help="Zero-day anomaly detection: probe for unusual behaviors")
    zd.add_argument("target", help="Target domain")
    zd.add_argument("--output", "-o", metavar="DIR",
                    help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")
    zd.add_argument("--rate", type=float, default=0.5, metavar="SEC",
                    help="Seconds between requests (default: 0.5)")
    zd.add_argument("--timeout", type=int, default=12, metavar="SEC",
                    help="Per-request timeout (default: 12)")


