"""
CLI command handlers for misc domain.
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

def cmd_script(args):
    from oneinfinity.modules.scripter import ScriptGenerator
    if args.type == "list" or not args.type:
        gen = ScriptGenerator(output_dir=".")
        gen.list_available()
        return
    d = get_program_dir()
    scripts_dir = str(d / "scripts")
    gen = ScriptGenerator(output_dir=scripts_dir)
    gen.generate(args.type)


def cmd_workflow(args):
    """
    oneinfinity workflow <target> — build and execute the optimal scan plan.
    Uses the capability map to select the right tools in the right order.
    """
    from oneinfinity.modules.utils import banner, warn
    from oneinfinity.modules.workflow import WorkflowEngine

    target = args.target
    output_dir = resolve_output_dir(args.output, target)
    phases = args.phases.split(",") if args.phases else None

    engine = WorkflowEngine(
        target=target,
        output_dir=output_dir,
        rate_limit=args.rate or 30,
        nuclei_severity=args.severity or "medium,high,critical",
        oob_url=args.oob or "",
        max_workers=args.workers or 3,
        timeout_multiplier=float(args.timeout_mult or 1.0),
    )

    plan = engine.build_plan()

    if args.plan_only:
        engine.print_plan(plan)
        return

    warn("Ensure you have explicit written authorization before running this workflow.")
    engine.print_plan(plan)
    state = engine.execute(plan)


def cmd_plugins(args):
    """oneinfinity plugins list|run — plugin registry management."""
    from oneinfinity.core.plugin_registry import plugin_registry
    plugin_registry.discover()

    subcommand = getattr(args, "subcommand", None)

    if subcommand == "list" or subcommand is None:
        print(plugin_registry.summary())
        print()
        for entry in plugin_registry.list_all():
            status = "enabled" if entry.enabled else "disabled"
            print(f"  {entry.name:<30} [{entry.plugin_type}] v{entry.version} — {entry.description}")
            print(f"    {'Tags:':<8} {', '.join(entry.tags)}")
        return

    if subcommand == "run":
        target = args.domain
        name = args.plugin_name
        print(f"[*] Running plugin '{name}' on {target}...")
        try:
            result = plugin_registry.run_plugin(name, target, {})
            import json
            print(json.dumps(result, indent=2, default=str))
        except Exception as e:
            print(f"[!] Plugin failed: {e}")


def cmd_cache(args):
    """oneinfinity cache stats|sweep|invalidate|clear — recon cache management."""
    from oneinfinity.core.cache import recon_cache
    subcommand = getattr(args, "subcommand", None)

    if subcommand == "stats" or subcommand is None:
        stats = recon_cache.stats()
        print(f"\n[*] Recon Cache Statistics")
        print(f"  Total entries : {stats['total']}")
        print(f"  Expired       : {stats['expired']}")
        print(f"  By tool:")
        for tool, count in stats.get("by_tool", {}).items():
            print(f"    {tool:<20} {count}")
        return

    if subcommand == "sweep":
        n = recon_cache.sweep_expired()
        print(f"[+] Swept {n} expired cache entries.")
        return

    if subcommand == "invalidate":
        n = recon_cache.invalidate_target(args.domain)
        print(f"[+] Invalidated {n} cache entries for {args.domain}.")
        return

    if subcommand == "clear":
        confirm = input("[!] Clear ALL cached recon data? [y/N] ").strip().lower()
        if confirm == "y":
            recon_cache.clear_all()
            print("[+] Cache cleared.")
        else:
            print("[-] Aborted.")


def cmd_benchmark(args):
    """
    oneinfinity benchmark --burp burp.json --oi results.json [--nuclei nuclei.jsonl]

    Compare OneInfinity findings against Burp Suite / Nuclei to measure coverage.
    """
    from oneinfinity.modules.utils import banner, ok, warn, err, info

    oi_path   = getattr(args, "oi", "")
    burp_path = getattr(args, "burp", "")
    nuclei_path = getattr(args, "nuclei", "")
    output    = getattr(args, "output", "benchmark_report.json")

    if not oi_path:
        err("--oi <oneinfinity-results.json> is required")
        sys.exit(1)
    if not burp_path and not nuclei_path:
        err("At least one reference tool required: --burp or --nuclei")
        sys.exit(1)

    banner("OneInfinity Benchmark Engine")

    try:
        from oneinfinity.core.benchmark_engine import get_benchmark_engine
        engine = get_benchmark_engine()

        references = []
        if burp_path:
            references.append({"path": burp_path, "fmt": "burp"})
        if nuclei_path:
            references.append({"path": nuclei_path, "fmt": "nuclei"})

        all_results = engine.compare_all(oi_findings_path=oi_path, references=references)

        for result in all_results:
            result.print_summary()

        if output:
            import json as _json
            combined = {
                "oi_file": oi_path,
                "comparisons": [r.to_dict() for r in all_results],
            }
            Path(output).write_text(_json.dumps(combined, indent=2))
            ok(f"Full benchmark report: {output}")

    except FileNotFoundError as exc:
        err(f"File not found: {exc}")
    except ImportError as exc:
        err(f"benchmark_engine not available: {exc}")
    except Exception as exc:
        err(f"Benchmark failed: {exc}")
        import traceback; traceback.print_exc()


def cmd_tool_run(args):
    """
    oneinfinity tool <name> [--target <target>] [--url <url>] [--domain <domain>]
    Run any registered tool directly.
    """
    from oneinfinity.modules.utils import banner, warn, err
    from oneinfinity.modules.tool_wrappers import ToolRegistry, TOOL_REGISTRY

    tool_name = args.tool_name
    if tool_name not in TOOL_REGISTRY:
        err(f"Unknown tool: {tool_name}")
        print(f"  Available tools: {', '.join(sorted(TOOL_REGISTRY.keys()))}")
        return

    reg = ToolRegistry()
    # Build kwargs from CLI args
    kwargs = {}
    if args.domain:
        kwargs["domain"] = args.domain
    if args.target:
        kwargs["target"] = args.target
    if args.url:
        kwargs["url"] = args.url
    if args.timeout:
        kwargs["timeout"] = args.timeout

    banner(f"Running: {tool_name}")
    result = reg.run(tool_name, **kwargs)

    if result.success:
        import json
        print(result.to_json())
    else:
        err(f"{tool_name} failed: {result.error}")
        if result.raw:
            print(result.raw[:500])




def register(subparsers):
    """Register misc commands with the CLI argument parser."""
    sub = subparsers
    sc = sub.add_parser("script", help="Generate test scripts")
    sc.add_argument("type", nargs="?", default="list",
                    help="Script type (cors|sqli|ssrf|idor|headers|redirect|subdomain-takeover) or 'list'")

    pw = sub.add_parser("workflow",
                         help="Build and execute an optimal scan workflow using the capability map")
    pw.add_argument("target", help="Target domain")
    pw.add_argument("--output", "-o", metavar="DIR",
                    help="Output directory (default: ~/.oneinfinity/raw/<target>)")
    pw.add_argument("--phases", metavar="LIST",
                    help="Comma-separated phases: passive,subdomain,dns,http,fingerprint,"
                         "ports,crawl,content,api,triage,vuln,cloud,secrets")
    pw.add_argument("--plan-only", dest="plan_only", action="store_true",
                    help="Print the plan without executing")
    pw.add_argument("--rate", type=int, metavar="N", help="Requests per minute")
    pw.add_argument("--severity", metavar="SEV",
                    help="Nuclei severity (default: medium,high,critical)")
    pw.add_argument("--oob", metavar="URL", help="OOB callback URL")
    pw.add_argument("--workers", type=int, metavar="N", help="Parallel workers (default: 3)")
    pw.add_argument("--timeout-mult", dest="timeout_mult", metavar="F",
                    help="Timeout multiplier, e.g. 2.0 for slow targets (default: 1.0)")

    plug_cmd = sub.add_parser("plugins", help="Plugin registry management")
    plug_sub = plug_cmd.add_subparsers(dest="subcommand")
    plug_sub.add_parser("list", help="List all registered plugins")
    plug_run = plug_sub.add_parser("run", help="Run a specific plugin")
    plug_run.add_argument("plugin_name", help="Plugin name")
    plug_run.add_argument("domain", help="Target domain")

    cache_cmd = sub.add_parser("cache", help="Recon cache management")
    cache_sub = cache_cmd.add_subparsers(dest="subcommand")
    cache_sub.add_parser("stats", help="Show cache statistics")
    cache_sub.add_parser("sweep", help="Remove expired cache entries")
    cache_inv = cache_sub.add_parser("invalidate", help="Invalidate cache for a target")
    cache_inv.add_argument("domain", help="Target domain to invalidate")
    cache_sub.add_parser("clear", help="Clear all cached data")

    bench = sub.add_parser(
        "benchmark",
        help="Compare OneInfinity coverage against Burp Suite / Nuclei exports",
    )
    bench.add_argument("--oi", required=False, default="",
                       help="Path to OneInfinity findings JSON (required)")
    bench.add_argument("--burp", default="",
                       help="Path to Burp Suite JSON export")
    bench.add_argument("--nuclei", default="",
                       help="Path to Nuclei JSONL output")
    bench.add_argument("--output", "-o", default="benchmark_report.json",
                       help="Output path for benchmark JSON report (default: benchmark_report.json)")

    pt = sub.add_parser("tool", help="Run any registered tool directly")
    pt.add_argument("tool_name", metavar="<tool>", help="Tool name (see: oneinfinity toolcheck)")
    pt.add_argument("--domain", metavar="DOMAIN")
    pt.add_argument("--target", metavar="TARGET")
    pt.add_argument("--url",    metavar="URL")
    pt.add_argument("--timeout", type=int, metavar="SEC")


