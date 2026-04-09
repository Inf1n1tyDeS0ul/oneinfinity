"""
CLI command handlers for swarm domain.
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

def cmd_swarm(args):
    """oneinfinity swarm <targets_file> — broad scan across many targets."""
    import concurrent.futures
    import threading
    from pathlib import Path

    targets_file = Path(args.targets_file)
    if not targets_file.exists():
        print(f"[!] Targets file not found: {targets_file}")
        return

    targets = [line.strip() for line in targets_file.read_text().splitlines()
               if line.strip() and not line.startswith("#")]
    if not targets:
        print("[!] No targets found in file.")
        return

    output_dir = getattr(args, "output", "recon")
    workers = getattr(args, "workers", 16)
    yes = getattr(args, "yes", False)
    platform = getattr(args, "platform", "hackerone")

    if not yes:
        confirm = input(f"\n[!] Swarm scan {len(targets)} targets? [y/N] ").strip().lower()
        if confirm != "y":
            print("[-] Aborted.")
            return

    from oneinfinity.core.scan_profiles import get_profile
    profile = get_profile("swarm")
    print(f"\n[*] Swarm scan starting — {len(targets)} targets, {workers} workers")
    print(f"[*] Profile: {profile.description}")

    results_lock = threading.Lock()
    findings_count = {}

    def scan_target(target):
        try:
            import types
            fake_args = types.SimpleNamespace(
                subcommand="run",
                domain=target,
                yes=True,
                output=output_dir,
                platform=platform,
                phases=["recon", "scan"],
                timeout=profile.scan_timeout,
                no_learn=False,
            )
            cmd_agents(fake_args)
            with results_lock:
                findings_count[target] = "done"
        except Exception as e:
            with results_lock:
                findings_count[target] = f"error: {e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_target, t): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            target = futures[fut]
            status = findings_count.get(target, "?")
            print(f"[*] {target}: {status}")

    print(f"\n[+] Swarm complete — {len(targets)} targets scanned")


def cmd_swarm_scan(args):
    """oneinfinity swarm-scan <target> — deploy all 14 specialized agents in parallel."""
    import asyncio
    import json as _json
    from pathlib import Path

    target = args.target
    session_cookie = getattr(args, "session_cookie", "") or ""
    bearer_token   = getattr(args, "bearer_token", "") or ""
    has_auth = bool(session_cookie or bearer_token)

    if not getattr(args, "yes", False):
        print(f"\n[*] Swarm Intelligence Scan")
        print(f"    Target      : {target}")
        print(f"    Agents      : {args.agents or 'all 14'}")
        print(f"    Concurrency : {args.concurrency}")
        print(f"    Simulation  : {'disabled' if args.no_simulate else 'enabled'}")
        print(f"    Auth mode   : {'enabled' if has_auth else 'unauthenticated'}")
        ans = input("\n  Proceed? [y/N] ").strip().lower()
        if ans != "y":
            print("  Aborted.")
            return

    try:
        from oneinfinity.agent_swarm_coordinator import AgentSwarmCoordinator, run_swarm
        from oneinfinity.swarm_intelligence_engine import AgentType
    except ImportError as e:
        print(f"[!] Import error: {e}")
        return

    auth_sessions = []
    jwt_tokens = []
    if session_cookie:
        auth_sessions.append({"cookie": session_cookie})
    if bearer_token:
        jwt_tokens.append(bearer_token)

    context = {
        "endpoints":    [ep.strip() for ep in args.endpoints.split(",") if ep.strip()] if args.endpoints else [],
        "tech_stack":   [t.strip() for t in args.tech.split(",") if t.strip()] if args.tech else [],
        "auth_sessions": auth_sessions,
        "jwt_tokens":    jwt_tokens,
    }

    agent_types = None
    if args.agents:
        try:
            agent_types = [AgentType(a) for a in args.agents]
        except ValueError as e:
            print(f"[!] Invalid agent type: {e}")
            return

    print(f"\n[*] Starting swarm scan against {target}...")
    result = asyncio.run(run_swarm(
        target=target,
        context=context,
        concurrency=args.concurrency,
        agent_types=agent_types,
    ))

    # ── Enforcement: register module + publish findings to ingestion bus ───────
    try:
        from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("swarm-scan")
    except Exception:
        pass
    try:
        from oneinfinity.result_ingestion_engine import get_ingestion_engine as _get_ie, RawResult as _RR
        import uuid as _sw_uuid
        _sw_sid = str(_sw_uuid.uuid4())[:8]
        _sw_bus = _get_ie()
        _sw_count = 0
        for _sf in result.findings:
            _sf_dict = _sf if isinstance(_sf, dict) else (
                _sf.__dict__ if hasattr(_sf, "__dict__") else {}
            )
            if _sf_dict:
                _sw_bus.ingest(_RR(scan_id=_sw_sid, source="swarm-scan", raw=_sf_dict))
                _sw_count += 1
        if _sw_count:
            print(f"[+] Ingestion bus: published {_sw_count} finding(s) from swarm-scan")
    except Exception as _swe:
        print(f"[!] Ingestion bus publish skipped: {_swe}")

    print(f"\n{result.summary()}")

    if result.simulation_priorities:
        print("\n[*] Pre-scan simulation top paths:")
        for s in result.simulation_priorities[:5]:
            rec = " ★" if s.get("recommended") else ""
            print(f"    {s['attack_type']:<28}  P={s['probability']:.0%}  EV={s['ev']:.2f}{rec}")

    if result.findings:
        print(f"\n[*] Findings ({len(result.findings)}):")
        print(f"  {'Severity':<10} {'CVSS':>5}  {'Type':<30}  Title")
        print(f"  {'─'*10} {'─'*5}  {'─'*30}  {'─'*40}")
        for f in sorted(result.findings, key=lambda x: x.cvss, reverse=True):
            sev = (f.severity or "?").upper()[:8]
            print(f"  {sev:<10} {f.cvss:>5.1f}  {f.vuln_type:<30}  {f.title[:60]}")

    if args.output:
        Path(args.output).write_text(_json.dumps(result.to_dict(), indent=2, default=str))
        print(f"\n[+] Results saved: {args.output}")


def cmd_distributed(args):
    """
    oneinfinity distributed --workers N [--targets file.txt] [--target domain]

    Distribute scan tasks across N parallel workers using the best available
    queue backend (Redis > shared filesystem > in-process memory).
    """
    from oneinfinity.modules.utils import banner, ok, info, warn, err

    max_workers = getattr(args, "workers", 4)
    targets_file = getattr(args, "targets", "")
    single_target = getattr(args, "target", "")
    output = getattr(args, "output", "")
    worker_mode = getattr(args, "worker_mode", False)

    # Worker mode: pull from queue and scan
    if worker_mode:
        banner(f"Distributed Worker Mode")
        info("Pulling tasks from queue...")
        try:
            from oneinfinity.core.distributed_engine import WorkerNode
            worker = WorkerNode(worker_id=0)
            worker.run()
            ok("Worker finished.")
        except Exception as exc:
            err(f"Worker failed: {exc}")
        return

    banner(f"Distributed Scanner — {max_workers} workers")

    targets = []
    if targets_file:
        try:
            targets.extend(l.strip() for l in open(targets_file) if l.strip())
        except Exception as exc:
            err(f"Could not read targets file: {exc}")
    if single_target:
        targets.append(single_target)

    if not targets:
        err("No targets specified. Use --target or --targets file.txt")
        sys.exit(1)

    info(f"Submitting {len(targets)} targets to {max_workers} workers...")
    try:
        from oneinfinity.core.distributed_engine import DistributedEngine
        engine = DistributedEngine(max_workers=max_workers)
        findings = engine.run(targets=targets)
        stats = engine.stats()

        ok(f"Distributed scan complete.")
        print(f"  Workers     : {max_workers}")
        print(f"  Targets     : {len(targets)}")
        print(f"  Backend     : {stats['backend']}")
        print(f"  Findings    : {len(findings)}")

        if output and findings:
            import json as _json
            Path(output).write_text(_json.dumps(findings, indent=2))
            ok(f"Findings saved: {output}")

    except ImportError as exc:
        err(f"distributed_engine not available: {exc}")
    except Exception as exc:
        err(f"Distributed scan failed: {exc}")
        import traceback; traceback.print_exc()


def cmd_simulate_attacks(args):
    """oneinfinity simulate-attacks <target> — Monte Carlo attack path simulation."""
    import asyncio
    import json as _json
    from pathlib import Path

    try:
        from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("simulate-attacks")
    except Exception:
        pass

    try:
        from oneinfinity.attack_simulation_engine import AttackSimulationEngine
    except ImportError as e:
        print(f"[!] Import error: {e}")
        return

    target     = args.target
    tech_stack = [t.strip() for t in args.tech.split(",") if t.strip()] if args.tech else []
    context    = {
        "tech_stack":    tech_stack,
        "waf_detected":  args.waf,
    }

    print(f"\n[*] Attack Path Simulation: {target}")
    if tech_stack:
        print(f"    Tech stack : {', '.join(tech_stack)}")
    if args.waf:
        print(f"    WAF        : detected (applying penalty)")
    print(f"    Monte Carlo: 200 trials per path\n")

    engine  = AttackSimulationEngine()
    results = asyncio.run(engine.simulate_all_paths(target, context))
    strategy = engine.select_strategy(results)

    AttackSimulationEngine.print_results(results, top_n=args.top)

    print(f"\n[*] Recommended Strategy:")
    print(f"    {strategy.reasoning}")
    print(f"    Agents to deploy: {', '.join(strategy.recommended_agents)}")

    # ── Direct vulnerability tests (race condition + payment tampering) ─────
    extra_findings = []
    probe_url = target if target.startswith("http") else f"https://{target}"
    try:
        from oneinfinity.modules.tool_wrappers import run_race_condition_test, run_payment_tampering_test

        print(f"\n[*] Running race condition test against {probe_url}...")
        rc_results = run_race_condition_test(probe_url)
        rc_list = rc_results if isinstance(rc_results, list) else ([rc_results] if isinstance(rc_results, dict) else [])
        for f in rc_list:
            if isinstance(f, dict) and f.get("severity") not in ("info", None):
                sev = f.get("severity", "?").upper()
                print(f"  [{sev}] Race Condition: {f.get('title', '?')} @ {f.get('url', probe_url)[:80]}")
        extra_findings.extend(rc_list)

        print(f"[*] Running payment/price tampering test against {probe_url}...")
        pt_results = run_payment_tampering_test(probe_url)
        pt_list = pt_results if isinstance(pt_results, list) else ([pt_results] if isinstance(pt_results, dict) else [])
        for f in pt_list:
            if isinstance(f, dict) and f.get("severity") not in ("info", None):
                sev = f.get("severity", "?").upper()
                print(f"  [{sev}] Payment Tampering: {f.get('title', '?')} @ {f.get('url', probe_url)[:80]}")
        extra_findings.extend(pt_list)

        vuln_extra = [f for f in extra_findings if isinstance(f, dict) and f.get("severity") not in ("info", None)]
        if vuln_extra:
            print(f"\n[+] Additional tests: {len(vuln_extra)} finding(s) from race condition/payment checks")
        else:
            print(f"[*] Additional tests: no findings from race condition/payment checks")
    except Exception as _extra_e:
        print(f"[!] Additional tests skipped: {_extra_e}")

    if args.output:
        out = [r.__dict__ for r in results]
        if extra_findings:
            out.extend([f for f in extra_findings if isinstance(f, dict)])
        Path(args.output).write_text(_json.dumps(out, indent=2, default=str))
        print(f"\n[+] Results saved: {args.output}")


def cmd_simulate_workflow(args):
    """oneinfinity simulate-workflow <workflow> — business logic workflow attack simulation."""
    import asyncio
    import json as _json
    from pathlib import Path

    try:
        from oneinfinity.workflow_simulation_engine import WorkflowSimulationEngine, AttackCategory
    except ImportError as e:
        print(f"[!] Import error: {e}")
        return

    categories = None
    if args.categories:
        try:
            categories = [AttackCategory(c) for c in args.categories]
        except ValueError as e:
            print(f"[!] Invalid category: {e}")
            return

    engine = WorkflowSimulationEngine(
        base_url       = args.base_url,
        session_cookie = args.cookie,
        session_token  = args.token,
    )

    workflows_to_run = (engine.list_workflows() if args.workflow == "all"
                        else [args.workflow])

    print(f"\n[*] Workflow Simulation — {args.base_url}")
    print(f"    Workflows  : {', '.join(workflows_to_run)}")
    print(f"    Categories : {', '.join(c.value for c in categories) if categories else 'all'}\n")

    all_findings = []
    for wf_name in workflows_to_run:
        print(f"  [~] Simulating workflow: {wf_name}")
        results = asyncio.run(engine.generate_and_run_attacks(wf_name, categories=categories))
        findings = engine.get_all_findings(results)
        all_findings.extend(findings)

        if results:
            print(f"      Vulnerable: {len(results)} attack(s) succeeded")
            for r in results[:5]:
                print(f"        → [{r.attack_category}] {r.vulnerability_desc[:80]}")
        else:
            print(f"      No vulnerabilities found")

    print(f"\n[*] Total findings: {len(all_findings)}")
    for f in all_findings:
        d = vars(f) if hasattr(f, "__dict__") else {}
        print(f"  [{d.get('severity','?').upper():8s}] {d.get('vuln_type','?')}: {d.get('title','')[:70]}")

    if args.output and all_findings:
        Path(args.output).write_text(_json.dumps(
            [vars(f) if hasattr(f, "__dict__") else f for f in all_findings],
            indent=2, default=str,
        ))
        print(f"\n[+] Results saved: {args.output}")


# ── Self-Evolving Architecture handlers ──────────────────────────────────────




def register(subparsers):
    """Register swarm commands with the CLI argument parser."""
    sub = subparsers
    swarm_cmd = sub.add_parser("swarm",
        help="Swarm scan: broad coverage across many targets with max parallelism")
    swarm_cmd.add_argument("targets_file", help="File with one domain per line")
    swarm_cmd.add_argument("--output", "-o", metavar="DIR", default="recon",
                           help="Output base directory")
    swarm_cmd.add_argument("--yes", "-y", action="store_true")
    swarm_cmd.add_argument("--workers", type=int, default=16,
                           help="Parallel workers (default: 16)")
    swarm_cmd.add_argument("--platform", default="hackerone")

    si_scan = sub.add_parser("swarm-scan",
        help="Multi-agent swarm intelligence scan (14 specialized agents)")
    si_scan.add_argument("target", help="Target domain or URL")
    si_scan.add_argument("--agents", nargs="+",
        choices=["xss", "sqli", "ssrf", "idor", "auth", "business_logic", "mobile", "api",
                 "deserialization", "race_condition", "file_upload", "oauth",
                 "prototype_pollution", "clickjacking"],
        default=None, help="Agent types to deploy (default: all 14)")
    si_scan.add_argument("--concurrency", type=int, default=6,
        help="Max concurrent agents (default: 6)")
    si_scan.add_argument("--no-simulate", action="store_true",
        help="Skip pre-scan attack path simulation")
    si_scan.add_argument("--endpoints", default="",
        help="Comma-separated endpoint list to focus agents on")
    si_scan.add_argument("--tech", default="",
        help="Comma-separated tech stack hints (e.g. php,mysql,aws)")
    si_scan.add_argument("--session-cookie", default="", dest="session_cookie",
        help="Session cookie for authenticated scanning (e.g. session=abc123)")
    si_scan.add_argument("--bearer-token", default="", dest="bearer_token",
        help="Bearer token for authenticated scanning (JWT or API key)")
    si_scan.add_argument("--output", "-o", default="",
        help="Write JSON results to this file")
    si_scan.add_argument("--yes", "-y", action="store_true", help="Skip confirmation")

    dist = sub.add_parser(
        "distributed",
        help="Distributed scanning: spread targets across N parallel workers",
    )
    dist.add_argument("--workers", type=int, default=4,
                      help="Number of parallel scan workers (default: 4)")
    dist.add_argument("--target", default="",
                      help="Single target domain to scan")
    dist.add_argument("--targets", default="",
                      help="Path to file with one target per line")
    dist.add_argument("--output", "-o", default="",
                      help="Write aggregated findings JSON to this file")
    dist.add_argument("--worker", dest="worker_mode", action="store_true",
                      help="Run as a worker node (pull tasks from queue)")

    si_sim = sub.add_parser("simulate-attacks",
        help="Simulate attack paths with Monte Carlo probability scoring (no live testing)")
    si_sim.add_argument("target", help="Target domain or URL")
    si_sim.add_argument("--tech", default="",
        help="Comma-separated tech stack hints (e.g. php,mysql,aws)")
    si_sim.add_argument("--waf", action="store_true", help="Mark target as WAF-protected")
    si_sim.add_argument("--top", type=int, default=10, help="Show top N results (default: 10)")
    si_sim.add_argument("--output", "-o", default="", help="Write JSON results to this file")

    wf_sim = sub.add_parser("simulate-workflow",
        help="Simulate business logic workflow attacks (checkout, login, transfer, etc.)")
    wf_sim.add_argument("workflow",
        choices=["checkout_flow", "login_flow", "password_reset_flow",
                 "fund_transfer_flow", "all"],
        help="Workflow to simulate")
    wf_sim.add_argument("--base-url", default="http://localhost",
        help="Base URL of the target application (default: http://localhost)")
    wf_sim.add_argument("--categories", nargs="+",
        choices=["price_manipulation", "coupon_stacking", "workflow_step_skip",
                 "race_condition", "parameter_tampering", "privilege_escalation",
                 "negative_quantity", "integer_overflow"],
        default=None, help="Attack categories to test (default: all)")
    wf_sim.add_argument("--cookie", default="", help="Session cookie for authenticated testing")
    wf_sim.add_argument("--token", default="", help="Bearer token for authenticated testing")
    wf_sim.add_argument("--output", "-o", default="", help="Write JSON results to this file")


