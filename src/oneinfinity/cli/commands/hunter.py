"""
CLI command handlers for hunter domain.
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

def cmd_hunter_start(args):
    """oneinfinity hunter-start — start autonomous multi-target bug bounty hunter."""
    import json as _json
    platforms = [p.strip() for p in getattr(args, "platforms", "hackerone").split(",")]
    auto_exploit = getattr(args, "auto_exploit", False)
    validate = not getattr(args, "no_validate", False)
    max_targets = getattr(args, "max_targets", 5)
    yes = getattr(args, "yes", False)
    out = getattr(args, "output", "")

    print(f"\n[*] Autonomous Bounty Hunter")
    print(f"    Platforms  : {', '.join(platforms)}")
    print(f"    Max targets: {max_targets}")
    print(f"    Auto-exploit: {auto_exploit}")
    print(f"    Validate:    {validate}")
    if not yes:
        resp = input("\nStart autonomous hunt? [y/N] ").strip().lower()
        if resp not in ("y", "yes"):
            print("Aborted.")
            return

    try:
        from oneinfinity.bounty.bounty_hunter_engine import BountyHunterEngine, HunterConfig
        engine = BountyHunterEngine()
        config = HunterConfig(
            max_targets=max_targets,
            auto_exploit=auto_exploit,
            validate_findings=validate,
            platforms=platforms,
        )
        print("\n[+] Starting autonomous hunt...\n")
        result = engine.run(config)
        rd = result if isinstance(result, dict) else {}
        findings = rd.get("findings", [])
        print(f"\n[✓] Hunt complete. {len(findings)} findings discovered.")
        if out and findings:
            Path(out).mkdir(parents=True, exist_ok=True)
            (Path(out) / "findings.json").write_text(_json.dumps(findings, indent=2))
            print(f"[+] Results saved: {out}/findings.json")
    except ImportError:
        print("[!] bounty_hunter_engine not found. Install or run the platform first.")
    except Exception as e:
        print(f"[✗] Error: {e}")


def cmd_hunter_scan(args):
    """Deploy autonomous 9-phase scan pipeline against a target."""
    from oneinfinity.modules.utils import banner, info, ok, err, ask
    from oneinfinity.scan.unified_scan_engine import get_engine

    target = args.target
    yes = getattr(args, "yes", False)

    banner(f"Hunter Scan — {target}")
    
    if not yes:
        resp = ask(f"Launch full autonomous scan against {target}? [y/N]: ").lower().strip()
        if resp not in ("y", "yes"):
            info("Aborted.")
            return

    engine = get_engine()
    
    def on_progress(phase, pct, msg):
        print(f"  [{pct}%] {phase}: {msg}")

    try:
        session = engine.scan(target, on_progress=on_progress)
        
        if session.status == "failed":
            err(f"Scan failed.")
        else:
            ok(f"Scan complete. Found {len(session.findings)} findings.")
            for f in session.findings[:10]:
                severity = f.get("severity", "info").upper()
                title = f.get("title", "Unknown")
                print(f"  [{severity:8s}] {title[:60]}")
            
            if len(session.findings) > 10:
                print(f"  ... and {len(session.findings)-10} more.")
                
    except Exception as exc:
        err(f"Scan execution failed: {exc}")


def cmd_hunter_status(args):
    """oneinfinity hunter-status — show status of active/recent session."""
    import json as _json
    import glob as _glob
    session_id = getattr(args, "session", "")
    watch = getattr(args, "watch", False)

    session_dir = raw_dir() / "hunter_sessions.json"
    if not session_dir.exists():
        print("[!] No hunter sessions found.")
        return

    try:
        sessions = _json.loads(session_dir.read_text())
        if session_id:
            s = sessions.get(session_id)
            if not s:
                print(f"[!] Session not found: {session_id}")
                return
            sessions_list = [s]
        else:
            sessions_list = list(sessions.values())[-5:]

        for s in sessions_list:
            sid = s.get("session_id", "?")[:12]
            status = s.get("status", "?")
            target = s.get("current_target", "multiple targets")
            nfindings = len(s.get("findings", []))
            progress = s.get("progress", 0)
            print(f"  [{status:10s}] {sid} | {target} | {nfindings} findings | {progress}%")
            if watch and s.get("status") == "running":
                log = s.get("progress_log", [])
                for line in log[-10:]:
                    print(f"    {line}")
    except Exception as e:
        print(f"[!] Error reading sessions: {e}")


def cmd_hunter_report(args):
    """oneinfinity hunter-report <session_id> — generate findings report."""
    import json as _json
    session_id = args.session_id
    fmt = getattr(args, "format", "markdown")
    platform = getattr(args, "platform", "HackerOne")
    out = getattr(args, "output", "")

    session_file = raw_dir() / "hunter_sessions.json"
    if not session_file.exists():
        print("[!] No sessions found.")
        return

    try:
        sessions = _json.loads(session_file.read_text())
        session = sessions.get(session_id)
        if not session:
            print(f"[!] Session not found: {session_id}")
            return

        findings = session.get("findings", [])
        target = session.get("current_target") or "multi-target"

        from oneinfinity.bounty.bounty_report_generator import bounty_report_generator
        report = bounty_report_generator.generate(target, findings, platform=platform, session_id=session_id)

        if fmt == "markdown":
            content = bounty_report_generator._render_markdown(report)
        elif fmt == "html":
            content = bounty_report_generator._render_html(report)
        else:
            content = _json.dumps(report.to_dict(), indent=2)

        if out:
            Path(out).write_text(content)
            print(f"[+] Report saved: {out}")
        else:
            print(content)
    except ImportError:
        print("[!] bounty_report_generator not found.")
    except Exception as e:
        print(f"[✗] Error: {e}")


def cmd_hunter(args):
    """
    oneinfinity hunter --scope scope.yaml [options]

    Full domination-mode bounty hunter:
      1. Loads scope from scope.yaml
      2. Discovers + prioritizes targets
      3. Scans in parallel (--workers)
      4. Generates submission-ready reports
    """
    from oneinfinity.modules.utils import banner, info, ok, warn, err

    scope_file = getattr(args, "scope", "") or "scope.yaml"
    max_targets = getattr(args, "max_targets", 10)
    max_workers = getattr(args, "workers", 3)
    severity_threshold = getattr(args, "severity", "medium")
    scan_mode = getattr(args, "mode", "fast")
    elite_strategy = getattr(args, "strategy", "")
    output_dir = getattr(args, "output", "")
    platforms = [p.strip() for p in getattr(args, "platforms", "hackerone").split(",")]
    benchmark_ref = getattr(args, "benchmark_ref", "")
    yes = getattr(args, "yes", False)

    banner("OneInfinity Hunter — Domination Mode")

    # Load and validate scope
    scope_path = Path(scope_file)
    if not scope_path.exists():
        scope_path = Path.cwd() / scope_file
    if not scope_path.exists():
        err(f"scope.yaml not found: {scope_file}")
        info("Create one with: oneinfinity setup <program-name>")
        sys.exit(1)

    try:
        from oneinfinity.modules.scope import ScopeManager
        sm = ScopeManager(str(scope_path.parent))
        sm.load()
        ok(f"Scope loaded: {scope_path}")
        sm.show_scope()
    except Exception as exc:
        warn(f"Could not display scope: {exc}")

    # Show persistent memory status
    try:
        from oneinfinity.learning.persistent_memory import get_memory as _gm
        _mem = _gm()
        _ms = _mem.stats()
        if _ms["total_runs"] > 0:
            ok(f"Persistent memory: {_ms['total_runs']} prior runs, "
               f"{_ms['total_findings']} findings ({_ms['total_confirmed']} confirmed)")
        else:
            info("Persistent memory: first run — learning begins now")
    except Exception:
        pass

    if not yes:
        resp = input("\nStart autonomous hunt? (you confirm authorization) [y/N]: ").strip().lower()
        if resp not in ("y", "yes"):
            print("Aborted.")
            sys.exit(0)

    try:
        from oneinfinity.bounty.bounty_hunter_engine import BountyHunterEngine, HunterConfig
        engine = BountyHunterEngine()
        config = HunterConfig(
            name=scope_path.parent.name,
            platforms=platforms,
            max_targets=max_targets,
            max_concurrent=max_workers,
            severity_threshold=severity_threshold,
            auto_exploit=True,
            auto_report=True,
            output_dir=output_dir,
            scan_mode=scan_mode,
            benchmark_ref_file=benchmark_ref,
            strategy=elite_strategy,
        )
        info(f"Scan mode  : {scan_mode}")
        if elite_strategy:
            info(f"Strategy   : {elite_strategy}")
        if benchmark_ref:
            info(f"Benchmark  : {benchmark_ref}")

        info(f"Scanning up to {max_targets} targets with {max_workers} parallel workers...")
        session = engine.run(config)

        print()
        ok(f"Hunt complete — {len(session.findings)} total findings, "
           f"{sum(1 for f in session.findings if f.confirmed)} confirmed")

        # Severity breakdown
        sev_counts: dict = {}
        for f in session.findings:
            s = f.severity if hasattr(f, "severity") else f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in sev_counts:
                print(f"  {sev:8s}: {sev_counts[sev]}")

        # Generate submission-ready report
        if session.findings:
            out = Path(output_dir) if output_dir else Path.cwd() / "reports"
            out.mkdir(parents=True, exist_ok=True)
            from oneinfinity.bounty.bounty_report_generator import bounty_report_generator
            findings_raw = [
                f.to_dict() if hasattr(f, "to_dict") else f
                for f in session.findings
            ]
            report = bounty_report_generator.generate(
                target=config.name,
                findings=findings_raw,
                platform=platforms[0].title() if platforms else "HackerOne",
                session_id=session.session_id,
            )
            paths = bounty_report_generator.save_all_formats(report, out / session.session_id)
            print()
            ok(f"Reports saved:")
            for fmt, p in paths.items():
                print(f"  {fmt:<10} {p}")

        # Benchmark metrics (always shown)
        m = session.benchmark_metrics
        if m:
            print()
            ok("Quality metrics:")
            print(f"  confirmed     : {m.get('confirmed', 0)}/{m.get('total_findings', 0)} "
                  f"({m.get('confirmed_pct', 0)}%)")
            print(f"  avg confidence: {m.get('avg_confidence', 0):.0%}")
            print(f"  coverage      : {m.get('targets_hit', 0)}/{m.get('targets_scanned', 0)} targets "
                  f"({m.get('coverage_pct', 0)}%)")
            if "accuracy_score" in m:
                print(f"  vs reference  : accuracy={m['accuracy_score']:.0%}, "
                      f"missed={m.get('missed_count', 0)}, extra={m.get('extra_count', 0)}")
            focus = session.ctx.get("focus_targets", [])
            if focus:
                print()
                info(f"Feedback loop: {len(focus)} focus targets saved for next run")
                info("Re-run with --mode deep to prioritise these targets")

    except ImportError as exc:
        err(f"Could not load bounty_hunter_engine: {exc}")
    except Exception as exc:
        err(f"Hunter failed: {exc}")
        import traceback; traceback.print_exc()




def register(subparsers):
    """Register hunter commands with the CLI argument parser."""
    sub = subparsers
    hunt = sub.add_parser("hunter-start", help="Start autonomous multi-target bug bounty hunter")
    hunt.add_argument("--max-targets", type=int, default=5, help="Max targets to scan (default: 5)")
    hunt.add_argument("--auto-exploit", action="store_true", help="Attempt auto-exploitation of findings")
    hunt.add_argument("--no-validate", action="store_true", help="Skip finding validation")
    hunt.add_argument("--platforms", default="hackerone", help="Bug bounty platforms: hackerone,bugcrowd,intigriti")
    hunt.add_argument("--yes", action="store_true", help="Skip confirmation")
    hunt.add_argument("--output", default="", help="Output directory for session results")

    hunt_scan = sub.add_parser("hunter-scan", help="Scan a specific target through the autonomous pipeline")
    hunt_scan.add_argument("target", help="Target domain to scan")
    hunt_scan.add_argument("--auto-exploit", action="store_true", help="Attempt exploitation")
    hunt_scan.add_argument("--no-validate", action="store_true", help="Skip validation")
    hunt_scan.add_argument("--output", default="", help="Output directory")
    hunt_scan.add_argument("--yes", action="store_true", help="Skip confirmation")

    hunt_status = sub.add_parser("hunter-status", help="Show status of active/recent hunter session")
    hunt_status.add_argument("--session", default="", help="Session ID (default: latest)")
    hunt_status.add_argument("--watch", action="store_true", help="Continuously poll status")

    hunt_report = sub.add_parser("hunter-report", help="Generate findings report from a hunter session")
    hunt_report.add_argument("session_id", help="Session ID to generate report for")
    hunt_report.add_argument("--format", choices=["markdown", "json", "html"], default="markdown")
    hunt_report.add_argument("--platform", default="HackerOne", help="Bug bounty platform template")
    hunt_report.add_argument("--output", default="", help="Output file path")

    hunter = sub.add_parser(
        "hunter",
        help="Domination-mode bounty hunter: scope → discover → parallel scan → report",
    )
    hunter.add_argument("--scope", default="scope.yaml",
                        help="Path to scope.yaml (default: scope.yaml in cwd)")
    hunter.add_argument("--max-targets", type=int, default=10, dest="max_targets",
                        help="Max targets to scan (default: 10)")
    hunter.add_argument("--workers", type=int, default=3,
                        help="Parallel scan workers (default: 3)")
    hunter.add_argument("--severity", default="medium",
                        choices=["critical", "high", "medium", "low", "info"],
                        help="Minimum severity threshold for reporting (default: medium)")
    hunter.add_argument("--platforms", default="hackerone",
                        help="Bug bounty platforms: hackerone,bugcrowd,intigriti (default: hackerone)")
    hunter.add_argument("--output", default="",
                        help="Output directory for reports (default: ./reports)")
    hunter.add_argument("--mode", "-m",
                        choices=["fast", "deep", "api-heavy", "stealth"],
                        default="fast",
                        help="Scan strategy: fast (default), deep, api-heavy, stealth")
    hunter.add_argument("--strategy", "-s",
                        choices=["aggressive", "stealthy", "high-value"],
                        default="",
                        help="Elite strategy: aggressive (broad+fast), stealthy (evasive), "
                             "high-value (auth/API ROI-focus)")
    hunter.add_argument("--yes", "-y", action="store_true",
                        help="Skip confirmation prompt")
    hunter.add_argument("--benchmark-ref", default="", dest="benchmark_ref",
                        metavar="FILE",
                        help="Burp/Nuclei reference file for post-hunt accuracy benchmark")


