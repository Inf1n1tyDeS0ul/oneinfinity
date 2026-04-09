"""
CLI command handlers for daemon domain.
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

def cmd_daemon_start(args):
    """oneinfinity daemon-start <target> [--targets t1,t2,...] — start the intelligence daemon."""
    raw = getattr(args, 'args', [])
    targets = []
    if raw:
        # Support both space-separated and comma-separated targets
        for t in raw:
            targets.extend(t.split(','))
    targets = [t.strip() for t in targets if t.strip()]

    if not targets:
        print("Usage: oneinfinity daemon-start <target> [target2 ...]")
        return

    try:
        from oneinfinity.intelligence_daemon import get_daemon
        d = get_daemon()
        if not d._running:
            d.start(targets=targets)
            print(f"  [+] Intelligence daemon started for: {', '.join(targets)}")
        else:
            for t in targets:
                d.add_target(t)
            print(f"  [+] Added targets to running daemon: {', '.join(targets)}")
        print(f"  [*] Active targets: {', '.join(sorted(d._targets))}")
        print(f"  [*] Workers: {len(d._workers)} loaded")
    except Exception as e:
        print(f"  [!] Error starting daemon: {e}")


def cmd_daemon_stop(args):
    """oneinfinity daemon-stop — stop the intelligence daemon."""
    try:
        from oneinfinity.intelligence_daemon import get_daemon
        d = get_daemon()
        if d._running:
            d.stop()
            print("  [+] Intelligence daemon stopped.")
        else:
            print("  [*] Daemon was not running.")
    except Exception as e:
        print(f"  [!] Error stopping daemon: {e}")


def cmd_daemon_status(args):
    """oneinfinity daemon-status — show daemon status and worker states."""
    try:
        from oneinfinity.intelligence_daemon import get_daemon
        d = get_daemon()
        status = d.status()
        running = status.get("running", False)
        print(f"\n  Intelligence Daemon — {'RUNNING' if running else 'STOPPED'}")
        print(f"  Uptime   : {status.get('uptime_s', 0):.0f}s")
        print(f"  Targets  : {', '.join(status.get('targets', [])) or 'none'}")

        workers = status.get("workers", {})
        if workers:
            print(f"\n  {'Worker':<22}  {'Status':<10}  {'Runs':>6}  {'Findings':>8}  {'Errors':>7}")
            print(f"  {'─'*22}  {'─'*10}  {'─'*6}  {'─'*8}  {'─'*7}")
            for name, ws in workers.items():
                st = ws.get("status", "?")
                runs = ws.get("runs", 0)
                findings = ws.get("findings", 0)
                errors = ws.get("errors", 0)
                enabled = "" if ws.get("enabled", True) else " [disabled]"
                print(f"  {name:<22}  {st:<10}  {runs:>6}  {findings:>8}  {errors:>7}{enabled}")

        try:
            from oneinfinity.event_bus import get_bus
            bus_stats = get_bus().stats()
            print(f"\n  Event Bus — published: {bus_stats.get('published', 0)}, "
                  f"processed: {bus_stats.get('processed', 0)}, "
                  f"dlq: {bus_stats.get('dlq_size', 0)}")
        except Exception:
            pass
        print()
    except Exception as e:
        print(f"  [!] Error reading daemon status: {e}")


def cmd_daemon_add_target(args):
    """oneinfinity daemon-add-target <target> — add a target to the running daemon."""
    raw = getattr(args, 'args', [])
    if not raw:
        print("Usage: oneinfinity daemon-add-target <target>")
        return
    target = raw[0].strip()
    try:
        from oneinfinity.intelligence_daemon import get_daemon
        d = get_daemon()
        d.add_target(target)
        print(f"  [+] Target '{target}' added to daemon.")
        print(f"  [*] Active targets: {', '.join(sorted(d._targets))}")
    except Exception as e:
        print(f"  [!] Error adding target: {e}")


# ── Model Orchestrator handlers ───────────────────────────────────────────────


def cmd_arch_status(args):
    """oneinfinity arch-status — show evolution engine status, recent changes, capabilities."""
    import json as _json
    try:
        from oneinfinity.auto_architecture_engine import cmd_arch_status as _status
        status = _status()
    except Exception as e:
        print(f"  [!] Error loading arch engine: {e}")
        return

    print("\n╔══════════════════════════════════════════════════════╗")
    print("║      One&Infinity — Self-Evolving Architecture       ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    es = status.get("engine_stats", {})
    print(f"  Events logged   : {es.get('total_events_logged', 0)}")
    print(f"  Queue size      : {es.get('queue_size', 0)}")
    print(f"  Running         : {es.get('running', False)}")

    ms = status.get("memory_stats", {})
    if ms:
        print(f"\n  Memory Store:")
        for k, v in ms.items():
            print(f"    {k:<25} {v}")

    print(f"\n  Skills: {status.get('total_skills', 0)} total")
    by_cat = status.get("skills_by_category", {})
    for cat, count in sorted(by_cat.items()):
        print(f"    {cat:<30} {count}")

    changes = status.get("recent_changes", [])
    if changes:
        print(f"\n  Recent Architecture Changes:")
        for c in changes[:5]:
            ts = _json.dumps(c.get("changed_at", ""))[:10]
            print(f"    [{c.get('change_type','?'):20s}] {c.get('summary','')[:60]}")

    insights = status.get("recent_insights", [])
    if insights:
        print(f"\n  Recent Insights (24h):")
        for ins in insights[:5]:
            print(f"    [{ins.get('category','?'):15s}] {ins.get('title','')[:60]}")
    print()


def cmd_arch_events(args):
    """oneinfinity arch-events — list recent platform events from the event bus."""
    limit = getattr(args, "limit", 20)
    etype = getattr(args, "type", "")
    try:
        from oneinfinity.auto_architecture_engine import get_engine
        engine = get_engine()
        events = engine.recent_events(limit=limit, event_type=etype)
    except Exception as e:
        print(f"  [!] {e}")
        return

    if not events:
        print("  No events recorded yet.")
        return

    print(f"\n  Recent Events ({len(events)}):")
    print(f"  {'Type':<30} {'Source':<25} {'Time'}")
    print("  " + "-" * 70)
    for ev in events:
        import datetime
        ts = datetime.datetime.fromtimestamp(ev.get("timestamp", 0)).strftime("%H:%M:%S")
        print(f"  {ev.get('event_type','?'):<30} {ev.get('source','?'):<25} {ts}")
    print()


def cmd_arch_insights(args):
    """oneinfinity arch-insights — show learning insights from the evolution memory."""
    limit  = getattr(args, "limit", 20)
    cat    = getattr(args, "category", "")
    hours  = getattr(args, "hours", 24)
    try:
        from oneinfinity.memory_manager import get_memory_manager
        mm = get_memory_manager()
        insights = mm.recent_insights(hours=hours, limit=limit)
        if cat:
            insights = [i for i in insights if i.get("category") == cat]
    except Exception as e:
        print(f"  [!] {e}")
        return

    if not insights:
        print(f"  No insights in the last {hours}h.")
        return

    print(f"\n  Learning Insights (last {hours}h):\n")
    for ins in insights:
        import datetime
        ts = datetime.datetime.fromtimestamp(ins.get("created_at", 0)).strftime("%Y-%m-%d %H:%M")
        conf = ins.get("confidence", 0)
        print(f"  ┌─ [{ins.get('category','?'):15s}] {ins.get('title','')}")
        print(f"  │  Confidence: {conf:.0%}  |  {ts}")
        body = ins.get("body", "")
        if body:
            print(f"  │  {body[:100]}")
        print(f"  └─ tags: {', '.join(ins.get('tags', []))}\n")


def cmd_arch_emit(args):
    """oneinfinity arch-emit feature_added --name X --desc Y --cat Z — emit a test event."""
    etype = getattr(args, "event_type", "feature_added")
    name  = getattr(args, "name", "Test Feature")
    desc  = getattr(args, "desc", "")
    cat   = getattr(args, "cat", "General")
    try:
        from oneinfinity.auto_architecture_engine import get_engine, ArchEvent, EventType
        engine = get_engine()
        ev = ArchEvent(
            event_type=EventType(etype),
            source="cli",
            data={"name": name, "description": desc, "category": cat},
        )
        eid = engine.emit(ev)
        print(f"  [+] Event emitted: {eid}")
    except Exception as e:
        print(f"  [!] {e}")


# ── Intelligence Daemon handlers ──────────────────────────────────────────────


def cmd_god_mode(args):
    """oneinfinity god-mode <target> — GOD MODE: full adaptive cascade, zero feature skip."""
    from oneinfinity.god_mode_engine import get_god_mode_conductor, GOD_MODE_LOG_DIR

    sub = getattr(args, "subcommand", None)

    # Argparse ambiguity: when [target] is optional and comes before subparsers,
    # a bare subcommand keyword (e.g. "stop") may be consumed as target.
    # Detect and re-route: if target holds a subcommand keyword, shift it.
    target_val = getattr(args, "target", None) or ""
    if not sub and target_val in ("status", "logs", "stop", "run"):
        sub = target_val
        args.target = ""

    # ── status ────────────────────────────────────────────────────────────────
    if sub == "status":
        scan_id = getattr(args, "scan_id", None) or None
        conductor = get_god_mode_conductor()
        data = conductor.status(scan_id)
        if data is None:
            print("  [!] No GOD MODE session found." + (f" (id: {scan_id})" if scan_id else ""))
            return
        print(f"\n  GOD MODE Session: {data.get('scan_id')}")
        print(f"  Target:     {data.get('target')}")
        print(f"  Elapsed:    {data.get('elapsed_seconds', 0):.0f}s")
        print(f"  Findings:   {data.get('finding_count', 0)}")
        print(f"  Terminated: {data.get('terminated_by') or 'running'}")
        print(f"  Missions:")
        for name, status in (data.get("missions") or {}).items():
            print(f"    {name:<12} {status}")
        print()
        return

    # ── logs ──────────────────────────────────────────────────────────────────
    if sub == "logs":
        import subprocess as _sp
        scan_id = getattr(args, "scan_id", None) or None
        if scan_id:
            log_path = str(GOD_MODE_LOG_DIR / f"god-mode-{scan_id}.log")
        else:
            files = sorted(GOD_MODE_LOG_DIR.glob("god-mode-*.log"),
                           key=lambda p: p.stat().st_mtime, reverse=True) if GOD_MODE_LOG_DIR.exists() else []
            if not files:
                print("  [!] No GOD MODE log files found.")
                return
            log_path = str(files[0])
        follow = getattr(args, "follow", False)
        if follow:
            _sp.run(["tail", "-f", log_path])
        else:
            _sp.run(["tail", "-n", "100", log_path])
        return

    # ── stop ──────────────────────────────────────────────────────────────────
    if sub == "stop":
        scan_id = getattr(args, "scan_id", None) or None
        conductor = get_god_mode_conductor()
        ok = conductor.stop(scan_id)
        if ok:
            print(f"  [+] Stop sentinel written. GOD MODE will finalize within 30s.")
        else:
            print("  [!] No active GOD MODE session found to stop.")
        return

    # ── run (default) ─────────────────────────────────────────────────────────
    if sub == "run":
        raw = getattr(args, "args", [])
        if raw:
            target = raw[0].strip()
        else:
            target = getattr(args, "target", None)
            if not target or target == "run":
                target = getattr(args, "scan_id", None) # argparse might have shifted it
    else:
        target = getattr(args, "target", None)

    if not target:
        print("Usage: oneinfinity god-mode <target> [options]")
        print("       oneinfinity god-mode status [scan-id]")
        print("       oneinfinity god-mode logs [--follow]")
        print("       oneinfinity god-mode stop [scan-id]")
        return

    background = getattr(args, "background", False)
    conductor = get_god_mode_conductor()
    conductor.run(
        target=target,
        background=background,
        no_swarm=getattr(args, "no_swarm", False),
        no_research=getattr(args, "no_research", False),
        report_fmt=getattr(args, "report_fmt", "markdown") or "markdown",
    )

    # Non-daemon background threads (daemon=False in GodModeConductor) keep
    # the process alive until the scan finishes — no need for a busy-wait loop here.




def register(subparsers):
    """Register daemon commands with the CLI argument parser."""
    sub = subparsers
    mob.add_argument("--fuzz", action="store_true", help="Fuzz discovered API endpoints")
    mob.add_argument("--device", default="", help="ADB device serial for dynamic analysis")
    mob.add_argument("--proxy-host", default="", help="Proxy host for traffic capture")
    mob.add_argument("--proxy-port", type=int, default=8080, help="Proxy port (default: 8080)")
    mob.add_argument("--output", default="", help="Output directory for report JSON")

    mob_static = sub.add_parser("mobile-static", help="Static analysis only (APK/IPA)")
    mob_static.add_argument("file", help="Path to APK or IPA file")
    mob_static.add_argument("--output", default="", help="Output file for results JSON")

    mob_dyn = sub.add_parser("mobile-dynamic", help="Dynamic analysis (requires connected device)")
    mob_dyn.add_argument("file", help="Path to APK file")
    mob_dyn.add_argument("package", help="Package name (e.g. com.example.app)")
    mob_dyn.add_argument("--device", default="", help="ADB device serial")
    mob_dyn.add_argument("--timeout", type=int, default=60, help="Analysis timeout seconds")

    mob_api = sub.add_parser("mobile-api-scan", help="Discover and fuzz mobile API endpoints")
    mob_api.add_argument("file", help="Path to APK or IPA file")
    mob_api.add_argument("--fuzz", action="store_true", help="Fuzz discovered endpoints")
    mob_api.add_argument("--output", default="", help="Output file for results JSON")

    mob_rep = sub.add_parser("mobile-report", help="Generate mobile security report from saved analysis")
    mob_rep.add_argument("app_id", help="App ID from previous analysis")
    mob_rep.add_argument("--format", choices=["json", "markdown", "html"], default="markdown")
    mob_rep.add_argument("--output", default="", help="Output file path")

    # ── Autonomous Bounty Hunter ───────────────────────────────────────────────
    hunt = sub.add_parser("hunter-start", help="Start autonomous multi-target bug bounty hunter")
    hunt.add_argument("--max-targets", type=int, default=5, help="Max targets to scan (default: 5)")
    gm = sub.add_parser("god-mode",
        help="GOD MODE: full adaptive cascade — every capability, zero skip")
    gm.add_argument("target", nargs="?", default="",
                    help="Target URL/domain, or: status / logs / stop")
    gm.add_argument("scan_id", nargs="?", default="",
                    help="Session ID for status/logs/stop (default: most recent)")
    gm.add_argument("--follow", "-f", action="store_true",
                    help="Follow log output (like tail -f) — used with 'logs'")
    gm.add_argument("--background", action="store_true",
                    help="Detach to background after Stage 1 (foundation)")
    gm.add_argument("--no-swarm", action="store_true",
                    help="Skip SwarmMission (lighter mode)")
    gm.add_argument("--no-research", action="store_true",
                    help="Skip ResearchMission (faster mode)")
    gm.add_argument("--report-fmt", default="markdown",
                    choices=["markdown", "json", "html"],
                    help="Report format (default: markdown)")


