"""
learning — Learning Intelligence CLI commands

  oneinfinity learning status
  oneinfinity learning patterns [--target TARGET]
  oneinfinity learning memory [--show-payloads]
  oneinfinity learning history [--limit N]
  oneinfinity learning tools [--vuln-type TYPE]
"""
from __future__ import annotations


def handle_learning(args):
    cmd = getattr(args, "learning_cmd", None)
    if cmd == "status":
        _learning_status()
    elif cmd == "patterns":
        _learning_patterns(getattr(args, "target", None))
    elif cmd == "memory":
        _learning_memory(getattr(args, "show_payloads", False))
    elif cmd == "history":
        _learning_history(getattr(args, "limit", 20))
    elif cmd == "tools":
        _learning_tools(getattr(args, "vuln_type", None))
    else:
        print("Usage: oneinfinity learning [status|patterns|memory|history|tools]")


def _learning_status():
    try:
        from oneinfinity.learning.persistent_memory import get_memory, load_memory
        load_memory()
        mem = get_memory()
        data = mem._data if hasattr(mem, '_data') else {}
        print("─── Learning Intelligence Status ───")
        print(f"  Successful payloads:  {len(data.get('successful_payloads', []))}")
        print(f"  Vulnerable patterns:  {len(data.get('vulnerable_patterns', []))}")
        print(f"  Failed payloads:      {len(data.get('failed_payloads', []))}")
        print(f"  Target profiles:      {len(data.get('target_profiles', {}))}")
        print(f"  Run count:            {data.get('run_count', 0)}")
        # KB stats
        try:
            from oneinfinity.core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            if mgr and mgr.mode in ("postgres", "distributed"):
                rows = mgr.sync_pg_execute_read("SELECT COUNT(*) FROM pattern_library", ())
                print(f"  Mined patterns in DB: {rows[0][0] if rows else 0}")
                rows2 = mgr.sync_pg_execute_read("SELECT COUNT(*) FROM tool_performance", ())
                print(f"  Tool perf records:    {rows2[0][0] if rows2 else 0}")
        except Exception:
            pass
    except Exception as exc:
        print(f"Error: {exc}")


def _learning_patterns(target=None):
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if not mgr or mgr.mode not in ("postgres", "distributed"):
            print("PostgreSQL required for pattern data. Current mode: " + getattr(mgr, 'mode', 'unknown'))
            return
        rows = mgr.sync_pg_execute_read(
            "SELECT tech_stack_key, vuln_type, occurrence_count, avg_cvss, best_tool "
            "FROM pattern_library ORDER BY occurrence_count DESC LIMIT 30",
            ()
        )
        if not rows:
            print("No patterns mined yet. Run scans to populate the learning database.")
            return
        print("─── Mined Vulnerability Patterns ───")
        print(f"  {'Tech Stack':<20} {'Vuln Type':<25} {'Count':>5} {'CVSS':>5} {'Best Tool'}")
        print("  " + "─" * 80)
        for r in rows:
            tech, vtype, count, cvss, tool = r
            print(f"  {str(tech):<20} {str(vtype):<25} {count:>5} {float(cvss or 0):>5.1f} {tool}")
    except Exception as exc:
        print(f"Error: {exc}")


def _learning_memory(show_payloads=False):
    try:
        from oneinfinity.learning.persistent_memory import get_memory, load_memory
        load_memory()
        mem = get_memory()
        data = mem._data if hasattr(mem, '_data') else {}
        print("─── Persistent Memory Contents ───")
        profiles = data.get("target_profiles", {})
        if profiles:
            print(f"\n  Target Profiles ({len(profiles)}):")
            for domain, profile in list(profiles.items())[:10]:
                print(f"    {domain}: {profile}")
        if show_payloads:
            payloads = data.get("successful_payloads", [])
            if payloads:
                print(f"\n  Successful Payloads (last {min(20, len(payloads))}):")
                for p in payloads[-20:]:
                    print(f"    [{p.get('vuln_type','?'):15}] {str(p.get('payload',''))[:60]}")
        patterns = data.get("vulnerable_patterns", [])
        if patterns:
            print(f"\n  Vulnerable Patterns (last {min(15, len(patterns))}):")
            for p in patterns[-15:]:
                print(f"    {p}")
    except Exception as exc:
        print(f"Error: {exc}")


def _learning_history(limit=20):
    try:
        from oneinfinity.learning.persistent_memory import get_memory, load_memory
        import json, pathlib
        load_memory()
        mem = get_memory()
        hist_path = mem._hist_path() if hasattr(mem, '_hist_path') else None
        if not hist_path or not pathlib.Path(hist_path).exists():
            print("No run history file found.")
            return
        history = json.loads(pathlib.Path(hist_path).read_text())
        recent = list(reversed(history))[:limit]
        print(f"─── Scan Run History (last {len(recent)}) ───")
        for run in recent:
            ts = run.get("timestamp", run.get("started_at", ""))
            target = run.get("target", "?")
            findings = run.get("findings_count", run.get("finding_count", "?"))
            status = run.get("status", "?")
            print(f"  {str(ts)[:19]:<20} {str(target):<35} {str(findings):>4} findings  {status}")
    except Exception as exc:
        print(f"Error: {exc}")


def _learning_tools(vuln_type=None):
    try:
        from oneinfinity.core.db_manager import get_db_manager_sync
        mgr = get_db_manager_sync()
        if not mgr or mgr.mode not in ("postgres", "distributed"):
            print("PostgreSQL required for tool performance data.")
            return
        if vuln_type:
            rows = mgr.sync_pg_execute_read(
                "SELECT tool_name, runs_total, runs_success, findings_total, avg_duration_s "
                "FROM tool_performance WHERE vuln_type ILIKE %s "
                "ORDER BY findings_total DESC LIMIT 20",
                (f"%{vuln_type}%",)
            )
            print(f"─── Best Tools for '{vuln_type}' ───")
        else:
            rows = mgr.sync_pg_execute_read(
                "SELECT tool_name, SUM(runs_total), SUM(runs_success), SUM(findings_total), AVG(avg_duration_s) "
                "FROM tool_performance GROUP BY tool_name ORDER BY SUM(findings_total) DESC LIMIT 25",
                ()
            )
            print("─── Tool Performance Leaderboard ───")

        print(f"  {'Tool':<18} {'Runs':>6} {'Success%':>9} {'Findings':>9} {'Avg(s)':>7}")
        print("  " + "─" * 56)
        for r in (rows or []):
            tool, runs, success, findings, dur = r
            pct = round(int(success or 0) / max(int(runs or 1), 1) * 100)
            print(f"  {str(tool):<18} {int(runs or 0):>6} {pct:>8}% {int(findings or 0):>9} {float(dur or 0):>7.1f}")
    except Exception as exc:
        print(f"Error: {exc}")


def register(subparsers):
    lp = subparsers.add_parser("learning", help="Learning intelligence commands")
    sub = lp.add_subparsers(dest="learning_cmd", metavar="<command>")

    sub.add_parser("status", help="Show learning system status")

    pat_p = sub.add_parser("patterns", help="Show mined vulnerability patterns")
    pat_p.add_argument("--target", metavar="TARGET")

    mem_p = sub.add_parser("memory", help="Show persistent memory contents")
    mem_p.add_argument("--show-payloads", action="store_true", dest="show_payloads")

    hist_p = sub.add_parser("history", help="Show scan run history")
    hist_p.add_argument("--limit", "-n", type=int, default=20)

    tools_p = sub.add_parser("tools", help="Show tool performance analytics")
    tools_p.add_argument("--vuln-type", dest="vuln_type", metavar="TYPE")

    lp.set_defaults(func=handle_learning)
    return lp


__all__ = ["handle_learning", "register"]
