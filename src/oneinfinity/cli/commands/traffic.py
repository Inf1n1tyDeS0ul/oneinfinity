"""
CLI command handlers for traffic domain.
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

def cmd_traffic_list(args):
    """oneinfinity traffic-list — list captured HTTP traffic."""
    from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
    requests = traffic_capture_engine.list(
        target=getattr(args, "target", "") or None,
        source=getattr(args, "source", "") or None,
        method=getattr(args, "method", "") or None,
        status_code=getattr(args, "status", None),
        flagged=True if getattr(args, "flagged", False) else None,
        search=getattr(args, "search", "") or None,
        limit=getattr(args, "limit", 50),
    )
    stats = traffic_capture_engine.stats()
    print(f"\n[*] Traffic Database: {stats['total']} requests, {stats['flagged']} flagged")
    print(f"    Sources: {stats['by_source']}\n")
    if not requests:
        print("  No requests found matching filters.")
        return
    print(f"  {'ID':<14} {'METHOD':<7} {'STATUS':<7} {'SOURCE':<14} {'URL'}")
    print(f"  {'─'*14} {'─'*7} {'─'*7} {'─'*14} {'─'*50}")
    for r in requests:
        flag = " [!]" if r.flagged else "    "
        url_short = r.url[:70] if len(r.url) > 70 else r.url
        print(f"  {r.id:<14} {r.method:<7} {r.response_status:<7} {r.source:<14} {url_short}{flag}")
    print()


def cmd_traffic_export(args):
    """oneinfinity traffic-export — export captured traffic."""
    from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
    fmt = getattr(args, "format", "json")
    output = getattr(args, "output", "traffic_export")
    target = getattr(args, "target", "") or None
    flagged = True if getattr(args, "flagged", False) else None

    ext = fmt
    path = f"{output}.{ext}"
    if fmt == "json":
        out = traffic_capture_engine.export_json(path, target=target, flagged=flagged)
    elif fmt == "csv":
        out = traffic_capture_engine.export_csv(path, target=target, flagged=flagged)
    elif fmt == "har":
        out = traffic_capture_engine.export_har(path, target=target, flagged=flagged)
    else:
        out = traffic_capture_engine.export_json(path)
    print(f"[+] Traffic exported to: {out}")


def cmd_replay_request(args):
    """oneinfinity replay-request <request_id> — replay a captured request."""
    from oneinfinity.scan.traffic_replay_engine import traffic_replay_engine
    from oneinfinity.infra.proxy_manager import configure_proxy_from_args

    configure_proxy_from_args(args)

    request_id = args.request_id

    # Parse header overrides
    header_overrides = {}
    for h in (getattr(args, "headers", None) or []):
        if ":" in h:
            k, _, v = h.partition(":")
            header_overrides[k.strip()] = v.strip()

    # Parse param overrides
    param_overrides = {}
    for p in (getattr(args, "params", None) or []):
        if "=" in p:
            k, _, v = p.partition("=")
            param_overrides[k.strip()] = v.strip()

    fuzz_param = getattr(args, "fuzz", "")
    fuzz_values = getattr(args, "fuzz_values", None)
    no_proxy = getattr(args, "no_proxy", False)

    if fuzz_param:
        results = traffic_replay_engine.fuzz_param(
            request_id, fuzz_param,
            custom_values=fuzz_values,
            use_proxy=not no_proxy,
        )
        suspicious = [r for r in results if r.suspicious]
        print(f"\n[+] Fuzz complete: {len(results)} probes, {len(suspicious)} suspicious")
    else:
        result = traffic_replay_engine.replay(
            request_id,
            method=getattr(args, "method", "") or None,
            url=getattr(args, "url", "") or None,
            headers=header_overrides or None,
            body=getattr(args, "body", None),
            params=param_overrides or None,
            use_proxy=not no_proxy,
        )


def cmd_replay_attack(args):
    """oneinfinity replay-attack <attack_id> — replay a discovered attack."""
    from attack_replay_engine import attack_replay_engine, PAYLOAD_LIBRARY
    from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
    from oneinfinity.infra.proxy_manager import configure_proxy_from_args

    configure_proxy_from_args(args)

    attack_id = args.attack_id
    payload = getattr(args, "payload", None)
    spray_type = getattr(args, "spray", "")
    wordlist = getattr(args, "wordlist", "")
    request_id = getattr(args, "request_id", "")

    # Auto-register from captured request if provided
    if request_id:
        req = traffic_capture_engine.get(request_id)
        if req:
            attack_id = attack_replay_engine.registry.from_captured_request(req)
            print(f"[*] Auto-registered attack: {attack_id}")

    if not attack_replay_engine.registry.get(attack_id):
        print(f"[-] Attack {attack_id!r} not found.")
        print("[*] Use --request-id to auto-register from a captured request.")
        print("[*] Or register programmatically via attack_replay_engine.registry.register()")
        return

    if wordlist:
        results = attack_replay_engine.spray_from_wordlist(attack_id, wordlist)
    elif spray_type:
        results = attack_replay_engine.spray_attack(attack_id, attack_type=spray_type)
        confirmed = [r for r in results if r.confirmed]
        print(f"[+] {len(confirmed)}/{len(results)} confirmed with {spray_type} payloads")
    else:
        result = attack_replay_engine.replay_attack(attack_id, payload=payload)


def cmd_proxy_status(args):
    """oneinfinity proxy-status — show proxy configuration."""
    from oneinfinity.infra.proxy_manager import proxy_manager
    status = proxy_manager.status()
    print(f"\n[*] Proxy Status")
    print(f"    Enabled : {status['enabled']}")
    print(f"    Address : {status['address'] or '(not configured)'}")
    print(f"    Scopes  : {', '.join(status['scopes'])}")
    print(f"    SSL verify: {status['verify_ssl']}")
    print(f"    Capture : {status['capture']}")
    print(f"    Active  : {status['active']}")
    if not status['enabled']:
        print("\n[*] To enable: oneinfinity proxy-set http://127.0.0.1:8080")
    print()


def cmd_proxy_set(args):
    """oneinfinity proxy-set <address> — configure proxy."""
    from oneinfinity.infra.proxy_manager import proxy_manager
    address = args.address
    scopes = getattr(args, "scope", ["all"])
    from oneinfinity.infra.proxy_manager import ProxyScope
    scope_map = {
        "all": ProxyScope.ALL,
        "recon": ProxyScope.RECON,
        "scan": ProxyScope.SCAN,
        "ai": ProxyScope.AI,
        "agent": ProxyScope.AGENT,
    }
    mapped_scopes = [scope_map.get(s, s) for s in scopes]
    proxy_manager.configure(address, scopes=mapped_scopes)
    proxy_manager.enable()
    print(f"[+] Proxy configured: {address}")
    print(f"    Scopes: {', '.join(scopes)}")
    print(f"    All HTTP requests from selected modules will route through {address}")


def cmd_replay_findings(args):
    """oneinfinity replay <findings_file> — convert findings to reproducible CLI workflows."""
    from oneinfinity.findings.finding_replay_engine import replay_findings_file

    findings_file   = args.findings_file
    run             = getattr(args, "run", False)
    filter_status   = getattr(args, "filter_status", "") or None
    filter_severity = getattr(args, "severity", None)
    filter_source   = getattr(args, "filter_source", "") or None
    output          = getattr(args, "output", "/data/raw/replay_report")
    docker_exec     = getattr(args, "docker_exec", "oneinfinity-orchestrator")

    print(f"[*] Loading findings from: {findings_file}")
    if filter_status:
        print(f"[*] Filtering by status: {filter_status}")
    if filter_severity:
        print(f"[*] Filtering by severity: {', '.join(filter_severity)}")
    if run:
        print(f"[*] Execution mode: ACTIVE (commands will run inside {docker_exec})")
    else:
        print(f"[*] Execution mode: DRY RUN (commands generated, not executed)")

    try:
        records = replay_findings_file(
            findings_path=findings_file,
            output_path=output,
            filter_status=filter_status,
            filter_severity=filter_severity,
            run=run,
            docker_exec=docker_exec if run else "",
        )
        print(f"\n[+] Replay complete — {len(records)} findings processed")
        print(f"[+] Report written: {output}.md")
        print(f"[+] JSON written:   {output}.json")

        # Print summary table
        by_sev = {}
        for r in records:
            by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
        print("\n  Severity breakdown:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = by_sev.get(sev, 0)
            if cnt:
                print(f"    {sev.upper():10s} {cnt}")

        # Print first 5 records with commands
        print("\n  Sample commands (first 5 findings):")
        for rec in records[:5]:
            print(f"\n  [{rec.severity.upper()}] {rec.vuln_type} → {rec.url[:60]}")
            for cmd in rec.commands[:2]:
                print(f"    $ {cmd[:100]}")

    except FileNotFoundError:
        print(f"[!] File not found: {findings_file}")
    except Exception as e:
        print(f"[!] Replay failed: {e}")
        import traceback; traceback.print_exc()




def register(subparsers):
    """Register traffic commands with the CLI argument parser."""
    sub = subparsers
    tl = sub.add_parser("traffic-list", help="List captured HTTP traffic")
    tl.add_argument("--target", default="", help="Filter by target domain")
    tl.add_argument("--source", default="", help="Filter by source module")
    tl.add_argument("--method", default="", help="Filter by HTTP method")
    tl.add_argument("--status", type=int, default=None, help="Filter by response status")
    tl.add_argument("--flagged", action="store_true", help="Show only flagged requests")
    tl.add_argument("--search", default="", help="Full-text search in URL/body")
    tl.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")

    te = sub.add_parser("traffic-export", help="Export captured traffic to file")
    te.add_argument("--format", choices=["json", "csv", "har"], default="json")
    te.add_argument("--output", "-o", default="traffic_export", help="Output filename (no extension)")
    te.add_argument("--target", default="", help="Filter by target domain")
    te.add_argument("--flagged", action="store_true", help="Export only flagged requests")

    rr = sub.add_parser("replay-request", help="Replay a captured HTTP request")
    rr.add_argument("request_id", help="Request ID from traffic-list")
    rr.add_argument("--method", default="", help="Override HTTP method")
    rr.add_argument("--url", default="", help="Override URL")
    rr.add_argument("--body", default=None, help="Override request body")
    rr.add_argument("--header", action="append", metavar="K:V", dest="headers",
                    help="Override/add header (can repeat)")
    rr.add_argument("--param", action="append", metavar="K=V", dest="params",
                    help="Override query/body param (can repeat)")
    rr.add_argument("--fuzz", metavar="PARAM", default="",
                    help="Fuzz a specific parameter")
    rr.add_argument("--fuzz-values", nargs="+", metavar="VAL",
                    help="Custom fuzz values (requires --fuzz)")
    rr.add_argument("--proxy", default="", help="Route through proxy (e.g. http://127.0.0.1:8080)")
    rr.add_argument("--no-proxy", dest="no_proxy", action="store_true", help="Disable proxy for this replay")

    ra = sub.add_parser("replay-attack", help="Replay a discovered attack with payload")
    ra.add_argument("attack_id", help="Attack ID (from vulnerability findings)")
    ra.add_argument("--payload", default=None, help="Custom payload to use")
    ra.add_argument("--spray", metavar="TYPE",
                    choices=[],
                    default="",
                    help="Spray all payloads of this type (xss|sqli|ssrf|lfi|...)")
    ra.add_argument("--wordlist", default="", metavar="FILE",
                    help="Custom payload wordlist (one per line)")
    ra.add_argument("--proxy", default="", help="Route through proxy")
    ra.add_argument("--request-id", dest="request_id", default="",
                    help="Link to captured request ID")

    ps = sub.add_parser("proxy-status", help="Show current proxy configuration")

    pset = sub.add_parser("proxy-set", help="Configure proxy for current session")
    pset.add_argument("address", help="Proxy address (e.g. http://127.0.0.1:8080)")
    pset.add_argument("--scope", nargs="+", default=["all"],
                      choices=["all", "recon", "scan", "ai", "agent"],
                      help="Scopes to proxy (default: all)")

    fr = sub.add_parser("replay", help="Convert findings.json into reproducible CLI workflows")
    fr.add_argument("findings_file", help="Path to findings JSON file")
    fr.add_argument("--run", action="store_true", help="Execute replay commands (not just generate)")
    fr.add_argument("--filter", dest="filter_status", default="", metavar="STATUS",
                    help="Filter by validation_status (e.g. confirmed, unverified)")
    fr.add_argument("--severity", nargs="+", default=None,
                    choices=["critical", "high", "medium", "low", "info"],
                    help="Filter by severity")
    fr.add_argument("--source", dest="filter_source", default="",
                    help="Filter by source_type (tool, simulated, ai_theory)")
    fr.add_argument("--output", "-o", default="/data/raw/replay_report",
                    help="Output path for replay report (without extension)")
    fr.add_argument("--docker-exec", dest="docker_exec", default="oneinfinity-orchestrator",
                    help="Docker container to execute commands in (default: oneinfinity-orchestrator)")


