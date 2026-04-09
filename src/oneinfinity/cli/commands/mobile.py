"""
CLI command handlers for mobile domain.
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

def cmd_mobile_analyze(args):
    """oneinfinity mobile-analyze <file> — full mobile security pipeline."""
    from oneinfinity.mobile_security_engine import analyze_cli
    analyze_cli(args)


def cmd_mobile_static(args):
    """oneinfinity mobile-static <file> — static analysis only."""
    import json as _json
    from oneinfinity.mobile_upload_manager import mobile_upload_manager
    from oneinfinity.mobile_static_analyzer import mobile_static_analyzer

    file_path = args.file
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return

    print(f"[*] Uploading {file_path}...")
    app = mobile_upload_manager.upload(file_path, os.path.basename(file_path))
    if hasattr(app, "to_dict"):
        app = app.to_dict()
    app.setdefault("app_id", app.get("id", ""))
    app.setdefault("extracted_dir", app.get("extract_path", ""))
    app_id = app["app_id"]
    extracted_dir = app["extracted_dir"]

    print(f"[*] Running static analysis (app_id={app_id})...")
    result = mobile_static_analyzer.analyze(app_id, file_path, extracted_dir)

    print(f"\nPackage:       {result.package_name}")
    print(f"Platform:      android (APK)")
    print(f"Min SDK:       {result.min_sdk}  Target SDK: {result.target_sdk}")
    print(f"Debuggable:    {result.debuggable}")
    print(f"Backup:        {result.backup_allowed}")
    print(f"Cleartext:     {result.cleartext_traffic}")
    print(f"Permissions:   {len(result.permissions)} ({len(result.dangerous_permissions)} dangerous)")
    print(f"Components:    {len(result.components)} ({len(result.exported_components)} exported)")
    print(f"Deep links:    {len(result.deep_links)}")
    print(f"Hardcoded URLs:{len(result.hardcoded_urls)}")
    print(f"Secrets:       {len(result.hardcoded_secrets)}")
    print(f"\nVulnerabilities ({len(result.vulnerabilities)}):")
    for v in result.vulnerabilities:
        print(f"  [{v.get('severity','?').upper():8s}] {v.get('type','?')}: {v.get('detail','')[:80]}")

    if args.output:
        Path(args.output).write_text(_json.dumps(result.to_dict(), indent=2))
        print(f"\n[+] Results saved: {args.output}")


def cmd_mobile_dynamic(args):
    """oneinfinity mobile-dynamic <file> <package> — dynamic analysis on device."""
    from oneinfinity.mobile_dynamic_analyzer import mobile_dynamic_analyzer

    result = mobile_dynamic_analyzer.analyze(
        app_id=Path(args.file).stem,
        package_name=args.package,
        apk_path=args.file if os.path.exists(args.file) else None,
        device_id=getattr(args, "device", "") or None,
        timeout=getattr(args, "timeout", 60),
    )
    print(f"\n[*] Dynamic Analysis — {args.package}")
    print(f"Device:          {result.device_id or 'none'}")
    print(f"ADB:             {'yes' if result.adb_available else 'NO'}")
    print(f"Frida:           {'yes' if result.frida_available else 'NO'}")
    print(f"SSL Pinning:     {'detected' if result.ssl_pinning_detected else 'not detected'}")
    print(f"Root Detection:  {'detected' if result.root_detection_detected else 'not detected'}")
    print(f"Network Reqs:    {len(result.network_requests)}")
    print(f"Crypto Ops:      {len(result.crypto_operations)}")
    print(f"\nFindings ({len(result.findings)}):")
    for f in result.findings:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        print(f"  [{d.get('severity','?').upper():8s}] {d.get('finding_type','?')}: {d.get('detail','')[:80]}")
    if result.errors:
        print(f"\nErrors:")
        for e in result.errors:
            print(f"  ! {e}")


def cmd_mobile_api_scan(args):
    """oneinfinity mobile-api-scan <file> — discover and optionally fuzz API endpoints."""
    import json as _json
    from oneinfinity.mobile_upload_manager import mobile_upload_manager
    from oneinfinity.mobile_api_discovery import mobile_api_discovery

    file_path = args.file
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return

    print(f"[*] Uploading {file_path}...")
    app = mobile_upload_manager.upload(file_path, os.path.basename(file_path))
    if hasattr(app, "to_dict"):
        app = app.to_dict()
    app.setdefault("app_id", app.get("id", ""))
    app.setdefault("extracted_dir", app.get("extract_path", ""))
    extracted_dir = app["extracted_dir"]

    print(f"[*] Discovering API endpoints...")
    result = mobile_api_discovery.discover(app["app_id"], extracted_dir)

    print(f"\nBase URLs ({len(result.base_urls)}):")
    for u in result.base_urls[:10]:
        print(f"  {u}")
    print(f"\nEndpoints ({len(result.endpoints)}):")
    for ep in result.endpoints[:20]:
        d = ep.to_dict() if hasattr(ep, "to_dict") else ep
        print(f"  [{d.get('method','GET'):6s}] {d.get('full_url') or d.get('path','')[:80]}")
    if len(result.endpoints) > 20:
        print(f"  ... and {len(result.endpoints)-20} more")
    print(f"\nGraphQL: {len(result.graphql_endpoints)}  WebSocket: {len(result.websocket_urls)}")
    print(f"Third-party: {', '.join(result.third_party_apis[:5])}")

    if args.output:
        Path(args.output).write_text(_json.dumps(result.to_dict(), indent=2))
        print(f"\n[+] Results saved: {args.output}")


def cmd_mobile_report(args):
    """oneinfinity mobile-report <app_id> — generate a formatted report."""
    import json as _json
    from oneinfinity.mobile_upload_manager import mobile_upload_manager

    app = mobile_upload_manager.get(args.app_id)
    if not app:
        print(f"[!] App not found: {args.app_id}")
        return

    fmt = getattr(args, "format", "markdown")
    out = getattr(args, "output", "")

    report_lines = [
        f"# Mobile Security Report — {app.get('app_name', args.app_id)}",
        f"",
        f"**Package:** {app.get('package_name', 'unknown')}",
        f"**Platform:** {app.get('platform', 'unknown')}",
        f"**File:** {app.get('file_path', '')}",
        f"**Analyzed:** {app.get('upload_time', '')}",
        f"",
        f"## Analysis Status",
        f"Use `oneinfinity mobile-analyze {app.get('file_path','')}` to run full analysis.",
    ]

    report_text = "\n".join(report_lines)
    if out:
        Path(out).write_text(report_text)
        print(f"[+] Report saved: {out}")
    else:
        print(report_text)




def register(subparsers):
    """Register mobile commands with the CLI argument parser."""
    sub = subparsers
    mob = sub.add_parser("mobile-analyze", help="Full mobile security analysis (APK/IPA)")
    mob.add_argument("file", help="Path to APK or IPA file")
    mob.add_argument("--no-static", action="store_true", help="Skip static analysis")
    mob.add_argument("--no-secrets", action="store_true", help="Skip secret scanning")
    mob.add_argument("--no-api", action="store_true", help="Skip API discovery")
    mob.add_argument("--dynamic", action="store_true", help="Run dynamic analysis (requires device)")
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


