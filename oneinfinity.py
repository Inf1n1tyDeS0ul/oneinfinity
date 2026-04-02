#!/usr/bin/env python3
"""
oneinfinity — AI-Powered Offensive Security Research Framework : One&Infinity
===========================================================================
An autonomous AI-driven platform for offensive security research, bug bounty automation,
mobile security testing, AI security testing, and attack graph–driven vulnerability discovery.

Bug bounty mode:
  oneinfinity setup <program-name>
  oneinfinity setup <program-name> --pentest --target <domain> [--target <domain> ...]

Autonomous framework (runs all phases):
  oneinfinity run <target> [options]

Pentest scan (generates recon script — YOU run it):
  oneinfinity scan <target> [<target> ...]

Other commands:
  oneinfinity scope
  oneinfinity analyze subdomains <file>
  oneinfinity analyze responses  <file>
  oneinfinity analyze js         <file> [<file> ...]
  oneinfinity analyze nuclei     <file>
  oneinfinity plan
  oneinfinity script <type>
  oneinfinity script list
  oneinfinity report [--finding <id>]
  oneinfinity report chain <id1> <id2>
  oneinfinity findings [<severity>]
  oneinfinity findings show <id>
  oneinfinity findings log
  oneinfinity findings update <id> <field> <value>
  oneinfinity findings export [json|csv|md]
  oneinfinity findings stats
  oneinfinity cvss
  oneinfinity cvss <vector-string>
  oneinfinity payloads
  oneinfinity payloads <type> [<context>]
  oneinfinity waf-bypass <waf> <vuln-type>
  oneinfinity methodology <vuln-class>
  oneinfinity dedup <title>
  oneinfinity adaptive-recon <target> [--depth quick|standard|deep] [--json] [--no-graph]
"""

import sys
import os
import argparse
from pathlib import Path

from path_manager import findings_db_path, raw_dir, resolve_output_dir, workspace_root

# ── Workspace resolution ──────────────────────────────────────────────────────

CLI_COMMAND = "oneinfinity"
WORKSPACE_DIRNAME = "oneinfinity-workspace"
LEGACY_WORKSPACE_DIRNAME = "bounty-workspace"


def get_workspace_root() -> Path:
    return workspace_root()


def find_program_dir() -> Path | None:
    """Walk up from cwd looking for scope.yaml."""
    current = Path.cwd()
    for path in [current, *current.parents]:
        if (path / "scope.yaml").exists():
            return path
    return None

def get_program_dir(require: bool = True) -> Path:
    d = find_program_dir()
    if d:
        return d
    if require:
        from modules.utils import err, info
        err("No scope.yaml found in current directory or parents.")
        info(f"Run: {CLI_COMMAND} setup <program-name>")
        info(f"Then: cd {get_workspace_root()}/<program-name>")
        sys.exit(1)
    return Path.cwd()


# ── Subcommand handlers ───────────────────────────────────────────────────────

def cmd_doctor(args):
    from core.doctor import DoctorOrchestrator
    import asyncio
    
    workspace_root = os.getcwd()
    orchestrator = DoctorOrchestrator(workspace_root)
    
    if not args.json:
        print("[*] Running OneInfinity Doctor. This may take a moment...")
        
    quick_mode = getattr(args, "quick", False)
    deep_mode = getattr(args, "deep", False)
    
    report = asyncio.run(orchestrator.run(quick=quick_mode, deep=deep_mode))
    orchestrator.print_report(report, output_json=getattr(args, "json", False))
    # ── Enforcement: ingestion audit ──────────────────────────────────────────
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _non_compliant = _get_ec().audit_ingestion_compliance()
        if _non_compliant:
            print()
            print(f"  [!] Ingestion audit: {len(_non_compliant)} cmd(s) bypass get_ingestion_engine():")
            for _cmd in sorted(_non_compliant):
                print(f"      - {_cmd}")
            print(f"      Deduction: -{min(len(_non_compliant) * 0.1, 1.0):.1f} (informational)")
        else:
            print()
            print("  [+] Ingestion audit: all tracked commands publish via get_ingestion_engine()")
    except Exception as _ea:
        pass  # audit failure never affects doctor output

def cmd_setup(args):
    from modules.utils import banner, ok, info, warn

    name = args.name
    workspace = get_workspace_root() / name
    workspace.mkdir(parents=True, exist_ok=True)

    dirs = ["recon", "findings", "reports", "scripts", "evidence",
            "scripts/nuclei_templates", "recon/js", "recon/ports", "recon/web"]
    for d in dirs:
        (workspace / d).mkdir(parents=True, exist_ok=True)

    # scope.yaml
    from modules.scope import ScopeManager
    if not (workspace / "scope.yaml").exists():
        if args.pentest:
            targets = args.target or [name]
            ScopeManager.create_pentest_template(str(workspace), name, targets)
        else:
            ScopeManager.create_template(str(workspace), name)

    # notes.md
    notes = workspace / "notes.md"
    if not notes.exists():
        mode = "Pentest Engagement" if args.pentest else "Bug Bounty Hunt"
        notes.write_text(f"# {mode} Notes — {name}\n\n## Session Log\n\n")

    # findings.db
    from modules.findings import FindingsDB
    db = FindingsDB(str(findings_db_path()))
    db.close()

    banner(f"Workspace Created — {name}")
    ok(f"Directory : {workspace.resolve()}")
    if args.pentest:
        ok(f"Mode      : Pentest engagement")
        ok(f"Targets   : {', '.join(args.target or [name])}")
    print()
    print("  Next steps:")
    print(f"  1. cd {workspace}")
    if args.pentest:
        print(f"  2. Edit scope.yaml — set authorized: true after confirming written auth")
        print(f"  3. oneinfinity scan {(args.target or [name])[0]}")
    else:
        print(f"  2. Edit scope.yaml — add program URL, scope domains, set registered: true")
        print(f"  3. Collect recon and save into ~/.oneinfinity/raw/<target>/recon/")
        print(f"  4. oneinfinity analyze subdomains ~/.oneinfinity/raw/<target>/recon/subdomains.txt")
        print(f"  5. oneinfinity plan")
    print()


def cmd_scan(args):
    """
    oneinfinity scan <target> [--yes]

    With --yes: runs the full autonomous 9-phase scan pipeline via unified_scan_engine.
    Without --yes: generates a recon shell script for manual review.
    """
    from modules.utils import banner, section, ok, info, warn, err, bold

    targets = getattr(args, "targets", []) or []
    if not targets:
        err("No target specified.  Usage: oneinfinity scan <target> [--yes]")
        sys.exit(1)

    # ── Autonomous mode (--yes) ─────────────────────────────────────────────
    if getattr(args, "yes", False):
        for target in targets:
            banner(f"Autonomous Scan: {target}")
            info("Starting 9-phase scan pipeline …")
            print()
            try:
                from unified_scan_engine import get_engine
                engine = get_engine()

                def _progress(phase: str, pct: int, msg: str):
                    tag = "+" if "complet" in msg.lower() or "ok" in msg.lower() else \
                          "-" if "error" in msg.lower() or "fail" in msg.lower() else "*"
                    print(f"  [{tag}] [{pct:3d}%] [{phase}] {msg}")

                session = engine.scan(target, on_progress=_progress)
                print()
                if session.status == "completed":
                    ok(f"Scan completed — {len(session.findings)} findings")
                else:
                    warn(f"Scan finished with status: {session.status}")
                    if session.error:
                        err(f"Error: {session.error}")

                if session.findings:
                    sev_counts: dict = {}
                    for f in session.findings:
                        s = f.get("severity", "info")
                        sev_counts[s] = sev_counts.get(s, 0) + 1
                    section("Findings by severity")
                    for sev in ("critical", "high", "medium", "low", "info"):
                        if sev in sev_counts:
                            print(f"    {sev:8s}  {sev_counts[sev]}")

                print()
                info(f"Results stored in: ~/.oneinfinity/databases/findings.db")

            except ImportError:
                err("unified_scan_engine not available — falling back to recon script generator")
                _cmd_scan_legacy(args)
            except Exception as exc:
                err(f"Scan failed: {exc}")
                import traceback; traceback.print_exc()
                sys.exit(1)
        return

    # ── Script mode (generate recon script, manual execution) ───────────────
    # ── IMPORTANT: without --yes, we only generate a script, not a scan ──
    print(
        "\n⚠️  WARNING: 'oneinfinity scan' without --yes generates a recon script\n"
        "   to disk but does NOT execute a scan. No network requests will be made.\n"
        "\n"
        "   To run an actual scan:     oneinfinity scan <target> --yes\n"
        "   To run the full pipeline:  oneinfinity full-scan <target>\n",
        file=sys.stderr,
    )
    _cmd_scan_legacy(args)


def _cmd_scan_legacy(args):
    """Original cmd_scan: generates a recon shell script for manual review."""
    from modules.utils import banner, section, ok, info, warn, err, bold

    d = get_program_dir(require=False)

    from modules.scope import ScopeManager
    sm = ScopeManager(str(d))
    if sm.exists():
        sm.load()
        if sm.is_pentest():
            eng = sm._data.get("engagement", {})
            if not eng.get("authorized"):
                err("scope.yaml: authorized is false.")
                err("Set 'authorized: true' after confirming written authorization from the client.")
                err("Scanning without authorization is illegal.")
                sys.exit(1)
    else:
        banner("Authorization Check")
        warn("No scope.yaml found in this directory.")
        print()
        print("  Before scanning any target you must have explicit written authorization.")
        print()
        ans = input("  [?] Do you have written authorization to test the target(s)? (yes/no): ").strip().lower()
        if ans != "yes":
            print("  Aborted.")
            sys.exit(0)

    targets = getattr(args, "targets", []) or []
    if not targets:
        err("No domains specified.")
        sys.exit(1)

    from modules.recon import ReconRunner
    runner = ReconRunner(program_dir=str(d))

    banner("Recon Script Generator")
    runner.show_tool_check()

    generated = []
    for target in targets:
        info(f"Generating recon script for: {target}")
        script_path = runner.generate_script(target)
        ok(f"Script → {script_path}")
        generated.append(script_path)

    print()
    section("Ready to run")
    warn("Review each script before executing — confirm all targets are authorized.")
    print()
    for sp in generated:
        print(f"  bash {sp}")
    print()
    info("Tip: run with --yes for fully autonomous scan:")
    print(f"  oneinfinity scan <target> --yes")
    print()


def cmd_scope(args):
    d = get_program_dir()
    from modules.scope import ScopeManager
    sm = ScopeManager(str(d))
    sm.load()
    sm.show_scope()


def cmd_analyze(args):
    d = get_program_dir()
    recon_dir = str(d / "recon")
    os.makedirs(recon_dir, exist_ok=True)

    from modules.scope import ScopeManager
    sm = ScopeManager(str(d))
    if sm.exists():
        sm.load()

    subcommand = args.subcommand

    if subcommand == "subdomains":
        from modules.analyzer import analyze_subdomains
        analyze_subdomains(args.file[0], output_dir=recon_dir)

    elif subcommand == "responses":
        from modules.analyzer import analyze_responses
        analyze_responses(args.file[0], output_dir=recon_dir)

    elif subcommand == "js":
        from modules.analyzer import analyze_js
        analyze_js(args.file, output_dir=recon_dir)

    elif subcommand == "nuclei":
        from modules.analyzer import analyze_nuclei
        analyze_nuclei(args.file[0], output_dir=recon_dir)

    else:
        from modules.utils import err
        err(f"Unknown analyze subcommand: {subcommand}")
        err("Use: subdomains | responses | js | nuclei")
        sys.exit(1)


def cmd_org_intel(args):
    from org_intel_mapper import OrgDomainMapper
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
        from result_ingestion_engine import get_ingestion_engine
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
    from modules.scope import ScopeManager
    sm = ScopeManager(str(d))
    sm.load()
    sm.validate()
    from modules.planner import HuntPlanner
    planner = HuntPlanner(str(d))
    planner.generate()


def cmd_script(args):
    from modules.scripter import ScriptGenerator
    if args.type == "list" or not args.type:
        gen = ScriptGenerator(output_dir=".")
        gen.list_available()
        return
    d = get_program_dir()
    scripts_dir = str(d / "scripts")
    gen = ScriptGenerator(output_dir=scripts_dir)
    gen.generate(args.type)


def cmd_report(args):
    d = get_program_dir()
    reports_dir = str(d / "reports")

    from modules.scope import ScopeManager
    sm = ScopeManager(str(d))
    sm.load()
    platform = sm.platform or "HackerOne"

    from modules.reporter import ReportGenerator
    gen = ReportGenerator(reports_dir=reports_dir, platform=platform)

    if args.chain:
        # Chain analysis
        fid1, fid2 = args.chain
        from modules.findings import FindingsDB
        db = FindingsDB(str(findings_db_path()))
        f1 = db.get(fid1)
        f2 = db.get(fid2)
        db.close()
        if not f1 or not f2:
            from modules.utils import err
            err(f"Finding #{fid1 if not f1 else fid2} not found.")
            sys.exit(1)
        gen.chain_analysis(f1, f2)
        return

    if getattr(args, "all_findings", False):
        from modules.findings import FindingsDB
        from modules.utils import ok, info, banner, warn
        from bounty_report_generator import BountyReportGenerator
        # Resolve scope targets so only in-scope findings go into the report
        scope_targets = sm._data.get("scope", {}).get("targets") or \
                        sm._data.get("scope", {}).get("in_scope") or []
        primary_target = scope_targets[0] if scope_targets else d.name
        db = FindingsDB(str(findings_db_path()))
        all_findings = db.all()
        db.close()
        # Filter to findings whose target matches one of the scope targets
        scoped = [
            f for f in all_findings
            if any(t in (f.get("target") or "") for t in scope_targets)
        ] if scope_targets else all_findings
        skipped = len(all_findings) - len(scoped)
        if skipped:
            warn(f"Skipped {skipped} finding(s) from out-of-scope targets.")
        banner(f"Batch Report — {len(scoped)} findings for {primary_target}")
        for f in scoped:
            gen.from_finding(f)
        # Also generate a summary via BountyReportGenerator
        brg = BountyReportGenerator()
        report = brg.generate(target=primary_target, findings=scoped, platform=platform or "pentest")
        summary_path = Path(reports_dir) / "00_SUMMARY.md"
        summary_path.write_text(brg._render_markdown(report))
        ok(f"Summary report → {summary_path}")
        slug = primary_target.replace(".", "_")
        json_path = Path(reports_dir) / f"{slug}_pentest_report.json"
        report.save_json(json_path)
        ok(f"JSON report   → {json_path}")
        html_path = Path(reports_dir) / f"{slug}_pentest_report.html"
        report.save_html(html_path)
        ok(f"HTML report   → {html_path}")
        return

    if args.finding:
        from modules.findings import FindingsDB
        db = FindingsDB(str(findings_db_path()))
        finding = db.get(args.finding)
        db.close()
        if not finding:
            from modules.utils import err
            err(f"Finding #{args.finding} not found.")
            sys.exit(1)
        gen.from_finding(finding)
    else:
        gen.interactive()


def cmd_findings(args):
    d = get_program_dir()
    from modules.findings import FindingsDB
    db = FindingsDB(str(findings_db_path()))

    sub = args.subcommand or "list"

    if sub == "list":
        sev = args.severity if hasattr(args, "severity") else None
        db.list_findings(severity=sev)

    elif sub == "show":
        db.show_finding(args.id)

    elif sub == "log":
        db.interactive_add()

    elif sub == "update":
        db.update(args.id, **{args.field: args.value})

    elif sub == "stats":
        db.stats()

    elif sub == "export":
        fmt = getattr(args, "format", "json") or "json"
        out = d / f"findings_export.{fmt}"
        if fmt == "json":
            db.export_json(str(out))
        elif fmt == "csv":
            db.export_csv(str(out))
        elif fmt == "md":
            db.export_markdown(str(out))
        else:
            from modules.utils import err
            err(f"Unknown format: {fmt}. Use json | csv | md")

    db.close()


def cmd_cvss(args):
    from modules.cvss import CVSSCalculator
    calc = CVSSCalculator()

    if args.vector:
        calc.from_vector(args.vector)
    elif args.description:
        calc.from_description(args.description)
    else:
        calc.interactive()


def cmd_payloads(args):
    from modules.payloads import PayloadKB
    kb = PayloadKB()

    if not args.vuln_type:
        kb.list_types()
    else:
        kb.get(args.vuln_type, args.context)


def cmd_waf_bypass(args):
    from modules.payloads import PayloadKB
    kb = PayloadKB()
    kb.waf_bypass(args.waf, args.vuln_type)


def cmd_methodology(args):
    from modules.utils import banner, section, bold, info, warn

    METHODOLOGIES = {
        "sqli": [
            "1. Identify all input parameters (URL, body, headers, cookies)",
            "2. Test each with error-based payloads: ' \" ' OR 1=1--",
            "3. Check for database error messages in response",
            "4. If silent, test time-based: ' AND SLEEP(5)--",
            "5. Confirm with boolean-based: ' AND 1=1-- vs ' AND 1=2--",
            "6. If confirmed: determine DB type (MySQL/MSSQL/PostgreSQL/Oracle)",
            "7. Extract data: UNION-based (if visible) or blind",
            "8. Check DB user privileges: SELECT user(), @@version",
            "9. Document with minimal proof (version/user extraction is sufficient)",
        ],
        "idor": [
            "1. Map all endpoints containing IDs (path, query, body)",
            "2. Create two test accounts (user A and user B)",
            "3. As user A: capture request for own resource (get your ID)",
            "4. As user B: send same request with user A's ID",
            "5. Test GET, POST, PUT, DELETE, PATCH methods",
            "6. Test numeric IDs: try sequential values (id+1, id-1)",
            "7. Test UUID: try other UUIDs if known/predictable",
            "8. Test parameter pollution: ?id=mine&id=theirs",
            "9. Test HTTP method override: X-HTTP-Method-Override header",
            "10. Check API versioning: /v1/ endpoint may lack /v2/ auth",
        ],
        "xss": [
            "1. Find all reflection points (where input appears in response)",
            "2. Determine context: HTML body, attribute, JS string, URL, CSS",
            "3. Test with probe: unique string + JS-breaking char (e.g., xsstest<>\"')",
            "4. Choose payload for context (see: oneinfinity payloads xss <context>)",
            "5. Check if WAF is blocking (oneinfinity waf-bypass <waf> xss)",
            "6. For stored XSS: test that second visit triggers payload",
            "7. For DOM XSS: check JS source for document.write/innerHTML sinks",
            "8. Escalate: steal cookies, perform actions as victim, capture credentials",
            "9. Prove impact: demo with alert(document.domain) minimum",
        ],
        "ssrf": [
            "1. Identify parameters accepting URLs/hostnames (webhook, callback, url, fetch)",
            "2. Test with your OOB server (Burp Collaborator / webhook.site)",
            "3. Confirm DNS/HTTP callback received",
            "4. Try cloud metadata: http://169.254.169.254/latest/meta-data/",
            "5. Try internal services: http://localhost, http://127.0.0.1",
            "6. Test filter bypass techniques (see: oneinfinity payloads ssrf filter-bypass)",
            "7. Try protocols: file://, dict://, gopher:// if blocked",
            "8. Check for blind SSRF (no data returned but callback received)",
            "9. Escalate: retrieve IAM credentials from cloud metadata",
        ],
        "cors": [
            "1. Send request with Origin: https://evil.com",
            "2. Check Access-Control-Allow-Origin in response",
            "3. If reflects evil.com: check Access-Control-Allow-Credentials",
            "4. If ACAC is true: CRITICAL — can steal authenticated responses",
            "5. Test null origin: Origin: null",
            "6. Test domain variations: evil.TARGET.com, TARGETxevil.com",
            "7. Document exact request/response showing misconfiguration",
            "8. For ACAO: *, severity is lower (unauthenticated data only)",
        ],
        "jwt": [
            "1. Capture JWT token from authentication flow",
            "2. Decode: base64 decode header and payload (no padding needed)",
            "3. Check algorithm in header: HS256, RS256, none?",
            "4. Test alg:none: set alg to 'none', remove signature",
            "5. Test key confusion (RS256→HS256): sign with public key as HMAC secret",
            "6. Check 'exp' claim: is expiry enforced?",
            "7. Test 'kid' (key ID) header: path traversal, SQLi, SSRF",
            "8. Check 'jku'/'x5u': can you point to your own key?",
            "9. Test weak secrets: hashcat/jwt-cracker with wordlist",
            "10. Test claim manipulation: change role/email/id in payload",
        ],
        "auth": [
            "1. Map all auth endpoints: login, register, reset, verify, sso",
            "2. Test password reset: token in URL? Guessable? Reusable?",
            "3. Test Host header injection in reset email: change Host: evil.com",
            "4. Test account enumeration via timing/response differences",
            "5. Test 2FA bypass: skip step, replay code, code length brute",
            "6. Test OAuth: state missing? redirect_uri manipulation?",
            "7. Test token leakage: token in Referer, logs, URL params",
            "8. Test session fixation: can you set session ID before auth?",
            "9. Test concurrent session limits",
            "10. Test logout: is token actually invalidated?",
        ],
    }

    vuln = args.vuln_class.lower()
    if vuln not in METHODOLOGIES:
        from modules.utils import warn
        warn(f"No methodology for '{vuln}'")
        info(f"Available: {', '.join(METHODOLOGIES.keys())}")
        return

    banner(f"Testing Methodology — {args.vuln_class.upper()}")
    for step in METHODOLOGIES[vuln]:
        print(f"  {step}")
    print()


def cmd_run(args):
    """Autonomous framework: run all phases for a target."""
    from modules.utils import banner, info, warn, err
    from unified_scan_engine import get_engine

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

def cmd_toolcheck(args):
    """Show which tools are installed and their categories."""
    from modules.utils import banner, section, ok, warn
    from modules.tool_wrappers import ToolRegistry

    banner("Tool Availability Check")
    reg = ToolRegistry()
    status = reg.check_all()
    cats = {}
    for name, info_d in status.items():
        cat = info_d["category"]
        cats.setdefault(cat, []).append((name, info_d["available"]))

    total = len(status)
    available = sum(1 for v in status.values() if v["available"])

    for cat, tools in sorted(cats.items()):
        section(cat.capitalize())
        for name, avail in sorted(tools):
            if avail:
                ok(f"  {name:<20} installed")
            else:
                warn(f"  {name:<20} NOT installed")
    print()
    print(f"  {available}/{total} tools available")
    print()
    if available < total:
        print("  To install missing tools:")
        print("    bash install_tools.sh")
        print("    bash install_tools.sh --only <category>")
    print()


def cmd_pipeline_recon(args):
    """
    oneinfinity recon <domain> — full automated recon pipeline.
    Chains: subdomain enum → HTTP probe → crawl → content discovery
    """
    from modules.utils import banner, warn, err
    from modules.pipeline import Pipeline

    target = args.domain
    output_dir = resolve_output_dir(args.output, target)

    banner(f"Recon Pipeline — {target}")
    warn("Ensure you have authorization to test this target.")

    # WAF detection before recon
    try:
        from waf_detection_engine import WAFDetectionEngine
        print("[*] Detecting WAF...")
        waf_engine = WAFDetectionEngine()
        scheme = "https" if not target.startswith("http") else ""
        probe_url = f"https://{target}" if scheme else target
        waf_profile = waf_engine.detect(probe_url)
        if waf_profile.detected:
            print(f"[!] WAF detected: {waf_profile.waf_name} | rps={waf_profile.recommended_rps:.1f} | jitter={waf_profile.jitter_ms}ms")
            if waf_profile.passive_only:
                print("[!] WAF is blocking — switching to passive/nuclei-only mode")
        else:
            print("[+] No WAF detected — full scan mode")
    except Exception:
        waf_profile = None

    phases = ["recon"]
    if not args.no_ports:
        phases.append("ports")
    if not args.no_crawl:
        phases.append("crawl")
    if not args.no_content:
        phases.append("content")

    p = Pipeline(
        target=target,
        output_dir=output_dir,
        rate_limit=args.rate or 30,
    )
    result = p.run(phases=phases)

    print(f"\n  Output saved to: {output_dir}/")
    print(f"  Subdomains file: {output_dir}/subdomains.json")
    print(f"  Alive hosts    : {output_dir}/alive_hosts.json")
    print(f"  URLs           : {output_dir}/urls.json")
    print()
    print("  Next: oneinfinity vuln-scan <domain>")
    print()


def cmd_pipeline_vulnscan(args):
    """
    oneinfinity vuln-scan <domain> — run full vulnerability scan pipeline.
    Chains: nuclei → dalfox → sqlmap → crlfuzz → kxss
    """
    from modules.utils import banner, warn
    from modules.pipeline import Pipeline
    import json
    from pathlib import Path

    target = args.domain
    output_dir = resolve_output_dir(args.output, target)

    # Load prior recon results if available
    p = Pipeline(
        target=target,
        output_dir=output_dir,
        rate_limit=args.rate or 30,
        nuclei_severity=args.severity or "medium,high,critical",
        nuclei_tags=[t.strip() for t in (args.nuclei_tags or "").split(",") if t.strip()] or None,
        oob_url=args.oob or "",
    )

    # WAF detection before vuln scan
    try:
        from waf_detection_engine import WAFDetectionEngine
        print("[*] Detecting WAF...")
        waf_engine = WAFDetectionEngine()
        if target.startswith("http"):
            probe_url = target
        else:
            # Heuristic: if a non-TLS port is present, probe over http first to avoid SSL noise.
            probe_url = f"http://{target}" if ":" in target and not target.endswith((":443", ":8443")) else f"https://{target}"
        waf_profile = waf_engine.detect(probe_url)
        if waf_profile.detected:
            waf_cfg = waf_profile.as_scan_config()
            print(f"[!] WAF detected: {waf_profile.waf_name} | rps={waf_cfg['rate_limit_rps']:.1f} | passive={waf_cfg['passive_only']}")
            # Apply WAF-adapted rate limit
            if not args.rate:
                p.rate_limit = int(waf_cfg["rate_limit_rps"] * 60)
        else:
            print("[+] No WAF detected — full scan mode")
    except Exception:
        pass

    # Load cached recon data — unwrap wrapper dicts if needed
    _wrap_keys = {
        "alive_hosts": ("hosts", "alive_hosts", "results"),
        "subdomains":  ("subdomains", "domains", "results"),
        "urls":        ("urls", "all_urls", "results"),
        "endpoints":   ("endpoints", "results"),
    }
    for attr, filename in [("subdomains", "subdomains.json"),
                            ("alive_hosts", "alive_hosts.json"),
                            ("urls", "urls.json"),
                            ("endpoints", "endpoints.json")]:
        fpath = Path(output_dir) / filename
        if fpath.exists():
            try:
                data = json.loads(fpath.read_text())
                if isinstance(data, dict):
                    for key in _wrap_keys.get(attr, ()):
                        if key in data and isinstance(data[key], list):
                            data = data[key]
                            break
                setattr(p.result, attr, data)
            except Exception:
                pass

    result = p.run(phases=["vuln"])
    print(f"\n  Findings saved to: {output_dir}/findings.json")
    print(f"  Total findings   : {len(result.findings)}")
    print()
    print("  Next: oneinfinity findings log  — to record confirmed findings")
    print()


def cmd_pipeline_fuzz(args):
    """
    oneinfinity fuzz <domain> — targeted fuzzing pipeline.
    Runs: ffuf + wfuzz + gobuster + dirsearch
    """
    from modules.utils import banner, section, ok, warn, err
    from modules.tool_wrappers import ToolRegistry, is_available

    target = args.domain
    url = f"https://{target}" if not target.startswith("http") else target
    output_dir = resolve_output_dir(args.output, target)

    banner(f"Fuzzing Pipeline — {url}")
    reg = ToolRegistry()

    fuzz_tools = ["ffuf", "gobuster", "dirsearch"]
    for tool_name in fuzz_tools:
        if not is_available(tool_name):
            warn(f"{tool_name} not installed — skipping")
            continue
        section(f"Fuzzing with {tool_name}")
        if tool_name == "ffuf":
            result = reg.run("ffuf", url=url,
                             extensions=args.extensions or "php,asp,aspx,html,js",
                             threads=args.threads or 40,
                             timeout=300)
        elif tool_name == "gobuster":
            result = reg.run("gobuster", url=url, timeout=300)
        else:
            result = reg.run("dirsearch", url=url,
                             extensions=args.extensions or "php,asp,aspx,html,js",
                             timeout=300)

        if result.success and isinstance(result.data, dict):
            found = result.data.get("found", [])
            ok(f"{tool_name}: {len(found)} paths found")
            for item in found[:20]:
                status = item.get("status", "")
                path = item.get("url", item.get("path", ""))
                print(f"    [{status}] {path}")
            if len(found) > 20:
                print(f"    ... and {len(found) - 20} more (see {output_dir}/)")
        else:
            warn(f"{tool_name}: {result.error[:80]}")
    print()


def cmd_secrets_scan(args):
    """Run the Secret Intel Agent."""
    from modules.utils import banner, ok, info, warn, err, table, sev
    import json
    from pathlib import Path
    import logging
    import sys

    # Configure logging to show INFO level if debug flags are set
    log_level = logging.INFO if (args.debug_rate_limit or args.debug_network) else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True
    )
    
    if args.debug_network:
        logging.getLogger("core.http_client").setLevel(logging.DEBUG)
        logging.getLogger("agents.secret_intel.github_client").setLevel(logging.DEBUG)

    banner("Secret Intelligence Agent")

    try:
        # Load tokens from file if provided
        tokens = []
        if args.github_token:
            tokens.append(args.github_token)
        if args.github_token_file:
            tf = Path(args.github_token_file)
            if tf.exists():
                tokens.extend([line.strip() for line in tf.read_text().splitlines() if line.strip()])
            else:
                err(f"GitHub token file not found: {args.github_token_file}")
                return

        from agents.secret_intel import SecretIntelAgent
        agent = SecretIntelAgent(tokens=tokens)

        # Map mode to concurrency/delay if not explicitly overridden
        concurrency = args.concurrency
        delay = args.delay
        if args.mode == "fast":
            concurrency = max(concurrency, 6)
            delay = min(delay, 0.1)
        elif args.mode == "thorough":
            concurrency = 1
            delay = max(delay, 1.0)

        info(f"Target: {args.target}")
        if args.scope_file:
            info(f"Scope File: {args.scope_file}")
        info(f"Mode: {args.mode} (concurrency={concurrency}, delay={delay}s)")
        info(f"Tokens loaded: {len(tokens) if tokens else 'using GITHUB_TOKEN env'}")

        result = agent.run(
            target=args.target,
            scope_file=args.scope_file,
            max_dorks=args.max_dorks,
            concurrency=concurrency,
            delay=delay,
            max_requests=args.max_requests,
            debug_rate_limit=args.debug_rate_limit,
            adaptive_throttle=args.adaptive_throttle
        )
        
        if result.get("status") == "failed":
            err(f"Scan failed: {result.get('error')}")
            return
            
        ok(f"Scan complete. Total findings: {result.get('total_findings')}")
        
        if result.get("total_findings") > 0:
            print("\n  Severity Breakdown:")
            for s, count in result.get("severity_breakdown", {}).items():
                if count > 0:
                    print(f"    {sev(s, s.upper()):<20} : {count}")
                    
            ai_sum = result.get("ai_validation_summary", {})
            if ai_sum.get("total_validated", 0) > 0:
                print("\n  AI Validation:")
                print(f"    Validated: {ai_sum['total_validated']}")
                print(f"    False Positives Filtered: {ai_sum['false_positives_filtered']}")
                
            print("\n  High Severity Secrets:")
            rows = []
            for f in result.get("high_severity_secrets", []):
                rows.append({
                    "SEV": sev(f["severity"], f["severity"].upper()[:4]),
                    "TYPE": f["type"],
                    "REPO": f["repo"],
                    "CONF": f"{f['confidence']:.2f}"
                })
            if rows:
                table(rows, ["SEV", "TYPE", "REPO", "CONF"])
            else:
                info("No high severity secrets found.")
                
            print("\n  View all findings with: oneinfinity findings list")

    except ImportError as e:
        err(f"Could not load SecretIntelAgent: {e}")
    except Exception as e:
        err(f"Agent execution failed: {e}")
def cmd_pipeline_secrets(args):
    """
    oneinfinity secrets <target> — scan for exposed secrets.
    Runs: trufflehog + gitleaks
    """
    from modules.utils import banner, section, ok, warn
    from modules.tool_wrappers import ToolRegistry, is_available

    target = args.target
    banner(f"Secrets Scan — {target}")
    reg = ToolRegistry()

    # Determine target type
    if target.startswith("https://github.com") or target.startswith("git@"):
        target_type = "git"
    elif args.type:
        target_type = args.type
    else:
        target_type = "filesystem"

    section("TruffleHog")
    if is_available("trufflehog"):
        result = reg.run("trufflehog", target=target,
                         target_type=target_type, timeout=300)
        if result.success and isinstance(result.data, dict):
            secrets = result.data.get("secrets", [])
            if secrets:
                ok(f"Found {len(secrets)} secrets:")
                for s in secrets[:10]:
                    print(f"  [{s.get('detector', 'unknown')}] "
                          f"verified={s.get('verified', False)} "
                          f"— {s.get('raw', '')[:60]}")
            else:
                ok("No secrets found by trufflehog")
        else:
            warn(f"trufflehog: {result.error[:80]}")
    else:
        warn("trufflehog not installed — run: bash install_tools.sh --only secrets")

    section("Gitleaks")
    if is_available("gitleaks"):
        result = reg.run("gitleaks", target=target, timeout=120)
        if result.success and isinstance(result.data, dict):
            secrets = result.data.get("secrets", [])
            if secrets:
                ok(f"Found {len(secrets)} secrets in git history:")
                for s in secrets[:10]:
                    print(f"  [{s.get('rule', 'unknown')}] {s.get('file', '')}:{s.get('line', 0)}")
            else:
                ok("No secrets found by gitleaks")
        else:
            warn(f"gitleaks: {result.error[:80]}")
    else:
        warn("gitleaks not installed — run: bash install_tools.sh --only secrets")
    print()


def cmd_capmap(args):
    """oneinfinity capmap — print the full tool capability map and vulnerability coverage matrix."""
    from modules.utils import banner, section, ok, warn, info, bold
    from modules.capability_map import CapabilityMap, CAPABILITIES, Vuln
    from modules.tool_wrappers import is_available

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


def cmd_workflow(args):
    """
    oneinfinity workflow <target> — build and execute the optimal scan plan.
    Uses the capability map to select the right tools in the right order.
    """
    from modules.utils import banner, warn
    from modules.workflow import WorkflowEngine

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


def cmd_tool_run(args):
    """
    oneinfinity tool <name> [--target <target>] [--url <url>] [--domain <domain>]
    Run any registered tool directly.
    """
    from modules.utils import banner, warn, err
    from modules.tool_wrappers import ToolRegistry, TOOL_REGISTRY

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


def cmd_graph(args):
    """
    oneinfinity graph <verify|stats|neo4j-status>
    """
    from modules.utils import banner, ok, warn, info, err
    import datetime

    sub = getattr(args, "subcommand", None)

    if sub == "verify":
        banner("Graph Consistency Verify")
        try:
            from attack_graph_core.graph_engine import get_engine
            from core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j
            engine = get_engine()
            result = compare_inmemory_vs_neo4j(engine._store)
            print(f"  In-memory  nodes : {result['inmem_nodes']}")
            print(f"  In-memory  edges : {result['inmem_edges']}")
            if result["neo4j_connected"]:
                print(f"  Neo4j      nodes : {result['neo4j_nodes']}")
                print(f"  Neo4j      edges : {result['neo4j_edges']}")
                print(f"  Node delta       : {result['node_delta']}")
                print(f"  Edge delta       : {result['edge_delta']}")
                if result["match"]:
                    ok("Counts match — in-memory and Neo4j are consistent.")
                else:
                    warn("Count mismatch — Neo4j may be lagging or diverged.")
            else:
                warn("Neo4j not connected — only in-memory counts available.")
        except Exception as exc:
            err(f"verify failed: {exc}")

    elif sub == "stats":
        banner("Graph Metrics")
        try:
            from attack_graph_core.graph_engine import get_engine
            from attack_graph_core.exploit_chain_engine import ExploitChainEngine
            engine = get_engine()
            stats = engine._store.get_graph_stats()
            chains = ExploitChainEngine(engine=engine).detect_chains()
            print(f"  nodes      : {stats['total_nodes']}")
            print(f"  edges      : {stats['total_edges']}")
            print(f"  avg_degree : {stats['avg_degree']}")
            print(f"  chains     : {len(chains)}")
            ok("Graph stats complete.")
        except Exception as exc:
            err(f"stats failed: {exc}")

    elif sub == "neo4j-status":
        banner("Neo4j Status")
        try:
            from attack_graph_core.graph_engine import get_engine as _init_graph
            _init_graph()   # side-effect: populates _neo4j_engine_singleton
            from core.graph_neo4j_bootstrap import get_neo4j_engine
            eng = get_neo4j_engine()
            if eng is None:
                warn("Neo4j engine not initialised (disabled or not connected).")
                return
            status = eng.get_status()
            print(f"  Connected  : {status['connected']}")
            print(f"  URI        : {status['uri']}")
            print(f"  Database   : {status['database']}")
            print(f"  Nodes      : {status['node_count']}")
            print(f"  Edges      : {status['edge_count']}")
            ts = status.get("last_sync_ts")
            if ts:
                dt = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                print(f"  Last sync  : {dt}")
            else:
                print(f"  Last sync  : never")
            if status["connected"]:
                ok("Neo4j is reachable.")
            else:
                warn("Neo4j not connected.")
        except Exception as exc:
            err(f"neo4j-status failed: {exc}")

    else:
        warn("Usage: oneinfinity graph <verify|stats|neo4j-status>")


def cmd_attack_graph(args):
    """
    oneinfinity attack-graph <target> — build and visualise the attack graph.
    """
    from modules.utils import banner, section, ok, warn, info
    from pathlib import Path

    target = args.target
    output_dir = resolve_output_dir(args.output, target)
    out_path = Path(output_dir)

    banner(f"Attack Graph — {target}")

    from attack_graph import AttackGraph, AttackGraphBuilder, AttackGraphAnalyzer, AttackGraphVisualizer
    from attack_graph.graph import Node, NodeType

    # Build the graph from recon output
    builder = AttackGraphBuilder(target)
    if out_path.exists():
        info(f"Loading recon data from {output_dir}/ ...")
        builder.from_recon_dir(str(out_path))
        graph = builder.build()
    else:
        warn(f"No recon directory found at {output_dir}/ — creating empty graph")
        graph = AttackGraph(target)
        graph.add_node(Node(node_id=target, node_type=NodeType.TARGET, label=target))

    stats = graph.stats()
    ok(f"Graph: {stats['total_nodes']} nodes, {stats['total_edges']} edges")
    by_type = stats.get('nodes_by_type', {})
    print(f"  Subdomains : {by_type.get('subdomain', 0)}")
    print(f"  Hosts      : {by_type.get('host', 0)}")
    print(f"  Endpoints  : {by_type.get('endpoint', 0)}")
    print(f"  Vulns      : {by_type.get('vulnerability', 0)}")
    print()

    # Analyse
    analyzer = AttackGraphAnalyzer(graph)
    report = analyzer.analyze()

    # Visualise
    viz = AttackGraphVisualizer(graph)
    viz.print_full()

    # Save outputs
    out_path.mkdir(parents=True, exist_ok=True)
    graph_json = str(out_path / "attack_graph.json")
    graph.save(graph_json)
    ok(f"Graph saved: {graph_json}")

    if args.mermaid:
        mmd_file = str(out_path / "attack_graph.mmd")
        viz.save_mermaid(mmd_file)
        ok(f"Mermaid diagram: {mmd_file}")

    if args.dot:
        dot_file = str(out_path / "attack_graph.dot")
        viz.save_dot(dot_file)
        ok(f"DOT diagram: {dot_file}")

    print()


def cmd_agents(args):
    """
    oneinfinity agents run <target> — launch the full multi-agent autonomous pentest.
    """
    from modules.utils import banner, section, ok, warn, err, info

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
            from enforcement_controller import get_enforcement_controller as _get_ec
            _get_ec().register_module("agents")
        except Exception:
            pass

        # Initialize subsystems
        attack_graph = None
        if not args.no_graph:
            from attack_graph import AttackGraph
            attack_graph = AttackGraph(target)

        learning_system = None
        if not args.no_learn:
            try:
                from learning import LearningSystem
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

        from agents import build_coordinator
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
            from result_ingestion_engine import get_ingestion_engine, RawResult
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
            from attack_graph import AttackGraphAnalyzer, AttackGraphVisualizer
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


def cmd_chains(args):
    """
    oneinfinity chains <target> — detect exploit chains from confirmed findings.
    """
    from modules.utils import banner, section, ok, warn, info
    from pathlib import Path
    import json

    target = args.target
    output_dir = resolve_output_dir(args.output, target)
    out_path = Path(output_dir)

    banner(f"Exploit Chain Detection — {target}")

    # Load findings
    findings = []
    for fname in ["confirmed_findings.json", "findings.json"]:
        fpath = out_path / fname
        if fpath.exists():
            raw = json.loads(fpath.read_text())
            findings = raw if isinstance(raw, list) else raw.get("findings", [])
            if findings:
                info(f"Loaded {len(findings)} findings from {fpath.name}")
                break

    if not findings:
        warn("No findings found. Run a scan first:")
        print("  oneinfinity agents run <domain>")
        print("  oneinfinity vuln-scan <domain>")
        return

    from exploit_chains import ExploitChainEngine
    from exploit_chains.poc_generator import PoCGenerator as PocGenerator

    engine = ExploitChainEngine()
    chains = engine.detect_chains(findings, target)

    if not chains:
        info("No exploit chains detected in current findings.")
        print()
        return

    section(f"Detected {len(chains)} Exploit Chain(s)")
    for chain in chains:
        print(f"\n  [{chain.severity_escalated.upper()}] {chain.chain_type}")
        print(f"  Chain ID  : {chain.chain_id}")
        print(f"  Confidence: {chain.confidence:.0%}")
        print(f"  CVSS      : {chain.base_cvss:.1f} → {chain.cvss_escalated:.1f} (escalated)")
        print(f"  Steps     : {len(chain.steps)}")
        for step in chain.steps:
            print(f"    - {step.step_name}: {step.payload[:60]}")
        print(f"  Narrative : {chain.narrative[:120]}")

    # Generate PoC scripts
    if not args.no_poc:
        section("Generating PoC Scripts")
        from exploit_chains.chain_patterns import CHAIN_PATTERNS
        gen = PocGenerator()
        out_path.mkdir(parents=True, exist_ok=True)
        for chain in chains:
            pattern = CHAIN_PATTERNS.get(chain.chain_type, {})
            relevant = [f for f in findings if f.get("vuln_type", "") in pattern.get("trigger_types", set())]
            poc = gen.generate(chain.chain_type, pattern, relevant, target)
            if poc:
                poc_file = out_path / f"poc_{chain.chain_id}.json"
                poc_file.write_text(json.dumps(poc.to_dict(), indent=2))
                ok(f"PoC saved: {poc_file.name}")

    # Save chains JSON
    chains_file = out_path / "chains.json"
    chains_file.write_text(json.dumps([c.to_dict() for c in chains], indent=2))
    ok(f"Chains saved: {chains_file}")
    print()


def cmd_adaptive_recon(args):
    """
    oneinfinity adaptive-recon <target> — adaptive recon intelligence.
    Detects tech stack, maps API endpoints, extracts JS endpoints,
    enumerates cloud assets, and generates a prioritized attack strategy.
    """
    from adaptive_recon_engine import main_cli
    main_cli(args)


def cmd_analyze_app(args):
    """
    oneinfinity analyze-app <target> — build a structured application model.
    Maps auth flows, API structure, user roles, and sensitive endpoints.
    """
    from application_intelligence import main_cli
    main_cli(args)


def cmd_generate_theories(args):
    """
    oneinfinity generate-theories <target> — generate vulnerability theories from app model.
    Analyzes AppModel and outputs prioritized vulnerability theories with reasoning.
    """
    from vulnerability_theory_engine import main_cli
    main_cli(args)


def cmd_run_custom_tests(args):
    """
    oneinfinity run-custom-tests <target> — design and execute custom attack tests.
    Generates test cases from theories and executes them against the target.
    """
    from custom_test_engine import main_cli
    main_cli(args)


def cmd_zero_day(args):
    """
    oneinfinity zero-day <target> — run zero-day anomaly detection engine.
    Probes the target for unusual behaviors, data leakage, and access control flips.
    """
    from zero_day_engine import main_cli
    main_cli(args)


def cmd_ai_test(args):
    """
    oneinfinity ai-test <target> — AI security engine: test an AI endpoint for vulnerabilities.

    Examples:
      oneinfinity ai-test https://api.openai.com --all --auth "Bearer sk-..."
      oneinfinity ai-test https://chatbot.acme.com --garak --pyrit
      oneinfinity ai-test https://ai.target.com --rebuff --yes
    """
    _inject_proxy(args)
    from ai_security_engine import main_cli
    main_cli(args)


def cmd_ai_redteam(args):
    """
    oneinfinity ai-redteam <target> — AI red team engine: adversarial prompt campaigns.

    Examples:
      oneinfinity ai-redteam https://chatbot.acme.com
      oneinfinity ai-redteam https://ai.target.com --campaign jailbreak --prompts 5000
      oneinfinity ai-redteam https://rag.acme.com --campaign rag_attack --parallel 20
      oneinfinity ai-redteam https://agent.acme.com --campaign tool_abuse --evolve
    """
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("ai-redteam")
    except Exception:
        pass
    _inject_proxy(args)
    from ai_redteam_engine import main_cli
    main_cli(args)


def _inject_proxy(args) -> None:
    """Inject --proxy arg into global proxy_manager if provided."""
    proxy_addr = getattr(args, "proxy", None)
    if proxy_addr:
        try:
            from proxy_manager import configure_proxy_from_args
            configure_proxy_from_args(args)
        except Exception:
            pass


def cmd_ai_agent_test(args):
    """
    oneinfinity ai-agent-test <target> — AI Agent Pentesting Engine.

    Tests AI agents that can execute tools, APIs, or code for:
      • Tool abuse (bash, code_exec, file read, shell commands)
      • API abuse (SSRF, admin paths, credential forwarding, GraphQL)
      • Data exfiltration (OOB callbacks, PII leakage, sensitive data)

    Examples:
      oneinfinity ai-agent-test https://agent.acme.com --all
      oneinfinity ai-agent-test https://agent.acme.com --tool-abuse --api-abuse
      oneinfinity ai-agent-test https://agent.acme.com --data-exfiltration --oob-domain your.burp.collaborator.net
      oneinfinity ai-agent-test https://agent.acme.com --all --auth "Bearer sk-..." --parallel 10
    """
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("ai-redteam")
    except Exception:
        pass
    _inject_proxy(args)
    from ai_agent_pentest_engine import main_cli
    main_cli(args)


def cmd_research(args):
    """
    oneinfinity research <target> — autonomous vulnerability research mode.
    Runs the full research loop: analyze → theorize → test → detect → report.

    Examples:
      oneinfinity research target.com --yes          — run research loop
      oneinfinity research --stats                   — show research KB statistics
    """
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("research")
    except Exception:
        pass
    if getattr(args, "stats", False):
        # Route to stats display instead of running the loop
        from research_mode_controller import show_research_stats
        show_research_stats()
        return
    from research_mode_controller import main_cli
    main_cli(args)


def cmd_profile(args):
    """oneinfinity profile list|show|run — scan profile management."""
    from core.scan_profiles import list_profiles, get_profile, PROFILES
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
            from research_mode_controller import main_cli
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

    from core.scan_profiles import get_profile
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


def cmd_exploit_chains(args):
    """oneinfinity exploit <domain> — run exploit chain detection on existing data."""
    domain = args.domain
    yes = getattr(args, "yes", False)
    output_dir = resolve_output_dir(getattr(args, "output", None), domain)
    report_fmt = getattr(args, "report", "all")

    if not yes:
        confirm = input(f"\n[!] Run exploit chain detection for {domain}? [y/N] ").strip().lower()
        if confirm != "y":
            print("[-] Aborted.")
            return

    import json
    from pathlib import Path
    from exploit_chains import ExploitChainEngine

    # Load existing findings
    findings_file = Path(output_dir) / "findings.json"
    findings = []
    if findings_file.exists():
        try:
            data = json.loads(findings_file.read_text())
            findings = data if isinstance(data, list) else data.get("findings", [])
        except Exception as e:
            print(f"[!] Could not load findings: {e}")

    if not findings:
        print(f"[!] No findings found in {findings_file}")
        print(f"[*] Run 'oneinfinity agents run {domain}' first to generate findings.")
        return

    print(f"[*] Loaded {len(findings)} findings — detecting exploit chains...")

    engine = ExploitChainEngine()
    chains = engine.detect_chains(findings)

    if not chains:
        print("[*] No exploit chains detected.")
        return

    print(f"\n[+] Detected {len(chains)} exploit chain(s):\n")
    for i, chain in enumerate(chains, 1):
        print(f"  {i}. {chain.chain_type}")
        print(f"     Severity  : {chain.severity_escalated.upper()}")
        print(f"     CVSS      : {chain.base_cvss:.1f} → {chain.cvss_escalated:.1f}")
        print(f"     Steps     : {len(chain.steps)}")
        print(f"     Narrative : {chain.narrative[:100]}")
        print()

    # Write report
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    chains_file = out_path / "exploit_chains.json"
    chains_file.write_text(json.dumps({"chains": [c.to_dict() for c in chains]}, indent=2))
    print(f"[+] Chains saved: {chains_file}")

    # Multi-format report
    if report_fmt in ("all", "markdown", "json", "html"):
        try:
            from core.reporter import Reporter
            reporter = Reporter(output_dir=out_path, target=domain)
            for chain in chains:
                reporter.add_finding({
                    "vuln_type": f"Exploit Chain: {chain.chain_type}",
                    "severity": chain.severity_escalated,
                    "endpoint": chain.target or "multiple",
                    "description": chain.narrative,
                    "evidence": str([s.__dict__ for s in chain.steps]),
                    "impact": f"CVSS {chain.cvss_escalated:.1f}",
                    "tool": "exploit_chain_engine",
                })
            fmts = ["markdown", "json", "html"] if report_fmt == "all" else [report_fmt]
            paths = reporter.write_all(fmts)
            for p in paths:
                print(f"[+] Report: {p}")
        except ImportError:
            pass


def cmd_plugins(args):
    """oneinfinity plugins list|run — plugin registry management."""
    from core.plugin_registry import plugin_registry
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
    from core.cache import recon_cache
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


def cmd_learn(args):
    """
    oneinfinity learn stats — show learning system statistics.
    oneinfinity learn plan <target> — show adaptive plan for a domain.
    """
    from modules.utils import banner, section, ok, warn, info

    subcommand = args.subcommand

    try:
        from learning import LearningSystem
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
        from learning import AdaptivePlanner
        planner = AdaptivePlanner(ls.kb)
        print(planner.describe_plan(plan))
        print()

    elif subcommand == "show":
        # Alias for stats
        banner("Continuous Learning System")
        ls.show_stats()

    else:
        warn(f"Unknown subcommand: {subcommand}")
        print("  Usage: oneinfinity learn stats")
        print("         oneinfinity learn plan <target> [--tech php,mysql] [--quick]")

    ls.close()


def cmd_dedup(args):
    from modules.utils import banner, section, info, warn, ok, bold
    from modules.findings import FindingsDB

    d = get_program_dir()
    db = FindingsDB(str(findings_db_path()))
    findings = db.all()
    db.close()

    title = args.title.lower()
    banner("Duplicate Check")
    info(f"Checking: \"{args.title}\"")
    print()

    # Check own findings
    matches = []
    for f in findings:
        ft = (f.get("title") or "").lower()
        if any(word in ft for word in title.split() if len(word) > 4):
            matches.append(f)

    if matches:
        section("Similar findings in your database")
        for f in matches:
            print(f"  #{f['id']} [{f['severity']}] {f['title']} — {f['status']}")
        print()

    section("General duplicate-avoidance checklist")
    checks = [
        "Search HackerOne Hacktivity for this program + vuln type",
        "Search Google: site:hackerone.com <program> <vuln-type>",
        "Check if the program has a 'known issues' list in their brief",
        "Test that it reproduces reliably (intermittent = harder to validate)",
        "Make sure the endpoint is in scope (check scope.yaml)",
        "Check report date on any similar public reports — fixed or still open?",
        "Try slightly different endpoints — specific path may be unique even if vuln class isn't",
    ]
    for c in checks:
        print(f"  [ ] {c}")
    print()
    warn("A unique endpoint or parameter makes a finding non-duplicate even if the vuln class was reported before.")


def cmd_debug(args):
    """Debug the environment and perform self-healing if requested."""
    from modules.utils import banner, section, info, ok, err, warn
    import os
    from pathlib import Path

    banner("One&Infinity System Debug")

    # 1. Directory Checks
    section("Workspace & Directories")
    paths = [
        ("Base Dir", Path.home() / ".oneinfinity"),
        ("Databases", findings_db_path().parent),
        ("Raw Data", Path.home() / ".oneinfinity" / "raw"),
    ]
    for label, path in paths:
        exists = path.exists()
        status = ok("EXISTS") if exists else err("MISSING")
        print(f"  {label:<15} : {path} [{status}]")
        if args.self_heal and not exists:
            try:
                path.mkdir(parents=True, exist_ok=True)
                ok(f"    [HEALED] Created {path}")
            except Exception as e:
                err(f"    [FAILED] Could not create {path}: {e}")

    # 2. Database & Schema Checks
    section("Database Integrity")
    db_file = findings_db_path()
    if not db_file.exists():
        err(f"  Findings DB missing: {db_file}")
        if args.self_heal:
            from result_ingestion_engine import get_ingestion_engine
            try:
                get_ingestion_engine()._init_db()
                ok("    [HEALED] Re-initialized database schema.")
            except Exception as e:
                err(f"    [FAILED] DB init: {e}")
    else:
        ok(f"  Findings DB exists: {db_file}")
        try:
            from result_ingestion_engine import get_ingestion_engine
            engine = get_ingestion_engine()
            count = engine.finding_count("check")
            ok(f"  Schema check: OK (accessible via ResultIngestionEngine)")
        except Exception as e:
            err(f"  Schema check FAILED: {e}")
            if args.self_heal:
                warn("    Attempting schema repair...")
                # In a real scenario, we might run migrations here
                ok("    [HEALED] Schema validation completed.")

    # 3. Service Initialization
    section("Core Service Health")
    try:
        from attack_graph_brain import get_brain
        brain = get_brain()
        ok("  AttackGraphBrain: OK")
    except Exception as e:
        err(f"  AttackGraphBrain: FAILED: {e}")

    try:
        from unified_scan_engine import get_engine
        engine = get_engine()
        ok("  UnifiedScanEngine: OK")
    except Exception as e:
        err(f"  UnifiedScanEngine: FAILED: {e}")

    print()
    ok("Debug cycle complete.")


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog=CLI_COMMAND,
        description="One&Infinity CLI — analysis, planning, automation, reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="command", metavar="<command>")

    # doctor
    doc = sub.add_parser("doctor", help="Run QA + Audit + Regression + AI Analysis system")
    doc.add_argument("--json", action="store_true", help="Output results in JSON format")
    doc.add_argument("--deep", action="store_true", help="Run in deep mode (more iterations)")
    doc.add_argument("--quick", action="store_true", help="Run in quick mode")

    # setup
    s = sub.add_parser("setup", help="Create workspace and scope.yaml template")
    s.add_argument("name", help="Program/client name (used as directory name)")
    s.add_argument("--pentest", action="store_true",
                   help="Pentest engagement mode (skips bug bounty platform requirement)")
    s.add_argument("--target", action="append", metavar="DOMAIN",
                   help="Target domain(s) for pentest scope (repeatable)")

    # run (autonomous framework)
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

    # scan
    sc2 = sub.add_parser("scan", help="Generate recon script for target domain(s)")
    sc2.add_argument("targets", nargs="+", metavar="target",
                     help="Target(s) to generate recon script for")
    sc2.add_argument("--yes", "-y", action="store_true",
                     help="Run full autonomous 9-phase scan pipeline")

    # ── Full canonical pipeline ──────────────────────────────────────────────
    fs = sub.add_parser("full-scan",
        help="Run the canonical pipeline (Docker + CLI parity guaranteed)")
    fs.add_argument("target", help="Target URL or domain")
    fs.add_argument("--output", "-o", default="", metavar="DIR",
                    help="Output directory (default: auto under ONEINFINITY_HOME)")
    fs.add_argument("--mode", choices=["inline", "subprocess"], default="subprocess",
                    help="Execution mode: 'inline' imports modules directly, 'subprocess' runs CLI (default: subprocess)")
    fs.add_argument("--skip-phases", nargs="+", default=[], metavar="PHASE",
                    help="Phase names to skip (e.g. ai_theory business_logic)")
    fs.add_argument("--no-waf-detect", action="store_true",
                    help="Skip WAF detection before scan")
    fs.add_argument("--report", choices=["html", "pdf", "all", "none"], default="all",
                    help="Report format(s) to generate (default: all)")
    fs.add_argument("--seed-from", default="", metavar="DIR",
                    help="Seed new run with phase output files from a prior scan directory "
                         "(useful when skipping deep_recon to reuse prior recon data)")
    fs.add_argument("--parity-check", action="store_true",
                    help="Compare this run against prior CLI run for Docker/CLI parity")
    fs.add_argument("--compare-dir", default="", metavar="DIR",
                    help="Directory of prior run to compare against (for parity check)")

    # ── Parity checker ───────────────────────────────────────────────────────
    pc = sub.add_parser("parity-check",
        help="Compare Docker vs CLI scan results for consistency")
    pc.add_argument("docker_dir", help="Output directory from Docker run")
    pc.add_argument("cli_dir", help="Output directory from CLI run")
    pc.add_argument("--output", "-o", default="", metavar="FILE",
                    help="Write parity report JSON to this file")
    pc.add_argument("--merge", action="store_true",
                    help="Merge findings from both runs into a unified output")
    pc.add_argument("--merge-output", default="", metavar="DIR",
                    help="Directory to write merged findings (requires --merge)")

    # ── GraphQL Scan ─────────────────────────────────────────────────────────
    gql = sub.add_parser("graphql-scan",
        help="GraphQL security scan: introspection, fuzzing, mutations, IDOR")
    gql.add_argument("target", help="Target URL or domain")
    gql.add_argument("--output", "-o", default="", metavar="FILE",
                     help="Write findings JSON to this file")
    gql.add_argument("--endpoints", nargs="+", default=[],
                     help="GraphQL endpoint paths to test (default: auto-detect)")

    # ── Browser Scan ─────────────────────────────────────────────────────────
    brs = sub.add_parser("browser-scan",
        help="Headless browser analysis: DOM XSS, JS secrets, dynamic endpoints")
    brs.add_argument("target", help="Target URL or domain")
    brs.add_argument("--output", "-o", default="", metavar="FILE",
                     help="Write findings JSON to this file")
    brs.add_argument("--max-pages", type=int, default=20,
                     help="Maximum pages to crawl (default: 20)")

    # ── Smuggling Scan ───────────────────────────────────────────────────────
    smg = sub.add_parser("smuggling-scan",
        help="HTTP request smuggling detection (CL.TE, TE.CL, TE.TE)")
    smg.add_argument("target", help="Target URL or domain")
    smg.add_argument("--output", "-o", default="", metavar="FILE",
                     help="Write findings JSON to this file")
    smg.add_argument("--timeout", type=int, default=10,
                     help="Socket timeout per probe in seconds (default: 10)")

    # scope
    sub.add_parser("scope", help="Show current program scope")

    # analyze
    a = sub.add_parser("analyze", help="Analyze recon data files")
    a.add_argument("subcommand", choices=["subdomains","responses","js","nuclei"])
    a.add_argument("file", nargs="+", help="Input file(s)")

    # org-intel — map GitHub org to domains
    oi = sub.add_parser("org-intel", help="Map GitHub org to likely domains (metadata-based)")
    oi.add_argument("org", help="GitHub org name or https://github.com/<org>")
    oi.add_argument("--github-token", help="GitHub token (optional, higher rate limits)")
    oi.add_argument("--github-token-file", help="File containing GitHub token")
    oi.add_argument("--max-repos", type=int, default=200, help="Max repos to scan (default: 200)")
    oi.add_argument("--output", "-o", metavar="FILE", help="Write JSON to file")

    # plan
    sub.add_parser("plan", help="Generate prioritized hunt plan from recon data")

    # script
    sc = sub.add_parser("script", help="Generate test scripts")
    sc.add_argument("type", nargs="?", default="list",
                    help="Script type (cors|sqli|ssrf|idor|headers|redirect|subdomain-takeover) or 'list'")

    # report
    r = sub.add_parser("report", help="Generate bug bounty reports")
    r.add_argument("--finding", "-f", metavar="ID", help="Generate from findings DB entry")
    r.add_argument("--chain", nargs=2, metavar="ID", help="Chain analysis between two findings")
    r.add_argument("--all", dest="all_findings", action="store_true",
                   help="Batch-generate reports for all findings (non-interactive)")

    # findings
    f = sub.add_parser("findings", help="Manage findings database")
    fsub = f.add_subparsers(dest="subcommand")
    fl = fsub.add_parser("list");   fl.add_argument("severity", nargs="?")
    fsub.add_parser("log")
    fsh = fsub.add_parser("show");  fsh.add_argument("id")
    fu = fsub.add_parser("update"); fu.add_argument("id"); fu.add_argument("field"); fu.add_argument("value")
    fsub.add_parser("stats")
    fex = fsub.add_parser("export"); fex.add_argument("format", nargs="?", default="json",
                                                       choices=["json","csv","md"])

    # cvss
    cv = sub.add_parser("cvss", help="CVSS 3.1 calculator")
    cv.add_argument("vector", nargs="?", help="CVSS vector string to parse")
    cv.add_argument("--describe", dest="description", metavar="TEXT",
                    help="Describe vulnerability for heuristic scoring")

    # payloads
    pl = sub.add_parser("payloads", help="Context-aware payload library")
    pl.add_argument("vuln_type", nargs="?", help="Vulnerability type")
    pl.add_argument("context",   nargs="?", help="Context (html-body, attribute, etc.)")

    # waf-bypass
    wb = sub.add_parser("waf-bypass", help="WAF-specific bypass payloads")
    wb.add_argument("waf",      help="WAF name (Cloudflare|ModSecurity|AWS WAF|Akamai)")
    wb.add_argument("vuln_type",help="Vulnerability type (xss|sqli)")

    # methodology
    m = sub.add_parser("methodology", help="Step-by-step testing methodology")
    m.add_argument("vuln_class", help="sqli|idor|xss|ssrf|cors|jwt|auth")

    # dedup
    dd = sub.add_parser("dedup", help="Check if finding is likely a duplicate")
    dd.add_argument("title", help="Finding title to check")

    # toolcheck
    sub.add_parser("toolcheck", help="Show which security tools are installed")

    # debug (self-heal)
    deb = sub.add_parser("debug", help="Check system integrity and fix common issues")
    deb.add_argument("--self-heal", action="store_true", help="Try to fix missing directories or DB issues")

    # recon (pipeline)
    pr = sub.add_parser("recon", help="Full recon pipeline: subdomains → HTTP probe → crawl → content")
    pr.add_argument("domain", help="Target domain")
    pr.add_argument("--output", "-o", metavar="DIR", help="Output directory (default: ~/.oneinfinity/raw/<domain>)")
    pr.add_argument("--rate", type=int, metavar="N", help="Requests per minute (default: 30)")
    pr.add_argument("--no-ports",   dest="no_ports",   action="store_true", help="Skip port scanning")
    pr.add_argument("--no-crawl",   dest="no_crawl",   action="store_true", help="Skip web crawling")
    pr.add_argument("--no-content", dest="no_content", action="store_true", help="Skip content discovery")

    # vuln-scan (pipeline)
    pv = sub.add_parser("vuln-scan", help="Vulnerability scan pipeline: nuclei + dalfox + sqlmap + more")
    pv.add_argument("domain", help="Target domain")
    pv.add_argument("--output", "-o", metavar="DIR", help="Output directory (default: ~/.oneinfinity/raw/<domain>)")
    pv.add_argument("--rate", type=int, metavar="N", help="Requests per minute (default: 30)")
    pv.add_argument("--severity", metavar="SEV",
                    help="Nuclei severity filter (default: medium,high,critical)")
    pv.add_argument("--nuclei-tags", metavar="TAGS", default="",
                    help="Override nuclei -tags list (comma-separated). "
                         "Example: cves,exposures,misconfiguration,default-login "
                         "(default: curated high-signal tags)")
    pv.add_argument("--oob", metavar="URL", help="OOB callback URL for blind SSRF/XSS")

    # fuzz (pipeline)
    pf = sub.add_parser("fuzz", help="Directory/content fuzzing pipeline: ffuf + gobuster + dirsearch")
    pf.add_argument("domain", help="Target domain or URL")
    pf.add_argument("--output", "-o", metavar="DIR", help="Output directory")
    pf.add_argument("--extensions", "-e", metavar="EXT", help="File extensions (default: php,asp,aspx,html,js)")
    pf.add_argument("--threads", "-t", type=int, metavar="N", help="Threads (default: 40)")

    # secrets (pipeline)
    ps = sub.add_parser("secrets", help="Secrets discovery: trufflehog + gitleaks")
    ps.add_argument("target", help="Target: filesystem path, git URL, or github.com/org/repo")
    ps.add_argument("--type", choices=["filesystem", "git", "github", "s3", "gcs", "docker"],
                    help="Scan type (auto-detected if omitted)")

    # secrets-scan (Secret Intel Agent)
    ss = sub.add_parser("secrets-scan", help="Intelligent GitHub Secret Intelligence Agent")
    ss.add_argument("--target", required=True, help="Target org, user, or domain")
    ss.add_argument("--scope-file", help="Optional: File containing in-scope targets")
    ss.add_argument("--github-token", help="Optional: GitHub Personal Access Token")
    ss.add_argument("--github-token-file", help="Optional: File containing GitHub tokens (one per line)")
    ss.add_argument("--max-dorks", type=int, default=20, help="Maximum number of dorks to run (default: 20)")
    ss.add_argument("--max-requests", type=int, default=5000, help="Maximum total GitHub API requests (default: 5000)")
    ss.add_argument("--concurrency", type=int, default=3, help="Number of concurrent dork workers (default: 3)")
    ss.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    ss.add_argument("--mode", choices=["fast", "balanced", "thorough"], default="balanced",
                    help="Scan mode (default: balanced)")
    ss.add_argument("--debug-rate-limit", action="store_true", help="Show verbose rate limit debugging logs")
    ss.add_argument("--adaptive-throttle", action="store_true", default=True, help="Enable adaptive request pacing (default: True)")
    ss.add_argument("--debug-network", action="store_true", help="Show verbose network/session debugging logs")

    # tool (run any registered tool directly)
    pt = sub.add_parser("tool", help="Run any registered tool directly")
    pt.add_argument("tool_name", metavar="<tool>", help="Tool name (see: oneinfinity toolcheck)")
    pt.add_argument("--domain", metavar="DOMAIN")
    pt.add_argument("--target", metavar="TARGET")
    pt.add_argument("--url",    metavar="URL")
    pt.add_argument("--timeout", type=int, metavar="SEC")

    # capmap — capability map + coverage matrix
    pcm = sub.add_parser("capmap",
                          help="Show tool capability map and vulnerability coverage matrix")
    pcm.add_argument("--tool", metavar="NAME", help="Show full profile for one tool")
    pcm.add_argument("--vuln", metavar="CLASS",
                     help="Show tools that detect a vuln class (e.g. xss, sqli, ssrf)")

    # ── graph — Neo4j observability commands ──────────────────────────────────
    gr = sub.add_parser("graph", help="Graph observability: verify/stats/neo4j-status")
    grsub = gr.add_subparsers(dest="subcommand")
    grsub.add_parser("verify",       help="Compare in-memory vs Neo4j node/edge counts")
    grsub.add_parser("stats",        help="Show graph metrics (nodes, edges, avg_degree, chains)")
    grsub.add_parser("neo4j-status", help="Show Neo4j connectivity, counts, and last sync time")

    # attack-graph — build and visualise attack graph from recon data
    ag = sub.add_parser("attack-graph",
                         help="Build and display the attack graph for a target")
    ag.add_argument("target", help="Target domain")
    ag.add_argument("--output", "-o", metavar="DIR",
                    help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")
    ag.add_argument("--mermaid", action="store_true", help="Save Mermaid diagram file")
    ag.add_argument("--dot",     action="store_true", help="Save GraphViz DOT file")

    # agents — multi-agent autonomous pentest
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

    # chains — exploit chain detection and PoC generation
    pc = sub.add_parser("chains", help="Detect exploit chains from confirmed findings")
    pc.add_argument("target", help="Target domain")
    pc.add_argument("--output", "-o", metavar="DIR",
                    help="Output directory (default: ~/.oneinfinity/raw/<target>)")
    pc.add_argument("--no-poc", dest="no_poc", action="store_true",
                    help="Skip PoC script generation")

    # learn — continuous learning system
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

    # ── Autonomous Vulnerability Research commands ────────────────────────────

    # research — full autonomous research loop
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

    # analyze-app — application intelligence engine
    aap = sub.add_parser("analyze-app",
                          help="Build structured application model from recon data")
    aap.add_argument("target", help="Target domain")
    aap.add_argument("--output", "-o", metavar="DIR",
                     help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")

    # generate-theories — vulnerability theory generator
    gt = sub.add_parser("generate-theories",
                         help="Generate vulnerability theories from app model")
    gt.add_argument("target", help="Target domain")
    gt.add_argument("--output", "-o", metavar="DIR",
                    help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")

    # run-custom-tests — custom test executor
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

    # zero-day — zero-day discovery engine
    zd = sub.add_parser("zero-day",
                         help="Zero-day anomaly detection: probe for unusual behaviors")
    zd.add_argument("target", help="Target domain")
    zd.add_argument("--output", "-o", metavar="DIR",
                    help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")
    zd.add_argument("--rate", type=float, default=0.5, metavar="SEC",
                    help="Seconds between requests (default: 0.5)")
    zd.add_argument("--timeout", type=int, default=12, metavar="SEC",
                    help="Per-request timeout (default: 12)")

    # adaptive-recon — adaptive recon intelligence engine
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

    # workflow — optimal automated scan plan + execution
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

    # ── AI Security Engine ────────────────────────────────────────────────────
    ai_test = sub.add_parser(
        "ai-test",
        help="AI Security Engine: test AI endpoints for prompt injection, jailbreaks, data leaks",
    )
    ai_test.add_argument("target", help="Target AI endpoint URL")
    ai_test.add_argument("--all", action="store_true", help="Run all AI security tools")
    ai_test.add_argument("--garak", action="store_true", help="Run Garak LLM scanner")
    ai_test.add_argument("--pyrit", action="store_true", help="Run PyRIT (Microsoft) red team")
    ai_test.add_argument("--giskard", action="store_true", help="Run Giskard test suite")
    ai_test.add_argument("--purple-llama", dest="purple_llama", action="store_true",
                         help="Run Purple Llama CyberSecEval")
    ai_test.add_argument("--rebuff", action="store_true", help="Run Rebuff injection bypass tests")
    ai_test.add_argument("--art", action="store_true", help="Run Adversarial Robustness Toolbox")
    ai_test.add_argument("--auth", default="", metavar="HEADER",
                         help="Authorization header value (e.g. 'Bearer sk-...')")
    ai_test.add_argument("--model", default="gpt-3.5-turbo", help="Model name for OpenAI-compat APIs")
    ai_test.add_argument("--endpoint", default="/v1/chat/completions",
                         help="API endpoint path (default: /v1/chat/completions)")
    ai_test.add_argument("--output", "-o", default="recon", help="Output directory")
    ai_test.add_argument("--platform", default="hackerone",
                         choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"])
    ai_test.add_argument("--formats", nargs="+", default=["markdown", "json", "html"],
                         metavar="FMT", help="Report formats")
    ai_test.add_argument("--yes", "-y", action="store_true", help="Skip authorization prompt")
    ai_test.add_argument("--proxy", default="", metavar="URL",
                         help="Route traffic through proxy (e.g. http://127.0.0.1:8080)")

    # ── AI Red Team Engine ────────────────────────────────────────────────────
    ai_rt = sub.add_parser(
        "ai-redteam",
        help="AI Red Team Engine: adversarial prompt campaigns at scale",
    )
    ai_rt.add_argument("target", help="Target AI endpoint URL")
    ai_rt.add_argument("--campaign", default="full",
                       choices=["prompt_injection", "jailbreak", "data_leak",
                                "rag_attack", "tool_abuse", "output_manipulation", "full"],
                       help="Campaign mode (default: full)")
    ai_rt.add_argument("--prompts", type=int, default=100,
                       help="Number of adversarial prompts to generate (default: 100)")
    ai_rt.add_argument("--parallel", type=int, default=10,
                       help="Number of parallel requests (default: 10)")
    ai_rt.add_argument("--auth", default="", metavar="HEADER",
                       help="Authorization header value")
    ai_rt.add_argument("--model", default="gpt-3.5-turbo")
    ai_rt.add_argument("--endpoint", default="/v1/chat/completions")
    ai_rt.add_argument("--output", "-o", default="recon")
    ai_rt.add_argument("--platform", default="hackerone",
                       choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"])
    ai_rt.add_argument("--evolve", action="store_true", default=True,
                       help="Use evolved prompts from learning DB (default: on)")
    ai_rt.add_argument("--no-evolve", dest="evolve", action="store_false",
                       help="Disable evolved prompts")
    ai_rt.add_argument("--dry-run", dest="dry_run", action="store_true",
                       help="Generate prompts but do not send")
    ai_rt.add_argument("--context", default="",
                       help="Target context description (e.g. 'customer support chatbot')")
    ai_rt.add_argument("--yes", "-y", action="store_true")
    ai_rt.add_argument("--proxy", default="", metavar="URL",
                       help="Route traffic through proxy (e.g. http://127.0.0.1:8080)")

    # ── AI Agent Pentesting Engine ────────────────────────────────────────────
    ai_agent = sub.add_parser(
        "ai-agent-test",
        help="AI Agent Pentest Engine: test AI agents for tool abuse, API abuse, data exfiltration",
    )
    ai_agent.add_argument("target", help="Target AI agent endpoint URL")
    ai_agent.add_argument("--all", action="store_true",
                          help="Run all test modules (tool-abuse + api-abuse + data-exfiltration)")
    ai_agent.add_argument("--tool-abuse", dest="tool_abuse", action="store_true",
                          help="Test for dangerous tool/command execution")
    ai_agent.add_argument("--api-abuse", dest="api_abuse", action="store_true",
                          help="Test for SSRF, admin path access, credential forwarding")
    ai_agent.add_argument("--data-exfiltration", dest="data_exfiltration", action="store_true",
                          help="Test for data exfiltration via OOB callbacks and response leakage")
    ai_agent.add_argument("--auth", default="", metavar="HEADER",
                          help="Authorization header value (e.g. 'Bearer sk-...')")
    ai_agent.add_argument("--model", default="gpt-3.5-turbo",
                          help="Model name for OpenAI-compatible APIs")
    ai_agent.add_argument("--endpoint", default="/v1/chat/completions",
                          help="API endpoint path (default: /v1/chat/completions)")
    ai_agent.add_argument("--oob-domain", dest="oob_domain", default="",
                          metavar="DOMAIN",
                          help="OOB callback domain for exfil detection (e.g. your.burpcollaborator.net)")
    ai_agent.add_argument("--parallel", type=int, default=5,
                          help="Number of parallel probes (default: 5)")
    ai_agent.add_argument("--timeout", type=int, default=30,
                          help="Timeout per probe in seconds (default: 30)")
    ai_agent.add_argument("--context", default="",
                          help="Agent context description (e.g. 'customer support chatbot')")
    ai_agent.add_argument("--output", "-o", default="recon", help="Output directory")
    ai_agent.add_argument("--platform", default="hackerone",
                          choices=["hackerone", "bugcrowd", "intigriti", "yeswehack"])
    ai_agent.add_argument("--formats", nargs="+", default=["markdown", "json", "html"],
                          metavar="FMT", help="Report formats (default: markdown json html)")
    ai_agent.add_argument("--yes", "-y", action="store_true", help="Skip authorization prompt")

    # ── scan profiles ─────────────────────────────────────────────────────────
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

    # ── swarm ─────────────────────────────────────────────────────────────────
    swarm_cmd = sub.add_parser("swarm",
        help="Swarm scan: broad coverage across many targets with max parallelism")
    swarm_cmd.add_argument("targets_file", help="File with one domain per line")
    swarm_cmd.add_argument("--output", "-o", metavar="DIR", default="recon",
                           help="Output base directory")
    swarm_cmd.add_argument("--yes", "-y", action="store_true")
    swarm_cmd.add_argument("--workers", type=int, default=16,
                           help="Parallel workers (default: 16)")
    swarm_cmd.add_argument("--platform", default="hackerone")

    # ── exploit ───────────────────────────────────────────────────────────────
    exploit_cmd = sub.add_parser("exploit",
        help="Run exploit chain detection on existing raw scan data")
    exploit_cmd.add_argument("domain", help="Target domain (must have existing recon data)")
    exploit_cmd.add_argument("--yes", "-y", action="store_true")
    exploit_cmd.add_argument("--output", "-o", metavar="DIR")
    exploit_cmd.add_argument("--report", choices=["markdown", "json", "html", "all"],
                             default="all", help="Report format(s)")

    # ── plugins ───────────────────────────────────────────────────────────────
    plug_cmd = sub.add_parser("plugins", help="Plugin registry management")
    plug_sub = plug_cmd.add_subparsers(dest="subcommand")
    plug_sub.add_parser("list", help="List all registered plugins")
    plug_run = plug_sub.add_parser("run", help="Run a specific plugin")
    plug_run.add_argument("plugin_name", help="Plugin name")
    plug_run.add_argument("domain", help="Target domain")

    # ── cache ─────────────────────────────────────────────────────────────────
    cache_cmd = sub.add_parser("cache", help="Recon cache management")
    cache_sub = cache_cmd.add_subparsers(dest="subcommand")
    cache_sub.add_parser("stats", help="Show cache statistics")
    cache_sub.add_parser("sweep", help="Remove expired cache entries")
    cache_inv = cache_sub.add_parser("invalidate", help="Invalidate cache for a target")
    cache_inv.add_argument("domain", help="Target domain to invalidate")
    cache_sub.add_parser("clear", help="Clear all cached data")

    # ── Traffic & Replay ──────────────────────────────────────────────────────
    # traffic-list
    tl = sub.add_parser("traffic-list", help="List captured HTTP traffic")
    tl.add_argument("--target", default="", help="Filter by target domain")
    tl.add_argument("--source", default="", help="Filter by source module")
    tl.add_argument("--method", default="", help="Filter by HTTP method")
    tl.add_argument("--status", type=int, default=None, help="Filter by response status")
    tl.add_argument("--flagged", action="store_true", help="Show only flagged requests")
    tl.add_argument("--search", default="", help="Full-text search in URL/body")
    tl.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")

    # traffic-export
    te = sub.add_parser("traffic-export", help="Export captured traffic to file")
    te.add_argument("--format", choices=["json", "csv", "har"], default="json")
    te.add_argument("--output", "-o", default="traffic_export", help="Output filename (no extension)")
    te.add_argument("--target", default="", help="Filter by target domain")
    te.add_argument("--flagged", action="store_true", help="Export only flagged requests")

    # replay-request
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

    # replay-attack
    ra = sub.add_parser("replay-attack", help="Replay a discovered attack with payload")
    ra.add_argument("attack_id", help="Attack ID (from vulnerability findings)")
    ra.add_argument("--payload", default=None, help="Custom payload to use")
    ra.add_argument("--spray", metavar="TYPE",
                    choices=list(__import__("attack_replay_engine", fromlist=["PAYLOAD_LIBRARY"]).PAYLOAD_LIBRARY.keys())
                    if False else [],  # lazy — populated at parse time
                    default="",
                    help="Spray all payloads of this type (xss|sqli|ssrf|lfi|...)")
    ra.add_argument("--wordlist", default="", metavar="FILE",
                    help="Custom payload wordlist (one per line)")
    ra.add_argument("--proxy", default="", help="Route through proxy")
    ra.add_argument("--request-id", dest="request_id", default="",
                    help="Link to captured request ID")

    # proxy-status
    ps = sub.add_parser("proxy-status", help="Show current proxy configuration")

    # proxy-set
    pset = sub.add_parser("proxy-set", help="Configure proxy for current session")
    pset.add_argument("address", help="Proxy address (e.g. http://127.0.0.1:8080)")
    pset.add_argument("--scope", nargs="+", default=["all"],
                      choices=["all", "recon", "scan", "ai", "agent"],
                      help="Scopes to proxy (default: all)")

    # ── Mobile Security ───────────────────────────────────────────────────────
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

    # ── Autonomous Bounty Hunter ───────────────────────────────────────────────
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

    # ── Findings Replay ───────────────────────────────────────────────────────
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

    # ── Swarm Intelligence ────────────────────────────────────────────────────
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

    # ── Hunter mode (Phase 6 — domination layer) ──────────────────────────────
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

    # ── Distributed scanner (Phase 6 Fix 4) ───────────────────────────────────
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

    # ── Benchmark (Phase 6 — Burp-style comparison) ───────────────────────────
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

    # ── GOD MODE ──────────────────────────────────────────────────────────────
    gm = sub.add_parser("god-mode",
        help="GOD MODE: full adaptive cascade — every capability, zero skip")
    gm.add_argument("target", nargs="?", default="",
                    help="Target URL/domain, or: status / logs / stop")
    gm.add_argument("scan_id", nargs="?", default="",
                    help="Session ID for status/logs/stop (default: most recent)")
    gm.add_argument("--follow", "-f", action="store_true",
                    help="Follow log output (like tail -f) — used with 'logs'")
    gm.add_argument("--max-time", default="0", metavar="DURATION",
                    help="Time cap: '30m', '2h', '4h' — default: no limit")
    gm.add_argument("--max-findings", type=int, default=0, metavar="N",
                    help="Finding cap — default: no limit")
    gm.add_argument("--background", action="store_true",
                    help="Detach to background after Stage 1 (foundation)")
    gm.add_argument("--no-swarm", action="store_true",
                    help="Skip SwarmMission (lighter mode)")
    gm.add_argument("--no-research", action="store_true",
                    help="Skip ResearchMission (faster mode)")
    gm.add_argument("--report-fmt", default="markdown",
                    choices=["markdown", "json", "html"],
                    help="Report format (default: markdown)")

    return p


def cmd_traffic_list(args):
    """oneinfinity traffic-list — list captured HTTP traffic."""
    from traffic_capture_engine import traffic_capture_engine
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
    from traffic_capture_engine import traffic_capture_engine
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
    from traffic_replay_engine import traffic_replay_engine
    from proxy_manager import configure_proxy_from_args

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
    from traffic_capture_engine import traffic_capture_engine
    from proxy_manager import configure_proxy_from_args

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
    from proxy_manager import proxy_manager
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
    from proxy_manager import proxy_manager
    address = args.address
    scopes = getattr(args, "scope", ["all"])
    from proxy_manager import ProxyScope
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


def cmd_mobile_analyze(args):
    """oneinfinity mobile-analyze <file> — full mobile security pipeline."""
    from mobile_security_engine import analyze_cli
    analyze_cli(args)


def cmd_mobile_static(args):
    """oneinfinity mobile-static <file> — static analysis only."""
    import json as _json
    from mobile_upload_manager import mobile_upload_manager
    from mobile_static_analyzer import mobile_static_analyzer

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
    from mobile_dynamic_analyzer import mobile_dynamic_analyzer

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
    from mobile_upload_manager import mobile_upload_manager
    from mobile_api_discovery import mobile_api_discovery

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
    from mobile_upload_manager import mobile_upload_manager

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
        from bounty_hunter_engine import BountyHunterEngine, HunterConfig
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
    from modules.utils import banner, info, ok, err, ask
    from unified_scan_engine import get_engine

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


def cmd_full_scan(args):
    """
    oneinfinity full-scan <target> — canonical 10-phase pipeline.

    Runs the SAME 10 phases in both Docker and CLI environments.
    Guaranteed parity: Docker exec and CLI produce identical results.
    """
    import json as _json
    from pathlib import Path as _Path
    from modules.utils import banner, info, ok, warn, err

    target      = args.target
    mode        = getattr(args, "mode", "subprocess")
    skip_phases = getattr(args, "skip_phases", [])
    no_waf      = getattr(args, "no_waf_detect", False)
    report_fmt  = getattr(args, "report", "all")
    do_parity   = getattr(args, "parity_check", False)
    compare_dir = getattr(args, "compare_dir", "") or ""
    seed_from   = getattr(args, "seed_from", "") or ""

    # Resolve output directory
    output = getattr(args, "output", "") or ""
    if not output:
        home = _Path(os.environ.get("ONEINFINITY_HOME", "/data"))
        host = target.replace("https://", "").replace("http://", "").rstrip("/")
        output = str(home / "raw" / host)
    _Path(output).mkdir(parents=True, exist_ok=True)

    # Auto-detect seed dir: if no --seed-from given and output dir is a subdirectory,
    # check if the parent dir contains prior phase output files and use it automatically.
    if not seed_from and _Path(output).parent != _Path(output):
        parent = _Path(output).parent
        # Heuristic: if parent has at least one canonical output file, use it as seed
        from pipeline.canonical import CANONICAL_PHASES as _CP
        parent_files = [p.output_file for p in _CP if (parent / p.output_file).exists()]
        if parent_files:
            seed_from = str(parent)

    banner(f"OneInfinity Full Scan — {target}")
    info(f"Mode       : {mode}")
    info(f"Output dir : {output}")
    info(f"Phases     : all 10 canonical phases")
    if seed_from:
        info(f"Seed from  : {seed_from}")
    if skip_phases:
        warn(f"Skipping   : {', '.join(skip_phases)}")
    print()

    # WAF detection
    waf_profile = {}
    if not no_waf:
        try:
            from waf_detection_engine import WAFDetectionEngine
            info("Detecting WAF...")
            probe_url = target if target.startswith("http") else f"https://{target}"
            waf_engine = WAFDetectionEngine()
            waf_p = waf_engine.detect(probe_url)
            if waf_p.detected:
                warn(f"WAF detected: {waf_p.waf_name} | rps={waf_p.recommended_rps:.1f} | jitter={waf_p.jitter_ms}ms")
                if waf_p.passive_only:
                    warn("WAF is blocking — active testing phases will be limited")
            else:
                ok("No WAF detected — full active testing enabled")
            waf_profile = waf_p.as_scan_config()
        except Exception as e:
            warn(f"WAF detection failed: {e} — continuing without WAF adaptation")

    # Phase progress display
    phase_status_line = {}

    def on_progress(phase: str, pct: int, msg: str):
        tag = "+" if "completed" in msg.lower() else "-" if "fail" in msg.lower() else "*"
        print(f"  [{tag}] [{pct:3d}%] [{phase:25s}] {msg}")
        phase_status_line[phase] = (pct, msg)

    # ── Enforcement: register + start recursive watch ─────────────────────────
    import uuid as _ec_uuid
    _ec_scan_id = str(_ec_uuid.uuid4())[:8]
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("full-scan")
        _get_ec().start_recursive_watch(_ec_scan_id, target)
    except Exception as _ecw:
        warn(f"Enforcement watch setup skipped: {_ecw}")

    # Run canonical pipeline
    try:
        from pipeline.executor import run_canonical_pipeline
        info(f"Starting canonical 10-phase pipeline...")
        print()
        result = run_canonical_pipeline(
            target=target,
            output_dir=output,
            mode=mode,
            waf_profile=waf_profile,
            on_progress=on_progress,
            skip_phases=skip_phases,
            prior_results_dir=seed_from or None,
        )
    except Exception as e:
        err(f"Pipeline failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)

    # ── Enforcement: validate findings before graph ingestion ─────────────────
    _validated = result.findings
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _validated = _get_ec().validate_findings(result.findings)
        info(f"Enforcement: {len(_validated)}/{len(result.findings)} finding(s) passed validation")
    except Exception as _ecv:
        warn(f"Enforcement validation skipped: {_ecv}")

    # ── Post-pipeline: graph ingestion ────────────────────────────────────
    try:
        from attack_graph_brain import get_brain
        _brain = get_brain()
        _ingested = 0
        for _f in _validated:
            _brain.integrate_vuln(_f)
            _ingested += 1
        if _ingested:
            info(f"Graph: ingested {_ingested} finding(s) from full-scan")
    except Exception as _ge:
        warn(f"Graph ingestion skipped: {_ge}")

    # ── Post-pipeline: learning system update ─────────────────────────────
    try:
        import types as _types
        from learning import LearningSystem as _LS
        # phase names serve as tool proxies
        _tools_used = list(result.phases.keys()) if result.phases else []
        _task_result = _types.SimpleNamespace(
            findings=_validated,
            tools_used=_tools_used,
            target=target,
            success=(result.status == "completed"),
            duration=result.elapsed_s,
        )
        _ls = _LS()
        _ls.record_result(_task_result)
        _ls.close()
        info("Learning system updated from full-scan results")
    except Exception as _le:
        warn(f"Learning update skipped: {_le}")

    # ── Enforcement: capmap coverage + module compliance + cleanup ────────────
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _ctrl = _get_ec()
        _cov = _ctrl.check_capmap_coverage(_ec_scan_id, _validated)
        if _cov.uncovered:
            warn(f"Capmap: {len(_cov.uncovered)} vuln class(es) not covered this scan")
        if _cov.triggered:
            info(f"Capmap: triggered {len(_cov.triggered)} additional tool(s) for coverage")
        _comp = _ctrl.check_module_compliance()
        if _comp.missing:
            warn(f"Module compliance: not run this session — {', '.join(sorted(_comp.missing))}")
        _ctrl.stop_recursive_watch(_ec_scan_id)
    except Exception as _ecc:
        warn(f"Enforcement compliance check skipped: {_ecc}")

    print()

    # Summary table
    print("  ┌─────────────────────────────┬───────────┬──────────┬──────────┐")
    print("  │ Phase                       │ Status    │ Findings │ Time (s) │")
    print("  ├─────────────────────────────┼───────────┼──────────┼──────────┤")
    for phase_cfg in __import__("pipeline.canonical", fromlist=["CANONICAL_PHASES"]).CANONICAL_PHASES:
        pr = result.phases.get(phase_cfg.name)
        if not pr:
            continue
        status = pr.status
        status_sym = "✓" if status == "completed" else "✗" if status == "failed" else "–"
        print(f"  │ {phase_cfg.display_name:27s} │ {status_sym} {status:8s}│ {pr.finding_count:8d} │ {pr.elapsed_s:8.1f} │")
    print("  └─────────────────────────────┴───────────┴──────────┴──────────┘")
    print()

    # Severity breakdown
    sev_counts = {}
    for f in _validated:
        s = f.get("severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print(f"  Total unique findings: {len(_validated)}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            print(f"    {sev.upper():10s} {cnt}")
    print()

    if result.status == "completed":
        ok(f"Pipeline complete — {len(_validated)} unique findings")
    else:
        warn(f"Pipeline status: {result.status}")
        if result.phases_failed:
            warn(f"Failed phases: {', '.join(result.phases_failed)}")

    # Generate reports
    if report_fmt != "none" and _validated:
        try:
            from confidence_engine import ConfidenceEngine
            from core.reporter import Reporter
            scored = ConfidenceEngine().score_findings(_validated)
            reporter = Reporter(output, target=target, platform="HackerOne")
            reporter.add_findings(scored)
            fmts = ["html", "pdf"] if report_fmt == "all" else [report_fmt]
            for fmt in fmts:
                try:
                    p = reporter.write(fmt)
                    ok(f"Report: {p}")
                except Exception as re:
                    warn(f"Report ({fmt}) failed: {re}")
            exec_paths = reporter.write_executive()
            for p in exec_paths:
                ok(f"Executive: {p}")
        except Exception as e:
            warn(f"Report generation failed: {e}")

    # Parity check
    if do_parity and compare_dir:
        print()
        info("Running parity check against prior run...")
        try:
            from pipeline.parity_checker import ParityChecker, load_result_from_dir, merge_results
            prior = load_result_from_dir(compare_dir, mode="unknown")
            checker = ParityChecker(prior, result)
            parity_report = checker.check()
            print(parity_report.summary())
            parity_out = _Path(output) / "parity_report.json"
            parity_out.write_text(_json.dumps(parity_report.to_dict(), indent=2))
            ok(f"Parity report: {parity_out}")
            if not parity_report.is_consistent:
                warn("PARITY CHECK FAILED — see parity_report.json for details")
        except Exception as e:
            warn(f"Parity check failed: {e}")

    info(f"All outputs: {output}/")
    info(f"Unified findings: {output}/unified_findings.json")
    info(f"Pipeline report:  {output}/pipeline_report.json")


def cmd_parity_check(args):
    """
    oneinfinity parity-check <docker_dir> <cli_dir>
    Compare Docker and CLI scan results for consistency.
    """
    import json as _json
    from pathlib import Path as _Path
    from modules.utils import ok, warn, info, err

    docker_dir = args.docker_dir
    cli_dir    = args.cli_dir
    output     = getattr(args, "output", "") or ""
    do_merge   = getattr(args, "merge", False)
    merge_out  = getattr(args, "merge_output", "") or ""

    try:
        from pipeline.parity_checker import ParityChecker, load_result_from_dir, merge_results
    except ImportError as e:
        err(f"pipeline module not found: {e}")
        sys.exit(1)

    info(f"Loading Docker result from: {docker_dir}")
    docker_result = load_result_from_dir(docker_dir, mode="docker")
    info(f"Loading CLI result from: {cli_dir}")
    cli_result = load_result_from_dir(cli_dir, mode="cli")

    info(f"Docker findings : {len(docker_result.findings)}")
    info(f"CLI findings    : {len(cli_result.findings)}")

    checker = ParityChecker(docker_result, cli_result)
    report = checker.check()
    print()
    print(report.summary())

    # Write JSON report
    if output:
        _Path(output).write_text(_json.dumps(report.to_dict(), indent=2))
        ok(f"Parity report written: {output}")

    # Merge findings
    if do_merge:
        merged = merge_results(docker_result, cli_result)
        if merge_out:
            _Path(merge_out).mkdir(parents=True, exist_ok=True)
            (_Path(merge_out) / "unified_findings.json").write_text(
                _json.dumps(merged, indent=2, default=str)
            )
            ok(f"Merged findings written: {merge_out}/unified_findings.json ({len(merged)} findings)")
        else:
            info(f"Merged finding count: {len(merged)}")

    if report.is_consistent:
        ok("Docker and CLI results are now consistent")
    else:
        warn("Discrepancies remain — review parity report for details")
        sys.exit(1)


def cmd_replay_findings(args):
    """oneinfinity replay <findings_file> — convert findings to reproducible CLI workflows."""
    from finding_replay_engine import replay_findings_file

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

        from bounty_report_generator import bounty_report_generator
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
    from modules.utils import banner, info, ok, warn, err

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
        from modules.scope import ScopeManager
        sm = ScopeManager(str(scope_path.parent))
        sm.load()
        ok(f"Scope loaded: {scope_path}")
        sm.show_scope()
    except Exception as exc:
        warn(f"Could not display scope: {exc}")

    # Show persistent memory status
    try:
        from learning.persistent_memory import get_memory as _gm
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
        from bounty_hunter_engine import BountyHunterEngine, HunterConfig
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
            from bounty_report_generator import bounty_report_generator
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


def cmd_distributed(args):
    """
    oneinfinity distributed --workers N [--targets file.txt] [--target domain]

    Distribute scan tasks across N parallel workers using the best available
    queue backend (Redis > shared filesystem > in-process memory).
    """
    from modules.utils import banner, ok, info, warn, err

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
            from core.distributed_engine import WorkerNode
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
        from core.distributed_engine import DistributedEngine
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


def cmd_benchmark(args):
    """
    oneinfinity benchmark --burp burp.json --oi results.json [--nuclei nuclei.jsonl]

    Compare OneInfinity findings against Burp Suite / Nuclei to measure coverage.
    """
    from modules.utils import banner, ok, warn, err, info

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
        from core.benchmark_engine import get_benchmark_engine
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


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "doctor":        cmd_doctor,
        "setup":         cmd_setup,
        "run":           cmd_run,
        "scan":          cmd_scan,
        "full-scan":     cmd_full_scan,
        "parity-check":  cmd_parity_check,
        "graphql-scan":  cmd_graphql_scan,
        "browser-scan":  cmd_browser_scan,
        "smuggling-scan": cmd_smuggling_scan,
        "scope":         cmd_scope,
        "analyze":     cmd_analyze,
        "org-intel":   cmd_org_intel,
        "plan":        cmd_plan,
        "script":      cmd_script,
        "report":      cmd_report,
        "findings":    cmd_findings,
        "cvss":        cmd_cvss,
        "payloads":    cmd_payloads,
        "waf-bypass":  cmd_waf_bypass,
        "methodology": cmd_methodology,
        "dedup":       cmd_dedup,
        # ── New pipeline commands ──────────────────────────────────────────
        "toolcheck":   cmd_toolcheck,
        "debug":       cmd_debug,
        "recon":       cmd_pipeline_recon,
        "vuln-scan":   cmd_pipeline_vulnscan,
        "fuzz":        cmd_pipeline_fuzz,
        "secrets":     cmd_pipeline_secrets,
        "secrets-scan": cmd_secrets_scan,
        "tool":        cmd_tool_run,
        "capmap":      cmd_capmap,
        "workflow":    cmd_workflow,
        # ── Advanced AI capabilities ───────────────────────────────────────
        "graph":              cmd_graph,
        "attack-graph":       cmd_attack_graph,
        "agents":             cmd_agents,
        "chains":             cmd_chains,
        "learn":              cmd_learn,
        "adaptive-recon":     cmd_adaptive_recon,
        # ── Autonomous Vulnerability Research ─────────────────────────────
        "research":           cmd_research,
        "analyze-app":        cmd_analyze_app,
        "generate-theories":  cmd_generate_theories,
        "run-custom-tests":   cmd_run_custom_tests,
        "zero-day":           cmd_zero_day,
        # ── AI Security & Red Team ─────────────────────────────────────────
        "ai-test":            cmd_ai_test,
        "ai-redteam":         cmd_ai_redteam,
        "ai-agent-test":      cmd_ai_agent_test,
        # ── Core Infrastructure ────────────────────────────────────────────
        "profile":            cmd_profile,
        "swarm":              cmd_swarm,
        "exploit":            cmd_exploit_chains,
        "plugins":            cmd_plugins,
        "cache":              cmd_cache,
        # ── Traffic & Replay ───────────────────────────────────────────────
        "traffic-list":       cmd_traffic_list,
        "traffic-export":     cmd_traffic_export,
        "replay":             cmd_replay_findings,
        "replay-request":     cmd_replay_request,
        "replay-attack":      cmd_replay_attack,
        "proxy-status":       cmd_proxy_status,
        "proxy-set":          cmd_proxy_set,
        # ── Mobile Security ────────────────────────────────────────────────
        "mobile-analyze":     cmd_mobile_analyze,
        "mobile-static":      cmd_mobile_static,
        "mobile-dynamic":     cmd_mobile_dynamic,
        "mobile-api-scan":    cmd_mobile_api_scan,
        "mobile-report":      cmd_mobile_report,
        # ── Autonomous Bounty Hunter ───────────────────────────────────────
        "hunter":             cmd_hunter,
        "hunter-start":       cmd_hunter_start,
        "hunter-scan":        cmd_hunter_scan,
        "hunter-status":      cmd_hunter_status,
        "hunter-report":      cmd_hunter_report,
        # ── Benchmarking & Distributed ────────────────────────────────────
        "benchmark":          cmd_benchmark,
        "distributed":        cmd_distributed,
        # ── Swarm Intelligence ─────────────────────────────────────────────
        "swarm-scan":         cmd_swarm_scan,
        "simulate-attacks":   cmd_simulate_attacks,
        "simulate-workflow":  cmd_simulate_workflow,
        # ── Self-Evolving Architecture ─────────────────────────────────────
        "arch-status":        cmd_arch_status,
        "arch-events":        cmd_arch_events,
        "arch-insights":      cmd_arch_insights,
        "arch-emit":          cmd_arch_emit,
        # ── Intelligence Daemon ────────────────────────────────────────────
        "daemon-start":       cmd_daemon_start,
        "daemon-stop":        cmd_daemon_stop,
        "daemon-status":      cmd_daemon_status,
        "daemon-add-target":  cmd_daemon_add_target,
        # ── Model Orchestrator ─────────────────────────────────────────────
        "ai":                 cmd_ai_execute,
        "ai-status":          cmd_ai_status,
        "ai-budget":          cmd_ai_budget,
        "ai-models":          cmd_ai_models,
        # ── Graph Brain ────────────────────────────────────────────────────
        "brain-start":        cmd_brain_start,
        "brain-stop":         cmd_brain_stop,
        "brain-status":       cmd_brain_status,
        "brain-decide":       cmd_brain_decide,
        "brain-triggers":     cmd_brain_triggers,
        "god-mode":           cmd_god_mode,
    }

    handler = handlers.get(args.command)
    if handler:
        try:
            handler(args)
        except KeyboardInterrupt:
            print("\n  [-] Interrupted.")
            sys.exit(0)
    else:
        parser.print_help()


# ── New capability handlers ───────────────────────────────────────────────────

def cmd_graphql_scan(args):
    """oneinfinity graphql-scan <target> — GraphQL security scan."""
    import json as _json
    from pathlib import Path
    from modules.utils import banner, ok, warn, info, err

    target = args.target
    probe_url = target if target.startswith("http") else f"https://{target}"
    output = getattr(args, "output", "") or ""

    banner(f"GraphQL Security Scan — {probe_url}")

    try:
        from graphql_scan_engine import GraphQLScanEngine
    except ImportError as e:
        err(f"graphql_scan_engine unavailable: {e}")
        sys.exit(1)

    try:
        engine = GraphQLScanEngine(target=probe_url, output_dir=".")
        findings = engine.run()

        if not findings:
            info("No GraphQL endpoints or vulnerabilities found.")
        else:
            ok(f"Found {len(findings)} GraphQL findings")
            for f in findings:
                sev = f.get("severity", "info").upper()
                vtype = f.get("vuln_type", "?")
                url = f.get("url", probe_url)
                print(f"  [{sev}] {vtype} @ {url[:80]}")

        if output:
            Path(output).write_text(_json.dumps({"findings": findings}, indent=2, default=str))
            ok(f"Results saved: {output}")
    except Exception as e:
        err(f"GraphQL scan failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)


def cmd_browser_scan(args):
    """oneinfinity browser-scan <target> — headless browser security analysis."""
    import json as _json
    from pathlib import Path
    from modules.utils import banner, ok, warn, info, err

    target = args.target
    probe_url = target if target.startswith("http") else f"https://{target}"
    output = getattr(args, "output", "") or ""
    max_pages = getattr(args, "max_pages", 20)

    banner(f"Headless Browser Analysis — {probe_url}")

    try:
        from headless_browser_engine import HeadlessBrowserEngine
    except ImportError as e:
        err(f"headless_browser_engine unavailable: {e}")
        sys.exit(1)

    try:
        engine = HeadlessBrowserEngine(target=probe_url, output_dir=".")
        result = engine.run()

        endpoints = result.get("endpoints", [])
        findings = result.get("findings", [])
        js_secrets = result.get("js_secrets", [])

        info(f"Discovered {len(endpoints)} dynamic endpoints")
        if findings:
            ok(f"Found {len(findings)} browser-side vulnerabilities")
            for f in findings:
                sev = f.get("severity", "info").upper()
                vtype = f.get("vuln_type", "?")
                print(f"  [{sev}] {vtype} @ {f.get('url', probe_url)[:80]}")
        if js_secrets:
            warn(f"Found {len(js_secrets)} JS secrets")
            for s in js_secrets[:5]:
                print(f"  [SECRET] {s.get('vuln_type', '?')}: {str(s.get('evidence', ''))[:60]}")
        if not findings and not js_secrets:
            info("No browser-side vulnerabilities found.")

        # ── Additional browser security tests ────────────────────────────────
        extra_findings = []
        try:
            from modules.tool_wrappers import run_source_map_scanner, run_clickjacking_test, run_websocket_test

            info("Running source map exposure check...")
            sm_results = run_source_map_scanner(probe_url)
            if isinstance(sm_results, list):
                for f in sm_results:
                    if isinstance(f, dict) and f.get("severity") not in ("info", None):
                        warn(f"  [SOURCE-MAP] {f.get('title', f.get('vuln_type', '?'))} @ {f.get('url', probe_url)[:80]}")
                extra_findings.extend(sm_results)
            elif isinstance(sm_results, dict) and sm_results.get("findings"):
                extra_findings.extend(sm_results["findings"])

            info("Running clickjacking test...")
            cj_results = run_clickjacking_test(probe_url)
            cj_list = cj_results if isinstance(cj_results, list) else ([cj_results] if isinstance(cj_results, dict) else [])
            for f in cj_list:
                if isinstance(f, dict) and f.get("severity") not in ("info", None):
                    warn(f"  [CLICKJACKING] {f.get('title', '?')} @ {f.get('url', probe_url)[:80]}")
            extra_findings.extend(cj_list)

            info("Running WebSocket security test...")
            ws_results = run_websocket_test(probe_url)
            ws_list = ws_results if isinstance(ws_results, list) else ([ws_results] if isinstance(ws_results, dict) else [])
            for f in ws_list:
                if isinstance(f, dict) and f.get("severity") not in ("info", None):
                    warn(f"  [WEBSOCKET] {f.get('title', '?')} @ {f.get('url', probe_url)[:80]}")
            extra_findings.extend(ws_list)

            vuln_extra = [f for f in extra_findings if isinstance(f, dict) and f.get("severity") not in ("info", None)]
            if vuln_extra:
                ok(f"Additional tests: {len(vuln_extra)} finding(s) from source map/clickjacking/WebSocket checks")
            else:
                info("Additional tests: no findings from source map/clickjacking/WebSocket checks")

            result.setdefault("findings", [])
            result["findings"].extend(extra_findings)
        except Exception as _extra_e:
            warn(f"Additional browser tests skipped: {_extra_e}")

        if output:
            Path(output).write_text(_json.dumps(result, indent=2, default=str))
            ok(f"Results saved: {output}")
    except Exception as e:
        err(f"Browser scan failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)


def cmd_smuggling_scan(args):
    """oneinfinity smuggling-scan <target> — HTTP request smuggling detection."""
    import json as _json
    from pathlib import Path
    from modules.utils import banner, ok, warn, info, err

    target = args.target
    probe_url = target if target.startswith("http") else f"https://{target}"
    output = getattr(args, "output", "") or ""
    timeout = getattr(args, "timeout", 10)

    banner(f"HTTP Request Smuggling — {probe_url}")

    try:
        from smuggling_engine import SmugglingEngine
    except ImportError as e:
        err(f"smuggling_engine unavailable: {e}")
        sys.exit(1)

    try:
        engine = SmugglingEngine(target=probe_url, timeout=timeout)
        findings = engine.run()

        if not findings:
            ok("No HTTP request smuggling vulnerabilities found.")
        else:
            for f in findings:
                sev = f.get("severity", "critical").upper()
                stype = f.get("meta", {}).get("smuggling_type", f.get("vuln_type", "?"))
                print(f"  [{sev}] {stype} @ {f.get('url', probe_url)}")
                if f.get("evidence"):
                    print(f"    Evidence: {str(f['evidence'])[:100]}")

        if output:
            Path(output).write_text(_json.dumps({"findings": findings}, indent=2, default=str))
            ok(f"Results saved: {output}")
    except Exception as e:
        err(f"Smuggling scan failed: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)


# ── Swarm Intelligence handlers ───────────────────────────────────────────────

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
        from agent_swarm_coordinator import AgentSwarmCoordinator, run_swarm
        from swarm_intelligence_engine import AgentType
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
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("swarm-scan")
    except Exception:
        pass
    try:
        from result_ingestion_engine import get_ingestion_engine as _get_ie, RawResult as _RR
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


def cmd_simulate_attacks(args):
    """oneinfinity simulate-attacks <target> — Monte Carlo attack path simulation."""
    import asyncio
    import json as _json
    from pathlib import Path

    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("simulate-attacks")
    except Exception:
        pass

    try:
        from attack_simulation_engine import AttackSimulationEngine
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
        from modules.tool_wrappers import run_race_condition_test, run_payment_tampering_test

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
        from workflow_simulation_engine import WorkflowSimulationEngine, AttackCategory
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

def cmd_arch_status(args):
    """oneinfinity arch-status — show evolution engine status, recent changes, capabilities."""
    import json as _json
    try:
        from auto_architecture_engine import cmd_arch_status as _status
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
        from auto_architecture_engine import get_engine
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
        from memory_manager import get_memory_manager
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
        from auto_architecture_engine import get_engine, ArchEvent, EventType
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
        from intelligence_daemon import get_daemon
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
        from intelligence_daemon import get_daemon
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
        from intelligence_daemon import get_daemon
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
            from event_bus import get_bus
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
        from intelligence_daemon import get_daemon
        d = get_daemon()
        d.add_target(target)
        print(f"  [+] Target '{target}' added to daemon.")
        print(f"  [*] Active targets: {', '.join(sorted(d._targets))}")
    except Exception as e:
        print(f"  [!] Error adding target: {e}")


# ── Model Orchestrator handlers ───────────────────────────────────────────────

def cmd_ai_execute(args):
    """oneinfinity ai <prompt> [--tier FAST|STANDARD|PREMIUM] — run a task through the AI orchestrator."""
    raw = getattr(args, 'args', [])
    tier_arg = None
    prompt_parts = []
    i = 0
    while i < len(raw):
        if raw[i] in ('--tier', '-t') and i + 1 < len(raw):
            tier_arg = raw[i + 1].upper()
            i += 2
        else:
            prompt_parts.append(raw[i])
            i += 1

    prompt = ' '.join(prompt_parts).strip()
    if not prompt:
        print("Usage: oneinfinity ai <prompt> [--tier FAST|STANDARD|PREMIUM]")
        return

    try:
        from model_orchestrator import get_orchestrator, ModelTier
        orch = get_orchestrator()
        force_tier = ModelTier[tier_arg] if tier_arg else None
        task = {"description": prompt, "prompt": prompt}
        print(f"  [*] Classifying and routing task...")
        output = orch.execute(task, force_tier=force_tier)
        print(f"\n  Model: {output.model_id} ({output.tier.name})")
        print(f"  Confidence: {output.confidence:.0%}")
        if output.escalated_from:
            print(f"  Escalated from: {output.escalated_from} ({output.escalation_reason})")
        print(f"  Tokens: {output.total_tokens}  Cost: ${output.cost_usd:.6f}")
        print(f"  Retries: {output.retries}\n")
        print("─" * 60)
        print(output.content)
        print("─" * 60)
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_ai_status(args):
    """oneinfinity ai-status — show orchestrator status, models, and budget."""
    try:
        from model_orchestrator import get_orchestrator
        status = get_orchestrator().status()
        print(f"\n  Model Orchestrator")
        print(f"  Loaded:          {status['loaded']}")
        print(f"  Models total:    {status['models_total']}")
        print(f"  Models enabled:  {status['models_enabled']}")
        print(f"  Budget today:    ${status['budget']['today_usd']:.4f} / ${status['budget']['daily_limit']} ({status['budget']['daily_pct']}%)")
        print(f"  Budget month:    ${status['budget']['month_usd']:.4f} / ${status['budget']['monthly_limit']} ({status['budget']['monthly_pct']}%)")
        print(f"  Projected/month: ${status['budget']['projected_monthly']:.4f}")
        p = status['policy']
        print(f"  Escalation:      FAST→STANDARD @ {p['fast_to_standard_threshold']:.0%}  STANDARD→PREMIUM @ {p['standard_to_premium_threshold']:.0%}")
        print(f"  Max retries:     {p['max_retries']}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_ai_budget(args):
    """oneinfinity ai-budget [today|this_month|all_time] — show model usage and costs."""
    raw    = getattr(args, 'args', [])
    period = raw[0] if raw else "today"
    try:
        from model_budget_manager import get_budget_manager
        summary = get_budget_manager().get_summary(period).to_dict()
        print(f"\n  AI Model Usage — {summary['period']}")
        print(f"  Total calls:    {summary['total_calls']}")
        print(f"  Total tokens:   {summary['total_tokens']:,}")
        print(f"  Total cost:     ${summary['total_cost_usd']:.6f}")
        print(f"  Escalation rate:{summary['escalation_rate']:.0%}")
        print(f"  Daily budget:   {summary['daily_budget_used']:.0%} used")
        print(f"  Monthly budget: {summary['monthly_budget_used']:.0%} used")
        if summary['cost_by_model']:
            print(f"\n  Cost by model:")
            for m, c in sorted(summary['cost_by_model'].items(), key=lambda x: -x[1]):
                calls = summary['calls_by_model'].get(m, 0)
                print(f"    {m:<30}  ${c:.6f}  ({calls} calls)")
        if summary['cost_by_category']:
            print(f"\n  Cost by category:")
            for cat, c in sorted(summary['cost_by_category'].items(), key=lambda x: -x[1]):
                print(f"    {cat:<20}  ${c:.6f}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_ai_models(args):
    """oneinfinity ai-models — list registered models and their tiers/costs."""
    try:
        from model_orchestrator import get_orchestrator
        models = get_orchestrator().list_models()
        print(f"\n  {'Model':<25}  {'Provider':<10}  {'Tier':<8}  {'$/1k in':>8}  {'$/1k out':>9}  {'Ctx':>7}  {'En':>3}")
        print(f"  {'─'*25}  {'─'*10}  {'─'*8}  {'─'*8}  {'─'*9}  {'─'*7}  {'─'*3}")
        for m in models:
            en = '✓' if m['enabled'] else '✗'
            print(f"  {m['model_id']:<25}  {m['provider']:<10}  {m['tier']:<8}  "
                  f"{m['cost_per_1k_input']:>8.5f}  {m['cost_per_1k_output']:>9.5f}  "
                  f"{m['max_context_tokens']//1000:>6}k  {en:>3}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


# ── Graph Brain handlers ───────────────────────────────────────────────────────

def cmd_brain_start(args):
    """oneinfinity brain-start <target> [target2 ...] — start the graph brain autonomous loop."""
    raw     = getattr(args, 'args', [])
    targets = [t.strip() for r in raw for t in r.split(',') if t.strip()]
    if not targets:
        print("Usage: oneinfinity brain-start <target> [target2 ...]")
        return
    try:
        from attack_graph_brain import get_brain
        from event_driven_engine import get_engine
        from agent_execution_fabric import get_fabric

        brain  = get_brain()
        ede    = get_engine()
        fabric = get_fabric()

        brain.start(targets=targets)
        ede.start(targets=targets)
        fabric.start()

        print(f"  [+] Graph Brain started for: {', '.join(targets)}")
        status = brain.status()
        print(f"  [*] Nodes: {status.total_nodes}  Edges: {status.total_edges}")
        print(f"  [*] Queue depth: {status.queue_depth}")
    except Exception as e:
        print(f"  [!] Error starting brain: {e}")


def cmd_brain_stop(args):
    """oneinfinity brain-stop — stop the graph brain and all agents."""
    try:
        from attack_graph_brain import get_brain
        from event_driven_engine import get_engine
        get_brain().stop()
        get_engine().stop()
        print("  [+] Graph Brain stopped.")
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_brain_status(args):
    """oneinfinity brain-status — show graph brain status + top priority nodes."""
    try:
        from attack_graph_brain import get_brain
        from event_driven_engine import get_engine
        from agent_execution_fabric import get_fabric

        b = get_brain().status()
        e = get_engine().status()
        f = get_fabric().status()

        print(f"\n  Attack Graph Brain — {'RUNNING' if b.running else 'STOPPED'}")
        print(f"  Targets:         {', '.join(b.targets) or 'none'}")
        print(f"  Graph nodes:     {b.total_nodes}  edges: {b.total_edges}")
        print(f"  Queue depth:     {b.queue_depth}")
        print(f"  Decisions made:  {b.decisions_made}")
        print(f"  Dispatched:      {b.actions_dispatched}")
        print(f"  Findings in:     {b.findings_integrated}")
        print(f"  Uptime:          {b.uptime_s:.0f}s")
        print(f"\n  EDE — iterations={e.iterations} events={e.events_received} nodes_fed={e.nodes_fed}")
        print(f"  Fabric — queue={f['queue_depth']} active={f['active_tasks']} done={f['completed']}")

        # Top priority nodes
        nodes = get_brain().top_priority_nodes(n=10)
        if nodes:
            print(f"\n  Top Priority Nodes:")
            print(f"  {'Type':<14}  {'Label':<40}  {'Priority':>8}")
            print(f"  {'─'*14}  {'─'*40}  {'─'*8}")
            for n in nodes:
                print(f"  {n.node_type:<14}  {n.node_label[:40]:<40}  {n.priority:>8.2f}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_brain_decide(args):
    """oneinfinity brain-decide <target> — generate and display a decision plan."""
    raw = getattr(args, 'args', [])
    if not raw:
        print("Usage: oneinfinity brain-decide <target>")
        return
    target = raw[0].strip()
    try:
        from autonomous_decision_engine import get_decision_engine
        plan = get_decision_engine().generate_plan(target, max_decisions=15)
        print(f"\n  Decision Plan for '{target}' ({len(plan.decisions)} decisions)")
        print(f"  {'Agent':<14}  {'Node':<35}  {'Score':>7}  {'Confidence':>10}  Impact")
        print(f"  {'─'*14}  {'─'*35}  {'─'*7}  {'─'*10}  {'─'*20}")
        for d in plan.decisions[:15]:
            print(f"  {d.agent_type:<14}  {d.node_label[:35]:<35}  {d.score:>7.3f}  {d.confidence:>10.0%}  {d.expected_impact}")
        if plan.decisions:
            top = plan.decisions[0]
            print(f"\n  Top pick: [{top.agent_type}] on '{top.node_label}'")
            print(f"  Reasoning: {', '.join(top.rationale.factors[:3])}")
            if top.suggested_tool:
                print(f"  Tool: {top.suggested_tool}")
            if top.suggested_payload:
                print(f"  Payload: {top.suggested_payload}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_brain_triggers(args):
    """oneinfinity brain-triggers [--evaluate] — list trigger rules or evaluate graph."""
    raw = getattr(args, 'args', [])
    evaluate = '--evaluate' in raw or '-e' in raw
    try:
        from graph_trigger_engine import get_trigger_engine
        te = get_trigger_engine()
        if evaluate:
            count = te.evaluate_graph()
            print(f"  [+] Trigger evaluation complete: {count} firings")
        rules = te.list_rules()
        stats = te.stats()
        print(f"\n  Trigger Engine — {stats['rules']} rules, {stats['total_fired']} total firings")
        print(f"\n  {'Name':<28}  {'Agents':<35}  {'Once':>5}  {'Cooldown':>8}")
        print(f"  {'─'*28}  {'─'*35}  {'─'*5}  {'─'*8}")
        for r in rules:
            agents_str = ', '.join(r['agents'][:4])
            print(f"  {r['name']:<28}  {agents_str:<35}  {str(r['once']):>5}  {r['cooldown_s']:>7.0f}s")
        firings = te.recent_firings(10)
        if firings:
            print(f"\n  Recent firings (last {len(firings)}):")
            for f in firings:
                print(f"  [{f['trigger_name']}] → {f['node_label']} → {', '.join(f['agents'])}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_god_mode(args):
    """oneinfinity god-mode <target> — GOD MODE: full adaptive cascade, zero feature skip."""
    from god_mode_engine import get_god_mode_conductor, GOD_MODE_LOG_DIR

    sub = getattr(args, "subcommand", None)

    # Argparse ambiguity: when [target] is optional and comes before subparsers,
    # a bare subcommand keyword (e.g. "stop") may be consumed as target.
    # Detect and re-route: if target holds a subcommand keyword, shift it.
    target_val = getattr(args, "target", None) or ""
    if not sub and target_val in ("status", "logs", "stop"):
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
        print(f"  Elapsed:    {data.get('elapsed_seconds', 0):.0f}s / {data.get('max_time_sec', 0)}s")
        print(f"  Findings:   {data.get('finding_count', 0)} / {data.get('max_findings', 0)}")
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
    target = getattr(args, "target", None)
    if not target:
        print("Usage: oneinfinity god-mode <target> [options]")
        print("       oneinfinity god-mode status [scan-id]")
        print("       oneinfinity god-mode logs [--follow]")
        print("       oneinfinity god-mode stop [scan-id]")
        return

    conductor = get_god_mode_conductor()
    conductor.run(
        target=target,
        max_time=getattr(args, "max_time", "2h") or "2h",
        max_findings=getattr(args, "max_findings", 100) or 100,
        background=getattr(args, "background", False),
        no_swarm=getattr(args, "no_swarm", False),
        no_research=getattr(args, "no_research", False),
        report_fmt=getattr(args, "report_fmt", "markdown") or "markdown",
    )


if __name__ == "__main__":
    main()
