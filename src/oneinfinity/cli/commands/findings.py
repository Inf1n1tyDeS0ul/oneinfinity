"""
CLI command handlers for findings domain.
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
from oneinfinity.infra.path_manager import findings_db_path, raw_dir, resolve_output_dir, workspace_root

log = logging.getLogger(__name__)

def cmd_findings(args):
    d = get_program_dir()
    from oneinfinity.modules.findings import FindingsDB
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
            from oneinfinity.modules.utils import err
            err(f"Unknown format: {fmt}. Use json | csv | md")

    db.close()


def cmd_report(args):
    d = get_program_dir()
    reports_dir = str(d / "reports")

    from oneinfinity.modules.scope import ScopeManager
    sm = ScopeManager(str(d))
    sm.load()
    platform = sm.platform or "HackerOne"

    from oneinfinity.modules.reporter import ReportGenerator
    gen = ReportGenerator(reports_dir=reports_dir, platform=platform)

    if args.chain:
        # Chain analysis
        fid1, fid2 = args.chain
        from oneinfinity.modules.findings import FindingsDB
        db = FindingsDB(str(findings_db_path()))
        f1 = db.get(fid1)
        f2 = db.get(fid2)
        db.close()
        if not f1 or not f2:
            from oneinfinity.modules.utils import err
            err(f"Finding #{fid1 if not f1 else fid2} not found.")
            sys.exit(1)
        gen.chain_analysis(f1, f2)
        return

    if getattr(args, "all_findings", False):
        from oneinfinity.modules.findings import FindingsDB
        from oneinfinity.modules.utils import ok, info, banner, warn
        from oneinfinity.bounty.bounty_report_generator import BountyReportGenerator
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
        from oneinfinity.modules.findings import FindingsDB
        db = FindingsDB(str(findings_db_path()))
        finding = db.get(args.finding)
        db.close()
        if not finding:
            from oneinfinity.modules.utils import err
            err(f"Finding #{args.finding} not found.")
            sys.exit(1)
        gen.from_finding(finding)
    else:
        gen.interactive()


def cmd_cvss(args):
    from oneinfinity.modules.cvss import CVSSCalculator
    calc = CVSSCalculator()

    if args.vector:
        calc.from_vector(args.vector)
    elif args.description:
        calc.from_description(args.description)
    else:
        calc.interactive()


def cmd_payloads(args):
    from oneinfinity.modules.payloads import PayloadKB
    kb = PayloadKB()

    if not args.vuln_type:
        kb.list_types()
    else:
        kb.get(args.vuln_type, args.context)


def cmd_waf_bypass(args):
    from oneinfinity.modules.payloads import PayloadKB
    kb = PayloadKB()
    kb.waf_bypass(args.waf, args.vuln_type)


def cmd_methodology(args):
    from oneinfinity.modules.utils import banner, section, bold, info, warn

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
        from oneinfinity.modules.utils import warn
        warn(f"No methodology for '{vuln}'")
        info(f"Available: {', '.join(METHODOLOGIES.keys())}")
        return

    banner(f"Testing Methodology — {args.vuln_class.upper()}")
    for step in METHODOLOGIES[vuln]:
        print(f"  {step}")
    print()




def register(subparsers):
    """Register findings commands with the CLI argument parser."""
    sub = subparsers
    f = sub.add_parser("findings", help="Manage findings database")
    fsub = f.add_subparsers(dest="subcommand")
    fl = fsub.add_parser("list");   fl.add_argument("severity", nargs="?")
    fsub.add_parser("log")
    fsh = fsub.add_parser("show");  fsh.add_argument("id")
    fu = fsub.add_parser("update"); fu.add_argument("id"); fu.add_argument("field"); fu.add_argument("value")
    fsub.add_parser("stats")
    fex = fsub.add_parser("export"); fex.add_argument("format", nargs="?", default="json",
                                                       choices=["json","csv","md"])

    r = sub.add_parser("report", help="Generate bug bounty reports")
    r.add_argument("--finding", "-f", metavar="ID", help="Generate from findings DB entry")
    r.add_argument("--chain", nargs=2, metavar="ID", help="Chain analysis between two findings")
    r.add_argument("--all", dest="all_findings", action="store_true",
                   help="Batch-generate reports for all findings (non-interactive)")

    cv = sub.add_parser("cvss", help="CVSS 3.1 calculator")
    cv.add_argument("vector", nargs="?", help="CVSS vector string to parse")
    cv.add_argument("--describe", dest="description", metavar="TEXT",
                    help="Describe vulnerability for heuristic scoring")

    pl = sub.add_parser("payloads", help="Context-aware payload library")
    pl.add_argument("vuln_type", nargs="?", help="Vulnerability type")
    pl.add_argument("context",   nargs="?", help="Context (html-body, attribute, etc.)")

    wb = sub.add_parser("waf-bypass", help="WAF-specific bypass payloads")
    wb.add_argument("waf",      help="WAF name (Cloudflare|ModSecurity|AWS WAF|Akamai)")
    wb.add_argument("vuln_type",help="Vulnerability type (xss|sqli)")

    m = sub.add_parser("methodology", help="Step-by-step testing methodology")
    m.add_argument("vuln_class", help="sqli|idor|xss|ssrf|cors|jwt|auth")


