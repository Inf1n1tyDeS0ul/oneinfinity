#!/usr/bin/env python3
"""
oneinfinity — AI-Powered Offensive Security Research Framework : One&Infinity
===========================================================================
An autonomous AI-driven platform for offensive security research, bug bounty automation,
mobile security testing, AI security testing, and attack graph-driven vulnerability discovery.

Bug bounty mode:
  oneinfinity setup <program-name>
  oneinfinity setup <program-name> --pentest --target <domain> [--target <domain> ...]

Autonomous framework (runs all phases):
  oneinfinity run <target> [options]

Pentest scan (generates recon script -- YOU run it):
  oneinfinity scan <target> [<target> ...]

Other commands:
  oneinfinity scope
  oneinfinity analyze subdomains <file>
  oneinfinity plan
  oneinfinity report [--finding <id>]
  oneinfinity findings [<severity>]
  oneinfinity cvss
  oneinfinity payloads
  oneinfinity dedup <title>

For the full command list: oneinfinity --help
"""
from __future__ import annotations
import sys
import os
import argparse
from pathlib import Path
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from oneinfinity.path_manager import findings_db_path, raw_dir, resolve_output_dir, workspace_root
from oneinfinity.cli._helpers import (
    CLI_COMMAND, WORKSPACE_DIRNAME, LEGACY_WORKSPACE_DIRNAME,
    get_workspace_root, find_program_dir, get_program_dir,
)

# Import domain command modules
from oneinfinity.cli.commands import core
from oneinfinity.cli.commands import analysis
from oneinfinity.cli.commands import findings
from oneinfinity.cli.commands import pipeline
from oneinfinity.cli.commands import agents
from oneinfinity.cli.commands import graph
from oneinfinity.cli.commands import swarm
from oneinfinity.cli.commands import mobile
from oneinfinity.cli.commands import traffic
from oneinfinity.cli.commands import ai
from oneinfinity.cli.commands import hunter
from oneinfinity.cli.commands import daemon
from oneinfinity.cli.commands import chains
from oneinfinity.cli.commands import research
from oneinfinity.cli.commands import misc
from oneinfinity.cli.commands import internal


# ── Argument parser (will be refactored to register() calls in a follow-up) ──
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
    pl2sub.add_parser("backfill", help="Backfill Neo4j learning graph from existing PG findings (idempotent)")

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
        "_internal_register": cmd__internal_register,
        "_internal_deep_recon": cmd__internal_deep_recon,
        "_internal_auth_session": cmd__internal_auth_session,
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


if __name__ == '__main__':
    main()
