"""
CLI command handlers for pipeline domain.
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

def cmd_pipeline_recon(args):
    """
    oneinfinity recon <domain> — full automated recon pipeline.
    Chains: subdomain enum → HTTP probe → crawl → content discovery
    """
    from oneinfinity.modules.utils import banner, warn, err
    from oneinfinity.modules.pipeline import Pipeline

    target = args.domain
    output_dir = resolve_output_dir(args.output, target)

    banner(f"Recon Pipeline — {target}")
    warn("Ensure you have authorization to test this target.")

    # WAF detection before recon
    try:
        from oneinfinity.waf_detection_engine import WAFDetectionEngine
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
    from oneinfinity.modules.utils import banner, warn
    from oneinfinity.modules.pipeline import Pipeline
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
        from oneinfinity.waf_detection_engine import WAFDetectionEngine
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
    from oneinfinity.modules.utils import banner, section, ok, warn, err
    from oneinfinity.modules.tool_wrappers import ToolRegistry, is_available

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
    from oneinfinity.modules.utils import banner, ok, info, warn, err, table, sev
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

        from oneinfinity.agents.secret_intel import SecretIntelAgent
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
    from oneinfinity.modules.utils import banner, section, ok, warn
    from oneinfinity.modules.tool_wrappers import ToolRegistry, is_available

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


def cmd_parity_check(args):
    """
    oneinfinity parity-check <docker_dir> <cli_dir>
    Compare Docker and CLI scan results for consistency.
    """
    import json as _json
    from pathlib import Path as _Path
    from oneinfinity.modules.utils import ok, warn, info, err

    docker_dir = args.docker_dir
    cli_dir    = args.cli_dir
    output     = getattr(args, "output", "") or ""
    do_merge   = getattr(args, "merge", False)
    merge_out  = getattr(args, "merge_output", "") or ""

    try:
        from oneinfinity.pipeline.parity_checker import ParityChecker, load_result_from_dir, merge_results
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


def cmd_full_scan(args):
    """
    oneinfinity full-scan <target> — canonical 10-phase pipeline.

    Runs the SAME 10 phases in both Docker and CLI environments.
    Guaranteed parity: Docker exec and CLI produce identical results.
    """
    import json as _json
    from pathlib import Path as _Path
    from oneinfinity.modules.utils import banner, info, ok, warn, err

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
        from oneinfinity.pipeline.canonical import CANONICAL_PHASES as _CP
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
            from oneinfinity.waf_detection_engine import WAFDetectionEngine
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
        from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("full-scan")
        _get_ec().start_recursive_watch(_ec_scan_id, target)
    except Exception as _ecw:
        warn(f"Enforcement watch setup skipped: {_ecw}")

    # Run canonical pipeline
    try:
        from oneinfinity.pipeline.executor import run_canonical_pipeline
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
        from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
        _validated = _get_ec().validate_findings(result.findings)
        info(f"Enforcement: {len(_validated)}/{len(result.findings)} finding(s) passed validation")
    except Exception as _ecv:
        warn(f"Enforcement validation skipped: {_ecv}")

    # ── Post-pipeline: graph ingestion ────────────────────────────────────
    try:
        from oneinfinity.attack_graph_brain import get_brain
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
        from oneinfinity.learning import LearningSystem as _LS
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
        from oneinfinity.enforcement_controller import get_enforcement_controller as _get_ec
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
            from oneinfinity.confidence_engine import ConfidenceEngine
            from oneinfinity.core.reporter import Reporter
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
            from oneinfinity.pipeline.parity_checker import ParityChecker, load_result_from_dir, merge_results
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


def cmd_graphql_scan(args):
    """oneinfinity graphql-scan <target> — GraphQL security scan."""
    import json as _json
    from pathlib import Path
    from oneinfinity.modules.utils import banner, ok, warn, info, err

    target = args.target
    probe_url = target if target.startswith("http") else f"https://{target}"
    output = getattr(args, "output", "") or ""

    banner(f"GraphQL Security Scan — {probe_url}")

    try:
        from oneinfinity.graphql_scan_engine import GraphQLScanEngine
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
    from oneinfinity.modules.utils import banner, ok, warn, info, err

    target = args.target
    probe_url = target if target.startswith("http") else f"https://{target}"
    output = getattr(args, "output", "") or ""
    max_pages = getattr(args, "max_pages", 20)

    banner(f"Headless Browser Analysis — {probe_url}")

    try:
        from oneinfinity.headless_browser_engine import HeadlessBrowserEngine
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
            from oneinfinity.modules.tool_wrappers import run_source_map_scanner, run_clickjacking_test, run_websocket_test

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
    from oneinfinity.modules.utils import banner, ok, warn, info, err

    target = args.target
    probe_url = target if target.startswith("http") else f"https://{target}"
    output = getattr(args, "output", "") or ""
    timeout = getattr(args, "timeout", 10)

    banner(f"HTTP Request Smuggling — {probe_url}")

    try:
        from oneinfinity.smuggling_engine import SmugglingEngine
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




def register(subparsers):
    """Register pipeline commands with the CLI argument parser."""
    sub = subparsers
    pr = sub.add_parser("recon", help="Full recon pipeline: subdomains → HTTP probe → crawl → content")
    pr.add_argument("domain", help="Target domain")
    pr.add_argument("--output", "-o", metavar="DIR", help="Output directory (default: ~/.oneinfinity/raw/<domain>)")
    pr.add_argument("--rate", type=int, metavar="N", help="Requests per minute (default: 30)")
    pr.add_argument("--no-ports",   dest="no_ports",   action="store_true", help="Skip port scanning")
    pr.add_argument("--no-crawl",   dest="no_crawl",   action="store_true", help="Skip web crawling")
    pr.add_argument("--no-content", dest="no_content", action="store_true", help="Skip content discovery")

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

    pf = sub.add_parser("fuzz", help="Directory/content fuzzing pipeline: ffuf + gobuster + dirsearch")
    pf.add_argument("domain", help="Target domain or URL")
    pf.add_argument("--output", "-o", metavar="DIR", help="Output directory")
    pf.add_argument("--extensions", "-e", metavar="EXT", help="File extensions (default: php,asp,aspx,html,js)")
    pf.add_argument("--threads", "-t", type=int, metavar="N", help="Threads (default: 40)")

    ps = sub.add_parser("secrets", help="Secrets discovery: trufflehog + gitleaks")
    ps.add_argument("target", help="Target: filesystem path, git URL, or github.com/org/repo")
    ps.add_argument("--type", choices=["filesystem", "git", "github", "s3", "gcs", "docker"],
                    help="Scan type (auto-detected if omitted)")

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

    gql = sub.add_parser("graphql-scan",
        help="GraphQL security scan: introspection, fuzzing, mutations, IDOR")
    gql.add_argument("target", help="Target URL or domain")
    gql.add_argument("--output", "-o", default="", metavar="FILE",
                     help="Write findings JSON to this file")
    gql.add_argument("--endpoints", nargs="+", default=[],
                     help="GraphQL endpoint paths to test (default: auto-detect)")

    brs = sub.add_parser("browser-scan",
        help="Headless browser analysis: DOM XSS, JS secrets, dynamic endpoints")
    brs.add_argument("target", help="Target URL or domain")
    brs.add_argument("--output", "-o", default="", metavar="FILE",
                     help="Write findings JSON to this file")
    brs.add_argument("--max-pages", type=int, default=20,
                     help="Maximum pages to crawl (default: 20)")

    smg = sub.add_parser("smuggling-scan",
        help="HTTP request smuggling detection (CL.TE, TE.CL, TE.TE)")
    smg.add_argument("target", help="Target URL or domain")
    smg.add_argument("--output", "-o", default="", metavar="FILE",
                     help="Write findings JSON to this file")
    smg.add_argument("--timeout", type=int, default=10,
                     help="Socket timeout per probe in seconds (default: 10)")


