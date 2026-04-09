"""
CLI command handlers for chains domain.
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

def cmd_chains(args):
    """
    oneinfinity chains <target> — detect exploit chains from confirmed findings.
    """
    from oneinfinity.modules.utils import banner, section, ok, warn, info
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

    from oneinfinity.attack.exploit_chain_engine import ExploitChainEngine
    from oneinfinity.attack.poc_generator import PoCGenerator as PocGenerator

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
        from oneinfinity.attack.chain_patterns import CHAIN_PATTERNS
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
    from oneinfinity.attack.exploit_chain_engine import ExploitChainEngine

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
            from oneinfinity.core.reporter import Reporter
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




def register(subparsers):
    """Register chains commands with the CLI argument parser."""
    sub = subparsers
    pc = sub.add_parser("chains", help="Detect exploit chains from confirmed findings")
    pc.add_argument("target", help="Target domain")
    pc.add_argument("--output", "-o", metavar="DIR",
                    help="Output directory (default: ~/.oneinfinity/raw/<target>)")
    pc.add_argument("--no-poc", dest="no_poc", action="store_true",
                    help="Skip PoC script generation")

    exploit_cmd = sub.add_parser("exploit",
        help="Run exploit chain detection on existing raw scan data")
    exploit_cmd.add_argument("domain", help="Target domain (must have existing recon data)")
    exploit_cmd.add_argument("--yes", "-y", action="store_true")
    exploit_cmd.add_argument("--output", "-o", metavar="DIR")
    exploit_cmd.add_argument("--report", choices=["markdown", "json", "html", "all"],
                             default="all", help="Report format(s)")


