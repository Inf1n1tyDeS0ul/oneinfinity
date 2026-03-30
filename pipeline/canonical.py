"""
pipeline/canonical.py — The ONE canonical scan pipeline for OneInfinity.

This is the authoritative definition of what a full scan must do.
BOTH Docker worker execution AND CLI execution must follow this pipeline exactly.
Any deviation is a bug.

Core phase summary (mandatory unless explicitly marked optional or skipped due to WAF passive mode):
  1.  target_registration   — Normalize URL, scope, and session metadata
  2.  deep_recon            — Subdomains, ports, crawl, endpoints, JS analysis
  3.  vuln_scan             — Nuclei full-template sweep + targeted scanners
  4.  active_testing        — Payload-based testing (SQLi, XSS, SSRF, IDOR, CORS, JWT)
  5.  auth_session          — Authentication detection, credential testing, session reuse
  6.  business_logic        — Workflow simulation + real-request logic flaws
  7.  exploit_validation    — Safe PoC execution (HTTP-only, non-destructive)
  8.  exploit_chains        — Chain detection across confirmed findings
  9.  attack_graph          — Build attack graph from all findings
  10. ai_theory             — AI-generated hypothesis findings (tagged separately)

Optional extension phases:
  11. graphql_scan          — GraphQL endpoint discovery + security testing
  12. browser_analysis      — Headless browser DOM/JS analysis
  13. smuggling_test        — HTTP request smuggling detection
  14. oob_check             — Poll OOB service for interactions

Each phase:
  - Has a mandatory flag (explicit skip → FAIL for mandatory phases)
  - Has a CLI command equivalent
  - Has a Docker exec equivalent
  - Has a timeout
  - Produces normalized findings written to a known output file
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class PhaseConfig:
    """Static configuration for one pipeline phase."""
    name: str                        # Internal identifier
    display_name: str                # Human-readable label
    description: str                 # What this phase does
    cli_command: str                 # oneinfinity.py <cli_command> <target>
    cli_extra_args: List[str]        # Additional CLI args (not target)
    output_file: str                 # Relative path under output_dir/
    mandatory: bool                  # If True, skipping this phase → FAIL
    timeout_s: int                   # Per-phase timeout in seconds
    pct_complete: int                # Progress % when done
    waf_adapt: bool                  # Honour WAF rate/jitter settings
    source_type: str                 # "tool" | "simulated" | "ai_theory"
    skip_on_waf_passive: bool        # Skip active payloads if WAF blocks


@dataclass
class CanonicalPhase:
    """Live state of one phase during an execution."""
    config: PhaseConfig
    status: str = "pending"          # pending | running | completed | failed | skipped
    started_at: float = 0.0
    ended_at: float = 0.0
    finding_count: int = 0
    error: str = ""
    meta: Dict = field(default_factory=dict)

    @property
    def elapsed_s(self) -> float:
        if self.started_at and self.ended_at:
            return round(self.ended_at - self.started_at, 2)
        return 0.0


# ---------------------------------------------------------------------------
# THE canonical phase list — order is law
# ---------------------------------------------------------------------------

CANONICAL_PHASES: List[PhaseConfig] = [
    PhaseConfig(
        name="target_registration",
        display_name="Target Registration",
        description="Normalize target URL, detect scheme, validate scope, create session metadata",
        cli_command="_internal_register",   # Handled inline by executor; no CLI subprocess
        cli_extra_args=[],
        output_file="target_registration.json",
        mandatory=True,
        timeout_s=30,
        pct_complete=5,
        waf_adapt=False,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="deep_recon",
        display_name="Deep Reconnaissance",
        description="Subdomains (subfinder/amass), HTTP probe (httpx), port scan (nmap), crawl (katana), endpoint extraction",
        cli_command="adaptive-recon",
        cli_extra_args=["--depth", "deep"],
        output_file="adaptive_recon.json",
        mandatory=True,
        timeout_s=900,
        pct_complete=20,
        waf_adapt=True,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="vuln_scan",
        display_name="Vulnerability Scanning",
        description="Nuclei full templates + dalfox + sqlmap + crlfuzz + kxss + zero-day detection",
        cli_command="vuln-scan",
        cli_extra_args=["--severity", "info,low,medium,high,critical"],
        output_file="findings.json",
        mandatory=True,
        timeout_s=1800,
        pct_complete=40,
        waf_adapt=True,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="active_testing",
        display_name="Active Payload Testing",
        description="Payload-based: SQLi, XSS, SSRF, IDOR, CORS, JWT, Deserialization, Race Condition, File Upload, OAuth, Prototype Pollution, Clickjacking",
        cli_command="swarm-scan",
        cli_extra_args=["--agents", "sqli", "xss", "ssrf", "idor", "auth", "api",
                        "deserialization", "race_condition", "file_upload", "oauth",
                        "prototype_pollution", "clickjacking", "--yes"],
        output_file="swarm_findings.json",
        mandatory=True,
        timeout_s=1200,
        pct_complete=58,
        waf_adapt=True,
        source_type="tool",
        skip_on_waf_passive=True,
    ),
    PhaseConfig(
        name="auth_session",
        display_name="Authentication & Session Testing",
        description="Detect login endpoints, test default creds, maintain session tokens, re-use across phases",
        cli_command="swarm-scan",
        cli_extra_args=["--agents", "auth", "--yes"],
        output_file="auth_findings.json",
        mandatory=True,
        timeout_s=600,
        pct_complete=66,
        waf_adapt=True,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="business_logic",
        display_name="Business Logic Testing",
        description="Workflow simulation + real HTTP request sequences for race conditions, price manipulation, privilege escalation",
        cli_command="simulate-attacks",
        cli_extra_args=[],
        output_file="attack_simulation.json",
        mandatory=True,
        timeout_s=600,
        pct_complete=74,
        waf_adapt=True,
        source_type="simulated",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="exploit_validation",
        display_name="Exploit Validation",
        description="Safe non-destructive HTTP probes per finding type — confirms exploitability",
        cli_command="_internal_validate",   # Handled inline by executor
        cli_extra_args=[],
        output_file="validation_results.json",
        mandatory=True,
        timeout_s=600,
        pct_complete=82,
        waf_adapt=True,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="exploit_chains",
        display_name="Exploit Chain Detection",
        description="Cross-finding chain detection: SSRF→RCE, XSS→session hijack, SQLi→auth bypass, etc.",
        cli_command="chains",
        cli_extra_args=[],
        output_file="chains.json",
        mandatory=True,
        timeout_s=300,
        pct_complete=88,
        waf_adapt=False,
        source_type="simulated",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="attack_graph",
        display_name="Attack Graph Generation",
        description="Build attack graph from all confirmed findings — node/edge topology of exploitation paths",
        cli_command="attack-graph",
        cli_extra_args=[],
        output_file="attack_graph.json",
        mandatory=True,
        timeout_s=120,
        pct_complete=91,
        waf_adapt=False,
        source_type="simulated",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="ai_theory",
        display_name="AI Theory Generation",
        description="AI-generated hypothesis findings based on app model — tagged source_type=ai_theory",
        cli_command="zero-day",
        cli_extra_args=[],
        output_file="zero_day.json",
        mandatory=False,   # Non-mandatory — no AI key = skip gracefully
        timeout_s=300,
        pct_complete=93,
        waf_adapt=False,
        source_type="ai_theory",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="graphql_scan",
        display_name="GraphQL Security Scan",
        description="Detect GraphQL endpoints; test introspection, deep nesting, batch queries, mutations, IDOR",
        cli_command="graphql-scan",
        cli_extra_args=[],
        output_file="graphql_findings.json",
        mandatory=False,
        timeout_s=300,
        pct_complete=95,
        waf_adapt=True,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="browser_analysis",
        display_name="Headless Browser Analysis",
        description="JS execution, DOM XSS detection, dynamic API endpoint extraction, JS secret scanning",
        cli_command="browser-scan",
        cli_extra_args=[],
        output_file="browser_findings.json",
        mandatory=False,
        timeout_s=300,
        pct_complete=97,
        waf_adapt=False,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="smuggling_test",
        display_name="HTTP Smuggling Test",
        description="Raw socket CL.TE / TE.CL / TE.TE desync detection via timing analysis",
        cli_command="smuggling-scan",
        cli_extra_args=[],
        output_file="smuggling_findings.json",
        mandatory=False,
        timeout_s=120,
        pct_complete=99,
        waf_adapt=False,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
    PhaseConfig(
        name="oob_check",
        display_name="OOB Interaction Check",
        description="Poll OOB callback server for DNS/HTTP interactions triggered during scan",
        cli_command="_internal_oob_check",
        cli_extra_args=[],
        output_file="oob_findings.json",
        mandatory=False,
        timeout_s=60,
        pct_complete=100,
        waf_adapt=False,
        source_type="tool",
        skip_on_waf_passive=False,
    ),
]

# Phase lookup by name
PHASE_MAP: Dict[str, PhaseConfig] = {p.name: p for p in CANONICAL_PHASES}

# Phase execution order
PHASE_ORDER: List[str] = [p.name for p in CANONICAL_PHASES]

# Mandatory phases — any failure here = overall FAIL
MANDATORY_PHASES: List[str] = [p.name for p in CANONICAL_PHASES if p.mandatory]

# WAF-passive phases that should be skipped when WAF is blocking
WAF_SKIP_PHASES: List[str] = [p.name for p in CANONICAL_PHASES if p.skip_on_waf_passive]


def phase_cli_args(phase: PhaseConfig, target: str, output_dir: str) -> List[str]:
    """
    Build the exact CLI argument list for a phase.
    This is THE canonical mapping — Docker and CLI use this identically.
    """
    from pathlib import Path

    args: List[str] = [phase.cli_command, target]
    args += list(phase.cli_extra_args)

    # Commands fall into three categories for --output:
    #   _no_output_flag   — no --output flag at all (_internal_*)
    #   _file_output_cmds — write a single JSON file; pass full file path
    #   everything else   — directory output; pass directory
    _file_output_cmds = {
        "swarm-scan", "simulate-attacks", "zero-day",
        "graphql-scan", "browser-scan", "smuggling-scan",
    }
    _no_output_flag = {"_internal_register", "_internal_validate", "_internal_oob_check"}

    if phase.cli_command in _no_output_flag:
        return args
    if phase.cli_command in _file_output_cmds:
        return args + ["--output", str(Path(output_dir) / phase.output_file)]
    return args + ["--output", output_dir]


def phase_docker_exec(
    phase: PhaseConfig,
    target: str,
    output_dir: str,
    container: str = "oneinfinity-orchestrator",
) -> List[str]:
    """
    Build the docker exec command for a phase.
    Wraps phase_cli_args() — the inner command is IDENTICAL to CLI.
    """
    inner = ["python", "/app/oneinfinity.py"] + phase_cli_args(phase, target, output_dir)
    return ["docker", "exec", container] + inner
