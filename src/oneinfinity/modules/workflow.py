"""
Optimal Bug Bounty Workflow Engine
====================================
Builds and executes a dependency-aware, capability-driven scan plan.

Design principles:
  1. Passive-first  — no target contact until explicitly authorized
  2. Gate-based     — each phase unlocks the next only if data is produced
  3. Triage-before-scan — gf/kxss narrow candidates before expensive tools
  4. Parallel where safe — passive + port-scan run in parallel with crawl
  5. Graceful degradation — missing tools → fallbacks, never hard-abort

Usage:
    from oneinfinity.modules.workflow import WorkflowEngine
    wf = WorkflowEngine(target="example.com", output_dir="~/.oneinfinity/raw/example.com")
    plan = wf.build_plan()
    wf.print_plan(plan)
    results = wf.execute(plan)
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from oneinfinity.modules.utils import banner, section, ok, info, warn, err, bold
from oneinfinity.modules.capability_map import CapabilityMap, Vuln, CAPABILITIES
from oneinfinity.modules.tool_wrappers import ToolRegistry, ToolResult, is_available


# ── Step container ────────────────────────────────────────────────────────────

@dataclass
class WorkflowStep:
    step_id: str
    tool: str
    phase: str
    description: str
    inputs: dict                    # kwargs passed to ToolRegistry.run()
    parallel_group: int = 0         # steps with same group run concurrently
    required: bool = False          # if True, failure stops downstream steps
    skip_if_empty: str = ""         # skip if this result key is empty
    produces: str = ""              # key in WorkflowState this step writes to
    confidence_min: str = "low"     # only log findings above this level
    enabled: bool = True

    def __repr__(self):
        return f"Step({self.step_id}: {self.tool})"


@dataclass
class StepResult:
    step_id: str
    tool: str
    success: bool
    data: Any = None
    error: str = ""
    duration: float = 0.0
    skipped: bool = False
    skip_reason: str = ""


@dataclass
class WorkflowState:
    """Shared mutable state — what we know so far about the target."""
    target: str
    subdomains: list[str] = field(default_factory=list)
    alive_hosts: list[dict] = field(default_factory=list)   # httpx output
    open_ports: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)           # all discovered URLs
    endpoints: list[str] = field(default_factory=list)      # URLs with params
    param_urls: list[str] = field(default_factory=list)     # paramspider output
    api_endpoints: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    dns_records: list[dict] = field(default_factory=list)
    cloud_assets: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    # Triage output from gf patterns
    sqli_candidates: list[str] = field(default_factory=list)
    xss_candidates: list[str] = field(default_factory=list)
    ssrf_candidates: list[str] = field(default_factory=list)
    redirect_candidates: list[str] = field(default_factory=list)
    rce_candidates: list[str] = field(default_factory=list)
    idor_candidates: list[str] = field(default_factory=list)
    lfi_candidates: list[str] = field(default_factory=list)

    def alive_urls(self) -> list[str]:
        return [h.get("url", "") for h in self.alive_hosts if h.get("url")]

    def has(self, key: str) -> bool:
        return bool(getattr(self, key, None))


# ── Workflow plan ─────────────────────────────────────────────────────────────

@dataclass
class WorkflowPlan:
    target: str
    steps: list[WorkflowStep] = field(default_factory=list)
    available_tools: list[str] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)

    def enabled_steps(self) -> list[WorkflowStep]:
        return [s for s in self.steps if s.enabled]

    def phases(self) -> list[str]:
        seen = []
        for s in self.steps:
            if s.phase not in seen:
                seen.append(s.phase)
        return seen


# ── Workflow engine ───────────────────────────────────────────────────────────

class WorkflowEngine:
    """
    Builds an optimal, dependency-aware scan plan and executes it.
    """

    def __init__(
        self,
        target: str,
        output_dir: str = ".",
        phases: list[str] = None,
        rate_limit: int = 30,
        nuclei_severity: str = "medium,high,critical",
        oob_url: str = "",
        max_workers: int = 3,
        timeout_multiplier: float = 1.0,
    ):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.phases = phases or [
            "passive", "subdomain", "dns", "http",
            "fingerprint", "ports", "crawl", "content",
            "api", "triage", "vuln", "cloud", "secrets",
        ]
        self.rate_limit = rate_limit
        self.nuclei_severity = nuclei_severity
        self.oob_url = oob_url
        self.max_workers = max_workers
        self.tmult = timeout_multiplier

        self.reg = ToolRegistry()
        self._avail = set(self.reg.available_tools())
        self.state = WorkflowState(target=target)
        self._step_results: list[StepResult] = []

    def _t(self, base: int) -> int:
        return max(30, int(base * self.tmult))

    def _avail_tool(self, *tools: str) -> Optional[str]:
        for t in tools:
            if t in self._avail:
                return t
        return None

    # ── Plan builder ─────────────────────────────────────────────────────────

    def build_plan(self) -> WorkflowPlan:
        """
        Construct the optimal scan plan based on available tools.
        Steps are organized into parallel groups where safe.
        """
        steps: list[WorkflowStep] = []
        t = self.target

        # ── PHASE: PASSIVE (no target contact) ──────────────────────────────
        if "passive" in self.phases:
            # Wayback/CommonCrawl fetch — passive, run first
            for tool in ["gauplus", "waybackurls"]:
                if tool in self._avail:
                    steps.append(WorkflowStep(
                        step_id=f"passive_{tool}",
                        tool=tool,
                        phase="passive",
                        description=f"Fetch historical URLs from web archives via {tool}",
                        inputs={"domain": t, "timeout": self._t(90)},
                        parallel_group=1,
                        produces="urls",
                    ))

            if "paramspider" in self._avail:
                steps.append(WorkflowStep(
                    step_id="passive_paramspider",
                    tool="paramspider",
                    phase="passive",
                    description="Discover parameterized URLs from web archives",
                    inputs={"domain": t, "timeout": self._t(90)},
                    parallel_group=1,
                    produces="param_urls",
                ))

        # ── PHASE: SUBDOMAIN ENUMERATION ────────────────────────────────────
        if "subdomain" in self.phases:
            # Run all available subdomain tools — more coverage = better
            sub_tools = {
                "assetfinder": ({"domain": t, "timeout": self._t(45)}, 2),
                "chaos":       ({"domain": t, "timeout": self._t(30)}, 2),
                "findomain":   ({"domain": t, "timeout": self._t(30)}, 2),
                "subfinder":   ({"domain": t, "timeout": self._t(90)}, 2),
                "sublist3r":   ({"domain": t, "timeout": self._t(150)}, 3),
                "amass":       ({"domain": t, "timeout": self._t(300)}, 3),
            }
            for tool, (kwargs, grp) in sub_tools.items():
                if tool in self._avail:
                    steps.append(WorkflowStep(
                        step_id=f"sub_{tool}",
                        tool=tool,
                        phase="subdomain",
                        description=f"Subdomain enumeration via {tool}",
                        inputs=kwargs,
                        parallel_group=grp,
                        produces="subdomains",
                    ))

        # ── PHASE: DNS ──────────────────────────────────────────────────────
        if "dns" in self.phases and "dnsx" in self._avail:
            steps.append(WorkflowStep(
                step_id="dns_resolve",
                tool="dnsx",
                phase="dns",
                description="Resolve all subdomains + detect dangling CNAMEs (subdomain takeover)",
                inputs={"domains": [], "timeout": self._t(60)},  # filled at runtime
                parallel_group=4,
                required=False,
                skip_if_empty="subdomains",
                produces="dns_records",
            ))

        # ── PHASE: HTTP PROBING ──────────────────────────────────────────────
        if "http" in self.phases and "httpx" in self._avail:
            steps.append(WorkflowStep(
                step_id="http_probe",
                tool="httpx",
                phase="http",
                description="Probe all subdomains for alive hosts, status codes, tech stack",
                inputs={"targets": [], "timeout": self._t(120)},  # filled at runtime
                parallel_group=5,
                required=True,   # everything downstream needs alive hosts
                skip_if_empty="subdomains",
                produces="alive_hosts",
            ))

        # ── PHASE: FINGERPRINTING ────────────────────────────────────────────
        if "fingerprint" in self.phases and "whatweb" in self._avail:
            steps.append(WorkflowStep(
                step_id="fingerprint_whatweb",
                tool="whatweb",
                phase="fingerprint",
                description="Fingerprint web technologies to target nuclei templates",
                inputs={"target": f"https://{t}", "timeout": self._t(30)},
                parallel_group=6,
                produces="tech_stack",
            ))

        # ── PHASE: PORT SCANNING ─────────────────────────────────────────────
        if "ports" in self.phases:
            port_tool = self._avail_tool("naabu", "rustscan", "nmap")
            if port_tool:
                steps.append(WorkflowStep(
                    step_id=f"ports_{port_tool}",
                    tool=port_tool,
                    phase="ports",
                    description=f"Port scan live hosts via {port_tool}",
                    inputs={"target": t, "timeout": self._t(120)},
                    parallel_group=6,   # parallel with fingerprinting
                    produces="open_ports",
                ))
            # Deep service scan with nmap if initial scan found ports
            if "nmap" in self._avail and port_tool != "nmap":
                steps.append(WorkflowStep(
                    step_id="ports_nmap_deep",
                    tool="nmap",
                    phase="ports",
                    description="Deep service/version detection on discovered ports",
                    inputs={"target": t, "flags": "-sV -T4 --open -sC",
                             "timeout": self._t(180)},
                    parallel_group=7,
                    skip_if_empty="open_ports",
                ))

        # ── PHASE: CRAWLING ──────────────────────────────────────────────────
        if "crawl" in self.phases:
            crawl_tool = self._avail_tool("katana", "hakrawler")
            if crawl_tool:
                kwargs = (
                    {"target": f"https://{t}", "timeout": self._t(200), "js_crawl": True}
                    if crawl_tool == "katana"
                    else {"url": f"https://{t}", "timeout": self._t(120)}
                )
                steps.append(WorkflowStep(
                    step_id=f"crawl_{crawl_tool}",
                    tool=crawl_tool,
                    phase="crawl",
                    description=f"Active web crawling (JS-aware) via {crawl_tool}",
                    inputs=kwargs,
                    parallel_group=7,
                    produces="urls",
                ))

        # ── PHASE: CONTENT DISCOVERY ─────────────────────────────────────────
        if "content" in self.phases:
            content_tool = self._avail_tool("ffuf", "gobuster", "dirsearch")
            if content_tool:
                steps.append(WorkflowStep(
                    step_id=f"content_{content_tool}",
                    tool=content_tool,
                    phase="content",
                    description=f"Directory/file brute-force via {content_tool}",
                    inputs={"url": f"https://{t}", "timeout": self._t(300)},
                    parallel_group=8,
                    skip_if_empty="alive_hosts",
                    produces="endpoints",
                ))

        # ── PHASE: API DISCOVERY ─────────────────────────────────────────────
        if "api" in self.phases:
            if "kiterunner" in self._avail:
                steps.append(WorkflowStep(
                    step_id="api_kiterunner",
                    tool="kiterunner",
                    phase="api",
                    description="API endpoint brute-force via kiterunner (23k+ routes)",
                    inputs={"target": f"https://{t}", "timeout": self._t(180)},
                    parallel_group=8,
                    produces="api_endpoints",
                ))
            if "arjun" in self._avail:
                steps.append(WorkflowStep(
                    step_id="api_arjun",
                    tool="arjun",
                    phase="api",
                    description="Discover hidden HTTP parameters via arjun",
                    inputs={"url": f"https://{t}", "timeout": self._t(90)},
                    parallel_group=9,
                    produces="endpoints",
                ))

        # ── PHASE: TRIAGE (gf pattern classification) ─────────────────────
        if "triage" in self.phases and "gf" in self._avail:
            triage_patterns = {
                "sqli":     "sqli_candidates",
                "xss":      "xss_candidates",
                "ssrf":     "ssrf_candidates",
                "redirect": "redirect_candidates",
                "rce":      "rce_candidates",
                "idor":     "idor_candidates",
                "lfi":      "lfi_candidates",
            }
            for pattern, produces in triage_patterns.items():
                steps.append(WorkflowStep(
                    step_id=f"triage_gf_{pattern}",
                    tool="gf",
                    phase="triage",
                    description=f"Filter URLs matching {pattern.upper()} pattern",
                    inputs={"urls": [], "pattern": pattern, "timeout": 10},
                    parallel_group=10,
                    skip_if_empty="urls",
                    produces=produces,
                ))

        # ── PHASE: VULNERABILITY SCANNING ────────────────────────────────────
        if "vuln" in self.phases:

            # Nuclei — broad multi-class scan
            if "nuclei" in self._avail:
                steps.append(WorkflowStep(
                    step_id="vuln_nuclei_broad",
                    tool="nuclei",
                    phase="vuln",
                    description="Broad nuclei scan (misconfigs, exposures, CVEs)",
                    inputs={
                        "target": f"https://{t}",
                        "severity": self.nuclei_severity,
                        "timeout": self._t(600),
                    },
                    parallel_group=11,
                    produces="findings",
                ))
                # Nuclei focused XSS pass
                steps.append(WorkflowStep(
                    step_id="vuln_nuclei_xss",
                    tool="nuclei",
                    phase="vuln",
                    description="Nuclei XSS-focused template pass",
                    inputs={
                        "target": f"https://{t}",
                        "templates": "xss",
                        "severity": "low,medium,high",
                        "timeout": self._t(180),
                    },
                    parallel_group=11,
                    produces="findings",
                ))

            # kxss — reflected character detection (fast triage for XSS)
            if "kxss" in self._avail:
                steps.append(WorkflowStep(
                    step_id="vuln_kxss",
                    tool="kxss",
                    phase="vuln",
                    description="Detect reflected special chars (XSS triage)",
                    inputs={"urls": [], "timeout": self._t(90)},
                    parallel_group=11,
                    skip_if_empty="xss_candidates",
                    produces="findings",
                ))

            # dalfox — XSS confirmation on kxss/gf candidates
            if "dalfox" in self._avail:
                steps.append(WorkflowStep(
                    step_id="vuln_dalfox",
                    tool="dalfox",
                    phase="vuln",
                    description="XSS confirmation + WAF bypass via dalfox",
                    inputs={"url": f"https://{t}", "timeout": self._t(180)},
                    parallel_group=12,
                    skip_if_empty="xss_candidates",
                    produces="findings",
                ))

            # sqlmap — SQLi on gf-filtered candidates
            if "sqlmap" in self._avail:
                steps.append(WorkflowStep(
                    step_id="vuln_sqlmap",
                    tool="sqlmap",
                    phase="vuln",
                    description="SQL injection testing on filtered candidates",
                    inputs={"url": f"https://{t}", "timeout": self._t(300)},
                    parallel_group=12,
                    skip_if_empty="sqli_candidates",
                    produces="findings",
                ))

            # crlfuzz — CRLF injection on alive hosts
            if "crlfuzz" in self._avail:
                steps.append(WorkflowStep(
                    step_id="vuln_crlfuzz",
                    tool="crlfuzz",
                    phase="vuln",
                    description="CRLF injection scan on alive hosts",
                    inputs={"target": f"https://{t}", "timeout": self._t(60)},
                    parallel_group=11,
                    produces="findings",
                ))

            # xssstrike — XSS alternative engine
            if "xssstrike" in self._avail and "dalfox" not in self._avail:
                steps.append(WorkflowStep(
                    step_id="vuln_xssstrike",
                    tool="xssstrike",
                    phase="vuln",
                    description="XSS scan via XSStrike",
                    inputs={"url": f"https://{t}", "timeout": self._t(120)},
                    parallel_group=12,
                    skip_if_empty="xss_candidates",
                    produces="findings",
                ))

            # commix — command injection on rce candidates
            if "commix" in self._avail:
                steps.append(WorkflowStep(
                    step_id="vuln_commix",
                    tool="commix",
                    phase="vuln",
                    description="OS command injection on filtered candidates",
                    inputs={"url": f"https://{t}", "timeout": self._t(180)},
                    parallel_group=12,
                    skip_if_empty="rce_candidates",
                    produces="findings",
                ))

            # nikto — web server scan
            if "nikto" in self._avail:
                steps.append(WorkflowStep(
                    step_id="vuln_nikto",
                    tool="nikto",
                    phase="vuln",
                    description="Web server misconfiguration scan via nikto",
                    inputs={"target": t, "timeout": self._t(240)},
                    parallel_group=11,
                    produces="findings",
                ))

        # ── PHASE: CLOUD ────────────────────────────────────────────────────
        if "cloud" in self.phases:
            if "s3scanner" in self._avail:
                steps.append(WorkflowStep(
                    step_id="cloud_s3scanner",
                    tool="s3scanner",
                    phase="cloud",
                    description="Scan for misconfigured S3 buckets",
                    inputs={"domain": t, "timeout": self._t(90)},
                    parallel_group=13,
                    produces="cloud_assets",
                ))
            if "cloudbrute" in self._avail:
                steps.append(WorkflowStep(
                    step_id="cloud_cloudbrute",
                    tool="cloudbrute",
                    phase="cloud",
                    description="Brute-force cloud storage assets (S3/GCS/Azure)",
                    inputs={"domain": t, "timeout": self._t(120)},
                    parallel_group=13,
                    produces="cloud_assets",
                ))

        # ── PHASE: SECRETS ──────────────────────────────────────────────────
        if "secrets" in self.phases:
            if "trufflehog" in self._avail:
                steps.append(WorkflowStep(
                    step_id="secrets_trufflehog",
                    tool="trufflehog",
                    phase="secrets",
                    description="Scan JS files and recon output for secrets via TruffleHog",
                    inputs={"target": str(self.output_dir),
                             "target_type": "filesystem",
                             "timeout": self._t(180)},
                    parallel_group=14,
                    produces="secrets",
                ))
            if "gitleaks" in self._avail:
                steps.append(WorkflowStep(
                    step_id="secrets_gitleaks",
                    tool="gitleaks",
                    phase="secrets",
                    description="Scan git history for leaked secrets via gitleaks",
                    inputs={"target": str(self.output_dir), "timeout": self._t(90)},
                    parallel_group=14,
                    produces="secrets",
                ))

        plan = WorkflowPlan(
            target=self.target,
            steps=steps,
            available_tools=list(self._avail),
            missing_tools=self.reg.missing_tools(),
        )
        return plan

    def print_plan(self, plan: WorkflowPlan):
        """Pretty-print the planned workflow."""
        banner(f"Workflow Plan — {plan.target}")
        info(f"Tools available : {len(plan.available_tools)}")
        info(f"Tools missing   : {len(plan.missing_tools)}")
        info(f"Total steps     : {len(plan.enabled_steps())}")
        print()

        current_phase = None
        for step in plan.steps:
            if not step.enabled:
                continue
            if step.phase != current_phase:
                current_phase = step.phase
                section(f"Phase: {step.phase.upper()}")
            skip_note = f"  [skip-if: {step.skip_if_empty} empty]" if step.skip_if_empty else ""
            parallel_note = f"  [parallel-group={step.parallel_group}]"
            print(f"  [{step.step_id}]")
            print(f"    Tool      : {step.tool}")
            print(f"    Purpose   : {step.description}")
            print(f"    Produces  : {step.produces or '(intermediate)'}")
            print(f"    Flags     : {parallel_note}{skip_note}")
            print()

        if plan.missing_tools:
            warn(f"Missing tools (install with: bash install_tools.sh):")
            for t in sorted(plan.missing_tools):
                cap = CAPABILITIES.get(t)
                cat = cap.category if cap else "?"
                print(f"    {t:<20} [{cat}]")
        print()

    # ── State persistence helpers ─────────────────────────────────────────────

    def _save(self, key: str, data: Any):
        out = self.output_dir / f"{key}.json"
        out.write_text(json.dumps(data, indent=2, default=str))

    def _load(self, key: str) -> Any:
        out = self.output_dir / f"{key}.json"
        if out.exists():
            try:
                return json.loads(out.read_text())
            except Exception:
                pass
        return None

    def _merge_list(self, attr: str, new_items: list):
        existing = set(getattr(self.state, attr, []))
        if isinstance(new_items, list):
            valid = [i for i in new_items if isinstance(i, str)]
            existing.update(valid)
            setattr(self.state, attr, sorted(existing))
        elif isinstance(new_items, dict):
            # e.g. alive_hosts is list[dict]
            lst = getattr(self.state, attr, [])
            lst.extend(new_items if isinstance(new_items, list) else [new_items])
            setattr(self.state, attr, lst)

    # ── Input resolution (fill runtime values) ────────────────────────────────

    def _resolve_inputs(self, step: WorkflowStep) -> dict:
        """Fill in runtime values that depend on previous step outputs."""
        inputs = dict(step.inputs)

        if step.tool in ("dnsx",):
            inputs["domains"] = self.state.subdomains[:500] or [self.target]

        elif step.tool in ("httpx",):
            inputs["targets"] = self.state.subdomains[:500] or [self.target]

        elif step.tool in ("kxss",):
            inputs["urls"] = (self.state.xss_candidates or
                              self.state.endpoints[:200] or
                              self.state.urls[:200])

        elif step.tool == "gf":
            inputs["urls"] = self.state.urls + self.state.endpoints

        elif step.tool in ("dalfox", "sqlmap", "xssstrike", "commix", "crlfuzz"):
            # Use the triage-filtered candidates for targeted scanning
            if step.tool == "dalfox":
                candidates = self.state.xss_candidates or self.state.endpoints[:10]
            elif step.tool == "sqlmap":
                candidates = self.state.sqli_candidates or self.state.endpoints[:5]
            elif step.tool in ("commix",):
                candidates = self.state.rce_candidates or self.state.endpoints[:5]
            else:
                candidates = self.state.alive_urls()[:5] or [f"https://{self.target}"]
            if candidates:
                inputs["url"] = candidates[0]

        elif step.tool == "nuclei":
            alive = self.state.alive_urls()
            if alive:
                inputs["target"] = alive[0]

        return inputs

    # ── Skip gate ─────────────────────────────────────────────────────────────

    def _should_skip(self, step: WorkflowStep) -> Optional[str]:
        if not step.skip_if_empty:
            return None
        val = getattr(self.state, step.skip_if_empty, None)
        if not val:
            return f"Skipped: '{step.skip_if_empty}' is empty — run earlier phases first"
        return None

    # ── Result absorber ───────────────────────────────────────────────────────

    def _absorb(self, step: WorkflowStep, result: ToolResult):
        """Extract data from a ToolResult and merge into workflow state."""
        d = result.data
        if not d:
            return

        p = step.produces
        if not p:
            return

        # Subdomains
        if p == "subdomains" and isinstance(d, dict):
            subs = d.get("subdomains", [])
            existing = set(self.state.subdomains)
            existing.update(subs)
            self.state.subdomains = sorted(existing)

        # Alive hosts
        elif p == "alive_hosts" and isinstance(d, dict):
            hosts = d.get("hosts", [])
            self.state.alive_hosts.extend(hosts)

        # DNS records
        elif p == "dns_records" and isinstance(d, dict):
            self.state.dns_records.extend(d.get("records", []))

        # Open ports
        elif p == "open_ports" and isinstance(d, dict):
            self.state.open_ports.extend(d.get("open_ports", []))

        # URLs (crawl, passive, etc.)
        elif p == "urls":
            new_urls = []
            if isinstance(d, dict):
                new_urls = d.get("urls", [])
            elif isinstance(d, list):
                new_urls = [i if isinstance(i, str) else str(i) for i in d]
            existing = set(self.state.urls)
            existing.update(new_urls)
            self.state.urls = sorted(existing)
            # Auto-classify endpoints (URLs with params)
            self.state.endpoints = sorted(set(
                self.state.endpoints + [u for u in self.state.urls if "?" in u]
            ))

        # Parameterized URLs from paramspider
        elif p == "param_urls" and isinstance(d, dict):
            pu = d.get("urls", [])
            existing = set(self.state.param_urls)
            existing.update(pu)
            self.state.param_urls = sorted(existing)
            # Also add to endpoints
            self.state.endpoints = sorted(set(self.state.endpoints + pu))

        # API endpoints
        elif p == "api_endpoints" and isinstance(d, dict):
            eps = d.get("endpoints", [])
            self.state.api_endpoints.extend(eps)

        # Tech stack
        elif p == "tech_stack" and isinstance(d, dict):
            techs = d.get("technologies", [])
            for tech_entry in techs:
                if isinstance(tech_entry, dict):
                    for plugin in tech_entry.get("plugins", {}).keys():
                        if plugin not in self.state.tech_stack:
                            self.state.tech_stack.append(plugin)

        # Endpoints (content discovery)
        elif p == "endpoints" and isinstance(d, dict):
            found = d.get("found", [])
            for item in found:
                url = item.get("url", "") or item.get("path", "")
                if url:
                    self.state.endpoints.append(url)
            self.state.endpoints = sorted(set(self.state.endpoints))

        # GF triage candidates
        elif p in ("sqli_candidates", "xss_candidates", "ssrf_candidates",
                   "redirect_candidates", "rce_candidates", "idor_candidates",
                   "lfi_candidates") and isinstance(d, dict):
            matches = d.get("matches", [])
            existing = set(getattr(self.state, p))
            existing.update(matches)
            setattr(self.state, p, sorted(existing))

        # Findings (vuln scanners)
        elif p == "findings":
            new_findings = []
            if isinstance(d, dict):
                new_findings = d.get("findings", [])
            elif isinstance(d, list):
                new_findings = d
            for f in new_findings:
                f["source_step"] = step.step_id
                self.state.findings.append(f)

        # Secrets
        elif p == "secrets" and isinstance(d, dict):
            secrets = d.get("secrets", [])
            self.state.secrets.extend(secrets)

        # Cloud assets
        elif p == "cloud_assets" and isinstance(d, dict):
            assets = d.get("buckets", d.get("found", []))
            self.state.cloud_assets.extend(assets)

        # Save to disk
        self._save(p, getattr(self.state, p, d))

    # ── Step executor ─────────────────────────────────────────────────────────

    def _run_step(self, step: WorkflowStep) -> StepResult:
        # Skip gate
        skip_reason = self._should_skip(step)
        if skip_reason:
            return StepResult(step_id=step.step_id, tool=step.tool,
                              success=True, skipped=True, skip_reason=skip_reason)

        inputs = self._resolve_inputs(step)
        t0 = time.time()
        try:
            tool_result = self.reg.run(step.tool, **inputs)
            duration = time.time() - t0

            if tool_result.success:
                self._absorb(step, tool_result)
                ok(f"  [{step.step_id}] {step.tool} — {duration:.1f}s")
            else:
                warn(f"  [{step.step_id}] {step.tool} FAILED: {tool_result.error[:80]}")

            return StepResult(
                step_id=step.step_id,
                tool=step.tool,
                success=tool_result.success,
                data=tool_result.data,
                error=tool_result.error,
                duration=duration,
            )
        except Exception as exc:
            duration = time.time() - t0
            err(f"  [{step.step_id}] {step.tool} crashed: {exc}")
            return StepResult(step_id=step.step_id, tool=step.tool,
                              success=False, error=str(exc), duration=duration)

    # ── Main execute ──────────────────────────────────────────────────────────

    def execute(self, plan: WorkflowPlan) -> WorkflowState:
        """
        Execute the workflow plan phase by phase.
        Within each parallel group, steps run concurrently.
        """
        banner(f"Executing Workflow — {plan.target}")
        t_start = time.time()

        # Group steps by phase → parallel_group for ordered execution
        from itertools import groupby
        steps = [s for s in plan.steps if s.enabled]

        # Execute in parallel-group order
        groups: dict[tuple[str, int], list[WorkflowStep]] = {}
        for step in steps:
            key = (step.phase, step.parallel_group)
            groups.setdefault(key, []).append(step)

        for (phase, grp_id), grp_steps in sorted(groups.items()):
            phase_steps_active = [s for s in grp_steps if s.enabled]
            if not phase_steps_active:
                continue

            section(f"Phase: {phase.upper()} (group {grp_id})")

            if len(phase_steps_active) == 1:
                result = self._run_step(phase_steps_active[0])
                self._step_results.append(result)
            else:
                # Parallel execution within group
                info(f"Running {len(phase_steps_active)} steps in parallel...")
                with ThreadPoolExecutor(max_workers=min(self.max_workers,
                                                        len(phase_steps_active))) as exe:
                    future_to_step = {
                        exe.submit(self._run_step, step): step
                        for step in phase_steps_active
                    }
                    for future in as_completed(future_to_step):
                        result = future.result()
                        self._step_results.append(result)

            # Check required steps
            for step in phase_steps_active:
                if step.required:
                    res = next((r for r in self._step_results
                                if r.step_id == step.step_id), None)
                    if res and not res.success and not res.skipped:
                        warn(f"Required step {step.step_id} failed — "
                             f"downstream steps may produce empty results")

        total = time.time() - t_start
        self._print_execution_summary(total)
        self._save("workflow_state", self.state.__dict__)
        return self.state

    def _print_execution_summary(self, total_duration: float):
        banner("Workflow Execution Summary")
        run = [r for r in self._step_results if not r.skipped]
        skipped = [r for r in self._step_results if r.skipped]
        failed = [r for r in run if not r.success]

        info(f"Steps run      : {len(run)}")
        info(f"Steps skipped  : {len(skipped)}")
        info(f"Steps failed   : {len(failed)}")
        info(f"Total duration : {total_duration:.1f}s")
        print()

        section("Discovered Assets")
        s = self.state
        print(f"  Subdomains      : {len(s.subdomains)}")
        print(f"  Alive hosts     : {len(s.alive_hosts)}")
        print(f"  Open ports      : {len(s.open_ports)}")
        print(f"  URLs            : {len(s.urls)}")
        print(f"  Endpoints       : {len(s.endpoints)}")
        print(f"  API endpoints   : {len(s.api_endpoints)}")
        print(f"  Cloud assets    : {len(s.cloud_assets)}")
        print()

        section("Vuln Triage Candidates")
        print(f"  SQLi candidates : {len(s.sqli_candidates)}")
        print(f"  XSS candidates  : {len(s.xss_candidates)}")
        print(f"  SSRF candidates : {len(s.ssrf_candidates)}")
        print(f"  Redirect cands  : {len(s.redirect_candidates)}")
        print(f"  RCE candidates  : {len(s.rce_candidates)}")
        print(f"  IDOR candidates : {len(s.idor_candidates)}")
        print(f"  LFI candidates  : {len(s.lfi_candidates)}")
        print()

        if s.findings:
            section("Findings")
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(
                s.findings,
                key=lambda f: sev_order.get(
                    str(f.get("severity", "info")).lower(), 5
                )
            )
            for f in sorted_findings[:30]:
                sev = str(f.get("severity", "info")).upper()
                name = f.get("name", f.get("template_id", f.get("type", "unknown")))
                host = f.get("matched_at", f.get("host", f.get("url", "")))
                print(f"  [{sev:<8}] {name:<35} {host}")
            if len(s.findings) > 30:
                print(f"  ... and {len(s.findings) - 30} more")

        if s.secrets:
            section("Secrets Found")
            for sec in s.secrets[:10]:
                detector = sec.get("detector", sec.get("rule", "unknown"))
                verified = "✓ VERIFIED" if sec.get("verified") else "unverified"
                print(f"  [{detector}] {verified}")

        print()
        info("All output saved to: " + str(self.output_dir))
        info("Next: oneinfinity findings log  — record confirmed findings")
        info("      bounty report         — generate report for a finding")
        print()
