"""
Adaptive Planner — uses knowledge base insights to dynamically order scan phases
and select optimal tools for a given target.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from learning.knowledge_base import KnowledgeBase
from learning.pattern_miner import PatternMiner, TargetInsight

from path_manager import db_path as db_path_fn

@dataclass
class AdaptivePlan:
    target: str
    ordered_phases: list[str]
    tool_overrides: dict[str, str]    # phase → preferred tool name
    skip_phases: list[str]
    focus_vuln_types: list[str]       # vuln types to prioritise
    insight: TargetInsight
    rationale: list[str] = field(default_factory=list)


class AdaptivePlanner:
    """
    Generates an optimised scan plan from learned patterns.

    Default phase order (baseline):
        recon → scan_nuclei → triage → scan_xss → scan_sqli →
        scan_ssrf → scan_secrets → exploit → validate → report

    The planner reorders and prunes this based on the target's history
    and predicted vulnerability patterns.
    """

    ALL_PHASES = [
        "recon",
        "scan_nuclei",
        "triage",
        "scan_xss",
        "scan_sqli",
        "scan_ssrf",
        "scan_secrets",
        "exploit",
        "validate",
        "report",
    ]

    VULN_TO_PHASE = {
        "XSS":                  "scan_xss",
        "SQL Injection":        "scan_sqli",
        "SSRF":                 "scan_ssrf",
        "Secret Exposure":      "scan_secrets",
        "OS Command Injection": "scan_nuclei",
        "CRLF Injection":       "scan_nuclei",
        "Open Redirect":        "scan_nuclei",
        "Security Misconfiguration": "scan_nuclei",
        "IDOR":                 "scan_nuclei",
        "Subdomain Takeover":   "recon",
    }

    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self.miner = PatternMiner(kb)

    def plan(self, target: str, tech_stack: list[str] | None = None,
             quick_mode: bool = False) -> AdaptivePlan:
        """
        Build an adaptive scan plan for a target.

        Parameters
        ----------
        target      : domain to scan
        tech_stack  : detected technologies (empty → full baseline scan)
        quick_mode  : skip low-yield phases to reduce scan time
        """
        insight = self.miner.predict_for_target(target, tech_stack)
        rationale: list[str] = list(insight.notes)

        # 1. Determine which vuln types to prioritise
        focus_vulns = [p.vuln_type for p in insight.predicted_vulns[:5]]

        # 2. Map focus vulns to phases and bring them forward
        priority_phases = []
        for vtype in focus_vulns:
            phase = self.VULN_TO_PHASE.get(vtype)
            if phase and phase not in priority_phases:
                priority_phases.append(phase)

        # 3. Build ordered phase list
        ordered = self._build_order(priority_phases, quick_mode, insight)

        # 4. Tool overrides from KB performance data
        tool_overrides = self._tool_overrides(focus_vulns)

        # 5. Phases to skip
        skip = []
        if quick_mode:
            skip.extend(["recon"])  # assume recon already done
            rationale.append("Quick mode: recon phase skipped (assumed pre-done)")
        if not focus_vulns:
            rationale.append("No prior patterns found — running full baseline scan")

        # 6. Rationale entries for prioritised phases
        if priority_phases:
            rationale.append(
                f"Prioritised phases based on tech stack patterns: {', '.join(priority_phases)}"
            )

        return AdaptivePlan(
            target=target,
            ordered_phases=ordered,
            tool_overrides=tool_overrides,
            skip_phases=skip,
            focus_vuln_types=focus_vulns,
            insight=insight,
            rationale=rationale,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_order(self, priority_phases: list[str], quick_mode: bool,
                     insight: TargetInsight) -> list[str]:
        """
        Construct ordered phase list:
        - recon always first (unless quick_mode)
        - priority phases moved forward
        - always end with validate, report
        """
        mandatory_first = ["recon"] if not quick_mode else []
        mandatory_last = ["exploit", "validate", "report"]

        middle_all = [p for p in self.ALL_PHASES
                      if p not in mandatory_first and p not in mandatory_last]

        # Bring priority phases to the front of middle
        ordered_middle = (
            [p for p in priority_phases if p in middle_all] +
            [p for p in middle_all if p not in priority_phases]
        )

        return mandatory_first + ordered_middle + mandatory_last

    def _tool_overrides(self, focus_vulns: list[str]) -> dict[str, str]:
        overrides: dict[str, str] = {}
        for vtype in focus_vulns:
            best = self.kb.best_tool_for_vuln(vtype, top_n=1)
            if best:
                phase = self.VULN_TO_PHASE.get(vtype, "")
                if phase:
                    overrides[phase] = best[0]["tool_name"]
        return overrides

    # ── Plan display ──────────────────────────────────────────────────────────

    def describe_plan(self, plan: AdaptivePlan) -> str:
        lines = [
            f"Adaptive Scan Plan — {plan.target}",
            "=" * 50,
            "",
            "Phase Order:",
        ]
        for i, phase in enumerate(plan.ordered_phases, 1):
            skip_flag = " [SKIP]" if phase in plan.skip_phases else ""
            override = plan.tool_overrides.get(phase, "")
            tool_note = f"  → preferred tool: {override}" if override else ""
            lines.append(f"  {i:2}. {phase}{skip_flag}{tool_note}")

        if plan.focus_vuln_types:
            lines += ["", "Predicted Vulnerability Focus:"]
            for vtype in plan.focus_vuln_types:
                lines.append(f"  • {vtype}")

        if plan.rationale:
            lines += ["", "Rationale:"]
            for note in plan.rationale:
                lines.append(f"  → {note}")

        if plan.insight.predicted_vulns:
            lines += ["", "Top Predicted Vulnerabilities:"]
            for p in plan.insight.predicted_vulns[:5]:
                lines.append(
                    f"  {p.vuln_type:<35} p={p.probability:.0%}  "
                    f"avg CVSS={p.avg_cvss:.1f}  tool={p.best_tool}"
                )

        return "\n".join(lines)


class LearningSystem:
    """
    Unified entry point for all learning subsystems.
    Used by AgentCoordinator and CLI commands.
    """

    def __init__(self, db_path: str = str(db_path_fn("knowledge_base.db"))):
        self.kb = KnowledgeBase(db_path)
        self.miner = PatternMiner(self.kb)
        self.planner = AdaptivePlanner(self.kb)

    def plan_for(self, target: str, tech_stack: list[str] | None = None,
                 quick: bool = False) -> AdaptivePlan:
        return self.planner.plan(target, tech_stack, quick_mode=quick)

    def record_result(self, task_result) -> None:
        """Called by coordinator after each task completes."""
        try:
            findings = task_result.findings or []
            tools = task_result.tools_used or []
            target = task_result.target

            # Record each tool as having run
            for tool in tools:
                self.kb.record_tool_run(
                    tool_name=tool,
                    vuln_type="",
                    target_type="web",
                    success=task_result.success,
                    findings_count=len(findings),
                    duration_s=getattr(task_result, "duration", 0.0),
                )

            # Record per-finding tool stats
            for f in findings:
                tool = f.get("source_tool", "")
                vtype = f.get("vuln_type", "")
                if tool and vtype:
                    self.kb.record_tool_run(
                        tool_name=tool, vuln_type=vtype, target_type="web",
                        success=True, findings_count=1,
                    )

            # Update tech-vuln patterns
            if findings:
                profile = self.kb.get_target_profile(target) or {}
                tech = profile.get("tech_stack", [])
                self.miner.record_findings(target, findings, tech_stack=tech)
        except Exception:
            pass  # Learning failures must never crash the main pipeline

    def stats(self) -> dict:
        return self.kb.stats()

    def show_stats(self):
        s = self.kb.stats()
        print(f"\n{'='*50}")
        print("  Continuous Learning System — Statistics")
        print(f"{'='*50}")
        print(f"  Scans completed:      {s['sessions']}")
        print(f"  Confirmed findings:   {s['confirmed_findings']}")
        print(f"  Unique targets:       {s['unique_targets']}")
        print()
        print("  Top Vulnerability Types:")
        for v in s.get("top_vuln_types", []):
            print(f"    {v['vuln_type']:<35} {v['count']} finding(s)")
        print()
        print("  Top Performing Tools:")
        for t in s.get("top_tools", []):
            print(f"    {t['tool']:<20} {t['findings']} finding(s)")
        print()

    def close(self):
        self.kb.close()
