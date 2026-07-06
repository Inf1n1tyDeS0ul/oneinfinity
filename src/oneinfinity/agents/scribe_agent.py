"""
Scribe Agent — reads all council outputs and generates a professional AI
penetration-test report using LLM-powered section writing.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ── Report template ────────────────────────────────────────────────────────────

AIVulnReportTemplate = """\
# AI Penetration Test Report
**Generated:** {generated_at}
**Scan ID:** {scan_id}
**Target:** {target}

---

## Executive Summary
{executive_summary}

---

## Technical Narrative
{technical_narrative}

---

## Vulnerability Details

### CVSS / Severity
- **Score:** {cvss_score}
- **Vector:** `{cvss_vector}`
- **Severity:** {severity}

### OWASP LLM Top 10
{owasp_llm_category}

### MITRE ATLAS
{mitre_atlas_technique}

---

## Attack Timeline
{attack_timeline}

---

## Payloads & Responses (Verbatim)
{payloads_verbatim}

---

## Root Cause Analysis
{root_cause_analysis}

---

## Remediation
{remediation_code_examples}

---

## Framework Mappings
{framework_mappings}

---
*Report produced by OneInfinity AI Security Council*
"""

# Per-section system prompts ────────────────────────────────────────────────────

_SECTION_SYSTEM = (
    "You are a senior penetration tester writing a professional security report "
    "for a bug-bounty program. Be precise, evidence-based, and write for a "
    "technical audience. Use Markdown formatting. Do not add preamble or sign-off."
)

_SECTION_PROMPTS: dict[str, str] = {
    "executive_summary": (
        "Write a concise two-paragraph executive summary of the following AI/LLM "
        "security assessment. First paragraph: what was tested and what was found. "
        "Second paragraph: business risk and recommended priority.\n\nContext:\n{context_json}"
    ),
    "technical_narrative": (
        "Write a detailed technical narrative (3-5 paragraphs) describing the attack "
        "chain: reconnaissance → exploitation → post-exploitation. Explain each stage "
        "using the provided evidence. Include specific HTTP requests, payloads, and "
        "responses where available.\n\nContext:\n{context_json}"
    ),
    "root_cause_analysis": (
        "Identify the root cause(s) of the vulnerability: the architectural decision, "
        "missing control, or implementation flaw that made exploitation possible. "
        "Be specific — reference the vulnerable code path, parameter, or configuration "
        "if visible in the evidence.\n\nContext:\n{context_json}"
    ),
    "remediation_code_examples": (
        "Provide concrete, actionable remediation steps with code examples where "
        "applicable. Include: (1) immediate short-term fix, (2) long-term architectural "
        "improvement, (3) detection/monitoring recommendation. Use fenced code blocks "
        "for any code.\n\nContext:\n{context_json}"
    ),
}


# ── Scribe Agent ───────────────────────────────────────────────────────────────

class ScribeAgent:
    """
    Reads all council outputs (surface profile, exploit plan, exploit trace,
    post-exploitation report, validated finding) and generates a complete,
    professional AI penetration-test report.

    The report is written to:
        ~/.oneinfinity/<scan_id>/report/ai_pentest_report.md
    and returned as a string.
    """

    def __init__(self, model_orchestrator=None):
        self._orch = model_orchestrator
        if self._orch is None:
            try:
                from oneinfinity.orchestration.model_orchestrator import get_orchestrator
                self._orch = get_orchestrator()
            except Exception:
                self._orch = None

    # ── Public API ────────────────────────────────────────────────────────────

    def write(
        self,
        surface_profile,
        exploit_plan,
        exploit_trace,
        post_exploit_report,
        validated_finding,
        scan_id: Optional[str] = None,
    ) -> str:
        """
        Generate a full AI pentest report from council outputs.

        Parameters
        ----------
        surface_profile : dict | str
            Output from SensorAgent / MCPSurfaceScanner.
        exploit_plan : dict | str
            Output from ReasoningAgent / ExploitPlanningAgent.
        exploit_trace : dict | str
            Output from StepwiseRunner / ExploitExecutionAgent.
        post_exploit_report : dict | str
            Output from PostExploitAgent / LLMGuidedPostExploit.
        validated_finding : AIEnrichedFinding | dict
            Output from FindingValidationAgent.
        scan_id : str | None
            Unique ID for this scan session (auto-generated if omitted).

        Returns
        -------
        str  — the full Markdown report.
        """
        import uuid as _uuid
        scan_id = scan_id or str(_uuid.uuid4())[:12]

        # Normalise all inputs to dicts/strings
        sp   = self._to_dict_or_str(surface_profile)
        ep   = self._to_dict_or_str(exploit_plan)
        et   = self._to_dict_or_str(exploit_trace)
        per  = self._to_dict_or_str(post_exploit_report)
        vf   = self._to_dict_or_str(validated_finding)

        # Build shared context once
        context = {
            "surface_profile":     sp,
            "exploit_plan":        ep,
            "exploit_trace":       et,
            "post_exploit_report": per,
            "validated_finding":   vf,
        }

        # LLM-generated sections
        exec_summary   = self._generate_section("executive_summary",         context)
        tech_narrative = self._generate_section("technical_narrative",       context)
        root_cause     = self._generate_section("root_cause_analysis",       context)
        remediation    = self._generate_section("remediation_code_examples", context)

        # Static / structured sections
        attack_timeline    = self._format_timeline(exploit_trace)
        payloads_verbatim  = self._format_payloads(exploit_trace, post_exploit_report)
        framework_mappings = self._format_framework_mappings(validated_finding)

        # Pull CVSS / severity from validated_finding
        cvss_score    = self._field(vf, "cvss_score",            "N/A")
        cvss_vector   = self._field(vf, "cvss_vector",           "N/A")
        severity      = self._field(vf, "severity",              "high")
        owasp_cat     = self._field(vf, "owasp_llm_category",    "N/A")
        mitre_tech    = self._field(vf, "mitre_atlas_technique",  "N/A")
        target        = (self._field(sp, "target", "")
                         or self._field(et, "url", "")
                         or self._field(et, "target", "unknown"))

        report = AIVulnReportTemplate.format(
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            scan_id=scan_id,
            target=target,
            executive_summary=exec_summary,
            technical_narrative=tech_narrative,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            owasp_llm_category=owasp_cat,
            mitre_atlas_technique=mitre_tech,
            attack_timeline=attack_timeline,
            payloads_verbatim=payloads_verbatim,
            root_cause_analysis=root_cause,
            remediation_code_examples=remediation,
            framework_mappings=framework_mappings,
        )

        # Persist to disk
        report_path = (
            Path.home()
            / ".oneinfinity"
            / scan_id
            / "report"
            / "ai_pentest_report.md"
        )
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report, encoding="utf-8")
            logger.info("ScribeAgent: report written to %s", report_path)
        except Exception as exc:
            logger.warning("ScribeAgent: could not write report to disk: %s", exc)

        return report

    def _generate_section(self, section_name: str, context: dict) -> str:
        """
        Issue a single LLM call to generate one report section.
        Returns a Markdown string (falls back to a placeholder on error).
        """
        if self._orch is None:
            return f"*[LLM unavailable — {section_name} not generated]*"

        template = _SECTION_PROMPTS.get(section_name)
        if template is None:
            return f"*[No prompt template for section '{section_name}']*"

        # Truncate large payloads to stay within context limits
        context_copy = {}
        for k, v in context.items():
            serialised = json.dumps(v) if isinstance(v, dict) else str(v)
            context_copy[k] = serialised[:2000] + "...[truncated]" if len(serialised) > 2000 else serialised

        prompt = template.format(context_json=json.dumps(context_copy, indent=2))

        try:
            output = self._orch.execute({
                "prompt":     prompt,
                "agent_type": "report_writing",
                "importance": "HIGH",
                "complexity": "HIGH",
            })
            return output.content.strip()
        except Exception as exc:
            logger.warning("ScribeAgent._generate_section(%s) failed: %s", section_name, exc)
            return f"*[Section generation failed: {exc}]*"

    def _format_timeline(self, trace) -> str:
        """
        Build a severity timeline as a Markdown table from the exploit trace.

        Accepts either a list of step dicts or a dict with a 'steps' list.
        Falls back gracefully if the structure is unrecognised.
        """
        steps = []
        if isinstance(trace, dict):
            # Common key names used by different council agents
            steps = (trace.get("steps")
                     or trace.get("timeline")
                     or trace.get("events")
                     or [])
        elif isinstance(trace, list):
            steps = trace

        if not steps:
            # Try to extract timestamped lines from string representation
            raw = json.dumps(trace) if isinstance(trace, dict) else str(trace)
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            if lines:
                rows = "\n".join(
                    f"| {i+1} | — | {line[:120]} |" for i, line in enumerate(lines[:20])
                )
                return (
                    "| # | Severity | Event |\n"
                    "|---|----------|-------|\n"
                    f"{rows}"
                )
            return "*No timeline data available.*"

        header = "| # | Timestamp | Severity | Action | Result |\n|---|-----------|----------|--------|--------|\n"
        rows = []
        for i, step in enumerate(steps[:50]):  # cap at 50 rows
            if not isinstance(step, dict):
                rows.append(f"| {i+1} | — | — | {str(step)[:80]} | — |")
                continue
            ts       = step.get("timestamp") or step.get("time") or "—"
            sev      = step.get("severity") or step.get("level") or "—"
            action   = step.get("action") or step.get("step") or step.get("name") or "—"
            result   = step.get("result") or step.get("output") or step.get("status") or "—"
            # Sanitise Markdown table special chars
            action  = str(action)[:80].replace("|", "\\|")
            result  = str(result)[:80].replace("|", "\\|")
            rows.append(f"| {i+1} | {ts} | {sev} | {action} | {result} |")

        return header + "\n".join(rows)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _format_payloads(self, exploit_trace, post_exploit_report) -> str:
        """Format raw payloads and responses verbatim as fenced code blocks."""
        blocks: list[str] = []

        for label, data in (("Exploit Trace", exploit_trace),
                             ("Post-Exploitation", post_exploit_report)):
            if not data:
                continue
            raw = json.dumps(data, indent=2) if isinstance(data, dict) else str(data)
            # Truncate very large outputs
            if len(raw) > 4000:
                raw = raw[:4000] + "\n... [truncated]"
            blocks.append(f"### {label}\n```\n{raw}\n```")

        return "\n\n".join(blocks) if blocks else "*No payload evidence captured.*"

    def _format_framework_mappings(self, validated_finding) -> str:
        """Render OWASP / MITRE / CVSS mappings as a structured table."""
        vf = self._to_dict_or_str(validated_finding)
        owasp  = self._field(vf, "owasp_llm_category",   "N/A")
        mitre  = self._field(vf, "mitre_atlas_technique", "N/A")
        cvss_v = self._field(vf, "cvss_vector",           "N/A")
        cvss_s = self._field(vf, "cvss_score",            "N/A")
        conf   = self._field(vf, "confirmed",              False)

        return (
            "| Framework | Reference | Notes |\n"
            "|-----------|-----------|-------|\n"
            f"| OWASP LLM Top 10 | {owasp} | AI/LLM-specific risk taxonomy |\n"
            f"| MITRE ATLAS | {mitre} | Adversarial ML threat technique |\n"
            f"| CVSS 3.1 | Score: {cvss_s} | Vector: `{cvss_v}` |\n"
            f"| Confirmed | {'✅ Yes' if conf else '⚠️ Unconfirmed'} | Automatic exploitation verified |\n"
        )

    @staticmethod
    def _to_dict_or_str(obj: Any) -> Any:
        """Normalise an input to dict (if possible) or string."""
        if obj is None:
            return {}
        if isinstance(obj, dict):
            return obj
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "__dict__"):
            return vars(obj)
        return str(obj)

    @staticmethod
    def _field(obj: Any, key: str, default: Any = "") -> Any:
        """Safely read a field from a dict or object."""
        if isinstance(obj, dict):
            return obj.get(key, default)
        if hasattr(obj, key):
            return getattr(obj, key, default)
        return default
