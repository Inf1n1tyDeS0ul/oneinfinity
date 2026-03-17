"""
Reporter — multi-format output for vulnerability findings.

Supported formats: markdown, json, html

Usage:
    reporter = Reporter(output_dir="~/.oneinfinity/raw/target.com", platform="hackerone")
    reporter.add_finding(finding_dict)
    reporter.write("markdown")
    reporter.write("json")
    reporter.write("html")
"""

from __future__ import annotations

import html
import json
import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}


@dataclass
class Finding:
    vuln_type: str
    severity: str
    endpoint: str
    parameter: str = ""
    description: str = ""
    evidence: str = ""
    reproduction: str = ""
    impact: str = ""
    remediation: str = ""
    cvss: float = 0.0
    confidence: float = 0.0
    tool: str = ""
    tags: List[str] = field(default_factory=list)
    report_file: str = ""
    fingerprint: str = ""
    why_selected: str = ""
    how_exploited: str = ""
    data_exposed: str = ""
    attacker_gains: str = ""
    impact_score: str = ""
    suggested_fix: str = ""
    bounty_score: float = 0.0
    estimated_payout: str = ""
    priority_rank: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 5)


class Reporter:
    """Collects findings and renders them in multiple formats."""

    def __init__(
        self,
        output_dir: str | Path,
        target: str = "",
        platform: str = "hackerone",
    ) -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._target = target
        self._platform = platform
        self._findings: List[Finding] = []
        self._meta: Dict[str, Any] = {
            "target": target,
            "platform": platform,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------ #
    #  Data input
    # ------------------------------------------------------------------ #

    def add_finding(self, finding: Dict[str, Any] | Finding) -> None:
        if isinstance(finding, dict):
            finding = Finding.from_dict(finding)
        self._findings.append(finding)

    def add_findings(self, findings: List[Dict[str, Any] | Finding]) -> None:
        for f in findings:
            self.add_finding(f)

    def set_meta(self, key: str, value: Any) -> None:
        self._meta[key] = value

    def count(self) -> int:
        return len(self._findings)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self._findings, key=lambda f: f.severity_rank())

    # ------------------------------------------------------------------ #
    #  Write
    # ------------------------------------------------------------------ #

    def write(self, fmt: str = "markdown") -> Path:
        fmt = fmt.lower()
        if fmt in ("md", "markdown"):
            return self._write_markdown()
        elif fmt == "json":
            return self._write_json()
        elif fmt == "html":
            return self._write_html()
        else:
            raise ValueError(f"Unknown format: {fmt}. Use markdown, json, or html")

    def write_all(self, formats: List[str] = None) -> List[Path]:
        formats = formats or ["markdown", "json", "html"]
        return [self.write(fmt) for fmt in formats]

    # ------------------------------------------------------------------ #
    #  Markdown
    # ------------------------------------------------------------------ #

    def _write_markdown(self) -> Path:
        path = self._output_dir / "report.md"
        lines = self._render_markdown()
        path.write_text("\n".join(lines), encoding="utf-8")
        log.info("Markdown report written: %s", path)
        return path

    def _render_markdown(self) -> List[str]:
        findings = self.sorted_findings()
        target = self._target or "Unknown Target"
        platform = self._platform
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = [
            f"# Vulnerability Report — {target}",
            "",
            f"**Platform**: {platform}  ",
            f"**Target**: `{target}`  ",
            f"**Generated**: {now}  ",
            f"**Findings**: {len(findings)}",
            "",
        ]

        # Severity summary table
        by_sev: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.lower()] = by_sev.get(f.severity.lower(), 0) + 1
        lines += [
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = by_sev.get(sev, 0)
            if cnt:
                emoji = SEVERITY_EMOJI.get(sev, "")
                lines.append(f"| {emoji} {sev.capitalize()} | {cnt} |")
        lines.append("")

        # Table of contents
        lines += ["## Findings", ""]
        for i, f in enumerate(findings, 1):
            anchor = re.sub(r"[^a-z0-9-]", "-", f"{i}-{f.vuln_type}".lower()).strip("-")
            emoji = SEVERITY_EMOJI.get(f.severity.lower(), "")
            lines.append(f"{i}. [{emoji} {f.vuln_type} — {f.endpoint}](#{anchor})")
        lines.append("")

        # Individual findings
        for i, f in enumerate(findings, 1):
            emoji = SEVERITY_EMOJI.get(f.severity.lower(), "")
            lines += [
                f"---",
                f"",
                f"### {i}. {emoji} {f.vuln_type}",
                f"",
                f"**Severity**: {f.severity.upper()}  ",
                f"**Endpoint**: `{f.endpoint}`  ",
            ]
            if f.parameter:
                lines.append(f"**Parameter**: `{f.parameter}`  ")
            if f.confidence:
                lines.append(f"**Confidence**: {int(f.confidence * 100)}%  ")
            if f.cvss:
                lines.append(f"**CVSS**: {f.cvss}  ")
            if f.tool:
                lines.append(f"**Detected by**: {f.tool}  ")
            lines.append("")

            if f.description:
                lines += ["**Description**", "", f.description, ""]

            if f.evidence:
                lines += ["**Evidence**", "", "```", f.evidence, "```", ""]

            if f.reproduction:
                lines += ["**Reproduction**", "", f.reproduction, ""]

            if f.impact:
                lines += ["**Impact**", "", f.impact, ""]

            if f.remediation:
                lines += ["**Remediation**", "", f.remediation, ""]

        return lines

    # ------------------------------------------------------------------ #
    #  JSON
    # ------------------------------------------------------------------ #

    def _write_json(self) -> Path:
        path = self._output_dir / "report.json"
        data = {
            "meta": self._meta,
            "summary": {
                "total": len(self._findings),
                "by_severity": self._severity_counts(),
            },
            "findings": [asdict(f) for f in self.sorted_findings()],
        }
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        log.info("JSON report written: %s", path)
        return path

    def _severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self._findings:
            sev = f.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    # ------------------------------------------------------------------ #
    #  HTML
    # ------------------------------------------------------------------ #

    def _write_html(self) -> Path:
        path = self._output_dir / "report.html"
        path.write_text(self._render_html(), encoding="utf-8")
        log.info("HTML report written: %s", path)
        return path

    def _render_html(self) -> str:
        findings = self.sorted_findings()
        target = html.escape(self._target or "Unknown Target")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        counts = self._severity_counts()

        rows = ""
        for i, f in enumerate(findings, 1):
            sev = f.severity.lower()
            color = SEVERITY_COLOR.get(sev, "#6b7280")
            rows += f"""
            <tr>
              <td>{i}</td>
              <td style="color:{color};font-weight:bold">{html.escape(f.severity.upper())}</td>
              <td>{html.escape(f.vuln_type)}</td>
              <td><code>{html.escape(f.endpoint)}</code></td>
              <td>{html.escape(f.parameter)}</td>
              <td>{int(f.confidence * 100)}%</td>
              <td>{html.escape(f.tool)}</td>
            </tr>"""

        summary_pills = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = counts.get(sev, 0)
            if cnt:
                color = SEVERITY_COLOR.get(sev, "#6b7280")
                summary_pills += f'<span style="background:{color};color:white;padding:4px 10px;border-radius:12px;margin:4px;display:inline-block">{sev.capitalize()}: {cnt}</span>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Report — {target}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f9fafb; color: #111827; }}
    .header {{ background: #1f2937; color: white; padding: 24px; border-radius: 8px; margin-bottom: 24px; }}
    .header h1 {{ margin: 0; font-size: 1.5rem; }}
    .meta {{ opacity: 0.7; font-size: 0.9rem; margin-top: 8px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    th {{ background: #374151; color: white; padding: 12px; text-align: left; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    td {{ padding: 12px; border-bottom: 1px solid #e5e7eb; font-size: 0.9rem; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover {{ background: #f3f4f6; }}
    code {{ background: #e5e7eb; padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; }}
    .summary {{ margin-bottom: 20px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>Vulnerability Report</h1>
    <div class="meta">Target: {target} &nbsp;|&nbsp; Generated: {now} &nbsp;|&nbsp; Platform: {html.escape(self._platform)}</div>
  </div>
  <div class="summary">{summary_pills}</div>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Type</th><th>Endpoint</th><th>Parameter</th><th>Confidence</th><th>Tool</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""


import re  # noqa: E402 (needed for _render_markdown anchor)
