"""
Report Agent — generates professional bug bounty reports from confirmed findings.
Integrates with the existing ReportGenerator and adds AI-enhanced descriptions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from oneinfinity.infra.path_manager import resolve_output_dir

from oneinfinity.agents.base import BaseAgent, Task, TaskResult


class ReportAgent(BaseAgent):
    AGENT_ID = "report_agent"
    DESCRIPTION = "Generates professional bug bounty reports; integrates existing reporter"
    SPECIALIZATIONS = ["report", "report_finding", "report_chain", "report_summary"]

    def execute_task(self, task: Task) -> TaskResult:
        handler = {
            "report":          self._report_all,
            "report_finding":  self._report_single,
            "report_chain":    self._report_chain,
            "report_summary":  self._report_summary,
        }.get(task.task_type, self._report_all)

        data, findings, tools = handler(task)
        return TaskResult(
            task_id=task.task_id,
            agent_id=self.agent_id,
            task_type=task.task_type,
            target=task.target,
            success=True,
            data=data,
            findings=findings,
            tools_used=tools,
        )

    def _load_confirmed(self, out_dir: Path, task: Task) -> list[dict]:
        findings = task.context.get("confirmed_findings", [])
        if not findings:
            for fname in ["confirmed_findings.json", "findings.json"]:
                f = out_dir / fname
                if f.exists():
                    raw = json.loads(f.read_text())
                    findings = raw if isinstance(raw, list) else raw.get("findings", [])
                    if findings:
                        break
        return [f for f in (findings or []) if not f.get("false_positive")]

    def _report_all(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        reports_dir = out_dir / "reports"
        reports_dir.mkdir(exist_ok=True)

        findings = self._load_confirmed(out_dir, task)
        if not findings:
            self.log("No confirmed findings to report", "warn")
            return {"reports": []}, [], []

        platform = task.context.get("platform", "HackerOne")
        report_files = []

        for f in findings:
            if self.is_aborted():
                break
            report_path = self._generate_report(f, reports_dir, platform, task.target)
            if report_path:
                report_files.append(report_path)
                self.log(f"Report: {Path(report_path).name}", "ok")

        # Master summary report
        summary = self._build_summary_report(findings, task.target, platform)
        summary_path = str(reports_dir / "00_SUMMARY.md")
        Path(summary_path).write_text(summary)
        report_files.insert(0, summary_path)
        self.log(f"Summary report: {summary_path}", "ok")

        return {"reports": report_files, "count": len(report_files)}, [], []

    def _generate_report(self, finding: dict, reports_dir: Path,
                          platform: str, target: str) -> str:
        """Generate a markdown report for one finding."""
        vuln_type = finding.get("vuln_type", "Unknown")
        severity = finding.get("severity", "info")
        endpoint = finding.get("matched_at", finding.get("url", finding.get("endpoint", "")))
        title = finding.get("name", finding.get("title", vuln_type))
        description = finding.get("description", finding.get("evidence", ""))
        cvss = finding.get("cvss_score", "N/A")
        steps = finding.get("steps_to_reproduce", self._auto_steps(finding))
        impact = finding.get("impact", self._auto_impact(vuln_type, severity))

        safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)[:40]
        report_path = str(reports_dir / f"{severity.upper()}_{safe_title}.md")

        if platform == "HackerOne":
            content = self._hackerone_template(
                title, vuln_type, severity, cvss, endpoint, target,
                description, steps, impact, finding
            )
        else:  # Bugcrowd / generic
            content = self._generic_template(
                title, vuln_type, severity, cvss, endpoint, target,
                description, steps, impact, finding
            )

        Path(report_path).write_text(content)
        return report_path

    def _hackerone_template(self, title, vuln_type, severity, cvss,
                             endpoint, target, description, steps, impact, finding) -> str:
        return f"""# {title}

## Summary
{description or f"A {vuln_type} vulnerability was discovered at {endpoint}."}

## Severity
**{severity.upper()}** (CVSS: {cvss})

## Vulnerability Type
{vuln_type}

## Target
- **Domain**: {target}
- **Endpoint**: `{endpoint}`
- **Parameter**: `{finding.get('parameter', 'N/A')}`
- **Method**: `{finding.get('method', 'GET')}`

## Steps to Reproduce
{steps}

## Impact
{impact}

## Evidence
```
{finding.get('evidence', finding.get('payload', 'See description above'))[:500]}
```

## Proof of Concept
```python
{finding.get('poc', '# See attached PoC script')}
```

## Remediation
{self._auto_remediation(vuln_type)}

---
*Report generated by One&Infinity — {finding.get('source_tool', 'multi-agent')}*
"""

    def _generic_template(self, title, vuln_type, severity, cvss,
                           endpoint, target, description, steps, impact, finding) -> str:
        return f"""# Vulnerability Report: {title}

**Severity**: {severity.upper()} | **CVSS**: {cvss}
**Type**: {vuln_type}
**Target**: {target} — `{endpoint}`

## Description
{description or f"A {vuln_type} vulnerability exists at {endpoint}."}

## Steps to Reproduce
{steps}

## Impact
{impact}

## Remediation
{self._auto_remediation(vuln_type)}

---
Generated by One&Infinity ReportAgent
"""

    def _build_summary_report(self, findings: list, target: str, platform: str) -> str:
        sev_counts = {}
        for f in findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        total_cvss = sum(f.get("cvss_score", 0) for f in findings)
        avg_cvss = total_cvss / len(findings) if findings else 0

        sev_order = ["critical", "high", "medium", "low", "info"]
        sev_table = "\n".join(
            f"| {s.capitalize():<10} | {sev_counts.get(s, 0)} |"
            for s in sev_order if sev_counts.get(s, 0)
        )

        finding_list = "\n".join(
            f"| {i+1} | {f.get('vuln_type','?'):<35} | {f.get('severity','?'):<8} "
            f"| {f.get('cvss_score', 'N/A')} | `{str(f.get('matched_at', f.get('url','?')))[:50]}` |"
            for i, f in enumerate(sorted(
                findings,
                key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(
                    x.get("severity","info"), 5)
            ))
        )

        return f"""# Bug Bounty Assessment Summary — {target}

**Platform**: {platform}
**Total Findings**: {len(findings)}
**Average CVSS**: {avg_cvss:.1f}

## Severity Distribution

| Severity   | Count |
|------------|-------|
{sev_table}

## Findings Overview

| # | Vulnerability Type | Severity | CVSS | Endpoint |
|---|--------------------|----------|------|----------|
{finding_list}

## Next Steps
1. Review individual finding reports in this directory
2. Verify each finding manually before submission
3. Check program scope for each endpoint
4. Run `oneinfinity dedup <title>` to check for known duplicates

---
*Generated by One&Infinity Multi-Agent System*
"""

    def _report_single(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        finding = task.context.get("finding", {})
        if not finding:
            return {}, [], []
        reports_dir = out_dir / "reports"
        reports_dir.mkdir(exist_ok=True)
        path = self._generate_report(finding, reports_dir,
                                      task.context.get("platform", "HackerOne"),
                                      task.target)
        return {"report": path}, [], []

    def _report_chain(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        chains_file = out_dir / "chains.json"
        if not chains_file.exists():
            return {}, [], []

        chains = json.loads(chains_file.read_text())
        reports_dir = out_dir / "reports"
        reports_dir.mkdir(exist_ok=True)
        report_files = []

        for chain in chains:
            content = f"""# Exploit Chain: {chain.get('title', 'Unnamed')}

**Chain Type**: {chain.get('chain_type', 'Unknown')}
**Escalated Severity**: {chain.get('escalated_severity', '?').upper()}
**Original Severities**: {' + '.join(s.get('severity','?') for s in chain.get('steps', []))}

## Chain Description
{chain.get('description', '')}

## Impact
{chain.get('impact', '')}

## Steps in Chain
"""
            for i, step in enumerate(chain.get('steps', []), 1):
                content += f"\n### Step {i}: {step.get('vuln_type', 'Unknown')}\n"
                content += f"- Endpoint: `{step.get('endpoint', '?')}`\n"
                content += f"- Severity: {step.get('severity', '?')}\n"
                content += f"- Evidence: {step.get('evidence', 'N/A')}\n"

            cid = chain.get("chain_id", "chain")
            path = str(reports_dir / f"CHAIN_{cid}.md")
            Path(path).write_text(content)
            report_files.append(path)
            self.log(f"Chain report: {Path(path).name}", "ok")

        return {"chain_reports": report_files}, [], []

    def _report_summary(self, task: Task):
        out_dir = resolve_output_dir(task.context.get("output_dir"), task.target)
        findings = self._load_confirmed(out_dir, task)
        summary = self._build_summary_report(
            findings, task.target, task.context.get("platform", "HackerOne")
        )
        path = str(out_dir / "SUMMARY.md")
        Path(path).write_text(summary)
        self.log(f"Summary: {path}", "ok")
        return {"summary": path}, [], []

    # ── Auto-generate content ─────────────────────────────────────────────────

    def _auto_steps(self, f: dict) -> str:
        vuln = f.get("vuln_type", "")
        endpoint = f.get("matched_at", f.get("url", ""))
        param = f.get("parameter", "")
        payload = f.get("payload", f.get("evidence", ""))[:100]
        return (
            f"1. Navigate to `{endpoint}`\n"
            f"2. {'Inject payload into parameter `'+param+'`' if param else 'Observe the response'}\n"
            f"3. Payload used: `{payload}`\n"
            f"4. Observe the vulnerability indicator in the response\n"
        )

    def _auto_impact(self, vuln_type: str, severity: str) -> str:
        impacts = {
            "XSS":                 "An attacker can execute arbitrary JavaScript in the victim's browser, steal session cookies, perform actions on behalf of the user, and redirect to phishing pages.",
            "SQL Injection":       "An attacker can read, modify, or delete database content, bypass authentication, and potentially escalate to OS-level command execution.",
            "SSRF":                "An attacker can make the server issue requests to internal services, cloud metadata endpoints (IAM credentials), and bypass firewall rules.",
            "CRLF Injection":      "An attacker can inject arbitrary HTTP headers, perform HTTP response splitting, set malicious cookies, and facilitate XSS attacks.",
            "OS Command Injection": "An attacker can execute arbitrary operating system commands on the server with the application's privileges, leading to full system compromise.",
            "Open Redirect":       "An attacker can redirect users to malicious websites, facilitating phishing attacks and credential harvesting.",
            "Secret Exposure":     "Exposed credentials allow an attacker to authenticate as the service, access protected resources, and move laterally within the infrastructure.",
            "Subdomain Takeover":  "An attacker can claim the subdomain, host malicious content under the target's trusted domain, and conduct phishing attacks.",
        }
        return impacts.get(vuln_type,
                           f"This {severity}-severity vulnerability could allow an attacker to compromise the confidentiality, integrity, or availability of the application.")

    def _auto_remediation(self, vuln_type: str) -> str:
        remediations = {
            "XSS":                 "Encode all user-supplied data before rendering in HTML. Implement a strict Content Security Policy (CSP). Use modern frameworks that auto-escape output.",
            "SQL Injection":       "Use parameterized queries or prepared statements exclusively. Never concatenate user input into SQL strings. Apply the principle of least privilege to database accounts.",
            "SSRF":                "Validate and whitelist allowed URL schemes and hosts. Block requests to RFC1918 ranges and cloud metadata addresses. Use a separate network segment for outbound requests.",
            "CRLF Injection":      "Sanitize CR (\\r) and LF (\\n) characters from all user inputs used in HTTP headers. Use secure HTTP response construction libraries.",
            "OS Command Injection": "Never pass user input to shell commands. Use language-native APIs instead of shell execution. If shell is required, use allowlists for permitted arguments.",
            "Open Redirect":       "Validate redirect URLs against an allowlist of trusted domains. Reject any URL not starting with your application's domain.",
            "Secret Exposure":     "Immediately rotate all exposed credentials. Remove secrets from source code and use environment variables or a secrets manager (Vault, AWS Secrets Manager).",
            "Subdomain Takeover":  "Remove dangling DNS records pointing to decommissioned services. Regularly audit CNAME records and implement a subdomain monitoring process.",
        }
        return remediations.get(vuln_type, "Apply appropriate input validation, output encoding, and follow security best practices for this vulnerability class.")
