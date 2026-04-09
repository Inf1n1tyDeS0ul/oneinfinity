"""
Bounty Report Generator — Auto-generate HackerOne/Bugcrowd/Intigriti reports
"""
import json
import time
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict
from pathlib import Path
from datetime import datetime

from oneinfinity.infra.path_manager import raw_dir

logger = logging.getLogger(__name__)

# CVSS base scores per vulnerability type
CVSS_BASE: Dict[str, float] = {
    "sqli": 9.8,
    "xss": 6.1,
    "ssrf": 8.6,
    "lfi": 7.5,
    "rce": 9.8,
    "cmdi": 9.8,
    "idor": 6.5,
    "auth_bypass": 9.1,
    "open_redirect": 6.1,
    "xxe": 7.5,
    "ssti": 9.8,
    "csrf": 8.8,
    "info_disclosure": 5.3,
    "misconfig": 7.5,
    "default_creds": 9.8,
}

SEVERITY_ORDER: List[str] = ["critical", "high", "medium", "low", "info"]


@dataclass
class ReportFinding:
    id: str
    title: str
    severity: str
    vuln_type: str
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    impact: str = ""
    remediation: str = ""
    poc_steps: List[str] = field(default_factory=list)
    validated: bool = False
    bounty_estimate: int = 0
    validation_status: str = ""        # confirmed / unverified / simulated / false_positive
    reproduction_cmd: str = ""         # exact OneInfinity CLI command to reproduce
    confidence: float = 0.0
    confidence_breakdown: str = ""


@dataclass
class BountyReport:
    report_id: str
    target: str
    program: Optional[str]
    platform: str
    session_id: str
    findings: List[ReportFinding]
    generated_at: str
    summary: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    estimated_total_bounty: int

    def to_dict(self) -> dict:
        data = asdict(self)
        return data

    def save_json(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
        logger.info("Saved JSON report: %s", path)

    def save_markdown(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        gen = BountyReportGenerator()
        md = gen._render_markdown(self)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(md)
        logger.info("Saved Markdown report: %s", path)

    def save_html(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        gen = BountyReportGenerator()
        html = gen._render_html(self)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        logger.info("Saved HTML report: %s", path)


class BountyReportGenerator:
    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def generate(
        self,
        target: str,
        findings: list,
        program: Optional[str] = None,
        platform: str = "HackerOne",
        session_id: Optional[str] = None,
    ) -> BountyReport:
        """Build a fully enriched BountyReport from raw finding dicts or ReportFinding objects."""
        ts = datetime.utcnow().isoformat()
        report_id = hashlib.sha256(f"{target}{ts}".encode()).hexdigest()[:16]
        if session_id is None:
            session_id = hashlib.sha256(f"{target}{time.time()}".encode()).hexdigest()[:8]

        # Pre-validate and classify all findings before enrichment
        raw_dicts = [
            f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else {})
            for f in findings
        ]
        try:
            from oneinfinity.core.finding_validator import get_classifier
            classified = get_classifier().classify(raw_dicts)
            # Exclude confirmed false positives; keep confirmed + unverified
            validated_dicts = classified.confirmed + classified.unverified
        except Exception:
            validated_dicts = raw_dicts   # fallback: include all

        enriched: List[ReportFinding] = []
        for idx, raw in enumerate(validated_dicts):
            if isinstance(raw, ReportFinding):
                f = raw
            else:
                f = self._dict_to_finding(raw, idx)
            enriched.append(self._enrich_finding(f))

        # sort by severity
        enriched.sort(key=lambda x: SEVERITY_ORDER.index(x.severity) if x.severity in SEVERITY_ORDER else 99)

        counts = {s: sum(1 for f in enriched if f.severity == s) for s in SEVERITY_ORDER}
        total_bounty = sum(f.bounty_estimate for f in enriched)
        summary = self._generate_summary(target, enriched)

        return BountyReport(
            report_id=report_id,
            target=target,
            program=program,
            platform=platform,
            session_id=session_id,
            findings=enriched,
            generated_at=ts,
            summary=summary,
            total_findings=len(enriched),
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            estimated_total_bounty=total_bounty,
        )

    # ------------------------------------------------------------------ #
    # Enrichment
    # ------------------------------------------------------------------ #

    def _dict_to_finding(self, raw: dict, idx: int) -> ReportFinding:
        """Convert a raw dict (from tool wrappers) to ReportFinding."""
        vuln_type = (raw.get("vuln_type") or raw.get("name") or "misconfig").lower()
        severity = (raw.get("severity") or "info").lower()
        fid = raw.get("id") or hashlib.sha256(f"{vuln_type}{raw.get('url','')}{idx}".encode()).hexdigest()[:12]
        vs = raw.get("validation_status", "")
        is_validated = bool(
            raw.get("validated", False)
            or raw.get("status") == "confirmed"
            or vs == "confirmed"
        )
        return ReportFinding(
            id=fid,
            title=raw.get("title") or raw.get("name") or vuln_type.upper(),
            severity=severity,
            vuln_type=vuln_type,
            url=raw.get("url") or raw.get("endpoint") or "",
            parameter=raw.get("parameter") or raw.get("param") or "",
            payload=raw.get("payload") or "",
            evidence=raw.get("evidence") or raw.get("output") or raw.get("description") or "",
            poc_steps=raw.get("poc_steps") or [],
            validated=is_validated,
            validation_status=vs or ("confirmed" if is_validated else "unverified"),
            reproduction_cmd=raw.get("reproduction_cmd") or "",
            confidence=float(raw.get("confidence", 0.0)),
            confidence_breakdown=raw.get("confidence_breakdown", ""),
        )

    def _enrich_finding(self, f: ReportFinding) -> ReportFinding:
        """Add CVSS score, vector, impact, remediation, bounty estimate."""
        if f.cvss_score == 0.0:
            f.cvss_score = CVSS_BASE.get(f.vuln_type, 5.0)
        if not f.cvss_vector:
            f.cvss_vector = self._build_cvss_vector(f.vuln_type, f.severity)
        if not f.impact:
            f.impact = self._get_impact(f.vuln_type)
        if not f.remediation:
            f.remediation = self._get_remediation(f.vuln_type)
        if f.bounty_estimate == 0:
            f.bounty_estimate = self._estimate_bounty(f)
        if not f.poc_steps:
            f.poc_steps = self._default_poc_steps(f)
        return f

    def _build_cvss_vector(self, vuln_type: str, severity: str) -> str:
        """Return a representative CVSS 3.1 vector string for the vulnerability type."""
        vectors = {
            "sqli":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "xss":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "ssrf":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            "lfi":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "rce":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cmdi":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "idor":           "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "auth_bypass":    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "open_redirect":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "xxe":            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "ssti":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "csrf":           "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            "info_disclosure":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "misconfig":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
            "default_creds":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
        return vectors.get(vuln_type, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")

    def _get_impact(self, vuln_type: str) -> str:
        impacts = {
            "sqli": (
                "SQL Injection allows an attacker to read, modify, or delete arbitrary data in the "
                "database, bypass authentication, and potentially achieve Remote Code Execution via "
                "database-level OS command features (e.g., xp_cmdshell, INTO OUTFILE)."
            ),
            "xss": (
                "Cross-Site Scripting enables an attacker to execute arbitrary JavaScript in a victim's "
                "browser, steal session cookies, perform actions on behalf of the user, redirect to "
                "phishing pages, and exfiltrate sensitive data visible in the DOM."
            ),
            "ssrf": (
                "Server-Side Request Forgery lets an attacker force the server to make outbound requests "
                "to internal services, cloud metadata endpoints (e.g., 169.254.169.254), and other "
                "restricted hosts, potentially leaking credentials or pivoting into internal networks."
            ),
            "lfi": (
                "Local File Inclusion allows an attacker to read arbitrary files on the server filesystem "
                "including /etc/passwd, SSH private keys, application source code, and configuration files "
                "containing database passwords or API secrets."
            ),
            "rce": (
                "Remote Code Execution grants full control of the server, enabling data exfiltration, "
                "persistent backdoors, lateral movement within the internal network, and complete "
                "compromise of all data hosted on or accessible from the server."
            ),
            "cmdi": (
                "Command Injection allows execution of arbitrary OS commands with the privileges of the "
                "web application process, leading to data theft, reverse shells, and full server takeover."
            ),
            "idor": (
                "Insecure Direct Object Reference allows attackers to access or modify other users' "
                "resources by manipulating identifiers, resulting in unauthorized data access, privacy "
                "violations, and potential data manipulation."
            ),
            "auth_bypass": (
                "Authentication Bypass allows attackers to gain access to protected functionality or "
                "accounts without valid credentials, potentially compromising all user data and "
                "administrative functions."
            ),
            "open_redirect": (
                "Open Redirect can be chained with phishing attacks to redirect users from a trusted "
                "domain to a malicious site, bypassing domain-reputation filters and facilitating "
                "credential theft."
            ),
            "xxe": (
                "XML External Entity injection enables file disclosure, SSRF, and in some configurations "
                "remote code execution by exploiting XML parsers that resolve external entity references."
            ),
            "ssti": (
                "Server-Side Template Injection typically leads to Remote Code Execution because template "
                "engines provide access to the underlying runtime environment, enabling arbitrary command "
                "execution on the server."
            ),
            "csrf": (
                "Cross-Site Request Forgery tricks authenticated users into performing unintended actions "
                "such as changing account settings, making transactions, or modifying sensitive data "
                "without their knowledge."
            ),
            "info_disclosure": (
                "Information Disclosure exposes sensitive data such as internal paths, software versions, "
                "API keys, or PII that can be used to plan further attacks or directly violate privacy "
                "regulations."
            ),
            "misconfig": (
                "Security Misconfiguration can expose administrative interfaces, disable security controls, "
                "reveal stack traces, or permit unintended access to sensitive functionality."
            ),
            "default_creds": (
                "Default Credentials provide immediate administrative access to the affected service, "
                "enabling an attacker to reconfigure the system, exfiltrate data, or use it as a "
                "pivot point for further attacks."
            ),
        }
        return impacts.get(vuln_type, "This vulnerability may allow unauthorized access or data exposure.")

    def _get_remediation(self, vuln_type: str) -> str:
        remediations = {
            "sqli": (
                "Use parameterized queries or prepared statements for all database interactions. "
                "Apply an allow-list for any dynamic table/column names. Enable a WAF rule for SQLi "
                "patterns as a defence-in-depth measure."
            ),
            "xss": (
                "HTML-encode all user-supplied output using context-aware escaping (HTML, JS, CSS, URL). "
                "Implement a strict Content-Security-Policy header. Use the HttpOnly and Secure flags on "
                "session cookies."
            ),
            "ssrf": (
                "Validate and allowlist outbound request destinations on the server side. Block requests "
                "to RFC-1918 addresses and cloud metadata endpoints. Use an egress firewall to restrict "
                "the application's outbound network access."
            ),
            "lfi": (
                "Never pass user-supplied input directly to filesystem functions. Use an allowlist of "
                "permitted files/directories. Chroot the application process and apply the principle of "
                "least privilege on file permissions."
            ),
            "rce": (
                "Avoid passing user input to shell commands or eval-like functions. If OS interaction is "
                "necessary, use language-level APIs with argument arrays (never string interpolation). "
                "Sandbox the process with AppArmor/seccomp and run with minimal privileges."
            ),
            "cmdi": (
                "Avoid constructing OS commands from user input. Use safe APIs that accept argument arrays "
                "rather than shell strings. Validate input strictly and apply allowlists."
            ),
            "idor": (
                "Enforce server-side authorization checks for every resource access. Use indirect "
                "references (e.g., UUIDs mapped per-session) rather than sequential or predictable IDs. "
                "Implement comprehensive access-control tests."
            ),
            "auth_bypass": (
                "Ensure all authentication checks are performed server-side and cannot be bypassed by "
                "manipulating client-supplied data. Use a well-tested authentication library. Audit all "
                "entry points for missing or incorrect auth checks."
            ),
            "open_redirect": (
                "Validate redirect targets against a server-side allowlist of permitted domains. Avoid "
                "including user-supplied data in redirect URLs. Display an interstitial warning when "
                "redirecting to external domains."
            ),
            "xxe": (
                "Disable external entity processing in your XML parser (set FEATURE_SECURE_PROCESSING). "
                "If possible, switch to a safer data format such as JSON. Validate and sanitize all "
                "XML input before parsing."
            ),
            "ssti": (
                "Never pass raw user input to template render functions. Use a sandboxed template engine "
                "or disable dangerous globals (config, self, request). Prefer logic-less templates for "
                "user-controlled content."
            ),
            "csrf": (
                "Implement anti-CSRF tokens (synchronizer token pattern) for all state-changing requests. "
                "Verify the Origin/Referer header as a secondary defence. Use SameSite=Strict or Lax on "
                "session cookies."
            ),
            "info_disclosure": (
                "Suppress detailed error messages in production; log them server-side instead. Remove "
                "software version banners from HTTP headers and HTML comments. Audit public endpoints for "
                "sensitive data exposure."
            ),
            "misconfig": (
                "Follow CIS Benchmarks and vendor hardening guides. Disable unnecessary features and "
                "default accounts. Automate configuration audits in the CI/CD pipeline."
            ),
            "default_creds": (
                "Change all default credentials immediately after installation. Enforce a strong password "
                "policy and multi-factor authentication for administrative interfaces. Restrict admin "
                "access to trusted IP ranges where possible."
            ),
        }
        return remediations.get(vuln_type, "Apply input validation, least privilege, and follow OWASP best practices.")

    def _estimate_bounty(self, finding: ReportFinding) -> int:
        """Estimate bounty payout in USD based on severity and vulnerability type."""
        table: Dict[str, Dict[str, int]] = {
            "critical": {
                "rce":          10000,
                "sqli":          5000,
                "ssti":          5000,
                "cmdi":          5000,
                "auth_bypass":   4000,
                "default_creds": 3000,
                "ssrf":          3000,
                "_default":      2500,
            },
            "high": {
                "sqli":   2000,
                "ssrf":   2000,
                "rce":    5000,
                "xxe":    1500,
                "lfi":    1500,
                "csrf":   1000,
                "xss":     500,
                "_default": 750,
            },
            "medium": {
                "idor":            400,
                "open_redirect":   200,
                "xss":             300,
                "info_disclosure": 200,
                "misconfig":       300,
                "_default":        250,
            },
            "low": {
                "_default": 100,
            },
            "info": {
                "_default": 0,
            },
        }
        severity_map = table.get(finding.severity, table["info"])
        return severity_map.get(finding.vuln_type, severity_map["_default"])

    def _default_poc_steps(self, f: ReportFinding) -> List[str]:
        """Generate generic PoC steps when none are provided."""
        steps = [
            f"Navigate to the target URL: {f.url}",
        ]
        if f.parameter:
            steps.append(f"Locate the '{f.parameter}' parameter in the request.")
        if f.payload:
            steps.append(f"Inject the following payload: `{f.payload}`")
        steps.append("Observe the server response for indicators of vulnerability.")
        if f.evidence:
            steps.append(f"Expected evidence in response: {f.evidence[:200]}")
        return steps

    def _generate_summary(self, target: str, findings: List[ReportFinding]) -> str:
        total = len(findings)
        if total == 0:
            return (
                f"Security assessment of {target} completed. No exploitable vulnerabilities "
                f"were identified during this engagement."
            )
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
        crit = counts.get("critical", 0)
        high = counts.get("high", 0)
        med = counts.get("medium", 0)
        low = counts.get("low", 0)
        total_bounty = sum(f.bounty_estimate for f in findings)
        top_types = list({f.vuln_type for f in findings if f.severity in ("critical", "high")})[:3]
        type_str = ", ".join(top_types) if top_types else "various vulnerability classes"

        return (
            f"Security assessment of **{target}** identified **{total} vulnerabilities** "
            f"({crit} Critical, {high} High, {med} Medium, {low} Low). "
            f"High-impact findings include {type_str}. "
            f"The estimated total bounty value for all findings is **${total_bounty:,} USD**. "
            f"Immediate remediation is recommended for all Critical and High severity findings "
            f"to prevent unauthorized access, data exfiltration, or service compromise."
        )

    # ------------------------------------------------------------------ #
    # Rendering
    # ------------------------------------------------------------------ #

    def _render_markdown(self, report: BountyReport) -> str:
        lines = []
        lines.append(f"# Bug Bounty Report: {report.target}")
        lines.append(f"\n**Report ID:** `{report.report_id}`  ")
        lines.append(f"**Platform:** {report.platform}  ")
        if report.program:
            lines.append(f"**Program:** {report.program}  ")
        lines.append(f"**Generated:** {report.generated_at} UTC  ")
        lines.append(f"**Session:** `{report.session_id}`")

        lines.append("\n---\n")
        lines.append("## Executive Summary\n")
        lines.append(report.summary)

        lines.append("\n---\n")
        lines.append("## Severity Breakdown\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| 🔴 Critical | {report.critical_count} |")
        lines.append(f"| 🟠 High     | {report.high_count} |")
        lines.append(f"| 🟡 Medium   | {report.medium_count} |")
        lines.append(f"| 🔵 Low      | {report.low_count} |")
        lines.append(f"| **Total**   | **{report.total_findings}** |")
        lines.append(f"\n**Estimated Total Bounty:** ${report.estimated_total_bounty:,} USD")

        lines.append("\n---\n")
        lines.append("## Findings\n")

        for i, f in enumerate(report.findings, 1):
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(f.severity, "⚪")
            lines.append(f"### {i}. {f.title}")
            lines.append(f"\n| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Severity** | {sev_icon} {f.severity.upper()} |")
            lines.append(f"| **CVSS Score** | {f.cvss_score} |")
            lines.append(f"| **CVSS Vector** | `{f.cvss_vector}` |")
            lines.append(f"| **Type** | {f.vuln_type} |")
            lines.append(f"| **URL** | `{f.url}` |")
            if f.parameter:
                lines.append(f"| **Parameter** | `{f.parameter}` |")
            lines.append(f"| **Validated** | {'Yes' if f.validated else 'No'} |")
            lines.append(f"| **Bounty Estimate** | ${f.bounty_estimate:,} |")

            if f.payload:
                lines.append(f"\n**Payload:**\n```\n{f.payload}\n```")

            if f.evidence:
                lines.append(f"\n**Evidence:**\n```\n{f.evidence}\n```")

            if f.poc_steps:
                lines.append("\n**Proof of Concept Steps:**")
                for step_num, step in enumerate(f.poc_steps, 1):
                    lines.append(f"{step_num}. {step}")

            lines.append(f"\n**Impact:**  \n{f.impact}")
            lines.append(f"\n**Remediation:**  \n{f.remediation}")
            lines.append("\n---\n")

        return "\n".join(lines)

    def _render_html(self, report: BountyReport) -> str:
        sev_colors = {
            "critical": "#e74c3c",
            "high":     "#e67e22",
            "medium":   "#f1c40f",
            "low":      "#3498db",
            "info":     "#95a5a6",
        }
        sev_text_colors = {
            "critical": "#fff",
            "high":     "#fff",
            "medium":   "#222",
            "low":      "#fff",
            "info":     "#fff",
        }

        def badge(severity: str) -> str:
            bg = sev_colors.get(severity, "#888")
            fg = sev_text_colors.get(severity, "#fff")
            return (
                f'<span style="background:{bg};color:{fg};padding:2px 8px;border-radius:4px;'
                f'font-size:0.85em;font-weight:bold;">{severity.upper()}</span>'
            )

        findings_html = ""
        for i, f in enumerate(report.findings, 1):
            poc_html = ""
            if f.poc_steps:
                poc_items = "".join(f"<li>{step}</li>" for step in f.poc_steps)
                poc_html = f"<p><strong>Proof of Concept Steps:</strong></p><ol>{poc_items}</ol>"

            evidence_html = ""
            if f.evidence:
                evidence_html = f"<p><strong>Evidence:</strong></p><pre><code>{f.evidence}</code></pre>"

            payload_html = ""
            if f.payload:
                payload_html = f"<p><strong>Payload:</strong></p><pre><code>{f.payload}</code></pre>"

            param_html = f"<tr><td>Parameter</td><td><code>{f.parameter}</code></td></tr>" if f.parameter else ""
            findings_html += f"""
        <details style="margin-bottom:16px;border:1px solid #333;border-radius:6px;overflow:hidden;">
          <summary style="background:#1e1e2e;padding:12px 16px;cursor:pointer;list-style:none;
                          display:flex;align-items:center;gap:12px;font-size:1.05em;">
            <span style="color:#aaa;min-width:24px;">{i}.</span>
            <span style="flex:1;color:#eee;">{f.title}</span>
            {badge(f.severity)}
            <span style="color:#888;font-size:0.85em;">${f.bounty_estimate:,}</span>
          </summary>
          <div style="padding:16px;background:#13131f;">
            <table style="border-collapse:collapse;width:100%;margin-bottom:12px;">
              <tr><td style="padding:4px 8px;color:#aaa;width:140px;">CVSS Score</td>
                  <td style="padding:4px 8px;color:#eee;">{f.cvss_score}</td></tr>
              <tr><td style="padding:4px 8px;color:#aaa;">CVSS Vector</td>
                  <td style="padding:4px 8px;color:#eee;font-family:monospace;font-size:0.85em;">{f.cvss_vector}</td></tr>
              <tr><td style="padding:4px 8px;color:#aaa;">Vuln Type</td>
                  <td style="padding:4px 8px;color:#eee;">{f.vuln_type}</td></tr>
              <tr><td style="padding:4px 8px;color:#aaa;">URL</td>
                  <td style="padding:4px 8px;color:#6cf;font-family:monospace;font-size:0.85em;">{f.url}</td></tr>
              {param_html}
              <tr><td style="padding:4px 8px;color:#aaa;">Validated</td>
                  <td style="padding:4px 8px;color:#eee;">{'Yes' if f.validated else 'No'}</td></tr>
            </table>
            {payload_html}
            {evidence_html}
            {poc_html}
            <p><strong style="color:#eee;">Impact:</strong></p>
            <p style="color:#ccc;">{f.impact}</p>
            <p><strong style="color:#eee;">Remediation:</strong></p>
            <p style="color:#ccc;">{f.remediation}</p>
          </div>
        </details>"""

        breakdown_rows = ""
        for sev in SEVERITY_ORDER:
            count = sum(1 for f in report.findings if f.severity == sev)
            bg = sev_colors.get(sev, "#888")
            breakdown_rows += (
                f'<tr><td style="padding:6px 12px;">{badge(sev)}</td>'
                f'<td style="padding:6px 12px;color:#eee;">{count}</td></tr>'
            )

        program_row = f"<p><strong>Program:</strong> {report.program}</p>" if report.program else ""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Bug Bounty Report — {report.target}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d0d1a; color: #ddd;
           margin: 0; padding: 0; line-height: 1.6; }}
    .container {{ max-width: 960px; margin: 0 auto; padding: 32px 16px; }}
    h1 {{ color: #fff; border-bottom: 2px solid #3498db; padding-bottom: 8px; }}
    h2 {{ color: #ccc; margin-top: 32px; }}
    pre {{ background: #1a1a2e; border: 1px solid #333; border-radius: 4px;
           padding: 12px; overflow-x: auto; color: #aef; font-size: 0.87em; }}
    code {{ font-family: 'Fira Code', monospace; }}
    table {{ border-collapse: collapse; }}
    summary::-webkit-details-marker {{ display: none; }}
    details > summary {{ user-select: none; }}
    .meta {{ color: #888; font-size: 0.9em; margin-bottom: 16px; }}
    .summary-box {{ background: #1a1a2e; border-left: 4px solid #3498db;
                   padding: 16px; border-radius: 4px; margin: 16px 0; color: #ccc; }}
    .bounty-total {{ font-size: 1.4em; color: #2ecc71; font-weight: bold; margin: 8px 0; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Bug Bounty Report: {report.target}</h1>
    <div class="meta">
      <strong>Report ID:</strong> <code>{report.report_id}</code> &nbsp;|&nbsp;
      <strong>Platform:</strong> {report.platform} &nbsp;|&nbsp;
      <strong>Generated:</strong> {report.generated_at} UTC
      {program_row}
    </div>

    <h2>Executive Summary</h2>
    <div class="summary-box">{report.summary}</div>

    <h2>Severity Breakdown</h2>
    <table style="margin-bottom:8px;">
      {breakdown_rows}
      <tr><td style="padding:6px 12px;color:#aaa;"><strong>Total</strong></td>
          <td style="padding:6px 12px;color:#eee;"><strong>{report.total_findings}</strong></td></tr>
    </table>
    <div class="bounty-total">Estimated Total Bounty: ${report.estimated_total_bounty:,} USD</div>

    <h2>Findings</h2>
    {findings_html}
  </div>
</body>
</html>"""

    # ------------------------------------------------------------------ #
    # File I/O helpers
    # ------------------------------------------------------------------ #

    def save_all_formats(self, report: BountyReport, output_dir: Optional[Path] = None) -> Dict[str, Path]:
        """Save JSON, Markdown, and HTML reports. Returns dict of format → path."""
        if output_dir is None:
            output_dir = raw_dir() / "reports" / report.report_id
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        paths = {
            "json":     output_dir / "report.json",
            "markdown": output_dir / "report.md",
            "html":     output_dir / "report.html",
        }
        report.save_json(paths["json"])
        report.save_markdown(paths["markdown"])
        report.save_html(paths["html"])
        logger.info("All reports saved to %s", output_dir)
        return paths

    # ------------------------------------------------------------------ #
    # Platform submission templates
    # ------------------------------------------------------------------ #

    def generate_hackerone_template(self, finding: ReportFinding) -> str:
        """Generate a HackerOne-formatted Markdown submission report."""
        poc_md = "\n".join(f"{i}. {s}" for i, s in enumerate(finding.poc_steps, 1))
        return f"""## Summary
{finding.title}

**Severity:** {finding.severity.upper()} (CVSS {finding.cvss_score})
**CVSS Vector:** `{finding.cvss_vector}`
**Vulnerability Type:** {finding.vuln_type}

## Description
{finding.impact}

## Steps To Reproduce
{poc_md}

## Vulnerable URL
`{finding.url}`
{"**Parameter:** `" + finding.parameter + "`" if finding.parameter else ""}

## Payload
```
{finding.payload}
```

## Evidence
```
{finding.evidence}
```

## Impact
{finding.impact}

## Remediation
{finding.remediation}

## Suggested Bounty
${finding.bounty_estimate:,} USD (based on CVSS {finding.cvss_score} and {finding.severity.upper()} severity)
"""

    def generate_bugcrowd_template(self, finding: ReportFinding) -> str:
        """Generate a Bugcrowd-formatted submission report."""
        poc_md = "\n".join(f"{i}. {s}" for i, s in enumerate(finding.poc_steps, 1))
        return f"""**Title:** {finding.title}

**VRT Category:** {finding.vuln_type.upper()}
**Severity:** {finding.severity.upper()}
**CVSS Score:** {finding.cvss_score}
**CVSS Vector:** `{finding.cvss_vector}`

---

### Target
- **URL:** `{finding.url}`
{"- **Parameter:** `" + finding.parameter + "`" if finding.parameter else ""}

### Description
{finding.impact}

### Steps to Reproduce
{poc_md}

### Proof of Concept
**Payload used:**
```
{finding.payload}
```

**Observed response / evidence:**
```
{finding.evidence}
```

### Impact Statement
{finding.impact}

### Suggested Fix
{finding.remediation}
"""


    # ------------------------------------------------------------------ #
    # Fix 5 — Submission-ready enhancements (Phase 6)
    # ------------------------------------------------------------------ #

    def calculate_confidence_score(self, finding: ReportFinding) -> float:
        """
        Score 0.0–1.0 based on evidence strength.

        Scoring criteria:
          +0.3  payload present
          +0.3  evidence present (non-trivial)
          +0.2  validated flag is True
          +0.1  poc_steps present (≥2 steps)
          +0.1  cvss_score > 0
        """
        score = 0.0
        if finding.payload and len(finding.payload) > 3:
            score += 0.3
        if finding.evidence and len(finding.evidence) > 20:
            score += 0.3
        if finding.validated:
            score += 0.2
        if finding.poc_steps and len(finding.poc_steps) >= 2:
            score += 0.1
        if finding.cvss_score > 0:
            score += 0.1
        return round(min(score, 1.0), 2)

    def strengthen_evidence(self, finding: ReportFinding) -> str:
        """
        Build a structured HTTP request/response pair block from available evidence.
        Used to enrich reports for triagers.
        """
        lines = []
        url = finding.url or "N/A"
        param = finding.parameter or "N/A"
        payload = finding.payload or "N/A"
        evidence = finding.evidence or ""

        lines.append("### HTTP Evidence")
        lines.append("```")
        lines.append(f"GET {url}")
        if finding.parameter and finding.payload:
            lines.append(f"Parameter: {param}")
            lines.append(f"Injected:  {payload}")
        lines.append("```")

        if evidence:
            lines.append("\n**Observed Response / Server Behaviour:**")
            lines.append("```")
            lines.append(evidence[:1000])
            if len(evidence) > 1000:
                lines.append(f"[... {len(evidence)-1000} bytes truncated ...]")
            lines.append("```")

        conf = self.calculate_confidence_score(finding)
        lines.append(f"\n**Evidence Confidence:** {conf:.0%}")
        return "\n".join(lines)

    def group_by_endpoint(self, findings: List[ReportFinding]) -> Dict[str, List[ReportFinding]]:
        """Group findings by normalised endpoint (path without query string)."""
        from urllib.parse import urlparse
        grouped: Dict[str, List[ReportFinding]] = {}
        for f in findings:
            try:
                parsed = urlparse(f.url)
                key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
            except Exception:
                key = f.url
            grouped.setdefault(key, []).append(f)
        return dict(sorted(grouped.items()))

    def group_by_vuln_type(self, findings: List[ReportFinding]) -> Dict[str, List[ReportFinding]]:
        """Group findings by vulnerability type, sorted by severity."""
        grouped: Dict[str, List[ReportFinding]] = {}
        for f in findings:
            grouped.setdefault(f.vuln_type, []).append(f)
        # Sort each group by severity
        for key in grouped:
            grouped[key].sort(
                key=lambda x: SEVERITY_ORDER.index(x.severity) if x.severity in SEVERITY_ORDER else 99
            )
        return dict(sorted(grouped.items()))

    def generate_ai_writeup(
        self,
        finding: ReportFinding,
        target: str,
        model: str = "claude-haiku-4-5-20251001",
    ) -> str:
        """
        Optional: Use LLM to generate a tailored impact explanation and
        reproduction steps.  Returns empty string if LLM is unavailable.

        Requires ANTHROPIC_API_KEY in environment.
        """
        try:
            import anthropic
            client = anthropic.Anthropic()
            prompt = (
                f"You are a professional bug bounty report writer. "
                f"Write a concise impact statement (2-3 sentences) and 4 numbered "
                f"reproduction steps for the following vulnerability:\n\n"
                f"Target: {target}\n"
                f"Vulnerability: {finding.vuln_type.upper()} — {finding.title}\n"
                f"URL: {finding.url}\n"
                f"Payload: {finding.payload or 'see evidence'}\n"
                f"Evidence: {finding.evidence[:300] if finding.evidence else 'N/A'}\n\n"
                f"Format:\n"
                f"IMPACT:\n<2-3 sentence impact>\n\n"
                f"STEPS:\n1. ...\n2. ...\n3. ...\n4. ..."
            )
            message = client.messages.create(
                model=model,
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text if message.content else ""
        except Exception as exc:
            logger.debug("AI writeup unavailable: %s", exc)
            return ""

    def generate_intigriti_template(self, finding: ReportFinding) -> str:
        """Generate an Intigriti-formatted submission report."""
        poc_md = "\n".join(f"{i}. {s}" for i, s in enumerate(finding.poc_steps, 1))
        conf = self.calculate_confidence_score(finding)
        return f"""# {finding.title}

**Severity:** {finding.severity.upper()}
**CVSS Score:** {finding.cvss_score} | `{finding.cvss_vector}`
**Type:** {finding.vuln_type}
**Confidence:** {conf:.0%}

---

## Affected Endpoint
`{finding.url}`{"  \n**Parameter:** `" + finding.parameter + "`" if finding.parameter else ""}

## Description
{finding.impact}

## Steps to Reproduce
{poc_md}

## Payload
```
{finding.payload or "N/A"}
```

## Proof / Evidence
```
{finding.evidence or "N/A"}
```

## Impact
{finding.impact}

## Suggested Fix
{finding.remediation}

---
*Report generated by OneInfinity | Confidence: {conf:.0%} | CVSS: {finding.cvss_score}*
"""

    def generate_submission_package(
        self,
        report: "BountyReport",
        platform: str = "hackerone",
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Path]:
        """
        Generate per-finding platform submission files + a grouped summary.

        Returns dict of filename → path.
        """
        if output_dir is None:
            output_dir = raw_dir() / "reports" / report.report_id / "submissions"
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        saved: Dict[str, Path] = {}
        platform = platform.lower()

        for f in report.findings:
            if platform == "bugcrowd":
                content = self.generate_bugcrowd_template(f)
                ext = "bugcrowd"
            elif platform == "intigriti":
                content = self.generate_intigriti_template(f)
                ext = "intigriti"
            else:
                content = self.generate_hackerone_template(f)
                ext = "hackerone"

            safe_id = f.id.replace("/", "_")[:20]
            filename = f"{safe_id}_{f.severity}_{f.vuln_type}.md"
            p = output_dir / filename
            p.write_text(content, encoding="utf-8")
            saved[filename] = p

        # Grouped summary
        by_type = self.group_by_vuln_type(report.findings)
        summary_lines = [f"# Submission Package — {report.target}\n"]
        for vtype, fs in by_type.items():
            summary_lines.append(f"\n## {vtype.upper()} ({len(fs)} finding(s))\n")
            for f in fs:
                conf = self.calculate_confidence_score(f)
                summary_lines.append(
                    f"- [{f.severity.upper()}] {f.title} — "
                    f"confidence={conf:.0%} bounty=${f.bounty_estimate:,}"
                )

        summary_path = output_dir / "SUBMISSION_SUMMARY.md"
        summary_path.write_text("\n".join(summary_lines), encoding="utf-8")
        saved["SUBMISSION_SUMMARY.md"] = summary_path

        logger.info("Submission package: %d files → %s", len(saved), output_dir)
        return saved


# Global singleton
bounty_report_generator = BountyReportGenerator()
