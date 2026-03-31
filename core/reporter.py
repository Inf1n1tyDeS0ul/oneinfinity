"""
Reporter — multi-format output for vulnerability findings.

Supported formats: markdown, json, html, pdf

Usage:
    reporter = Reporter(output_dir="~/.oneinfinity/raw/target.com", platform="hackerone")
    reporter.add_finding(finding_dict)
    reporter.write("html")    # Professional styled HTML report
    reporter.write("pdf")     # PDF generated via fpdf2
    reporter.write("markdown")
    reporter.write("json")
    reporter.write_executive()  # Executive summary (HTML + PDF)
"""

from __future__ import annotations

import html
import json
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#2563eb",
    "info":     "#6b7280",
}

SEVERITY_BG = {
    "critical": "#fef2f2",
    "high":     "#fff7ed",
    "medium":   "#fffbeb",
    "low":      "#eff6ff",
    "info":     "#f9fafb",
}

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}

_IMPACT_MAP = {
    "sqli":                   "Attackers could extract the entire database, including user credentials, PII, and sensitive business records, enabling full data breach.",
    "xss":                    "Users can be tricked into executing attacker-controlled JavaScript, leading to session hijacking, credential theft, and drive-by malware.",
    "ssrf":                   "Internal infrastructure and cloud metadata endpoints (AWS/GCP/Azure) may be accessed by external attackers, enabling lateral movement.",
    "cors":                   "Cross-origin requests from attacker-controlled sites can silently steal authenticated data, API keys, and perform actions on behalf of users.",
    "cors_misconfiguration":  "Misconfigured CORS headers allow unauthorized cross-origin access to authenticated APIs, exposing user data to malicious sites.",
    "idor":                   "Users can enumerate and access other users' records, accounts, or files by manipulating predictable identifiers.",
    "jwt_none_alg":           "JWT signature verification is bypassed via the 'none' algorithm, allowing attackers to forge tokens and impersonate any user including admins.",
    "auth_bypass":            "Authentication controls can be circumvented using header injection or path traversal, exposing protected endpoints without credentials.",
    "race_condition":         "Concurrent requests can exploit timing windows to trigger duplicate transactions, bypass rate limits, or corrupt shared state.",
    "information_disclosure": "Sensitive internal details (stack traces, credentials, API keys, server versions) are exposed to unauthenticated users.",
    "weak_cipher":            "Outdated TLS ciphers allow decryption of HTTPS traffic via BEAST, POODLE, or similar attacks against intercepted sessions.",
    "exploit_chain":          "Multiple vulnerabilities are chained to achieve escalating impact — from low-severity entry point to critical system compromise.",
}

_REMEDIATION_MAP = {
    "sqli":                   "Use parameterized queries or ORM frameworks. Never concatenate user input into SQL strings. Apply input validation and least-privilege DB accounts.",
    "xss":                    "Apply context-aware output encoding. Use Content-Security-Policy headers. Sanitize HTML with DOMPurify. Set HttpOnly and SameSite cookie flags.",
    "ssrf":                   "Validate and allowlist URL schemes and destinations. Block requests to RFC1918 addresses and cloud metadata IPs (169.254.169.254). Use a network egress proxy.",
    "cors":                   "Explicitly allowlist trusted origins. Avoid wildcards (*) with credentials. Validate Origin header server-side. Use vary: Origin header.",
    "cors_misconfiguration":  "Explicitly allowlist trusted origins. Remove Access-Control-Allow-Origin: * when credentials are involved.",
    "idor":                   "Enforce server-side authorization on every object access. Use indirect references (GUIDs/hashed IDs) and verify ownership before returning data.",
    "jwt_none_alg":           "Explicitly reject 'none' algorithm in JWT validation. Use an allowlist of accepted algorithms. Verify signature before trusting claims.",
    "auth_bypass":            "Remove trust in client-supplied headers (X-Forwarded-For, X-Original-URL). Apply authentication at the application layer, not only at proxies.",
    "race_condition":         "Use database-level locks, optimistic concurrency control, or atomic operations. Apply idempotency keys on sensitive endpoints.",
    "information_disclosure": "Suppress stack traces in production. Remove server version headers. Store secrets in vaults, not in responses or source code.",
    "weak_cipher":            "Disable SSLv3, TLS 1.0, TLS 1.1, RC4, DES, 3DES, and export ciphers. Enforce TLS 1.2+ with AEAD ciphers. Enable HSTS.",
    "exploit_chain":          "Address each component vulnerability individually following their specific remediations. Implement defense-in-depth across all layers.",
}


def _fmt_duration(seconds: int) -> str:
    """Format integer seconds as 'Xh Ym Zs'."""
    if seconds <= 0:
        return "N/A"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


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
    source_type: str = ""
    validation_status: str = ""   # confirmed / unverified / false_positive / simulated
    confidence_breakdown: str = ""
    poc: str = ""                  # proof-of-concept payload / request
    poc_steps: List[str] = field(default_factory=list)   # ordered reproduction steps
    reproduction_cmd: str = ""     # exact OneInfinity CLI command to reproduce
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in d.items() if k in known}
        if "endpoint" not in filtered:
            filtered["endpoint"] = d.get("url", d.get("endpoint", ""))
        if "severity" in filtered and not isinstance(filtered["severity"], str):
            filtered["severity"] = str(filtered["severity"])
        try:
            filtered["confidence"] = float(filtered.get("confidence", 0.0))
        except (TypeError, ValueError):
            filtered["confidence"] = 0.0
        try:
            filtered["cvss"] = float(filtered.get("cvss", 0.0))
        except (TypeError, ValueError):
            filtered["cvss"] = 0.0
        # Derive validation_status from source_type when not explicitly set
        if not filtered.get("validation_status"):
            st = filtered.get("source_type", "")
            if st == "tool":
                filtered["validation_status"] = "confirmed"
            elif st == "ai_theory":
                filtered["validation_status"] = "unverified"
            elif st == "simulated":
                filtered["validation_status"] = "simulated"
        # Ensure poc_steps is always a list of strings
        if "poc_steps" in filtered and not isinstance(filtered["poc_steps"], list):
            filtered["poc_steps"] = []
        return cls(**filtered)

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 5)

    def effective_impact(self) -> str:
        return self.impact or _IMPACT_MAP.get(self.vuln_type.lower(), "Potential unauthorized access or data exposure.")

    def effective_remediation(self) -> str:
        return self.remediation or _REMEDIATION_MAP.get(self.vuln_type.lower(), "Apply input validation, follow OWASP secure coding guidelines.")


class Reporter:
    """Collects findings and renders them in professional HTML, PDF, JSON, and Markdown formats."""

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

    def _severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self._findings:
            sev = f.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _overall_risk(self, counts: Dict[str, int]) -> str:
        c, h = counts.get("critical", 0), counts.get("high", 0)
        if c >= 2 or (c >= 1 and h >= 2):
            return "CRITICAL"
        elif c >= 1 or h >= 3:
            return "HIGH"
        elif h >= 1:
            return "MEDIUM"
        else:
            return "LOW"

    # ------------------------------------------------------------------ #
    #  Write dispatch
    # ------------------------------------------------------------------ #

    def write(self, fmt: str = "html") -> Path:
        fmt = fmt.lower()
        if fmt in ("md", "markdown"):
            return self._write_markdown()
        elif fmt == "json":
            return self._write_json()
        elif fmt == "html":
            return self._write_html()
        elif fmt == "pdf":
            return self._write_pdf()
        else:
            raise ValueError(f"Unknown format: {fmt}. Use html, pdf, markdown, json")

    def write_all(self, formats: List[str] = None) -> List[Path]:
        formats = formats or ["html", "pdf", "json", "markdown"]
        return [self.write(fmt) for fmt in formats]

    def write_executive(self) -> List[Path]:
        """Write executive summary as both HTML and PDF."""
        html_path = self._write_executive_html()
        try:
            pdf_path = self._write_executive_pdf()
            return [html_path, pdf_path]
        except Exception as e:
            log.warning("Executive PDF skipped: %s", e)
            return [html_path]

    def render_to_buffer(self, sections: list | None = None) -> bytes:
        """Generate PDF and return raw bytes. `sections` controls which sections appear.

        Section keys: 'exec', 'findings', 'chains', 'meta', 'remediation'.
        None (default) = all sections. Empty list = cover page only.
        """
        import tempfile
        from pathlib import Path as _Path
        tmp = _Path(tempfile.mktemp(suffix=".pdf"))
        try:
            self._render_pdf(tmp, executive=False, sections=sections)
            return tmp.read_bytes()
        finally:
            tmp.unlink(missing_ok=True)

    # ------------------------------------------------------------------ #
    #  High-Quality HTML Report
    # ------------------------------------------------------------------ #

    def _write_html(self) -> Path:
        path = self._output_dir / "report.html"
        path.write_text(self._render_html(), encoding="utf-8")
        log.info("HTML report written: %s", path)
        return path

    def _render_html(self) -> str:
        findings = self.sorted_findings()
        counts = self._severity_counts()
        target = html.escape(self._target or "Unknown Target")
        platform = html.escape(self._platform)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        risk = self._overall_risk(counts)
        risk_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#2563eb"}.get(risk, "#6b7280")

        # Stat cards
        stat_cards = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = counts.get(sev, 0)
            clr = SEVERITY_COLOR.get(sev, "#6b7280")
            stat_cards += f"""
            <div class="stat-card" style="border-top:4px solid {clr}">
              <div class="stat-number" style="color:{clr}">{cnt}</div>
              <div class="stat-label">{sev.capitalize()}</div>
            </div>"""

        # Donut chart data (inline SVG)
        donut_svg = self._donut_svg(counts)

        # Finding cards
        finding_cards = ""
        for i, f in enumerate(findings, 1):
            sev = f.severity.lower()
            clr = SEVERITY_COLOR.get(sev, "#6b7280")
            bg  = SEVERITY_BG.get(sev, "#f9fafb")
            lbl = SEVERITY_LABEL.get(sev, sev.upper())
            vuln = html.escape(f.vuln_type)
            ep   = html.escape(f.endpoint)
            conf_pct = int(f.confidence * 100)
            conf_bar_color = "#22c55e" if conf_pct >= 75 else "#f59e0b" if conf_pct >= 50 else "#ef4444"
            cvss_badge = f'<span class="cvss-badge" style="background:{clr}">{f.cvss:.1f}</span>' if f.cvss else ""
            tool_badge = f'<span class="tool-badge">{html.escape(f.tool)}</span>' if f.tool else ""
            src_badge  = f'<span class="src-badge">{html.escape(f.source_type)}</span>' if f.source_type else ""
            val_badge  = ""
            if f.validation_status == "confirmed":
                val_badge = '<span class="val-badge confirmed">✓ Confirmed</span>'
            elif f.validation_status == "rejected":
                val_badge = '<span class="val-badge rejected">✗ Rejected</span>'
            elif f.validation_status:
                val_badge = f'<span class="val-badge">{html.escape(f.validation_status)}</span>'

            impact_text = html.escape(f.effective_impact())
            remediation_text = html.escape(f.effective_remediation())

            evidence_block = ""
            if f.evidence:
                evidence_block = f"""
                <div class="section-block">
                  <div class="section-label">Evidence</div>
                  <pre class="code-block">{html.escape(f.evidence[:800])}</pre>
                </div>"""

            reproduction_block = ""
            _repro_text = f.reproduction_cmd or f.reproduction
            if _repro_text:
                reproduction_block = f"""
                <div class="section-block">
                  <div class="section-label">Reproduction Steps</div>
                  <pre class="code-block">{html.escape(_repro_text[:600])}</pre>
                </div>"""

            param_row = f'<div class="meta-item"><span class="meta-key">Parameter</span><code>{html.escape(f.parameter)}</code></div>' if f.parameter else ""
            conf_row  = f"""
                <div class="meta-item">
                  <span class="meta-key">Confidence</span>
                  <div class="conf-bar-wrap">
                    <div class="conf-bar" style="width:{conf_pct}%;background:{conf_bar_color}"></div>
                  </div>
                  <span class="conf-pct">{conf_pct}%</span>
                </div>""" if f.confidence else ""

            finding_cards += f"""
            <div class="finding-card" id="f{i}" style="border-left:5px solid {clr}">
              <div class="finding-header" style="background:{bg}">
                <div class="finding-num">{i}</div>
                <div class="finding-title-group">
                  <span class="sev-badge" style="background:{clr}">{lbl}</span>
                  {cvss_badge}
                  <span class="finding-name">{vuln}</span>
                  {tool_badge}{src_badge}{val_badge}
                </div>
              </div>
              <div class="finding-body">
                <div class="meta-row">
                  <div class="meta-item"><span class="meta-key">Endpoint</span><code class="endpoint-code">{ep}</code></div>
                  {param_row}
                  {conf_row}
                </div>
                <div class="section-block">
                  <div class="section-label">Business Impact</div>
                  <p class="section-text">{impact_text}</p>
                </div>
                {evidence_block}
                {reproduction_block}
                <div class="section-block remediation-block">
                  <div class="section-label">Remediation</div>
                  <p class="section-text">{remediation_text}</p>
                </div>
              </div>
            </div>"""

        # TOC links
        toc_links = ""
        for i, f in enumerate(findings, 1):
            sev = f.severity.lower()
            clr = SEVERITY_COLOR.get(sev, "#6b7280")
            lbl = SEVERITY_LABEL.get(sev, sev.upper())
            toc_links += f'<a href="#f{i}" class="toc-link"><span class="toc-badge" style="background:{clr}">{lbl}</span> {html.escape(f.vuln_type)} <span class="toc-ep">{html.escape(f.endpoint[:50])}</span></a>\n'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment Report — {target}</title>
  <style>
    :root {{
      --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', Roboto, sans-serif;
      --mono: 'SF Mono', 'JetBrains Mono', 'Fira Code', Consolas, monospace;
      --bg: #f1f5f9;
      --card-bg: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #64748b;
      --radius: 12px;
      --shadow: 0 1px 3px rgba(0,0,0,.08), 0 4px 16px rgba(0,0,0,.06);
    }}

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: var(--font);
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      font-size: 15px;
    }}

    /* ── Cover ── */
    .cover {{
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
      color: white;
      padding: 60px 48px 48px;
      position: relative;
      overflow: hidden;
    }}
    .cover::before {{
      content: '';
      position: absolute;
      top: -80px; right: -80px;
      width: 400px; height: 400px;
      background: radial-gradient(circle, rgba(99,102,241,.18) 0%, transparent 70%);
      pointer-events: none;
    }}
    .cover-brand {{
      font-size: 13px;
      letter-spacing: .12em;
      text-transform: uppercase;
      color: #94a3b8;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .cover-brand-dot {{ width: 8px; height: 8px; background: #6366f1; border-radius: 50%; }}
    .cover-title {{ font-size: 2.4rem; font-weight: 700; letter-spacing: -.02em; line-height: 1.2; margin-bottom: 8px; }}
    .cover-target {{ font-size: 1.3rem; color: #94a3b8; margin-bottom: 32px; }}
    .cover-meta {{
      display: flex; gap: 32px; flex-wrap: wrap;
      padding-top: 32px;
      border-top: 1px solid rgba(255,255,255,.1);
    }}
    .cover-meta-item {{ display: flex; flex-direction: column; gap: 4px; }}
    .cover-meta-key {{ font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: #64748b; }}
    .cover-meta-val {{ font-size: 15px; font-weight: 600; color: #e2e8f0; }}
    .risk-pill {{
      display: inline-block;
      padding: 6px 18px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: 700;
      letter-spacing: .06em;
      background: {risk_color};
      color: white;
    }}

    /* ── Layout ── */
    .container {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}

    /* ── Section headers ── */
    .section-title {{
      font-size: 11px;
      font-weight: 700;
      letter-spacing: .12em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 2px solid var(--border);
    }}

    /* ── Stat cards ── */
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(5, 1fr);
      gap: 16px;
      margin-bottom: 36px;
    }}
    .stat-card {{
      background: var(--card-bg);
      border-radius: var(--radius);
      padding: 20px;
      box-shadow: var(--shadow);
      text-align: center;
    }}
    .stat-number {{ font-size: 2rem; font-weight: 800; line-height: 1; }}
    .stat-label {{ font-size: 12px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .06em; }}

    /* ── Overview grid ── */
    .overview-grid {{ display: grid; grid-template-columns: 1fr 260px; gap: 24px; margin-bottom: 36px; }}
    .overview-card {{
      background: var(--card-bg);
      border-radius: var(--radius);
      padding: 24px;
      box-shadow: var(--shadow);
    }}

    /* ── Donut chart ── */
    .donut-wrap {{ display: flex; flex-direction: column; align-items: center; gap: 16px; }}
    .donut-legend {{ width: 100%; }}
    .legend-item {{ display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 13px; }}
    .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
    .legend-count {{ margin-left: auto; font-weight: 600; }}

    /* ── TOC ── */
    .toc-list {{ display: flex; flex-direction: column; gap: 6px; }}
    .toc-link {{
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 14px;
      border-radius: 8px;
      text-decoration: none;
      color: var(--text);
      transition: background .15s;
      font-size: 14px;
      border: 1px solid var(--border);
      background: var(--card-bg);
    }}
    .toc-link:hover {{ background: #f8fafc; }}
    .toc-badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: .06em;
      color: white;
      flex-shrink: 0;
    }}
    .toc-ep {{ color: var(--muted); font-size: 12px; margin-left: auto; font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 260px; }}

    /* ── Finding cards ── */
    .findings-list {{ display: flex; flex-direction: column; gap: 24px; margin-bottom: 40px; }}
    .finding-card {{
      background: var(--card-bg);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    .finding-header {{
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
    }}
    .finding-num {{
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: rgba(0,0,0,.06);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 13px;
      font-weight: 700;
      flex-shrink: 0;
    }}
    .finding-title-group {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; flex: 1; }}
    .finding-name {{ font-size: 16px; font-weight: 600; }}
    .sev-badge {{
      display: inline-block;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: .06em;
      color: white;
    }}
    .cvss-badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 700;
      color: white;
    }}
    .tool-badge, .src-badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 11px;
      background: #f1f5f9;
      color: #475569;
      border: 1px solid #e2e8f0;
    }}
    .val-badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 11px;
      background: #f1f5f9;
      color: #475569;
      border: 1px solid #e2e8f0;
    }}
    .val-badge.confirmed {{ background: #dcfce7; color: #166534; border-color: #bbf7d0; }}
    .val-badge.rejected  {{ background: #fee2e2; color: #991b1b; border-color: #fecaca; }}

    .finding-body {{ padding: 20px; }}

    .meta-row {{ display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
    .meta-item {{ display: flex; align-items: center; gap: 12px; font-size: 13px; }}
    .meta-key {{ font-weight: 600; color: var(--muted); width: 90px; flex-shrink: 0; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
    .endpoint-code {{
      font-family: var(--mono);
      font-size: 13px;
      background: #f8fafc;
      padding: 4px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
      word-break: break-all;
    }}
    code {{ font-family: var(--mono); font-size: 13px; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }}

    .conf-bar-wrap {{ flex: 1; max-width: 160px; height: 6px; background: #e2e8f0; border-radius: 999px; overflow: hidden; }}
    .conf-bar {{ height: 100%; border-radius: 999px; }}
    .conf-pct {{ font-size: 13px; font-weight: 600; }}

    .section-block {{ margin-bottom: 16px; }}
    .section-label {{
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .08em;
      color: var(--muted);
      margin-bottom: 8px;
    }}
    .section-text {{ font-size: 14px; line-height: 1.65; color: #334155; }}
    .code-block {{
      background: #0f172a;
      color: #e2e8f0;
      font-family: var(--mono);
      font-size: 12.5px;
      line-height: 1.6;
      padding: 16px;
      border-radius: 8px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .remediation-block {{ background: #f0fdf4; border-radius: 8px; padding: 16px; border: 1px solid #bbf7d0; }}
    .remediation-block .section-label {{ color: #166534; }}
    .remediation-block .section-text {{ color: #15803d; }}

    /* ── Footer ── */
    .footer {{
      text-align: center;
      padding: 32px;
      color: var(--muted);
      font-size: 13px;
      border-top: 1px solid var(--border);
      margin-top: 48px;
    }}

    /* ── Print ── */
    @media print {{
      body {{ background: white; font-size: 13px; }}
      .cover {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .stat-card, .finding-card, .overview-card {{ box-shadow: none; border: 1px solid var(--border); }}
      .finding-card {{ page-break-inside: avoid; }}
    }}

    @media (max-width: 768px) {{
      .stat-grid {{ grid-template-columns: repeat(3, 1fr); }}
      .overview-grid {{ grid-template-columns: 1fr; }}
      .toc-ep {{ display: none; }}
    }}
  </style>
</head>
<body>

<!-- Cover -->
<div class="cover">
  <div class="cover-brand"><span class="cover-brand-dot"></span>OneInfinity Security Platform</div>
  <div class="cover-title">Security Assessment Report</div>
  <div class="cover-target">{target}</div>
  <div class="cover-meta">
    <div class="cover-meta-item">
      <span class="cover-meta-key">Generated</span>
      <span class="cover-meta-val">{now}</span>
    </div>
    <div class="cover-meta-item">
      <span class="cover-meta-key">Platform</span>
      <span class="cover-meta-val">{platform}</span>
    </div>
    <div class="cover-meta-item">
      <span class="cover-meta-key">Total Findings</span>
      <span class="cover-meta-val">{len(findings)}</span>
    </div>
    <div class="cover-meta-item">
      <span class="cover-meta-key">Overall Risk</span>
      <span class="risk-pill">{risk}</span>
    </div>
  </div>
</div>

<div class="container">

  <!-- Severity stats -->
  <div class="section-title" style="margin-top:0">Severity Distribution</div>
  <div class="stat-grid">{stat_cards}</div>

  <!-- Overview: risk chart + TOC -->
  <div class="overview-grid">
    <div class="overview-card">
      <div class="section-label" style="margin-bottom:16px">Table of Contents</div>
      <div class="toc-list">{toc_links}</div>
    </div>
    <div class="overview-card">
      <div class="donut-wrap">
        {donut_svg}
        <div class="donut-legend">
          {''.join(f'<div class="legend-item"><span class="legend-dot" style="background:{SEVERITY_COLOR.get(s, "#6b7280")}"></span>{s.capitalize()}<span class="legend-count">{counts.get(s, 0)}</span></div>' for s in ["critical","high","medium","low","info"] if counts.get(s,0))}
        </div>
      </div>
    </div>
  </div>

  <!-- Findings -->
  <div class="section-title">Vulnerability Findings</div>
  <div class="findings-list">{finding_cards}</div>

</div>

<div class="footer">
  Generated by <strong>OneInfinity Security Platform</strong> &nbsp;·&nbsp; {now} &nbsp;·&nbsp; Confidential
</div>

</body>
</html>"""

    def _donut_svg(self, counts: Dict[str, int]) -> str:
        """Generate an inline SVG donut chart for severity distribution."""
        total = sum(counts.values()) or 1
        size = 160
        cx = cy = size / 2
        r = 60
        stroke_w = 24
        gap = 2

        colors = [SEVERITY_COLOR.get(s, "#6b7280") for s in ["critical", "high", "medium", "low", "info"]]
        values = [counts.get(s, 0) for s in ["critical", "high", "medium", "low", "info"]]

        circumference = 2 * 3.14159 * r
        paths = []
        offset = 0
        for val, color in zip(values, colors):
            if val == 0:
                continue
            pct = val / total
            dash = max(0, pct * circumference - gap)
            paths.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
                f'stroke-width="{stroke_w}" stroke-dasharray="{dash:.2f} {circumference:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
            )
            offset += pct * circumference

        return f"""<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e2e8f0" stroke-width="{stroke_w}"/>
  {''.join(paths)}
  <text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="central" font-size="22" font-weight="800" fill="#0f172a">{total}</text>
  <text x="{cx}" y="{cy + 18}" text-anchor="middle" font-size="10" fill="#94a3b8">FINDINGS</text>
</svg>"""

    # ------------------------------------------------------------------ #
    #  PDF Report (fpdf2)
    # ------------------------------------------------------------------ #

    def _write_pdf(self) -> Path:
        path = self._output_dir / "report.pdf"
        self._render_pdf(path, executive=False)
        log.info("PDF report written: %s", path)
        return path

    def _write_executive_pdf(self) -> Path:
        path = self._output_dir / "executive_report.pdf"
        self._render_pdf(path, executive=True)
        log.info("Executive PDF written: %s", path)
        return path

    def _render_pdf(self, path: Path, executive: bool = False, sections: list | None = None) -> None:
        from fpdf import FPDF, XPos, YPos

        findings = self.sorted_findings()
        counts   = self._severity_counts()
        target   = self._target or "Unknown Target"
        platform = self._platform
        now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        risk     = self._overall_risk(counts)

        DARK  = (15, 23, 42)      # #0f172a
        GRAY  = (100, 116, 139)   # #64748b
        LIGHT = (241, 245, 249)   # #f1f5f9
        WHITE = (255, 255, 255)
        GREEN_BG = (240, 253, 244)
        GREEN_FG = (22, 101, 52)

        SEV_RGB = {
            "critical": (220, 38,  38),
            "high":     (234, 88,  12),
            "medium":   (217, 119,  6),
            "low":      (37,  99, 235),
            "info":     (107, 114, 128),
        }

        def safe(text: str, maxlen: int = 0) -> str:
            """Strip characters unsupported by Helvetica (latin-1 range only)."""
            text = text.encode("latin-1", errors="replace").decode("latin-1")
            if maxlen and len(text) > maxlen:
                text = text[:maxlen] + "..."
            return text

        class OIPdf(FPDF):
            def normalize_text(self, text: str) -> str:
                """Silently replace unsupported characters instead of raising."""
                return text.encode("latin-1", errors="replace").decode("latin-1")

            def header(self):
                if self.page_no() == 1:
                    return
                self.set_fill_color(*DARK)
                self.rect(0, 0, 210, 10, "F")
                self.set_font("Helvetica", "B", 7)
                self.set_text_color(*WHITE)
                self.set_y(2)
                self.cell(0, 6, f"Security Assessment Report — {target}", align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self.set_text_color(*DARK)
                self.ln(2)

            def footer(self):
                self.set_y(-12)
                self.set_font("Helvetica", "", 7)
                self.set_text_color(*GRAY)
                self.cell(0, 8, f"OneInfinity Security Platform  ·  {now}  ·  Confidential  ·  Page {self.page_no()}", align="C")
                self.set_text_color(*DARK)

        pdf = OIPdf(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=18)
        pdf.set_margins(18, 14, 18)
        pdf.set_font("Helvetica", "", 10)

        # Section gating: None = all sections enabled
        _all_sections = {"exec", "findings", "chains", "meta", "remediation"}
        _active = _all_sections if sections is None else set(sections)

        def _has(key: str) -> bool:
            return key in _active

        def section_header(text: str):
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*GRAY)
            pdf.cell(0, 5, text.upper(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_draw_color(226, 232, 240)
            pdf.set_line_width(0.3)
            pdf.line(pdf.get_x(), pdf.get_y(), 192, pdf.get_y())
            pdf.ln(4)
            pdf.set_text_color(*DARK)

        # ── Cover Page ──
        pdf.add_page()
        pdf.set_fill_color(*DARK)
        pdf.rect(0, 0, 210, 297, "F")

        # Brand
        pdf.set_y(40)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(99, 102, 241)
        pdf.cell(0, 6, "* ONEINFINITY SECURITY PLATFORM", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(8)

        # Title
        pdf.set_font("Helvetica", "B", 28)
        pdf.set_text_color(*WHITE)
        pdf.cell(0, 12, "Security Assessment", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(0, 12, "Report", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(6)

        # Target
        pdf.set_font("Helvetica", "", 16)
        pdf.set_text_color(148, 163, 184)
        pdf.cell(0, 8, target, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(24)

        # Divider
        pdf.set_draw_color(51, 65, 85)
        pdf.set_line_width(0.3)
        pdf.line(30, pdf.get_y(), 180, pdf.get_y())
        pdf.ln(16)

        # Meta grid
        meta_items = [
            ("Generated", now),
            ("Platform", platform),
            ("Total Findings", str(len(findings))),
            ("Overall Risk", risk),
        ]
        col_w = 42
        start_x = (210 - col_w * len(meta_items)) / 2
        for label, value in meta_items:
            pdf.set_x(start_x)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(col_w, 5, label.upper(), align="C", new_x=XPos.RIGHT)
        pdf.ln(5)
        for label, value in meta_items:
            pdf.set_x(start_x)
            if label == "Overall Risk":
                r_rgb = SEV_RGB.get(risk.lower(), (107, 114, 128))
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(*r_rgb)
            else:
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(*WHITE)
            pdf.cell(col_w, 7, value, align="C", new_x=XPos.RIGHT)
        pdf.ln(7)
        pdf.ln(32)

        # Severity bar on cover
        bar_x, bar_y, bar_h = 30, pdf.get_y(), 8
        bar_total_w = 150
        total_f = sum(counts.values()) or 1
        cx = bar_x
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = counts.get(sev, 0)
            if cnt == 0:
                continue
            w = (cnt / total_f) * bar_total_w
            pdf.set_fill_color(*SEV_RGB.get(sev, (107, 114, 128)))
            pdf.rect(cx, bar_y, w, bar_h, "F")
            cx += w
        pdf.ln(bar_h + 6)

        # Severity legend
        legend_x = 30
        pdf.set_y(bar_y + bar_h + 4)
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = counts.get(sev, 0)
            if cnt == 0:
                continue
            pdf.set_x(legend_x)
            pdf.set_fill_color(*SEV_RGB.get(sev, (107, 114, 128)))
            pdf.rect(legend_x, pdf.get_y() + 1.5, 4, 4, "F")
            pdf.set_x(legend_x + 6)
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(148, 163, 184)
            label = f"{sev.capitalize()} ({cnt})"
            pdf.cell(32, 7, label, new_x=XPos.RIGHT)
            legend_x += 32

        if _has("exec"):
            # ── Summary Page ──
            pdf.add_page()
            pdf.set_text_color(*DARK)

            section_header("Executive Summary")

            # Risk overview box
            r_rgb = SEV_RGB.get(risk.lower(), (107, 114, 128))
            pdf.set_fill_color(r_rgb[0], r_rgb[1], r_rgb[2])
            box_y = pdf.get_y()
            pdf.rect(18, box_y, 174, 18, "F")
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(*WHITE)
            pdf.set_y(box_y + 4)
            pdf.cell(0, 10, f"Overall Risk Level: {risk}  |  {len(findings)} Vulnerabilities Found", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(6)
            pdf.set_text_color(*DARK)

            # Severity table
            section_header("Severity Breakdown")
            headers = ["Severity", "Count", "Business Exposure", "Timeframe"]
            col_ws = [30, 18, 100, 30]
            exposure_map = {
                "critical": ("Immediate breach risk — urgent remediation required", "24–48 hrs"),
                "high":     ("Significant exposure — remediate soon",               "7 days"),
                "medium":   ("Moderate risk — schedule remediation",                "30 days"),
                "low":      ("Limited exposure — next planned sprint",              "Next sprint"),
                "info":     ("Informational — no direct risk",                      "Backlog"),
            }

            pdf.set_fill_color(*DARK)
            pdf.set_text_color(*WHITE)
            pdf.set_font("Helvetica", "B", 8)
            x0 = pdf.get_x()
            for h, w in zip(headers, col_ws):
                pdf.cell(w, 7, h, border=0, fill=True, new_x=XPos.RIGHT)
            pdf.ln(7)

            pdf.set_font("Helvetica", "", 8)
            for sev in ["critical", "high", "medium", "low", "info"]:
                cnt = counts.get(sev, 0)
                if cnt == 0:
                    continue
                rgb = SEV_RGB.get(sev, (107, 114, 128))
                exp, tf = exposure_map.get(sev, ("", ""))
                row_y = pdf.get_y()
                pdf.set_fill_color(245, 247, 250)
                pdf.rect(18, row_y, 174, 7, "F")
                pdf.set_text_color(*rgb)
                pdf.set_font("Helvetica", "B", 8)
                pdf.cell(col_ws[0], 7, sev.capitalize(), new_x=XPos.RIGHT)
                pdf.set_text_color(*DARK)
                pdf.set_font("Helvetica", "B", 8)
                pdf.cell(col_ws[1], 7, str(cnt), new_x=XPos.RIGHT)
                pdf.set_font("Helvetica", "", 8)
                pdf.cell(col_ws[2], 7, exp, new_x=XPos.RIGHT)
                pdf.cell(col_ws[3], 7, tf, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(8)

        if not executive and _has("findings"):
            # ── Findings Pages ──
            for i, f in enumerate(findings, 1):
                sev  = f.severity.lower()
                rgb  = SEV_RGB.get(sev, (107, 114, 128))
                lbl  = SEVERITY_LABEL.get(sev, sev.upper())

                # Check available space (need at least 50mm for a finding)
                if pdf.get_y() > 230:
                    pdf.add_page()

                # Finding header band
                band_y = pdf.get_y()
                pdf.set_fill_color(*rgb)
                pdf.rect(18, band_y, 174, 10, "F")
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(*WHITE)
                pdf.set_y(band_y + 2)
                pdf.cell(10, 6, f"{i}.", new_x=XPos.RIGHT)
                pdf.cell(20, 6, lbl, new_x=XPos.RIGHT)
                pdf.set_font("Helvetica", "B", 9)
                cvss_str = f"  CVSS {f.cvss:.1f}" if f.cvss else ""
                pdf.cell(0, 6, f.vuln_type + cvss_str, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.ln(2)
                pdf.set_text_color(*DARK)

                # Meta row
                pdf.set_fill_color(*LIGHT)
                pdf.rect(18, pdf.get_y(), 174, 8, "F")
                pdf.set_font("Helvetica", "", 7.5)
                pdf.set_text_color(*GRAY)
                pdf.cell(20, 8, "Endpoint:", new_x=XPos.RIGHT)
                pdf.set_font("Helvetica", "B", 7.5)
                pdf.set_text_color(*DARK)
                ep_text = f.endpoint[:90] + ("…" if len(f.endpoint) > 90 else "")
                pdf.cell(90, 8, ep_text, new_x=XPos.RIGHT)
                if f.confidence:
                    pdf.set_font("Helvetica", "", 7.5)
                    pdf.set_text_color(*GRAY)
                    pdf.cell(22, 8, "Confidence:", new_x=XPos.RIGHT)
                    pdf.set_font("Helvetica", "B", 7.5)
                    pdf.set_text_color(*DARK)
                    pdf.cell(20, 8, f"{int(f.confidence*100)}%", new_x=XPos.RIGHT)
                if f.source_type:
                    pdf.set_font("Helvetica", "", 7.5)
                    pdf.set_text_color(*GRAY)
                    pdf.cell(14, 8, "Source:", new_x=XPos.RIGHT)
                    pdf.set_font("Helvetica", "B", 7.5)
                    pdf.set_text_color(*DARK)
                    pdf.cell(0, 8, f.source_type, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                else:
                    pdf.ln(8)
                pdf.ln(3)

                def label_text(label: str, text: str, bg: tuple = None, fg: tuple = DARK):
                    if not text.strip():
                        return
                    if pdf.get_y() > 245:
                        pdf.add_page()
                    pdf.set_font("Helvetica", "B", 7)
                    pdf.set_text_color(*GRAY)
                    pdf.cell(0, 4, label.upper(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(1)
                    pdf.set_font("Helvetica", "", 8.5)
                    pdf.set_text_color(*fg)
                    if bg:
                        # colored box
                        txt_h = max(8, len(text) // 70 * 4 + 8)
                        bx = pdf.get_x()
                        by = pdf.get_y()
                        pdf.set_fill_color(*bg)
                        pdf.rect(bx, by, 174, txt_h + 4, "F")
                        pdf.set_y(by + 2)
                        pdf.multi_cell(174, 4.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    else:
                        pdf.multi_cell(174, 4.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(3)
                    pdf.set_text_color(*DARK)

                label_text("Business Impact", f.effective_impact())
                if f.evidence:
                    label_text("Evidence", f.evidence[:400])
                _repro = f.reproduction_cmd or f.reproduction
                if _repro:
                    label_text("Reproduction", _repro[:300])
                label_text("Remediation", f.effective_remediation(), bg=GREEN_BG, fg=GREEN_FG)

                # Divider
                pdf.set_draw_color(226, 232, 240)
                pdf.set_line_width(0.2)
                pdf.line(18, pdf.get_y(), 192, pdf.get_y())
                pdf.ln(6)

        # ── Attack Chains Section ──
        if _has("chains"):
            chains_data = self._meta.get("attack_chains") or []
            if chains_data:
                pdf.add_page()
                section_header("Attack Chains")
                for chain in chains_data:
                    chain_text = chain.get("chain", "")
                    uplift = chain.get("cvss_uplift", "")
                    desc = chain.get("description", "")
                    if pdf.get_y() > 240:
                        pdf.add_page()
                    # Chain header band
                    band_y = pdf.get_y()
                    pdf.set_fill_color(*DARK)
                    pdf.rect(18, band_y, 174, 9, "F")
                    pdf.set_font("Helvetica", "B", 8.5)
                    pdf.set_text_color(*WHITE)
                    pdf.set_y(band_y + 2)
                    pdf.cell(0, 6, safe(chain_text, 100), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_text_color(*DARK)
                    pdf.ln(2)
                    if uplift:
                        pdf.set_font("Helvetica", "", 8)
                        pdf.set_text_color(*GRAY)
                        pdf.cell(30, 5, "CVSS Uplift:", new_x=XPos.RIGHT)
                        pdf.set_font("Helvetica", "B", 8)
                        pdf.set_text_color(220, 38, 38)
                        pdf.cell(0, 5, safe(uplift, 60), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                        pdf.set_text_color(*DARK)
                    if desc:
                        pdf.set_font("Helvetica", "", 8)
                        pdf.multi_cell(174, 4.5, safe(desc, 400), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.ln(5)
                    pdf.set_draw_color(226, 232, 240)
                    pdf.line(18, pdf.get_y(), 192, pdf.get_y())
                    pdf.ln(5)

        # ── Scan Metadata Section ──
        if _has("meta"):
            pdf.add_page()
            section_header("Scan Metadata")
            meta_rows = [
                ("Scan ID",     safe(str(self._meta.get("scan_id", "N/A")), 60)),
                ("Target",      safe(str(self._meta.get("target", target)), 80)),
                ("Status",      safe(str(self._meta.get("status", "completed")), 40)),
                ("Duration",    _fmt_duration(int(self._meta.get("scan_duration_s") or 0))),
                ("Generated",   now),
            ]
            phases = self._meta.get("phases_complete") or []
            if phases:
                meta_rows.append(("Phases Run", safe(", ".join(phases), 200)))
            for label, value in meta_rows:
                if pdf.get_y() > 250:
                    pdf.add_page()
                row_y = pdf.get_y()
                pdf.set_fill_color(245, 247, 250)
                pdf.rect(18, row_y, 174, 8, "F")
                pdf.set_font("Helvetica", "B", 8)
                pdf.set_text_color(*GRAY)
                pdf.cell(45, 8, label, new_x=XPos.RIGHT)
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(*DARK)
                pdf.multi_cell(129, 8, value, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(4)

        # ── Remediation Summary Section ──
        if _has("remediation"):
            pdf.add_page()
            section_header("Remediation Summary")
            seen_remediations: set = set()
            for sev in ["critical", "high", "medium", "low", "info"]:
                sev_findings = [f for f in findings if f.severity.lower() == sev]
                if not sev_findings:
                    continue
                rgb = SEV_RGB.get(sev, (107, 114, 128))
                pdf.set_font("Helvetica", "B", 8.5)
                pdf.set_text_color(*rgb)
                pdf.cell(0, 6, f"{sev.upper()} PRIORITY", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_text_color(*DARK)
                for f in sev_findings:
                    rem = f.effective_remediation()
                    if rem in seen_remediations:
                        continue
                    seen_remediations.add(rem)
                    if pdf.get_y() > 245:
                        pdf.add_page()
                    pdf.set_fill_color(*GREEN_BG)
                    box_start = pdf.get_y()
                    txt_h = max(10, (len(rem) // 65 + 1) * 4 + 6)
                    pdf.rect(18, box_start, 174, txt_h, "F")
                    pdf.set_y(box_start + 2)
                    pdf.set_font("Helvetica", "", 8)
                    pdf.set_text_color(*GREEN_FG)
                    pdf.multi_cell(174, 4.5, safe(rem, 500), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_text_color(*DARK)
                    pdf.ln(3)
                pdf.ln(4)

        pdf.output(str(path))

    # ------------------------------------------------------------------ #
    #  Executive HTML Report
    # ------------------------------------------------------------------ #

    def _write_executive_html(self) -> Path:
        path = self._output_dir / "executive_report.html"
        path.write_text(self._render_executive_html(), encoding="utf-8")
        log.info("Executive HTML written: %s", path)
        return path

    def _render_executive_html(self) -> str:
        findings = self.sorted_findings()
        counts   = self._severity_counts()
        target   = html.escape(self._target or "Unknown Target")
        platform = html.escape(self._platform)
        now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        risk     = self._overall_risk(counts)
        risk_color = SEVERITY_COLOR.get(risk.lower(), "#6b7280")

        exposure_map = {
            "critical": ("24–48 hrs",  "#dc2626"),
            "high":     ("7 days",     "#ea580c"),
            "medium":   ("30 days",    "#d97706"),
            "low":      ("Next sprint","#2563eb"),
            "info":     ("Backlog",    "#6b7280"),
        }

        # Risk table rows
        risk_rows = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = counts.get(sev, 0)
            if cnt == 0:
                continue
            clr = SEVERITY_COLOR.get(sev, "#6b7280")
            tf, _ = exposure_map.get(sev, ("—", clr))
            exp_map = {
                "critical": "Immediate breach risk — requires urgent remediation",
                "high":     "Significant exposure — remediate within 7 days",
                "medium":   "Moderate risk — remediate within 30 days",
                "low":      "Limited exposure — remediate in next sprint",
                "info":     "Informational — no direct risk",
            }
            risk_rows += f"""
            <tr>
              <td><span class="sev-dot" style="background:{clr}"></span><strong style="color:{clr}">{sev.capitalize()}</strong></td>
              <td style="text-align:center;font-weight:700;font-size:1.1rem">{cnt}</td>
              <td>{exp_map.get(sev,'')}</td>
              <td><span class="tf-badge" style="color:{clr};border-color:{clr}">{tf}</span></td>
            </tr>"""

        # Top issues
        top5 = [f for f in findings if f.severity.lower() in ("critical", "high")][:5]
        if not top5:
            top5 = findings[:5]

        issue_cards = ""
        for i, f in enumerate(top5, 1):
            sev = f.severity.lower()
            clr = SEVERITY_COLOR.get(sev, "#6b7280")
            lbl = SEVERITY_LABEL.get(sev, sev.upper())
            impact = html.escape(f.effective_impact())
            remediation = html.escape(f.effective_remediation())
            issue_cards += f"""
            <div class="issue-card" style="border-left:5px solid {clr}">
              <div class="issue-header">
                <span class="issue-num">{i}</span>
                <span class="issue-badge" style="background:{clr}">{lbl}</span>
                <span class="issue-title">{html.escape(f.vuln_type)}</span>
              </div>
              <div class="issue-ep">
                <strong>Affected:</strong> <code>{html.escape(f.endpoint)}</code>
              </div>
              <div class="issue-row">
                <div class="issue-block">
                  <div class="issue-label">Business Impact</div>
                  <p>{impact}</p>
                </div>
                <div class="issue-block remediation">
                  <div class="issue-label">Recommended Action</div>
                  <p>{remediation}</p>
                </div>
              </div>
            </div>"""

        # Roadmap rows
        roadmap = [
            ("P1", "Immediate", "Critical", counts.get("critical", 0), "24–48 hours",  "#dc2626"),
            ("P2", "Urgent",    "High",     counts.get("high", 0),     "7 days",       "#ea580c"),
            ("P3", "Standard",  "Medium",   counts.get("medium", 0),   "30 days",      "#d97706"),
            ("P4", "Planned",   "Low/Info", counts.get("low", 0) + counts.get("info", 0), "Next sprint", "#2563eb"),
        ]
        roadmap_rows = "".join(
            f'<tr><td><strong style="color:{clr}">{p}</strong><span class="pri-label">{urg}</span></td>'
            f'<td style="color:{clr};font-weight:600">{sev}</td>'
            f'<td style="text-align:center;font-weight:700">{cnt}</td>'
            f'<td>{tf}</td></tr>'
            for p, urg, sev, cnt, tf, clr in roadmap
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Executive Security Report — {target}</title>
  <style>
    :root {{
      --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', Roboto, sans-serif;
      --mono: 'SF Mono', 'Fira Code', Consolas, monospace;
      --dark: #0f172a; --text: #1e293b; --muted: #64748b;
      --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0;
      --radius: 12px;
    }}
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.6; font-size: 15px; }}

    .cover {{
      background: linear-gradient(135deg, #0f172a, #1e3a5f);
      color: white; padding: 64px 48px 48px;
    }}
    .cover-eyebrow {{ font-size: 11px; letter-spacing:.14em; text-transform:uppercase; color:#94a3b8; margin-bottom:12px; }}
    .cover-title {{ font-size: 2.2rem; font-weight: 800; letter-spacing: -.02em; line-height: 1.15; }}
    .cover-target {{ font-size: 1.2rem; color: #94a3b8; margin-top: 8px; margin-bottom: 36px; }}
    .cover-chips {{ display: flex; gap: 16px; flex-wrap: wrap; }}
    .chip {{ background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.15); border-radius: 8px; padding: 12px 20px; }}
    .chip-label {{ font-size: 10px; letter-spacing:.1em; text-transform: uppercase; color: #94a3b8; }}
    .chip-value {{ font-size: 15px; font-weight: 700; color: #e2e8f0; margin-top: 4px; }}
    .risk-chip .chip-value {{ color: {risk_color}; font-size: 16px; }}

    .container {{ max-width: 960px; margin: 0 auto; padding: 48px 24px; }}

    .card {{ background: var(--card); border-radius: var(--radius); border: 1px solid var(--border); padding: 28px; margin-bottom: 28px; box-shadow: 0 1px 4px rgba(0,0,0,.06); }}
    .card-title {{ font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid var(--border); }}

    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th {{ text-align: left; padding: 10px 14px; background: var(--dark); color: white; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }}
    td {{ padding: 12px 14px; border-bottom: 1px solid var(--border); }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f8fafc; }}

    .sev-dot {{ display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 8px; }}
    .tf-badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 600; border: 1.5px solid; }}

    .issue-card {{ background: var(--card); border-radius: var(--radius); border: 1px solid var(--border); margin-bottom: 16px; overflow: hidden; }}
    .issue-header {{ display: flex; align-items: center; gap: 10px; padding: 16px 20px; border-bottom: 1px solid var(--border); background: #f8fafc; }}
    .issue-num {{ width: 28px; height: 28px; border-radius: 50%; background: #e2e8f0; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; }}
    .issue-badge {{ display: inline-block; padding: 3px 10px; border-radius: 6px; font-size: 10px; font-weight: 700; color: white; letter-spacing: .06em; }}
    .issue-title {{ font-size: 16px; font-weight: 600; }}
    .issue-ep {{ padding: 10px 20px; font-size: 13px; border-bottom: 1px solid var(--border); background: #fffbf0; }}
    .issue-ep code {{ font-family: var(--mono); font-size: 12px; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; word-break: break-all; }}
    .issue-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0; }}
    .issue-block {{ padding: 16px 20px; font-size: 14px; line-height: 1.65; }}
    .issue-block.remediation {{ background: #f0fdf4; border-left: 1px solid var(--border); }}
    .issue-label {{ font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); margin-bottom: 8px; }}
    .issue-block.remediation .issue-label {{ color: #166534; }}
    .issue-block.remediation p {{ color: #15803d; }}

    .pri-label {{ margin-left: 8px; font-size: 11px; color: var(--muted); font-weight: 400; }}

    .footer {{ text-align: center; padding: 32px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 32px; }}

    @media print {{
      .cover {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .issue-card, .card {{ break-inside: avoid; }}
    }}
    @media (max-width: 640px) {{
      .cover {{ padding: 32px 24px; }}
      .cover-chips {{ flex-direction: column; }}
      .issue-row {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>

<div class="cover">
  <div class="cover-eyebrow">OneInfinity Security Platform · Executive Summary</div>
  <div class="cover-title">Security Assessment Report</div>
  <div class="cover-target">{target}</div>
  <div class="cover-chips">
    <div class="chip"><div class="chip-label">Generated</div><div class="chip-value">{now}</div></div>
    <div class="chip"><div class="chip-label">Platform</div><div class="chip-value">{platform}</div></div>
    <div class="chip"><div class="chip-label">Findings</div><div class="chip-value">{len(findings)}</div></div>
    <div class="chip risk-chip"><div class="chip-label">Overall Risk</div><div class="chip-value">{risk}</div></div>
  </div>
</div>

<div class="container">

  <div class="card">
    <div class="card-title">Risk Summary</div>
    <table>
      <thead><tr><th>Severity</th><th>Count</th><th>Business Exposure</th><th>Timeframe</th></tr></thead>
      <tbody>{risk_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <div class="card-title">Top Issues Requiring Immediate Attention</div>
    {issue_cards}
  </div>

  <div class="card">
    <div class="card-title">Remediation Roadmap</div>
    <table>
      <thead><tr><th>Priority</th><th>Severity</th><th>Count</th><th>Target Timeframe</th></tr></thead>
      <tbody>{roadmap_rows}</tbody>
    </table>
  </div>

</div>

<div class="footer">
  Generated by <strong>OneInfinity Security Platform</strong> &nbsp;·&nbsp; {now} &nbsp;·&nbsp; Confidential &nbsp;·&nbsp; For authorized recipients only
</div>
</body>
</html>"""

    # ------------------------------------------------------------------ #
    #  Markdown (kept for compatibility)
    # ------------------------------------------------------------------ #

    def _write_markdown(self) -> Path:
        path = self._output_dir / "report.md"
        lines = self._render_markdown()
        path.write_text("\n".join(lines), encoding="utf-8")
        log.info("Markdown report written: %s", path)
        return path

    def _render_markdown(self) -> List[str]:
        findings = self.sorted_findings()
        target   = self._target or "Unknown Target"
        now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        counts   = self._severity_counts()

        lines = [
            f"# Security Assessment Report — {target}",
            "",
            f"**Platform**: {self._platform}  ",
            f"**Generated**: {now}  ",
            f"**Findings**: {len(findings)}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["critical", "high", "medium", "low", "info"]:
            cnt = counts.get(sev, 0)
            if cnt:
                lines.append(f"| {sev.capitalize()} | {cnt} |")
        lines.append("")

        for i, f in enumerate(findings, 1):
            anchor = re.sub(r"[^a-z0-9-]", "-", f"{i}-{f.vuln_type}".lower()).strip("-")
            lines.append(f"{i}. [{f.severity.upper()} — {f.vuln_type}](#{anchor})")
        lines.append("")

        for i, f in enumerate(findings, 1):
            lines += [
                "---", "",
                f"### {i}. {f.vuln_type}",
                "",
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
            if f.evidence:
                lines += ["**Evidence**", "", "```", f.evidence, "```", ""]
            repro = f.reproduction_cmd or f.reproduction
            if repro:
                lines += ["**Reproduce**", "", f"```bash\n{repro}\n```", ""]
            if f.poc_steps:
                lines += ["**PoC Steps**", ""]
                for step in f.poc_steps:
                    lines.append(f"1. {step}")
                lines.append("")
            lines += ["**Impact**", "", f.effective_impact(), ""]
            lines += ["**Remediation**", "", f.effective_remediation(), ""]

        return lines

    # ------------------------------------------------------------------ #
    #  JSON
    # ------------------------------------------------------------------ #

    def _write_json(self) -> Path:
        path = self._output_dir / "report.json"
        data = {
            "meta":     self._meta,
            "summary":  {"total": len(self._findings), "by_severity": self._severity_counts()},
            "findings": [asdict(f) for f in self.sorted_findings()],
        }
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        log.info("JSON report written: %s", path)
        return path
