"""Report generator: draft platform-ready bug bounty reports from finding data."""

import os
import re
from datetime import datetime
from pathlib import Path
from modules.utils import banner, section, ok, info, warn, bold, ask, slugify, write_text

# ── Platform format profiles ──────────────────────────────────────────────────

PLATFORM_NOTES = {
    "HackerOne": {
        "title_pattern": "[VulnType] in [Component] allows [Impact]",
        "severity_labels": ["none", "low", "medium", "high", "critical"],
        "notes": "HackerOne uses its own CVSS calculator — provide the vector string.",
    },
    "Bugcrowd": {
        "title_pattern": "[VulnType]: [Component] — [Short Impact]",
        "severity_labels": ["P5", "P4", "P3", "P2", "P1"],
        "notes": "Bugcrowd uses VRT classification. Include P-rating suggestion.",
    },
    "Intigriti": {
        "title_pattern": "[VulnType] on [Component]",
        "severity_labels": ["informational", "low", "medium", "high", "critical"],
        "notes": "Intigriti requires CWE mapping and CVSS 3.1 justification.",
    },
    "Private": {
        "title_pattern": "[VulnType] in [Component]",
        "severity_labels": ["info", "low", "medium", "high", "critical"],
        "notes": "Follow the program's own reporting template if provided.",
    },
}

# Bugcrowd VRT mapping (simplified)
BUGCROWD_VRT = {
    "sqli":              ("server-side-injection", "sql-injection", "P1"),
    "xss":               ("cross-site-scripting-xss", "reflected-xss", "P3"),
    "xss-stored":        ("cross-site-scripting-xss", "stored-xss", "P2"),
    "ssrf":              ("server-side-request-forgery-ssrf", "", "P2"),
    "idor":              ("broken-access-control", "insecure-direct-object-reference", "P2"),
    "rce":               ("remote-code-execution", "", "P1"),
    "lfi":               ("local-file-inclusion", "", "P2"),
    "ssti":              ("server-side-template-injection", "", "P1"),
    "open-redirect":     ("unvalidated-redirects-and-forwards", "open-redirect", "P4"),
    "cors":              ("broken-access-control", "cors-misconfiguration", "P3"),
    "info-disclosure":   ("sensitive-data-exposure", "server-information-disclosure", "P5"),
    "auth-bypass":       ("broken-authentication", "authentication-bypass", "P2"),
    "csrf":              ("cross-site-request-forgery-csrf", "", "P4"),
    "subdomain-takeover":("dns-vulnerability", "subdomain-takeover", "P2"),
    "xxe":               ("xml-external-entity-injection-xxe", "", "P2"),
    "command-injection": ("server-side-injection", "os-command-injection", "P1"),
}

# CWE mapping
CWE_MAP = {
    "sqli":               ("CWE-89",  "Improper Neutralization of Special Elements used in an SQL Command"),
    "xss":                ("CWE-79",  "Improper Neutralization of Input During Web Page Generation"),
    "ssrf":               ("CWE-918", "Server-Side Request Forgery"),
    "idor":               ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "rce":                ("CWE-78",  "Improper Neutralization of Special Elements used in an OS Command"),
    "lfi":                ("CWE-22",  "Improper Limitation of a Pathname to a Restricted Directory"),
    "ssti":               ("CWE-94",  "Improper Control of Generation of Code"),
    "open-redirect":      ("CWE-601", "URL Redirection to Untrusted Site"),
    "cors":               ("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
    "info-disclosure":    ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
    "auth-bypass":        ("CWE-287", "Improper Authentication"),
    "csrf":               ("CWE-352", "Cross-Site Request Forgery"),
    "subdomain-takeover": ("CWE-840", "Business Logic Errors"),
    "xxe":                ("CWE-611", "Improper Restriction of XML External Entity Reference"),
    "command-injection":  ("CWE-77",  "Improper Neutralization of Special Elements used in a Command"),
    "path-traversal":     ("CWE-22",  "Improper Limitation of a Pathname to a Restricted Directory"),
    "mass-assignment":    ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
}

OWASP_MAP = {
    "sqli":           "A03:2021 — Injection",
    "xss":            "A03:2021 — Injection",
    "ssrf":           "A10:2021 — Server-Side Request Forgery",
    "idor":           "A01:2021 — Broken Access Control",
    "rce":            "A03:2021 — Injection",
    "lfi":            "A01:2021 — Broken Access Control",
    "ssti":           "A03:2021 — Injection",
    "open-redirect":  "A01:2021 — Broken Access Control",
    "cors":           "A05:2021 — Security Misconfiguration",
    "info-disclosure":"A02:2021 — Cryptographic Failures",
    "auth-bypass":    "A07:2021 — Identification and Authentication Failures",
    "csrf":           "A01:2021 — Broken Access Control",
    "xxe":            "A05:2021 — Security Misconfiguration",
    "command-injection": "A03:2021 — Injection",
}


class ReportGenerator:
    def __init__(self, reports_dir: str, platform: str = "HackerOne"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.platform = platform

    def _normalize_vuln_type(self, vt: str) -> str:
        return vt.lower().replace(" ", "-").replace("_", "-")

    def _get_cwe(self, vuln_type: str) -> tuple[str, str]:
        return CWE_MAP.get(self._normalize_vuln_type(vuln_type),
                           ("CWE-?", "See MITRE CWE for classification"))

    def _get_owasp(self, vuln_type: str) -> str:
        return OWASP_MAP.get(self._normalize_vuln_type(vuln_type), "OWASP Top 10")

    def _bugcrowd_vrt(self, vuln_type: str) -> str:
        k = self._normalize_vuln_type(vuln_type)
        if k in BUGCROWD_VRT:
            cat, sub, rating = BUGCROWD_VRT[k]
            return f"{cat} > {sub} ({rating})" if sub else f"{cat} ({rating})"
        return f"Unclassified ({vuln_type})"

    # ── Interactive report drafting ───────────────────────────────────────────

    def interactive(self, finding: dict = None) -> str:
        """Build a report interactively or from a finding dict."""
        banner("Report Generator")
        pf = PLATFORM_NOTES.get(self.platform, PLATFORM_NOTES["HackerOne"])
        info(f"Platform: {self.platform}")
        info(f"Title pattern: {pf['title_pattern']}")
        print()

        f = finding or {}

        def prompt(field, default=""):
            val = f.get(field) or default
            if val:
                print(f"  {bold(field)}: {val}")
                override = ask(f"  Press Enter to keep or type new value: ").strip()
                return override if override else val
            return ask(f"  {bold(field)}: ").strip()

        title       = prompt("title")
        vuln_type   = prompt("vuln_type", "XSS")
        severity    = prompt("severity", "medium")
        cvss_score  = prompt("cvss_score", "")
        cvss_vector = prompt("cvss_vector", "")
        endpoint    = prompt("endpoint")
        method      = prompt("method", "GET")
        parameter   = prompt("parameter", "")
        description = prompt("description")
        steps       = f.get("steps_to_reproduce") or ""
        if not steps:
            print(f"\n  {bold('Steps to reproduce')} (paste multi-line, end with a blank line):")
            lines = []
            while True:
                line = input("    ")
                if not line:
                    break
                lines.append(line)
            steps = "\n".join(lines)
        impact      = prompt("impact")
        poc         = prompt("poc", "")

        cwe_id, cwe_name = self._get_cwe(vuln_type)
        owasp = self._get_owasp(vuln_type)

        return self._render(
            title=title, vuln_type=vuln_type, severity=severity,
            cvss_score=cvss_score, cvss_vector=cvss_vector,
            endpoint=endpoint, method=method, parameter=parameter,
            description=description, steps=steps, impact=impact, poc=poc,
            cwe_id=cwe_id, cwe_name=cwe_name, owasp=owasp,
        )

    def from_finding(self, finding: dict) -> str:
        """Generate a report from a findings DB record."""
        vt = finding.get("vuln_type", "")
        cwe_id, cwe_name = self._get_cwe(vt)
        owasp = self._get_owasp(vt)
        return self._render(
            title=finding.get("title", ""),
            vuln_type=vt,
            severity=finding.get("severity", "medium"),
            cvss_score=str(finding.get("cvss_score") or ""),
            cvss_vector=finding.get("cvss_vector") or "",
            endpoint=finding.get("endpoint") or "",
            method=finding.get("method") or "GET",
            parameter=finding.get("parameter") or "",
            description=finding.get("description") or "",
            steps=finding.get("steps_to_reproduce") or "",
            impact=finding.get("impact") or "",
            poc=finding.get("poc") or "",
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            owasp=owasp,
        )

    def _render(self, *, title, vuln_type, severity, cvss_score, cvss_vector,
                endpoint, method, parameter, description, steps, impact, poc,
                cwe_id, cwe_name, owasp) -> str:
        sev_upper = severity.upper() if severity else "MEDIUM"
        score_str = f"{cvss_score} ({sev_upper})" if cvss_score else sev_upper

        lines = [f"## {title}", ""]

        # Severity block
        lines += ["### Severity", ""]
        lines.append(f"**CVSS 3.1:** {score_str}")
        if cvss_vector:
            lines.append(f"**Vector:** `{cvss_vector}`")
        if self.platform == "Bugcrowd":
            lines.append(f"**VRT:** {self._bugcrowd_vrt(vuln_type)}")
        lines.append("")

        # Summary
        lines += ["### Summary", ""]
        if description:
            lines.append(description)
        else:
            lines.append(f"A {vuln_type} vulnerability exists at `{endpoint}`. "
                         "An attacker can exploit this to [describe impact].")
        lines.append("")

        # Steps
        lines += ["### Steps to Reproduce", ""]
        if steps:
            lines.append(steps)
        else:
            lines += [
                f"1. Log in as a regular user and navigate to `{endpoint}`.",
                f"2. Intercept the request with Burp Suite or browser DevTools.",
                f"3. Modify the `{parameter or '[parameter]'}` parameter to [payload].",
                "4. Observe that [vulnerable behavior].",
            ]
        lines.append("")

        # HTTP details
        if endpoint:
            lines += ["**Request:**", "", "```http"]
            lines.append(f"{method} {endpoint} HTTP/1.1")
            lines.append("Host: [target]")
            lines.append("Authorization: Bearer [token]")
            lines.append("Content-Type: application/json")
            lines.append("")
            lines.append("[request body if applicable]")
            lines += ["```", ""]

            lines += ["**Response:**", "", "```http"]
            lines += ["HTTP/1.1 200 OK", "", "[response showing vulnerability]", "```", ""]

        # PoC
        if poc:
            lines += ["### Proof of Concept", "", "```bash", poc, "```", ""]

        # Impact
        lines += ["### Impact", ""]
        if impact:
            lines.append(impact)
        else:
            lines.append("An attacker could [describe worst-case outcome], affecting [scope of users/data].")
        lines.append("")

        # Remediation
        lines += ["### Remediation", ""]
        remediation = self._remediation(vuln_type)
        lines.append(remediation)
        lines.append("")

        # References
        lines += ["### References", ""]
        lines.append(f"- {cwe_id}: {cwe_name}")
        lines.append(f"- {owasp}")
        if self.platform == "Intigriti":
            lines.append(f"- CVSS 3.1 Calculator: https://www.first.org/cvss/calculator/3.1")
        lines.append("")

        report = "\n".join(lines)

        # Save
        slug = slugify(title)[:50]
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M")
        filename = f"{sev_upper[:3].lower()}-{slug}-{timestamp}.md"
        out_path = self.reports_dir / filename
        out_path.write_text(report)

        print("\n" + report)
        ok(f"\nReport saved → {out_path}")
        return str(out_path)

    def _remediation(self, vuln_type: str) -> str:
        vt = self._normalize_vuln_type(vuln_type)
        remediations = {
            "sqli": (
                "Use parameterized queries or prepared statements. "
                "Never interpolate user input into SQL strings. "
                "Example (Python): `cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))`"
            ),
            "xss": (
                "Encode all user-supplied data before rendering in HTML. "
                "Implement a strict Content Security Policy (CSP). "
                "Use framework-provided escaping functions (e.g., `{{ value | escape }}` in Jinja2)."
            ),
            "ssrf": (
                "Validate and whitelist allowed URL schemes and destinations. "
                "Block requests to private IP ranges (RFC 1918) and cloud metadata endpoints. "
                "Use a DNS resolver that validates the final IP after resolution."
            ),
            "idor": (
                "Enforce authorization on every object access: verify the requesting user "
                "owns or has permission to access the requested resource. "
                "Avoid using predictable IDs — use random UUIDs or opaque tokens."
            ),
            "cors": (
                "Do not reflect the request Origin header blindly. "
                "Maintain an explicit allowlist of trusted origins. "
                "Never combine `Access-Control-Allow-Credentials: true` with a wildcard or reflected origin."
            ),
            "open-redirect": (
                "Validate redirect destinations against a whitelist of allowed URLs/domains. "
                "If dynamic redirects are necessary, use an indirect reference map rather than "
                "accepting full URLs from users."
            ),
            "ssti": (
                "Never pass user input directly into template rendering functions. "
                "Use sandboxed template environments where available. "
                "Separate template logic from user-controlled data."
            ),
            "xxe": (
                "Disable XML external entity processing in your XML parser. "
                "In Java: `factory.setFeature('http://xml.org/sax/features/external-general-entities', false)`. "
                "Prefer JSON for data exchange where XML is not required."
            ),
            "command-injection": (
                "Avoid passing user input to shell commands. "
                "If shell execution is necessary, use language-native APIs with argument arrays "
                "(not string interpolation). Whitelist allowed input values."
            ),
            "subdomain-takeover": (
                "Remove or update dangling DNS CNAME records pointing to decommissioned services. "
                "Implement a process to audit DNS records when services are shut down."
            ),
        }
        return remediations.get(vt, "Apply input validation, output encoding, and enforce least-privilege access control.")

    # ── Chain analysis ────────────────────────────────────────────────────────

    def chain_analysis(self, finding1: dict, finding2: dict) -> str:
        banner("Bug Chain Analysis")
        f1 = finding1.get("title", "Finding A")
        f2 = finding2.get("title", "Finding B")
        v1 = self._normalize_vuln_type(finding1.get("vuln_type", ""))
        v2 = self._normalize_vuln_type(finding2.get("vuln_type", ""))

        print(f"  Chain: [{f1}] + [{f2}]")
        print()

        # Known powerful chains
        chains = {
            ("open-redirect", "cors"):          ("High", "CORS + Open Redirect: steal authenticated responses from redirected pages"),
            ("cors", "open-redirect"):          ("High", "CORS + Open Redirect: combined for cross-origin data theft"),
            ("ssrf", "info-disclosure"):        ("Critical", "SSRF + Info Disclosure: reach internal services and extract credentials"),
            ("xss", "csrf"):                    ("High", "XSS + CSRF: bypass CSRF tokens and perform state-changing actions"),
            ("open-redirect", "xss"):           ("High", "XSS via open redirect — bypass CSP/filters"),
            ("info-disclosure", "sqli"):        ("Critical", "Leaked credentials/schema + SQLi: full database compromise"),
            ("idor", "ssrf"):                   ("Critical", "IDOR exposes internal URLs → SSRF for metadata/service access"),
            ("auth-bypass", "idor"):            ("Critical", "Auth bypass → IDOR: access any user's data without authentication"),
            ("subdomain-takeover", "cors"):     ("High", "Subdomain takeover → control CORS origin: steal authenticated data"),
            ("subdomain-takeover", "xss"):      ("High", "Subdomain takeover → persistent XSS via same-origin trust"),
        }

        chain_key = (v1, v2)
        rev_key   = (v2, v1)

        if chain_key in chains or rev_key in chains:
            severity, desc = chains.get(chain_key) or chains.get(rev_key)
            section("Chain Identified")
            print(f"  {bold('Combined Severity:')} {severity}")
            print(f"  {bold('Attack Path:')} {desc}")
            print()
            section("Exploitation Scenario")
            print(f"  1. Exploit [{f1}] to gain [initial access/data/redirect]")
            print(f"  2. Use that to amplify [{f2}]")
            print(f"  3. Combined impact: {desc}")
        else:
            section("Chain Assessment")
            print(f"  No known high-impact chain between {v1} and {v2}.")
            print(f"  Consider: can {v1} be used to reach the {v2} endpoint?")
            print(f"            does {v1} expose data needed to exploit {v2}?")
            print(f"            does {v2} affect users targeted via {v1}?")

        print()
        return chain_key
