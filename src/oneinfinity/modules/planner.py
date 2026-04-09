"""Hunt planner: generates a prioritized test plan from recon analysis data."""

import json
import os
from pathlib import Path

from oneinfinity.path_manager import resolve_output_dir
from oneinfinity.modules.utils import banner, section, ok, info, warn, bold, cyan, sev, write_text


# Priority rules: each rule has a detector and a resulting test item
PRIORITY_RULES = [
    # ── Quick wins ─────────────────────────────────────────────────────────────
    {
        "priority": 1,
        "source": "responses",
        "key": "interesting",
        "condition": lambda v: any(i.get("status") == "403" for i in v),
        "test": "Access control bypass: 403 responses found — try method override, path variation, header injection",
        "vuln_class": "Access Control",
    },
    {
        "priority": 1,
        "source": "responses",
        "key": "interesting",
        "condition": lambda v: any(i.get("status") == "401" for i in v),
        "test": "Auth endpoint analysis: 401 responses — test token manipulation, default creds, bypass headers",
        "vuln_class": "Authentication",
    },
    {
        "priority": 1,
        "source": "js",
        "key": "secrets",
        "condition": lambda v: len(v) > 0,
        "test": "Verify hardcoded secrets found in JS — test each API key/token for active access",
        "vuln_class": "Info Disclosure",
    },
    {
        "priority": 1,
        "source": "js",
        "key": "sourcemaps",
        "condition": lambda v: len(v) > 0,
        "test": "Fetch .map files to recover full source code — review for additional vulns",
        "vuln_class": "Info Disclosure",
    },
    {
        "priority": 1,
        "source": "responses",
        "key": "admin_panels",
        "condition": lambda v: len(v) > 0,
        "test": "Admin panels detected — test default creds, open registration, auth bypass",
        "vuln_class": "Authentication",
    },
    # ── CORS / Headers ─────────────────────────────────────────────────────────
    {
        "priority": 2,
        "source": "responses",
        "key": "by_status",
        "condition": lambda v: "200" in v and len(v.get("200", [])) > 0,
        "test": "CORS misconfiguration: test all 200-response hosts with evil.com origin + credentials",
        "vuln_class": "CORS",
    },
    # ── High-value subdomain targets ───────────────────────────────────────────
    {
        "priority": 2,
        "source": "subdomains",
        "key": "by_category",
        "condition": lambda v: "api" in v and len(v.get("api", [])) > 0,
        "test": "API subdomains: test IDOR, mass assignment, missing auth on discovered endpoints",
        "vuln_class": "IDOR / Auth",
    },
    {
        "priority": 2,
        "source": "subdomains",
        "key": "by_category",
        "condition": lambda v: "staging" in v or "dev" in v,
        "test": "Staging/dev environments: often have weaker auth — test for info disclosure and relaxed controls",
        "vuln_class": "Auth / Info Disclosure",
    },
    {
        "priority": 2,
        "source": "subdomains",
        "key": "by_category",
        "condition": lambda v: "infra" in v and len(v.get("infra", [])) > 0,
        "test": "Internal infra (Jenkins/Kibana/Grafana): check for open access, default creds, RCE",
        "vuln_class": "Auth / RCE",
    },
    # ── GraphQL ────────────────────────────────────────────────────────────────
    {
        "priority": 2,
        "source": "js",
        "key": "endpoints",
        "condition": lambda v: any("graphql" in e.lower() for e in v),
        "test": "GraphQL detected: test introspection, batch abuse, IDOR via mutations, depth attacks",
        "vuln_class": "GraphQL",
    },
    # ── Injection surface from JS endpoints ────────────────────────────────────
    {
        "priority": 3,
        "source": "js",
        "key": "endpoints",
        "condition": lambda v: any(
            any(p in e for p in ["{id}", "?id=", "/user/", "/account/", "/document/"])
            for e in v
        ),
        "test": "IDOR candidates in API endpoints: test ID parameters with other users' IDs",
        "vuln_class": "IDOR",
    },
    {
        "priority": 3,
        "source": "js",
        "key": "endpoints",
        "condition": lambda v: any(
            any(p in e for p in ["/webhook", "/callback", "/fetch", "/proxy", "/url"])
            for e in v
        ),
        "test": "SSRF candidates: endpoints accepting URLs — test against cloud metadata, internal services",
        "vuln_class": "SSRF",
    },
    # ── Nuclei actionable findings ─────────────────────────────────────────────
    {
        "priority": 1,
        "source": "nuclei",
        "key": "actionable",
        "condition": lambda v: any(f.get("severity") in ("critical","high") for f in v),
        "test": "Nuclei: manually verify critical/high severity findings before reporting",
        "vuln_class": "Various",
    },
    {
        "priority": 2,
        "source": "nuclei",
        "key": "actionable",
        "condition": lambda v: any(f.get("severity") == "medium" for f in v),
        "test": "Nuclei: manually verify medium severity findings, check for false positives",
        "vuln_class": "Various",
    },
    # ── WAF present ────────────────────────────────────────────────────────────
    {
        "priority": 3,
        "source": "responses",
        "key": "wafs",
        "condition": lambda v: len(v) > 0,
        "test": "WAF detected: use WAF-specific bypass payloads when testing injections",
        "vuln_class": "WAF Bypass",
    },
]

# Static tests always included regardless of recon data
STATIC_TESTS = [
    (1, "Check /.git/config, /.env, /backup.zip, /.svn/entries on all live hosts", "Info Disclosure"),
    (1, "Check /swagger.json, /openapi.json, /api/docs, /graphiql on API hosts", "API Exposure"),
    (2, "Test security headers: CSP, HSTS, X-Frame-Options on all 200 hosts", "Headers"),
    (2, "Subdomain takeover: check CNAME → unregistered services (Heroku/GH Pages/S3)", "Subdomain Takeover"),
    (3, "JWT analysis: check alg:none, weak secret (rs256→hs256 confusion), exp bypass", "Auth"),
    (3, "Race conditions: test coupon/payment/vote endpoints with concurrent requests", "Business Logic"),
    (3, "Password reset: test token reuse, host header injection, response manipulation", "Auth"),
]


class HuntPlanner:
    def __init__(self, program_dir: str):
        self.program_dir = Path(program_dir)
        self.recon_dir   = resolve_output_dir(self.program_dir / "recon")
        self.scripts_dir = self.program_dir / "scripts"

    def _load_analysis(self, name: str) -> dict:
        path = self.recon_dir / f"{name}_analysis.json"
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return {}

    def generate(self) -> str:
        """Generate a prioritized hunt plan based on available recon data."""
        # Load all available analysis results
        data = {
            "subdomains": self._load_analysis("subdomains"),
            "responses":  self._load_analysis("responses"),
            "js":         self._load_analysis("js"),
            "nuclei":     self._load_analysis("nuclei"),
        }

        has_data = any(bool(v) for v in data.values())

        banner("Hunt Plan Generator")
        if not has_data:
            warn("No recon analysis data found in ~/.oneinfinity/raw/<target>/recon/")
            info("Run: oneinfinity analyze subdomains ~/.oneinfinity/raw/<target>/recon/subdomains.txt")
            info("     oneinfinity analyze responses  ~/.oneinfinity/raw/<target>/recon/httpx_output.json")
            info("     oneinfinity analyze js         ~/.oneinfinity/raw/<target>/recon/*.js")
            info("     oneinfinity analyze nuclei     ~/.oneinfinity/raw/<target>/recon/nuclei_output.json")

        tests = {1: [], 2: [], 3: []}  # priority → items

        # Apply dynamic rules
        for rule in PRIORITY_RULES:
            source_data = data.get(rule["source"], {})
            val = source_data.get(rule["key"])
            if val is not None:
                try:
                    if rule["condition"](val):
                        tests[rule["priority"]].append(
                            (rule["test"], rule["vuln_class"])
                        )
                except Exception:
                    pass

        # Add static tests
        for priority, test, vc in STATIC_TESTS:
            tests[priority].append((test, vc))

        # Build markdown output
        lines = [f"# Hunt Plan — {self.program_dir.name}\n"]
        lines.append(f"Generated from recon data in `{self.recon_dir}`\n")

        priority_labels = {
            1: "Priority 1 — Quick Wins (test first)",
            2: "Priority 2 — High-Impact Targets",
            3: "Priority 3 — Deep Dive",
        }

        for p in [1, 2, 3]:
            if tests[p]:
                lines.append(f"\n## {priority_labels[p]}\n")
                for test, vc in tests[p]:
                    lines.append(f"- [ ] **[{vc}]** {test}")

        lines.append("\n## Scripts Available\n")
        lines.append("Generate ready-to-run test scripts with:\n")
        lines.append("```")
        lines.append("oneinfinity script cors          # CORS misconfiguration test")
        lines.append("oneinfinity script sqli          # SQL injection fuzzing")
        lines.append("oneinfinity script ssrf          # SSRF probe")
        lines.append("oneinfinity script idor          # IDOR enumeration")
        lines.append("oneinfinity script headers       # Security headers audit")
        lines.append("oneinfinity script redirect      # Open redirect test")
        lines.append("oneinfinity script subdomain-takeover  # Takeover check")
        lines.append("```")

        plan = "\n".join(lines)

        # Print to terminal
        print(plan)

        # Save to file
        out = self.program_dir / "hunt_plan.md"
        out.write_text(plan)
        print()
        ok(f"Hunt plan saved → {out}")

        return plan
