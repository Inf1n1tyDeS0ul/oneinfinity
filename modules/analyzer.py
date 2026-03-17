"""Recon data analysis: subdomains, httpx responses, JavaScript, Nuclei output."""

import re
import json
from collections import defaultdict
from modules.utils import (banner, section, ok, info, warn, bold,
                           cyan, sev, table, read_lines, read_jsonl, write_text)

# ── Subdomain Analyzer ────────────────────────────────────────────────────────

# Keywords that suggest high-value targets
HIGH_VALUE_KEYWORDS = [
    "admin", "api", "internal", "dev", "staging", "test", "beta",
    "dashboard", "panel", "manage", "portal", "console", "backend",
    "corp", "vpn", "git", "jenkins", "jira", "confluence", "kibana",
    "grafana", "prometheus", "sso", "auth", "login", "oauth",
    "graphql", "ws", "websocket", "mail", "smtp", "ftp", "sftp",
]

CATEGORY_MAP = {
    "api":       ["api", "ws", "websocket", "graphql", "rest", "rpc"],
    "admin":     ["admin", "panel", "manage", "portal", "console", "dashboard", "control"],
    "staging":   ["staging", "stage", "stg", "uat", "preprod"],
    "dev":       ["dev", "development", "local", "sandbox", "test", "beta", "demo"],
    "auth":      ["auth", "sso", "oauth", "login", "identity", "iam", "idp"],
    "infra":     ["jenkins", "gitlab", "github", "ci", "cd", "build", "deploy",
                  "monitor", "grafana", "kibana", "prometheus", "zabbix", "nagios"],
    "mail":      ["mail", "smtp", "mx", "email", "webmail"],
    "storage":   ["cdn", "assets", "static", "img", "media", "s3", "storage", "files"],
    "vpn":       ["vpn", "remote", "access", "jump"],
    "internal":  ["internal", "intranet", "corp", "corporate", "private"],
}


def _categorize(sub: str) -> str:
    sub_lower = sub.lower()
    for category, keywords in CATEGORY_MAP.items():
        if any(k in sub_lower.split(".")[0] for k in keywords):
            return category
    return "general"


def _is_high_value(sub: str) -> bool:
    prefix = sub.lower().split(".")[0]
    return any(kw in prefix for kw in HIGH_VALUE_KEYWORDS)


def analyze_subdomains(path: str, output_dir: str = ".") -> dict:
    """Parse a subdomain list and produce a structured analysis."""
    lines = read_lines(path)
    # Deduplicate
    subdomains = sorted(set(l.strip().lstrip("*.") for l in lines if l))

    by_category = defaultdict(list)
    high_value   = []
    patterns     = defaultdict(int)

    for sub in subdomains:
        cat = _categorize(sub)
        by_category[cat].append(sub)
        if _is_high_value(sub):
            high_value.append(sub)
        # Count second-level patterns
        parts = sub.split(".")
        if len(parts) >= 3:
            patterns[parts[0]] += 1

    banner("Subdomain Analysis")
    info(f"Total unique subdomains: {len(subdomains)}")
    info(f"High-value targets: {len(high_value)}")

    section("By Category")
    cat_rows = [{"Category": cat, "Count": str(len(subs)), "Examples": ", ".join(subs[:3])}
                for cat, subs in sorted(by_category.items(), key=lambda x: -len(x[1]))]
    table(cat_rows, ["Category", "Count", "Examples"])

    section("High-Value Targets (test first)")
    for s in high_value[:20]:
        print(f"  {bold('→')} {s}  [{_categorize(s)}]")

    # Detect naming patterns suggesting more subdomains
    section("Naming Patterns Detected")
    for prefix, count in sorted(patterns.items(), key=lambda x: -x[1])[:10]:
        print(f"  Pattern '{prefix}-*': {count} matches")

    # Save structured output
    result = {
        "total": len(subdomains),
        "all": subdomains,
        "by_category": dict(by_category),
        "high_value": high_value,
    }

    out = f"{output_dir}/subdomains_analysis.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    ok(f"Saved → {out}")

    # Write high-value list for direct use
    hv_out = f"{output_dir}/high_value_hosts.txt"
    write_text(hv_out, "\n".join(high_value))
    ok(f"High-value hosts → {hv_out}")

    return result


# ── HTTPX Response Analyzer ───────────────────────────────────────────────────

STATUS_LABELS = {
    "200": "OK",       "301": "Redirect", "302": "Redirect",
    "401": "Auth req", "403": "Forbidden","404": "Not found",
    "500": "Server err","502": "Bad GW",  "503": "Unavail",
}

INTERESTING_HEADERS = [
    "x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-varnish", "via",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "Akamai":     ["akamai", "x-check-cacheable", "x-akamai"],
    "AWS WAF":    ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"],
    "Imperva":    ["incap_ses", "_incapsula_"],
    "ModSecurity":["mod_security", "modsec"],
    "F5 BIG-IP":  ["bigipserver", "f5-trafficshield"],
    "Sucuri":     ["x-sucuri-id", "sucuri"],
}


def _detect_waf(headers: dict, cookies: str) -> str | None:
    combined = " ".join(str(v).lower() for v in headers.values()) + (cookies or "").lower()
    for waf, sigs in WAF_SIGNATURES.items():
        if any(s in combined for s in sigs):
            return waf
    return None


def analyze_responses(path: str, output_dir: str = ".") -> dict:
    """Parse httpx JSON lines output."""
    entries = read_jsonl(path)
    if not entries:
        # Try single JSON array
        try:
            with open(path) as f:
                entries = json.load(f)
            if isinstance(entries, dict):
                entries = [entries]
        except Exception:
            warn(f"Could not parse {path} as JSONL or JSON.")
            return {}

    by_status  = defaultdict(list)
    tech_map   = defaultdict(list)
    interesting = []
    wafs_found  = {}
    admin_panels = []

    for e in entries:
        url      = e.get("url") or e.get("input", "")
        status   = str(e.get("status_code") or e.get("status", ""))
        title    = e.get("title", "")
        tech     = e.get("technologies") or e.get("tech") or []
        headers  = e.get("headers") or {}
        webserver = e.get("webserver") or headers.get("server", "")

        by_status[status].append({"url": url, "title": title})

        for t in (tech if isinstance(tech, list) else [tech]):
            if t:
                tech_map[str(t)].append(url)

        # WAF detection
        waf = _detect_waf(headers, e.get("response", ""))
        if waf:
            wafs_found[url] = waf

        # Flag interesting status codes
        if status in ("401", "403", "500", "502"):
            interesting.append({"url": url, "status": status, "reason": STATUS_LABELS.get(status, "")})

        # Admin panel detection
        url_lower = url.lower() + " " + title.lower()
        if any(kw in url_lower for kw in ["admin", "panel", "dashboard", "console", "manage"]):
            admin_panels.append(url)

    banner("HTTP Response Analysis")
    info(f"Total hosts: {len(entries)}")

    section("Status Code Distribution")
    for code, hosts in sorted(by_status.items()):
        label = STATUS_LABELS.get(code, "")
        print(f"  {bold(code)} {label:<12} — {len(hosts)} hosts")

    section("Technology Stack")
    for tech, hosts in sorted(tech_map.items(), key=lambda x: -len(x[1]))[:20]:
        print(f"  {tech:<35} {len(hosts)} hosts")

    if wafs_found:
        section("WAFs / CDNs Detected")
        for url, waf in wafs_found.items():
            print(f"  {bold(waf):<20} {url}")

    if admin_panels:
        section("Admin Panels / Dashboards Found")
        for p in admin_panels:
            print(f"  {bold('→')} {p}")

    section("Interesting Responses (401/403/5xx)")
    if interesting:
        table(interesting, ["status", "url", "reason"])
    else:
        print("  None found.")

    result = {
        "total": len(entries),
        "by_status": {k: [h["url"] for h in v] for k, v in by_status.items()},
        "technologies": dict(tech_map),
        "wafs": wafs_found,
        "admin_panels": admin_panels,
        "interesting": interesting,
    }

    out = f"{output_dir}/responses_analysis.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    ok(f"Saved → {out}")
    return result


# ── JavaScript Analyzer ───────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",     "API Key"),
    (r"(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",  "Secret Key"),
    (r"(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9._\-]{20,})['\"]", "Token"),
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]",              "Password"),
    (r"AKIA[0-9A-Z]{16}",                                                        "AWS Access Key"),
    (r"(?i)(aws[_-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",          "AWS Secret"),
    (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",                 "JWT Token"),
    (r"(?i)bearer\s+([A-Za-z0-9_\-\.]{20,})",                                   "Bearer Token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",                         "Private Key"),
    (r"(?i)(gh[pousr]_[A-Za-z0-9_]{36})",                                        "GitHub Token"),
    (r"(?i)(slack[_-]?token|xox[baprs]-[0-9A-Za-z\-]+)",                        "Slack Token"),
    (r"(?i)(firebase[_-]?key|AIza[0-9A-Za-z\-_]{35})",                          "Firebase Key"),
    (r"(?i)(mapbox[_-]?token|pk\.eyJ1[A-Za-z0-9\-_\.]+)",                      "Mapbox Token"),
]

ENDPOINT_PATTERNS = [
    r"""['"](/(?:api|v\d+|graphql|rest|ws|rpc|admin|internal)[/\w\-\.\{\}?&=]*)['""]""",
    r"""fetch\s*\(\s*['"](https?://[^'"]+)['"]\s*\)""",
    r"""axios\.[a-z]+\s*\(\s*['"](/[^'"]+)['"]\s*\)""",
    r"""(?:url|endpoint|path|route)\s*[:=]\s*['"]((?:https?://|/)[^'"]{4,})['""]""",
    r"""(?:\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"]((?:https?://|/)[^'"]+)['"]\s*[,\)]""",
]

SOURCEMAP_PATTERN = r"//[#@]\s*sourceMappingURL=(.+\.map)"


def analyze_js(paths: list[str] | str, output_dir: str = ".") -> dict:
    """Analyze JavaScript file(s) for endpoints, secrets, and patterns."""
    if isinstance(paths, str):
        paths = [paths]

    all_secrets   = []
    all_endpoints = set()
    all_sourcemaps = []

    for path in paths:
        try:
            with open(path, errors="ignore") as f:
                content = f.read()
        except FileNotFoundError:
            warn(f"File not found: {path}")
            continue

        # Secrets
        for pattern, label in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                snippet = match.group(0)[:120]
                line_no = content[:match.start()].count("\n") + 1
                all_secrets.append({
                    "file":    path,
                    "line":    line_no,
                    "type":    label,
                    "snippet": snippet,
                })

        # Endpoints
        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content):
                ep = match.group(1)
                if len(ep) > 3 and not ep.endswith((".png",".jpg",".css",".ico")):
                    all_endpoints.add(ep)

        # Source maps
        for match in re.finditer(SOURCEMAP_PATTERN, content):
            all_sourcemaps.append({"file": path, "map_url": match.group(1)})

    banner("JavaScript Analysis")
    info(f"Files analyzed: {len(paths)}")
    info(f"Endpoints extracted: {len(all_endpoints)}")
    info(f"Potential secrets: {len(all_secrets)}")
    info(f"Source maps referenced: {len(all_sourcemaps)}")

    if all_secrets:
        section("Potential Secrets (VERIFY BEFORE REPORTING)")
        for s in all_secrets:
            print(f"  {sev('high', '[!]')} {s['type']:<20} {s['file']}:{s['line']}")
            print(f"      {s['snippet'][:100]}")

    if all_endpoints:
        section("API Endpoints Discovered")
        sorted_ep = sorted(all_endpoints)
        for ep in sorted_ep[:50]:
            print(f"  {ep}")
        if len(sorted_ep) > 50:
            info(f"  ... and {len(sorted_ep)-50} more (see js_analysis.json)")

    if all_sourcemaps:
        section("Source Maps (may expose full source code)")
        for sm in all_sourcemaps:
            print(f"  {bold('→')} {sm['map_url']}  (in {sm['file']})")

    result = {
        "files_analyzed": len(paths),
        "endpoints": sorted(all_endpoints),
        "secrets":   all_secrets,
        "sourcemaps": all_sourcemaps,
    }
    out = f"{output_dir}/js_analysis.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    ok(f"Saved → {out}")
    return result


# ── Nuclei Output Analyzer ────────────────────────────────────────────────────

def analyze_nuclei(path: str, output_dir: str = ".") -> dict:
    """Parse nuclei JSON lines output and prioritize findings."""
    entries = read_jsonl(path)
    if not entries:
        try:
            with open(path) as f:
                entries = json.load(f)
        except Exception:
            warn(f"Could not parse {path}")
            return {}

    findings = []
    false_positive_hints = ["ssl", "favicon", "tech-detect", "waf-detect"]

    for e in entries:
        template_id = e.get("template-id") or e.get("templateID", "")
        severity    = (e.get("info", {}).get("severity") or
                       e.get("severity") or "info").lower()
        name        = (e.get("info", {}).get("name") or
                       e.get("name") or template_id)
        host        = e.get("host") or e.get("matched-at") or ""
        matched     = e.get("matched-at") or e.get("matched") or host
        matcher     = e.get("matcher-name") or ""
        description = e.get("info", {}).get("description") or ""
        tags        = e.get("info", {}).get("tags") or []

        # Flag likely false positives
        is_fp_hint = any(t in (template_id or "").lower() for t in false_positive_hints)

        findings.append({
            "template_id": template_id,
            "name":        name,
            "severity":    severity,
            "matched":     matched,
            "matcher":     matcher,
            "description": description,
            "tags":        tags if isinstance(tags, list) else [tags],
            "fp_hint":     is_fp_hint,
        })

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 5))

    banner("Nuclei Results Analysis")
    info(f"Total findings: {len(findings)}")

    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    for s in ["critical", "high", "medium", "low", "info"]:
        if counts[s]:
            print(f"  {sev(s, s.upper()):<20} {counts[s]}")

    # Show actionable findings (non-info, non-fp-hint)
    actionable = [f for f in findings if f["severity"] not in ("info",) and not f["fp_hint"]]
    if actionable:
        section("Actionable Findings (verify these)")
        rows = [{"SEV": sev(f["severity"], f["severity"].upper()[:4]),
                 "NAME": f["name"][:45],
                 "MATCHED": f["matched"][:55]}
                for f in actionable]
        table(rows, ["SEV", "NAME", "MATCHED"])

    # Info/tech-detect findings
    info_only = [f for f in findings if f["severity"] == "info"]
    if info_only:
        section(f"Informational ({len(info_only)}) — Technology/WAF/SSL")
        for f in info_only[:10]:
            print(f"  {f['name']:<40} {f['matched'][:50]}")

    result = {
        "total": len(findings),
        "actionable": actionable,
        "all": findings,
        "by_severity": dict(counts),
    }
    out = f"{output_dir}/nuclei_analysis.json"
    with open(out, "w") as f:
        json.dump(result, f, indent=2)
    ok(f"Saved → {out}")
    return result
