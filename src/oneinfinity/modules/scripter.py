"""Script generator: produces scope-checked, rate-limited test scripts."""

import os
from pathlib import Path
from oneinfinity.modules.utils import banner, section, ok, info, warn, err, bold

# ── Script templates ──────────────────────────────────────────────────────────

SCRIPT_HEADER = '''\
#!/usr/bin/env python3
"""
TOOL    : {name}
PURPOSE : {purpose}
USAGE   : python3 {filename}
SCOPE   : Reads targets from scope.yaml — edit TARGETS below after review.

IMPORTANT: Review all TARGETS and confirm they match your authorized scope
           before executing. YOU run this script; the assistant does NOT.
"""

import sys
import time
import json
import os

# ── Rate limiter ──────────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, rpm=30):
        self.delay = 60.0 / rpm
        self._last = 0.0

    def wait(self):
        elapsed = time.time() - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.time()

rl = RateLimiter(rpm=30)  # Adjust to match program rate limits

# ── Confirmation gate ─────────────────────────────────────────────────────────
def confirm(targets, description):
    print("\\n" + "="*60)
    print(f"  {{description}}")
    print("="*60)
    print(f"\\n  Targets ({len(targets)}):")
    for t in targets: print(f"    - {{t}}")
    print("\\n  [!] Confirm these are within your authorized program scope.")
    ans = input("  [?] Continue? (yes/no): ").strip().lower()
    if ans != "yes":
        print("  [-] Aborted.")
        sys.exit(0)
'''

# ─────────────────────────────────────────────────────────────────────────────
SCRIPTS: dict[str, dict] = {

# ── CORS ─────────────────────────────────────────────────────────────────────
"cors": {
    "name": "CORS Misconfiguration Tester",
    "purpose": "Test for CORS misconfiguration on in-scope hosts",
    "filename": "test_cors.py",
    "body": '''\
try:
    import httpx
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

# ── Edit targets to match your in-scope hosts ─────────────────────────────────
TARGETS = [
    "https://api.TARGET.com",
    "https://app.TARGET.com",
]

ORIGINS = [
    "https://evil.com",
    "null",
    "https://TARGET.com.evil.com",
    "https://TARGETXcom.evil.com",
]

OUTPUT = "cors_results.json"

# ─────────────────────────────────────────────────────────────────────────────

def test_cors(client, url, origin):
    try:
        r = client.get(url, headers={"Origin": origin}, timeout=10, follow_redirects=True)
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "").lower()
        if acao and acao not in ("*",):
            severity = "HIGH" if acac == "true" else "MEDIUM"
            return {
                "url": url, "origin_sent": origin,
                "acao": acao, "acac": acac, "severity": severity,
            }
    except Exception as e:
        print(f"  [!] Error {url}: {e}")
    return None

if __name__ == "__main__":
    confirm(TARGETS, "CORS Misconfiguration Test")
    findings = []
    with httpx.Client() as client:
        for url in TARGETS:
            for origin in ORIGINS:
                rl.wait()
                result = test_cors(client, url, origin)
                if result:
                    findings.append(result)
                    print(f"  [+] {result[\'severity\']} CORS: {url} reflects {origin}")
                    print(f"      ACAO: {result[\'acao\']} | ACAC: {result[\'acac\']}")
    if findings:
        with open(OUTPUT, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"\\n  [+] {len(findings)} findings saved → {OUTPUT}")
    else:
        print("\\n  [-] No CORS misconfigurations found.")
''',
},

# ── Headers ───────────────────────────────────────────────────────────────────
"headers": {
    "name": "Security Headers Auditor",
    "purpose": "Audit security headers on in-scope hosts",
    "filename": "test_headers.py",
    "body": '''\
try:
    import httpx
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

TARGETS = [
    "https://TARGET.com",
]

REQUIRED_HEADERS = {
    "strict-transport-security": "HSTS missing",
    "content-security-policy":   "CSP missing",
    "x-frame-options":           "Clickjacking possible",
    "x-content-type-options":    "MIME sniffing possible",
    "referrer-policy":           "Referrer policy missing",
    "permissions-policy":        "Permissions policy missing",
}

LEAK_HEADERS = ["x-powered-by", "server", "x-aspnet-version",
                "x-aspnetmvc-version", "x-generator"]

OUTPUT = "headers_audit.json"

def audit_host(client, url):
    try:
        r = client.get(url, timeout=10, follow_redirects=True)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        missing = {k: v for k, v in REQUIRED_HEADERS.items() if k not in hdrs}
        leaking = {k: hdrs[k] for k in LEAK_HEADERS if k in hdrs}
        return {
            "url": url, "status": r.status_code,
            "missing_headers": missing,
            "leaking_headers": leaking,
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

if __name__ == "__main__":
    confirm(TARGETS, "Security Headers Audit")
    results = []
    with httpx.Client() as client:
        for url in TARGETS:
            rl.wait()
            r = audit_host(client, url)
            results.append(r)
            if r.get("missing_headers"):
                print(f"  [!] {url}")
                for h, msg in r["missing_headers"].items():
                    print(f"      MISSING: {h} — {msg}")
            if r.get("leaking_headers"):
                print(f"  [~] {url} leaks:")
                for h, v in r["leaking_headers"].items():
                    print(f"      {h}: {v}")
    with open(OUTPUT, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\\n  [+] Results → {OUTPUT}")
''',
},

# ── Open Redirect ─────────────────────────────────────────────────────────────
"redirect": {
    "name": "Open Redirect Tester",
    "purpose": "Test for open redirect vulnerabilities on common parameters",
    "filename": "test_redirect.py",
    "body": '''\
try:
    import httpx
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

BASE_URLS = [
    "https://TARGET.com",
]

REDIRECT_PARAMS = ["url", "next", "redirect", "redirect_url", "return",
                   "return_url", "goto", "dest", "destination", "redir",
                   "location", "target", "link", "continue", "forward"]

PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\\\evil.com",
    "https://TARGET.com.evil.com",
    "%2F%2Fevil.com",
    "https:evil.com",
]

OUTPUT = "redirect_results.json"

def test(client, base, param, payload):
    url = f"{base}?{param}={payload}"
    try:
        r = client.get(url, timeout=10, follow_redirects=False)
        loc = r.headers.get("location", "")
        if "evil.com" in loc or (loc and not loc.startswith("/")):
            return {"url": url, "location": loc, "status": r.status_code}
    except Exception:
        pass
    return None

if __name__ == "__main__":
    confirm(BASE_URLS, "Open Redirect Test")
    findings = []
    with httpx.Client() as client:
        for base in BASE_URLS:
            for param in REDIRECT_PARAMS:
                for payload in PAYLOADS:
                    rl.wait()
                    result = test(client, base, param, payload)
                    if result:
                        findings.append(result)
                        print(f"  [+] Redirect: {result[\'url\']}")
                        print(f"      Location: {result[\'location\']}")
    if findings:
        with open(OUTPUT, "w") as f: json.dump(findings, f, indent=2)
        print(f"\\n  [+] {len(findings)} findings → {OUTPUT}")
    else:
        print("\\n  [-] No open redirects found.")
''',
},

# ── SSRF ──────────────────────────────────────────────────────────────────────
"ssrf": {
    "name": "SSRF Probe Script",
    "purpose": "Identify SSRF candidates; does NOT auto-exfiltrate. Logs which endpoints accept URLs.",
    "filename": "test_ssrf.py",
    "body": '''\
try:
    import httpx
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

# Endpoints that accept URL parameters — fill from JS analysis
URL_PARAMS = [
    # ("https://api.TARGET.com/webhook", "POST", "url"),
    # ("https://api.TARGET.com/fetch",   "GET",  "target"),
]

# Use an out-of-band interaction URL from Burp Collaborator or webhook.site
# Replace with your own OOB endpoint
OOB_URL = "https://YOUR-BURP-COLLABORATOR-OR-WEBHOOK.site"

INTERNAL_PROBES = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",           # GCP metadata
    "http://169.254.169.254/metadata/v1/",        # Azure metadata
]

OUTPUT = "ssrf_candidates.json"

def probe(client, url, method, param, target):
    try:
        if method.upper() == "POST":
            r = client.post(url, json={param: target}, timeout=10)
        else:
            r = client.get(url, params={param: target}, timeout=10)
        return {
            "endpoint": url, "param": param, "probed": target,
            "status": r.status_code, "size": len(r.content),
            "note": "Review response for internal data"
        }
    except Exception as e:
        return {"endpoint": url, "param": param, "probed": target, "error": str(e)}

if __name__ == "__main__":
    if not URL_PARAMS:
        print("[!] No URL_PARAMS defined. Fill from JS analysis output.")
        sys.exit(0)
    targets = [u for u, _, _ in URL_PARAMS]
    confirm(targets, "SSRF Probe (OOB + internal probe)")
    print(f"\\n[!] OOB URL: {OOB_URL}")
    print("[!] Monitor your OOB endpoint for callbacks during this test.\\n")
    results = []
    with httpx.Client(follow_redirects=False) as client:
        for (url, method, param) in URL_PARAMS:
            for target in [OOB_URL] + INTERNAL_PROBES:
                rl.wait()
                r = probe(client, url, method, param, target)
                results.append(r)
                if "error" not in r:
                    print(f"  [~] {url} | {param}={target[:40]} → {r[\'status\']} ({r[\'size\']}b)")
    with open(OUTPUT, "w") as f: json.dump(results, f, indent=2)
    print(f"\\n  [*] Results → {OUTPUT}")
    print("  [*] Check your OOB endpoint for any callbacks!")
''',
},

# ── IDOR ──────────────────────────────────────────────────────────────────────
"idor": {
    "name": "IDOR Enumeration Script",
    "purpose": "Test ID parameters for insecure direct object references",
    "filename": "test_idor.py",
    "body": '''\
try:
    import httpx
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

# Fill from your authenticated session — use YOUR user ID as baseline
MY_USER_ID   = "YOUR_USER_ID_HERE"
AUTH_TOKEN   = "YOUR_AUTH_TOKEN_HERE"  # Bearer token / session cookie

# Endpoints to test — fill from JS analysis
ENDPOINTS = [
    # "https://api.TARGET.com/api/v1/users/{id}/profile",
    # "https://api.TARGET.com/api/v1/documents/{id}",
]

# IDs to test (sequential, your ID ± offsets, known IDs)
def generate_ids(base_id):
    try:
        base = int(base_id)
        return [str(base + i) for i in range(-5, 6) if base + i != base]
    except ValueError:
        # UUID or non-numeric — manual testing needed
        return []

OUTPUT = "idor_results.json"

def test_endpoint(client, template, test_id, headers):
    url = template.replace("{id}", test_id)
    try:
        r = client.get(url, headers=headers, timeout=10)
        return {
            "url": url, "id_tested": test_id, "status": r.status_code,
            "size": len(r.content),
            "note": "MANUAL REVIEW if status 200 and different from own resource"
        }
    except Exception as e:
        return {"url": url, "id_tested": test_id, "error": str(e)}

if __name__ == "__main__":
    if not ENDPOINTS or MY_USER_ID == "YOUR_USER_ID_HERE":
        print("[!] Fill ENDPOINTS and MY_USER_ID before running.")
        sys.exit(0)
    confirm(ENDPOINTS, "IDOR Enumeration Test")
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}"}
    test_ids = generate_ids(MY_USER_ID)
    if not test_ids:
        print("[!] Non-numeric ID detected — add test IDs manually to test_ids list.")
        test_ids = []
    results = []
    with httpx.Client() as client:
        for endpoint in ENDPOINTS:
            for tid in test_ids:
                rl.wait()
                r = test_endpoint(client, endpoint, tid, headers)
                results.append(r)
                status = r.get("status")
                size   = r.get("size", 0)
                print(f"  [~] id={tid} → {status} ({size}b) — {r[\'url\']}")
    with open(OUTPUT, "w") as f: json.dump(results, f, indent=2)
    print(f"\\n  [*] Results → {OUTPUT}")
    print("  [!] Manually review any 200 responses for other users\\' data.")
''',
},

# ── Subdomain Takeover ────────────────────────────────────────────────────────
"subdomain-takeover": {
    "name": "Subdomain Takeover Checker",
    "purpose": "Check CNAME records for dangling references to unregistered services",
    "filename": "test_takeover.py",
    "body": '''\
import subprocess

# ── Set your target domain ────────────────────────────────────────────────────
TARGET = "YOUR_TARGET_DOMAIN"   # <-- replace with the domain you scanned

# Resolve subdomains file from One&Infinity data directory
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.expanduser("~/oneinfinity"))
try:
    import oneinfinity.path_manager as _pm
    SUBDOMAINS_FILE = str(_pm.get_target_path(TARGET, subdir="recon") / "subdomains.txt")
except Exception:
    # Fallback when path_manager is unavailable
    SUBDOMAINS_FILE = _os.path.join(
        _os.path.expanduser("~"), ".oneinfinity", "raw",
        TARGET.replace("://", "_").replace("/", "_"),
        "recon", "subdomains.txt",
    )

# Fingerprints: {service: [error string in response body]}
FINGERPRINTS = {
    "GitHub Pages":      ["There isn't a GitHub Pages site here"],
    "Heroku":            ["No such app", "herokuapp.com"],
    "Shopify":           ["Sorry, this shop is currently unavailable"],
    "AWS S3":            ["NoSuchBucket", "The specified bucket does not exist"],
    "Fastly":            ["Fastly error: unknown domain"],
    "Netlify":           ["Not found - Request ID"],
    "Ghost":             ["The thing you were looking for is no longer here"],
    "Surge.sh":          ["project not found"],
    "Tumblr":            ["Whatever you were looking for doesn\\\'t currently exist"],
    "Azure":             ["ErrorCode: BlobNotFound", "404 Web Site not found"],
    "Zendesk":           ["Help Center Closed"],
    "Pantheon":          ["The gods are wise"],
    "Fly.io":            ["404 Not found"],
}

OUTPUT = "takeover_candidates.json"

try:
    import httpx
except ImportError:
    import subprocess as sp, sys
    sp.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

def check_cname(domain):
    try:
        result = subprocess.run(["dig", "+short", "CNAME", domain],
                                capture_output=True, text=True, timeout=5)
        cname = result.stdout.strip()
        return cname if cname else None
    except Exception:
        return None

def check_takeover(client, domain):
    cname = check_cname(domain)
    if not cname:
        return None
    try:
        r = client.get(f"http://{domain}", timeout=8, follow_redirects=True)
        body = r.text
        for service, fingerprints in FINGERPRINTS.items():
            if any(fp in body for fp in fingerprints):
                return {
                    "domain": domain, "cname": cname,
                    "service": service, "status": r.status_code,
                    "severity": "HIGH",
                }
    except Exception:
        pass
    return None

if __name__ == "__main__":
    try:
        with open(SUBDOMAINS_FILE) as f:
            domains = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"[!] {SUBDOMAINS_FILE} not found. Run subdomain enumeration first.")
        import sys; sys.exit(1)

    print(f"[*] Checking {len(domains)} subdomains for takeover...")
    candidates = []
    with httpx.Client(verify=False) as client:
        for domain in domains:
            result = check_takeover(client, domain)
            if result:
                candidates.append(result)
                print(f"  [+] TAKEOVER CANDIDATE: {domain} → {result[\'service\']}")
                print(f"      CNAME: {result[\'cname\']}")

    import json
    with open(OUTPUT, "w") as f: json.dump(candidates, f, indent=2)
    if candidates:
        print(f"\\n  [+] {len(candidates)} candidates → {OUTPUT}")
        print("  [!] Manually verify each before reporting — confirm the service is claimable.")
    else:
        print("\\n  [-] No takeover candidates found.")
''',
},

# ── SQLi Fuzzer ───────────────────────────────────────────────────────────────
"sqli": {
    "name": "SQL Injection Fuzzer",
    "purpose": "Fuzz identified parameters for SQL injection (error-based and time-based detection)",
    "filename": "test_sqli.py",
    "body": '''\
try:
    import httpx
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

# Fill from JS analysis / manual recon — param name + endpoint
TARGETS = [
    # {"url": "https://api.TARGET.com/api/users", "method": "GET",  "param": "id"},
    # {"url": "https://api.TARGET.com/login",     "method": "POST", "param": "username"},
]

# Error-based payloads (detect via error message in response)
ERROR_PAYLOADS = ["\'", "\"", "\'--", "\'/*", "1\' AND \'1\'=\'1", "1 AND 1=2--"]

# Time-based payloads (detect via response time > threshold)
TIME_PAYLOADS = [
    ("MySQL",  "1\' AND SLEEP(5)--"),
    ("MSSQL",  "1\'; WAITFOR DELAY \'00:00:05\'--"),
    ("PostgreSQL", "1\'; SELECT pg_sleep(5)--"),
    ("Oracle", "1\' AND 1=dbms_pipe.receive_message(\'a\',5)--"),
]

TIME_THRESHOLD = 4.5  # seconds

ERROR_SIGNATURES = [
    "sql syntax", "mysql", "ora-", "pg_", "syntax error", "unclosed quotation",
    "sqlexception", "invalid query", "database error", "quoted string not properly terminated",
]

OUTPUT = "sqli_candidates.json"

def send(client, target, value):
    url, method, param = target["url"], target["method"], target["param"]
    t0 = __import__("time").time()
    try:
        if method.upper() == "POST":
            r = client.post(url, data={param: value}, timeout=12)
        else:
            r = client.get(url, params={param: value}, timeout=12)
        elapsed = __import__("time").time() - t0
        return r, elapsed
    except httpx.TimeoutException:
        return None, __import__("time").time() - t0

if __name__ == "__main__":
    if not TARGETS:
        print("[!] Fill TARGETS list with endpoints and parameters to test.")
        import sys; sys.exit(0)
    confirm([t["url"] for t in TARGETS], "SQL Injection Fuzzer")
    candidates = []
    with httpx.Client(follow_redirects=True) as client:
        for target in TARGETS:
            print(f"\\n  [~] Testing {target[\'url\']} [{target[\'param\']}]")
            # Error-based
            for payload in ERROR_PAYLOADS:
                rl.wait()
                r, elapsed = send(client, target, payload)
                if r and any(sig in r.text.lower() for sig in ERROR_SIGNATURES):
                    print(f"  [+] ERROR-BASED SQLi? payload={payload!r}")
                    candidates.append({"type": "error-based", "target": target, "payload": payload})
            # Time-based
            for db, payload in TIME_PAYLOADS:
                rl.wait()
                r, elapsed = send(client, target, payload)
                if elapsed >= TIME_THRESHOLD:
                    print(f"  [+] TIME-BASED SQLi? ({db}) elapsed={elapsed:.1f}s payload={payload!r}")
                    candidates.append({"type": "time-based", "db": db, "target": target,
                                       "payload": payload, "elapsed": elapsed})
    import json
    with open(OUTPUT, "w") as f: json.dump(candidates, f, indent=2)
    if candidates:
        print(f"\\n  [+] {len(candidates)} candidates → {OUTPUT}")
        print("  [!] Manually confirm each — use sqlmap only if program allows automated tools.")
    else:
        print("\\n  [-] No SQLi indicators found.")
''',
},

}  # end SCRIPTS dict


class ScriptGenerator:
    def __init__(self, output_dir: str = "."):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def list_available(self):
        banner("Available Test Scripts")
        rows = []
        for key, meta in SCRIPTS.items():
            rows.append({
                "Command":  key,
                "Script":   meta["filename"],
                "Purpose":  meta["purpose"][:60],
            })
        from oneinfinity.modules.utils import table
        table(rows, ["Command", "Script", "Purpose"])
        print()

    def generate(self, script_type: str, target: str = "") -> str | None:
        key = script_type.lower()
        if key not in SCRIPTS:
            err(f"Unknown script type: '{key}'")
            info(f"Available: {', '.join(SCRIPTS.keys())}")
            return None

        meta = SCRIPTS[key]
        header = SCRIPT_HEADER.format(
            name=meta["name"],
            purpose=meta["purpose"],
            filename=meta["filename"],
        )
        body = meta["body"]
        # Substitute real target when provided so the generated script is ready to run
        if target:
            body = body.replace("YOUR_TARGET_DOMAIN", target)

        content = header + "\n" + body

        out_path = self.output_dir / meta["filename"]
        out_path.write_text(content)
        out_path.chmod(0o755)

        banner(f"Script Generated: {meta['filename']}")
        info(meta["purpose"])
        print()
        warn("Before running:")
        if not target:
            print("  1. Open the script and replace YOUR_TARGET_DOMAIN with the actual target")
        print("  2. Verify all URLs are within your authorized program scope")
        print("  3. Adjust rate limits to match program rules")
        print("  4. Run: python3 " + str(out_path))
        print()
        ok(f"Script saved → {out_path}")
        return str(out_path)
