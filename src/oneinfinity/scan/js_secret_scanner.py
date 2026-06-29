"""
JS Secret Scanner
=================
Deep web-JS secret scanner wrapping mobile patterns + Shannon entropy + live validation.
Augments the baseline JSIntelligence run in _phase_recon with:
  - 45+ secret patterns (web + mobile combined)
  - jsluice AST-based URL extraction (zero regex FPs)
  - js-beautify deobfuscation pre-processing
  - JS file version diffing (emit new_js_endpoint/new_js_secret findings on change)

Called exclusively from _phase_js_intelligence so it always has the full
URL list produced by recon + browser_analysis + js_chunk_enumerator.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import ssl
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Tuple

log = logging.getLogger("oneinfinity.scan.js_secret_scanner")

# ── Unified secret pattern library (web + mobile) ────────────────────────────
# Tuples: (name, pattern, severity, entropy_min, validate_type)
_PATTERNS: list[tuple] = [
    # Web patterns (from JSIntelligence in adaptive_recon_engine)
    ("Google API Key",    re.compile(r"""AIza[0-9A-Za-z_\-]{35}"""),                                       "high",     3.5, "firebase"),
    ("AWS Access Key",    re.compile(r"""AKIA[0-9A-Z]{16}"""),                                              "critical", 3.8, None),
    ("AWS Secret Key",    re.compile(r"""(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"""),     "critical", 4.5, None),
    ("Private Key",       re.compile(r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"""),        "critical", 0.0, None),
    ("Bearer Token",      re.compile(r"""[Bb]earer\s+([A-Za-z0-9\-_\.]{20,200})"""),                       "high",     3.0, None),
    ("JWT Token",         re.compile(r"""eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"""),    "high",     3.0, None),
    ("GitHub PAT",        re.compile(r"""gh[pousr]_[A-Za-z0-9]{36,255}"""),                                 "critical", 4.0, None),
    ("Slack Token",       re.compile(r"""xox[baprs]-[0-9A-Za-z\-]{10,48}"""),                               "high",     3.5, None),
    ("Stripe Secret",     re.compile(r"""sk_(?:live|test)_[A-Za-z0-9]{20,}"""),                             "critical", 4.0, None),
    ("OpenAI API Key",    re.compile(r"""sk-[A-Za-z0-9]{20,}"""),                                           "high",     4.0, None),
    ("Twilio SID",        re.compile(r"""AC[a-z0-9]{32}"""),                                                "medium",   3.5, None),
    ("Hardcoded Password",re.compile(r"""(?:password|passwd|pwd|secret)\s*[=:]\s*["']([^"']{6,60})["']""", re.I), "high", 2.5, None),
    ("Generic API Key",   re.compile(r"""(?:api[_\-]?key|apikey|access[_\-]?key)\s*[=:]\s*["']([A-Za-z0-9_\-]{16,64})["']""", re.I), "high", 3.5, None),
    ("Mapbox Token",      re.compile(r"""pk\.[A-Za-z0-9]{40,}"""),                                          "medium",   3.8, None),
    ("Firebase DB URL",   re.compile(r"""https://[a-zA-Z0-9\-]+\.firebaseio\.com"""),                       "high",     0.0, "firebase_db"),
    ("Sentry DSN",        re.compile(r"""https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+"""),    "medium",   0.0, None),
    ("Telegram Bot Token",re.compile(r"""[0-9]{8,10}:[A-Za-z0-9_\-]{35}"""),                               "high",     3.5, None),
    # Mobile patterns (from mobile/secret_detection.py)
    ("AWS Access Key (mobile)", re.compile(r"""(?i)aws[_\-]?access[_\-]?key[_\-]?id[\s"'=:]+([A-Z0-9]{20})"""), "critical", 3.8, None),
    ("AWS Secret (mobile)",     re.compile(r"""(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s"'=:]+([A-Za-z0-9/+]{40})"""), "critical", 4.5, None),
    ("GCP Service Account",     re.compile(r'''"type"\s*:\s*"service_account"'''),                          "critical", 0.0, None),
    ("GCP API Key",             re.compile(r"""AIza[0-9A-Za-z_\-]{35}"""),                                  "high",     3.5, None),
    ("GitHub Token (ghp)",      re.compile(r"""ghp_[A-Za-z0-9]{36,255}"""),                                 "critical", 4.0, None),
    ("GitHub Token (ghs)",      re.compile(r"""ghs_[A-Za-z0-9]{36,}"""),                                    "high",     4.0, None),
    ("GitLab PAT",              re.compile(r"""glpat-[A-Za-z0-9_\-]{20}"""),                                "critical", 4.0, None),
    ("Stripe Publishable",      re.compile(r"""pk_(?:live|test)_[A-Za-z0-9]{20,}"""),                       "medium",   4.0, None),
    ("Shopify Secret",          re.compile(r"""shpss_[0-9a-fA-F]{32}"""),                                   "critical", 4.0, None),
    ("Shopify Access Token",    re.compile(r"""shpat_[0-9a-fA-F]{32}"""),                                   "critical", 4.0, None),
    ("PayPal Secret",           re.compile(r"""access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"""),    "critical", 4.0, None),
    ("Braintree Token",         re.compile(r"""(?i)braintree[_\-]?(?:token|key|secret)\s*[=:"\s]+([A-Za-z0-9_\-]{20,})"""), "critical", 3.8, None),
    ("Mapbox Secret Token",     re.compile(r"""sk\.eyJ1Ijoi[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"""),           "high",     3.8, None),
    ("Facebook App Secret",     re.compile(r"""(?i)facebook[_\-]?(?:app[_\-]?secret|secret)\s*[=:"\s]+([A-Za-z0-9]{32,})"""), "critical", 4.0, None),
    ("Twitter API Secret",      re.compile(r"""(?i)twitter[_\-]?(?:api[_\-]?secret|consumer[_\-]?secret)\s*[=:"\s]+([A-Za-z0-9]{35,44})"""), "critical", 4.0, None),
    ("SendGrid API Key",        re.compile(r"""SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}"""),           "critical", 4.0, None),
    ("Twilio Auth Token",       re.compile(r"""(?i)twilio[_\-]?auth[_\-]?token\s*[=:"\s]+([A-Za-z0-9]{32})"""), "critical", 4.0, None),
    ("Intercom Key",            re.compile(r"""(?i)intercom[_\-]?(?:app[_\-]?id|secret)\s*[=:"\s]+([A-Za-z0-9]{8,})"""), "high", 3.5, None),
    ("Algolia API Key",         re.compile(r"""(?i)algolia[_\-]?api[_\-]?key\s*[=:"\s]+([A-Za-z0-9]{32})"""), "high", 4.0, None),
    ("PubNub Secret Key",       re.compile(r"""sub-c-[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"""), "high", 3.8, None),
    ("Amplitude API Key",       re.compile(r"""(?i)amplitude[_\-]?api[_\-]?key\s*[=:"\s]+([A-Za-z0-9]{32})"""), "medium", 4.0, None),
    ("RapidAPI Key",            re.compile(r"""(?i)x-rapidapi-key\s*[=:"\s]+([A-Za-z0-9_\-]{32,})"""),     "high",     4.0, None),
    ("Cloudinary Cloud Name",   re.compile(r"""cloudinary\.config\s*\([^)]*api_secret\s*:\s*["']([^"']{16,})["']"""), "high", 3.5, None),
    ("OneSignal App ID",        re.compile(r"""[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""), "low", 0.0, None),
    ("Database Connection String", re.compile(r"""(?:mongodb|postgresql|mysql|redis|sqlite):\/\/[^"'\s<>]{10,}"""), "critical", 0.0, None),
    ("Private RSA Key Inline",  re.compile(r"""-----BEGIN RSA PRIVATE KEY-----[^-]{50,}-----END RSA PRIVATE KEY-----"""), "critical", 0.0, None),
    ("Hardcoded JWT Secret",    re.compile(r"""(?i)jwt[_\-]?secret\s*[=:]\s*["']([^"']{8,})["']"""),        "critical", 3.0, None),
]

# Known FP placeholder values
_FP_VALUES = frozenset({
    "your_api_key", "your-api-key", "YOUR_API_KEY", "api_key_here",
    "xxxxxxxxxxxx", "xxxxxxxxxxxxxxxx", "placeholder", "changeme",
    "example", "test", "demo", "secret", "password", "token",
    "INSERT_KEY_HERE", "REPLACE_ME", "<YOUR_API_KEY>", "undefined",
    "null", "false", "true", "0", "1", "none", "n/a",
})

# AWS Secret Key requires nearby context
_AWS_SECRET_CONTEXT_RE = re.compile(r"(?:secret|aws|key)", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    l = len(s)
    return -sum((f / l) * math.log2(f / l) for f in freq.values())


def _extract_value(m: re.Match, content: str) -> str:
    try:
        return m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
    except IndexError:
        return m.group(0)


class JSSecretScanner:
    """
    Deep web-JS secret scanner.
    Designed to run AFTER the baseline JSIntelligence pass in _phase_recon,
    adding coverage of mobile patterns, jsluice, js-beautify, and version diffing.
    """

    def __init__(
        self,
        timeout: int = 15,
        headers: dict = None,
        run_jsluice: bool = True,
        run_beautify: bool = True,
        max_files: int = 60,
    ):
        self.timeout = timeout
        self.headers = headers or {}
        self.run_jsluice = run_jsluice
        self.run_beautify = run_beautify
        self.max_files = max_files
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_urls(
        self,
        target: str,
        js_urls: List[str],
        session_id: str = "",
        known_finding_ids: set = None,
    ) -> List[dict]:
        """
        Fetch and deep-scan up to max_files JS URLs.
        Returns deduplicated findings not already in known_finding_ids.
        """
        if not js_urls:
            return []
        known_ids = known_finding_ids or set()
        urls_to_scan = list(dict.fromkeys(js_urls))[: self.max_files]
        all_findings: List[dict] = []

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {
                pool.submit(self._process_single_url, target, url, session_id): url
                for url in urls_to_scan
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as exc:
                    log.debug("JSSecretScanner: error processing %s: %s", url, exc)

        # Dedup + filter already-known
        seen_ids: set = set()
        result: List[dict] = []
        for f in all_findings:
            fid = f.get("finding_id", "")
            if fid and fid in known_ids:
                continue
            if fid in seen_ids:
                continue
            seen_ids.add(fid)
            result.append(f)

        log.info(
            "JSSecretScanner: scanned %d JS URLs → %d new findings for %s",
            len(urls_to_scan), len(result), target,
        )
        return result

    def scan_content(
        self,
        target: str,
        url: str,
        content: str,
        session_id: str = "",
        from_source_map: bool = False,
    ) -> List[dict]:
        """Scan pre-fetched JS content. Used by js_source_map_reconstructor."""
        if not content:
            return []
        findings = self._scan_content_inner(target, url, content, from_source_map)
        # jsluice pass on pre-fetched content
        if self.run_jsluice:
            jsluice_findings = self._jsluice_scan_content(content, url, target)
            findings.extend(jsluice_findings)
        return findings

    # ── Internal: fetch + process ─────────────────────────────────────────────

    def _process_single_url(self, target: str, url: str, session_id: str) -> List[dict]:
        content, content_hash = self._fetch_js(url)
        if not content:
            return []

        findings: List[dict] = []

        # Version diff check
        diff_findings = self._version_diff_check(url, content_hash, content, target, session_id)
        findings.extend(diff_findings)

        # js-beautify deobfuscation (Tier 4)
        if self.run_beautify:
            beautified = self._beautify(content)
            scan_content = beautified if beautified else content
        else:
            scan_content = content

        # Secret scan with combined patterns
        secret_findings = self._scan_content_inner(target, url, scan_content, False)
        findings.extend(secret_findings)

        # jsluice AST-based URL extraction (Tier 4)
        if self.run_jsluice:
            jsluice_findings = self._jsluice_scan_content(scan_content, url, target)
            findings.extend(jsluice_findings)

        return findings

    def _fetch_js(self, url: str) -> Tuple[str, str]:
        """Returns (content, sha256_hash). Empty string if fetch fails."""
        try:
            h = {"User-Agent": "Mozilla/5.0 (OneInfinity JSSecretScanner/3.0)"}
            h.update(self.headers)
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "javascript" in ct or "text" in ct or url.endswith(".js"):
                    raw = resp.read(600_000)
                    content = raw.decode("utf-8", errors="replace")
                    content_hash = hashlib.sha256(raw).hexdigest()
                    return content, content_hash
        except Exception as exc:
            log.debug("JSSecretScanner: fetch failed for %s: %s", url, exc)
        return "", ""

    def _scan_content_inner(
        self, target: str, url: str, content: str, from_source_map: bool
    ) -> List[dict]:
        findings: List[dict] = []
        for name, pattern, severity, entropy_min, validate_type in _PATTERNS:
            m = pattern.search(content)
            if not m:
                continue
            value = _extract_value(m, content)
            # Context check for AWS secret key
            if name == "AWS Secret Key":
                window = content[max(0, m.start() - 80): m.end() + 80]
                if not _AWS_SECRET_CONTEXT_RE.search(window):
                    continue
            # Skip OneSignal UUID FPs (very common, low value unless context)
            if name == "OneSignal App ID" and not re.search(r"(?i)onesignal|app[_\-]?id", content[max(0, m.start()-60):m.end()+60]):
                continue
            # Entropy filter
            if entropy_min > 0 and _entropy(value) < entropy_min:
                continue
            # Known FP filter
            if value.lower().strip() in _FP_VALUES:
                continue
            # Minimum length guard
            if len(value) < 6:
                continue

            finding_id = hashlib.md5(f"jss_{name}_{url}".encode()).hexdigest()[:16]
            finding = {
                "finding_id": finding_id,
                "vuln_type": "js_secret",
                "name": name,
                "title": f"JS Secret: {name} in {url}",
                "severity": severity,
                "url": url,
                "value_preview": value[:50] + "..." if len(value) > 50 else value,
                "confidence": 0.85,
                "tool": "js_secret_scanner",
                "source_type": "active",
                "target": target,
                "from_source_map": from_source_map,
                "entropy": round(_entropy(value), 2),
            }

            if validate_type == "firebase":
                finding = self._validate_firebase(finding, value, target)
            elif validate_type == "firebase_db":
                finding = self._validate_firebase_db(finding, m.group(0))

            findings.append(finding)
        return findings

    # ── jsluice subprocess (Tier 4) ───────────────────────────────────────────

    def _jsluice_scan_content(self, content: str, url: str, target: str) -> List[dict]:
        """
        Run jsluice urls -i <tempfile> for AST-based URL extraction.
        jsluice handles string concatenation — zero regex FPs on URL structure.
        Falls back gracefully if jsluice is not installed.
        """
        if not self._jsluice_available():
            return []
        findings: List[dict] = []
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".js", delete=False, encoding="utf-8"
            ) as f:
                f.write(content)
                tmp_path = f.name
            result = subprocess.run(
                ["jsluice", "urls", "-i", tmp_path],
                capture_output=True, text=True, timeout=30,
            )
            Path(tmp_path).unlink(missing_ok=True)
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    ep = data.get("url") or data.get("endpoint") or data.get("value") or ""
                    if ep and len(ep) > 4 and (ep.startswith("/") or ep.startswith("http")):
                        fid = hashlib.md5(f"jsluice_{ep}_{url}".encode()).hexdigest()[:16]
                        findings.append({
                            "finding_id": fid,
                            "vuln_type": "js_endpoint",
                            "name": "JS Endpoint (jsluice)",
                            "title": f"AST-extracted endpoint: {ep}",
                            "severity": "info",
                            "url": url,
                            "endpoint_path": ep,
                            "confidence": 0.90,
                            "tool": "jsluice",
                            "source_type": "active",
                            "target": target,
                        })
                except Exception:
                    pass
        except Exception as exc:
            log.debug("jsluice scan failed (non-fatal): %s", exc)
        return findings

    def _jsluice_available(self) -> bool:
        import shutil
        return shutil.which("jsluice") is not None

    # ── js-beautify subprocess (Tier 4) ──────────────────────────────────────

    def _beautify(self, content: str) -> str:
        """
        Run js-beautify to deobfuscate minified JS.
        Returns empty string if js-beautify is unavailable.
        Skips files that look like they're already well-formatted (> 3% newlines).
        """
        newline_ratio = content.count("\n") / max(len(content), 1)
        if newline_ratio > 0.03:
            return ""  # Already readable — skip beautify
        if not self._beautify_available():
            return ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".js", delete=False, encoding="utf-8"
            ) as f:
                f.write(content[:500_000])  # cap at 500KB
                tmp = f.name
            result = subprocess.run(
                ["js-beautify", tmp],
                capture_output=True, text=True, timeout=30,
            )
            Path(tmp).unlink(missing_ok=True)
            return result.stdout if result.returncode == 0 else ""
        except Exception as exc:
            log.debug("js-beautify failed (non-fatal): %s", exc)
            return ""

    def _beautify_available(self) -> bool:
        import shutil
        return shutil.which("js-beautify") is not None

    # ── JS version diffing (Tier 4) ───────────────────────────────────────────

    def _version_diff_check(
        self, url: str, content_hash: str, content: str, target: str, session_id: str
    ) -> List[dict]:
        """
        Compare current JS file hash against the last stored hash.
        On change, re-extract endpoints + secrets and mark them as 'new_in_version'.
        """
        if not session_id or not content_hash:
            return []
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            eng = get_ingestion_engine()
            prior = eng.get_recon_asset(asset_id=f"js_hash_{hashlib.md5(url.encode()).hexdigest()[:12]}")
        except Exception:
            prior = None

        try:
            self._store_js_hash(url, content_hash, session_id)
        except Exception as exc:
            log.debug("Failed to store JS hash: %s", exc)

        if prior is None:
            return []  # First time seeing this file

        prior_hash = (prior.get("metadata") or {}).get("hash") if isinstance(prior, dict) else ""
        if prior_hash == content_hash:
            return []  # Unchanged

        # File changed — extract new secrets and emit diff finding
        findings = self._scan_content_inner(target, url, content, False)
        diff_findings = []
        for f in findings:
            f_copy = dict(f)
            f_copy["finding_id"] = hashlib.md5(
                f"jsdiff_{f.get('name', '')}_{url}".encode()
            ).hexdigest()[:16]
            f_copy["vuln_type"] = "new_js_secret" if f.get("vuln_type") == "js_secret" else "new_js_endpoint"
            f_copy["title"] = f"[NEW VERSION] {f.get('title', '')}"
            f_copy["confidence"] = min(1.0, f_copy.get("confidence", 0.85) + 0.1)
            f_copy["js_version_changed"] = True
            diff_findings.append(f_copy)

        if diff_findings:
            log.info(
                "JSSecretScanner: JS file changed at %s → %d new secrets/endpoints",
                url, len(diff_findings),
            )
        return diff_findings

    def _store_js_hash(self, url: str, content_hash: str, session_id: str) -> None:
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
        eng = get_ingestion_engine()
        asset_id = f"js_hash_{hashlib.md5(url.encode()).hexdigest()[:12]}"
        eng.ingest_recon_asset(
            session_id,
            "js_file_hash",
            url,
            {"hash": content_hash, "updated_at": time.time()},
        )

    # ── Live validation helpers ────────────────────────────────────────────────

    def _validate_firebase(self, finding: dict, api_key: str, target: str) -> dict:
        domain_parts = target.split(".")
        project_id = domain_parts[0] if len(domain_parts) >= 2 else target
        db_url = f"https://{project_id}.firebaseio.com/.json?auth={api_key}"
        try:
            req = urllib.request.Request(db_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5, context=self._ssl_ctx) as resp:
                if resp.status == 200:
                    body = resp.read(200).decode("utf-8", errors="replace")
                    if body not in ("null", ""):
                        finding["severity"] = "critical"
                        finding["vuln_type"] = "firebase_exposed"
                        finding["confidence"] = 0.98
        except Exception:
            pass
        return finding

    def _validate_firebase_db(self, finding: dict, db_url: str) -> dict:
        test_url = db_url.rstrip("/") + "/.json"
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5, context=self._ssl_ctx) as resp:
                if resp.status == 200:
                    body = resp.read(200).decode("utf-8", errors="replace")
                    if body not in ("null", ""):
                        finding["severity"] = "critical"
                        finding["vuln_type"] = "firebase_exposed"
                        finding["confidence"] = 0.98
        except Exception:
            pass
        return finding
