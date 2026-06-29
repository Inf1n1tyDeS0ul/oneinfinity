"""
JS Source Map Reconstructor
============================
Actively hunts for .map files for ALL discovered JS files — not just those
with an inline sourceMappingURL comment (which is what the baseline
JSIntelligence pass in _phase_recon already covers).

Strategy:
  1. For each JS URL, probe: <url>.map, <url>?source_map=1
  2. Parse V3 source maps: extract sources[], sourcesContent[]
  3. Concatenate sourcesContent → reconstruct pre-minification source
  4. Re-run full secret + endpoint extraction on the clear text
  5. Emit structured findings tagged with from_source_map=True
  6. Identify internal webpack:// package names for dependency confusion
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple

log = logging.getLogger("oneinfinity.scan.js_source_map_reconstructor")

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# Endpoint patterns reused for source-map content scan
_ENDPOINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"""fetch\s*\(\s*["'`](/?[a-zA-Z0-9_\-/:%?&=.#]{4,200})["'`]"""),
    re.compile(r"""axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*["'`](/?[a-zA-Z0-9_\-/:%?&=.#]{4,200})["'`]"""),
    re.compile(r"""["'](?:url|path|endpoint|href|action|route|api)\s*["']\s*:\s*["'`](/?[a-zA-Z0-9_\-/%?&=.#]{4,200})["'`]"""),
    re.compile(r"""["'`](/(?:api|v\d+|internal|graphql|admin|mobile|rpc|services?)/[a-zA-Z0-9_\-/%?&=.]{2,150})["'`]"""),
    re.compile(r"""`\s*(/(?:api|v\d+|graphql|admin|internal)[^`]{2,150})`"""),
    re.compile(r"""(?:apiUrl|baseUrl|apiBase|API_URL|BASE_URL)\s*[=:]\s*["'`]([^"'`\s]{4,200})["'`]"""),
]


def _extract_endpoints_from_source(content: str) -> List[str]:
    found: set[str] = set()
    for pat in _ENDPOINT_PATTERNS:
        for m in pat.finditer(content):
            val = m.group(1).strip()
            if val and len(val) < 200:
                found.add(val)
    return sorted({
        ep for ep in found
        if ep.startswith("/") and len(ep) > 4
        and not any(ep.endswith(ext) for ext in [".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".css"])
    })


class JSSourceMapReconstructor:
    """
    Reconstructs pre-minification JavaScript source from .map files,
    then re-runs endpoint and secret extraction on the clear text.
    """

    def __init__(self, timeout: int = 15, headers: dict = None):
        self.timeout = timeout
        self.headers = headers or {}

    # ── Public API ────────────────────────────────────────────────────────────

    def reconstruct_all(
        self,
        target: str,
        js_urls: List[str],
        secret_scanner=None,
    ) -> Tuple[List[dict], List[str]]:
        """
        For each JS URL, probe for companion .map files.
        Returns (findings, extra_endpoint_paths).

        secret_scanner: optional JSSecretScanner instance for secret extraction.
        """
        all_findings: List[dict] = []
        all_endpoints: set[str] = set()

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(self._reconstruct_one, target, url, secret_scanner): url
                for url in js_urls
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings, endpoints = future.result()
                    all_findings.extend(findings)
                    all_endpoints.update(endpoints)
                except Exception as exc:
                    log.debug("Reconstruction failed for %s: %s", url, exc)

        return all_findings, sorted(all_endpoints)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _reconstruct_one(
        self,
        target: str,
        js_url: str,
        secret_scanner,
    ) -> Tuple[List[dict], List[str]]:
        map_url = self._find_map_url(js_url)
        if not map_url:
            return [], []

        map_data = self._fetch_map(map_url)
        if not map_data:
            return [], []

        sources = map_data.get("sources", [])
        sources_content = map_data.get("sourcesContent", [])

        # Identify internal webpack:// packages (dependency confusion surface)
        internal_packages = sorted({
            re.sub(r"webpack://[^/]*/", "", s).split("/")[0]
            for s in sources
            if "webpack://" in s and "node_modules" not in s and not s.endswith(".css")
        })

        # Reconstruct pre-minification source
        if not sources_content:
            log.debug("No sourcesContent in map for %s", js_url)
            return self._emit_map_exposure_finding(map_url, js_url, target, sources, internal_packages, has_content=False), []

        reconstructed = "\n".join(c for c in sources_content if isinstance(c, str))
        if not reconstructed:
            return self._emit_map_exposure_finding(map_url, js_url, target, sources, internal_packages, has_content=False), []

        findings = self._emit_map_exposure_finding(map_url, js_url, target, sources, internal_packages, has_content=True)

        # Re-run endpoint extraction on clear text
        endpoints = _extract_endpoints_from_source(reconstructed)

        # Re-run secret scan on clear text (use JSSecretScanner if available, else basic)
        if secret_scanner:
            secret_findings = secret_scanner.scan_content(
                target, map_url, reconstructed, from_source_map=True
            )
        else:
            secret_findings = self._basic_secret_scan(reconstructed, map_url, target)

        findings.extend(secret_findings)

        # Dependency confusion finding if internal packages found
        if internal_packages:
            fid = hashlib.md5(f"dep_confusion_{map_url}".encode()).hexdigest()[:16]
            findings.append({
                "finding_id": fid,
                "vuln_type": "dependency_confusion",
                "name": "Dependency Confusion Risk",
                "title": f"Internal package names exposed in source map: {map_url}",
                "severity": "high",
                "url": map_url,
                "internal_packages": internal_packages[:20],
                "confidence": 0.75,
                "tool": "js_source_map_reconstructor",
                "source_type": "active",
                "target": target,
                "from_source_map": True,
                "evidence": f"webpack:// packages: {', '.join(internal_packages[:10])}",
            })

        log.info(
            "Reconstructor: %s → %d findings, %d endpoints, %d dep-confusion packages",
            js_url, len(findings), len(endpoints), len(internal_packages),
        )
        return findings, endpoints

    def _find_map_url(self, js_url: str) -> Optional[str]:
        """Try common .map URL patterns for a JS file."""
        candidates = [
            js_url + ".map",
            js_url.replace(".min.js", ".js.map"),
            re.sub(r"\?.*$", "", js_url) + ".map",
        ]
        h = {"User-Agent": "Mozilla/5.0 (OneInfinity MapHunter/1.0)"}
        h.update(self.headers)
        for candidate in candidates:
            try:
                req = urllib.request.Request(candidate, headers=h)
                req.get_method = lambda: "HEAD"
                with urllib.request.urlopen(req, timeout=5, context=_SSL_CTX) as resp:
                    if resp.status in (200, 304):
                        ct = resp.headers.get("Content-Type", "")
                        if "json" in ct or "map" in ct or candidate.endswith(".map"):
                            return candidate
            except Exception:
                continue
        return None

    def _fetch_map(self, map_url: str) -> Optional[dict]:
        h = {"User-Agent": "Mozilla/5.0 (OneInfinity MapHunter/1.0)"}
        h.update(self.headers)
        try:
            req = urllib.request.Request(map_url, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL_CTX) as resp:
                if resp.status not in (200, 304):
                    return None
                raw = resp.read(10_000_000).decode("utf-8", errors="replace")
                if '"sources"' not in raw:
                    return None
                return json.loads(raw)
        except Exception as exc:
            log.debug("Map fetch failed for %s: %s", map_url, exc)
            return None

    def _emit_map_exposure_finding(
        self,
        map_url: str,
        js_url: str,
        target: str,
        sources: List[str],
        internal_packages: List[str],
        has_content: bool,
    ) -> List[dict]:
        fid = hashlib.md5(f"map_exposed_{map_url}".encode()).hexdigest()[:16]
        severity = "high" if has_content else "medium"
        title = (
            f"Source Map Exposes Pre-Minification Source ({len(sources)} files): {map_url}"
            if has_content else
            f"Source Map Found (no sourcesContent): {map_url}"
        )
        return [{
            "finding_id": fid,
            "vuln_type": "source_map_exposed",
            "name": "Source Map Exposed",
            "title": title,
            "severity": severity,
            "url": map_url,
            "js_url": js_url,
            "sources_count": len(sources),
            "has_source_content": has_content,
            "internal_packages": internal_packages[:10],
            "confidence": 0.92,
            "tool": "js_source_map_reconstructor",
            "source_type": "active",
            "target": target,
            "from_source_map": True,
            "evidence": (
                f"Source map at {map_url} exposes {len(sources)} original source files"
                + (f" with source content" if has_content else "")
            ),
        }]

    def _basic_secret_scan(self, content: str, url: str, target: str) -> List[dict]:
        """Minimal fallback secret scan when JSSecretScanner is not available."""
        import math as _math
        findings: List[dict] = []
        # Only scan for the highest-confidence patterns
        high_conf = [
            ("AWS Access Key", re.compile(r"""AKIA[0-9A-Z]{16}"""), "critical"),
            ("GitHub PAT",     re.compile(r"""gh[pousr]_[A-Za-z0-9]{36,255}"""), "critical"),
            ("Stripe Secret",  re.compile(r"""sk_(?:live|test)_[A-Za-z0-9]{20,}"""), "critical"),
            ("Private Key",    re.compile(r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"""), "critical"),
        ]
        for name, pat, sev in high_conf:
            m = pat.search(content)
            if not m:
                continue
            value = m.group(0)
            fid = hashlib.md5(f"sm_basic_{name}_{url}".encode()).hexdigest()[:16]
            findings.append({
                "finding_id": fid,
                "vuln_type": "js_secret",
                "name": name,
                "title": f"JS Secret in source map: {name}",
                "severity": sev,
                "url": url,
                "value_preview": value[:40] + "...",
                "confidence": 0.90,
                "tool": "js_source_map_reconstructor",
                "from_source_map": True,
                "target": target,
            })
        return findings
