"""
Prototype Pollution Source Scanner
=====================================
STATIC analysis of JavaScript source code for unsafe object merge patterns.
Distinct from run_prototype_pollution_test (HTTP-level injection testing).

Detects unsafe merge sinks:
  - _.merge(obj, userInput)              — lodash deep merge
  - jQuery.extend(true, obj, userInput)  — jQuery deep extend
  - deepmerge(a, b)                      — deepmerge library
  - Object.assign({}, userInput)         — shallow assign with external input
  - Object.setPrototypeOf(obj, src)      — direct prototype manipulation
  - __proto__ in dynamic object access

For each match, extracts a taint path showing what variable flows into the sink,
calculates a confidence score based on context signals (user_id, req.body, params, etc.),
and emits structured findings with vuln_type="prototype_pollution_source" so they
feed into the prototype_pollution_to_xss_rce exploit chain.
"""
from __future__ import annotations

import hashlib
import logging
import re
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

log = logging.getLogger("oneinfinity.scan.prototype_pollution_source_scanner")

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Sink patterns ─────────────────────────────────────────────────────────────

# Each tuple: (sink_name, pattern, confidence_base)
_SINK_PATTERNS: list[tuple] = [
    # lodash _.merge — deep merge that writes to Object.prototype
    (
        "lodash_merge",
        re.compile(
            r"""_\s*\.\s*merge\s*\(\s*(?:\{\s*\}|[a-zA-Z_$][a-zA-Z0-9_$.]*)\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$.]+)\s*\)""",
            re.I,
        ),
        0.75,
    ),
    # jQuery.extend(true, ...) — deep extend
    (
        "jquery_extend_deep",
        re.compile(
            r"""(?:jQuery|\$)\s*\.\s*extend\s*\(\s*true\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$][a-zA-Z0-9_$.]*)\s*\)""",
            re.I,
        ),
        0.80,
    ),
    # deepmerge(a, b)
    (
        "deepmerge",
        re.compile(
            r"""deepmerge\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$][a-zA-Z0-9_$.]*)\s*\)""",
            re.I,
        ),
        0.80,
    ),
    # Object.assign({}, userControlled) — shallow but still pollutes if target has __proto__
    (
        "object_assign",
        re.compile(
            r"""Object\s*\.\s*assign\s*\(\s*\{\s*\}\s*,\s*([a-zA-Z_$][a-zA-Z0-9_$][a-zA-Z0-9_$.]*)\s*\)""",
        ),
        0.55,
    ),
    # Object.setPrototypeOf
    (
        "set_prototype_of",
        re.compile(
            r"""Object\s*\.\s*setPrototypeOf\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*,""",
        ),
        0.70,
    ),
    # Direct __proto__ write
    (
        "proto_direct_write",
        re.compile(
            r"""([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\[\s*['"__proto__'"]+\s*\]\s*="""
            r"""|([a-zA-Z_$][a-zA-Z0-9_$]*)\.(__proto__|constructor\.prototype)\s*=""",
        ),
        0.85,
    ),
    # JSON.parse on user input without sanitisation — feeds pollutable merges
    (
        "json_parse_user_input",
        re.compile(
            r"""JSON\s*\.\s*parse\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.|user\.)[a-zA-Z0-9_.]+""",
        ),
        0.65,
    ),
    # qs library deep parse: qs.parse(str, {allowPrototypes: true})
    (
        "qs_allow_prototypes",
        re.compile(
            r"""qs\s*\.\s*parse\s*\([^)]*allowPrototypes\s*:\s*true""",
        ),
        0.90,
    ),
]

# ── Taint source indicators (higher confidence when present near a sink) ──────
_TAINT_SOURCES: list[re.Pattern] = [
    re.compile(r"""req\s*\.\s*(?:body|query|params|headers)"""),
    re.compile(r"""request\s*\.\s*(?:body|query|params|data)"""),
    re.compile(r"""user[Ii]nput|userdata|userData"""),
    re.compile(r"""JSON\s*\.\s*parse"""),
    re.compile(r"""qs\.parse|querystring\.parse"""),
    re.compile(r"""process\.argv|process\.env"""),
    re.compile(r"""localStorage\.getItem|sessionStorage\.getItem"""),
    re.compile(r"""document\.location|window\.location"""),
    re.compile(r"""fetch\([^)]+\)\.then|\.json\(\)"""),
]

# Window to search for taint sources around a match (chars before/after)
_TAINT_WINDOW = 300


class PrototypePollutionSourceScanner:
    """
    Static JS source analysis for prototype pollution sinks.
    """

    def __init__(self, timeout: int = 15, headers: dict = None):
        self.timeout = timeout
        self.headers = headers or {}

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_urls(self, target: str, js_urls: List[str]) -> List[dict]:
        """Fetch and scan a list of JS URLs. Returns findings."""
        all_findings: List[dict] = []
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {
                pool.submit(self._process_url, target, url): url
                for url in js_urls
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as exc:
                    log.debug("PP scan failed for %s: %s", url, exc)
        return all_findings

    def scan_content(self, target: str, url: str, content: str) -> List[dict]:
        """Scan pre-fetched JS content. Called by _phase_js_intelligence."""
        return self._analyze_content(target, url, content)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _process_url(self, target: str, url: str) -> List[dict]:
        content = self._fetch(url)
        if not content:
            return []
        return self._analyze_content(target, url, content)

    def _fetch(self, url: str) -> str:
        h = {"User-Agent": "Mozilla/5.0 (OneInfinity PPScanner/1.0)"}
        h.update(self.headers)
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout, context=_SSL_CTX) as resp:
                ct = resp.headers.get("Content-Type", "")
                if "javascript" in ct or "text" in ct or url.endswith(".js"):
                    return resp.read(600_000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""

    def _analyze_content(self, target: str, url: str, content: str) -> List[dict]:
        findings: List[dict] = []
        lines = content.splitlines()

        for sink_name, pattern, base_confidence in _SINK_PATTERNS:
            for m in pattern.finditer(content):
                # Extract groups for taint path
                groups = [g for g in m.groups() if g] if m.lastindex else []
                taint_candidates = groups

                # Calculate line number
                line_no = content[: m.start()].count("\n") + 1

                # Context window for taint analysis
                window_start = max(0, m.start() - _TAINT_WINDOW)
                window_end = min(len(content), m.end() + _TAINT_WINDOW)
                context_window = content[window_start:window_end]

                # Score taint proximity
                taint_score = sum(
                    1 for tp in _TAINT_SOURCES if tp.search(context_window)
                )
                confidence = min(0.95, base_confidence + taint_score * 0.05)

                # Extract meaningful taint variable name
                taint_path = self._extract_taint_path(taint_candidates, context_window)

                # Build finding
                fid = hashlib.md5(
                    f"pp_source_{sink_name}_{url}_{line_no}".encode()
                ).hexdigest()[:16]

                snippet = content[max(0, m.start() - 40): m.end() + 40].strip()

                finding = {
                    "finding_id": fid,
                    "vuln_type": "prototype_pollution_source",
                    "name": f"Prototype Pollution Sink: {sink_name}",
                    "title": f"Unsafe Object Merge ({sink_name}) at {url}:{line_no}",
                    "severity": "high",
                    "url": url,
                    "line_number": line_no,
                    "sink_type": sink_name,
                    "taint_path": taint_path,
                    "code_snippet": snippet[:200],
                    "confidence": round(confidence, 2),
                    "tool": "prototype_pollution_source_scanner",
                    "source_type": "static",
                    "target": target,
                    "evidence": (
                        f"Sink: {sink_name} | Taint sources detected: {taint_score} | "
                        f"Line: {line_no}"
                    ),
                    "remediation": (
                        "Sanitize user-controlled input before passing to merge functions. "
                        "Use allowlist validation. Consider lodash 4.17.21+ (patched) or "
                        "replace with safe alternatives."
                    ),
                }
                findings.append(finding)

        return findings

    def _extract_taint_path(self, groups: List[str], window: str) -> str:
        """Identify the most likely user-controlled variable flowing into the sink."""
        if not groups:
            return "unknown"
        target_var = groups[-1] if groups else ""

        # Check if the variable name appears near a taint source
        for src_pat in _TAINT_SOURCES:
            m = src_pat.search(window)
            if m:
                # Find a nearby variable assignment
                assign_re = re.compile(
                    rf"""(?:const|let|var)\s+{re.escape(target_var)}\s*=\s*([^\n;{{}}]+)"""
                )
                am = assign_re.search(window)
                if am:
                    return f"{target_var} ← {am.group(1).strip()[:80]}"
                return f"{target_var} (near: {m.group(0)[:60]})"

        return target_var or "unknown"
