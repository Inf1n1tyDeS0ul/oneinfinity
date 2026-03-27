"""
core/benchmark_engine.py — Burp-Style Benchmarking Engine (Phase 6)

Compares OneInfinity findings against Burp Suite exports, Nuclei results,
or any JSONL/JSON tool output to measure:
  - Coverage: what fraction of known vulns were found
  - Missed vulns: in reference tool but not in OI
  - Extra findings: in OI but not in reference (potential new discoveries)
  - Accuracy score: intersection / reference × 100

Supported import formats:
  - Burp Suite JSON export (standard Site Map export)
  - Nuclei JSONL (one JSON object per line)
  - OneInfinity JSON (array of finding dicts)
  - Generic JSON (best-effort normalisation)

CLI usage (via oneinfinity.py):
    oneinfinity benchmark --burp burp.json --oi results.json
    oneinfinity benchmark --nuclei nuclei.jsonl --oi results.json
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

log = logging.getLogger("oneinfinity.core.benchmark")

# ---------------------------------------------------------------------------
# Vuln-type normalisation map
# ---------------------------------------------------------------------------

_VULN_ALIASES: Dict[str, str] = {
    # XSS
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "stored xss": "xss",
    "reflected xss": "xss",
    "dom xss": "xss",
    "xss (reflected)": "xss",
    "xss (stored)": "xss",
    "xss (dom-based)": "xss",
    # SQLi
    "sql injection": "sqli",
    "sql_injection": "sqli",
    "blind sql injection": "sqli",
    "error-based sql injection": "sqli",
    "time-based sql injection": "sqli",
    # SSRF
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    # IDOR
    "insecure direct object reference": "idor",
    "insecure direct object references": "idor",
    "broken object level authorization": "idor",
    "bola": "idor",
    # LFI
    "local file inclusion": "lfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    # RCE
    "remote code execution": "rce",
    "code execution": "rce",
    "rce": "rce",
    # Command injection
    "command injection": "cmdi",
    "os command injection": "cmdi",
    "shell injection": "cmdi",
    # Auth
    "authentication bypass": "auth_bypass",
    "broken authentication": "auth_bypass",
    "auth bypass": "auth_bypass",
    # Open redirect
    "open redirect": "open_redirect",
    "url redirect": "open_redirect",
    "unvalidated redirect": "open_redirect",
    # XXE
    "xml external entity": "xxe",
    "xml external entity injection": "xxe",
    "xxe injection": "xxe",
    # SSTI
    "server-side template injection": "ssti",
    "template injection": "ssti",
    # CSRF
    "cross-site request forgery": "csrf",
    "cross site request forgery": "csrf",
    # Info disclosure
    "information disclosure": "info_disclosure",
    "sensitive data exposure": "info_disclosure",
    "information leakage": "info_disclosure",
    # JWT
    "jwt weakness": "jwt_weakness",
    "jwt vulnerability": "jwt_weakness",
    # Misconfig
    "security misconfiguration": "misconfig",
    "misconfiguration": "misconfig",
    "cors misconfiguration": "misconfig",
    "cors": "misconfig",
    # GraphQL
    "graphql injection": "graphql",
    "graphql introspection": "graphql",
}


def normalise_vuln_type(raw: str) -> str:
    """Normalise a raw vulnerability type string to a canonical key."""
    clean = raw.strip().lower()
    # Direct lookup
    if clean in _VULN_ALIASES:
        return _VULN_ALIASES[clean]
    # Substring lookup
    for alias, canonical in _VULN_ALIASES.items():
        if alias in clean:
            return canonical
    # Fall back: strip special chars and return short form
    return re.sub(r"[^a-z0-9_]", "_", clean)[:30]


def normalise_endpoint(url: str) -> str:
    """Strip query string and fragment — compare on path only."""
    url = url.strip()
    # Remove fragment
    url = url.split("#")[0]
    # Remove query string for matching (keep host + path)
    url = url.split("?")[0]
    # Remove trailing slash
    return url.rstrip("/").lower()


# ---------------------------------------------------------------------------
# Normalised finding model
# ---------------------------------------------------------------------------


class NormFinding:
    """Normalised finding for cross-tool comparison."""

    __slots__ = ("vuln_type", "endpoint", "severity", "source", "raw")

    def __init__(
        self,
        vuln_type: str,
        endpoint: str,
        severity: str,
        source: str,
        raw: Optional[dict] = None,
    ) -> None:
        self.vuln_type = normalise_vuln_type(vuln_type)
        self.endpoint = normalise_endpoint(endpoint)
        self.severity = (severity or "info").lower()
        self.source = source
        self.raw = raw or {}

    def match_key(self) -> Tuple[str, str]:
        """Key used for set-based comparison: (vuln_type, endpoint)."""
        return (self.vuln_type, self.endpoint)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "endpoint":  self.endpoint,
            "severity":  self.severity,
            "source":    self.source,
        }


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _parse_burp_json(data: list) -> List[NormFinding]:
    """
    Parse Burp Suite JSON export.
    Burp exports: array of items with 'issueName', 'host', 'path', 'severity'.
    Also handles the 'issues' wrapper format.
    """
    findings = []
    # Handle {"issues": [...]} wrapper
    if isinstance(data, dict):
        data = data.get("issues", data.get("items", []))
    if not isinstance(data, list):
        log.warning("[benchmark] Burp data is not a list/dict with issues key")
        return findings

    for item in data:
        if not isinstance(item, dict):
            continue
        vuln = item.get("issueName") or item.get("name") or item.get("type") or ""
        host = item.get("host") or item.get("domain") or ""
        path = item.get("path") or item.get("url") or "/"
        severity = item.get("severity") or item.get("risk") or "info"

        if not host:
            url = item.get("url") or ""
        else:
            if not path.startswith("/"):
                path = "/" + path
            scheme = "https"
            url = f"{scheme}://{host}{path}"

        if vuln and url:
            findings.append(NormFinding(vuln_type=vuln, endpoint=url,
                                        severity=severity, source="burp", raw=item))
    log.info("[benchmark] Burp: parsed %d findings", len(findings))
    return findings


def _parse_nuclei_jsonl(text: str) -> List[NormFinding]:
    """
    Parse Nuclei JSONL output (one JSON object per line).
    Fields: template-id, host, type, matched-at, severity, info.severity
    """
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        vuln = (
            item.get("template-id")
            or item.get("templateID")
            or item.get("info", {}).get("name")
            or item.get("type")
            or "unknown"
        )
        url = item.get("matched-at") or item.get("host") or item.get("url") or ""
        severity = (
            item.get("info", {}).get("severity")
            or item.get("severity")
            or "info"
        )
        if url:
            findings.append(NormFinding(vuln_type=vuln, endpoint=url,
                                        severity=severity, source="nuclei", raw=item))

    log.info("[benchmark] Nuclei: parsed %d findings", len(findings))
    return findings


def _parse_oi_json(data: list) -> List[NormFinding]:
    """Parse OneInfinity findings array."""
    findings = []
    if isinstance(data, dict):
        # Unwrap common wrappers
        data = data.get("findings", data.get("results", [data]))
    if not isinstance(data, list):
        return findings

    for item in data:
        if not isinstance(item, dict):
            continue
        vuln = item.get("vuln_type") or item.get("type") or item.get("name") or "unknown"
        url = item.get("url") or item.get("endpoint") or item.get("target") or ""
        severity = item.get("severity") or "info"
        if url:
            findings.append(NormFinding(vuln_type=vuln, endpoint=url,
                                        severity=severity, source="oneinfinity", raw=item))

    log.info("[benchmark] OI: parsed %d findings", len(findings))
    return findings


def load_findings(path: str, fmt: Optional[str] = None) -> List[NormFinding]:
    """
    Load and normalise findings from a file.

    fmt: 'burp', 'nuclei', 'oi', or auto-detect from extension/content.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Findings file not found: {path}")

    raw_text = p.read_text(encoding="utf-8", errors="replace")

    # Auto-detect format
    if fmt is None:
        if p.suffix in (".jsonl",):
            fmt = "nuclei"
        else:
            # Peek at content
            stripped = raw_text.strip()
            if stripped.startswith("[") or stripped.startswith("{"):
                try:
                    parsed = json.loads(stripped)
                    # If it looks like Burp (has 'issueName' or 'issues')
                    if isinstance(parsed, dict) and ("issues" in parsed or "items" in parsed):
                        fmt = "burp"
                    elif isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                        if "issueName" in parsed[0] or "risk" in parsed[0]:
                            fmt = "burp"
                        elif "template-id" in parsed[0] or "templateID" in parsed[0]:
                            fmt = "nuclei_json"
                        else:
                            fmt = "oi"
                    else:
                        fmt = "oi"
                except json.JSONDecodeError:
                    fmt = "nuclei"  # try JSONL
            else:
                fmt = "nuclei"

    if fmt == "burp":
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            log.error("[benchmark] Failed to parse Burp JSON from %s", path)
            return []
        return _parse_burp_json(data)

    elif fmt in ("nuclei", "nuclei_jsonl"):
        return _parse_nuclei_jsonl(raw_text)

    elif fmt == "nuclei_json":
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            data = []
        if isinstance(data, list):
            text = "\n".join(json.dumps(item) for item in data)
            return _parse_nuclei_jsonl(text)
        return _parse_nuclei_jsonl(raw_text)

    else:  # oi or generic
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            log.warning("[benchmark] Could not parse %s as JSON — trying JSONL", path)
            return _parse_nuclei_jsonl(raw_text)
        return _parse_oi_json(data)


# ---------------------------------------------------------------------------
# Comparison engine
# ---------------------------------------------------------------------------


class BenchmarkResult:
    """Results of a benchmark comparison."""

    def __init__(
        self,
        reference_source: str,
        reference_count: int,
        oi_count: int,
        common: List[dict],
        missed: List[dict],
        extra: List[dict],
    ) -> None:
        self.reference_source = reference_source
        self.reference_count = reference_count
        self.oi_count = oi_count
        self.common = common      # in both reference and OI
        self.missed = missed      # in reference but NOT in OI
        self.extra = extra        # in OI but NOT in reference

    @property
    def accuracy_score(self) -> float:
        """Percentage of reference findings detected by OI."""
        if self.reference_count == 0:
            return 0.0
        return round(len(self.common) / self.reference_count * 100, 1)

    @property
    def coverage(self) -> str:
        return f"{len(self.common)}/{self.reference_count} ({self.accuracy_score}%)"

    def to_dict(self) -> dict:
        return {
            "reference_source":  self.reference_source,
            "reference_count":   self.reference_count,
            "oi_count":          self.oi_count,
            "common_count":      len(self.common),
            "missed_count":      len(self.missed),
            "extra_count":       len(self.extra),
            "accuracy_score":    self.accuracy_score,
            "coverage":          self.coverage,
            "missed_vulns":      self.missed,
            "extra_findings":    self.extra,
            "common_findings":   self.common,
        }

    def print_summary(self) -> None:
        """Print a human-readable benchmark report to stdout."""
        print(f"\n{'='*60}")
        print(f"  Benchmark: OneInfinity vs {self.reference_source.upper()}")
        print(f"{'='*60}")
        print(f"  Reference findings : {self.reference_count}")
        print(f"  OI findings        : {self.oi_count}")
        print(f"  Matched (common)   : {len(self.common)}")
        print(f"  Missed by OI       : {len(self.missed)}")
        print(f"  Extra (OI only)    : {len(self.extra)}")
        print(f"  Accuracy Score     : {self.accuracy_score}%")
        print(f"  Coverage           : {self.coverage}")
        print()

        if self.missed:
            print("  Missed Vulnerabilities (in reference, not in OI):")
            for m in self.missed[:20]:
                print(f"    [{m['severity'][:4].upper()}] {m['vuln_type']:<20} {m['endpoint'][:60]}")
            if len(self.missed) > 20:
                print(f"    ... and {len(self.missed)-20} more")
            print()

        if self.extra:
            print("  Extra Findings (in OI, not in reference — potential new vulns):")
            for e in self.extra[:10]:
                print(f"    [{e['severity'][:4].upper()}] {e['vuln_type']:<20} {e['endpoint'][:60]}")
            if len(self.extra) > 10:
                print(f"    ... and {len(self.extra)-10} more")
            print()

        print(f"{'='*60}\n")


class BenchmarkEngine:
    """
    Compares OneInfinity findings against a reference tool's output.

    Usage::
        engine = BenchmarkEngine()
        result = engine.compare(oi_findings_path="oi.json", reference_path="burp.json", reference_fmt="burp")
        result.print_summary()
        engine.save_report(result, "benchmark_report.json")
    """

    def compare(
        self,
        oi_findings_path: str,
        reference_path: str,
        reference_fmt: Optional[str] = None,
        oi_fmt: Optional[str] = None,
    ) -> BenchmarkResult:
        """
        Compare OI findings against a reference tool export.

        Returns a BenchmarkResult with coverage, missed, extra, accuracy.
        """
        oi_findings = load_findings(oi_findings_path, fmt=oi_fmt or "oi")
        ref_findings = load_findings(reference_path, fmt=reference_fmt)

        ref_source = ref_findings[0].source if ref_findings else (reference_fmt or "reference")

        # Build match-key sets
        oi_keys: Dict[Tuple[str, str], NormFinding] = {
            f.match_key(): f for f in oi_findings
        }
        ref_keys: Dict[Tuple[str, str], NormFinding] = {
            f.match_key(): f for f in ref_findings
        }

        common_keys = set(oi_keys) & set(ref_keys)
        missed_keys = set(ref_keys) - set(oi_keys)
        extra_keys  = set(oi_keys) - set(ref_keys)

        common = [ref_keys[k].to_dict() for k in sorted(common_keys)]
        missed = [ref_keys[k].to_dict() for k in sorted(missed_keys)]
        extra  = [oi_keys[k].to_dict()  for k in sorted(extra_keys)]

        result = BenchmarkResult(
            reference_source=ref_source,
            reference_count=len(ref_findings),
            oi_count=len(oi_findings),
            common=common,
            missed=missed,
            extra=extra,
        )

        log.info(
            "[benchmark] OI vs %s: %d/%d matched, accuracy=%.1f%%",
            ref_source, len(common), len(ref_findings), result.accuracy_score,
        )
        return result

    def compare_from_dicts(
        self,
        oi_findings: list,
        ref_file: str,
        reference_fmt: Optional[str] = None,
    ) -> "BenchmarkResult":
        """
        Compare in-memory OI findings (list of dicts) against a reference file.
        Avoids writing a temp file by parsing the list directly.
        """
        oi_norms = _parse_oi_json(oi_findings)
        ref_norms = load_findings(ref_file, fmt=reference_fmt)

        ref_source = ref_norms[0].source if ref_norms else (reference_fmt or "reference")

        oi_keys: Dict[Tuple[str, str], NormFinding] = {f.match_key(): f for f in oi_norms}
        ref_keys: Dict[Tuple[str, str], NormFinding] = {f.match_key(): f for f in ref_norms}

        common_keys = set(oi_keys) & set(ref_keys)
        missed_keys = set(ref_keys) - set(oi_keys)
        extra_keys  = set(oi_keys) - set(ref_keys)

        result = BenchmarkResult(
            reference_source=ref_source,
            reference_count=len(ref_norms),
            oi_count=len(oi_norms),
            common=[ref_keys[k].to_dict() for k in sorted(common_keys)],
            missed=[ref_keys[k].to_dict() for k in sorted(missed_keys)],
            extra=[oi_keys[k].to_dict() for k in sorted(extra_keys)],
        )
        log.info(
            "[benchmark] in-memory vs %s: %d/%d matched, accuracy=%.1f%%",
            ref_source, len(common_keys), len(ref_norms), result.accuracy_score,
        )
        return result

    def compare_all(
        self,
        oi_findings_path: str,
        references: List[dict],
    ) -> List[BenchmarkResult]:
        """
        Compare OI against multiple reference tools.
        references: list of {"path": ..., "fmt": ...} dicts
        """
        results = []
        for ref in references:
            try:
                result = self.compare(
                    oi_findings_path=oi_findings_path,
                    reference_path=ref["path"],
                    reference_fmt=ref.get("fmt"),
                )
                results.append(result)
            except Exception as exc:
                log.error("[benchmark] Failed to compare against %s: %s", ref.get("path"), exc)
        return results

    def save_report(
        self,
        result: BenchmarkResult,
        output_path: str = "benchmark_report.json",
    ) -> Path:
        """Save benchmark result as JSON."""
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result.to_dict(), indent=2))
        log.info("[benchmark] Report saved: %s", p)
        return p


# ---------------------------------------------------------------------------
# Fix 2 — Benchmark Feedback Loop
# ---------------------------------------------------------------------------


class BenchmarkFeedbackLoop:
    """
    Analyses a BenchmarkResult and feeds intelligence back into the scan
    pipeline context so missed vulnerabilities trigger a targeted re-scan.

    Usage::
        loop = BenchmarkFeedbackLoop()
        trigger = loop.apply(result, ctx)
        if trigger:
            run_targeted_scan(ctx["focus_targets"])
    """

    # Minimum missed-vuln count before triggering a re-scan
    RESCAN_THRESHOLD: int = 1

    # Severity weights used to boost priority of missed vuln types
    _SEV_WEIGHT: Dict[str, float] = {
        "critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5, "info": 0.2,
    }

    def apply(self, result: BenchmarkResult, ctx: Optional[dict] = None) -> bool:
        """
        Feed benchmark intelligence back into the pipeline context.

        Actions:
          1. ctx["focus_targets"] — unique URLs from missed findings (for re-scan)
          2. ctx["priority_vuln_types"] — missed vuln types with boosted weights
          3. ctx["benchmark_score"] — latest accuracy score for dashboard display
          4. Logs improvement recommendations

        Returns True if a re-scan is recommended.
        """
        if ctx is None:
            ctx = {}

        ctx["benchmark_score"] = result.accuracy_score

        if not result.missed:
            log.info("[feedback] No missed vulns — coverage is 100%%")
            return False

        # 1. Extract focus targets from missed findings
        focus_targets = list({
            m.get("endpoint", "")
            for m in result.missed
            if m.get("endpoint")
        })
        ctx["focus_targets"] = focus_targets
        log.info("[feedback] %d missed vulns → %d focus targets for re-scan",
                 len(result.missed), len(focus_targets))

        # 2. Build priority_vuln_types with severity-weighted importance
        vuln_type_weights: Dict[str, float] = {}
        for m in result.missed:
            vtype = m.get("vuln_type", "unknown")
            sev   = m.get("severity", "info").lower()
            weight = self._SEV_WEIGHT.get(sev, 0.2)
            vuln_type_weights[vtype] = vuln_type_weights.get(vtype, 0.0) + weight

        # Sort descending by aggregate weight
        sorted_types = sorted(vuln_type_weights.items(), key=lambda x: x[1], reverse=True)
        ctx["priority_vuln_types"] = [vt for vt, _ in sorted_types]
        log.info("[feedback] Priority vuln types: %s",
                 [f"{vt}({w:.1f})" for vt, w in sorted_types[:5]])

        # 3. Recommend tool boosts for missed vuln types
        _VULN_TO_TOOLS: Dict[str, List[str]] = {
            "xss":            ["dalfox", "kxss"],
            "sqli":           ["sqlmap"],
            "ssrf":           ["nuclei"],
            "idor":           ["nuclei", "burpsuite"],
            "lfi":            ["nuclei"],
            "rce":            ["nuclei", "commix"],
            "jwt_weakness":   ["jwt_tool"],
            "graphql":        ["graphql_scan"],
            "info_disclosure": ["nuclei"],
            "misconfig":      ["nuclei"],
        }
        recommended_tools: List[str] = []
        for vtype, _ in sorted_types[:5]:
            tools = _VULN_TO_TOOLS.get(vtype, [])
            for t in tools:
                if t not in recommended_tools:
                    recommended_tools.append(t)

        ctx["benchmark_recommended_tools"] = recommended_tools
        if recommended_tools:
            log.info("[feedback] Recommended tools for re-scan: %s", recommended_tools[:5])

        # 4. Decide whether to trigger
        trigger = len(result.missed) >= self.RESCAN_THRESHOLD
        if trigger:
            log.info(
                "[feedback] Re-scan TRIGGERED: %d missed vulns on %d targets. "
                "Add ctx['focus_targets'] to next scan queue.",
                len(result.missed), len(focus_targets),
            )
        return trigger

    def extract_focus_targets(self, missed: List[dict]) -> List[str]:
        """
        Convenience: extract unique endpoints from a missed-vulns list.
        Used externally when calling code doesn't want to apply full ctx update.
        """
        return list({m.get("endpoint", "") for m in missed if m.get("endpoint")})

    def boost_vuln_types_in_ctx(
        self,
        vuln_types: List[str],
        ctx: dict,
        multiplier: float = 1.5,
    ) -> None:
        """
        Increase priority weights for specific vuln types in the pipeline ctx.
        Called by the decision engine to uprank missed vuln types.
        """
        existing: Dict[str, float] = ctx.get("vuln_type_weights", {})
        for vt in vuln_types:
            existing[vt] = existing.get(vt, 1.0) * multiplier
        ctx["vuln_type_weights"] = existing
        log.debug("[feedback] Boosted vuln types: %s", vuln_types[:5])


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional[BenchmarkEngine] = None
_feedback_instance: Optional[BenchmarkFeedbackLoop] = None


def get_benchmark_engine() -> BenchmarkEngine:
    global _instance
    if _instance is None:
        _instance = BenchmarkEngine()
    return _instance


def get_feedback_loop() -> BenchmarkFeedbackLoop:
    global _feedback_instance
    if _feedback_instance is None:
        _feedback_instance = BenchmarkFeedbackLoop()
    return _feedback_instance
