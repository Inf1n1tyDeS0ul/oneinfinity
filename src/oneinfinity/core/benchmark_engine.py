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
# ---------------------------------------------------------------------------
# Phase 3 — oneinfinity-Bench: Internal Vulnerability Benchmark (Pillar 5.1)
# ---------------------------------------------------------------------------
#
# Modeled after CyberGym: run oneinfinity against deliberately vulnerable targets
# with known ground-truth vulnerabilities. Measure recall, precision, FP rate.
# This is the CI/CD pipeline for oneinfinity's security intelligence.
#
# Usage:
#   bench = OIBench()
#   result = bench.run(target_name="juice_shop", scan_id="existing-scan-id")
#   print(f"Recall: {result.recall:.1%}, Precision: {result.precision:.1%}")

import time as _time
import uuid as _uuid
from dataclasses import dataclass as _dataclass, field as _field


@_dataclass
class OIBenchKnownVuln:
    """A known vulnerability in a benchmark target."""
    vuln_type: str
    url_pattern: str        # regex pattern to match finding URLs
    severity: str
    description: str = ""


@_dataclass
class OIBenchTarget:
    """A deliberately vulnerable benchmark target with known ground truth."""
    name: str               # e.g. "juice_shop", "dvwa", "webgoat"
    url: str                # base URL of the running target
    known_vulns: List[OIBenchKnownVuln] = _field(default_factory=list)
    notes: str = ""


@_dataclass
class OIBenchResult:
    """Result of running oneinfinity against one benchmark target."""
    target_name: str
    scan_id: str
    run_at: float = _field(default_factory=_time.time)

    # Ground truth
    known_count: int = 0
    found_count: int = 0     # known vulns found by oneinfinity
    missed_count: int = 0    # known vulns NOT found
    extra_count: int = 0     # findings not in ground truth (potential FP or new discovery)

    # Metrics
    recall: float = 0.0       # found / known  — "did we find what we should?"
    precision: float = 0.0    # found / (found + extra)  — "are our findings accurate?"
    fp_rate: float = 0.0      # extra / total_findings

    # Per-category breakdown
    coverage_by_category: Dict[str, dict] = _field(default_factory=dict)

    # Detail
    found_vulns: List[dict] = _field(default_factory=list)
    missed_vulns: List[dict] = _field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target_name":          self.target_name,
            "scan_id":              self.scan_id,
            "run_at":               self.run_at,
            "known_count":          self.known_count,
            "found_count":          self.found_count,
            "missed_count":         self.missed_count,
            "extra_count":          self.extra_count,
            "recall":               round(self.recall, 4),
            "precision":            round(self.precision, 4),
            "fp_rate":              round(self.fp_rate, 4),
            "coverage_by_category": self.coverage_by_category,
        }

    def summary(self) -> str:
        return (
            f"OI-Bench [{self.target_name}] "
            f"Recall={self.recall:.1%} "
            f"Precision={self.precision:.1%} "
            f"FP-rate={self.fp_rate:.1%} "
            f"({self.found_count}/{self.known_count} known vulns found)"
        )


# ── Pre-defined benchmark targets ─────────────────────────────────────────────
# Update these URLs to point to running instances of each target.
# Targets are intentionally vulnerable — NEVER scan against production systems.

KNOWN_BENCH_TARGETS: Dict[str, OIBenchTarget] = {
    "juice_shop": OIBenchTarget(
        name="juice_shop",
        url="http://localhost:3000",
        notes="OWASP Juice Shop — comprehensive modern web app with 100+ challenges",
        known_vulns=[
            OIBenchKnownVuln("sqli",          r"/rest/user/login",       "critical"),
            OIBenchKnownVuln("xss",           r"/search\?q=",            "medium"),
            OIBenchKnownVuln("idor",          r"/api/users/",            "high"),
            OIBenchKnownVuln("jwt_weak",      r"/rest/user/login",       "high"),
            OIBenchKnownVuln("path_traversal",r"/ftp/",                  "medium"),
            OIBenchKnownVuln("ssrf",          r"/profile/image",         "high"),
            OIBenchKnownVuln("xxe",           r"/api/",                  "high"),
            OIBenchKnownVuln("csrf",          r"/api/BasketItems/",      "medium"),
        ],
    ),
    "dvwa": OIBenchTarget(
        name="dvwa",
        url="http://localhost:4280",
        notes="Damn Vulnerable Web App — classic web vulnerability training target",
        known_vulns=[
            OIBenchKnownVuln("sqli",          r"/vulnerabilities/sqli/", "critical"),
            OIBenchKnownVuln("xss_reflected", r"/vulnerabilities/xss_r/","medium"),
            OIBenchKnownVuln("xss_stored",    r"/vulnerabilities/xss_s/","high"),
            OIBenchKnownVuln("file_inclusion",r"/vulnerabilities/fi/",   "high"),
            OIBenchKnownVuln("cmdi",          r"/vulnerabilities/exec/", "critical"),
            OIBenchKnownVuln("csrf",          r"/vulnerabilities/csrf/", "medium"),
            OIBenchKnownVuln("file_upload",   r"/vulnerabilities/upload/","high"),
        ],
    ),
    "webgoat": OIBenchTarget(
        name="webgoat",
        url="http://localhost:8080/WebGoat",
        notes="OWASP WebGoat — Java-based intentionally insecure web application",
        known_vulns=[
            OIBenchKnownVuln("sqli",          r"/WebGoat/SqlInjection",   "critical"),
            OIBenchKnownVuln("xss",           r"/WebGoat/CrossSiteScripting","medium"),
            OIBenchKnownVuln("idor",          r"/WebGoat/IDOR",           "high"),
            OIBenchKnownVuln("jwt_weak",      r"/WebGoat/JWT",            "high"),
            OIBenchKnownVuln("path_traversal",r"/WebGoat/PathTraversal",  "medium"),
            OIBenchKnownVuln("ssrf",          r"/WebGoat/SSRF",           "high"),
        ],
    ),
}


class OIBench:
    """
    Phase 3 — oneinfinity-Bench: Internal Vulnerability Benchmark.

    Scores existing scan findings against ground-truth known vulnerabilities
    in deliberately vulnerable benchmark targets.

    This is NOT an active scanner — it reads findings from an already-completed
    scan (via get_findings()) and scores them against the ground truth.

    Workflow:
      1. Run a God Mode scan against a benchmark target (Juice Shop, DVWA, etc.)
      2. Call OIBench().score(scan_id, target_name) to measure recall/precision
      3. Results are stored in benchmark_history for trend tracking

    CI/CD use: run OI-Bench after every deployment to detect regressions.
    """

    def __init__(self) -> None:
        self._history: List[OIBenchResult] = []

    def score(self, scan_id: str, target_name: str) -> OIBenchResult:
        """
        Score an existing scan against benchmark ground truth.

        Reads findings from postgres via get_ingestion_engine().get_findings()
        and matches them against the known vulnerability list for the target.
        """
        target = KNOWN_BENCH_TARGETS.get(target_name)
        if target is None:
            available = ", ".join(KNOWN_BENCH_TARGETS.keys())
            raise KeyError(
                f"Unknown benchmark target '{target_name}'. "
                f"Available: {available}. "
                f"Add custom targets to KNOWN_BENCH_TARGETS."
            )

        # Fetch findings for this scan
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            findings = get_ingestion_engine().get_findings(scan_id=scan_id) or []
        except Exception as exc:
            log.warning("OIBench.score: failed to fetch findings for %s: %s", scan_id, exc)
            findings = []

        result = self._compute_score(scan_id, target, findings)
        self._history.append(result)
        log.info(result.summary())
        return result

    def score_from_findings(
        self,
        findings: List[dict],
        target_name: str,
        scan_id: str = "",
    ) -> OIBenchResult:
        """Score in-memory findings — useful for testing without postgres."""
        target = KNOWN_BENCH_TARGETS.get(target_name)
        if target is None:
            raise KeyError(f"Unknown benchmark target '{target_name}'")
        return self._compute_score(scan_id or _uuid.uuid4().hex[:8], target, findings)

    def history(self) -> List[OIBenchResult]:
        """Return all scored results for this session."""
        return list(self._history)

    def add_custom_target(
        self,
        name: str,
        url: str,
        known_vulns: List[dict],
        notes: str = "",
    ) -> None:
        """
        Register a custom benchmark target at runtime.

        known_vulns: list of {vuln_type, url_pattern, severity} dicts.
        """
        KNOWN_BENCH_TARGETS[name] = OIBenchTarget(
            name=name,
            url=url,
            notes=notes,
            known_vulns=[
                OIBenchKnownVuln(
                    vuln_type=v.get("vuln_type", ""),
                    url_pattern=v.get("url_pattern", ""),
                    severity=v.get("severity", "medium"),
                    description=v.get("description", ""),
                )
                for v in known_vulns
            ],
        )
        log.info("OIBench: registered custom target '%s' with %d known vulns",
                 name, len(known_vulns))

    # ── Internal ─────────────────────────────────────────────────────────────

    def _compute_score(
        self,
        scan_id: str,
        target: OIBenchTarget,
        findings: List[dict],
    ) -> OIBenchResult:
        """Match findings against known vulns and compute metrics."""
        result = OIBenchResult(
            target_name=target.name,
            scan_id=scan_id,
            known_count=len(target.known_vulns),
        )

        found_set: Set[str] = set()  # indices of known_vulns that were found

        for i, kv in enumerate(target.known_vulns):
            matched = self._find_match(kv, findings)
            if matched:
                found_set.add(str(i))
                result.found_vulns.append({
                    "known_vuln": {"vuln_type": kv.vuln_type, "url_pattern": kv.url_pattern},
                    "matched_finding": matched,
                })
            else:
                result.missed_vulns.append({
                    "vuln_type": kv.vuln_type,
                    "url_pattern": kv.url_pattern,
                    "severity": kv.severity,
                })

        # Findings not matching any known vuln
        known_finding_ids = {
            f.get("finding_id")
            for f in [v["matched_finding"] for v in result.found_vulns]
            if f.get("finding_id")
        }
        extra = [f for f in findings if f.get("finding_id") not in known_finding_ids]

        result.found_count  = len(found_set)
        result.missed_count = result.known_count - result.found_count
        result.extra_count  = len(extra)

        total = result.found_count + result.extra_count
        result.recall    = result.found_count / max(result.known_count, 1)
        result.precision = result.found_count / max(total, 1)
        result.fp_rate   = result.extra_count / max(len(findings), 1)

        # Per-category breakdown
        categories: Dict[str, dict] = {}
        for kv in target.known_vulns:
            cat = kv.vuln_type.split("_")[0]
            categories.setdefault(cat, {"known": 0, "found": 0})
            categories[cat]["known"] += 1
        for v in result.found_vulns:
            cat = v["known_vuln"]["vuln_type"].split("_")[0]
            categories.setdefault(cat, {"known": 0, "found": 0})
            categories[cat]["found"] += 1
        result.coverage_by_category = {
            cat: {**d, "recall": d["found"] / max(d["known"], 1)}
            for cat, d in categories.items()
        }

        return result

    @staticmethod
    def _find_match(kv: OIBenchKnownVuln, findings: List[dict]) -> Optional[dict]:
        """Find the best-matching finding for a known vulnerability."""
        _vuln_type_norm = _VULN_ALIASES  # reuse existing normalisation map
        kv_type = kv.vuln_type.lower().strip()
        url_re = re.compile(kv.url_pattern, re.I) if kv.url_pattern else None

        for f in findings:
            f_type = str(f.get("vuln_type") or f.get("type") or "").lower()
            f_type_norm = _vuln_type_norm.get(f_type, f_type)
            if f_type_norm != kv_type and f_type != kv_type:
                continue
            if url_re:
                f_url = str(f.get("url") or f.get("endpoint") or "")
                if not url_re.search(f_url):
                    continue
            return f
        return None


def get_oi_bench() -> OIBench:
    """Return a fresh OIBench instance."""
    return OIBench()
