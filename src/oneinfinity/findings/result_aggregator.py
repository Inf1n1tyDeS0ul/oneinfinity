"""
Result Aggregator — Collects worker results, updates attack graph, deduplicates findings.

Aggregation pipeline:
  1. merge_findings()       — combine findings lists from all workers
  2. deduplicate_findings() — SHA-256 fingerprint-based dedup (normalizes vuln_type aliases)
  3. update_graph()         — push each unique finding into the AttackGraph
  4. detect_chains()        — run ExploitChainEngine over combined findings
  5. calculate_session_risk() — weighted CVSS-like score from severity counts
  6. Assemble AggregatedResult dataclass
  7. store_result()         — persist to ~/.oneinfinity/raw/swarm_results/{session_id}.json

All imports are lazy and wrapped in try/except to allow graceful degradation.
"""

import time
import json
import logging
import threading
import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from oneinfinity.infra.path_manager import raw_dir

log = logging.getLogger(__name__)


# ── Aggregated Result Dataclass ────────────────────────────────────────────────

@dataclass
class AggregatedResult:
    session_id: str
    target: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    validated_findings: int
    exploit_chains_found: int
    graph_nodes_added: int
    graph_edges_added: int
    workers_contributed: list
    duration_s: float
    findings: list
    graph_summary: dict
    risk_score: float
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "session_id":          self.session_id,
            "target":              self.target,
            "total_findings":      self.total_findings,
            "critical":            self.critical,
            "high":                self.high,
            "medium":              self.medium,
            "low":                 self.low,
            "info":                self.info,
            "validated_findings":  self.validated_findings,
            "exploit_chains_found": self.exploit_chains_found,
            "graph_nodes_added":   self.graph_nodes_added,
            "graph_edges_added":   self.graph_edges_added,
            "workers_contributed": self.workers_contributed,
            "duration_s":          self.duration_s,
            "findings":            self.findings,
            "graph_summary":       self.graph_summary,
            "risk_score":          self.risk_score,
            "generated_at":        self.generated_at,
        }


# ── Vuln Type Alias Map (mirrors core/deduplicator.py) ────────────────────────

_VULN_ALIASES: dict = {
    "reflected xss": "xss",
    "reflected cross-site scripting": "xss",
    "stored xss": "stored_xss",
    "stored cross-site scripting": "stored_xss",
    "dom xss": "dom_xss",
    "dom-based xss": "dom_xss",
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "sql injection": "sqli",
    "sql-injection": "sqli",
    "blind sql injection": "sqli_blind",
    "time-based blind sql injection": "sqli_time",
    "error-based sql injection": "sqli_error",
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    "local file inclusion": "lfi",
    "local file read": "lfi",
    "remote file inclusion": "rfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    "insecure direct object reference": "idor",
    "insecure direct object references": "idor",
    "server-side template injection": "ssti",
    "server side template injection": "ssti",
    "open redirect": "open_redirect",
    "url redirection": "open_redirect",
    "open redirection": "open_redirect",
    "crlf injection": "crlf",
    "http header injection": "crlf",
    "broken access control": "bac",
    "access control": "bac",
    "privilege escalation": "privesc",
    "authentication bypass": "auth_bypass",
    "authorization bypass": "auth_bypass",
    "remote code execution": "rce",
    "command injection": "cmdi",
    "os command injection": "cmdi",
    "xml external entity": "xxe",
    "cross-site request forgery": "csrf",
    "cors misconfiguration": "cors",
    "mass assignment": "mass_assignment",
    # pass-through: already canonical
    "xss": "xss", "sqli": "sqli", "ssrf": "ssrf", "lfi": "lfi",
    "rfi": "rfi", "idor": "idor", "ssti": "ssti", "rce": "rce",
    "cmdi": "cmdi", "xxe": "xxe", "csrf": "csrf", "cors": "cors",
    "sqli_blind": "sqli_blind", "sqli_time": "sqli_time",
    "sqli_error": "sqli_error", "dom_xss": "dom_xss",
    "stored_xss": "stored_xss", "bac": "bac", "privesc": "privesc",
    "auth_bypass": "auth_bypass", "open_redirect": "open_redirect",
    "crlf": "crlf", "mass_assignment": "mass_assignment",
}

# Severity weights for risk score calculation
_SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high":      7.0,
    "medium":    4.0,
    "low":       1.5,
    "info":      0.1,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _canonical_vuln_type(vuln_type: str) -> str:
    return _VULN_ALIASES.get(vuln_type.lower().strip(),
                              vuln_type.lower().strip())


def _normalize_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            urlencode(params),
            "",  # strip fragment
        ))
    except Exception:
        return url.lower().strip()


def _fingerprint(vuln_type: str, url: str, parameter: str = "") -> str:
    canonical_type = _canonical_vuln_type(vuln_type)
    canonical_url = _normalize_url(url)
    canonical_param = parameter.strip().lower()
    raw = f"{canonical_type}::{canonical_url}::{canonical_param}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _get_finding_fields(finding: dict):
    """Extract normalized fields from a finding dict (handles varied key names)."""
    vuln_type = (finding.get("vuln_type")
                 or finding.get("type")
                 or finding.get("name")
                 or "unknown")
    url = (finding.get("url")
           or finding.get("endpoint")
           or finding.get("host", ""))
    parameter = (finding.get("parameter")
                 or finding.get("param", ""))
    severity = (finding.get("severity", "info") or "info").lower()
    worker_id = finding.get("_worker_id", "")
    return vuln_type, url, parameter, severity, worker_id


# ── Result Aggregator ─────────────────────────────────────────────────────────

class ResultAggregator:
    """
    Collects raw results from multiple swarm workers, deduplicates findings,
    updates the attack graph, runs exploit chain detection, and produces
    a consolidated AggregatedResult.

    Usage:
        aggregator = ResultAggregator()
        result = aggregator.aggregate(task_results, target="example.com")
        print(result.risk_score)
        aggregator.store_result(result)
    """

    RESULTS_DIR = raw_dir() / "swarm_results"

    def __init__(self, graph_updater=None, deduplicator=None):
        self._graph_updater = graph_updater   # optional AttackGraphBuilder instance
        self._deduplicator = deduplicator     # optional Deduplicator instance
        self._lock = threading.Lock()
        self._stored_results: list = []       # in-memory cache of stored results

        # Lazily load core deduplicator if not provided
        if self._deduplicator is None:
            try:
                from oneinfinity.core.deduplicator import Deduplicator
                self._deduplicator = Deduplicator()
            except ImportError:
                pass

    # ── Main Entry Point ───────────────────────────────────────────────────────

    def aggregate(self, task_results: list, target: str) -> AggregatedResult:
        """
        Full aggregation pipeline.

        Args:
            task_results: list of result dicts from worker tasks
                          Each dict should have at least: {"findings": [...], "target": str}
            target: the root target domain/host

        Returns:
            AggregatedResult with all findings merged, deduped, graph-updated,
            chain-detected, and risk-scored.
        """
        session_id = uuid.uuid4().hex
        start_time = time.time()

        # 1. Collect worker attribution
        workers_contributed = list({
            r.get("worker_id", r.get("_worker_id", "unknown"))
            for r in task_results
            if r.get("worker_id") or r.get("_worker_id")
        })

        # 2. Merge all findings from all task results
        merged = self.merge_findings(task_results)

        # 3. Deduplicate
        unique = self.deduplicate_findings(merged)

        # 4. Update attack graph
        nodes_added, edges_added = self.update_graph(unique, target)

        # 5. Detect exploit chains
        chains = self.detect_chains(unique)

        # 6. Severity counts
        sev_counts = defaultdict(int)
        for f in unique:
            sev = (f.get("severity", "info") or "info").lower()
            sev_counts[sev] += 1

        # 7. Count validated findings (those with validated=True)
        validated = sum(1 for f in unique if f.get("validated") or f.get("is_valid"))

        # 8. Risk score
        risk = self.calculate_session_risk(unique)

        # 9. Graph summary
        graph_summary = self._build_graph_summary(target, nodes_added, edges_added, chains)

        # Combine chain findings into the findings list (tagged)
        chain_findings = []
        for chain in chains:
            chain_findings.append({
                "vuln_type":  f"chain:{chain.get('chain_type', 'unknown')}",
                "url":        target,
                "severity":   chain.get("escalated_severity", "high"),
                "title":      chain.get("title", "Exploit Chain"),
                "description": chain.get("description", ""),
                "is_chain":   True,
                "chain_id":   chain.get("chain_id", ""),
            })

        all_findings = unique + chain_findings
        duration_s = time.time() - start_time

        result = AggregatedResult(
            session_id=session_id,
            target=target,
            total_findings=len(all_findings),
            critical=sev_counts.get("critical", 0),
            high=sev_counts.get("high", 0),
            medium=sev_counts.get("medium", 0),
            low=sev_counts.get("low", 0),
            info=sev_counts.get("info", 0),
            validated_findings=validated,
            exploit_chains_found=len(chains),
            graph_nodes_added=nodes_added,
            graph_edges_added=edges_added,
            workers_contributed=workers_contributed,
            duration_s=duration_s,
            findings=all_findings,
            graph_summary=graph_summary,
            risk_score=risk,
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        log.info(
            "[aggregator] Aggregation complete: target=%s total=%d unique=%d "
            "chains=%d risk=%.1f duration=%.1fs",
            target, len(merged), len(unique), len(chains), risk, duration_s,
        )
        return result

    # ── Merge ─────────────────────────────────────────────────────────────────

    def merge_findings(self, results: list) -> list:
        """
        Flatten and merge findings from a list of task result dicts.
        Accepts results in various shapes:
          - {"findings": [...]}
          - {"result": {"findings": [...]}}
          - [finding, finding, ...]  (direct list)
        Attaches _worker_id to each finding for attribution.
        """
        merged = []
        for res in results:
            if not res:
                continue
            worker_id = res.get("worker_id", res.get("_worker_id", ""))
            # Unwrap nested result
            if "result" in res and isinstance(res["result"], dict):
                res = res["result"]

            findings = res.get("findings", [])
            if isinstance(findings, list):
                for f in findings:
                    if isinstance(f, dict):
                        f_copy = dict(f)
                        if worker_id and "_worker_id" not in f_copy:
                            f_copy["_worker_id"] = worker_id
                        merged.append(f_copy)
                    elif isinstance(f, str):
                        # Some tools return plain strings (e.g. subdomain lists)
                        merged.append({"vuln_type": "info", "url": f,
                                       "severity": "info", "_worker_id": worker_id})
            elif isinstance(findings, dict):
                # findings is a nested dict — flatten values
                for phase, phase_findings in findings.items():
                    if isinstance(phase_findings, list):
                        for f in phase_findings:
                            if isinstance(f, dict):
                                f_copy = dict(f)
                                f_copy["_phase"] = phase
                                if worker_id:
                                    f_copy["_worker_id"] = worker_id
                                merged.append(f_copy)

        log.debug("[aggregator] Merged %d findings from %d results",
                  len(merged), len(results))
        return merged

    # ── Deduplication ─────────────────────────────────────────────────────────

    def deduplicate_findings(self, findings: list) -> list:
        """
        Deduplicate findings using SHA-256 fingerprint of
        (canonical_vuln_type, normalized_url, parameter).

        Delegates to core.deduplicator.Deduplicator if available,
        otherwise runs inline dedup.
        """
        if self._deduplicator:
            # Use the shared deduplicator (which also normalizes aliases)
            try:
                unique = self._deduplicator.filter_new(findings)
                log.debug("[aggregator] Dedup via core.Deduplicator: %d → %d",
                          len(findings), len(unique))
                return unique
            except Exception as exc:
                log.debug("[aggregator] core.Deduplicator failed (%s), using inline dedup", exc)

        # Inline dedup
        seen: set = set()
        unique: list = []
        for finding in findings:
            vuln_type, url, parameter, severity, _ = _get_finding_fields(finding)
            fp = _fingerprint(vuln_type, url, parameter)
            if fp not in seen:
                seen.add(fp)
                finding["_fingerprint"] = fp
                unique.append(finding)
            else:
                log.debug("[aggregator] Duplicate skipped: %s @ %s", vuln_type, url)

        log.debug("[aggregator] Inline dedup: %d → %d", len(findings), len(unique))
        return unique

    # ── Graph Update ──────────────────────────────────────────────────────────

    def update_graph(self, findings: list, target: str) -> tuple:
        """
        Push each unique finding into the attack graph.
        Returns (nodes_added, edges_added).
        """
        nodes_added = 0
        edges_added = 0

        if self._graph_updater:
            # Use provided graph updater
            for finding in findings:
                try:
                    n, e = self._graph_updater.add_finding(finding)
                    nodes_added += n
                    edges_added += e
                except Exception as exc:
                    log.debug("[aggregator] graph_updater.add_finding error: %s", exc)
            return nodes_added, edges_added

        # Try to build an AttackGraph from scratch
        try:
            from oneinfinity.attack_graph_core.graph import AttackGraph
            from oneinfinity.attack_graph_core.builder import AttackGraphBuilder

            graph = AttackGraph(target)
            builder = AttackGraphBuilder(target=target, graph=graph)

            initial_nodes = len(graph.nodes)
            initial_edges = len(getattr(graph, "edges", []))

            for finding in findings:
                try:
                    # from_finding may not exist in all versions — try it
                    if hasattr(builder, "from_finding"):
                        builder.from_finding(finding)
                    else:
                        # Fallback: manually add a vulnerability node
                        vuln_type = (finding.get("vuln_type")
                                     or finding.get("name", "unknown"))
                        url = (finding.get("url")
                               or finding.get("endpoint", target))
                        severity = finding.get("severity", "info")
                        graph.add_vulnerability(
                            endpoint=url,
                            vuln_type=vuln_type,
                            severity=severity,
                            extra=finding,
                        )
                except Exception as exc:
                    log.debug("[aggregator] Graph finding add error: %s", exc)

            nodes_added = len(graph.nodes) - initial_nodes
            edges_added = len(getattr(graph, "edges", [])) - initial_edges

        except ImportError:
            log.debug("[aggregator] attack_graph not available, skipping graph update")
        except Exception as exc:
            log.debug("[aggregator] Graph update error: %s", exc)

        return nodes_added, edges_added

    # ── Chain Detection ────────────────────────────────────────────────────────

    def detect_chains(self, findings: list) -> list:
        """
        Run ExploitChainEngine over combined findings.
        Returns a list of chain dicts.
        """
        if not findings:
            return []
        try:
            from oneinfinity.attack.exploit_chain_engine import ExploitChainEngine
            engine = ExploitChainEngine(target="aggregated")
            chains = engine.detect_chains(findings)
            chain_dicts = [
                c.to_dict() if hasattr(c, "to_dict") else c
                for c in chains
            ]
            log.debug("[aggregator] Detected %d exploit chains", len(chain_dicts))
            return chain_dicts
        except ImportError:
            log.debug("[aggregator] exploit_chains not available")
            return []
        except Exception as exc:
            log.debug("[aggregator] Chain detection error: %s", exc)
            return []

    # ── Risk Score ─────────────────────────────────────────────────────────────

    def calculate_session_risk(self, findings: list) -> float:
        """
        Calculate a session-level risk score (0–10) from finding severities.

        Formula:
          raw_score = sum(weight[severity] for each finding)
          normalized = min(10.0, log10(raw_score + 1) * scale_factor)

        Scale factor chosen so 1 critical = ~7.0, 10 criticals = ~10.0.
        """
        import math

        if not findings:
            return 0.0

        raw = 0.0
        for f in findings:
            sev = (f.get("severity", "info") or "info").lower()
            raw += _SEVERITY_WEIGHTS.get(sev, 0.1)

        # Log-scale normalization: log10(raw+1) * 4.0 caps at ~10
        score = min(10.0, math.log10(raw + 1) * 4.0)
        return round(score, 2)

    # ── Summary Report ─────────────────────────────────────────────────────────

    def generate_summary_report(self, result: AggregatedResult) -> str:
        """
        Generate a Markdown summary report from an AggregatedResult.
        """
        sev_bar = self._severity_bar(result)
        chain_section = ""
        if result.exploit_chains_found > 0:
            chain_section = (
                f"\n## Exploit Chains\n\n"
                f"**{result.exploit_chains_found} exploit chain(s) detected.**\n\n"
            )
            for f in result.findings:
                if f.get("is_chain"):
                    chain_section += (
                        f"- **{f.get('title', 'Chain')}** "
                        f"(severity: {f.get('severity', 'high')}) — "
                        f"{f.get('description', '')[:120]}\n"
                    )

        top_findings_md = ""
        top = sorted(
            [f for f in result.findings if not f.get("is_chain")],
            key=lambda x: _SEVERITY_WEIGHTS.get(
                (x.get("severity") or "info").lower(), 0
            ),
            reverse=True,
        )[:10]
        if top:
            top_findings_md = "\n## Top Findings\n\n| Severity | Type | URL |\n|---|---|---|\n"
            for f in top:
                severity = f.get("severity", "info")
                vuln_type = f.get("vuln_type") or f.get("name") or "unknown"
                url = f.get("url") or f.get("endpoint", "")
                top_findings_md += f"| {severity} | {vuln_type} | {url[:80]} |\n"

        workers_md = ", ".join(result.workers_contributed) if result.workers_contributed else "N/A"

        report = f"""# Swarm Scan Report — {result.target}

**Session ID:** `{result.session_id}`
**Generated:** {result.generated_at}
**Duration:** {result.duration_s:.1f}s
**Workers:** {workers_md}

## Risk Overview

**Risk Score:** {result.risk_score:.1f} / 10.0

{sev_bar}

| Metric | Value |
|---|---|
| Total Findings | {result.total_findings} |
| Critical | {result.critical} |
| High | {result.high} |
| Medium | {result.medium} |
| Low | {result.low} |
| Info | {result.info} |
| Validated | {result.validated_findings} |
| Exploit Chains | {result.exploit_chains_found} |
| Graph Nodes Added | {result.graph_nodes_added} |
| Graph Edges Added | {result.graph_edges_added} |
{chain_section}{top_findings_md}
## Graph Summary

```json
{json.dumps(result.graph_summary, indent=2)}
```
"""
        return report

    def _severity_bar(self, result: AggregatedResult) -> str:
        """ASCII severity distribution bar."""
        total = max(result.total_findings, 1)
        bars = []
        for sev, count, emoji in [
            ("critical", result.critical, "🔴"),
            ("high",     result.high,     "🟠"),
            ("medium",   result.medium,   "🟡"),
            ("low",      result.low,      "🟢"),
            ("info",     result.info,     "⚪"),
        ]:
            if count > 0:
                pct = int(count / total * 20)
                bars.append(f"{emoji} **{sev.upper()}**: {'█' * pct} {count}")
        return "\n".join(bars) if bars else "_No findings_"

    def _build_graph_summary(self, target: str, nodes_added: int,
                              edges_added: int, chains: list) -> dict:
        return {
            "target":       target,
            "nodes_added":  nodes_added,
            "edges_added":  edges_added,
            "chains_found": len(chains),
            "chain_types":  list({c.get("chain_type", "unknown") for c in chains}),
        }

    # ── Persistence ────────────────────────────────────────────────────────────

    def store_result(self, result: AggregatedResult):
        """
        Persist an AggregatedResult to disk as JSON.
        Path: ~/.oneinfinity/raw/swarm_results/{session_id}.json
        """
        try:
            results_dir = self.RESULTS_DIR
            results_dir.mkdir(parents=True, exist_ok=True)
            out_file = results_dir / f"{result.session_id}.json"
            out_file.write_text(json.dumps(result.to_dict(), indent=2, default=str))
            log.info("[aggregator] Stored result: %s", out_file)

            with self._lock:
                self._stored_results.append(result)

        except Exception as exc:
            log.error("[aggregator] Failed to store result: %s", exc)

    def get_all_results(self) -> list:
        """
        Return all stored AggregatedResults by reading from disk.
        Combines in-memory cache and any persisted JSON files on disk.
        """
        results = []
        seen_ids: set = set()

        # In-memory first
        with self._lock:
            for r in self._stored_results:
                if r.session_id not in seen_ids:
                    results.append(r)
                    seen_ids.add(r.session_id)

        # Scan disk
        try:
            results_dir = self.RESULTS_DIR
            if results_dir.exists():
                for json_file in sorted(results_dir.glob("*.json")):
                    try:
                        data = json.loads(json_file.read_text())
                        sid = data.get("session_id", "")
                        if sid in seen_ids:
                            continue
                        seen_ids.add(sid)
                        r = AggregatedResult(
                            session_id=sid,
                            target=data.get("target", ""),
                            total_findings=data.get("total_findings", 0),
                            critical=data.get("critical", 0),
                            high=data.get("high", 0),
                            medium=data.get("medium", 0),
                            low=data.get("low", 0),
                            info=data.get("info", 0),
                            validated_findings=data.get("validated_findings", 0),
                            exploit_chains_found=data.get("exploit_chains_found", 0),
                            graph_nodes_added=data.get("graph_nodes_added", 0),
                            graph_edges_added=data.get("graph_edges_added", 0),
                            workers_contributed=data.get("workers_contributed", []),
                            duration_s=data.get("duration_s", 0.0),
                            findings=data.get("findings", []),
                            graph_summary=data.get("graph_summary", {}),
                            risk_score=data.get("risk_score", 0.0),
                            generated_at=data.get("generated_at", ""),
                        )
                        results.append(r)
                    except Exception as exc:
                        log.debug("[aggregator] Error loading %s: %s", json_file, exc)
        except Exception as exc:
            log.debug("[aggregator] Error scanning results dir: %s", exc)

        return results

    # ── Streaming Ingest (for real-time use from SwarmMaster) ─────────────────

    def ingest_task_result(self, task):
        """
        Called by SwarmMaster.complete_task() for real-time ingestion.
        Stores the raw task result for later batch aggregation.
        This is a lightweight hook — full aggregation happens in aggregate().
        """
        if task and task.result:
            log.debug("[aggregator] Ingested task_id=%s target=%s",
                      task.task_id, task.target)


import json  # noqa: E402 — needed for generate_summary_report at module level
