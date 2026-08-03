"""
Deduplicator — fingerprint-based finding deduplication.

Prevents duplicate vulnerability reports from flooding reports when the
same issue is found by multiple tools (e.g. dalfox + nuclei both find XSS
on the same endpoint/parameter).

Fingerprint strategy:
  1. Normalize URL (strip fragment, sort query params alphabetically)
  2. Canonicalize vuln type (aliases collapsed: "reflected xss" → "xss")
  3. SHA-256(vuln_type + normalized_url + parameter_name)

Usage:
    dedup = Deduplicator()
    for finding in raw_findings:
        if dedup.is_new(finding):
            dedup.add(finding)
            unique_findings.append(finding)
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

log = logging.getLogger(__name__)

# Canonical vuln type aliases
_VULN_ALIASES: Dict[str, str] = {
    # XSS
    "reflected xss": "xss",
    "reflected cross-site scripting": "xss",
    "stored xss": "stored_xss",
    "stored cross-site scripting": "stored_xss",
    "dom xss": "dom_xss",
    "dom-based xss": "dom_xss",
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    # SQLi
    "sql injection": "sqli",
    "sql-injection": "sqli",
    "blind sql injection": "sqli_blind",
    "time-based blind sql injection": "sqli_time",
    "error-based sql injection": "sqli_error",
    # SSRF
    "server-side request forgery": "ssrf",
    "server side request forgery": "ssrf",
    # LFI/RFI
    "local file inclusion": "lfi",
    "local file read": "lfi",
    "remote file inclusion": "rfi",
    "path traversal": "lfi",
    "directory traversal": "lfi",
    # IDOR
    "insecure direct object reference": "idor",
    "insecure direct object references": "idor",
    # SSTI
    "server-side template injection": "ssti",
    "server side template injection": "ssti",
    # Open Redirect
    "open redirect": "open_redirect",
    "url redirection": "open_redirect",
    "open redirection": "open_redirect",
    # CRLF
    "crlf injection": "crlf",
    "http header injection": "crlf",
    # Auth
    "broken access control": "bac",
    "access control": "bac",
    "privilege escalation": "privesc",
    "authentication bypass": "auth_bypass",
    "authorization bypass": "auth_bypass",
    # Misc
    "rce": "rce",
    "remote code execution": "rce",
    "command injection": "cmdi",
    "os command injection": "cmdi",
    "xxe": "xxe",
    "xml external entity": "xxe",
    "csrf": "csrf",
    "cross-site request forgery": "csrf",
    "cors misconfiguration": "cors",
    "cors": "cors",
    "mass assignment": "mass_assignment",
    "idor": "idor",
    "ssrf": "ssrf",
    "lfi": "lfi",
    "xss": "xss",
    "sqli": "sqli",
    "sqli_blind": "sqli_blind",
}


def _canonical_vuln_type(vuln_type: str) -> str:
    return _VULN_ALIASES.get(vuln_type.lower().strip(), vuln_type.lower().strip())


def _normalize_url(url: str) -> str:
    """Sort query parameters to ensure consistent URL fingerprinting."""
    try:
        parsed = urlparse(url)
        params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            urlencode(params),
            "",  # strip fragment
        ))
        return normalized
    except Exception:
        return url.lower().strip()


def _make_fingerprint(
    vuln_type: str,
    url: str,
    parameter: str = "",
) -> str:
    canonical_type = _canonical_vuln_type(vuln_type)
    canonical_url = _normalize_url(url)
    canonical_param = parameter.strip().lower()
    raw = f"{canonical_type}::{canonical_url}::{canonical_param}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class Deduplicator:
    """
    Tracks fingerprints of seen findings and filters duplicates.

    Supports soft dedup (same fingerprint = duplicate) and
    near-dedup (same endpoint + vuln type, different parameter = related).
    """

    def __init__(self) -> None:
        self._seen: Set[str] = set()
        self._endpoint_vuln: Set[str] = set()  # endpoint+vuln without param
        self._findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    #  Core API
    # ------------------------------------------------------------------ #

    def is_new(self, finding: Dict[str, Any]) -> bool:
        """Return True if this finding has not been seen before."""
        fp = self._fingerprint(finding)
        return fp not in self._seen

    def add(self, finding: Dict[str, Any]) -> str:
        """Record a finding. Returns the fingerprint."""
        fp = self._fingerprint(finding)
        self._seen.add(fp)
        ev = self._endpoint_vuln_key(finding)
        self._endpoint_vuln.add(ev)
        self._findings.append({**finding, "_fingerprint": fp})
        return fp

    def filter_new(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return only new (unseen) findings from the list, adding them as seen."""
        result = []
        for f in findings:
            if self.is_new(f):
                self.add(f)
                result.append(f)
            else:
                log.debug("Duplicate finding skipped: %s @ %s", f.get("vuln_type"), f.get("url", f.get("endpoint")))
        return result

    def is_related(self, finding: Dict[str, Any]) -> bool:
        """
        True if same endpoint + vuln_type already has at least one finding
        (possibly with a different parameter).
        """
        ev = self._endpoint_vuln_key(finding)
        return ev in self._endpoint_vuln

    def reset(self) -> None:
        self._seen.clear()
        self._endpoint_vuln.clear()
        self._findings.clear()

    # ------------------------------------------------------------------ #
    #  Stats
    # ------------------------------------------------------------------ #

    def stats(self) -> dict:
        return {
            "unique": len(self._findings),
            "fingerprints": len(self._seen),
        }

    def list_unique(self) -> List[Dict[str, Any]]:
        return list(self._findings)

    # ------------------------------------------------------------------ #
    #  Internals
    # ------------------------------------------------------------------ #

    def _fingerprint(self, finding: Dict[str, Any]) -> str:
        vuln_type = finding.get("vuln_type") or finding.get("type") or finding.get("name") or "unknown"
        url = finding.get("url") or finding.get("endpoint") or ""
        parameter = finding.get("parameter") or finding.get("param") or ""
        # Do NOT include tool in fingerprint: same vuln found by different tools
        # (e.g. dalfox + nuclei both finding XSS on same endpoint) must dedup.
        return _make_fingerprint(str(vuln_type), str(url), str(parameter))

    def _endpoint_vuln_key(self, finding: Dict[str, Any]) -> str:
        vuln_type = finding.get("vuln_type") or finding.get("type") or finding.get("name") or "unknown"
        url = finding.get("url") or finding.get("endpoint") or ""
        canonical_type = _canonical_vuln_type(str(vuln_type))
        canonical_url = _normalize_url(str(url))
        raw = f"{canonical_type}::{canonical_url}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ── SemanticDeduplicator ──────────────────────────────────────────────────────

class SemanticDeduplicator:
    """
    Phase 1 — Semantic Root-Cause Deduplication.

    The existing Deduplicator deduplicates by URL + vuln_type + parameter.
    This class goes one level deeper: it clusters findings that share the
    same UNDERLYING ROOT CAUSE, even if they appear at different URLs.

    Example: a SQLi in a shared ORM query that affects 400 endpoints is
    reported as ONE finding with 400 affected_urls, not 400 separate findings.
    This is how a senior penetration tester writes a report.

    Strategy (two-tier):
      1. Heuristic pre-clustering: group by (vuln_type, path_template, parameter_class).
         Path template = URL with all numeric path segments replaced by {id}.
         Fast, no LLM cost.
      2. LLM validation: for groups with >1 member, ask the LLM whether they
         truly share a root cause or just look similar. Small LLM call per group.

    Called from ReportMission Step 2a, after the existing Deduplicator step.
    Input:  list of finding dicts (already URL-deduplicated by Deduplicator)
    Output: list of finding dicts — one representative per root-cause cluster,
            with an 'affected_urls' list and 'instance_count' field added.
    """

    # Path template: replace numeric segments and UUIDs with {id}
    _ID_SEGMENT = re.compile(
        r"(?<=/)\d{1,10}(?=/|$)|"
        r"(?<=/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)",
        re.I,
    )

    def cluster_root_causes(
        self,
        findings: List[Dict[str, Any]],
        use_llm: bool = True,
        max_llm_groups: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Cluster findings by root cause and return one representative per cluster.

        Each representative gains two extra fields:
          affected_urls:  list of all URLs in the cluster
          instance_count: number of findings merged into this one

        use_llm=True:  LLM validates ambiguous clusters (recommended)
        use_llm=False: heuristic-only (zero cost, less accurate)
        max_llm_groups: cap on LLM calls per batch (cost control)
        """
        if not findings:
            return findings

        # Step 1: heuristic pre-clustering
        clusters = self._heuristic_cluster(findings)
        log.info(
            "SemanticDeduplicator: %d findings → %d heuristic clusters",
            len(findings), len(clusters),
        )

        # Step 2: LLM validation for ambiguous clusters (>1 member)
        if use_llm:
            ambiguous = [c for c in clusters if len(c) > 1][:max_llm_groups]
            if ambiguous:
                clusters = self._llm_validate_clusters(clusters, ambiguous)
                log.info(
                    "SemanticDeduplicator: %d clusters after LLM validation",
                    len(clusters),
                )

        # Step 3: build output — one representative per cluster
        result = []
        for cluster in clusters:
            if len(cluster) == 1:
                f = dict(cluster[0])
                f.setdefault("affected_urls", [f.get("url", "")])
                f.setdefault("instance_count", 1)
                result.append(f)
                continue

            # Pick the representative: highest confidence in the cluster
            representative = max(cluster, key=lambda x: float(x.get("confidence", 0)))
            rep = dict(representative)
            rep["affected_urls"] = list({
                f.get("url", "") for f in cluster if f.get("url")
            })
            rep["instance_count"] = len(cluster)
            # Boost confidence slightly when multiple instances confirm root cause
            rep["confidence"] = min(1.0, float(rep.get("confidence", 0.8)) + 0.05)
            result.append(rep)

        log.info(
            "SemanticDeduplicator: final output %d root-cause findings "
            "(from %d URL-deduplicated findings)",
            len(result), len(findings),
        )
        return result

    # ── Internals ─────────────────────────────────────────────────────────────

    def _path_template(self, url: str) -> str:
        """Replace numeric/UUID path segments with {id} to get a path template."""
        try:
            parsed = urlparse(url)
            path = self._ID_SEGMENT.sub("{id}", parsed.path)
            return f"{parsed.netloc.lower()}{path}"
        except Exception:
            return url.lower()

    def _param_class(self, finding: Dict[str, Any]) -> str:
        """Classify parameter name into a semantic class."""
        param = (
            finding.get("parameter") or finding.get("param") or ""
        ).lower()
        if any(k in param for k in ["id", "uid", "uuid", "ref", "key"]):
            return "id_param"
        if any(k in param for k in ["search", "q", "query", "filter", "keyword"]):
            return "search_param"
        if any(k in param for k in ["user", "name", "login", "email"]):
            return "user_param"
        if any(k in param for k in ["file", "path", "dir", "upload"]):
            return "file_param"
        return "generic_param"

    def _cluster_key(self, finding: Dict[str, Any]) -> str:
        """Heuristic cluster key: vuln_type + path_template + param_class."""
        vt = _canonical_vuln_type(
            finding.get("vuln_type") or finding.get("type") or "unknown"
        )
        pt = self._path_template(
            finding.get("url") or finding.get("endpoint") or ""
        )
        pc = self._param_class(finding)
        return f"{vt}::{pt}::{pc}"

    def _heuristic_cluster(
        self, findings: List[Dict[str, Any]]
    ) -> List[List[Dict[str, Any]]]:
        """Group findings by heuristic cluster key."""
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            key = self._cluster_key(f)
            groups.setdefault(key, []).append(f)
        return list(groups.values())

    def _llm_validate_clusters(
        self,
        all_clusters: List[List[Dict[str, Any]]],
        ambiguous: List[List[Dict[str, Any]]],
    ) -> List[List[Dict[str, Any]]]:
        """
        Ask LLM whether heuristically-grouped clusters truly share a root cause.
        Splits clusters that the LLM says are NOT the same root cause.
        """
        try:
            from oneinfinity.orchestration.offensive_router import get_model_for_task
            provider = get_model_for_task("passive_analysis")
        except Exception as exc:
            log.debug("SemanticDeduplicator: LLM unavailable: %s", exc)
            return all_clusters

        validated_clusters = [c for c in all_clusters if len(c) == 1]
        for cluster in ambiguous:
            keep_merged = self._ask_llm_same_root(provider, cluster)
            if keep_merged:
                validated_clusters.append(cluster)
            else:
                # Split: each finding becomes its own cluster
                validated_clusters.extend([[f] for f in cluster])
        return validated_clusters

    @staticmethod
    def _ask_llm_same_root(provider, cluster: List[Dict[str, Any]]) -> bool:
        """
        Ask the LLM: do these findings share the same root cause?
        Returns True to merge, False to split.
        """
        sample = cluster[:5]  # cap prompt size
        items = "\n".join(
            f"  [{i+1}] vuln_type={f.get('vuln_type')} url={f.get('url','')} "
            f"param={f.get('parameter') or f.get('param','')} "
            f"evidence={str(f.get('evidence',''))[:80]}"
            for i, f in enumerate(sample)
        )
        prompt = (
            f"These {len(cluster)} security findings have the same vulnerability type "
            f"and similar URL patterns.\n\n{items}\n\n"
            f"Do they share the SAME root cause (same vulnerable code path, "
            f"same parameter class, same underlying flaw)? "
            f"Answer with ONLY 'yes' or 'no'."
        )
        try:
            resp = provider.chat(
                prompt=prompt,
                system="You are a security expert. Answer only 'yes' or 'no'.",
                max_tokens=10,
                temperature=0.0,
            )
            return resp.text.strip().lower().startswith("y")
        except Exception as exc:
            log.debug("SemanticDeduplicator._ask_llm_same_root failed: %s", exc)
            return True  # default: merge on LLM failure (conservative)
