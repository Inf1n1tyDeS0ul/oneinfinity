"""
semantic_traffic_analyzer.py — HTTP Semantics Intelligence Layer

Uses LLM-based semantic analysis to:
1. Predict hidden endpoints from discovered URL patterns (REST API surface expansion)
2. Identify parameters likely vulnerable to IDOR, injection, business logic flaws
3. Cluster HTTP requests by semantic similarity to find anomalous behavior
4. Surface hidden API paths by semantic context (e.g., /users/{id} → /users/{id}/permissions)

This is a NEW capability — no existing implementation. Council Sprint 4.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("oneinfinity.intelligence.semantic_traffic_analyzer")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PredictedEndpoint:
    path: str
    method: str
    reason: str
    priority: str = "medium"  # high / medium / low
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "method": self.method,
            "reason": self.reason,
            "priority": self.priority,
            "confidence": self.confidence,
        }


@dataclass
class ParameterRisk:
    param_name: str
    risk_type: str  # idor / injection / business_logic
    reason: str
    endpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "param_name": self.param_name,
            "risk_type": self.risk_type,
            "reason": self.reason,
            "endpoints": self.endpoints,
        }


@dataclass
class TrafficCluster:
    cluster_id: str
    pattern: str
    urls: list[str]
    anomaly_score: float = 0.0
    anomaly_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "pattern": self.pattern,
            "urls": self.urls,
            "anomaly_score": self.anomaly_score,
            "anomaly_reason": self.anomaly_reason,
        }


# ---------------------------------------------------------------------------
# Known high-sensitivity path patterns (used for filtering predictions)
# ---------------------------------------------------------------------------

_HIGH_SENSITIVITY_RE = re.compile(
    r"/(admin|internal|private|secret|management|payment|billing|checkout"
    r"|auth|login|token|oauth|config|settings|env|debug|dev|api/v\d+)",
    re.I,
)


class SemanticTrafficAnalyzer:
    """
    LLM-powered semantic analysis of HTTP traffic patterns.

    Usage::
        analyzer = SemanticTrafficAnalyzer(target="https://example.com")
        predicted = analyzer.analyze_endpoints(discovered_urls)
        risky_params = analyzer.analyze_parameters(request_log)
    """

    def __init__(self, target: str = "", llm_provider=None) -> None:
        self.target = target
        self._provider = llm_provider  # can be injected or auto-detected

    def _get_provider(self):
        if self._provider is not None:
            return self._provider
        try:
            from oneinfinity.infra.llm_provider import LLMProviderFactory
            self._provider = LLMProviderFactory().auto_detect()
        except Exception as exc:
            log.debug("[SemanticTraffic] LLM provider unavailable: %s", exc)
        return self._provider

    # ── Endpoint Prediction ───────────────────────────────────────────────────

    def analyze_endpoints(
        self,
        urls: list[str],
        max_predictions: int = 20,
    ) -> list[PredictedEndpoint]:
        """
        Given discovered URLs, predict additional hidden endpoints that likely exist.
        Uses LLM to reason about REST API patterns and common endpoint conventions.
        """
        if not urls:
            return []

        provider = self._get_provider()
        if provider is None:
            return self._heuristic_endpoint_prediction(urls)

        # Normalize and deduplicate URLs for the prompt
        paths = self._extract_paths(urls)
        paths_sample = "\n".join(paths[:50])  # Cap context size

        prompt = (
            f"You are an expert API security researcher analyzing a web application's URL structure.\n\n"
            f"Discovered endpoints:\n{paths_sample}\n\n"
            f"Based on these patterns, predict up to {max_predictions} additional API endpoints "
            f"that likely exist but haven't been discovered yet. Consider:\n"
            f"- REST resource nesting (e.g. /users/{{id}} → /users/{{id}}/settings, /users/{{id}}/roles)\n"
            f"- Admin/management variants (e.g. /api/v1/users → /api/v1/admin/users)\n"
            f"- Common CRUD endpoints (list, detail, create, update, delete)\n"
            f"- Version endpoints (v1 → v2, v3)\n"
            f"- Batch/bulk endpoints (/users/bulk, /orders/batch)\n"
            f"- Export endpoints (/users/export, /reports/download)\n"
            f"- Status/health variants (/admin/health, /api/status)\n\n"
            f"Focus on endpoints that could reveal security vulnerabilities (IDOR, auth bypass, "
            f"information disclosure, privilege escalation).\n\n"
            f"Return ONLY valid JSON:\n"
            '{"predicted": [{"path": "/api/v1/users/1/permissions", "method": "GET", '
            '"reason": "Users resource likely has permissions sub-resource", '
            '"priority": "high"}]}'
        )

        try:
            resp = provider.chat(
                prompt,
                system="You are an expert API security researcher. Respond ONLY with valid JSON.",
                max_tokens=2000,
                temperature=0.4,
            )
            raw = json.loads(resp.text.strip() if resp else "{}")
            predicted_raw = raw.get("predicted", [])

            results = []
            for item in predicted_raw:
                path = item.get("path", "")
                if not path or not path.startswith("/"):
                    continue
                results.append(PredictedEndpoint(
                    path=path,
                    method=item.get("method", "GET"),
                    reason=item.get("reason", ""),
                    priority=item.get("priority", "medium"),
                    confidence=0.6 if _HIGH_SENSITIVITY_RE.search(path) else 0.4,
                ))

            log.info("[SemanticTraffic] Predicted %d new endpoints from %d discovered", len(results), len(urls))
            return results

        except Exception as exc:
            log.debug("[SemanticTraffic] Endpoint prediction failed: %s", exc)
            return self._heuristic_endpoint_prediction(urls)

    # ── Parameter Risk Analysis ───────────────────────────────────────────────

    def analyze_parameters(
        self,
        request_log: list[dict],
    ) -> list[ParameterRisk]:
        """
        Analyze parameter names across intercepted requests to identify security risks.
        Groups parameters by risk category: IDOR, injection, business logic.
        """
        if not request_log:
            return []

        # Extract all unique parameter names
        param_occurrences: dict[str, list[str]] = {}
        for req in request_log:
            url = req.get("url", "")
            params = req.get("params", {}) or {}
            body = req.get("body", {}) or {}

            # From URL query string
            if "?" in url:
                qs = url.split("?", 1)[1]
                for pair in qs.split("&"):
                    name = pair.split("=")[0]
                    if name:
                        param_occurrences.setdefault(name, []).append(url)

            # From request body
            for key in list(params.keys()) + list(body.keys()):
                if key:
                    param_occurrences.setdefault(key, []).append(url)

        if not param_occurrences:
            return []

        provider = self._get_provider()
        param_names = list(param_occurrences.keys())[:80]  # Cap for prompt size

        if provider is None:
            return self._heuristic_parameter_analysis(param_occurrences)

        prompt = (
            f"You are an expert API security researcher. Analyze these HTTP request parameter names "
            f"for security vulnerabilities:\n\nParameters: {', '.join(param_names)}\n\n"
            f"Classify each parameter by risk:\n"
            f"- idor: numeric IDs, user identifiers, object references (id, user_id, account_id, order_id)\n"
            f"- injection: user-controlled input fields (query, search, q, filter, sort, name, email)\n"
            f"- business_logic: financial/state/quantity fields (amount, price, quantity, status, role, discount)\n"
            f"- sensitive: data fields that shouldn't be user-controllable (admin, debug, internal, token)\n\n"
            f"Return ONLY valid JSON:\n"
            '{"idor_params": ["id", "user_id"], "injection_params": ["q", "search"], '
            '"business_logic_params": ["amount", "status"], "sensitive_params": ["admin", "debug"]}'
        )

        try:
            resp = provider.chat(
                prompt,
                system="You are an API security expert. Respond ONLY with valid JSON.",
                max_tokens=1000,
                temperature=0.2,
            )
            raw = json.loads(resp.text.strip() if resp else "{}")

            results: list[ParameterRisk] = []
            for risk_type, params in [
                ("idor", raw.get("idor_params", [])),
                ("injection", raw.get("injection_params", [])),
                ("business_logic", raw.get("business_logic_params", [])),
                ("sensitive", raw.get("sensitive_params", [])),
            ]:
                for p in params:
                    if p in param_occurrences:
                        results.append(ParameterRisk(
                            param_name=p,
                            risk_type=risk_type,
                            reason=f"Parameter '{p}' is classified as {risk_type} risk",
                            endpoints=param_occurrences[p][:5],
                        ))

            log.info("[SemanticTraffic] Identified %d risky parameters from %d total", len(results), len(param_names))
            return results

        except Exception as exc:
            log.debug("[SemanticTraffic] Parameter analysis failed: %s", exc)
            return self._heuristic_parameter_analysis(param_occurrences)

    # ── Request Clustering ────────────────────────────────────────────────────

    def cluster_requests(
        self,
        requests: list[dict],
    ) -> list[TrafficCluster]:
        """
        Group HTTP requests by semantic pattern. Identifies anomalous outlier requests
        that may represent attack vectors or unexpected behaviors.
        """
        if not requests:
            return []

        # Simple path-based clustering using regex normalization
        pattern_groups: dict[str, list[str]] = {}
        for req in requests:
            url = req.get("url", "")
            pattern = self._normalize_path(url)
            pattern_groups.setdefault(pattern, []).append(url)

        clusters: list[TrafficCluster] = []
        for i, (pattern, urls) in enumerate(sorted(pattern_groups.items(), key=lambda x: len(x[1]), reverse=True)):
            # Flag singleton requests as potentially anomalous
            anomaly_score = 1.0 if len(urls) == 1 else 0.0
            anomaly_reason = "Singleton request — unique pattern not seen elsewhere" if anomaly_score > 0 else ""

            clusters.append(TrafficCluster(
                cluster_id=f"cluster_{i}",
                pattern=pattern,
                urls=urls[:20],
                anomaly_score=anomaly_score,
                anomaly_reason=anomaly_reason,
            ))

        return clusters

    # ── Semantic Diff ─────────────────────────────────────────────────────────

    def semantic_diff_responses(
        self,
        clean_response: str,
        payload_response: str,
        vuln_type: str,
    ) -> tuple[bool, float, str]:
        """
        LLM-powered semantic comparison of clean vs payload HTTP responses.
        Returns (is_vulnerable: bool, confidence: float, evidence: str).

        Used as a tiebreaker when status-code-based validation is ambiguous.
        """
        provider = self._get_provider()
        if provider is None:
            return False, 0.0, "No LLM provider available"

        # Truncate to avoid excessive token usage
        clean_snippet = clean_response[:600]
        payload_snippet = payload_response[:600]

        prompt = (
            f"Compare these two HTTP responses from a security test.\n\n"
            f"Response A (clean/baseline):\n{clean_snippet}\n\n"
            f"Response B (with {vuln_type} attack payload):\n{payload_snippet}\n\n"
            f"Does Response B show evidence of a {vuln_type} vulnerability? Look for:\n"
            f"- Error messages revealing internal state (SQL errors, stack traces)\n"
            f"- Reflected payload content (XSS, SSTI evaluation)\n"
            f"- Unexpected data disclosure (other users' data for IDOR)\n"
            f"- Behavioral changes indicating injection (timing, content changes)\n"
            f"- Server-side execution evidence (file content, command output)\n\n"
            f"Be conservative: only flag as vulnerable if there's clear evidence.\n\n"
            f"Return ONLY valid JSON:\n"
            '{"is_vulnerable": false, "confidence": 0.0-1.0, "evidence": "...", "reasoning": "..."}'
        )

        try:
            resp = provider.chat(
                prompt,
                system="You are an expert web security analyst. Respond ONLY with valid JSON.",
                max_tokens=500,
                temperature=0.1,
            )
            raw = json.loads(resp.text.strip() if resp else "{}")
            is_vuln = bool(raw.get("is_vulnerable", False))
            confidence = float(raw.get("confidence", 0.0))
            evidence = str(raw.get("evidence", ""))
            return is_vuln, confidence, evidence

        except Exception as exc:
            log.debug("[SemanticTraffic] Semantic diff failed: %s", exc)
            return False, 0.0, ""

    # ── Heuristic fallbacks (no LLM) ─────────────────────────────────────────

    def _heuristic_endpoint_prediction(self, urls: list[str]) -> list[PredictedEndpoint]:
        """Predict endpoints without LLM using known REST conventions."""
        paths = self._extract_paths(urls)
        predictions = []
        seen = set(paths)

        for path in paths:
            # Add common sub-resources
            for sub in ["/permissions", "/settings", "/profile", "/history", "/export"]:
                candidate = path.rstrip("/") + sub
                if candidate not in seen:
                    seen.add(candidate)
                    predictions.append(PredictedEndpoint(
                        path=candidate,
                        method="GET",
                        reason=f"Common sub-resource of {path}",
                        priority="medium",
                        confidence=0.3,
                    ))

            # Strip IDs and add list endpoint
            normalized = re.sub(r"/\d+", "", path)
            if normalized not in seen and normalized != path:
                seen.add(normalized)
                predictions.append(PredictedEndpoint(
                    path=normalized,
                    method="GET",
                    reason=f"List endpoint inferred from {path}",
                    priority="low",
                    confidence=0.4,
                ))

        return predictions[:20]

    def _heuristic_parameter_analysis(
        self,
        param_occurrences: dict[str, list[str]],
    ) -> list[ParameterRisk]:
        """Classify parameters without LLM using regex patterns."""
        results = []
        idor_re = re.compile(r"^(id|user_?id|account_?id|order_?id|item_?id|product_?id|customer_?id)$", re.I)
        inject_re = re.compile(r"^(q|query|search|filter|sort|name|email|username|title|body|content|message)$", re.I)
        biz_re = re.compile(r"^(amount|price|quantity|qty|discount|coupon|status|role|plan|tier|limit|offset)$", re.I)

        for param, endpoints in param_occurrences.items():
            if idor_re.match(param):
                results.append(ParameterRisk(param, "idor", f"'{param}' is an object identifier", endpoints[:5]))
            elif inject_re.match(param):
                results.append(ParameterRisk(param, "injection", f"'{param}' is a user input field", endpoints[:5]))
            elif biz_re.match(param):
                results.append(ParameterRisk(param, "business_logic", f"'{param}' is a business logic parameter", endpoints[:5]))

        return results

    def _extract_paths(self, urls: list[str]) -> list[str]:
        """Extract and normalize URL paths from a list of full URLs."""
        paths = set()
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url if url.startswith("http") else f"https://x{url}")
                path = parsed.path or "/"
                paths.add(path)
            except Exception:
                pass
        return sorted(paths)

    def _normalize_path(self, url: str) -> str:
        """Replace numeric segments with {id} for clustering."""
        try:
            parsed = urllib.parse.urlparse(url if url.startswith("http") else f"https://x{url}")
            path = re.sub(r"/\d+", "/{id}", parsed.path)
            # Also normalize UUIDs
            path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "/{uuid}", path, flags=re.I)
            return path
        except Exception:
            return url
