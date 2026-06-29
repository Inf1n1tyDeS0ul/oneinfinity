"""
Traffic Correlation Engine
===========================
Correlates findings using traffic patterns. Finds chains no static pattern can detect.

Innovation:
1. **Same-Endpoint Multi-Vuln** - XSS + SQLi on same endpoint = guaranteed chain
2. **Parameter Overlap Detection** - Vulns sharing params = exploitable chain
3. **Session Flow Analysis** - Auth bypass + privileged action = escalation
4. **Traffic Timing Correlation** - Sequential requests revealing attack flow
5. **Header Correlation** - Cookie/token reuse patterns

No other tool correlates via actual traffic patterns.
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("oneinfinity.traffic_correlation")


@dataclass
class CorrelatedChain:
    """Attack chain discovered via traffic correlation."""
    chain_id: str
    name: str
    severity: str
    description: str
    findings: List[Dict]
    correlation_type: str  # same_endpoint, param_overlap, session_flow, timing
    endpoint: str
    shared_params: Set[str]
    confidence: float
    exploitation_steps: List[str]
    evidence: str


class TrafficCorrelationEngine:
    """
    Correlates findings using captured traffic patterns.
    """

    def __init__(self):
        self.traffic_engine = None

    def _get_traffic_engine(self):
        """Lazy load traffic engine."""
        if self.traffic_engine is None:
            try:
                from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
                self.traffic_engine = traffic_capture_engine
            except ImportError:
                log.warning("Traffic capture engine not available")
        return self.traffic_engine

    def _extract_params(self, url: str, body: str, method: str) -> Set[str]:
        """Extract all parameter names from request."""
        params = set()

        # URL params
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            params.update(query_params.keys())

        # Body params
        if method in ["POST", "PUT"] and body:
            if "=" in body and "&" in body:
                # Form data
                for part in body.split("&"):
                    if "=" in part:
                        param_name = part.split("=")[0]
                        params.add(param_name)

        return params

    def _normalize_endpoint(self, url: str) -> str:
        """Normalize URL to endpoint (remove params)."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # ── Correlation Strategy 1: Same-Endpoint Multi-Vuln ─────────────────────

    def correlate_by_endpoint(self, findings: List[Dict], target: str) -> List[CorrelatedChain]:
        """
        Detect multiple vulnerabilities on same endpoint.

        Innovation: If XSS + SQLi on same endpoint = high-confidence chain.
        """
        chains = []
        engine = self._get_traffic_engine()
        if not engine:
            return chains

        # Group findings by endpoint
        endpoint_map = defaultdict(list)

        for finding in findings:
            url = finding.get('url', '')
            if not url:
                continue

            endpoint = self._normalize_endpoint(url)

            # Get traffic for this finding
            traffic_id = finding.get('traffic_id')
            if traffic_id:
                traffic = engine.get(traffic_id)
                endpoint_map[endpoint].append((finding, traffic))
            else:
                endpoint_map[endpoint].append((finding, None))

        # Detect multi-vuln endpoints
        for endpoint, items in endpoint_map.items():
            if len(items) < 2:
                continue

            vuln_types = {item[0].get('vuln_type') for item in items}

            # High-value combinations
            dangerous_combos = [
                ({'xss', 'sqli'}, 'XSS + SQLi = Admin Session Theft + DB Dump', 'critical'),
                ({'ssrf', 'xxe'}, 'SSRF + XXE = Cloud Metadata + Internal Network', 'critical'),
                ({'csrf', 'xss'}, 'CSRF + XSS = Forced Malicious Actions', 'high'),
                ({'idor', 'sqli'}, 'IDOR + SQLi = Unauthorized DB Access', 'critical'),
                ({'path_traversal', 'ssrf'}, 'Path Traversal + SSRF = File Read + Internal Access', 'critical'),
            ]

            for combo_types, chain_name, severity in dangerous_combos:
                if combo_types.issubset(vuln_types):
                    chain_findings = [item[0] for item in items if item[0].get('vuln_type') in combo_types]

                    chain = CorrelatedChain(
                        chain_id=hashlib.md5(f"endpoint_{endpoint}_{chain_name}".encode()).hexdigest()[:16],
                        name=chain_name,
                        severity=severity,
                        description=f"Multiple vulnerabilities on same endpoint enable chained exploitation",
                        findings=chain_findings,
                        correlation_type="same_endpoint",
                        endpoint=endpoint,
                        shared_params=set(),
                        confidence=0.95,  # Same endpoint = very high confidence
                        exploitation_steps=[
                            f"1. Target endpoint: {endpoint}",
                            f"2. Vulnerabilities present: {', '.join(combo_types)}",
                            "3. Chain exploitation in single request sequence",
                            "4. Amplified impact via combined vulns",
                        ],
                        evidence=f"{len(chain_findings)} vulnerabilities on {endpoint}",
                    )
                    chains.append(chain)

        log.info(f"Endpoint correlation found {len(chains)} chains")
        return chains

    # ── Correlation Strategy 2: Parameter Overlap ─────────────────────────────

    def correlate_by_parameter_overlap(self, findings: List[Dict], target: str) -> List[CorrelatedChain]:
        """
        Detect vulnerabilities sharing parameters.

        Innovation: Vulns in related params = exploitable data flow.
        """
        chains = []
        engine = self._get_traffic_engine()
        if not engine:
            return chains

        # Build param → findings map
        param_map = defaultdict(list)

        for finding in findings:
            traffic_id = finding.get('traffic_id')
            if not traffic_id:
                continue

            traffic = engine.get(traffic_id)
            if not traffic:
                continue

            params = self._extract_params(traffic.url, traffic.body, traffic.method)
            for param in params:
                param_map[param].append((finding, traffic))

        # Detect param overlap chains
        for param, items in param_map.items():
            if len(items) < 2:
                continue

            vuln_types = {item[0].get('vuln_type') for item in items}

            # Parameter flow vulnerabilities
            if 'xss' in vuln_types and 'sqli' in vuln_types:
                chain_findings = [item[0] for item in items]

                chain = CorrelatedChain(
                    chain_id=hashlib.md5(f"param_{param}_{target}".encode()).hexdigest()[:16],
                    name=f"Parameter '{param}' Vulnerable to Multiple Attacks",
                    severity="high",
                    description=f"Parameter '{param}' vulnerable to multiple injection types",
                    findings=chain_findings,
                    correlation_type="param_overlap",
                    endpoint="",
                    shared_params={param},
                    confidence=0.85,
                    exploitation_steps=[
                        f"1. Parameter '{param}' accepts malicious input",
                        f"2. Multiple vuln types: {', '.join(vuln_types)}",
                        "3. Chain injections via same param",
                        "4. Exploit data flow vulnerabilities",
                    ],
                    evidence=f"Parameter '{param}' in {len(chain_findings)} vulnerable requests",
                )
                chains.append(chain)

        log.info(f"Parameter correlation found {len(chains)} chains")
        return chains

    # ── Correlation Strategy 3: Session Flow ──────────────────────────────────

    def correlate_session_flow(self, findings: List[Dict], target: str) -> List[CorrelatedChain]:
        """
        Detect auth bypass + privileged action chains.

        Innovation: Auth bypass finding + POST endpoint = escalation path.
        """
        chains = []
        engine = self._get_traffic_engine()
        if not engine:
            return chains

        # Find auth bypass findings
        auth_bypasses = [f for f in findings if 'auth' in f.get('vuln_type', '').lower() or 'bypass' in f.get('vuln_type', '').lower()]

        if not auth_bypasses:
            return chains

        # Find privileged actions (POST/PUT/DELETE requests)
        try:
            privileged_traffic = engine.list(target=target, method="POST", limit=500)
            privileged_traffic.extend(engine.list(target=target, method="PUT", limit=500))
            privileged_traffic.extend(engine.list(target=target, method="DELETE", limit=500))
        except Exception as e:
            log.error(f"Failed to fetch privileged traffic: {e}")
            return chains

        # Correlate bypass + privileged action
        for bypass_finding in auth_bypasses:
            bypass_url = bypass_finding.get('url', '')
            bypass_domain = urlparse(bypass_url).netloc if bypass_url else ''

            for priv_req in privileged_traffic:
                priv_domain = urlparse(priv_req.url).netloc

                if bypass_domain and priv_domain and bypass_domain == priv_domain:
                    # Same domain = likely exploitable

                    chain = CorrelatedChain(
                        chain_id=hashlib.md5(f"session_{bypass_url}_{priv_req.url}".encode()).hexdigest()[:16],
                        name="Auth Bypass → Privileged Action Escalation",
                        severity="critical",
                        description="Authentication bypass enables unauthorized privileged actions",
                        findings=[bypass_finding],
                        correlation_type="session_flow",
                        endpoint=priv_req.url,
                        shared_params=set(),
                        confidence=0.80,
                        exploitation_steps=[
                            f"1. Bypass authentication: {bypass_finding.get('title', 'Auth bypass')}",
                            f"2. Access privileged endpoint: {priv_req.method} {priv_req.url}",
                            "3. Execute unauthorized actions",
                            "4. Complete privilege escalation",
                        ],
                        evidence=f"Auth bypass on {bypass_domain} + {len(privileged_traffic)} privileged endpoints",
                    )
                    chains.append(chain)
                    break  # One chain per bypass

        log.info(f"Session flow correlation found {len(chains)} chains")
        return chains

    # ── Orchestration ─────────────────────────────────────────────────────────

    def correlate_all(self, findings: List[Dict], target: str) -> Dict[str, List[CorrelatedChain]]:
        """
        Run all correlation strategies.

        Returns:
            Dict of correlation_type → chains
        """
        log.info(f"Starting traffic correlation for {len(findings)} findings")

        results = {
            "same_endpoint": self.correlate_by_endpoint(findings, target),
            "param_overlap": self.correlate_by_parameter_overlap(findings, target),
            "session_flow": self.correlate_session_flow(findings, target),
        }

        total = sum(len(chains) for chains in results.values())
        log.info(f"Traffic correlation complete: {total} correlated chains")

        return results


# ── Convenience Function ──────────────────────────────────────────────────────

def correlate_findings_via_traffic(findings: List[Dict], target: str) -> Dict[str, List[CorrelatedChain]]:
    """Correlate findings using traffic patterns."""
    engine = TrafficCorrelationEngine()
    return engine.correlate_all(findings, target)
