"""Risk Analyzer — scores the attack graph and produces a risk report."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
import datetime

CVSS_SEVERITY = {
    "critical": 9.0, "high": 7.0, "medium": 5.0,
    "low": 2.5, "info": 0.5, "none": 0.0,
}

IMPACT_MULTIPLIER = {
    "rce": 2.0, "remote_code_execution": 2.0,
    "data_exfil": 1.8, "ato": 1.7, "account_takeover": 1.7,
    "priv_esc": 1.6, "ssrf": 1.5, "sqli": 1.6,
    "xss": 1.3, "idor": 1.4, "lfi": 1.4,
    "open_redirect": 1.1, "misconfig": 1.0, "info_disclosure": 0.9,
}


@dataclass
class RiskScore:
    node_id: str
    node_label: str
    vuln_type: str
    base_cvss: float
    exploitability: float
    chain_bonus: float
    business_impact: float
    final_score: float
    severity: str
    rationale: str

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id, "node_label": self.node_label,
            "vuln_type": self.vuln_type, "base_cvss": round(self.base_cvss, 2),
            "exploitability": round(self.exploitability, 2),
            "chain_bonus": round(self.chain_bonus, 2),
            "business_impact": round(self.business_impact, 2),
            "final_score": round(self.final_score, 2),
            "severity": self.severity, "rationale": self.rationale,
        }


@dataclass
class GraphRiskReport:
    target: str
    generated_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    total_nodes: int = 0
    vuln_nodes: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_risk_score: float = 0.0
    overall_severity: str = "none"
    risk_scores: List[RiskScore] = field(default_factory=list)
    top_risks: List[RiskScore] = field(default_factory=list)
    chains_detected: int = 0
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "total_nodes": self.total_nodes,
            "vuln_nodes": self.vuln_nodes,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "overall_risk_score": round(self.overall_risk_score, 2),
            "overall_severity": self.overall_severity,
            "top_risks": [r.to_dict() for r in self.top_risks],
            "chains_detected": self.chains_detected,
            "recommendations": self.recommendations,
        }


class RiskAnalyzer:
    """Analyzes graph nodes and exploit chains to produce a risk report."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(RiskAnalyzer, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, graph_engine=None, chain_engine=None):
        if self._initialized and graph_engine is None and chain_engine is None:
            return
        self.graph = graph_engine
        self.chain_engine = chain_engine
        self._initialized = True

    def analyze(self, target: str) -> GraphRiskReport:
        from .graph_store import _enum_to_str
        report = GraphRiskReport(target=target)

        if self.graph is None:
            return self._demo_report(target)

        try:
            nodes = self.graph.find_nodes(target=target) if target else []
        except Exception:
            nodes = []

        report.total_nodes = len(nodes)
        risk_scores = []

        for node in nodes:
            # Normalise NodeType: handles Enum instances and repr strings
            nt = _enum_to_str(getattr(node, "node_type", ""))
            if "vulnerability" not in nt:
                continue
            report.vuln_nodes += 1
            meta = getattr(node, "metadata", {})
            label = getattr(node, "label", "")
            nid = getattr(node, "id", "")
            vuln_type = meta.get("vuln_type", meta.get("type", "unknown")).lower()
            severity_str = meta.get("severity", "medium").lower()
            base_cvss = CVSS_SEVERITY.get(severity_str, 5.0)
            exploitability = self._exploitability(meta)
            chain_bonus = self._chain_bonus(vuln_type)
            business_impact = IMPACT_MULTIPLIER.get(vuln_type, 1.0)
            final = min((base_cvss + exploitability + chain_bonus) * business_impact, 10.0)
            final_sev = self._severity_label(final)

            if final_sev == "critical":
                report.critical_count += 1
            elif final_sev == "high":
                report.high_count += 1
            elif final_sev == "medium":
                report.medium_count += 1
            else:
                report.low_count += 1

            rs = RiskScore(
                node_id=nid, node_label=label, vuln_type=vuln_type,
                base_cvss=base_cvss, exploitability=exploitability,
                chain_bonus=chain_bonus, business_impact=business_impact,
                final_score=final, severity=final_sev,
                rationale=f"{vuln_type} ({severity_str}); impact×{business_impact}",
            )
            risk_scores.append(rs)

        chains = []
        if self.chain_engine:
            try:
                chains = self.chain_engine.detect_chains(target)
            except Exception:
                pass
        report.chains_detected = len(chains)

        if risk_scores:
            report.overall_risk_score = max(r.final_score for r in risk_scores)
        report.overall_severity = self._severity_label(report.overall_risk_score)

        risk_scores.sort(key=lambda r: -r.final_score)
        report.risk_scores = risk_scores
        report.top_risks = risk_scores[:5]
        report.recommendations = self._build_recommendations(report, chains)
        return report

    def _exploitability(self, meta: dict) -> float:
        score = 0.0
        if meta.get("exploitable") or meta.get("confirmed"):
            score += 2.0
        if meta.get("public_exploit"):
            score += 1.5
        if meta.get("auth_required") is False:
            score += 1.0
        return min(score, 3.0)

    def _chain_bonus(self, vuln_type: str) -> float:
        chain_vulns = {"xss", "ssrf", "sqli", "lfi", "jwt_weakness", "xxe",
                       "idor", "file_upload", "open_redirect"}
        return 1.5 if vuln_type in chain_vulns else 0.0

    def _severity_label(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 1.0:
            return "low"
        return "info"

    def _build_recommendations(self, report: GraphRiskReport, chains: list) -> List[str]:
        recs = []
        if report.critical_count > 0:
            recs.append(f"URGENT: {report.critical_count} critical finding(s) require immediate remediation")
        if report.chains_detected > 0:
            recs.append(f"{report.chains_detected} exploit chain(s) detected — prioritize chain-breaking patches")
        if report.high_count > 0:
            recs.append(f"Address {report.high_count} high-severity finding(s) within 7 days")
        if report.medium_count > 3:
            recs.append("Consider a comprehensive security review — significant medium-severity density")
        if not recs:
            recs.append("No high-impact findings detected; maintain regular scanning cadence")
        return recs

    def _demo_report(self, target: str) -> GraphRiskReport:
        top = [
            RiskScore(node_id="v1", node_label="XSS on /search",
                      vuln_type="xss", base_cvss=7.0, exploitability=2.0,
                      chain_bonus=1.5, business_impact=1.3,
                      final_score=8.45, severity="high",
                      rationale="Reflected XSS; chain-eligible"),
            RiskScore(node_id="v2", node_label="SSRF on /fetch",
                      vuln_type="ssrf", base_cvss=9.0, exploitability=2.0,
                      chain_bonus=1.5, business_impact=1.5,
                      final_score=10.0, severity="critical",
                      rationale="SSRF reaching cloud metadata; critical impact"),
        ]
        return GraphRiskReport(
            target=target, total_nodes=45, vuln_nodes=12,
            critical_count=2, high_count=4, medium_count=6, low_count=0,
            overall_risk_score=10.0, overall_severity="critical",
            risk_scores=top, top_risks=top, chains_detected=2,
            recommendations=[
                "URGENT: 2 critical finding(s) require immediate remediation",
                "2 exploit chain(s) detected — prioritize chain-breaking patches",
            ],
        )


# Module-level singleton instance (used by attack_planner and other callers)
risk_analyzer = RiskAnalyzer()
