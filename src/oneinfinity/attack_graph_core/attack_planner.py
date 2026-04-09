"""
attack_planner.py — Analyzes attack graph and determines the next best attack actions.
Produces a prioritized AttackPlan that drives autonomous testing decisions.
"""

import logging
import uuid
import time
from dataclasses import dataclass, field
from typing import Optional

from .graph_engine import NodeType, EdgeType, get_engine
from .graph_query_engine import GraphQueryEngine, AttackPath, graph_query_engine
from .risk_analyzer import RiskAnalyzer, risk_analyzer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Impact priority mapping (lower number = higher priority)
# ---------------------------------------------------------------------------

IMPACT_PRIORITY = {
    "rce": 1,
    "data_exfil": 1,
    "ato": 2,
    "priv_esc": 2,
    "ssrf_cloud": 3,
    "sql_exfil": 3,
    "xss_ato": 4,
    "subdomain_takeover": 5,
    "lfi": 5,
    "xxe": 5,
    "file_upload": 5,
    "ssti": 5,
    "deserialization": 5,
    "open_redirect": 7,
    "info_disclosure": 8,
    "misconfig": 9,
    "default": 6,
}

# Maps vuln type keywords to best tool
TOOL_MAP = {
    "sqli": "sqlmap",
    "sql_injection": "sqlmap",
    "xss": "dalfox",
    "cross_site_scripting": "dalfox",
    "ssrf": "nuclei",
    "ssti": "nuclei",
    "lfi": "nuclei",
    "rce": "nuclei",
    "xxe": "nuclei",
    "idor": "custom_http",
    "bac": "custom_http",
    "auth_bypass": "custom_http",
    "jwt": "jwt_tool",
    "open_redirect": "custom_http",
    "subdomain_takeover": "nuclei",
    "misconfig": "nuclei",
    "cors": "custom_http",
    "mass_assignment": "custom_http",
    "insecure_upload": "custom_http",
    "deserialization": "ysoserial",
    "secret": "trufflehog",
    "credential": "trufflehog",
    "default": "nuclei",
}

# Maps vuln type to expected impact category
IMPACT_MAP = {
    "sqli": "sql_exfil",
    "sql_injection": "sql_exfil",
    "xss": "xss_ato",
    "ssrf": "ssrf_cloud",
    "ssti": "rce",
    "rce": "rce",
    "lfi": "lfi",
    "xxe": "ssrf_cloud",
    "idor": "priv_esc",
    "bac": "priv_esc",
    "auth_bypass": "ato",
    "jwt": "ato",
    "open_redirect": "ato",
    "subdomain_takeover": "subdomain_takeover",
    "file_upload": "rce",
    "deserialization": "rce",
    "default": "info_disclosure",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AttackAction:
    action_id: str
    action_type: str           # test_vulnerability / exploit / escalate / enumerate / validate
    target_node_id: str
    target_label: str
    priority: int              # 1 (highest) - 10
    expected_impact: str       # ato / rce / data_exfil / priv_esc / info_disclosure
    estimated_cvss: float
    prerequisites: list = field(default_factory=list)
    suggested_tool: str = ""
    suggested_payload: str = ""
    reasoning: str = ""
    confidence: float = 0.5

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target_node_id": self.target_node_id,
            "target_label": self.target_label,
            "priority": self.priority,
            "expected_impact": self.expected_impact,
            "estimated_cvss": self.estimated_cvss,
            "prerequisites": self.prerequisites,
            "suggested_tool": self.suggested_tool,
            "suggested_payload": self.suggested_payload,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
        }


@dataclass
class AttackPlan:
    plan_id: str
    target: str
    actions: list              # list[AttackAction] ordered by priority
    attack_paths: list         # list[AttackPath]
    chains_detected: int
    high_impact_paths: int
    recommended_next_action: object  # AttackAction
    graph_summary: dict
    generated_at: str

    def to_dict(self) -> dict:
        rna = self.recommended_next_action
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "actions": [a.to_dict() for a in self.actions],
            "attack_paths": [p.to_dict() if hasattr(p, "to_dict") else p for p in self.attack_paths],
            "chains_detected": self.chains_detected,
            "high_impact_paths": self.high_impact_paths,
            "recommended_next_action": rna.to_dict() if rna and hasattr(rna, "to_dict") else None,
            "graph_summary": self.graph_summary,
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# AttackPlanner
# ---------------------------------------------------------------------------

class AttackPlanner:
    """
    Analyzes the attack graph and produces a prioritized AttackPlan.
    All other autonomous engines can call plan() or get_next_action()
    to decide what to do next.
    """

    def __init__(self, query_engine: GraphQueryEngine = None, risk_analyzer_: RiskAnalyzer = None):
        self._query_engine = query_engine
        self._risk_analyzer = risk_analyzer_

    @property
    def query_engine(self) -> GraphQueryEngine:
        if self._query_engine is None:
            self._query_engine = graph_query_engine
        return self._query_engine

    @property
    def risk_anal(self) -> RiskAnalyzer:
        if self._risk_analyzer is None:
            self._risk_analyzer = risk_analyzer
        return self._risk_analyzer

    def plan(self, target: str) -> AttackPlan:
        """
        Full planning cycle:
        1. Query graph for target subgraph
        2. Find attack paths + chains
        3. Score vulns
        4. Generate ordered action list
        """
        engine = get_engine()
        logger.info(f"AttackPlanner: planning for {target}")

        # Find the target node
        target_node_id = engine._label_index.get((NodeType.TARGET, target))
        if target_node_id is None:
            # Try subdomain
            target_node_id = engine._label_index.get((NodeType.SUBDOMAIN, target))

        attack_paths = []
        if target_node_id:
            attack_paths = self.query_engine.find_attack_paths(target_node_id, max_depth=7)

        # Also collect chains
        chains = (
            self.query_engine.find_exploitable_vulnerability_chains()
            + self.query_engine.find_privilege_escalation_chains()
            + self.query_engine.find_ssrf_to_cloud_chains()
            + self.query_engine.find_xss_to_takeover_chains()
        )

        # Get all vulnerabilities in target subgraph
        all_vulns = engine.find_nodes(node_type=NodeType.VULNERABILITY)

        # Generate actions
        path_actions = self._generate_actions_from_paths(attack_paths)
        vuln_actions = self._generate_actions_from_vulns(all_vulns)

        combined = path_actions + vuln_actions
        ordered = self._prioritize_actions(combined)

        high_impact = sum(1 for p in attack_paths if p.impact_score >= 7.5)
        graph_summary = engine.get_stats()
        graph_summary["attack_surface"] = self.query_engine.get_attack_surface()

        recommended = ordered[0] if ordered else self._default_action(target)

        return AttackPlan(
            plan_id=str(uuid.uuid4()),
            target=target,
            actions=ordered,
            attack_paths=attack_paths[:20],
            chains_detected=len(chains),
            high_impact_paths=high_impact,
            recommended_next_action=recommended,
            graph_summary=graph_summary,
            generated_at=str(time.time()),
        )

    def get_next_action(self, target: str) -> Optional[AttackAction]:
        """Return the single highest-priority action for the target right now."""
        plan = self.plan(target)
        return plan.recommended_next_action

    # ------------------------------------------------------------------
    # Action generation
    # ------------------------------------------------------------------

    def _generate_actions_from_paths(self, paths: list) -> list:
        """Generate AttackActions from AttackPath objects."""
        actions = []
        seen_nodes = set()
        for path in paths:
            for node in path.nodes:
                if node is None or node.id in seen_nodes:
                    continue
                if node.node_type not in [NodeType.VULNERABILITY, NodeType.EXPLOIT, NodeType.PARAMETER]:
                    continue
                seen_nodes.add(node.id)
                action = self._node_to_action(node, path)
                actions.append(action)
        return actions

    def _generate_actions_from_vulns(self, vulns: list) -> list:
        """Generate AttackActions from standalone Vulnerability nodes."""
        actions = []
        for node in vulns:
            if node is None:
                continue
            action = self._node_to_action(node, path=None)
            actions.append(action)
        return actions

    def _node_to_action(self, node, path: Optional[AttackPath]) -> AttackAction:
        """Convert a graph node + optional path into an AttackAction."""
        vuln_type = ""
        if node.node_type == NodeType.VULNERABILITY:
            vuln_type = node.properties.get("vuln_type", "").lower()
            action_type = "test_vulnerability" if not node.exploitable else "exploit"
        elif node.node_type == NodeType.EXPLOIT:
            vuln_type = "exploit"
            action_type = "exploit"
        elif node.node_type == NodeType.PARAMETER:
            action_type = "enumerate"
            vuln_type = "parameter"
        else:
            action_type = "test_vulnerability"

        expected_impact = self._get_impact_type(vuln_type)
        priority = IMPACT_PRIORITY.get(expected_impact, IMPACT_PRIORITY["default"])
        tool = self._determine_tool(vuln_type, node)
        cvss = float(node.properties.get("cvss", 0.0))
        if cvss == 0.0:
            from .risk_analyzer import CVSS_SEVERITY
            cvss = CVSS_SEVERITY.get(vuln_type, 5.0)
        confidence = 0.8 if node.validated else (0.6 if node.exploitable else 0.4)

        # Adjust priority up if validated or part of chain
        if node.validated:
            priority = max(1, priority - 1)
        if node.exploitable:
            priority = max(1, priority - 1)

        score = self._score_action(node, path)

        return AttackAction(
            action_id=str(uuid.uuid4()),
            action_type=action_type,
            target_node_id=node.id,
            target_label=node.label,
            priority=priority,
            expected_impact=expected_impact,
            estimated_cvss=cvss,
            prerequisites=self._get_prerequisites(node),
            suggested_tool=tool,
            suggested_payload=node.properties.get("payload", ""),
            reasoning=self._get_reasoning(node, path),
            confidence=round(confidence, 2),
        )

    def _prioritize_actions(self, actions: list) -> list:
        """
        Sort actions by:
        1. Priority (ascending — lower is more important)
        2. Confidence (descending)
        3. CVSS score (descending)
        """
        # De-duplicate by target node
        seen = {}
        for action in actions:
            nid = action.target_node_id
            if nid not in seen or action.priority < seen[nid].priority:
                seen[nid] = action
        unique = list(seen.values())
        unique.sort(
            key=lambda a: (a.priority, -a.confidence, -a.estimated_cvss)
        )
        return unique

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _score_action(self, node, path: Optional[AttackPath]) -> float:
        """Score an action based on node severity, exploitability, and path score."""
        from .graph_engine import NodeType
        from .risk_analyzer import CVSS_SEVERITY
        score = 0.0

        sev = node.severity or "medium"
        sev_scores = {"critical": 10, "high": 7, "medium": 5, "low": 2, "info": 0.5}
        score += sev_scores.get(sev, 5)

        if node.exploitable:
            score += 3
        if node.validated:
            score += 2

        vuln_type = node.properties.get("vuln_type", "").lower()
        score += CVSS_SEVERITY.get(vuln_type, 5.0) * 0.3

        if path is not None:
            score += path.total_score * 0.2

        return round(score, 2)

    def _determine_tool(self, vuln_type: str, node) -> str:
        """Return the most appropriate tool for testing this vulnerability."""
        vt = vuln_type.lower()
        for key, tool in TOOL_MAP.items():
            if key in vt:
                return tool
        # Check node properties
        tool_from_props = node.properties.get("tool", "")
        if tool_from_props:
            return tool_from_props
        return TOOL_MAP["default"]

    def _get_impact_type(self, vuln_type: str) -> str:
        """Map a vuln type string to an impact category."""
        vt = vuln_type.lower()
        for key, impact in IMPACT_MAP.items():
            if key in vt:
                return impact
        return IMPACT_MAP["default"]

    def _get_prerequisites(self, node) -> list:
        """Return a list of prerequisite node IDs (nodes that must be exploited first)."""
        engine = get_engine()
        prereqs = []
        for edge in engine.get_edges_to(node.id):
            if edge.edge_type == EdgeType.REQUIRES:
                prereqs.append(edge.source_id)
        return prereqs

    def _get_reasoning(self, node, path: Optional[AttackPath]) -> str:
        """Generate human-readable reasoning for why this action is recommended."""
        parts = []
        vuln_type = node.properties.get("vuln_type", node.node_type.value)
        sev = node.severity or "unknown"
        parts.append(f"Node '{node.label}' is a {vuln_type} with {sev} severity.")

        if node.exploitable:
            parts.append("A working exploit has been confirmed.")
        if node.validated:
            parts.append("Finding has been validated (confirmed true positive).")
        if path:
            parts.append(f"Part of attack path scoring {path.total_score:.1f}/10 "
                         f"with entry point '{path.entry_point}' → impact '{path.final_impact}'.")

        cvss = node.properties.get("cvss", 0.0)
        if cvss:
            parts.append(f"CVSS score: {cvss}.")

        tool_hint = self._determine_tool(vuln_type, node)
        parts.append(f"Recommended tool: {tool_hint}.")
        return " ".join(parts)

    def _estimate_bounty(self, action: AttackAction) -> int:
        """Estimate bounty for an action based on impact type."""
        bounty_map = {
            "rce": 15000,
            "data_exfil": 10000,
            "sql_exfil": 8000,
            "ato": 5000,
            "priv_esc": 5000,
            "ssrf_cloud": 10000,
            "xss_ato": 3000,
            "subdomain_takeover": 7500,
            "lfi": 3000,
            "info_disclosure": 500,
            "misconfig": 300,
            "default": 1000,
        }
        return bounty_map.get(action.expected_impact, bounty_map["default"])

    def _default_action(self, target: str) -> AttackAction:
        """Return a default enumerate action when graph has no useful data."""
        return AttackAction(
            action_id=str(uuid.uuid4()),
            action_type="enumerate",
            target_node_id="",
            target_label=target,
            priority=5,
            expected_impact="info_disclosure",
            estimated_cvss=0.0,
            prerequisites=[],
            suggested_tool="nuclei",
            suggested_payload="",
            reasoning=f"No vulnerabilities found yet for {target}. Start with surface enumeration.",
            confidence=0.5,
        )


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

attack_planner = AttackPlanner()
