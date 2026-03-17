"""
autonomous_decision_engine.py — Autonomous Decision Engine

Analyzes the current attack graph state and produces a ranked list of
Decisions — with probability estimates, impact scores, and reasoning.

Scoring model per potential action:
  score = (impact_weight × exploitability_estimate × novelty_factor)
          / (effort_cost × (1 + already_tested_penalty))

Where:
  impact_weight         — severity of what we expect to find (by node type + graph context)
  exploitability_estimate — how likely this node is vulnerable (based on node attrs + patterns)
  novelty_factor        — 1.0 if never tested, decreasing with each test
  effort_cost           — relative cost to run the agent (fast/slow tools)
  already_tested_penalty — 0 if fresh, grows with each previous test attempt

The engine also:
  - Analyzes attack path chains and recommends pivoting
  - Tracks which decisions led to findings (outcome feedback)
  - Provides "Why" explanations for each decision
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("autonomous_decision_engine")

# ── Scoring constants ──────────────────────────────────────────────────────────

# Expected impact per node type (0-10)
_IMPACT_BY_TYPE: Dict[str, float] = {
    "CREDENTIAL":    10.0,
    "IMPACT":        10.0,
    "EXPLOIT":        9.5,
    "AUTH_FLOW":      9.0,
    "VULNERABILITY":  9.0,
    "API_ENDPOINT":   7.5,
    "PARAMETER":      7.0,
    "URL":            5.0,
    "SERVICE":        4.5,
    "SUBDOMAIN":      4.0,
    "TECHNOLOGY":     3.0,
    "TARGET":         2.0,
    "default":        4.0,
}

# Effort cost per agent type (1.0 = fast, higher = slower)
_EFFORT_BY_AGENT: Dict[str, float] = {
    "recon":          1.0,
    "xss":            1.5,
    "open_redirect":  1.0,
    "sqli":           3.0,
    "ssrf":           2.0,
    "ssti":           1.5,
    "idor":           2.0,
    "auth":           2.5,
    "biz_logic":      3.0,
    "exploit":        3.0,
    "mobile":         4.0,
    "ai_security":    3.5,
    "default":        2.0,
}

# Exploitability patterns — boost score if label/props match
_EXPLOIT_PATTERNS: List[Tuple[str, float]] = [
    (r"id=",          0.3),
    (r"user",         0.2),
    (r"admin",        0.4),
    (r"debug",        0.3),
    (r"token",        0.3),
    (r"key",          0.25),
    (r"password",     0.4),
    (r"secret",       0.4),
    (r"upload",       0.3),
    (r"include",      0.25),
    (r"file",         0.2),
    (r"redirect",     0.2),
    (r"sql",          0.3),
    (r"exec",         0.35),
    (r"cmd",          0.35),
    (r"eval",         0.35),
    (r"template",     0.2),
    (r"\.php",        0.2),
    (r"\.asp",        0.2),
    (r"graphql",      0.25),
    (r"internal",     0.3),
    (r"localhost",    0.3),
    (r"127\.",        0.4),
    (r"169\.254",     0.5),  # metadata service
]


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class DecisionRationale:
    impact_score:          float
    exploitability_score:  float
    novelty_factor:        float
    effort_cost:           float
    tested_penalty:        float
    final_score:           float
    factors:               List[str]  # human-readable reasons

    def to_dict(self) -> dict:
        return {
            "impact_score":         round(self.impact_score, 3),
            "exploitability_score": round(self.exploitability_score, 3),
            "novelty_factor":       round(self.novelty_factor, 3),
            "effort_cost":          round(self.effort_cost, 3),
            "tested_penalty":       round(self.tested_penalty, 3),
            "final_score":          round(self.final_score, 3),
            "factors":              self.factors,
        }


@dataclass
class Decision:
    decision_id:   str
    target:        str
    node_id:       str
    node_label:    str
    node_type:     str
    agent_type:    str
    score:         float
    confidence:    float       # 0-1, how confident we are this will yield findings
    expected_impact: str       # "critical_rce", "ato", "data_exfil", etc.
    rationale:     DecisionRationale
    suggested_payload: str = ""
    suggested_tool:    str = ""
    attack_path:       List[str] = field(default_factory=list)  # path from target root
    made_at:           float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "decision_id":      self.decision_id,
            "target":           self.target,
            "node_id":          self.node_id,
            "node_label":       self.node_label,
            "node_type":        self.node_type,
            "agent_type":       self.agent_type,
            "score":            round(self.score, 3),
            "confidence":       round(self.confidence, 3),
            "expected_impact":  self.expected_impact,
            "rationale":        self.rationale.to_dict(),
            "suggested_payload": self.suggested_payload,
            "suggested_tool":   self.suggested_tool,
            "attack_path":      self.attack_path,
            "made_at":          self.made_at,
        }


@dataclass
class DecisionPlan:
    plan_id:     str
    target:      str
    decisions:   List[Decision]
    top_paths:   List[dict]
    graph_summary: dict
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "plan_id":      self.plan_id,
            "target":       self.target,
            "decisions":    [d.to_dict() for d in self.decisions[:20]],
            "top_paths":    self.top_paths[:10],
            "graph_summary": self.graph_summary,
            "generated_at": self.generated_at,
        }


# ── Outcome feedback ──────────────────────────────────────────────────────────

@dataclass
class OutcomeFeedback:
    decision_id: str
    agent_type:  str
    node_id:     str
    success:     bool         # did the decision yield a finding?
    severity:    str
    recorded_at: float = field(default_factory=time.time)


# ── Main engine ────────────────────────────────────────────────────────────────

class AutonomousDecisionEngine:
    """
    Reads the attack graph, scores every (node, agent) pair,
    and produces a ranked DecisionPlan.
    """

    def __init__(self) -> None:
        import re
        self._re = re
        self._lock = threading.RLock()
        self._feedback: deque = deque(maxlen=2000)

        # Outcome stats: agent_type → {attempts, successes}
        self._agent_stats: Dict[str, Dict[str, int]] = {}

        # Recent decisions log
        self._decision_history: deque = deque(maxlen=500)

    # ── Core scoring ─────────────────────────────────────────────────────────

    def _impact_score(self, node) -> float:
        type_str = str(node.node_type).split(".")[-1]
        base = _IMPACT_BY_TYPE.get(type_str, _IMPACT_BY_TYPE["default"])
        # Boost for known high-severity
        sev_boost = {"critical": 2.0, "high": 1.5, "medium": 1.1,
                     "low": 1.0, "info": 0.9}.get(
            str(node.severity or "").lower(), 1.0)
        return min(base * sev_boost, 10.0)

    def _exploitability_estimate(self, node, agent_type: str) -> float:
        """Estimate probability (0-1) that this node is exploitable by this agent."""
        base = 0.3  # default 30% chance

        label = str(node.label or "").lower()
        props = str(node.properties or {}).lower()
        text  = label + " " + props

        for pattern, boost in _EXPLOIT_PATTERNS:
            if self._re.search(pattern, text, self._re.IGNORECASE):
                base = min(base + boost, 1.0)

        # Agent-specific adjustments
        if agent_type == "xss" and "param" in text:
            base = min(base + 0.2, 1.0)
        if agent_type == "sqli" and any(k in text for k in ("id=", "user", "search", "q=")):
            base = min(base + 0.2, 1.0)
        if agent_type == "ssrf" and any(k in text for k in ("url", "webhook", "callback", "fetch")):
            base = min(base + 0.25, 1.0)
        if agent_type == "auth" and any(k in text for k in ("login", "auth", "token", "jwt")):
            base = min(base + 0.2, 1.0)
        if agent_type == "idor" and any(k in text for k in ("id=", "/user/", "/account/")):
            base = min(base + 0.2, 1.0)

        # Feedback adjustment — boost if agent previously succeeded on similar nodes
        with self._lock:
            stats = self._agent_stats.get(agent_type, {})
        attempts  = stats.get("attempts", 0)
        successes = stats.get("successes", 0)
        if attempts > 5:
            historical_rate = successes / attempts
            base = 0.6 * base + 0.4 * historical_rate

        # Already exploitable bonus
        if node.exploitable:
            base = min(base + 0.3, 1.0)

        return round(base, 4)

    def _novelty_factor(self, node, agent_type: str,
                         tested_agents: set) -> float:
        """1.0 = never tested; decreases with repeated tests."""
        if agent_type not in tested_agents:
            return 1.0
        n_tests = sum(1 for a in tested_agents if a == agent_type)
        return max(0.1, 1.0 - n_tests * 0.25)

    def _effort_cost(self, agent_type: str) -> float:
        return _EFFORT_BY_AGENT.get(agent_type, _EFFORT_BY_AGENT["default"])

    def _score_pair(self, node, agent_type: str,
                     tested_agents: set) -> Tuple[float, DecisionRationale]:
        impact    = self._impact_score(node)
        exploit   = self._exploitability_estimate(node, agent_type)
        novelty   = self._novelty_factor(node, agent_type, tested_agents)
        effort    = self._effort_cost(agent_type)
        penalty   = len(tested_agents) * 0.05

        numerator   = impact * exploit * novelty
        denominator = effort * (1.0 + penalty)
        score = round(numerator / max(denominator, 0.001), 4)

        factors = []
        if impact >= 8:
            factors.append(f"high-impact node type (weight={impact:.1f})")
        if exploit >= 0.5:
            factors.append(f"exploitability estimate={exploit:.0%}")
        if novelty < 1.0:
            factors.append(f"already tested partially (novelty={novelty:.2f})")
        if penalty > 0:
            factors.append(f"tested by {len(tested_agents)} agents previously")
        if node.exploitable:
            factors.append("node marked exploitable")
        if str(node.severity or "").lower() in ("critical", "high"):
            factors.append(f"severity={node.severity}")

        rationale = DecisionRationale(
            impact_score=impact,
            exploitability_score=exploit,
            novelty_factor=novelty,
            effort_cost=effort,
            tested_penalty=penalty,
            final_score=score,
            factors=factors,
        )
        return score, rationale

    # ── Decision plan generation ──────────────────────────────────────────────

    def generate_plan(self, target: str,
                       tested_map: Dict[str, set] = None,
                       max_decisions: int = 50) -> DecisionPlan:
        """
        Analyze the graph for a given target and return a ranked DecisionPlan.
        tested_map: {node_id → set of agent_types already tested}
        """
        tested_map = tested_map or {}
        decisions  = []
        top_paths  = []
        graph_summary = {}

        try:
            from attack_graph_core.graph_engine import get_engine
            from attack_graph_core.graph_query_engine import GraphQueryEngine

            eng   = get_engine()
            query = GraphQueryEngine(eng)

            # Graph summary
            stats = eng.get_stats()
            graph_summary = {
                "total_nodes": stats.get("total_nodes", 0),
                "total_edges": stats.get("total_edges", 0),
                "target": target,
            }

            # Top attack paths for context
            target_nodes = eng.find_nodes(node_type="TARGET", label_contains=target)
            if target_nodes:
                paths = query.find_attack_paths(target_nodes[0].id, max_depth=8)
                top_paths = [p.to_dict() for p in paths[:10]]

            # Score all (node, agent) pairs
            nodes = eng.find_nodes()
            from attack_graph_core.graph_engine import NodeType as NT

            # Map of agent types per node type
            from attack_graph_brain import _TYPE_AGENTS
            for node in nodes:
                type_str    = str(node.node_type).split(".")[-1]
                agents      = _TYPE_AGENTS.get(type_str, [])
                tested_here = tested_map.get(node.id, set())

                for agent_type in agents:
                    score, rationale = self._score_pair(node, agent_type, tested_here)
                    if score < 0.01:
                        continue

                    confidence = min(rationale.exploitability_score, 1.0)
                    impact_str = self._expected_impact(node, agent_type)
                    payload, tool = self._suggest(agent_type, node)

                    d = Decision(
                        decision_id=str(uuid.uuid4())[:10],
                        target=target,
                        node_id=node.id,
                        node_label=node.label,
                        node_type=type_str,
                        agent_type=agent_type,
                        score=score,
                        confidence=confidence,
                        expected_impact=impact_str,
                        rationale=rationale,
                        suggested_payload=payload,
                        suggested_tool=tool,
                    )
                    decisions.append(d)

        except Exception as exc:
            log.warning("Decision plan generation error: %s", exc)

        # Sort by score descending
        decisions.sort(key=lambda d: d.score, reverse=True)

        plan = DecisionPlan(
            plan_id=str(uuid.uuid4())[:10],
            target=target,
            decisions=decisions[:max_decisions],
            top_paths=top_paths,
            graph_summary=graph_summary,
        )

        # Record in history
        with self._lock:
            for d in plan.decisions[:10]:
                self._decision_history.append(d)

        return plan

    def _expected_impact(self, node, agent_type: str) -> str:
        """Human-readable expected impact label."""
        mapping = {
            ("CREDENTIAL",  "auth"):  "account_takeover",
            ("AUTH_FLOW",   "auth"):  "auth_bypass",
            ("PARAMETER",   "sqli"):  "sql_injection",
            ("PARAMETER",   "xss"):   "cross_site_scripting",
            ("PARAMETER",   "ssrf"):  "ssrf",
            ("API_ENDPOINT","idor"):  "insecure_direct_object_ref",
            ("VULNERABILITY","exploit"): "exploit_chain",
        }
        type_str = str(node.node_type).split(".")[-1]
        return mapping.get((type_str, agent_type), f"{agent_type}_finding")

    def _suggest(self, agent_type: str, node) -> Tuple[str, str]:
        """Return (suggested_payload, suggested_tool) for an agent+node pair."""
        tools = {
            "xss":          ("dalfox", '<script>alert(1)</script>'),
            "sqli":         ("sqlmap", "' OR 1=1 --"),
            "ssrf":         ("nuclei", "http://169.254.169.254/latest/meta-data/"),
            "open_redirect":("",       "//evil.com/%2F.."),
            "ssti":         ("",       "{{7*7}}"),
            "idor":         ("",       "Enumerate IDs: /api/user/{1..100}"),
            "auth":         ("jwt_tool", "JWT alg=none bypass"),
            "biz_logic":    ("",       "Price manipulation / race condition"),
            "exploit":      ("nuclei", "CVE exploit chain"),
            "recon":        ("nuclei subfinder httpx", ""),
        }
        tool, payload = tools.get(agent_type, ("nuclei", ""))
        return payload, tool

    # ── Outcome feedback ──────────────────────────────────────────────────────

    def record_outcome(self, decision_id: str, agent_type: str,
                        node_id: str, success: bool, severity: str = "info") -> None:
        fb = OutcomeFeedback(
            decision_id=decision_id,
            agent_type=agent_type,
            node_id=node_id,
            success=success,
            severity=severity,
        )
        with self._lock:
            self._feedback.append(fb)
            stats = self._agent_stats.setdefault(agent_type, {"attempts": 0, "successes": 0})
            stats["attempts"] += 1
            if success:
                stats["successes"] += 1

    # ── Query ─────────────────────────────────────────────────────────────────

    def recent_decisions(self, limit: int = 20) -> List[dict]:
        with self._lock:
            items = list(self._decision_history)
        items.reverse()
        return [d.to_dict() for d in items[:limit]]

    def agent_stats(self) -> Dict[str, dict]:
        with self._lock:
            return {k: dict(v) for k, v in self._agent_stats.items()}

    def predict_success_probability(self, agent_type: str,
                                     node_label: str) -> float:
        """Quick estimate without full scoring."""
        with self._lock:
            stats = self._agent_stats.get(agent_type, {})
        attempts  = stats.get("attempts", 0)
        successes = stats.get("successes", 0)
        if attempts < 3:
            return 0.3  # default prior
        return round(successes / attempts, 3)


# ── Singleton ──────────────────────────────────────────────────────────────────

_decision_engine: Optional[AutonomousDecisionEngine] = None
_de_lock = threading.Lock()


def get_decision_engine() -> AutonomousDecisionEngine:
    global _decision_engine
    if _decision_engine is None:
        with _de_lock:
            if _decision_engine is None:
                _decision_engine = AutonomousDecisionEngine()
    return _decision_engine
