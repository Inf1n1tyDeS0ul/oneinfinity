"""
attack_simulation_engine.py — Pre-Execution Attack Path Simulation

Simulates attack paths BEFORE live testing to focus swarm agent effort
on the highest expected-value vectors.

Algorithm per path:
  1. Base probability  ← KB historical success rate for this vuln_type
  2. Tech modifier     ← +0.20 for known-vulnerable tech, -0.10 for hardened
  3. WAF penalty       ← -0.15 if WAF detected
  4. Depth penalty     ← 0.95^(graph_depth) per hop from entry node
  5. Agent skill rate  ← from in-memory agent EMA (injected by coordinator)
  6. Monte Carlo       ← N=200 Bernoulli trials → empirical probability

Impact formula:
  base_cvss × exploitation_ease × blast_radius

Expected Value:
  EV = probability × impact

Strategy selection: top K paths by EV where EV ≥ threshold.

Usage:
    engine = AttackSimulationEngine(knowledge_base=kb)
    results = asyncio.run(engine.simulate_all_paths("example.com", context))
    strategy = engine.select_strategy(results)
    print(strategy.reasoning)
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Optional platform imports ─────────────────────────────────────────────────

try:
    from attack_graph_core.graph_engine import get_engine, NodeType
    from attack_graph_core.graph_query_engine import GraphQueryEngine
    _GRAPH_AVAILABLE = True
except ImportError:
    _GRAPH_AVAILABLE = False

try:
    from core.learning_repository import get_learning_repo_sync as _get_learning_repo_sync
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False
    _get_learning_repo_sync = None  # type: ignore


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class SimulationResult:
    """Result of simulating a single attack path."""
    path_id:            str
    attack_type:        str           # e.g. "sqli", "ssrf_cloud_metadata"
    target:             str
    success_probability: float        # 0.0 – 1.0 (Monte Carlo empirical)
    impact_score:       float         # 0.0 – 10.0 (CVSS-aligned)
    expected_value:     float         # probability × impact
    recommended:        bool
    reasoning:          str
    factors:            Dict[str, float] = field(default_factory=dict)
    simulated_at:       float          = field(default_factory=time.time)

    def __repr__(self) -> str:
        rec = "★ RECOMMENDED" if self.recommended else "  skip"
        return (f"[{self.attack_type:<28}] "
                f"P={self.success_probability:.2f} "
                f"I={self.impact_score:.1f} "
                f"EV={self.expected_value:.3f}  {rec}")


@dataclass
class AttackStrategy:
    """Selected attack strategy after ranking all simulated paths."""
    strategy_id:    str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    top_paths:      List[SimulationResult] = field(default_factory=list)
    primary:        Optional[SimulationResult] = None
    reasoning:      str = ""
    total_paths:    int = 0
    recommended_agents: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "━━━ ATTACK STRATEGY ━━━",
            f"Primary: {self.primary.attack_type if self.primary else 'N/A'}",
            f"  P={self.primary.success_probability:.2f}  EV={self.primary.expected_value:.3f}",
            f"Reasoning: {self.reasoning}",
            "",
            "Top 5 paths by Expected Value:",
        ]
        for r in self.top_paths[:5]:
            lines.append(f"  {r}")
        return "\n".join(lines)


# ── Known attack paths configuration ─────────────────────────────────────────

# (attack_type, base_cvss, exploitation_ease, relevant_techs, hardened_techs)
ATTACK_PATH_CATALOG: List[Tuple[str, float, float, List[str], List[str]]] = [
    # vuln_type           CVSS   ease   vuln_tech                 hardened_tech
    ("sqli_error",        9.8,   0.90,  ["php","mysql","asp","coldfusion"],   ["postgresql","prisma","hibernate"]),
    ("sqli_blind_time",   9.1,   0.75,  ["php","mysql","mssql"],              ["parameterised_queries"]),
    ("xss_reflected",     7.4,   0.85,  ["php","asp","jsp","template"],       ["react","angular","vue"]),
    ("xss_dom",           7.4,   0.75,  ["javascript","jquery","angular1"],   ["react","csp"]),
    ("xss_stored",        8.8,   0.80,  ["php","cms","wordpress","drupal"],   ["csp","sanitizer"]),
    ("ssrf_cloud",        9.3,   0.70,  ["aws","gcp","azure","cloud","k8s"],  ["imdsv2","vpc_isolation"]),
    ("ssrf_internal",     8.6,   0.65,  ["microservices","docker","k8s"],     ["service_mesh"]),
    ("idor_horizontal",   8.1,   0.80,  ["rest_api","graphql","json"],        ["uuid","random_id"]),
    ("idor_path",         8.1,   0.75,  ["rest_api","numeric_id"],            ["uuid"]),
    ("auth_weak_creds",   9.8,   0.95,  ["admin_panel","cms","wordpress"],    ["mfa","lockout"]),
    ("jwt_none_alg",      9.0,   0.85,  ["jwt","nodejs","python","go"],       ["rs256","es256"]),
    ("jwt_weak_secret",   8.5,   0.70,  ["jwt","nodejs","python"],            ["rs256","long_secret"]),
    ("graphql_introspection", 5.3, 0.95,["graphql","apollo","hasura"],        ["introspection_disabled"]),
    ("bola",              8.1,   0.80,  ["rest_api","graphql"],               ["object_ownership_check"]),
    ("mass_assignment",   8.8,   0.75,  ["rails","laravel","django","node"],  ["allowlist_fields"]),
    ("race_condition",    7.5,   0.60,  ["checkout","payment","transfer"],    ["redis_lock","idempotency"]),
    ("price_manipulation",9.1,  0.70,  ["ecommerce","cart","checkout"],      ["server_validation"]),
    ("ssrf_lfi",          8.6,   0.65,  ["python","php","java"],              ["allowlist_schemes"]),
    ("business_logic",    7.2,   0.55,  ["saas","fintech","ecommerce"],       []),
    ("mobile_ssl_bypass", 6.5,   0.72,  ["android","ios","mobile"],           ["cert_pinning_enforced"]),
    ("mobile_secrets",    7.8,   0.88,  ["android","ios","mobile","apk"],     ["secrets_manager"]),
    ("api_version_bypass",6.5,  0.60,  ["rest_api","versioned_api"],         []),
    ("rate_limit_bypass", 5.8,   0.70,  ["api","auth","login"],               ["stricter_rate_limit"]),
]


# ── Engine ────────────────────────────────────────────────────────────────────

class AttackSimulationEngine:
    """
    Monte Carlo attack path simulator.

    For each attack type in the catalog, runs N Bernoulli trials where
    each trial's probability is computed from tech/WAF/depth/history
    factors. The empirical win rate across trials becomes the reported
    success probability.
    """

    MONTE_CARLO_N      = 200     # trials per path
    RECOMMEND_EV_THRESHOLD = 2.5  # paths above this EV are recommended
    MAX_PATHS_RETURNED = 30

    def __init__(
        self,
        knowledge_base: Optional[Any] = None,
        attack_graph:   Optional[Any] = None,
    ):
        self.knowledge_base = knowledge_base
        self.attack_graph   = attack_graph or (get_engine() if _GRAPH_AVAILABLE else None)
        self._kb_cache: Dict[str, float] = {}   # vuln_type → historical success rate

    # ── Public API ────────────────────────────────────────────────────────────

    async def simulate_all_paths(
        self, target: str, context: Dict[str, Any]
    ) -> List[SimulationResult]:
        """
        Simulate every attack type in the catalog for this target.
        Returns results sorted by expected_value descending.
        """
        loop     = asyncio.get_event_loop()
        graph_depths = await loop.run_in_executor(None, self._get_graph_depths, target)
        kb_rates     = await loop.run_in_executor(None, self._load_kb_rates, target)

        tech_stack = [t.lower() for t in context.get("tech_stack", [])]
        waf        = bool(context.get("waf_detected", False))
        has_cloud  = any(t in " ".join(tech_stack) for t in ["aws", "gcp", "azure", "cloud"])

        tasks = [
            loop.run_in_executor(
                None,
                self._simulate_path,
                attack_type, base_cvss, ease,
                vuln_techs, hardened_techs,
                tech_stack, waf, has_cloud,
                graph_depths.get(attack_type, 1),
                kb_rates.get(attack_type, 0.35),
                target,
            )
            for attack_type, base_cvss, ease, vuln_techs, hardened_techs
            in ATTACK_PATH_CATALOG
        ]

        results_raw = await asyncio.gather(*tasks, return_exceptions=True)
        results = [r for r in results_raw if isinstance(r, SimulationResult)]

        # Mark recommended
        ev_values = [r.expected_value for r in results]
        threshold = max(self.RECOMMEND_EV_THRESHOLD,
                        (sum(ev_values) / len(ev_values)) if ev_values else 2.5)
        for r in results:
            r.recommended = r.expected_value >= threshold

        results.sort(key=lambda r: r.expected_value, reverse=True)

        logger.info(
            "[Simulation] %d paths simulated for %s | top EV=%.3f (%s)",
            len(results), target,
            results[0].expected_value if results else 0,
            results[0].attack_type if results else "N/A",
        )
        return results[:self.MAX_PATHS_RETURNED]

    def select_strategy(self, results: List[SimulationResult], top_k: int = 5) -> AttackStrategy:
        """
        Select the best attack strategy from simulation results.
        Returns an AttackStrategy with primary attack and top alternatives.
        """
        recommended = [r for r in results if r.recommended]
        top = (recommended or results)[:top_k]
        primary = top[0] if top else None

        agent_map = {
            "sqli":         "sqli",
            "xss":          "xss",
            "ssrf":         "ssrf",
            "idor":         "idor",
            "auth":         "auth",
            "jwt":          "auth",
            "graphql":      "api",
            "bola":         "api",
            "mass":         "api",
            "race":         "business_logic",
            "price":        "business_logic",
            "business":     "business_logic",
            "mobile":       "mobile",
            "api":          "api",
            "rate":         "api",
        }
        recommended_agents = list(dict.fromkeys(
            agent_map.get(next((k for k in agent_map if r.attack_type.startswith(k)), ""), r.attack_type)
            for r in top
        ))

        reasoning_parts = []
        if primary:
            reasoning_parts.append(
                f"Primary: {primary.attack_type} (P={primary.success_probability:.0%}, "
                f"EV={primary.expected_value:.2f})"
            )
        if len(top) > 1:
            alts = ", ".join(r.attack_type for r in top[1:3])
            reasoning_parts.append(f"Alternatives: {alts}")

        high_impact = [r for r in results if r.impact_score >= 9.0]
        if high_impact:
            reasoning_parts.append(
                f"Critical-impact path available: {high_impact[0].attack_type} "
                f"(CVSS {high_impact[0].impact_score:.1f})"
            )

        return AttackStrategy(
            top_paths          = top,
            primary            = primary,
            reasoning          = " | ".join(reasoning_parts),
            total_paths        = len(results),
            recommended_agents = recommended_agents[:6],
        )

    # ── Monte Carlo simulation ────────────────────────────────────────────────

    def _simulate_path(
        self,
        attack_type:    str,
        base_cvss:      float,
        exploitation_ease: float,
        vuln_techs:     List[str],
        hardened_techs: List[str],
        tech_stack:     List[str],
        waf_detected:   bool,
        has_cloud:      bool,
        graph_depth:    int,
        kb_rate:        float,
        target:         str,
    ) -> SimulationResult:
        """Run Monte Carlo simulation for a single attack type."""
        rng = random.Random(hash(f"{target}{attack_type}") & 0xFFFF_FFFF)

        # ── Factor computation ────────────────────────────────────────────────
        factors: Dict[str, float] = {}

        # 1. KB historical rate
        factors["kb_history"] = kb_rate

        # 2. Tech modifier
        tech_str = " ".join(tech_stack)
        vuln_match    = sum(1 for t in vuln_techs    if t in tech_str)
        hardened_match= sum(1 for t in hardened_techs if t in tech_str)
        tech_mod = min(0.30, vuln_match * 0.12) - min(0.25, hardened_match * 0.15)
        factors["tech_modifier"] = tech_mod

        # 3. WAF penalty
        waf_pen = -0.15 if waf_detected else 0.0
        # Slightly less penalty for non-web attacks
        if attack_type.startswith("ssrf") or attack_type.startswith("idor"):
            waf_pen *= 0.5
        factors["waf_penalty"] = waf_pen

        # 4. Graph depth penalty  (each hop: ×0.95)
        depth_penalty = -(1.0 - 0.95 ** max(0, graph_depth - 1))
        factors["depth_penalty"] = depth_penalty

        # 5. Cloud bonus for SSRF paths
        cloud_bonus = 0.18 if (has_cloud and "ssrf_cloud" in attack_type) else 0.0
        factors["cloud_bonus"] = cloud_bonus

        # 6. Exploitation ease modifier (base_ease - 0.5 → ±range)
        ease_mod = (exploitation_ease - 0.70) * 0.20
        factors["ease_modifier"] = ease_mod

        # ── Trial probability ─────────────────────────────────────────────────
        p_trial = max(0.02, min(0.97,
            kb_rate + tech_mod + waf_pen + depth_penalty + cloud_bonus + ease_mod
        ))
        factors["trial_probability"] = p_trial

        # ── Monte Carlo ───────────────────────────────────────────────────────
        successes = sum(1 for _ in range(self.MONTE_CARLO_N) if rng.random() < p_trial)
        empirical_p = successes / self.MONTE_CARLO_N

        # ── Impact computation ────────────────────────────────────────────────
        exploit_ease_score = exploitation_ease
        blast_radius = 1.0
        if "ssrf_cloud" in attack_type:
            blast_radius = 1.4   # Cloud-wide impact
        elif "sqli" in attack_type:
            blast_radius = 1.3
        elif "auth" in attack_type or "cred" in attack_type:
            blast_radius = 1.2

        impact = min(10.0, base_cvss * exploit_ease_score * blast_radius / 10.0 * 10.0)
        # Normalize: base_cvss is already on 0–10, just apply modifiers
        impact = min(10.0, base_cvss * (0.8 + exploit_ease_score * 0.2) * blast_radius)
        impact = min(10.0, impact)

        ev = empirical_p * impact

        # ── Reasoning ────────────────────────────────────────────────────────
        reasoning_parts = [
            f"KB base={kb_rate:.0%}",
            f"tech={'+' if tech_mod >= 0 else ''}{tech_mod:.2f}",
        ]
        if waf_pen:
            reasoning_parts.append(f"WAF={waf_pen:.2f}")
        if cloud_bonus:
            reasoning_parts.append(f"cloud=+{cloud_bonus:.2f}")
        reasoning_parts.append(f"→ P={empirical_p:.0%} I={impact:.1f} EV={ev:.2f}")
        reasoning = " | ".join(reasoning_parts)

        return SimulationResult(
            path_id             = uuid.uuid4().hex[:8],
            attack_type         = attack_type,
            target              = target,
            success_probability = round(empirical_p, 4),
            impact_score        = round(impact, 2),
            expected_value      = round(ev, 4),
            recommended         = False,   # set after all paths ranked
            reasoning           = reasoning,
            factors             = factors,
        )

    # ── Graph depth lookup ────────────────────────────────────────────────────

    def _get_graph_depths(self, target: str) -> Dict[str, int]:
        """
        Query the attack graph to determine how many hops each vuln type
        is from a known entry point (lower depth = easier to reach).
        Returns {attack_type: depth} with default 1 if graph unavailable.
        """
        depths: Dict[str, int] = {}
        if not self.attack_graph or not _GRAPH_AVAILABLE:
            return depths

        try:
            vuln_nodes = self.attack_graph.find_nodes(node_type=NodeType.VULNERABILITY)
            for node in vuln_nodes:
                vtype = node.properties.get("vuln_type", "")
                if vtype:
                    # Use the node's risk_score as a proxy for depth
                    # (nodes discovered later / deeper have lower risk_score)
                    depth = max(1, round((10.0 - (node.risk_score or 5.0)) / 2))
                    existing = depths.get(vtype, 999)
                    depths[vtype] = min(existing, depth)
        except Exception as exc:
            logger.debug("[Simulation] Graph depth lookup error: %s", exc)

        return depths

    # ── KB historical rate lookup ─────────────────────────────────────────────

    def _load_kb_rates(self, target: str) -> Dict[str, float]:
        """
        Query the knowledge base for historical success rates per vuln_type.
        Falls back to catalog defaults when no history exists.
        """
        rates: Dict[str, float] = {}
        if not self.knowledge_base or not _KB_AVAILABLE:
            return rates

        try:
            # Use best_tool_for_vuln as a proxy for success probability
            for attack_type, _, _, _, _ in ATTACK_PATH_CATALOG:
                # Normalise to base vuln type (strip suffix)
                base_type = attack_type.split("_")[0]
                tools = self.knowledge_base.best_tool_for_vuln_sync(base_type, top_n=1)
                if tools:
                    t = tools[0]
                    total = t.get("runs_total", 0)
                    success = t.get("runs_success", 0)
                    if total > 0:
                        rates[attack_type] = success / total
        except Exception as exc:
            logger.debug("[Simulation] KB rate lookup error: %s", exc)

        return rates

    # ── Quick print helper ────────────────────────────────────────────────────

    @staticmethod
    def print_results(results: List[SimulationResult], top_n: int = 10) -> None:
        print(f"\n{'Attack Type':<30} {'P':>6}  {'Impact':>7}  {'EV':>7}  Rec")
        print("─" * 65)
        for r in results[:top_n]:
            rec = "★" if r.recommended else " "
            print(f"{r.attack_type:<30} {r.success_probability:>6.1%}  "
                  f"{r.impact_score:>7.1f}  {r.expected_value:>7.3f}  {rec}")
        print()
