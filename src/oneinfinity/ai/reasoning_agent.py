"""
ai/reasoning_agent.py — LLM-Guided Exploit Reasoning Agent

Bridges the AttackGraphBrain and ModelOrchestrator to produce a ranked,
chain-of-thought ExploitPlan for a given attack surface profile.

Usage::
    from oneinfinity.ai.reasoning_agent import ReasoningAgent

    agent = ReasoningAgent(
        surface_profile={"target": "example.com", "endpoints": [...], ...},
        model_orchestrator=get_orchestrator(),   # optional — lazy if omitted
        brain=get_brain(),                       # optional — lazy if omitted
    )
    plan = agent.build_plan()
    # plan.steps  →  List[ExploitStep]
"""
from __future__ import annotations

import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


class ReasoningAgent:
    """
    High-level entry point for autonomous exploit plan construction.

    Instantiates an ExploitPlanBuilder against the provided (or lazily
    resolved) AttackGraphBrain + ModelOrchestrator, then calls build_plan()
    to produce a ranked ExploitPlan.

    Args:
        surface_profile:    dict or any object with .to_dict() / .__dict__
                            describing the target attack surface.  The 'target'
                            key (or .target attribute) is used as the plan target.
        model_orchestrator: ModelOrchestrator instance.  If None, resolved via
                            get_orchestrator() on first use.
        brain:              AttackGraphBrain instance.  If None, resolved via
                            get_brain() on first use.
    """

    def __init__(
        self,
        surface_profile: Any,
        model_orchestrator: Optional[Any] = None,
        brain: Optional[Any] = None,
    ) -> None:
        self._profile = surface_profile
        self._orch    = model_orchestrator
        self._brain   = brain

    # ── Public API ─────────────────────────────────────────────────────────────

    def build_plan(self):
        """
        Build and return an ExploitPlan for the surface profile provided at
        construction time.

        Returns:
            ExploitPlan — ordered list of ExploitStep objects (3-8 steps).
        """
        from oneinfinity.intelligence.attack_graph_brain import ExploitPlanBuilder
        from oneinfinity.intelligence.attack_graph_brain import get_brain

        brain = self._brain
        if brain is None:
            brain = get_brain()

        builder = ExploitPlanBuilder(
            brain=brain,
            model_orchestrator=self._orch,  # ExploitPlanBuilder resolves lazily too
        )

        target = self._extract_target(self._profile)
        log.info("[ReasoningAgent] Building exploit plan for target='%s'", target)

        plan = builder.build_plan(surface_profile=self._profile, target=target)
        log.info(
            "[ReasoningAgent] Plan ready: plan_id=%s steps=%d target=%s",
            plan.plan_id,
            len(plan.steps),
            plan.target,
        )
        return plan

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_target(surface_profile: Any) -> str:
        """Pull the target identifier from the surface profile."""
        if isinstance(surface_profile, dict):
            return (
                surface_profile.get("target")
                or surface_profile.get("host")
                or surface_profile.get("domain")
                or surface_profile.get("url")
                or "unknown"
            )
        for attr in ("target", "host", "domain", "url"):
            val = getattr(surface_profile, attr, None)
            if val:
                return str(val)
        return "unknown"
