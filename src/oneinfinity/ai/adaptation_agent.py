"""
ai/adaptation_agent.py — Payload Adaptation Agent for the AI Council pipeline.

Wraps BytesEncodingMutator, FilterReverseEngineer (from sensor_agent), and
OutputAdapter to provide bypass-suggestion and filter-inference capabilities
to the StepwiseExploitRunner.
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

log = logging.getLogger(__name__)


class AdaptationAgent:
    """
    Bridges the exploit runner to the sensor-layer mutators and output adapter.

    Responsibilities:
      - suggest_bypass: given a failed step, mutate the payload via
        BytesEncodingMutator to evade string-level filters.
      - reverse_engineer_filters: delegate to FilterReverseEngineer to infer
        bypass strings from empirical blocked/allowed probe lists.
    """

    def __init__(
        self,
        surface_profile=None,
        model_orchestrator=None,
    ) -> None:
        from oneinfinity.ai.sensor_agent import BytesEncodingMutator, FilterReverseEngineer
        from oneinfinity.ai.output_adapter import OutputAdapter

        self._bytes_mutator = BytesEncodingMutator()
        # FilterReverseEngineer resolves the orchestrator lazily via get_orchestrator();
        # it does not accept model_orchestrator as a constructor arg.
        self._filter_re = FilterReverseEngineer()
        self._output_adapter = OutputAdapter()
        self._profile = surface_profile

    # ── Public API ─────────────────────────────────────────────────────────────

    def suggest_bypass(self, step: Any, prev_result: Any) -> str:
        """
        Given a failed exploit step and its previous result, return a
        mutated payload that attempts to evade the target's filters.

        Strategy: encode via bytes-literal to evade string-pattern scanners.
        Falls back to the original payload if mutation yields nothing.
        """
        payload: str = getattr(step, "payload_template", "") or ""
        try:
            mutated = self._bytes_mutator.mutate_to_bytes_literal(payload)
        except Exception as exc:
            log.warning("[AdaptationAgent] bytes mutation failed: %s", exc)
            mutated = ""
        return mutated or payload

    def reverse_engineer_filters(
        self,
        blocked: List[str],
        allowed: List[str],
    ) -> List[str]:
        """
        Return inferred bypass strings based on empirical blocked/allowed
        probe string lists.

        Internally converts plain strings to the probe-dict format expected
        by FilterReverseEngineer.infer_and_bypass.
        """
        try:
            blocked_probes = [{"payload": p} for p in (blocked or [])]
            allowed_probes = [{"payload": p} for p in (allowed or [])]
            _pattern, bypasses = self._filter_re.infer_and_bypass(
                blocked_probes, allowed_probes
            )
            return bypasses or []
        except Exception as exc:
            log.warning("[AdaptationAgent] filter reverse-engineering failed: %s", exc)
            return []
