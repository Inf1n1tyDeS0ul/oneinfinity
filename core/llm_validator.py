"""
core/llm_validator.py — LLM Output Validation + Hallucination Guard (Phase 5)

Validates all LLM JSON outputs against strict schemas.
Rejects:
  - unknown actions not in VALID_ACTIONS
  - endpoints not in known_urls (hallucination guard)
  - malformed structures
  - type mismatches

Safe fallback: every validate_* method returns (False, []) on bad input.
The pipeline continues with Phase 3 rules + decision engine when LLM fails.
"""
from __future__ import annotations

import logging
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

log = logging.getLogger("oneinfinity.core.llm_validator")

_VALID_PRIORITIES: FrozenSet[str] = frozenset({"high", "medium", "low"})
_VALID_CONFIDENCES: FrozenSet[str] = frozenset({"high", "medium", "low"})

# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class LLMValidator:
    """
    Validates LLM JSON outputs for correctness and hallucination.

    All methods return (is_valid: bool, cleaned_items: list).
    When is_valid=False, cleaned_items is always [].
    """

    # ── Attack plan ────────────────────────────────────────────────────────────

    def validate_attack_plan(
        self,
        parsed: Optional[dict],
        valid_actions: FrozenSet[str],
        known_urls: Optional[List[str]] = None,
    ) -> Tuple[bool, list]:
        """
        Validate an attack_plan LLM response.

        Hallucination guard:
          - action must be in valid_actions
          - if known_urls provided, target must substring-match at least one known URL
            (or be empty — empty target is accepted for broad suggestions)

        Returns (True, validated_items) or (False, []).
        """
        if not isinstance(parsed, dict):
            log.debug("[LLMVal] attack_plan: not a dict")
            return False, []
        raw_plan = parsed.get("attack_plan")
        if not isinstance(raw_plan, list):
            log.debug("[LLMVal] attack_plan: missing or non-list 'attack_plan'")
            return False, []

        known_set: Optional[Set[str]] = set(known_urls) if known_urls else None
        validated: list = []

        for i, entry in enumerate(raw_plan[:5]):
            if not isinstance(entry, dict):
                log.debug("[LLMVal] attack_plan[%d]: not a dict — skipping", i)
                continue

            # Action validation (hallucination guard)
            action = str(entry.get("action", "")).strip()
            if action not in valid_actions:
                log.debug("[LLMVal] attack_plan[%d]: unknown action '%s' — discarding", i, action)
                continue

            # Target validation (hallucination guard)
            ep_target = str(entry.get("target", "")).strip()[:300]
            if known_set and ep_target:
                # Accept if target is a substring of any known URL or vice versa
                if not any(ep_target in u or u in ep_target for u in known_set):
                    log.debug(
                        "[LLMVal] attack_plan[%d]: target '%s' not in known URLs — discarding",
                        i, ep_target[:60],
                    )
                    continue

            # Priority normalisation
            priority = str(entry.get("priority", "medium")).strip().lower()
            if priority not in _VALID_PRIORITIES:
                priority = "medium"

            reason = str(entry.get("reason", ""))[:300]

            validated.append({
                "action":   action,
                "target":   ep_target,
                "reason":   reason,
                "priority": priority,
            })

        if not validated:
            log.debug("[LLMVal] attack_plan: all items rejected — returning empty")
            return False, []

        log.debug("[LLMVal] attack_plan: %d/%d items validated", len(validated), len(raw_plan))
        return True, validated

    # ── Response signals ───────────────────────────────────────────────────────

    def validate_signals(
        self,
        parsed: Optional[dict],
        valid_actions: FrozenSet[str],
    ) -> Tuple[bool, list]:
        """
        Validate response analysis signals.

        Each signal must have: type, confidence, evidence.
        next_action is validated against valid_actions if present.

        Returns (True, validated_signals) or (False, []).
        """
        if not isinstance(parsed, dict):
            return False, []
        raw_signals = parsed.get("signals")
        if not isinstance(raw_signals, list):
            return False, []

        validated: list = []
        for i, sig in enumerate(raw_signals[:3]):
            if not isinstance(sig, dict):
                continue

            sig_type = str(sig.get("type", "")).strip().lower()
            if not sig_type:
                continue

            evidence = str(sig.get("evidence", "")).strip()
            if not evidence:
                log.debug("[LLMVal] signal[%d]: empty evidence — discarding", i)
                continue

            confidence = str(sig.get("confidence", "low")).strip().lower()
            if confidence not in _VALID_CONFIDENCES:
                confidence = "low"

            # Validate next_action
            next_action = str(sig.get("next_action", "")).strip()
            if next_action and next_action not in valid_actions:
                log.debug("[LLMVal] signal[%d]: unknown next_action '%s' — clearing", i, next_action)
                next_action = ""

            validated.append({
                "type":            sig_type[:100],
                "confidence":      confidence,
                "evidence":        evidence[:500],
                "next_action":     next_action,
                "recommendation":  str(sig.get("recommendation", ""))[:200],
            })

        return (True, validated) if validated else (False, [])

    # ── Payloads ───────────────────────────────────────────────────────────────

    def validate_payloads(self, parsed: Optional[dict]) -> Tuple[bool, List[str]]:
        """
        Validate payload suggestion output.

        Returns (True, payloads_list) or (False, []).
        Payloads must be non-empty strings, max 500 chars each.
        """
        if not isinstance(parsed, dict):
            return False, []
        raw = parsed.get("payloads")
        if not isinstance(raw, list):
            return False, []

        payloads = [
            str(p).strip()[:500]
            for p in raw[:5]
            if p and str(p).strip()
        ]
        return (True, payloads) if payloads else (False, [])

    # ── Chain priority ranking ────────────────────────────────────────────────

    def validate_chain_ranking(
        self,
        parsed: Optional[dict],
        valid_chain_types: List[str],
    ) -> Tuple[bool, List[str]]:
        """
        Validate chain priority ranking output.

        Returns (True, ordered_chain_types) or (False, []).
        Only chain_types present in valid_chain_types are kept.
        """
        if not isinstance(parsed, dict):
            return False, []
        ranked = parsed.get("priority_chains")
        if not isinstance(ranked, list):
            return False, []
        valid_set = set(valid_chain_types)
        ordered = [str(ct).strip() for ct in ranked[:10] if str(ct).strip() in valid_set]
        return (True, ordered) if ordered else (False, [])


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_validator_instance: Optional[LLMValidator] = None


def get_llm_validator() -> LLMValidator:
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = LLMValidator()
    return _validator_instance
