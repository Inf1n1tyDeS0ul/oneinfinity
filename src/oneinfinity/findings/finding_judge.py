"""
src/oneinfinity/findings/finding_judge.py
Phase 0 — Verified Finding Architecture

Finding Judge Agent — autonomous semantic evaluator for security findings.

Architecture (from ExploitGym agent-as-judge design):
  The judge runs on a DIFFERENT model from the scan agent that generated the finding.
  This prevents hallucination anchoring — where the scanning model's confidence bias
  propagates into its own evaluation.

Three-tier confidence system:
  CONFIRMED  — judge verified the evidence is conclusive; exploitation is proven
  INFERRED   — multiple corroborating signals but no replay confirmation
  CANDIDATE  — single pattern match only; likely needs manual review

Usage (synchronous, called from scan pipelines):
  from oneinfinity.findings.finding_judge import get_judge
  verdict = get_judge().evaluate(finding_dict)
  # verdict: JudgeVerdict dataclass

Usage (batch, for post-scan evaluation):
  get_judge().evaluate_batch(findings_list)
  # updates postgres directly via sync_update_finding_judge
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.finding_judge")

# ── Confidence tier constants ─────────────────────────────────────────────────
TIER_CONFIRMED = "CONFIRMED"
TIER_INFERRED  = "INFERRED"
TIER_CANDIDATE = "CANDIDATE"

# Minimum heuristic confidence thresholds before calling the LLM judge.
# Below SKIP_THRESHOLD we assign CANDIDATE without an LLM call (saves cost).
_SKIP_THRESHOLD = 0.40   # findings below this are noise; skip LLM entirely
_INFERRED_MIN   = 0.60   # ≥0.60 qualifies for INFERRED without confirmation
_CONFIRMED_MIN  = 0.90   # ≥0.90 heuristic + judge agreement → CONFIRMED

# ── Judge prompt ──────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are an expert penetration tester and security finding validator.
Your role is to evaluate whether a reported security finding is a TRUE POSITIVE
or FALSE POSITIVE, and to assign a confidence tier.

You MUST respond with ONLY valid JSON — no prose, no markdown, no code fences.
The JSON must match this exact schema:
{
  "confirmed": <true|false>,
  "confidence": <float 0.0-1.0>,
  "tier": "<CONFIRMED|INFERRED|CANDIDATE>",
  "fp_risk": "<low|medium|high>",
  "fp_reasoning": "<one sentence explaining the FP risk assessment>",
  "confirmation_step": "<concrete single HTTP request or action that would prove this>",
  "severity_assessment": "<critical|high|medium|low|info>",
  "reasoning": "<2-3 sentences: what makes this evidence conclusive or not>"
}

Tier definitions:
  CONFIRMED  — the evidence conclusively proves exploitation (e.g. SQL error with data,
               blind timing delta >2000ms, XSS execution context confirmed, SSRF OOB hit)
  INFERRED   — multiple strong indicators but no single definitive proof
               (e.g. parameter reflected in HTML but not executed, timing delta borderline)
  CANDIDATE  — single weak indicator only (e.g. status code change, generic error message,
               parameter name in error text without data disclosure)

Be conservative. When in doubt, downgrade the tier. A CONFIRMED finding that is a FP
damages trust more than a CANDIDATE finding that is a TP.
"""

_USER_PROMPT_TEMPLATE = """\
Evaluate this security finding:

VULN TYPE:    {vuln_type}
SEVERITY:     {severity}
URL:          {url}
METHOD:       {method}
TOOL:         {tool}
CONFIDENCE:   {confidence}
SOURCE TYPE:  {source_type}

EVIDENCE:
{evidence}

PAYLOAD USED:
{payload}

REQUEST (if available):
{request}

RESPONSE DIFF / KEY RESPONSE:
{response_diff}

ADDITIONAL CONTEXT:
{extra_context}

Respond with ONLY the JSON verdict object.
"""


# ── JudgeVerdict dataclass ────────────────────────────────────────────────────

@dataclass
class JudgeVerdict:
    """Structured output from the finding judge."""
    finding_id: str
    confirmed: bool
    tier: str                      # CONFIRMED | INFERRED | CANDIDATE
    confidence: float              # 0.0 – 1.0  (semantic, not heuristic)
    fp_risk: str                   # low | medium | high
    fp_reasoning: str
    confirmation_step: str
    severity_assessment: str
    reasoning: str
    model_used: str = ""
    judged_at: float = field(default_factory=time.time)
    raw_response: str = ""         # raw LLM output for debugging
    judge_error: Optional[str] = None  # set if LLM call failed

    def to_dict(self) -> dict:
        return {
            "confirmed":           self.confirmed,
            "tier":                self.tier,
            "confidence":          self.confidence,
            "fp_risk":             self.fp_risk,
            "fp_reasoning":        self.fp_reasoning,
            "confirmation_step":   self.confirmation_step,
            "severity_assessment": self.severity_assessment,
            "reasoning":           self.reasoning,
            "model_used":          self.model_used,
            "judged_at":           self.judged_at,
            "judge_error":         self.judge_error,
        }


# ── Finding Judge ─────────────────────────────────────────────────────────────

class FindingJudge:
    """
    Evaluates security findings using an LLM judge.

    Uses a DIFFERENT model from the scan agent:
      - Judge model: "judge" task type → routed per offensive_router model table
        (conservative model: high precision over recall)
      - Attack/payload model: "exploit" task type → creative, unconstrained

    This separation prevents the scan agent's confidence from anchoring the verdict.
    """

    def __init__(self) -> None:
        self._provider = None   # lazy — initialised on first call

    def _get_provider(self):
        """Lazy provider init — avoids import-time side effects."""
        if self._provider is None:
            from oneinfinity.infra.llm_provider import get_provider
            try:
                self._provider = get_provider("judge")
            except Exception as exc:
                log.warning("FindingJudge: could not get judge provider: %s", exc)
                self._provider = None
        return self._provider

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(self, finding: dict) -> JudgeVerdict:
        """
        Evaluate a single finding dict and return a JudgeVerdict.

        The finding dict is the same shape as NormalizedFinding.to_dict() or
        the dicts returned by DBManager.get_findings() / ResultIngestionEngine.get_findings().

        Does NOT write to the database — caller decides whether to persist.
        Use evaluate_and_persist() to update postgres in one call.
        """
        finding_id = finding.get("finding_id", "unknown")
        heuristic_confidence = float(finding.get("confidence", 0.5))

        # Fast path: skip LLM call for very low-confidence findings
        if heuristic_confidence < _SKIP_THRESHOLD:
            log.debug("FindingJudge: skip LLM for %s (confidence=%.2f < %.2f)",
                      finding_id, heuristic_confidence, _SKIP_THRESHOLD)
            return self._heuristic_verdict(finding, TIER_CANDIDATE,
                                           reason="Heuristic confidence below skip threshold")

        provider = self._get_provider()
        if provider is None:
            log.warning("FindingJudge: no provider available — falling back to heuristic")
            return self._heuristic_verdict(finding, self._heuristic_tier(heuristic_confidence))

        prompt = self._build_prompt(finding)
        try:
            resp = provider.chat(
                prompt=prompt,
                system=_SYSTEM_PROMPT,
                max_tokens=512,
                temperature=0.1,   # low temperature — we want deterministic evaluation
            )
            verdict = self._parse_response(finding_id, resp.text, provider.name)
            log.info(
                "FindingJudge: %s → %s (fp_risk=%s, confidence=%.2f) [model=%s]",
                finding_id, verdict.tier, verdict.fp_risk, verdict.confidence, provider.name,
            )
            return verdict
        except Exception as exc:
            log.warning("FindingJudge: LLM call failed for %s: %s — using heuristic",
                        finding_id, exc)
            v = self._heuristic_verdict(
                finding,
                self._heuristic_tier(heuristic_confidence),
                reason=f"LLM judge failed: {exc}",
            )
            v.judge_error = str(exc)
            return v

    def evaluate_and_persist(self, finding: dict) -> JudgeVerdict:
        """
        Evaluate a finding and immediately write the verdict to postgres.

        Preferred call site for God Mode scan pipeline — one call does both.
        Returns the verdict for optional further processing.
        """
        verdict = self.evaluate(finding)
        finding_id = finding.get("finding_id")
        if not finding_id:
            log.warning("FindingJudge.evaluate_and_persist: finding has no finding_id — not persisting")
            return verdict
        try:
            from oneinfinity.core.db_manager import get_db_manager_sync
            db = get_db_manager_sync()
            if db is not None:
                db.sync_update_finding_judge(
                    finding_id=finding_id,
                    confirmed_tier=verdict.tier,
                    judge_verdict=verdict.to_dict(),
                )
            else:
                log.warning("FindingJudge: db not available — verdict not persisted for %s", finding_id)
        except Exception as exc:
            log.warning("FindingJudge: persist failed for %s: %s", finding_id, exc)
        return verdict

    def evaluate_batch(
        self,
        findings: List[dict],
        *,
        persist: bool = True,
        skip_already_judged: bool = True,
    ) -> List[JudgeVerdict]:
        """
        Evaluate a list of findings.

        persist=True (default): writes each verdict to postgres immediately.
        skip_already_judged=True (default): skips findings that already have a
          non-null confirmed_tier (avoids re-judging on repeated calls).

        Designed for post-scan evaluation runs — call after a God Mode scan
        completes to judge all findings from that scan.
        """
        verdicts = []
        skipped = 0
        for f in findings:
            if skip_already_judged and f.get("confirmed_tier") is not None:
                skipped += 1
                continue
            if persist:
                v = self.evaluate_and_persist(f)
            else:
                v = self.evaluate(f)
            verdicts.append(v)

        log.info(
            "FindingJudge.evaluate_batch: %d evaluated, %d skipped (already judged)",
            len(verdicts), skipped,
        )
        return verdicts

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_prompt(self, finding: dict) -> str:
        """Build the judge prompt from a finding dict."""
        raw = finding.get("raw") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}

        # Extract request/response from common locations
        request_str = (
            raw.get("request") or
            finding.get("request") or
            ""
        )
        response_diff = (
            raw.get("response_diff") or
            raw.get("response") or
            finding.get("response_diff") or
            finding.get("evidence") or
            ""
        )
        extra_context_parts = []
        if finding.get("poc_steps"):
            extra_context_parts.append(f"PoC steps: {finding['poc_steps']}")
        if finding.get("reproduction_cmd"):
            extra_context_parts.append(f"Reproduction command: {finding['reproduction_cmd']}")
        if raw.get("chain_context"):
            extra_context_parts.append(f"Chain context: {raw['chain_context']}")

        # Truncate large fields to avoid token blowout
        def _trunc(s: str, limit: int = 800) -> str:
            s = str(s)
            return s[:limit] + " [truncated]" if len(s) > limit else s

        return _USER_PROMPT_TEMPLATE.format(
            vuln_type=finding.get("vuln_type", "unknown"),
            severity=finding.get("severity", "unknown"),
            url=finding.get("url", ""),
            method=raw.get("method", finding.get("method", "unknown")),
            tool=finding.get("tool", "unknown"),
            confidence=finding.get("confidence", 0.0),
            source_type=finding.get("source_type", "unknown"),
            evidence=_trunc(finding.get("evidence", ""), 1000),
            payload=_trunc(finding.get("payload", ""), 400),
            request=_trunc(request_str, 600),
            response_diff=_trunc(response_diff, 1000),
            extra_context="\n".join(extra_context_parts) or "None",
        )

    def _parse_response(self, finding_id: str, raw_text: str, model_name: str) -> JudgeVerdict:
        """Parse LLM JSON response into a JudgeVerdict."""
        # Strip markdown fences if present
        text = raw_text.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
        text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
        text = text.strip()

        try:
            data: Dict[str, Any] = json.loads(text)
        except json.JSONDecodeError as exc:
            log.warning("FindingJudge: JSON parse failed for %s: %s | raw=%r",
                        finding_id, exc, raw_text[:200])
            # Partial parse: try to extract tier at minimum
            tier = TIER_CANDIDATE
            if "CONFIRMED" in raw_text.upper():
                tier = TIER_CONFIRMED
            elif "INFERRED" in raw_text.upper():
                tier = TIER_INFERRED
            return JudgeVerdict(
                finding_id=finding_id,
                confirmed=tier == TIER_CONFIRMED,
                tier=tier,
                confidence=0.5,
                fp_risk="medium",
                fp_reasoning="JSON parse failed — conservative assessment",
                confirmation_step="Manual verification required",
                severity_assessment="medium",
                reasoning=f"LLM returned unparseable JSON: {raw_text[:100]}",
                model_used=model_name,
                raw_response=raw_text,
                judge_error=f"JSON parse error: {exc}",
            )

        # Normalise tier
        tier_raw = str(data.get("tier", "")).upper().strip()
        if tier_raw not in (TIER_CONFIRMED, TIER_INFERRED, TIER_CANDIDATE):
            # Infer from confirmed bool
            tier_raw = TIER_CONFIRMED if data.get("confirmed") else TIER_CANDIDATE

        # Clamp confidence
        try:
            conf = float(data.get("confidence", 0.5))
            conf = max(0.0, min(1.0, conf))
        except (TypeError, ValueError):
            conf = 0.5

        # Validate fp_risk
        fp_risk = str(data.get("fp_risk", "medium")).lower()
        if fp_risk not in ("low", "medium", "high"):
            fp_risk = "medium"

        # Validate severity
        severity = str(data.get("severity_assessment", "medium")).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        return JudgeVerdict(
            finding_id=finding_id,
            confirmed=bool(data.get("confirmed", False)),
            tier=tier_raw,
            confidence=conf,
            fp_risk=fp_risk,
            fp_reasoning=str(data.get("fp_reasoning", "")),
            confirmation_step=str(data.get("confirmation_step", "")),
            severity_assessment=severity,
            reasoning=str(data.get("reasoning", "")),
            model_used=model_name,
            raw_response=raw_text,
        )

    @staticmethod
    def _heuristic_tier(confidence: float) -> str:
        """Assign a tier purely from heuristic confidence (no LLM call)."""
        if confidence >= _CONFIRMED_MIN:
            return TIER_CONFIRMED
        if confidence >= _INFERRED_MIN:
            return TIER_INFERRED
        return TIER_CANDIDATE

    @staticmethod
    def _heuristic_verdict(
        finding: dict,
        tier: str,
        reason: str = "Heuristic evaluation (no LLM call)",
    ) -> JudgeVerdict:
        """Build a JudgeVerdict from heuristic data when LLM is unavailable."""
        confidence = float(finding.get("confidence", 0.5))
        return JudgeVerdict(
            finding_id=finding.get("finding_id", "unknown"),
            confirmed=tier == TIER_CONFIRMED,
            tier=tier,
            confidence=confidence,
            fp_risk="low" if confidence >= 0.9 else ("medium" if confidence >= 0.6 else "high"),
            fp_reasoning=reason,
            confirmation_step="Manual verification required (no LLM judge available)",
            severity_assessment=finding.get("severity", "medium"),
            reasoning=reason,
            model_used="heuristic",
        )


# ── Module-level singleton ────────────────────────────────────────────────────

_judge: Optional[FindingJudge] = None


def get_judge() -> FindingJudge:
    """Return the module-level FindingJudge singleton (created on first call)."""
    global _judge
    if _judge is None:
        _judge = FindingJudge()
    return _judge
