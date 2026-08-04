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
        vuln_type = str(finding.get("vuln_type", "unknown") or "unknown").lower()

        # ── HITL threshold lookup ─────────────────────────────────────────────
        # When researchers have given ≥5 TP/FP verdicts for this vuln type, use
        # the calibrated threshold from the HITL engine instead of the hardcoded
        # _SKIP_THRESHOLD / _CONFIRMED_MIN.  This is the primary mechanism by
        # which human feedback tightens or loosens the judge for each vuln class.
        _effective_skip    = _SKIP_THRESHOLD
        _effective_confirm = _CONFIRMED_MIN
        try:
            from oneinfinity.learning.hitl_rl_engine import get_hitl_engine as _get_hitl_e
            _hitl = _get_hitl_e()
            _tp, _fp = _hitl._get_counts(vuln_type)
            if _tp + _fp >= 5:  # enough data to trust the calibration
                _cal = _hitl.get_validation_threshold(vuln_type)
                # Only tighten skip threshold when FP rate is high (threshold > 0.7)
                # Never loosen it below the engineering floor of 0.35.
                _effective_skip    = max(0.35, min(_SKIP_THRESHOLD, _cal - 0.30))
                _effective_confirm = _cal
                log.debug(
                    "FindingJudge: HITL calibration applied [%s] threshold=%.2f "
                    "skip=%.2f confirm=%.2f (tp=%d fp=%d)",
                    vuln_type, _cal, _effective_skip, _effective_confirm, _tp, _fp,
                )
        except Exception:
            pass  # always fall back to hardcoded constants

        # ── Scope guard ─────────────────────────────────────────────────────
        # Off-scope findings (URL belongs to a different domain than the scan
        # target) must never be CONFIRMED or INFERRED by heuristic alone.
        # The ingest pipeline already caps confidence to < _INFERRED_MIN for
        # off-scope findings, but we double-check here in case the finding
        # arrives via a different path (e.g. post_scan_verifier batch).
        _url  = finding.get("url", "") or ""
        _target = finding.get("target", "") or ""
        _off_scope = False
        if _url and _target:
            try:
                from urllib.parse import urlparse as _up
                _url_host = _up(_url).netloc.split(":")[0].lstrip("www.") if "://" in _url else ""
                _tgt_host = _up(_target).netloc.split(":")[0].lstrip("www.") if "://" in _target else _target.split("/")[0].lstrip("www.")
                if _url_host and _tgt_host and _url_host not in ("localhost", "127.0.0.1"):
                    _off_scope = not (_url_host == _tgt_host or _url_host.endswith("." + _tgt_host))
            except Exception:
                pass

        if _off_scope:
            # Hard cap: heuristic promotes max to CANDIDATE for off-scope URLs.
            # If there is real evidence the LLM judge may still upgrade to INFERRED,
            # but never CONFIRMED — that requires in-scope replay proof.
            if heuristic_confidence >= _CONFIRMED_MIN:
                heuristic_confidence = _INFERRED_MIN - 0.01  # force below CONFIRMED
            log.debug(
                "FindingJudge: off-scope URL [%s @ %s vs target=%s] — capping heuristic",
                finding_id, _url, _target,
            )

        # Fast path: skip LLM call for very low-confidence findings
        if heuristic_confidence < _effective_skip:
            log.debug("FindingJudge: skip LLM for %s (confidence=%.2f < %.2f)",
                      finding_id, heuristic_confidence, _effective_skip)
            return self._heuristic_verdict(finding, TIER_CANDIDATE,
                                           reason="Heuristic confidence below skip threshold")

        provider = self._get_provider()
        if provider is None:
            log.warning("FindingJudge: no provider available — falling back to heuristic")
            tier = self._heuristic_tier(heuristic_confidence)
            # Off-scope: if heuristic says CONFIRMED, cap at INFERRED
            if _off_scope and tier == TIER_CONFIRMED:
                tier = TIER_INFERRED
            return self._heuristic_verdict(finding, tier)

        prompt = self._build_prompt(finding)
        try:
            resp = provider.chat(
                prompt=prompt,
                system=_SYSTEM_PROMPT,
                max_tokens=512,
                temperature=0.1,   # low temperature — we want deterministic evaluation
            )
            verdict = self._parse_response(finding_id, resp.text, provider.name)
            # Off-scope cap: LLM should not auto-CONFIRM findings at unrelated domains.
            # The LLM sees the URL and might correctly identify a real vuln on a third-party
            # host, but we can't replay-confirm cross-origin, so max tier is INFERRED.
            if _off_scope and verdict.tier == TIER_CONFIRMED:
                verdict.tier = TIER_INFERRED
                verdict.confirmed = False
                verdict.fp_reasoning = (
                    f"[scope-guard] URL {_url!r} is off-scope for target {_target!r}. "
                    "Downgraded from CONFIRMED→INFERRED: replay confirmation requires in-scope target."
                )
                log.info(
                    "FindingJudge: scope-guard downgraded %s CONFIRMED→INFERRED (off-scope host)",
                    finding_id,
                )
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

        # Phase 3 (Pillar 5.4): Auto-generate nuclei template for CONFIRMED findings.
        # Fires in the same thread (daemon) — non-blocking relative to the scan.
        if verdict.tier == TIER_CONFIRMED:
            try:
                # Merge confirmed_tier into finding dict so auto_generate checks pass
                enriched = {**finding, "confirmed_tier": TIER_CONFIRMED}
                from oneinfinity.attack.nuclei_template_generator import auto_generate_from_confirmed
                auto_generate_from_confirmed(enriched)
            except Exception as exc:
                log.debug("FindingJudge: nuclei auto-gen failed for %s: %s", finding_id, exc)

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
        # Add scan target so the LLM judge can flag cross-origin findings as higher FP risk.
        _tgt = finding.get("target", "") or finding.get("scan_target", "")
        if _tgt:
            extra_context_parts.append(f"Scan target (in-scope domain): {_tgt}")
        _furl = finding.get("url", "") or ""
        if _tgt and _furl and _tgt not in _furl and "://" in _furl:
            try:
                from urllib.parse import urlparse as _up
                _fhost = _up(_furl).netloc
                _thost = _up(_tgt).netloc if "://" in _tgt else _tgt.split("/")[0]
                if _fhost and _thost and _fhost != _thost:
                    extra_context_parts.append(
                        f"WARNING: finding URL host ({_fhost!r}) differs from scan target ({_thost!r}). "
                        "Treat as cross-origin / out-of-scope — assign fp_risk=high unless the finding "
                        "describes a server-side issue that directly affects the scan target."
                    )
            except Exception:
                pass

        # Truncate large fields to avoid token blowout
        def _trunc(s: str, limit: int = 800) -> str:
            s = str(s)
            return s[:limit] + " [truncated]" if len(s) > limit else s

        # Append HITL few-shot examples (researcher-confirmed TP/FP patterns).
        # Only appended when examples exist — no performance cost when HITL is empty.
        try:
            from oneinfinity.learning.hitl_rl_engine import get_hitl_engine as _get_hitl
            _few_shot = _get_hitl().build_few_shot_prompt_section(
                finding.get("vuln_type", "unknown")
            )
            if _few_shot:
                extra_context_parts.append(_few_shot)
        except Exception:
            pass

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
