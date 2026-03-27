"""
core/ai_reasoning_engine.py — LLM Reasoning Layer for OneInfinity (Phase 4)

Responsibilities:
  - Analyze target context and existing findings
  - Generate structured attack strategy (JSON output only)
  - Suggest next-step actions per-iteration
  - Analyze complex tool responses for hidden patterns
  - Suggest targeted payloads for WAF bypass

Architecture:
  - LLM is a REASONING layer — tools perform execution
  - AI suggestions are always ADDITIVE (never override rules)
  - System is OPTIONAL — all methods return empty results on LLM failure
  - JSON schema strictly enforced; hallucinated findings are rejected
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Dict, List, Optional

log = logging.getLogger("oneinfinity.core.ai_reasoning_engine")

# ---------------------------------------------------------------------------
# Allowed actions — maps to concrete tool names
# ---------------------------------------------------------------------------

_ACTION_TO_TOOL: Dict[str, str] = {
    "test_xss":           "dalfox",
    "test_sqli":          "sqlmap",
    "test_ssrf":          "nuclei",
    "test_idor":          "nuclei",
    "test_lfi":           "nuclei",
    "test_rce":           "nuclei",
    "test_auth":          "nuclei",
    "test_jwt":           "jwt_tool",
    "test_graphql":       "graphql_scan",
    "fuzz_api":           "kiterunner",
    "test_s3":            "s3scanner",
    "test_cmdi":          "commix",
    "test_ssti":          "nuclei",
    "test_xxe":           "nuclei",
    "test_open_redirect": "nuclei",
}

_VALID_ACTIONS = frozenset(_ACTION_TO_TOOL.keys())
_VALID_PRIORITIES = frozenset({"high", "medium", "low"})

# Signal type → tool — for response-analysis actionable signals
_SIGNAL_TO_TOOL: Dict[str, str] = {
    "xss":                  "dalfox",
    "sqli":                 "sqlmap",
    "sql_injection":        "sqlmap",
    "ssrf":                 "nuclei",
    "idor":                 "nuclei",
    "jwt_weakness":         "jwt_tool",
    "business_logic":       "nuclei",
    "auth_bypass":          "nuclei",
    "open_redirect":        "nuclei",
    "information_disclosure": "nuclei",
    "lfi":                  "nuclei",
    "rce":                  "nuclei",
    "ssti":                 "nuclei",
    "xxe":                  "nuclei",
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class AttackPlanItem:
    __slots__ = ("action", "target", "reason", "priority", "tool")

    def __init__(self, action: str, target: str, reason: str, priority: str = "medium") -> None:
        self.action = action
        self.target = target
        self.reason = reason
        self.priority = priority if priority in _VALID_PRIORITIES else "medium"
        self.tool: str = _ACTION_TO_TOOL.get(action, "nuclei")

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "priority": self.priority,
            "tool": self.tool,
        }


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are an expert penetration tester. Your role is REASONING ONLY — not execution. "
    "Always respond with valid JSON matching the exact schema requested. "
    "No explanations outside the JSON object. Maximum 5 items per attack_plan."
)

_PLAN_PROMPT = """\
Analyze this security assessment context and generate a targeted attack plan.

TARGET: {target}
TECH STACK: {tech_stack}
ENDPOINTS ({endpoint_count} total, sample):
{endpoints_sample}

PARAMETERIZED ENDPOINTS:
{params_sample}

EXISTING FINDINGS ({finding_count}):
{findings_sample}

AUTH CONTEXT: {auth_context}

Respond ONLY with valid JSON:
{{
  "attack_plan": [
    {{
      "action": "<one of: {valid_actions}>",
      "target": "<specific endpoint or parameter from the list above>",
      "reason": "<one sentence — why this is likely vulnerable>",
      "priority": "<high|medium|low>"
    }}
  ]
}}

Constraints:
- Maximum 5 items
- Only suggest actions not already confirmed in existing findings
- Only use endpoints listed above — do not invent new ones
- Priority 'high' only for high-impact attack classes (RCE, SQLi, auth bypass)
"""

_RESPONSE_ANALYSIS_PROMPT = """\
Analyze this security tool output for hidden vulnerabilities.

TOOL: {tool_name}
TARGET: {target}
OUTPUT (first 2000 chars):
{response_text}

Respond ONLY with valid JSON:
{{
  "signals": [
    {{
      "type": "<vulnerability_type e.g. xss|sqli|ssrf|idor|auth_bypass|business_logic>",
      "confidence": "<high|medium|low>",
      "evidence": "<exact text from the output that indicates this>",
      "next_action": "<one of: {valid_actions}>",
      "recommendation": "<one sentence next action>"
    }}
  ]
}}

Constraints:
- Maximum 3 signals
- Only include signals with direct textual evidence from the output
- next_action MUST be one of the listed valid_actions
- If no signals: return {{"signals": []}}

Valid actions: {valid_actions}
"""

_PAYLOAD_PROMPT = """\
Suggest 3-5 targeted WAF bypass payloads for this specific context.

CONTEXT: {context}
VULNERABILITY TYPE: {vuln_type}
EXISTING PAYLOADS (already tried, do not repeat):
{existing_payloads}
WAF FILTER BEHAVIOR: {filter_behavior}

Respond ONLY with valid JSON:
{{
  "payloads": ["<payload1>", "<payload2>", "<payload3>"]
}}

Constraints:
- Maximum 5 payloads
- Must differ meaningfully from existing payloads listed above
- Each payload must be a raw string with no surrounding quotes inside
"""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AIReasoningEngine:
    """
    LLM reasoning layer — strategy and analysis only, zero execution.

    Phase 5 upgrades:
      - All calls cached via LLMCache (SHA256 keyed, TTL-aware)
      - Prompt deduplication via ctx["llm_prompt_history"]
      - Output validated + hallucination-guarded via LLMValidator
      - Context built via context_builder.build_llm_context()
      - Call guard: skip LLM when context hasn't changed meaningfully

    Every public method is safe to call without API keys; returns empty
    results on failure so the pipeline continues with rules + decision engine.
    """

    def __init__(self, timeout_s: float = 30.0) -> None:
        self._timeout_s = timeout_s
        self._orchestrator = None  # lazy
        self._cache = None         # lazy — LLMCache singleton
        self._validator = None     # lazy — LLMValidator singleton
        # Per-instance call guard: (task_type → last context fingerprint)
        self._last_fingerprints: Dict[str, str] = {}

    # ── Lazy accessors ─────────────────────────────────────────────────────────

    def _get_orchestrator(self):
        if self._orchestrator is not None:
            return self._orchestrator
        try:
            from model_orchestrator import get_orchestrator
            self._orchestrator = get_orchestrator()
            return self._orchestrator
        except Exception as exc:
            log.debug("[ARE] model_orchestrator unavailable: %s", exc)
            return None

    def _get_cache(self):
        if self._cache is None:
            try:
                from core.llm_cache import get_llm_cache
                self._cache = get_llm_cache()
            except Exception:
                pass
        return self._cache

    def _get_validator(self):
        if self._validator is None:
            try:
                from core.llm_validator import get_llm_validator
                self._validator = get_llm_validator()
            except Exception:
                pass
        return self._validator

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _call_llm(
        self,
        prompt: str,
        task_type: str = "security_analysis",
        ctx: Optional[dict] = None,
    ) -> Optional[str]:
        """
        Call LLM with cache lookup, prompt deduplication, and timeout guard.

        Steps:
          1. Check prompt-dedup history in ctx["llm_prompt_history"]
          2. Look up cache by (model, task_type, prompt)
          3. On miss: call model_orchestrator, store in cache
          4. Return content or None
        """
        orch = self._get_orchestrator()
        if orch is None:
            return None

        cache = self._get_cache()

        # Determine model_id for cache key (use default if unknown)
        model_id = "default"
        try:
            model_id = getattr(orch, "_last_model_id", None) or "default"
        except Exception:
            pass

        cache_key = cache.make_key(model_id, task_type, prompt) if cache else ""
        prompt_hash = cache.make_prompt_hash(prompt) if cache else ""

        # ── Fix 2: Prompt deduplication ──────────────────────────────────────
        if ctx is not None and prompt_hash:
            history: set = ctx.setdefault("llm_prompt_history", set())
            if prompt_hash in history:
                log.debug("[ARE] Prompt dedup HIT (task=%s) — skipping LLM call", task_type)
                return None
            history.add(prompt_hash)
            # Cap history size
            if len(history) > 200:
                ctx["llm_prompt_history"] = set(list(history)[-100:])

        # ── Fix 1: Cache lookup ───────────────────────────────────────────────
        if cache and cache_key:
            cached = cache.get(cache_key, task_type=task_type)
            if cached is not None:
                log.debug("[ARE] Cache HIT (task=%s key=%s…)", task_type, cache_key[:10])
                return cached

        # ── LLM call ─────────────────────────────────────────────────────────
        try:
            t_start = time.time()
            output = orch.execute(
                task={
                    "prompt":      f"{_SYSTEM_PROMPT}\n\n{prompt}",
                    "description": task_type,
                    "importance":  "medium",
                    "complexity":  "medium",
                    "latency":     "interactive",
                },
                task_id=f"are-{int(t_start * 1000) % 999999}",
            )
            elapsed = time.time() - t_start
            if elapsed > self._timeout_s:
                log.warning("[ARE] LLM timeout (%.1fs)", elapsed)
                return None
            content = getattr(output, "content", None) or ""
            log.debug("[ARE] %s: %.2fs, %d chars", task_type, elapsed, len(content))
            if not content:
                return None
            # Store in cache
            if cache and cache_key:
                cache.set(cache_key, content, task_type=task_type)
            return content
        except Exception as exc:
            log.debug("[ARE] LLM call failed (%s): %s", task_type, exc)
            return None

    # ── Fix 7: Call guard ──────────────────────────────────────────────────────

    def _should_call_llm(
        self,
        task_type: str,
        context_fp: str,
        findings: List[dict],
        ctx: Optional[dict] = None,
    ) -> bool:
        """
        Skip LLM call if:
          - context fingerprint unchanged from last call of this task_type
          - no new findings AND no new chain_data AND no new signals

        Returns True if the call should proceed.
        """
        last_fp = self._last_fingerprints.get(task_type, "")
        if last_fp == context_fp:
            # Context unchanged — check if there is new data that warrants a call
            chain_data = (ctx or {}).get("chain_data", {})
            signals = (ctx or {}).get("loop_history", {}).get("ai_signals", [])
            if not findings and not chain_data.get("tokens") and not signals:
                log.debug("[ARE] Call guard: context unchanged, no new data — skipping %s", task_type)
                return False
        self._last_fingerprints[task_type] = context_fp
        return True

    def _parse_json(self, text: str) -> Optional[dict]:
        """Extract and parse the first JSON object from LLM output."""
        if not text:
            return None
        # Strip markdown fences
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fenced:
            text = fenced.group(1)
        # Find first { … } block
        block = re.search(r"\{.*\}", text, re.DOTALL)
        if block:
            text = block.group(0)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            log.debug("[ARE] JSON parse error: %s | text=%s", exc, text[:300])
            return None

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate_attack_plan(
        self,
        target: str,
        endpoints: List[str],
        params_map: Dict[str, List[str]],
        findings: List[dict],
        tech_stack: str = "unknown",
        auth_context: Optional[dict] = None,
        ctx: Optional[dict] = None,           # pipeline context for cache/dedup/guard
    ) -> List[AttackPlanItem]:
        """
        Generate a structured attack plan from target context.

        Phase 5 enhancements:
          - Uses context_builder for lean, consistent prompt content
          - Call guard: skip if context fingerprint unchanged and no new data
          - Prompt dedup: skip if same prompt already sent this session
          - Output validated + hallucination-guarded via LLMValidator
          - Response cached by SHA256 key

        Returns empty list when LLM unavailable or guard fires.
        """
        try:
            # ── Build structured context ──────────────────────────────────────
            if ctx is not None:
                from core.context_builder import build_llm_context, context_fingerprint, format_for_prompt
                built = build_llm_context(
                    ctx, target,
                    max_endpoints=10, max_findings=5, max_params=5,
                )
                ctx_fp = context_fingerprint(built)
                prompt_body = format_for_prompt(built)
                known_urls = built["top_endpoints"] + built["auth_endpoints"]
            else:
                # Fallback: build inline (callers without ctx)
                built = None
                ctx_fp = ""
                endpoints_sample = "\n".join(f"  {u}" for u in endpoints[:10]) or "  (none)"
                params_sample = "\n".join(
                    f"  {url}: {', '.join(params)}"
                    for url, params in list(params_map.items())[:8]
                ) or "  (none)"
                findings_sample = "\n".join(
                    f"  [{f.get('severity','?')}] {f.get('vuln_type','?')} @ "
                    f"{f.get('url', f.get('target','?'))}"
                    for f in findings[:5]
                ) or "  (none)"
                prompt_body = (
                    f"TARGET: {target}\nTECH STACK: {str(tech_stack)[:200]}\n"
                    f"ENDPOINTS ({len(endpoints)} total):\n{endpoints_sample}\n"
                    f"PARAMETERS:\n{params_sample}\n"
                    f"EXISTING FINDINGS ({len(findings)}):\n{findings_sample}\n"
                    f"AUTH CONTEXT: {json.dumps(auth_context or {})[:300]}"
                )
                known_urls = endpoints[:20]

            # ── Fix 7: Call guard ─────────────────────────────────────────────
            if ctx_fp and not self._should_call_llm(
                "attack_plan_generation", ctx_fp, findings, ctx
            ):
                return []

            prompt = _PLAN_PROMPT.format(
                target=target,
                tech_stack=str(tech_stack)[:200],
                endpoint_count=len(endpoints),
                endpoints_sample="\n".join(f"  {u}" for u in endpoints[:10]) or "  (none)",
                params_sample="\n".join(
                    f"  {url}: {', '.join(params)}"
                    for url, params in list(params_map.items())[:8]
                ) or "  (none)",
                finding_count=len(findings),
                findings_sample="\n".join(
                    f"  [{f.get('severity','?')}] {f.get('vuln_type','?')} @ "
                    f"{f.get('url', f.get('target','?'))}"
                    for f in findings[:5]
                ) or "  (none)",
                auth_context=json.dumps(auth_context or {})[:300],
                valid_actions=", ".join(sorted(_VALID_ACTIONS)),
            )

            raw = self._call_llm(prompt, task_type="attack_plan_generation", ctx=ctx)
            if not raw:
                return []

            parsed = self._parse_json(raw)

            # ── Fix 4+5: Validate + hallucination guard ───────────────────────
            validator = self._get_validator()
            if validator:
                ok, validated_entries = validator.validate_attack_plan(
                    parsed, _VALID_ACTIONS, known_urls
                )
                if not ok:
                    log.debug("[ARE] attack_plan validation failed — returning empty")
                    return []
            else:
                # Inline minimal validation fallback
                if not parsed or "attack_plan" not in parsed:
                    return []
                validated_entries = [
                    e for e in parsed["attack_plan"][:5]
                    if isinstance(e, dict) and e.get("action") in _VALID_ACTIONS
                ]

            items: List[AttackPlanItem] = [
                AttackPlanItem(
                    action=e["action"],
                    target=e.get("target", "")[:300],
                    reason=e.get("reason", "")[:300],
                    priority=e.get("priority", "medium"),
                )
                for e in validated_entries
            ]

            log.info("[ARE] Attack plan: %d validated items", len(items))
            return items

        except Exception as exc:
            log.debug("[ARE] generate_attack_plan exception: %s", exc)
            return []

    def map_plan_to_tools(self, plan: List[AttackPlanItem]) -> List[str]:
        """
        Convert attack plan items → ordered, deduplicated tool list.
        High priority items first.
        """
        seen: set = set()
        tools: List[str] = []
        for priority in ("high", "medium", "low"):
            for item in plan:
                if item.priority == priority and item.tool not in seen:
                    tools.append(item.tool)
                    seen.add(item.tool)
        return tools

    def generate_attack_plan_batch(
        self,
        target: str,
        endpoint_groups: List[List[str]],
        params_map: Dict[str, List[str]],
        findings: List[dict],
        tech_stack: str = "unknown",
        ctx: Optional[dict] = None,
    ) -> List[AttackPlanItem]:
        """
        Fix 8: Batch LLM request — analyze multiple endpoint groups in one call.

        Combines up to 3 groups into a single prompt instead of N separate calls.
        Returns merged, deduplicated AttackPlanItems.
        """
        if not endpoint_groups:
            return []
        # Flatten and dedup, capping at 15 endpoints
        merged_endpoints: List[str] = []
        seen_eps: set = set()
        for grp in endpoint_groups[:3]:
            for ep in grp[:5]:
                if ep not in seen_eps:
                    merged_endpoints.append(ep)
                    seen_eps.add(ep)
        if not merged_endpoints:
            return []
        return self.generate_attack_plan(
            target=target,
            endpoints=merged_endpoints,
            params_map=params_map,
            findings=findings,
            tech_stack=tech_stack,
            ctx=ctx,
        )

    def analyze_response(
        self,
        tool_name: str,
        target: str,
        response_text: str,
        ctx: Optional[dict] = None,
    ) -> List[dict]:
        """
        Analyze a tool's raw output for actionable vulnerability signals.

        Returns list of signal dicts:
          {source, tool, type, confidence, evidence, next_action, tool_to_run, recommendation}

        ``next_action`` is a validated action string from _VALID_ACTIONS.
        ``tool_to_run`` is the concrete tool name mapped from next_action.
        Returns empty list on failure — never blocks pipeline.
        """
        if not response_text or len(response_text.strip()) < 50:
            return []
        try:
            prompt = _RESPONSE_ANALYSIS_PROMPT.format(
                tool_name=tool_name,
                target=target,
                response_text=response_text[:2000],
                valid_actions=", ".join(sorted(_VALID_ACTIONS)),
            )
            raw = self._call_llm(prompt, task_type="response_analysis", ctx=ctx)
            if not raw:
                return []
            parsed = self._parse_json(raw)

            # ── Validate signals via LLMValidator ─────────────────────────────
            validator = self._get_validator()
            if validator:
                ok, validated_sigs = validator.validate_signals(parsed, _VALID_ACTIONS)
                if not ok:
                    return []
                raw_sigs = validated_sigs
            else:
                if not parsed or "signals" not in parsed:
                    return []
                raw_sigs = parsed["signals"][:3]

            signals: List[dict] = []
            for sig in raw_sigs:
                sig_type = str(sig.get("type", "")).strip().lower()
                if not sig_type:
                    continue
                next_action = str(sig.get("next_action", "")).strip()
                tool_to_run = (
                    _ACTION_TO_TOOL.get(next_action)
                    or _SIGNAL_TO_TOOL.get(sig_type)
                    or ""
                )
                signals.append({
                    "source":         "ai_analysis",
                    "tool":           tool_name,
                    "type":           sig_type[:100],
                    "confidence":     sig.get("confidence", "low"),
                    "evidence":       sig.get("evidence", "")[:500],
                    "next_action":    next_action,
                    "tool_to_run":    tool_to_run,
                    "recommendation": sig.get("recommendation", "")[:200],
                })
            if signals:
                log.info("[ARE] Response analysis: %d actionable signals from %s", len(signals), tool_name)
            return signals
        except Exception as exc:
            log.debug("[ARE] analyze_response exception: %s", exc)
            return []

    def signals_to_tools(self, signals: List[dict]) -> List[str]:
        """
        Convert actionable AI signals to executable tool names.
        Ordered by confidence: high → medium → low.
        Deduped — each tool appears at most once.
        """
        seen: set = set()
        tools: List[str] = []
        for conf in ("high", "medium", "low"):
            for sig in signals:
                if sig.get("confidence") != conf:
                    continue
                tool = sig.get("tool_to_run", "")
                if tool and tool not in seen:
                    tools.append(tool)
                    seen.add(tool)
        return tools

    def suggest_payloads(
        self,
        context: str,
        vuln_type: str,
        existing_payloads: List[str],
        filter_behavior: str = "unknown",
        ctx: Optional[dict] = None,
    ) -> List[str]:
        """
        Suggest 3–5 targeted payloads for WAF bypass.
        Complements (never replaces) HttpPayloadMutator.
        Returns empty list on failure.
        Cached + validated.
        """
        try:
            prompt = _PAYLOAD_PROMPT.format(
                context=str(context)[:500],
                vuln_type=vuln_type,
                existing_payloads="\n".join(f"  - {p}" for p in existing_payloads[:5]),
                filter_behavior=str(filter_behavior)[:200],
            )
            raw = self._call_llm(prompt, task_type="payload_suggestion", ctx=ctx)
            if not raw:
                return []
            parsed = self._parse_json(raw)
            validator = self._get_validator()
            if validator:
                ok, payloads = validator.validate_payloads(parsed)
                if not ok:
                    return []
            else:
                if not parsed or "payloads" not in parsed:
                    return []
                payloads = [str(p)[:500] for p in parsed["payloads"][:5] if p and str(p).strip()]
            if payloads:
                log.info("[ARE] Payload suggestion: %d payloads for %s", len(payloads), vuln_type)
            return payloads
        except Exception as exc:
            log.debug("[ARE] suggest_payloads exception: %s", exc)
            return []

    def rank_chains(
        self,
        chain_types: List[str],
        target: str,
        findings: List[dict],
        ctx: Optional[dict] = None,
    ) -> List[str]:
        """
        Fix 9: Use LLM to rank exploit chains by priority.
        Returns ordered list of chain_types (highest impact first).
        Falls back to severity-based sort if LLM unavailable.
        """
        if not chain_types:
            return []
        _CHAIN_RANK_PROMPT = (
            f"Rank these exploit chains by potential impact for target {target}.\n"
            f"Available chains: {', '.join(chain_types)}\n"
            f"Existing findings: {len(findings)} ({', '.join(set(f.get('severity','') for f in findings[:5]))})\n\n"
            "Respond ONLY with valid JSON:\n"
            '{{"priority_chains": ["<chain_type1>", "<chain_type2>", ...]}}\n\n'
            "Constraints:\n"
            "- Only include chain types from the Available chains list above\n"
            "- Order by expected impact (critical > high > medium > low)\n"
        )
        try:
            raw = self._call_llm(_CHAIN_RANK_PROMPT, task_type="security_analysis", ctx=ctx)
            if not raw:
                return chain_types
            parsed = self._parse_json(raw)
            validator = self._get_validator()
            if validator:
                ok, ranked = validator.validate_chain_ranking(parsed, chain_types)
                if ok:
                    # Append any unranked chains at the end
                    ranked_set = set(ranked)
                    tail = [ct for ct in chain_types if ct not in ranked_set]
                    log.info("[ARE] Chain ranking: %d chains ordered by AI", len(ranked))
                    return ranked + tail
        except Exception as exc:
            log.debug("[ARE] rank_chains exception: %s", exc)
        return chain_types


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[AIReasoningEngine] = None


def get_ai_reasoning_engine() -> AIReasoningEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AIReasoningEngine()
    return _engine_instance
