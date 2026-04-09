"""
model_orchestrator.py — Model Orchestration Engine

Routes tasks to the optimal AI model using:
  1. Task classification  → required tier
  2. Budget check         → cheapest viable model
  3. Model call           → with retry + failover
  4. Confidence scoring   → escalate if below threshold
  5. Outcome recording    → feed back into decision engine

Escalation flow:
  FAST → STANDARD → PREMIUM
   ↑         ↑
  conf<0.65  conf<0.75

Provider support:
  - OpenAI   (requests to api.openai.com)
  - Anthropic (requests to api.anthropic.com)
  Both via raw HTTP using requests — no SDK dependency.

Integration points (all optional, graceful fallback):
  - attack_graph_brain: execute_for_brain(action)
  - graph_trigger_engine: execute_for_trigger(firing)
  - intelligence_daemon: execute_for_daemon(worker, event)
  - autonomous_decision_engine: record_outcome()
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from oneinfinity.task_classifier import (
    TaskClassification, TaskClassifier, TaskCategory,
    ComplexityLevel, ImportanceLevel, LatencyClass, get_classifier,
)
from oneinfinity.model_budget_manager import (
    ModelBudgetManager, BudgetConfig, BudgetExhaustedError, get_budget_manager,
)

log = logging.getLogger("model_orchestrator")

# ── Model tier ─────────────────────────────────────────────────────────────────

class ModelTier(IntEnum):
    FAST     = 1
    STANDARD = 2
    PREMIUM  = 3


# ── Model registry ─────────────────────────────────────────────────────────────

@dataclass
class ModelConfig:
    model_id:            str
    provider:            str              # "openai" | "anthropic"
    tier:                ModelTier
    cost_per_1k_input:   float
    cost_per_1k_output:  float
    max_context_tokens:  int
    latency_class:       str
    capabilities:        Set[str]         # TaskCategory values
    enabled:             bool = True
    api_base:            str  = ""        # override endpoint
    extra:               dict = field(default_factory=dict)

    def cost_estimate(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens  / 1000 * self.cost_per_1k_input
              + output_tokens / 1000 * self.cost_per_1k_output)

    def to_dict(self) -> dict:
        return {
            "model_id":           self.model_id,
            "provider":           self.provider,
            "tier":               self.tier.name,
            "cost_per_1k_input":  self.cost_per_1k_input,
            "cost_per_1k_output": self.cost_per_1k_output,
            "max_context_tokens": self.max_context_tokens,
            "capabilities":       sorted(self.capabilities),
            "enabled":            self.enabled,
        }


# ── Output & confidence ────────────────────────────────────────────────────────

@dataclass
class ModelOutput:
    output_id:      str
    task_id:        str
    model_id:       str
    tier:           ModelTier
    content:        str
    confidence:     float          # 0-1 composite score
    input_tokens:   int
    output_tokens:  int
    cost_usd:       float
    duration_ms:    float
    escalated_from: Optional[str]  # model_id of the model that was escalated from
    escalation_reason: str
    retries:        int
    metadata:       dict = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict:
        return {
            "output_id":        self.output_id,
            "task_id":          self.task_id,
            "model_id":         self.model_id,
            "tier":             self.tier.name,
            "content":          self.content,
            "confidence":       round(self.confidence, 3),
            "tokens":           self.total_tokens,
            "cost_usd":         round(self.cost_usd, 6),
            "duration_ms":      round(self.duration_ms, 1),
            "escalated_from":   self.escalated_from,
            "escalation_reason": self.escalation_reason,
            "retries":          self.retries,
        }


# ── Confidence evaluator ───────────────────────────────────────────────────────

class ConfidenceEvaluator:
    """
    Scores model output quality without calling another model.
    Combines multiple rule-based signals into a composite 0-1 score.
    """

    # Expected minimum token counts per category
    _MIN_TOKENS: Dict[str, int] = {
        TaskCategory.EXPLOIT_GEN:      80,
        TaskCategory.VULN_ANALYSIS:    60,
        TaskCategory.HYPOTHESIS:       50,
        TaskCategory.CHAIN_DETECTION:  60,
        TaskCategory.CODE_ANALYSIS:    80,
        TaskCategory.REPORT_WRITING:   100,
        TaskCategory.BIZ_LOGIC:        60,
        "default":                     30,
    }

    _UNCERTAINTY_PATTERNS = re.compile(
        r"\b(i(?:'m| am) not sure|i(?:'m| am) uncertain|unclear|might be|could be|"
        r"possibly|probably|i cannot determine|hard to say|it depends|"
        r"without more (context|information)|i don't have enough)\b",
        re.IGNORECASE,
    )

    _REFUSAL_PATTERNS = re.compile(
        r"\b(i(?:'m| am) unable to|i cannot|i can'?t|i won'?t|"
        r"i(?:'m| am) not able to|that(?:'s| is) not something i can)\b",
        re.IGNORECASE,
    )

    # Category-specific required keywords
    _CATEGORY_VALIDATORS: Dict[str, List[str]] = {
        TaskCategory.VULN_ANALYSIS:   ["severity", "cvss", "vulnerability", "impact"],
        TaskCategory.EXPLOIT_GEN:     ["payload", "exploit", "poc", "code", "bypass"],
        TaskCategory.HYPOTHESIS:      ["vulnerability", "likely", "parameter", "endpoint"],
        TaskCategory.CHAIN_DETECTION: ["chain", "leads to", "enables", "escalate"],
        TaskCategory.REPORT_WRITING:  ["impact", "severity", "steps", "recommendation"],
    }

    def score(self, output: ModelOutput, classification: TaskClassification) -> float:
        """Compute composite confidence score (0-1)."""
        content  = output.content or ""
        category = classification.category

        signals: List[Tuple[float, float]] = []  # (score, weight)

        # 1. Refusal check — hard zero
        if self._REFUSAL_PATTERNS.search(content):
            log.debug("Refusal detected in output from %s", output.model_id)
            return 0.05

        # 2. Length adequacy
        min_tok = self._MIN_TOKENS.get(category, self._MIN_TOKENS["default"])
        approx_tokens = max(1, len(content) // 4)
        length_score  = min(1.0, approx_tokens / max(min_tok, 1))
        signals.append((length_score, 2.0))

        # 3. Uncertainty markers (penalize)
        uncertainty_count = len(self._UNCERTAINTY_PATTERNS.findall(content))
        uncertainty_score = max(0.0, 1.0 - uncertainty_count * 0.15)
        signals.append((uncertainty_score, 1.5))

        # 4. Category-specific keyword presence
        required = self._CATEGORY_VALIDATORS.get(category, [])
        if required:
            found   = sum(1 for kw in required if kw.lower() in content.lower())
            kw_score = found / len(required)
            signals.append((kw_score, 2.0))

        # 5. JSON validity check (if output looks like JSON)
        if content.strip().startswith("{") or content.strip().startswith("["):
            try:
                json.loads(content)
                signals.append((1.0, 1.0))
            except json.JSONDecodeError:
                signals.append((0.2, 1.0))

        # 6. Coherence heuristic — penalize very short outputs for complex tasks
        if classification.complexity >= ComplexityLevel.HIGH and approx_tokens < 50:
            signals.append((0.2, 2.0))
        else:
            signals.append((1.0, 0.5))

        # 7. Classifier confidence carries over slightly
        signals.append((classification.classifier_confidence, 0.5))

        # Weighted average
        total_weight = sum(w for _, w in signals)
        composite    = sum(s * w for s, w in signals) / max(total_weight, 0.001)
        return round(min(1.0, max(0.0, composite)), 4)


# ── Routing policy ─────────────────────────────────────────────────────────────

@dataclass
class RoutingPolicy:
    fast_to_standard_threshold:  float = 0.65
    standard_to_premium_threshold: float = 0.75
    max_retries_same_model:      int   = 2
    retry_backoff_base_s:        float = 1.0
    temperature_by_tier:         Dict[str, float] = field(default_factory=lambda: {
        "FAST": 0.2, "STANDARD": 0.3, "PREMIUM": 0.4
    })
    min_tier_by_importance: Dict[str, str] = field(default_factory=lambda: {
        "CRITICAL": "STANDARD",
    })

    @classmethod
    def from_dict(cls, d: dict) -> "RoutingPolicy":
        p = cls()
        thresh = d.get("escalation_thresholds", {})
        p.fast_to_standard_threshold     = thresh.get("FAST_to_STANDARD", 0.65)
        p.standard_to_premium_threshold  = thresh.get("STANDARD_to_PREMIUM", 0.75)
        p.max_retries_same_model         = d.get("max_retries_same_model", 2)
        p.retry_backoff_base_s           = d.get("retry_backoff_base_s", 1.0)
        p.temperature_by_tier            = d.get("temperature", p.temperature_by_tier)
        p.min_tier_by_importance         = d.get("min_tier_by_importance", p.min_tier_by_importance)
        return p


# ── Provider backends ─────────────────────────────────────────────────────────

import shutil as _shutil
import subprocess as _subprocess


class _OpenAIBackend:
    """
    OpenAI Chat Completions API.
    Auth: OPENAI_API_KEY env var (required — Codex CLI JWT is not accepted by the standard API).
    """

    BASE_URL = "https://api.openai.com/v1/chat/completions"

    def __init__(self) -> None:
        self._api_key = os.environ.get("OPENAI_API_KEY", "")
        if not self._api_key:
            log.debug("[openai] OPENAI_API_KEY not set — OpenAI models will be unavailable")

    def call(self, model_id: str, system: str, prompt: str,
             temperature: float, max_tokens: int) -> Tuple[str, int, int]:
        import requests as req
        if not self._api_key:
            raise RuntimeError("OPENAI_API_KEY not set")
        payload = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": prompt},
            ],
            "temperature": temperature,
            "max_tokens":  min(max_tokens, 4096),
        }
        resp = req.post(
            self.BASE_URL,
            json=payload,
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            timeout=60,
        )
        resp.raise_for_status()
        data          = resp.json()
        content       = data["choices"][0]["message"]["content"]
        usage         = data.get("usage", {})
        return content, usage.get("prompt_tokens", len(prompt) // 4), usage.get("completion_tokens", len(content) // 4)


class _AnthropicBackend:
    """
    Anthropic Claude API.
    Auth priority:
      1. ANTHROPIC_API_KEY env var  → direct HTTP to api.anthropic.com
      2. claude CLI installed       → subprocess: claude -p <prompt> --model <id>
    """

    BASE_URL = "https://api.anthropic.com/v1/messages"

    # Map YAML model IDs to the short aliases accepted by the claude CLI
    _CLI_MODEL_ALIASES: Dict[str, str] = {
        "claude-haiku-4-5":  "claude-haiku-4-5",
        "claude-sonnet-4-6": "claude-sonnet-4-6",
        "claude-opus-4-6":   "claude-opus-4-6",
    }

    def __init__(self) -> None:
        self._api_key  = os.environ.get("ANTHROPIC_API_KEY", "")
        self._use_cli  = False
        if not self._api_key:
            if _shutil.which("claude"):
                self._use_cli = True
                log.info("[anthropic] ANTHROPIC_API_KEY not set — using 'claude' CLI subprocess")
            else:
                log.debug("[anthropic] No credentials: set ANTHROPIC_API_KEY or install Claude Code CLI")

    def call(self, model_id: str, system: str, prompt: str,
             temperature: float, max_tokens: int) -> Tuple[str, int, int]:
        if self._use_cli:
            return self._call_cli(model_id, system, prompt)
        return self._call_api(model_id, system, prompt, temperature, max_tokens)

    def _call_api(self, model_id: str, system: str, prompt: str,
                  temperature: float, max_tokens: int) -> Tuple[str, int, int]:
        import requests as req
        if not self._api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        payload = {
            "model": model_id, "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature, "max_tokens": min(max_tokens, 4096),
        }
        resp = req.post(self.BASE_URL, json=payload, headers={
            "x-api-key": self._api_key, "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }, timeout=60)
        resp.raise_for_status()
        data  = resp.json()
        content = data["content"][0]["text"]
        usage = data.get("usage", {})
        return content, usage.get("input_tokens", len(prompt) // 4), usage.get("output_tokens", len(content) // 4)

    def _call_cli(self, model_id: str, system: str, prompt: str) -> Tuple[str, int, int]:
        cli_model = self._CLI_MODEL_ALIASES.get(model_id, model_id)
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        cmd = [
            "claude", "-p", full_prompt,
            "--model", cli_model,
            "--allowed-tools", "",          # disable all tools — pure LLM response
            "--max-budget-usd", "0.50",
        ]
        result = _subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"claude CLI exited {result.returncode}: {result.stderr[:300]}")
        content = result.stdout.strip()
        in_tok  = len(full_prompt) // 4
        out_tok = len(content) // 4
        return content, in_tok, out_tok


class _GeminiBackend:
    """
    Google Gemini via gemini CLI subprocess.
    Auth: gemini CLI OAuth session (~/.gemini/oauth_creds.json).
    Requires: npm install -g @google/gemini-cli  +  gemini (login once interactively)
    """

    # Map YAML model IDs to the -m flag values accepted by the gemini CLI
    _CLI_MODEL_MAP: Dict[str, Optional[str]] = {
        "gemini-2.0-flash":              None,         # omit -m → uses CLI default
        "gemini-2.5-pro-preview-03-25":  "gemini-2.5-pro",
    }

    def __init__(self) -> None:
        self._available = bool(_shutil.which("gemini"))
        if self._available:
            log.info("[gemini] 'gemini' CLI found — Gemini models available via CLI subprocess")
        else:
            log.debug("[gemini] 'gemini' CLI not found — Gemini models unavailable")

    def call(self, model_id: str, system: str, prompt: str,
             temperature: float, max_tokens: int) -> Tuple[str, int, int]:
        if not self._available:
            raise RuntimeError("gemini CLI not installed: npm install -g @google/gemini-cli")
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        cli_model = self._CLI_MODEL_MAP.get(model_id, model_id)
        cmd = ["gemini", "-p", full_prompt, "--approval-mode", "plan"]
        if cli_model:
            cmd.extend(["-m", cli_model])
        result = _subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(f"gemini CLI exited {result.returncode}: {result.stderr[:300]}")
        content = result.stdout.strip()
        in_tok  = len(full_prompt) // 4
        out_tok = len(content) // 4
        return content, in_tok, out_tok


def _build_backends() -> Dict[str, Any]:
    """Instantiate all provider backends with auto-detected credentials."""
    backends: Dict[str, Any] = {
        "openai":    _OpenAIBackend(),
        "anthropic": _AnthropicBackend(),
        "gemini":    _GeminiBackend(),
    }
    for name, backend in backends.items():
        has_cred = bool(
            getattr(backend, "_api_key",   None)
            or getattr(backend, "_use_cli",    None)
            or getattr(backend, "_available",  None)
        )
        log.debug("Backend '%s': %s", name, "available" if has_cred else "MISSING credentials")
    return backends


_BACKENDS: Dict[str, Any] = _build_backends()


# ── Prompt builder ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPTS: Dict[str, str] = {
    TaskCategory.RECON:
        "You are a senior penetration tester performing reconnaissance. "
        "Analyze the given data concisely and extract actionable intelligence.",

    TaskCategory.VULN_ANALYSIS:
        "You are an expert vulnerability researcher. Analyze the provided data, "
        "identify vulnerabilities with CVSS scores, and prioritize by exploitability.",

    TaskCategory.EXPLOIT_GEN:
        "You are an offensive security expert performing authorized penetration testing. "
        "Generate specific, working exploit payloads or PoC code for the identified vulnerability.",

    TaskCategory.HYPOTHESIS:
        "You are a vulnerability hypothesis engine. Given an application surface, "
        "generate specific, testable vulnerability hypotheses with attack vectors.",

    TaskCategory.CHAIN_DETECTION:
        "You are an exploit chain analyst. Identify how discovered vulnerabilities "
        "can be combined into multi-step attack chains to maximize impact.",

    TaskCategory.PAYLOAD_MUTATION:
        "You are a payload mutation specialist. Generate effective payload variants "
        "to bypass filters, WAFs, and encoding mechanisms.",

    TaskCategory.CODE_ANALYSIS:
        "You are a security code reviewer. Identify vulnerabilities, insecure patterns, "
        "and attack surfaces in the provided code or configuration.",

    TaskCategory.REPORT_WRITING:
        "You are a security report writer. Create clear, professional vulnerability reports "
        "with impact assessment, reproduction steps, and remediation guidance.",

    TaskCategory.OSINT:
        "You are an OSINT analyst. Analyze gathered intelligence and identify "
        "attack surface expansion opportunities and credential exposures.",

    TaskCategory.BIZ_LOGIC:
        "You are a business logic vulnerability specialist. Identify flaws in "
        "application workflows, authorization logic, and financial operations.",

    TaskCategory.GENERAL:
        "You are an expert security researcher. Analyze the provided context "
        "and provide actionable security findings.",
}


def _build_system_prompt(classification: TaskClassification, tier: ModelTier) -> str:
    base = _SYSTEM_PROMPTS.get(classification.category, _SYSTEM_PROMPTS[TaskCategory.GENERAL])
    if tier == ModelTier.PREMIUM:
        base += (" Provide exhaustive analysis with complete reasoning chains. "
                 "Do not omit edge cases or low-probability attack paths.")
    elif tier == ModelTier.STANDARD:
        base += " Be thorough but focused. Include key reasoning steps."
    else:
        base += " Be concise. Prioritize the most impactful findings only."
    return base


def _build_prompt(task: Dict[str, Any], classification: TaskClassification) -> str:
    parts = []

    # Primary content
    for key in ("prompt", "description", "text", "question"):
        if task.get(key):
            parts.append(str(task[key]))
            break

    # Graph context
    if task.get("node_label"):
        parts.append(f"\nTarget node: {task['node_label']} (type: {task.get('node_type','?')})")
    if task.get("node_properties"):
        props = {k: v for k, v in (task["node_properties"].items()
                                   if isinstance(task.get("node_properties"), dict)
                                   else {})}
        if props:
            parts.append(f"Node properties: {json.dumps(props, indent=2)[:500]}")

    # Context dict
    ctx = task.get("context", {})
    if isinstance(ctx, dict) and ctx:
        parts.append("\nAdditional context:")
        for k, v in list(ctx.items())[:8]:
            parts.append(f"  {k}: {str(v)[:200]}")

    # Task metadata for orientation
    if task.get("agent_type"):
        parts.append(f"\nRequested agent type: {task['agent_type']}")
    if task.get("target"):
        parts.append(f"Target: {task['target']}")
    if task.get("severity"):
        parts.append(f"Severity context: {task['severity']}")

    # Complexity hint for deeper models
    if classification.complexity >= ComplexityLevel.HIGH:
        parts.append(f"\nNote: This is a high-complexity task requiring deep analysis "
                     f"(reasoning depth {classification.reasoning_depth}/5).")

    return "\n".join(parts) or "No input provided."


# ── Main orchestrator ──────────────────────────────────────────────────────────

class ModelOrchestrator:
    """
    Central model routing engine.

    Usage:
        orchestrator = get_orchestrator()
        output = orchestrator.execute(task_dict)
        print(output.content)
    """

    def __init__(self) -> None:
        self._models:     Dict[str, ModelConfig] = {}
        self._policy:     RoutingPolicy = RoutingPolicy()
        self._classifier: TaskClassifier = get_classifier()
        self._budget:     ModelBudgetManager = get_budget_manager()
        self._confidence: ConfidenceEvaluator = ConfidenceEvaluator()
        self._lock        = threading.RLock()
        self._history:    deque = deque(maxlen=500)
        self._loaded      = False

        # Hooks for integration modules
        self._pre_execute_hooks:  List[Callable] = []
        self._post_execute_hooks: List[Callable] = []

    # ── Configuration ─────────────────────────────────────────────────────────

    def load_config(self, path: Optional[Path] = None) -> None:
        """Load model registry and routing policy from models.yaml."""
        if path is None:
            path = Path(__file__).parent / "config" / "models.yaml"
        try:
            import yaml
            with open(path) as f:
                cfg = yaml.safe_load(f)
        except ImportError:
            # yaml not installed — fallback to manual dict parse or load defaults
            log.warning("PyYAML not installed; loading default model registry")
            self._load_defaults()
            return
        except FileNotFoundError:
            log.warning("models.yaml not found at %s; using defaults", path)
            self._load_defaults()
            return

        # Parse models
        for model_id, mcfg in cfg.get("models", {}).items():
            try:
                tier_str = mcfg.get("tier", "FAST")
                tier = ModelTier[tier_str]
                self.register_model(ModelConfig(
                    model_id=model_id,
                    provider=mcfg.get("provider", "openai"),
                    tier=tier,
                    cost_per_1k_input=float(mcfg.get("cost_per_1k_input", 0.001)),
                    cost_per_1k_output=float(mcfg.get("cost_per_1k_output", 0.002)),
                    max_context_tokens=int(mcfg.get("max_context_tokens", 8192)),
                    latency_class=mcfg.get("latency_class", LatencyClass.INTERACTIVE),
                    capabilities=set(mcfg.get("capabilities", [TaskCategory.GENERAL])),
                    enabled=bool(mcfg.get("enabled", True)),
                ))
            except Exception as e:
                log.warning("Skipping model %s: %s", model_id, e)

        # Parse budget
        if "budget" in cfg:
            budget_cfg = BudgetConfig.from_dict(cfg["budget"])
            self._budget.update_config(budget_cfg)

        # Parse routing policy
        if "routing" in cfg:
            self._policy = RoutingPolicy.from_dict(cfg["routing"])

        self._auto_enable_cli_models()
        self._loaded = True
        log.info("Loaded %d models from %s", len(self._models), path)

    def _load_defaults(self) -> None:
        """Built-in defaults when YAML is unavailable."""
        defaults = [
            ModelConfig(
                model_id="gpt-4o-mini",
                provider="openai",
                tier=ModelTier.FAST,
                cost_per_1k_input=0.00015,
                cost_per_1k_output=0.00060,
                max_context_tokens=128000,
                latency_class=LatencyClass.INTERACTIVE,
                capabilities=set(TaskCategory.ALL),
                enabled=True,
            ),
            ModelConfig(
                model_id="gpt-4o",
                provider="openai",
                tier=ModelTier.STANDARD,
                cost_per_1k_input=0.00250,
                cost_per_1k_output=0.01000,
                max_context_tokens=128000,
                latency_class=LatencyClass.INTERACTIVE,
                capabilities=set(TaskCategory.ALL),
                enabled=True,
            ),
        ]
        for m in defaults:
            self.register_model(m)
        self._loaded = True

    def _auto_enable_cli_models(self) -> None:
        """
        Enable models that are disabled in YAML but have CLI credentials available.
        Priority: env API key > CLI OAuth token.
        Models are only auto-enabled when their provider backend has valid credentials.
        """
        _provider_has_cred: Dict[str, bool] = {}
        for provider, backend in _BACKENDS.items():
            has_cred = bool(
                getattr(backend, "_api_key",   None)   # API key set
                or getattr(backend, "_use_cli",   None)   # claude CLI available
                or getattr(backend, "_available", None)   # gemini CLI available
            )
            _provider_has_cred[provider] = has_cred

        with self._lock:
            for model_id, model in self._models.items():
                if model.enabled:
                    continue
                if _provider_has_cred.get(model.provider, False):
                    model.enabled = True
                    log.info(
                        "[CLI auth] Auto-enabled model '%s' (provider=%s)",
                        model_id, model.provider,
                    )

    def register_model(self, config: ModelConfig) -> None:
        with self._lock:
            self._models[config.model_id] = config
        log.debug("Registered model: %s (tier=%s enabled=%s)",
                  config.model_id, config.tier.name, config.enabled)

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load_config()

    # ── Model selection ────────────────────────────────────────────────────────

    def _models_for_tier(self, tier: ModelTier,
                          category: str) -> List[ModelConfig]:
        """Return enabled models for the given tier that support the category, sorted by cost."""
        with self._lock:
            candidates = [
                m for m in self._models.values()
                if m.tier == tier
                and m.enabled
                and (category in m.capabilities or TaskCategory.GENERAL in m.capabilities)
            ]
        candidates.sort(key=lambda m: m.cost_per_1k_input + m.cost_per_1k_output)
        return candidates

    def _select_model(self, classification: TaskClassification,
                       tier: ModelTier) -> Optional[ModelConfig]:
        """
        Pick the cheapest available model in the given tier that:
        1. Supports the task category
        2. Has budget remaining
        """
        for model in self._models_for_tier(tier, classification.category):
            allowed, reason = self._budget.can_use_model(model.model_id, classification.category)
            if allowed:
                return model
        return None

    def _initial_tier(self, classification: TaskClassification) -> ModelTier:
        """Determine the starting tier based on task classification."""
        # Check minimum tier by importance override
        min_tier_str = self._policy.min_tier_by_importance.get(
            classification.importance.name, None
        )
        if min_tier_str:
            min_tier = ModelTier[min_tier_str]
        else:
            min_tier = ModelTier.FAST

        # Complexity-driven initial tier
        if classification.complexity >= ComplexityLevel.CRITICAL:
            initial = ModelTier.PREMIUM
        elif classification.complexity >= ComplexityLevel.HIGH:
            initial = ModelTier.STANDARD
        else:
            initial = ModelTier.FAST

        return max(initial, min_tier)

    # ── Main execution ─────────────────────────────────────────────────────────

    def execute(self, task: Dict[str, Any],
                 force_tier: Optional[ModelTier] = None,
                 task_id: Optional[str] = None) -> ModelOutput:
        """
        Core method. Classify → select → call → validate → escalate if needed.

        task dict keys used:
          prompt / description / text — content
          agent_type, node_type, node_label, node_properties
          severity, graph_priority, target
          importance, complexity, latency  (explicit overrides)
          context  (dict of extra data)
        """
        self._ensure_loaded()
        task_id = task_id or str(uuid.uuid4())[:12]

        # Pre-execute hooks
        for hook in self._pre_execute_hooks:
            try:
                hook(task, task_id)
            except Exception:
                pass

        # Classify
        classification = self._classifier.classify(task)
        log.debug("Task %s: category=%s complexity=%s importance=%s tier_hint=%s",
                  task_id, classification.category,
                  classification.complexity.name, classification.importance.name,
                  classification.tier_hint)

        # Determine starting tier
        start_tier = force_tier or self._initial_tier(classification)

        # Execute with escalation loop
        output = self._execute_with_escalation(task, classification, start_tier, task_id)

        # Post-execute hooks
        for hook in self._post_execute_hooks:
            try:
                hook(output, classification)
            except Exception:
                pass

        # Store in history
        with self._lock:
            self._history.append({
                "task_id":        task_id,
                "model_id":       output.model_id,
                "tier":           output.tier.name,
                "confidence":     output.confidence,
                "cost_usd":       output.cost_usd,
                "escalated_from": output.escalated_from,
                "category":       classification.category,
                "complexity":     classification.complexity.name,
                "timestamp":      time.time(),
            })

        return output

    def _execute_with_escalation(self, task: Dict[str, Any],
                                  classification: TaskClassification,
                                  start_tier: ModelTier,
                                  task_id: str) -> ModelOutput:
        """
        Try start_tier → check confidence → escalate if needed.
        Returns the best output obtained.
        """
        current_tier   = start_tier
        escalated_from = None
        best_output    = None

        while current_tier <= ModelTier.PREMIUM:
            model_cfg = self._select_model(classification, current_tier)

            if model_cfg is None:
                log.warning("No model available for tier %s — escalating", current_tier.name)
                current_tier = ModelTier(current_tier + 1)
                continue

            output = self._call_with_retry(task, classification, model_cfg, task_id,
                                            escalated_from=escalated_from)

            if output is None:
                # All retries failed — try next tier
                current_tier = ModelTier(current_tier + 1)
                continue

            # Score confidence
            output.confidence = self._confidence.score(output, classification)
            best_output = output

            log.debug("Task %s: model=%s confidence=%.3f tier=%s",
                      task_id, model_cfg.model_id, output.confidence, current_tier.name)

            # Escalation thresholds
            if current_tier == ModelTier.FAST:
                threshold = self._policy.fast_to_standard_threshold
            elif current_tier == ModelTier.STANDARD:
                threshold = self._policy.standard_to_premium_threshold
            else:
                break  # PREMIUM — no further escalation

            if output.confidence >= threshold:
                break  # Good enough — stop here

            # Need to escalate
            reason = (f"confidence {output.confidence:.3f} < threshold {threshold:.3f} "
                      f"for tier {current_tier.name}")
            log.info("Escalating task %s: %s", task_id, reason)
            escalated_from = model_cfg.model_id
            output.escalation_reason = reason
            current_tier = ModelTier(current_tier + 1)

        if best_output is None:
            # Complete failure — return a structured error output
            best_output = ModelOutput(
                output_id=str(uuid.uuid4())[:12],
                task_id=task_id,
                model_id="none",
                tier=start_tier,
                content="",
                confidence=0.0,
                input_tokens=0,
                output_tokens=0,
                cost_usd=0.0,
                duration_ms=0.0,
                escalated_from=escalated_from,
                escalation_reason="all_models_failed",
                retries=0,
                metadata={"error": "No model could complete this task"},
            )

        return best_output

    def _call_with_retry(self, task: Dict[str, Any],
                          classification: TaskClassification,
                          model_cfg: ModelConfig,
                          task_id: str,
                          escalated_from: Optional[str] = None) -> Optional[ModelOutput]:
        """
        Call a specific model with exponential backoff retry.
        Returns None if all retries exhausted.
        """
        system  = _build_system_prompt(classification, model_cfg.tier)
        prompt  = _build_prompt(task, classification)
        temp    = self._policy.temperature_by_tier.get(model_cfg.tier.name, 0.3)
        backend = _BACKENDS.get(model_cfg.provider)

        if backend is None:
            log.error("No backend registered for provider '%s'", model_cfg.provider)
            return None

        for attempt in range(self._policy.max_retries_same_model + 1):
            if attempt > 0:
                wait = self._policy.retry_backoff_base_s * (2 ** (attempt - 1))
                log.debug("Retry %d for %s, waiting %.1fs", attempt, model_cfg.model_id, wait)
                time.sleep(wait)

            try:
                t0 = time.monotonic()
                content, in_tok, out_tok = backend.call(
                    model_id=model_cfg.model_id,
                    system=system,
                    prompt=prompt,
                    temperature=temp,
                    max_tokens=min(4096, model_cfg.max_context_tokens // 4),
                )
                duration_ms = (time.monotonic() - t0) * 1000
                cost_usd    = model_cfg.cost_estimate(in_tok, out_tok)

                # Record usage
                self._budget.record(
                    model_id=model_cfg.model_id,
                    provider=model_cfg.provider,
                    task_id=task_id,
                    task_category=classification.category,
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    cost_usd=cost_usd,
                    duration_ms=duration_ms,
                    escalation=(escalated_from is not None),
                )

                return ModelOutput(
                    output_id=str(uuid.uuid4())[:12],
                    task_id=task_id,
                    model_id=model_cfg.model_id,
                    tier=model_cfg.tier,
                    content=content,
                    confidence=0.0,  # filled in by caller
                    input_tokens=in_tok,
                    output_tokens=out_tok,
                    cost_usd=cost_usd,
                    duration_ms=duration_ms,
                    escalated_from=escalated_from,
                    escalation_reason="",
                    retries=attempt,
                )

            except BudgetExhaustedError as e:
                log.warning("Budget exhausted for %s: %s", model_cfg.model_id, e)
                return None

            except Exception as e:
                # Classify the error
                err_str = str(e).lower()
                if "429" in err_str or "rate limit" in err_str:
                    log.warning("Rate limit on %s (attempt %d)", model_cfg.model_id, attempt)
                    continue  # retry
                elif "401" in err_str or "403" in err_str or "api key" in err_str:
                    log.error("Auth error for %s: %s", model_cfg.model_id, e)
                    return None  # no point retrying
                elif "timeout" in err_str or "connection" in err_str:
                    log.warning("Network error on %s: %s (attempt %d)",
                                model_cfg.model_id, e, attempt)
                    continue  # retry
                else:
                    log.error("Unexpected error from %s: %s", model_cfg.model_id, e)
                    return None

        return None

    # ── Integration points ────────────────────────────────────────────────────

    def execute_for_brain(self, action) -> Optional[ModelOutput]:
        """
        Called by AttackGraphBrain / EventDrivenEngine when the brain
        needs AI analysis for a high-priority node action.
        """
        task = {
            "description":    action.reasoning,
            "agent_type":     action.agent_type,
            "node_type":      action.node_type,
            "node_label":     action.node_label,
            "target":         action.target,
            "graph_priority": action.priority,
            "context":        action.context or {},
        }
        try:
            return self.execute(task, task_id=f"brain:{action.action_id}")
        except Exception as e:
            log.warning("Brain execution failed: %s", e)
            return None

    def execute_for_trigger(self, firing) -> Optional[ModelOutput]:
        """
        Called by GraphTriggerEngine when a trigger fires and needs
        AI-generated attack guidance.
        """
        task = {
            "description": (
                f"Trigger '{firing.trigger_name}' fired for node '{firing.node_label}'. "
                f"Agents to execute: {', '.join(firing.agents)}. "
                f"Generate specific attack guidance and payload recommendations."
            ),
            "agent_type": firing.agents[0] if firing.agents else "",
            "node_label": firing.node_label,
            "target":     firing.target,
            "importance": "high" if firing.priority >= 9.0 else "normal",
        }
        try:
            return self.execute(task, task_id=f"trigger:{firing.trigger_name[:20]}")
        except Exception as e:
            log.warning("Trigger execution failed: %s", e)
            return None

    def execute_for_daemon(self, worker_name: str, event: dict) -> Optional[ModelOutput]:
        """
        Called by IntelligenceDaemon workers when they need AI reasoning
        (e.g., HypothesisWorker, ExploitChainWorker).
        """
        event_type = event.get("event_type", "")
        data       = event.get("data", {})
        task = {
            "description": (
                f"Daemon worker '{worker_name}' received event '{event_type}'. "
                f"Target: {data.get('target', 'unknown')}. "
                f"Data: {json.dumps(data, default=str)[:500]}"
            ),
            "agent_type": worker_name.replace("Worker", "").lower(),
            "severity":   data.get("severity", ""),
            "target":     data.get("target", ""),
            "importance": "critical" if event_type in
                          ("NEW_VULNERABILITY", "CHAIN_DETECTED") else "normal",
        }
        try:
            return self.execute(task, task_id=f"daemon:{worker_name[:20]}")
        except Exception as e:
            log.warning("Daemon execution failed: %s", e)
            return None

    # ── Hooks ─────────────────────────────────────────────────────────────────

    def add_pre_hook(self, fn: Callable) -> None:
        """fn(task: dict, task_id: str) called before each execution."""
        self._pre_execute_hooks.append(fn)

    def add_post_hook(self, fn: Callable) -> None:
        """fn(output: ModelOutput, classification: TaskClassification) called after."""
        self._post_execute_hooks.append(fn)

    # ── Query / status ────────────────────────────────────────────────────────

    def list_models(self, enabled_only: bool = False) -> List[dict]:
        with self._lock:
            models = list(self._models.values())
        if enabled_only:
            models = [m for m in models if m.enabled]
        return [m.to_dict() for m in models]

    def recent_executions(self, limit: int = 20) -> List[dict]:
        with self._lock:
            items = list(self._history)
        items.reverse()
        return items[:limit]

    def status(self) -> dict:
        self._ensure_loaded()
        budget_status = self._budget.status()
        with self._lock:
            model_count = len(self._models)
            enabled     = sum(1 for m in self._models.values() if m.enabled)
        return {
            "loaded":         self._loaded,
            "models_total":   model_count,
            "models_enabled": enabled,
            "budget":         budget_status,
            "recent_executions": len(self._history),
            "policy": {
                "fast_to_standard_threshold":    self._policy.fast_to_standard_threshold,
                "standard_to_premium_threshold": self._policy.standard_to_premium_threshold,
                "max_retries":                   self._policy.max_retries_same_model,
            },
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

_orchestrator: Optional[ModelOrchestrator] = None
_orch_lock = threading.Lock()


def get_orchestrator() -> ModelOrchestrator:
    global _orchestrator
    if _orchestrator is None:
        with _orch_lock:
            if _orchestrator is None:
                _orchestrator = ModelOrchestrator()
                _orchestrator.load_config()
    return _orchestrator
