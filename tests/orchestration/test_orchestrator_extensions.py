# tests/orchestration/test_orchestrator_extensions.py
"""Tests for new orchestrator extensions: Ollama routing, CLI fallback, discovery."""
import os
from unittest.mock import patch, MagicMock

import pytest


def _make_orchestrator():
    """Return a fresh ModelOrchestrator with no models loaded."""
    from oneinfinity.orchestration.model_orchestrator import ModelOrchestrator
    orch = ModelOrchestrator.__new__(ModelOrchestrator)
    import threading, collections
    orch._models = {}
    orch._lock = threading.Lock()
    orch._history = collections.deque(maxlen=500)
    orch._loaded = False
    from oneinfinity.infra.model_budget_manager import get_budget_manager
    orch._budget = get_budget_manager()
    from oneinfinity.orchestration.model_orchestrator import RoutingPolicy
    orch._policy = RoutingPolicy()
    return orch


# ── ModelConfig.fallback_provider field ──────────────────────────────────────

def test_modelconfig_has_fallback_provider_field():
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.0001,
        cost_per_1k_output=0.0004, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )
    assert cfg.fallback_provider is None   # default


def test_modelconfig_fallback_provider_can_be_set():
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.0001,
        cost_per_1k_output=0.0004, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
        fallback_provider="codex",
    )
    assert cfg.fallback_provider == "codex"


# ── Ollama provider routing ───────────────────────────────────────────────────

def test_call_with_retry_routes_ollama_to_ollama_backend():
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    from oneinfinity.orchestration.backends import get_backend, register_backend
    from oneinfinity.orchestration.backends import BackendResult
    from oneinfinity.orchestration.backends.ollama import OllamaBackend
    # Re-register in case clean_backends_registry fixture wiped it
    if get_backend("ollama") is None:
        register_backend(OllamaBackend())

    cfg = ModelConfig(
        model_id="llama3.2:3b", provider="ollama",
        tier=ModelTier.FAST, cost_per_1k_input=0.0,
        cost_per_1k_output=0.0, max_context_tokens=8192,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )

    mock_result = BackendResult(content="ollama response", input_tokens=10, output_tokens=5, duration_ms=100.0)
    orch = _make_orchestrator()

    with patch.object(get_backend("ollama"), "call", return_value=mock_result) as mock_call:
        from oneinfinity.orchestration.model_orchestrator import TaskClassification, TaskCategory, ComplexityLevel, ImportanceLevel
        classification = TaskClassification(
            category=TaskCategory.GENERAL, complexity=ComplexityLevel.LOW,
            importance=ImportanceLevel.NORMAL, latency_class="INTERACTIVE",
            estimated_tokens=100, reasoning_depth=1, tags=[], classifier_confidence=0.8,
        )
        output = orch._call_with_retry({}, classification, cfg, "test-task-id")

    assert mock_call.called
    assert output is not None
    assert output.content == "ollama response"


# ── _auto_discover_ollama ─────────────────────────────────────────────────────

def test_auto_discover_ollama_registers_new_models():
    from oneinfinity.orchestration.backends.ollama import DiscoveredModel
    orch = _make_orchestrator()

    discovered = [
        DiscoveredModel(name="llama3.2:3b",  tier="FAST",    context_tokens=8192),
        DiscoveredModel(name="llama3.1:70b", tier="PREMIUM", context_tokens=131072),
    ]

    with patch("oneinfinity.orchestration.backends.ollama.OllamaBackend.discover_models",
               return_value=discovered):
        orch._auto_discover_ollama(ollama_cfg={})

    assert "llama3.2:3b"  in orch._models
    assert "llama3.1:70b" in orch._models
    assert orch._models["llama3.2:3b"].provider  == "ollama"
    assert orch._models["llama3.1:70b"].tier.name == "PREMIUM"


def test_auto_discover_ollama_yaml_entry_wins():
    """models.yaml explicit entry is not overwritten by auto-discovery."""
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    from oneinfinity.orchestration.backends.ollama import DiscoveredModel
    orch = _make_orchestrator()

    # Pre-register explicit YAML entry for llama3.2:3b as STANDARD
    orch._models["llama3.2:3b"] = ModelConfig(
        model_id="llama3.2:3b", provider="ollama", tier=ModelTier.STANDARD,
        cost_per_1k_input=0.0, cost_per_1k_output=0.0, max_context_tokens=131072,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )

    discovered = [DiscoveredModel(name="llama3.2:3b", tier="FAST", context_tokens=8192)]
    with patch("oneinfinity.orchestration.backends.ollama.OllamaBackend.discover_models",
               return_value=discovered):
        orch._auto_discover_ollama(ollama_cfg={})

    # YAML entry tier (STANDARD) must be preserved
    assert orch._models["llama3.2:3b"].tier == ModelTier.STANDARD


def test_auto_discover_ollama_skipped_when_disabled():
    orch = _make_orchestrator()
    with patch("oneinfinity.orchestration.backends.ollama.OllamaBackend.discover_models") as mock_disc:
        orch._auto_discover_ollama(ollama_cfg={"auto_discover": False})
    mock_disc.assert_not_called()


# ── _register_cli_models ──────────────────────────────────────────────────────

def test_register_cli_models_enables_codex_when_binary_found():
    orch = _make_orchestrator()
    with patch("shutil.which", side_effect=lambda x: "/bin/codex" if x == "codex" else None):
        orch._register_cli_models(cli_cfg={"enabled": True, "codex_model": "o4-mini", "claude_model": "claude-opus-4-6", "max_budget_usd": 0.10})
    assert "codex-cli" in orch._models
    assert orch._models["codex-cli"].enabled is True


def test_register_cli_models_enables_claude_when_binary_found():
    orch = _make_orchestrator()
    with patch("shutil.which", side_effect=lambda x: "/bin/claude" if x == "claude" else None):
        orch._register_cli_models(cli_cfg={"enabled": True, "codex_model": "o4-mini", "claude_model": "claude-opus-4-6", "max_budget_usd": 0.10})
    assert "claude-cli" in orch._models
    assert orch._models["claude-cli"].enabled is True


def test_register_cli_models_skips_when_binary_missing():
    orch = _make_orchestrator()
    with patch("shutil.which", return_value=None):
        orch._register_cli_models(cli_cfg={"enabled": True, "codex_model": "o4-mini", "claude_model": "claude-opus-4-6", "max_budget_usd": 0.10})
    assert "codex-cli" not in orch._models
    assert "claude-cli" not in orch._models


# ── _assign_cli_fallbacks ─────────────────────────────────────────────────────

def test_assign_cli_fallbacks_sets_codex_when_no_openai_key(monkeypatch):
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    orch = _make_orchestrator()
    orch._models["gpt-4o-mini"] = ModelConfig(
        model_id="gpt-4o-mini", provider="openai", tier=ModelTier.FAST,
        cost_per_1k_input=0.00015, cost_per_1k_output=0.0006,
        max_context_tokens=128000, latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )
    with patch("shutil.which", side_effect=lambda x: "/bin/codex" if x == "codex" else None):
        orch._assign_cli_fallbacks(cli_cfg={"enabled": True, "on_errors": ["auth", "quota"]})
    assert orch._models["gpt-4o-mini"].fallback_provider == "codex"


def test_assign_cli_fallbacks_sets_claude_when_no_anthropic_key(monkeypatch):
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    orch = _make_orchestrator()
    orch._models["claude-haiku-4-5"] = ModelConfig(
        model_id="claude-haiku-4-5", provider="anthropic", tier=ModelTier.FAST,
        cost_per_1k_input=0.0008, cost_per_1k_output=0.004,
        max_context_tokens=200000, latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )
    with patch("shutil.which", side_effect=lambda x: "/bin/claude" if x == "claude" else None):
        orch._assign_cli_fallbacks(cli_cfg={"enabled": True, "on_errors": ["auth", "quota"]})
    assert orch._models["claude-haiku-4-5"].fallback_provider == "claude-cli"


def test_assign_cli_fallbacks_skips_when_disabled():
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier
    orch = _make_orchestrator()
    orch._models["gpt-4o-mini"] = ModelConfig(
        model_id="gpt-4o-mini", provider="openai", tier=ModelTier.FAST,
        cost_per_1k_input=0.00015, cost_per_1k_output=0.0006,
        max_context_tokens=128000, latency_class="INTERACTIVE", capabilities={"GENERAL"},
    )
    orch._assign_cli_fallbacks(cli_cfg={"enabled": False})
    assert orch._models["gpt-4o-mini"].fallback_provider is None


# ── CLI fallback in _call_with_retry ─────────────────────────────────────────

def test_cli_fallback_called_on_auth_error():
    """When API raises 401, fallback_provider CLI backend is tried."""
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier, TaskClassification, TaskCategory, ComplexityLevel, ImportanceLevel
    from oneinfinity.orchestration.backends import get_backend, register_backend
    from oneinfinity.orchestration.backends import BackendResult
    from oneinfinity.orchestration.backends.cli import CodexCliBackend

    if get_backend("codex") is None:
        register_backend(CodexCliBackend())

    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
        fallback_provider="codex",
    )

    classification = TaskClassification(
        category=TaskCategory.GENERAL, complexity=ComplexityLevel.LOW,
        importance=ImportanceLevel.NORMAL, latency_class="INTERACTIVE",
        estimated_tokens=100, reasoning_depth=1, tags=[], classifier_confidence=0.8,
    )

    orch = _make_orchestrator()
    codex_result = BackendResult(content="codex fallback response", input_tokens=10, output_tokens=5, duration_ms=200.0)

    # Patch OpenAI backend to raise 401, patch codex backend to succeed
    from oneinfinity.orchestration import model_orchestrator as _mo
    with patch.dict(_mo._BACKENDS, {"openai": MagicMock(call=MagicMock(side_effect=RuntimeError("401 Unauthorized")))}):
        with patch.object(get_backend("codex"), "is_available", return_value=True):
            with patch.object(get_backend("codex"), "call", return_value=codex_result) as mock_codex:
                output = orch._call_with_retry({}, classification, cfg, "task-fallback-test")

    assert mock_codex.called
    assert output is not None
    assert output.content == "codex fallback response"


def test_cli_fallback_not_triggered_on_rate_limit():
    """429 rate limit retries normally — does NOT trigger CLI fallback."""
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier, TaskClassification, TaskCategory, ComplexityLevel, ImportanceLevel
    from oneinfinity.orchestration.backends import get_backend, register_backend
    from oneinfinity.orchestration.backends.cli import CodexCliBackend

    if get_backend("codex") is None:
        register_backend(CodexCliBackend())

    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
        fallback_provider="codex",
    )
    classification = TaskClassification(
        category=TaskCategory.GENERAL, complexity=ComplexityLevel.LOW,
        importance=ImportanceLevel.NORMAL, latency_class="INTERACTIVE",
        estimated_tokens=100, reasoning_depth=1, tags=[], classifier_confidence=0.8,
    )

    orch = _make_orchestrator()
    orch._policy.max_retries_same_model = 0   # no retries

    from oneinfinity.orchestration import model_orchestrator as _mo
    with patch.dict(_mo._BACKENDS, {"openai": MagicMock(call=MagicMock(side_effect=RuntimeError("429 rate limit")))}):
        with patch.object(get_backend("codex"), "call") as mock_codex:
            orch._call_with_retry({}, classification, cfg, "task-ratelimit-test")

    mock_codex.assert_not_called()


def test_cli_fallback_not_triggered_when_unavailable():
    """If CLI binary not found, auth error returns None (escalates)."""
    from oneinfinity.orchestration.model_orchestrator import ModelConfig, ModelTier, TaskClassification, TaskCategory, ComplexityLevel, ImportanceLevel
    from oneinfinity.orchestration.backends import get_backend, register_backend
    from oneinfinity.orchestration.backends.cli import CodexCliBackend

    if get_backend("codex") is None:
        register_backend(CodexCliBackend())

    cfg = ModelConfig(
        model_id="gpt-4o-mini", provider="openai",
        tier=ModelTier.FAST, cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006, max_context_tokens=128000,
        latency_class="INTERACTIVE", capabilities={"GENERAL"},
        fallback_provider="codex",
    )
    classification = TaskClassification(
        category=TaskCategory.GENERAL, complexity=ComplexityLevel.LOW,
        importance=ImportanceLevel.NORMAL, latency_class="INTERACTIVE",
        estimated_tokens=100, reasoning_depth=1, tags=[], classifier_confidence=0.8,
    )

    orch = _make_orchestrator()
    from oneinfinity.orchestration import model_orchestrator as _mo
    with patch.dict(_mo._BACKENDS, {"openai": MagicMock(call=MagicMock(side_effect=RuntimeError("401 Unauthorized")))}):
        with patch.object(get_backend("codex"), "is_available", return_value=False):
            output = orch._call_with_retry({}, classification, cfg, "task-no-cli")

    assert output is None
