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
