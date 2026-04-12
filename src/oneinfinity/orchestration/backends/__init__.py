"""
orchestration/backends — Pluggable AI provider backend registry.

Provides:
  BaseBackend     — abstract base class all backends implement
  BackendResult   — unified result container
  register_backend / get_backend / list_backends — module-level registry
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class BackendResult:
    """Unified result from any backend call."""
    content: str
    input_tokens: int
    output_tokens: int
    duration_ms: float
    error: str = ""

    @property
    def failed(self) -> bool:
        return bool(self.error)


class BaseBackend(ABC):
    """Abstract base for all AI provider backends."""

    #: Provider identifier — matches ModelConfig.provider values
    provider: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this backend can be used right now."""
        ...

    @abstractmethod
    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        """Execute a prompt and return a BackendResult. Never raises — errors go in result.error."""
        ...


# ── Global registry ──────────────────────────────────────────────────────────

_BACKENDS: dict[str, "BaseBackend"] = {}


def register_backend(backend: BaseBackend) -> None:
    """Register a backend instance under its provider name. Idempotent."""
    if not backend.provider:
        raise ValueError(f"Backend {type(backend).__name__} has no provider string set")
    _BACKENDS[backend.provider] = backend
    log.debug("Backend registered: %s", backend.provider)


def get_backend(provider: str) -> Optional[BaseBackend]:
    """Return the registered backend for the given provider, or None."""
    return _BACKENDS.get(provider)


def list_backends() -> list[str]:
    """Return all registered provider names."""
    return list(_BACKENDS.keys())
