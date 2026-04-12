# src/oneinfinity/orchestration/backends/ollama.py
"""
orchestration/backends/ollama.py — Ollama local LLM backend.

Uses Ollama's OpenAI-compatible endpoint:
  POST {host}/v1/chat/completions

Environment:
  OLLAMA_HOST — override default http://localhost:11434 (global)

Per-model override: pass host= to call() or discover_models().
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from oneinfinity.orchestration.backends import BackendResult, BaseBackend, register_backend

log = logging.getLogger(__name__)

_DEFAULT_HOST = "http://localhost:11434"


def _get_host(per_model_host: Optional[str] = None) -> str:
    return (
        per_model_host
        or os.environ.get("OLLAMA_HOST", "").strip()
        or _DEFAULT_HOST
    ).rstrip("/")


def _infer_tier(name: str) -> str:
    """Heuristic tier assignment based on parameter count in model name."""
    lower = name.lower()
    is_reasoning = any(k in lower for k in ("deepseek-r1", "qwq", ":think"))

    if any(k in lower for k in ("70b", "72b", "65b", "671b")):
        tier = "PREMIUM"
    elif any(k in lower for k in ("27b", "32b", "34b", "13b", "14b")):
        tier = "STANDARD"
    else:
        tier = "FAST"

    if is_reasoning:
        if tier == "FAST":
            tier = "STANDARD"
        elif tier == "STANDARD":
            tier = "PREMIUM"

    return tier


@dataclass
class DiscoveredModel:
    name: str
    tier: str          # "FAST" | "STANDARD" | "PREMIUM"
    context_tokens: int = 8192


class OllamaBackend(BaseBackend):
    provider = "ollama"

    def __init__(self, host: Optional[str] = None, timeout: int = 60):
        self._host = host
        self._timeout = timeout

    def _effective_host(self, per_model_host: Optional[str] = None) -> str:
        return _get_host(per_model_host or self._host)

    def is_available(self, host: Optional[str] = None) -> bool:
        try:
            urllib.request.urlopen(self._effective_host(host) + "/", timeout=2)
            return True
        except Exception:
            return False

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
        host: Optional[str] = None,
    ) -> BackendResult:
        effective_host = self._effective_host(host)
        url = f"{effective_host}/v1/chat/completions"

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = json.dumps({
            "model": model_id,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }).encode()

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error=f"HTTP {e.code}: {body[:200]}",
            )
        except Exception as e:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error=str(e),
            )

        duration_ms = (time.monotonic() - t0) * 1000
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return BackendResult(
            content=content,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            duration_ms=duration_ms,
        )

    def discover_models(self, host: Optional[str] = None) -> list[DiscoveredModel]:
        """Query /api/tags and return discovered models with tier heuristics."""
        url = self._effective_host(host) + "/api/tags"
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            log.debug("Ollama discovery failed (%s): %s", url, e)
            return []

        results = []
        for model in data.get("models", []):
            name = model.get("name", "").strip()
            if not name:
                continue
            results.append(DiscoveredModel(
                name=name,
                tier=_infer_tier(name),
                context_tokens=8192,
            ))
        return results


# Register singleton at import time so orchestrator can find it by provider name
register_backend(OllamaBackend())
