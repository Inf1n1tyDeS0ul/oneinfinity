# src/oneinfinity/orchestration/backends/groq.py
"""
orchestration/backends/groq.py — Groq Cloud LLM backend.

Free-tier API with generous daily limits.
Sign up free at https://console.groq.com — no credit card required.

Environment:
  GROQ_API_KEY — required (set to any value to enable)
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Optional

from oneinfinity.orchestration.backends import BackendResult, BaseBackend, register_backend

log = logging.getLogger(__name__)

_BASE_URL = "https://api.groq.com/openai/v1/chat/completions"


class GroqBackend(BaseBackend):
    """
    Groq cloud backend via REST API (OpenAI-compatible).
    Free tier: LLaMA 3.3 70B, Mixtral 8x7B, Gemma2 9B.
    Rate limits apply but are generous for personal use.
    """

    provider = "groq"

    def __init__(self) -> None:
        self._api_key: str = os.environ.get("GROQ_API_KEY", "").strip()
        if self._api_key:
            log.info("[groq] GROQ_API_KEY set — Groq free-tier models available")
        else:
            log.debug("[groq] GROQ_API_KEY not set — Groq models unavailable; "
                      "sign up free at https://console.groq.com")

    def is_available(self) -> bool:
        return bool(self._api_key)

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        if not self._api_key:
            return BackendResult(
                content="",
                input_tokens=0,
                output_tokens=0,
                duration_ms=0.0,
                error="GROQ_API_KEY not set — sign up free at https://console.groq.com",
            )

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body = json.dumps({
            "model": model_id,
            "messages": messages,
            "max_tokens": min(max_tokens, 8192),
            "temperature": temperature,
        }).encode()

        t0 = time.monotonic()
        req = urllib.request.Request(
            _BASE_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode(errors="replace")
            duration_ms = (time.monotonic() - t0) * 1000
            return BackendResult(
                content="",
                input_tokens=0,
                output_tokens=0,
                duration_ms=duration_ms,
                error=f"Groq API error {exc.code}: {err_body[:300]}",
            )
        except Exception as exc:
            duration_ms = (time.monotonic() - t0) * 1000
            return BackendResult(
                content="",
                input_tokens=0,
                output_tokens=0,
                duration_ms=duration_ms,
                error=f"Groq request failed: {exc}",
            )

        duration_ms = (time.monotonic() - t0) * 1000
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        return BackendResult(
            content=content,
            input_tokens=usage.get("prompt_tokens", len(prompt) // 4),
            output_tokens=usage.get("completion_tokens", len(content) // 4),
            duration_ms=duration_ms,
        )


# Register on module import
register_backend(GroqBackend())
