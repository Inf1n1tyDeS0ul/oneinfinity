# src/oneinfinity/orchestration/backends/cli.py
"""
orchestration/backends/cli.py — CLI-based AI backends.

CodexCliBackend  — OpenAI Codex CLI  (`codex exec`)
ClaudeCliBackend — Claude Code CLI   (`claude -p`)

Both record cost=0.0 locally; billed through user's own accounts.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Optional

from oneinfinity.orchestration.backends import BackendResult, BaseBackend, register_backend

log = logging.getLogger(__name__)


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token, minimum 1."""
    return max(1, len(text) // 4)


class CodexCliBackend(BaseBackend):
    """OpenAI Codex CLI backend. Uses `codex exec` for non-interactive execution."""

    provider = "codex"

    def __init__(self, model: str = "o4-mini"):
        self._model = model

    def is_available(self) -> bool:
        return shutil.which("codex") is not None

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        effective_model = model_id or self._model
        t0 = time.monotonic()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                [
                    "codex", "exec",
                    "-m", effective_model,
                    "--full-auto",
                    "--dangerously-bypass-approvals-and-sandbox",
                    "-o", tmp_path,
                    full_prompt,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            duration_ms = (time.monotonic() - t0) * 1000

            if result.returncode != 0:
                return BackendResult(
                    content="", input_tokens=0, output_tokens=0,
                    duration_ms=duration_ms,
                    error=f"codex exit {result.returncode}: {result.stderr[:300]}",
                )

            content = ""
            if os.path.exists(tmp_path):
                content = open(tmp_path).read().strip()
            if not content:
                content = result.stdout.strip()

        except subprocess.TimeoutExpired:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error="codex CLI timed out after 120s",
            )
        except FileNotFoundError:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error="codex binary not found",
            )
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        return BackendResult(
            content=content,
            input_tokens=_estimate_tokens(full_prompt),
            output_tokens=_estimate_tokens(content),
            duration_ms=duration_ms,
        )


class ClaudeCliBackend(BaseBackend):
    """Claude Code CLI backend. Uses `claude -p` for non-interactive execution."""

    provider = "claude-cli"

    def __init__(self, model: str = "claude-opus-4-6", max_budget_usd: float = 0.10):
        self._model = model
        self._max_budget = max_budget_usd

    def is_available(self) -> bool:
        return shutil.which("claude") is not None

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        effective_model = model_id or self._model
        t0 = time.monotonic()
        try:
            result = subprocess.run(
                [
                    "claude", "-p", full_prompt,
                    "--model", effective_model,
                    "--allowed-tools", "",
                    "--max-budget-usd", str(self._max_budget),
                    "--output-format", "text",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            duration_ms = (time.monotonic() - t0) * 1000

            if result.returncode != 0:
                return BackendResult(
                    content="", input_tokens=0, output_tokens=0,
                    duration_ms=duration_ms,
                    error=f"claude exit {result.returncode}: {result.stderr[:300]}",
                )

            content = result.stdout.strip()

        except subprocess.TimeoutExpired:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error="claude CLI timed out after 120s",
            )
        except FileNotFoundError:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=(time.monotonic() - t0) * 1000,
                error="claude binary not found",
            )

        return BackendResult(
            content=content,
            input_tokens=_estimate_tokens(full_prompt),
            output_tokens=_estimate_tokens(content),
            duration_ms=duration_ms,
        )


# Register singletons at import time
register_backend(CodexCliBackend())
register_backend(ClaudeCliBackend())
