# src/oneinfinity/orchestration/backends/antigravity.py
"""
orchestration/backends/antigravity.py — Antigravity CLI backend.

Antigravity CLI (agy) is Google's terminal agent that replaced Gemini CLI.
It provides free access to Gemini 2.0 Flash and Gemini 2.5 Pro via Google
OAuth — no API key, no credit card, just a Google account.

Install (macOS / Linux):
    curl -fsSL https://antigravity.google/cli/install.sh | bash
    # or: brew install --cask antigravity-cli

First run (one-time auth):
    agy
    # Opens browser for Google Sign-In; creds cached in ~/.gemini/

Credentials are stored at ~/.gemini/antigravity-cli/ and never expire
unless you run `agy /logout`.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from oneinfinity.orchestration.backends import BackendResult, BaseBackend, register_backend

log = logging.getLogger(__name__)

# Map YAML model IDs → --model flag values accepted by agy.
# None means omit --model (uses agy's configured default, currently gemini-2.0-flash).
_MODEL_MAP: dict[str, Optional[str]] = {
    "gemini-2.0-flash":             None,
    "gemini-2.5-pro-preview-03-25": "gemini-2.5-pro",
}

_INSTALL_HINT = (
    "Antigravity CLI not installed.\n"
    "  Install:  curl -fsSL https://antigravity.google/cli/install.sh | bash\n"
    "  macOS:    brew install --cask antigravity-cli\n"
    "  Auth:     run `agy` once and sign in with your Google account (free)"
)

_AUTH_HINT = (
    "Antigravity CLI is installed but not authenticated.\n"
    "  Run `agy` and sign in with your Google account to enable free Gemini access."
)


def _agy_is_authenticated() -> bool:
    """
    Heuristic: check for an OAuth credential file written by `agy` on first login.
    The file is created at ~/.gemini/antigravity-cli/credentials.json or
    ~/.gemini/oauth_creds.json (Gemini CLI legacy path, still honoured by agy).
    Returns True when either path exists and is non-empty.
    """
    candidates = [
        Path.home() / ".gemini" / "antigravity-cli" / "credentials.json",
        Path.home() / ".gemini" / "oauth_creds.json",     # legacy Gemini CLI path
    ]
    return any(p.exists() and p.stat().st_size > 0 for p in candidates)


class AntigravityBackend(BaseBackend):
    """
    Antigravity CLI backend — free Gemini access via Google OAuth.
    Uses `agy -p <prompt> --yolo [--model <model>]` subprocess.
    --yolo disables interactive approval prompts for non-interactive use.
    """

    provider = "antigravity"

    def __init__(self) -> None:
        self._binary: Optional[str] = shutil.which("agy")
        self._authenticated: bool = False

        if self._binary:
            self._authenticated = _agy_is_authenticated()
            if self._authenticated:
                log.info("[antigravity] agy found + authenticated — free Gemini models available")
            else:
                log.warning(
                    "[antigravity] agy found but NOT authenticated. "
                    "Run `agy` once to sign in with your Google account."
                )
        else:
            log.debug("[antigravity] agy not found. %s", _INSTALL_HINT)

    def is_available(self) -> bool:
        # Re-probe binary and auth on each check (user may have just installed/logged in)
        self._binary = shutil.which("agy")
        self._authenticated = _agy_is_authenticated() if self._binary else False
        return bool(self._binary and self._authenticated)

    def call(
        self,
        model_id: str,
        prompt: str,
        system: str,
        temperature: float,
        max_tokens: int,
    ) -> BackendResult:
        if not self._binary:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0, duration_ms=0.0,
                error=_INSTALL_HINT,
            )
        if not _agy_is_authenticated():
            return BackendResult(
                content="", input_tokens=0, output_tokens=0, duration_ms=0.0,
                error=_AUTH_HINT,
            )

        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        cli_model = _MODEL_MAP.get(model_id, model_id)  # fall back to raw model_id

        # --yolo: skip all interactive tool-approval prompts
        cmd = [self._binary, "-p", full_prompt, "--yolo"]
        if cli_model:
            cmd.extend(["--model", cli_model])

        t0 = time.monotonic()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                env={**os.environ, "NO_COLOR": "1"},   # suppress ANSI in output
            )
        except subprocess.TimeoutExpired:
            duration_ms = (time.monotonic() - t0) * 1000
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=duration_ms,
                error="agy timed out after 120s",
            )
        except Exception as exc:
            duration_ms = (time.monotonic() - t0) * 1000
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=duration_ms,
                error=f"agy subprocess error: {exc}",
            )

        duration_ms = (time.monotonic() - t0) * 1000

        if result.returncode != 0:
            return BackendResult(
                content="", input_tokens=0, output_tokens=0,
                duration_ms=duration_ms,
                error=f"agy exited {result.returncode}: {result.stderr[:400]}",
            )

        content = result.stdout.strip()
        in_tok  = len(full_prompt) // 4
        out_tok = len(content) // 4
        return BackendResult(
            content=content,
            input_tokens=in_tok,
            output_tokens=out_tok,
            duration_ms=duration_ms,
        )


# Register on module import
register_backend(AntigravityBackend())
