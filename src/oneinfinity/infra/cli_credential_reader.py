"""
cli_credential_reader.py — Read AI CLI credentials for OneInfinity

Reads OAuth/auth tokens from installed AI CLI tools:
  - Claude Code CLI  (~/.claude/.credentials.json)  → Anthropic API (Bearer auth)
  - Gemini CLI       (~/.gemini/oauth_creds.json)   → Google Generative AI API (OAuth)
  - Codex CLI        (~/.codex/auth.json)            → OpenAI API (Bearer JWT)

These tokens let OneInfinity use AI features without separate API keys,
leveraging existing CLI subscriptions and quotas.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("cli_credential_reader")
_HOME = Path.home()


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _is_expired(ts_ms: Any, buffer_s: int = 120) -> bool:
    """Return True if the timestamp (milliseconds) is expired or within buffer_s seconds."""
    if not ts_ms:
        return False
    try:
        ts_s = float(ts_ms) / 1000 if float(ts_ms) > 1e10 else float(ts_ms)
        return ts_s < time.time() + buffer_s
    except (ValueError, TypeError):
        return False


def read_claude_code_token() -> Optional[str]:
    """
    Read Claude Code CLI OAuth access token.
    Token format: sk-ant-oat01-*
    Used with Anthropic API as: Authorization: Bearer <token>
    Returns token string or None if unavailable/expired.

    Credential file structure (one of two layouts):
      { "accessToken": "...", "expiresAt": 123... }          (flat)
      { "claudeAiOauth": { "accessToken": "...", ... } }     (nested)
    """
    path = _HOME / ".claude" / ".credentials.json"
    data = _load_json(path)
    if not data:
        return None

    # Support both flat and nested credential layouts
    oauth = data.get("claudeAiOauth") or data
    token = oauth.get("accessToken") or oauth.get("access_token")
    if not token:
        return None

    expires_at = oauth.get("expiresAt") or oauth.get("expires_at")
    if expires_at and _is_expired(expires_at):
        log.debug("Claude Code OAuth token is expired")
        return None

    sub = oauth.get("subscriptionType", "unknown")
    log.debug("Claude Code CLI token available (subscription: %s)", sub)
    return token


def read_gemini_token() -> Optional[str]:
    """
    Read Gemini CLI OAuth access token.
    Token format: ya29.*
    Used with Google AI API as: Authorization: Bearer <token>
    Returns token string or None if unavailable/expired.
    """
    path = _HOME / ".gemini" / "oauth_creds.json"
    data = _load_json(path)
    if not data:
        return None
    token = data.get("access_token") or data.get("token")
    if not token:
        return None
    # Google tokens expire quickly (~1h), check expiry field
    expiry = data.get("expiry") or data.get("token_expiry")
    if expiry and _is_expired(expiry):
        log.debug("Gemini CLI OAuth token is expired")
        return None
    log.debug("Gemini CLI token available")
    return token


def read_codex_token() -> Optional[str]:
    """
    Read Codex CLI OAuth access token (JWT Bearer token).
    Used with OpenAI API as: Authorization: Bearer <jwt>
    Returns token string or None if unavailable.
    Note: OpenAI's standard API may not accept OAuth JWTs — used as best-effort fallback.
    """
    path = _HOME / ".codex" / "auth.json"
    data = _load_json(path)
    if not data:
        return None
    token = (data.get("access_token")
             or data.get("accessToken")
             or (data.get("session") or {}).get("access_token"))
    if token:
        log.debug("Codex CLI token available")
    return token or None


def get_available_cli_providers() -> Dict[str, str]:
    """
    Returns {provider_key: token} for all available CLI credential stores.
    Keys: "anthropic_cli", "gemini_cli", "codex_cli"
    """
    available: Dict[str, str] = {}

    token = read_claude_code_token()
    if token:
        available["anthropic_cli"] = token
        log.info("[CLI auth] Claude Code Pro OAuth token detected")

    token = read_gemini_token()
    if token:
        available["gemini_cli"] = token
        log.info("[CLI auth] Gemini CLI OAuth token detected")

    token = read_codex_token()
    if token:
        available["codex_cli"] = token
        log.info("[CLI auth] Codex CLI JWT token detected")

    if not available:
        log.debug("[CLI auth] No CLI credentials found")

    return available
