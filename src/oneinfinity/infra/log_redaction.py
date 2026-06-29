"""log_redaction.py — Prevent raw payload/credential strings from appearing in logs."""

from __future__ import annotations
import re
import logging

# Patterns that look like sensitive payloads or credentials
_REDACT_PATTERNS = [
    re.compile(r"<script[\s\S]*?>[\s\S]*?</script>", re.IGNORECASE),
    re.compile(r"(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"(?:payload|raw)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
    # JWT tokens (eyJ...)
    re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
    # Authorization / Cookie headers in log lines
    re.compile(r'(?i)Authorization\s*:\s*\S+'),
    re.compile(r'(?i)Cookie\s*:\s*.+'),
    # AWS STS / session tokens
    re.compile(r'(?i)X-Amz-Security-Token\s*[:=]\s*\S+'),
    # API key / token / secret in URL query params
    re.compile(r'(?i)[?&](?:api_key|token|secret|key)=([^&\s]+)'),
]

_REDACTED = "[REDACTED]"


def redact(value: str) -> str:
    """Return value with sensitive patterns replaced by [REDACTED]."""
    if not isinstance(value, str):
        return value
    for pat in _REDACT_PATTERNS:
        value = pat.sub(_REDACTED, value)
    return value


def safe_log(logger: logging.Logger, level: int, msg: str, *args: object) -> None:
    """Log msg at level, redacting any args that look like payloads."""
    safe_args = tuple(redact(str(a)) if isinstance(a, str) else a for a in args)
    logger.log(level, msg, *safe_args)
