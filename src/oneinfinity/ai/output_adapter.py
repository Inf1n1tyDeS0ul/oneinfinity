"""
output_adapter.py — Bypass strategies for encoding/extracting LLM output.

Seven strategies are provided; each transforms a plain-text payload string
into an alternative representation that may pass content filters or exfiltrate
data through side channels.
"""

from __future__ import annotations

import codecs
from typing import Dict

_STRATEGIES = (
    "numeric",
    "base256",
    "hex_concat",
    "rot13",
    "unicode_escape",
    "split_concat",
    "error_leak",
)


class OutputAdapter:
    """Transform a payload string with one of seven bypass encoding strategies.

    Usage::

        adapter = OutputAdapter()
        encoded = adapter.adapt("hello", "rot13")  # "uryyb"
        all_forms = adapter.adapt_all("hello")     # dict with all 7 keys
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def adapt(self, payload: str, strategy: str) -> str:
        """Apply *strategy* to *payload* and return the encoded string.

        Raises:
            ValueError: if *strategy* is not one of the seven known names.
        """
        handler = getattr(self, f"_strategy_{strategy}", None)
        if handler is None:
            raise ValueError(
                f"Unknown strategy {strategy!r}. "
                f"Valid choices: {', '.join(_STRATEGIES)}"
            )
        return handler(payload)

    def adapt_all(self, payload: str) -> Dict[str, str]:
        """Return a dict mapping every strategy name to its encoded form."""
        return {s: self.adapt(payload, s) for s in _STRATEGIES}

    # ------------------------------------------------------------------
    # Strategy implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _strategy_numeric(s: str) -> str:
        """Convert each character to its ordinal value; return as a list repr."""
        return str([ord(c) for c in s])

    @staticmethod
    def _strategy_base256(s: str) -> str:
        """Encode as a bytes constructor call: ``bytes([...])``."""
        return f"bytes({[ord(c) for c in s]})"

    @staticmethod
    def _strategy_hex_concat(s: str) -> str:
        """Concatenate hex representations: ``'0x68' + '0x65' + ...``."""
        return "".join(hex(ord(c)) for c in s)

    @staticmethod
    def _strategy_rot13(s: str) -> str:
        """Apply ROT-13 substitution cipher."""
        return codecs.encode(s, "rot_13")

    @staticmethod
    def _strategy_unicode_escape(s: str) -> str:
        """Encode using Python unicode-escape (ASCII-safe)."""
        return s.encode("unicode_escape").decode()

    @staticmethod
    def _strategy_split_concat(s: str) -> str:
        """Split every 3 characters and show as a Python string concatenation."""
        chunks = [s[i : i + 3] for i in range(0, len(s), 3)]
        return "+".join(repr(c) for c in chunks) if chunks else repr(s)

    @staticmethod
    def _strategy_error_leak(s: str) -> str:
        """Embed payload in a fake error message string."""
        return f'ValueError: unexpected token near "{s}" at offset 0'
