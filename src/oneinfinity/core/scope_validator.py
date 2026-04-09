"""
Scope Validator — authorization and scope guardrails.

Prevents accidental out-of-scope testing by validating every
target URL/domain/IP against declared scope rules before any
active probe is sent.

Usage:
    sv = ScopeValidator()
    sv.add_in_scope("*.acme.com")
    sv.add_in_scope("acme.com")
    sv.add_out_of_scope("admin.acme.com")  # explicit exclude

    sv.check("api.acme.com")   # → True (in scope)
    sv.check("admin.acme.com") # → False (out of scope)
    sv.check("evil.com")       # → False (not in scope list)
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# Domains that are ALWAYS out of scope regardless of user config
_ALWAYS_OOS = [
    "localhost",
    "127.*",
    "::1",
    "0.0.0.0",
    "169.254.*",        # link-local
    "10.*",             # RFC-1918
    "172.16.*",         # RFC-1918
    "192.168.*",        # RFC-1918
    "*.internal",
    "*.local",
    "*.corp",
    "*.example.com",
    "*.test",
]


@dataclass
class ScopeRule:
    pattern: str
    is_wildcard: bool
    is_cidr: bool
    _cidr_net: Optional[ipaddress.IPv4Network] = field(default=None, repr=False)

    @classmethod
    def from_pattern(cls, pattern: str) -> "ScopeRule":
        pattern = pattern.strip().lower()
        # Check CIDR
        try:
            net = ipaddress.IPv4Network(pattern, strict=False)
            return cls(pattern=pattern, is_wildcard=False, is_cidr=True, _cidr_net=net)
        except ValueError:
            pass
        is_wc = "*" in pattern or "?" in pattern
        return cls(pattern=pattern, is_wildcard=is_wc, is_cidr=False)

    def matches(self, value: str) -> bool:
        value = value.lower().strip()
        if self.is_cidr and self._cidr_net:
            try:
                return ipaddress.IPv4Address(value) in self._cidr_net
            except ValueError:
                return False
        if self.is_wildcard:
            return fnmatch.fnmatch(value, self.pattern)
        return value == self.pattern or value.endswith("." + self.pattern)


class ScopeValidator:
    """
    Validates targets against a declared scope.

    Modes:
      strict  — must be explicitly in-scope AND not out-of-scope
      relaxed — pass unless explicitly out-of-scope
    """

    def __init__(self, mode: str = "strict") -> None:
        if mode not in ("strict", "relaxed"):
            raise ValueError("mode must be 'strict' or 'relaxed'")
        self._mode = mode
        self._in_scope: List[ScopeRule] = []
        self._out_of_scope: List[ScopeRule] = [
            ScopeRule.from_pattern(p) for p in _ALWAYS_OOS
        ]
        self._audit_log: List[dict] = []
        self._require_auth: bool = False
        self._auth_confirmed: bool = False

    # ------------------------------------------------------------------ #
    #  Configuration
    # ------------------------------------------------------------------ #

    def add_in_scope(self, pattern: str) -> None:
        self._in_scope.append(ScopeRule.from_pattern(pattern))
        log.debug("In-scope: %s", pattern)

    def add_out_of_scope(self, pattern: str) -> None:
        self._out_of_scope.append(ScopeRule.from_pattern(pattern))
        log.debug("Out-of-scope: %s", pattern)

    def set_mode(self, mode: str) -> None:
        if mode not in ("strict", "relaxed"):
            raise ValueError("mode must be 'strict' or 'relaxed'")
        self._mode = mode

    def require_authorization(self, confirmed: bool = False) -> None:
        """
        When require_authorization=True, all active probes must be
        gated behind explicit user confirmation.
        """
        self._require_auth = True
        self._auth_confirmed = confirmed

    def confirm_authorization(self) -> None:
        self._auth_confirmed = True
        log.info("[scope] Authorization confirmed by user")

    # ------------------------------------------------------------------ #
    #  Validation
    # ------------------------------------------------------------------ #

    def check(self, target: str) -> bool:
        """
        Returns True if target is in scope and authorized.
        Logs every check to the audit trail.
        """
        host = self._extract_host(target)
        if not host:
            self._audit("INVALID", target, "could not extract host")
            return False

        # Always out-of-scope check first
        for rule in self._out_of_scope:
            if rule.matches(host):
                self._audit("OOS", target, f"matches OOS rule: {rule.pattern}")
                return False

        # In-scope check
        in_scope = False
        if not self._in_scope:
            # No scope defined — pass in relaxed, block in strict
            in_scope = self._mode == "relaxed"
        else:
            for rule in self._in_scope:
                if rule.matches(host):
                    in_scope = True
                    break

        if not in_scope:
            self._audit("OOS", target, "not in declared scope")
            return False

        # Authorization gate
        if self._require_auth and not self._auth_confirmed:
            self._audit("UNAUTH", target, "authorization not confirmed")
            return False

        self._audit("OK", target, "")
        return True

    def check_url(self, url: str) -> bool:
        return self.check(url)

    def assert_in_scope(self, target: str) -> None:
        """Raise ScopeViolationError if target is out of scope."""
        if not self.check(target):
            raise ScopeViolationError(f"Target out of scope: {target}")

    def filter_in_scope(self, targets: List[str]) -> List[str]:
        """Return only the in-scope targets from a list."""
        return [t for t in targets if self.check(t)]

    # ------------------------------------------------------------------ #
    #  Audit log
    # ------------------------------------------------------------------ #

    def _audit(self, verdict: str, target: str, reason: str) -> None:
        entry = {"verdict": verdict, "target": target, "reason": reason}
        self._audit_log.append(entry)
        if verdict != "OK":
            log.warning("[scope] %s — %s: %s", verdict, target, reason)

    def audit_log(self) -> List[dict]:
        return list(self._audit_log)

    def oos_violations(self) -> List[dict]:
        return [e for e in self._audit_log if e["verdict"] == "OOS"]

    # ------------------------------------------------------------------ #
    #  Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_host(target: str) -> Optional[str]:
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            host = parsed.hostname
        elif "/" in target:
            host = target.split("/")[0]
        else:
            host = target
        # Strip port
        if host and ":" in host:
            host = host.rsplit(":", 1)[0]
        return host or None

    def summary(self) -> str:
        lines = [
            f"Scope Validator — mode={self._mode}",
            f"  In-scope rules  : {len(self._in_scope)}",
            f"  Out-of-scope    : {len(self._out_of_scope)}",
            f"  Auth required   : {self._require_auth}",
            f"  Auth confirmed  : {self._auth_confirmed}",
            f"  Audit entries   : {len(self._audit_log)}",
        ]
        return "\n".join(lines)


class ScopeViolationError(Exception):
    """Raised when a target is accessed outside declared scope."""
