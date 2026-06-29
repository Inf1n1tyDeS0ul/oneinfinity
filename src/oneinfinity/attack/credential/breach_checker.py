"""breach_checker.py — HIBP k-anonymity SHA1 prefix lookup (no API key required)."""
from __future__ import annotations

import hashlib
import logging
import time
import urllib.request
from typing import Dict, List, Tuple

log = logging.getLogger("oneinfinity.credential.breach_checker")

HIBP_API = "https://api.pwnedpasswords.com/range/"


class HIBPChecker:
    """
    Check passwords against HaveIBeenPwned using k-anonymity (SHA1 prefix).
    Sends only first 5 chars of SHA1 — the plaintext password never leaves the machine.
    No API key required.
    """

    def __init__(self, rate_limit_ms: int = 200):
        self.rate_limit_ms = rate_limit_ms
        self._cache: Dict[str, int] = {}  # sha1_prefix → {suffix: count}

    def breach_count(self, password: str) -> int:
        """Return number of times password appeared in known breaches (0 = not found)."""
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        if prefix in self._cache:
            return self._cache.get(sha1, 0)

        try:
            req = urllib.request.Request(
                f"{HIBP_API}{prefix}",
                headers={"Add-Padding": "true", "User-Agent": "OneInfinity/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8")
            for line in body.splitlines():
                if ":" in line:
                    s, count = line.split(":", 1)
                    key = prefix + s.strip()
                    self._cache[key] = int(count.strip())
            time.sleep(self.rate_limit_ms / 1000)
        except Exception as exc:
            log.debug("HIBP check failed for prefix %s: %s", prefix, exc)
            return 0

        return self._cache.get(sha1, 0)

    def is_pwned(self, password: str) -> bool:
        """Return True if password has appeared in known breaches."""
        return self.breach_count(password) > 0

    def rank_by_breach_count(self, passwords: List[str]) -> List[Tuple[str, int]]:
        """
        Return passwords sorted by breach frequency (most common first).
        High breach count = password is very common = spray it first.
        """
        ranked = []
        for pw in passwords:
            count = self.breach_count(pw)
            ranked.append((pw, count))
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def filter_pwned(self, passwords: List[str]) -> List[str]:
        """Return only passwords that have appeared in known breaches."""
        return [pw for pw in passwords if self.is_pwned(pw)]
