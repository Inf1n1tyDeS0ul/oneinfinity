"""
TokenManager — dedicated, thread-safe GitHub token lifecycle manager.

Responsibilities:
  - Track per-token quota (remaining, reset_epoch, error_count, request_count)
  - Select the best available token on every request
  - Pre-emptively rotate before quota is exhausted (threshold: remaining <= 5)
  - Report minimum wait time when all tokens are exhausted
  - Expose a diagnostics snapshot for observability

Design invariants:
  - All state mutations are protected by a single RLock
  - Token strings are never logged in full (last-4 only)
  - No sleeps inside this class — callers decide whether/how long to wait
"""

import os
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

# Rotate away from a token once remaining falls to this level
_ROTATION_THRESHOLD = 5
# Consider a token's window expired if reset_epoch is in the past
_CLOCK_SKEW_BUFFER  = 2.0   # seconds


@dataclass
class TokenState:
    token:          str
    remaining:      int   = 30        # conservative default before first response
    limit:          int   = 30        # per-window limit (search API default)
    reset_epoch:    float = 0.0       # Unix timestamp when window resets
    total_requests: int   = 0
    error_count:    int   = 0
    last_used_at:   float = field(default_factory=time.time)

    # ── Derived properties ────────────────────────────────────────────────────

    def is_window_expired(self, now: Optional[float] = None) -> bool:
        """True if the rate-limit window has already reset."""
        return (now or time.time()) >= (self.reset_epoch + _CLOCK_SKEW_BUFFER)

    def effective_remaining(self, now: Optional[float] = None) -> int:
        """Remaining quota, treating an expired window as full."""
        if self.is_window_expired(now):
            return self.limit or 30
        return self.remaining

    def is_usable(self, threshold: int = _ROTATION_THRESHOLD) -> bool:
        return self.effective_remaining() > threshold

    def seconds_until_usable(self) -> float:
        """0.0 if already usable, otherwise seconds until window resets."""
        if self.is_usable():
            return 0.0
        wait = max(0.0, self.reset_epoch - time.time()) + _CLOCK_SKEW_BUFFER
        return wait

    @property
    def masked(self) -> str:
        """Last-4-chars preview for safe logging."""
        return f"...{self.token[-4:]}" if len(self.token) >= 4 else "????"


class TokenManager:
    """
    Central coordinator for a pool of GitHub API tokens.

    Usage:
        mgr = TokenManager.from_env()          # auto-loads GITHUB_TOKEN / GITHUB_TOKENS
        token = mgr.best_token()               # pick best token, or None if all exhausted
        mgr.record_response(token, resp.headers, resp.status_code)
        if mgr.all_exhausted():
            time.sleep(mgr.min_wait_seconds())
    """

    def __init__(self, tokens: List[str]):
        if not tokens:
            logger.warning(
                "TokenManager initialised with zero tokens — "
                "unauthenticated GitHub limits apply (60 req/hr)."
            )
        self._states: Dict[str, TokenState] = {
            t: TokenState(token=t) for t in tokens
        }
        self._lock  = threading.RLock()
        self._tokens: List[str] = list(tokens)   # ordered for round-robin fallback

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls, extra_tokens: Optional[List[str]] = None) -> "TokenManager":
        """
        Build a manager from environment variables.

        Resolution order:
          1. *extra_tokens* argument
          2. GITHUB_TOKENS=t1,t2,t3   (comma-separated)
          3. GITHUB_TOKEN=t1           (single token)
        """
        pool: List[str] = []
        if extra_tokens:
            pool = [t.strip() for t in extra_tokens if t.strip()]
        else:
            multi = os.environ.get("GITHUB_TOKENS", "")
            single = os.environ.get("GITHUB_TOKEN", "")
            if multi:
                pool = [t.strip() for t in multi.split(",") if t.strip()]
            elif single:
                pool = [single.strip()]

        logger.info("TokenManager: %d token(s) loaded.", len(pool))
        return cls(pool)

    # ── State updates ─────────────────────────────────────────────────────────

    def record_response(self, token: str, headers: dict, status_code: int) -> None:
        """
        Update token state from the HTTP response headers and status code.
        Called after every request, whether successful or not.
        """
        with self._lock:
            state = self._states.get(token)
            if state is None:
                return

            state.total_requests += 1
            state.last_used_at   = time.time()

            if "X-RateLimit-Remaining" in headers:
                state.remaining = int(headers["X-RateLimit-Remaining"])
            if "X-RateLimit-Reset" in headers:
                state.reset_epoch = float(headers["X-RateLimit-Reset"])
            if "X-RateLimit-Limit" in headers:
                state.limit = int(headers["X-RateLimit-Limit"])

            if status_code in (403, 429, 500, 503):
                state.error_count += 1

            if state.remaining <= _ROTATION_THRESHOLD:
                logger.debug(
                    "Token %s: remaining=%d — at rotation threshold.",
                    state.masked, state.remaining,
                )

    # ── Token selection ───────────────────────────────────────────────────────

    def best_token(self) -> Optional[str]:
        """
        Return the token with the highest effective remaining quota.

        Selection criteria (in order):
          1. Highest remaining quota among usable tokens (remaining > threshold)
          2. None if all tokens are exhausted

        Thread-safe; O(n) over the token pool.
        """
        if not self._tokens:
            return None

        with self._lock:
            now = time.time()
            best: Optional[TokenState] = None

            for t in self._tokens:
                state = self._states[t]
                eff   = state.effective_remaining(now)

                if eff <= _ROTATION_THRESHOLD:
                    continue   # exhausted

                if best is None or eff > best.effective_remaining(now):
                    best = state

            if best is None:
                # Last resort: check if any token is about to reset
                return None

            # Optional: Log if we are switching tokens
            # We don't store "current_token" statefully in the manager 
            # as it's intended to be stateless per-request selection.
            
            logger.debug(
                "[token] selected %s (quota=%d/%d, errors=%d)",
                best.masked, best.remaining, best.limit, best.error_count,
            )
            return best.token

    def all_exhausted(self) -> bool:
        """True if every token is at or below the rotation threshold."""
        with self._lock:
            return all(
                not self._states[t].is_usable()
                for t in self._tokens
            )

    def min_wait_seconds(self) -> float:
        """
        Minimum seconds to sleep before any token becomes usable again.
        Returns 0.0 if at least one token is already usable.
        """
        if not self._tokens:
            return 60.0
        with self._lock:
            waits = [self._states[t].seconds_until_usable() for t in self._tokens]
            return min(waits)

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        """Return a safe snapshot of all token states for observability."""
        with self._lock:
            now = time.time()
            return {
                "token_count":    len(self._tokens),
                "any_usable":     not self.all_exhausted(),
                "min_wait_s":     round(self.min_wait_seconds(), 1),
                "tokens": [
                    {
                        "masked":       self._states[t].masked,
                        "remaining":    self._states[t].remaining,
                        "limit":        self._states[t].limit,
                        "resets_in_s":  max(0, round(self._states[t].reset_epoch - now, 1)),
                        "total_req":    self._states[t].total_requests,
                        "errors":       self._states[t].error_count,
                        "usable":       self._states[t].is_usable(),
                    }
                    for t in self._tokens
                ],
            }
