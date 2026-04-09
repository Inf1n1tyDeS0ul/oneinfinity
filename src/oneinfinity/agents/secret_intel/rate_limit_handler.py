"""
RateLimitHandler — header-driven adaptive pacing for GitHub API requests.

Key insight: GitHub exposes *exactly* how many requests remain in the current
window and when that window resets.  Using that information we can compute the
ideal inter-request delay without blind sleeps.

Two resource buckets on GitHub:
  search   — 30 req/min authenticated, 10 unauthenticated
  core     — 5 000 req/hr authenticated, 60 unauthenticated

Secondary rate limits (undocumented but enforced):
  ~5 concurrent requests per second across any endpoint
  ~900 content requests per minute

This module never sleeps — it only computes how long callers *should* sleep.
"""

import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── GitHub API rate-limit constants ───────────────────────────────────────────
_SEARCH_LIMIT_PER_MIN   = 30      # authenticated search requests/minute
_SEARCH_SECONDARY_RPS   = 4       # safe upper bound requests/second (secondary RL)
_CORE_LIMIT_PER_HR      = 5000    # authenticated core requests/hour
_MIN_SEARCH_DELAY       = 1.0 / _SEARCH_SECONDARY_RPS   # 0.25 s
_MIN_CORE_DELAY         = 0.05    # 50 ms floor for core API


class RateLimitHandler:
    """
    Stateless helper — all methods are static.

    All *headers* arguments accept a dict-like mapping of HTTP response headers.
    All return values are floats in **seconds**.
    """

    # ── Primary: adaptive delay from quota headers ────────────────────────────

    @staticmethod
    def adaptive_search_delay(headers: dict) -> float:
        """
        Compute how long to wait after a GitHub *search* API response before
        firing the next search request.

        Algorithm:
          1. Parse remaining quota and reset epoch from response headers.
          2. Compute ideal pace = time_remaining / requests_remaining.
          3. Apply a 0.8 safety factor so we finish the quota a bit early.
          4. Clamp to [MIN_SEARCH_DELAY, 60s].

        When remaining is 0 returns seconds_until_reset + 1.
        """
        remaining = _parse_int(headers, "X-RateLimit-Remaining", default=30)
        reset_at  = _parse_float(headers, "X-RateLimit-Reset",    default=time.time() + 60)
        now       = time.time()
        window    = max(1.0, reset_at - now)

        if remaining <= 0:
            wait = window + 1.0
            logger.warning(
                "Search quota exhausted — must wait %.0fs for reset.", wait
            )
            return wait

        # Distribute remaining quota evenly over remaining window
        ideal_pace = window / remaining
        # Safety factor: aim to use quota 20% more slowly than strictly required
        paced      = ideal_pace * 0.8

        if remaining <= 5:
            # Critical — slow down significantly to avoid overshooting
            delay = max(_MIN_SEARCH_DELAY, min(paced, 10.0))
            logger.debug("Search RL: remaining=%d (critical) → delay=%.2fs", remaining, delay)
        elif remaining <= 15:
            delay = max(_MIN_SEARCH_DELAY, min(paced, 4.0))
            logger.debug("Search RL: remaining=%d (low) → delay=%.2fs", remaining, delay)
        else:
            # Plenty of quota — use secondary-RL minimum only
            delay = _MIN_SEARCH_DELAY
            logger.debug("Search RL: remaining=%d (healthy) → delay=%.2fs", remaining, delay)

        return delay

    @staticmethod
    def adaptive_core_delay(headers: dict) -> float:
        """
        Compute inter-request delay for GitHub *core* (non-search) endpoints.

        Core quota is generous (5 000/hr) so most of the time we return the
        minimum floor.  We only back off meaningfully when remaining < 200.
        """
        remaining = _parse_int(headers, "X-RateLimit-Remaining", default=1000)
        reset_at  = _parse_float(headers, "X-RateLimit-Reset",    default=time.time() + 3600)
        now       = time.time()
        window    = max(1.0, reset_at - now)

        if remaining <= 0:
            wait = window + 1.0
            logger.warning("Core quota exhausted — must wait %.0fs.", wait)
            return wait

        if remaining < 200:
            ideal_pace = window / remaining
            delay      = max(_MIN_CORE_DELAY, min(ideal_pace * 0.8, 5.0))
            logger.debug("Core RL: remaining=%d → delay=%.2fs", remaining, delay)
            return delay

        return _MIN_CORE_DELAY

    # ── Retry timing ──────────────────────────────────────────────────────────

    @staticmethod
    def retry_after(
        headers: dict,
        status_code: int,
        attempt: int,
        base_backoff: float = 1.0,
    ) -> float:
        """
        Return how long to wait before the *next* retry attempt.

        Priority:
          1. Explicit Retry-After header (most authoritative)
          2. Time until X-RateLimit-Reset if quota is 0
          3. Exponential backoff: base * 2^attempt + jitter ±0.5s
        """
        import random

        # 1. Explicit Retry-After
        retry_after_hdr = headers.get("Retry-After", "")
        if retry_after_hdr:
            try:
                explicit = float(retry_after_hdr)
                logger.debug("Retry-After header: %.0fs.", explicit)
                return explicit + 0.5
            except ValueError:
                pass

        # 2. Rate-limit reset (only when quota actually 0)
        if status_code in (403, 429):
            remaining = _parse_int(headers, "X-RateLimit-Remaining", default=1)
            if remaining == 0:
                reset_at = _parse_float(headers, "X-RateLimit-Reset", default=time.time() + 60)
                wait     = max(1.0, reset_at - time.time()) + 1.0
                logger.debug("Quota=0 → sleep until reset: %.0fs.", wait)
                return wait

        # 3. Exponential backoff
        _BACKOFF_CAPS = [1, 2, 4, 8, 16, 30]
        cap   = _BACKOFF_CAPS[min(attempt, len(_BACKOFF_CAPS) - 1)]
        sleep = base_backoff * (2 ** attempt) + random.uniform(-0.5, 0.5)
        sleep = max(0.5, min(sleep, float(cap)))
        logger.debug("Backoff attempt %d → %.1fs.", attempt, sleep)
        return sleep

    # ── Rotation hint ─────────────────────────────────────────────────────────

    @staticmethod
    def should_rotate(headers: dict, threshold: int = 5) -> bool:
        """
        Return True if the active token's remaining quota is at or below
        *threshold* — caller should try to rotate before the next request.
        """
        remaining = _parse_int(headers, "X-RateLimit-Remaining", default=999)
        return remaining <= threshold

    # ── Quota summary for logging ─────────────────────────────────────────────

    @staticmethod
    def quota_summary(headers: dict) -> str:
        """One-line quota summary string suitable for debug logging."""
        remaining = _parse_int(headers, "X-RateLimit-Remaining", default=-1)
        limit     = _parse_int(headers, "X-RateLimit-Limit",     default=-1)
        reset_at  = _parse_float(headers, "X-RateLimit-Reset",   default=0.0)
        resets_in = max(0, int(reset_at - time.time()))
        return f"quota={remaining}/{limit} resets_in={resets_in}s"


# ── Module-level helpers ──────────────────────────────────────────────────────

def _parse_int(headers: dict, key: str, default: int) -> int:
    try:
        return int(headers.get(key, default))
    except (TypeError, ValueError):
        return default


def _parse_float(headers: dict, key: str, default: float) -> float:
    try:
        return float(headers.get(key, default))
    except (TypeError, ValueError):
        return default
