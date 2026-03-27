"""
core/stealth_engine.py — Stealth & Evasion Layer (Phase 6)

Provides stealth-aware HTTP sessions for all active scanning:
  - User-Agent rotation (real browser fingerprints, no tool branding)
  - Randomised request headers (Accept-Language, Accept-Encoding, Referer)
  - Proxy pool support (ONEINFINITY_PROXIES env var, comma-separated)
  - Ban detection: HTTP 429, CAPTCHA pages, WAF blocks, Cloudflare challenges
  - Adaptive delay: exponential back-off with jitter on ban detection
  - No "OneInfinity-*" strings in outbound headers

Thread-safe: all public helpers and StealthSession are safe for concurrent use.
"""
from __future__ import annotations

import logging
import os
import random
import threading
import time
from typing import List, Optional, Tuple

log = logging.getLogger("oneinfinity.core.stealth")

# ---------------------------------------------------------------------------
# Real browser User-Agent strings (Chrome / Firefox / Safari / Edge)
# ---------------------------------------------------------------------------

_USER_AGENTS: List[str] = [
    # Chrome — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.129 Safari/537.36",
    # Chrome — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome — Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox — Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    # Edge — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Mobile — Android Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # Mobile — iOS Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]

_ACCEPT_LANGUAGES: List[str] = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.8,fr;q=0.6",
    "en-US,en;q=0.9,de;q=0.8",
    "en-CA,en;q=0.9",
    "en-AU,en;q=0.9,en-GB;q=0.8",
]

_ACCEPT_ENCODINGS: List[str] = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, deflate, br, zstd",
    "br, gzip, deflate",
]

_ACCEPT_HEADERS: List[str] = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

# ---------------------------------------------------------------------------
# Ban-detection patterns
# ---------------------------------------------------------------------------

_BAN_STATUS_CODES = frozenset({429, 403, 503})

_BAN_BODY_KEYWORDS = frozenset({
    "captcha", "cf-challenge", "ray id", "attention required",
    "please wait", "ddos protection", "bot detected", "access denied",
    "rate limit exceeded", "too many requests", "blocked", "forbidden",
    "security check", "i'm under attack", "just a moment", "challenge",
    "incapsula", "sucuri", "f5 big-ip", "barracuda",
})

# ---------------------------------------------------------------------------
# Proxy pool
# ---------------------------------------------------------------------------


def _load_proxy_pool() -> List[str]:
    """
    Load proxy list from ONEINFINITY_PROXIES environment variable.
    Format: comma-separated proxy URLs, e.g.:
        http://user:pass@proxy1:8080,http://proxy2:8080
    Returns empty list if not set.
    """
    raw = os.environ.get("ONEINFINITY_PROXIES", "").strip()
    if not raw:
        return []
    proxies = [p.strip() for p in raw.split(",") if p.strip()]
    log.debug("[stealth] Proxy pool: %d proxies loaded", len(proxies))
    return proxies


_PROXY_POOL: List[str] = _load_proxy_pool()


def _random_proxy() -> Optional[dict]:
    """Return a random proxy dict for requests, or None if pool is empty."""
    if not _PROXY_POOL:
        return None
    p = random.choice(_PROXY_POOL)
    return {"http": p, "https": p}


# ---------------------------------------------------------------------------
# Header builder
# ---------------------------------------------------------------------------


def build_stealth_headers(extra: Optional[dict] = None) -> dict:
    """
    Build a randomised, realistic browser-like header set.
    Excludes all OneInfinity branding.
    """
    headers = {
        "User-Agent":      random.choice(_USER_AGENTS),
        "Accept":          random.choice(_ACCEPT_HEADERS),
        "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
        "Accept-Encoding": random.choice(_ACCEPT_ENCODINGS),
        "Connection":      "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    # Occasionally add DNT header (real browsers do this ~30% of the time)
    if random.random() < 0.3:
        headers["DNT"] = "1"
    # Occasionally add Sec-Fetch headers (modern browsers)
    if random.random() < 0.6:
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "none"
    if extra:
        headers.update(extra)
    return headers


# ---------------------------------------------------------------------------
# Ban detection
# ---------------------------------------------------------------------------


def is_banned(resp) -> Tuple[bool, str]:
    """
    Detect if an HTTP response indicates banning or rate-limiting.

    Returns (is_banned: bool, reason: str).
    """
    if resp is None:
        return False, ""

    # Status code check
    code = getattr(resp, "status_code", 0)
    if code == 429:
        return True, f"HTTP 429 Too Many Requests"
    if code == 503:
        body_sample = (getattr(resp, "text", "") or "")[:500].lower()
        if any(kw in body_sample for kw in ("ddos", "captcha", "cloudflare", "challenge")):
            return True, f"HTTP 503 with WAF challenge"

    # Body keyword check (only on 2xx/4xx to avoid false positives)
    if code in (200, 403):
        body_lower = (getattr(resp, "text", "") or "")[:2000].lower()
        for kw in _BAN_BODY_KEYWORDS:
            if kw in body_lower:
                return True, f"Ban keyword detected: '{kw}'"

    return False, ""


# ---------------------------------------------------------------------------
# Adaptive delay
# ---------------------------------------------------------------------------


class AdaptiveDelay:
    """
    Tracks consecutive ban detections and applies exponential back-off.

    Usage::
        delay = AdaptiveDelay(base_s=0.5, max_s=60.0)
        delay.record_ban()    # call when ban detected
        delay.wait()          # blocks for current delay; resets on success
        delay.record_success()
    """

    def __init__(self, base_s: float = 0.5, max_s: float = 60.0, jitter: float = 0.3) -> None:
        self._base = base_s
        self._max = max_s
        self._jitter = jitter
        self._consecutive_bans = 0
        self._lock = threading.Lock()

    def record_ban(self) -> None:
        with self._lock:
            self._consecutive_bans += 1
            delay = min(self._base * (2 ** self._consecutive_bans), self._max)
            log.warning("[stealth] Ban detected (#%d). Back-off: %.1fs", self._consecutive_bans, delay)

    def record_success(self) -> None:
        with self._lock:
            if self._consecutive_bans > 0:
                self._consecutive_bans = max(0, self._consecutive_bans - 1)

    def current_delay(self) -> float:
        with self._lock:
            if self._consecutive_bans == 0:
                return 0.0
            base_delay = min(self._base * (2 ** self._consecutive_bans), self._max)
            jitter_amt = base_delay * self._jitter * random.random()
            return base_delay + jitter_amt

    def wait(self) -> None:
        d = self.current_delay()
        if d > 0:
            log.debug("[stealth] Adaptive delay: %.2fs", d)
            time.sleep(d)

    @property
    def is_backing_off(self) -> bool:
        return self._consecutive_bans > 0


# ---------------------------------------------------------------------------
# Stealth Session wrapper
# ---------------------------------------------------------------------------


class StealthSession:
    """
    A requests.Session wrapper that applies stealth headers, proxy rotation,
    ban detection, and adaptive back-off to every request.

    Usage::
        session = StealthSession()
        resp = session.get("https://example.com/search?q=test")
        if resp and resp.status_code == 200:
            ...
    """

    def __init__(
        self,
        timeout_s: float = 10.0,
        rotate_ua: bool = True,
        use_proxies: bool = True,
        base_delay_s: float = 0.3,
        max_delay_s: float = 90.0,
    ) -> None:
        self._timeout = timeout_s
        self._rotate_ua = rotate_ua
        self._use_proxies = use_proxies
        self._delay = AdaptiveDelay(base_s=base_delay_s, max_s=max_delay_s)
        self._session = None
        self._lock = threading.Lock()

    def _get_session(self):
        if self._session is None:
            try:
                import requests
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                s = requests.Session()
                # No branding headers set at session level; set per-request
                s.max_redirects = 3
                self._session = s
            except ImportError:
                return None
        return self._session

    def _prepare_request_kwargs(self, kwargs: dict) -> dict:
        """Inject stealth headers and proxy into request kwargs."""
        # Merge stealth headers (caller's headers take priority)
        caller_headers = dict(kwargs.pop("headers", {}) or {})
        stealth_headers = build_stealth_headers()
        merged = {**stealth_headers, **caller_headers}
        kwargs["headers"] = merged

        # Proxy rotation
        if self._use_proxies:
            proxy = _random_proxy()
            if proxy and "proxies" not in kwargs:
                kwargs["proxies"] = proxy

        # Defaults
        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)
        return kwargs

    def get(self, url: str, **kwargs) -> Optional[object]:
        """Stealth GET — applies headers, proxy, ban detection, back-off."""
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[object]:
        """Stealth POST."""
        return self._request("POST", url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[object]:
        s = self._get_session()
        if s is None:
            return None

        self._delay.wait()
        kwargs = self._prepare_request_kwargs(kwargs)

        try:
            resp = s.request(method, url, **kwargs)
            banned, reason = is_banned(resp)
            if banned:
                self._delay.record_ban()
                log.warning("[stealth] %s %s → BANNED: %s", method, url[:80], reason)
            else:
                self._delay.record_success()
            return resp
        except Exception as exc:
            log.debug("[stealth] %s %s failed: %s", method, url[:80], exc)
            return None

    @property
    def backing_off(self) -> bool:
        return self._delay.is_backing_off

    def stats(self) -> dict:
        return {
            "consecutive_bans": self._delay._consecutive_bans,
            "current_delay_s": round(self._delay.current_delay(), 2),
        }


# ---------------------------------------------------------------------------
# Fix 3 — Behavior-based stealth additions
# ---------------------------------------------------------------------------

# Endpoints where real users naturally slow down — double delay here
_SENSITIVE_ENDPOINT_KEYWORDS = frozenset({
    "login", "signin", "auth", "oauth", "sso", "password", "reset",
    "admin", "panel", "dashboard", "payment", "checkout", "billing",
    "2fa", "mfa", "verify", "confirm", "transfer", "withdraw",
})

# Typical navigation inter-request delays (seconds) to mimic human pacing
_NAV_DELAYS: List[Tuple[float, float]] = [
    (0.4, 1.2),   # quick click
    (1.0, 2.5),   # reading a page
    (0.2, 0.6),   # fast programmatic
]


def is_sensitive_endpoint(url: str) -> bool:
    """Return True if the URL path contains a sensitive keyword."""
    url_lower = url.lower()
    return any(kw in url_lower for kw in _SENSITIVE_ENDPOINT_KEYWORDS)


def human_delay(url: str = "", sensitive_multiplier: float = 2.0) -> None:
    """
    Inject a human-like delay before a request.
    Sensitive endpoints get longer delays to avoid triggering bot-detection
    on login/payment flows where rapid-fire requests are abnormal.
    """
    lo, hi = random.choice(_NAV_DELAYS)
    delay = random.uniform(lo, hi)
    if url and is_sensitive_endpoint(url):
        delay *= sensitive_multiplier
    if delay > 0.05:
        log.debug("[stealth] Human delay: %.2fs (%s)",
                  delay, "sensitive" if is_sensitive_endpoint(url) else "normal")
        time.sleep(delay)


class AdaptiveRateLimiter:
    """
    Tracks per-host error rate and reduces request rate when 403/429 are
    repeatedly returned — mimics a careful human backing off.

    Usage::
        limiter = AdaptiveRateLimiter()
        limiter.record(host, status_code)
        limiter.wait(host)   # blocks if host is throttled
    """

    def __init__(
        self,
        window_s: float = 60.0,
        max_errors: int = 5,
        base_backoff_s: float = 2.0,
    ) -> None:
        self._window = window_s
        self._max_errors = max_errors
        self._base_backoff = base_backoff_s
        self._error_log: Dict[str, List[float]] = {}   # host → [timestamps]
        self._lock = threading.Lock()

    def record(self, host: str, status_code: int) -> None:
        if status_code in (403, 429, 503):
            with self._lock:
                now = time.time()
                events = [t for t in self._error_log.get(host, []) if now - t < self._window]
                events.append(now)
                self._error_log[host] = events
                if len(events) >= self._max_errors:
                    log.warning("[stealth/rate] Host %s: %d errors in %.0fs — throttling",
                                host, len(events), self._window)

    def wait(self, host: str) -> None:
        with self._lock:
            now = time.time()
            events = [t for t in self._error_log.get(host, []) if now - t < self._window]
            self._error_log[host] = events
            error_count = len(events)

        if error_count >= self._max_errors:
            # Exponential back-off proportional to error count
            backoff = min(self._base_backoff * (1.5 ** (error_count - self._max_errors)), 30.0)
            log.debug("[stealth/rate] Host %s throttled — waiting %.1fs", host, backoff)
            time.sleep(backoff)
        elif error_count > 0:
            # Small jitter even for low error counts
            time.sleep(random.uniform(0.1, 0.5))


# Module-level rate limiter shared across sessions
_rate_limiter = AdaptiveRateLimiter()


class BrowserSession(StealthSession):
    """
    Enhanced StealthSession that mimics a real browser session:
      - Persists cookies across requests (like a real logged-in user)
      - Applies human-like delays (sensitive endpoint detection)
      - Uses per-host adaptive rate limiting
      - Rotates User-Agent only on new "navigation" (not every request)

    Inherits all ban-detection and proxy-rotation from StealthSession.
    """

    def __init__(
        self,
        timeout_s: float = 12.0,
        use_proxies: bool = True,
        human_pacing: bool = True,
        persist_cookies: bool = True,
    ) -> None:
        super().__init__(timeout_s=timeout_s, use_proxies=use_proxies)
        self._human_pacing   = human_pacing
        self._persist_cookies = persist_cookies
        self._request_count  = 0
        self._ua_rotation_interval = random.randint(8, 20)  # rotate UA every N requests
        self._current_ua: Optional[str] = None

    def _get_current_ua(self) -> str:
        """Rotate UA every N requests (not every request, which is suspicious)."""
        if (self._current_ua is None
                or self._request_count % self._ua_rotation_interval == 0):
            self._current_ua = random.choice(_USER_AGENTS)
            log.debug("[browser] UA rotated (req#%d)", self._request_count)
        return self._current_ua

    def _prepare_request_kwargs(self, kwargs: dict) -> dict:
        """Override to use persistent UA and cookie jar."""
        caller_headers = dict(kwargs.pop("headers", {}) or {})
        stealth_headers = build_stealth_headers()
        # Override UA with session-persistent one
        stealth_headers["User-Agent"] = self._get_current_ua()
        merged = {**stealth_headers, **caller_headers}
        kwargs["headers"] = merged

        # Proxy rotation
        if self._use_proxies:
            proxy = _random_proxy()
            if proxy and "proxies" not in kwargs:
                kwargs["proxies"] = proxy

        kwargs.setdefault("timeout", self._timeout)
        kwargs.setdefault("verify", False)

        # Cookie persistence: allow_redirects=True mimics browser behaviour
        if self._persist_cookies:
            kwargs.setdefault("allow_redirects", True)
        else:
            kwargs.setdefault("allow_redirects", False)

        return kwargs

    def _request(self, method: str, url: str, **kwargs) -> Optional[object]:
        self._request_count += 1

        # Human-like pacing
        if self._human_pacing:
            human_delay(url)

        # Per-host rate limiting
        try:
            from urllib.parse import urlparse as _up
            host = _up(url).hostname or url.split("/")[2].split(":")[0]
        except Exception:
            host = url[:30]

        _rate_limiter.wait(host)

        s = self._get_session()
        if s is None:
            return None

        self._delay.wait()
        kwargs = self._prepare_request_kwargs(kwargs)

        try:
            # Use the underlying requests.Session to preserve cookie jar
            resp = s.request(method, url, **kwargs)

            banned, reason = is_banned(resp)
            if banned:
                self._delay.record_ban()
                _rate_limiter.record(host, resp.status_code)
                log.warning("[browser] %s %s → BANNED: %s", method, url[:80], reason)
            else:
                self._delay.record_success()
                _rate_limiter.record(host, resp.status_code)

            return resp
        except Exception as exc:
            log.debug("[browser] %s %s failed: %s", method, url[:80], exc)
            return None

    def get_session_cookies(self) -> dict:
        """Return current cookie jar as dict (persisted across requests)."""
        s = self._get_session()  # raw requests.Session
        if s and hasattr(s, "cookies"):
            return dict(s.cookies)
        return {}


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_stealth_session_instance: Optional[StealthSession] = None
_stealth_lock = threading.Lock()


def get_stealth_session(
    timeout_s: float = 10.0,
    use_proxies: bool = True,
) -> StealthSession:
    """Return a module-level singleton StealthSession."""
    global _stealth_session_instance
    with _stealth_lock:
        if _stealth_session_instance is None:
            _stealth_session_instance = StealthSession(
                timeout_s=timeout_s,
                use_proxies=use_proxies,
            )
    return _stealth_session_instance


def new_stealth_session(timeout_s: float = 10.0, use_proxies: bool = True) -> StealthSession:
    """Create a fresh, independent StealthSession (e.g. per-worker use)."""
    return StealthSession(timeout_s=timeout_s, use_proxies=use_proxies)


def new_browser_session(
    timeout_s: float = 12.0,
    use_proxies: bool = True,
    human_pacing: bool = True,
) -> BrowserSession:
    """
    Create a BrowserSession with cookie persistence and human-like pacing.
    Use for auth flows and sensitive endpoint scanning.
    """
    return BrowserSession(
        timeout_s=timeout_s,
        use_proxies=use_proxies,
        human_pacing=human_pacing,
    )
