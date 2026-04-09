"""
GitHubSearchClient — refactored for resilience, session reuse, and adaptive rate limiting.

Now uses centralized core.http_client for persistent sessions and robust retries.
"""

import base64
import logging
import threading
import time
import random
from collections import OrderedDict
from typing import Any, Dict, List, Optional

import requests
from oneinfinity.core.http_client import safe_request
from oneinfinity.agents.secret_intel.token_manager import TokenManager
from oneinfinity.agents.secret_intel.rate_limit_handler import RateLimitHandler

logger = logging.getLogger(__name__)

# ── Tunables ──────────────────────────────────────────────────────────────────
_MAX_CONCURRENT     = 4      # global semaphore: total in-flight requests
_CACHE_MAXSIZE      = 500    # LRU file-content cache entries
_SEARCH_TIMEOUT     = 20     # seconds per search request
_FETCH_TIMEOUT      = 15     # seconds per file-fetch request
_DEFAULT_BASE_DELAY = 3.0    # base delay between requests for throttling


# ── LRU content cache ─────────────────────────────────────────────────────────

class LRUContentCache:
    """Thread-safe LRU cache for file content."""
    def __init__(self, maxsize: int = _CACHE_MAXSIZE):
        self._store:   OrderedDict = OrderedDict()
        self._lock     = threading.Lock()
        self._maxsize  = maxsize
        self._hits     = 0
        self._misses   = 0

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                self._hits += 1
                return self._store[key]
            self._misses += 1
            return None

    def put(self, key: str, value: str) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = value
            if len(self._store) > self._maxsize:
                self._store.popitem(last=False)

    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            total = self._hits + self._misses
            hit_rate = round(self._hits / total * 100, 1) if total else 0
            return {
                "size":      len(self._store),
                "hits":      self._hits,
                "misses":    self._misses,
                "hit_rate%": hit_rate,
            }


# ── Client ────────────────────────────────────────────────────────────────────

class GitHubSearchClient:
    """
    GitHub REST API client — refactored for resilience and session reuse.
    """

    def __init__(
        self,
        token:  Optional[str]       = None,
        tokens: Optional[List[str]] = None,
        cache:  Optional[LRUContentCache] = None,
        max_requests: int = 5000,
        delay: float = _DEFAULT_BASE_DELAY,
        debug_rate_limit: bool = False,
        adaptive_throttle: bool = True
    ):
        explicit = tokens or ([token] if token else None)
        self.token_mgr = TokenManager.from_env(extra_tokens=explicit)
        self.rl        = RateLimitHandler()
        self.cache     = cache or LRUContentCache()
        self.base_url  = "https://api.github.com"
        
        self.max_requests = max_requests
        self.request_count = 0
        self.base_delay = delay
        self.debug_rate_limit = debug_rate_limit
        self.adaptive_throttle = adaptive_throttle

        # Global concurrency cap
        self._sem = threading.Semaphore(_MAX_CONCURRENT)
        
        if self.debug_rate_limit:
            logger.info("[github] client initialized (resilient session + adaptive throttling)")

    def _headers(self, token: Optional[str]) -> Dict[str, str]:
        h = {}
        if token:
            h["Authorization"] = f"token {token}"
        return h

    def _apply_throttle(self):
        """Global request pacing with jitter."""
        jitter = random.uniform(0, 1.0)
        sleep_time = self.base_delay + jitter
        logger.debug(f"[throttle] sleeping {sleep_time:.2f}s (base={self.base_delay}s)")
        time.sleep(sleep_time)

    def _request_with_retry(
        self,
        method:  str,
        url:     str,
        params:  Optional[dict] = None,
        timeout: int = _SEARCH_TIMEOUT,
    ) -> Optional[requests.Response]:
        """
        Refactored request loop with session reuse and adaptive rate limiting.
        """
        # 1. Budget Check
        if self.request_count >= self.max_requests:
            logger.warning(f"[budget] limit ({self.max_requests}) reached.")
            return None

        # 2. Throttling
        self._apply_throttle()

        for attempt in range(5):  # Max 5 internal retry attempts for rotation
            # 3. Token Selection
            token = self.token_mgr.best_token()
            if token is None:
                wait = self.token_mgr.min_wait_seconds()
                logger.warning(f"[rate-limit] all tokens exhausted. sleeping {wait:.0f}s")
                time.sleep(wait)
                continue

            with self._sem:
                resp = safe_request(
                    method, url,
                    params=params,
                    headers=self._headers(token),
                    timeout=timeout
                )

            if resp is None:
                # safe_request already handled ConnectionError/Timeout and retried 5 times
                return None

            self.request_count += 1

            # 4. Quota Tracking
            self.token_mgr.record_response(token, resp.headers, resp.status_code)

            if resp.status_code == 200:
                if self.debug_rate_limit:
                    logger.info(f"[rate-limit] {url[:60]} | {self.rl.quota_summary(resp.headers)}")
                return resp

            # 5. Handle Rate Limits (403/429)
            if resp.status_code in (403, 429):
                # Check for Retry-After
                sleep_for = self.rl.retry_after(resp.headers, resp.status_code, attempt)
                
                # Check if we can rotate tokens
                new_token = self.token_mgr.best_token()
                if new_token and new_token != token:
                    logger.info(f"[token] rotating on HTTP {resp.status_code}")
                    continue
                
                logger.warning(f"[rate-limit] hit on HTTP {resp.status_code}. sleeping {sleep_for:.1f}s")
                time.sleep(sleep_for)
                continue

            # 6. Other errors
            if resp.status_code in (422, 404):
                return None
            
            # For 5xx, safe_request already retried. If we are here, it still failed.
            if resp.status_code >= 500:
                return None

        return None

    def search_code(self, query: str, per_page: int = 100) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        page = 1
        while True:
            logger.debug(f"Search: page={page} query='{query[:60]}'")
            resp = self._request_with_retry(
                "GET",
                f"{self.base_url}/search/code",
                params={"q": query, "per_page": per_page, "page": page},
                timeout=_SEARCH_TIMEOUT,
            )

            if resp is None: break

            items = resp.json().get("items", [])
            results.extend(items)
            if len(items) < per_page or len(results) >= 1000: break

            page += 1
            if self.adaptive_throttle:
                delay = self.rl.adaptive_search_delay(resp.headers)
                logger.debug(f"[adaptive] search inter-page delay: {delay:.2f}s")
                time.sleep(delay)

        return results

    def get_file_content(self, url: str) -> Optional[str]:
        cached = self.cache.get(url)
        if cached is not None: return cached

        resp = self._request_with_retry("GET", url, timeout=_FETCH_TIMEOUT)
        if resp is None: return None

        try:
            data = resp.json()
            if data.get("encoding") == "base64" and "content" in data:
                content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                self.cache.put(url, content)
                return content
        except Exception as e:
            logger.warning(f"[decode] failed for {url[:80]}: {e}")

        return None

    def status(self) -> Dict[str, Any]:
        return {
            "token_pool": self.token_mgr.status(),
            "cache":      self.cache.stats,
            "requests":   self.request_count
        }
