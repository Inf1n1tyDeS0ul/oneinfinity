"""
Centralized HTTP client for One&Infinity.
Provides session reuse, robust retries with exponential backoff, 
and safe request wrappers to handle connection/DNS issues.
"""

import time
import random
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any, Union

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 5
BACKOFF_FACTOR = 1.0
STATUS_FORCELIST = [429, 500, 502, 503, 504]
MAX_BACKOFF_SECONDS = 8.0


def _parse_retry_after_seconds(headers: Any) -> Optional[float]:
    try:
        if headers is None:
            return None
        getter = headers.get if hasattr(headers, "get") else None
        value = getter("Retry-After") if getter else None
        if value is None and getter:
            value = getter("retry-after")
        if value is None:
            return None
        seconds = float(value)
        if seconds < 0:
            return None
        return seconds
    except Exception:
        return None


def _backoff_seconds(attempt: int, retry_after_seconds: Optional[float] = None) -> float:
    if retry_after_seconds is not None:
        return min(float(retry_after_seconds), MAX_BACKOFF_SECONDS)
    base = BACKOFF_FACTOR * (2 ** max(0, attempt - 1))
    return min(base + random.uniform(0, 1), MAX_BACKOFF_SECONDS)

class OneInfinityHTTPClient:
    """
    Production-grade HTTP client with persistent session and retry logic.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(OneInfinityHTTPClient, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        if self._initialized:
            return
        
        self.timeout = timeout
        self.session = requests.Session()
        
        # Configure retry strategy for underlying transport
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=STATUS_FORCELIST,
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
            raise_on_status=False
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Standard headers
        self.session.headers.update({
            "User-Agent": "OneInfinity/1.0.0 (Autonomous Security Research Framework)",
            "Accept": "application/vnd.github.v3+json",
        })
        
        self._initialized = True
        logger.debug("OneInfinityHTTPClient initialized with persistent session.")

    def safe_request(
        self, 
        method: str, 
        url: str, 
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        handle_rate_limit: bool = True
    ) -> Optional[requests.Response]:
        """
        Execute a request safely with retries and exception handling.
        """
        req_timeout = timeout or self.timeout
        
        # Manual retry loop for network-level failures that HTTPAdapter might miss
        # or when we want explicit logging of retries.
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=headers,
                    json=json_data,
                    timeout=req_timeout
                )
                
                status_code = int(getattr(resp, "status_code", 0) or 0)

                # If we get a response, return it (even if 4xx/5xx, caller handles logic).
                if status_code >= 400:
                    logger.debug(f"[http] {method} {url} -> {status_code}")

                # Retry on transient upstream failures / throttling when transport-level
                # retries are bypassed (e.g., mocked sessions in tests).
                if status_code in STATUS_FORCELIST and attempt < MAX_RETRIES:
                    retry_after = _parse_retry_after_seconds(getattr(resp, "headers", None))
                    wait = _backoff_seconds(attempt, retry_after_seconds=retry_after if handle_rate_limit else None)
                    logger.warning(
                        f"[retry] attempt {attempt}/{MAX_RETRIES} for {url} after HTTP {status_code} (sleep={wait:.2f}s)"
                    )
                    time.sleep(wait)
                    continue

                return resp
                
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                logger.warning(f"[retry] attempt {attempt}/{MAX_RETRIES} for {url} after {type(e).__name__}")
                if attempt == MAX_RETRIES:
                    logger.error(f"[network] giving up on {url} after {MAX_RETRIES} attempts.")
                    return None
                
                # Exponential backoff for manual retries
                wait = _backoff_seconds(attempt)
                time.sleep(wait)
                
            except requests.exceptions.RequestException as e:
                logger.error(f"[network] unrecoverable error for {url}: {e}")
                return None
            
        return None

# Global helper for easy access
_client = None

def get_http_client() -> OneInfinityHTTPClient:
    global _client
    if _client is None:
        _client = OneInfinityHTTPClient()
    return _client

def safe_request(method: str, url: str, **kwargs) -> Optional[requests.Response]:
    """Global wrapper for safe requests."""
    return get_http_client().safe_request(method, url, **kwargs)
