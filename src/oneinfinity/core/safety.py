"""
Safety Guard — prevents destructive actions and enforces rate limits.
"""
import logging
import re
import threading
from typing import List, Dict

logger = logging.getLogger(__name__)

DESTRUCTIVE_PATTERNS = [
    r"(?i)rm\s+-rf",
    r"(?i)drop\s+table",
    r"(?i)delete\s+from",
    r"(?i)truncate\s+",
    r"(?i)shutdown",
    r"(?i)reboot",
    r"(?i)format\s+",
    r"(?i)mkfs",
]

class SafetyGuard:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SafetyGuard, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if self._initialized: return
        self.safe_mode = True
        self.rate_limit_delay = 1.0
        self._compiled_destructive = [re.compile(p) for p in DESTRUCTIVE_PATTERNS]
        self._initialized = True

    def configure(self, safe_mode: bool = None, rate_limit: float = None):
        if safe_mode is not None:
            self.safe_mode = safe_mode
            logger.info(f"[SAFETY] Safe Mode set to: {self.safe_mode}")
        if rate_limit is not None:
            self.rate_limit_delay = rate_limit
            logger.info(f"[SAFETY] Rate limit delay set to: {self.rate_limit_delay}s")

    def is_safe_payload(self, payload: str) -> bool:
        if not self.safe_mode:
            return True
        for pattern in self._compiled_destructive:
            if pattern.search(payload):
                logger.warning(f"[SAFETY] Destructive payload blocked: {payload[:50]}...")
                return False
        return True

    def validate_action(self, action_type: str, target: str) -> bool:
        if self.safe_mode and action_type in ("delete", "destructive"):
            logger.warning(f"[SAFETY] Action {action_type} blocked for {target}")
            return False
        return True

    def get_config(self) -> Dict:
        return {
            "safe_mode": self.safe_mode,
            "rate_limit_delay": self.rate_limit_delay
        }

safety_guard = SafetyGuard()
