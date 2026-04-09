"""
core/llm_cache.py — LLM Response Cache (Phase 5)

SHA256-keyed, TTL-aware cache for all LLM calls.
Persists to JSON on disk; loaded on first access.

Key design:
  - Normalises prompts before hashing (whitespace collapse)
  - Thread-safe with RLock
  - Atomic JSON writes (write to temp + rename)
  - Never raises — cache miss is always safe
  - Separate TTLs by task_type (response_analysis shorter than attack_plan)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Optional

log = logging.getLogger("oneinfinity.core.llm_cache")

# ---------------------------------------------------------------------------
# Task-type TTLs (seconds)
# ---------------------------------------------------------------------------

_DEFAULT_TTL: int = 3600          # 1 hour — attack plans
_TASK_TTL: Dict[str, int] = {
    "attack_plan_generation": 3600,   # 1 h  — stable for same target
    "response_analysis":       900,   # 15 m — tool outputs change
    "payload_suggestion":     1800,   # 30 m — WAF context changes
    "security_analysis":      3600,
}

_WHITESPACE_RE = re.compile(r"\s+")


def _normalise(text: str) -> str:
    """Collapse whitespace for stable hashing."""
    return _WHITESPACE_RE.sub(" ", text).strip()


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class LLMCache:
    """
    Thread-safe, persistent LLM response cache.

    Usage::

        cache = get_llm_cache()
        key = cache.make_key("gpt-4o-mini", "attack_plan_generation", prompt)
        cached = cache.get(key, task_type="attack_plan_generation")
        if cached:
            return cached
        response = call_llm(prompt)
        cache.set(key, response, task_type="attack_plan_generation")
    """

    def __init__(self, cache_path: Optional[Path] = None) -> None:
        if cache_path is None:
            _base = Path(os.environ.get("ONEINFINITY_DATA_DIR", "data"))
            _base.mkdir(parents=True, exist_ok=True)
            cache_path = _base / "llm_cache.json"
        self._path = cache_path
        self._lock = threading.RLock()
        self._cache: Dict[str, dict] = {}
        self._hits: int = 0
        self._misses: int = 0
        self._dirty: bool = False
        self._load()

    # ── Persistence ────────────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            if self._path.exists():
                with open(self._path) as f:
                    data = json.load(f)
                # Only load entries that haven't expired at max TTL
                cutoff = time.time() - max(_TASK_TTL.values(), default=_DEFAULT_TTL)
                self._cache = {
                    k: v for k, v in data.items()
                    if isinstance(v, dict) and v.get("timestamp", 0) > cutoff
                }
                log.info("[LLMCache] Loaded %d entries from %s", len(self._cache), self._path)
        except Exception as exc:
            log.debug("[LLMCache] Load failed (starting empty): %s", exc)
            self._cache = {}

    def _persist(self) -> None:
        """Atomic JSON write — temp file + rename."""
        try:
            tmp = self._path.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(self._cache, f, separators=(",", ":"))
            tmp.replace(self._path)
            self._dirty = False
        except Exception as exc:
            log.debug("[LLMCache] Persist failed: %s", exc)

    # ── Key generation ─────────────────────────────────────────────────────────

    def make_key(self, model: str, task_type: str, prompt: str) -> str:
        """SHA256 of model + task_type + normalised prompt."""
        raw = f"{model}:{task_type}:{_normalise(prompt)}"
        return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

    def make_prompt_hash(self, prompt: str) -> str:
        """Lightweight hash for prompt deduplication (no model/task prefix)."""
        return hashlib.sha256(_normalise(prompt).encode("utf-8", errors="replace")).hexdigest()[:16]

    # ── Public API ─────────────────────────────────────────────────────────────

    def get(self, key: str, task_type: str = "security_analysis") -> Optional[str]:
        """Return cached response or None if missing / expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            ttl = _TASK_TTL.get(task_type, _DEFAULT_TTL)
            if time.time() - entry.get("timestamp", 0) > ttl:
                del self._cache[key]
                self._misses += 1
                return None
            self._hits += 1
            log.debug("[LLMCache] HIT %s (task=%s)", key[:12], task_type)
            return entry["response"]

    def set(self, key: str, response: str, task_type: str = "security_analysis") -> None:
        """Store a response. Persists async-ish: every 10 writes."""
        with self._lock:
            self._cache[key] = {
                "response":  response,
                "timestamp": time.time(),
                "task_type": task_type,
            }
            self._dirty = True
            # Persist every 10 new entries to avoid excessive I/O
            if len(self._cache) % 10 == 0:
                self._persist()

    def flush(self) -> None:
        """Force-persist current cache state."""
        with self._lock:
            if self._dirty:
                self._persist()

    def stats(self) -> dict:
        with self._lock:
            total = self._hits + self._misses
            return {
                "entries":  len(self._cache),
                "hits":     self._hits,
                "misses":   self._misses,
                "hit_rate": round(self._hits / total, 3) if total else 0.0,
            }

    def evict_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        with self._lock:
            before = len(self._cache)
            now = time.time()
            self._cache = {
                k: v for k, v in self._cache.items()
                if now - v.get("timestamp", 0) <= _TASK_TTL.get(v.get("task_type", ""), _DEFAULT_TTL)
            }
            removed = before - len(self._cache)
            if removed:
                self._persist()
            return removed


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_cache_instance: Optional[LLMCache] = None


def get_llm_cache() -> LLMCache:
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = LLMCache()
    return _cache_instance
