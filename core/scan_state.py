# core/scan_state.py
"""Bounded in-memory scan state cache with optional SQLite eviction.

Replaces unbounded SCANS and VULNERABILITIES global dicts in main.py.
Caps in-memory entries (LRU eviction) and optionally persists evicted
entries to a SQLite-backed DB when one is provided.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional

_DEFAULT_CAP = 500


class BoundedScanCache:
    """Thread-safe LRU cache with optional SQLite eviction on overflow.

    Supports dict-like access: cache[key], cache[key] = val, key in cache,
    cache.get(key), cache.delete(key), len(cache), cache.get_all_in_memory().
    """

    def __init__(self, cap: int = _DEFAULT_CAP, db=None):
        """
        Args:
            cap: Maximum number of entries to keep in memory.
            db: Optional ScanDB-like object with .upsert(data) for eviction persistence.
        """
        self._cap = cap
        self._cache: OrderedDict[str, Dict] = OrderedDict()
        self._lock = threading.Lock()
        self._db = db

    # ── Write ────────────────────────────────────────────────────────────────

    def put(self, key: str, data: Dict) -> None:
        with self._lock:
            self._cache[key] = data
            self._cache.move_to_end(key)
            if len(self._cache) > self._cap:
                _, evicted = self._cache.popitem(last=False)
                if self._db is not None:
                    try:
                        self._db.upsert(evicted)
                    except Exception:
                        pass  # eviction is best-effort

    def delete(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)
        if self._db is not None:
            try:
                self._db.delete(key)
            except Exception:
                pass

    # ── Read ─────────────────────────────────────────────────────────────────

    def get(self, key: str, default=None) -> Optional[Dict]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        # Cache miss — try SQLite fallback
        if self._db is not None:
            try:
                result = self._db.get(key)
                if result:
                    return result
            except Exception:
                pass
        return default

    def get_all_in_memory(self) -> List[Dict]:
        with self._lock:
            return list(self._cache.values())

    # ── Dict protocol ────────────────────────────────────────────────────────

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __getitem__(self, key: str) -> Dict:
        result = self.get(key)
        if result is None:
            raise KeyError(key)
        return result

    def __setitem__(self, key: str, data: Dict) -> None:
        self.put(key, data)

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    def update(self, key: str, data: Dict) -> None:
        """Update an existing entry in-place, or create if not present."""
        with self._lock:
            if key in self._cache:
                self._cache[key].update(data)
                self._cache.move_to_end(key)
                return
        # Not in cache — do a full put
        self.put(key, data)

    def values(self):
        """Compatibility: iterate in-memory values."""
        with self._lock:
            return list(self._cache.values())

    def items(self):
        """Compatibility: iterate in-memory (key, value) pairs."""
        with self._lock:
            return list(self._cache.items())
