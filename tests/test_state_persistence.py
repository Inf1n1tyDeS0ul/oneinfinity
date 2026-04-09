# tests/test_state_persistence.py
import sys
from oneinfinity.core.scan_state import BoundedScanCache


def test_bounded_cache_does_not_exceed_cap():
    """BoundedScanCache must not hold more than `cap` entries in memory."""
    cache = BoundedScanCache(cap=5)
    for i in range(20):
        cache[f"scan-{i}"] = {"id": f"scan-{i}", "status": "completed"}
    assert len(cache) <= 5, f"Cache exceeded cap: {len(cache)} entries"


def test_bounded_cache_recent_entries_accessible():
    """Most recently added entries must be retrievable."""
    cache = BoundedScanCache(cap=5)
    for i in range(10):
        cache[f"scan-{i}"] = {"id": f"scan-{i}", "status": "completed"}
    # Last entry must be in cache
    assert cache.get("scan-9") is not None, "Most recent entry must be accessible"


def test_bounded_cache_contains_works():
    """`in` operator must work."""
    cache = BoundedScanCache(cap=10)
    cache["test-id"] = {"id": "test-id"}
    assert "test-id" in cache
    assert "nonexistent" not in cache


def test_bounded_cache_delete_works():
    cache = BoundedScanCache(cap=10)
    cache["del-test"] = {"id": "del-test"}
    assert "del-test" in cache
    cache.delete("del-test")
    assert "del-test" not in cache


def test_bounded_cache_get_all_in_memory():
    cache = BoundedScanCache(cap=10)
    cache["a"] = {"id": "a"}
    cache["b"] = {"id": "b"}
    all_items = cache.get_all_in_memory()
    assert len(all_items) == 2
    ids = {item["id"] for item in all_items}
    assert ids == {"a", "b"}
