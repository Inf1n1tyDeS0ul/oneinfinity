"""tests/test_hunt_memory.py — Unit tests for persistent hunt memory."""
from __future__ import annotations
import threading
import tempfile
import os
import pytest
from unittest.mock import patch


def test_hunt_memory_imports():
    from oneinfinity.learning.persistent_memory import HuntMemory, get_hunt_memory
    assert HuntMemory is not None


def test_remember_and_get_target():
    """remember() stores a note; get_target() retrieves it."""
    from oneinfinity.learning.persistent_memory import HuntMemory
    import oneinfinity.learning.persistent_memory as _pm

    with tempfile.TemporaryDirectory() as tmp:
        with patch.object(_pm, "_memory_dir", return_value=__import__("pathlib").Path(tmp)):
            mem = HuntMemory()
            mem.remember(target="example.com", note="Found SSRF on /webhook", vuln_type="ssrf")
            data = mem.get_target("example.com")
    assert "ssrf" in data.get("vulns", [])
    assert len(data.get("notes", [])) > 0


def test_pickup_unknown_target_no_crash():
    """pickup() for an unknown target returns a string (not empty list, not exception)."""
    from oneinfinity.learning.persistent_memory import HuntMemory
    import oneinfinity.learning.persistent_memory as _pm

    with tempfile.TemporaryDirectory() as tmp:
        with patch.object(_pm, "_memory_dir", return_value=__import__("pathlib").Path(tmp)):
            mem = HuntMemory()
            result = mem.pickup("unknown.target.xyz")
    assert isinstance(result, str)
    assert "unknown" in result.lower() or "no hunt" in result.lower()


def test_memory_persists_across_instances():
    """Saved memory should be loadable by a new HuntMemory instance from same dir."""
    from oneinfinity.learning.persistent_memory import HuntMemory
    import oneinfinity.learning.persistent_memory as _pm
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        with patch.object(_pm, "_memory_dir", return_value=tmp_path):
            mem1 = HuntMemory()
            mem1.remember(target="persist.com", note="Open redirect on /go", vuln_type="open_redirect")

        with patch.object(_pm, "_memory_dir", return_value=tmp_path):
            mem2 = HuntMemory()
            data = mem2.get_target("persist.com")
    assert "open_redirect" in data.get("vulns", [])


def test_no_race_condition_under_concurrent_writes():
    """Concurrent writes should not corrupt storage (lock must hold)."""
    from oneinfinity.learning.persistent_memory import HuntMemory
    import oneinfinity.learning.persistent_memory as _pm
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        with patch.object(_pm, "_memory_dir", return_value=tmp_path):
            mem = HuntMemory()
            errors = []

            def _write(n):
                try:
                    mem.remember(target="concurrent.com", note=f"note-{n}", vuln_type="xss")
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=_write, args=(i,)) for i in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

    assert len(errors) == 0, f"Race condition errors: {errors}"


def test_singleton_get_hunt_memory():
    """get_hunt_memory() returns the same instance on repeated calls."""
    from oneinfinity.learning.persistent_memory import get_hunt_memory
    m1 = get_hunt_memory()
    m2 = get_hunt_memory()
    assert m1 is m2
