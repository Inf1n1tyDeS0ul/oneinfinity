import pytest
from unittest.mock import MagicMock, patch
pytest.importorskip("adbutils")
from oneinfinity.mobile.adb_forensics import AegisForensicEngine, LogcatSentinel

def test_forensics_device_disconnect_graceful():
    """Verify that a device disconnect mid-audit doesn't crash the engine."""
    engine = AegisForensicEngine()
    engine.adb = MagicMock()
    mock_device = engine.adb.device.return_value
    
    # Simulate disconnect during shell command
    mock_device.shell.side_effect = Exception("device offline")
    
    findings = engine.run_audit("serial", "com.test.app")
    # Should return partial findings or empty list, not raise
    assert isinstance(findings, list)

def test_large_logcat_processing():
    """Stress test logcat sentinel with many lines."""
    sentinel = LogcatSentinel("com.test.app")
    # Use valid prefix for regex: email: john@leak.com
    lines = [f"D/Test: line {i} with email: email_{i}@leak.com" for i in range(1000)]
    
    hits = []
    for line in lines:
        hit = sentinel.process_line(line)
        if hit:
            hits.append(hit)
            
    assert len(hits) == 1000
    assert "@leak.com" in hits[0]["payload"]

def test_engine_no_adb_available():
    """Verify engine handles case where adbutils is missing or fails."""
    engine = AegisForensicEngine()
    engine.adb = None # Force none
    
    devices = engine.list_devices()
    assert devices == []
    
    findings = engine.run_audit("serial", "pkg")
    assert len(findings) == 1
    assert "ADB not available" in findings[0]["message"]

def test_memory_scour_no_pid():
    """Verify memory scour handles case where app is not running."""
    device = MagicMock()
    device.shell.return_value = "" # pidof returns nothing
    
    from oneinfinity.mobile.adb_forensics import MemoryScour
    scour = MemoryScour(device, "com.test.app")
    findings = scour.scour_memory()
    assert findings == []
