import pytest
import threading
import time
from unittest.mock import MagicMock, patch
pytest.importorskip("adbutils")
from oneinfinity.mobile.adb_forensics import AegisForensicEngine

class MockShellStream:
    def __init__(self, lines):
        self.lines = lines
        self.closed = False
        self._iter = iter(lines)

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            return next(self._iter)
        except StopIteration:
            # Simulate blocking wait if we want, but for tests we just end
            raise StopIteration

    def close(self):
        self.closed = True

def test_logcat_lifecycle_cleanup():
    """Verify that logcat thread and stream are cleaned up after run_audit."""
    mock_adb = MagicMock()
    mock_device = MagicMock()
    mock_adb.device.return_value = mock_device
    
    # Mock shell(stream=True) to return our MockShellStream
    mock_stream = MockShellStream(["line1", "line2", "line3"])
    mock_device.shell.side_effect = lambda cmd, stream=False: mock_stream if stream else ""

    engine = AegisForensicEngine()
    engine.adb = mock_adb

    # Patch time.sleep to speed up test
    with patch("time.sleep"):
        findings = engine.run_audit("serial123", "com.example.app")

    # Verify stream was closed
    assert mock_stream.closed is True
    
    # Verify we got findings if sentinel matches (none will match here but that's fine for lifecycle test)
    assert isinstance(findings, list)

def test_logcat_lifecycle_multiple_calls():
    """Verify multiple audits don't leave hanging threads or open streams."""
    mock_adb = MagicMock()
    mock_device = MagicMock()
    mock_adb.device.return_value = mock_device
    
    streams = []
    def mock_shell(cmd, stream=False):
        if stream:
            s = MockShellStream(["line1", "line2"])
            streams.append(s)
            return s
        return ""
    
    mock_device.shell.side_effect = mock_shell

    engine = AegisForensicEngine()
    engine.adb = mock_adb

    with patch("time.sleep"):
        for _ in range(3):
            engine.run_audit("serial123", "com.example.app")

    assert len(streams) == 3
    for s in streams:
        assert s.closed is True

def test_logcat_lifecycle_error_cleanup():
    """Verify cleanup even if an error occurs during audit."""
    mock_adb = MagicMock()
    mock_device = MagicMock()
    mock_adb.device.return_value = mock_device
    
    mock_stream = MockShellStream(["line1"])
    mock_device.shell.side_effect = lambda cmd, stream=False: mock_stream if stream else ""

    # Force an error in one of the checks
    with patch("oneinfinity.mobile.adb_forensics.EnvironmentIntegrity.check_all", side_effect=RuntimeError("Audit crash")):
        engine = AegisForensicEngine()
        engine.adb = mock_adb
        
        with patch("time.sleep"):
            engine.run_audit("serial123", "com.example.app")

    # Stream should still be closed due to finally block
    assert mock_stream.closed is True
