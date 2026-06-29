import pytest
pytest.importorskip("adbutils")
from oneinfinity.mobile.adb_forensics import LogcatSentinel

def test_logcat_sentinel_redaction_email():
    sentinel = LogcatSentinel("com.test.app")
    line = "D/App: logging email: john.doe@example.com"
    hit = sentinel.process_line(line)
    assert hit is not None
    # redacted: jo...e@example.com (since local 'john.doe' > 3)
    assert "jo..." in hit["payload"]
    assert "john.doe" not in hit["payload"]
    assert "@example.com" in hit["payload"]

def test_logcat_sentinel_redaction_token():
    sentinel = LogcatSentinel("com.test.app")
    line = "I/Auth: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    hit = sentinel.process_line(line)
    assert hit is not None
    # redacted: first 10 chars + ...[REDACTED]
    assert hit["payload"].startswith("bearer eyJ")
    assert "[REDACTED]" in hit["payload"]

def test_logcat_sentinel_no_leak():
    sentinel = LogcatSentinel("com.test.app")
    line = "V/View: rendering some buttons"
    assert sentinel.process_line(line) is None
