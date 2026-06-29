import pytest
from unittest.mock import MagicMock, patch
pytest.importorskip("adbutils")
from oneinfinity.mobile.adb_forensics import LogcatSentinel, SandboxExplorer

def test_logcat_sentinel_redacting():
    """Verify LogcatSentinel redacts sensitive information in findings."""
    sentinel = LogcatSentinel(package_name="com.test.app")
    
    # Test email redacting
    line_email = "D/Test: User email: john.doe@example.com"
    hit_email = sentinel.process_line(line_email)
    assert hit_email is not None
    assert hit_email["type"] == "pii_leak"
    # Expected redacted: john...com or similar. 
    # Current implementation doesn't redact, so this should FAIL initially.
    assert "john.doe@example.com" not in hit_email["payload"]
    assert "..." in hit_email["payload"]

    # Test token redacting
    line_token = "I/Auth: Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    hit_token = sentinel.process_line(line_token)
    assert hit_token is not None
    assert hit_token["type"] == "token_leak"
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in hit_token["payload"]
    assert "..." in hit_token["payload"]

def test_sandbox_explorer_depth_limit():
    """Verify SandboxExplorer limits recursion depth or uses a timeout."""
    mock_device = MagicMock()
    # Mock rooted
    mock_device.shell.side_effect = ["/system/xbin/su", "mock output"]
    
    explorer = SandboxExplorer(mock_device, "com.test.app")
    # We want to ensure it doesn't just do 'ls -R' without any limits if large
    # For now, let's just check if the command was modified or if it uses a timeout
    explorer.explore()
    
    # Check if the shell command has some limit or if we pass a timeout to shell
    # This might depend on how we implement it.
    # If we use `timeout` command in shell:
    calls = [call.args[0] for call in mock_device.shell.call_args_list]
    ls_call = next(c for c in calls if "ls -R" in c)
    assert "timeout" in ls_call or "max-depth" in ls_call or "head" in ls_call
