import pytest
from unittest.mock import MagicMock, patch
from oneinfinity.mobile.deep_link_fuzzer import DeepLinkFuzzer

@pytest.fixture
def fuzzer():
    return DeepLinkFuzzer(device_id="test_device")

def test_fuzzer_no_device_id():
    fuzzer = DeepLinkFuzzer(device_id=None)
    findings = fuzzer.fuzz("com.example.app", ["example://test"])
    assert findings == []

def test_fuzzer_no_links(fuzzer):
    findings = fuzzer.fuzz("com.example.app", [])
    assert findings == []

@patch("subprocess.run")
def test_fuzzer_crash_detection(mock_run, fuzzer):
    # Mock ADB start success
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    
    # Mock crash detection: first pidof returns something, second (after launch) returns nothing
    # Also mock logcat showing FATAL EXCEPTION
    side_effects = [
        # _launch_deep_link
        MagicMock(returncode=0, stdout="", stderr=""),
        # _check_for_crash -> pidof
        MagicMock(returncode=1, stdout="", stderr=""),
        # _check_for_crash -> logcat
        MagicMock(returncode=0, stdout="FATAL EXCEPTION in com.example.app\nNullPointerException", stderr=""),
        # _clear_app_data -> force-stop
        MagicMock(returncode=0, stdout="", stderr="")
    ]
    mock_run.side_effect = side_effects
    
    # Run fuzz with one link and one payload to keep it simple
    with patch.object(fuzzer, 'payloads', {"dos": ["A" * 5000]}):
        findings = fuzzer.fuzz("com.example.app", ["example://test"])
    
    assert len(findings) > 0
    assert "Denial of Service" in findings[0].vulnerability
    assert findings[0].target == "com.example.app"
