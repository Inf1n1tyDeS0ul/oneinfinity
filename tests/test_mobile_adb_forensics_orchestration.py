import pytest
from unittest.mock import MagicMock, patch
pytest.importorskip("adbutils")
from oneinfinity.mobile.adb_forensics import AegisForensicEngine

@pytest.fixture
def mock_adb():
    with patch("adbutils.adb") as m:
        yield m

def test_run_audit_orchestration(mock_adb):
    """Verify run_audit orchestrates all forensic modules."""
    mock_device = MagicMock()
    mock_adb.device.return_value = mock_device

    # Mock shell responses
    def shell_mock(cmd, stream=False):
        if "logcat" in cmd: return []
        if "getprop ro.debuggable" in cmd: return "1"
        if "getenforce" in cmd: return "Enforcing"
        if "dumpsys package" in cmd: return "allowBackup=true"
        # Long parcel to pass length check
        if "service call clipboard" in cmd: return "Result: Parcel(00000000 00000000 00000000 00000000 00000000)"
        if "which su" in cmd: return "/system/bin/su"
        if "ls -R" in cmd: return "data"
        if "pidof" in cmd: return "1234"
        return ""
    
    mock_device.shell.side_effect = shell_mock

    engine = AegisForensicEngine()
    # Mock time.sleep to speed up test
    with patch("time.sleep"):
        findings = engine.run_audit("serial123", "com.example.app")

    # Verify we got findings from multiple modules
    categories = [f.get("category") for f in findings]
    assert "env_integrity" in categories
    assert "system_artifact" in categories
    assert "sandbox_access" in categories
    assert "memory_forensics" in categories

def test_run_audit_partial_failure(mock_adb):
    """Verify run_audit continues even if some modules fail."""
    mock_device = MagicMock()
    mock_adb.device.return_value = mock_device

    # EnvironmentIntegrity succeeds, SystemArtifacts raises
    def shell_mock(cmd, stream=False):
        if "logcat" in cmd: return []
        if "getprop" in cmd: return "0"
        if "getenforce" in cmd: return "Enforcing"
        if "dumpsys" in cmd: return "allowBackup=false"
        if "service call clipboard" in cmd: raise Exception("Clip fail")
        if "which su" in cmd: return ""
        if "pidof" in cmd: return ""
        return ""
    
    mock_device.shell.side_effect = shell_mock

    engine = AegisForensicEngine()
    with patch("time.sleep"):
        findings = engine.run_audit("serial123", "com.example.app")

    assert isinstance(findings, list)
    categories = [f.get("category") for f in findings]
    # Sandbox should return something even if not rooted
    assert "sandbox_access" in categories
