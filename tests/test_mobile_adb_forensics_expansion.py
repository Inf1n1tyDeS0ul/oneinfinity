import pytest
from unittest.mock import MagicMock
pytest.importorskip("adbutils")
from oneinfinity.mobile.adb_forensics import EnvironmentIntegrity, SystemArtifacts, MemoryScour

@pytest.fixture
def mock_device():
    return MagicMock()

def test_memory_scour_dump_success(mock_device):
    """Verify MemoryScour initiates dumpheap successfully."""
    package_name = "com.example.app"
    pid = "1234"
    # Mock pidof returns PID
    mock_device.shell.return_value = pid

    scour = MemoryScour(mock_device, package_name)
    findings = scour.scour_memory()
    
    assert len(findings) == 1
    assert findings[0]["type"] == "heap_dump_initiated"
    mock_device.shell.assert_any_call(f"pidof {package_name}")

def test_memory_scour_app_not_running(mock_device):
    """Verify MemoryScour handles app not running."""
    package_name = "com.example.app"
    # Mock pidof returns empty string
    mock_device.shell.return_value = ""

    scour = MemoryScour(mock_device, package_name)
    findings = scour.scour_memory()
    
    assert findings == []

def test_environment_integrity_debuggable(mock_device):
    """Verify EnvironmentIntegrity checks ro.debuggable."""
    # Mock shell calls in check_all
    def shell_mock(cmd):
        if "ro.debuggable" in cmd: return "1"
        if "dumpsys package" in cmd: return "allowBackup=false"
        return ""
    mock_device.shell.side_effect = shell_mock

    integrity = EnvironmentIntegrity(mock_device, package_name="com.example.app")
    findings = integrity.check_all()
    
    assert any(f["type"] == "global_debug" for f in findings)

def test_environment_integrity_allow_backup(mock_device):
    """Verify EnvironmentIntegrity checks allowBackup."""
    def shell_mock(cmd):
        if "ro.debuggable" in cmd: return "0"
        if "dumpsys package" in cmd: return "allowBackup=true"
        return ""
    mock_device.shell.side_effect = shell_mock

    integrity = EnvironmentIntegrity(mock_device, package_name="com.example.app")
    findings = integrity.check_all()
    
    assert any(f["type"] == "backup_allowed" for f in findings)

def test_system_artifacts_clipboard(mock_device):
    """Verify SystemArtifacts checks clipboard."""
    # Provide a long enough response to pass the length check (>50)
    mock_device.shell.return_value = "Result: Parcel(00000000 00000000 00000000 00000000 00000000 00000000)"

    artifacts = SystemArtifacts(mock_device)
    findings = artifacts.check_clipboard()
    
    assert len(findings) == 1
    assert findings[0]["type"] == "clipboard_leak"

def test_system_artifacts_clipboard_empty(mock_device):
    """Verify SystemArtifacts handles empty clipboard."""
    mock_device.shell.return_value = ""

    artifacts = SystemArtifacts(mock_device)
    findings = artifacts.check_clipboard()
    
    assert findings == []
