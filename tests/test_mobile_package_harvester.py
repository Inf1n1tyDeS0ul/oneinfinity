import pytest
from unittest.mock import MagicMock, patch
import os
pytest.importorskip("adbutils")
from oneinfinity.mobile.adb_forensics import PackageHarvester

def test_list_packages_mocked():
    """Verify list_packages correctly parses pm list packages -f output."""
    mock_device = MagicMock()
    mock_device.shell.return_value = (
        "package:/data/app/com.example.app-1/base.apk=com.example.app\n"
        "package:/system/priv-app/Settings/Settings.apk=com.android.settings\n"
    )
    
    harvester = PackageHarvester(mock_device)
    packages = harvester.list_packages()
    
    assert len(packages) == 2
    assert packages[0]["name"] == "com.example.app"
    assert packages[0]["path"] == "/data/app/com.example.app-1/base.apk"
    assert packages[1]["name"] == "com.android.settings"
    assert packages[1]["path"] == "/system/priv-app/Settings/Settings.apk"
    mock_device.shell.assert_called_with("pm list packages -f")

def test_pull_package_success():
    """Verify pull_package calls pm path and device.pull correctly."""
    mock_device = MagicMock()
    # Mock pm path output
    mock_device.shell.return_value = "package:/data/app/com.example.app-1/base.apk"
    
    harvester = PackageHarvester(mock_device)
    
    with patch("os.path.exists") as mock_exists:
        mock_exists.return_value = True
        result = harvester.pull_package("com.example.app", "/tmp/test.apk")
        
        assert result is True
        # shlex.quote("com.example.app") == "com.example.app"
        mock_device.shell.assert_called_with("pm path com.example.app")
        mock_device.pull.assert_called_with("/data/app/com.example.app-1/base.apk", "/tmp/test.apk")

def test_pull_package_not_found():
    """Verify pull_package returns False if package path is not found."""
    mock_device = MagicMock()
    mock_device.shell.return_value = "Error: package not found"
    
    harvester = PackageHarvester(mock_device)
    result = harvester.pull_package("com.nonexistent.app", "/tmp/test.apk")
    
    assert result is False
    mock_device.pull.assert_not_called()
