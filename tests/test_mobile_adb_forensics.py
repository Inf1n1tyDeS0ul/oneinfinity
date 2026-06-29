import pytest
from unittest.mock import MagicMock, patch
pytest.importorskip("adbutils")
from oneinfinity.mobile.adb_forensics import AegisForensicEngine

def test_list_devices_mocked():
    """Verify list_devices returns serials and states from adbutils."""
    mock_device = MagicMock()
    mock_device.serial = "emulator-5554"
    mock_device.state = "device" # In my code I use str(getattr(d, 'state', ...))
    
    with patch("adbutils.adb.list") as mock_list:
        mock_list.return_value = [mock_device]
        
        engine = AegisForensicEngine()
        devices = engine.list_devices()
        
        assert isinstance(devices, list)
        assert len(devices) == 1
        assert devices[0]["serial"] == "emulator-5554"
        assert devices[0]["state"] == "device"

def test_list_devices_empty():
    """Verify list_devices handles no devices."""
    with patch("adbutils.adb.list") as mock_list:
        mock_list.return_value = []
        
        engine = AegisForensicEngine()
        devices = engine.list_devices()
        
        assert devices == []

def test_list_devices_error():
    """Verify list_devices handles errors gracefully."""
    with patch("adbutils.adb.list") as mock_list:
        mock_list.side_effect = Exception("ADB error")
        
        engine = AegisForensicEngine()
        devices = engine.list_devices()
        
        assert devices == []

def test_security_engine_lazy_load():
    """Verify MobileSecurityEngine lazily loads AegisForensicEngine."""
    from oneinfinity.mobile.security_engine import MobileSecurityEngine
    engine = MobileSecurityEngine()
    
    # Initially None
    assert engine._forensic_engine is None
    
    # After lazy load, it should be the class
    engine._lazy_load()
    assert engine._forensic_engine is AegisForensicEngine
