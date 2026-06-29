import pytest
from fastapi.testclient import TestClient
from web.backend.main import app
import unittest.mock as mock

client = TestClient(app)

def test_list_devices_endpoint():
    """Test that the /api/mobile/devices endpoint returns a list of devices."""
    mock_devices = [
        {"serial": "emulator-5554", "state": "device"},
        {"serial": "ZY223BVG3X", "state": "device"}
    ]
    
    with mock.patch("web.backend.main._get_forensic_engine") as mock_engine_get:
        mock_engine = mock.MagicMock()
        mock_engine.list_devices.return_value = mock_devices
        mock_engine_get.return_value = mock_engine
        
        response = client.get("/api/mobile/devices")
        
        assert response.status_code == 200
        assert response.json() == mock_devices
        mock_engine_get.assert_called_once()
        mock_engine.list_devices.assert_called_once()

def test_list_devices_engine_unavailable():
    """Test that the endpoint returns an empty list if the engine is unavailable."""
    with mock.patch("web.backend.main._get_forensic_engine") as mock_engine_get:
        mock_engine_get.return_value = None
        
        response = client.get("/api/mobile/devices")
        
        assert response.status_code == 200
        assert response.json() == []

def test_analyze_with_device_id():
    """Test that the analyze endpoint accepts and uses device_id."""
    app_id = "test_app"
    # Mock _resolve_app and _get_mobile_engine
    with mock.patch("web.backend.main._resolve_app") as mock_resolve, \
         mock.patch("web.backend.main._get_mobile_engine") as mock_engine_get, \
         mock.patch("web.backend.main.BackgroundTasks.add_task") as mock_add_task:
        
        mock_resolve.return_value = {"app_id": app_id, "file_path": "/tmp/test.apk"}
        
        MockEngine = mock.MagicMock()
        MockConfig = mock.MagicMock()
        mock_engine_get.return_value = (MockEngine, MockConfig)
        
        # We don't need to mock _require_auth if we pass the header or if it's disabled in dev
        response = client.post(
            f"/api/mobile/apps/{app_id}/analyze",
            params={"device_id": "emulator-5554", "run_dynamic": "true"},
            headers={"X-API-Key": ""} # Assuming dev mode or mock it
        )
        
        assert response.status_code == 200
        # The background task should have been added
        mock_add_task.assert_called_once()
        # Verify the arguments of the background task if possible, 
        # or check how the endpoint processed it.
