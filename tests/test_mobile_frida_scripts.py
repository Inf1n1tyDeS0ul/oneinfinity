
import os
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from pathlib import Path

# Setup environment before importing app
os.environ["ONEINFINITY_API_KEY"] = "test-key"

from web.backend.main import app

client = TestClient(app)

def test_mobile_frida_scripts_includes_content():
    """
    Test that /api/mobile/apps/{app_id}/frida-scripts includes script_content
    by reading the .js files from disk. Updated for Phase 1 security fix.
    """
    app_id = "mob_001_test"

    # Use authorized path (within ~/.oneinfinity/mobile/uploads/)
    oneinfinity_home = Path.home() / ".oneinfinity"
    authorized_path = oneinfinity_home / "mobile" / "uploads" / "frida_scripts" / "hook_network.js"

    # Mock data returned by _get_mobile_result
    mock_result = {
        "frida_scripts": {
            "status": "complete",
            "scripts": [
                {
                    "name": "Hook Network",
                    "path": str(authorized_path),  # ✅ Now within whitelist
                    "description": "Hooks networking",
                    "hook_type": "network",
                    "auto_run": False
                }
            ],
            "total": 1,
            "scripts_dir": str(authorized_path.parent)
        }
    }

    # Content we expect to see
    expected_content = "console.log('hooked network');"

    # We need to mock _get_mobile_result AND the file reading
    with patch("web.backend.main._get_mobile_result", return_value=mock_result), \
         patch("pathlib.Path.exists", return_value=True), \
         patch("pathlib.Path.is_file", return_value=True), \
         patch("pathlib.Path.read_text", return_value=expected_content):

        resp = client.get(f"/api/mobile/apps/{app_id}/frida-scripts")
        assert resp.status_code == 200
        data = resp.json()

        assert "scripts" in data
        assert len(data["scripts"]) > 0

        script = data["scripts"][0]
        assert "name" in script
        assert "script_content" in script, "script_content should be present in the response"
        assert script["script_content"] == expected_content
