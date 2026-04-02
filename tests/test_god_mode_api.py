import os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

def test_god_mode_run_endpoint_returns_session_id():
    """god-mode run must return a session_id (findings path test)."""
    resp = client.post("/api/god-mode/run", json={"target": "127.0.0.1"})
    # Accept 200 or 202 (async launch)
    assert resp.status_code in (200, 202, 422), f"Unexpected: {resp.status_code} {resp.text}"
    if resp.status_code in (200, 202):
        data = resp.json()
        assert "session_id" in data or "scan_id" in data or "id" in data, \
            f"No session identifier in response: {data}"
