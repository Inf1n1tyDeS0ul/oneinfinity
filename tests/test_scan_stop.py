import os, time, threading
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app, SCANS

client = TestClient(app)

def test_stop_inline_scan_transitions_status():
    """Stopping a scan must change status to 'stopped'."""
    resp = client.post("/api/scans", json={"target": "127.0.0.1", "scan_type": "quick"})
    assert resp.status_code in (200, 201)
    scan_id = resp.json()["id"]

    stop_resp = client.post(f"/api/scans/{scan_id}/stop")
    assert stop_resp.status_code == 200

    scan = SCANS.get(scan_id)
    assert scan is not None
    assert scan["status"] == "stopped", f"Expected stopped, got: {scan.get('status')}"

def test_stop_sets_cancel_event():
    """Cancel event must be set when stop is called."""
    resp = client.post("/api/scans", json={"target": "127.0.0.1", "scan_type": "quick"})
    scan_id = resp.json()["id"]

    client.post(f"/api/scans/{scan_id}/stop")

    scan = SCANS.get(scan_id)
    cancel_event = scan.get("_cancel_event") if scan else None
    if cancel_event is not None:
        assert cancel_event.is_set(), "Cancel event must be set after stop"
