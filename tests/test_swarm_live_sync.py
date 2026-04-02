import os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

def test_findings_endpoint_returns_list():
    """GET /api/findings must return a list (not error)."""
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

def test_findings_accepts_scan_id_filter():
    """GET /api/findings?scan_id=x must filter without error."""
    resp = client.get("/api/findings", params={"scan_id": "nonexistent-scan"})
    assert resp.status_code == 200
    assert resp.json() == []
