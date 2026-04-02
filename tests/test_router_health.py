import os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

def test_router_health_endpoint_exists():
    resp = client.get("/api/health/routers")
    assert resp.status_code == 200
    data = resp.json()
    assert "registered" in data
    assert "failed" in data

def test_failed_routers_reported():
    resp = client.get("/api/health/routers")
    data = resp.json()
    for failed in data.get("failed", []):
        assert "name" in failed
        assert "error" in failed
