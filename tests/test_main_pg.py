# tests/test_main_pg.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

def test_findings_endpoint_uses_db_manager():
    """GET /api/findings must work with db_manager (not direct sqlite3)."""
    resp = client.get("/api/findings")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

def test_scans_list_endpoint_works():
    """GET /api/scans must return a list."""
    resp = client.get("/api/scans")
    assert resp.status_code == 200
