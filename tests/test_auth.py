# tests/test_auth.py
import os
import pytest

# Set key BEFORE importing app
os.environ["ONEINFINITY_API_KEY"] = "test-secret"

from fastapi.testclient import TestClient

# Import app after setting env
import sys
sys.path.insert(0, "/home/devendra-yadav/oneinfinity")
from web.backend.main import app

client = TestClient(app, raise_server_exceptions=False)


def test_unauthenticated_scan_returns_401():
    """Without key header, protected endpoints must return 401."""
    resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "quick"})
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"


def test_authenticated_scan_passes_auth():
    """With correct key, request must not be rejected with 401."""
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "scan_type": "quick"},
        headers={"X-API-Key": "test-secret"},
    )
    assert resp.status_code != 401, f"Valid key returned 401: {resp.text}"


def test_wrong_key_returns_401():
    """Wrong key must return 401."""
    resp = client.post(
        "/api/scans",
        json={"target": "example.com", "scan_type": "quick"},
        headers={"X-API-Key": "wrong-key"},
    )
    assert resp.status_code == 401, f"Wrong key should return 401, got {resp.status_code}"


def test_no_key_env_allows_all():
    """When ONEINFINITY_API_KEY is empty string, all requests pass (local dev mode)."""
    import importlib
    # Temporarily clear the key
    original = os.environ.get("ONEINFINITY_API_KEY", "")
    os.environ["ONEINFINITY_API_KEY"] = ""

    # Reload to pick up new env
    import web.backend.main as m
    m._API_KEY = ""

    resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "quick"})
    assert resp.status_code != 401, f"Empty key should allow all, got {resp.status_code}"

    # Restore
    os.environ["ONEINFINITY_API_KEY"] = original
    m._API_KEY = original
