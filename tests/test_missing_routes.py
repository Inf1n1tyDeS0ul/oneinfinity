import os
os.environ["ONEINFINITY_API_KEY"] = ""

from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app)

ROUTES_TO_CHECK = [
    ("GET",  "/api/cache/stats", None),
    ("POST", "/api/cache/sweep", {}),
    ("POST", "/api/cache/clear", {}),
    ("POST", "/api/benchmark",   {"target": "127.0.0.1"}),
    ("POST", "/api/distributed/scan", {"target": "127.0.0.1"}),
    ("GET",  "/api/safety", None),
    ("GET",  "/api/waf/stats", None),
    ("POST", "/api/workflow/run", {"target": "127.0.0.1", "workflow": "recon"}),
    ("POST", "/api/reports/replay", {"finding_id": "test-id"}),
]

def test_all_routes_return_not_404():
    failures = []
    for method, path, body in ROUTES_TO_CHECK:
        if method == "GET":
            resp = client.get(path)
        else:
            resp = client.post(path, json=body or {})
        if resp.status_code == 404:
            failures.append(f"{method} {path} → 404")
    assert not failures, "Routes still returning 404:\n" + "\n".join(failures)
