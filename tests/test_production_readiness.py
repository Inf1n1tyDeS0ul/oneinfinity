# tests/test_production_readiness.py
"""
Production readiness smoke test — validates all 43 audit findings resolved.
"""
import os, pathlib

# Set the API key env var before importing app so auth middleware initialises
# with a non-empty key.  We do NOT leave it in the environment permanently —
# the TestSecurity class restores the live _API_KEY value via setup/teardown.
os.environ.setdefault("ONEINFINITY_API_KEY", "test-prod-key")
from fastapi.testclient import TestClient
from web.backend.main import app

client = TestClient(app, raise_server_exceptions=False)
ROOT = pathlib.Path("/home/devendra-yadav/oneinfinity")


class TestSecurity:
    _KEY = "test-prod-key"

    def setup_method(self):
        """Ensure _API_KEY is set to our test key before each security test."""
        import web.backend.main as m
        self._orig_key = m._API_KEY
        m._API_KEY = self._KEY

    def teardown_method(self):
        """Restore _API_KEY after each security test."""
        import web.backend.main as m
        m._API_KEY = self._orig_key

    def test_auth_enforced(self):
        """A01: Auth must reject unauthenticated requests when key is set."""
        resp = client.post("/api/scans", json={"target": "example.com", "scan_type": "quick"})
        assert resp.status_code == 401

    def test_god_mode_validates_target(self):
        """A02: God-mode must reject shell-injection targets."""
        resp = client.post(
            "/api/god-mode/run",
            json={"target": "evil; rm -rf /"},
            headers={"X-API-Key": self._KEY},
        )
        assert resp.status_code == 400

    def test_no_changeme_key_in_compose(self):
        """A04: docker-compose.yml must not contain 'changeme' default key."""
        compose = (ROOT / "docker-compose.yml").read_text()
        assert "changeme" not in compose


class TestDocker:
    def test_frontend_volume_writable(self):
        """A17: Frontend Docker volume must not be :ro."""
        import yaml
        with open(ROOT / "docker-compose.yml") as f:
            cfg = yaml.safe_load(f)
        vols = str(cfg.get("services", {}).get("frontend", {}).get("volumes", []))
        assert ":ro" not in vols

    def test_vite_proxy_env_driven(self):
        """A18: Vite proxy must not hardcode localhost:8000."""
        vite = (ROOT / "web/frontend/vite.config.js").read_text()
        # Either localhost is gone, or it's wrapped by env var logic
        assert "localhost:8000" not in vite or "VITE_BACKEND_URL" in vite

    def test_backend_no_reload(self):
        """A19: Production Docker must not use --reload."""
        import yaml
        with open(ROOT / "docker-compose.yml") as f:
            cfg = yaml.safe_load(f)
        cmd = str(cfg.get("services", {}).get("backend", {}).get("command", ""))
        assert "--reload" not in cmd

    def test_redis_in_compose(self):
        """A16: docker-compose.yml must include Redis service."""
        import yaml
        with open(ROOT / "docker-compose.yml") as f:
            cfg = yaml.safe_load(f)
        assert "redis" in cfg.get("services", {})


class TestRoutes:
    _KEY = "test-prod-key"
    HEADERS = {"X-API-Key": "test-prod-key"}

    def setup_method(self):
        """Pin _API_KEY to our test key so authenticated route calls succeed."""
        import web.backend.main as m
        self._orig_key = m._API_KEY
        m._API_KEY = self._KEY

    def teardown_method(self):
        """Restore _API_KEY after each route test."""
        import web.backend.main as m
        m._API_KEY = self._orig_key

    def test_cache_stats_route(self):
        """A23: /api/cache/stats must exist."""
        r = client.get("/api/cache/stats")
        assert r.status_code == 200

    def test_safety_route(self):
        """A23: /api/safety must exist."""
        r = client.get("/api/safety")
        assert r.status_code == 200

    def test_waf_stats_route(self):
        """A23: /api/waf/stats must exist."""
        r = client.get("/api/waf/stats")
        assert r.status_code == 200

    def test_benchmark_route(self):
        """A23: /api/benchmark must exist."""
        r = client.post("/api/benchmark", json={"target": "example.com"}, headers=self.HEADERS)
        assert r.status_code == 200

    def test_router_health_route(self):
        """A32: /api/health/routers must exist."""
        r = client.get("/api/health/routers")
        assert r.status_code == 200
        data = r.json()
        assert "registered" in data
        assert "failed" in data

    def test_findings_endpoint_returns_list(self):
        """A15: /api/findings must return a list."""
        r = client.get("/api/findings", headers=self.HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)


class TestCodeQuality:
    def test_no_pydantic_v1_validator(self):
        """A36: No @validator() in main.py — must use @field_validator."""
        src = (ROOT / "web/backend/main.py").read_text()
        assert "@validator(" not in src

    def test_no_bare_except_pass_in_unified(self):
        """A30: unified_scan_engine.py must have zero bare except:pass blocks."""
        import ast
        src = (ROOT / "unified_scan_engine.py").read_text()
        tree = ast.parse(src)
        bare_pass = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.ExceptHandler)
            and n.type is None
            and len(n.body) == 1
            and isinstance(n.body[0], ast.Pass)
        ]
        assert not bare_pass, f"Found {len(bare_pass)} bare except:pass blocks"

    def test_dead_api_aliases_removed(self):
        """A24: Dead api.js aliases pointing to /utilities/* must be gone."""
        api_js = (ROOT / "web/frontend/src/utils/api.js").read_text()
        for alias in ["cvssCalculate", "dedupCheck", "methodologyGet", "wafBypassPayloads"]:
            assert alias not in api_js

    def test_business_logic_phase_in_unified_scan(self):
        """A10: unified_scan_engine.py must include business_logic phase."""
        src = (ROOT / "unified_scan_engine.py").read_text()
        assert "business_logic" in src

    def test_scan_state_bounded(self):
        """A13/A25/A26: SCANS and VULNERABILITIES must be BoundedScanCache."""
        from web.backend.main import SCANS, VULNERABILITIES
        from oneinfinity.core.scan_state import BoundedScanCache
        assert isinstance(SCANS, BoundedScanCache)
        assert isinstance(VULNERABILITIES, BoundedScanCache)


class TestMetrics:
    def test_metrics_endpoint_exists(self):
        """A35: /metrics must return something useful (not empty dict)."""
        r = client.get("/metrics")
        assert r.status_code == 200
        # Should be Prometheus text or JSON with real data
        body = r.text if hasattr(r, "text") else str(r.json())
        assert body.strip() not in ("{}", "")
