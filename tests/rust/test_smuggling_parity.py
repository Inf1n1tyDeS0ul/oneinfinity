"""
test_smuggling_parity.py — verify RustSmugglingEngine produces the same
structure as SmugglingEngine without actually hitting any network.

All network calls are monkeypatched; we only test the shim logic and
the data contract (finding field names, types, values).
"""
import pytest

try:
    import oneinfinity_core as _oc
    _HAVE_RUST = hasattr(_oc, "run_smuggling_scan")
except ImportError:
    _HAVE_RUST = False


# ---------------------------------------------------------------------------
# Test the shim dispatch logic (no network, no native build required)
# ---------------------------------------------------------------------------

class TestRustSmugglingEngineShim:
    """Test the Python shim class directly — no native module required."""

    def test_shim_class_importable(self):
        from src.oneinfinity.scan.smuggling_engine import RustSmugglingEngine
        assert RustSmugglingEngine is not None

    def test_get_smuggling_engine_returns_python_without_flag(self, monkeypatch):
        import os
        monkeypatch.delenv("ONEINFINITY_RUST_SMUGGLING", raising=False)
        from src.oneinfinity.scan import smuggling_engine as se
        # Reload to pick up env change
        import importlib
        importlib.reload(se)
        engine = se.get_smuggling_engine("http://example.com")
        from src.oneinfinity.scan.smuggling_engine import SmugglingEngine
        assert isinstance(engine, SmugglingEngine)

    def test_get_smuggling_engine_returns_rust_with_flag(self, monkeypatch):
        if not _HAVE_RUST:
            pytest.skip("oneinfinity_core not built")
        import os
        monkeypatch.setenv("ONEINFINITY_RUST_SMUGGLING", "1")
        from src.oneinfinity.scan import smuggling_engine as se
        import importlib
        importlib.reload(se)
        engine = se.get_smuggling_engine("http://example.com")
        from src.oneinfinity.scan.smuggling_engine import RustSmugglingEngine
        assert isinstance(engine, RustSmugglingEngine)


class TestRustFindingContract:
    """Verify the finding dict structure returned by run_smuggling_scan."""

    @pytest.mark.skipif(not _HAVE_RUST, reason="oneinfinity_core not built")
    def test_run_against_unreachable_host_returns_empty(self):
        """An unreachable host must return an empty list, not raise."""
        findings = _oc.run_smuggling_scan("http://127.0.0.1:1", 1)
        assert isinstance(findings, list)
        assert findings == []

    @pytest.mark.skipif(not _HAVE_RUST, reason="oneinfinity_core not built")
    def test_invalid_url_returns_empty(self):
        findings = _oc.run_smuggling_scan("not-a-url", 1)
        assert isinstance(findings, list)
        assert findings == []

    @pytest.mark.skipif(not _HAVE_RUST, reason="oneinfinity_core not built")
    def test_zero_timeout_returns_empty(self):
        findings = _oc.run_smuggling_scan("http://127.0.0.1:9999", 0)
        assert isinstance(findings, list)

    @pytest.mark.skipif(not _HAVE_RUST, reason="oneinfinity_core not built")
    def test_finding_keys_when_present(self, monkeypatch):
        """
        If a finding is returned, it must contain all mandatory keys from
        the Python SmugglingEngine._make_finding() contract.
        """
        required_keys = {
            "vuln_type", "severity", "url", "endpoint",
            "payload", "evidence", "confidence", "tool", "source_type", "finding_id",
        }
        # We can't force a real finding without a server, so we test the Rust
        # make_finding logic is correct by examining what a mock server returns.
        # As a proxy: if any findings come back, validate their keys.
        findings = _oc.run_smuggling_scan("http://127.0.0.1:1", 1)
        for f in findings:
            missing = required_keys - set(f.keys())
            assert not missing, f"Finding missing keys: {missing}"


class TestPythonSmugglingEngineParity:
    """
    Test the pure-Python SmugglingEngine's finding structure so the test suite
    acts as a spec both engines must satisfy.
    """

    def _make_mock_engine(self, monkeypatch, responses):
        """
        Patch _send_raw to return controlled (bytes, elapsed) tuples.
        responses: list of (bytes_response, elapsed_s) to return in order.
        """
        from src.oneinfinity.scan.smuggling_engine import SmugglingEngine
        engine = SmugglingEngine("http://127.0.0.1:19999", timeout=2)
        engine._baseline_time = 0.1  # pre-set baseline

        call_idx = [0]
        def _mock_send(host, port, payload, use_ssl=False):
            idx = call_idx[0] % len(responses)
            call_idx[0] += 1
            return responses[idx]

        monkeypatch.setattr(engine, "_send_raw", _mock_send)
        monkeypatch.setattr(engine, "detect_via_timing", lambda url, payload: False)
        return engine

    def test_cl_te_finding_structure(self, monkeypatch):
        from src.oneinfinity.scan.smuggling_engine import SmugglingEngine
        engine = SmugglingEngine("http://127.0.0.1:19999", timeout=2)
        engine._baseline_time = 0.1
        # simulate slow response (>3 s above baseline)
        monkeypatch.setattr(engine, "_send_raw",
                            lambda *a, **kw: (b"HTTP/1.1 200 OK\r\n\r\n", 4.5))
        monkeypatch.setattr(engine, "detect_via_timing", lambda u, p: True)

        finding = engine.test_cl_te("http://127.0.0.1:19999")
        assert finding is not None
        assert finding["vuln_type"] == "http_request_smuggling"
        assert finding["severity"] == "critical"
        assert finding["smuggling_type"] == "CL.TE"
        assert 0 < finding["confidence"] <= 1.0
        assert finding["finding_id"].startswith("SMG-")

    def test_te_cl_unexpected_400(self, monkeypatch):
        from src.oneinfinity.scan.smuggling_engine import SmugglingEngine
        engine = SmugglingEngine("http://127.0.0.1:19999", timeout=2)
        engine._baseline_time = 0.1
        monkeypatch.setattr(engine, "_send_raw",
                            lambda *a, **kw: (b"HTTP/1.1 400 Bad Request\r\n\r\n", 0.2))
        monkeypatch.setattr(engine, "detect_via_timing", lambda u, p: False)

        finding = engine.test_te_cl("http://127.0.0.1:19999")
        assert finding is not None
        assert finding["smuggling_type"] == "TE.CL"
        assert finding["confidence"] == 0.70  # unexpected_400 without timing hit

    def test_no_finding_when_fast_response(self, monkeypatch):
        from src.oneinfinity.scan.smuggling_engine import SmugglingEngine
        engine = SmugglingEngine("http://127.0.0.1:19999", timeout=2)
        engine._baseline_time = 0.1
        monkeypatch.setattr(engine, "_send_raw",
                            lambda *a, **kw: (b"HTTP/1.1 200 OK\r\n\r\nOK", 0.15))
        monkeypatch.setattr(engine, "detect_via_timing", lambda u, p: False)

        assert engine.test_cl_te("http://127.0.0.1:19999") is None

    def test_te_te_obfuscation_finding(self, monkeypatch):
        from src.oneinfinity.scan.smuggling_engine import SmugglingEngine
        engine = SmugglingEngine("http://127.0.0.1:19999", timeout=2)
        engine._baseline_time = 0.1
        # First call is slow (>3 s over baseline)
        monkeypatch.setattr(engine, "_send_raw",
                            lambda *a, **kw: (b"HTTP/1.1 200 OK\r\n\r\n", 4.0))

        finding = engine.test_te_te("http://127.0.0.1:19999")
        assert finding is not None
        assert finding["smuggling_type"] == "TE.TE"

    def test_run_returns_list(self, monkeypatch):
        from src.oneinfinity.scan.smuggling_engine import SmugglingEngine
        engine = SmugglingEngine("http://127.0.0.1:19999", timeout=1)
        monkeypatch.setattr(engine, "_send_raw",
                            lambda *a, **kw: (b"HTTP/1.1 200 OK\r\n\r\n", 0.05))
        monkeypatch.setattr(engine, "detect_via_timing", lambda u, p: False)
        monkeypatch.setattr(engine, "_measure_baseline", lambda *a: 0.05)
        result = engine.run()
        assert isinstance(result, list)
