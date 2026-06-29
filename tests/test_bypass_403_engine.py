"""tests/test_bypass_403_engine.py — Unit tests for 403/401 bypass engine."""
from __future__ import annotations
import urllib.error
import pytest
from unittest.mock import patch, MagicMock


def _mock_urlopen(status_code: int, body: bytes = b""):
    """Return a context-manager mock mimicking urllib response/HTTPError."""
    if status_code >= 400:
        exc = urllib.error.HTTPError(
            url="https://example.com/x",
            code=status_code,
            msg="Forbidden",
            hdrs=MagicMock(),
            fp=MagicMock(read=lambda n=None: body),
        )
        return MagicMock(side_effect=exc)
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.status = status_code
    resp.read = lambda n=None: body
    resp.headers = {}
    return MagicMock(return_value=resp)


def test_bypass_engine_imports():
    from oneinfinity.attack.bypass_403_engine import Bypass403Engine
    engine = Bypass403Engine(timeout=5)
    assert engine is not None


def test_bypass_report_structure():
    """test() always returns a BypassReport with the expected fields."""
    from oneinfinity.attack.bypass_403_engine import Bypass403Engine
    with patch("urllib.request.urlopen", _mock_urlopen(403)):
        report = Bypass403Engine(timeout=2).test("https://example.com/admin")
    assert report is not None
    assert hasattr(report, "bypasses_found")
    assert hasattr(report, "findings")
    assert hasattr(report, "elapsed_s")


def test_no_bypass_when_all_403():
    """When all probes return 403, bypasses_found == 0."""
    from oneinfinity.attack.bypass_403_engine import Bypass403Engine
    with patch("urllib.request.urlopen", _mock_urlopen(403)):
        report = Bypass403Engine(timeout=2).test("https://example.com/secure")
    assert report.bypasses_found == 0


def test_bypass_engine_handles_network_error():
    """Network errors on probes should not crash the engine."""
    from oneinfinity.attack.bypass_403_engine import Bypass403Engine
    with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
        report = Bypass403Engine(timeout=1).test("https://example.com/slow")
    assert report is not None
    assert report.bypasses_found == 0


def test_bypass_findings_list_non_empty():
    """findings list always has entries (one per technique attempted)."""
    from oneinfinity.attack.bypass_403_engine import Bypass403Engine
    with patch("urllib.request.urlopen", _mock_urlopen(403)):
        report = Bypass403Engine(timeout=2).test("https://example.com/x")
    assert len(report.findings) > 0


def test_bypass_found_when_techniques_return_200():
    """Baseline 403, techniques return 200 → bypasses_found > 0."""
    import urllib.request
    from oneinfinity.attack.bypass_403_engine import Bypass403Engine

    call_count = {"n": 0}

    def _side_effect(req, timeout=10, context=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # First call (baseline) → 403
            exc = urllib.error.HTTPError(
                url="", code=403, msg="Forbidden",
                hdrs=MagicMock(), fp=MagicMock(read=lambda n=None: b""),
            )
            raise exc
        # All technique probes → 200 with body larger than baseline
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        resp.status = 200
        resp.read = lambda n=None: b"X" * 2000
        return resp

    with patch("urllib.request.urlopen", side_effect=_side_effect):
        report = Bypass403Engine(timeout=2).test("https://example.com/secret")
    assert report.bypasses_found > 0
