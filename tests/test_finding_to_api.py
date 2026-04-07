# tests/test_finding_to_api.py
import os
os.environ["ONEINFINITY_API_KEY"] = ""

from web.backend.main import _finding_to_api


def test_finding_to_api_includes_scan_id():
    """_finding_to_api must pass scan_id through to the API dict."""
    raw = {
        "finding_id": "abc123",
        "title": "SQL Injection",
        "severity": "high",
        "target": "example.com",
        "scan_id": "gm-be922d",
    }
    result = _finding_to_api(raw)
    assert result["scan_id"] == "gm-be922d"


def test_finding_to_api_scan_id_defaults_to_empty_string():
    """_finding_to_api must return scan_id='' when the raw finding has none."""
    raw = {"finding_id": "xyz", "title": "XSS", "severity": "medium", "target": "t.com"}
    result = _finding_to_api(raw)
    assert result["scan_id"] == ""
