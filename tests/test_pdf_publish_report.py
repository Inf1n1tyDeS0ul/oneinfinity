"""Tests for PDF Publish Report feature — Reporter.render_to_buffer with sections filter."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from oneinfinity.core.reporter import Reporter


def _make_reporter(tmp_dir):
    r = Reporter(output_dir=tmp_dir, target="https://example.com", platform="hackerone")
    r.add_finding({
        "vuln_type": "xss",
        "severity": "high",
        "endpoint": "https://example.com/search",
        "description": "Reflected XSS in search parameter",
        "evidence": "<script>alert(1)</script> reflected in response",
        "cvss": 7.5,
        "confidence": 0.9,
    })
    r.add_finding({
        "vuln_type": "sqli",
        "severity": "critical",
        "endpoint": "https://example.com/api/users",
        "description": "SQL injection in user lookup",
        "cvss": 9.1,
        "confidence": 0.95,
    })
    return r


def test_render_to_buffer_returns_pdf_bytes(tmp_path):
    r = _make_reporter(str(tmp_path))
    result = r.render_to_buffer()
    assert isinstance(result, bytes)
    assert result[:4] == b"%PDF", f"Expected PDF header, got {result[:4]!r}"


def test_render_to_buffer_with_exec_only(tmp_path):
    r = _make_reporter(str(tmp_path))
    result = r.render_to_buffer(sections=["exec"])
    assert result[:4] == b"%PDF"


def test_render_to_buffer_with_findings_only(tmp_path):
    r = _make_reporter(str(tmp_path))
    result = r.render_to_buffer(sections=["findings"])
    assert result[:4] == b"%PDF"


def test_render_to_buffer_all_sections(tmp_path):
    r = _make_reporter(str(tmp_path))
    r.set_meta("attack_chains", [
        {"chain": "xss → account_takeover", "cvss_uplift": "7.5 → 9.3", "description": "XSS leads to ATO via stolen session cookie"},
    ])
    r.set_meta("phases_complete", ["deep_recon", "vuln_scan", "active_testing", "auth_session"])
    r.set_meta("scan_duration_s", 3276)
    result = r.render_to_buffer(sections=["exec", "findings", "chains", "meta", "remediation"])
    assert result[:4] == b"%PDF"
    assert len(result) > 5000  # non-trivial PDF


def test_render_to_buffer_empty_sections_list(tmp_path):
    """Empty sections list → only cover page."""
    r = _make_reporter(str(tmp_path))
    result = r.render_to_buffer(sections=[])
    assert result[:4] == b"%PDF"


# ── Endpoint tests ─────────────────────────────────────────────────────────

def test_publish_endpoint_returns_pdf(tmp_path, monkeypatch):
    """POST /api/reports/publish returns application/pdf bytes."""
    import sys, os
    # Add backend and project root to path
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "backend"))
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    # Patch ingestion engine to return a test finding
    mock_finding = {
        "scan_id": "test-scan-1",
        "finding_id": "f001",
        "vuln_type": "xss",
        "severity": "high",
        "url": "https://test.example.com/search",
        "endpoint": "https://test.example.com/search",
        "description": "XSS in search",
        "cvss": 7.5,
        "confidence": 0.9,
        "source_type": "tool",
        "tool": "zap",
        "target": "test.example.com",
        "created_at": "2026-03-31T10:00:00",
        "raw": "{}",
    }

    class MockIngestion:
        def get_findings(self, scan_id=None, **kwargs):
            return [mock_finding]

    import oneinfinity.result_ingestion_engine as rie
    monkeypatch.setattr(rie, "get_ingestion_engine", lambda: MockIngestion())

    # Mock god mode state file
    import oneinfinity.god_mode_engine as gme
    class MockStateFile:
        def read(self):
            return {
                "scan_id": "test-scan-1",
                "target": "https://test.example.com",
                "status": "completed",
                "elapsed_seconds": 600,
                "phases_complete": ["deep_recon", "vuln_scan"],
                "finding_count": 1,
            }
    monkeypatch.setattr(gme, "GodModeStateFile", lambda scan_id: MockStateFile())

    from fastapi.testclient import TestClient
    import main as app_module
    # Disable auth for test
    monkeypatch.setattr(app_module, "_require_auth", lambda: None)
    client = TestClient(app_module.app)

    resp = client.post("/api/reports/publish", json={
        "scan_id": "test-scan-1",
        "sections": ["exec", "findings", "meta"],
    })
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
