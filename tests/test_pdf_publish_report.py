"""Tests for PDF Publish Report feature — Reporter.render_to_buffer with sections filter."""
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.reporter import Reporter


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
