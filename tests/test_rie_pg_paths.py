# tests/test_rie_pg_paths.py
"""Verify RIE routes all methods through DBManager when in PG mode."""
import pytest
from unittest.mock import MagicMock, patch


def make_pg_mgr(mode="postgres"):
    """Return a mock DBManager in PG mode."""
    mgr = MagicMock()
    mgr.mode = mode
    return mgr


def _make_engine():
    import oneinfinity.findings.result_ingestion_engine as rie
    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._broadcast_cb = None
    return engine


# ── _check_and_store ──────────────────────────────────────────────────────────

def test_check_and_store_uses_pg_when_available():
    """In PG mode, _check_and_store delegates to mgr.sync_check_and_save_finding."""
    from oneinfinity.findings.result_ingestion_engine import NormalizedFinding
    import oneinfinity.findings.result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_check_and_save_finding.return_value = True

    finding = NormalizedFinding(
        scan_id="s1", target="example.com", title="XSS",
        severity="high", vuln_type="xss", evidence="poc",
        tool="dalfox", url="https://example.com/q",
    )

    engine = _make_engine()
    with patch("oneinfinity.findings.result_ingestion_engine._require_pg", return_value=mock_mgr):
        result = engine._check_and_store(finding)

    assert result is True
    mock_mgr.sync_check_and_save_finding.assert_called_once()


def test_check_and_store_returns_false_for_duplicate():
    """In PG mode, _check_and_store returns False when DBManager signals duplicate."""
    from oneinfinity.findings.result_ingestion_engine import NormalizedFinding
    import oneinfinity.findings.result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_check_and_save_finding.return_value = False

    finding = NormalizedFinding(
        scan_id="s1", target="example.com", title="XSS",
        severity="high", vuln_type="xss", evidence="poc",
        tool="dalfox", url="https://example.com/q",
    )

    engine = _make_engine()
    with patch("oneinfinity.findings.result_ingestion_engine._require_pg", return_value=mock_mgr):
        result = engine._check_and_store(finding)

    assert result is False


# ── get_findings ──────────────────────────────────────────────────────────────

def test_get_findings_uses_pg_when_available():
    """In PG mode, get_findings delegates to mgr.sync_get_findings."""
    import oneinfinity.findings.result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_get_findings.return_value = [{"finding_id": "f1", "vuln_type": "xss"}]

    engine = _make_engine()
    with patch("oneinfinity.findings.result_ingestion_engine._require_pg", return_value=mock_mgr):
        results = engine.get_findings(scan_id="scan1")

    assert len(results) == 1
    assert results[0]["finding_id"] == "f1"
    mock_mgr.sync_get_findings.assert_called_once_with(scan_id="scan1", target=None, severity=None)


# ── ingest_recon_asset ────────────────────────────────────────────────────────

def test_ingest_recon_asset_uses_pg_when_available():
    """In PG mode, ingest_recon_asset delegates to mgr.sync_save_recon_asset."""
    import oneinfinity.findings.result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()

    engine = _make_engine()
    with patch("oneinfinity.findings.result_ingestion_engine._require_pg", return_value=mock_mgr):
        engine.ingest_recon_asset("scan1", "subdomain", "sub.example.com", {"ip": "1.2.3.4"})

    mock_mgr.sync_save_recon_asset.assert_called_once()
    args = mock_mgr.sync_save_recon_asset.call_args[0]
    assert args[1] == "scan1"
    assert args[2] == "subdomain"
    assert args[3] == "sub.example.com"
    assert args[4] == {"ip": "1.2.3.4"}


# ── get_recon_assets ──────────────────────────────────────────────────────────

def test_get_recon_assets_uses_pg_when_available():
    """In PG mode, get_recon_assets delegates to mgr.sync_get_recon_assets."""
    import oneinfinity.findings.result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_get_recon_assets.return_value = [{"asset_id": "a1", "value": "sub.example.com"}]

    engine = _make_engine()
    with patch("oneinfinity.findings.result_ingestion_engine._require_pg", return_value=mock_mgr):
        results = engine.get_recon_assets(scan_id="scan1", asset_type="subdomain")

    assert len(results) == 1
    mock_mgr.sync_get_recon_assets.assert_called_once_with(scan_id="scan1", asset_type="subdomain")


# ── store_raw_findings ────────────────────────────────────────────────────────

def test_store_raw_findings_uses_pg_when_available():
    """In PG mode, store_raw_findings delegates to mgr.sync_store_raw_findings."""
    import oneinfinity.findings.result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_store_raw_findings.return_value = 2

    engine = _make_engine()
    findings = [{"tool": "nuclei"}, {"tool": "dalfox"}]
    with patch("oneinfinity.findings.result_ingestion_engine._require_pg", return_value=mock_mgr):
        count = engine.store_raw_findings(findings)

    assert count == 2
    mock_mgr.sync_store_raw_findings.assert_called_once_with(findings)


# ── delete_findings_for_scan ─────────────────────────────────────────────────

def test_delete_findings_for_scan_uses_pg_when_available():
    """In PG mode, delete_findings_for_scan delegates to mgr.sync_delete_findings_for_scan."""
    import oneinfinity.findings.result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_delete_findings_for_scan.return_value = 5

    engine = _make_engine()
    with patch("oneinfinity.findings.result_ingestion_engine._require_pg", return_value=mock_mgr):
        count = engine.delete_findings_for_scan("scan1")

    assert count == 5
    mock_mgr.sync_delete_findings_for_scan.assert_called_once_with("scan1")


# ── finding_count ─────────────────────────────────────────────────────────────

def test_finding_count_uses_pg_when_available():
    """In PG mode, finding_count delegates to mgr.sync_finding_count."""
    import oneinfinity.findings.result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_finding_count.return_value = 7

    engine = _make_engine()
    with patch("oneinfinity.findings.result_ingestion_engine._require_pg", return_value=mock_mgr):
        count = engine.finding_count("scan1")

    assert count == 7
    mock_mgr.sync_finding_count.assert_called_once_with("scan1")
