# tests/test_rie_pg_paths.py
"""Verify RIE routes all methods through DBManager when in PG mode."""
import pytest
from unittest.mock import MagicMock, patch


def make_pg_mgr(mode="postgres"):
    """Return a mock DBManager in PG mode."""
    mgr = MagicMock()
    mgr.mode = mode
    return mgr


# ── _check_and_store ──────────────────────────────────────────────────────────

def test_check_and_store_uses_pg_when_available():
    """In PG mode, _check_and_store delegates to mgr.sync_check_and_save_finding."""
    from result_ingestion_engine import NormalizedFinding
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_check_and_save_finding.return_value = True

    finding = NormalizedFinding(
        scan_id="s1", target="example.com", title="XSS",
        severity="high", vuln_type="xss", evidence="poc",
        tool="dalfox", url="https://example.com/q",
    )

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        result = engine._check_and_store(finding)

    assert result is True
    mock_mgr.sync_check_and_save_finding.assert_called_once()


def test_check_and_store_returns_false_for_duplicate():
    """In PG mode, _check_and_store returns False when DBManager signals duplicate."""
    from result_ingestion_engine import NormalizedFinding
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_check_and_save_finding.return_value = False

    finding = NormalizedFinding(
        scan_id="s1", target="example.com", title="XSS",
        severity="high", vuln_type="xss", evidence="poc",
        tool="dalfox", url="https://example.com/q",
    )

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        result = engine._check_and_store(finding)

    assert result is False


# ── get_findings ──────────────────────────────────────────────────────────────

def test_get_findings_uses_pg_when_available():
    """In PG mode, get_findings delegates to mgr.sync_get_findings."""
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_get_findings.return_value = [{"finding_id": "f1", "vuln_type": "xss"}]

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        results = engine.get_findings(scan_id="scan1")

    assert len(results) == 1
    assert results[0]["finding_id"] == "f1"
    mock_mgr.sync_get_findings.assert_called_once_with(scan_id="scan1", target=None, severity=None)


# ── ingest_recon_asset ────────────────────────────────────────────────────────

def test_ingest_recon_asset_uses_pg_when_available():
    """In PG mode, ingest_recon_asset delegates to mgr.sync_save_recon_asset."""
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
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
    import result_ingestion_engine as rie

    mock_mgr = make_pg_mgr()
    mock_mgr.sync_get_recon_assets.return_value = [{"asset_id": "a1", "value": "sub.example.com"}]

    engine = rie.ResultIngestionEngine.__new__(rie.ResultIngestionEngine)
    engine._db_path = "/tmp/fake.db"
    engine._lock = __import__("threading").Lock()
    engine._broadcast_cb = None

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        results = engine.get_recon_assets(scan_id="scan1", asset_type="subdomain")

    assert len(results) == 1
    mock_mgr.sync_get_recon_assets.assert_called_once_with(scan_id="scan1", asset_type="subdomain")
