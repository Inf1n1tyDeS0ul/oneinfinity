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
