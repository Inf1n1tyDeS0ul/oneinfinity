# tests/test_ingestion_engine_pg.py
import asyncio, os
from unittest.mock import patch, AsyncMock, MagicMock

def test_ingest_delegates_to_db_manager_save_finding():
    """ResultIngestionEngine.ingest() must call sync_check_and_save_finding in Postgres mode."""
    saved = []

    mock_mgr = MagicMock()
    mock_mgr.mode = "postgres"
    mock_mgr.sync_check_and_save_finding = lambda f: saved.append(f) or True

    with patch("result_ingestion_engine._get_db_manager_sync", return_value=mock_mgr):
        from result_ingestion_engine import ResultIngestionEngine, RawResult
        engine = ResultIngestionEngine()
        raw = RawResult(scan_id="scan-1", source="nuclei", raw={
            "template-id": "xss-001", "info": {"severity": "high"},
            "matched-at": "http://example.com/test", "host": "example.com",
        })
        engine.ingest(raw)
        assert len(saved) == 1, "sync_check_and_save_finding must have been called exactly once"

def test_ingest_falls_back_to_sqlite_when_no_pg():
    """ResultIngestionEngine.ingest() must fall back to SQLite when Postgres unavailable."""
    with patch.dict(os.environ, {}, clear=True):
        from result_ingestion_engine import ResultIngestionEngine, RawResult
        engine = ResultIngestionEngine()
        raw = RawResult(scan_id="scan-1", source="nuclei", raw={
            "template-id": "test-001", "info": {"severity": "low"},
            "matched-at": "http://localhost/test", "host": "localhost",
        })
        # Must not raise
        engine.ingest(raw)
