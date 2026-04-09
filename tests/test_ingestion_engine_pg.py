# tests/test_ingestion_engine_pg.py
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, "/home/devendra-yadav/oneinfinity")


def test_ingest_delegates_to_db_manager_save_finding():
    """ResultIngestionEngine.ingest() must call sync_check_and_save_finding in Postgres mode."""
    saved = []

    mock_mgr = MagicMock()
    mock_mgr.mode = "postgres"
    mock_mgr.sync_check_and_save_finding = lambda f: saved.append(f) or True

    with patch("result_ingestion_engine._require_pg", return_value=mock_mgr):
        from result_ingestion_engine import ResultIngestionEngine, RawResult
        engine = ResultIngestionEngine()
        raw = RawResult(scan_id="scan-1", source="nuclei", raw={
            "template-id": "xss-001", "info": {"severity": "high"},
            "matched-at": "http://example.com/test", "host": "example.com",
        })
        engine.ingest(raw)
        assert len(saved) == 1, "sync_check_and_save_finding must have been called exactly once"


def test_ingest_raises_when_pg_unavailable():
    """ResultIngestionEngine.ingest() must catch RuntimeError when PG is unavailable."""
    with patch("result_ingestion_engine._require_pg",
               side_effect=RuntimeError("PostgreSQL is required")):
        from result_ingestion_engine import ResultIngestionEngine, RawResult
        engine = ResultIngestionEngine()
        raw = RawResult(scan_id="scan-1", source="nuclei", raw={
            "template-id": "test-001", "info": {"severity": "low"},
            "matched-at": "http://localhost/test", "host": "localhost",
        })
        # ingest() catches DB errors and returns None — does not propagate
        result = engine.ingest(raw)
        assert result is None
