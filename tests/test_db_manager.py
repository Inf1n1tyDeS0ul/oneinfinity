# tests/test_db_manager.py
import asyncio, os
from unittest.mock import patch, AsyncMock, MagicMock

def test_db_manager_mode_distributed_when_both_available():
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379", "POSTGRES_URL": "postgresql://localhost/test"}):
        with patch("oneinfinity.core.pg_client.get_async_pool", new_callable=AsyncMock) as mock_pg:
            mock_pg.return_value = MagicMock()  # non-None = available
            with patch("oneinfinity.core.redis_client.get_redis", return_value=MagicMock()):
                from oneinfinity.core import db_manager as dm
                dm._manager = None
                mgr = asyncio.run(dm.get_db_manager())
                assert mgr.mode in ("distributed", "postgres")

def test_db_manager_mode_sqlite_when_no_postgres():
    with patch.dict(os.environ, {}, clear=True):
        with patch("oneinfinity.core.pg_client.get_async_pool", new_callable=AsyncMock) as mock_pg:
            mock_pg.return_value = None
            from oneinfinity.core import db_manager as dm
            dm._manager = None
            mgr = asyncio.run(dm.get_db_manager())
            assert mgr.mode == "sqlite"

def test_sync_save_finding_does_not_raise(tmp_path):
    """sync_save_finding must not raise in SQLite mode."""
    with patch.dict(os.environ, {}, clear=True):
        with patch("oneinfinity.core.pg_client.get_async_pool", new_callable=AsyncMock) as mock_pg:
            mock_pg.return_value = None
            from oneinfinity.core import db_manager as dm
            dm._manager = None
            mgr = asyncio.run(dm.get_db_manager())
            finding = {
                "finding_id": "test-001", "scan_id": "scan-1",
                "target": "example.com", "title": "Test", "severity": "high",
                "vuln_type": "xss", "evidence": "proof", "tool": "test",
                "confidence": 0.9, "cvss": 7.5, "status": "new",
                "source_type": "tool", "created_at": "2026-01-01T00:00:00",
                "raw": {},
            }
            result = mgr.sync_save_finding(finding)
            assert result == finding["finding_id"]
