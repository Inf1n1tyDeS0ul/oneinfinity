# tests/test_memory_manager_pg.py
"""Tests verifying MemoryManager routes writes/reads through _require_pg in PG-only mode."""
import sys
import os
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _make_pg_mgr():
    mgr = MagicMock()
    mgr.mode = "postgres"
    mgr.sync_pg_execute_write = MagicMock(return_value=1)
    mgr.sync_pg_execute_read = MagicMock(return_value=[])
    return mgr


def test_store_exploit_chain_calls_pg_execute_write(tmp_path):
    """store_exploit_chain() must call sync_pg_execute_write with exploit_chain_records SQL."""
    from oneinfinity.memory_manager import MemoryManager, ExploitChainRecord
    mock_mgr = _make_pg_mgr()

    with patch("oneinfinity.memory_manager._require_pg", return_value=mock_mgr):
        mm = MemoryManager()
        chain = ExploitChainRecord(
            chain_name="test-chain",
            steps=["sqli", "rce"],
            target="http://example.com",
        )
        mm.store_exploit_chain(chain)

    assert mock_mgr.sync_pg_execute_write.called, "sync_pg_execute_write should be called"
    sql = mock_mgr.sync_pg_execute_write.call_args[0][0]
    assert "exploit_chain_records" in sql, f"SQL should target exploit_chain_records, got: {sql!r}"


def test_get_patterns_calls_pg_execute_read(tmp_path):
    """get_patterns() must call sync_pg_execute_read with attack_patterns SQL in PG mode."""
    from oneinfinity.memory_manager import MemoryManager
    mock_mgr = _make_pg_mgr()

    with patch("oneinfinity.memory_manager._require_pg", return_value=mock_mgr):
        mm = MemoryManager()
        mm.get_patterns(vuln_type="xss", limit=10)

    assert mock_mgr.sync_pg_execute_read.called, "sync_pg_execute_read should be called"
    sql = mock_mgr.sync_pg_execute_read.call_args[0][0]
    assert "attack_patterns" in sql, f"SQL should target attack_patterns, got: {sql!r}"


def test_store_exploit_chain_raises_when_pg_unavailable(tmp_path):
    """When PG is unavailable, store_exploit_chain() must raise RuntimeError."""
    from oneinfinity.memory_manager import MemoryManager, ExploitChainRecord

    with patch("oneinfinity.memory_manager._require_pg",
               side_effect=RuntimeError("PostgreSQL is required")):
        mm = MemoryManager()
        chain = ExploitChainRecord(
            chain_name="fail-chain",
            steps=["xss"],
            target="http://localhost",
        )
        try:
            mm.store_exploit_chain(chain)
            assert False, "Expected RuntimeError"
        except RuntimeError as exc:
            assert "PostgreSQL" in str(exc)
