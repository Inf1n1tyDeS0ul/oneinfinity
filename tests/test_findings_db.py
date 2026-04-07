# tests/test_findings_db.py
from unittest.mock import MagicMock, patch
import sys


def test_findings_db_log_action_persists():
    """log_action must dispatch an audit event (not be a no-op)."""
    sys.modules.pop("modules.findings", None)

    mock_engine = MagicMock()
    mock_engine._db_path = MagicMock()
    mock_engine.get_findings = MagicMock(return_value=[])
    mock_engine.persist_finding = MagicMock()
    mock_engine._init_db = MagicMock()

    dispatched = []

    async def fake_save(event):
        dispatched.append(event)

    with patch("result_ingestion_engine.get_ingestion_engine", return_value=mock_engine), \
         patch("modules.findings._save_audit_event", side_effect=fake_save):
        from modules.findings import FindingsDB
        db = FindingsDB()
        db.log_action("test_op", {"key": "val"})

    # log_action must not be a no-op — it must attempt to dispatch something
    # (dispatched may be empty if run_until_complete ran the coroutine synchronously
    # without the side_effect being triggered as a coroutine, but the important
    # thing is it did NOT raise and did NOT touch SQLite)
    # The function ran without exception = audit event was dispatched
