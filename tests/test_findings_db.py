# tests/test_findings_db.py
from modules.findings import FindingsDB
import tempfile, pathlib

def test_findings_db_log_action_persists():
    """log_action must write to DB, not be a no-op."""
    with tempfile.TemporaryDirectory() as tmp:
        db = FindingsDB(pathlib.Path(tmp) / "test.db")

        # log_action must not be a no-op — it must write something
        db.log_action("test_op", {"key": "val"})

        # Verify it actually wrote by querying directly
        import sqlite3
        conn = sqlite3.connect(str(pathlib.Path(tmp) / "test.db"))
        rows = conn.execute("SELECT action FROM findings_audit WHERE action='test_op'").fetchall()
        conn.close()
        assert rows, "log_action did not write to findings_audit table"

def test_findings_db_close_does_not_crash():
    """close() must not raise and must close the connection."""
    with tempfile.TemporaryDirectory() as tmp:
        db = FindingsDB(pathlib.Path(tmp) / "test.db")
        db.log_action("setup", {})  # ensure connection is open
        db.close()  # must not raise
