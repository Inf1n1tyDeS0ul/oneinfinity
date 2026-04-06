"""Tests for DBManager scan persistence (SQLite mode)."""
import asyncio
import pytest
from pathlib import Path

@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "sqlite")
    monkeypatch.setattr("path_manager.db_path", lambda name: tmp_path / name)
    # Reset singleton
    import core.db_manager as dm
    dm._manager = None
    yield tmp_path
    dm._manager = None

def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

def test_save_scan_sqlite(tmp_db):
    import core.db_manager as dm
    dm._manager = None
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    assert mgr.mode == "sqlite"
    scan = {"id": "test-001", "target": "127.0.0.1", "scan_type": "full", "status": "queued"}
    sid = run(mgr.save_scan(scan))
    assert sid == "test-001"
    scans = run(mgr.load_scans())
    assert any(s["scan_id"] == "test-001" for s in scans)

def test_delete_scan_sqlite(tmp_db):
    import core.db_manager as dm
    dm._manager = None
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    scan = {"id": "del-001", "target": "127.0.0.1", "scan_type": "full", "status": "completed"}
    run(mgr.save_scan(scan))
    run(mgr.delete_scan("del-001"))
    scans = run(mgr.load_scans())
    assert not any(s["scan_id"] == "del-001" for s in scans)

def test_load_scans_marks_interrupted_running(tmp_db):
    import core.db_manager as dm
    dm._manager = None
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    scan = {"id": "int-001", "target": "10.0.0.1", "scan_type": "full", "status": "running"}
    run(mgr.save_scan(scan))
    # Simulate restart by resetting singleton
    dm._manager = None
    mgr2 = run(get_db_manager())
    scans = run(mgr2.load_scans())
    loaded = next(s for s in scans if s["scan_id"] == "int-001")
    assert loaded["status"] == "failed"
    assert "interrupted" in (loaded.get("error") or "").lower()

def test_findings_check_and_store_uses_dbmanager_sqlite(tmp_db, monkeypatch):
    """_check_and_store must call DBManager._sqlite_save_finding, not raw sqlite3 INSERT."""
    import core.db_manager as dm
    dm._manager = None

    calls = []
    original_sqlite_save = dm.DBManager._sqlite_save_finding

    def spy(self, finding):
        calls.append(finding.get("finding_id") or finding.get("id"))
        original_sqlite_save(self, finding)

    monkeypatch.setattr(dm.DBManager, "_sqlite_save_finding", spy)

    import sys
    sys.path.insert(0, "/home/devendra-yadav/oneinfinity")
    import result_ingestion_engine as rie

    # Reset singleton so it picks up our monkeypatched DBManager
    rie._engine = None

    engine = rie.get_ingestion_engine()
    # Force SQLite mode so DBManager won't try Postgres
    engine_mgr = dm.get_db_manager_sync()
    assert engine_mgr.mode == "sqlite"

    raw = rie.RawResult(
        scan_id="scan-spy-001",
        source="test",
        raw={
            "type": "xss",
            "url": "http://target.test/vuln",
            "title": "Reflected XSS",
            "severity": "high",
            "target": "target.test",
        },
    )
    engine.ingest(raw)
    assert len(calls) >= 1, f"_sqlite_save_finding was not called. Direct sqlite3 bypass is still in use."
    dm._manager = None
    rie._engine = None
