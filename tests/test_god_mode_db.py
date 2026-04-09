"""Test that GodModeStateFile.write() persists scan to DBManager first."""
import asyncio
import time
import pytest

def reset_mgr():
    import core.db_manager as dm
    dm._manager = None

def test_write_calls_dbmanager_sync_save_scan(tmp_path, monkeypatch):
    """write() must call DBManager.sync_save_scan with scan metadata."""
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "sqlite")
    monkeypatch.setattr("path_manager.db_path", lambda name: tmp_path / name)
    reset_mgr()

    import core.db_manager as dm
    saved = []

    def capture_save(self, scan):
        saved.append(dict(scan))

    monkeypatch.setattr(dm.DBManager, "sync_save_scan", capture_save)

    import sys
    from oneinfinity.god_mode_engine import GodModeStateFile, GodModeSession

    sf = GodModeStateFile.__new__(GodModeStateFile)
    sf.path = tmp_path / "god-mode-test.json"

    session = GodModeSession(
        scan_id="test-gm-001",
        target="http://test.local",
        start_time=time.time(),
        finding_count=3,
    )
    sf.write(session)

    assert len(saved) == 1, f"sync_save_scan was not called. Got: {saved}"
    assert saved[0]["scan_id"] == "test-gm-001"
    assert saved[0]["target"] == "http://test.local"
    reset_mgr()


def test_write_falls_back_to_json_when_dbmanager_fails(tmp_path, monkeypatch, caplog):
    """When DBManager raises, write() must fall back to JSON and log FALLBACK TRIGGERED."""
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "sqlite")
    monkeypatch.setattr("path_manager.db_path", lambda name: tmp_path / name)
    reset_mgr()

    import core.db_manager as dm

    def raise_error(self, scan):
        raise RuntimeError("DB unavailable")

    monkeypatch.setattr(dm.DBManager, "sync_save_scan", raise_error)

    import sys
    from oneinfinity.god_mode_engine import GodModeStateFile, GodModeSession
    import logging

    sf = GodModeStateFile.__new__(GodModeStateFile)
    sf.path = tmp_path / "god-mode-fallback.json"

    session = GodModeSession(
        scan_id="fallback-001",
        target="http://fallback.test",
        start_time=time.time(),
    )
    with caplog.at_level(logging.WARNING):
        sf.write(session)

    assert sf.path.exists(), "JSON fallback file was not written"
    assert "FALLBACK TRIGGERED" in caplog.text, f"Expected FALLBACK TRIGGERED in logs, got: {caplog.text}"
    reset_mgr()
