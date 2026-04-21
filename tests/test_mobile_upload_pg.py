"""
tests/test_mobile_upload_pg.py
==============================
Tests for MobileUploadManager PG-only migration.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_pg_mgr():
    """Return a MagicMock that looks like DBManager in postgres mode."""
    mgr = MagicMock()
    mgr.mode = "postgres"
    mgr.sync_pg_execute_write.return_value = 1
    mgr.sync_pg_execute_read.return_value = []
    return mgr


# ── tests ─────────────────────────────────────────────────────────────────────

class TestMobileUploadManagerPG:

    # ── Test 1: save() calls sync_pg_execute_write with mobile_apps SQL ──────

    def test_save_calls_pg_execute_write(self):
        mgr = _make_pg_mgr()

        from oneinfinity.mobile.upload_manager import MobileApp, MobileUploadManager
        app = MobileApp(
            id="testapp001",
            filename="sample.apk",
            platform="android",
            package_name="com.example.test",
            app_name="Test App",
            version_name="1.0.0",
            version_code="1",
        )

        with patch("oneinfinity.mobile.upload_manager._require_pg", return_value=mgr):
            manager = MobileUploadManager()
            manager._store(app)

        mgr.sync_pg_execute_write.assert_called_once()
        call_args = mgr.sync_pg_execute_write.call_args
        sql: str = call_args[0][0]
        params = call_args[0][1]
        assert "mobile_apps" in sql, f"SQL does not mention mobile_apps: {sql!r}"
        assert "INSERT INTO" in sql.upper(), f"Expected INSERT in SQL: {sql!r}"
        assert "ON CONFLICT" in sql.upper(), f"Expected ON CONFLICT in SQL: {sql!r}"
        assert "testapp001" in params, f"Expected app id in params: {params!r}"

    # ── Test 2: list_apps() calls sync_pg_execute_read ────────────────────────

    def test_list_calls_pg_execute_read(self):
        mgr = _make_pg_mgr()

        with patch("oneinfinity.mobile.upload_manager._require_pg", return_value=mgr):
            from oneinfinity.mobile.upload_manager import MobileUploadManager
            manager = MobileUploadManager()
            result = manager.list_apps(platform="android", limit=25)

        mgr.sync_pg_execute_read.assert_called_once()
        call_args = mgr.sync_pg_execute_read.call_args
        sql: str = call_args[0][0]
        params = call_args[0][1]
        assert "mobile_apps" in sql, f"SQL does not mention mobile_apps: {sql!r}"
        assert "platform" in sql, f"Expected platform filter in SQL: {sql!r}"
        assert "android" in params, f"Expected 'android' in params: {params!r}"
        assert 25 in params, f"Expected limit 25 in params: {params!r}"
        assert result == [], "Expected empty list (mocked empty read)"

    def test_list_no_filter_calls_pg_execute_read(self):
        mgr = _make_pg_mgr()

        with patch("oneinfinity.mobile.upload_manager._require_pg", return_value=mgr):
            from oneinfinity.mobile.upload_manager import MobileUploadManager
            manager = MobileUploadManager()
            result = manager.list_apps()

        mgr.sync_pg_execute_read.assert_called_once()
        call_args = mgr.sync_pg_execute_read.call_args
        sql: str = call_args[0][0]
        assert "mobile_apps" in sql
        assert result == []

    # ── Test 3: update_status() calls sync_pg_execute_write with UPDATE ───────

    def test_update_status_calls_pg_execute_write(self):
        mgr = _make_pg_mgr()

        with patch("oneinfinity.mobile.upload_manager._require_pg", return_value=mgr):
            from oneinfinity.mobile.upload_manager import MobileUploadManager
            manager = MobileUploadManager()
            manager.update_status("testapp001", "done")

        mgr.sync_pg_execute_write.assert_called_once()
        call_args = mgr.sync_pg_execute_write.call_args
        sql: str = call_args[0][0]
        params = call_args[0][1]
        assert "UPDATE MOBILE_APPS" in sql.upper(), f"Expected UPDATE mobile_apps in SQL: {sql!r}"
        assert "analysis_status" in sql, f"Expected analysis_status in SQL: {sql!r}"
        assert "done" in params, f"Expected status 'done' in params: {params!r}"
        assert "testapp001" in params, f"Expected app_id in params: {params!r}"

    # ── Test 4: get() calls sync_pg_execute_read and reconstructs MobileApp ───

    def test_get_calls_pg_execute_read(self):
        mgr = _make_pg_mgr()
        fake_row = {
            "id": "testapp001",
            "filename": "sample.apk",
            "platform": "android",
            "package_name": "com.example.test",
            "app_name": "Test App",
            "version_name": "1.0.0",
            "version_code": "1",
            "min_sdk": "21",
            "target_sdk": "33",
            "file_size": 1024,
            "sha256": "abc123",
            "upload_path": "/tmp/sample.apk",
            "extract_path": "/tmp/extract",
            "uploaded_at": "2026-04-08T10:00:00",
            "analysis_status": "done",
            "metadata": "{}",
        }
        mgr.sync_pg_execute_read.return_value = [fake_row]

        with patch("oneinfinity.mobile.upload_manager._require_pg", return_value=mgr):
            from oneinfinity.mobile.upload_manager import MobileUploadManager
            manager = MobileUploadManager()
            app = manager.get("testapp001")

        mgr.sync_pg_execute_read.assert_called_once()
        call_args = mgr.sync_pg_execute_read.call_args
        sql: str = call_args[0][0]
        params = call_args[0][1]
        assert "mobile_apps" in sql
        assert "id" in sql
        assert "testapp001" in params

        assert app is not None
        assert app.id == "testapp001"
        assert app.platform == "android"
        assert app.analysis_status == "done"

    def test_get_returns_none_when_not_found(self):
        mgr = _make_pg_mgr()
        mgr.sync_pg_execute_read.return_value = []

        with patch("oneinfinity.mobile.upload_manager._require_pg", return_value=mgr):
            from oneinfinity.mobile.upload_manager import MobileUploadManager
            manager = MobileUploadManager()
            app = manager.get("nonexistent")

        assert app is None

    # ── Test 5: RuntimeError when PG unavailable ──────────────────────────────

    def test_update_status_raises_when_pg_unavailable(self):
        """When PG is unavailable, update_status must raise RuntimeError."""
        with patch("oneinfinity.mobile.upload_manager._require_pg",
                   side_effect=RuntimeError("PostgreSQL is required")):
            from oneinfinity.mobile.upload_manager import MobileUploadManager
            manager = MobileUploadManager()
            try:
                manager.update_status("fallback01", "done")
                assert False, "Expected RuntimeError"
            except RuntimeError as exc:
                assert "PostgreSQL" in str(exc)
