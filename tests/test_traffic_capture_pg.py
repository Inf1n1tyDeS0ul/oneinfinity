"""
tests/test_traffic_capture_pg.py
=================================
Tests for TrafficCaptureEngine PG-first migration.

Strategy: mock get_db_manager_sync() to return a fake DBManager in PG mode,
then verify the engine calls sync_pg_execute_write / sync_pg_execute_read
with SQL targeting captured_requests.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ── helpers ──────────────────────────────────────────────────────────────────

def _make_pg_mgr():
    """Return a MagicMock that looks like DBManager in postgres mode."""
    mgr = MagicMock()
    mgr.mode = "postgres"
    mgr.sync_pg_execute_write.return_value = 1
    mgr.sync_pg_execute_read.return_value = []
    return mgr


# ── tests ─────────────────────────────────────────────────────────────────────

class TestTrafficCapturePG:

    def _engine_with_pg(self, mgr):
        """Instantiate TrafficCaptureEngine with PG mgr injected, skipping SQLite _init_db."""
        with patch(
            "traffic_capture_engine.TrafficCaptureEngine._pg",
            return_value=mgr,
        ):
            from oneinfinity.traffic_capture_engine import TrafficCaptureEngine
            engine = TrafficCaptureEngine.__new__(TrafficCaptureEngine)
            import threading
            engine._local = threading.local()
            engine._lock = threading.Lock()
            engine._listeners = []
            # _init_db: PG mode returns early — simulate by doing nothing
            return engine

    # ── Test 1: store() calls sync_pg_execute_write with captured_requests SQL ──

    def test_store_calls_pg_execute_write(self):
        mgr = _make_pg_mgr()
        engine = self._engine_with_pg(mgr)

        from oneinfinity.traffic_capture_engine import CapturedRequest
        req = CapturedRequest(
            method="GET",
            url="http://example.com/test",
            source="test",
        )

        with patch.object(engine, "_pg", return_value=mgr):
            engine.store(req)

        mgr.sync_pg_execute_write.assert_called_once()
        call_args = mgr.sync_pg_execute_write.call_args
        sql: str = call_args[0][0]
        assert "captured_requests" in sql, f"SQL does not mention captured_requests: {sql!r}"
        assert "INSERT INTO" in sql.upper(), f"Expected INSERT in SQL: {sql!r}"
        assert "ON CONFLICT" in sql.upper(), f"Expected ON CONFLICT in SQL: {sql!r}"

    # ── Test 2: list() (get_all) calls sync_pg_execute_read ──────────────────

    def test_list_calls_pg_execute_read(self):
        mgr = _make_pg_mgr()
        engine = self._engine_with_pg(mgr)

        with patch.object(engine, "_pg", return_value=mgr):
            result = engine.list(source="recon", limit=10)

        mgr.sync_pg_execute_read.assert_called_once()
        call_args = mgr.sync_pg_execute_read.call_args
        sql: str = call_args[0][0]
        assert "captured_requests" in sql, f"SQL does not mention captured_requests: {sql!r}"
        assert "source" in sql, f"Expected source filter in SQL: {sql!r}"
        # params should contain "recon" and 10 (limit)
        params = call_args[0][1]
        assert "recon" in params, f"Expected 'recon' in params: {params!r}"
        assert result == [], "Expected empty list (mocked empty read)"

    # ── Test 3: get() calls sync_pg_execute_read with WHERE id clause ─────────

    def test_get_calls_pg_execute_read_by_id(self):
        mgr = _make_pg_mgr()
        # Return a row that can be reconstructed into a CapturedRequest
        fake_row = {
            "id": "abc123",
            "method": "POST",
            "url": "http://victim.com/api",
            "headers": "{}",
            "body": "",
            "response_status": 200,
            "response_headers": "{}",
            "response_body": "",
            "source": "scan",
            "target_domain": "victim.com",
            "proxied": False,
            "proxy_address": "",
            "timestamp": "2026-04-08T12:00:00",
            "duration_ms": 42,
            "tags": "[]",
            "vuln_id": "",
            "attack_type": "",
            "flagged": False,
            "flag_reason": "",
        }
        mgr.sync_pg_execute_read.return_value = [fake_row]

        engine = self._engine_with_pg(mgr)

        with patch.object(engine, "_pg", return_value=mgr):
            req = engine.get("abc123")

        mgr.sync_pg_execute_read.assert_called_once()
        call_args = mgr.sync_pg_execute_read.call_args
        sql: str = call_args[0][0]
        params = call_args[0][1]
        assert "captured_requests" in sql
        assert "id" in sql
        assert "abc123" in params

        assert req is not None
        assert req.id == "abc123"
        assert req.method == "POST"
        assert req.url == "http://victim.com/api"
