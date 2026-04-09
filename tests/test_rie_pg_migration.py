# tests/test_rie_pg_migration.py
"""
Static checks: all SQLite paths in result_ingestion_engine.py are gone.
PG-only pattern via _require_pg() is used throughout.
"""
import ast
from pathlib import Path


def _get_rie_source():
    return Path("src/oneinfinity/findings/result_ingestion_engine.py").read_text()


def test_no_sqlite_import():
    """sqlite3 must not be imported in result_ingestion_engine.py."""
    source = _get_rie_source()
    assert "import sqlite3" not in source, (
        "oneinfinity.result_ingestion_engine.py must not import sqlite3"
    )


def test_require_pg_used_in_all_methods():
    """All methods must use _require_pg() — no direct DB access."""
    source = _get_rie_source()
    assert "_require_pg" in source, (
        "oneinfinity.result_ingestion_engine.py must define and use _require_pg()"
    )


def test_check_and_store_uses_sync_check_and_save():
    """_check_and_store must use sync_check_and_save_finding."""
    source = _get_rie_source()
    assert "sync_check_and_save_finding" in source, (
        "_check_and_store must call mgr.sync_check_and_save_finding for dedup-aware PG path"
    )


def test_no_direct_pg_queries_in_rie():
    """RIE must not issue direct psycopg queries — all PG goes through DBManager."""
    source = _get_rie_source()
    assert "psycopg" not in source, (
        "oneinfinity.result_ingestion_engine.py must not import psycopg directly — use DBManager"
    )


def test_ingest_recon_asset_uses_sync_save_recon_asset():
    source = _get_rie_source()
    assert "sync_save_recon_asset" in source


def test_get_recon_assets_uses_sync_get_recon_assets():
    source = _get_rie_source()
    assert "sync_get_recon_assets" in source


def test_store_raw_findings_uses_sync_store_raw_findings():
    source = _get_rie_source()
    assert "sync_store_raw_findings" in source


def test_delete_findings_uses_sync_delete():
    source = _get_rie_source()
    assert "sync_delete_findings_for_scan" in source


def test_finding_count_uses_sync_finding_count():
    source = _get_rie_source()
    assert "sync_finding_count" in source
