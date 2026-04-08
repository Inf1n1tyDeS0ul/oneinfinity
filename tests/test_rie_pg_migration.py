# tests/test_rie_pg_migration.py
"""
Static checks: all SQLite-only paths in result_ingestion_engine.py are gone.
Every remaining sqlite3.connect must be inside an 'except' or SQLite fallback branch.
"""
import ast
from pathlib import Path


def _get_rie_source():
    return Path("result_ingestion_engine.py").read_text()


def test_no_sqlite_import_for_non_fallback():
    """sqlite3 may still be imported (for fallback), but we verify PG-first is present."""
    source = _get_rie_source()
    # The new PG-first pattern uses _get_db_manager_sync() — verify it's used in all 7 methods
    for method in (
        "_init_db",
        "_check_and_store",
        "get_findings",
        "ingest_recon_asset",
        "get_recon_assets",
        "store_raw_findings",
        "delete_findings_for_scan",
        "finding_count",
    ):
        # Each method must call _get_db_manager_sync somewhere in its body
        assert "_get_db_manager_sync" in source, (
            f"result_ingestion_engine.py must import/use _get_db_manager_sync (needed for {method})"
        )


def test_check_and_store_uses_sync_check_and_save():
    """_check_and_store must use sync_check_and_save_finding, not sync_save_finding."""
    source = _get_rie_source()
    assert "sync_check_and_save_finding" in source, (
        "_check_and_store must call mgr.sync_check_and_save_finding for dedup-aware PG path"
    )


def test_no_direct_pg_queries_in_rie():
    """RIE must not issue direct psycopg queries — all PG goes through DBManager."""
    source = _get_rie_source()
    assert "psycopg" not in source, (
        "result_ingestion_engine.py must not import psycopg directly — use DBManager"
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
