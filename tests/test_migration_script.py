# tests/test_migration_script.py
import sqlite3, tempfile, pathlib, os

def _make_test_sqlite(path: pathlib.Path) -> None:
    """Create a minimal findings.db for testing."""
    conn = sqlite3.connect(str(path))
    conn.execute("""
        CREATE TABLE findings (
            finding_id TEXT PRIMARY KEY, scan_id TEXT, target TEXT, title TEXT,
            severity TEXT, vuln_type TEXT, evidence TEXT, payload TEXT, url TEXT,
            tool TEXT, confidence REAL, cvss REAL, status TEXT, source_type TEXT,
            created_at TEXT, raw_json TEXT
        )
    """)
    conn.execute("""
        INSERT INTO findings VALUES
        ('f-001','scan-1','example.com','Test XSS','high','xss','proof','<script>','http://example.com',
         'dalfox',0.9,7.5,'new','tool','2026-01-01T00:00:00','{}')
    """)
    conn.execute("""
        CREATE TABLE recon_assets (
            asset_id TEXT PRIMARY KEY, scan_id TEXT, asset_type TEXT,
            value TEXT, metadata_json TEXT, created_at TEXT
        )
    """)
    conn.execute("INSERT INTO recon_assets VALUES ('a-001','scan-1','subdomain','sub.example.com','{}','2026-01-01T00:00:00')")
    conn.commit()
    conn.close()


def test_migrate_extracts_findings():
    """Migration script must extract all rows from SQLite findings table."""
    from scripts.migrate_sqlite_to_pg import extract_findings
    with tempfile.TemporaryDirectory() as tmp:
        db_path = pathlib.Path(tmp) / "findings.db"
        _make_test_sqlite(db_path)
        rows = extract_findings(str(db_path))
        assert len(rows) == 1
        assert rows[0]["finding_id"] == "f-001"
        assert rows[0]["severity"] == "high"


def test_migrate_transforms_finding_to_pg_schema():
    """transform_finding must produce Postgres-compatible dict."""
    from scripts.migrate_sqlite_to_pg import transform_finding
    sqlite_row = {
        "finding_id": "f-001", "scan_id": "scan-1", "target": "example.com",
        "title": "XSS", "severity": "high", "vuln_type": "xss",
        "evidence": "proof", "payload": "<script>", "url": "http://example.com",
        "tool": "dalfox", "confidence": 0.9, "cvss": 7.5,
        "status": "new", "source_type": "tool",
        "created_at": "2026-01-01T00:00:00", "raw_json": "{}",
    }
    pg_row = transform_finding(sqlite_row)
    assert pg_row["finding_id"] == "f-001"
    assert "data" in pg_row
    import json
    data = json.loads(pg_row["data"])
    assert "evidence" in data


def test_migration_aborts_safely_on_pg_failure():
    """If Postgres insert fails, migration must raise and leave Postgres untouched."""
    from unittest.mock import patch, MagicMock
    from scripts.migrate_sqlite_to_pg import run_migration

    mock_conn = MagicMock()
    mock_conn.__enter__ = MagicMock(return_value=mock_conn)
    mock_conn.__exit__ = MagicMock(return_value=False)
    mock_conn.execute = MagicMock(side_effect=Exception("simulated PG failure"))

    with patch("psycopg.connect", return_value=mock_conn):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(pathlib.Path(tmp) / "findings.db")
            conn = sqlite3.connect(db_path)
            conn.execute(
                "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, scan_id TEXT, target TEXT,"
                "title TEXT, severity TEXT, vuln_type TEXT, evidence TEXT, payload TEXT,"
                "url TEXT, tool TEXT, confidence REAL, cvss REAL, status TEXT,"
                "source_type TEXT, created_at TEXT, raw_json TEXT)"
            )
            conn.commit()
            conn.close()

            try:
                run_migration(postgres_url="postgresql://localhost/test", sqlite_paths={"findings": db_path})
                raised = False
            except Exception:
                raised = True

            assert raised, "Migration must raise on PG failure"
