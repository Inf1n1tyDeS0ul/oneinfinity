# tests/test_schema.py
import pathlib

SCHEMA = pathlib.Path("/home/devendra-yadav/oneinfinity/db/schema.sql").read_text()

def test_scans_table_exists():
    assert "CREATE TABLE" in SCHEMA and "scans" in SCHEMA

def test_findings_table_exists():
    assert "findings" in SCHEMA

def test_findings_has_required_columns():
    for col in ("finding_id", "scan_id", "severity", "data"):
        assert col in SCHEMA, f"Missing column: {col}"

def test_knowledge_base_table_exists():
    assert "knowledge_base" in SCHEMA

def test_all_tables_present():
    for table in ("scans", "findings", "agents", "events", "knowledge_base", "recon_assets"):
        assert table in SCHEMA, f"Missing table: {table}"
