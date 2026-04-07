"""Verify that db/schema.sql contains all 5 learning table definitions."""
from pathlib import Path


def _schema():
    return Path("db/schema.sql").read_text()


def test_learning_scan_sessions_table_present():
    assert "CREATE TABLE IF NOT EXISTS learning_scan_sessions" in _schema()


def test_learning_findings_table_present():
    assert "CREATE TABLE IF NOT EXISTS learning_findings" in _schema()


def test_tool_performance_table_present():
    assert "CREATE TABLE IF NOT EXISTS tool_performance" in _schema()


def test_target_profiles_table_present():
    assert "CREATE TABLE IF NOT EXISTS target_profiles" in _schema()


def test_pattern_library_table_present():
    assert "CREATE TABLE IF NOT EXISTS pattern_library" in _schema()
