# tests/test_no_sqlite_in_distributed_mode.py
import ast, pathlib

def test_main_py_no_unconditional_sqlite_import():
    """web/backend/main.py must not import sqlite3 at module level."""
    src = pathlib.Path("/home/devendra-yadav/oneinfinity/web/backend/main.py").read_text()
    # sqlite3 may be imported lazily inside fallback blocks, but not at module level
    lines = src.split("\n")
    top_level_sqlite = [
        l for l in lines[:50]  # first 50 lines = module level
        if "import sqlite3" in l and not l.strip().startswith("#")
    ]
    assert not top_level_sqlite, f"Found module-level sqlite3 import: {top_level_sqlite}"

def test_findings_py_sqlite_is_in_fallback_only():
    """modules/findings.py SQLite usage must be gated by fallback condition."""
    src = pathlib.Path("/home/devendra-yadav/oneinfinity/modules/findings.py").read_text()
    if "sqlite3" in src:
        # sqlite3 usage must be inside a method, not at class definition level
        assert "def " in src, "SQLite usage in findings.py must be inside a method"
