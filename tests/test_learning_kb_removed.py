# tests/test_learning_kb_removed.py
"""
Static checks: KnowledgeBase and sqlite3 are fully gone from the learning module.
These tests fail before deletion and pass after.
"""
import ast
from pathlib import Path


def test_knowledge_base_file_is_deleted():
    assert not Path("learning/knowledge_base.py").exists(), (
        "learning/knowledge_base.py must be deleted"
    )


def test_learning_init_does_not_import_knowledge_base():
    source = Path("learning/__init__.py").read_text()
    assert "KnowledgeBase" not in source, (
        "learning/__init__.py must not import or export KnowledgeBase"
    )


def test_no_sqlite3_import_in_learning_module():
    """No file under learning/ (except backfill.py which reads the main findings DB) may import sqlite3."""
    learning_dir = Path("learning")
    for py_file in learning_dir.glob("*.py"):
        if py_file.name == "backfill.py":
            continue  # backfill.py reads main findings.db as a fallback — sqlite3 is intentional
        source = py_file.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "sqlite3", (
                        f"sqlite3 must not be imported in {py_file}"
                    )
            if isinstance(node, ast.ImportFrom):
                assert node.module != "sqlite3", (
                    f"sqlite3 must not be imported in {py_file}"
                )


def test_no_raw_conn_access_in_main():
    """web/backend/main.py must not use kb._conn (raw SQLite access)."""
    source = Path("web/backend/main.py").read_text()
    assert "kb._conn" not in source, (
        "web/backend/main.py must not access kb._conn directly"
    )
    assert "knowledge_base.py" not in source, (
        "web/backend/main.py must not reference learning/knowledge_base.py"
    )
