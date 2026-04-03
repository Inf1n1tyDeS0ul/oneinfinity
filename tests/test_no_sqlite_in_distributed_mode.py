# tests/test_no_sqlite_in_distributed_mode.py
import ast, pathlib


def _get_top_level_sqlite_imports(src: str) -> list:
    """Return list of top-level (module-scope) sqlite3 import statements."""
    tree = ast.parse(src)
    imports = []
    for node in tree.body:  # only top-level statements
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "sqlite3":
                    imports.append(f"line {node.lineno}: import sqlite3")
        elif isinstance(node, ast.ImportFrom):
            if node.module and "sqlite3" in node.module:
                imports.append(f"line {node.lineno}: from {node.module} import ...")
    return imports


def test_main_py_no_unconditional_sqlite_import():
    """web/backend/main.py must not import sqlite3 at module level."""
    src = pathlib.Path("/home/devendra-yadav/oneinfinity/web/backend/main.py").read_text()
    top_level = _get_top_level_sqlite_imports(src)
    assert not top_level, f"Found module-level sqlite3 import in main.py: {top_level}"


def test_findings_py_no_module_level_sqlite_import():
    """modules/findings.py must not import sqlite3 at module level (use lazy import)."""
    src = pathlib.Path("/home/devendra-yadav/oneinfinity/modules/findings.py").read_text()
    top_level = _get_top_level_sqlite_imports(src)
    assert not top_level, f"Found module-level sqlite3 import in findings.py: {top_level}"
