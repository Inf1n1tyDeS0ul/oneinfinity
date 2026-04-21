# tests/test_main_targets.py
"""Tests for /api/targets endpoints after TargetDB removal."""
import os
os.environ["ONEINFINITY_API_KEY"] = ""

import ast
import pathlib
import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture
def mock_repo():
    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[
        {"target_id": "t1", "target_value": "example.com", "id": "t1",
         "domain": "example.com", "status": "pending", "target_type": "web",
         "name": "example.com", "platform": "hackerone", "scope": [],
         "created_at": "2026-04-07T00:00:00", "last_scan_time": None,
         "vuln_count": 0, "severity_counts": {}}
    ])
    repo.get = AsyncMock(return_value=None)
    repo.add = AsyncMock(return_value={
        "target_id": "new1", "target_value": "new.com", "id": "new1",
        "domain": "new.com", "status": "pending", "target_type": "web",
        "name": "new.com", "platform": "hackerone", "scope": [],
        "created_at": "2026-04-07T00:00:00", "last_scan_time": None,
        "vuln_count": 0, "severity_counts": {}
    })
    repo.delete = AsyncMock(return_value=True)
    return repo


def test_main_py_has_no_targetdb_class():
    """TargetDB class must be removed from main.py."""
    PROJECT_ROOT = pathlib.Path(__file__).parent.parent
    src = (PROJECT_ROOT / "web/backend/main.py").read_text()
    assert "class TargetDB" not in src, "TargetDB class must be removed from main.py"


def test_main_py_has_no_target_db_instantiation():
    """_target_db = TargetDB(...) must be removed from main.py."""
    PROJECT_ROOT = pathlib.Path(__file__).parent.parent
    src = (PROJECT_ROOT / "web/backend/main.py").read_text()
    assert "_target_db = TargetDB" not in src


def test_main_py_imports_target_repository():
    """main.py must import TargetRepository and get_target_repo."""
    PROJECT_ROOT = pathlib.Path(__file__).parent.parent
    src = (PROJECT_ROOT / "web/backend/main.py").read_text()
    assert "from oneinfinity.core.target_repository import" in src
    assert "TargetRepository" in src
    assert "get_target_repo" in src


def test_main_py_has_no_unconditional_sqlite_import():
    """main.py must not import sqlite3 at module level."""
    PROJECT_ROOT = pathlib.Path(__file__).parent.parent
    src = (PROJECT_ROOT / "web/backend/main.py").read_text()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name != "sqlite3", f"Found top-level sqlite3 import at line {node.lineno}"


def test_main_py_has_no_db_connect_function():
    """_db_connect helper must be removed from main.py."""
    PROJECT_ROOT = pathlib.Path(__file__).parent.parent
    src = (PROJECT_ROOT / "web/backend/main.py").read_text()
    assert "def _db_connect(" not in src


def test_main_py_has_startup_failfast():
    """_lifespan must contain the fail-fast RuntimeError check."""
    PROJECT_ROOT = pathlib.Path(__file__).parent.parent
    src = (PROJECT_ROOT / "web/backend/main.py").read_text()
    assert "PostgreSQL not available" in src
