import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import MagicMock, patch, call


def _make_neo4j_engine(connected=True):
    """Build Neo4jEngine with a fully-mocked driver (no real Neo4j needed)."""
    from core.neo4j_engine import Neo4jEngine
    eng = Neo4jEngine.__new__(Neo4jEngine)
    eng._uri = "bolt://localhost:7687"
    eng._auth = ("neo4j", "test")
    eng._database = "neo4j"
    eng._connected = connected
    mock_driver = MagicMock()
    eng._driver = mock_driver if connected else None
    return eng, mock_driver


def test_bootstrap_schema_runs_all_three_statements():
    """bootstrap_schema must issue CONSTRAINT + 2 INDEX statements."""
    eng, driver = _make_neo4j_engine()
    mock_sess = MagicMock()
    driver.session.return_value.__enter__ = lambda s: mock_sess
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    eng.bootstrap_schema()

    calls = [str(c) for c in mock_sess.run.call_args_list]
    assert any("CONSTRAINT" in c for c in calls), "CONSTRAINT statement missing"
    assert any("INDEX" in c and "n.type" in c for c in calls), "node type INDEX missing"
    assert any("INDEX" in c and "r.type" in c for c in calls), "rel type INDEX missing"


def test_bootstrap_schema_noop_when_disconnected():
    """bootstrap_schema must be safe to call when driver is None."""
    eng, _ = _make_neo4j_engine(connected=False)
    eng.bootstrap_schema()  # should not raise
