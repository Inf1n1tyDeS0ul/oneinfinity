"""Unit tests for Neo4jKnowledgeBase — Neo4j driver is mocked."""
from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest
from oneinfinity.learning.neo4j_knowledge_base import Neo4jKnowledgeBase


def _make_kb(available: bool = True) -> Neo4jKnowledgeBase:
    """Return a Neo4jKnowledgeBase with a mocked or absent driver."""
    kb = Neo4jKnowledgeBase.__new__(Neo4jKnowledgeBase)
    kb._available = available
    kb._database = "neo4j"
    if available:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)
        kb._driver = mock_driver
        kb._mock_session = mock_session
    else:
        kb._driver = None
    return kb


class TestNeo4jKnowledgeBaseUnavailable:
    """All methods must be no-ops when Neo4j is unavailable."""

    def test_record_finding_noop(self):
        kb = _make_kb(available=False)
        kb.record_finding("s1", {"vuln_type": "XSS", "target": "example.com"})  # must not raise

    def test_best_tool_for_vuln_returns_empty(self):
        kb = _make_kb(available=False)
        assert kb.best_tool_for_vuln("XSS") == []

    def test_get_target_profile_returns_none(self):
        kb = _make_kb(available=False)
        assert kb.get_target_profile("example.com") is None

    def test_patterns_for_tech_stack_returns_empty(self):
        kb = _make_kb(available=False)
        assert kb.patterns_for_tech_stack(["wordpress"]) == []

    def test_stats_returns_zeroed(self):
        kb = _make_kb(available=False)
        s = kb.stats()
        assert s["sessions"] == 0
        assert s["confirmed_findings"] == 0
        assert s["unique_targets"] == 0

    def test_start_session_noop(self):
        kb = _make_kb(available=False)
        result = kb.start_session("s1", "example.com")
        assert result == "s1"

    def test_record_tool_run_noop(self):
        kb = _make_kb(available=False)
        kb.record_tool_run("nuclei", "XSS")  # must not raise


class TestNeo4jKnowledgeBaseAvailable:
    """When available, methods must run Cypher via the driver session."""

    def test_record_finding_calls_session_run(self):
        kb = _make_kb(available=True)
        kb.record_finding("s1", {
            "vuln_type": "XSS", "target": "example.com",
            "severity": "high", "cvss_score": 7.5,
            "source_tool": "dalfox", "payload": "<script>",
        })
        assert kb._mock_session.run.called

    def test_upsert_target_profile_calls_session_run(self):
        kb = _make_kb(available=True)
        kb.upsert_target_profile("example.com", tech_stack=["nginx", "php"])
        assert kb._mock_session.run.called

    def test_upsert_pattern_calls_session_run(self):
        kb = _make_kb(available=True)
        kb.upsert_pattern(["wordpress"], "SQL Injection", cvss=7.0, best_tool="sqlmap")
        assert kb._mock_session.run.called

    def test_record_tool_run_calls_session_run(self):
        kb = _make_kb(available=True)
        kb.record_tool_run("dalfox", "XSS", success=True, findings_count=3)
        assert kb._mock_session.run.called
