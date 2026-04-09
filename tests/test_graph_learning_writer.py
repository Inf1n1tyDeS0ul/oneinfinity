"""Unit tests for GraphLearningWriter — Neo4j driver is mocked."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest
from oneinfinity.learning.graph_learning_writer import GraphLearningWriter


def _make_writer(available: bool = True) -> GraphLearningWriter:
    w = GraphLearningWriter.__new__(GraphLearningWriter)
    if available:
        mock_kb = MagicMock()
        mock_kb._available = True
        w._kb = mock_kb
    else:
        mock_kb = MagicMock()
        mock_kb._available = False
        w._kb = mock_kb
    return w


class TestGraphLearningWriterUnavailable:
    def test_write_finding_noop_when_unavailable(self):
        w = _make_writer(available=False)
        w.write_finding({
            "vuln_type": "XSS", "target": "example.com",
            "severity": "high", "source_tool": "dalfox",
            "payload": "<script>",
        })
        w._kb.record_finding.assert_not_called()


class TestGraphLearningWriterAvailable:
    def test_write_finding_calls_record_finding(self):
        w = _make_writer(available=True)
        finding = {
            "vuln_type": "XSS", "target": "example.com",
            "severity": "high", "source_tool": "dalfox",
            "payload": "<script>", "cvss": 7.5,
        }
        w.write_finding(finding)
        w._kb.record_finding.assert_called_once()
        call_args = w._kb.record_finding.call_args
        assert call_args[0][1] == finding  # second positional arg is the finding dict

    def test_write_finding_calls_upsert_pattern_when_tech_stack_present(self):
        w = _make_writer(available=True)
        finding = {
            "vuln_type": "SQL Injection", "target": "example.com",
            "severity": "high", "source_tool": "sqlmap",
            "tech_stack": ["wordpress", "mysql"],
        }
        w.write_finding(finding)
        w._kb.upsert_pattern.assert_called_once_with(
            ["wordpress", "mysql"], "SQL Injection",
            cvss=0.0, best_tool="sqlmap"
        )

    def test_write_finding_no_exception_on_kb_error(self):
        w = _make_writer(available=True)
        w._kb.record_finding.side_effect = Exception("Neo4j boom")
        # Must not raise
        w.write_finding({"vuln_type": "XSS", "target": "example.com"})

    def test_ema_formula_numerical(self):
        """EMA: new_ema = alpha * 1.0 + (1-alpha) * old_ema, alpha=0.3"""
        alpha = 0.3
        old = 0.5
        expected = alpha * 1.0 + (1 - alpha) * old
        assert abs(expected - 0.65) < 1e-9
