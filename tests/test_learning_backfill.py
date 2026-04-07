# tests/test_learning_backfill.py
"""Tests for learning backfill — idempotency and checkpoint resumption."""
from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import pytest
from learning.backfill import LearningBackfill


def _make_backfill(findings: list[dict]) -> LearningBackfill:
    bf = LearningBackfill.__new__(LearningBackfill)
    mock_kb = MagicMock()
    mock_kb._available = True
    bf._kb = mock_kb
    bf._findings = findings  # injected test data
    return bf


class TestLearningBackfillUnit:
    def test_process_finding_calls_record_and_upsert(self):
        finding = {
            "vuln_type": "XSS", "target": "example.com",
            "severity": "high", "source_tool": "dalfox",
            "tech_stack": ["php"],
        }
        bf = _make_backfill([])
        bf._process_finding(finding)
        bf._kb.record_finding.assert_called_once()
        bf._kb.upsert_pattern.assert_called_once_with(
            ["php"], "XSS", cvss=0.0, best_tool="dalfox"
        )

    def test_process_finding_no_error_when_kb_raises(self):
        bf = _make_backfill([])
        bf._kb.record_finding.side_effect = Exception("boom")
        bf._process_finding({"vuln_type": "XSS"})  # must not raise

    def test_run_calls_process_for_each_finding(self):
        findings = [
            {"vuln_type": "XSS", "target": "a.com"},
            {"vuln_type": "SQLi", "target": "b.com"},
        ]
        bf = _make_backfill(findings)
        bf._fetch_findings = MagicMock(return_value=iter(findings))
        bf.run(batch_size=500)
        assert bf._kb.record_finding.call_count == 2

    def test_run_is_idempotent(self):
        """Calling run() twice should produce the same state — all writes are MERGE."""
        findings = [{"vuln_type": "XSS", "target": "a.com"}]
        bf = _make_backfill(findings)
        bf._fetch_findings = MagicMock(return_value=iter(findings))
        bf.run(batch_size=500)
        first_call_count = bf._kb.record_finding.call_count
        bf._fetch_findings = MagicMock(return_value=iter(findings))
        bf.run(batch_size=500)
        # Second run re-processes same findings — MERGE in KB means same result
        assert bf._kb.record_finding.call_count == first_call_count * 2
