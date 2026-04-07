# tests/test_learning_repository.py
"""Tests for LearningRepository — verifies delegation to DBManager mock."""
import asyncio
import time
import pytest
from unittest.mock import AsyncMock, MagicMock


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def make_repo():
    """LearningRepository backed by a fully mocked DBManager."""
    from core.learning_repository import LearningRepository
    db = MagicMock()
    db.save_learning_session = AsyncMock()
    db.get_learning_session = AsyncMock(return_value=None)
    db.list_learning_sessions = AsyncMock(return_value=[])
    db.save_learning_finding = AsyncMock()
    db.record_tool_run = AsyncMock()
    db.get_best_tool_for_vuln = AsyncMock(return_value=[])
    db.upsert_target_profile = AsyncMock()
    db.get_target_profile = AsyncMock(return_value=None)
    db.upsert_pattern = AsyncMock()
    db.get_patterns_for_tech_stack = AsyncMock(return_value=[])
    db.get_learning_stats = AsyncMock(return_value={
        "sessions": 0, "confirmed_findings": 0, "unique_targets": 0,
        "top_vuln_types": [], "top_tools": [],
    })
    db.list_tool_performance = AsyncMock(return_value=[])
    return LearningRepository(db), db


# ── start_session / finish_session ───────────────────────────────────────────

def test_start_session_calls_save_with_session_fields():
    repo, db = make_repo()
    run(repo.start_session("s1", "t.com", phases=["recon", "scan"]))
    db.save_learning_session.assert_called_once()
    d = db.save_learning_session.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["target"] == "t.com"
    assert d["phases"] == ["recon", "scan"]
    assert d["finished_at"] is None


def test_finish_session_calls_save_with_finish_fields():
    repo, db = make_repo()
    run(repo.finish_session("s1", total_findings=5, tools_used=["nuclei"]))
    db.save_learning_session.assert_called_once()
    d = db.save_learning_session.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["total_findings"] == 5
    assert d["tools_used"] == ["nuclei"]
    assert d["finished_at"] is not None


# ── record_finding / record_findings_bulk ────────────────────────────────────

def test_record_finding_extracts_fields_from_dict():
    repo, db = make_repo()
    finding = {
        "target": "t.com", "vuln_type": "sqli", "severity": "high",
        "cvss_score": 7.5, "endpoint": "/login", "parameter": "id",
        "source_tool": "sqlmap",
    }
    run(repo.record_finding("s1", finding, confirmed=True))
    db.save_learning_finding.assert_called_once()
    d = db.save_learning_finding.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["vuln_type"] == "sqli"
    assert d["confirmed"] == 1


def test_record_finding_confirmed_false_stores_zero():
    repo, db = make_repo()
    run(repo.record_finding("s1", {"vuln_type": "xss", "target": "t.com"}, confirmed=False))
    d = db.save_learning_finding.call_args[0][0]
    assert d["confirmed"] == 0


def test_record_findings_bulk_calls_save_per_finding():
    repo, db = make_repo()
    findings = [
        {"vuln_type": "xss", "target": "t.com"},
        {"vuln_type": "sqli", "target": "t.com"},
    ]
    run(repo.record_findings_bulk("s1", findings, confirmed=True))
    assert db.save_learning_finding.call_count == 2


# ── record_tool_run / best_tool_for_vuln ─────────────────────────────────────

def test_record_tool_run_passes_duration_s_field():
    repo, db = make_repo()
    run(repo.record_tool_run(
        tool_name="nuclei", vuln_type="xss", target_type="web",
        success=True, findings_count=3, duration_s=4.2,
    ))
    db.record_tool_run.assert_called_once()
    d = db.record_tool_run.call_args[0][0]
    assert d["tool_name"] == "nuclei"
    assert d["avg_duration_s"] == 4.2
    assert d["runs_success"] == 1


def test_record_tool_run_failure_stores_zero_success():
    repo, db = make_repo()
    run(repo.record_tool_run("nuclei", success=False))
    d = db.record_tool_run.call_args[0][0]
    assert d["runs_success"] == 0


def test_best_tool_for_vuln_returns_empty_list_when_no_data():
    repo, db = make_repo()
    result = run(repo.best_tool_for_vuln("xss", top_n=1))
    assert result == []


# ── upsert_target_profile / get_target_profile ───────────────────────────────

def test_upsert_target_profile_passes_domain_and_tech_stack():
    repo, db = make_repo()
    run(repo.upsert_target_profile("t.com", tech_stack=["WordPress", "MySQL"]))
    db.upsert_target_profile.assert_called_once()
    d = db.upsert_target_profile.call_args[0][0]
    assert d["domain"] == "t.com"
    assert "WordPress" in d["tech_stack"]


def test_get_target_profile_returns_none_when_not_found():
    repo, db = make_repo()
    result = run(repo.get_target_profile("missing.com"))
    assert result is None


# ── upsert_pattern / patterns_for_tech_stack ─────────────────────────────────

def test_upsert_pattern_builds_tech_stack_key():
    repo, db = make_repo()
    run(repo.upsert_pattern(["WordPress", "MySQL"], "sqli", cvss=7.0, best_tool="sqlmap"))
    db.upsert_pattern.assert_called_once()
    d = db.upsert_pattern.call_args[0][0]
    # key is sorted, lowercased, comma-joined
    assert d["tech_stack_key"] == "mysql,wordpress"
    assert d["vuln_type"] == "sqli"
    assert d["avg_cvss"] == 7.0


def test_patterns_for_tech_stack_builds_key():
    repo, db = make_repo()
    run(repo.patterns_for_tech_stack(["WordPress", "MySQL"]))
    db.get_patterns_for_tech_stack.assert_called_once_with("mysql,wordpress")


# ── stats / recent_sessions / get_tool_performance_stats ─────────────────────

def test_stats_returns_dict():
    repo, db = make_repo()
    result = run(repo.stats())
    assert "sessions" in result
    assert "confirmed_findings" in result


def test_recent_sessions_passes_limit():
    repo, db = make_repo()
    run(repo.recent_sessions(limit=5))
    db.list_learning_sessions.assert_called_once_with(5)


def test_get_tool_performance_stats_returns_list():
    repo, db = make_repo()
    result = run(repo.get_tool_performance_stats())
    assert result == []


def test_close_is_a_noop():
    repo, db = make_repo()
    repo.close()  # must not raise


# ── Sync wrappers ─────────────────────────────────────────────────────────────

def test_start_session_sync_calls_db():
    repo, db = make_repo()
    repo.start_session_sync("s1", "t.com")
    db.save_learning_session.assert_called_once()


def test_finish_session_sync_calls_db():
    repo, db = make_repo()
    repo.finish_session_sync("s1", total_findings=3)
    db.save_learning_session.assert_called_once()


def test_record_finding_sync_calls_db():
    repo, db = make_repo()
    repo.record_finding_sync("s1", {"vuln_type": "xss", "target": "t.com"})
    db.save_learning_finding.assert_called_once()


def test_record_tool_run_sync_calls_db():
    repo, db = make_repo()
    repo.record_tool_run_sync("nuclei")
    db.record_tool_run.assert_called_once()


def test_best_tool_for_vuln_sync_returns_list():
    repo, db = make_repo()
    result = repo.best_tool_for_vuln_sync("xss")
    assert isinstance(result, list)


def test_get_target_profile_sync_returns_none_for_missing():
    repo, db = make_repo()
    assert repo.get_target_profile_sync("missing.com") is None


def test_get_tool_performance_stats_sync_returns_list():
    repo, db = make_repo()
    assert repo.get_tool_performance_stats_sync() == []
