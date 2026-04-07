# tests/test_research_repository.py
"""Tests for ResearchRepository — verifies delegation to DBManager mock."""
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
    """ResearchRepository backed by a fully mocked DBManager."""
    from core.research_repository import ResearchRepository
    db = MagicMock()
    db.save_research_session = AsyncMock()
    db.list_research_sessions = AsyncMock(return_value=[])
    db.save_research_theory = AsyncMock()
    db.update_research_theory_status = AsyncMock()
    db.save_test_outcome = AsyncMock()
    db.save_research_discovery = AsyncMock()
    db.upsert_cross_target_pattern = AsyncMock()
    db.list_research_discoveries = AsyncMock(return_value=[])
    db.get_cross_target_patterns = AsyncMock(return_value=[])
    return ResearchRepository(db), db


def make_session(session_id="s1", target="t.com", status="running", ended_at=0.0):
    """Minimal ResearchSession stand-in (plain object with the right attributes)."""
    s = MagicMock()
    s.session_id = session_id
    s.target = target
    s.output_dir = "/tmp/out"
    s.platform = "HackerOne"
    s.started_at = time.time()
    s.ended_at = ended_at
    s.status = status
    s.iteration = 1
    s.theories_generated = 2
    s.tests_executed = 5
    s.anomalies_found = 1
    s.confirmed_vulns = 1
    return s


# ── save_session / finish_session ─────────────────────────────────────────────

def test_save_session_calls_db_with_session_fields():
    repo, db = make_repo()
    session = make_session()
    run(repo.save_session(session))
    db.save_research_session.assert_called_once()
    d = db.save_research_session.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["target"] == "t.com"
    assert d["status"] == "running"


def test_finish_session_includes_ended_at():
    repo, db = make_repo()
    session = make_session(status="completed", ended_at=time.time())
    run(repo.finish_session(session))
    db.save_research_session.assert_called_once()
    d = db.save_research_session.call_args[0][0]
    assert d["status"] == "completed"
    assert d["ended_at"] is not None


def test_save_session_sync_works_synchronously():
    repo, db = make_repo()
    session = make_session()
    repo.save_session_sync(session)  # must not raise
    db.save_research_session.assert_called_once()


def test_finish_session_sync_works_synchronously():
    repo, db = make_repo()
    session = make_session(status="aborted", ended_at=time.time())
    repo.finish_session_sync(session)
    db.save_research_session.assert_called_once()


# ── record_theory ─────────────────────────────────────────────────────────────

def test_record_theory_passes_correct_fields():
    repo, db = make_repo()
    run(repo.record_theory("th1", "s1", "t.com", "/api/v1", "xss", "high", 0.9, "reason"))
    db.save_research_theory.assert_called_once()
    d = db.save_research_theory.call_args[0][0]
    assert d["theory_id"] == "th1"
    assert d["vuln_type"] == "xss"
    assert d["confidence"] == 0.9
    assert d["status"] == "pending"
    assert isinstance(d["created_at"], float)


def test_record_theory_sync_works_synchronously():
    repo, db = make_repo()
    repo.record_theory_sync("th1", "s1", "t.com", "/api", "sqli", "critical", 0.95, "why")
    db.save_research_theory.assert_called_once()


# ── update_theory_status ──────────────────────────────────────────────────────

def test_update_theory_status_calls_db_with_timestamp():
    repo, db = make_repo()
    run(repo.update_theory_status("th1", "confirmed"))
    db.update_research_theory_status.assert_called_once()
    args = db.update_research_theory_status.call_args[0]
    assert args[0] == "th1"
    assert args[1] == "confirmed"
    assert isinstance(args[2], float)  # updated_at


def test_update_theory_status_sync_works_synchronously():
    repo, db = make_repo()
    repo.update_theory_status_sync("th1", "rejected")
    db.update_research_theory_status.assert_called_once()


# ── record_test_outcome ───────────────────────────────────────────────────────

def test_record_test_outcome_maps_all_fields():
    repo, db = make_repo()
    run(repo.record_test_outcome(
        "s1", "th1", "t.com", "/api/search", "xss", "<script>",
        200, 1024, 50.0, 0.7, 1, "reflected in body", time.time(),
    ))
    db.save_test_outcome.assert_called_once()
    d = db.save_test_outcome.call_args[0][0]
    assert d["session_id"] == "s1"
    assert d["payload"] == "<script>"
    assert d["confirmed"] == 1


def test_record_test_outcome_sync_works_synchronously():
    repo, db = make_repo()
    repo.record_test_outcome_sync(
        "s1", "th1", "t.com", "/login", "sqli", "' OR 1=1",
        500, 256, 200.0, 0.9, 0, "", time.time(),
    )
    db.save_test_outcome.assert_called_once()


# ── save_discovery ────────────────────────────────────────────────────────────

def test_save_discovery_calls_both_db_methods():
    repo, db = make_repo()
    run(repo.save_discovery(
        "r1", "s1", "t.com", "xss", "Reflected XSS", "high", 0.95,
        "/api/v1/search", "desc", "impact", ["step1"], "poc", "fix", "ev",
        7.5, time.time(),
    ))
    db.save_research_discovery.assert_called_once()
    db.upsert_cross_target_pattern.assert_called_once()


def test_save_discovery_normalizes_endpoint_digits_to_id():
    repo, db = make_repo()
    run(repo.save_discovery(
        "r1", "s1", "t.com", "idor", "IDOR", "high", 0.9,
        "/api/v1/users/42/posts/7", "desc", "impact", [],
        "poc", "fix", "evidence", 8.0, time.time(),
    ))
    pattern_data = db.upsert_cross_target_pattern.call_args[0][0]
    assert pattern_data["endpoint_pattern"] == "/api/v1/users/{id}/posts/{id}"
    assert pattern_data["vuln_type"] == "idor"


def test_save_discovery_sync_works_synchronously():
    repo, db = make_repo()
    repo.save_discovery_sync(
        "r1", "s1", "t.com", "xss", "XSS", "medium", 0.8,
        "/search", "desc", "impact", [], "poc", "fix", "ev", 5.0, time.time(),
    )
    db.save_research_discovery.assert_called_once()
    db.upsert_cross_target_pattern.assert_called_once()


# ── get_known_patterns ────────────────────────────────────────────────────────

def test_get_known_patterns_delegates_min_count():
    repo, db = make_repo()
    db.get_cross_target_patterns = AsyncMock(return_value=[{"vuln_type": "xss", "success_count": 3}])
    result = run(repo.get_known_patterns(min_count=2))
    db.get_cross_target_patterns.assert_called_once_with(2)
    assert result[0]["success_count"] == 3


def test_get_known_patterns_sync():
    repo, db = make_repo()
    db.get_cross_target_patterns = AsyncMock(return_value=[{"vuln_type": "sqli"}])
    result = repo.get_known_patterns_sync(min_count=1)
    assert result[0]["vuln_type"] == "sqli"


# ── get_session_history ───────────────────────────────────────────────────────

def test_get_session_history_passes_target_kwarg():
    repo, db = make_repo()
    db.list_research_sessions = AsyncMock(return_value=[{"session_id": "s1"}])
    result = run(repo.get_session_history(target="t.com"))
    db.list_research_sessions.assert_called_once_with(target="t.com")
    assert len(result) == 1


def test_get_session_history_sync():
    repo, db = make_repo()
    db.list_research_sessions = AsyncMock(return_value=[{"session_id": "s2"}])
    result = repo.get_session_history_sync("t.com")
    assert result[0]["session_id"] == "s2"


# ── get_confirmed_discoveries ─────────────────────────────────────────────────

def test_get_confirmed_discoveries_passes_session_id_kwarg():
    repo, db = make_repo()
    db.list_research_discoveries = AsyncMock(return_value=[{"report_id": "r1"}])
    result = run(repo.get_confirmed_discoveries(session_id="s1"))
    db.list_research_discoveries.assert_called_once_with(session_id="s1")
    assert len(result) == 1


def test_get_confirmed_discoveries_sync():
    repo, db = make_repo()
    db.list_research_discoveries = AsyncMock(return_value=[{"report_id": "r9"}])
    result = repo.get_confirmed_discoveries_sync()
    assert result[0]["report_id"] == "r9"
