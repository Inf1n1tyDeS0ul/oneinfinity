# tests/test_target_repository.py
"""Tests for TargetRepository — verifies it delegates to DBManager."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def make_mock_db(**method_returns):
    """Return a MagicMock DBManager with configurable async method returns."""
    mock_db = MagicMock()
    for method_name, return_value in method_returns.items():
        setattr(mock_db, method_name, AsyncMock(return_value=return_value))
    return mock_db


def test_add_delegates_to_save_target():
    """TargetRepository.add must call db.save_target with a target dict."""
    from oneinfinity.core.target_repository import TargetRepository
    expected = {"target_id": "t1", "target_value": "example.com", "id": "t1", "domain": "example.com"}
    db = make_mock_db(save_target=expected)
    repo = TargetRepository(db)
    result = run(repo.add("t1", "example.com", "Example", "hackerone", "web"))
    db.save_target.assert_called_once()
    call_data = db.save_target.call_args[0][0]
    assert call_data["target_id"] == "t1"
    assert call_data["target_value"] == "example.com"
    assert result["target_id"] == "t1"


def test_add_uses_target_value_as_name_when_name_empty():
    """add must use target_value as name when name is empty string."""
    from oneinfinity.core.target_repository import TargetRepository
    db = make_mock_db(save_target={"target_id": "t1", "target_value": "example.com"})
    repo = TargetRepository(db)
    run(repo.add("t1", "example.com"))
    call_data = db.save_target.call_args[0][0]
    assert call_data["name"] == "example.com"


def test_list_all_delegates_to_list_targets():
    from oneinfinity.core.target_repository import TargetRepository
    targets = [{"target_id": "t1"}, {"target_id": "t2"}]
    db = make_mock_db(list_targets=targets)
    repo = TargetRepository(db)
    result = run(repo.list_all())
    db.list_targets.assert_called_once()
    assert result == targets


def test_get_delegates_to_get_target():
    from oneinfinity.core.target_repository import TargetRepository
    target = {"target_id": "t1", "target_value": "example.com"}
    db = make_mock_db(get_target=target)
    repo = TargetRepository(db)
    result = run(repo.get("t1"))
    db.get_target.assert_called_once_with("t1")
    assert result == target


def test_get_returns_none_when_not_found():
    from oneinfinity.core.target_repository import TargetRepository
    db = make_mock_db(get_target=None)
    repo = TargetRepository(db)
    result = run(repo.get("nonexistent"))
    assert result is None


def test_delete_delegates_to_delete_target():
    from oneinfinity.core.target_repository import TargetRepository
    db = make_mock_db(delete_target=True)
    repo = TargetRepository(db)
    result = run(repo.delete("t1"))
    db.delete_target.assert_called_once_with("t1")
    assert result is True


def test_update_status_delegates_to_update_target_status():
    from oneinfinity.core.target_repository import TargetRepository
    db = make_mock_db(update_target_status=None)
    repo = TargetRepository(db)
    run(repo.update_status("t1", "scanning", "2026-04-07T12:00:00"))
    db.update_target_status.assert_called_once_with("t1", "scanning", "2026-04-07T12:00:00")


def test_update_vuln_count_delegates_to_update_target_vuln_count():
    from oneinfinity.core.target_repository import TargetRepository
    db = make_mock_db(update_target_vuln_count=None)
    repo = TargetRepository(db)
    run(repo.update_vuln_count("t1", 7))
    db.update_target_vuln_count.assert_called_once_with("t1", 7)


def test_get_target_repo_returns_repository_instance():
    """get_target_repo() must return a TargetRepository."""
    from oneinfinity.core.target_repository import TargetRepository, get_target_repo
    from unittest.mock import patch
    import core.db_manager as dm
    dm._manager = None
    mock_mgr = MagicMock()
    with patch("oneinfinity.core.target_repository.get_db_manager", new_callable=AsyncMock,
               return_value=mock_mgr):
        repo = run(get_target_repo())
    assert isinstance(repo, TargetRepository)
    assert repo._db is mock_mgr
