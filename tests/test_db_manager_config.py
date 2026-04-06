"""Tests for DBManager strict-mode config enforcement."""
import asyncio
import pytest

def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

def reset_mgr():
    import core.db_manager as dm
    dm._manager = None

def test_explicit_postgres_without_url_raises(monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "postgres")
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    reset_mgr()
    from core.db_manager import get_db_manager
    with pytest.raises(RuntimeError, match="POSTGRES_URL"):
        run(get_db_manager())
    reset_mgr()

def test_explicit_distributed_without_postgres_raises(monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "distributed")
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    reset_mgr()
    from core.db_manager import get_db_manager
    with pytest.raises(RuntimeError, match="POSTGRES_URL"):
        run(get_db_manager())
    reset_mgr()

def test_explicit_sqlite_does_not_raise(monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "sqlite")
    reset_mgr()
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    assert mgr.mode == "sqlite"
    reset_mgr()

def test_explicit_distributed_without_redis_raises(monkeypatch):
    monkeypatch.setenv("ONEINFINITY_STORAGE_MODE", "distributed")
    monkeypatch.setenv("POSTGRES_URL", "postgresql://localhost/test")
    monkeypatch.delenv("REDIS_URL", raising=False)
    reset_mgr()
    from core.db_manager import get_db_manager
    with pytest.raises(RuntimeError, match="REDIS_URL"):
        run(get_db_manager())
    reset_mgr()

def test_no_env_defaults_to_sqlite(monkeypatch):
    monkeypatch.delenv("ONEINFINITY_STORAGE_MODE", raising=False)
    monkeypatch.delenv("POSTGRES_URL", raising=False)
    reset_mgr()
    from core.db_manager import get_db_manager
    mgr = run(get_db_manager())
    assert mgr.mode == "sqlite"
    reset_mgr()
