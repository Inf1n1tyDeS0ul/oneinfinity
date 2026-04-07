# tests/test_db_manager_get_findings_hardened.py
"""get_findings must raise in sqlite/memory mode — no silent SQLite fallback."""
import asyncio
import pytest


def run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_get_findings_raises_in_sqlite_mode():
    """After hardening, get_findings must raise RuntimeError in sqlite mode."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "sqlite"
    with pytest.raises(RuntimeError, match="Postgres"):
        run(mgr.get_findings())


def test_get_findings_raises_in_memory_mode():
    """get_findings must raise in memory mode too."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    mgr.mode = "memory"
    with pytest.raises(RuntimeError, match="Postgres"):
        run(mgr.get_findings())


def test_sqlite_get_findings_method_removed():
    """_sqlite_get_findings must not exist on DBManager after hardening."""
    import core.db_manager as dm
    dm._manager = None
    mgr = dm.DBManager()
    assert not hasattr(mgr, "_sqlite_get_findings"), \
        "_sqlite_get_findings must be removed from DBManager"
