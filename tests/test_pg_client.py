# tests/test_pg_client.py
import os
from unittest.mock import patch

def test_get_async_pool_returns_none_when_no_url():
    """get_async_pool() returns None when POSTGRES_URL is unset."""
    import asyncio
    with patch.dict(os.environ, {}, clear=True):
        from oneinfinity.core import pg_client
        pg_client._async_pool = None
        result = asyncio.run(pg_client.get_async_pool())
        assert result is None

def test_get_sync_conn_returns_none_when_no_url():
    """get_sync_conn() returns None when POSTGRES_URL is unset."""
    with patch.dict(os.environ, {}, clear=True):
        from oneinfinity.core import pg_client
        pg_client._sync_conn = None
        result = pg_client.get_sync_conn()
        assert result is None

def test_close_pg_is_idempotent():
    """close_pg() must not raise when no connection exists."""
    import asyncio
    from oneinfinity.core.pg_client import close_pg
    asyncio.run(close_pg())  # must not raise
