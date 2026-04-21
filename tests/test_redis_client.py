# tests/test_redis_client.py
import os
from unittest.mock import patch, MagicMock

def test_get_redis_returns_none_when_no_url():
    """get_redis() must return None when REDIS_URL is not set."""
    with patch.dict(os.environ, {}, clear=True):
        # Reset module-level cache
        import importlib
        import oneinfinity.core.redis_client as rc
        rc._client = None
        rc._pool = None
        result = rc.get_redis()
        assert result is None

def test_get_redis_returns_none_when_unreachable():
    """get_redis() must return None (not raise) when Redis is unreachable."""
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:19999/0"}):
        import oneinfinity.core.redis_client as rc
        rc._client = None
        rc._pool = None
        result = rc.get_redis()
        assert result is None

def test_close_redis_is_idempotent():
    """close_redis() must not raise when called with no connection."""
    from oneinfinity.core.redis_client import close_redis
    close_redis()  # must not raise
    close_redis()  # second call also must not raise
