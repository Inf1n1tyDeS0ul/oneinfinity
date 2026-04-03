# tests/test_graph_config.py
import os
from unittest.mock import patch
import importlib

def test_load_graph_config_reads_redis_url():
    with patch.dict(os.environ, {"REDIS_URL": "redis://localhost:6379/0"}):
        import core.graph_config as gc
        importlib.reload(gc)
        cfg = gc.load_graph_config()
        assert cfg["redis"]["url"] == "redis://localhost:6379/0"

def test_load_graph_config_reads_postgres_url():
    with patch.dict(os.environ, {"POSTGRES_URL": "postgresql://localhost/oneinfinity"}):
        import core.graph_config as gc
        importlib.reload(gc)
        cfg = gc.load_graph_config()
        assert cfg["postgres"]["url"] == "postgresql://localhost/oneinfinity"

def test_load_graph_config_reads_storage_mode():
    with patch.dict(os.environ, {"ONEINFINITY_STORAGE_MODE": "sqlite"}):
        import core.graph_config as gc
        importlib.reload(gc)
        cfg = gc.load_graph_config()
        assert cfg["storage_mode"] == "sqlite"

def test_storage_mode_defaults_to_auto():
    with patch.dict(os.environ, {}, clear=True):
        import core.graph_config as gc
        importlib.reload(gc)
        cfg = gc.load_graph_config()
        assert cfg["storage_mode"] == "auto"
