# tests/test_hybrid_architecture.py
"""
Hybrid architecture integration test.
Validates the full stack in SQLite fallback mode (no external services needed).
"""
import os
os.environ["ONEINFINITY_API_KEY"] = ""
os.environ.pop("POSTGRES_URL", None)
os.environ.pop("REDIS_URL", None)

import asyncio

def test_db_manager_initializes_in_sqlite_mode():
    """DBManager must initialize in SQLite mode when no Postgres URL."""
    from oneinfinity.core import db_manager as dm
    dm._manager = None
    mgr = asyncio.run(dm.get_db_manager())
    assert mgr.mode in ("sqlite", "memory")

def test_redis_swarm_state_works_without_redis():
    """RedisSwarmState must work in memory mode when redis=None."""
    from oneinfinity.core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="integ-scan", redis=None)
    state.claim_task("t1", "agent-1")
    state.add_active_finding("f1")
    state.increment_agent_stat("recon", 3)
    assert state.get_claimed_tasks()["t1"] == "agent-1"
    assert "f1" in state.get_active_findings()
    assert state.get_agent_stats()["recon"] == 3

def test_event_bus_publishes_without_redis():
    """EventBus must publish and dispatch events without Redis."""
    from oneinfinity.orchestration.event_bus import EventBus, EventType
    received = []
    bus = EventBus()
    bus.on(EventType.NEW_TARGET, lambda e: received.append(e.data))
    bus.publish(EventType.NEW_TARGET, {"target": "test.com"}, correlation_id="scan-1")
    import time; time.sleep(0.15)
    assert any(d.get("target") == "test.com" for d in received)

def test_graph_config_reads_all_new_env_vars():
    """graph_config must expose redis, postgres, storage_mode keys."""
    from oneinfinity.core.graph_config import load_graph_config
    cfg = load_graph_config()
    assert "redis" in cfg
    assert "postgres" in cfg
    assert "storage_mode" in cfg

def test_neo4j_primary_backend_exists():
    """Neo4jPrimaryBackend must be importable."""
    from oneinfinity.core.graph_storage import Neo4jPrimaryBackend
    assert Neo4jPrimaryBackend is not None

def test_neo4j_engine_ping_returns_false_without_neo4j():
    """Neo4jEngine.ping() must return False without a real Neo4j."""
    from oneinfinity.core.neo4j_engine import Neo4jEngine
    engine = Neo4jEngine.__new__(Neo4jEngine)
    engine._driver = None
    assert engine.ping() is False

def test_migration_script_importable():
    """migrate_sqlite_to_pg must be importable and expose extract_findings."""
    from scripts.migrate_sqlite_to_pg import extract_findings, transform_finding, run_migration
    assert callable(extract_findings)
    assert callable(transform_finding)
    assert callable(run_migration)
