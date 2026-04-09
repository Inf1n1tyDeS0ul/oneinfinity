# tests/test_swarm_state_redis.py
from unittest.mock import MagicMock, patch
import json

def _make_mock_redis():
    """Build a mock Redis client backed by a real dict."""
    store = {}
    sets = {}
    expiry = {}

    r = MagicMock()

    def hset(key, mapping=None, **kwargs):
        if key not in store:
            store[key] = {}
        if mapping:
            store[key].update(mapping)
        store[key].update(kwargs)

    def hget(key, field):
        return store.get(key, {}).get(field)

    def hgetall(key):
        return dict(store.get(key, {}))

    def hdel(key, *fields):
        for f in fields:
            store.get(key, {}).pop(f, None)

    def sadd(key, *members):
        if key not in sets:
            sets[key] = set()
        sets[key].update(members)

    def smembers(key):
        return sets.get(key, set())

    def srem(key, *members):
        if key in sets:
            sets[key].discard(*members)

    def set_(key, value, nx=False, ex=None):
        if nx and key in store:
            return False
        store[key] = value
        if ex:
            expiry[key] = ex
        return True

    def get(key):
        return store.get(key)

    def expire(key, seconds):
        expiry[key] = seconds
        return True

    def delete(*keys):
        for k in keys:
            store.pop(k, None)
            sets.pop(k, None)

    r.hset = MagicMock(side_effect=hset)
    r.hget = MagicMock(side_effect=hget)
    r.hgetall = MagicMock(side_effect=hgetall)
    r.hdel = MagicMock(side_effect=hdel)
    r.sadd = MagicMock(side_effect=sadd)
    r.smembers = MagicMock(side_effect=smembers)
    r.srem = MagicMock(side_effect=srem)
    r.set = MagicMock(side_effect=set_)
    r.get = MagicMock(side_effect=get)
    r.expire = MagicMock(side_effect=expire)
    r.delete = MagicMock(side_effect=delete)
    return r


def test_claim_task_stores_in_redis():
    r = _make_mock_redis()
    from oneinfinity.core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="scan-1", redis=r)
    state.claim_task("task-001", "agent-A")
    claimed = state.get_claimed_tasks()
    assert claimed.get("task-001") == "agent-A"


def test_add_finding_stores_in_redis():
    r = _make_mock_redis()
    from oneinfinity.core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="scan-1", redis=r)
    state.add_active_finding("finding-abc")
    assert "finding-abc" in state.get_active_findings()


def test_leader_election_set_nx():
    r = _make_mock_redis()
    from oneinfinity.core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="scan-1", redis=r)
    assert state.acquire_leader("worker-1") is True
    assert state.acquire_leader("worker-2") is False  # already locked


def test_fallback_state_when_redis_none():
    """When redis=None, RedisSwarmState uses in-memory fallback."""
    from oneinfinity.core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="scan-1", redis=None)
    state.claim_task("task-001", "agent-A")
    assert state.get_claimed_tasks().get("task-001") == "agent-A"
