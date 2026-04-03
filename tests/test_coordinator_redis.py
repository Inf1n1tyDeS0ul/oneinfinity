# tests/test_coordinator_redis.py
from unittest.mock import patch

def test_coordinator_uses_redis_state_when_available():
    """AgentSwarmCoordinator must use RedisSwarmState when Redis is reachable."""
    mock_redis = object()  # non-None signals Redis available

    with patch("core.redis_client.get_redis", return_value=mock_redis):
        from agent_swarm_coordinator import AgentSwarmCoordinator
        coordinator = AgentSwarmCoordinator.__new__(AgentSwarmCoordinator)
        from core.swarm_state_redis import RedisSwarmState
        state = coordinator._make_swarm_state("scan-test")
        assert isinstance(state, RedisSwarmState)
        assert state._r is mock_redis

def test_coordinator_falls_back_to_memory_state_when_no_redis():
    """AgentSwarmCoordinator must fall back to in-memory SharedSwarmState."""
    with patch("core.redis_client.get_redis", return_value=None):
        from agent_swarm_coordinator import AgentSwarmCoordinator, SharedSwarmState
        coordinator = AgentSwarmCoordinator.__new__(AgentSwarmCoordinator)
        state = coordinator._make_swarm_state("scan-test")
        assert isinstance(state, SharedSwarmState)
