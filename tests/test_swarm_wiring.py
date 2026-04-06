"""Test that scan() uses _make_swarm_state() factory, not SharedSwarmState() directly."""
import asyncio
import pytest

def test_scan_uses_make_swarm_state_factory(monkeypatch):
    """_make_swarm_state must be called during scan(), not SharedSwarmState() directly."""
    import sys
    sys.path.insert(0, "/home/devendra-yadav/oneinfinity")
    from agent_swarm_coordinator import AgentSwarmCoordinator, SharedSwarmState

    coordinator = AgentSwarmCoordinator.__new__(AgentSwarmCoordinator)
    coordinator._sim_engine = None
    coordinator._agents = []

    factory_calls = []

    def spy_factory(self, scan_id):
        factory_calls.append(scan_id)
        return SharedSwarmState(session_id=scan_id)

    monkeypatch.setattr(AgentSwarmCoordinator, "_make_swarm_state", spy_factory)

    async def run():
        try:
            await coordinator.scan("http://test.local", {})
        except Exception:
            pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run())
    finally:
        loop.close()

    assert len(factory_calls) > 0, "_make_swarm_state() was never called — scan() still uses SharedSwarmState() directly"

def test_redis_swarm_state_has_session_id_property():
    import sys
    sys.path.insert(0, "/home/devendra-yadav/oneinfinity")
    from core.swarm_state_redis import RedisSwarmState
    state = RedisSwarmState(scan_id="abc-123", redis=None)
    assert state.session_id == "abc-123"
    assert state.scan_id == "abc-123"
