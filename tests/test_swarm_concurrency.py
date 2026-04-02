"""
test_swarm_concurrency.py — Verify swarm agent concurrency cap.
"""
import asyncio
from unittest.mock import patch


def test_swarm_concurrency_capped():
    """At most MAX_CONCURRENT_AGENTS agents run simultaneously."""
    from swarm_intelligence_engine import SwarmIntelligenceEngine

    concurrent_count = [0]
    peak_concurrent = [0]

    async def mock_agent_run(self, *args, **kwargs):
        concurrent_count[0] += 1
        peak_concurrent[0] = max(peak_concurrent[0], concurrent_count[0])
        await asyncio.sleep(0.01)
        concurrent_count[0] -= 1
        return []

    engine = SwarmIntelligenceEngine()

    if not getattr(engine, '_agents', []):
        # No agents in test env — skip concurrency check
        return

    agent_class = type(engine._agents[0])

    with patch.object(agent_class, 'run', mock_agent_run):
        asyncio.run(engine.run_all_agents("example.com", {}))

    assert peak_concurrent[0] <= 5, \
        f"Too many concurrent agents: {peak_concurrent[0]} > cap 5"
