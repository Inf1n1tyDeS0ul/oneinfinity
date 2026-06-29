import pytest
from unittest.mock import MagicMock, AsyncMock
from oneinfinity.scan.autonomous_crawler import AutonomousCrawler, StateNode

@pytest.mark.asyncio
async def test_perceive_state_hashing():
    # Mock Playwright Page
    mock_page = MagicMock()
    mock_page.url = "https://example.com"
    mock_page.content = AsyncMock(return_value="<html><body><h1>Test</h1></body></html>")
    
    crawler = AutonomousCrawler()
    state = await crawler._perceive_state(mock_page)
    
    assert isinstance(state, StateNode)
    assert state.url == "https://example.com"
    assert state.state_hash is not None
    assert len(state.state_hash) == 64  # SHA-256 hex length
