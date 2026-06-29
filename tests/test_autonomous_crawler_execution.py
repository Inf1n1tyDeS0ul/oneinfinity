import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from oneinfinity.scan.autonomous_crawler import AutonomousCrawler, ActionCommand, StateNode

@pytest.mark.asyncio
async def test_run_max_depth_limit():
    """Test that crawler stops after max_depth is reached."""
    llm_client = MagicMock()
    # Mock LLM to always return a non-destructive click action
    llm_client.complete.return_value = '{"thought": "test", "action": "click", "target": "#btn", "value": null, "is_destructive": False}'
    
    crawler = AutonomousCrawler(llm_client=llm_client)
    
    # Mock Playwright
    with patch("oneinfinity.scan.autonomous_crawler.async_playwright") as mock_async_playwright:
        # async_playwright() returns an async context manager
        mock_p = AsyncMock()
        mock_async_playwright.return_value.__aenter__.return_value = mock_p
        
        mock_browser = AsyncMock()
        mock_p.chromium.launch.return_value = mock_browser
        
        mock_context = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        
        mock_page = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_page.goto = AsyncMock()
        mock_browser.close = AsyncMock()
        
        # Mock _perceive_state to return different states to avoid loop detection initially
        states = [
            StateNode(url="http://test.com", state_hash=f"hash{i}", content_summary=f"summary{i}")
            for i in range(10)
        ]
        crawler._perceive_state = AsyncMock(side_effect=states)
        crawler._decide_next_action = AsyncMock(return_value=ActionCommand(
            thought="test", action="click", target="#btn", is_destructive=False
        ))
        mock_page.click = AsyncMock()
        
        # Execute with max_depth=3
        await crawler.run(url="http://test.com", max_depth=3)
        
        # Verify loop ran 3 times
        assert crawler._perceive_state.call_count == 3
        assert crawler._decide_next_action.call_count == 3
        assert mock_page.click.call_count == 3

@pytest.mark.asyncio
async def test_run_loop_detection():
    """Test that crawler stops if it encounters a visited state."""
    llm_client = MagicMock()
    crawler = AutonomousCrawler(llm_client=llm_client)
    
    with patch("oneinfinity.scan.autonomous_crawler.async_playwright") as mock_async_playwright:
        mock_p = AsyncMock()
        mock_async_playwright.return_value.__aenter__.return_value = mock_p
        mock_browser = AsyncMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_context = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_page = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_page.goto = AsyncMock()
        
        # State 1 -> State 2 -> State 1 (Loop!)
        state1 = StateNode(url="http://test.com/1", state_hash="hash1")
        state2 = StateNode(url="http://test.com/2", state_hash="hash2")
        crawler._perceive_state = AsyncMock(side_effect=[state1, state2, state1])
        
        crawler._decide_next_action = AsyncMock(return_value=ActionCommand(
            thought="test", action="click", target="#btn", is_destructive=False
        ))
        
        await crawler.run(url="http://test.com/1", max_depth=10)
        
        # perception 1: hash1 added
        # action 1
        # perception 2: hash2 added
        # action 2
        # perception 3: hash1 detected -> break
        assert crawler._perceive_state.call_count == 3
        assert crawler._decide_next_action.call_count == 2
        assert mock_page.click.call_count == 2

@pytest.mark.asyncio
async def test_run_safety_gate():
    """Test that crawler stops if it encounters a destructive action."""
    llm_client = MagicMock()
    crawler = AutonomousCrawler(llm_client=llm_client)
    
    with patch("oneinfinity.scan.autonomous_crawler.async_playwright") as mock_async_playwright:
        mock_p = AsyncMock()
        mock_async_playwright.return_value.__aenter__.return_value = mock_p
        mock_browser = AsyncMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_context = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_page = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_page.goto = AsyncMock()
        
        crawler._perceive_state = AsyncMock(return_value=StateNode(url="http://test.com", state_hash="hash1"))
        
        # Destructive action!
        crawler._decide_next_action = AsyncMock(return_value=ActionCommand(
            thought="dangerous", action="click", target="#delete-all", is_destructive=True
        ))
        
        await crawler.run(url="http://test.com", max_depth=10)
        
        # Should stop before executing the action
        assert crawler._perceive_state.call_count == 1
        assert crawler._decide_next_action.call_count == 1
        assert mock_page.click.call_count == 0
