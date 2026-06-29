import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from oneinfinity.scan.autonomous_crawler import AutonomousCrawler, ActionCommand, StateNode

@pytest.mark.asyncio
async def test_resource_cleanup_on_failure():
    """Test that browser.close is called even if navigation fails."""
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
        
        # Simulate failure during goto
        mock_page.goto.side_effect = Exception("Network error")
        
        mock_browser.close = AsyncMock()
        
        try:
            await crawler.run(url="http://test.com")
        except Exception:
            pass
            
        # Verify close was still called
        mock_browser.close.assert_called_once()

@pytest.mark.asyncio
async def test_action_retry_logic_success():
    """Test that actions are retried and succeed on second attempt."""
    crawler = AutonomousCrawler()
    mock_page = AsyncMock()
    
    # First call fails, second succeeds
    mock_page.click.side_effect = [Exception("Transient error"), None]
    
    action = ActionCommand(thought="test", action="click", target="#btn")
    
    await crawler._execute_action_with_retry(mock_page, action)
    
    assert mock_page.click.call_count == 2
    assert mock_page.wait_for_timeout.call_count == 1 # One wait between retries

@pytest.mark.asyncio
async def test_action_retry_logic_exhaustion():
    """Test that actions fail after all retries are exhausted."""
    crawler = AutonomousCrawler()
    mock_page = AsyncMock()
    
    # All calls fail
    mock_page.click.side_effect = Exception("Permanent error")
    
    action = ActionCommand(thought="test", action="click", target="#btn")
    
    with pytest.raises(Exception, match="Permanent error"):
        await crawler._execute_action_with_retry(mock_page, action, max_retries=2)
    
    assert mock_page.click.call_count == 3 # Initial + 2 retries

@pytest.mark.asyncio
async def test_state_hashing_uses_body():
    """Test that state hashing specifically looks for body content."""
    mock_page = AsyncMock()
    mock_page.url = "https://example.com"
    mock_page.inner_html.return_value = "<div>Body Content</div>"
    mock_page.content.return_value = "<html><body><div>Body Content</div></body></html>"
    mock_page.evaluate.return_value = {"nodes": [{"text": "Body Content"}]}
    crawler = AutonomousCrawler()
    state = await crawler._perceive_state(mock_page)
    mock_page.inner_html.assert_called_with("body")
    assert "Body Content" in state.content_summary
