import pytest
from unittest.mock import MagicMock
from oneinfinity.scan.autonomous_crawler import AutonomousCrawler, ActionCommand

@pytest.mark.asyncio
async def test_decide_next_action_parsing():
    # Setup
    llm_client = MagicMock()
    # Mock LLM response as a JSON string
    llm_client.complete.return_value = '{"thought": "I need to login", "action": "click", "target": "#login-btn", "value": null, "is_destructive": false}'
    
    crawler = AutonomousCrawler(llm_client=llm_client)
    simplified_dom = "<html><body><button id='login-btn'>Login</button></body></html>"
    
    # Execute
    action = await crawler._decide_next_action(simplified_dom)
    
    # Verify
    assert isinstance(action, ActionCommand)
    assert action.thought == "I need to login"
    assert action.action == "click"
    assert action.target == "#login-btn"
    assert action.is_destructive is False
    llm_client.complete.assert_called_once()

@pytest.mark.asyncio
async def test_decide_next_action_markdown_json():
    """Bug: Fails if LLM returns markdown-wrapped JSON."""
    llm_client = MagicMock()
    # Mock LLM response with markdown
    llm_client.complete.return_value = '```json\n{"thought": "test", "action": "click", "target": "#btn", "value": null, "is_destructive": false}\n```'
    
    crawler = AutonomousCrawler(llm_client=llm_client)
    action = await crawler._decide_next_action("<html></html>")
    
    assert action.thought == "test"
    assert action.target == "#btn"

@pytest.mark.asyncio
async def test_decide_next_action_invalid_json():
    # Setup
    llm_client = MagicMock()
    llm_client.complete.return_value = "Invalid JSON"
    
    crawler = AutonomousCrawler(llm_client=llm_client)
    
    # Execute & Verify
    with pytest.raises(ValueError, match="Failed to parse LLM response"):
        await crawler._decide_next_action("<html></html>")

@pytest.mark.asyncio
async def test_decide_next_action_missing_fields():
    """Risk: Valid JSON but missing required Pydantic fields."""
    llm_client = MagicMock()
    # Missing 'action' and 'target'
    llm_client.complete.return_value = '{"thought": "incomplete"}'
    
    crawler = AutonomousCrawler(llm_client=llm_client)
    
    # Verify it raises ValueError due to Pydantic ValidationError
    with pytest.raises(ValueError, match="Failed to parse LLM response"):
        await crawler._decide_next_action("<html></html>")
