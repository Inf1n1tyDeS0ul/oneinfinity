import hashlib
import json
import re
import logging
from typing import Optional, Any, Set
from pydantic import BaseModel, ValidationError
try:
    from playwright.async_api import async_playwright
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    async_playwright = None  # type: ignore
    _PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger(__name__)

class StateNode(BaseModel):
    url: str
    state_hash: str
    content_summary: Optional[str] = None

class ActionCommand(BaseModel):
    thought: str
    action: str
    target: str
    value: Optional[str] = None
    is_destructive: bool = False

class AutonomousCrawler:
    def __init__(self, llm_client: Any = None):
        self.llm_client = llm_client
        self.visited_states: Set[str] = set()

    async def run(self, url: str, max_depth: int = 10):
        """
        Main execution loop for the autonomous crawler.
        """
        if not _PLAYWRIGHT_AVAILABLE:
            logger.warning("playwright not installed; autonomous crawler skipped for %s", url)
            return []
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                page = await context.new_page()
                
                await page.goto(url)
                
                for depth in range(max_depth):
                    state = await self._perceive_state(page)
                    
                    if state.state_hash in self.visited_states:
                        logger.info(f"Loop detected at state {state.state_hash}. Stopping.")
                        break
                    
                    self.visited_states.add(state.state_hash)
                    
                    # Simplified DOM for LLM (just using content summary for now)
                    action = await self._decide_next_action(state.content_summary or "")
                    
                    logger.info(f"Depth {depth}: {action.thought} | Action: {action.action} | Target: {action.target}")
                    
                    if action.is_destructive:
                        logger.warning(f"AWAITING_APPROVAL: Destructive action detected: {action.action} on {action.target}")
                        # For MVP, we stop at destructive actions
                        break
                    
                    try:
                        await self._execute_action_with_retry(page, action)
                    except Exception as e:
                        logger.error(f"Failed to execute action {action.action} on {action.target} after retries: {e}")
                        break
            finally:
                await browser.close()

    async def _execute_action_with_retry(self, page, action: ActionCommand, max_retries: int = 2):
        last_exception = None
        for attempt in range(max_retries + 1):
            try:
                if action.action == "click":
                    await page.click(action.target, timeout=5000)
                elif action.action == "type":
                    await page.fill(action.target, action.value or "", timeout=5000)
                elif action.action == "back":
                    await page.go_back(timeout=5000)
                elif action.action == "wait":
                    await page.wait_for_timeout(2000)
                else:
                    logger.warning(f"Unknown action: {action.action}")
                return # Success
            except Exception as e:
                last_exception = e
                if attempt < max_retries:
                    logger.warning(f"Retry {attempt + 1}/{max_retries} for action {action.action} on {action.target}")
                    await page.wait_for_timeout(1000)
                else:
                    raise last_exception

    async def _perceive_state(self, page) -> StateNode:
        url = page.url
        try:
            # Inject smart extraction script
            from oneinfinity.utils.browser_utils import get_accessibility_script
            elements = await page.evaluate(get_accessibility_script())
            content_summary = json.dumps(elements, indent=2)
            
            # For hashing, still use full body to detect subtle changes
            body_content = await page.inner_html("body")
        except Exception:
            # Fallback
            body_content = await page.content()
            content_summary = body_content[:2000]
        
        # Comprehensive state hashing
        state_hash = hashlib.sha256(f"{url}|{body_content}".encode()).hexdigest()
        
        return StateNode(
            url=url,
            state_hash=state_hash,
            content_summary=content_summary
        )

    async def _decide_next_action(self, simplified_dom: str) -> ActionCommand:
        """
        Ask LLM to decide the next action based on the simplified DOM.
        """
        if not self.llm_client:
            raise ValueError("llm_client is required for decision making")

        prompt = (
            f"Simplified DOM:\n{simplified_dom}\n\n"
            "Decide the next navigation action. Return ONLY a JSON object with this schema:\n"
            "{\n"
            "  \"thought\": \"reasoning for the action\",\n"
            "  \"action\": \"click|type|hover|wait|back\",\n"
            "  \"target\": \"CSS selector or null\",\n"
            "  \"value\": \"text to type or null\",\n"
            "  \"is_destructive\": boolean\n"
            "}"
        )
        response_text = self.llm_client.complete(prompt)
        
        # Clean markdown formatting if present
        json_match = re.search(r"```json\s*(.*?)\s*```", response_text, re.DOTALL)
        if json_match:
            clean_json = json_match.group(1)
        else:
            # Fallback: remove any leading/trailing markdown code block indicators if search fails
            clean_json = response_text.strip().strip("`")
            if clean_json.startswith("json"):
                clean_json = clean_json[4:].strip()

        try:
            data = json.loads(clean_json)
            return ActionCommand(**data)
        except (json.JSONDecodeError, ValidationError) as e:
            raise ValueError(f"Failed to parse LLM response: {response_text}") from e
