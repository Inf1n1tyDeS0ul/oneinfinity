"""
MCP AI Client - Invokes external AI (Claude/Gemini/Ollama) for strategic decisions.

Used by god-mode conductor for high-level planning and mission prioritization.
"""
import json
import logging
import os
import subprocess
from typing import Dict, List, Optional

log = logging.getLogger("oneinfinity.mcp_ai_client")


class MCPAIClient:
    """
    Invokes external AI via MCP for strategic god-mode decisions.
    Falls back gracefully if MCP unavailable.
    """

    def __init__(self):
        self._enabled = self._check_mcp_enabled()
        self._provider = None
        self._model = None
        if self._enabled:
            self._load_config()

    def _check_mcp_enabled(self) -> bool:
        """Check if MCP external AI enabled in config."""
        try:
            import yaml
            from pathlib import Path
            config_path = Path(__file__).parent.parent.parent.parent / "config" / "mcp.yaml"
            if not config_path.exists():
                return False
            with open(config_path) as f:
                config = yaml.safe_load(f)
            return config.get("mcp_mode", {}).get("enable_for_ui_scans", False)
        except Exception as exc:
            log.debug("[MCP AI] Config check failed: %s", exc)
            return False

    def _load_config(self):
        """Load MCP AI provider config."""
        try:
            import yaml
            from pathlib import Path
            config_path = Path(__file__).parent.parent.parent.parent / "config" / "mcp.yaml"
            with open(config_path) as f:
                config = yaml.safe_load(f)
            ui_orch = config.get("ui_orchestrator", {})
            self._provider = ui_orch.get("provider", "anthropic")
            self._model = ui_orch.get("model", "claude-sonnet-4")
        except Exception as exc:
            log.warning("[MCP AI] Config load failed: %s", exc)
            self._enabled = False

    def plan_mission_priority(
        self,
        target: str,
        foundation_results: dict,
        available_missions: List[str]
    ) -> Optional[Dict]:
        """
        Ask external AI to prioritize missions based on foundation recon.

        Returns dict with:
        - mission_order: List[str] - recommended execution order
        - rationale: str - reasoning
        - focus_areas: List[str] - high-value attack surfaces
        """
        if not self._enabled:
            return None

        try:
            prompt = self._build_planning_prompt(target, foundation_results, available_missions)
            response = self._invoke_ai(prompt, task="god_mode_planning")

            if response:
                log.info("[MCP AI] Received mission planning guidance from %s", self._provider)
                return self._parse_planning_response(response, missions=available_missions)

        except Exception as exc:
            log.debug("[MCP AI] Planning invocation failed (non-fatal): %s", exc)

        return None

    def suggest_attack_strategy(
        self,
        target: str,
        findings: List[dict],
        mission_status: dict
    ) -> Optional[Dict]:
        """
        Ask external AI for strategic attack recommendations based on current state.

        Returns dict with:
        - next_actions: List[str] - recommended next steps
        - pivot_suggestions: List[str] - lateral movement ideas
        - priority_targets: List[str] - high-value endpoints
        """
        if not self._enabled:
            return None

        try:
            prompt = self._build_strategy_prompt(target, findings, mission_status)
            response = self._invoke_ai(prompt, task="attack_strategy")

            if response:
                log.info("[MCP AI] Received attack strategy from %s", self._provider)
                return self._parse_strategy_response(response)

        except Exception as exc:
            log.debug("[MCP AI] Strategy invocation failed (non-fatal): %s", exc)

        return None

    def _build_planning_prompt(
        self,
        target: str,
        foundation: dict,
        missions: List[str]
    ) -> str:
        """Build prompt for mission planning."""
        return f"""You are a security assessment orchestrator helping prioritize analysis modules
for an authorized vulnerability assessment on {target}.

Reconnaissance summary:
- Subdomains: {foundation.get('subdomains_count', 0)}
- Endpoints discovered: {foundation.get('endpoints_count', 0)}
- Technologies: {foundation.get('technologies', [])}
- WAF present: {foundation.get('waf_detected', False)}

Available analysis modules:
{chr(10).join(f'- {m}' for m in missions)}

Prioritize the modules based on the reconnaissance data.
Consider: endpoint density, technology risk profile, WAF impact on active testing.

Respond in JSON only, no other text:
{{
  "mission_order": ["full_scan", "swarm", "research", "auth_test"],
  "rationale": "brief reasoning based on the recon data",
  "focus_areas": ["authentication", "api_endpoints", "business_logic"]
}}"""

    def _build_strategy_prompt(
        self,
        target: str,
        findings: List[dict],
        status: dict
    ) -> str:
        """Build prompt for attack strategy."""
        findings_summary = []
        for f in findings[:10]:
            findings_summary.append(
                f"- {f.get('vuln_type', 'unknown')} ({f.get('severity', '?')}) at {f.get('url', '?')}"
            )

        return f"""You are assisting a god-mode penetration test that is in progress.

Target: {target}

Current findings ({len(findings)} total):
{chr(10).join(findings_summary)}

Mission status:
{json.dumps(status, indent=2)}

Provide strategic recommendations for:
1. Next attack vectors to explore
2. Lateral movement opportunities
3. Chain exploitation possibilities

Respond in JSON format:
{{
  "next_actions": ["test XSS on auth forms", "check for IDOR on /api/users"],
  "pivot_suggestions": ["leverage XSS for session hijacking", "combine SQLi + file upload"],
  "priority_targets": ["/admin", "/api/internal"]
}}"""

    def _invoke_ai(self, prompt: str, task: str) -> Optional[str]:
        """Invoke external AI via appropriate method.
        Tries configured provider first, then falls back to any available LLMProvider."""
        # Primary: try the configured provider
        if self._provider == "anthropic":
            result = self._invoke_claude(prompt)
            if result:
                return result
        elif self._provider == "google":
            result = self._invoke_gemini(prompt)
            if result:
                return result
        elif self._provider == "ollama":
            result = self._invoke_ollama(prompt)
            if result:
                return result
        elif self._provider == "bedrock":
            result = self._invoke_bedrock(prompt)
            if result:
                return result
        # Fallback: route through unified LLMProvider (picks best available: Bedrock, Groq, etc.)
        try:
            from oneinfinity.infra.llm_provider import get_provider
            provider = get_provider("analysis")
            resp = provider.chat(prompt, max_tokens=2048, temperature=0.3)
            if resp and resp.text:
                log.info("[MCP AI] Fell back to LLMProvider/%s", provider.name)
                return resp.text.strip()
        except Exception as exc:
            log.debug("[MCP AI] LLMProvider fallback failed: %s", exc)
        log.warning("[MCP AI] All providers exhausted for task=%s provider=%s", task, self._provider)
        return None

    def _invoke_bedrock(self, prompt: str) -> Optional[str]:
        """Invoke Claude via AWS Bedrock (no ANTHROPIC_API_KEY required)."""
        try:
            import boto3, json as _json, os as _os
            region = _os.environ.get("AWS_REGION", _os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
            client = boto3.client("bedrock-runtime", region_name=region)
            model_id = self._model or "eu.anthropic.claude-sonnet-4-6"
            # Normalize to a Bedrock-compatible model ID
            if model_id in ("claude-sonnet-4", "claude-sonnet-4-20250514"):
                model_id = "eu.anthropic.claude-sonnet-4-6"
            resp = client.converse(
                modelId=model_id,
                messages=[{"role": "user", "content": [{"text": prompt}]}],
                inferenceConfig={"maxTokens": 2048},
            )
            return resp["output"]["message"]["content"][0]["text"].strip()
        except Exception as exc:
            log.debug("[MCP AI] Bedrock invocation failed: %s", exc)
            return None

    def _invoke_claude(self, prompt: str) -> Optional[str]:
        """Invoke Claude via Anthropic API."""
        try:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if not api_key:
                return None

            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            message = client.messages.create(
                model=self._model or "claude-sonnet-4-20250514",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}]
            )

            return message.content[0].text

        except Exception as exc:
            log.debug("[MCP AI] Claude invocation failed: %s", exc)
            return None

    def _invoke_gemini(self, prompt: str) -> Optional[str]:
        """Invoke Gemini via Google API."""
        try:
            api_key = os.environ.get("GOOGLE_API_KEY")
            if not api_key:
                return None

            import google.generativeai as genai
            genai.configure(api_key=api_key)

            model = genai.GenerativeModel(self._model or "gemini-2.0-flash-exp")
            response = model.generate_content(prompt)

            return response.text

        except Exception as exc:
            log.debug("[MCP AI] Gemini invocation failed: %s", exc)
            return None

    def _invoke_ollama(self, prompt: str) -> Optional[str]:
        """Invoke Ollama local LLM."""
        try:
            import requests
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self._model or "deepseek-r1:7b",
                    "prompt": prompt,
                    "stream": False,
                },
                timeout=60
            )

            if response.ok:
                data = response.json()
                return data.get("response", "")

        except Exception as exc:
            log.debug("[MCP AI] Ollama invocation failed: %s", exc)

        return None

    def _parse_planning_response(self, response: str, missions: Optional[List[str]] = None) -> Optional[Dict]:
        """Parse JSON from AI planning response.
        Tries multiple extraction strategies; returns a default plan on total failure."""
        import re as _re
        if not response:
            return None
        # 1. Detect safety refusals — don't try to parse them
        refusal_markers = ("i won't", "i will not", "i cannot", "i can't", "not able to",
                           "unauthorized", "illegal", "unethical")
        if any(m in response.lower()[:200] for m in refusal_markers):
            log.warning("[MCP AI] LLM returned a safety refusal for planning prompt — using default order")
            return {"mission_order": missions or [], "rationale": "default (AI declined)",
                    "focus_areas": []}
        # 2. Extract from ```json ... ``` or ``` ... ``` fences
        candidate = response
        for pat in [r"```json\s*(.*?)```", r"```\s*(.*?)```"]:
            m = _re.search(pat, response, _re.DOTALL)
            if m:
                candidate = m.group(1).strip()
                break
        # 3. If no fences, try to find the first {...} block
        if candidate == response:
            m = _re.search(r'\{.*\}', response, _re.DOTALL)
            if m:
                candidate = m.group(0).strip()
        try:
            return json.loads(candidate)
        except Exception as exc:
            log.debug("[MCP AI] Response parsing failed: %s | candidate[:80]: %s",
                      exc, candidate[:80])
            return None

    def _parse_strategy_response(self, response: str) -> Optional[Dict]:
        """Parse JSON response from AI strategy."""
        return self._parse_planning_response(response)


_client: Optional[MCPAIClient] = None


def get_mcp_ai_client() -> MCPAIClient:
    """Get singleton MCP AI client."""
    global _client
    if _client is None:
        _client = MCPAIClient()
    return _client
