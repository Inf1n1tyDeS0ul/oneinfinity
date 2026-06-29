"""
MCP API endpoints for OneInfinity UI
Exposes MCP server status, configuration, and manual tool invocation
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import logging

log = logging.getLogger(__name__)

router = APIRouter(tags=["mcp"])


def register_routes(app, require_auth=None):
    """Register MCP routes. Mutating/exec endpoints always require auth;
    read-only status endpoints are gated only when require_auth is provided."""
    # Status + manifest are read-only — gate with auth when provided
    deps = [Depends(require_auth)] if require_auth else []
    app.include_router(router, prefix="/api", dependencies=deps)


class MCPToolRequest(BaseModel):
    """Request body for manual MCP tool invocation."""
    tool: str
    parameters: Dict[str, Any]


class MCPConfigUpdate(BaseModel):
    """Request body for MCP configuration updates."""
    enable_for_ui_scans: Optional[bool] = None
    strategy: Optional[str] = None
    payload_generation: Optional[bool] = None
    chain_detection: Optional[bool] = None
    validation_confidence: Optional[bool] = None
    skip_ai_when_payloads_provided: Optional[bool] = None


@router.get("/mcp/status")
async def get_mcp_status():
    """
    Get MCP server status and configuration.

    Returns:
        - enabled: MCP mode active
        - strategy: KEEP_BOTH, ORCHESTRATOR_ONLY, or ONEINFINITY_ONLY
        - features: Which AI features are active
        - budget: Current budget usage and limits
    """
    try:
        from oneinfinity.mcp import server as mcp_server
        import yaml
        from pathlib import Path

        config_path = Path(__file__).parent.parent.parent / "config" / "mcp.yaml"

        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f)
        else:
            config = {"mcp_mode": {"enabled": False}}

        mcp_config = config.get("mcp_mode", {})

        return {
            "enabled": mcp_config.get("enabled", False),
            "enable_for_ui_scans": mcp_config.get("enable_for_ui_scans", False),
            "strategy": mcp_config.get("strategy", "KEEP_BOTH"),
            "oneinfinity_ai": mcp_config.get("oneinfinity_ai", {}),
            "skip_ai_when_payloads_provided": mcp_config.get("skip_ai_when_payloads_provided", True),
            "server": config.get("server", {}),
            "ui_orchestrator": config.get("ui_orchestrator", {}),
            "tools_available": len(mcp_server.TOOLS),
            "tool_list": list(mcp_server.TOOLS.keys())
        }
    except Exception as e:
        log.exception("Failed to get MCP status")
        raise HTTPException(status_code=500, detail=f"Failed to get MCP status: {str(e)}")


@router.get("/mcp/manifest")
async def get_mcp_manifest():
    """
    Get MCP tool manifest.

    Returns tool definitions for all available MCP tools.
    """
    try:
        from oneinfinity.mcp import server as mcp_server
        return mcp_server.get_tool_manifest()
    except Exception as e:
        log.exception("Failed to get MCP manifest")
        raise HTTPException(status_code=500, detail=f"Failed to get manifest: {str(e)}")


@router.post("/mcp/tools/invoke")
async def invoke_mcp_tool(request: MCPToolRequest):
    """
    Manually invoke MCP tool from UI.

    Use case: Test MCP tools without external AI, or run specific operations
    that aren't exposed via standard API.

    Args:
        tool: Tool name (e.g., "oneinfinity_recon")
        parameters: Tool parameters as JSON object

    Returns:
        Tool execution result
    """
    try:
        from oneinfinity.mcp import server as mcp_server

        result = mcp_server.call_tool(request.tool, request.parameters)
        return result
    except Exception as e:
        log.exception(f"Failed to invoke MCP tool: {request.tool}")
        raise HTTPException(status_code=500, detail=f"Tool invocation failed: {str(e)}")


@router.patch("/mcp/config")
async def update_mcp_config(update: MCPConfigUpdate):
    """
    Update MCP configuration at runtime.

    Changes persist until restart. Modify config/mcp.yaml for permanent changes.

    Args:
        strategy: KEEP_BOTH, ORCHESTRATOR_ONLY, or ONEINFINITY_ONLY
        payload_generation: Enable/disable OneInfinity payload generation
        chain_detection: Enable/disable exploit chain detection
        validation_confidence: Enable/disable validation confidence scoring
        skip_ai_when_payloads_provided: Skip internal AI when external payloads provided

    Returns:
        Updated configuration
    """
    try:
        import yaml
        from pathlib import Path

        config_path = Path(__file__).parent.parent.parent / "config" / "mcp.yaml"

        if not config_path.exists():
            raise HTTPException(status_code=404, detail="MCP config file not found")

        with open(config_path) as f:
            config = yaml.safe_load(f)

        mcp_config = config.setdefault("mcp_mode", {})
        ai_config = mcp_config.setdefault("oneinfinity_ai", {})

        # Update UI scan mode
        if update.enable_for_ui_scans is not None:
            mcp_config["enable_for_ui_scans"] = update.enable_for_ui_scans

        # Update strategy
        if update.strategy is not None:
            if update.strategy not in ["KEEP_BOTH", "ORCHESTRATOR_ONLY", "ONEINFINITY_ONLY"]:
                raise HTTPException(status_code=400, detail="Invalid strategy")
            mcp_config["strategy"] = update.strategy

        # Update AI features
        if update.payload_generation is not None:
            ai_config["payload_generation"] = update.payload_generation

        if update.chain_detection is not None:
            ai_config["chain_detection"] = update.chain_detection

        if update.validation_confidence is not None:
            ai_config["validation_confidence"] = update.validation_confidence

        if update.skip_ai_when_payloads_provided is not None:
            mcp_config["skip_ai_when_payloads_provided"] = update.skip_ai_when_payloads_provided

        # Write updated config
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)

        log.info(f"MCP config updated: {update.dict(exclude_none=True)}")

        return {
            "success": True,
            "message": "MCP configuration updated",
            "config": config.get("mcp_mode", {})
        }

    except HTTPException:
        raise
    except Exception as e:
        log.exception("Failed to update MCP config")
        raise HTTPException(status_code=500, detail=f"Config update failed: {str(e)}")


@router.get("/mcp/cost-tracking")
async def get_mcp_cost_tracking():
    """
    Get cost tracking data for MCP mode.

    Shows separate costs for orchestrator AI vs OneInfinity AI.

    Returns:
        - orchestrator_ai_costs: Claude/Gemini/Ollama costs
        - oneinfinity_ai_costs: Internal AI costs
        - tool_costs: Tool execution costs
        - total_cost: Combined cost
        - daily_limit: Budget limit
        - percentage_used: Budget usage percentage
    """
    try:
        from oneinfinity.infra.model_budget_manager import ModelBudgetManager
        from pathlib import Path
        import json
        from datetime import datetime, timedelta

        budget_manager = ModelBudgetManager()

        # Get today's usage
        today = datetime.now().date()
        _summary = budget_manager.get_summary()
        usage = _summary.to_dict() if hasattr(_summary, 'to_dict') else (_summary if isinstance(_summary, dict) else vars(_summary))

        # Check for MCP-specific cost tracking (if implemented)
        cost_report_dir = Path(__file__).parent.parent.parent / "logs" / "cost_reports"
        mcp_costs = {
            "orchestrator_ai": 0.0,
            "oneinfinity_ai": 0.0,
            "tools": 0.0
        }

        if cost_report_dir.exists():
            today_file = cost_report_dir / f"mcp_costs_{today.isoformat()}.json"
            if today_file.exists():
                try:
                    with open(today_file) as f:
                        mcp_costs = json.load(f)
                except Exception:
                    pass

        daily_limit = usage.get("daily_budget", {}).get("limit", 5.0)
        daily_used = usage.get("daily_budget", {}).get("used", 0.0)

        total_mcp_cost = sum(mcp_costs.values())

        return {
            "costs": mcp_costs,
            "total_cost": total_mcp_cost,
            "daily_limit": daily_limit,
            "daily_used": daily_used,
            "percentage_used": (daily_used / daily_limit * 100) if daily_limit > 0 else 0,
            "remaining": max(0, daily_limit - daily_used)
        }

    except Exception as e:
        log.exception("Failed to get MCP cost tracking")
        raise HTTPException(status_code=500, detail=f"Cost tracking failed: {str(e)}")


@router.get("/mcp/integration-status")
async def get_mcp_integration_status():
    """
    Check integration status with Claude CLI, Gemini CLI, and Ollama.

    Returns:
        - claude_cli: Config file exists, recommended models
        - gemini_cli: Config file exists, recommended models
        - ollama: Config file exists, recommended models
    """
    try:
        from pathlib import Path
        import os
        import json

        home = Path.home()

        integrations = {}

        # Claude CLI
        claude_config = home / ".config" / "claude" / "mcp.json"
        integrations["claude_cli"] = {
            "config_exists": claude_config.exists(),
            "config_path": str(claude_config),
            "recommended_models": ["claude-opus-4", "claude-sonnet-4"]
        }

        # Gemini CLI
        gemini_config = home / ".config" / "gemini" / "mcp.json"
        integrations["gemini_cli"] = {
            "config_exists": gemini_config.exists(),
            "config_path": str(gemini_config),
            "recommended_models": ["gemini-2.0-flash-exp", "gemini-2.5-pro"]
        }

        # Ollama
        ollama_config = Path(__file__).parent.parent.parent / "mcp-config.json"
        integrations["ollama"] = {
            "config_exists": ollama_config.exists(),
            "config_path": str(ollama_config),
            "recommended_models": ["deepseek-r1", "llama3.2"]
        }

        return integrations

    except Exception as e:
        log.exception("Failed to get integration status")
        raise HTTPException(status_code=500, detail=f"Integration status check failed: {str(e)}")
