import asyncio
from typing import Dict, Any

async def scan_scenario() -> Dict[str, Any]:
    """Simulate scan engine execution."""
    await asyncio.sleep(0.1)
    # Simulate a successful scan with some findings
    return {"status": "success", "findings": ["vuln1", "vuln2"]}

async def agent_scenario() -> Dict[str, Any]:
    """Simulate agent router execution."""
    await asyncio.sleep(0.1)
    # Simulate routing a task successfully
    return {"status": "success", "action": "recon", "target": "example.com"}

async def ingestion_scenario() -> Dict[str, Any]:
    """Simulate ingestion pipeline execution."""
    await asyncio.sleep(0.1)
    # Simulate ingesting records
    return {"status": "success", "ingested_count": 5}

async def api_scenario() -> Dict[str, Any]:
    """Simulate API execution if present."""
    await asyncio.sleep(0.1)
    # Simulate successful API response
    return {"status": "success", "data": "ok"}

async def tool_registry_scenario() -> Dict[str, Any]:
    """Check tool registry availability (real, lightweight)."""
    await asyncio.sleep(0.05)
    try:
        from oneinfinity.modules.tool_wrappers import ToolRegistry
        reg = ToolRegistry()
        available = reg.available_tools()
        missing = reg.missing_tools()
        return {
            "status": "success",
            "available_count": len(available),
            "missing_count": len(missing),
            "available_sample": available[:5],
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

async def ingestion_db_scenario() -> Dict[str, Any]:
    """Validate findings DB initialization (real)."""
    await asyncio.sleep(0.05)
    try:
        from oneinfinity.result_ingestion_engine import get_ingestion_engine
        eng = get_ingestion_engine()
        return {
            "status": "success",
            "db_path": str(eng._db_path),
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

async def unified_scan_engine_scenario() -> Dict[str, Any]:
    """Import UnifiedScanEngine to ensure core pipeline is available."""
    await asyncio.sleep(0.05)
    try:
        from oneinfinity.unified_scan_engine import get_engine
        eng = get_engine()
        return {"status": "success", "engine": str(type(eng).__name__)}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

SCENARIOS = {
    "scan_engine": scan_scenario,
    "agent_router": agent_scenario,
    "ingestion_pipeline": ingestion_scenario,
    "api_endpoint": api_scenario,
    "tool_registry": tool_registry_scenario,
    "ingestion_db": ingestion_db_scenario,
    "unified_scan_engine": unified_scan_engine_scenario,
}
