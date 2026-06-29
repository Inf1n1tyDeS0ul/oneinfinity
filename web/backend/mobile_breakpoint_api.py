"""
Mobile Breakpoint API — live request interception

Flow:
  1. POST /api/mobile/breakpoint/rule  → push breakpoint_add to device
  2. Device hits matching request, sends breakpoint_hit over WS
  3. mobile_agent_api routes breakpoint_hit here: store pending future
  4. Frontend polls GET /api/mobile/breakpoint/pending/{device_id}
  5. Tester edits request in BreakpointPanel.jsx, clicks "Release"
  6. POST /api/mobile/breakpoint/resume/{bp_id} → send breakpoint_resume to device
  7. Device unblocks coroutine, forwards (modified) bytes
"""

import asyncio
from fastapi import HTTPException
from typing import Dict, List
import uuid


# Pending breakpoints waiting for tester to release
# bp_id -> {"device_id", "url", "method", "headers", "raw_size", "future"}
_pending: Dict[str, dict] = {}

# Per-device rule registry
_device_rules: Dict[str, List[dict]] = {}


async def add_breakpoint_rule_handler(device_id: str, rule: dict) -> dict:
    """Push a breakpoint rule to the device."""
    from .mobile_agent_api import active_devices

    if device_id not in active_devices:
        raise HTTPException(404, f"Device {device_id} not connected")

    rule_id = rule.get("id") or str(uuid.uuid4())[:8]
    rule["id"] = rule_id

    if device_id not in _device_rules:
        _device_rules[device_id] = []
    _device_rules[device_id] = [r for r in _device_rules[device_id] if r.get("id") != rule_id]
    _device_rules[device_id].append(rule)

    ws = active_devices[device_id]
    await ws.send_json({"type": "breakpoint_add", **rule})
    return {"status": "pushed", "rule_id": rule_id}


async def remove_breakpoint_rule_handler(device_id: str, rule_id: str) -> dict:
    """Remove a breakpoint rule from the device."""
    from .mobile_agent_api import active_devices

    if device_id not in active_devices:
        raise HTTPException(404, f"Device {device_id} not connected")

    if device_id in _device_rules:
        _device_rules[device_id] = [r for r in _device_rules[device_id] if r.get("id") != rule_id]

    ws = active_devices[device_id]
    await ws.send_json({"type": "breakpoint_remove", "id": rule_id})

    # Unblock any pending hit for this rule
    for bp_id, bp in list(_pending.items()):
        if bp.get("rule_id", "").startswith(rule_id):
            bp["future"].set_result(None)
            del _pending[bp_id]

    return {"status": "removed", "rule_id": rule_id}


def ingest_breakpoint_hit(device_id: str, msg: dict):
    """Called by mobile_agent_api when breakpoint_hit WS message arrives."""
    bp_id = msg.get("breakpoint_id", "")
    if not bp_id:
        return

    loop = asyncio.get_event_loop()
    future = loop.create_future()

    _pending[bp_id] = {
        "breakpoint_id": bp_id,
        "device_id": device_id,
        "url": msg.get("url", ""),
        "method": msg.get("method", ""),
        "headers": msg.get("headers", {}),
        "raw_size": msg.get("raw_size", 0),
        "future": future,
    }


async def resume_breakpoint_handler(bp_id: str, modified_bytes: str = "") -> dict:
    """Release a paused breakpoint, optionally with modified request bytes."""
    bp = _pending.get(bp_id)
    if not bp:
        raise HTTPException(404, f"Breakpoint {bp_id} not found or already released")

    from .mobile_agent_api import active_devices
    device_id = bp["device_id"]

    if device_id not in active_devices:
        del _pending[bp_id]
        raise HTTPException(404, f"Device {device_id} disconnected")

    ws = active_devices[device_id]
    await ws.send_json({
        "type": "breakpoint_resume",
        "breakpoint_id": bp_id,
        "modified_bytes": modified_bytes,
    })

    del _pending[bp_id]
    return {"status": "resumed", "breakpoint_id": bp_id}


async def list_pending_breakpoints_handler(device_id: str) -> List[dict]:
    """List all breakpoints waiting for release for a device."""
    return [
        {k: v for k, v in bp.items() if k != "future"}
        for bp in _pending.values()
        if bp["device_id"] == device_id
    ]
