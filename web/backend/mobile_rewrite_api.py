"""
Mobile Rewrite Rule API — priority-ordered rewrite engine

Pushes rewrite rules to companion device via WebSocket.
Rules evaluated in priority order: redirect > replace_request > replace_response
                                    > modify_request > modify_response
"""

from fastapi import HTTPException
from typing import Dict, List
import uuid


# Per-device rule registry (in-memory, device is source of truth)
_device_rules: Dict[str, List[dict]] = {}


async def add_rewrite_rule_handler(device_id: str, rule: dict) -> dict:
    """Push a rewrite rule to the device."""
    from .mobile_agent_api import active_devices

    if device_id not in active_devices:
        raise HTTPException(404, f"Device {device_id} not connected")

    rule_id = rule.get("id") or str(uuid.uuid4())[:8]
    rule["id"] = rule_id

    # Track server-side for listing
    if device_id not in _device_rules:
        _device_rules[device_id] = []
    _device_rules[device_id] = [r for r in _device_rules[device_id] if r.get("id") != rule_id]
    _device_rules[device_id].append(rule)

    ws = active_devices[device_id]
    await ws.send_json({"type": "rewrite_rule_add", **rule})
    return {"status": "pushed", "rule_id": rule_id}


async def remove_rewrite_rule_handler(device_id: str, rule_id: str) -> dict:
    """Remove a rewrite rule from the device."""
    from .mobile_agent_api import active_devices

    if device_id not in active_devices:
        raise HTTPException(404, f"Device {device_id} not connected")

    if device_id in _device_rules:
        _device_rules[device_id] = [r for r in _device_rules[device_id] if r.get("id") != rule_id]

    ws = active_devices[device_id]
    await ws.send_json({"type": "rewrite_rule_remove", "id": rule_id})
    return {"status": "removed", "rule_id": rule_id}


async def list_rewrite_rules_handler(device_id: str) -> List[dict]:
    """List tracked rewrite rules for a device."""
    return _device_rules.get(device_id, [])
