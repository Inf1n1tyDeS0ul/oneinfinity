"""
Repeater API — replay any captured request with modifications.

Like Burp Repeater: pre-populate from traffic history, edit any field,
send, see diff vs original response.
"""

import asyncio
import difflib
import time
import uuid
from typing import Dict, List, Optional

from fastapi import HTTPException

# Per-device repeater history: device_id -> list of {id, request, response, ts}
_history: Dict[str, List[dict]] = {}


async def send_repeater_request(body: dict) -> dict:
    """
    Replay a request from the device. Dispatches via AttackExecutor
    (execute_attack WebSocket command) and waits for the result.

    Body: {device_id, method, url, headers, body, timeout?}
    """
    device_id = body.get("device_id", "")
    method = body.get("method", "GET").upper()
    url = body.get("url", "")
    headers = body.get("headers", {})
    req_body = body.get("body", "")
    timeout = body.get("timeout", 30)

    if not device_id or not url:
        raise HTTPException(400, "device_id and url required")

    from .mobile_agent_api import active_devices
    ws = active_devices.get(device_id)
    if not ws:
        raise HTTPException(404, f"Device {device_id} not connected")

    request_id = str(uuid.uuid4())[:8]

    # Build a single-payload attack command targeting the exact URL
    cmd = {
        "type": "execute_attack",
        "attack_id": f"repeater_{request_id}",
        "url": url,
        "method": method,
        "headers": headers,
        "payloads": [req_body],  # single "payload" = the request body as-is
        "param": "",
        "position": "body",
        "vuln_type": "repeater",
        "capture_baseline": False,
    }

    # Set up a future to capture the response
    loop = asyncio.get_event_loop()
    result_future: asyncio.Future = loop.create_future()
    _pending_results[request_id] = result_future

    await ws.send_json(cmd)

    try:
        result = await asyncio.wait_for(result_future, timeout=timeout)
    except asyncio.TimeoutError:
        _pending_results.pop(request_id, None)
        raise HTTPException(504, f"Request timed out after {timeout}s")
    finally:
        _pending_results.pop(request_id, None)

    entry = {
        "id": request_id,
        "timestamp": time.time(),
        "request": {"method": method, "url": url, "headers": headers, "body": req_body},
        "response": result,
    }
    _history.setdefault(device_id, []).append(entry)
    # Keep last 100
    if len(_history[device_id]) > 100:
        _history[device_id] = _history[device_id][-100:]

    return entry


# Pending repeater results: request_id -> Future
_pending_results: Dict[str, asyncio.Future] = {}


def resolve_repeater_result(attack_id: str, result: dict) -> bool:
    """Called from mobile_agent_api when attack_finding arrives for a repeater request."""
    if not attack_id.startswith("repeater_"):
        return False
    request_id = attack_id[len("repeater_"):]
    future = _pending_results.get(request_id)
    if future and not future.done():
        future.set_result({
            "status_code": result.get("attack_status", 0),
            "body": result.get("response_preview", ""),
            "headers": {},
            "timing_ms": result.get("attack_ms", 0),
        })
        return True
    return False


async def get_repeater_history(device_id: str) -> List[dict]:
    return list(reversed(_history.get(device_id, [])))


async def diff_repeater_responses(entry_id_a: str, entry_id_b: str, device_id: str) -> dict:
    """Return unified diff of two repeater response bodies."""
    history = _history.get(device_id, [])
    a = next((e for e in history if e["id"] == entry_id_a), None)
    b = next((e for e in history if e["id"] == entry_id_b), None)
    if not a or not b:
        raise HTTPException(404, "One or both entry IDs not found")

    body_a = (a.get("response") or {}).get("body", "")
    body_b = (b.get("response") or {}).get("body", "")

    diff = list(difflib.unified_diff(
        body_a.splitlines(keepends=True),
        body_b.splitlines(keepends=True),
        fromfile=f"response_{entry_id_a}",
        tofile=f"response_{entry_id_b}",
        lineterm="",
    ))

    return {
        "entry_id_a": entry_id_a,
        "entry_id_b": entry_id_b,
        "diff": "".join(diff),
        "changed": body_a != body_b,
    }
