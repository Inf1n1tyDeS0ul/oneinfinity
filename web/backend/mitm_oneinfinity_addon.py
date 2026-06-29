"""
mitmproxy addon for OneInfinity — streams all flows to the backend.

Run via:
  mitmdump --mode transparent --listen-port 8080 --ssl-insecure -s mitm_oneinfinity_addon.py

Environment variables (set by mobile_mitm_api.py before launching):
  OI_BACKEND_URL   — e.g. http://127.0.0.1:8000
  OI_DEVICE_ID     — companion device_id
  OI_INTERCEPT     — "1" to enable intercept mode (pause each request)
"""

import json
import os
import time
import threading
import requests
from mitmproxy import http

BACKEND = os.environ.get("OI_BACKEND_URL", "http://127.0.0.1:8000")
DEVICE_ID = os.environ.get("OI_DEVICE_ID", "unknown")

# Intercept mode — flows are paused until backend resumes them
_intercept_enabled = os.environ.get("OI_INTERCEPT", "0") == "1"
_intercept_lock = threading.Lock()
# flow_id -> threading.Event (set when backend calls resume)
_pending_flows: dict = {}
# flow_id -> modified request bytes (None = pass through unchanged)
_modified_flows: dict = {}


def _post(path: str, data: dict):
    try:
        requests.post(f"{BACKEND}{path}", json=data, timeout=5)
    except Exception:
        pass


def request(flow: http.HTTPFlow):
    global _intercept_enabled

    if _intercept_enabled:
        # Pause flow — wait for backend to resume
        flow_id = str(id(flow))
        evt = threading.Event()
        with _intercept_lock:
            _pending_flows[flow_id] = evt

        req = flow.request
        _post("/api/mobile/mitm/intercept/hit", {
            "device_id": DEVICE_ID,
            "flow_id": flow_id,
            "method": req.method,
            "url": req.pretty_url,
            "headers": dict(req.headers),
            "body": req.get_text(strict=False) or "",
            "timestamp": time.time(),
        })

        flow.intercept()
        # Block until resume called (max 120s)
        evt.wait(timeout=120)

        with _intercept_lock:
            modified = _modified_flows.pop(flow_id, None)
            _pending_flows.pop(flow_id, None)

        if modified:
            # Apply modification
            try:
                mod = json.loads(modified)
                if "method" in mod:
                    flow.request.method = mod["method"]
                if "url" in mod:
                    flow.request.url = mod["url"]
                if "headers" in mod:
                    flow.request.headers.clear()
                    for k, v in mod["headers"].items():
                        flow.request.headers[k] = v
                if "body" in mod:
                    flow.request.set_text(mod["body"])
            except Exception:
                pass

        flow.resume()


def response(flow: http.HTTPFlow):
    req = flow.request
    resp = flow.response

    try:
        req_body = req.get_text(strict=False) or ""
    except Exception:
        req_body = ""
    try:
        resp_body = resp.get_text(strict=False) or ""
    except Exception:
        resp_body = ""

    duration_ms = 0
    if hasattr(flow, "duration") and flow.duration:
        duration_ms = int(flow.duration * 1000)

    _post("/api/mobile/mitm/ingest", {
        "device_id": DEVICE_ID,
        "request": {
            "method": req.method,
            "url": req.pretty_url,
            "headers": dict(req.headers),
            "body": req_body,
        },
        "response": {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp_body[:65536],
        },
        "duration_ms": duration_ms,
    })


def resume_flow(flow_id: str, modified: str = None):
    """Called from mobile_mitm_api when tester clicks Forward."""
    with _intercept_lock:
        if modified:
            _modified_flows[flow_id] = modified
        evt = _pending_flows.get(flow_id)
    if evt:
        evt.set()


def set_intercept(enabled: bool):
    global _intercept_enabled
    _intercept_enabled = enabled
