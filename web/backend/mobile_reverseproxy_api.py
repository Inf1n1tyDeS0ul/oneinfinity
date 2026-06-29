"""
Mobile Reverse Proxy API — no CA cert required

Starts a mitmproxy instance in reverse mode for a target host.
Device redirects target host → 127.0.0.1:local_port via /etc/hosts (root required)
or via adb reverse for non-rooted devices.

Traffic intercepted by mitmproxy flows into mobile_agent_api.ingest_traffic().
"""

import asyncio
import subprocess
import uuid
from typing import Dict, List
from fastapi import HTTPException


# Active reverse proxy workers
_workers: Dict[str, dict] = {}
_port_counter = 9100  # start allocating from this port


async def start_reverse_proxy_handler(body: dict) -> dict:
    """Start a reverse proxy worker for a target host."""
    global _port_counter

    target_host = body.get("target_host", "").strip()
    device_id = body.get("device_id", "")

    if not target_host:
        raise HTTPException(400, "target_host required")

    # Allocate a local port
    local_port = _port_counter
    _port_counter += 1

    proxy_id = str(uuid.uuid4())[:8]
    target_url = target_host if target_host.startswith("http") else f"https://{target_host}"

    # Build mitmproxy addon that pipes traffic into ingest_traffic
    addon_code = _build_addon(device_id, proxy_id)
    addon_path = f"/tmp/oneinfinity_rp_{proxy_id}.py"
    with open(addon_path, "w") as f:
        f.write(addon_code)

    cmd = [
        "mitmdump",
        "--mode", f"reverse:{target_url}",
        "--listen-port", str(local_port),
        "--ssl-insecure",   # accept self-signed certs on upstream
        "--quiet",
        "-s", addon_path,
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        raise HTTPException(500, "mitmdump not found — install mitmproxy: pip install mitmproxy")

    _workers[proxy_id] = {
        "proxy_id": proxy_id,
        "device_id": device_id,
        "target_host": target_host,
        "target_url": target_url,
        "local_port": local_port,
        "process": proc,
        "addon_path": addon_path,
    }

    # Push setup command to device if connected
    from . import mobile_agent_api
    if device_id and device_id in mobile_agent_api.active_devices:
        ws = mobile_agent_api.active_devices[device_id]
        await ws.send_json({
            "type": "setup_reverse_proxy",
            "proxy_id": proxy_id,
            "target_host": target_host.split("/")[-1].split(":")[0],  # bare hostname
            "local_port": local_port,
        })

    return {
        "proxy_id": proxy_id,
        "local_port": local_port,
        "target_url": target_url,
        "adb_command": f"adb reverse tcp:{local_port} tcp:{local_port}",
        "hosts_entry": f"127.0.0.1  {target_host.replace('https://', '').replace('http://', '').split('/')[0]}",
        "status": "started",
    }


async def stop_reverse_proxy_handler(proxy_id: str) -> dict:
    """Stop a running reverse proxy worker."""
    worker = _workers.get(proxy_id)
    if not worker:
        raise HTTPException(404, f"Proxy {proxy_id} not found")

    proc = worker.get("process")
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Clean up addon file
    import os
    try:
        os.remove(worker.get("addon_path", ""))
    except Exception:
        pass

    del _workers[proxy_id]
    return {"status": "stopped", "proxy_id": proxy_id}


async def list_reverse_proxies_handler() -> List[dict]:
    """List all active reverse proxy workers."""
    return [
        {k: v for k, v in w.items() if k not in ("process", "addon_path")}
        for w in _workers.values()
        if w.get("process") and w["process"].poll() is None
    ]


def _build_addon(device_id: str, proxy_id: str) -> str:
    """Generate a mitmproxy addon script that pipes traffic to the ingest endpoint."""
    return f'''
import sys, json, requests

DEVICE_ID = "{device_id}"
PROXY_ID = "{proxy_id}"
INGEST_URL = "http://127.0.0.1:8000/api/mobile/reverseproxy/ingest"


class OneInfinityAddon:
    def response(self, flow):
        try:
            req = flow.request
            resp = flow.response
            data = {{
                "device_id": DEVICE_ID,
                "proxy_id": PROXY_ID,
                "request": {{
                    "method": req.method,
                    "url": req.pretty_url,
                    "headers": dict(req.headers),
                    "body": req.get_text(strict=False) or "",
                }},
                "response": {{
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.get_text(strict=False) or "",
                }},
            }}
            requests.post(INGEST_URL, json=data, timeout=2)
        except Exception:
            pass


addons = [OneInfinityAddon()]
'''


async def ingest_reverseproxy_traffic_handler(body: dict) -> dict:
    """Receive traffic from the mitmproxy addon and feed into mobile_agent_api."""
    from . import mobile_agent_api
    device_id = body.get("device_id", "")
    await mobile_agent_api.ingest_traffic(
        device_id,
        body.get("request", {}),
        body.get("response", {})
    )
    return {"status": "ok"}
