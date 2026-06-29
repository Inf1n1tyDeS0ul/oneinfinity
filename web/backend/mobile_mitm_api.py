"""
Layer 1: mitmproxy Transparent HTTPS Proxy

Sets up mitmproxy in transparent mode on the host, redirects device traffic
via iptables on the rooted Android device. Gives full decrypted HTTP/1.x and
HTTP/2 content for ~75% of apps (those without cert pinning).

Also implements Burp-like intercept mode: flows can be paused, edited, and
forwarded — reuses the existing mobile_breakpoint_api pending map pattern.
"""

import asyncio
import logging
import os
import subprocess
import shutil
import time
import uuid
from typing import Dict, List, Optional

from fastapi import HTTPException

log = logging.getLogger("oneinfinity.mobile_mitm")


def _get_adb_serial() -> str:
    try:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                return parts[0]
    except Exception:
        pass
    return ""

_ADDON_PATH = os.path.join(os.path.dirname(__file__), "mitm_oneinfinity_addon.py")

# Active mitm workers: device_id -> process
_workers: Dict[str, dict] = {}

# Intercept mode: device_id -> bool
_intercept_enabled: Dict[str, bool] = {}

# Pending intercepted flows: flow_id -> {device_id, request, future}
_pending_intercepts: Dict[str, dict] = {}


async def start_mitm_handler(body: dict) -> dict:
    """Start mitmproxy transparent proxy for a device."""
    device_id = body.get("device_id", "")
    port = body.get("port", 8080)
    if not device_id:
        raise HTTPException(400, "device_id required")
    if device_id in _workers and _workers[device_id]["process"].poll() is None:
        return {"status": "already_running", "device_id": device_id, "port": _workers[device_id]["port"]}

    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        raise HTTPException(500, "mitmdump not found — install: pip install mitmproxy")

    env = {**os.environ,
           "OI_BACKEND_URL": "http://127.0.0.1:8000",
           "OI_DEVICE_ID": device_id,
           "OI_INTERCEPT": "0"}

    proc = subprocess.Popen(
        [mitmdump,
         "--mode", "transparent",
         "--listen-port", str(port),
         "--ssl-insecure",
         "--quiet",
         "-s", _ADDON_PATH],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    _workers[device_id] = {"process": proc, "port": port, "started_at": time.time()}

    # Set up adb reverse so device port 8080 → Mac port 8080
    # Then configure device system proxy to 127.0.0.1:8080
    # This is the correct approach for USB-connected devices.
    # Do NOT use iptables redirect — that breaks routing when mitmproxy is on the host.
    adb_serial = _get_adb_serial()
    adb_cmd = ["adb"]
    if adb_serial:
        adb_cmd += ["-s", adb_serial]

    try:
        subprocess.run(adb_cmd + ["reverse", f"tcp:{port}", f"tcp:{port}"],
                       capture_output=True, timeout=10)
        subprocess.run(adb_cmd + ["shell", "settings", "put", "global",
                                   "http_proxy", f"127.0.0.1:{port}"],
                       capture_output=True, timeout=10)
    except Exception as e:
        log.warning("[mitm] adb reverse/proxy setup failed: %s", e)

    return {"status": "started", "device_id": device_id, "port": port,
            "note": "adb reverse and system proxy set. CA cert needed for HTTPS decryption."}


async def stop_mitm_handler(device_id: str) -> dict:
    """Stop mitmproxy and remove iptables rules."""
    worker = _workers.pop(device_id, None)
    if worker:
        proc = worker["process"]
        if proc.poll() is None:
            proc.terminate()

    # Remove system proxy and adb reverse
    adb_serial = _get_adb_serial()
    adb_cmd = ["adb"]
    if adb_serial:
        adb_cmd += ["-s", adb_serial]
    try:
        subprocess.run(adb_cmd + ["shell", "settings", "put", "global", "http_proxy", ":0"],
                       capture_output=True, timeout=10)
        subprocess.run(adb_cmd + ["reverse", "--remove", f"tcp:{worker['port'] if worker else 8080}"],
                       capture_output=True, timeout=10)
    except Exception as e:
        log.warning("[mitm] adb proxy teardown failed: %s", e)

    return {"status": "stopped", "device_id": device_id}


async def mitm_status_handler(device_id: str) -> dict:
    worker = _workers.get(device_id)
    if not worker:
        return {"status": "stopped", "device_id": device_id}
    running = worker["process"].poll() is None
    return {"status": "running" if running else "stopped",
            "device_id": device_id, "port": worker["port"]}


async def enable_intercept_handler(body: dict) -> dict:
    """Toggle intercept mode for a device's mitmproxy worker."""
    device_id = body.get("device_id", "")
    enabled = body.get("enabled", True)
    if not device_id:
        raise HTTPException(400, "device_id required")

    _intercept_enabled[device_id] = enabled

    # Signal the addon via env var replacement requires restart — instead
    # use a sidecar flag file the addon polls
    flag_path = f"/tmp/oi_mitm_intercept_{device_id}"
    if enabled:
        open(flag_path, "w").close()
    else:
        try:
            os.remove(flag_path)
        except FileNotFoundError:
            pass

    # Restart mitmproxy with updated OI_INTERCEPT env if running
    worker = _workers.get(device_id)
    if worker and worker["process"].poll() is None:
        worker["process"].terminate()
        port = worker["port"]
        mitmdump = shutil.which("mitmdump")
        env = {**os.environ,
               "OI_BACKEND_URL": "http://127.0.0.1:8000",
               "OI_DEVICE_ID": device_id,
               "OI_INTERCEPT": "1" if enabled else "0"}
        proc = subprocess.Popen(
            [mitmdump, "--mode", "transparent", "--listen-port", str(port),
             "--ssl-insecure", "--quiet", "-s", _ADDON_PATH],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _workers[device_id] = {"process": proc, "port": port, "started_at": time.time()}

    return {"status": "ok", "device_id": device_id, "intercept": enabled}


async def intercept_hit_handler(body: dict) -> dict:
    """Called by mitm addon when a request is intercepted (paused)."""
    device_id = body.get("device_id", "")
    flow_id = body.get("flow_id", "")
    if not flow_id:
        return {"status": "ignored"}

    loop = asyncio.get_event_loop()
    future = loop.create_future()

    _pending_intercepts[flow_id] = {
        "flow_id": flow_id,
        "device_id": device_id,
        "method": body.get("method", ""),
        "url": body.get("url", ""),
        "headers": body.get("headers", {}),
        "body": body.get("body", ""),
        "timestamp": body.get("timestamp", time.time()),
        "future": future,
        "source": "mitm",
    }

    return {"status": "queued", "flow_id": flow_id}


async def list_pending_intercepts_handler(device_id: str) -> List[dict]:
    """List all paused flows waiting for tester action."""
    return [
        {k: v for k, v in entry.items() if k != "future"}
        for entry in _pending_intercepts.values()
        if entry["device_id"] == device_id
    ]


async def resume_intercept_handler(flow_id: str, body: dict) -> dict:
    """Forward a paused flow, optionally with modified request."""
    entry = _pending_intercepts.pop(flow_id, None)
    if not entry:
        raise HTTPException(404, f"Flow {flow_id} not found or already forwarded")

    modified = body.get("modified")  # JSON string with {method, url, headers, body}
    # Signal the addon (it's blocking in a thread waiting for a file flag)
    flag_path = f"/tmp/oi_mitm_resume_{flow_id}"
    with open(flag_path, "w") as f:
        f.write(modified or "")

    return {"status": "forwarded", "flow_id": flow_id, "modified": bool(modified)}


async def ingest_mitm_traffic_handler(body: dict) -> dict:
    """Receive decrypted flow from addon and store it."""
    device_id = body.get("device_id", "")
    from .mobile_agent_api import store_traffic
    await store_traffic(
        device_id,
        body.get("request", {}),
        body.get("response", {}),
        source="mitm",
        duration_ms=body.get("duration_ms", 0),
        decrypted=True,
    )
    return {"status": "ok"}


async def install_ca_cert_handler(body: dict) -> dict:
    """Push mitmproxy CA cert to Android system trust store (root required)."""
    device_id = body.get("device_id", "")
    ca_pem_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

    if not os.path.exists(ca_pem_path):
        raise HTTPException(404, f"CA cert not found at {ca_pem_path}. Run mitmdump once to generate it.")

    # Get hash for Android cert naming
    result = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", ca_pem_path],
        capture_output=True, text=True, timeout=10
    )
    cert_hash = result.stdout.strip().split("\n")[0].strip()
    if not cert_hash:
        raise HTTPException(500, "Could not compute cert hash")

    dest = f"{cert_hash}.0"
    adb = ["adb"]
    if device_id:
        adb += ["-s", device_id]

    # Push cert
    subprocess.run(adb + ["push", ca_pem_path, f"/data/local/tmp/{dest}"],
                   check=True, timeout=15)

    # Install into system trust store
    cmds = [
        "mount -o rw,remount /system",
        f"cp /data/local/tmp/{dest} /system/etc/security/cacerts/{dest}",
        f"chmod 644 /system/etc/security/cacerts/{dest}",
        "mount -o ro,remount /system",
    ]
    for cmd in cmds:
        subprocess.run(adb + ["shell", "su", "-c", cmd], timeout=10)

    return {"status": "installed", "cert_hash": cert_hash,
            "dest": f"/system/etc/security/cacerts/{dest}",
            "note": "Reboot device for cert to take effect in all apps"}


def list_mitm_workers() -> List[dict]:
    return [
        {"device_id": did, "port": w["port"],
         "running": w["process"].poll() is None,
         "started_at": w["started_at"]}
        for did, w in _workers.items()
    ]
