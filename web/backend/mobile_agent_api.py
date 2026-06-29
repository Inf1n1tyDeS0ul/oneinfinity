"""
OneInfinity Mobile Companion Agent API

WebSocket bidirectional communication for Android/iOS companion apps.
Handles device registration, command dispatch, traffic ingestion.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from typing import Dict, Optional, List
import asyncio
import json
import os
import pathlib
import secrets
import time
from datetime import datetime

# Active device connections
active_devices: Dict[str, WebSocket] = {}
device_metadata: Dict[str, dict] = {}
device_timestamps: Dict[str, float] = {}
device_tokens: Dict[str, str] = {}  # device_id -> registration token
# Device logs storage - stores last 500 logs per device
device_logs: Dict[str, List[dict]] = {}

# ── Persistent device registry ────────────────────────────────────────────────
# device_metadata is persisted to disk so devices survive backend restarts.
# Devices are shown as offline=True until they reconnect via WebSocket.

def _registry_path() -> pathlib.Path:
    try:
        from oneinfinity.infra.path_manager import raw_dir
        p = raw_dir() / "mobile" / "device_registry.json"
    except Exception:
        p = pathlib.Path(__file__).parent / "device_registry.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _persist_registry() -> None:
    """Write device_metadata to disk (best-effort)."""
    try:
        _registry_path().write_text(json.dumps(device_metadata, indent=2))
    except Exception:
        pass


def _load_registry() -> None:
    """Load persisted device_metadata from disk on startup."""
    try:
        data = json.loads(_registry_path().read_text())
        if isinstance(data, dict):
            device_metadata.update(data)
    except Exception:
        pass


# Load on import so devices are visible immediately after restart
_load_registry()

# ─────────────────────────────────────────────────────────────────────────────


def verify_device_token(device_id: str, token: str) -> bool:
    """Verify the per-device token issued at registration.
    If no token is stored for this device (e.g. backend restarted), allow through."""
    stored = device_tokens.get(device_id)
    if stored is None:
        return True   # no token issued yet — allow (device must re-register to get one)
    return stored == token


async def register_device_handler(device_info: dict) -> dict:
    """
    Register new companion device

    Payload:
    {
        "device_id": "abc123",
        "platform": "android" | "ios",
        "version": "14",
        "root_status": true,
        "capabilities": ["traffic", "frida", "proxy"]
    }
    """
    device_id = device_info.get("device_id")
    if not device_id:
        raise HTTPException(400, "device_id required")

    # Issue a per-device token for WebSocket authentication
    token = secrets.token_urlsafe(32)
    device_tokens[device_id] = token

    device_metadata[device_id] = {
        **device_info,
        "registered_at": datetime.utcnow().isoformat()
    }
    _persist_registry()

    # Phase 4: Register platform for cross-platform correlation engine
    try:
        from .mobile_ios_api import register_device_platform
        register_device_platform(device_id, device_info.get("platform", "android"), device_info)
    except Exception:
        pass

    return {
        "status": "registered",
        "device_id": device_id,
        "backend_version": "1.0",
        "ws_endpoint": f"/ws/mobile/{device_id}",
        "ws_token": token
    }


async def mobile_websocket_handler(websocket: WebSocket, device_id: str):
    """Bidirectional control channel"""
    await websocket.accept()
    active_devices[device_id] = websocket
    device_timestamps[device_id] = time.time()

    # If device reconnected after backend restart, restore it as online even
    # if it hasn't sent a fresh register POST yet (metadata loaded from disk).
    needs_reregister = device_id not in device_metadata or "platform" not in device_metadata.get(device_id, {})
    if device_id not in device_metadata:
        device_metadata[device_id] = {"device_id": device_id, "registered_at": datetime.utcnow().isoformat()}
    # Persist on connect so the device survives the next restart
    _persist_registry()

    # Only ask for re-registration when metadata is stale/incomplete (backend restarted
    # without disk data). Do NOT send this on every connect — it causes a register loop
    # because registerDevice() opens a new WebSocket which triggers another request.
    if needs_reregister:
        try:
            await websocket.send_json({"type": "request_reregister"})
        except Exception:
            pass

    print(f"[mobile-agent] Device connected: {device_id}")

    try:
        while True:
            data = await websocket.receive_json()
            await handle_device_message(device_id, data, websocket)
    except WebSocketDisconnect:
        if device_id in active_devices:
            del active_devices[device_id]
        print(f"[mobile-agent] Device disconnected: {device_id}")


async def handle_device_message(device_id: str, msg: dict, ws: WebSocket):
    """Route messages from device"""
    msg_type = msg.get("type")

    if msg_type == "heartbeat":
        device_timestamps[device_id] = time.time()
        await ws.send_json({"type": "heartbeat_ack", "timestamp": time.time()})

    elif msg_type == "traffic":
        await ingest_traffic(device_id, msg.get("request", {}), msg.get("response", {}))

    elif msg_type == "vuln_found":
        await ingest_finding(device_id, msg.get("finding", {}))

    elif msg_type == "log":
        await store_device_log(device_id, msg.get("message", ""))

    elif msg_type == "status_update":
        await handle_status_update(device_id, msg)

    elif msg_type == "frida_server_ready":
        # Phase 4: iOS/Android FridaManager confirms frida-server is running.
        # Update device metadata with server status and log it.
        session_id = msg.get("session_id", "")
        bundle_id = msg.get("package_name", "")
        running = msg.get("server_running", False)
        platform = msg.get("platform", device_metadata.get(device_id, {}).get("platform", "unknown"))
        if device_id in device_metadata:
            device_metadata[device_id]["frida_server_running"] = running
            device_metadata[device_id]["frida_ready_for"] = bundle_id
        print(f"[mobile-agent] frida_server_ready: device={device_id} platform={platform} "
              f"session={session_id} pkg={bundle_id} running={running}")

    elif msg_type == "frida_output":
        # Phase 3: route Frida output to mobile_frida_api for parsing + enrichment
        try:
            from .mobile_frida_api import ingest_frida_output
            ingest_frida_output(device_id, msg.get("session_id", ""), msg)
        except Exception as e:
            print(f"[mobile-agent] frida_output ingestion error: {e}")

    elif msg_type == "attack_finding":
        # Route to repeater if it's a repeater request
        try:
            from .mobile_repeater_api import resolve_repeater_result
            if resolve_repeater_result(msg.get("attack_id", ""), msg):
                return  # handled by repeater, don't persist as vuln finding
        except Exception:
            pass
        # Phase 2: attack finding streamed from AttackExecutor
        await ingest_finding(device_id, {
            "vuln_type": msg.get("vuln_type", "unknown"),
            "title": f"[Mobile Attack] {msg.get('vuln_type', 'finding')} on {msg.get('url', '')}",
            "severity": "medium",
            "evidence": str(msg.get("indicators", [])),
            "payload": msg.get("payload", ""),
            "url": msg.get("url", ""),
            "confidence": 0.7 if msg.get("indicators") else 0.4,
            "tool": "mobile_attack_executor",
        })

    elif msg_type == "injection_result":
        # Phase 2+3: mid-flight injection result from PayloadInjector
        # FIX #4: injection_id is NOT the same as frida session_id.
        # The companion must include source_session_id if it wants findings
        # routed to a Frida session. Otherwise persist as a standalone finding.
        try:
            from .mobile_frida_api import ingest_frida_output
            indicators = msg.get("indicators", [])
            vuln_type = msg.get("vuln_type", "injection")
            # Only route to frida session if source_session_id is explicitly set
            frida_session_id = msg.get("source_session_id", "")
            if frida_session_id:
                # FIX #1: f-string with nested quotes fixed — use explicit string concat
                finding_json = json.dumps({
                    "vulnerability": vuln_type,
                    "severity": "medium",
                    "evidence": str(indicators),
                    "attack_type": vuln_type,
                    "confidence": 0.7,
                })
                ingest_frida_output(device_id, frida_session_id, {
                    "session_id": frida_session_id,
                    "output": "[FRIDA_FINDING] " + finding_json,
                    "script_name": "payload_injector",
                    "package_name": msg.get("device_id", device_id),
                })
            else:
                # Persist directly as a standalone mobile agent finding
                if indicators:
                    await ingest_finding(device_id, {
                        "vuln_type": vuln_type,
                        "title": f"[Injection] {vuln_type} — {msg.get('param', '')}",
                        "severity": "medium",
                        "evidence": str(indicators),
                        "payload": msg.get("payload", ""),
                        "url": msg.get("url", ""),
                        "confidence": 0.7,
                        "tool": "payload_injector",
                    })
        except Exception as e:
            print(f"[mobile-agent] injection_result processing error: {e}")

    elif msg_type == "deeplink_fuzz_result":
        # Gap E: companion reports result of a deeplink fuzz case execution
        await ingest_finding(device_id, {
            "vuln_type": msg.get("vuln_type", "deeplink_injection"),
            "title": f"[Deeplink Fuzz] {msg.get('url', '')}",
            "severity": msg.get("severity", "medium"),
            "evidence": msg.get("evidence", ""),
            "url": msg.get("url", ""),
            "payload": msg.get("payload", ""),
            "confidence": 0.7,
            "tool": "ios_deeplink_fuzzer",
        })

    elif msg_type == "breakpoint_hit":
        try:
            from .mobile_breakpoint_api import ingest_breakpoint_hit
            ingest_breakpoint_hit(device_id, msg)
        except Exception as e:
            print(f"[mobile-agent] breakpoint_hit ingestion error: {e}")

    elif msg_type == "frida_ssl_hook_request":
        # App-side Frida SSL manager requesting backend to inject ssl_read_write_hook
        pid = msg.get("pid", -1)
        process_name = msg.get("process_name", "*")
        print(f"[mobile-agent] frida_ssl_hook_request: device={device_id} pid={pid} proc={process_name}")
        try:
            from .mobile_frida_api import inject_script_handler
            asyncio.create_task(inject_script_handler({
                "device_id": device_id,
                "package_name": process_name if process_name != "*" else "com.android.chrome",
                "script_name": "ssl_read_write_hook",
                "timeout": 0,
                "pid": pid if pid != -1 else None,
            }))
        except Exception as e:
            print(f"[mobile-agent] frida_ssl_hook_request error: {e}")

    elif msg_type == "frida_ssl_status":
        status = msg.get("status", "")
        count = msg.get("injected_count", 0)
        if device_id in device_metadata:
            device_metadata[device_id]["frida_ssl_status"] = status
            device_metadata[device_id]["frida_ssl_injected"] = count
        print(f"[mobile-agent] frida_ssl_status: {device_id} status={status} injected={count}")

    elif msg_type == "ebpf_output":
        # eBPF line from device — route to ecapture line stream parser
        try:
            line = msg.get("line", "")
            if line and line.strip():
                from .mobile_ebpf_capture import _strip_ansi, _ECAP_CONN_RE
                clean = _strip_ansi(line)
                # Connection metadata lines — emit as CONNECT entries
                cm = _ECAP_CONN_RE.search(clean)
                if cm:
                    dst_ip = (cm.group(5) or cm.group(6) or "").replace("::ffff:", "")
                    dst_port = int(cm.group(7))
                    pid = int(cm.group(1))
                    comm = cm.group(2).strip()
                    if dst_ip and dst_port > 0 and not comm.startswith("oneinfinity"):
                        await store_traffic(
                            device_id,
                            {"method": "CONNECT",
                             "url": f"https://{dst_ip}:{dst_port}",
                             "headers": {}, "body": "",
                             "_process": comm, "_pid": pid},
                            {"status_code": 0, "headers": {}, "body": ""},
                            source="ebpf", decrypted=False
                        )
                # Plaintext payload lines — parse as HTTP
                elif any(x in clean for x in ("GET ", "POST ", "PUT ", "DELETE ", "HTTP/", "Host:")):
                    from .mobile_ebpf_capture import _emit_ecapture_flow
                    asyncio.create_task(_emit_ecapture_flow(device_id, {}, clean))
        except Exception as e:
            print(f"[mobile-agent] ebpf_output error: {e}")

    elif msg_type == "ebpf_status":
        status = msg.get("status", "")
        if device_id in device_metadata:
            device_metadata[device_id]["ebpf_status"] = status
        print(f"[mobile-agent] ebpf_status: {device_id} status={status}")

    elif msg_type == "request_ecapture_push":
        # App asking backend to push ecapture binary
        print(f"[mobile-agent] ecapture push requested by {device_id}")
        try:
            from .mobile_ebpf_capture import push_ecapture_binary
            asyncio.create_task(_push_ecapture_and_notify(device_id))
        except Exception as e:
            print(f"[mobile-agent] ecapture push error: {e}")

    else:
        print(f"[mobile-agent] Unknown message type: {msg_type}")


async def _push_ecapture_and_notify(device_id: str):
    try:
        from .mobile_ebpf_capture import push_ecapture_binary
        result = await push_ecapture_binary(device_id)
        ws = active_devices.get(device_id)
        if ws:
            if result.get("success"):
                await ws.send_json({"type": "ecapture_pushed", "device_id": device_id})
            else:
                await ws.send_json({"type": "log", "message": f"[eBPF] Push failed: {result.get('error')}"})
    except Exception as e:
        print(f"[mobile-agent] _push_ecapture_and_notify error: {e}")


async def ingest_traffic_http(device_id: str, request: dict, response: dict) -> dict:
    """
    Gap D: HTTP endpoint for PacketTunnelProvider traffic upload.
    Extension uses POST /api/mobile/traffic instead of WebSocket so it
    does not compete with the main companion app's command WebSocket.
    """
    await ingest_traffic(device_id, request, response)
    return {"status": "ok", "device_id": device_id}


async def send_deeplink_fuzz_handler(device_id: str, fuzz_cases: list) -> dict:
    """
    Gap E: Push deeplink fuzz cases to iOS companion for execution.
    Companion opens each URL scheme locally via UIApplication.shared.open().
    """
    if device_id not in active_devices:
        raise HTTPException(404, f"Device {device_id} not connected")
    ws = active_devices[device_id]
    try:
        await ws.send_json({
            "type": "deeplink_fuzz",
            "device_id": device_id,
            "fuzz_cases": fuzz_cases[:50],  # cap to avoid flooding
        })
        return {"status": "sent", "fuzz_cases_count": min(len(fuzz_cases), 50)}
    except Exception as e:
        raise HTTPException(500, f"Failed to send deeplink fuzz: {e}")


async def send_command_handler(device_id: str, command: dict) -> dict:
    """Send command to device from UI"""
    if device_id not in active_devices:
        raise HTTPException(404, f"Device {device_id} not connected")

    ws = active_devices[device_id]
    try:
        await ws.send_json(command)
        return {"status": "sent", "device_id": device_id, "command_type": command.get("type")}
    except Exception as e:
        raise HTTPException(500, f"Failed to send command: {str(e)}")


async def get_device_status_handler(device_id: str) -> dict:
    """Check device health"""
    if device_id not in device_metadata:
        raise HTTPException(404, f"Device {device_id} not registered")

    online = device_id in active_devices
    uptime = calculate_uptime(device_id) if online else 0

    return {
        "status": "online" if online else "offline",
        "metadata": device_metadata.get(device_id, {}),
        "uptime": uptime,
        "last_seen": device_timestamps.get(device_id)
    }


async def list_devices_handler() -> List[dict]:
    """List all registered devices with capture status."""
    devices = []
    
    # Try to get unified capture status for each device
    try:
        from .mobile_unified_capture import get_capture_status
    except ImportError:
        get_capture_status = None

    for device_id, metadata in device_metadata.items():
        online = device_id in active_devices
        device_info = {
            **metadata,
            "online": online,
            "uptime": calculate_uptime(device_id) if online else 0
        }
        
        # Add capture status if engine available
        if get_capture_status:
            try:
                status = await get_capture_status(device_id)
                device_info["capture_status"] = status
            except Exception:
                pass
                
        devices.append(device_info)
    return devices


async def unregister_device_handler(device_id: str) -> dict:
    """Remove a stale device from the registry (in-memory + persisted)."""
    removed = False
    for store in (device_metadata, device_tokens, device_timestamps, device_logs):
        if device_id in store:
            del store[device_id]
            removed = True
    if device_id in active_devices:
        try:
            await active_devices[device_id].close()
        except Exception:
            pass
        del active_devices[device_id]
        removed = True
    _persist_registry()
    if not removed:
        raise HTTPException(404, f"Device {device_id} not found")
    return {"status": "removed", "device_id": device_id}


async def ingest_traffic(device_id: str, request: dict, response: dict):
    """Process captured traffic"""

    # FIX #15: Ingest for correlation before storing (so we have the chain data)
    try:
        from .mobile_correlation_engine import ingest_event
        ingest_event(device_id, "network", {"url": request.get("url"), "method": request.get("method"), "request": request, "response": response})
    except ImportError:
        pass

    # Store in traffic database
    await store_traffic(device_id, request, response)

    # Run lightweight vulnerability detection
    findings = await quick_scan(request, response)

    if findings:
        # Ingest into result engine
        try:
            from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
            engine = get_ingestion_engine()

            for f in findings:
                engine.persist_finding({
                    "source": "mobile_agent",
                    "device_id": device_id,
                    "vuln_type": f["type"],
                    "title": f.get("type", "mobile_finding").upper(),
                    "url": request.get("url", ""),
                    "parameter": f.get("parameter"),
                    "payload": f.get("payload", ""),
                    "severity": f["severity"],
                    "evidence": f.get("evidence", ""),
                    "tool": "mobile_agent_quick_scan",
                    "confidence": 0.7,
                })
        except ImportError:
            print("[mobile-agent] Result ingestion engine not available")

    # Broadcast to UI via WebSocket (TODO: implement UI broadcast)
    # await broadcast_to_ui({
    #     "type": "new_traffic",
    #     "device_id": device_id,
    #     "request": request,
    #     "response": response,
    #     "findings": findings
    # })


async def quick_scan(req: dict, resp: dict) -> List[dict]:
    """Lightweight vulnerability detection"""
    findings = []

    url = req.get("url", "")
    params = req.get("params", {})
    resp_body = resp.get("body", "") if resp else ""

    # SQL injection patterns
    if any(p in url for p in ["'", '"', "--", "/*", ";"]):
        if resp and any(err in resp_body.lower() for err in ["sql", "mysql", "sqlite", "syntax error", "database"]):
            findings.append({
                "type": "sqli",
                "severity": "high",
                "evidence": "SQL error pattern in response",
                "payload": url
            })

    # XSS reflection
    for param, value in params.items():
        if resp and str(value) in resp_body:
            # Check if unencoded
            if "<" in str(value) or ">" in str(value):
                findings.append({
                    "type": "xss",
                    "parameter": param,
                    "severity": "medium",
                    "evidence": f"Parameter {param} reflected unencoded",
                    "payload": str(value)
                })

    # Sensitive data exposure
    if resp:
        sensitive_patterns = ["password", "api_key", "secret", "token", "private_key"]
        for pattern in sensitive_patterns:
            if pattern in resp_body.lower():
                findings.append({
                    "type": "sensitive_data",
                    "severity": "high",
                    "evidence": f"Potential {pattern} exposure in response"
                })
                break

    return findings


async def ingest_finding(device_id: str, finding: dict):
    """Ingest finding from device"""
    try:
        from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine
        engine = get_ingestion_engine()

        enriched = {
            "source": "mobile_agent",
            "device_id": device_id,
            "tool": finding.get("tool", "mobile_agent"),
            "title": finding.get("title", finding.get("vuln_type", "mobile_finding")),
            "confidence": finding.get("confidence", 0.7),
            **finding,
        }
        engine.persist_finding(enriched)

        # Phase 4: Feed into cross-platform correlation engine
        try:
            from .mobile_ios_api import ingest_finding_for_correlation
            platform = device_metadata.get(device_id, {}).get("platform", "android")
            ingest_finding_for_correlation(enriched, platform, device_id)
        except Exception:
            pass
    except ImportError:
        print("[mobile-agent] Result ingestion engine not available")


async def store_device_log(device_id: str, message: str):
    """Store device log entry in memory."""
    if device_id not in device_logs:
        device_logs[device_id] = []
    
    log_entry = {
        "timestamp": time.time(),
        "level": "INFO",
        "tag": "DEVICE",
        "message": message,
    }
    
    device_logs[device_id].append(log_entry)
    # Keep only last 500 logs
    if len(device_logs[device_id]) > 500:
        device_logs[device_id].pop(0)
    
    timestamp_str = datetime.utcnow().isoformat()
    print(f"[{device_id}] [{timestamp_str}] {message}")


async def get_device_logs_handler(device_id: str, limit: int = 100) -> List[dict]:
    """Retrieve logs for a device."""
    logs = device_logs.get(device_id, [])
    return logs[-limit:]


async def get_app_info_handler(device_id: str, package_name: str) -> dict:
    """Request app metadata from companion device."""
    ws = active_devices.get(device_id)
    if not ws:
        raise HTTPException(404, f"Device {device_id} not connected")
    
    # Send command to device
    command = {
        "type": "get_app_info",
        "package_name": package_name
    }
    await ws.send_json(command)
    
    # In a real system, we'd wait for a response via WebSocket and use a Future.
    # For now, we'll return a placeholder or wait briefly.
    return {
        "status": "requested",
        "device_id": device_id,
        "package_name": package_name,
        "note": "Command sent to device. Result will appear in status updates."
    }


async def mirror_fuzz_handler(device_id: str, traffic_id: str) -> dict:
    """
    Innovative 'Mirror Fuzzing' — re-triggers a UI interaction observed in traffic
    and automatically injects mutation hooks into the app's internal logic.
    """
    ws = active_devices.get(device_id)
    if not ws:
        raise HTTPException(404, "Device not connected")

    # 1. Fetch the correlation chain to find the UI interaction
    try:
        from .mobile_correlation_engine import get_correlation_chain
        chain = await get_correlation_chain(device_id, traffic_id)
    except Exception:
        chain = None

    if not chain or not chain.get("preceding_ui"):
        raise HTTPException(400, "No UI interaction correlated with this traffic entry. Cannot mirror.")

    # 2. Get the last UI interaction
    last_ui = chain["preceding_ui"][0]
    
    # 3. Send 'mirror_fuzz' command to device
    # The device companion will:
    #   a. Find the view by ID/text
    #   b. performClick() on it
    #   c. While doing so, the Frida hooks (if active) will mutate the outgoing data
    await ws.send_json({
        "type": "mirror_fuzz",
        "ui_action": last_ui,
        "traffic_id": traffic_id,
        "mutation_payloads": ["<script>alert(1)</script>", "admin' --", "() { :; }; /bin/bash"]
    })

    return {
        "status": "started",
        "ui_action": last_ui["idName"] or last_ui["text"],
        "note": "Device is replaying the UI action with mutations."
    }


async def store_traffic(device_id: str, request: dict, response: dict,
                        source: str = "unknown", duration_ms: int = 0,
                        decrypted: bool = False, modified: bool = False,
                        session_id: str = ""):
    """Store traffic — routes through MergeEngine if unified session active, else SQLite direct."""
    try:
        from .mobile_unified_capture import route_to_merge
        await route_to_merge(device_id, request, response,
                             source=source, duration_ms=duration_ms,
                             decrypted=decrypted, modified=modified, session_id=session_id)
    except Exception as e:
        print(f"[mobile-agent] Traffic storage error: {e}")


async def handle_status_update(device_id: str, msg: dict):
    """Handle status updates from device"""
    if device_id in device_metadata:
        device_metadata[device_id].update({
            "last_status": msg.get("status"),
            "updated_at": datetime.utcnow().isoformat()
        })


def calculate_uptime(device_id: str) -> float:
    """Calculate device uptime in seconds"""
    if device_id not in device_timestamps:
        return 0.0
    return time.time() - device_timestamps[device_id]


async def get_traffic_handler(
    device_id: str,
    limit: int = 100,
    source: str = "",
    decrypted_only: bool = False,
    url_contains: str = "",
    method: str = "",
) -> List[dict]:
    """Get captured traffic for device from SQLite store."""
    try:
        from .mobile_traffic_store import get_traffic
        return await get_traffic(
            device_id, limit=limit,
            source=source or None,
            decrypted_only=decrypted_only,
            url_contains=url_contains or None,
            method=method or None,
        )
    except Exception as e:
        print(f"[mobile-agent] get_traffic error: {e}")
        return []


# Export handlers for integration with main.py
__all__ = [
    "register_device_handler",
    "mobile_websocket_handler",
    "verify_device_token",
    "send_command_handler",
    "get_device_status_handler",
    "list_devices_handler",
    "get_traffic_handler",
    "get_device_logs_handler",
    "get_app_info_handler",
    "mirror_fuzz_handler",
    "active_devices",
    "device_metadata",
    "device_logs"
]
