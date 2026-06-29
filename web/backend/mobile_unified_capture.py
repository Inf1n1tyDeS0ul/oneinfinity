"""
Unified Capture Session — one button, all layers, merged output.

Replaces the separate start/stop calls for tcpdump, mitmproxy, eBPF, and VPN.

Startup sequence (parallel, ~5s):
  1. Probe capabilities (root, mitmdump, frida-server, ecapture)
  2. Start all available layers simultaneously
  3. MergeEngine collapses duplicates by (method+url) within a 500ms window
  4. Richest version (highest PRIORITY) written to SQLite
  5. WebSocket broadcast pushes each new entry to subscribed frontends

Intercept (Option B — layer-aware):
  - Normal apps  → mitmproxy intercepts (full HTTP modify)
  - Pinned apps  → Frida SSL_write hook intercepts (TLS buffer modify)
  - Resume routes to the correct layer automatically via `source` field
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

log = logging.getLogger("oneinfinity.unified_capture")

# Source priority for merge deduplication — higher = richer
SOURCE_PRIORITY: Dict[str, int] = {
    "frida_ssl":    5,
    "mitm":         4,
    "ebpf":         3,
    "ebpf_tshark":  3,
    "tcpdump":      1,
    "vpn":          0,
    "unknown":      0,
}

MERGE_WINDOW_MS = 500  # collapse duplicates within this window


# ── Active sessions ───────────────────────────────────────────────────────────

_sessions: Dict[str, "UnifiedCaptureSession"] = {}

# WebSocket subscribers: device_id -> set of WebSocket objects
_ws_subscribers: Dict[str, Set] = {}


def subscribe_ws(device_id: str, ws) -> None:
    _ws_subscribers.setdefault(device_id, set()).add(ws)


def unsubscribe_ws(device_id: str, ws) -> None:
    _ws_subscribers.get(device_id, set()).discard(ws)


async def _broadcast(device_id: str, entry: dict) -> None:
    """Push a traffic entry to all subscribed WebSocket clients."""
    subs = list(_ws_subscribers.get(device_id, set()))
    if not subs:
        return
    msg = json.dumps({"type": "traffic_entry", "entry": entry})
    dead = []
    for ws in subs:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_subscribers.get(device_id, set()).discard(ws)


# ── Capability probe ──────────────────────────────────────────────────────────

@dataclass
class Capabilities:
    root: bool = False
    mitmdump: bool = False
    frida_server: bool = False
    ecapture: bool = False
    tcpdump: bool = False


def _get_adb_serial() -> str:
    """Get the ADB serial of the first connected device."""
    try:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                return parts[0]
    except Exception:
        pass
    return ""


async def probe_capabilities(device_id: str) -> Capabilities:
    caps = Capabilities()
    # device_id is Android ID — we need ADB serial for adb commands
    serial = _get_adb_serial()
    adb = ["adb"]
    if serial:
        adb += ["-s", serial]

    loop = asyncio.get_event_loop()

    def _probe_sync() -> Capabilities:
        c = Capabilities()

        # root
        try:
            r = subprocess.run(adb + ["shell", "su", "-c", "id"],
                               capture_output=True, text=True, timeout=5)
            c.root = "uid=0" in r.stdout
        except Exception:
            pass

        # mitmdump on host
        c.mitmdump = shutil.which("mitmdump") is not None

        # frida-server on device
        try:
            r = subprocess.run(adb + ["shell", "su", "-c", "ps -e"],
                               capture_output=True, text=True, timeout=8)
            c.frida_server = "frida-server" in r.stdout
        except Exception:
            pass

        # ecapture on device
        try:
            r = subprocess.run(adb + ["shell", "su", "-c", "ls /data/local/tmp/ecapture"],
                               capture_output=True, text=True, timeout=5)
            c.ecapture = "ecapture" in r.stdout
        except Exception:
            pass

        # tcpdump on device
        try:
            r = subprocess.run(adb + ["shell", "su", "-c", "which tcpdump"],
                               capture_output=True, text=True, timeout=5)
            c.tcpdump = "/tcpdump" in r.stdout
        except Exception:
            pass

        return c

    return await loop.run_in_executor(None, _probe_sync)


# ── Merge engine ──────────────────────────────────────────────────────────────

class MergeEngine:
    """
    Consumes raw traffic entries from all layers via an asyncio.Queue.
    Collapses duplicates within a 500ms window, keeping the richest version.
    Writes survivors to SQLite and broadcasts to WebSocket subscribers.
    """

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.queue: asyncio.Queue = asyncio.Queue()
        self._window: Dict[str, dict] = {}  # merge_key -> entry
        self._window_ts: Dict[str, float] = {}  # merge_key -> first_seen_ts
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def put(self, entry: dict) -> None:
        await self.queue.put(entry)

    def _merge_key(self, entry: dict) -> str:
        req = entry.get("request", {})
        method = req.get("method", "")
        url = (req.get("url", "") or "").split("?")[0]  # ignore query string for dedup
        bucket = int(entry.get("timestamp", time.time()) * 1000 // MERGE_WINDOW_MS)
        return f"{method}|{url}|{bucket}"

    async def _run(self) -> None:
        from .mobile_traffic_store import store_traffic as _store

        while True:
            try:
                # Drain queue with a short timeout so we can flush stale entries
                try:
                    entry = await asyncio.wait_for(self.queue.get(), timeout=0.1)
                    key = self._merge_key(entry)
                    existing = self._window.get(key)
                    src = entry.get("source", "unknown")
                    existing_src = (existing or {}).get("source", "unknown")

                    if (not existing or
                            SOURCE_PRIORITY.get(src, 0) > SOURCE_PRIORITY.get(existing_src, 0)):
                        self._window[key] = entry
                        self._window_ts[key] = entry.get("timestamp", time.time())

                except asyncio.TimeoutError:
                    pass

                # Flush entries older than MERGE_WINDOW_MS
                now = time.time()
                stale_keys = [
                    k for k, ts in self._window_ts.items()
                    if (now - ts) * 1000 > MERGE_WINDOW_MS
                ]
                for k in stale_keys:
                    entry = self._window.pop(k)
                    self._window_ts.pop(k, None)
                    req = entry.get("request", {})
                    resp = entry.get("response", {})
                    try:
                        await _store(
                            self.device_id,
                            req, resp,
                            source=entry.get("source", "unknown"),
                            duration_ms=entry.get("duration_ms", 0),
                            decrypted=entry.get("decrypted", False),
                            modified=entry.get("modified", False),
                            session_id=entry.get("session_id", ""),
                        )
                        await _broadcast(self.device_id, entry)
                    except Exception as e:
                        log.debug("MergeEngine store error: %s", e)

            except asyncio.CancelledError:
                # Flush remaining window on shutdown
                from .mobile_traffic_store import store_traffic as _store
                for entry in self._window.values():
                    req = entry.get("request", {})
                    resp = entry.get("response", {})
                    try:
                        await _store(
                            self.device_id, req, resp,
                            source=entry.get("source", "unknown"),
                            decrypted=entry.get("decrypted", False),
                        )
                    except Exception:
                        pass
                break
            except Exception as e:
                log.error("MergeEngine error: %s", e)
                await asyncio.sleep(0.1)


# ── Unified Capture Session ───────────────────────────────────────────────────

@dataclass
class LayerStatus:
    name: str
    running: bool = False
    error: str = ""
    started_at: float = 0.0


@dataclass
class UnifiedCaptureSession:
    device_id: str
    caps: Capabilities = field(default_factory=Capabilities)
    layers: Dict[str, LayerStatus] = field(default_factory=dict)
    merge_engine: Optional[MergeEngine] = field(default=None)
    started_at: float = field(default_factory=time.time)
    intercept_enabled: bool = False
    entry_count: int = 0

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "started_at": self.started_at,
            "intercept_enabled": self.intercept_enabled,
            "entry_count": self.entry_count,
            "capabilities": {
                "root": self.caps.root,
                "mitmdump": self.caps.mitmdump,
                "frida_server": self.caps.frida_server,
                "ecapture": self.caps.ecapture,
                "tcpdump": self.caps.tcpdump,
            },
            "layers": {
                name: {"running": s.running, "error": s.error}
                for name, s in self.layers.items()
            },
        }


async def start_unified_capture(device_id: str) -> dict:
    """Start all available capture layers for a device."""
    if device_id in _sessions:
        sess = _sessions[device_id]
        if any(s.running for s in sess.layers.values()):
            return {"status": "already_running", **sess.to_dict()}

    log.info("[unified] Probing capabilities for %s", device_id)
    caps = await probe_capabilities(device_id)
    log.info("[unified] caps: root=%s mitm=%s frida=%s ebpf=%s tcpdump=%s",
             caps.root, caps.mitmdump, caps.frida_server, caps.ecapture, caps.tcpdump)

    session = UnifiedCaptureSession(device_id=device_id, caps=caps)
    session.merge_engine = MergeEngine(device_id)
    session.merge_engine.start()
    _sessions[device_id] = session

    # Patch store_traffic for all layers to go through MergeEngine
    _install_merge_hook(device_id, session.merge_engine)

    # Start layers in parallel
    tasks = []

    tasks.append(_start_layer_tcpdump(session))

    if caps.mitmdump:
        tasks.append(_start_layer_mitm(session))
    else:
        session.layers["mitm"] = LayerStatus("mitm", running=False,
                                              error="mitmdump not installed")

    if caps.frida_server:
        tasks.append(_start_layer_frida(session))
    else:
        session.layers["frida_ssl"] = LayerStatus("frida_ssl", running=False,
                                                   error="frida-server not running on device")

    if caps.ecapture:
        tasks.append(_start_layer_ebpf(session))
    else:
        session.layers["ebpf"] = LayerStatus("ebpf", running=False,
                                              error="ecapture binary not found on device")

    await asyncio.gather(*tasks, return_exceptions=True)

    log.info("[unified] Started for %s: layers=%s",
             device_id, {k: v.running for k, v in session.layers.items()})

    return {"status": "started", **session.to_dict()}


async def stop_unified_capture(device_id: str) -> dict:
    """Stop all layers and the merge engine."""
    session = _sessions.pop(device_id, None)
    if not session:
        return {"status": "not_running", "device_id": device_id}

    _remove_merge_hook(device_id)

    if session.merge_engine:
        session.merge_engine.stop()

    tasks = []
    if session.layers.get("tcpdump", LayerStatus("")).running:
        tasks.append(_stop_layer_tcpdump(device_id))
    if session.layers.get("mitm", LayerStatus("")).running:
        tasks.append(_stop_layer_mitm(device_id))
    if session.layers.get("frida_ssl", LayerStatus("")).running:
        tasks.append(_stop_layer_frida(device_id))
    if session.layers.get("ebpf", LayerStatus("")).running:
        tasks.append(_stop_layer_ebpf(device_id))

    await asyncio.gather(*tasks, return_exceptions=True)

    return {"status": "stopped", "device_id": device_id}


async def get_capture_status(device_id: str) -> dict:
    session = _sessions.get(device_id)
    if not session:
        return {"status": "stopped", "device_id": device_id}
    return {"status": "running", **session.to_dict()}


async def set_intercept_mode(device_id: str, enabled: bool) -> dict:
    """Toggle intercept mode — routes to the correct layer per-request."""
    session = _sessions.get(device_id)
    if not session:
        raise Exception(f"No active session for {device_id}")
    session.intercept_enabled = enabled

    # Enable on mitmproxy layer
    if session.layers.get("mitm", LayerStatus("")).running:
        try:
            from .mobile_mitm_api import enable_intercept_handler
            await enable_intercept_handler({"device_id": device_id, "enabled": enabled})
        except Exception as e:
            log.warning("[unified] mitm intercept toggle failed: %s", e)

    # Enable on Frida layer via send() to running script
    if session.layers.get("frida_ssl", LayerStatus("")).running:
        try:
            from .mobile_agent_api import active_devices
            ws = active_devices.get(device_id)
            if ws:
                await ws.send_json({
                    "type": "frida_intercept_mode",
                    "enabled": enabled,
                })
        except Exception as e:
            log.warning("[unified] frida intercept toggle failed: %s", e)

    return {"device_id": device_id, "intercept_enabled": enabled}


# ── Merge hook — patches store_traffic globally per device ───────────────────

_original_store_traffic = None
_merge_hooks: Dict[str, MergeEngine] = {}


def _install_merge_hook(device_id: str, engine: MergeEngine) -> None:
    """Register this device's merge engine to receive all store_traffic calls."""
    _merge_hooks[device_id] = engine


def _remove_merge_hook(device_id: str) -> None:
    _merge_hooks.pop(device_id, None)


async def route_to_merge(device_id: str, request: dict, response: dict,
                         source: str = "unknown", duration_ms: int = 0,
                         decrypted: bool = False, modified: bool = False,
                         session_id: str = "") -> None:
    """
    Called by mobile_agent_api.store_traffic() — routes to MergeEngine
    if a unified session is active for this device, otherwise falls through
    to direct SQLite write.
    """
    engine = _merge_hooks.get(device_id)
    entry = {
        "device_id": device_id,
        "timestamp": time.time(),
        "source": source,
        "decrypted": decrypted,
        "modified": modified,
        "session_id": session_id,
        "duration_ms": duration_ms,
        "request": request,
        "response": response,
    }

    if engine:
        # Update entry count
        sess = _sessions.get(device_id)
        if sess:
            sess.entry_count += 1
        await engine.put(entry)
    else:
        # No unified session — write directly to SQLite
        from .mobile_traffic_store import store_traffic as _store
        await _store(device_id, request, response,
                     source=source, duration_ms=duration_ms,
                     decrypted=decrypted, modified=modified, session_id=session_id)


# ── Layer start/stop implementations ─────────────────────────────────────────

async def _start_layer_tcpdump(session: UnifiedCaptureSession) -> None:
    session.layers["tcpdump"] = LayerStatus("tcpdump")
    try:
        from .mobile_tcpdump_capture import start_tcpdump_capture
        result = await start_tcpdump_capture(session.device_id)
        session.layers["tcpdump"].running = result.get("status") in ("started", "already_running")
        session.layers["tcpdump"].started_at = time.time()
    except Exception as e:
        session.layers["tcpdump"].error = str(e)
        log.warning("[unified] tcpdump start failed: %s", e)


async def _stop_layer_tcpdump(device_id: str) -> None:
    try:
        from .mobile_tcpdump_capture import stop_tcpdump_capture
        await stop_tcpdump_capture(device_id)
    except Exception:
        pass


async def _start_layer_mitm(session: UnifiedCaptureSession) -> None:
    session.layers["mitm"] = LayerStatus("mitm")
    try:
        from .mobile_mitm_api import start_mitm_handler
        result = await start_mitm_handler({"device_id": session.device_id, "port": 8080})
        session.layers["mitm"].running = result.get("status") in ("started", "already_running")
        session.layers["mitm"].started_at = time.time()
    except Exception as e:
        session.layers["mitm"].error = str(e)
        log.warning("[unified] mitm start failed: %s", e)


async def _stop_layer_mitm(device_id: str) -> None:
    try:
        from .mobile_mitm_api import stop_mitm_handler
        await stop_mitm_handler(device_id)
    except Exception:
        pass


async def _start_layer_frida(session: UnifiedCaptureSession) -> None:
    session.layers["frida_ssl"] = LayerStatus("frida_ssl")
    try:
        from .mobile_agent_api import active_devices
        ws = active_devices.get(session.device_id)
        if ws:
            # Trigger app-side FridaSslHookManager — it enumerates PIDs and requests injection
            await ws.send_json({"type": "start_frida_ssl", "device_id": session.device_id})
            session.layers["frida_ssl"].running = True
            session.layers["frida_ssl"].started_at = time.time()
            log.info("[unified] Frida SSL hook triggered on device %s", session.device_id)
        else:
            session.layers["frida_ssl"].error = "device not connected via WebSocket"
    except Exception as e:
        session.layers["frida_ssl"].error = str(e)
        log.warning("[unified] frida ssl hook start failed: %s", e)


async def _stop_layer_frida(device_id: str) -> None:
    try:
        from .mobile_agent_api import active_devices
        ws = active_devices.get(device_id)
        if ws:
            await ws.send_json({"type": "frida_stop", "session_id": "ssl_hook"})
    except Exception:
        pass


async def _start_layer_ebpf(session: UnifiedCaptureSession) -> None:
    session.layers["ebpf"] = LayerStatus("ebpf")
    try:
        # Run ecapture directly from backend via adb — more reliable than app-side
        from .mobile_ebpf_capture import start_ebpf_capture
        serial = _get_adb_serial()
        result = await start_ebpf_capture(serial or session.device_id)
        session.layers["ebpf"].running = result.get("status") in ("started", "already_running")
        session.layers["ebpf"].started_at = time.time()
        if session.layers["ebpf"].running:
            log.info("[unified] eBPF capture started via adb for %s", session.device_id)
        else:
            session.layers["ebpf"].error = result.get("error", "unknown error")
    except Exception as e:
        session.layers["ebpf"].error = str(e)
        log.warning("[unified] ebpf start failed: %s", e)


async def _stop_layer_ebpf(device_id: str) -> None:
    try:
        from .mobile_ebpf_capture import stop_ebpf_capture
        await stop_ebpf_capture(device_id)
    except Exception:
        pass
