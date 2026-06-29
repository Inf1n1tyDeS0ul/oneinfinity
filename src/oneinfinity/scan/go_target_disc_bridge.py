"""
go_target_disc_bridge.py — Python wrapper for oi-target-disc gRPC sidecar.

Architecture
────────────
oi-target-disc is a gRPC service on port 50057 (env TARGET_DISC_GRPC_PORT).
It implements TargetDisc:
    rpc Scan(TargetDiscRequest) returns (stream OpenPort)
    rpc Health(HealthCheckRequest) returns (HealthCheckResponse)

TargetDiscRequest fields (JSON codec):
    target (string), ports ([]int32), timeout_ms (int32), scan_id (string)

OpenPort fields:
    ip, port (int32), banner, service, scan_id

Usage
─────
    from oneinfinity.scan.go_target_disc_bridge import GoTargetDiscBridge
    bridge = GoTargetDiscBridge()
    open_ports = await bridge.scan(
        target="192.168.1.0/24",
        scan_id="scan_001",
    )
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import time
import uuid
from typing import Any

log = logging.getLogger("oi.go_target_disc_bridge")

_SIDECAR_NAME = "oi-target-disc"
_GRPC_PORT_ENV = "TARGET_DISC_GRPC_PORT"
_DEFAULT_PORT = 50057
_DEFAULT_TIMEOUT = 300.0

# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------

def _binary_path() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", ".."))
    local = os.path.join(
        repo_root, "src", "go", "oi-target-disc", "oi-target-disc"
    )
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    found = shutil.which(_SIDECAR_NAME)
    if found:
        return found
    local_bin = os.path.join(
        os.path.expanduser("~"), ".local", "bin", _SIDECAR_NAME
    )
    if os.path.isfile(local_bin) and os.access(local_bin, os.X_OK):
        return local_bin
    return None


# ---------------------------------------------------------------------------
# Sidecar management
# ---------------------------------------------------------------------------

_sidecar_proc: subprocess.Popen | None = None


def _get_port() -> int:
    return int(os.environ.get(_GRPC_PORT_ENV, _DEFAULT_PORT))


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


def _ensure_sidecar() -> bool:
    global _sidecar_proc
    port = _get_port()
    if _port_open(port):
        return True

    binary = _binary_path()
    if not binary:
        log.warning("[go_target_disc_bridge] oi-target-disc binary not found — disabled")
        return False

    env = os.environ.copy()
    env[_GRPC_PORT_ENV] = str(port)
    try:
        _sidecar_proc = subprocess.Popen(
            [binary],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        log.warning("[go_target_disc_bridge] failed to start sidecar: %s", exc)
        return False

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.1)

    log.warning("[go_target_disc_bridge] sidecar did not open port %d", port)
    return False


def shutdown_sidecar() -> None:
    global _sidecar_proc
    if _sidecar_proc and _sidecar_proc.poll() is None:
        _sidecar_proc.terminate()
        try:
            _sidecar_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _sidecar_proc.kill()
    _sidecar_proc = None


# ---------------------------------------------------------------------------
# gRPC call
# ---------------------------------------------------------------------------

def _stream_call(port: int, request: dict, timeout: float) -> list[dict]:
    try:
        import grpc
    except ImportError:
        log.debug("[go_target_disc_bridge] grpcio not available")
        return []

    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    try:
        call = channel.unary_stream(
            "/oneinfinity.v1.TargetDisc/Scan",
            request_serializer=lambda r: json.dumps(r).encode(),
            response_deserializer=lambda b: json.loads(b),
        )
        return list(call(request, timeout=timeout))
    except Exception as exc:
        log.debug("[go_target_disc_bridge] stream call error: %s", exc)
        return []
    finally:
        channel.close()


# ---------------------------------------------------------------------------
# GoTargetDiscBridge
# ---------------------------------------------------------------------------

class GoTargetDiscBridge:
    """
    Python wrapper for oi-target-disc TargetDisc gRPC sidecar.

    Performs concurrent TCP port scanning with banner grabbing.
    Results are suitable for piping into GoServiceCVEBridge.map_services().
    """

    def __init__(self) -> None:
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is None:
            self._available = _ensure_sidecar()
        return self._available

    async def scan(
        self,
        target: str,
        ports: list[int] | None = None,
        timeout_ms: int = 1000,
        scan_id: str | None = None,
        call_timeout: float = _DEFAULT_TIMEOUT,
        store_findings: bool = True,
    ) -> list[dict]:
        """
        Discover open ports on *target* (IP or CIDR).

        Parameters
        ----------
        target : str
            IP, hostname, or CIDR (e.g. "10.0.0.0/24").
        ports : list[int] | None
            Ports to probe; None → sidecar's built-in default list.
        timeout_ms : int
            Per-connection timeout in milliseconds.
        scan_id : str | None
            Correlation ID; auto-generated if None.
        call_timeout : float
            Total gRPC call timeout in seconds.
        store_findings : bool
            Persist findings to DBManager when True.

        Returns
        -------
        list[dict]
            Finding dicts with keys: ip, port, service, banner, …
        """
        if not self.is_available():
            log.info("[go_target_disc_bridge] sidecar unavailable — skipping scan")
            return []

        sid = scan_id or uuid.uuid4().hex[:16]
        request: dict = {
            "target": target,
            "timeout_ms": timeout_ms,
            "scan_id": sid,
        }
        if ports:
            request["ports"] = ports

        port = _get_port()
        raw_results = _stream_call(port, request, call_timeout)
        findings = [self._normalize(r, target, sid) for r in raw_results]
        findings = [f for f in findings if f]

        if store_findings and findings:
            await self._store(findings)

        log.info(
            "[go_target_disc_bridge] scan(%s) → %d open ports",
            target, len(findings)
        )
        return findings

    @staticmethod
    def _normalize(raw: Any, target: str, scan_id: str) -> dict | None:
        if not isinstance(raw, dict):
            return None
        ip = raw.get("ip", "")
        port = raw.get("port", 0)
        service = raw.get("service", "")
        banner = raw.get("banner", "")
        return {
            "id": uuid.uuid4().hex,
            "vuln_type": "open_port",
            "severity": "info",
            "url": f"{ip}:{port}",
            "target": target,
            "evidence": (
                f"Open port {port}/{service} on {ip}"
                + (f" — banner: {banner[:200]}" if banner else "")
            ),
            "tool": "oi-target-disc",
            "confidence": 1.0,
            "scan_id": raw.get("scan_id") or scan_id,
            "metadata": {
                "ip": ip,
                "port": str(port),
                "service": service,
                "banner": banner,
            },
        }

    @staticmethod
    async def _store(findings: list[dict]) -> None:
        try:
            from oneinfinity.core.db_manager import get_db_manager
            db = await get_db_manager()
            for f in findings:
                try:
                    await db.save_finding(f)
                except Exception as exc:
                    log.debug("[go_target_disc_bridge] DB save_finding error: %s", exc)
        except Exception as exc:
            log.debug("[go_target_disc_bridge] DB unavailable: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

async def discover_targets(
    target: str,
    ports: list[int] | None = None,
    scan_id: str | None = None,
    call_timeout: float = _DEFAULT_TIMEOUT,
) -> list[dict]:
    """Convenience wrapper."""
    bridge = GoTargetDiscBridge()
    return await bridge.scan(
        target=target,
        ports=ports,
        scan_id=scan_id,
        call_timeout=call_timeout,
    )
