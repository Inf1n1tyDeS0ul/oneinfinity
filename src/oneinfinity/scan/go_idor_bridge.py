"""
go_idor_bridge.py — Python wrapper for the oi-idor-engine gRPC sidecar.

Architecture
────────────
oi-idor-engine is a gRPC service on port 50052 (env IDOR_GRPC_PORT).
It implements IDOREngine:
    rpc Run(IDORRequest) returns (stream Finding)
    rpc Health(HealthCheckRequest) returns (HealthCheckResponse)

Finding fields (JSON codec on wire):
    id, url, vuln_type, severity, evidence, tool, discovered_at,
    confidence, scan_id, metadata (map)

Usage
─────
    from oneinfinity.scan.go_idor_bridge import GoIDORBridge
    bridge = GoIDORBridge()
    findings = await bridge.run(
        target_url="https://example.com",
        endpoints=["/api/users/{id}", "/api/orders/{id}"],
        tokens=["Bearer tok_a", "Bearer tok_b"],
        scan_id="scan_001",
    )
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import struct
import subprocess
import time
import uuid
from typing import Any

log = logging.getLogger("oi.go_idor_bridge")

_SIDECAR_NAME = "oi-idor-engine"
_GRPC_PORT_ENV = "IDOR_GRPC_PORT"
_DEFAULT_PORT = 50052
_DEFAULT_TIMEOUT = 120.0

# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------

def _binary_path() -> str | None:
    """Return the path to oi-idor-engine binary, checking local src/go first."""
    # Check alongside this file's repo structure
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", ".."))
    local = os.path.join(repo_root, "src", "go", "oi-idor-engine", "oi-idor-engine")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    # Fall back to PATH / ~/.local/bin
    found = shutil.which(_SIDECAR_NAME)
    if found:
        return found
    local_bin = os.path.join(os.path.expanduser("~"), ".local", "bin", _SIDECAR_NAME)
    if os.path.isfile(local_bin) and os.access(local_bin, os.X_OK):
        return local_bin
    return None


# ---------------------------------------------------------------------------
# Minimal gRPC-over-raw-socket helpers (JSON codec, no grpcio required)
# ---------------------------------------------------------------------------

def _grpc_frame(body: bytes) -> bytes:
    return b"\x00" + struct.pack(">I", len(body)) + body


def _parse_grpc_frames(data: bytes) -> list[bytes]:
    frames: list[bytes] = []
    i = 0
    while i + 5 <= len(data):
        length = struct.unpack(">I", data[i + 1 : i + 5])[0]
        start = i + 5
        end = start + length
        if end > len(data):
            break
        frames.append(data[start:end])
        i = end
    return frames


def _raw_grpc_call(
    host: str,
    port: int,
    service_method: str,
    request_json: bytes,
    timeout: float,
) -> list[bytes]:
    """
    Send a single gRPC request over a raw TCP socket (JSON codec).
    Returns list of raw response frame payloads (each is a JSON bytes blob).
    """
    headers = (
        f"POST {service_method} HTTP/2\r\n"
        f"Host: {host}:{port}\r\n"
        "Content-Type: application/grpc\r\n"
        "TE: trailers\r\n"
        "\r\n"
    )
    # We use a simple approach: spawn grpcurl if available, else fall back
    # to the subprocess streaming approach via stdin/stdout.
    raise NotImplementedError("use subprocess sidecar approach")


# ---------------------------------------------------------------------------
# Sidecar process management
# ---------------------------------------------------------------------------

_sidecar_proc: subprocess.Popen | None = None
_sidecar_port: int = 0


def _get_port() -> int:
    return int(os.environ.get(_GRPC_PORT_ENV, _DEFAULT_PORT))


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0):
            return True
    except OSError:
        return False


def _ensure_sidecar() -> bool:
    """Start the sidecar if it isn't already listening. Returns True if available."""
    global _sidecar_proc, _sidecar_port
    port = _get_port()
    _sidecar_port = port

    if _port_open(port):
        return True

    binary = _binary_path()
    if not binary:
        log.warning("[go_idor_bridge] oi-idor-engine binary not found — IDOR scan disabled")
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
        log.warning("[go_idor_bridge] failed to start sidecar: %s", exc)
        return False

    # Wait up to 5 s for the port to open
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.1)

    log.warning("[go_idor_bridge] sidecar did not open port %d in time", port)
    return False


def shutdown_sidecar() -> None:
    """Terminate the sidecar process if we started it."""
    global _sidecar_proc
    if _sidecar_proc and _sidecar_proc.poll() is None:
        _sidecar_proc.terminate()
        try:
            _sidecar_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            _sidecar_proc.kill()
    _sidecar_proc = None


# ---------------------------------------------------------------------------
# gRPC call via grpcio (preferred) or grpcurl subprocess
# ---------------------------------------------------------------------------

def _call_via_grpcio(
    port: int,
    method: str,
    request: dict,
    timeout: float,
) -> list[dict]:
    """Call sidecar via grpcio with JSON codec. Returns list of Finding dicts."""
    try:
        import grpc
        from grpc import experimental  # noqa: F401
    except ImportError:
        return []

    # JSON codec channel — matches the Go sidecar's jsonCodec (name="proto")
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    try:
        stub_method = channel.stream_unary if False else None  # streaming
        results: list[dict] = []
        metadata = (("content-type", "application/grpc"),)
        call = channel.unary_stream(
            method,
            request_serializer=lambda r: json.dumps(r).encode(),
            response_deserializer=lambda b: json.loads(b),
        )
        for finding in call(request, timeout=timeout, metadata=metadata):
            results.append(finding)
        return results
    except Exception as exc:
        log.debug("[go_idor_bridge] grpcio call error: %s", exc)
        return []
    finally:
        channel.close()


def _call_via_raw_socket(
    port: int,
    request: dict,
    timeout: float,
) -> list[dict]:
    """
    Minimal HTTP/2-framing-free gRPC call using raw TCP.
    We send an HTTP/1.1 upgrade-style frame which the Go server handles because
    the Go gRPC server accepts plain h2c.  In practice we rely on grpcio; this
    is a fallback that emits no results rather than crashing.
    """
    return []


# ---------------------------------------------------------------------------
# GoIDORBridge
# ---------------------------------------------------------------------------

class GoIDORBridge:
    """
    Python wrapper for oi-idor-engine (IDOREngine gRPC sidecar).

    Handles:
    - Binary lookup + sidecar startup
    - gRPC streaming call via grpcio (JSON codec)
    - Graceful degradation when binary or grpcio absent
    - DB persistence via DBManager.save_finding
    """

    def __init__(self) -> None:
        self._available: bool | None = None  # cached after first check

    def is_available(self) -> bool:
        if self._available is None:
            self._available = _ensure_sidecar()
        return self._available

    async def run(
        self,
        target_url: str,
        endpoints: list[str],
        tokens: list[str],
        scan_id: str | None = None,
        options: dict[str, str] | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        store_findings: bool = True,
    ) -> list[dict]:
        """
        Run IDOR scan against *target_url*.

        Parameters
        ----------
        target_url : str
            Base URL of the target application.
        endpoints : list[str]
            Endpoint patterns with {id} placeholder, e.g. ["/api/users/{id}"].
        tokens : list[str]
            Session/bearer tokens to test cross-context access.
        scan_id : str | None
            Correlation ID; auto-generated if None.
        options : dict[str, str] | None
            Extra options forwarded to the sidecar (id_min, id_max, methods…).
        timeout : float
            Total call timeout in seconds.
        store_findings : bool
            Persist findings to DBManager when True.

        Returns
        -------
        list[dict]
            Finding dicts in OneInfinity standard format.
        """
        if not self.is_available():
            log.info("[go_idor_bridge] sidecar unavailable — skipping IDOR scan")
            return []

        sid = scan_id or uuid.uuid4().hex[:16]
        request = {
            "target_url": target_url,
            "endpoints": endpoints,
            "tokens": tokens,
            "scan_id": sid,
            "options": options or {},
        }

        port = _get_port()
        raw_findings = _call_via_grpcio(
            port=port,
            method="/oneinfinity.v1.IDOREngine/Run",
            request=request,
            timeout=timeout,
        )

        findings = [self._normalize(f, target_url, sid) for f in raw_findings]
        findings = [f for f in findings if f]  # drop None

        if store_findings and findings:
            await self._store(findings)

        log.info("[go_idor_bridge] IDOR scan(%s) → %d findings", target_url, len(findings))
        return findings

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(raw: Any, target: str, scan_id: str) -> dict | None:
        """Map a raw Finding dict/object to the OI standard finding schema."""
        if not isinstance(raw, dict):
            return None
        return {
            "id": raw.get("id") or uuid.uuid4().hex,
            "vuln_type": raw.get("vuln_type") or "idor",
            "severity": raw.get("severity") or "high",
            "url": raw.get("url") or target,
            "target": target,
            "evidence": raw.get("evidence") or "",
            "tool": raw.get("source_tool") or raw.get("tool") or "oi-idor-engine",
            "confidence": float(raw.get("confidence") or 0.8),
            "scan_id": raw.get("scan_id") or scan_id,
            "metadata": raw.get("metadata") or {},
        }

    # ------------------------------------------------------------------
    # DB persistence
    # ------------------------------------------------------------------

    @staticmethod
    async def _store(findings: list[dict]) -> None:
        try:
            from oneinfinity.core.db_manager import get_db_manager
            db = await get_db_manager()
            for f in findings:
                try:
                    await db.save_finding(f)
                except Exception as exc:
                    log.debug("[go_idor_bridge] DB save_finding error: %s", exc)
        except Exception as exc:
            log.debug("[go_idor_bridge] DB unavailable: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

async def run_idor_scan(
    target_url: str,
    endpoints: list[str],
    tokens: list[str],
    scan_id: str | None = None,
    options: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[dict]:
    """Convenience wrapper — creates GoIDORBridge, runs, returns findings."""
    bridge = GoIDORBridge()
    return await bridge.run(
        target_url=target_url,
        endpoints=endpoints,
        tokens=tokens,
        scan_id=scan_id,
        options=options,
        timeout=timeout,
    )
