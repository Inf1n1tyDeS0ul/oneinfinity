"""
go_ssrf_bridge.py — Python wrapper for the oi-ssrf gRPC sidecar.

Architecture
────────────
oi-ssrf is a gRPC service on port 50053 (env SSRF_GRPC_PORT).
It implements SSRFScanner:
    rpc Scan(ScanRequest) returns (stream Finding)
    rpc Health(HealthCheckRequest) returns (HealthCheckResponse)

Finding fields (JSON codec):
    id, url, vuln_type, severity, evidence, source_tool,
    discovered_at, metadata, confidence, scan_id

Usage
─────
    from oneinfinity.scan.go_ssrf_bridge import GoSSRFBridge
    bridge = GoSSRFBridge()
    findings = await bridge.scan(
        target_url="https://example.com/fetch?url=",
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

log = logging.getLogger("oi.go_ssrf_bridge")

_SIDECAR_NAME = "oi-ssrf"
_GRPC_PORT_ENV = "SSRF_GRPC_PORT"
_DEFAULT_PORT = 50053
_DEFAULT_TIMEOUT = 120.0

# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------

def _binary_path() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", ".."))
    local = os.path.join(repo_root, "src", "go", "oi-ssrf", "oi-ssrf")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    found = shutil.which(_SIDECAR_NAME)
    if found:
        return found
    local_bin = os.path.join(os.path.expanduser("~"), ".local", "bin", _SIDECAR_NAME)
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
        log.warning("[go_ssrf_bridge] oi-ssrf binary not found — SSRF scan disabled")
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
        log.warning("[go_ssrf_bridge] failed to start sidecar: %s", exc)
        return False

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.1)

    log.warning("[go_ssrf_bridge] sidecar did not open port %d in time", port)
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

def _call_via_grpcio(port: int, request: dict, timeout: float) -> list[dict]:
    try:
        import grpc
    except ImportError:
        log.debug("[go_ssrf_bridge] grpcio not available")
        return []

    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    try:
        call = channel.unary_stream(
            "/oneinfinity.v1.SSRFScanner/Scan",
            request_serializer=lambda r: json.dumps(r).encode(),
            response_deserializer=lambda b: json.loads(b),
        )
        results = []
        for finding in call(request, timeout=timeout):
            results.append(finding)
        return results
    except Exception as exc:
        log.debug("[go_ssrf_bridge] grpcio call error: %s", exc)
        return []
    finally:
        channel.close()


# ---------------------------------------------------------------------------
# GoSSRFBridge
# ---------------------------------------------------------------------------

class GoSSRFBridge:
    """
    Python wrapper for oi-ssrf SSRFScanner gRPC sidecar.

    Handles:
    - Binary lookup + sidecar startup
    - gRPC streaming call via grpcio (JSON codec)
    - Graceful degradation when binary/grpcio absent
    - DB persistence via DBManager.save_finding
    """

    def __init__(self) -> None:
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is None:
            self._available = _ensure_sidecar()
        return self._available

    async def scan(
        self,
        target_url: str,
        scan_id: str | None = None,
        options: dict[str, str] | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        store_findings: bool = True,
    ) -> list[dict]:
        """
        Run SSRF scan against *target_url*.

        Parameters
        ----------
        target_url : str
            URL or parameter string to test for SSRF (e.g. /fetch?url=).
        scan_id : str | None
            Correlation ID; auto-generated if None.
        options : dict[str, str] | None
            Extra options forwarded to the sidecar.
        timeout : float
            Call timeout in seconds.
        store_findings : bool
            Persist findings to DBManager when True.

        Returns
        -------
        list[dict]
            Finding dicts in OneInfinity standard format.
        """
        if not self.is_available():
            log.info("[go_ssrf_bridge] sidecar unavailable — skipping SSRF scan")
            return []

        sid = scan_id or uuid.uuid4().hex[:16]
        request = {
            "target_url": target_url,
            "scan_id": sid,
            "options": options or {},
        }

        port = _get_port()
        raw_findings = _call_via_grpcio(port=port, request=request, timeout=timeout)
        findings = [self._normalize(f, target_url, sid) for f in raw_findings]
        findings = [f for f in findings if f]

        if store_findings and findings:
            await self._store(findings)

        log.info("[go_ssrf_bridge] SSRF scan(%s) → %d findings", target_url, len(findings))
        return findings

    @staticmethod
    def _normalize(raw: Any, target: str, scan_id: str) -> dict | None:
        if not isinstance(raw, dict):
            return None
        return {
            "id": raw.get("id") or uuid.uuid4().hex,
            "vuln_type": raw.get("vuln_type") or "ssrf",
            "severity": raw.get("severity") or "high",
            "url": raw.get("url") or target,
            "target": target,
            "evidence": raw.get("evidence") or "",
            "tool": raw.get("source_tool") or "oi-ssrf",
            "confidence": float(raw.get("confidence") or 0.85),
            "scan_id": raw.get("scan_id") or scan_id,
            "metadata": raw.get("metadata") or {},
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
                    log.debug("[go_ssrf_bridge] DB save_finding error: %s", exc)
        except Exception as exc:
            log.debug("[go_ssrf_bridge] DB unavailable: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

async def run_ssrf_scan(
    target_url: str,
    scan_id: str | None = None,
    options: dict[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[dict]:
    """Convenience wrapper."""
    bridge = GoSSRFBridge()
    return await bridge.scan(
        target_url=target_url,
        scan_id=scan_id,
        options=options,
        timeout=timeout,
    )
