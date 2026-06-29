"""
go_oob_bridge.py — Python wrapper for the oi-oob-listener gRPC sidecar.

Architecture
────────────
oi-oob-listener is a gRPC service on port 50054 (env OOB_GRPC_PORT).
It implements OOBService:
    rpc Start(OOBStartRequest) returns (OOBDomain)   — get a unique OOB subdomain
    rpc Poll(PollRequest) returns (stream Interaction) — poll for callbacks
    rpc Health(HealthCheckRequest) returns (HealthCheckResponse)

Interaction fields:
    protocol, source_ip, payload, received_at (unix ns), scan_id

OOBDomain fields:
    domain, scan_id

Usage
─────
    from oneinfinity.scan.go_oob_bridge import GoOOBBridge
    bridge = GoOOBBridge()
    oob = await bridge.start(scan_id="scan_001", target_hint="example.com")
    # oob["domain"] → unique DNS/HTTP callback domain
    # inject oob["domain"] into payloads, then:
    interactions = await bridge.poll(scan_id="scan_001", timeout=30)
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

log = logging.getLogger("oi.go_oob_bridge")

_SIDECAR_NAME = "oi-oob-listener"
_GRPC_PORT_ENV = "OOB_GRPC_PORT"
_DEFAULT_PORT = 50054
_DEFAULT_TIMEOUT = 60.0

# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------

def _binary_path() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", ".."))
    local = os.path.join(repo_root, "src", "go", "oi-oob-listener", "oi-oob-listener")
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
        log.warning("[go_oob_bridge] oi-oob-listener binary not found — OOB tracking disabled")
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
        log.warning("[go_oob_bridge] failed to start sidecar: %s", exc)
        return False

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.1)

    log.warning("[go_oob_bridge] sidecar did not open port %d in time", port)
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
# gRPC calls
# ---------------------------------------------------------------------------

def _unary_call(port: int, method: str, request: dict, timeout: float) -> dict | None:
    try:
        import grpc
    except ImportError:
        return None

    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    try:
        call = channel.unary_unary(
            method,
            request_serializer=lambda r: json.dumps(r).encode(),
            response_deserializer=lambda b: json.loads(b),
        )
        return call(request, timeout=timeout)
    except Exception as exc:
        log.debug("[go_oob_bridge] unary call %s error: %s", method, exc)
        return None
    finally:
        channel.close()


def _stream_call(port: int, method: str, request: dict, timeout: float) -> list[dict]:
    try:
        import grpc
    except ImportError:
        return []

    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    try:
        call = channel.unary_stream(
            method,
            request_serializer=lambda r: json.dumps(r).encode(),
            response_deserializer=lambda b: json.loads(b),
        )
        return list(call(request, timeout=timeout))
    except Exception as exc:
        log.debug("[go_oob_bridge] stream call %s error: %s", method, exc)
        return []
    finally:
        channel.close()


# ---------------------------------------------------------------------------
# GoOOBBridge
# ---------------------------------------------------------------------------

class GoOOBBridge:
    """
    Python wrapper for oi-oob-listener OOBService gRPC sidecar.

    Provides:
    - start()  → register a scan session, get an OOB callback domain
    - poll()   → collect interactions that arrived for a scan session
    - findings_from_interactions() → convert interactions to OI findings
    """

    def __init__(self) -> None:
        self._available: bool | None = None

    def is_available(self) -> bool:
        if self._available is None:
            self._available = _ensure_sidecar()
        return self._available

    async def start(
        self,
        scan_id: str | None = None,
        target_hint: str = "",
        timeout: float = 10.0,
    ) -> dict:
        """
        Register an OOB session with the listener sidecar.

        Returns
        -------
        dict
            {"domain": "<unique-callback-domain>", "scan_id": "<sid>"}
            Returns {"domain": "", "scan_id": sid} when sidecar unavailable.
        """
        sid = scan_id or uuid.uuid4().hex[:16]
        if not self.is_available():
            log.info("[go_oob_bridge] sidecar unavailable — OOB tracking disabled")
            return {"domain": "", "scan_id": sid}

        port = _get_port()
        request = {"scan_id": sid, "target_hint": target_hint}
        result = _unary_call(
            port, "/oneinfinity.v1.OOBService/Start", request, timeout
        )
        if result and isinstance(result, dict):
            return {"domain": result.get("domain", ""), "scan_id": sid}
        return {"domain": "", "scan_id": sid}

    async def poll(
        self,
        scan_id: str,
        timeout: float = _DEFAULT_TIMEOUT,
        store_findings: bool = True,
    ) -> list[dict]:
        """
        Poll for OOB interactions received for *scan_id*.

        Returns
        -------
        list[dict]
            Interaction dicts: {protocol, source_ip, payload, received_at, scan_id}.
        """
        if not self.is_available():
            return []

        port = _get_port()
        raw = _stream_call(
            port, "/oneinfinity.v1.OOBService/Poll",
            {"scan_id": scan_id}, timeout
        )

        interactions = [self._normalize_interaction(r, scan_id) for r in raw]
        interactions = [i for i in interactions if i]

        if store_findings and interactions:
            findings = self.findings_from_interactions(interactions)
            await self._store(findings)

        return interactions

    @staticmethod
    def _normalize_interaction(raw: Any, scan_id: str) -> dict | None:
        if not isinstance(raw, dict):
            return None
        return {
            "protocol": raw.get("protocol", ""),
            "source_ip": raw.get("source_ip", ""),
            "payload": raw.get("payload", ""),
            "received_at": raw.get("received_at", 0),
            "scan_id": raw.get("scan_id") or scan_id,
        }

    @staticmethod
    def findings_from_interactions(interactions: list[dict]) -> list[dict]:
        """Convert OOB interactions to OI finding dicts for DB storage."""
        findings = []
        for ix in interactions:
            findings.append({
                "id": uuid.uuid4().hex,
                "vuln_type": "oob_interaction",
                "severity": "high",
                "url": "",
                "target": ix.get("source_ip", ""),
                "evidence": (
                    f"OOB {ix.get('protocol','').upper()} callback from "
                    f"{ix.get('source_ip','')} — payload: {ix.get('payload','')[:200]}"
                ),
                "tool": "oi-oob-listener",
                "confidence": 0.95,
                "scan_id": ix.get("scan_id", ""),
                "metadata": {
                    "protocol": ix.get("protocol", ""),
                    "source_ip": ix.get("source_ip", ""),
                    "received_at": str(ix.get("received_at", "")),
                },
            })
        return findings

    @staticmethod
    async def _store(findings: list[dict]) -> None:
        try:
            from oneinfinity.core.db_manager import get_db_manager
            db = await get_db_manager()
            for f in findings:
                try:
                    await db.save_finding(f)
                except Exception as exc:
                    log.debug("[go_oob_bridge] DB save_finding error: %s", exc)
        except Exception as exc:
            log.debug("[go_oob_bridge] DB unavailable: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

async def start_oob_session(
    scan_id: str | None = None,
    target_hint: str = "",
) -> dict:
    """Start an OOB session and return {domain, scan_id}."""
    bridge = GoOOBBridge()
    return await bridge.start(scan_id=scan_id, target_hint=target_hint)


async def poll_oob_interactions(
    scan_id: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> list[dict]:
    """Poll for OOB interactions for a given scan session."""
    bridge = GoOOBBridge()
    return await bridge.poll(scan_id=scan_id, timeout=timeout)
