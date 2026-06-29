"""
grpc_client.py — Centralized gRPC client for all Go sidecars.
Phase 0: port config loaded from config/ports.json.
Phase 2: mTLS certificates added.

NEVER import sidecar stubs directly — use this module.
"""
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# Port config — single source of truth
_PORTS_FILE = Path(__file__).resolve().parents[4] / "config" / "ports.json"
_ports: Optional[dict] = None


def _load_ports() -> dict:
    global _ports
    if _ports is None:
        try:
            _ports = json.loads(_PORTS_FILE.read_text())
        except FileNotFoundError:
            log.error(
                "gRPC port config not found at %s. "
                "Run Phase 0 setup or create config/ports.json manually.",
                _PORTS_FILE,
            )
            raise RuntimeError(f"config/ports.json not found at {_PORTS_FILE}")
    return _ports


def _get_address(service_name: str) -> str:
    ports = _load_ports()
    if service_name not in ports:
        raise ValueError(
            f"Unknown sidecar '{service_name}'. "
            f"Valid services: {list(ports.keys())}. "
            "Add to config/ports.json if this is a new service."
        )
    return f"127.0.0.1:{ports[service_name]}"


def _make_channel(service_name: str, timeout: float = 5.0):
    """Create an insecure gRPC channel to a loopback sidecar.
    Phase 2 will upgrade to mTLS. Raises with clear diagnostics if unavailable.
    """
    try:
        import grpc
    except ImportError:
        raise ImportError(
            "grpcio not installed. Run: pip install grpcio grpcio-tools"
        )

    address = _get_address(service_name)
    try:
        channel = grpc.insecure_channel(address)
        # Probe channel readiness
        grpc.channel_ready_future(channel).result(timeout=timeout)
        return channel
    except grpc.FutureTimeoutError:
        raise ConnectionError(
            f"Cannot reach {service_name} at {address}. "
            f"Is the Go sidecar running? Start with: ./bin/{service_name} "
            f"(built from src/go/{service_name}/). "
            "Phase 0: sidecars are stubs and must be started manually."
        )


# Public API — one getter per service
def phase_runner_channel(timeout: float = 5.0):
    return _make_channel("oi-phase-runner", timeout)

def recon_probe_channel(timeout: float = 5.0):
    return _make_channel("oi-recon-probe", timeout)

def ssrf_channel(timeout: float = 5.0):
    return _make_channel("oi-ssrf", timeout)

def oob_channel(timeout: float = 5.0):
    return _make_channel("oi-oob-listener", timeout)

def idor_channel(timeout: float = 5.0):
    return _make_channel("oi-idor-engine", timeout)

def crawler_channel(timeout: float = 5.0):
    return _make_channel("oi-crawler", timeout)

def live_surface_channel(timeout: float = 5.0):
    return _make_channel("oi-live-surface", timeout)

def ingest_channel(timeout: float = 5.0):
    return _make_channel("oi-ingest", timeout)

def target_disc_channel(timeout: float = 5.0):
    return _make_channel("oi-target-disc", timeout)


def credential_spray_channel(timeout: float = 5.0):
    return _make_channel("oi-credential-spray", timeout)

def service_cve_mapper_channel(timeout: float = 5.0):
    return _make_channel("oi-service-cve-mapper", timeout)

def lateral_portscan_channel(timeout: float = 5.0):
    return _make_channel("oi-lateral-portscan", timeout)