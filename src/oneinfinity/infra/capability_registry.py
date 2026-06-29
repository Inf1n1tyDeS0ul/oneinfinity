"""
capability_registry.py — Sidecar capability catalogue for One&Infinity.

Every Go sidecar that provides gRPC services is registered here as a
Capability entry.  The registry is read by sidecar_manager.py at startup
and by the task_dispatcher to decide which capabilities are available.

Adding a new sidecar:
    1. Add a Capability entry below.
    2. Ensure config/ports.json has the matching port.
    3. Build the binary: cd src/go/<name> && go build -o bin/<name> .
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Capability:
    name: str                   # matches key in config/ports.json
    kind: str                   # "go" | "python"
    binary: str                 # relative path from repo root
    port: int                   # gRPC listen port (loopback)
    required: bool = False      # if True, startup fails when unavailable
    description: str = ""


# ── Registry ──────────────────────────────────────────────────────────────────

CAPABILITIES: List[Capability] = [
    # ── Phase orchestration ────────────────────────────────────────────────
    Capability(
        name="oi-phase-runner",
        kind="go",
        binary="src/go/oi-phase-runner/bin/oi-phase-runner",
        port=50051,
        required=True,
        description="Phase orchestration and task scheduling",
    ),

    # ── New Phase-2 Go sidecars ────────────────────────────────────────────
    Capability(
        name="oi-recon-probe",
        kind="go",
        binary="src/go/oi-recon-probe/bin/oi-recon-probe",
        port=50052,
        required=False,
        description="Concurrent DNS enumeration with 500-goroutine pool, wildcard detection, "
                    "CNAME chain following, and all 6 DNS record types",
    ),
    Capability(
        name="oi-ssrf",
        kind="go",
        binary="src/go/oi-ssrf/bin/oi-ssrf",
        port=50053,
        required=False,
        description="SSRF detection and OOB-confirmed exploitation sidecar",
    ),
    Capability(
        name="oi-oob-listener",
        kind="go",
        binary="src/go/oi-oob-listener/bin/oi-oob-listener",
        port=50054,
        required=False,
        description="Out-of-band interaction listener (DNS/HTTP callbacks)",
    ),
    Capability(
        name="oi-idor-engine",
        kind="go",
        binary="src/go/oi-idor-engine/bin/oi-idor-engine",
        port=50055,
        required=False,
        description="IDOR detection and object-reference enumeration engine",
    ),
    Capability(
        name="oi-crawler",
        kind="go",
        binary="src/go/oi-crawler/bin/oi-crawler",
        port=50056,
        required=False,
        description="Concurrent web crawler with JS rendering support",
    ),
    Capability(
        name="oi-target-disc",
        kind="go",
        binary="src/go/oi-target-disc/bin/oi-target-disc",
        port=50059,
        required=False,
        description="Target discovery and port-scan coordination sidecar",
    ),
    Capability(
        name="oi-credential-spray",
        kind="go",
        binary="src/go/oi-credential-spray/bin/oi-credential-spray",
        port=50060,
        required=False,
        description="Credential spray engine with lockout detection and rate limiting",
    ),
    Capability(
        name="oi-service-cve-mapper",
        kind="go",
        binary="src/go/oi-service-cve-mapper/bin/oi-service-cve-mapper",
        port=50061,
        required=False,
        description="Maps discovered services to known CVEs via NVD/OSV feeds",
    ),
    Capability(
        name="oi-lateral-portscan",
        kind="go",
        binary="src/go/oi-lateral-portscan/bin/oi-lateral-portscan",
        port=50062,
        required=False,
        description="High-speed internal port scanner for lateral movement targets",
    ),
    Capability(
        name="oi-live-surface",
        kind="go",
        binary="src/go/oi-live-surface/bin/oi-live-surface",
        port=50057,
        required=False,
        description="Live attack surface expansion: real-time subdomain and service discovery",
    ),
    Capability(
        name="oi-ingest",
        kind="go",
        binary="src/go/oi-ingest/bin/oi-ingest",
        port=50058,
        required=False,
        description="Finding ingestion sidecar: async gRPC receiver for scan results",
    ),
]

# ── Lookup helpers ────────────────────────────────────────────────────────────

_BY_NAME: dict[str, Capability] = {c.name: c for c in CAPABILITIES}


def get(name: str) -> Optional[Capability]:
    """Return the Capability for *name*, or None if not registered."""
    return _BY_NAME.get(name)


def all_go() -> List[Capability]:
    """All Go-binary capabilities."""
    return [c for c in CAPABILITIES if c.kind == "go"]


def required() -> List[Capability]:
    """Capabilities that must be available at startup."""
    return [c for c in CAPABILITIES if c.required]


def by_port(port: int) -> Optional[Capability]:
    """Reverse lookup by gRPC port number."""
    for c in CAPABILITIES:
        if c.port == port:
            return c
    return None
