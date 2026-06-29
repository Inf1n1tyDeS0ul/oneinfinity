"""
sidecar_manager.py — Lifecycle manager for One&Infinity Go sidecars.

Lifecycle contract
──────────────────
start(name)   → launch the sidecar binary, wait until the gRPC port responds.
stop(name)    → send SIGTERM; escalate to SIGKILL after grace_period_s.
restart(name) → stop then start.
status(name)  → SidecarStatus(running, pid, port, uptime_s)
start_all()   → start every Capability with required=True; optionally all.
stop_all()    → graceful shutdown of every tracked process.

Sidecars are identified by their Capability.name (e.g. "oi-crawler").
Binaries are resolved relative to the repository root (the directory
containing config/ports.json).

Usage:
    from oneinfinity.infra.sidecar_manager import SidecarManager
    mgr = SidecarManager()
    mgr.start("oi-crawler")
    # ... scan work ...
    mgr.stop_all()
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from oneinfinity.infra.capability_registry import CAPABILITIES, Capability, get as _cap_get

log = logging.getLogger(__name__)

# Repository root = 4 levels up from this file:
# src/oneinfinity/infra/sidecar_manager.py → repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]

_DEFAULT_STARTUP_TIMEOUT = 10.0   # seconds to wait for port to open
_DEFAULT_GRACE_PERIOD    = 5.0    # seconds between SIGTERM and SIGKILL


@dataclass
class SidecarStatus:
    name: str
    running: bool
    pid: Optional[int] = None
    port: Optional[int] = None
    uptime_s: float = 0.0
    error: str = ""


@dataclass
class _ManagedProc:
    capability: Capability
    proc: subprocess.Popen
    started_at: float = field(default_factory=time.time)


class SidecarManager:
    """Start, stop, and monitor One&Infinity Go sidecar processes."""

    def __init__(
        self,
        startup_timeout: float = _DEFAULT_STARTUP_TIMEOUT,
        grace_period: float = _DEFAULT_GRACE_PERIOD,
    ) -> None:
        self._procs: Dict[str, _ManagedProc] = {}
        self._startup_timeout = startup_timeout
        self._grace_period = grace_period

    # ── Public API ────────────────────────────────────────────────────────

    def start(self, name: str) -> SidecarStatus:
        """Start sidecar *name* and block until its gRPC port is reachable."""
        cap = _cap_get(name)
        if cap is None:
            return SidecarStatus(name=name, running=False,
                                 error=f"Unknown sidecar '{name}'; add to capability_registry.py")

        if name in self._procs and self._procs[name].proc.poll() is None:
            log.debug("sidecar %s already running (pid=%d)", name, self._procs[name].proc.pid)
            return self._status(name)

        binary = _REPO_ROOT / cap.binary
        if not binary.is_file():
            return SidecarStatus(
                name=name, running=False, port=cap.port,
                error=f"Binary not found: {binary}. Build with: "
                      f"cd src/go/{name} && go build -o bin/{name} .",
            )

        log.info("Starting sidecar %s (binary=%s, port=%d)", name, binary, cap.port)
        proc = subprocess.Popen(
            [str(binary)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,   # own process group → clean kill
        )
        self._procs[name] = _ManagedProc(capability=cap, proc=proc)

        # Wait for gRPC port to become reachable
        if not self._wait_for_port(cap.port, self._startup_timeout):
            stderr = proc.stderr.read(4096).decode(errors="replace") if proc.stderr else ""
            proc.kill()
            self._procs.pop(name, None)
            return SidecarStatus(
                name=name, running=False, port=cap.port,
                error=f"Sidecar did not open port {cap.port} within "
                      f"{self._startup_timeout}s. stderr: {stderr[:300]}",
            )

        log.info("Sidecar %s ready on port %d (pid=%d)", name, cap.port, proc.pid)
        return self._status(name)

    def stop(self, name: str) -> None:
        """Gracefully terminate sidecar *name*."""
        mp = self._procs.pop(name, None)
        if mp is None:
            return
        self._terminate(mp)

    def restart(self, name: str) -> SidecarStatus:
        """Stop then start sidecar *name*."""
        self.stop(name)
        return self.start(name)

    def status(self, name: str) -> SidecarStatus:
        return self._status(name)

    def start_all(self, include_optional: bool = False) -> Dict[str, SidecarStatus]:
        """Start all required sidecars (and optional ones if *include_optional* is True)."""
        results: Dict[str, SidecarStatus] = {}
        for cap in CAPABILITIES:
            if cap.kind != "go":
                continue
            if cap.required or include_optional:
                results[cap.name] = self.start(cap.name)
        return results

    def stop_all(self) -> None:
        """Gracefully stop all managed sidecars."""
        names = list(self._procs.keys())
        for name in names:
            mp = self._procs.pop(name, None)
            if mp:
                self._terminate(mp)

    def all_status(self) -> Dict[str, SidecarStatus]:
        return {name: self._status(name) for name in self._procs}

    # ── Internal helpers ──────────────────────────────────────────────────

    def _status(self, name: str) -> SidecarStatus:
        cap = _cap_get(name)
        mp = self._procs.get(name)
        if mp is None or mp.proc.poll() is not None:
            return SidecarStatus(
                name=name,
                running=False,
                port=cap.port if cap else None,
                error="not running" if mp is None else f"exited with rc={mp.proc.poll()}",
            )
        return SidecarStatus(
            name=name,
            running=True,
            pid=mp.proc.pid,
            port=mp.capability.port,
            uptime_s=time.time() - mp.started_at,
        )

    def _terminate(self, mp: _ManagedProc) -> None:
        """SIGTERM → wait grace_period → SIGKILL."""
        proc = mp.proc
        name = mp.capability.name
        if proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            proc.terminate()
        deadline = time.time() + self._grace_period
        while time.time() < deadline:
            if proc.poll() is not None:
                log.info("Sidecar %s stopped cleanly", name)
                return
            time.sleep(0.1)
        log.warning("Sidecar %s did not stop within %.1fs; sending SIGKILL", name, self._grace_period)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            proc.kill()

    @staticmethod
    def _wait_for_port(port: int, timeout: float) -> bool:
        """Return True once localhost:*port* accepts a TCP connection."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.25)
        return False
