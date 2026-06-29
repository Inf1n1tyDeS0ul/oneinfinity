"""
go_lateral_portscan_bridge.py — Python wrapper for oi-lateral-portscan.

Architecture
────────────
oi-lateral-portscan is a CLI tool (not a gRPC sidecar).
It reads flags and emits NDJSON findings to stdout:
    {"vuln_type":"lateral_open_port","ip":"10.x","port":6379,
     "service":"redis","banner":"...","ts":"..."}

Invocation:
    oi-lateral-portscan --targets 10.0.0.0/24 --ports 22,80,443,6379 \
                        --timeout 500 --workers 200

Usage
─────
    from oneinfinity.scan.go_lateral_portscan_bridge import GoLateralPortscanBridge
    bridge = GoLateralPortscanBridge()
    findings = await bridge.scan(
        targets=["10.0.0.0/24", "172.16.0.1"],
        ports=[22, 80, 443, 8080, 6379, 27017],
        scan_id="scan_001",
    )
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import uuid
from typing import Any

log = logging.getLogger("oi.go_lateral_portscan_bridge")

_SIDECAR_NAME = "oi-lateral-portscan"
_DEFAULT_TIMEOUT = 300.0
_DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 5432,
                  6379, 8080, 8443, 8888, 9200, 27017]


# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------

def _binary_path() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", ".."))
    local = os.path.join(
        repo_root, "src", "go", "oi-lateral-portscan", "oi-lateral-portscan"
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
# GoLateralPortscanBridge
# ---------------------------------------------------------------------------

class GoLateralPortscanBridge:
    """
    Python wrapper for oi-lateral-portscan (CLI, NDJSON output).

    Handles:
    - Binary lookup
    - Subprocess invocation with timeout
    - NDJSON parsing to OI finding dicts
    - Graceful degradation when binary absent
    - DB persistence via DBManager.save_finding
    """

    def is_available(self) -> bool:
        return _binary_path() is not None

    async def scan(
        self,
        targets: list[str],
        ports: list[int] | None = None,
        timeout_ms: int = 500,
        workers: int = 200,
        scan_id: str | None = None,
        call_timeout: float = _DEFAULT_TIMEOUT,
        store_findings: bool = True,
    ) -> list[dict]:
        """
        Scan internal network targets for open ports.

        Parameters
        ----------
        targets : list[str]
            IPs or CIDRs to scan (e.g. ["10.0.0.0/24", "192.168.1.5"]).
        ports : list[int] | None
            Ports to probe; defaults to a common attack-surface set.
        timeout_ms : int
            Per-connection timeout in milliseconds.
        workers : int
            Concurrency level.
        scan_id : str | None
            Correlation ID; auto-generated if None.
        call_timeout : float
            Total subprocess timeout in seconds.
        store_findings : bool
            Persist findings to DBManager when True.

        Returns
        -------
        list[dict]
            Finding dicts in OneInfinity standard format.
        """
        binary = _binary_path()
        if not binary:
            log.warning("[go_lateral_portscan_bridge] binary not found — skipping")
            return []

        if not targets:
            return []

        sid = scan_id or uuid.uuid4().hex[:16]
        port_list = ports if ports is not None else _DEFAULT_PORTS
        ports_str = ",".join(str(p) for p in port_list)
        targets_str = ",".join(targets)

        cmd = [
            binary,
            "--targets", targets_str,
            "--ports", ports_str,
            "--timeout", str(timeout_ms),
            "--workers", str(workers),
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=call_timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("[go_lateral_portscan_bridge] scan timed out after %.0fs", call_timeout)
            return []
        except OSError as exc:
            log.warning("[go_lateral_portscan_bridge] subprocess error: %s", exc)
            return []

        if result.returncode not in (0, 1):
            log.debug("[go_lateral_portscan_bridge] exit %d stderr: %s",
                      result.returncode, result.stderr[:200])

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            f = self._normalize(raw, sid)
            if f:
                findings.append(f)

        if store_findings and findings:
            await self._store(findings)

        log.info(
            "[go_lateral_portscan_bridge] scan(%s) → %d open ports",
            targets_str[:80], len(findings)
        )
        return findings

    @staticmethod
    def _normalize(raw: Any, scan_id: str) -> dict | None:
        if not isinstance(raw, dict):
            return None
        ip = raw.get("ip", "")
        port = raw.get("port", 0)
        service = raw.get("service", "")
        banner = raw.get("banner", "")
        return {
            "id": uuid.uuid4().hex,
            "vuln_type": raw.get("vuln_type") or "lateral_open_port",
            "severity": "info",
            "url": f"{ip}:{port}",
            "target": ip,
            "evidence": (
                f"Open port {port}/{service} on {ip}"
                + (f" — banner: {banner[:200]}" if banner else "")
            ),
            "tool": "oi-lateral-portscan",
            "confidence": 1.0,
            "scan_id": scan_id,
            "metadata": {
                "ip": ip,
                "port": str(port),
                "service": service,
                "banner": banner,
                "ts": raw.get("ts", ""),
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
                    log.debug("[go_lateral_portscan_bridge] DB save_finding error: %s", exc)
        except Exception as exc:
            log.debug("[go_lateral_portscan_bridge] DB unavailable: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

async def run_lateral_portscan(
    targets: list[str],
    ports: list[int] | None = None,
    scan_id: str | None = None,
    call_timeout: float = _DEFAULT_TIMEOUT,
) -> list[dict]:
    """Convenience wrapper."""
    bridge = GoLateralPortscanBridge()
    return await bridge.scan(
        targets=targets,
        ports=ports,
        scan_id=scan_id,
        call_timeout=call_timeout,
    )
