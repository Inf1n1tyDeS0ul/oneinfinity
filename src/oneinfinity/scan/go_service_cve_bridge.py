"""
go_service_cve_bridge.py — Python wrapper for oi-service-cve-mapper.

Architecture
────────────
oi-service-cve-mapper is a CLI tool (not gRPC).
It reads NDJSON {host, port, banner, service} from stdin and emits
NDJSON CVE findings to stdout:
    {"host":"...", "port":22, "service":"openssh", "version":"8.0",
     "cve_id":"CVE-2023-XXXX", "cvss":9.8, "description":"...",
     "vuln_type":"service_cve", "banner":"...", "ts":"..."}

Invocation:
    echo '{"host":"10.0.0.1","port":22,"banner":"OpenSSH 8.0","service":"ssh"}' \
      | oi-service-cve-mapper

Usage
─────
    from oneinfinity.scan.go_service_cve_bridge import GoServiceCVEBridge
    bridge = GoServiceCVEBridge()
    findings = await bridge.map_services(
        services=[
            {"host": "10.0.0.1", "port": 22, "banner": "OpenSSH 8.0", "service": "ssh"},
        ],
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

log = logging.getLogger("oi.go_service_cve_bridge")

_SIDECAR_NAME = "oi-service-cve-mapper"
_DEFAULT_TIMEOUT = 60.0


# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------

def _binary_path() -> str | None:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.normpath(os.path.join(here, "..", "..", ".."))
    local = os.path.join(
        repo_root, "src", "go", "oi-service-cve-mapper", "oi-service-cve-mapper"
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
# GoServiceCVEBridge
# ---------------------------------------------------------------------------

class GoServiceCVEBridge:
    """
    Python wrapper for oi-service-cve-mapper (CLI, stdin→stdout NDJSON).

    Handles:
    - Binary lookup
    - Subprocess invocation with stdin pipe and timeout
    - NDJSON input/output parsing
    - Graceful degradation when binary absent
    - DB persistence via DBManager.save_finding
    """

    def is_available(self) -> bool:
        return _binary_path() is not None

    async def map_services(
        self,
        services: list[dict],
        scan_id: str | None = None,
        call_timeout: float = _DEFAULT_TIMEOUT,
        store_findings: bool = True,
    ) -> list[dict]:
        """
        Map service banners to known CVEs.

        Parameters
        ----------
        services : list[dict]
            Each entry must have keys: host, port, banner, service.
        scan_id : str | None
            Correlation ID; auto-generated if None.
        call_timeout : float
            Subprocess timeout in seconds.
        store_findings : bool
            Persist findings to DBManager when True.

        Returns
        -------
        list[dict]
            CVE finding dicts in OneInfinity standard format.
        """
        binary = _binary_path()
        if not binary:
            log.warning("[go_service_cve_bridge] binary not found — CVE mapping disabled")
            return []

        if not services:
            return []

        sid = scan_id or uuid.uuid4().hex[:16]

        # Build NDJSON input
        stdin_lines = []
        for svc in services:
            record = {
                "host": svc.get("host", ""),
                "port": int(svc.get("port", 0)),
                "banner": svc.get("banner", ""),
                "service": svc.get("service", ""),
            }
            stdin_lines.append(json.dumps(record))
        stdin_data = "\n".join(stdin_lines) + "\n"

        try:
            result = subprocess.run(
                [binary],
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=call_timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("[go_service_cve_bridge] timed out after %.0fs", call_timeout)
            return []
        except OSError as exc:
            log.warning("[go_service_cve_bridge] subprocess error: %s", exc)
            return []

        if result.returncode != 0:
            log.debug(
                "[go_service_cve_bridge] exit %d stderr: %s",
                result.returncode, result.stderr[:200]
            )

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
            "[go_service_cve_bridge] mapped %d services → %d CVE findings",
            len(services), len(findings)
        )
        return findings

    @staticmethod
    def _normalize(raw: Any, scan_id: str) -> dict | None:
        if not isinstance(raw, dict):
            return None
        host = raw.get("host", "")
        port = raw.get("port", 0)
        cve_id = raw.get("cve_id", "")
        cvss = float(raw.get("cvss") or 0.0)

        # Map CVSS to severity
        if cvss >= 9.0:
            severity = "critical"
        elif cvss >= 7.0:
            severity = "high"
        elif cvss >= 4.0:
            severity = "medium"
        else:
            severity = "low"

        return {
            "id": uuid.uuid4().hex,
            "vuln_type": raw.get("vuln_type") or "service_cve",
            "severity": severity,
            "url": f"{host}:{port}",
            "target": host,
            "evidence": (
                f"{cve_id} on {raw.get('service','')} {raw.get('version','')} "
                f"(CVSS {cvss:.1f}): {raw.get('description','')[:300]}"
            ),
            "tool": "oi-service-cve-mapper",
            "confidence": 0.9,
            "scan_id": scan_id,
            "metadata": {
                "cve_id": cve_id,
                "cvss": str(cvss),
                "host": host,
                "port": str(port),
                "service": raw.get("service", ""),
                "version": raw.get("version", ""),
                "banner": raw.get("banner", "")[:200],
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
                    log.debug("[go_service_cve_bridge] DB save_finding error: %s", exc)
        except Exception as exc:
            log.debug("[go_service_cve_bridge] DB unavailable: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

async def map_services_to_cves(
    services: list[dict],
    scan_id: str | None = None,
    call_timeout: float = _DEFAULT_TIMEOUT,
) -> list[dict]:
    """Convenience wrapper."""
    bridge = GoServiceCVEBridge()
    return await bridge.map_services(
        services=services,
        scan_id=scan_id,
        call_timeout=call_timeout,
    )
