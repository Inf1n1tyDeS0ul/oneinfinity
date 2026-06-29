"""
go_service_cve_mapper.py — Python wrapper for the oi-service-cve-mapper Go tool.

Architecture
────────────
oi-service-cve-mapper is a high-throughput NDJSON pipe tool — it reads
InputRecord lines from stdin and emits CVEFinding lines to stdout:

    stdin  → {"host":"10.0.0.1","port":6379,"banner":"Redis 6.2.1","service":"redis"}
    stdout ← {"host":"10.0.0.1","port":6379,"service":"redis","version":"6.2.1",
               "cve_id":"CVE-2022-0543","cvss":9.8,"description":"...","vuln_type":"rce",...}

The binary is registered in the capability registry at port 50061
(service_cve_mapper_channel). That channel is used for readiness probing;
the binary itself is invoked as a subprocess pipe for data throughput.

Primary use-case in the SSRF lateral movement chain:
    1. _add_lateral_movement_targets() discovers IPs via cloud metadata SSRF.
    2. oi-lateral-portscan enumerates open ports and banners.
    3. THIS wrapper pipes those banners through oi-service-cve-mapper.
    4. Returns HIGH/CRITICAL CVE findings for the lateral IPs.

Finding format: {vuln_type, severity, url, evidence, tool, target}

Usage
─────
    from oneinfinity.scan.go_service_cve_mapper import GoServiceCveMapper
    mapper = GoServiceCveMapper()
    findings = await mapper.map_services([
        {"host": "10.0.1.5", "port": 6379, "banner": "Redis 6.2.1", "service": "redis"},
        {"host": "10.0.1.6", "port": 9200, "banner": "elasticsearch 7.10", "service": "elasticsearch"},
    ])
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.go_service_cve_mapper")

_TOOL_NAME = "go_service_cve_mapper"
_SIDECAR_NAME = "oi-service-cve-mapper"

# Binary path: repo_root/src/go/oi-service-cve-mapper/bin/oi-service-cve-mapper
_REPO_ROOT = Path(__file__).resolve().parents[4]
_BINARY = _REPO_ROOT / "src" / "go" / "oi-service-cve-mapper" / "bin" / _SIDECAR_NAME


# ─── Finding dataclass ────────────────────────────────────────────────────────

@dataclass
class CveFinding:
    """Normalised CVE finding from oi-service-cve-mapper."""
    finding_id: str
    vuln_type: str = "service_cve"
    severity: str = "high"
    url: str = ""               # http://host:port/
    target: str = ""            # host:port
    host: str = ""
    port: int = 0
    service: str = ""
    version: str = ""
    cve_id: str = ""
    cvss: float = 0.0
    description: str = ""
    banner: str = ""
    evidence: str = ""
    confidence: float = 0.95
    tool: str = _TOOL_NAME
    source_type: str = "active"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "version": self.version,
            "cve_id": self.cve_id,
            "cvss": self.cvss,
            "description": self.description,
            "banner": self.banner,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "tool": self.tool,
            "source_type": self.source_type,
        }


# ─── Severity mapper ──────────────────────────────────────────────────────────

def _cvss_to_severity(cvss: float) -> str:
    """Map CVSS score to OneInfinity severity string."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


# ─── Main wrapper class ────────────────────────────────────────────────────────

class GoServiceCveMapper:
    """
    Python facade over the oi-service-cve-mapper Go tool.

    The binary reads NDJSON service records from stdin (one JSON object per
    line) and writes CVE findings to stdout.  This wrapper manages the
    subprocess lifecycle, feeds service records in batches, and parses the
    NDJSON output into CveFinding objects.

    Graceful degradation: if the binary is absent (not yet built), the method
    returns an empty list and logs a build hint rather than raising.

    Thread-safety: instances are NOT thread-safe; create one per scan task.
    """

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    # ── Public API ─────────────────────────────────────────────────────────

    async def map_services(
        self,
        services: List[Dict[str, Any]],
    ) -> List[CveFinding]:
        """
        Map a list of discovered services to known CVEs.

        Parameters
        ──────────
        services:
            List of dicts with keys: host, port, banner, service.
            Extra keys are forwarded as-is to the binary.

        Returns
        ───────
        List of CveFinding (one per matched CVE per service record).
        Empty list on binary-absent or empty input.
        """
        if not services:
            return []

        if not _BINARY.is_file():
            log.warning(
                "go_service_cve_mapper: binary not found at %s. "
                "Build with: cd src/go/oi-service-cve-mapper && "
                "go build -o bin/oi-service-cve-mapper .",
                _BINARY,
            )
            return []

        # Build NDJSON stdin payload
        stdin_lines = []
        for svc in services:
            rec = {
                "host": str(svc.get("host", "")),
                "port": int(svc.get("port", 0)),
                "banner": str(svc.get("banner", "")),
                "service": str(svc.get("service", "")),
            }
            stdin_lines.append(json.dumps(rec))
        stdin_payload = "\n".join(stdin_lines) + "\n"

        # Run in executor to stay non-blocking
        loop = asyncio.get_event_loop()
        raw_output = await loop.run_in_executor(
            None,
            self._run_subprocess,
            stdin_payload,
        )

        if raw_output is None:
            return []

        return self._parse_output(raw_output)

    def map_services_sync(
        self,
        services: List[Dict[str, Any]],
    ) -> List[CveFinding]:
        """Synchronous variant for non-async callers."""
        if not services:
            return []

        if not _BINARY.is_file():
            log.warning(
                "go_service_cve_mapper: binary not found at %s. "
                "Build with: cd src/go/oi-service-cve-mapper && "
                "go build -o bin/oi-service-cve-mapper .",
                _BINARY,
            )
            return []

        stdin_lines = [
            json.dumps({
                "host": str(s.get("host", "")),
                "port": int(s.get("port", 0)),
                "banner": str(s.get("banner", "")),
                "service": str(s.get("service", "")),
            })
            for s in services
        ]
        stdin_payload = "\n".join(stdin_lines) + "\n"
        raw_output = self._run_subprocess(stdin_payload)
        if raw_output is None:
            return []
        return self._parse_output(raw_output)

    # ── Integration helpers ────────────────────────────────────────────────

    async def map_from_port_scan(
        self,
        port_scan_findings: List[Dict[str, Any]],
    ) -> List[CveFinding]:
        """
        Convenience adapter: accepts findings from oi-lateral-portscan
        (vuln_type="lateral_open_port") and maps them through the CVE database.

        Port scan finding schema:
            {"vuln_type":"lateral_open_port","ip":"10.x","port":N,
             "service":"redis","banner":"...","evidence":"..."}
        """
        services = [
            {
                "host": f.get("ip", f.get("host", "")),
                "port": f.get("port", 0),
                "banner": f.get("banner", ""),
                "service": f.get("service", ""),
            }
            for f in port_scan_findings
            if f.get("vuln_type") == "lateral_open_port"
        ]
        return await self.map_services(services)

    # ── Internal helpers ───────────────────────────────────────────────────

    def _run_subprocess(self, stdin_payload: str) -> Optional[str]:
        """
        Invoke oi-service-cve-mapper as a subprocess pipe.
        Returns raw stdout string or None on error.
        """
        try:
            result = subprocess.run(
                [str(_BINARY)],
                input=stdin_payload,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            log.error(
                "go_service_cve_mapper: binary timed out after %ds", self._timeout
            )
            return None
        except FileNotFoundError:
            log.warning(
                "go_service_cve_mapper: binary not executable at %s", _BINARY
            )
            return None
        except Exception as exc:
            log.error("go_service_cve_mapper: subprocess error: %s", exc)
            return None

        if result.returncode != 0:
            log.error(
                "go_service_cve_mapper: binary exited %d: %s",
                result.returncode,
                result.stderr[:500],
            )
            return None

        if result.stderr:
            log.debug("go_service_cve_mapper stderr: %s", result.stderr[:300])

        return result.stdout

    def _parse_output(self, raw_output: str) -> List[CveFinding]:
        """Parse NDJSON output lines into CveFinding objects."""
        findings: List[CveFinding] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                log.debug("go_service_cve_mapper: skipping non-JSON line: %r", line[:80])
                continue

            if not isinstance(obj, dict):
                continue

            finding = self._normalise(obj)
            if finding:
                findings.append(finding)

        log.info(
            "go_service_cve_mapper: mapped %d CVE findings from %d output lines",
            len(findings),
            len(raw_output.splitlines()),
        )
        return findings

    @staticmethod
    def _normalise(raw: Dict[str, Any]) -> Optional[CveFinding]:
        """
        Map a raw CVEFinding dict from the Go binary → CveFinding.

        Go binary output schema:
            host, port, service, version, cve_id, cvss,
            description, vuln_type, banner, ts
        """
        cve_id = raw.get("cve_id", "")
        host = raw.get("host", "")
        port = int(raw.get("port", 0))
        service = raw.get("service", "")
        cvss = float(raw.get("cvss", 0.0))
        description = raw.get("description", "")
        version = raw.get("version", "")
        banner = raw.get("banner", "")
        vuln_type = raw.get("vuln_type", "service_cve")

        if not cve_id or not host:
            return None

        severity = _cvss_to_severity(cvss)
        target = f"{host}:{port}"
        url = f"http://{target}/"

        finding_id = hashlib.md5(
            f"cve_{host}_{port}_{cve_id}".encode()
        ).hexdigest()[:16]

        evidence = (
            f"{cve_id} (CVSS {cvss:.1f}) on {service} {version} at {target}. "
            f"{description}"
        )
        if banner:
            evidence += f" Banner: {banner[:120]}"

        return CveFinding(
            finding_id=finding_id,
            vuln_type=vuln_type or "service_cve",
            severity=severity,
            url=url,
            target=target,
            host=host,
            port=port,
            service=service,
            version=version,
            cve_id=cve_id,
            cvss=cvss,
            description=description,
            banner=banner,
            evidence=evidence,
            confidence=0.95 if cvss >= 7.0 else 0.80,
            tool=_TOOL_NAME,
        )

    def health(self) -> bool:
        """
        Probe the service_cve_mapper gRPC channel for readiness.
        Falls back to binary-exists check if channel is unavailable.
        """
        try:
            from oneinfinity.infra.grpc_client import service_cve_mapper_channel
            service_cve_mapper_channel(timeout=2.0)
            return True
        except Exception:
            pass
        # Fallback: check binary exists
        return _BINARY.is_file()


# ─── Convenience function ─────────────────────────────────────────────────────

async def map_services(
    services: List[Dict[str, Any]],
    timeout: int = 30,
) -> List[CveFinding]:
    """Module-level convenience: create mapper, run, return findings."""
    mapper = GoServiceCveMapper(timeout=timeout)
    return await mapper.map_services(services)
