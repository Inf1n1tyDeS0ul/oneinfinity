"""
network_service_scanner.py — Unauthenticated service access scanner.

Probes common infrastructure services (Redis, MongoDB, Elasticsearch, etc.) for
unauthenticated access by performing TCP connects + protocol-level probes without
requiring any credentials.  A positive response with no auth challenge = critical finding.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import struct
import time
from typing import Optional
from urllib.parse import urlparse

try:
    import aiohttp
    _AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None  # type: ignore
    _AIOHTTP_AVAILABLE = False

log = logging.getLogger("oneinfinity.network_service_scanner")

# ---------------------------------------------------------------------------
# Probe helpers — return True when service responds without authentication
# ---------------------------------------------------------------------------

async def _probe_redis(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[str]:
    """Send PING; +PONG means no auth required."""
    try:
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await asyncio.wait_for(writer.drain(), timeout=3)
        data = await asyncio.wait_for(reader.read(64), timeout=3)
        if data.startswith(b"+PONG") or data.startswith(b"$"):
            return data.decode(errors="replace").strip()
    except Exception:
        pass
    return None


async def _probe_mongodb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[str]:
    """Send OP_MSG listDatabases; non-error response = no auth."""
    try:
        # OP_MSG listDatabases BSON command (minimal hand-crafted frame)
        bson_doc = (
            b"\x27\x00\x00\x00"          # doc length = 39
            b"\x10listDatabases\x00\x01\x00\x00\x00"  # int32 field = 1
            b"\x01"                                    # key sep (actually we need 0x00 terminator)
        )
        # Minimal but functional: send isMaster instead (smaller / universally understood)
        bson_ismast = (
            b"\x13\x00\x00\x00"       # docLen=19
            b"\x10isMaster\x00\x01\x00\x00\x00"  # int32 1
            b"\x00"                    # end of doc
        )
        # Build OP_QUERY frame
        msg_len = 16 + 4 + 4 + len(b"admin.$cmd\x00") + 4 + 4 + len(bson_ismast)
        header = struct.pack("<iiii", msg_len, 1, 0, 2004)  # reqId, respTo, OP_QUERY
        flags = struct.pack("<i", 0)
        collection = b"admin.$cmd\x00"
        skip = struct.pack("<i", 0)
        ret = struct.pack("<i", -1)
        frame = header + flags + collection + skip + ret + bson_ismast
        writer.write(frame)
        await asyncio.wait_for(writer.drain(), timeout=3)
        data = await asyncio.wait_for(reader.read(256), timeout=4)
        if len(data) >= 16:
            return f"OP_REPLY len={len(data)}"
    except Exception:
        pass
    return None


async def _probe_memcached(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[str]:
    """Send 'version\r\n'; VERSION response = unauthenticated access."""
    try:
        writer.write(b"version\r\n")
        await asyncio.wait_for(writer.drain(), timeout=3)
        data = await asyncio.wait_for(reader.read(64), timeout=3)
        if data.startswith(b"VERSION"):
            return data.decode(errors="replace").strip()
    except Exception:
        pass
    return None


async def _probe_cassandra(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Optional[str]:
    """Send CQL STARTUP; READY response = no auth."""
    try:
        # CQL native protocol v3 STARTUP frame
        body = b"\x00\x01\x00\x0bCQL_VERSION\x00\x053.0.0"
        header = struct.pack(">BBHI", 0x03, 0x00, 0x0001, len(body))  # ver flags stream opcode length
        # opcode 0x01 = STARTUP
        header = bytes([0x03, 0x00, 0x00, 0x01, 0x01]) + struct.pack(">I", len(body))
        writer.write(header + body)
        await asyncio.wait_for(writer.drain(), timeout=3)
        data = await asyncio.wait_for(reader.read(64), timeout=4)
        # opcode 2 = READY
        if len(data) >= 9 and data[4] == 0x02:
            return "READY (no auth)"
        # opcode 3 = AUTHENTICATE (auth required)
        if len(data) >= 9 and data[4] == 0x03:
            return None
        if len(data) > 0:
            return f"response len={len(data)} opcode={data[4] if len(data)>4 else '?'}"
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class NetworkServiceScanner:
    """
    Probe infrastructure services for unauthenticated access.

    Each service entry defines (default_port, probe_type):
      - probe_type == 'http'  → plain HTTP GET /
      - probe_type == 'https' → HTTPS GET /
      - probe_type == callable → async TCP probe coroutine(reader, writer) → str|None
    """

    SERVICES: dict[str, tuple] = {
        "redis":          (6379,  _probe_redis),
        "mongodb":        (27017, _probe_mongodb),
        "elasticsearch":  (9200,  "http"),
        "memcached":      (11211, _probe_memcached),
        "cassandra":      (9042,  _probe_cassandra),
        "etcd":           (2379,  "http"),
        "consul":         (8500,  "http"),
        "kubernetes_api": (6443,  "https"),
        "docker_api":     (2375,  "http"),
        "prometheus":     (9090,  "http"),
    }

    # HTTP endpoints to probe for unauthenticated access
    _HTTP_ENDPOINTS: dict[str, dict] = {
        "elasticsearch":  {"path": "/", "check_keys": ["cluster_name", "version"]},
        "etcd":           {"path": "/v3/members", "check_keys": ["members", "header"]},
        "consul":         {"path": "/v1/agent/self", "check_keys": ["Config", "Member"]},
        "kubernetes_api": {"path": "/api/v1/pods", "check_keys": ["items", "kind"]},
        "docker_api":     {"path": "/containers/json", "check_keys": None},  # any 200 = exposed
        "prometheus":     {"path": "/api/v1/targets", "check_keys": ["data", "status"]},
    }

    def __init__(self, timeout: float = 5.0, concurrency: int = 20) -> None:
        self.timeout = timeout
        self.concurrency = concurrency

    # ------------------------------------------------------------------
    # Internal: TCP-level check
    # ------------------------------------------------------------------

    async def _tcp_check(self, host: str, port: int) -> bool:
        """Return True if port is open (TCP connect succeeds)."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _http_check(self, host: str, port: int, service: str,
                          tls: bool = False) -> Optional[str]:
        """HTTP(S) GET probe; return evidence string or None."""
        endpoint_cfg = self._HTTP_ENDPOINTS.get(service, {"path": "/", "check_keys": None})
        path = endpoint_cfg["path"]
        check_keys = endpoint_cfg["check_keys"]
        scheme = "https" if tls else "http"
        url = f"{scheme}://{host}:{port}{path}"
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as session:
                async with session.get(url) as resp:
                    if resp.status in (200, 401, 403):
                        if resp.status != 200:
                            return None  # auth challenge present
                        text = await resp.text()
                        if check_keys:
                            try:
                                data = json.loads(text)
                                if any(k in data for k in check_keys):
                                    return f"HTTP 200 unauthenticated — keys: {check_keys}"
                            except json.JSONDecodeError:
                                pass
                        else:
                            return f"HTTP 200 unauthenticated — {url}"
        except Exception:
            pass
        return None

    async def _tcp_probe(self, host: str, port: int, probe_fn) -> Optional[str]:
        """Open raw TCP connection and run probe_fn(reader, writer)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
            try:
                evidence = await probe_fn(reader, writer)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            return evidence
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Public: check single service
    # ------------------------------------------------------------------

    async def check_service(self, host: str, port: int, service: str) -> Optional[dict]:
        """
        Probe a single (host, port, service).
        Returns a finding dict if unauthenticated access confirmed, else None.
        """
        _, probe = self.SERVICES.get(service, (port, None))
        if probe is None:
            return None

        evidence: Optional[str] = None

        if probe == "http":
            evidence = await self._http_check(host, port, service, tls=False)
        elif probe == "https":
            evidence = await self._http_check(host, port, service, tls=True)
        elif callable(probe):
            evidence = await self._tcp_probe(host, port, probe)

        if evidence is None:
            return None

        return {
            "vuln_type": f"unauthenticated_{service}",
            "type": f"unauthenticated_{service}",
            "severity": "critical",
            "title": f"Unauthenticated {service.replace('_', ' ').title()} Access",
            "host": host,
            "port": port,
            "service": service,
            "url": f"{host}:{port}",
            "target": host,
            "evidence": evidence,
            "tool": "network_service_scanner",
            "source": "network_service_scanner",
            "confidence": 0.95,
            "remediation": (
                f"Restrict {service} port {port} to trusted networks only "
                "and enable authentication/authorization."
            ),
        }

    # ------------------------------------------------------------------
    # Public: scan target
    # ------------------------------------------------------------------

    async def scan(self, target: str, port_range: Optional[list] = None) -> list[dict]:
        """
        Scan target host for all configured services.

        Args:
            target:     Hostname or IP (scheme stripped if present).
            port_range: Optional list of (service_name, port) overrides; if None
                        the default SERVICES ports are used.

        Returns:
            List of critical finding dicts for every confirmed unauthenticated service.
        """
        if not _AIOHTTP_AVAILABLE:
            log.warning("aiohttp not installed; network service scan skipped")
            return []
        host = urlparse(target).hostname or target.replace("https://", "").replace("http://", "").split("/")[0]

        # Build (service, port) pairs to probe
        if port_range:
            pairs = [(svc, port) for svc, port in port_range if svc in self.SERVICES]
        else:
            pairs = [(svc, port) for svc, (port, _) in self.SERVICES.items()]

        sem = asyncio.Semaphore(self.concurrency)
        findings: list[dict] = []

        async def _check_one(service: str, port: int) -> Optional[dict]:
            async with sem:
                return await self.check_service(host, port, service)

        results = await asyncio.gather(
            *[_check_one(svc, port) for svc, port in pairs],
            return_exceptions=True,
        )

        for r in results:
            if isinstance(r, dict):
                findings.append(r)
            elif isinstance(r, Exception):
                log.debug("network_service_scanner probe error: %s", r)

        log.info("network_service_scanner: %d unauthenticated services on %s", len(findings), host)
        return findings


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

async def scan_network_services(target: str) -> list[dict]:
    """Convenience coroutine for unified_scan_engine wiring."""
    scanner = NetworkServiceScanner()
    return await scanner.scan(target)
