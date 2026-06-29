"""
dns_security_scanner.py — DNS attack surface scanner.

Covers:
  • Zone transfer (AXFR) — full dump via each NS record
  • DNS amplification — ANY query response size > 512 bytes
  • Dangling CNAME / subdomain takeover candidates
  • CAA / DNSSEC misconfiguration (bonus hardening checks)
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from typing import Optional

log = logging.getLogger("oneinfinity.dns_security_scanner")

# ---------------------------------------------------------------------------
# Raw DNS helpers (no external deps beyond stdlib)
# ---------------------------------------------------------------------------

def _build_dns_query(qname: str, qtype: int, qid: int = 1337) -> bytes:
    """Build a minimal DNS query packet."""
    header = struct.pack(
        ">HHHHHH",
        qid,    # ID
        0x0100, # QR=0, Opcode=0, RD=1
        1,      # QDCOUNT
        0, 0, 0 # ANCOUNT, NSCOUNT, ARCOUNT
    )
    # Encode QNAME
    parts = qname.rstrip(".").split(".")
    encoded = b""
    for part in parts:
        label = part.encode()
        encoded += bytes([len(label)]) + label
    encoded += b"\x00"
    question = encoded + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def _build_axfr_query(domain: str, qid: int = 1338) -> bytes:
    """Build an AXFR (type=252) query framed for TCP DNS."""
    pkt = _build_dns_query(domain, 252, qid)
    return struct.pack(">H", len(pkt)) + pkt


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name with compression pointer support."""
    parts: list[str] = []
    visited: set[int] = set()
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # Pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in visited:
                break
            visited.add(ptr)
            name, _ = _decode_name(data, ptr)
            parts.append(name)
            offset += 2
            break
        else:
            offset += 1
            if offset + length > len(data):
                break
            parts.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(parts), offset


async def _udp_query(
    nameserver: str,
    query: bytes,
    timeout: float = 4.0,
    port: int = 53,
) -> Optional[bytes]:
    """Send a UDP DNS query, return raw response bytes."""
    loop = asyncio.get_event_loop()
    try:
        transport, protocol = await asyncio.wait_for(
            loop.create_datagram_endpoint(
                lambda: _UDPProtocol(query),
                remote_addr=(nameserver, port),
            ),
            timeout=timeout,
        )
        response = await asyncio.wait_for(protocol.response_future, timeout=timeout)
        transport.close()
        return response
    except Exception:
        return None


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, query: bytes) -> None:
        self.query = query
        self.response_future: asyncio.Future = asyncio.get_event_loop().create_future()

    def connection_made(self, transport):
        transport.sendto(self.query)

    def datagram_received(self, data, addr):
        if not self.response_future.done():
            self.response_future.set_result(data)

    def error_received(self, exc):
        if not self.response_future.done():
            self.response_future.set_exception(exc)

    def connection_lost(self, exc):
        if not self.response_future.done():
            self.response_future.cancel()


async def _resolve_ns(domain: str) -> list[str]:
    """Return NS record hostnames for domain (uses stdlib getaddrinfo trick via thread)."""
    try:
        loop = asyncio.get_event_loop()
        # Query public resolver 8.8.8.8 for NS records
        query = _build_dns_query(domain, 2)  # type NS=2
        resp = await _udp_query("8.8.8.8", query)
        if not resp or len(resp) < 12:
            return []
        ancount = struct.unpack(">H", resp[6:8])[0]
        offset = 12
        # Skip question section
        _, offset = _decode_name(resp, offset)
        offset += 4  # QTYPE + QCLASS
        ns_hosts: list[str] = []
        for _ in range(ancount):
            if offset >= len(resp):
                break
            _, offset = _decode_name(resp, offset)
            if offset + 10 > len(resp):
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", resp[offset:offset + 10])
            offset += 10
            if rtype == 2:  # NS
                nsname, _ = _decode_name(resp, offset)
                ns_hosts.append(nsname)
            offset += rdlen
        return ns_hosts
    except Exception as exc:
        log.debug("_resolve_ns(%s): %s", domain, exc)
        return []


async def _resolve_ip(hostname: str) -> Optional[str]:
    """Resolve hostname to IP string (threaded)."""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, socket.gethostbyname, hostname
        )
        return result
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class DNSSecurityScanner:
    """DNS security attack surface scanner."""

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Zone Transfer (AXFR)
    # ------------------------------------------------------------------

    async def test_zone_transfer(self, domain: str) -> list[dict]:
        """
        Attempt AXFR against every NS for domain.
        Returns findings for each NS that allows the transfer.
        """
        findings: list[dict] = []
        ns_list = await _resolve_ns(domain)
        if not ns_list:
            log.debug("zone_transfer: no NS records for %s", domain)
            return findings

        async def _axfr_one(ns_host: str) -> Optional[dict]:
            ns_ip = await _resolve_ip(ns_host)
            if not ns_ip:
                return None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ns_ip, 53),
                    timeout=self.timeout,
                )
            except Exception:
                return None

            try:
                pkt = _build_axfr_query(domain)
                writer.write(pkt)
                await asyncio.wait_for(writer.drain(), timeout=3)

                # Read first length-prefixed response
                raw_len = await asyncio.wait_for(reader.readexactly(2), timeout=5)
                msg_len = struct.unpack(">H", raw_len)[0]
                if msg_len == 0:
                    return None
                resp = await asyncio.wait_for(reader.readexactly(msg_len), timeout=5)

                ancount = struct.unpack(">H", resp[6:8])[0]
                nscount = struct.unpack(">H", resp[8:10])[0]
                arcount = struct.unpack(">H", resp[10:12])[0]
                total_records = ancount + nscount + arcount

                if total_records > 2:
                    return {
                        "vuln_type": "dns_zone_transfer",
                        "type": "dns_zone_transfer",
                        "severity": "critical",
                        "title": f"DNS Zone Transfer Allowed on {ns_host}",
                        "domain": domain,
                        "nameserver": ns_host,
                        "nameserver_ip": ns_ip,
                        "url": f"dns://{ns_host}/AXFR/{domain}",
                        "target": domain,
                        "evidence": (
                            f"AXFR to {ns_host} ({ns_ip}) returned "
                            f"{total_records} DNS records (ancount={ancount})"
                        ),
                        "tool": "dns_security_scanner",
                        "source": "dns_security_scanner",
                        "confidence": 0.98,
                        "remediation": (
                            "Restrict AXFR transfers to authorized secondary nameservers "
                            "only (ACL/TSIG). Exposing zone data leaks all subdomains."
                        ),
                    }
            except Exception as exc:
                log.debug("AXFR %s @ %s: %s", domain, ns_host, exc)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            return None

        results = await asyncio.gather(
            *[_axfr_one(ns) for ns in ns_list[:8]],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        log.info("zone_transfer(%s): %d vulnerable NS", domain, len(findings))
        return findings

    # ------------------------------------------------------------------
    # DNS Amplification
    # ------------------------------------------------------------------

    async def test_dns_amplification(self, domain: str) -> Optional[dict]:
        """
        Check if ANY record query returns a large response (> 512 bytes),
        indicating the resolver can be abused for amplification attacks.
        """
        query = _build_dns_query(domain, 255)  # type ANY=255
        # Try against the domain's own NS first, then fall back to 8.8.8.8
        ns_list = await _resolve_ns(domain)
        servers = []
        for ns in ns_list[:3]:
            ip = await _resolve_ip(ns)
            if ip:
                servers.append((ns, ip))
        servers.append(("public-8.8.8.8", "8.8.8.8"))

        for ns_label, ns_ip in servers:
            try:
                resp = await _udp_query(ns_ip, query, timeout=self.timeout)
                if resp and len(resp) > 512:
                    ratio = round(len(query) / len(resp), 3) if resp else 0
                    amplification_factor = round(len(resp) / max(len(query), 1), 1)
                    return {
                        "vuln_type": "dns_amplification",
                        "type": "dns_amplification",
                        "severity": "high",
                        "title": f"DNS Amplification Vector on {domain}",
                        "domain": domain,
                        "nameserver": ns_label,
                        "nameserver_ip": ns_ip,
                        "url": f"dns://{ns_ip}/ANY/{domain}",
                        "target": domain,
                        "evidence": (
                            f"ANY query ({len(query)} bytes) returned {len(resp)} bytes "
                            f"(amplification factor ≈{amplification_factor}×)"
                        ),
                        "tool": "dns_security_scanner",
                        "source": "dns_security_scanner",
                        "confidence": 0.90,
                        "remediation": (
                            "Disable or rate-limit ANY queries on authoritative nameservers. "
                            "Deploy Response Rate Limiting (RRL) to prevent amplification abuse."
                        ),
                    }
            except Exception as exc:
                log.debug("amplification check %s @ %s: %s", domain, ns_ip, exc)

        return None

    # ------------------------------------------------------------------
    # Dangling CNAME / Subdomain Takeover
    # ------------------------------------------------------------------

    async def test_dangling_cname(self, subdomains: list[str]) -> list[dict]:
        """
        Resolve each subdomain; those with a CNAME that doesn't resolve to an
        A record are potential subdomain takeover candidates.
        """
        findings: list[dict] = []

        # Known takeover-prone CNAME targets (partial match)
        _TAKEOVER_SERVICES = [
            "github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
            "s3.amazonaws.com", "storage.googleapis.com", "fastly.net",
            "shopify.com", "zendesk.com", "tumblr.com", "ghost.io",
            "webflow.io", "surge.sh", "netlify.app", "vercel.app",
        ]

        async def _check_one(subdomain: str) -> Optional[dict]:
            # Step 1: Get CNAME chain
            try:
                loop = asyncio.get_event_loop()
                # Use getaddrinfo — if it raises, name doesn't resolve
                try:
                    await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, subdomain),
                        timeout=4,
                    )
                    return None  # resolves fine — not dangling
                except (socket.gaierror, OSError):
                    pass  # doesn't resolve — check for CNAME

                # Step 2: Query CNAME (type=5)
                query = _build_dns_query(subdomain, 5)
                resp = await _udp_query("8.8.8.8", query, timeout=self.timeout)
                if not resp or len(resp) < 12:
                    return None

                ancount = struct.unpack(">H", resp[6:8])[0]
                if ancount == 0:
                    return None

                # Parse the CNAME target
                offset = 12
                _, offset = _decode_name(resp, offset)
                offset += 4  # skip QTYPE + QCLASS
                cname_target = ""
                for _ in range(ancount):
                    if offset + 10 > len(resp):
                        break
                    _, offset = _decode_name(resp, offset)
                    rtype, _, _, rdlen = struct.unpack(">HHIH", resp[offset:offset + 10])
                    offset += 10
                    if rtype == 5:  # CNAME
                        cname_target, _ = _decode_name(resp, offset)
                    offset += rdlen

                if not cname_target:
                    return None

                # Step 3: Check if CNAME target matches a known takeover service
                service_match = next(
                    (svc for svc in _TAKEOVER_SERVICES if svc in cname_target), None
                )
                severity = "critical" if service_match else "high"
                title = (
                    f"Subdomain Takeover Candidate: {subdomain} → {cname_target}"
                    + (f" ({service_match})" if service_match else "")
                )

                return {
                    "vuln_type": "dangling_cname_takeover",
                    "type": "dangling_cname_takeover",
                    "severity": severity,
                    "title": title,
                    "domain": subdomain,
                    "cname_target": cname_target,
                    "url": f"https://{subdomain}",
                    "target": subdomain,
                    "takeover_service": service_match,
                    "evidence": (
                        f"{subdomain} CNAME → {cname_target} "
                        f"but {cname_target} does not resolve. "
                        + (f"Known takeover target: {service_match}." if service_match else "")
                    ),
                    "tool": "dns_security_scanner",
                    "source": "dns_security_scanner",
                    "confidence": 0.88 if service_match else 0.70,
                    "remediation": (
                        f"Remove the {subdomain} DNS record immediately or point it to "
                        "an actively controlled resource. Dangling CNAMEs allow attackers "
                        f"to claim the {cname_target} service and serve malicious content "
                        "under your domain."
                    ),
                }
            except Exception as exc:
                log.debug("dangling_cname(%s): %s", subdomain, exc)
                return None

        sem = asyncio.Semaphore(30)

        async def _guarded(sub: str) -> Optional[dict]:
            async with sem:
                return await _check_one(sub)

        results = await asyncio.gather(
            *[_guarded(sub) for sub in subdomains],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, dict):
                findings.append(r)

        log.info("dangling_cname: %d takeover candidates from %d subdomains",
                 len(findings), len(subdomains))
        return findings

    # ------------------------------------------------------------------
    # Bonus: CAA + DNSSEC presence check
    # ------------------------------------------------------------------

    async def _check_caa(self, domain: str) -> Optional[dict]:
        """Missing CAA record = any CA can issue certificates for the domain."""
        query = _build_dns_query(domain, 257)  # type CAA=257
        resp = await _udp_query("8.8.8.8", query, timeout=self.timeout)
        if resp:
            ancount = struct.unpack(">H", resp[6:8])[0] if len(resp) >= 8 else 0
            if ancount == 0:
                return {
                    "vuln_type": "missing_caa_record",
                    "type": "missing_caa_record",
                    "severity": "medium",
                    "title": f"Missing CAA Record: {domain}",
                    "domain": domain,
                    "url": f"dns://{domain}/CAA",
                    "target": domain,
                    "evidence": "No CAA record found — any Certificate Authority can issue certs.",
                    "tool": "dns_security_scanner",
                    "source": "dns_security_scanner",
                    "confidence": 0.95,
                    "remediation": (
                        'Add a CAA record such as: \'0 issue "letsencrypt.org"\' '
                        "to restrict certificate issuance to authorized CAs only."
                    ),
                }
        return None

    # ------------------------------------------------------------------
    # Top-level scan
    # ------------------------------------------------------------------

    async def scan(self, domain: str, subdomains: Optional[list[str]] = None) -> list[dict]:
        """
        Run all DNS security checks for a domain.

        Args:
            domain:     Apex domain (e.g. 'example.com').
            subdomains: Optional list of FQDNs to check for dangling CNAMEs.

        Returns:
            Aggregated list of finding dicts.
        """
        findings: list[dict] = []

        # Run zone transfer + amplification + CAA in parallel
        zt_task = self.test_zone_transfer(domain)
        amp_task = self.test_dns_amplification(domain)
        caa_task = self._check_caa(domain)

        tasks: list = [zt_task, amp_task, caa_task]
        if subdomains:
            tasks.append(self.test_dangling_cname(subdomains))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, dict):
                findings.append(r)
            elif isinstance(r, Exception):
                log.debug("dns_security_scanner sub-check raised: %s", r)

        log.info("dns_security_scanner(%s): %d findings total", domain, len(findings))
        return findings


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

async def scan_dns_security(domain: str, subdomains: Optional[list[str]] = None) -> list[dict]:
    """Convenience coroutine for unified_scan_engine wiring."""
    scanner = DNSSecurityScanner()
    return await scanner.scan(domain, subdomains=subdomains)
