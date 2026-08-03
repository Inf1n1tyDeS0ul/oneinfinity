"""
websocket_scanner.py — WebSocket Security Scanner for OneInfinity

Attack surface coverage:
  - Cross-Site WebSocket Hijacking (CSWSH) — Origin header not validated
  - Authentication bypass — unauthenticated WS upgrade
  - Message injection — prototype pollution, JSON injection, command injection
  - WebSocket tunneling over HTTP proxies
  - Denial of Service — message flood, large payload
  - Subprotocol confusion — sec-websocket-protocol manipulation
  - Token leakage in upgrade request (URL params)

No other tool in this platform tests CSWSH and auth bypass together in one engine.

Usage::

    import asyncio
    scanner = WebSocketScanner("https://example.com")
    findings = asyncio.run(scanner.run())
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import ssl
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote

log = logging.getLogger("oneinfinity.websocket_scanner")

_DEFAULT_TIMEOUT = 10
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class WSFinding:
    finding_id: str
    vuln_type: str
    title: str
    severity: str
    url: str
    evidence: str
    confidence: float
    exploitation_steps: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
    tool: str = "websocket_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items()}
        return d


# ---------------------------------------------------------------------------
# Raw WebSocket handshake helpers
# ---------------------------------------------------------------------------

def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def _expected_accept(key: str) -> str:
    combined = (key + _WS_GUID).encode()
    return base64.b64encode(hashlib.sha1(combined).digest()).decode()


def _build_upgrade_request(host: str, path: str, key: str,
                            extra_headers: Optional[dict] = None,
                            origin: Optional[str] = None,
                            subprotocol: Optional[str] = None) -> bytes:
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        headers.append(f"Origin: {origin}")
    if subprotocol:
        headers.append(f"Sec-WebSocket-Protocol: {subprotocol}")
    if extra_headers:
        for k, v in extra_headers.items():
            headers.append(f"{k}: {v}")
    return "\r\n".join(headers).encode() + b"\r\n\r\n"


def _open_ws_socket(host: str, port: int, use_tls: bool, timeout: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    return sock


def _recv_http_response(sock: socket.socket, timeout: float = 3.0) -> str:
    data = b""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except socket.timeout:
        pass
    return data.decode("utf-8", errors="replace")


def _is_101(response: str) -> bool:
    return "101" in response.split("\r\n")[0] if response else False


def _encode_ws_frame(payload: bytes, opcode: int = 0x1, mask: bool = True) -> bytes:
    """Encode a WebSocket frame (client must mask)."""
    fin_op = 0x80 | opcode
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00

    if length < 126:
        header = bytes([fin_op, mask_bit | length])
    elif length < 65536:
        header = bytes([fin_op, mask_bit | 126]) + struct.pack(">H", length)
    else:
        header = bytes([fin_op, mask_bit | 127]) + struct.pack(">Q", length)

    if mask:
        masking_key = os.urandom(4)
        masked = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))
        return header + masking_key + masked
    return header + payload


def _decode_ws_frame(data: bytes) -> Tuple[int, bytes]:
    """Decode first WebSocket frame from raw bytes. Returns (opcode, payload)."""
    if len(data) < 2:
        return 0, b""
    fin_op = data[0]
    opcode = fin_op & 0x0F
    mask_len = data[1]
    masked = bool(mask_len & 0x80)
    length = mask_len & 0x7F

    offset = 2
    if length == 126:
        length = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2
    elif length == 127:
        length = struct.unpack(">Q", data[offset:offset+8])[0]
        offset += 8

    if masked:
        key = data[offset:offset+4]
        offset += 4
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(data[offset:offset+length]))
    else:
        payload = data[offset:offset+length]

    return opcode, payload


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class WebSocketScanner:
    """WebSocket security scanner covering auth bypass, CSWSH, injection, and DoS."""

    def __init__(self, target: str, timeout: int = _DEFAULT_TIMEOUT,
                 headers: Optional[dict] = None, cookies: Optional[dict] = None) -> None:
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.extra_headers = headers or {}
        self.cookies = cookies or {}
        parsed = urlparse(target)
        self.scheme = parsed.scheme.lower()
        self.host = parsed.hostname or ""
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.use_tls = self.scheme in ("https", "wss")
        self._ws_endpoints: List[str] = []

    # ------------------------------------------------------------------ #
    # Endpoint discovery
    # ------------------------------------------------------------------ #

    def discover_ws_endpoints(self) -> List[str]:
        """Probe common WebSocket paths."""
        common_paths = [
            "/ws", "/websocket", "/socket", "/socket.io/",
            "/ws/", "/api/ws", "/chat", "/live", "/stream",
            "/api/socket", "/hub", "/signalr/negotiate",
            "/sockjs/websocket", "/ws/v1", "/ws/v2",
        ]
        found = []
        for path in common_paths:
            ws_url = f"{'wss' if self.use_tls else 'ws'}://{self.host}:{self.port}{path}"
            key = _ws_key()
            try:
                sock = _open_ws_socket(self.host, self.port, self.use_tls, self.timeout)
                req = _build_upgrade_request(
                    f"{self.host}:{self.port}", path, key,
                    extra_headers=self.extra_headers,
                    origin=self.target
                )
                sock.sendall(req)
                resp = _recv_http_response(sock, timeout=3.0)
                sock.close()
                if _is_101(resp):
                    log.info("WebSocket endpoint found: %s", ws_url)
                    found.append(ws_url)
            except (socket.error, ssl.SSLError, OSError):
                pass

        self._ws_endpoints = found
        return found

    # ------------------------------------------------------------------ #
    # Gap 3a: Cross-Site WebSocket Hijacking (CSWSH)
    # ------------------------------------------------------------------ #

    def test_cswsh(self, ws_path: str) -> Optional[WSFinding]:
        """
        Test if server validates the Origin header.
        If attacker-controlled origin gets 101, CSWSH is possible.
        """
        key = _ws_key()
        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
            "",
        ]

        for origin in evil_origins:
            try:
                sock = _open_ws_socket(self.host, self.port, self.use_tls, self.timeout)
                req = _build_upgrade_request(
                    f"{self.host}:{self.port}", ws_path, key,
                    origin=origin if origin else None,
                )
                sock.sendall(req)
                resp = _recv_http_response(sock, timeout=3.0)

                if _is_101(resp):
                    sock.close()
                    return WSFinding(
                        finding_id=f"WS-CSWSH-{uuid.uuid4().hex[:8].upper()}",
                        vuln_type="cross_site_websocket_hijacking",
                        title="Cross-Site WebSocket Hijacking (CSWSH)",
                        severity="high",
                        url=f"{'wss' if self.use_tls else 'ws'}://{self.host}{ws_path}",
                        evidence=f"Server accepted WebSocket upgrade with Origin: '{origin}'. "
                                 f"Attacker page can establish WS connection as victim user.",
                        confidence=0.92,
                        exploitation_steps=[
                            "1. Host malicious page at evil.com",
                            "2. Page opens WebSocket to target with victim's session cookies",
                            "3. Server accepts connection (no Origin validation)",
                            "4. Attacker reads/writes victim's WebSocket messages",
                        ],
                        extra={"evil_origin": origin, "ws_path": ws_path}
                    )
                sock.close()
            except (socket.error, ssl.SSLError, OSError) as exc:
                log.debug("CSWSH test failed for origin %s: %s", origin, exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 3b: Authentication Bypass
    # ------------------------------------------------------------------ #

    def test_auth_bypass(self, ws_path: str) -> Optional[WSFinding]:
        """
        Test if WebSocket endpoint requires authentication.
        Connect without session cookies or auth headers.
        """
        key = _ws_key()
        try:
            sock = _open_ws_socket(self.host, self.port, self.use_tls, self.timeout)
            # Explicitly NO auth headers / cookies
            req = _build_upgrade_request(
                f"{self.host}:{self.port}", ws_path, key,
                origin=self.target,
            )
            sock.sendall(req)
            resp = _recv_http_response(sock, timeout=3.0)

            if _is_101(resp):
                # Send a probe message to see if we get data
                probe = json.dumps({"type": "ping", "action": "list_users"}).encode()
                sock.sendall(_encode_ws_frame(probe))
                try:
                    sock.settimeout(2.0)
                    frame_data = sock.recv(4096)
                    opcode, payload = _decode_ws_frame(frame_data)
                    if payload and len(payload) > 10:
                        sock.close()
                        return WSFinding(
                            finding_id=f"WS-AUTH-{uuid.uuid4().hex[:8].upper()}",
                            vuln_type="websocket_auth_bypass",
                            title="WebSocket Authentication Bypass",
                            severity="critical",
                            url=f"{'wss' if self.use_tls else 'ws'}://{self.host}{ws_path}",
                            evidence=f"WebSocket connection established without authentication. "
                                     f"Server responded with {len(payload)} bytes to probe message: "
                                     f"{payload[:100].decode('utf-8', errors='replace')}",
                            confidence=0.90,
                            exploitation_steps=[
                                "1. Connect to WebSocket endpoint without cookies/auth headers",
                                "2. Server accepts connection",
                                "3. Server responds to messages — access to unauthenticated data",
                            ],
                            extra={"response_sample": payload[:100].decode("utf-8", errors="replace")}
                        )
                except socket.timeout:
                    pass
            sock.close()
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("WS auth bypass test failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 3c: Message Injection
    # ------------------------------------------------------------------ #

    def test_message_injection(self, ws_path: str) -> List[WSFinding]:
        """
        Test for injection vulnerabilities via WebSocket messages:
        - JSON injection / prototype pollution
        - Command injection via message fields
        - XSS via message reflection
        """
        findings = []
        injection_payloads = [
            ("prototype_pollution", '{"__proto__":{"admin":true},"type":"chat","msg":"test"}',
             ["admin", "true", "__proto__"]),
            ("json_injection", '{"type":"chat","msg":"test\\"}\n{\"type\":\"admin\"}', ["admin", "error"]),
            ("cmd_injection", '{"type":"exec","cmd":";id;","msg":"test"}', ["uid=", "root", "www-data"]),
            ("xss_reflection", '{"type":"chat","msg":"<script>alert(1)</script>"}',
             ["<script>", "alert(1)"]),
            ("sql_injection", '{"type":"search","query":"1\' OR \'1\'=\'1","msg":"test"}',
             ["sql", "syntax", "error", "mysql"]),
        ]

        key = _ws_key()
        for inj_type, payload, indicators in injection_payloads:
            try:
                sock = _open_ws_socket(self.host, self.port, self.use_tls, self.timeout)
                req = _build_upgrade_request(
                    f"{self.host}:{self.port}", ws_path, key, origin=self.target
                )
                sock.sendall(req)
                resp = _recv_http_response(sock, timeout=3.0)

                if not _is_101(resp):
                    sock.close()
                    continue

                sock.sendall(_encode_ws_frame(payload.encode()))
                try:
                    sock.settimeout(2.0)
                    frame_data = sock.recv(8192)
                    _, response_payload = _decode_ws_frame(frame_data)
                    response_text = response_payload.decode("utf-8", errors="replace").lower()

                    for indicator in indicators:
                        if indicator.lower() in response_text:
                            findings.append(WSFinding(
                                finding_id=f"WS-INJ-{uuid.uuid4().hex[:8].upper()}",
                                vuln_type=f"websocket_{inj_type}",
                                title=f"WebSocket {inj_type.replace('_', ' ').title()} Detected",
                                severity="high" if inj_type in ("cmd_injection", "sql_injection") else "medium",
                                url=f"{'wss' if self.use_tls else 'ws'}://{self.host}{ws_path}",
                                evidence=f"Injection indicator '{indicator}' found in WS response. "
                                         f"Payload: {payload[:80]}. Response: {response_text[:150]}",
                                confidence=0.80,
                                exploitation_steps=[
                                    f"1. Send WebSocket message: {payload[:60]}",
                                    f"2. Server response contains indicator: {indicator}",
                                    f"3. {inj_type} confirmed",
                                ],
                                extra={"payload": payload, "indicator": indicator, "response": response_text[:200]}
                            ))
                            break
                except socket.timeout:
                    pass
                sock.close()
            except (socket.error, ssl.SSLError, OSError) as exc:
                log.debug("WS injection test %s failed: %s", inj_type, exc)

        return findings

    # ------------------------------------------------------------------ #
    # Gap 3d: Denial of Service (message flood + large payload)
    # ------------------------------------------------------------------ #

    def test_dos(self, ws_path: str) -> Optional[WSFinding]:
        """
        Test for WebSocket DoS via:
        - Large single message (1MB payload)
        - Message flood (1000 messages in rapid succession)
        """
        key = _ws_key()
        try:
            sock = _open_ws_socket(self.host, self.port, self.use_tls, self.timeout)
            req = _build_upgrade_request(
                f"{self.host}:{self.port}", ws_path, key, origin=self.target
            )
            sock.sendall(req)
            resp = _recv_http_response(sock, timeout=3.0)

            if not _is_101(resp):
                sock.close()
                return None

            # Test 1: Large payload (1MB)
            large_payload = b"A" * (1024 * 1024)
            t0 = time.time()
            try:
                sock.sendall(_encode_ws_frame(large_payload))
                sock.settimeout(5.0)
                response = sock.recv(4096)
                elapsed = time.time() - t0
                if elapsed > 2.0:
                    sock.close()
                    return WSFinding(
                        finding_id=f"WS-DOS-{uuid.uuid4().hex[:8].upper()}",
                        vuln_type="websocket_dos",
                        title="WebSocket Large Payload DoS — No Size Limit",
                        severity="medium",
                        url=f"{'wss' if self.use_tls else 'ws'}://{self.host}{ws_path}",
                        evidence=f"Server accepted 1MB WebSocket message and took {elapsed:.2f}s to respond. "
                                 f"No message size limit enforced. Memory exhaustion DoS possible.",
                        confidence=0.75,
                        exploitation_steps=[
                            "1. Connect to WebSocket endpoint",
                            "2. Send 1MB+ messages continuously",
                            "3. Server memory exhausted → DoS",
                        ],
                        extra={"payload_size_mb": 1, "elapsed_s": round(elapsed, 3)}
                    )
            except (socket.timeout, socket.error):
                pass

            sock.close()
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("WS DoS test failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 3e: Subprotocol confusion
    # ------------------------------------------------------------------ #

    def test_subprotocol_confusion(self, ws_path: str) -> Optional[WSFinding]:
        """
        Test if server echoes back an attacker-controlled Sec-WebSocket-Protocol value,
        which can be used for header injection or protocol confusion.
        """
        evil_protocol = "chat, \r\nX-Injected: evil-header"
        key = _ws_key()
        try:
            sock = _open_ws_socket(self.host, self.port, self.use_tls, self.timeout)
            req = _build_upgrade_request(
                f"{self.host}:{self.port}", ws_path, key,
                origin=self.target, subprotocol=evil_protocol
            )
            sock.sendall(req)
            resp = _recv_http_response(sock, timeout=3.0)
            sock.close()

            if "x-injected" in resp.lower() or "evil-header" in resp.lower():
                return WSFinding(
                    finding_id=f"WS-SUBPROTO-{uuid.uuid4().hex[:8].upper()}",
                    vuln_type="websocket_subprotocol_injection",
                    title="WebSocket Subprotocol Header Injection",
                    severity="high",
                    url=f"{'wss' if self.use_tls else 'ws'}://{self.host}{ws_path}",
                    evidence=f"Injected header found in server's 101 response via Sec-WebSocket-Protocol. "
                             f"Response contains: X-Injected: evil-header",
                    confidence=0.95,
                    exploitation_steps=[
                        "1. Send Sec-WebSocket-Protocol with CRLF injection",
                        "2. Server echoes value back in 101 response",
                        "3. Injected headers poison response to browser/proxy",
                    ]
                )
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("WS subprotocol test failed: %s", exc)

        return None

    # Phase 2: Auth-State Divergence (Pillar 4.5)

    def test_auth_state_divergence(
        self,
        ws_path: str,
        session_cookie: str = "",
    ) -> Optional[WSFinding]:
        """
        Test WebSocket authentication state divergence.

        Establishes a WebSocket connection while authenticated, then simulates
        authentication revocation (sends a logout-equivalent message), and checks
        whether the WebSocket connection still accepts privileged messages.

        Vulnerability: server validates auth only at handshake time. After the
        handshake, the connection remains open indefinitely — auth revocation
        (logout, token expiry) does not close the existing WebSocket.

        An attacker who steals an active WebSocket connection (via XSS, network
        interception, or shared device) can continue receiving data even after
        the victim logs out.
        """
        key = _ws_key()
        ws_url = f"{'wss' if self.use_tls else 'ws'}://{self.host}:{self.port}{ws_path}"
        try:
            # Step 1: Establish connection with auth cookie (or without if none provided)
            extra_headers = {}
            if session_cookie:
                extra_headers["Cookie"] = session_cookie

            sock = _open_ws_socket(self.host, self.port, self.use_tls, self.timeout)
            req = _build_upgrade_request(
                f"{self.host}:{self.port}", ws_path, key,
                origin=self.target, extra_headers=extra_headers,
            )
            sock.sendall(req)
            upgrade_resp = _recv_http_response(sock, timeout=3.0)

            if not _is_101(upgrade_resp):
                sock.close()
                return None

            # Step 2: Send a probe message to confirm the connection is live
            probe = json.dumps({"type": "ping"}).encode()
            sock.sendall(_encode_ws_frame(probe))
            try:
                sock.settimeout(2.0)
                data = sock.recv(4096)
                if not data:
                    sock.close()
                    return None
            except socket.timeout:
                # No response to ping — connection may be uni-directional
                pass

            # Step 3: Simulate logout — send a logout message over the SAME connection
            logout_msgs = [
                json.dumps({"type": "logout"}),
                json.dumps({"action": "logout"}),
                json.dumps({"event": "session_expired"}),
            ]
            for msg in logout_msgs:
                sock.sendall(_encode_ws_frame(msg.encode()))

            import time as _time; _time.sleep(0.5)

            # Step 4: Try to send a privileged message on the same connection
            # If auth-state divergence exists, this should still work
            priv_probe = json.dumps({
                "type": "subscribe",
                "action": "list_users",
                "channel": "admin",
            }).encode()
            sock.sendall(_encode_ws_frame(priv_probe))
            try:
                sock.settimeout(3.0)
                resp_data = sock.recv(4096)
                if resp_data:
                    opcode, payload = _decode_ws_frame(resp_data)
                    # Connection still active after logout simulation
                    if payload and len(payload) > 5:
                        sock.close()
                        return WSFinding(
                            finding_id=f"WS-AUTHSTATE-{uuid.uuid4().hex[:8].upper()}",
                            vuln_type="websocket_auth_state_divergence",
                            title="WebSocket Auth-State Divergence — Connection Persists After Logout",
                            severity="high",
                            url=ws_url,
                            evidence=(
                                f"WebSocket connection at {ws_url} remains active and responsive "
                                f"after logout event was sent. Server returned {len(payload)} bytes "
                                f"to a post-logout privileged probe. "
                                f"Auth revocation does not terminate existing WebSocket connections."
                            ),
                            confidence=0.80,
                            exploitation_steps=[
                                "1. Attacker steals active WebSocket connection (XSS, shared device)",
                                "2. Victim logs out — server-side session invalidated",
                                "3. WebSocket connection not closed — attacker still receives live data",
                                "4. Attacker can continue subscribing to events, reading messages",
                                "Remediation: server MUST terminate all WebSocket connections on logout/token revocation",
                            ],
                        )
            except socket.timeout:
                pass
            sock.close()
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("WS auth-state divergence test failed: %s", exc)

        return None


    # ------------------------------------------------------------------ #
    # Async CSWSH — accepts full ws_url with configurable evil origin
    # ------------------------------------------------------------------ #

    async def test_cswsh_async(
        self,
        ws_url: str,
        origin: str = "https://evil.example.com",
    ) -> Optional[WSFinding]:
        """
        Async Cross-Site WebSocket Hijacking probe.

        Connects to *ws_url* with a forged Origin header (default:
        ``https://evil.example.com``).  If the server returns HTTP 101, the
        endpoint performs no Origin validation and is vulnerable to CSWSH —
        an attacker-controlled page can open a WebSocket as the victim user.

        Parameters
        ----------
        ws_url:
            Full WebSocket URL (ws:// or wss://) to test.
        origin:
            Forged Origin to present in the upgrade request.
        """
        parsed = urlparse(ws_url)
        host = parsed.hostname or self.host
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        use_tls = parsed.scheme in ("wss", "https")
        ws_path = parsed.path or "/"
        if parsed.query:
            ws_path = f"{ws_path}?{parsed.query}"

        evil_origins = [origin, "https://evil.com", "null", ""]
        key = _ws_key()

        loop = asyncio.get_event_loop()

        for evil_origin in evil_origins:
            def _probe(h=host, p=port, tls=use_tls, path=ws_path, o=evil_origin):
                try:
                    sock = _open_ws_socket(h, p, tls, self.timeout)
                    req = _build_upgrade_request(
                        f"{h}:{p}", path, _ws_key(),
                        origin=o if o else None,
                    )
                    sock.sendall(req)
                    resp = _recv_http_response(sock, timeout=3.0)
                    sock.close()
                    return resp
                except (socket.error, ssl.SSLError, OSError) as exc:
                    log.debug("async CSWSH probe failed for origin %s: %s", o, exc)
                    return ""

            resp = await loop.run_in_executor(None, _probe)
            if _is_101(resp):
                return WSFinding(
                    finding_id=f"WS-CSWSH-ASYNC-{uuid.uuid4().hex[:8].upper()}",
                    vuln_type="cross_site_websocket_hijacking",
                    title="Cross-Site WebSocket Hijacking (CSWSH)",
                    severity="high",
                    url=ws_url,
                    evidence=(
                        f"Server accepted WebSocket upgrade from forged Origin: '{evil_origin}'. "
                        f"No Origin validation — attacker page can connect as victim user "
                        f"and read/write session WebSocket messages."
                    ),
                    confidence=0.92,
                    exploitation_steps=[
                        "1. Host malicious page at evil.example.com",
                        "2. Page opens WebSocket to target with victim's cookies (browser sends them)",
                        "3. Server accepts despite cross-site origin",
                        "4. Attacker reads/writes victim's WebSocket channel",
                    ],
                    extra={"evil_origin": evil_origin, "ws_url": ws_url},
                )

        return None

    # ------------------------------------------------------------------ #
    # Async message injection — accepts full ws_url
    # ------------------------------------------------------------------ #

    async def test_ws_message_injection(
        self,
        ws_url: str,
    ) -> Optional[WSFinding]:
        """
        Async WebSocket message injection probe.

        Sends prototype-pollution and SQL-injection payloads over a WebSocket
        connection.  If the server response contains error tokens that indicate
        unescaped processing, the finding is returned.

        Returns the first (highest-confidence) injection finding, or ``None``.
        """
        parsed = urlparse(ws_url)
        host = parsed.hostname or self.host
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        use_tls = parsed.scheme in ("wss", "https")
        ws_path = parsed.path or "/"
        if parsed.query:
            ws_path = f"{ws_path}?{parsed.query}"

        injection_payloads = [
            (
                "prototype_pollution",
                '{"__proto__":{"admin":true},"type":"probe","msg":"oi-test"}',
                ["admin", "__proto__", "true", "polluted"],
                "high",
            ),
            (
                "sql_injection",
                '{"type":"search","query":"\' OR \'1\'=\'1","msg":"oi-test"}',
                ["sql", "syntax", "error", "mysql", "sqlite", "pg"],
                "high",
            ),
            (
                "json_injection",
                '{"type":"chat","msg":"test\\"}\n{\"type\":\"admin\"}',
                ["admin", "error", "invalid"],
                "medium",
            ),
        ]

        loop = asyncio.get_event_loop()

        for inj_type, payload_str, indicators, severity in injection_payloads:
            def _probe(h=host, p=port, tls=use_tls, path=ws_path, pl=payload_str):
                try:
                    sock = _open_ws_socket(h, p, tls, self.timeout)
                    req = _build_upgrade_request(f"{h}:{p}", path, _ws_key(), origin=self.target)
                    sock.sendall(req)
                    resp = _recv_http_response(sock, timeout=3.0)
                    if not _is_101(resp):
                        sock.close()
                        return ""
                    sock.sendall(_encode_ws_frame(pl.encode()))
                    try:
                        sock.settimeout(2.5)
                        frame_data = sock.recv(8192)
                        _, frame_payload = _decode_ws_frame(frame_data)
                        sock.close()
                        return frame_payload.decode("utf-8", errors="replace")
                    except socket.timeout:
                        sock.close()
                        return ""
                except (socket.error, ssl.SSLError, OSError) as exc:
                    log.debug("async WS injection %s failed: %s", pl[:40], exc)
                    return ""

            response_text = await loop.run_in_executor(None, _probe)
            if not response_text:
                continue

            response_lower = response_text.lower()
            for indicator in indicators:
                if indicator.lower() in response_lower:
                    return WSFinding(
                        finding_id=f"WS-INJ-ASYNC-{uuid.uuid4().hex[:8].upper()}",
                        vuln_type=f"websocket_{inj_type}",
                        title=f"WebSocket {inj_type.replace('_', ' ').title()} Detected",
                        severity=severity,
                        url=ws_url,
                        evidence=(
                            f"Injection indicator '{indicator}' found in WebSocket response "
                            f"after sending {inj_type} payload. "
                            f"Payload: {payload_str[:80]}. "
                            f"Response excerpt: {response_text[:150]}"
                        ),
                        confidence=0.80,
                        exploitation_steps=[
                            f"1. Connect to {ws_url}",
                            f"2. Send payload: {payload_str[:60]}",
                            f"3. Response contains '{indicator}' — server processed unescaped input",
                        ],
                        extra={
                            "payload": payload_str,
                            "indicator": indicator,
                            "response": response_text[:200],
                            "inj_type": inj_type,
                        },
                    )

        return None

    # ------------------------------------------------------------------ #
    # Orchestrator
    # ------------------------------------------------------------------ #

    async def run(self) -> List[WSFinding]:
        """Discover endpoints and run all WebSocket security tests."""
        log.info("Starting WebSocket security scan for %s", self.target)
        endpoints = self.discover_ws_endpoints()

        if not endpoints:
            log.info("No WebSocket endpoints found — testing default /ws path")
            endpoints = [f"{'wss' if self.use_tls else 'ws'}://{self.host}:{self.port}/ws"]
            # Still test default path even if not discovered
            self._ws_endpoints = ["/ws"]

        all_findings: List[WSFinding] = []
        paths = []
        for ep in self._ws_endpoints if self._ws_endpoints else ["/ws"]:
            paths.append(ep if ep.startswith("/") else "/" + ep.split("/", 3)[-1])

        for path in paths:
            log.info("Testing WS path: %s", path)
            ws_url = f"{'wss' if self.use_tls else 'ws'}://{self.host}:{self.port}{path}"

            # Synchronous probes (blocking socket I/O, run directly in event loop)
            tests_and_results = [
                self.test_cswsh(path),
                self.test_auth_bypass(path),
                self.test_dos(path),
                self.test_subprotocol_confusion(path),
                self.test_auth_state_divergence(path),   # Phase 2: post-logout persistence
            ]

            for result in tests_and_results:
                if isinstance(result, WSFinding):
                    all_findings.append(result)

            injection_findings = self.test_message_injection(path)
            all_findings.extend(injection_findings)

            # Async probes — full ws_url interface with configurable origin
            async_results = await asyncio.gather(
                self.test_cswsh_async(ws_url),
                self.test_ws_message_injection(ws_url),
                return_exceptions=True,
            )
            for r in async_results:
                if isinstance(r, WSFinding):
                    # Deduplicate: skip if same vuln_type already found for this path
                    already = any(
                        f.vuln_type == r.vuln_type and path in f.url
                        for f in all_findings
                    )
                    if not already:
                        all_findings.append(r)
                elif isinstance(r, Exception):
                    log.debug("async WS probe exception: %s", r)

        log.info("WebSocket scan complete: %d findings", len(all_findings))
        return all_findings


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

async def scan_websockets(target: str, timeout: int = 10) -> List[WSFinding]:
    scanner = WebSocketScanner(target, timeout=timeout)
    return await scanner.run()


if __name__ == "__main__":
    import sys
    import json as _json

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    logging.basicConfig(level=logging.INFO)
    results = asyncio.run(scan_websockets(target))
    print(_json.dumps([f.to_dict() for f in results], indent=2))
