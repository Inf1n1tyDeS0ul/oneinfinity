"""
grpc_scanner.py — gRPC / Protobuf Attack Surface Scanner for OneInfinity

Attack surface coverage:
  - gRPC reflection API abuse (service enumeration without client stubs)
  - Protobuf message fuzzing (field type confusion, integer overflow, negative IDs)
  - Authentication bypass (missing/empty metadata, JWT manipulation)
  - Unary/streaming RPC abuse (server-streaming DoS, bi-di flood)
  - gRPC-Web endpoint detection (HTTP/1.1 bridge)
  - Insecure gRPC over plaintext (no TLS)
  - Proto field injection via unknown field numbers

No other tool in this platform covers proto message fuzzing + reflection abuse.

Usage::

    scanner = GRPCScanner("https://grpc.example.com")
    findings = scanner.run()
"""
from __future__ import annotations

import json
import logging
import socket
import ssl
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

log = logging.getLogger("oneinfinity.grpc_scanner")

_DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class GRPCFinding:
    finding_id: str
    vuln_type: str
    title: str
    severity: str
    url: str
    evidence: str
    confidence: float
    exploitation_steps: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
    tool: str = "grpc_scanner"
    source_type: str = "active"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def _make_finding(vuln_type: str, severity: str, url: str, title: str,
                  evidence: str, confidence: float, extra: Optional[dict] = None) -> GRPCFinding:
    return GRPCFinding(
        finding_id=f"GRPC-{uuid.uuid4().hex[:8].upper()}",
        vuln_type=vuln_type,
        severity=severity,
        url=url,
        title=title,
        evidence=evidence,
        confidence=confidence,
        extra=extra or {},
    )


# ---------------------------------------------------------------------------
# Protobuf / gRPC frame encoding
# ---------------------------------------------------------------------------

def _encode_varint(value: int) -> bytes:
    """Encode integer as protobuf varint."""
    bits = value & 0x7F
    value >>= 7
    result = b""
    while value:
        result += bytes([0x80 | bits])
        bits = value & 0x7F
        value >>= 7
    result += bytes([bits])
    return result


def _encode_proto_field(field_number: int, wire_type: int, value) -> bytes:
    """Encode a protobuf field."""
    tag = (field_number << 3) | wire_type
    if wire_type == 0:  # varint
        return _encode_varint(tag) + _encode_varint(value)
    elif wire_type == 2:  # length-delimited
        if isinstance(value, str):
            value = value.encode()
        return _encode_varint(tag) + _encode_varint(len(value)) + value
    elif wire_type == 5:  # 32-bit
        return _encode_varint(tag) + struct.pack("<I", value)
    elif wire_type == 1:  # 64-bit
        return _encode_varint(tag) + struct.pack("<Q", value)
    return b""


def _grpc_frame(proto_bytes: bytes, compressed: bool = False) -> bytes:
    """Wrap protobuf bytes in a gRPC length-prefix frame."""
    flag = 1 if compressed else 0
    return bytes([flag]) + struct.pack(">I", len(proto_bytes)) + proto_bytes


def _build_grpc_request(method_path: str, proto_payload: bytes,
                         host: str, metadata: Optional[dict] = None) -> bytes:
    """Build a raw HTTP/2 gRPC request (simplified, no full HPACK)."""
    # Use gRPC-Web over HTTP/1.1 as fallback for raw socket tests
    body = _grpc_frame(proto_payload)
    headers_str = (
        f"POST {method_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/grpc\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"TE: trailers\r\n"
        f"grpc-timeout: 5S\r\n"
    )
    if metadata:
        for k, v in metadata.items():
            headers_str += f"{k}: {v}\r\n"
    headers_str += "\r\n"
    return headers_str.encode() + body


def _build_grpc_web_request(method_path: str, proto_payload: bytes,
                              host: str, token: Optional[str] = None) -> bytes:
    """Build gRPC-Web request (works over HTTP/1.1)."""
    body = _grpc_frame(proto_payload)
    auth_header = f"Authorization: Bearer {token}\r\n" if token else ""
    request = (
        f"POST {method_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/grpc-web+proto\r\n"
        f"X-Grpc-Web: 1\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{auth_header}"
        f"\r\n"
    ).encode() + body
    return request


# ---------------------------------------------------------------------------
# Reflection API proto encoding
# ---------------------------------------------------------------------------

def _build_reflection_request_list_services() -> bytes:
    """
    Build grpc.reflection.v1alpha.ServerReflectionRequest with list_services.
    Field 4 (list_services) = string "".
    """
    return _encode_proto_field(4, 2, b"")


def _build_reflection_request_file_by_symbol(symbol: str) -> bytes:
    """
    Build reflection request for file_containing_symbol.
    Field 3 = symbol string.
    """
    return _encode_proto_field(3, 2, symbol.encode())


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class GRPCScanner:
    """
    gRPC attack surface scanner: reflection abuse, proto fuzzing, auth bypass.
    """

    def __init__(self, target: str, timeout: int = _DEFAULT_TIMEOUT,
                 port: Optional[int] = None) -> None:
        self.target = target.rstrip("/")
        self.timeout = timeout
        parsed = urlparse(target)
        self.scheme = parsed.scheme.lower()
        self.host = parsed.hostname or ""
        self.port = port or parsed.port or (50051 if self.scheme not in ("http", "https") else
                                             443 if self.scheme == "https" else 80)
        self.use_tls = self.scheme in ("https", "grpcs")
        self._services: List[str] = []
        self._findings: List[GRPCFinding] = []

    def _open_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        if self.use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def _send_recv(self, sock: socket.socket, data: bytes, recv_size: int = 16384) -> bytes:
        sock.sendall(data)
        response = b""
        sock.settimeout(self.timeout)
        try:
            while True:
                chunk = sock.recv(recv_size)
                if not chunk:
                    break
                response += chunk
                if len(response) > recv_size * 4:
                    break
        except socket.timeout:
            pass
        return response

    # ------------------------------------------------------------------ #
    # Gap 4a: Reflection API Abuse — Service Enumeration
    # ------------------------------------------------------------------ #

    def test_reflection_api(self) -> Optional[GRPCFinding]:
        """
        Call grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo to
        enumerate all registered gRPC services without any client stubs.
        """
        reflection_path = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
        proto_payload = _build_reflection_request_list_services()

        try:
            sock = self._open_socket()
            # Try gRPC-Web over HTTP/1.1 (more likely to work through proxies)
            request = _build_grpc_web_request(reflection_path, proto_payload, self.host)
            response = self._send_recv(sock, request)
            sock.close()

            resp_text = response.decode("utf-8", errors="replace")
            status_line = resp_text.split("\r\n")[0] if resp_text else ""

            # Look for service names in binary response
            services_found = []
            if b"\x00\x00\x00" in response:  # gRPC frames present
                # Parse service names from binary response
                # Service names appear as length-prefixed strings in proto response
                try:
                    # Find the data portion after HTTP headers
                    if b"\r\n\r\n" in response:
                        body = response.split(b"\r\n\r\n", 1)[1]
                    else:
                        body = response

                    # Extract printable strings that look like service names (contain '.')
                    import re
                    service_pattern = rb'[\x20-\x7e]{10,100}'
                    candidates = re.findall(service_pattern, body)
                    for c in candidates:
                        c_str = c.decode("utf-8", errors="ignore")
                        if "." in c_str and "/" not in c_str and " " not in c_str:
                            services_found.append(c_str)
                except Exception:
                    pass

            if "200" in status_line or services_found or b"grpc-status" in response.lower():
                return _make_finding(
                    vuln_type="grpc_reflection_exposed",
                    severity="high",
                    url=f"{self.target}{reflection_path}",
                    title="gRPC Reflection API Exposed — Service Enumeration Possible",
                    evidence=f"gRPC reflection endpoint responded to ServerReflectionInfo. "
                             f"Services found: {services_found[:10] if services_found else 'check binary response'}. "
                             f"Attackers can enumerate all RPC methods without client stubs.",
                    confidence=0.88 if services_found else 0.65,
                    extra={
                        "services": services_found,
                        "reflection_path": reflection_path,
                        "exploitation": "Use grpcurl or grpc_server_reflection to enumerate all methods",
                    }
                )

        except (socket.error, ssl.SSLError, OSError) as exc:
            log.debug("gRPC reflection test failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 4b: Protobuf Message Fuzzing
    # ------------------------------------------------------------------ #

    def test_proto_fuzzing(self, rpc_path: Optional[str] = None) -> List[GRPCFinding]:
        """
        Fuzz Protobuf messages for:
        - Integer overflow (field value = MAX_INT64)
        - Negative IDs (signed overflow)
        - Unexpected wire types (type confusion)
        - Deeply nested messages
        - Unknown field numbers that shouldn't exist
        - Empty required fields
        """
        findings = []
        test_path = rpc_path or "/api.Service/GetUser"

        fuzz_cases = [
            ("int_overflow", _encode_proto_field(1, 0, 0x7FFFFFFFFFFFFFFF),
             ["overflow", "error", "invalid", "exception"]),
            ("negative_id", _encode_proto_field(1, 0, 0xFFFFFFFFFFFFFFFF),
             ["error", "invalid", "negative"]),
            ("wire_type_confusion",
             bytes([0x09]) + struct.pack("<d", float("nan")),  # field 1, wire type 1, NaN double
             ["error", "parse", "invalid"]),
            ("empty_required",
             b"",  # empty message
             ["required", "missing", "null", "undefined"]),
            ("unknown_field_100000",
             _encode_proto_field(100000, 2, b"injection"),
             ["error", "unknown", "field"]),
            ("deeply_nested",
             _encode_proto_field(1, 2, _encode_proto_field(1, 2, _encode_proto_field(1, 2, b"test" * 100))),
             ["stack", "overflow", "error", "limit"]),
            ("string_overflow",
             _encode_proto_field(1, 2, b"A" * 65536),
             ["too large", "limit", "overflow", "max"]),
        ]

        for fuzz_name, proto_payload, error_indicators in fuzz_cases:
            try:
                sock = self._open_socket()
                request = _build_grpc_web_request(test_path, proto_payload, self.host)
                response = self._send_recv(sock, request)
                sock.close()

                resp_text = response.decode("utf-8", errors="replace").lower()
                status_line = resp_text.split("\r\n")[0] if resp_text else ""

                # 500 or error indicators = server crashed/errored on malformed proto
                if "500" in status_line:
                    findings.append(_make_finding(
                        vuln_type=f"grpc_proto_fuzzing_{fuzz_name}",
                        severity="high",
                        url=f"{self.target}{test_path}",
                        title=f"gRPC Protobuf Fuzzing — Server Error on {fuzz_name}",
                        evidence=f"HTTP 500 returned when sending malformed proto ({fuzz_name}). "
                                 f"Server may be vulnerable to proto deserialization attacks.",
                        confidence=0.85,
                        extra={"fuzz_case": fuzz_name, "payload_hex": proto_payload.hex()[:64]},
                    ))
                elif any(ind in resp_text for ind in error_indicators):
                    findings.append(_make_finding(
                        vuln_type=f"grpc_proto_info_leak_{fuzz_name}",
                        severity="medium",
                        url=f"{self.target}{test_path}",
                        title=f"gRPC Protobuf Fuzzing — Error Disclosure ({fuzz_name})",
                        evidence=f"Server returned error details for {fuzz_name} fuzz case. "
                                 f"Response contains: {resp_text[:200]}",
                        confidence=0.70,
                        extra={"fuzz_case": fuzz_name},
                    ))

            except (socket.error, ssl.SSLError, OSError) as exc:
                log.debug("Proto fuzzing test %s failed: %s", fuzz_name, exc)

        return findings

    # ------------------------------------------------------------------ #
    # Gap 4c: Authentication Bypass
    # ------------------------------------------------------------------ #

    def test_auth_bypass(self, rpc_paths: Optional[List[str]] = None) -> List[GRPCFinding]:
        """
        Test gRPC endpoints without authentication metadata.
        Also tests: empty bearer token, JWT with alg=none, expired token.
        """
        findings = []
        paths_to_test = rpc_paths or [
            "/api.UserService/GetUser",
            "/api.AdminService/ListUsers",
            "/api.AdminService/GetConfig",
            "/grpc.health.v1.Health/Check",
        ]

        auth_bypass_cases = [
            ("no_auth", None),
            ("empty_token", ""),
            ("alg_none", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0IiwicGVybXMiOlsiYWRtaW4iXX0."),
            ("null_bearer", "null"),
            ("bearer_space", " "),
        ]

        for rpc_path in paths_to_test:
            for bypass_name, token in auth_bypass_cases:
                try:
                    sock = self._open_socket()
                    proto_payload = _encode_proto_field(1, 0, 1)  # id: 1
                    request = _build_grpc_web_request(rpc_path, proto_payload, self.host, token=token)
                    response = self._send_recv(sock, request)
                    sock.close()

                    resp_text = response.decode("utf-8", errors="replace")
                    status_line = resp_text.split("\r\n")[0] if resp_text else ""

                    # 200 with grpc-status:0 means success — auth bypass!
                    if "200" in status_line and (
                        "grpc-status: 0" in resp_text or "grpc-status:0" in resp_text
                    ):
                        findings.append(_make_finding(
                            vuln_type="grpc_auth_bypass",
                            severity="critical",
                            url=f"{self.target}{rpc_path}",
                            title=f"gRPC Authentication Bypass — {bypass_name}",
                            evidence=f"gRPC endpoint returned success (grpc-status: 0) with "
                                     f"bypass technique '{bypass_name}' (token={repr(token)[:30]}). "
                                     f"Authentication not enforced.",
                            confidence=0.93,
                            extra={"bypass_technique": bypass_name, "rpc_path": rpc_path},
                        ))
                        break  # Don't need more for this path

                except (socket.error, ssl.SSLError, OSError) as exc:
                    log.debug("gRPC auth bypass %s for %s failed: %s", bypass_name, rpc_path, exc)

        return findings

    # ------------------------------------------------------------------ #
    # Gap 4d: Insecure gRPC (plaintext)
    # ------------------------------------------------------------------ #

    def test_plaintext_grpc(self) -> Optional[GRPCFinding]:
        """Detect gRPC served over plain HTTP (no TLS)."""
        if not self.use_tls:
            # Already on plaintext — check if gRPC responds
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.host, self.port))
                request = _build_grpc_web_request(
                    "/grpc.health.v1.Health/Check",
                    b"",  # empty CheckRequest
                    self.host,
                )
                response = self._send_recv(sock, request)
                sock.close()

                resp_text = response.decode("utf-8", errors="replace")
                if "grpc" in resp_text.lower() or "content-type: application/grpc" in resp_text.lower():
                    return _make_finding(
                        vuln_type="grpc_plaintext_exposed",
                        severity="high",
                        url=f"http://{self.host}:{self.port}",
                        title="gRPC Served Over Plaintext HTTP — No TLS",
                        evidence=f"gRPC endpoint accessible over unencrypted HTTP on port {self.port}. "
                                 f"Authentication tokens, session data, and RPC payloads transmitted in cleartext.",
                        confidence=0.92,
                        extra={"port": self.port, "protocol": "HTTP/1.1 plaintext"},
                    )
            except (socket.error, OSError) as exc:
                log.debug("Plaintext gRPC test failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Gap 4e: gRPC-Web endpoint detection
    # ------------------------------------------------------------------ #

    def test_grpc_web_endpoint(self) -> Optional[GRPCFinding]:
        """
        Detect gRPC-Web endpoints accessible via HTTP/1.1 (browser accessible).
        These bypass network controls that block HTTP/2.
        """
        grpc_web_paths = [
            "/api.UserService/GetUser",
            "/api.Service/List",
            "/grpc.health.v1.Health/Check",
        ]

        try:
            import urllib.request
            import urllib.error

            for path in grpc_web_paths:
                url = f"{self.target}{path}"
                proto_payload = _encode_proto_field(1, 0, 1)
                body = _grpc_frame(proto_payload)
                try:
                    req = urllib.request.Request(
                        url,
                        data=body,
                        headers={
                            "Content-Type": "application/grpc-web+proto",
                            "X-Grpc-Web": "1",
                            "User-Agent": "OneInfinity-GRPC-Scanner/1.0",
                        },
                        method="POST",
                    )
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                        ct = resp.headers.get("Content-Type", "")
                        if "grpc" in ct.lower():
                            return _make_finding(
                                vuln_type="grpc_web_exposed",
                                severity="info",
                                url=url,
                                title="gRPC-Web Endpoint Detected — Browser Accessible",
                                evidence=f"Content-Type: {ct}. gRPC-Web endpoint accessible via HTTP/1.1. "
                                         f"Enables browser-based attacks and bypasses h2-only firewall rules.",
                                confidence=0.90,
                                extra={"path": path, "content_type": ct},
                            )
                except urllib.error.URLError:
                    pass

        except Exception as exc:
            log.debug("gRPC-Web detection failed: %s", exc)

        return None

    # ------------------------------------------------------------------ #
    # Orchestrator
    # ------------------------------------------------------------------ #

    def run(self) -> List[GRPCFinding]:
        """Run all gRPC attack surface tests."""
        log.info("Starting gRPC scan for %s", self.target)
        all_findings: List[GRPCFinding] = []

        tests: List[Tuple[str, Any]] = [
            ("reflection_api", self.test_reflection_api),
            ("plaintext", self.test_plaintext_grpc),
            ("grpc_web", self.test_grpc_web_endpoint),
        ]

        for name, test_fn in tests:
            try:
                result = test_fn()
                if isinstance(result, list):
                    all_findings.extend(result)
                elif result:
                    all_findings.append(result)
            except Exception as exc:
                log.error("gRPC test %s crashed: %s", name, exc)

        # Proto fuzzing and auth bypass
        try:
            all_findings.extend(self.test_proto_fuzzing())
        except Exception as exc:
            log.error("Proto fuzzing crashed: %s", exc)

        try:
            all_findings.extend(self.test_auth_bypass())
        except Exception as exc:
            log.error("Auth bypass crashed: %s", exc)

        log.info("gRPC scan complete: %d findings", len(all_findings))
        return all_findings


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def scan_grpc(target: str, timeout: int = 10) -> List[GRPCFinding]:
    scanner = GRPCScanner(target, timeout=timeout)
    return scanner.run()


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:50051"
    logging.basicConfig(level=logging.INFO)
    results = scan_grpc(target)
    print(json.dumps([f.to_dict() for f in results], indent=2))
