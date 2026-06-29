"""
go_ssrf_engine.py — Python wrapper for the oi-ssrf Go gRPC sidecar.

Service: SSRFScanner (proto/oneinfinity.proto)
  rpc Scan(ScanRequest) returns (stream Finding)
  rpc Health(HealthCheckRequest) returns (HealthCheckResponse)

Wire protocol: gRPC over HTTP/2, protobuf binary encoding (standard proto3).
No _pb2 stubs are generated — proto messages are serialised manually using the
same _encode_varint / _encode_proto_field helpers as grpc_scanner.py.

Channel creation delegates to oneinfinity.infra.grpc_client.ssrf_channel().
If grpcio is absent the wrapper degrades gracefully (returns []).

ScanRequest fields (proto field numbers):
  1: target_url  (string)
  2: scan_id     (string)
  3: options     (map<string,string>)  — encoded as repeated embedded msg {1:key,2:val}
  4: headers     (repeated string)
  5: timeout_seconds (int32)

Finding fields (proto field numbers):
  1: id           (string)
  2: url          (string)
  3: vuln_type    (string)
  4: severity     (string)
  5: evidence     (string)
  6: source_tool  (string)
  7: discovered_at(int64)
  8: metadata     (map<string,string>)
  9: confidence   (float)
  10: scan_id      (string)
"""
from __future__ import annotations

import logging
import socket
import struct
import uuid
from typing import Any

log = logging.getLogger("oi.go_ssrf_engine")

_SIDECAR_NAME = "oi-ssrf"
_SERVICE_PATH = "/oneinfinity.v1.SSRFScanner"


# ---------------------------------------------------------------------------
# Minimal protobuf + gRPC frame helpers (mirrors grpc_scanner.py)
# ---------------------------------------------------------------------------

def _encode_varint(value: int) -> bytes:
    bits = value & 0x7F
    value >>= 7
    result = b""
    while value:
        result += bytes([0x80 | bits])
        bits = value & 0x7F
        value >>= 7
    result += bytes([bits])
    return result


def _encode_field(field_number: int, wire_type: int, value: Any) -> bytes:
    tag = (field_number << 3) | wire_type
    if wire_type == 0:   # varint
        return _encode_varint(tag) + _encode_varint(int(value))
    elif wire_type == 2:  # length-delimited (string, bytes, embedded message)
        if isinstance(value, str):
            value = value.encode()
        return _encode_varint(tag) + _encode_varint(len(value)) + value
    elif wire_type == 1:  # 64-bit
        return _encode_varint(tag) + struct.pack("<Q", int(value))
    elif wire_type == 5:  # 32-bit
        return _encode_varint(tag) + struct.pack("<I", int(value))
    return b""


def _grpc_frame(proto_bytes: bytes) -> bytes:
    """Wrap proto bytes in a gRPC length-prefix frame (compressed=0)."""
    return bytes([0]) + struct.pack(">I", len(proto_bytes)) + proto_bytes


def _parse_grpc_frames(data: bytes) -> list[bytes]:
    """Split a raw gRPC response body into individual proto payloads."""
    messages: list[bytes] = []
    offset = 0
    while offset + 5 <= len(data):
        length = struct.unpack(">I", data[offset + 1: offset + 5])[0]
        offset += 5
        if offset + length > len(data):
            break
        messages.append(data[offset: offset + length])
        offset += length
    return messages


def _decode_finding(proto: bytes, target: str) -> dict:
    """
    Decode a proto3 Finding message into a OneInfinity finding dict.
    Fields: 1=id(str) 2=url(str) 3=vuln_type(str) 4=severity(str)
            5=evidence(str) 6=source_tool(str) 9=confidence(float32)
            10=scan_id(str)
    """
    fields: dict[int, list] = {}
    pos = 0
    while pos < len(proto):
        if pos >= len(proto):
            break
        # decode tag varint
        tag_val = 0
        shift = 0
        while pos < len(proto):
            b = proto[pos]; pos += 1
            tag_val |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        field_num = tag_val >> 3
        wire_type = tag_val & 0x07
        if wire_type == 0:      # varint
            v = 0; shift = 0
            while pos < len(proto):
                b = proto[pos]; pos += 1
                v |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            fields.setdefault(field_num, []).append(v)
        elif wire_type == 2:    # length-delimited
            ln = 0; shift = 0
            while pos < len(proto):
                b = proto[pos]; pos += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            val = proto[pos: pos + ln]; pos += ln
            fields.setdefault(field_num, []).append(val)
        elif wire_type == 5:    # 32-bit
            fields.setdefault(field_num, []).append(proto[pos: pos + 4]); pos += 4
        elif wire_type == 1:    # 64-bit
            fields.setdefault(field_num, []).append(proto[pos: pos + 8]); pos += 8
        else:
            break  # unknown wire type — stop parsing

    def _str(fn: int) -> str:
        vals = fields.get(fn, [])
        return vals[0].decode(errors="replace") if vals else ""

    confidence = 0.0
    if 9 in fields and fields[9]:
        raw = fields[9][0]
        confidence = struct.unpack("<f", raw)[0] if len(raw) == 4 else 0.0

    return {
        "vuln_type": _str(3) or "ssrf",
        "severity":  _str(4) or "high",
        "tool":      _str(6) or _SIDECAR_NAME,
        "url":       _str(2) or target,
        "evidence":  _str(5),
        "target":    target,
        "confidence": confidence,
        "scan_id":   _str(10),
        "_id":       _str(1),
    }


def _build_scan_request(target: str, scan_id: str,
                         options: dict[str, str], timeout_s: int) -> bytes:
    """Encode ScanRequest as proto3 bytes."""
    body = b""
    body += _encode_field(1, 2, target)       # target_url
    body += _encode_field(2, 2, scan_id)      # scan_id
    for k, v in options.items():              # options map entry
        entry = _encode_field(1, 2, k) + _encode_field(2, 2, v)
        body += _encode_field(3, 2, entry)
    body += _encode_field(5, 0, timeout_s)    # timeout_seconds
    return body


# ---------------------------------------------------------------------------
# GoSSRFEngine
# ---------------------------------------------------------------------------

class GoSSRFEngine:
    """
    Wrapper for the oi-ssrf gRPC sidecar (SSRFScanner service).

    Degrades gracefully when grpcio is absent or the sidecar is not running.

    Usage::

        if GoSSRFEngine.is_available():
            engine = GoSSRFEngine()
            findings = await engine.scan("https://example.com/api?url=FUZZ")
    """

    _SIDECAR = _SIDECAR_NAME

    @classmethod
    def is_available(cls) -> bool:
        """True if grpcio is importable and the sidecar port is reachable."""
        try:
            import grpc  # noqa: F401
        except ImportError:
            return False
        try:
            from oneinfinity.infra.grpc_client import ssrf_channel
            ch = ssrf_channel(timeout=2.0)
            ch.close()
            return True
        except Exception:
            return False

    async def scan(
        self,
        target: str,
        payloads: list[str] | None = None,
        timeout: int = 60,
        scan_id: str | None = None,
        oob_domain: str | None = None,
    ) -> list[dict]:
        """
        Run SSRF scan against *target* via oi-ssrf gRPC sidecar.

        Returns list of finding dicts: {vuln_type, severity, tool, url,
        evidence, target, confidence, scan_id}.  Returns [] on any failure.
        """
        try:
            import grpc
        except ImportError:
            log.debug("[go_ssrf_engine] grpcio not installed — skipping")
            return []

        try:
            from oneinfinity.infra.grpc_client import ssrf_channel
        except ImportError:
            log.debug("[go_ssrf_engine] grpc_client not importable — skipping")
            return []

        try:
            channel = ssrf_channel(timeout=5.0)
        except Exception as exc:
            log.debug("[go_ssrf_engine] sidecar unavailable: %s", exc)
            return []

        sid = scan_id or uuid.uuid4().hex[:12]
        options: dict[str, str] = {}
        if oob_domain:
            options["oob_domain"] = oob_domain
        if payloads:
            options["extra_payloads"] = ",".join(payloads)

        proto_req = _build_scan_request(target, sid, options, timeout)
        framed_req = _grpc_frame(proto_req)
        method = f"{_SERVICE_PATH}/Scan"

        findings: list[dict] = []
        try:
            stub = channel.unary_stream(
                method,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            for raw_frame in stub(framed_req, timeout=float(timeout + 5)):
                for proto_bytes in _parse_grpc_frames(raw_frame):
                    if proto_bytes:
                        findings.append(_decode_finding(proto_bytes, target))
        except grpc.RpcError as exc:
            log.debug("[go_ssrf_engine] RPC error: %s", exc)
        except Exception as exc:
            log.warning("[go_ssrf_engine] unexpected error: %s", exc)
        finally:
            channel.close()

        return findings
