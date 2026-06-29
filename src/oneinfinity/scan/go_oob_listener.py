"""
go_oob_listener.py — Python wrapper for the oi-oob-listener gRPC sidecar.

Service: OOBService (proto/oneinfinity.proto)
  rpc Start(OOBStartRequest) returns (OOBDomain)
  rpc Poll(PollRequest) returns (stream Interaction)
  rpc Health(HealthCheckRequest) returns (HealthCheckResponse)

The oi-oob-listener sidecar runs embedded HTTP/DNS/SMTP servers and
correlates callbacks by scan_id subdomain (format: <scan_id>.oob.local).

Proto message field numbers used here:

  OOBStartRequest: 1=scan_id(str)  2=target_hint(str)
  OOBDomain:       1=domain(str)   2=scan_id(str)
  PollRequest:     1=scan_id(str)  2=timeout_seconds(int32)
  Interaction:     1=protocol(str) 2=source_ip(str)  3=payload(str)
                   4=received_at(int64)  5=scan_id(str)

No _pb2 stubs required — proto messages are serialised manually.
Channel creation uses oneinfinity.infra.grpc_client.oob_channel().
Degrades gracefully (returns [] / empty string) when grpcio is absent
or the sidecar is not running.

This module also exports ``_GOOB_MARKER`` so oob_engine.py can detect
the fast-path backend without a circular import.
"""
from __future__ import annotations

import logging
import struct
import uuid
from typing import Any

log = logging.getLogger("oi.go_oob_listener")

_SIDECAR_NAME   = "oi-oob-listener"
_OOB_SVC        = "/oneinfinity.v1.OOBService"

# Sentinel used by oob_engine.py to check if the Go backend is present.
_GOOB_MARKER = "go_oob_listener.GoOOBListener"


# ---------------------------------------------------------------------------
# Protobuf + gRPC frame helpers (same pattern as grpc_scanner.py)
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
    if wire_type == 0:
        return _encode_varint(tag) + _encode_varint(int(value))
    elif wire_type == 2:
        if isinstance(value, str):
            value = value.encode()
        return _encode_varint(tag) + _encode_varint(len(value)) + value
    elif wire_type == 1:
        return _encode_varint(tag) + struct.pack("<Q", int(value))
    elif wire_type == 5:
        return _encode_varint(tag) + struct.pack("<I", int(value))
    return b""


def _grpc_frame(proto_bytes: bytes) -> bytes:
    return bytes([0]) + struct.pack(">I", len(proto_bytes)) + proto_bytes


def _parse_grpc_frames(data: bytes) -> list[bytes]:
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


def _decode_proto(proto: bytes) -> dict[int, list]:
    """Decode proto3 wire bytes into {field_number: [values]}."""
    fields: dict[int, list] = {}
    pos = 0
    while pos < len(proto):
        tag_val = 0; shift = 0
        while pos < len(proto):
            b = proto[pos]; pos += 1
            tag_val |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        field_num = tag_val >> 3
        wire_type = tag_val & 0x07
        if wire_type == 0:
            v = 0; shift = 0
            while pos < len(proto):
                b = proto[pos]; pos += 1
                v |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            fields.setdefault(field_num, []).append(v)
        elif wire_type == 2:
            ln = 0; shift = 0
            while pos < len(proto):
                b = proto[pos]; pos += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            fields.setdefault(field_num, []).append(proto[pos: pos + ln]); pos += ln
        elif wire_type == 5:
            fields.setdefault(field_num, []).append(proto[pos: pos + 4]); pos += 4
        elif wire_type == 1:
            fields.setdefault(field_num, []).append(proto[pos: pos + 8]); pos += 8
        else:
            break
    return fields


def _s(fields: dict, fn: int) -> str:
    vals = fields.get(fn, [])
    return vals[0].decode(errors="replace") if vals and isinstance(vals[0], bytes) else ""


# ---------------------------------------------------------------------------
# Proto message builders
# ---------------------------------------------------------------------------

def _build_oob_start_request(scan_id: str, target_hint: str = "") -> bytes:
    body = _encode_field(1, 2, scan_id)
    if target_hint:
        body += _encode_field(2, 2, target_hint)
    return body


def _build_poll_request(scan_id: str, timeout_seconds: int) -> bytes:
    return _encode_field(1, 2, scan_id) + _encode_field(2, 0, timeout_seconds)


# ---------------------------------------------------------------------------
# Proto message decoders
# ---------------------------------------------------------------------------

def _decode_oob_domain(proto: bytes) -> str:
    """Decode OOBDomain proto → domain string (field 1)."""
    f = _decode_proto(proto)
    return _s(f, 1)


def _decode_interaction(proto: bytes) -> dict:
    """Decode Interaction proto → plain dict."""
    f = _decode_proto(proto)
    received_at = 0
    if 4 in f and f[4]:
        v = f[4][0]
        if isinstance(v, int):
            received_at = v
        elif isinstance(v, bytes) and len(v) == 8:
            received_at = struct.unpack("<q", v)[0]
    return {
        "protocol":    _s(f, 1) or "unknown",
        "source_ip":   _s(f, 2),
        "payload":     _s(f, 3),
        "received_at": received_at,
        "scan_id":     _s(f, 5),
    }


# ---------------------------------------------------------------------------
# GoOOBListener
# ---------------------------------------------------------------------------

class GoOOBListener:
    """
    Python wrapper for the oi-oob-listener gRPC sidecar (OOBService).

    Allocates a unique ``<scan_id>.oob.local`` subdomain via the sidecar's
    Start RPC and reads back callbacks via Poll.

    Degrades gracefully when grpcio is absent or the sidecar is unreachable:
    ``start()`` returns an empty string, ``read_callbacks()`` returns [].

    Usage::

        listener = GoOOBListener()
        domain = listener.start()              # "<scan_id>.oob.local" or ""
        # ... inject domain into payloads ...
        hits = listener.read_callbacks(timeout=30)
        listener.stop()                        # no-op; sidecar manages itself

    ``scan_id`` is also accessible as ``listener.scan_id`` for payload
    correlation with GoSSRFEngine.
    """

    def __init__(self, scan_id: str | None = None, target_hint: str = "") -> None:
        self.scan_id: str = scan_id or uuid.uuid4().hex[:12]
        self.target_hint: str = target_hint
        self._domain: str = ""
        self._channel: Any = None

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @classmethod
    def is_available(cls) -> bool:
        """True if grpcio is importable and the OOB sidecar port is reachable."""
        try:
            import grpc  # noqa: F401
        except ImportError:
            return False
        try:
            from oneinfinity.infra.grpc_client import oob_channel
            ch = oob_channel(timeout=2.0)
            ch.close()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, port: int = 4444) -> str:  # port param kept for API compat
        """
        Allocate an OOB subdomain via OOBService.Start.

        The *port* parameter is accepted for API compatibility with
        OOBEngine but is ignored — port configuration is owned by the
        sidecar (see config/ports.json / oi-oob-listener env vars).

        Returns
        -------
        str
            ``<scan_id>.oob.local`` on success, ``""`` on failure.
        """
        try:
            import grpc  # noqa: F401
        except ImportError:
            log.debug("[go_oob_listener] grpcio not installed")
            return ""

        try:
            from oneinfinity.infra.grpc_client import oob_channel
            self._channel = oob_channel(timeout=5.0)
        except Exception as exc:
            log.debug("[go_oob_listener] OOB sidecar unavailable: %s", exc)
            return ""

        proto_req = _build_oob_start_request(self.scan_id, self.target_hint)
        framed = _grpc_frame(proto_req)

        try:
            import grpc
            stub = self._channel.unary_unary(
                f"{_OOB_SVC}/Start",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            raw = stub(framed, timeout=5.0)
            for proto_bytes in _parse_grpc_frames(raw):
                domain = _decode_oob_domain(proto_bytes)
                if domain:
                    self._domain = domain
                    log.info("[go_oob_listener] OOB domain: %s", domain)
                    return domain
        except Exception as exc:
            log.debug("[go_oob_listener] Start RPC error: %s", exc)

        # Fallback: synthesise the domain locally (matches sidecar logic)
        self._domain = f"{self.scan_id}.oob.local"
        log.debug("[go_oob_listener] using synthesised domain: %s", self._domain)
        return self._domain

    def read_callbacks(self, timeout: int = 30) -> list[dict]:
        """
        Poll the OOB sidecar for interactions received for this scan_id.

        Parameters
        ----------
        timeout : int
            Seconds to wait for new interactions (passed to OOBService.Poll).

        Returns
        -------
        list[dict]
            Each dict: {protocol, source_ip, payload, received_at, scan_id}.
            Returns [] if the sidecar is unavailable.
        """
        if self._channel is None:
            log.debug("[go_oob_listener] read_callbacks called before start()")
            return []

        proto_req = _build_poll_request(self.scan_id, timeout)
        framed = _grpc_frame(proto_req)
        interactions: list[dict] = []

        try:
            import grpc
            stub = self._channel.unary_stream(
                f"{_OOB_SVC}/Poll",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            for raw_frame in stub(framed, timeout=float(timeout + 5)):
                for proto_bytes in _parse_grpc_frames(raw_frame):
                    if proto_bytes:
                        interactions.append(_decode_interaction(proto_bytes))
        except Exception as exc:
            log.debug("[go_oob_listener] Poll error: %s", exc)

        log.debug("[go_oob_listener] read_callbacks → %d interactions", len(interactions))
        return interactions

    def stop(self) -> None:
        """
        Release the gRPC channel.  The sidecar process itself is managed
        by SidecarManager and is not stopped here.
        """
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                pass
            self._channel = None

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def domain(self) -> str:
        """The allocated OOB domain, or empty string if not started."""
        return self._domain
