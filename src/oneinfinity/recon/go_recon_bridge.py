"""
go_recon_bridge.py — Python wrapper for oi-crawler and oi-recon-probe gRPC sidecars.

Services (proto/oneinfinity.proto):

  CrawlerService  (oi-crawler, port 50056)
    rpc Crawl(CrawlRequest) returns (stream URL)
    rpc Health(HealthCheckRequest) returns (HealthCheckResponse)

  ReconProbe  (oi-recon-probe, port 50052)
    rpc ScanHTTP(ScanRequest) returns (stream Finding)
    rpc Health(HealthCheckRequest) returns (HealthCheckResponse)

Proto message field numbers used here:

  CrawlRequest:  1=start_url(str) 2=scan_id(str) 3=max_pages(int32)
                 4=parallelism(int32) 5=excluded_patterns(repeated str)

  URL:           1=url(str) 2=method(str) 3=status_code(int32)
                 4=forms(repeated str) 5=js_files(repeated str)

  ScanRequest:   1=target_url(str) 2=scan_id(str)
                 3=options(map<str,str>) 5=timeout_seconds(int32)

  Finding:       1=id(str) 2=url(str) 3=vuln_type(str) 4=severity(str)
                 5=evidence(str) 6=source_tool(str) 9=confidence(float32)
                 10=scan_id(str)

No _pb2 stubs required — proto messages are serialised manually using the
same varint/length-delimited helpers as grpc_scanner.py.
Channel creation uses oneinfinity.infra.grpc_client channel factories.
Degrades to [] when grpcio is absent or sidecars are unreachable.
"""
from __future__ import annotations

import logging
import struct
import uuid
from typing import Any

log = logging.getLogger("oi.go_recon_bridge")

_CRAWLER_SIDECAR  = "oi-crawler"
_RECON_SIDECAR    = "oi-recon-probe"
_CRAWLER_SVC      = "/oneinfinity.v1.CrawlerService"
_RECON_SVC        = "/oneinfinity.v1.ReconProbe"


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
    if wire_type == 0:    # varint
        return _encode_varint(tag) + _encode_varint(int(value))
    elif wire_type == 2:  # length-delimited
        if isinstance(value, str):
            value = value.encode()
        return _encode_varint(tag) + _encode_varint(len(value)) + value
    elif wire_type == 1:  # 64-bit
        return _encode_varint(tag) + struct.pack("<Q", int(value))
    elif wire_type == 5:  # 32-bit
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


def _decode_proto_strings(proto: bytes) -> dict[int, list]:
    """
    Decode a proto3 message into {field_number: [raw_value, ...]} map.
    wire_type 0 → int, wire_type 2 → bytes, wire_type 5 → bytes(4),
    wire_type 1 → bytes(8).
    """
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


def _str_field(fields: dict, fn: int) -> str:
    vals = fields.get(fn, [])
    return vals[0].decode(errors="replace") if vals and isinstance(vals[0], bytes) else ""


def _str_fields(fields: dict, fn: int) -> list[str]:
    return [v.decode(errors="replace") for v in fields.get(fn, []) if isinstance(v, bytes)]


# ---------------------------------------------------------------------------
# Proto message builders
# ---------------------------------------------------------------------------

def _build_crawl_request(start_url: str, scan_id: str,
                          max_pages: int, parallelism: int,
                          excluded_patterns: list[str]) -> bytes:
    body = b""
    body += _encode_field(1, 2, start_url)
    body += _encode_field(2, 2, scan_id)
    body += _encode_field(3, 0, max_pages)
    body += _encode_field(4, 0, parallelism)
    for pat in excluded_patterns:
        body += _encode_field(5, 2, pat)
    return body


def _build_scan_request(target_url: str, scan_id: str,
                         options: dict[str, str], timeout_s: int) -> bytes:
    body = b""
    body += _encode_field(1, 2, target_url)
    body += _encode_field(2, 2, scan_id)
    for k, v in options.items():
        entry = _encode_field(1, 2, k) + _encode_field(2, 2, v)
        body += _encode_field(3, 2, entry)
    body += _encode_field(5, 0, timeout_s)
    return body


# ---------------------------------------------------------------------------
# Proto message decoders
# ---------------------------------------------------------------------------

def _decode_url(proto: bytes) -> dict:
    """Decode a URL proto message into a plain dict."""
    f = _decode_proto_strings(proto)
    return {
        "url":         _str_field(f, 1),
        "method":      _str_field(f, 2) or "GET",
        "status_code": f.get(3, [0])[0] if f.get(3) else 0,
        "forms":       _str_fields(f, 4),
        "js_files":    _str_fields(f, 5),
    }


def _decode_finding(proto: bytes, target: str) -> dict:
    """Decode a Finding proto message into a OneInfinity standard finding dict."""
    f = _decode_proto_strings(proto)
    confidence = 0.0
    if 9 in f and f[9] and len(f[9][0]) == 4:
        confidence = struct.unpack("<f", f[9][0])[0]
    return {
        "vuln_type":  _str_field(f, 3) or "recon",
        "severity":   _str_field(f, 4) or "info",
        "tool":       _str_field(f, 6) or _RECON_SIDECAR,
        "url":        _str_field(f, 2) or target,
        "evidence":   _str_field(f, 5),
        "target":     target,
        "confidence": confidence,
        "scan_id":    _str_field(f, 10),
        "_id":        _str_field(f, 1),
    }


# ---------------------------------------------------------------------------
# Shared channel helpers
# ---------------------------------------------------------------------------

def _get_channel(channel_fn):
    """Call a grpc_client channel factory; return None on any error."""
    try:
        import grpc  # noqa: F401
    except ImportError:
        log.debug("[go_recon_bridge] grpcio not installed")
        return None
    try:
        return channel_fn(timeout=5.0)
    except Exception as exc:
        log.debug("[go_recon_bridge] channel unavailable: %s", exc)
        return None


def _stream_call(channel, method: str, framed_req: bytes, timeout: float) -> list[bytes]:
    """
    Execute a server-streaming gRPC call on *channel*.
    Returns raw gRPC frame payloads. Returns [] on RpcError.
    """
    try:
        import grpc
    except ImportError:
        return []
    results: list[bytes] = []
    try:
        stub = channel.unary_stream(
            method,
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        for raw_frame in stub(framed_req, timeout=timeout):
            results.extend(_parse_grpc_frames(raw_frame))
    except grpc.RpcError as exc:
        log.debug("[go_recon_bridge] RPC %s error: %s", method, exc)
    return results


# ---------------------------------------------------------------------------
# GoReconBridge
# ---------------------------------------------------------------------------

class GoReconBridge:
    """
    Python wrapper for oi-crawler (CrawlerService) and
    oi-recon-probe (ReconProbe) gRPC sidecars.

    Degrades gracefully when grpcio is absent or sidecars are not running.

    Usage::

        bridge = GoReconBridge()
        if GoReconBridge.is_available():
            urls    = await bridge.crawl("https://example.com", depth=3)
            probes  = await bridge.probe(urls[:50])
    """

    @classmethod
    def is_available(cls) -> bool:
        """True if grpcio is importable and at least one sidecar port is reachable."""
        try:
            import grpc  # noqa: F401
        except ImportError:
            return False
        try:
            from oneinfinity.infra.grpc_client import crawler_channel
            ch = crawler_channel(timeout=2.0)
            ch.close()
            return True
        except Exception:
            pass
        try:
            from oneinfinity.infra.grpc_client import recon_probe_channel
            ch = recon_probe_channel(timeout=2.0)
            ch.close()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # crawl — CrawlerService.Crawl(CrawlRequest) → stream URL
    # ------------------------------------------------------------------

    async def crawl(
        self,
        target: str,
        depth: int = 3,
        max_pages: int = 5000,
        parallelism: int = 50,
        excluded_patterns: list[str] | None = None,
        scan_id: str | None = None,
    ) -> list[str]:
        """
        Crawl *target* via oi-crawler and return all discovered URLs.

        Parameters
        ----------
        target : str
            Start URL for the crawl.
        depth : int
            Crawl depth (passed as a hint via options; the sidecar uses
            max_pages as the primary budget).
        max_pages : int
            Maximum pages the sidecar will fetch.
        parallelism : int
            Concurrent fetcher goroutines inside the sidecar.
        excluded_patterns : list[str] | None
            Regex patterns for URLs to skip.
        scan_id : str | None
            Correlation ID; auto-generated if None.

        Returns
        -------
        list[str]
            Deduplicated list of discovered URLs.  Returns [] on failure.
        """
        try:
            from oneinfinity.infra.grpc_client import crawler_channel
        except ImportError:
            log.debug("[go_recon_bridge] grpc_client not importable")
            return []

        channel = _get_channel(crawler_channel)
        if channel is None:
            return []

        sid = scan_id or uuid.uuid4().hex[:12]
        proto_req = _build_crawl_request(
            start_url=target,
            scan_id=sid,
            max_pages=max_pages,
            parallelism=parallelism,
            excluded_patterns=excluded_patterns or [],
        )
        framed = _grpc_frame(proto_req)

        raw_frames = _stream_call(
            channel, f"{_CRAWLER_SVC}/Crawl", framed, timeout=300.0,
        )
        channel.close()

        seen: set[str] = set()
        urls: list[str] = []
        for frame in raw_frames:
            if not frame:
                continue
            url_obj = _decode_url(frame)
            u = url_obj.get("url", "")
            if u and u not in seen:
                seen.add(u)
                urls.append(u)

        log.debug("[go_recon_bridge] crawl(%s) → %d URLs", target, len(urls))
        return urls

    # ------------------------------------------------------------------
    # probe — ReconProbe.ScanHTTP(ScanRequest) → stream Finding
    # ------------------------------------------------------------------

    async def probe(
        self,
        urls: list[str],
        timeout: int = 60,
        scan_id: str | None = None,
        options: dict[str, str] | None = None,
    ) -> list[dict]:
        """
        HTTP-probe *urls* via oi-recon-probe (DNS enum, TXT secrets, CT logs).

        Each URL in *urls* triggers a separate ScanHTTP RPC.  Results are
        aggregated and returned as OneInfinity finding dicts.

        Parameters
        ----------
        urls : list[str]
            URLs (or bare domains) to probe.
        timeout : int
            Per-URL RPC timeout in seconds.
        scan_id : str | None
            Shared correlation ID for the batch.
        options : dict[str, str] | None
            Extra ScanRequest options forwarded verbatim to the sidecar.

        Returns
        -------
        list[dict]
            Finding dicts: {vuln_type, severity, tool, url, evidence,
            target, confidence, scan_id}.  Returns [] on failure.
        """
        if not urls:
            return []

        try:
            from oneinfinity.infra.grpc_client import recon_probe_channel
        except ImportError:
            log.debug("[go_recon_bridge] grpc_client not importable")
            return []

        channel = _get_channel(recon_probe_channel)
        if channel is None:
            return []

        sid = scan_id or uuid.uuid4().hex[:12]
        opts = options or {}
        findings: list[dict] = []

        try:
            for url in urls:
                proto_req = _build_scan_request(url, sid, opts, timeout)
                framed = _grpc_frame(proto_req)
                raw_frames = _stream_call(
                    channel, f"{_RECON_SVC}/ScanHTTP", framed,
                    timeout=float(timeout + 5),
                )
                for frame in raw_frames:
                    if frame:
                        findings.append(_decode_finding(frame, url))
        finally:
            channel.close()

        log.debug("[go_recon_bridge] probe(%d urls) → %d findings", len(urls), len(findings))
        return findings
