"""
go_idor_engine.py — Python wrapper for the oi-idor-engine gRPC sidecar.

The oi-idor-engine sidecar registers a JSON codec under the "proto" codec
name, so every gRPC message is a JSON object wrapped in the standard
5-byte length-prefix frame.  We mimic this exactly: encode the request
as JSON, frame it, stream the response, and decode each JSON frame into a
OneInfinity finding dict.

Service: oneinfinity.v1.IDOREngine
Stream RPC: /oneinfinity.v1.IDOREngine/Run  (server-streaming)
"""
from __future__ import annotations

import json
import logging
import struct
import uuid
from typing import Any

log = logging.getLogger("oi.go_idor_engine")

_SERVICE_PATH = "/oneinfinity.v1.IDOREngine"


# ---------------------------------------------------------------------------
# gRPC frame helpers
# ---------------------------------------------------------------------------

def _grpc_frame(payload: bytes) -> bytes:
    """Wrap *payload* in a gRPC length-prefix frame (no compression)."""
    return bytes([0]) + struct.pack(">I", len(payload)) + payload


def _parse_grpc_frames(data: bytes) -> list[bytes]:
    """Split a raw gRPC response body into individual message payloads."""
    messages: list[bytes] = []
    pos = 0
    while pos + 5 <= len(data):
        length = struct.unpack_from(">I", data, pos + 1)[0]
        pos += 5
        if pos + length > len(data):
            break
        messages.append(data[pos : pos + length])
        pos += length
    return messages


def _decode_finding(raw: bytes, target: str) -> dict | None:
    """Decode a JSON-framed Finding from the IDOR sidecar."""
    try:
        f: dict = json.loads(raw)
    except Exception:
        return None
    if not f.get("url") and not f.get("URL"):
        return None
    # Normalise PascalCase → snake_case
    return {
        "id":          f.get("id") or f.get("ID") or uuid.uuid4().hex[:16],
        "url":         f.get("url") or f.get("URL", ""),
        "vuln_type":   f.get("vuln_type") or f.get("VulnType") or "idor",
        "severity":    f.get("severity") or f.get("Severity") or "high",
        "evidence":    f.get("evidence") or f.get("Evidence") or "",
        "tool":        f.get("source_tool") or f.get("SourceTool") or "oi-idor-engine",
        "confidence":  f.get("confidence") or f.get("Confidence") or 0.8,
        "scan_id":     f.get("scan_id") or f.get("ScanID") or "",
        "target":      target,
        "metadata":    f.get("metadata") or f.get("Metadata") or {},
    }


# ---------------------------------------------------------------------------
# GoIDOREngine
# ---------------------------------------------------------------------------

class GoIDOREngine:
    """
    Python wrapper for oi-idor-engine (IDOREngine) gRPC sidecar.

    Degrades gracefully when grpcio is absent or the sidecar is not running.

    Usage::

        if GoIDOREngine.is_available():
            engine = GoIDOREngine()
            findings = await engine.run(
                target="https://example.com",
                session_tokens=["Bearer eyJ...", "Bearer eyJ..."],
                endpoint_patterns=["/api/users/", "/api/orders/"],
            )
    """

    @classmethod
    def is_available(cls) -> bool:
        """True if grpcio is importable and the oi-idor-engine port is reachable."""
        try:
            import grpc  # noqa: F401
        except ImportError:
            return False
        try:
            from oneinfinity.infra.grpc_client import idor_channel
            ch = idor_channel(timeout=2.0)
            ch.close()
            return True
        except Exception:
            return False

    async def run(
        self,
        target: str,
        session_tokens: list[str] | None = None,
        endpoint_patterns: list[str] | None = None,
        parallelism: int = 10,
        timeout: int = 120,
        scan_id: str | None = None,
        options: dict[str, str] | None = None,
    ) -> list[dict]:
        """
        Run IDOR scan against *target* via oi-idor-engine gRPC sidecar.

        Parameters
        ----------
        target : str
            Base URL of the application under test.
        session_tokens : list[str] | None
            Auth tokens for at least two accounts (attacker + victim).
            Fewer than two tokens → horizontal IDOR probing only.
        endpoint_patterns : list[str] | None
            URL path prefixes to constrain the scan (e.g. ``["/api/v1/users"]``).
            Empty list lets the sidecar probe all discovered endpoints.
        parallelism : int
            Concurrent probe goroutines inside the sidecar.
        timeout : int
            RPC timeout in seconds.
        scan_id : str | None
            Correlation ID; auto-generated if None.
        options : dict[str, str] | None
            Arbitrary string options forwarded to the sidecar.

        Returns
        -------
        list[dict]
            Finding dicts with keys: id, url, vuln_type, severity, evidence,
            tool, confidence, scan_id, target, metadata.  Returns [] on failure.
        """
        try:
            import grpc
        except ImportError:
            log.debug("[go_idor_engine] grpcio not installed — skipping")
            return []

        try:
            from oneinfinity.infra.grpc_client import idor_channel
        except ImportError:
            log.debug("[go_idor_engine] grpc_client not importable — skipping")
            return []

        try:
            channel = idor_channel(timeout=5.0)
        except Exception as exc:
            log.debug("[go_idor_engine] sidecar unavailable: %s", exc)
            return []

        sid = scan_id or uuid.uuid4().hex[:12]
        req_obj: dict[str, Any] = {
            "target_url":        target,
            "scan_id":           sid,
            "session_tokens":    session_tokens or [],
            "endpoint_patterns": endpoint_patterns or [],
            "parallelism":       parallelism,
            "options":           options or {},
        }
        req_bytes = json.dumps(req_obj).encode()
        framed_req = _grpc_frame(req_bytes)
        method = f"{_SERVICE_PATH}/Run"

        findings: list[dict] = []
        try:
            stub = channel.unary_stream(
                method,
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            for raw_frame in stub(framed_req, timeout=float(timeout + 5)):
                for payload in _parse_grpc_frames(raw_frame):
                    if payload:
                        f = _decode_finding(payload, target)
                        if f:
                            findings.append(f)
        except grpc.RpcError as exc:
            log.debug("[go_idor_engine] RPC error: %s", exc)
        except Exception as exc:
            log.warning("[go_idor_engine] unexpected error: %s", exc)
        finally:
            channel.close()

        log.debug("[go_idor_engine] run(%s) → %d findings", target, len(findings))
        return findings
