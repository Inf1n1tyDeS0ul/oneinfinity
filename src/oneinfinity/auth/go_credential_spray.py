"""
go_credential_spray.py — Python wrapper for the oi-credential-spray Go sidecar.

Architecture
────────────
oi-credential-spray is a gRPC service registered in the sidecar registry at
port 50060.  It implements the CredentialSpray service from proto/oneinfinity.proto:

    service CredentialSpray {
        rpc Run(CredentialSprayRequest) returns (stream Finding);
        rpc Health(HealthCheckRequest) returns (HealthCheckResponse);
    }

This wrapper:
1. Ensures the sidecar is running via SidecarManager.
2. Sends a CredentialSprayRequest over the gRPC channel.
3. Collects streaming Finding results.
4. Returns normalised finding dicts matching the OneInfinity finding schema:
   {vuln_type, severity, url, evidence, tool, target}.

Rate-limiting and lockout detection are implemented inside the Go binary.
This wrapper exposes per-call delay_ms for coarse throttling from Python.

Usage
─────
    from oneinfinity.auth.go_credential_spray import GoCredentialSpray
    spray = GoCredentialSpray()
    findings = await spray.run(
        target_url="https://example.com",
        login_endpoint="/api/v1/login",
        usernames=["admin", "root"],
        passwords=["password", "123456"],
        scan_id="scan_001",
        delay_ms=500,
    )
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

log = logging.getLogger("oneinfinity.go_credential_spray")

_SIDECAR_NAME = "oi-credential-spray"
_TOOL_NAME = "go_credential_spray"


# ─── Finding dataclass ────────────────────────────────────────────────────────

@dataclass
class CredentialFinding:
    """Normalised finding from oi-credential-spray."""
    finding_id: str
    vuln_type: str = "credential_spray_success"
    severity: str = "critical"
    url: str = ""
    target: str = ""           # host:port
    service: str = ""
    username: str = ""
    password: str = ""
    evidence: str = ""
    confidence: float = 0.99
    tool: str = _TOOL_NAME
    source_type: str = "active"
    scan_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "url": self.url,
            "target": self.target,
            "service": self.service,
            "username": self.username,
            "password": self.password,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "tool": self.tool,
            "source_type": self.source_type,
            "scan_id": self.scan_id,
        }


# ─── gRPC stubs (hand-rolled; no protoc required) ─────────────────────────────

class _CredentialSprayStub:
    """
    Minimal hand-rolled gRPC stub for the CredentialSpray service.

    Mirrors the pattern established in grpc_client.py — uses the shared
    insecure channel and JSON codec that all Go sidecars register.

    Message layout (proto field numbers):
        CredentialSprayRequest:
            target_url=1, scan_id=2, login_endpoint=3,
            usernames=4 (repeated), passwords=5 (repeated), delay_ms=6
        Finding (response stream):
            id=1, url=2, vuln_type=3, severity=4, evidence=5,
            source_tool=6, discovered_at=7, metadata=8, confidence=9, scan_id=10
        HealthCheckRequest: service=1
        HealthCheckResponse: status=1
    """

    _METHOD_RUN = "/oneinfinity.v1.CredentialSpray/Run"
    _METHOD_HEALTH = "/oneinfinity.v1.CredentialSpray/Health"

    def __init__(self, channel):
        try:
            import grpc
        except ImportError:
            raise ImportError("grpcio not installed. Run: pip install grpcio")

        import json as _json

        # Server-streaming call: unary request → stream of responses
        self._run = channel.stream_unary  # placeholder; actual below
        self._channel = channel

        # Build callable descriptors following grpc.Channel.unary_stream pattern
        self._run_call = channel.unary_stream(
            self._METHOD_RUN,
            request_serializer=lambda req: _json.dumps(req).encode(),
            response_deserializer=lambda b: _json.loads(b),
        )
        self._health_call = channel.unary_unary(
            self._METHOD_HEALTH,
            request_serializer=lambda req: _json.dumps(req).encode(),
            response_deserializer=lambda b: _json.loads(b),
        )

    def Run(self, request: dict, timeout: float = 120.0):
        """Stream Finding records for the credential spray request."""
        return self._run_call(request, timeout=timeout)

    def Health(self, request: dict, timeout: float = 5.0):
        return self._health_call(request, timeout=timeout)


# ─── Main wrapper class ────────────────────────────────────────────────────────

class GoCredentialSpray:
    """
    Python facade over the oi-credential-spray gRPC sidecar.

    Handles sidecar lifecycle (auto-start if not running), gRPC channel
    management, and normalisation of streaming Finding proto messages into
    CredentialFinding objects.

    Rate-limiting is handled by the Go binary (configurable via delay_ms).
    Lockout detection is also Go-side; the binary backs off automatically
    after 3–5 consecutive failures per service/host.
    """

    def __init__(self, startup_timeout: float = 15.0, call_timeout: float = 120.0):
        self._startup_timeout = startup_timeout
        self._call_timeout = call_timeout
        self._channel = None
        self._stub: Optional[_CredentialSprayStub] = None

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def _ensure_sidecar(self) -> None:
        """Start oi-credential-spray if not already running."""
        try:
            from oneinfinity.infra.sidecar_manager import SidecarManager
            mgr = SidecarManager(startup_timeout=self._startup_timeout)
            status = mgr.start(_SIDECAR_NAME)
            if not status.running:
                log.warning(
                    "go_credential_spray: sidecar unavailable — %s. "
                    "Build with: cd src/go/oi-credential-spray && "
                    "go build -o bin/oi-credential-spray .",
                    status.error,
                )
        except Exception as exc:
            log.debug("go_credential_spray: sidecar autostart skipped: %s", exc)

    def _get_stub(self) -> _CredentialSprayStub:
        if self._stub is None:
            self._ensure_sidecar()
            from oneinfinity.infra.grpc_client import credential_spray_channel
            self._channel = credential_spray_channel(timeout=self._startup_timeout)
            self._stub = _CredentialSprayStub(self._channel)
        return self._stub

    def close(self) -> None:
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                pass
            self._channel = None
            self._stub = None

    # ── Public API ─────────────────────────────────────────────────────────

    async def run(
        self,
        target_url: str,
        login_endpoint: str,
        usernames: List[str],
        passwords: List[str],
        scan_id: Optional[str] = None,
        delay_ms: int = 300,
    ) -> List[CredentialFinding]:
        """
        Execute credential spray via Go sidecar.

        Parameters
        ──────────
        target_url:     Base URL of the target (used for Finding.url).
        login_endpoint: Specific login path (e.g. /api/v1/login).
        usernames:      Candidate usernames.
        passwords:      Candidate passwords.
        scan_id:        Scan session identifier (auto-generated if omitted).
        delay_ms:       Inter-attempt delay in milliseconds (passed to Go).

        Returns
        ───────
        List of CredentialFinding for each successful credential pair.
        Empty list if the sidecar is unavailable (graceful degradation).
        """
        if not usernames or not passwords:
            log.debug("go_credential_spray: empty username or password list — skipping")
            return []

        if scan_id is None:
            scan_id = uuid.uuid4().hex

        request = {
            "target_url": target_url,
            "scan_id": scan_id,
            "login_endpoint": login_endpoint,
            "usernames": usernames,
            "passwords": passwords,
            "delay_ms": delay_ms,
        }

        findings: List[CredentialFinding] = []

        try:
            stub = self._get_stub()
        except (ConnectionError, ImportError, Exception) as exc:
            log.warning(
                "go_credential_spray: sidecar unavailable, skipping spray: %s", exc
            )
            return []

        try:
            for raw in stub.Run(request, timeout=self._call_timeout):
                finding = self._normalise(raw, target_url, scan_id)
                if finding:
                    findings.append(finding)
                    log.info(
                        "go_credential_spray: valid credential found — %s:%s @ %s",
                        finding.username, finding.password, finding.service,
                    )
                    # Phase C: emit CREDENTIAL_ACQUIRED immediately per credential.
                    # Fire inside the loop (not after) so scoped recon starts
                    # without waiting for the full spray to complete.
                    # DA2 schema: session_id ref only — no raw password on the bus.
                    try:
                        from oneinfinity.orchestration.event_bus import get_bus, EventType, Priority
                        from oneinfinity.auth.session_manager import SessionManager, LoginSession
                        import time as _time, uuid as _uuid
                        # Build a minimal LoginSession from the credential finding
                        _ls = LoginSession(
                            session_id=str(_uuid.uuid4())[:12],
                            target=target_url,
                            login_url=login_endpoint if login_endpoint.startswith("http")
                                      else target_url.rstrip("/") + "/" + login_endpoint.lstrip("/"),
                            cookies=[],
                            auth_headers={"Authorization": f"Basic {finding.username}:{finding.password}"}
                                         if finding.service != "web" else {},
                            local_storage={},
                            session_storage={},
                            indexeddb_snapshot={},
                            har_path="",
                            recorder="credential_spray",
                            name=f"spray_{finding.username}_{scan_id[:8]}",
                        )
                        # Save BEFORE emitting — receiver resolves via session_id
                        SessionManager().save(_ls, name=_ls.name)
                        get_bus().publish(
                            EventType.CREDENTIAL_ACQUIRED,
                            {
                                "session_id": _ls.session_id,
                                "target": target_url,
                                "service": finding.service or "web",
                                "username": finding.username,
                                "auth_tier": 1,
                                "login_endpoint": login_endpoint,
                                "scan_id": scan_id,
                                "role_hint": finding.role if hasattr(finding, "role") else None,
                                "spray_finding_id": finding.finding_id,
                            },
                            source="go_credential_spray",
                            priority=Priority.HIGH,
                        )
                        log.info("go_credential_spray: CREDENTIAL_ACQUIRED event fired for %s", finding.username)
                    except Exception as _evt_exc:
                        log.warning("go_credential_spray: CREDENTIAL_ACQUIRED event failed (non-fatal): %s", _evt_exc)
        except Exception as exc:
            log.error("go_credential_spray: RPC error during Run: %s", exc)

        log.info(
            "go_credential_spray: spray complete — %d valid credentials found", len(findings)
        )
        return findings

    def run_sync(
        self,
        target_url: str,
        login_endpoint: str,
        usernames: List[str],
        passwords: List[str],
        scan_id: Optional[str] = None,
        delay_ms: int = 300,
    ) -> List[CredentialFinding]:
        """Synchronous wrapper around run() for non-async callers.
        PE2 fix: use asyncio.run() instead of get_event_loop().run_until_complete()
        to prevent deadlock when called from EventBus worker threads.
        """
        import asyncio
        return asyncio.run(
            self.run(
                target_url=target_url,
                login_endpoint=login_endpoint,
                usernames=usernames,
                passwords=passwords,
                scan_id=scan_id,
                delay_ms=delay_ms,
            )
        )

    # ── Internal helpers ───────────────────────────────────────────────────

    @staticmethod
    def _normalise(
        raw: Dict[str, Any],
        target_url: str,
        scan_id: str,
    ) -> Optional[CredentialFinding]:
        """
        Map a raw Finding proto dict → CredentialFinding.

        The Go binary emits Finding messages with:
          - vuln_type  = "credential_spray_success"
          - metadata   = {"service": ..., "username": ..., "password": ...,
                          "host": ..., "port": ...}
          - severity   = "critical"
          - evidence   = human-readable description
        """
        if not isinstance(raw, dict):
            return None

        # Go Finding proto fields
        vuln_type = raw.get("vuln_type", "credential_spray_success")
        severity = raw.get("severity", "critical")
        evidence = raw.get("evidence", "")
        metadata = raw.get("metadata", {})

        service = metadata.get("service", raw.get("service", "unknown"))
        username = metadata.get("username", raw.get("username", ""))
        password = metadata.get("password", raw.get("password", ""))
        host = metadata.get("host", "")
        port_str = metadata.get("port", "")
        target = f"{host}:{port_str}" if host else target_url

        if not username:
            return None  # not a successful credential hit

        finding_id = hashlib.md5(
            f"cred_{target}_{service}_{username}".encode()
        ).hexdigest()[:16]

        return CredentialFinding(
            finding_id=finding_id,
            vuln_type=vuln_type,
            severity=severity,
            url=target_url,
            target=target,
            service=service,
            username=username,
            password=password,
            evidence=evidence or (
                f"Valid credential confirmed: {username}:{password} "
                f"on {service} at {target}"
            ),
            confidence=0.99,
            tool=_TOOL_NAME,
            scan_id=scan_id,
        )

    def health(self) -> bool:
        """Return True if the sidecar is reachable and healthy."""
        try:
            stub = self._get_stub()
            resp = stub.Health({"service": _SIDECAR_NAME})
            # ServingStatus: 1 = SERVING
            return resp.get("status", 0) == 1
        except Exception as exc:
            log.debug("go_credential_spray: health check failed: %s", exc)
            return False


# ─── Convenience function ─────────────────────────────────────────────────────

async def spray_credentials(
    target_url: str,
    login_endpoint: str,
    usernames: List[str],
    passwords: List[str],
    scan_id: Optional[str] = None,
    delay_ms: int = 300,
) -> List[CredentialFinding]:
    """Module-level convenience wrapper — creates a GoCredentialSpray, runs, closes."""
    wrapper = GoCredentialSpray()
    try:
        return await wrapper.run(
            target_url=target_url,
            login_endpoint=login_endpoint,
            usernames=usernames,
            passwords=passwords,
            scan_id=scan_id,
            delay_ms=delay_ms,
        )
    finally:
        wrapper.close()
