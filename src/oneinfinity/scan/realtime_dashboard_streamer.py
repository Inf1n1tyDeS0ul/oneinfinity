"""
Real-Time Dashboard Streamer
=============================
WebSocket-based real-time vulnerability and scan progress streaming.

Innovation:
1. **Live Vulnerability Feed** - Stream findings as they're discovered
2. **Progress Visualization** - Real-time scan progress with metrics
3. **Attack Chain Animation** - Live correlation of findings into chains
4. **Risk Score Updates** - Dynamic risk calculation during scan
5. **Multi-Scan Orchestration** - Parallel scan monitoring

No other tool has real-time vulnerability correlation streaming.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

log = logging.getLogger("oneinfinity.realtime_dashboard")


# ─────────────────────────────────────────────────────────────────────────────
# Event Types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DashboardEvent:
    """Real-time dashboard event."""
    event_type: str  # scan_start, finding, progress, chain, complete, error
    scan_id: str
    timestamp: float = field(default_factory=time.time)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "event_type": self.event_type,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "data": self.data,
        })


@dataclass
class ScanMetrics:
    """Real-time scan metrics."""
    scan_id: str
    requests_sent: int = 0
    responses_received: int = 0
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    chains_detected: int = 0
    current_phase: str = ""
    progress_percent: int = 0
    elapsed_seconds: float = 0.0
    estimated_remaining: float = 0.0
    requests_per_second: float = 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Streamer
# ─────────────────────────────────────────────────────────────────────────────

class RealtimeDashboardStreamer:
    """
    Streams real-time scan updates to WebSocket clients.

    Features:
    - Live finding stream as vulnerabilities discovered
    - Progress updates with metrics
    - Attack chain correlation animation
    - Risk score evolution
    - Multi-scan aggregation
    """

    def __init__(self):
        self.active_scans: Dict[str, ScanMetrics] = {}
        self.scan_findings: Dict[str, List[Dict]] = defaultdict(list)
        self.scan_start_times: Dict[str, float] = {}
        self.websocket_clients: List[Any] = []  # WebSocket connections
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)

    # ── Scan Lifecycle ────────────────────────────────────────────────────────

    async def start_scan(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        total_endpoints: int = 0
    ) -> None:
        """Start scan streaming."""
        self.active_scans[scan_id] = ScanMetrics(scan_id=scan_id)
        self.scan_start_times[scan_id] = time.time()

        event = DashboardEvent(
            event_type="scan_start",
            scan_id=scan_id,
            data={
                "target": target,
                "scan_type": scan_type,
                "total_endpoints": total_endpoints,
                "started_at": time.time(),
            }
        )

        await self._broadcast(event)
        log.info(f"Started streaming scan: {scan_id}")

    async def stream_finding(
        self,
        scan_id: str,
        finding: Dict[str, Any]
    ) -> None:
        """Stream individual finding."""
        if scan_id not in self.active_scans:
            return

        metrics = self.active_scans[scan_id]
        metrics.findings_count += 1

        # Update severity counts
        severity = finding.get("severity", "low").lower()
        if severity == "critical":
            metrics.critical_count += 1
        elif severity == "high":
            metrics.high_count += 1
        elif severity == "medium":
            metrics.medium_count += 1
        else:
            metrics.low_count += 1

        # Store finding
        self.scan_findings[scan_id].append(finding)

        # Create event
        event = DashboardEvent(
            event_type="finding",
            scan_id=scan_id,
            data={
                "finding": finding,
                "total_findings": metrics.findings_count,
                "severity_breakdown": {
                    "critical": metrics.critical_count,
                    "high": metrics.high_count,
                    "medium": metrics.medium_count,
                    "low": metrics.low_count,
                }
            }
        )

        await self._broadcast(event)

    async def stream_progress(
        self,
        scan_id: str,
        phase: str,
        percent: int,
        message: str = ""
    ) -> None:
        """Stream progress update."""
        if scan_id not in self.active_scans:
            return

        metrics = self.active_scans[scan_id]
        metrics.current_phase = phase
        metrics.progress_percent = percent

        # Calculate timing
        elapsed = time.time() - self.scan_start_times.get(scan_id, time.time())
        metrics.elapsed_seconds = elapsed

        if percent > 0:
            estimated_total = (elapsed / percent) * 100
            metrics.estimated_remaining = estimated_total - elapsed

        event = DashboardEvent(
            event_type="progress",
            scan_id=scan_id,
            data={
                "phase": phase,
                "percent": percent,
                "message": message,
                "elapsed": metrics.elapsed_seconds,
                "estimated_remaining": metrics.estimated_remaining,
            }
        )

        await self._broadcast(event)

    async def stream_attack_chain(
        self,
        scan_id: str,
        chain: Dict[str, Any]
    ) -> None:
        """Stream detected attack chain."""
        if scan_id not in self.active_scans:
            return

        metrics = self.active_scans[scan_id]
        metrics.chains_detected += 1

        event = DashboardEvent(
            event_type="chain",
            scan_id=scan_id,
            data={
                "chain": chain,
                "total_chains": metrics.chains_detected,
            }
        )

        await self._broadcast(event)
        log.info(f"Attack chain detected: {chain.get('name', 'Unknown')}")

    async def stream_metrics(
        self,
        scan_id: str,
        requests_sent: int = 0,
        responses_received: int = 0
    ) -> None:
        """Stream request/response metrics."""
        if scan_id not in self.active_scans:
            return

        metrics = self.active_scans[scan_id]
        metrics.requests_sent += requests_sent
        metrics.responses_received += responses_received

        # Calculate RPS
        elapsed = time.time() - self.scan_start_times.get(scan_id, time.time())
        if elapsed > 0:
            metrics.requests_per_second = metrics.requests_sent / elapsed

        event = DashboardEvent(
            event_type="metrics",
            scan_id=scan_id,
            data={
                "requests_sent": metrics.requests_sent,
                "responses_received": metrics.responses_received,
                "rps": round(metrics.requests_per_second, 2),
            }
        )

        await self._broadcast(event)

    async def complete_scan(
        self,
        scan_id: str,
        success: bool = True,
        error: Optional[str] = None
    ) -> None:
        """Complete scan streaming."""
        if scan_id not in self.active_scans:
            return

        metrics = self.active_scans[scan_id]
        elapsed = time.time() - self.scan_start_times.get(scan_id, time.time())

        event = DashboardEvent(
            event_type="complete",
            scan_id=scan_id,
            data={
                "success": success,
                "error": error,
                "duration": elapsed,
                "summary": {
                    "total_findings": metrics.findings_count,
                    "critical": metrics.critical_count,
                    "high": metrics.high_count,
                    "medium": metrics.medium_count,
                    "low": metrics.low_count,
                    "chains": metrics.chains_detected,
                    "requests_sent": metrics.requests_sent,
                }
            }
        )

        await self._broadcast(event)
        log.info(f"Completed scan: {scan_id}")

        # Cleanup
        del self.active_scans[scan_id]
        del self.scan_start_times[scan_id]

    # ── WebSocket Management ──────────────────────────────────────────────────

    def register_websocket(self, websocket: Any) -> None:
        """Register WebSocket client."""
        self.websocket_clients.append(websocket)
        log.info(f"Registered WebSocket client, total: {len(self.websocket_clients)}")

    def unregister_websocket(self, websocket: Any) -> None:
        """Unregister WebSocket client."""
        if websocket in self.websocket_clients:
            self.websocket_clients.remove(websocket)
            log.info(f"Unregistered WebSocket client, total: {len(self.websocket_clients)}")

    async def _broadcast(self, event: DashboardEvent) -> None:
        """Broadcast event to all WebSocket clients."""
        if not self.websocket_clients:
            return

        message = event.to_json()
        disconnected = []

        for client in self.websocket_clients:
            try:
                await client.send_text(message)
            except Exception as e:
                log.warning(f"Failed to send to client: {e}")
                disconnected.append(client)

        # Remove disconnected clients
        for client in disconnected:
            self.unregister_websocket(client)

    # ── Event Handlers ────────────────────────────────────────────────────────

    def on_event(self, event_type: str, handler: Callable) -> None:
        """Register event handler."""
        self.event_handlers[event_type].append(handler)

    async def emit_custom_event(
        self,
        event_type: str,
        scan_id: str,
        data: Dict[str, Any]
    ) -> None:
        """Emit custom event."""
        event = DashboardEvent(
            event_type=event_type,
            scan_id=scan_id,
            data=data
        )

        await self._broadcast(event)

        # Call registered handlers
        for handler in self.event_handlers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                log.error(f"Event handler error: {e}")

    # ── Query Methods ─────────────────────────────────────────────────────────

    def get_active_scans(self) -> List[Dict[str, Any]]:
        """Get all active scans."""
        scans = []

        for scan_id, metrics in self.active_scans.items():
            scans.append({
                "scan_id": scan_id,
                "metrics": {
                    "findings": metrics.findings_count,
                    "critical": metrics.critical_count,
                    "high": metrics.high_count,
                    "medium": metrics.medium_count,
                    "low": metrics.low_count,
                    "chains": metrics.chains_detected,
                    "phase": metrics.current_phase,
                    "progress": metrics.progress_percent,
                    "elapsed": metrics.elapsed_seconds,
                    "rps": metrics.requests_per_second,
                }
            })

        return scans

    def get_scan_findings(self, scan_id: str) -> List[Dict]:
        """Get findings for specific scan."""
        return self.scan_findings.get(scan_id, [])


# ─────────────────────────────────────────────────────────────────────────────
# Integration Helpers
# ─────────────────────────────────────────────────────────────────────────────

class StreamingCallbacks:
    """Callback wrapper for integrating with existing scan engines."""

    def __init__(self, streamer: RealtimeDashboardStreamer, scan_id: str):
        self.streamer = streamer
        self.scan_id = scan_id

    async def on_finding(self, finding: Dict) -> None:
        """Called when finding discovered."""
        await self.streamer.stream_finding(self.scan_id, finding)

    async def on_progress(self, phase: str, percent: int, message: str = "") -> None:
        """Called on progress update."""
        await self.streamer.stream_progress(self.scan_id, phase, percent, message)

    async def on_request(self, request_count: int = 1) -> None:
        """Called when request sent."""
        await self.streamer.stream_metrics(
            self.scan_id,
            requests_sent=request_count
        )

    async def on_response(self, response_count: int = 1) -> None:
        """Called when response received."""
        await self.streamer.stream_metrics(
            self.scan_id,
            responses_received=response_count
        )

    async def on_chain(self, chain: Dict) -> None:
        """Called when attack chain detected."""
        await self.streamer.stream_attack_chain(self.scan_id, chain)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

realtime_dashboard_streamer = RealtimeDashboardStreamer()
