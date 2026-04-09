"""
event_driven_engine.py — Event-Driven Execution Engine

Orchestrates the core autonomous loop:

  Graph Update  →  Brain Decision  →  Agent Dispatch  →  Finding Integration  →  repeat

This engine:
  1. Subscribes to EventBus events (NEW_TARGET, NEW_ENDPOINT, NEW_PARAMETER, etc.)
  2. Routes events into the AttackGraphBrain (node integration)
  3. Polls the brain for next actions and dispatches to AgentExecutionFabric
  4. Feeds agent findings back into the brain
  5. Drives the continuous loop until no new paths or max depth reached

Event routing table:
  NEW_TARGET          → brain.add_target()  + rescore
  NEW_ENDPOINT        → brain.integrate_node(URL/API_ENDPOINT)
  NEW_PARAMETER       → brain.integrate_node(PARAMETER)
  NEW_API             → brain.integrate_node(API_ENDPOINT)
  NEW_VULNERABILITY   → brain.integrate_finding()
  SCAN_PROGRESS_UPDATE → rescore + loop iteration
  EXPLOIT_ATTEMPTED   → brain.mark_tested()
  OSINT_RESULT        → brain.integrate_node(SUBDOMAIN/SERVICE)
  CHAIN_DETECTED      → log + emit AGENT_STATUS
  LEARNING_UPDATE     → no-op (informational)
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("event_driven_engine")


# ── Loop config ────────────────────────────────────────────────────────────────

@dataclass
class LoopConfig:
    # How often to poll brain for next actions (seconds)
    dispatch_interval_s: float = 1.0
    # How often to re-score the full graph (seconds)
    rescore_interval_s:  float = 30.0
    # Maximum concurrent agent tasks
    max_concurrent:      int   = 8
    # Stop if no new decisions for this many seconds (0 = never stop)
    idle_timeout_s:      float = 0.0
    # Maximum loop iterations (0 = unlimited)
    max_iterations:      int   = 0
    # Maximum graph traversal depth
    max_depth:           int   = 10
    # Whether to auto-start fabric workers
    auto_start_fabric:   bool  = True


@dataclass
class EngineStatus:
    running:        bool
    iterations:     int
    events_received: int
    nodes_fed:      int
    actions_sent:   int
    findings_fed:   int
    last_event_at:  float
    last_dispatch_at: float
    uptime_s:       float
    targets:        List[str]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ── Main engine ────────────────────────────────────────────────────────────────

class EventDrivenEngine:
    """
    Ties together EventBus + AttackGraphBrain + AgentExecutionFabric
    into a continuous autonomous attack loop.
    """

    def __init__(self, config: Optional[LoopConfig] = None) -> None:
        self._config = config or LoopConfig()

        # Core singletons (lazy)
        self._brain   = None
        self._bus     = None
        self._fabric  = None

        # State
        self._running      = False
        self._started_at   = 0.0
        self._lock         = threading.RLock()
        self._loop_thread: Optional[threading.Thread] = None
        self._bus_sub_thread: Optional[threading.Thread] = None

        # Counters
        self._iterations       = 0
        self._events_received  = 0
        self._nodes_fed        = 0
        self._actions_sent     = 0
        self._findings_fed     = 0
        self._last_event_at    = 0.0
        self._last_dispatch_at = 0.0
        self._targets: Set[str] = set()

        # Asyncio event loop for async dispatch (runs in background thread)
        self._aio_loop: Optional[asyncio.AbstractEventLoop] = None
        self._aio_thread: Optional[threading.Thread] = None

    # ── Lazy accessors ────────────────────────────────────────────────────────

    def _get_brain(self):
        if self._brain is None:
            from oneinfinity.attack_graph_brain import get_brain
            self._brain = get_brain()
        return self._brain

    def _get_bus(self):
        if self._bus is None:
            from oneinfinity.event_bus import get_bus
            self._bus = get_bus()
        return self._bus

    def _get_fabric(self):
        if self._fabric is None:
            from oneinfinity.swarm.agent_execution_fabric import get_fabric
            self._fabric = get_fabric()
        return self._fabric

    # ── Start / stop ──────────────────────────────────────────────────────────

    def start(self, targets: List[str]) -> None:
        with self._lock:
            if self._running:
                for t in targets:
                    self._add_target(t)
                return
            self._running    = True
            self._started_at = time.time()
            self._targets    = set(targets)

        # Start asyncio loop for fabric
        self._aio_loop = asyncio.new_event_loop()
        self._aio_thread = threading.Thread(
            target=self._aio_loop.run_forever,
            daemon=True, name="ede-aio",
        )
        self._aio_thread.start()

        # Start event bus subscription thread
        self._bus_sub_thread = threading.Thread(
            target=self._bus_subscriber_loop,
            daemon=True, name="ede-bus",
        )
        self._bus_sub_thread.start()

        # Start main dispatch loop
        self._loop_thread = threading.Thread(
            target=self._main_loop,
            daemon=True, name="ede-main",
        )
        self._loop_thread.start()

        # Initialise brain
        brain = self._get_brain()
        brain.start(targets)
        brain.set_finding_callback(self._on_fabric_finding)

        # Start fabric
        if self._config.auto_start_fabric:
            fabric = self._get_fabric()
            fabric.start(max_workers=self._config.max_concurrent)

        log.info("EventDrivenEngine started for targets: %s", targets)

    def stop(self) -> None:
        with self._lock:
            self._running = False
        try:
            self._get_brain().stop()
        except Exception:
            pass
        try:
            if self._aio_loop and self._aio_loop.is_running():
                self._aio_loop.call_soon_threadsafe(self._aio_loop.stop)
        except Exception:
            pass
        log.info("EventDrivenEngine stopped.")

    def add_target(self, target: str) -> None:
        with self._lock:
            self._targets.add(target)
        self._add_target(target)

    def _add_target(self, target: str) -> None:
        self._get_brain().add_target(target)
        self._publish_event("NEW_TARGET", {"target": target, "domain": target})

    # ── Bus subscription loop ─────────────────────────────────────────────────

    def _bus_subscriber_loop(self) -> None:
        """Poll bus ring buffer and route events into the brain."""
        bus = self._get_bus()
        last_seen: float = time.time() - 5.0  # catch recent events

        while self._running:
            try:
                events = bus.recent(limit=200)
                for ev in events:
                    ts = ev.get("timestamp", 0)
                    if ts <= last_seen:
                        continue
                    last_seen = max(last_seen, ts)
                    self._route_event(ev)
            except Exception as exc:
                log.debug("Bus poll error: %s", exc)
            time.sleep(0.5)

    def _route_event(self, ev: dict) -> None:
        """Route a bus event into the graph brain."""
        et   = ev.get("event_type", "")
        data = ev.get("data") or {}
        with self._lock:
            self._events_received += 1
            self._last_event_at = time.time()

        brain = self._get_brain()

        if et == "NEW_TARGET":
            target = data.get("target") or data.get("domain", "")
            if target:
                brain.add_target(target)

        elif et in ("NEW_ENDPOINT", "NEW_URL"):
            url  = data.get("url") or data.get("endpoint", "")
            if url:
                props = {"url": url, "domain": data.get("target", url)}
                node_type = "API_ENDPOINT" if "/api" in url.lower() else "URL"
                brain.integrate_node(node_type, url, target=data.get("target", ""), properties=props)
                with self._lock:
                    self._nodes_fed += 1

        elif et == "NEW_PARAMETER":
            param  = data.get("parameter") or data.get("name", "")
            url    = data.get("url", "")
            if param:
                label = f"{param}@{url}" if url else param
                brain.integrate_node("PARAMETER", label,
                                      target=data.get("target", ""),
                                      properties={"name": param, "url": url})
                with self._lock:
                    self._nodes_fed += 1

        elif et in ("NEW_API", "API_ENDPOINT"):
            endpoint = data.get("endpoint") or data.get("url", "")
            if endpoint:
                brain.integrate_node("API_ENDPOINT", endpoint,
                                      target=data.get("target", ""),
                                      properties=dict(data))
                with self._lock:
                    self._nodes_fed += 1

        elif et == "NEW_VULNERABILITY":
            node_id  = data.get("node_id", "")
            agent    = data.get("agent_type", "unknown")
            if node_id:
                brain.integrate_finding(node_id, agent, data)
            else:
                # No node_id — create a vulnerability node
                label = data.get("vuln_type") or data.get("name", "vulnerability")
                brain.integrate_node("VULNERABILITY", label,
                                      target=data.get("target", ""),
                                      properties=dict(data),
                                      exploitable=True,
                                      severity=data.get("severity", "medium"))
                with self._lock:
                    self._nodes_fed += 1

        elif et == "EXPLOIT_ATTEMPTED":
            node_id    = data.get("node_id", "")
            agent_type = data.get("agent_type", "exploit")
            if node_id:
                brain.mark_tested(node_id, agent_type)

        elif et == "OSINT_RESULT":
            subdomain = data.get("subdomain") or data.get("host", "")
            if subdomain:
                brain.integrate_node("SUBDOMAIN", subdomain,
                                      target=data.get("target", subdomain),
                                      properties=dict(data))
                with self._lock:
                    self._nodes_fed += 1

        elif et == "SCAN_PROGRESS_UPDATE":
            # Trigger a rescore so new nodes get prioritized
            phase = data.get("phase", "")
            if phase in ("recon", "scan", "exploit"):
                brain.rescore_graph(data.get("target"))

    # ── Main dispatch loop ────────────────────────────────────────────────────

    def _main_loop(self) -> None:
        """Main autonomous loop: brain → decision → dispatch → repeat."""
        brain      = self._get_brain()
        last_rescore = time.time()
        last_idle  = time.time()
        iterations = 0

        while self._running:
            try:
                # Periodic rescore
                if time.time() - last_rescore > self._config.rescore_interval_s:
                    brain.rescore_graph()
                    last_rescore = time.time()

                # Get next decisions (batch up to max_concurrent)
                dispatched_this_iter = 0
                for _ in range(self._config.max_concurrent):
                    for target in list(self._targets):
                        decision = brain.make_decision(target)
                        if decision:
                            self._dispatch_decision(decision)
                            dispatched_this_iter += 1
                            last_idle = time.time()

                if dispatched_this_iter > 0:
                    iterations += 1
                    with self._lock:
                        self._iterations += 1
                    self._publish_event("SCAN_PROGRESS_UPDATE", {
                        "phase": "graph_loop",
                        "iteration": iterations,
                        "dispatched": dispatched_this_iter,
                    })

                # Idle timeout check
                if (self._config.idle_timeout_s > 0
                        and time.time() - last_idle > self._config.idle_timeout_s):
                    log.info("EDE idle timeout reached after %d iterations", iterations)
                    break

                # Max iterations check
                if self._config.max_iterations and iterations >= self._config.max_iterations:
                    log.info("EDE max iterations (%d) reached", iterations)
                    break

            except Exception as exc:
                log.warning("Main loop error: %s", exc)

            time.sleep(self._config.dispatch_interval_s)

        self._running = False
        log.info("EventDrivenEngine main loop exited after %d iterations", iterations)

    def _dispatch_decision(self, decision) -> None:
        """Send a brain decision to the agent execution fabric."""
        try:
            fabric  = self._get_fabric()
            action  = decision.action
            task_id = fabric.submit_task(
                agent_type  = action.agent_type,
                node_id     = action.node_id,
                node_label  = action.node_label,
                node_type   = action.node_type,
                target      = action.target,
                context     = action.context,
                priority    = action.priority,
                on_complete = self._on_fabric_finding,
            )
            with self._lock:
                self._actions_sent += 1
                self._last_dispatch_at = time.time()
            log.debug("Dispatched %s agent for node %s (task %s)",
                      action.agent_type, action.node_label, task_id)
        except Exception as exc:
            log.warning("Dispatch failed: %s", exc)

    def _on_fabric_finding(self, finding: dict) -> None:
        """Callback from fabric when an agent completes a task."""
        try:
            node_id    = finding.get("node_id", "")
            agent_type = finding.get("agent_type", "unknown")
            brain      = self._get_brain()
            if node_id:
                brain.integrate_finding(node_id, agent_type, finding)
            with self._lock:
                self._findings_fed += 1
            # Persist to SQLite so get_findings() and graph_vuln_update can see it
            try:
                from oneinfinity.findings.result_ingestion_engine import get_ingestion_engine, RawResult
                get_ingestion_engine().ingest(RawResult(
                    scan_id=finding.get("scan_id", "agent_direct"),
                    source=agent_type,
                    raw=finding,
                ))
            except Exception as exc:
                log.debug("_on_fabric_finding: RIE ingest failed: %s", exc)
            # Publish finding to bus
            self._publish_event("NEW_VULNERABILITY", finding)
        except Exception as exc:
            log.debug("Finding callback error: %s", exc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _publish_event(self, event_type: str, data: dict) -> None:
        try:
            from oneinfinity.event_bus import get_bus, EventType
            try:
                et = EventType(event_type)
            except ValueError:
                et = EventType.AGENT_STATUS
            get_bus().publish(event_type=et, source="event_driven_engine", data=data)
        except Exception:
            pass

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> EngineStatus:
        with self._lock:
            return EngineStatus(
                running          = self._running,
                iterations       = self._iterations,
                events_received  = self._events_received,
                nodes_fed        = self._nodes_fed,
                actions_sent     = self._actions_sent,
                findings_fed     = self._findings_fed,
                last_event_at    = self._last_event_at,
                last_dispatch_at = self._last_dispatch_at,
                uptime_s         = time.time() - self._started_at if self._started_at else 0.0,
                targets          = sorted(self._targets),
            )


# ── Singleton ──────────────────────────────────────────────────────────────────

_engine: Optional[EventDrivenEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> EventDrivenEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = EventDrivenEngine()
    return _engine
