"""
intelligence_daemon.py — Always-Running Autonomous Intelligence Daemon

Transforms One&Infinity from a pipeline-based scanner into an event-driven
autonomous security research platform.

Architecture
------------
One `IntelligenceDaemon` instance runs as a background daemon thread.
Inside it, nine `WorkerEngine` subclasses each listen to specific EventBus
topics and respond automatically — no explicit CLI commands required.

Nine built-in capabilities
--------------------------
1. HypothesisWorker        — continuous vuln hypothesis generation
2. GraphExpansionWorker    — real-time attack graph expansion
3. ExploitChainWorker      — background exploit chaining
4. PayloadMutationWorker   — autonomous payload mutation + retry
5. TrafficReplayWorker     — auto traffic replay (auth / API / sensitive)
6. BusinessLogicWorker     — workflow detection + multi-step logic attacks
7. OSINTExpansionWorker    — subdomain / related domain / cloud asset discovery
8. SwarmWorker             — parallel specialized agent execution
9. LearningWorker          — real-time KB update after every finding

Usage
-----
    from oneinfinity.intelligence_daemon import get_daemon, DaemonConfig
    daemon = get_daemon()
    daemon.start(target="example.com")
    # ... runs indefinitely in background ...
    daemon.stop()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from oneinfinity.event_bus import EventBus, BusEvent, EventType, Priority, get_bus

log = logging.getLogger("oneinfinity.daemon")


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class WorkerConfig:
    enabled: bool = True
    cooldown_s: float = 30.0      # min seconds between runs per target
    max_concurrent: int = 3       # max parallel tasks inside this worker
    priority: Priority = Priority.NORMAL
    extra: dict = field(default_factory=dict)


@dataclass
class DaemonConfig:
    """Per-capability configuration passed to IntelligenceDaemon."""
    hypothesis:     WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=20))
    graph_expand:   WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=10))
    exploit_chain:  WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=15))
    payload_mutate: WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=5))
    traffic_replay: WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=60))
    biz_logic:      WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=45))
    osint_expand:   WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=120))
    swarm:          WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=30))
    learning:       WorkerConfig = field(default_factory=lambda: WorkerConfig(cooldown_s=2))

    def to_dict(self) -> dict:
        return {k: asdict(v) for k, v in self.__dict__.items()}


# ── Worker state ──────────────────────────────────────────────────────────────

class WorkerStatus(str, Enum):
    IDLE     = "idle"
    RUNNING  = "running"
    SLEEPING = "sleeping"
    DISABLED = "disabled"
    ERROR    = "error"


@dataclass
class WorkerState:
    name: str
    status: WorkerStatus = WorkerStatus.IDLE
    runs: int = 0
    events_processed: int = 0
    findings: int = 0
    errors: int = 0
    last_run: float = 0.0
    current_target: str = ""
    current_phase: str = ""
    log_tail: list[str] = field(default_factory=list)

    def log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.log_tail.append(entry)
        if len(self.log_tail) > 40:
            self.log_tail.pop(0)
        log.info("[%s] %s", self.name, msg)

    def to_dict(self) -> dict:
        return {
            "name":              self.name,
            "status":            self.status.value,
            "runs":              self.runs,
            "events_processed":  self.events_processed,
            "findings":          self.findings,
            "errors":            self.errors,
            "last_run":          self.last_run,
            "current_target":    self.current_target,
            "current_phase":     self.current_phase,
            "log_tail":          self.log_tail[-10:],
        }


# ── Base worker ───────────────────────────────────────────────────────────────

class WorkerEngine(ABC):
    """
    Base class for all nine intelligence workers.

    Each worker:
    - Subscribes to a set of EventBus topics
    - Implements `handle(event)` as an async coroutine
    - Publishes results back to the bus
    - Respects cooldown per target to avoid hammering the same host
    """

    SUBSCRIPTIONS: list[EventType] = []   # override in subclass

    def __init__(self, bus: EventBus, config: WorkerConfig, loop: asyncio.AbstractEventLoop):
        self._bus    = bus
        self._config = config
        self._loop   = loop
        self.state   = WorkerState(name=self.__class__.__name__)
        self._semaphore: Optional[asyncio.Semaphore] = None
        # {target: last_triggered_ts}
        self._cooldowns: dict[str, float] = {}
        # Active scan targets set externally
        self._targets: set[str] = set()
        self._correlation_id = ""

    def attach(self, targets: set[str], correlation_id: str = ""):
        """Called by daemon to inject active targets after init."""
        self._targets = targets
        self._correlation_id = correlation_id

    def register(self):
        """Subscribe to all declared event types."""
        if not self._config.enabled:
            self.state.status = WorkerStatus.DISABLED
            return
        for et in self.SUBSCRIPTIONS:
            self._bus.on(et, self._on_event)
        self._semaphore = asyncio.Semaphore(self._config.max_concurrent)

    def _on_event(self, event: BusEvent):
        """Sync bridge called by the bus; schedules the async handler."""
        if not self._config.enabled:
            return
        target = event.data.get("target", "")
        if self._throttled(target):
            return
        asyncio.run_coroutine_threadsafe(self._guarded_handle(event), self._loop)

    async def _guarded_handle(self, event: BusEvent):
        assert self._semaphore is not None
        async with self._semaphore:
            target = event.data.get("target", "")
            self.state.events_processed += 1
            self.state.status = WorkerStatus.RUNNING
            self.state.current_target = target
            try:
                await self.handle(event)
                self.state.runs += 1
                self.state.last_run = time.time()
                self._cooldowns[target] = time.time()
            except Exception as exc:
                self.state.errors += 1
                self.state.status = WorkerStatus.ERROR
                log.exception("[%s] Error handling %s: %s", self.state.name, event.event_type, exc)
            finally:
                self.state.status = WorkerStatus.IDLE

    def _throttled(self, target: str) -> bool:
        last = self._cooldowns.get(target, 0.0)
        return (time.time() - last) < self._config.cooldown_s

    def _publish(self, event_type: EventType, data: dict, source: str = ""):
        self._bus.publish(
            event_type, data,
            source=source or self.state.name,
            priority=self._config.priority,
            correlation_id=self._correlation_id,
        )

    @abstractmethod
    async def handle(self, event: BusEvent): ...


# ── 1. Hypothesis Worker ──────────────────────────────────────────────────────

class HypothesisWorker(WorkerEngine):
    """
    Generates vulnerability theories from AppModel + TechProfile + Attack Graph.
    Publishes HYPOTHESIS_CREATED events for each theory; downstream workers
    pick them up and dispatch tests.
    """

    SUBSCRIPTIONS = [EventType.NEW_TARGET, EventType.NEW_ENDPOINT, EventType.NEW_PARAMETER]

    async def handle(self, event: BusEvent):
        target = event.data.get("target", event.data.get("url", ""))
        if not target:
            return
        self.state.current_phase = "generating_hypotheses"
        self.state.log(f"Generating hypotheses for: {target}")

        theories = await self._loop.run_in_executor(None, self._generate, event)
        for t in theories:
            self.state.findings += 1
            self._publish(EventType.HYPOTHESIS_CREATED, t, source="hypothesis_worker")
            self.state.log(f"  → {t['vuln_type']} on {t['endpoint'][:60]} (conf={t['confidence']:.0%})")

    def _generate(self, event: BusEvent) -> list[dict]:
        theories = []
        try:
            from oneinfinity.vulnerability_theory_engine import VulnerabilityTheoryEngine
            from oneinfinity.application_intelligence import AppIntelligence
            target = event.data.get("target", event.data.get("url", ""))
            domain = _to_domain(target)
            app = AppIntelligence()
            model = app.build_model(domain)
            engine = VulnerabilityTheoryEngine()
            theory_set = engine.generate_theories(model)
            theories = [t.to_dict() for t in theory_set.theories[:20]]  # top 20
        except Exception as exc:
            log.debug("[HypothesisWorker] generate failed: %s", exc)
            # Fallback: rule-based quick theories from event data
            url = event.data.get("url", event.data.get("target", ""))
            params = event.data.get("params", [])
            for p in (params or ["q", "id", "search", "page"])[:5]:
                theories.append({
                    "theory_id":    str(uuid.uuid4())[:8],
                    "vuln_type":    _param_to_vuln(p),
                    "endpoint":     url,
                    "parameters":   [p],
                    "confidence":   0.5,
                    "severity":     "medium",
                    "reasoning":    f"Parameter '{p}' is commonly injectable",
                    "attack_hints": ["fuzz with common payloads", "check error messages"],
                    "tags":         ["auto-generated"],
                    "status":       "pending",
                })
        return theories


# ── 2. Graph Expansion Worker ─────────────────────────────────────────────────

class GraphExpansionWorker(WorkerEngine):
    """
    Listens for new vulnerabilities / graph nodes and expands the attack graph:
    - Adds new paths from the node
    - Assigns agents to promising paths
    - Emits NEW_GRAPH_NODE for downstream workers
    """

    SUBSCRIPTIONS = [EventType.NEW_VULNERABILITY, EventType.NEW_GRAPH_NODE, EventType.NEW_ENDPOINT]

    async def handle(self, event: BusEvent):
        self.state.current_phase = "expanding_graph"
        target = event.data.get("target", "")
        self.state.log(f"Expanding attack graph for {target}")

        result = await self._loop.run_in_executor(None, self._expand, event)
        if result:
            self._publish(EventType.NEW_GRAPH_NODE, result, source="graph_expansion_worker")
            self.state.findings += 1

    def _expand(self, event: BusEvent) -> dict | None:
        try:
            from oneinfinity.attack_graph_core.graph_engine import get_engine, NodeType, EdgeType
            g = get_engine()
            d = event.data
            vuln_type = d.get("vuln_type", d.get("label", "unknown"))
            target    = d.get("target", "")

            node = g.add_node(
                NodeType.VULNERABILITY,
                label=vuln_type,
                properties={
                    "target":   target,
                    "endpoint": d.get("endpoint", d.get("url", "")),
                    "severity": d.get("severity", "info"),
                    "source":   "intelligence_daemon",
                    "auto":     True,
                },
                severity=d.get("severity", "info"),
            )

            # Find attack paths from this node
            from oneinfinity.attack_graph_core.graph_query_engine import GraphQueryEngine
            qe = GraphQueryEngine(g)
            paths = qe.find_attack_paths(source_node_id=node.id, max_depth=4)

            self.state.log(f"  → {len(paths)} new attack paths from {vuln_type}")
            return {
                "node_id":   node.id,
                "node_type": "vulnerability",
                "label":     vuln_type,
                "target":    target,
                "paths":     len(paths),
            }
        except Exception as exc:
            log.debug("[GraphExpansionWorker] expand failed: %s", exc)
            return None


# ── 3. Exploit Chain Worker ───────────────────────────────────────────────────

class ExploitChainWorker(WorkerEngine):
    """
    Continuously attempts exploit chaining whenever a new vulnerability arrives.
    Checks all 12+ known chain patterns from chain_patterns.py.
    Publishes CHAIN_DETECTED events.
    """

    SUBSCRIPTIONS = [EventType.NEW_VULNERABILITY]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._seen_vulns: dict[str, set[str]] = {}  # target → {vuln_types}

    async def handle(self, event: BusEvent):
        d = event.data
        target   = d.get("target", "")
        vtype    = d.get("vuln_type", "")
        self.state.current_phase = "chaining"
        self.state.log(f"Checking chain opportunities: {vtype} on {target}")

        if target not in self._seen_vulns:
            self._seen_vulns[target] = set()
        self._seen_vulns[target].add(vtype)

        chains = await self._loop.run_in_executor(
            None, self._find_chains, target, self._seen_vulns[target]
        )
        for chain in chains:
            self.state.findings += 1
            self._publish(EventType.CHAIN_DETECTED, chain, source="exploit_chain_worker")
            self.state.log(f"  ⛓ Chain found: {chain['chain_name']} (CVSS={chain['cvss']:.1f})")

    def _find_chains(self, target: str, vuln_types: set[str]) -> list[dict]:
        chains = []
        try:
            from oneinfinity.exploit_chains.chain_patterns import CHAIN_PATTERNS
            for pattern in CHAIN_PATTERNS:
                required = set(r.lower() for r in pattern.requires)
                present  = set(v.lower() for v in vuln_types)
                if required.issubset(present):
                    chains.append({
                        "chain_name":  pattern.chain_type,
                        "steps":       pattern.requires,
                        "target":      target,
                        "cvss":        9.0 if pattern.escalated_severity == "critical" else 7.5,
                        "confirmed":   False,
                        "description": pattern.description_template,
                        "confidence":  pattern.confidence,
                    })
        except Exception as exc:
            log.debug("[ExploitChainWorker] chain detection failed: %s", exc)
        return chains


# ── 4. Payload Mutation Worker ────────────────────────────────────────────────

class PayloadMutationWorker(WorkerEngine):
    """
    Listens for EXPLOIT_ATTEMPTED events where success=False.
    Applies mutation strategies (encoding, case-variation, WAF bypass, etc.)
    and re-publishes PAYLOAD_MUTATED for retry.
    """

    SUBSCRIPTIONS = [EventType.EXPLOIT_ATTEMPTED]

    STRATEGIES = ["base64", "unicode", "html_entity", "double_encode",
                  "case_swap", "comment_insertion", "null_byte", "newline"]

    async def handle(self, event: BusEvent):
        d = event.data
        if d.get("success", True):
            return   # only mutate failed payloads

        payload   = d.get("payload", "")
        vuln_type = d.get("vuln_type", "")
        endpoint  = d.get("endpoint", "")
        target    = d.get("target", "")

        if not payload:
            return

        self.state.current_phase = "mutating_payloads"
        self.state.log(f"Mutating payload for {vuln_type} on {endpoint[:50]}")

        mutants = await self._loop.run_in_executor(None, self._mutate, payload, vuln_type)
        for mutant, strategy in mutants[:8]:
            self._publish(EventType.PAYLOAD_MUTATED, {
                "original":  payload,
                "mutant":    mutant,
                "strategy":  strategy,
                "vuln_type": vuln_type,
                "endpoint":  endpoint,
                "target":    target,
                "attempt":   d.get("attempt", 0) + 1,
            }, source="payload_mutation_worker")
            self.state.findings += 1

    def _mutate(self, payload: str, vuln_type: str) -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []
        try:
            from oneinfinity.exploit_generator import ExploitGenerator
            gen = ExploitGenerator()
            variants = gen.mutate(payload, vuln_type, strategies=self.STRATEGIES)
            results = [(v, s) for v, s in zip(variants, self.STRATEGIES)]
        except Exception:
            # Fallback built-in mutations
            import base64, urllib.parse
            results = [
                (base64.b64encode(payload.encode()).decode(), "base64"),
                (urllib.parse.quote(payload, safe=""), "url_encode"),
                (payload.replace("<", "＜").replace(">", "＞"), "unicode_fullwidth"),
                (payload.replace("'", "\\'"), "escape_quotes"),
                (payload.upper(), "uppercase"),
                (payload.lower(), "lowercase"),
                (payload.replace(" ", "/**/"), "comment_space"),
                (payload + "\x00", "null_byte"),
            ]
        return results[:8]


# ── 5. Traffic Replay Worker ──────────────────────────────────────────────────

class TrafficReplayWorker(WorkerEngine):
    """
    Automatically replays auth requests, API calls, and sensitive endpoints
    found during discovery.  Looks for differences that indicate auth bypass,
    IDOR, or parameter tampering opportunities.
    """

    SUBSCRIPTIONS = [EventType.NEW_API, EventType.NEW_ENDPOINT]

    SENSITIVE_PATTERNS = [
        "/api/", "/v1/", "/v2/", "/v3/",
        "/user", "/account", "/admin", "/profile",
        "/payment", "/checkout", "/order", "/transfer",
        "/auth", "/login", "/token", "/session",
        "/export", "/download", "/file", "/upload",
    ]

    async def handle(self, event: BusEvent):
        d     = event.data
        url   = d.get("url", "")
        if not any(p in url.lower() for p in self.SENSITIVE_PATTERNS):
            return   # only replay sensitive endpoints

        target = d.get("target", "")
        self.state.current_phase = "traffic_replay"
        self.state.log(f"Replaying: {url[:70]}")

        result = await self._loop.run_in_executor(None, self._replay, d)
        if result and result.get("anomaly"):
            self._publish(EventType.NEW_VULNERABILITY, {
                "vuln_type": result["anomaly_type"],
                "severity":  "medium",
                "endpoint":  url,
                "target":    target,
                "evidence":  result,
                "source":    "traffic_replay",
                "auto":      True,
            }, source="traffic_replay_worker")
            self.state.findings += 1

    def _replay(self, data: dict) -> dict | None:
        try:
            from oneinfinity.traffic_replay_engine import TrafficReplayEngine
            engine = TrafficReplayEngine()
            url    = data.get("url", "")
            method = data.get("method", "GET")
            headers= data.get("headers", {})
            body   = data.get("body", "")

            # Replay 1: with different auth header (none vs original)
            result = engine.replay(url, method=method, headers=headers, body=body)
            result_noauth = engine.replay(url, method=method,
                                          headers={k: v for k, v in headers.items()
                                                   if "auth" not in k.lower()},
                                          body=body)

            if result and result_noauth:
                # Check if removing auth changes the response significantly
                if (result.status_code == result_noauth.status_code and
                        result.status_code in (200, 201)):
                    return {"anomaly": True, "anomaly_type": "Auth Bypass",
                            "url": url, "detail": "Auth header not required"}
        except Exception as exc:
            log.debug("[TrafficReplayWorker] replay failed: %s", exc)
        return None


# ── 6. Business Logic Worker ──────────────────────────────────────────────────

class BusinessLogicWorker(WorkerEngine):
    """
    Detects application workflows automatically, generates multi-step logic
    attack sequences, and dispatches them.
    """

    SUBSCRIPTIONS = [EventType.NEW_TARGET, EventType.NEW_API, EventType.WORKFLOW_DETECTED]

    WORKFLOW_SIGNALS = [
        ("checkout", ["cart", "checkout", "payment", "confirm", "order"]),
        ("auth",     ["login", "signup", "register", "oauth", "token"]),
        ("transfer", ["transfer", "send", "withdraw", "payment", "wire"]),
        ("reset",    ["reset", "forgot", "recover", "password"]),
        ("profile",  ["profile", "account", "settings", "update"]),
    ]

    async def handle(self, event: BusEvent):
        d      = event.data
        target = d.get("target", "")
        url    = d.get("url", "")
        self.state.current_phase = "workflow_detection"

        # Detect workflow from URL patterns
        if event.event_type == EventType.NEW_API:
            for wf_name, signals in self.WORKFLOW_SIGNALS:
                if any(s in url.lower() for s in signals):
                    self.state.log(f"Workflow detected: {wf_name} on {target}")
                    self._publish(EventType.WORKFLOW_DETECTED, {
                        "workflow_id":   f"{wf_name}_{_short_hash(target)}",
                        "workflow_type": wf_name,
                        "target":        target,
                        "url":           url,
                        "auto":          True,
                    }, source="biz_logic_worker")
                    return

        # Run business logic attacks on detected workflow
        if event.event_type == EventType.WORKFLOW_DETECTED:
            wf_type = d.get("workflow_type", "")
            self.state.log(f"Running logic attacks on workflow: {wf_type}")
            findings = await self._loop.run_in_executor(None, self._attack, d)
            for f in findings:
                self.state.findings += 1
                self._publish(EventType.NEW_VULNERABILITY, f, source="biz_logic_worker")

    def _attack(self, data: dict) -> list[dict]:
        findings = []
        try:
            from oneinfinity.workflow_simulation_engine import WorkflowSimulationEngine
            from oneinfinity.business_logic_attack_engine import BusinessLogicAttackEngine
            target = data.get("target", "")
            wf_type = data.get("workflow_type", "checkout")

            engine = WorkflowSimulationEngine(base_url=f"https://{_to_domain(target)}")
            import asyncio as _a
            results = _a.run(engine.generate_and_run_attacks(wf_type))
            for r in (results or []):
                if getattr(r, "vulnerability_found", False):
                    findings.append({
                        "vuln_type": getattr(r, "category", "Business Logic"),
                        "severity":  getattr(r, "severity", "medium"),
                        "title":     getattr(r, "title", "Business Logic Flaw"),
                        "target":    target,
                        "endpoint":  data.get("url", ""),
                        "auto":      True,
                    })
        except Exception as exc:
            log.debug("[BusinessLogicWorker] attack failed: %s", exc)
        return findings


# ── 7. OSINT Expansion Worker ─────────────────────────────────────────────────

class OSINTExpansionWorker(WorkerEngine):
    """
    Automatically expands target scope: discovers subdomains, related domains,
    cloud assets, and adds them to the scan queue by publishing NEW_TARGET events.
    """

    SUBSCRIPTIONS = [EventType.NEW_TARGET]

    async def handle(self, event: BusEvent):
        target = event.data.get("target", "")
        domain = _to_domain(target)
        if not domain:
            return

        self.state.current_phase = "osint_expansion"
        self.state.log(f"OSINT expansion for: {domain}")

        discovered = await self._loop.run_in_executor(None, self._collect, domain)
        for sub in discovered:
            if sub != domain:
                self.state.findings += 1
                self._publish(EventType.NEW_TARGET, {
                    "target":      sub,
                    "parent":      domain,
                    "source":      "osint_expansion",
                    "auto":        True,
                }, source="osint_expansion_worker")

        self.state.log(f"  → {len(discovered)} assets discovered for {domain}")

        # Also publish OSINT_RESULT with full data
        self._publish(EventType.OSINT_RESULT, {
            "target":     domain,
            "assets":     discovered,
            "count":      len(discovered),
        }, source="osint_expansion_worker")

    def _collect(self, domain: str) -> list[str]:
        assets: list[str] = []
        try:
            from oneinfinity.recon.osint_collector import OSINTCollector
            collector = OSINTCollector()
            result = collector.collect(domain)
            assets = list(set(result.subdomains + result.urls))[:50]
        except Exception:
            # Fallback: DNS brute force with common prefixes
            import socket
            prefixes = ["www", "api", "admin", "mail", "staging", "dev",
                        "test", "beta", "app", "cdn", "static", "blog"]
            for prefix in prefixes:
                sub = f"{prefix}.{domain}"
                try:
                    socket.gethostbyname(sub)
                    assets.append(sub)
                except Exception:
                    pass
        return assets


# ── 8. Swarm Worker ───────────────────────────────────────────────────────────

class SwarmWorker(WorkerEngine):
    """
    Launches parallel specialized security agents (XSS, SQLi, SSRF, IDOR,
    Auth Bypass, Business Logic, Mobile, API Security) whenever a new target
    or endpoint is added.  Agents run concurrently and publish findings as
    NEW_VULNERABILITY events.
    """

    SUBSCRIPTIONS = [EventType.NEW_TARGET, EventType.NEW_ENDPOINT]

    AGENT_TYPES = ["xss", "sqli", "ssrf", "idor", "auth_bypass",
                   "business_logic", "api_security"]

    async def handle(self, event: BusEvent):
        target = event.data.get("target", event.data.get("url", ""))
        if not target:
            return
        self.state.current_phase = "swarm_launch"
        self.state.log(f"Launching swarm agents for: {target[:60]}")

        # Publish AGENT_STATUS for each agent (UI feedback)
        for atype in self.AGENT_TYPES:
            self._publish(EventType.AGENT_STATUS, {
                "agent_type": atype,
                "status":     "launching",
                "target":     target,
                "phase":      "init",
                "auto":       True,
            }, source="swarm_worker")

        findings = await self._loop.run_in_executor(None, self._run_swarm, target)
        for f in findings:
            self.state.findings += 1
            self._publish(EventType.NEW_VULNERABILITY, f, source="swarm_worker")

        self.state.log(f"  → Swarm complete: {len(findings)} findings")

    def _run_swarm(self, target: str) -> list[dict]:
        findings: list[dict] = []
        try:
            from oneinfinity.swarm.agent_swarm_coordinator import AgentSwarmCoordinator
            import asyncio as _a
            coordinator = AgentSwarmCoordinator()
            result = _a.run(coordinator.scan(target, context={"auto": True, "source": "daemon"}))
            if hasattr(result, "findings"):
                for f in (result.findings or []):
                    d = f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else {})
                    d.setdefault("target", target)
                    d.setdefault("auto", True)
                    findings.append(d)
        except Exception as exc:
            log.debug("[SwarmWorker] swarm scan failed: %s", exc)
        return findings


# ── 9. Learning Worker ────────────────────────────────────────────────────────

class LearningWorker(WorkerEngine):
    """
    Updates the Knowledge Base immediately after every successful exploit,
    failed attempt, and pattern discovery.  Also updates MemoryManager
    (evolution.db) for the self-evolving architecture system.
    """

    SUBSCRIPTIONS = [
        EventType.NEW_VULNERABILITY,
        EventType.EXPLOIT_ATTEMPTED,
        EventType.CHAIN_DETECTED,
        EventType.PAYLOAD_MUTATED,
    ]

    async def handle(self, event: BusEvent):
        self.state.current_phase = "learning"
        await self._loop.run_in_executor(None, self._learn, event)
        self.state.findings += 1

    def _learn(self, event: BusEvent):
        d = event.data
        try:
            from oneinfinity.core.learning_repository import get_learning_repo_sync
            kb = get_learning_repo_sync()
            if event.event_type == EventType.NEW_VULNERABILITY:
                sid = d.get("session_id", f"daemon_{int(time.time())}")
                kb.record_finding_sync(sid, {
                    "vuln_type":   d.get("vuln_type", "unknown"),
                    "severity":    d.get("severity", "info"),
                    "cvss_score":  d.get("cvss", 0.0),
                    "endpoint":    d.get("endpoint", ""),
                    "source_tool": d.get("source", "daemon"),
                    "target":      d.get("target", ""),
                }, confirmed=True)
            elif event.event_type == EventType.EXPLOIT_ATTEMPTED:
                kb.record_tool_run_sync(
                    tool_name=d.get("tool", "exploit_engine"),
                    vuln_type=d.get("vuln_type", ""),
                    target_type="web",
                    success=d.get("success", False),
                    findings_count=1 if d.get("success") else 0,
                    duration_s=d.get("duration_s", 0.0),
                )
        except Exception as exc:
            log.debug("[LearningWorker] KB update failed: %s", exc)

        try:
            from oneinfinity.memory_manager import get_memory_manager, AttackPattern, LearningInsight
            mm = get_memory_manager()
            if event.event_type in (EventType.NEW_VULNERABILITY, EventType.EXPLOIT_ATTEMPTED):
                pat = AttackPattern(
                    vuln_type=d.get("vuln_type", ""),
                    target_tech=d.get("tech", ""),
                    payload=str(d.get("payload", ""))[:256],
                    endpoint_pattern=d.get("endpoint", ""),
                    cvss=float(d.get("cvss", 0.0) or 0.0),
                    success_rate=1.0 if d.get("success", True) else 0.0,
                    agent_source=d.get("source", "daemon"),
                )
                mm.upsert_attack_pattern(pat)
            if event.event_type == EventType.CHAIN_DETECTED:
                from oneinfinity.memory_manager import ExploitChainRecord
                chain = ExploitChainRecord(
                    chain_name=d.get("chain_name", "auto_chain"),
                    steps=d.get("steps", []),
                    target=d.get("target", ""),
                    cvss_combined=float(d.get("cvss", 0.0) or 0.0),
                    confirmed=False,
                )
                mm.store_exploit_chain(chain)
            self._publish(EventType.LEARNING_UPDATE, {
                "category":      event.event_type.value,
                "target":        d.get("target", ""),
                "pattern_count": 1,
            }, source="learning_worker")
        except Exception as exc:
            log.debug("[LearningWorker] MemoryManager update failed: %s", exc)


# ── Daemon ────────────────────────────────────────────────────────────────────

class IntelligenceDaemon:
    """
    Always-running autonomous intelligence daemon.

    Creates and manages nine WorkerEngine instances.
    Runs its own asyncio event loop in a daemon thread so it never blocks
    the main application.

    Example
    -------
    daemon = get_daemon()
    daemon.configure(DaemonConfig(osint_expand=WorkerConfig(cooldown_s=300)))
    daemon.start(target="example.com")
    """

    def __init__(self, config: Optional[DaemonConfig] = None, bus: Optional[EventBus] = None):
        self._config  = config or DaemonConfig()
        self._bus     = bus or get_bus()
        self._targets: set[str] = set()
        self._correlation_id = str(uuid.uuid4())[:8]
        self._running = False
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._thread: Optional[threading.Thread] = None
        self._workers: list[WorkerEngine] = []
        self._start_ts: float = 0.0
        self._status: str = "stopped"

        self._init_workers()

    # ── Init ──────────────────────────────────────────────────────────────────

    def _init_workers(self):
        cfg = self._config
        loop = self._loop
        bus  = self._bus
        self._workers = [
            HypothesisWorker    (bus, cfg.hypothesis,     loop),
            GraphExpansionWorker(bus, cfg.graph_expand,   loop),
            ExploitChainWorker  (bus, cfg.exploit_chain,  loop),
            PayloadMutationWorker(bus, cfg.payload_mutate, loop),
            TrafficReplayWorker (bus, cfg.traffic_replay, loop),
            BusinessLogicWorker (bus, cfg.biz_logic,      loop),
            OSINTExpansionWorker(bus, cfg.osint_expand,   loop),
            SwarmWorker         (bus, cfg.swarm,          loop),
            LearningWorker      (bus, cfg.learning,       loop),
        ]

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, target: str = "", targets: list[str] | None = None):
        """Start the daemon and register the given target(s)."""
        if self._running:
            if target:
                self.add_target(target)
            return

        if target:
            self._targets.add(target)
        if targets:
            self._targets.update(targets)

        # Register all workers
        for w in self._workers:
            w.attach(self._targets, self._correlation_id)
            w.register()

        # Start asyncio loop thread
        self._running = True
        self._status  = "running"
        self._start_ts = time.time()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="intelligence-daemon",
            daemon=True,
        )
        self._thread.start()

        # Publish NEW_TARGET for each registered target
        for t in self._targets:
            self._emit_new_target(t)

        log.info("[Daemon] Started. Targets: %s", self._targets)
        return self

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def stop(self):
        if not self._running:
            return
        self._running = False
        self._status  = "stopped"
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        log.info("[Daemon] Stopped.")

    def add_target(self, target: str):
        """Dynamically add a new target while the daemon is running."""
        self._targets.add(target)
        for w in self._workers:
            w._targets = self._targets
        self._emit_new_target(target)

    def remove_target(self, target: str):
        self._targets.discard(target)

    def configure(self, config: DaemonConfig):
        """Hot-reload configuration (re-creates workers)."""
        self._config = config
        for w in self._workers:
            w._config = getattr(config, _worker_cfg_key(w), w._config)

    def enable_worker(self, name: str):
        for w in self._workers:
            if w.state.name.lower().replace("worker", "") in name.lower():
                w._config.enabled = True
                w.state.status = WorkerStatus.IDLE

    def disable_worker(self, name: str):
        for w in self._workers:
            if w.state.name.lower().replace("worker", "") in name.lower():
                w._config.enabled = False
                w.state.status = WorkerStatus.DISABLED

    # ── Status & query ────────────────────────────────────────────────────────

    def status(self) -> dict:
        uptime = time.time() - self._start_ts if self._start_ts else 0
        return {
            "status":          self._status,
            "running":         self._running,
            "uptime_s":        round(uptime, 1),
            "targets":         sorted(self._targets),
            "correlation_id":  self._correlation_id,
            "workers":         [w.state.to_dict() for w in self._workers],
            "bus_stats":       self._bus.stats(),
            "total_findings":  sum(w.state.findings for w in self._workers),
            "total_errors":    sum(w.state.errors for w in self._workers),
        }

    def worker_states(self) -> list[dict]:
        return [w.state.to_dict() for w in self._workers]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _emit_new_target(self, target: str):
        self._bus.publish(
            EventType.NEW_TARGET,
            {"target": target, "source": "daemon", "auto": True},
            source="intelligence_daemon",
            priority=Priority.HIGH,
            correlation_id=self._correlation_id,
        )


# ── Singleton ─────────────────────────────────────────────────────────────────

_daemon: Optional[IntelligenceDaemon] = None
_daemon_lock = threading.Lock()


def get_daemon(config: Optional[DaemonConfig] = None) -> IntelligenceDaemon:
    global _daemon
    if _daemon is None:
        with _daemon_lock:
            if _daemon is None:
                _daemon = IntelligenceDaemon(config=config)
    return _daemon


# ── Utility helpers ───────────────────────────────────────────────────────────

def _to_domain(target: str) -> str:
    from urllib.parse import urlparse
    parsed = urlparse(target)
    return parsed.netloc or parsed.path.split("/")[0] or target


def _short_hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:6]


def _param_to_vuln(param: str) -> str:
    p = param.lower()
    if any(x in p for x in ["id", "user", "uid", "pid"]):   return "IDOR"
    if any(x in p for x in ["url", "redirect", "next"]):    return "SSRF"
    if any(x in p for x in ["q", "search", "query"]):       return "XSS"
    if any(x in p for x in ["sort", "order", "filter"]):    return "SQL Injection"
    return "XSS"


def _worker_cfg_key(w: WorkerEngine) -> str:
    mapping = {
        "HypothesisWorker":     "hypothesis",
        "GraphExpansionWorker": "graph_expand",
        "ExploitChainWorker":   "exploit_chain",
        "PayloadMutationWorker":"payload_mutate",
        "TrafficReplayWorker":  "traffic_replay",
        "BusinessLogicWorker":  "biz_logic",
        "OSINTExpansionWorker": "osint_expand",
        "SwarmWorker":          "swarm",
        "LearningWorker":       "learning",
    }
    return mapping.get(w.__class__.__name__, "")


# ── CLI convenience ───────────────────────────────────────────────────────────

def cmd_daemon_start(target: str, config: Optional[DaemonConfig] = None) -> IntelligenceDaemon:
    d = get_daemon(config)
    d.start(target=target)
    return d


def cmd_daemon_status() -> dict:
    return get_daemon().status()
