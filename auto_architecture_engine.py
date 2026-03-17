"""
auto_architecture_engine.py — Self-Evolving Architecture Engine

Central event bus for the One&Infinity platform.  Any module can emit an
ArchEvent and all registered handlers receive it.  Built-in handlers
automatically update:
  - MemoryManager   (scan results, attack patterns, exploit chains, insights)
  - ArchitectureUpdater (ARCHITECTURE.md)
  - SkillsTracker   (SKILLS.md + in-memory capability registry)
  - ReadmeGenerator (README.md)

Integration hooks are provided for:
  - AttackGraphEngine  (subscribe to node/edge additions)
  - KnowledgeBase      (subscribe to scan session completions)
  - AgentSwarmCoordinator (subscribe to swarm findings)
  - MobileSecurityEngine  (subscribe to mobile scan results)
  - AISecurityEngine      (subscribe to AI vulnerability discoveries)
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Optional

log = logging.getLogger("oneinfinity.arch_engine")

# ── Event types ───────────────────────────────────────────────────────────────

class EventType(str, Enum):
    FEATURE_ADDED          = "feature_added"
    SCAN_COMPLETED         = "scan_completed"
    VULNERABILITY_DISCOVERED = "vulnerability_discovered"
    EXPLOIT_CHAIN_DETECTED = "exploit_chain_detected"
    TOOL_INTEGRATED        = "tool_integrated"
    AGENT_FINDING          = "agent_finding"
    MOBILE_SCAN_COMPLETED  = "mobile_scan_completed"
    AI_VULN_DISCOVERED     = "ai_vuln_discovered"
    GRAPH_NODE_ADDED       = "graph_node_added"
    GRAPH_CHAIN_FOUND      = "graph_chain_found"
    ARCHITECTURE_UPDATED   = "architecture_updated"
    SKILL_REGISTERED       = "skill_registered"
    INSIGHT_GENERATED      = "insight_generated"


@dataclass
class ArchEvent:
    """
    A platform event.

    Attributes
    ----------
    event_type  : EventType
    source      : str        — which engine/module emitted the event
    data        : dict       — event payload (content depends on event_type)
    event_id    : str        — UUID4 (auto-assigned)
    timestamp   : float      — unix epoch (auto-assigned)
    """
    event_type: EventType
    source: str
    data: dict = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


# ── Handler type ──────────────────────────────────────────────────────────────

Handler = Callable[[ArchEvent], None]


# ── Engine ────────────────────────────────────────────────────────────────────

class AutoArchitectureEngine:
    """
    Event bus + dispatch engine.

    Thread-safe: events can be emitted from any thread.  Handlers are
    executed synchronously in the dispatch thread (a dedicated background
    daemon thread), so they must not block for more than a few seconds.

    Usage
    -----
    engine = get_engine()
    engine.emit(ArchEvent(EventType.FEATURE_ADDED, "my_module", {"name": "Cool Feature"}))
    engine.subscribe(EventType.SCAN_COMPLETED, my_handler)
    """

    def __init__(self):
        self._handlers: dict[EventType, list[Handler]] = {et: [] for et in EventType}
        self._wildcard: list[Handler] = []   # handlers subscribed to ALL events
        self._queue: "queue.Queue[ArchEvent]" = __import__("queue").Queue()
        self._event_log: list[dict] = []      # in-memory ring buffer (last 500)
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Lazy singletons (resolved on first event to avoid circular imports)
        self._memory:   Any = None
        self._arch_upd: Any = None
        self._skills:   Any = None
        self._readme:   Any = None

        self._start_dispatch_thread()
        self._register_builtin_handlers()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _start_dispatch_thread(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._dispatch_loop,
            name="arch-engine-dispatch",
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._running = False
        # Unblock the queue
        self._queue.put(None)  # type: ignore[arg-type]

    def _dispatch_loop(self):
        while self._running:
            try:
                event = self._queue.get(timeout=2.0)
                if event is None:
                    break
                self._dispatch(event)
            except __import__("queue").Empty:
                continue
            except Exception as exc:
                log.exception("Dispatch error: %s", exc)

    def _dispatch(self, event: ArchEvent):
        # Log to ring buffer
        with self._lock:
            self._event_log.append(event.to_dict())
            if len(self._event_log) > 500:
                self._event_log.pop(0)

        # Call specific handlers
        for handler in list(self._handlers.get(event.event_type, [])):
            try:
                handler(event)
            except Exception as exc:
                log.warning("Handler %s raised: %s", handler.__name__, exc)

        # Call wildcard handlers
        for handler in list(self._wildcard):
            try:
                handler(event)
            except Exception as exc:
                log.warning("Wildcard handler %s raised: %s", handler.__name__, exc)

    # ── Subscribe ─────────────────────────────────────────────────────────────

    def subscribe(self, event_type: EventType | None, handler: Handler):
        """
        Subscribe to a specific event type.
        Pass event_type=None to subscribe to ALL events (wildcard).
        """
        with self._lock:
            if event_type is None:
                if handler not in self._wildcard:
                    self._wildcard.append(handler)
            else:
                if handler not in self._handlers[event_type]:
                    self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: EventType | None, handler: Handler):
        with self._lock:
            if event_type is None:
                self._wildcard = [h for h in self._wildcard if h is not handler]
            else:
                self._handlers[event_type] = [
                    h for h in self._handlers[event_type] if h is not handler
                ]

    # ── Emit ──────────────────────────────────────────────────────────────────

    def emit(self, event: ArchEvent):
        """Enqueue an event for asynchronous dispatch."""
        self._queue.put(event)
        return event.event_id

    def emit_sync(self, event: ArchEvent):
        """Dispatch event immediately in the calling thread (blocks)."""
        self._dispatch(event)
        return event.event_id

    # ── Convenience emitters ──────────────────────────────────────────────────

    def feature_added(self, name: str, description: str, category: str = "General",
                      command: str = "", engine: str = "", tools: list[str] | None = None,
                      source: str = "platform") -> str:
        return self.emit(ArchEvent(
            EventType.FEATURE_ADDED, source,
            {"name": name, "description": description, "category": category,
             "command": command, "engine": engine, "tools": tools or []}
        ))

    def scan_completed(self, session_id: str, target: str, findings: list[dict],
                       tools_used: list[str] | None = None, duration_s: float = 0.0,
                       source: str = "scan_pipeline") -> str:
        return self.emit(ArchEvent(
            EventType.SCAN_COMPLETED, source,
            {"session_id": session_id, "target": target,
             "findings": findings, "tools_used": tools_used or [],
             "duration_s": duration_s, "total": len(findings)}
        ))

    def vulnerability_discovered(self, vuln_type: str, target: str, severity: str,
                                  cvss: float = 0.0, endpoint: str = "", payload: str = "",
                                  tool: str = "", agent: str = "", source: str = "scan") -> str:
        return self.emit(ArchEvent(
            EventType.VULNERABILITY_DISCOVERED, source,
            {"vuln_type": vuln_type, "target": target, "severity": severity,
             "cvss": cvss, "endpoint": endpoint, "payload": payload,
             "tool": tool, "agent": agent}
        ))

    def exploit_chain_detected(self, chain_name: str, steps: list[str],
                                target: str = "", cvss: float = 0.0,
                                confirmed: bool = False, session_id: str = "",
                                source: str = "chain_detector") -> str:
        return self.emit(ArchEvent(
            EventType.EXPLOIT_CHAIN_DETECTED, source,
            {"chain_name": chain_name, "steps": steps, "target": target,
             "cvss": cvss, "confirmed": confirmed, "session_id": session_id}
        ))

    def tool_integrated(self, tool_name: str, version: str = "",
                        capabilities: list[str] | None = None,
                        source: str = "tool_registry") -> str:
        return self.emit(ArchEvent(
            EventType.TOOL_INTEGRATED, source,
            {"tool_name": tool_name, "version": version,
             "capabilities": capabilities or []}
        ))

    # ── Query ─────────────────────────────────────────────────────────────────

    def recent_events(self, limit: int = 50, event_type: str = "") -> list[dict]:
        with self._lock:
            events = list(self._event_log)
        if event_type:
            events = [e for e in events if e["event_type"] == event_type]
        return list(reversed(events))[:limit]

    def stats(self) -> dict:
        with self._lock:
            total = len(self._event_log)
            by_type: dict[str, int] = {}
            for e in self._event_log:
                t = e["event_type"]
                by_type[t] = by_type.get(t, 0) + 1
        return {
            "total_events_logged": total,
            "by_type": by_type,
            "queue_size": self._queue.qsize(),
            "running": self._running,
        }

    # ── Built-in handlers ─────────────────────────────────────────────────────

    def _resolve_singletons(self):
        """Lazily resolve module singletons to avoid circular imports at load time."""
        if self._memory is None:
            try:
                from memory_manager import get_memory_manager
                self._memory = get_memory_manager()
            except Exception as e:
                log.debug("memory_manager not available: %s", e)

        if self._arch_upd is None:
            try:
                from architecture_updater import get_architecture_updater
                self._arch_upd = get_architecture_updater()
            except Exception as e:
                log.debug("architecture_updater not available: %s", e)

        if self._skills is None:
            try:
                from skills_tracker import get_skills_tracker, Skill
                self._skills = get_skills_tracker()
            except Exception as e:
                log.debug("skills_tracker not available: %s", e)

        if self._readme is None:
            try:
                from readme_generator import get_readme_generator
                self._readme = get_readme_generator()
            except Exception as e:
                log.debug("readme_generator not available: %s", e)

    def _register_builtin_handlers(self):
        self.subscribe(EventType.FEATURE_ADDED,          self._on_feature_added)
        self.subscribe(EventType.SCAN_COMPLETED,         self._on_scan_completed)
        self.subscribe(EventType.VULNERABILITY_DISCOVERED,self._on_vulnerability_discovered)
        self.subscribe(EventType.EXPLOIT_CHAIN_DETECTED, self._on_exploit_chain_detected)
        self.subscribe(EventType.TOOL_INTEGRATED,        self._on_tool_integrated)
        self.subscribe(EventType.AGENT_FINDING,          self._on_agent_finding)
        self.subscribe(EventType.MOBILE_SCAN_COMPLETED,  self._on_mobile_scan_completed)
        self.subscribe(EventType.AI_VULN_DISCOVERED,     self._on_ai_vuln_discovered)
        self.subscribe(EventType.GRAPH_CHAIN_FOUND,      self._on_graph_chain_found)

    # ── Handler: feature_added ────────────────────────────────────────────────

    def _on_feature_added(self, event: ArchEvent):
        self._resolve_singletons()
        d = event.data
        name        = d.get("name", "Unknown Feature")
        description = d.get("description", "")
        category    = d.get("category", "General")
        command     = d.get("command", "")
        engine      = d.get("engine", "")
        tools       = d.get("tools", [])

        # 1. Register in SkillsTracker
        if self._skills:
            from skills_tracker import Skill, CATEGORIES
            # Map category to canonical slug
            cat_map = {
                "web": "web_security", "mobile": "mobile_security",
                "ai": "ai_security", "exploit": "exploit_development",
                "graph": "attack_graph_intelligence", "swarm": "swarm_intelligence",
                "reverse": "reverse_engineering",
            }
            cat_slug = category.lower().replace(" ", "_")
            for key in cat_map:
                if key in cat_slug:
                    cat_slug = cat_map[key]
                    break
            if cat_slug not in CATEGORIES:
                cat_slug = "web_security"
            skill = Skill(name=name, category=cat_slug, command=command,
                          engine=engine, description=description, tools=tools,
                          source_event=event.event_type.value)
            is_new = self._skills.register(skill, rewrite=True)

        # 2. Update ArchitectureUpdater
        if self._arch_upd:
            from architecture_updater import ComponentEntry
            comp = ComponentEntry(name=name, file=engine or name,
                                  description=description, category=category)
            self._arch_upd.add_component(comp)

        # 3. Update ReadmeGenerator
        if self._readme:
            from readme_generator import FeatureEntry, CLICommand
            fe = FeatureEntry(title=name, description=description, category=category)
            self._readme.add_feature(fe)
            if command:
                self._readme.add_cli_command(CLICommand(command=command, description=description,
                                                         category=category))
            self._readme.force_write()

        # 4. Store insight
        if self._memory:
            from memory_manager import LearningInsight
            self._memory.store_insight(LearningInsight(
                category="feature",
                title=f"New capability: {name}",
                body=f"Category: {category}. Engine: {engine}. {description}",
                confidence=1.0,
                source_event=event.event_type.value,
                tags=["feature", category.lower()],
            ))

        # 5. Snapshot capabilities
        if self._skills and self._memory:
            caps = self._skills.capability_names()
            self._memory.snapshot_capabilities(caps, trigger_event="feature_added")

        # 6. Log architecture change
        if self._memory:
            self._memory.log_architecture_change(
                "component_added",
                f"Feature added: {name} ({category})",
                section=engine,
                trigger_event="feature_added",
            )

        log.info("[arch] feature_added: %s (%s)", name, category)

    # ── Handler: scan_completed ────────────────────────────────────────────────

    def _on_scan_completed(self, event: ArchEvent):
        self._resolve_singletons()
        d = event.data
        findings    = d.get("findings", [])
        session_id  = d.get("session_id", str(uuid.uuid4()))
        target      = d.get("target", "")
        tools_used  = d.get("tools_used", [])
        duration_s  = d.get("duration_s", 0.0)

        if not self._memory:
            return

        # Tally severity counts
        crit = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        confirmed = sum(1 for f in findings if f.get("confirmed", True))

        from memory_manager import ScanResultSummary, AttackPattern, LearningInsight

        summary = ScanResultSummary(
            session_id=session_id, target=target,
            started_at=event.timestamp - duration_s, finished_at=event.timestamp,
            phases=d.get("phases", []), total_findings=len(findings),
            confirmed_findings=confirmed, critical_count=crit,
            high_count=high, tools_used=tools_used,
        )
        self._memory.store_scan_summary(summary)

        # Mine patterns from confirmed high/critical findings
        new_patterns = 0
        for f in findings:
            if not f.get("payload") and not f.get("vuln_type"):
                continue
            pat = AttackPattern(
                vuln_type=f.get("vuln_type", ""),
                target_tech=f.get("tech", ""),
                payload=f.get("payload", "")[:256],
                endpoint_pattern=f.get("endpoint", ""),
                cvss=float(f.get("cvss", f.get("cvss_score", 0.0)) or 0.0),
                success_rate=1.0 if f.get("confirmed", True) else 0.0,
                agent_source=f.get("source_tool", event.source),
            )
            self._memory.upsert_attack_pattern(pat)
            new_patterns += 1

        # Generate insight if interesting findings found
        if crit + high > 0:
            self._memory.store_insight(LearningInsight(
                category="scan",
                title=f"Scan completed: {target} — {crit} critical, {high} high",
                body=(f"Session {session_id}: {len(findings)} total findings, "
                      f"{confirmed} confirmed. Tools: {', '.join(tools_used[:5])}."),
                confidence=0.9,
                source_event="scan_completed",
                tags=["scan", target, "findings"],
            ))

        log.info("[arch] scan_completed: %s, %d findings, %d patterns mined",
                 target, len(findings), new_patterns)

    # ── Handler: vulnerability_discovered ─────────────────────────────────────

    def _on_vulnerability_discovered(self, event: ArchEvent):
        self._resolve_singletons()
        d = event.data
        if not self._memory:
            return

        from memory_manager import AttackPattern, LearningInsight

        pat = AttackPattern(
            vuln_type=d.get("vuln_type", ""),
            target_tech=d.get("tech", ""),
            payload=d.get("payload", "")[:256],
            endpoint_pattern=d.get("endpoint", ""),
            cvss=float(d.get("cvss", 0.0) or 0.0),
            success_rate=1.0,
            agent_source=d.get("tool", d.get("agent", event.source)),
        )
        self._memory.upsert_attack_pattern(pat)

        # Only generate insight for high/critical
        sev = d.get("severity", "info").lower()
        if sev in ("critical", "high"):
            self._memory.store_insight(LearningInsight(
                category="vulnerability",
                title=f"{d.get('vuln_type', 'Vulnerability')} found on {d.get('target', '?')}",
                body=(f"Severity: {sev}. CVSS: {d.get('cvss', 0.0):.1f}. "
                      f"Endpoint: {d.get('endpoint', '?')}. "
                      f"Payload: {d.get('payload', '')[:80]}."),
                confidence=0.85,
                source_event="vulnerability_discovered",
                tags=["vuln", d.get("vuln_type", ""), sev],
            ))

        log.debug("[arch] vulnerability_discovered: %s on %s (%s)",
                  d.get("vuln_type"), d.get("target"), sev)

    # ── Handler: exploit_chain_detected ───────────────────────────────────────

    def _on_exploit_chain_detected(self, event: ArchEvent):
        self._resolve_singletons()
        d = event.data
        if not self._memory:
            return

        from memory_manager import ExploitChainRecord, LearningInsight

        chain = ExploitChainRecord(
            chain_name=d.get("chain_name", "unknown_chain"),
            steps=d.get("steps", []),
            target=d.get("target", ""),
            cvss_combined=float(d.get("cvss", 0.0) or 0.0),
            confirmed=d.get("confirmed", False),
            session_id=d.get("session_id", ""),
            description=d.get("description", ""),
            remediation=d.get("remediation", ""),
        )
        cid = self._memory.store_exploit_chain(chain)

        steps_str = " → ".join(d.get("steps", []))
        self._memory.store_insight(LearningInsight(
            category="chain",
            title=f"Exploit chain: {d.get('chain_name', '?')}",
            body=(f"Steps: {steps_str}. Target: {d.get('target', '?')}. "
                  f"CVSS: {d.get('cvss', 0):.1f}. "
                  f"Confirmed: {d.get('confirmed', False)}."),
            confidence=0.95 if d.get("confirmed") else 0.7,
            source_event="exploit_chain_detected",
            tags=["chain", d.get("chain_name", ""), "exploit"],
        ))

        # Update architecture changelog
        if self._memory:
            self._memory.log_architecture_change(
                "metric_updated",
                f"Exploit chain detected: {d.get('chain_name')} on {d.get('target')}",
                trigger_event="exploit_chain_detected",
            )

        log.info("[arch] exploit_chain_detected: %s (%s)", d.get("chain_name"), steps_str)

    # ── Handler: tool_integrated ──────────────────────────────────────────────

    def _on_tool_integrated(self, event: ArchEvent):
        self._resolve_singletons()
        d = event.data
        tool_name   = d.get("tool_name", "")
        version     = d.get("version", "")
        capabilities = d.get("capabilities", [])

        if self._skills:
            from skills_tracker import Skill
            skill = Skill(
                name=f"Tool: {tool_name}",
                category="web_security",
                command="",
                engine=tool_name,
                description=f"Version {version}. " + "; ".join(capabilities[:3]),
                tools=[tool_name],
                source_event="tool_integrated",
            )
            self._skills.register(skill, rewrite=True)

        if self._arch_upd:
            from architecture_updater import ComponentEntry
            self._arch_upd.add_component(ComponentEntry(
                name=tool_name,
                file=tool_name,
                description=f"v{version}: " + ", ".join(capabilities[:3]) if capabilities else version,
                category="Tools",
            ), section_title="Tool Inventory")

        if self._memory:
            from memory_manager import LearningInsight
            self._memory.store_insight(LearningInsight(
                category="tool",
                title=f"Tool integrated: {tool_name} v{version}",
                body=f"Capabilities: {', '.join(capabilities)}",
                confidence=1.0,
                source_event="tool_integrated",
                tags=["tool", tool_name],
            ))

        log.info("[arch] tool_integrated: %s v%s", tool_name, version)

    # ── Handler: agent_finding (swarm) ────────────────────────────────────────

    def _on_agent_finding(self, event: ArchEvent):
        """Translate a swarm agent finding to a vulnerability_discovered event."""
        d = event.data
        self.emit(ArchEvent(
            EventType.VULNERABILITY_DISCOVERED,
            source=f"swarm.{d.get('agent_type', 'unknown')}",
            data={
                "vuln_type":  d.get("vuln_type", ""),
                "target":     d.get("target", ""),
                "severity":   d.get("severity", "info"),
                "cvss":       d.get("cvss", 0.0),
                "endpoint":   d.get("endpoint", ""),
                "payload":    d.get("payload", ""),
                "agent":      d.get("agent_type", ""),
            }
        ))

    # ── Handler: mobile_scan_completed ────────────────────────────────────────

    def _on_mobile_scan_completed(self, event: ArchEvent):
        self._resolve_singletons()
        d = event.data
        if not self._memory:
            return

        from memory_manager import LearningInsight, AttackPattern
        findings = d.get("findings", [])
        for f in findings:
            if f.get("vuln_type"):
                pat = AttackPattern(
                    vuln_type=f.get("vuln_type", ""),
                    target_tech="android",
                    payload=str(f.get("evidence", ""))[:200],
                    cvss=float(f.get("cvss", 0.0) or 0.0),
                    success_rate=1.0,
                    agent_source="mobile_security_engine",
                )
                self._memory.upsert_attack_pattern(pat)

        if findings:
            self._memory.store_insight(LearningInsight(
                category="mobile",
                title=f"Mobile scan: {d.get('app_name', '?')} — {len(findings)} findings",
                body=f"APK: {d.get('apk_path', '?')}. Findings: {len(findings)}.",
                confidence=0.9,
                source_event="mobile_scan_completed",
                tags=["mobile", "android"],
            ))

    # ── Handler: ai_vuln_discovered ───────────────────────────────────────────

    def _on_ai_vuln_discovered(self, event: ArchEvent):
        self._resolve_singletons()
        d = event.data
        if not self._memory:
            return

        from memory_manager import AttackPattern, LearningInsight
        pat = AttackPattern(
            vuln_type=d.get("vuln_type", "ai_vulnerability"),
            target_tech="llm",
            payload=d.get("prompt", "")[:256],
            cvss=float(d.get("cvss", 0.0) or 0.0),
            success_rate=1.0,
            agent_source=d.get("tool", "ai_security_engine"),
        )
        self._memory.upsert_attack_pattern(pat)
        self._memory.store_insight(LearningInsight(
            category="ai_security",
            title=f"AI vulnerability: {d.get('vuln_type', '?')} on {d.get('target', '?')}",
            body=d.get("description", ""),
            confidence=0.8,
            source_event="ai_vuln_discovered",
            tags=["ai", d.get("vuln_type", ""), "llm"],
        ))

    # ── Handler: graph_chain_found ────────────────────────────────────────────

    def _on_graph_chain_found(self, event: ArchEvent):
        """Translate an attack-graph chain to exploit_chain_detected."""
        d = event.data
        self.emit(ArchEvent(
            EventType.EXPLOIT_CHAIN_DETECTED,
            source="attack_graph_core",
            data={
                "chain_name": d.get("chain_name", "graph_chain"),
                "steps":      d.get("steps", []),
                "target":     d.get("target", ""),
                "cvss":       d.get("cvss_combined", 0.0),
                "confirmed":  False,
            }
        ))

    # ── AttackGraphEngine integration hook ────────────────────────────────────

    def attach_attack_graph(self, engine: Any):
        """
        Subscribe to AttackGraphEngine events.
        Emits GRAPH_NODE_ADDED when a vulnerability node is added.
        """
        def _node_listener(node):
            try:
                from attack_graph_core.graph_engine import NodeType
                if node.node_type in (NodeType.VULNERABILITY, NodeType.EXPLOIT):
                    self.emit(ArchEvent(
                        EventType.VULNERABILITY_DISCOVERED,
                        source="attack_graph",
                        data={
                            "vuln_type": node.label,
                            "target":    node.properties.get("target", ""),
                            "severity":  node.severity or "info",
                            "cvss":      node.risk_score,
                            "endpoint":  node.properties.get("url", ""),
                        }
                    ))
            except Exception:
                pass
        try:
            engine.subscribe("node_added", _node_listener)
            log.info("[arch] Attached to AttackGraphEngine")
        except Exception as e:
            log.debug("Could not attach to AttackGraphEngine: %s", e)

    # ── KnowledgeBase integration hook ────────────────────────────────────────

    def attach_knowledge_base(self, kb: Any):
        """
        Monkey-patch KnowledgeBase.finish_session to emit scan_completed.
        Non-invasive: wraps the method, preserves original behaviour.
        """
        original_finish = kb.finish_session

        def _patched_finish(session_id, total_findings, tools_used=None, notes=""):
            original_finish(session_id, total_findings, tools_used=tools_used, notes=notes)
            try:
                row = kb._conn.execute(
                    "SELECT target FROM scan_sessions WHERE session_id=?", (session_id,)
                ).fetchone()
                target = row["target"] if row else ""
                self.emit(ArchEvent(
                    EventType.SCAN_COMPLETED, "knowledge_base",
                    {"session_id": session_id, "target": target,
                     "total_findings": total_findings, "tools_used": tools_used or []}
                ))
            except Exception:
                pass

        kb.finish_session = _patched_finish
        log.info("[arch] Attached to KnowledgeBase")

    # ── Swarm coordinator integration hook ────────────────────────────────────

    def attach_swarm_coordinator(self, coordinator: Any):
        """
        Subscribe to the swarm coordinator's event bus for AgentFindings.
        This uses coordinator's internal broadcast if it exposes one, otherwise
        wraps the coordinator's `scan` method.
        """
        original_scan = getattr(coordinator, "scan", None)
        if original_scan is None:
            return

        import asyncio

        async def _patched_scan(target, context=None):
            result = await original_scan(target, context)
            try:
                for finding in (result.findings if hasattr(result, "findings") else []):
                    self.emit(ArchEvent(
                        EventType.AGENT_FINDING, "swarm_coordinator",
                        finding.to_dict() if hasattr(finding, "to_dict") else finding
                    ))
                for chain in (result.chains if hasattr(result, "chains") else []):
                    self.emit(ArchEvent(
                        EventType.EXPLOIT_CHAIN_DETECTED, "swarm_coordinator",
                        chain if isinstance(chain, dict) else {"chain_name": str(chain), "steps": []}
                    ))
            except Exception:
                pass
            return result

        coordinator.scan = _patched_scan
        log.info("[arch] Attached to AgentSwarmCoordinator")


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: AutoArchitectureEngine | None = None
_instance_lock = threading.Lock()


def get_engine() -> AutoArchitectureEngine:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = AutoArchitectureEngine()
    return _instance


# ── CLI helpers (used by oneinfinity.py arch-* commands) ─────────────────────

def cmd_arch_status() -> dict:
    engine = get_engine()
    try:
        from memory_manager import get_memory_manager
        mm = get_memory_manager()
        mem_stats = mm.stats()
        cap_snap = mm.latest_capability_snapshot()
        recent_changes = mm.get_architecture_changelog(limit=5)
        recent_insights = mm.recent_insights(hours=24, limit=5)
    except Exception:
        mem_stats = {}
        cap_snap = None
        recent_changes = []
        recent_insights = []

    try:
        from skills_tracker import get_skills_tracker
        st = get_skills_tracker()
        skills_summary = st.categories_summary()
        total_skills = st.total_count()
    except Exception:
        skills_summary = {}
        total_skills = 0

    return {
        "engine_stats":      engine.stats(),
        "memory_stats":      mem_stats,
        "capability_snapshot": cap_snap,
        "total_skills":      total_skills,
        "skills_by_category": skills_summary,
        "recent_changes":    recent_changes,
        "recent_insights":   recent_insights,
    }
