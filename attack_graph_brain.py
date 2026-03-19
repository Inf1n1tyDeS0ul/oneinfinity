"""
attack_graph_brain.py — Central Attack Graph Brain

The graph brain is the intelligence hub of the platform.
All modules feed data IN via events; all decisions come OUT via the brain.

Architecture:
  ┌─────────────────────────────────────────────────────────┐
  │                  AttackGraphBrain                        │
  │                                                         │
  │  ┌──────────────┐   ┌──────────────┐  ┌─────────────┐  │
  │  │ AttackGraph  │   │  NodeScorer  │  │ ActionQueue │  │
  │  │  Engine      │   │  (priority)  │  │ (priority)  │  │
  │  └──────────────┘   └──────────────┘  └─────────────┘  │
  │  ┌──────────────┐   ┌──────────────┐  ┌─────────────┐  │
  │  │ RiskAnalyzer │   │  Query       │  │ Decision    │  │
  │  │              │   │  Engine      │  │ History     │  │
  │  └──────────────┘   └──────────────┘  └─────────────┘  │
  └─────────────────────────────────────────────────────────┘
         ▲  publish / subscribe  ▼
     ┌───────────────────────────────┐
     │         EventBus              │
     └───────────────────────────────┘

Priority scoring formula per node:
  priority = base_type_weight
           × (1 + connectivity_factor)
           × (1 + vuln_bonus)
           × (1 + depth_penalty)
           × (1 - tested_discount)
"""

from __future__ import annotations

import heapq
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import logging
log = logging.getLogger(__name__)

# ── Weights & constants ────────────────────────────────────────────────────────

# Base priority weight per node type (higher = more interesting)
_TYPE_WEIGHTS: Dict[str, float] = {
    "AUTH_FLOW":    10.0,
    "VULNERABILITY": 9.5,
    "EXPLOIT":       9.0,
    "API_ENDPOINT":  8.5,
    "PARAMETER":     7.0,
    "URL":           5.5,
    "SUBDOMAIN":     5.0,
    "SERVICE":       4.5,
    "TECHNOLOGY":    3.0,
    "TARGET":        2.0,
    "CREDENTIAL":    9.8,
    "IMPACT":       10.0,
    "default":       4.0,
}

# Agents allowed per node type
_TYPE_AGENTS: Dict[str, List[str]] = {
    "PARAMETER":     ["xss", "sqli", "ssrf", "ssti", "open_redirect"],
    "API_ENDPOINT":  ["idor", "auth", "biz_logic", "sqli"],
    "AUTH_FLOW":     ["auth", "biz_logic"],
    "URL":           ["xss", "sqli", "ssrf", "recon"],
    "SUBDOMAIN":     ["recon"],
    "TARGET":        ["recon"],
    "VULNERABILITY": ["exploit", "sqli", "xss"],
    "SERVICE":       ["recon", "ssrf"],
    "TECHNOLOGY":    ["recon"],
    "CREDENTIAL":    ["auth"],
}

MAX_DECISION_HISTORY = 500
MAX_ACTION_QUEUE = 1000


# ── Data models ───────────────────────────────────────────────────────────────

class BrainEventType(str, Enum):
    NODE_PRIORITIZED     = "NODE_PRIORITIZED"
    ACTION_QUEUED        = "ACTION_QUEUED"
    ACTION_DISPATCHED    = "ACTION_DISPATCHED"
    FINDING_INTEGRATED   = "FINDING_INTEGRATED"
    RISK_RECALCULATED    = "RISK_RECALCULATED"
    GRAPH_SNAPSHOT       = "GRAPH_SNAPSHOT"
    DECISION_MADE        = "DECISION_MADE"
    LOOP_ITERATION       = "LOOP_ITERATION"


@dataclass
class BrainAction:
    """A prioritized action the brain wants to execute."""
    action_id:   str
    agent_type:  str          # "xss", "sqli", "recon", etc.
    node_id:     str
    node_label:  str
    node_type:   str
    target:      str
    priority:    float        # higher = more urgent (negated for heapq)
    context:     Dict[str, Any] = field(default_factory=dict)
    created_at:  float = field(default_factory=time.time)
    dispatched:  bool = False
    reasoning:   str = ""

    def to_dict(self) -> dict:
        return {
            "action_id":  self.action_id,
            "agent_type": self.agent_type,
            "node_id":    self.node_id,
            "node_label": self.node_label,
            "node_type":  self.node_type,
            "target":     self.target,
            "priority":   round(self.priority, 3),
            "context":    self.context,
            "created_at": self.created_at,
            "dispatched": self.dispatched,
            "reasoning":  self.reasoning,
        }

    # heapq is a min-heap; negate priority so highest priority pops first
    def __lt__(self, other: "BrainAction") -> bool:
        return self.priority > other.priority


@dataclass
class NodePriorityRecord:
    node_id:       str
    node_label:    str
    node_type:     str
    target:        str
    priority:      float
    risk_score:    float
    in_degree:     int
    out_degree:    int
    agents_tested: List[str]
    calculated_at: float = field(default_factory=time.time)


@dataclass
class BrainDecision:
    decision_id:  str
    target:       str
    action:       BrainAction
    graph_state:  dict        # snapshot of key stats when decision was made
    reasoning:    str
    confidence:   float       # 0-1
    made_at:      float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "target":      self.target,
            "action":      self.action.to_dict(),
            "graph_state": self.graph_state,
            "reasoning":   self.reasoning,
            "confidence":  round(self.confidence, 3),
            "made_at":     self.made_at,
        }


@dataclass
class BrainStatus:
    running:         bool
    targets:         List[str]
    total_nodes:     int
    total_edges:     int
    queue_depth:     int
    decisions_made:  int
    actions_dispatched: int
    findings_integrated: int
    last_loop_at:    float
    uptime_s:        float

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ── Main Brain class ───────────────────────────────────────────────────────────

class AttackGraphBrain:
    """
    Central brain: wraps AttackGraphEngine, scores nodes, queues actions,
    integrates findings, and drives the autonomous attack loop.
    """

    def __init__(self) -> None:
        # Core engine (shared singleton from attack_graph_core)
        self._engine = None      # lazy-loaded
        self._query  = None
        self._risk   = None

        # State
        self._running:     bool = False
        self._targets:     Set[str] = set()
        self._lock:        threading.RLock = threading.RLock()
        self._started_at:  float = 0.0

        # Priority action queue (max-heap via negated priority)
        self._action_queue: List[BrainAction] = []
        self._queued_ids:   Set[str] = set()   # (node_id, agent_type) to avoid duplicates

        # Tracked state per node
        self._node_priorities: Dict[str, NodePriorityRecord] = {}
        self._agents_tested:   Dict[str, Set[str]] = defaultdict(set)  # node_id → set of agent_types
        self._findings:        Dict[str, List[dict]] = defaultdict(list)  # node_id → findings

        # Decision history
        self._decisions: deque = deque(maxlen=MAX_DECISION_HISTORY)

        # Counters
        self._decisions_made      = 0
        self._actions_dispatched  = 0
        self._findings_integrated = 0
        self._last_loop_at        = 0.0

        # Callbacks (set by event_driven_engine)
        self._on_action_ready: Optional[Callable[[BrainAction], None]] = None
        self._on_finding: Optional[Callable[[dict], None]] = None

    # ── Lazy accessors ────────────────────────────────────────────────────────

    def _get_engine(self):
        if self._engine is None:
            try:
                from attack_graph_core.graph_engine import get_engine
                self._engine = get_engine()
            except Exception as e:
                raise RuntimeError(f"AttackGraphEngine unavailable: {e}")
        return self._engine

    def _get_query(self):
        if self._query is None:
            from attack_graph_core.graph_query_engine import GraphQueryEngine
            self._query = GraphQueryEngine(self._get_engine())
        return self._query

    def _get_risk(self):
        if self._risk is None:
            from attack_graph_core.risk_analyzer import RiskAnalyzer
            self._risk = RiskAnalyzer(self._get_engine())
        return self._risk

    # ── Target management ─────────────────────────────────────────────────────

    def add_target(self, target: str) -> None:
        with self._lock:
            self._targets.add(target)
            try:
                eng = self._get_engine()
                eng.get_or_create_node("TARGET", target, properties={"domain": target})
            except Exception:
                pass
        self._publish(BrainEventType.NODE_PRIORITIZED, {
            "action": "target_added", "target": target
        })

    def remove_target(self, target: str) -> None:
        with self._lock:
            self._targets.discard(target)

    # ── Graph mutations (called by event_driven_engine) ───────────────────────

    def record_success(self, node_id: str, agent_type: str):
        """Reward a node and its parents for a successful finding."""
        with self._lock:
            # Persistent reward state could be added to node properties
            try:
                eng = self._get_engine()
                node = eng.get_node(node_id)
                reward = float(node.properties.get("brain_reward", 1.0))
                eng.update_node(node_id, properties={"brain_reward": reward * 1.5})
                # Propagate some reward to parents
                for parent_id in eng.get_edges_to(node_id):
                    p_node = eng.get_node(parent_id)
                    p_reward = float(p_node.properties.get("brain_reward", 1.0))
                    eng.update_node(parent_id, properties={"brain_reward": p_reward * 1.2})
            except Exception: pass
            self.rescore_graph()

    def record_failure(self, node_id: str, agent_type: str):
        """Penalize a node for repeated failures."""
        with self._lock:
            try:
                eng = self._get_engine()
                node = eng.get_node(node_id)
                penalty = float(node.properties.get("brain_penalty", 1.0))
                eng.update_node(node_id, properties={"brain_penalty": penalty * 0.8})
            except Exception: pass
            self.rescore_graph()

    def integrate_node(self, node_type: str, label: str, target: str,
                        properties: dict = None, **kwargs) -> Optional[str]:
        """Add/update a node; re-score and queue new actions."""
        try:
            # Convert uppercase string keys (e.g. "SUBDOMAIN") to proper NodeType enums
            from attack_graph_core.graph_engine import NodeType
            if isinstance(node_type, str) and node_type.upper() in NodeType.__members__:
                real_type = NodeType[node_type.upper()]
            else:
                real_type = node_type

            eng  = self._get_engine()
            node, created = eng.get_or_create_node(
                real_type, label,
                properties=properties or {},
                **kwargs
            )
            if created:
                self._score_and_enqueue(node)
            return node.id
        except Exception as e:
            # Log error but don't crash
            # log.warning(f"integrate_node failed: {e}") 
            return None

    def integrate_finding(self, node_id: str, agent_type: str, finding: dict) -> None:
        """Record that an agent found something on a node; update graph; re-score neighbours."""
        try:
            eng = self._get_engine()
            node = eng.get_node(node_id)
            if node:
                # Mark as exploitable if finding is a real vuln
                severity = finding.get("severity", "info")
                if severity in ("critical", "high", "medium"):
                    eng.update_node(node_id, exploitable=True, severity=severity)
                    # Create or link a VULNERABILITY node
                    vuln_label = finding.get("vuln_type") or finding.get("name", "finding")
                    vuln_node, _ = eng.get_or_create_node(
                        "VULNERABILITY", vuln_label,
                        properties={"severity": severity, **finding},
                        severity=severity, exploitable=True,
                    )
                    eng.add_edge(node_id, vuln_node.id, "HAS_VULNERABILITY",
                                  label=vuln_label, probability=0.9)
                    # Re-score the vulnerability node
                    self._score_and_enqueue(vuln_node)
                # Re-score neighbours
                for nb in eng.get_neighbors(node_id):
                    self._score_and_enqueue(nb)
        except Exception:
            pass

        with self._lock:
            self._agents_tested[node_id].add(agent_type)
            self._findings[node_id].append(finding)
            self._findings_integrated += 1

        self._publish(BrainEventType.FINDING_INTEGRATED, {
            "node_id": node_id, "agent_type": agent_type,
            "finding": finding,
        })

    def integrate_vuln(self, finding: dict) -> Optional[str]:
        """Insert a normalised finding dict as a VULNERABILITY node and wire it to its parent."""
        import uuid as _uuid
        finding_id = finding.get("finding_id") or finding.get("id") or str(_uuid.uuid4())[:12]
        target     = finding.get("target", "")
        url        = finding.get("url") or target
        severity   = finding.get("severity", "info")
        vuln_type  = finding.get("vuln_type") or finding.get("attack_type", "")
        title      = finding.get("title") or vuln_type or "finding"

        properties = {
            "finding_id": finding_id,
            "severity":   severity,
            "vuln_type":  vuln_type,
            "title":      title,
            "url":        url,
            "tool":       finding.get("tool", ""),
            "evidence":   str(finding.get("evidence", ""))[:200],
            "status":     finding.get("status", "new"),
        }

        node_id = self.integrate_node(
            "VULNERABILITY", finding_id, target, properties=properties
        )
        if node_id is None:
            return None

        # Wire parent → VULNERABILITY edge
        try:
            eng = self._get_engine()
            for parent_label in ([url] if url and url != target else []) + [target]:
                parents = eng.find_nodes(label_contains=parent_label)
                for p in parents:
                    if p.label == parent_label and p.id != node_id:
                        eng.add_edge(p.id, node_id, "HAS_VULN",
                                     label=vuln_type or "vulnerability", probability=0.9)
                        break
        except Exception as exc:
            log.debug("integrate_vuln: edge wiring failed [%s]: %s", finding_id, exc)

        log.info("[GRAPH] Added vulnerability node: %s (severity=%s)", finding_id, severity)
        return node_id

    def mark_tested(self, node_id: str, agent_type: str) -> None:
        with self._lock:
            self._agents_tested[node_id].add(agent_type)

    # ── Priority scoring ──────────────────────────────────────────────────────

    def _score_node(self, node) -> float:
        """Calculate priority score for a node."""
        try:
            eng = self._get_engine()
            type_str  = str(node.node_type).split(".")[-1]
            base      = _TYPE_WEIGHTS.get(type_str, _TYPE_WEIGHTS["default"])

            # Connectivity bonus
            in_deg  = len(eng.get_edges_to(node.id))
            out_deg = len(eng.get_edges_from(node.id))
            total   = in_deg + out_deg
            conn    = min(total / 10.0, 1.0)  # cap at 1.0

            # Vulnerability bonus
            vuln_bonus = 0.5 if node.exploitable else 0.0

            # Severity bonus
            sev_bonus = {
                "critical": 1.0, "high": 0.7, "medium": 0.4,
                "low": 0.1, "info": 0.0,
            }.get(str(node.severity or "info"), 0.0)

            # Tested discount
            tested = self._agents_tested.get(node.id, set())
            wanted = set(_TYPE_AGENTS.get(type_str, []))
            if wanted:
                tested_ratio = len(tested & wanted) / len(wanted)
            else:
                tested_ratio = 1.0 if tested else 0.0
            tested_discount = tested_ratio * 0.7  # fully tested → 70% discount

            # Feedback reward/penalty
            reward = float(node.properties.get("brain_reward", 1.0))
            penalty = float(node.properties.get("brain_penalty", 1.0))

            score = (
                base
                * (1.0 + conn * 0.5)
                * (1.0 + vuln_bonus)
                * (1.0 + sev_bonus)
                * (1.0 - tested_discount)
                * reward
                * penalty
            )
            return round(score, 4)
        except Exception:
            return 1.0

    def _score_and_enqueue(self, node) -> None:
        """Score a node and enqueue any untested agents."""
        priority = self._score_node(node)
        type_str  = str(node.node_type).split(".")[-1]
        tested    = self._agents_tested.get(node.id, set())
        agents    = _TYPE_AGENTS.get(type_str, [])

        record = NodePriorityRecord(
            node_id=node.id, node_label=node.label,
            node_type=type_str,
            target=str(node.properties.get("domain", node.label)),
            priority=priority, risk_score=float(node.risk_score or 0),
            in_degree=0, out_degree=0,
            agents_tested=list(tested),
        )
        with self._lock:
            self._node_priorities[node.id] = record

        for agent_type in agents:
            if agent_type not in tested:
                self._enqueue_action(node, agent_type, priority)

    def _enqueue_action(self, node, agent_type: str, priority: float) -> None:
        """Push a BrainAction onto the priority queue (deduplicated)."""
        key = f"{node.id}::{agent_type}"
        with self._lock:
            if key in self._queued_ids:
                return
            if len(self._action_queue) >= MAX_ACTION_QUEUE:
                return  # queue full; drop low-priority additions
            self._queued_ids.add(key)

        target = str(node.properties.get("domain", node.label))
        reasoning = (
            f"Node '{node.label}' (type={str(node.node_type).split('.')[-1]}) "
            f"has priority {priority:.2f}; agent '{agent_type}' has not yet tested it"
        )
        action = BrainAction(
            action_id=str(uuid.uuid4())[:12],
            agent_type=agent_type,
            node_id=node.id,
            node_label=node.label,
            node_type=str(node.node_type).split(".")[-1],
            target=target,
            priority=priority,
            context={"node_properties": dict(node.properties or {})},
            reasoning=reasoning,
        )
        with self._lock:
            heapq.heappush(self._action_queue, action)

        self._publish(BrainEventType.ACTION_QUEUED, {
            "action_id": action.action_id, "agent_type": agent_type,
            "node_id": node.id, "node_label": node.label,
            "priority": priority,
        })

    # ── Decision / dispatch ───────────────────────────────────────────────────

    def next_action(self) -> Optional[BrainAction]:
        """Pop the highest-priority pending action. Returns None if queue empty."""
        with self._lock:
            while self._action_queue:
                action = heapq.heappop(self._action_queue)
                key = f"{action.node_id}::{action.agent_type}"
                self._queued_ids.discard(key)
                # Skip if already tested since enqueue time
                if action.agent_type in self._agents_tested.get(action.node_id, set()):
                    continue
                action.dispatched = True
                self._actions_dispatched += 1
                return action
        return None

    def make_decision(self, target: str) -> Optional[BrainDecision]:
        """Derive the next best decision from current graph state."""
        action = self.next_action()
        if action is None:
            return None

        try:
            stats = self._get_engine().get_stats()
        except Exception:
            stats = {}

        graph_state = {
            "total_nodes": stats.get("total_nodes", 0),
            "total_edges": stats.get("total_edges", 0),
            "queue_depth": len(self._action_queue),
            "findings":    self._findings_integrated,
        }
        confidence = min(action.priority / 20.0, 1.0)
        decision = BrainDecision(
            decision_id=str(uuid.uuid4())[:12],
            target=target,
            action=action,
            graph_state=graph_state,
            reasoning=action.reasoning,
            confidence=confidence,
        )
        with self._lock:
            self._decisions.append(decision)
            self._decisions_made += 1

        self._publish(BrainEventType.DECISION_MADE, decision.to_dict())
        return decision

    # ── Bulk re-score (called periodically) ───────────────────────────────────

    def rescore_graph(self, target: Optional[str] = None) -> int:
        """Re-score all nodes in the graph (or for a specific target)."""
        rescored = 0
        try:
            eng = self._get_engine()
            nodes = eng.find_nodes()
            for node in nodes:
                self._score_and_enqueue(node)
                rescored += 1
        except Exception:
            pass
        if rescored:
            self._publish(BrainEventType.RISK_RECALCULATED, {
                "rescored": rescored, "target": target
            })
        return rescored

    # ── Query helpers ─────────────────────────────────────────────────────────

    def top_priority_nodes(self, n: int = 20) -> List[NodePriorityRecord]:
        with self._lock:
            records = sorted(
                self._node_priorities.values(),
                key=lambda r: r.priority,
                reverse=True,
            )
        return records[:n]

    def decision_history(self, limit: int = 50) -> List[dict]:
        with self._lock:
            items = list(self._decisions)
        items.reverse()
        return [d.to_dict() for d in items[:limit]]

    def queue_snapshot(self, limit: int = 50) -> List[dict]:
        with self._lock:
            # sorted copy — don't mutate the heap
            items = sorted(self._action_queue, key=lambda a: a.priority, reverse=True)
        return [a.to_dict() for a in items[:limit]]

    def findings_for_node(self, node_id: str) -> List[dict]:
        return list(self._findings.get(node_id, []))

    def attack_paths(self, target: str) -> List[dict]:
        try:
            q = self._get_query()
            eng = self._get_engine()
            targets = eng.find_nodes(node_type="TARGET", label_contains=target)
            if not targets:
                return []
            paths = q.find_attack_paths(targets[0].id, max_depth=8)
            return [p.to_dict() for p in paths[:20]]
        except Exception:
            return []

    def risk_report(self, target: str) -> dict:
        try:
            r = self._get_risk()
            return r.analyze(target).to_dict()
        except Exception:
            return {"target": target, "error": "risk analyzer unavailable"}

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> BrainStatus:
        try:
            stats = self._get_engine().get_stats()
            n_nodes = stats.get("total_nodes", 0)
            n_edges = stats.get("total_edges", 0)
        except Exception:
            n_nodes = n_edges = 0

        with self._lock:
            return BrainStatus(
                running=self._running,
                targets=sorted(self._targets),
                total_nodes=n_nodes,
                total_edges=n_edges,
                queue_depth=len(self._action_queue),
                decisions_made=self._decisions_made,
                actions_dispatched=self._actions_dispatched,
                findings_integrated=self._findings_integrated,
                last_loop_at=self._last_loop_at,
                uptime_s=time.time() - self._started_at if self._started_at else 0.0,
            )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, targets: List[str]) -> None:
        with self._lock:
            if self._running:
                for t in targets:
                    self.add_target(t)
                return
            self._running = True
            self._started_at = time.time()
        for t in targets:
            self.add_target(t)
        self.rescore_graph()

    def stop(self) -> None:
        with self._lock:
            self._running = False

    def set_action_callback(self, cb: Callable[[BrainAction], None]) -> None:
        self._on_action_ready = cb

    def set_finding_callback(self, cb: Callable[[dict], None]) -> None:
        self._on_finding = cb

    # ── Internal event publish ─────────────────────────────────────────────────

    def _publish(self, event_type: BrainEventType, data: dict) -> None:
        try:
            from event_bus import get_bus, EventType
            # Map brain events onto bus events where appropriate
            mapping = {
                BrainEventType.FINDING_INTEGRATED: "NEW_VULNERABILITY",
                BrainEventType.ACTION_QUEUED:       "AGENT_STATUS",
                BrainEventType.DECISION_MADE:       "AGENT_STATUS",
            }
            et_str = mapping.get(event_type, "AGENT_STATUS")
            try:
                et = EventType(et_str)
            except ValueError:
                et = EventType.AGENT_STATUS
            get_bus().publish(event_type=et, source="brain", data={
                "brain_event": event_type.value, **data
            })
        except Exception:
            pass


# ── Singleton ──────────────────────────────────────────────────────────────────

_brain: Optional[AttackGraphBrain] = None
_brain_lock = threading.Lock()


def get_brain() -> AttackGraphBrain:
    global _brain
    if _brain is None:
        with _brain_lock:
            if _brain is None:
                _brain = AttackGraphBrain()
    return _brain
