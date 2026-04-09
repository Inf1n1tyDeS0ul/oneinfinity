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
                from oneinfinity.attack_graph_core.graph_engine import get_engine
                self._engine = get_engine()
            except Exception as e:
                raise RuntimeError(f"AttackGraphEngine unavailable: {e}")
        return self._engine

    def _get_query(self):
        if self._query is None:
            from oneinfinity.attack_graph_core.graph_query_engine import GraphQueryEngine
            self._query = GraphQueryEngine(self._get_engine())
        return self._query

    def _get_risk(self):
        if self._risk is None:
            from oneinfinity.attack_graph_core.risk_analyzer import RiskAnalyzer
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
            from oneinfinity.attack_graph_core.graph_engine import NodeType
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
            from oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
            eng = self._get_engine()
            node = eng.get_node(node_id)
            if node:
                severity = finding.get("severity", "info")
                if severity in ("critical", "high", "medium"):
                    eng.update_node(node_id, exploitable=True, severity=severity)
                    vuln_label = finding.get("vuln_type") or finding.get("name", "finding")
                    vuln_node, _ = eng.get_or_create_node(
                        NodeType.VULNERABILITY, vuln_label,
                        properties={"severity": severity, **finding},
                        severity=severity, exploitable=True,
                    )
                    eng.add_edge(node_id, vuln_node.id, EdgeType.HAS_VULNERABILITY,
                                 label=vuln_label, probability=0.9)
                    self._score_and_enqueue(vuln_node)
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

        # Wire parent → VULNERABILITY edge using explicit label lookup (exact match).
        # If no parent node exists yet, create the target node on the fly so the
        # vulnerability is never left as a disconnected island.
        try:
            from oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
            eng = self._get_engine()
            wired = False
            for parent_label in ([url] if url and url != target else []) + [target]:
                # Prefer exact-label matches over substring search
                for ntype in (NodeType.URL, NodeType.API_ENDPOINT, NodeType.SUBDOMAIN,
                              NodeType.TARGET):
                    key = (ntype, parent_label)
                    parent_id = eng._label_index.get(key)
                    if parent_id and parent_id != node_id:
                        eng.add_edge(parent_id, node_id, EdgeType.HAS_VULNERABILITY,
                                     label=vuln_type or "vulnerability", probability=0.9)
                        wired = True
                        break
                if wired:
                    break

            if not wired:
                # No existing parent node — create a target node for the domain so
                # this vulnerability (and future ones for the same target) have a
                # reachable root in the graph.
                from urllib.parse import urlparse as _urlparse
                target_label = target or (_urlparse(url).netloc if url else "")
                if target_label and target_label != node_id:
                    t_node, _ = eng.get_or_create_node(
                        NodeType.TARGET, target_label,
                        properties={"domain": target_label},
                        source="integrate_vuln",
                    )
                    eng.add_edge(t_node.id, node_id, EdgeType.HAS_VULNERABILITY,
                                 label=vuln_type or "vulnerability", probability=0.9)
        except Exception as exc:
            log.debug("integrate_vuln: edge wiring failed [%s]: %s", finding_id, exc)

        log.info("[GRAPH] Added vulnerability node: %s (severity=%s)", finding_id, severity)
        return node_id

    def integrate_token(self, token_value: str, token_type: str, issuer_label: str,
                        target: str, properties: dict = None) -> Optional[str]:
        """
        Create a TOKEN node and wire it to its issuer (auth_flow/service) and
        any protected endpoints.

        token_type:   "jwt" | "api_key" | "oauth" | "session_cookie" | "bearer"
        issuer_label: label of the AUTH_FLOW or SERVICE node that issued it
        """
        try:
            from oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
            import hashlib
            eng = self._get_engine()
            # Fingerprint the token (don't store raw secrets in the graph)
            token_fp = hashlib.sha256(token_value.encode()).hexdigest()[:16]
            token_label = f"{token_type}:{token_fp}"
            props = {
                "token_type": token_type,
                "fingerprint": token_fp,
                "target": target,
                **(properties or {}),
            }
            token_node, created = eng.get_or_create_node(
                NodeType.TOKEN, token_label, properties=props,
                source="token_extractor",
            )
            if created:
                self._score_and_enqueue(token_node)

            # Wire issuer → TOKEN
            for issuer_type in (NodeType.AUTH_FLOW, NodeType.SERVICE):
                issuer_id = eng._label_index.get((issuer_type, issuer_label))
                if issuer_id:
                    eng.add_edge(issuer_id, token_node.id, EdgeType.ISSUES_TOKEN,
                                 label="issues_token", probability=1.0)
                    break

            # Register raw token in the execution engine's same-run cache so
            # _build_auth_headers() can inject it into subsequent requests
            # within this run, without persisting secrets to SQLite.
            try:
                from oneinfinity.core.token_execution_engine import get_token_execution_engine
                get_token_execution_engine().store_raw_token(token_fp, token_value)
            except Exception as cache_exc:
                log.debug("integrate_token: could not cache raw token: %s", cache_exc)

            log.info("[GRAPH] Token node: %s (type=%s, target=%s)", token_label, token_type, target)
            return token_node.id
        except Exception as exc:
            log.debug("integrate_token failed: %s", exc)
            return None

    def integrate_session(self, session_id: str, target: str, auth_endpoint: str = "",
                          properties: dict = None) -> Optional[str]:
        """
        Create a SESSION node and wire it to its authentication endpoint.
        """
        try:
            from oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
            import hashlib
            eng = self._get_engine()
            sess_fp = hashlib.sha256(session_id.encode()).hexdigest()[:16]
            sess_label = f"session:{sess_fp}"
            props = {
                "fingerprint": sess_fp,
                "target": target,
                "auth_endpoint": auth_endpoint,
                **(properties or {}),
            }
            sess_node, created = eng.get_or_create_node(
                NodeType.SESSION, sess_label, properties=props,
                source="session_extractor",
            )
            if created:
                self._score_and_enqueue(sess_node)

            # Wire session → protected endpoint (AUTH_FOR)
            if auth_endpoint:
                for ep_type in (NodeType.URL, NodeType.API_ENDPOINT):
                    ep_id = eng._label_index.get((ep_type, auth_endpoint))
                    if ep_id:
                        eng.add_edge(sess_node.id, ep_id, EdgeType.AUTH_FOR,
                                     label="auth_for", probability=0.9)
                        break

            log.info("[GRAPH] Session node: %s (target=%s)", sess_label, target)
            return sess_node.id
        except Exception as exc:
            log.debug("integrate_session failed: %s", exc)
            return None

    def extract_tokens_from_response(self, response_headers: dict, response_body: str,
                                     url: str, target: str) -> list:
        """
        Extract tokens/sessions from an HTTP response and add them to the graph.
        Returns list of created token node IDs.
        """
        import re
        node_ids = []

        # Extract JWT tokens (Authorization header or body)
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        for header_val in response_headers.values():
            for match in jwt_pattern.finditer(str(header_val)):
                nid = self.integrate_token(match.group(), "jwt", url, target,
                                           {"source": "response_header"})
                if nid:
                    node_ids.append(nid)
        for match in jwt_pattern.finditer(response_body or ""):
            nid = self.integrate_token(match.group(), "jwt", url, target,
                                       {"source": "response_body"})
            if nid:
                node_ids.append(nid)

        # Extract Set-Cookie session tokens
        set_cookie = response_headers.get("Set-Cookie", "") or response_headers.get("set-cookie", "")
        if set_cookie:
            cookie_session = re.search(r'(?:session|sess|SESS|PHPSESSID|JSESSIONID)=([^;]+)', set_cookie)
            if cookie_session:
                nid = self.integrate_session(cookie_session.group(1), target, url,
                                             {"cookie": cookie_session.group(0)})
                if nid:
                    node_ids.append(nid)

        # Extract bearer tokens from Authorization header
        auth_header = response_headers.get("Authorization", "") or response_headers.get("authorization", "")
        bearer_match = re.search(r'Bearer\s+([A-Za-z0-9_\-\.]+)', str(auth_header))
        if bearer_match:
            nid = self.integrate_token(bearer_match.group(1), "bearer", url, target,
                                       {"source": "authorization_header"})
            if nid:
                node_ids.append(nid)

        return node_ids

    def integrate_api_relationships(self, source_url: str, response_body: str,
                                    response_headers: dict, target: str) -> int:
        """
        FIX 2: Deep relationship modeling.
        Detects API→API CALLS edges and endpoint→auth AUTH_FOR edges from
        HTTP response content (redirects, JSON hrefs, JS fetch() calls).
        Returns count of new edges wired.
        """
        import re
        edges_added = 0
        try:
            from oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
            eng = self._get_engine()

            # Resolve or create the source endpoint node
            src_id = (eng._label_index.get((NodeType.URL, source_url)) or
                      eng._label_index.get((NodeType.API_ENDPOINT, source_url)))
            if src_id is None:
                src_node = eng.add_node(NodeType.URL, source_url,
                                        properties={"url": source_url, "target": target})
                src_id = src_node.id

            # 1. Detect API call patterns in JS / JSON (fetch, axios, XMLHttpRequest, href)
            api_call_re = re.compile(
                r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`\s]+)['"`]"""
                r"""|["']href["']\s*:\s*["']([^"']+)["']"""
                r"""|url\s*:\s*["']([^"']{6,})["']""",
                re.IGNORECASE,
            )
            for m in api_call_re.finditer(response_body or ""):
                called = next((g for g in m.groups() if g), None)
                if not called:
                    continue
                # Normalise relative paths
                if called.startswith("/") and "://" not in called:
                    from urllib.parse import urlparse as _up
                    parsed = _up(source_url)
                    called = f"{parsed.scheme}://{parsed.netloc}{called}"
                if "://" not in called:
                    continue
                called_id = (eng._label_index.get((NodeType.API_ENDPOINT, called)) or
                             eng._label_index.get((NodeType.URL, called)))
                if called_id is None:
                    called_node = eng.add_node(NodeType.API_ENDPOINT, called,
                                               properties={"url": called, "target": target,
                                                           "discovered_via": "js_analysis"})
                    called_id = called_node.id
                    self._score_and_enqueue(called_node)
                # Add CALLS edge
                e = eng.add_edge(src_id, called_id, EdgeType.CALLS,
                                 label="calls", probability=0.8)
                if e:
                    edges_added += 1

            # 2. Detect redirect targets → CALLS edge
            location = response_headers.get("Location", "") or response_headers.get("location", "")
            if location and "://" in location:
                redir_id = (eng._label_index.get((NodeType.URL, location)) or
                            eng._label_index.get((NodeType.API_ENDPOINT, location)))
                if redir_id is None:
                    redir_node = eng.add_node(NodeType.URL, location,
                                              properties={"url": location, "target": target,
                                                          "discovered_via": "redirect"})
                    redir_id = redir_node.id
                e = eng.add_edge(src_id, redir_id, EdgeType.CALLS,
                                 label="redirect", probability=0.9)
                if e:
                    edges_added += 1

            # 3. Detect auth requirements (401/403 with WWW-Authenticate)
            status_hint = response_headers.get("_status_code", 0)
            www_auth = response_headers.get("WWW-Authenticate", "") or \
                       response_headers.get("www-authenticate", "")
            if www_auth or str(status_hint) in ("401", "403"):
                # Find or create an AUTH_FLOW node for this endpoint's auth scheme
                auth_scheme = (www_auth.split()[0] if www_auth else "unknown_auth").lower()
                auth_label = f"auth:{auth_scheme}:{target}"
                auth_node, _ = eng.get_or_create_node(
                    NodeType.AUTH_FLOW, auth_label,
                    properties={"scheme": auth_scheme, "target": target,
                                "endpoint": source_url},
                )
                e = eng.add_edge(src_id, auth_node.id, EdgeType.AUTHENTICATED_BY,
                                 label="requires_auth", probability=1.0,
                                 requires_auth=True)
                if e:
                    edges_added += 1

        except Exception as exc:
            log.debug("integrate_api_relationships: failed for %s: %s", source_url, exc)

        if edges_added:
            log.debug("[GRAPH] Deep relationships: +%d edges from %s", edges_added, source_url)
        return edges_added

    def record_chain_failure(self, chain_type: str, vuln_type: str, target: str) -> None:
        """
        FIX 6: Record a failed/unexecutable chain so its nodes get deprioritized.
        """
        try:
            from oneinfinity.attack_graph_core.graph_engine import NodeType
            eng = self._get_engine()
            # Find vulnerability nodes that were part of this chain trigger
            cands = eng.find_nodes(node_type=NodeType.VULNERABILITY, label_contains=vuln_type)
            for node in cands:
                # Optionally filter by target if stored in properties; skip check if not present
                if target and node.properties.get("target") and node.properties["target"] != target:
                    continue
                penalty = float(node.properties.get("brain_penalty", 1.0))
                eng.update_node(node.id, properties={"brain_penalty": penalty * 0.7,
                                                      "chain_failure": chain_type})
                log.debug("record_chain_failure: penalized node %s (chain=%s)", node.id[:8], chain_type)
            try:
                from oneinfinity.core.graph_neo4j_bootstrap import publish_chain_feedback_neo4j
                publish_chain_feedback_neo4j(
                    chain_type, False, target=target or "", vuln_type=vuln_type or "",
                )
            except Exception:
                pass
        except Exception as exc:
            log.debug("record_chain_failure: %s", exc)

    def compute_graph_metrics(self) -> dict:
        """
        FIX 8: Return graph quality metrics for inclusion in reports.
        """
        try:
            eng = self._get_engine()
            stats = eng.get_stats()
            n = stats.get("total_nodes", 0)
            e = stats.get("total_edges", 0)
            avg_degree = round((2 * e / n), 2) if n > 0 else 0.0

            # Chain success rate from node properties
            from oneinfinity.attack_graph_core.graph_engine import NodeType
            all_vulns = eng.find_nodes(node_type=NodeType.VULNERABILITY)
            chain_success = sum(1 for v in all_vulns if v.properties.get("chain_confirmed"))
            chain_attempts = sum(1 for v in all_vulns if v.properties.get("chain_attempts", 0) > 0)
            chain_rate = round(chain_success / chain_attempts, 2) if chain_attempts > 0 else 0.0

            exploitable = stats.get("exploitable_nodes", 0)
            validated   = stats.get("validated_nodes", 0)

            return {
                "node_count":        n,
                "edge_count":        e,
                "avg_degree":        avg_degree,
                "chain_success_rate": chain_rate,
                "chain_attempts":    chain_attempts,
                "chain_confirmed":   chain_success,
                "exploitable_nodes": exploitable,
                "validated_nodes":   validated,
                "nodes_by_type":     stats.get("nodes_by_type", {}),
                "edges_by_type":     stats.get("edges_by_type", {}),
                "vulns_by_severity": stats.get("vulnerabilities_by_severity", {}),
            }
        except Exception as exc:
            log.debug("compute_graph_metrics: %s", exc)
            return {}

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

            # Graph-score: reachability of this node from known high-value vuln nodes
            graph_score = 0.0
            try:
                q = self._get_query()
                # Count how many confirmed-exploitable vulns can reach this node
                from oneinfinity.attack_graph_core.graph_engine import NodeType as _NT
                exploit_parents = eng.find_nodes(node_type=_NT.VULNERABILITY, exploitable=True)
                reachable_count = 0
                for ep in exploit_parents[:10]:  # cap to avoid O(n²)
                    paths = q.dfs_paths(ep.id, node.id, max_depth=3)
                    if paths:
                        reachable_count += 1
                # Cap contribution at 0.5 (5 or more reachable exploits → full bonus)
                graph_score = min(reachable_count / 10.0, 0.5)
            except Exception:
                pass

            # Feedback reward/penalty
            reward = float(node.properties.get("brain_reward", 1.0))
            penalty = float(node.properties.get("brain_penalty", 1.0))

            score = (
                base
                * (1.0 + conn * 0.5)
                * (1.0 + vuln_bonus)
                * (1.0 + sev_bonus)
                * (1.0 + graph_score)
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
            from oneinfinity.event_bus import get_bus, EventType
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
