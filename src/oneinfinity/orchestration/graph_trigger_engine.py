"""
graph_trigger_engine.py — Graph Trigger Engine

Evaluates declarative trigger rules against the live attack graph
and spawns agent tasks when conditions are met.

Trigger anatomy:
  condition  — a callable(node, context) → bool
  agents     — list of agent types to spawn
  priority   — override priority (None = brain-computed)
  once       — if True, fire only once per (node_id, trigger_name)
  cooldown_s — minimum seconds between re-fires for the same node

Built-in trigger rules (in priority order):
  1.  parameter_detected     → xss, sqli, ssrf, ssti, open_redirect
  2.  api_endpoint_detected  → idor, auth, biz_logic
  3.  auth_flow_detected     → auth, biz_logic
  4.  subdomain_discovered   → recon
  5.  vulnerability_found    → exploit_chain (trigger chain worker)
  6.  high_risk_node         → all relevant agents
  7.  credential_found       → auth, exploit
  8.  service_found          → recon, ssrf
  9.  technology_detected    → recon (version-specific testing)
  10. admin_endpoint         → auth, idor, biz_logic
  11. upload_endpoint        → file_upload_agent
  12. graphql_endpoint       → sqli, idor, auth
  13. jwt_detected           → auth (JWT specific tests)
  14. open_redirect_param    → open_redirect
  15. ssrf_sink              → ssrf
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

log = logging.getLogger("graph_trigger_engine")

# ── Data models ───────────────────────────────────────────────────────────────

ConditionFn = Callable[[Any, dict], bool]  # (node, context) → bool


@dataclass
class TriggerRule:
    name:       str
    condition:  ConditionFn
    agents:     List[str]
    priority:   Optional[float] = None  # None = use brain score
    once:       bool = True             # fire only once per node
    cooldown_s: float = 60.0
    tags:       List[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "agents":      self.agents,
            "priority":    self.priority,
            "once":        self.once,
            "cooldown_s":  self.cooldown_s,
            "tags":        self.tags,
            "description": self.description,
        }


@dataclass
class TriggerFiring:
    trigger_name: str
    node_id:      str
    node_label:   str
    agents:       List[str]
    priority:     float
    target:       str
    fired_at:     float = field(default_factory=time.time)
    context:      dict  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "trigger_name": self.trigger_name,
            "node_id":      self.node_id,
            "node_label":   self.node_label,
            "agents":       self.agents,
            "priority":     self.priority,
            "target":       self.target,
            "fired_at":     self.fired_at,
        }


# ── Condition helpers ─────────────────────────────────────────────────────────

def _node_type_is(type_str: str) -> ConditionFn:
    def _check(node, ctx: dict) -> bool:
        return str(node.node_type).split(".")[-1] == type_str
    return _check


def _label_matches(*patterns: str) -> ConditionFn:
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    def _check(node, ctx: dict) -> bool:
        label = str(node.label or "")
        return any(r.search(label) for r in compiled)
    return _check


def _props_contain(key: str, *values: str) -> ConditionFn:
    def _check(node, ctx: dict) -> bool:
        props = node.properties or {}
        val   = str(props.get(key, "")).lower()
        return any(v.lower() in val for v in values)
    return _check


def _severity_in(*levels: str) -> ConditionFn:
    def _check(node, ctx: dict) -> bool:
        return str(node.severity or "").lower() in levels
    return _check


def _and(*conds: ConditionFn) -> ConditionFn:
    def _check(node, ctx: dict) -> bool:
        return all(c(node, ctx) for c in conds)
    return _check


def _or(*conds: ConditionFn) -> ConditionFn:
    def _check(node, ctx: dict) -> bool:
        return any(c(node, ctx) for c in conds)
    return _check


# ── Built-in trigger rules ─────────────────────────────────────────────────────

def _build_builtin_triggers() -> List[TriggerRule]:
    return [
        TriggerRule(
            name="parameter_detected",
            description="URL parameter → inject XSS, SQLi, SSRF, SSTI, open redirect payloads",
            condition=_node_type_is("PARAMETER"),
            agents=["xss", "sqli", "ssrf", "ssti", "open_redirect"],
            priority=8.0,
            once=False, cooldown_s=300.0,
            tags=["injection"],
        ),
        TriggerRule(
            name="api_endpoint_detected",
            description="REST/GraphQL API endpoint → test IDOR, auth bypass, business logic",
            condition=_node_type_is("API_ENDPOINT"),
            agents=["idor", "auth", "biz_logic"],
            priority=8.5,
            once=False, cooldown_s=600.0,
            tags=["api"],
        ),
        TriggerRule(
            name="auth_flow_detected",
            description="Authentication flow → test auth bypass and business logic",
            condition=_node_type_is("AUTH_FLOW"),
            agents=["auth", "biz_logic"],
            priority=9.0,
            once=False, cooldown_s=600.0,
            tags=["auth"],
        ),
        TriggerRule(
            name="subdomain_discovered",
            description="New subdomain → full recon pass",
            condition=_node_type_is("SUBDOMAIN"),
            agents=["recon"],
            priority=6.0,
            once=True, cooldown_s=3600.0,
            tags=["recon"],
        ),
        TriggerRule(
            name="vulnerability_found",
            description="Confirmed vulnerability → attempt exploit chains",
            condition=_and(_node_type_is("VULNERABILITY"), _severity_in("critical", "high", "medium")),
            agents=["exploit"],
            priority=9.5,
            once=False, cooldown_s=120.0,
            tags=["exploit"],
        ),
        TriggerRule(
            name="credential_found",
            description="Leaked credential → auth / ATO tests",
            condition=_node_type_is("CREDENTIAL"),
            agents=["auth", "exploit"],
            priority=9.8,
            once=True, cooldown_s=600.0,
            tags=["auth", "exploit"],
        ),
        TriggerRule(
            name="service_found",
            description="Exposed service → recon + SSRF pivot",
            condition=_node_type_is("SERVICE"),
            agents=["recon", "ssrf"],
            priority=5.5,
            once=True, cooldown_s=1800.0,
            tags=["recon"],
        ),
        TriggerRule(
            name="technology_detected",
            description="Identified technology → version-specific CVE scan",
            condition=_node_type_is("TECHNOLOGY"),
            agents=["recon"],
            priority=4.0,
            once=True, cooldown_s=7200.0,
            tags=["recon"],
        ),
        TriggerRule(
            name="admin_endpoint",
            description="Admin/management endpoint → privileged auth and IDOR tests",
            condition=_and(
                _or(_node_type_is("URL"), _node_type_is("API_ENDPOINT")),
                _label_matches(r"/admin", r"/manage", r"/dashboard", r"/control",
                               r"/panel", r"/superuser", r"/staff", r"/backoffice"),
            ),
            agents=["auth", "idor", "biz_logic"],
            priority=9.2,
            once=False, cooldown_s=600.0,
            tags=["admin", "auth"],
        ),
        TriggerRule(
            name="upload_endpoint",
            description="File upload endpoint → upload bypass, path traversal",
            condition=_and(
                _or(_node_type_is("URL"), _node_type_is("API_ENDPOINT")),
                _label_matches(r"/upload", r"/file", r"/import", r"/attachment",
                               r"/media", r"/document"),
            ),
            agents=["xss", "sqli"],
            priority=8.0,
            once=False, cooldown_s=600.0,
            tags=["upload"],
        ),
        TriggerRule(
            name="graphql_endpoint",
            description="GraphQL endpoint → introspection, injection, IDOR",
            condition=_and(
                _or(_node_type_is("URL"), _node_type_is("API_ENDPOINT")),
                _label_matches(r"/graphql", r"/gql", r"/query"),
            ),
            agents=["sqli", "idor", "auth"],
            priority=8.5,
            once=False, cooldown_s=600.0,
            tags=["graphql"],
        ),
        TriggerRule(
            name="jwt_detected",
            description="JWT token in props → JWT-specific auth bypass tests",
            condition=_props_contain("auth_type", "jwt", "bearer"),
            agents=["auth"],
            priority=8.8,
            once=True, cooldown_s=600.0,
            tags=["jwt", "auth"],
        ),
        TriggerRule(
            name="open_redirect_param",
            description="Known redirect parameter names → open redirect test",
            condition=_and(
                _node_type_is("PARAMETER"),
                _label_matches(r"(?:^|@)(url|redirect|next|return|goto|dest|destination|target)"),
            ),
            agents=["open_redirect", "ssrf"],
            priority=7.5,
            once=False, cooldown_s=300.0,
            tags=["redirect", "ssrf"],
        ),
        TriggerRule(
            name="ssrf_sink",
            description="SSRF-prone endpoint patterns → SSRF tests",
            condition=_and(
                _or(_node_type_is("URL"), _node_type_is("API_ENDPOINT"), _node_type_is("PARAMETER")),
                _label_matches(r"fetch", r"webhook", r"callback", r"proxy",
                               r"load", r"ping", r"import.*url", r"download"),
            ),
            agents=["ssrf"],
            priority=8.2,
            once=False, cooldown_s=300.0,
            tags=["ssrf"],
        ),
        TriggerRule(
            name="high_risk_node",
            description="Any exploitable, high/critical node → exhaustive agent sweep",
            condition=_and(
                _severity_in("critical", "high"),
                lambda node, ctx: bool(node.exploitable),
            ),
            agents=["xss", "sqli", "ssrf", "idor", "auth"],
            priority=10.0,
            once=False, cooldown_s=120.0,
            tags=["high_risk"],
        ),
    ]


# ── GraphTriggerEngine ────────────────────────────────────────────────────────

class GraphTriggerEngine:
    """
    Evaluates trigger rules against graph nodes and fires agent tasks.
    Plugs into the EventBus to receive NEW_NODE / NEW_ENDPOINT etc. events.
    """

    def __init__(self) -> None:
        self._rules: List[TriggerRule] = _build_builtin_triggers()
        self._lock  = threading.RLock()

        # Track firings: (node_id, trigger_name) → last fired timestamp
        self._firings: Dict[Tuple[str, str], float] = {}
        # Full firing history (recent)
        self._history: List[TriggerFiring] = []
        self._max_history = 500

        # Callbacks
        self._on_trigger: Optional[Callable[[TriggerFiring], None]] = None

        # Counters
        self._total_fired = 0
        self._total_evaluated = 0

    # ── Rule management ───────────────────────────────────────────────────────

    def add_rule(self, rule: TriggerRule) -> None:
        with self._lock:
            self._rules.append(rule)

    def remove_rule(self, name: str) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.name != name]
            return len(self._rules) < before

    def list_rules(self) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in self._rules]

    def set_trigger_callback(self, cb: Callable[[TriggerFiring], None]) -> None:
        self._on_trigger = cb

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate_node(self, node, context: dict = None) -> List[TriggerFiring]:
        """Evaluate all rules against a node; return firings (and invoke callback)."""
        context   = context or {}
        fired     = []
        target    = str((node.properties or {}).get("domain", node.label))
        now       = time.time()

        with self._lock:
            rules_snapshot = list(self._rules)

        for rule in rules_snapshot:
            self._total_evaluated += 1
            try:
                if not rule.condition(node, context):
                    continue
            except Exception:
                continue

            key = (node.id, rule.name)

            with self._lock:
                last = self._firings.get(key, 0.0)
                if rule.once and last > 0:
                    continue
                if now - last < rule.cooldown_s:
                    continue
                self._firings[key] = now

            priority = rule.priority or 7.0
            firing = TriggerFiring(
                trigger_name=rule.name,
                node_id=node.id,
                node_label=node.label,
                agents=list(rule.agents),
                priority=priority,
                target=target,
                context=context,
            )
            fired.append(firing)
            self._total_fired += 1

            with self._lock:
                self._history.append(firing)
                if len(self._history) > self._max_history:
                    self._history.pop(0)

            if self._on_trigger:
                try:
                    self._on_trigger(firing)
                except Exception as e:
                    log.warning("Trigger callback error: %s", e)

            log.debug("Trigger '%s' fired for node '%s' → agents %s",
                      rule.name, node.label, rule.agents)

        return fired

    def evaluate_graph(self) -> int:
        """Evaluate all rules against all nodes in the graph. Returns total firings."""
        total = 0
        try:
            from oneinfinity.attack_graph_core.graph_engine import get_engine
            nodes = get_engine().find_nodes()
            for node in nodes:
                firings = self.evaluate_node(node)
                total += len(firings)
        except Exception as e:
            log.warning("Graph evaluation error: %s", e)
        return total

    # ── Query ─────────────────────────────────────────────────────────────────

    def recent_firings(self, limit: int = 50) -> List[dict]:
        with self._lock:
            items = list(self._history[-limit:])
        items.reverse()
        return [f.to_dict() for f in items]

    def stats(self) -> dict:
        return {
            "rules":          len(self._rules),
            "total_evaluated": self._total_evaluated,
            "total_fired":    self._total_fired,
            "history_size":   len(self._history),
        }


# ── Singleton ──────────────────────────────────────────────────────────────────

_trigger_engine: Optional[GraphTriggerEngine] = None
_te_lock = threading.Lock()


def get_trigger_engine() -> GraphTriggerEngine:
    global _trigger_engine
    if _trigger_engine is None:
        with _te_lock:
            if _trigger_engine is None:
                _trigger_engine = GraphTriggerEngine()
    return _trigger_engine
