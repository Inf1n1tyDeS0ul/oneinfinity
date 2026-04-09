"""
agent_swarm_coordinator.py — Swarm Orchestration Engine

Coordinates all specialized agents through:
  - Priority task queue (asyncio.PriorityQueue)
  - Parallel execution with rate-limiting semaphore
  - Agent competition: multiple agents bid on the same endpoint; first win
    broadcasts to others which may then abort
  - Agent collaboration: findings emitted to an event bus (asyncio.Queue)
    so a SQLI finding on a URL can immediately trigger IDORAgent on the same URL
  - Shared mutable state: attack graph + KB + findings (async-safe)
  - Result aggregation: SHA-256 dedup + chain candidate detection

Usage:
    from oneinfinity.agent_swarm_coordinator import AgentSwarmCoordinator

    coord = AgentSwarmCoordinator(
        tool_registry=reg,
        attack_graph=engine,
        knowledge_base=kb,
    )
    result = asyncio.run(coord.scan(target="example.com", context={...}))
    print(result.summary())
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Optional platform imports ─────────────────────────────────────────────────

try:
    from oneinfinity.attack_graph_core.graph_engine import AttackGraphEngine, NodeType, EdgeType, get_engine
    _GRAPH_AVAILABLE = True
except ImportError:
    _GRAPH_AVAILABLE = False

try:
    from oneinfinity.core.learning_repository import get_learning_repo_sync as _get_learning_repo_sync
    _KB_AVAILABLE = True
except ImportError:
    _KB_AVAILABLE = False
    _get_learning_repo_sync = None  # type: ignore

try:
    from oneinfinity.attack_graph_core.graph_query_engine import GraphQueryEngine
    _QUERY_AVAILABLE = True
except ImportError:
    _QUERY_AVAILABLE = False

from oneinfinity.swarm_intelligence_engine import (
    AgentType, AgentFinding, SwarmAgent,
    create_agent, create_full_swarm,
)
try:
    from oneinfinity.attack_simulation_engine import AttackSimulationEngine
    _SIM_AVAILABLE = True
except ImportError:
    _SIM_AVAILABLE = False


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass(order=True)
class SwarmTask:
    """Unit of work dispatched to one or more agents."""
    priority:    float              = field(compare=True)   # lower = higher priority
    task_id:     str                = field(compare=False, default_factory=lambda: uuid.uuid4().hex[:10])
    agent_type:  AgentType          = field(compare=False, default=AgentType.XSS)
    target:      str                = field(compare=False, default="")
    context:     Dict[str, Any]     = field(compare=False, default_factory=dict)
    claimed_by:  Optional[str]      = field(compare=False, default=None)
    completed:   bool               = field(compare=False, default=False)
    created_at:  float              = field(compare=False, default_factory=time.time)


@dataclass
class SharedSwarmState:
    """Thread-safe shared state accessible by all agents."""
    session_id:    str                = field(default_factory=lambda: f"SWARM-{uuid.uuid4().hex[:8].upper()}")
    findings:      List[AgentFinding] = field(default_factory=list)
    event_queue:   asyncio.Queue      = field(default_factory=asyncio.Queue)
    claimed_tasks: Dict[str, str]     = field(default_factory=dict)  # task_id → agent_id
    agent_results: Dict[str, List]    = field(default_factory=dict)  # agent_id → findings
    graph_nodes_added: int            = 0
    started_at:    float              = field(default_factory=time.time)

    def claim_task(self, task_id: str, agent_id: str) -> None:
        """Mark a task as claimed by an agent (in-memory)."""
        self.claimed_tasks[task_id] = agent_id

    def to_dict(self) -> Dict:
        return {
            "session_id":      self.session_id,
            "total_findings":  len(self.findings),
            "agents_ran":      len(self.agent_results),
            "graph_additions": self.graph_nodes_added,
            "elapsed_s":       round(time.time() - self.started_at, 1),
        }


@dataclass
class SwarmScanResult:
    """Aggregated output from a completed swarm scan."""
    session_id:    str
    target:        str
    findings:      List[AgentFinding]
    agent_stats:   Dict[str, int]          # agent_type → finding count
    chain_candidates: List[Dict]
    graph_stats:   Dict
    simulation_priorities: List[Dict]
    elapsed_s:     float
    dedup_removed: int

    def summary(self) -> str:
        lines = [
            f"━━━ SWARM SCAN RESULT ━━━",
            f"Session : {self.session_id}",
            f"Target  : {self.target}",
            f"Elapsed : {self.elapsed_s:.1f}s",
            f"Findings: {len(self.findings)} (dedup removed {self.dedup_removed})",
            "",
            "By agent:",
        ]
        for agent, count in sorted(self.agent_stats.items(), key=lambda x: -x[1]):
            lines.append(f"  {agent:<20} {count}")
        if self.chain_candidates:
            lines.append(f"\nChain candidates: {len(self.chain_candidates)}")
            for c in self.chain_candidates[:3]:
                lines.append(f"  → {c.get('chain')}: {c.get('steps')}")
        return "\n".join(lines)

    def to_dict(self) -> Dict:
        return {
            "session_id":          self.session_id,
            "target":              self.target,
            "findings":            [vars(f) for f in self.findings],
            "agent_stats":         self.agent_stats,
            "chain_candidates":    self.chain_candidates,
            "graph_stats":         self.graph_stats,
            "simulation_priorities": self.simulation_priorities,
            "elapsed_s":           self.elapsed_s,
            "dedup_removed":       self.dedup_removed,
        }


# ── Coordinator ───────────────────────────────────────────────────────────────

class AgentSwarmCoordinator:
    """
    Central orchestrator for the multi-agent swarm.

    Responsibilities:
      1. Build task queue from simulation priorities + context
      2. Spin up agents; inject shared state + event bus
      3. Run agents in parallel (configurable concurrency)
      4. Process event bus: broadcast findings, trigger collaborations
      5. Aggregate, dedup, and chain-detect all findings
      6. Update attack graph with final risk assessment
    """

    # How many agents run concurrently
    DEFAULT_CONCURRENCY = 6

    # Collaboration triggers: when agent A finds vuln_type V,
    # immediately enqueue a task for agent B with boosted priority.
    COLLABORATION_RULES: List[Tuple[str, AgentType, float]] = [
        # (found vuln_type_prefix, trigger_agent_type, priority_boost)
        ("sqli",            AgentType.IDOR,           0.20),
        ("ssrf",            AgentType.IDOR,           0.15),
        ("xss",             AgentType.AUTH,           0.10),
        ("idor",            AgentType.AUTH,           0.15),
        ("auth",            AgentType.IDOR,           0.20),
        ("graphql",         AgentType.IDOR,           0.25),
        ("mass_assignment", AgentType.AUTH,           0.20),
        ("weak_credential", AgentType.BUSINESS_LOGIC, 0.10),
    ]

    def __init__(
        self,
        tool_registry:  Optional[Any] = None,
        attack_graph:   Optional[Any] = None,
        knowledge_base: Optional[Any] = None,
        concurrency:    int            = DEFAULT_CONCURRENCY,
        agent_types:    Optional[List[AgentType]] = None,
    ):
        self.tool_registry  = tool_registry or self._try_load_registry()
        self.attack_graph   = attack_graph  or self._try_load_graph()
        self.knowledge_base = knowledge_base or self._try_load_kb()
        self.concurrency    = concurrency
        self.agent_types    = agent_types or list(AgentType)
        self._sim_engine: Optional[Any] = None
        if _SIM_AVAILABLE:
            try:
                self._sim_engine = AttackSimulationEngine(knowledge_base=self.knowledge_base)
            except Exception:
                pass

    # ── State factory ─────────────────────────────────────────────────────────

    def _make_swarm_state(self, scan_id: str):
        """Return Redis-backed state when Redis is available, else in-memory."""
        try:
            from oneinfinity.core.redis_client import get_redis
            from oneinfinity.core.swarm_state_redis import RedisSwarmState
            r = get_redis()
            if r is not None:
                return RedisSwarmState(scan_id=scan_id, redis=r)
        except Exception as exc:
            logger.warning("Swarm state: Redis init failed (%s) — using in-memory", exc)
        return SharedSwarmState(session_id=scan_id)

    # ── Public API ────────────────────────────────────────────────────────────

    async def scan(self, target: str, context: Dict[str, Any]) -> SwarmScanResult:
        """
        Run the full swarm against a target.

        context keys (all optional):
          endpoints      : List[str]
          parameters     : Dict[str, List[str]]  endpoint → params
          tech_stack     : List[str]
          auth_endpoints : List[str]
          jwt_tokens     : List[str]
          auth_sessions  : List[Dict]  [{cookie, token, other_username}]
          api_endpoints  : List[str]
          js_sinks       : List[Dict]
          apk_id         : str
          current_user_id: int
          workflows      : List[Dict]
        """
        start = time.time()
        import uuid as _uuid
        _session_id = _uuid.uuid4().hex[:16]
        state = self._make_swarm_state(_session_id)
        # event_queue and findings are always process-local
        _local_findings: list = getattr(state, "findings", [])
        _local_queue = getattr(state, "event_queue", asyncio.Queue())
        state_dict: Dict[str, Any] = {
            "session_id":    state.session_id,
            "findings":      _local_findings,
            "event_queue":   _local_queue,
            "claimed_tasks": getattr(state, "_mem_claimed", {}),
            "_swarm_state":  state,   # retained so listeners can call state.claim_task()
        }

        logger.info("[Coordinator] Starting swarm session %s for %s", state.session_id, target)

        # ── 1. Pre-scan simulation to rank attack priorities ──────────────────
        sim_priorities: List[Dict] = []
        if self._sim_engine:
            try:
                sim_results = await self._sim_engine.simulate_all_paths(target, context)
                sim_priorities = [
                    {"attack_type": r.attack_type,
                     "probability": round(r.success_probability, 3),
                     "impact":      round(r.impact_score, 2),
                     "ev":          round(r.expected_value, 3),
                     "recommended": r.recommended}
                    for r in sim_results[:10]
                ]
                logger.info("[Coordinator] Simulation complete: %d paths ranked", len(sim_results))
            except Exception as exc:
                logger.debug("[Coordinator] Simulation error: %s", exc)

        # ── 2. Build task queue ───────────────────────────────────────────────
        task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        await self._build_task_queue(task_queue, target, context, sim_priorities)

        # ── 3. Instantiate agents with shared state ───────────────────────────
        agents = create_full_swarm(
            tool_registry  = self.tool_registry,
            attack_graph   = self.attack_graph,
            knowledge_base = self.knowledge_base,
            shared_state   = state_dict,
            agent_types    = self.agent_types,
        )

        # Inject multi-session context for IDOR agent
        idor_agent = agents.get(AgentType.IDOR)
        if idor_agent and hasattr(idor_agent, "set_auth_sessions"):
            idor_agent.set_auth_sessions(context.get("auth_sessions", []))

        # ── 4. Run agent pool in parallel ─────────────────────────────────────
        semaphore = asyncio.Semaphore(self.concurrency)

        async def run_agent(agent: SwarmAgent, task: SwarmTask) -> List[AgentFinding]:
            async with semaphore:
                try:
                    merged_ctx = {**context, **task.context}
                    return await agent.run(task.target, merged_ctx)
                except Exception as exc:
                    logger.error("[Coordinator] Agent %s error: %s", agent.name, exc)
                    return []

        # Drain the task queue and collect coroutines
        coros = []
        while not task_queue.empty():
            task: SwarmTask = (await task_queue.get())[1]
            agent = agents.get(task.agent_type)
            if agent:
                coros.append(run_agent(agent, task))

        # ── 5. Execute all agents + event bus listener concurrently ──────────
        event_listener_task = asyncio.create_task(
            self._event_bus_listener(state_dict, agents, task_queue, target, context)
        )

        agent_result_lists = await asyncio.gather(*coros, return_exceptions=True)
        event_listener_task.cancel()
        try:
            await event_listener_task
        except asyncio.CancelledError:
            pass

        # ── 6. Collect all findings ───────────────────────────────────────────
        all_raw: List[AgentFinding] = list(_local_findings)
        for res in agent_result_lists:
            if isinstance(res, list):
                all_raw.extend(res)

        # ── 7. Aggregate: dedup + chain detection + graph update ──────────────
        (unique_findings, dedup_removed, chain_candidates) = await self._aggregate(
            all_raw, target, state.session_id
        )

        # ── 8. Build stats ────────────────────────────────────────────────────
        agent_stats: Dict[str, int] = {}
        for f in unique_findings:
            key = f.agent_type.value if hasattr(f.agent_type, "value") else str(f.agent_type)
            agent_stats[key] = agent_stats.get(key, 0) + 1

        graph_stats = {}
        if self.attack_graph and _GRAPH_AVAILABLE:
            try:
                graph_stats = self.attack_graph.get_stats()
            except Exception:
                pass

        elapsed = round(time.time() - start, 2)
        logger.info(
            "[Coordinator] Swarm complete: %d findings, %d deduped, %.1fs",
            len(unique_findings), dedup_removed, elapsed
        )

        return SwarmScanResult(
            session_id            = state.session_id,
            target                = target,
            findings              = unique_findings,
            agent_stats           = agent_stats,
            chain_candidates      = chain_candidates,
            graph_stats           = graph_stats,
            simulation_priorities = sim_priorities,
            elapsed_s             = elapsed,
            dedup_removed         = dedup_removed,
        )

    # ── Task queue builder ────────────────────────────────────────────────────

    async def _build_task_queue(
        self,
        queue:          asyncio.PriorityQueue,
        target:         str,
        context:        Dict,
        sim_priorities: List[Dict],
    ) -> None:
        """
        Create one SwarmTask per agent type.
        Priority is derived from simulation expected-value scores when available;
        otherwise uses a sensible default ordering.
        """
        # Build EV lookup from simulation
        ev_lookup: Dict[str, float] = {}
        for s in sim_priorities:
            if s.get("recommended"):
                ev_lookup[s["attack_type"]] = s.get("ev", 0.5)

        DEFAULT_PRIORITIES: Dict[AgentType, float] = {
            AgentType.SQLI:           0.10,
            AgentType.SSRF:           0.15,
            AgentType.AUTH:           0.20,
            AgentType.IDOR:           0.25,
            AgentType.XSS:            0.30,
            AgentType.API:            0.35,
            AgentType.BUSINESS_LOGIC: 0.40,
            AgentType.MOBILE:         0.50,
        }

        for agent_type in self.agent_types:
            # Derive priority: lower number = higher priority
            ev = ev_lookup.get(agent_type.value, 0.0)
            base_prio = DEFAULT_PRIORITIES.get(agent_type, 0.50)
            # Simulation boost: subtract EV (so high-EV attacks get lower priority number)
            priority = max(0.01, base_prio - ev * 0.3)

            task = SwarmTask(
                priority   = priority,
                agent_type = agent_type,
                target     = target,
                context    = {},   # agent reads from outer context
            )
            await queue.put((priority, task))

        logger.debug("[Coordinator] Task queue built: %d tasks", queue.qsize())

    # ── Event bus ─────────────────────────────────────────────────────────────

    async def _event_bus_listener(
        self,
        state_dict: Dict[str, Any],
        agents:    Dict[AgentType, SwarmAgent],
        queue:     asyncio.PriorityQueue,
        target:    str,
        context:   Dict,
    ) -> None:
        """
        Listens on the shared event queue.
        When an agent publishes a finding:
          - Check collaboration rules
          - If triggered, enqueue a new high-priority task for the target agent
            with the finding's endpoint added to context
        """
        processed: Set[str] = set()
        _event_queue: asyncio.Queue = state_dict["event_queue"]
        _claimed_tasks: dict = state_dict["claimed_tasks"]

        while True:
            try:
                event = await asyncio.wait_for(_event_queue.get(), timeout=2.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return

            if event.get("type") != "finding":
                continue

            finding: AgentFinding = event.get("finding")
            if not finding or finding.finding_id in processed:
                continue
            processed.add(finding.finding_id)

            # Competition: mark task as claimed by the finder (via state for Redis persistence)
            _swarm_state = state_dict.get("_swarm_state")
            if _swarm_state is not None:
                _swarm_state.claim_task(finding.target, finding.agent_id)
            else:
                _claimed_tasks[finding.target] = finding.agent_id

            # Collaboration: trigger partner agents
            for vuln_prefix, target_agent_type, boost in self.COLLABORATION_RULES:
                if finding.vuln_type.startswith(vuln_prefix):
                    partner = agents.get(target_agent_type)
                    if partner and partner.status.value in ("idle", "done"):
                        collab_ctx = {
                            "endpoints":   [finding.target],
                            "triggered_by": finding.finding_id,
                            "vuln_context": finding.vuln_type,
                        }
                        new_task = SwarmTask(
                            priority   = 0.05 - boost,   # very high priority
                            agent_type = target_agent_type,
                            target     = target,
                            context    = collab_ctx,
                        )
                        await queue.put((new_task.priority, new_task))
                        logger.info(
                            "[EventBus] %s finding → triggering %s (collaboration)",
                            finding.vuln_type, target_agent_type.value,
                        )

    # ── Aggregation ───────────────────────────────────────────────────────────

    async def _aggregate(
        self, findings: List[AgentFinding], target: str, session_id: str
    ) -> Tuple[List[AgentFinding], int, List[Dict]]:
        """
        1. Deduplicate by SHA-256 fingerprint (vuln_type + target + payload[:80])
        2. Detect exploit chain candidates from chain_potential overlap
        3. Update graph with confirmed high-confidence findings
        Returns (unique_findings, dedup_removed, chain_candidates)
        """
        seen: Dict[str, AgentFinding] = {}
        dedup_removed = 0

        for f in findings:
            fp = hashlib.sha256(
                f"{f.vuln_type}|{f.target}|{f.payload[:80]}".encode()
            ).hexdigest()[:16]
            if fp not in seen:
                seen[fp] = f
            else:
                dedup_removed += 1
                # Keep the higher-confidence version
                if f.confidence > seen[fp].confidence:
                    seen[fp] = f

        unique = list(seen.values())
        unique.sort(key=lambda x: x.cvss, reverse=True)

        # Chain candidate detection
        chain_candidates = self._detect_chains(unique)

        # Persist to KB
        if self.knowledge_base and _KB_AVAILABLE:
            try:
                for f in unique:
                    self.knowledge_base.record_finding_sync(
                        session_id=session_id,
                        finding=f.to_kb_dict(),
                        confirmed=f.reproduced,
                    )
            except Exception as exc:
                logger.debug("[Coordinator] KB persist error: %s", exc)

        return unique, dedup_removed, chain_candidates

    def _detect_chains(self, findings: List[AgentFinding]) -> List[Dict]:
        """
        Cross-reference chain_potential fields to find confirmed multi-step chains.
        Returns dicts describing detected chains with step details.
        """
        # Build index: chain_name → [finding, ...]
        chain_index: Dict[str, List[AgentFinding]] = {}
        for f in findings:
            for cp in f.chain_potential:
                chain_index.setdefault(cp, []).append(f)

        # Known multi-step chain patterns (chain_a links to chain_b)
        KNOWN_CHAINS = [
            ("xss_to_account_takeover",    "xss",          "auth",    "XSS → Account Takeover"),
            ("sqli_to_rce",                "sqli",         "ssrf",    "SQLi → RCE"),
            ("sqli_to_data_exfiltration",  "sqli",         "idor",    "SQLi → Data Exfil"),
            ("ssrf_to_iam_takeover",       "ssrf",         "auth",    "SSRF → IAM Takeover"),
            ("ssrf_cloud_chain",           "ssrf",         "idor",    "SSRF → Cloud Metadata → Priv Esc"),
            ("idor_to_account_takeover",   "idor",         "auth",    "IDOR → Account Takeover"),
            ("bola_to_data_breach",        "bola",         "idor",    "BOLA → Data Breach"),
            ("price_manipulation_to_free_goods", "price",  "business","Price Manipulation Chain"),
            ("race_condition_to_double_spend", "race",     "business","Race → Double Spend"),
            ("weak_creds_to_full_compromise", "weak_creds","auth",    "Weak Creds → Full Compromise"),
        ]

        detected = []
        for chain_name, step1_prefix, step2_type, description in KNOWN_CHAINS:
            step1 = [f for f in findings if f.vuln_type.startswith(step1_prefix)
                     or chain_name in f.chain_potential]
            step2 = [f for f in findings if step2_type in f.agent_type.value]
            if step1 and step2:
                detected.append({
                    "chain":       chain_name,
                    "description": description,
                    "steps":       f"{step1[0].vuln_type} → {step2[0].vuln_type}",
                    "cvss_max":    max(step1[0].cvss, step2[0].cvss),
                    "findings":    [step1[0].finding_id, step2[0].finding_id],
                })

        return detected

    # ── Graph integration ─────────────────────────────────────────────────────

    def add_target_to_graph(self, target: str) -> Optional[str]:
        """Register the target domain as a TARGET node. Returns node id."""
        if not self.attack_graph or not _GRAPH_AVAILABLE:
            return None
        try:
            node = self.attack_graph.add_node(
                node_type=NodeType.TARGET,
                label=target,
                source="swarm_coordinator",
            )
            return node.id
        except Exception:
            return None

    # ── Lazy loader helpers ───────────────────────────────────────────────────

    @staticmethod
    def _try_load_registry():
        if not _GRAPH_AVAILABLE:
            return None
        try:
            from oneinfinity.modules.tool_wrappers import ToolRegistry
            return ToolRegistry()
        except Exception:
            return None

    @staticmethod
    def _try_load_graph():
        if not _GRAPH_AVAILABLE:
            return None
        try:
            return get_engine()
        except Exception:
            return None

    @staticmethod
    def _try_load_kb():
        if not _KB_AVAILABLE:
            return None
        try:
            return _get_learning_repo_sync()
        except Exception:
            return None


# ── Convenience runner ────────────────────────────────────────────────────────

async def run_swarm(
    target:        str,
    context:       Dict[str, Any],
    tool_registry: Optional[Any] = None,
    attack_graph:  Optional[Any] = None,
    knowledge_base: Optional[Any] = None,
    concurrency:   int = AgentSwarmCoordinator.DEFAULT_CONCURRENCY,
    agent_types:   Optional[List[AgentType]] = None,
) -> SwarmScanResult:
    """Top-level helper: create coordinator and run a full swarm scan."""
    coord = AgentSwarmCoordinator(
        tool_registry  = tool_registry,
        attack_graph   = attack_graph,
        knowledge_base = knowledge_base,
        concurrency    = concurrency,
        agent_types    = agent_types,
    )
    return await coord.scan(target, context)
