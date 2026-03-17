"""
Multi-Agent Coordinator — orchestrates all specialist agents for autonomous pentesting.
Distributes tasks by specialization, routes messages, manages agent lifecycle.

v2: Integrates core infrastructure — parallel scan sub-tasks, deduplication,
multi-format reporting, scope validation, scan profiles, and plugin registry.
"""

from __future__ import annotations

import concurrent.futures
import queue
import threading
import time
import uuid
from pathlib import Path
from typing import List, Optional

from agents.base import (
    AgentState, BaseAgent, Message, MessageType, Task, TaskResult
)

# Core infrastructure (imported lazily to keep backward compatibility)
def _load_core():
    try:
        from core.deduplicator import Deduplicator
        from core.reporter import Reporter
        from core.scope_validator import ScopeValidator
        from core.scan_profiles import get_profile, PROFILES
        from core.plugin_registry import plugin_registry
        from core.cache import recon_cache
        return Deduplicator, Reporter, ScopeValidator, get_profile, PROFILES, plugin_registry, recon_cache
    except ImportError:
        return None, None, None, None, None, None, None


class AgentCoordinator:
    """
    Central coordinator for the multi-agent pentesting system.

    Lifecycle
    ---------
    1. Register agent classes via ``register()``
    2. Call ``start()`` to spawn agent threads
    3. Submit tasks via ``submit()`` or ``run_pentest()``
    4. Call ``wait_for_all()`` / ``shutdown()`` when done

    Message routing
    ---------------
    Each agent has an inbox ``queue.Queue``.  The coordinator owns a shared
    ``outbox`` queue that agents write results/status to.  The coordinator's
    dispatcher thread reads the outbox and routes follow-up messages.
    """

    def __init__(self, attack_graph=None, learning_system=None,
                 profile: str = "deep", scope: Optional[list] = None):
        self._agent_classes: dict[str, type] = {}   # agent_id → class
        self._agents: dict[str, BaseAgent] = {}      # agent_id → instance
        self._specialization_map: dict[str, list[str]] = {}  # task_type → [agent_id]
        self._outbox: queue.Queue = queue.Queue()    # agents write here
        self._results: list[TaskResult] = []
        self._pending: dict[str, Task] = {}          # task_id → Task
        self._lock = threading.Lock()
        self._running = False
        self._dispatcher_thread: Optional[threading.Thread] = None
        self.attack_graph = attack_graph
        self.learning_system = learning_system

        # Core infrastructure
        Deduplicator, Reporter, ScopeValidator, get_profile, PROFILES, plugin_registry, recon_cache = _load_core()
        self._deduplicator = Deduplicator() if Deduplicator else None
        self._scope_validator = ScopeValidator() if ScopeValidator else None
        if scope and self._scope_validator:
            for s in scope:
                self._scope_validator.add_in_scope(s)
        self._profile = None
        if get_profile:
            try:
                self._profile = get_profile(profile)
            except KeyError:
                pass
        self._plugin_registry = plugin_registry
        self._recon_cache = recon_cache
        # Discover plugins
        if plugin_registry:
            try:
                plugin_registry.discover()
            except Exception:
                pass

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, agent_class: type) -> "AgentCoordinator":
        """Register an agent class by its AGENT_ID."""
        aid = agent_class.AGENT_ID
        self._agent_classes[aid] = agent_class
        for spec in getattr(agent_class, "SPECIALIZATIONS", []):
            self._specialization_map.setdefault(spec, []).append(aid)
        return self

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> "AgentCoordinator":
        """Spawn all registered agent threads and the dispatcher."""
        from modules.tool_wrappers import ToolRegistry
        shared_registry = ToolRegistry()
        for aid, cls in self._agent_classes.items():
            agent = cls(outbox=self._outbox)
            agent.attack_graph = self.attack_graph
            agent.knowledge_base = getattr(self.learning_system, "kb", None)
            agent.tool_registry = shared_registry
            agent.daemon = True
            agent.start()
            self._agents[aid] = agent

        self._running = True
        self._dispatcher_thread = threading.Thread(
            target=self._dispatcher_loop, daemon=True, name="coordinator-dispatcher"
        )
        self._dispatcher_thread.start()
        return self

    def shutdown(self, timeout: float = 30.0):
        """Signal all agents to stop and wait for threads."""
        self._running = False
        for agent in self._agents.values():
            agent.stop()
        if self._dispatcher_thread:
            self._dispatcher_thread.join(timeout=5.0)

    # ── Task submission ───────────────────────────────────────────────────────

    def submit(self, task: Task) -> str:
        """Route a single task to the best available agent. Returns task_id."""
        agent = self._best_agent(task.task_type)
        if not agent:
            raise RuntimeError(
                f"No agent available for task_type={task.task_type!r}. "
                f"Registered: {list(self._specialization_map.keys())}"
            )
        with self._lock:
            self._pending[task.task_id] = task
        task.assigned_to = agent.agent_id
        msg = Message(
            msg_type=MessageType.TASK,
            sender="coordinator",
            recipient=agent.agent_id,
            payload={"task": task},
        )
        agent.inbox.put(msg)
        return task.task_id

    def _best_agent(self, task_type: str) -> Optional[BaseAgent]:
        candidates = self._specialization_map.get(task_type, [])
        for aid in candidates:
            agent = self._agents.get(aid)
            if agent and agent.state in (AgentState.IDLE, AgentState.RUNNING):
                return agent
        # Fallback: any idle agent
        for agent in self._agents.values():
            if agent.state == AgentState.IDLE:
                return agent
        return None

    # ── Dispatcher loop ───────────────────────────────────────────────────────

    def _dispatcher_loop(self):
        while self._running:
            try:
                msg: Message = self._outbox.get(timeout=1.0)
            except queue.Empty:
                continue

            if msg.msg_type == MessageType.RESULT:
                result: TaskResult = msg.payload.get("result")
                if result:
                    with self._lock:
                        self._results.append(result)
                        self._pending.pop(result.task_id, None)
                    self._on_result(result)

            elif msg.msg_type == MessageType.SPAWN:
                # An agent requests spawning a follow-up task
                new_task: Task = msg.payload.get("task")
                if new_task:
                    try:
                        self.submit(new_task)
                    except RuntimeError as e:
                        print(f"[coordinator] SPAWN failed: {e}")

            elif msg.msg_type == MessageType.STATUS:
                pass  # Could log / store status

    def _on_result(self, result: TaskResult):
        """Hook called each time a task completes — trigger follow-up tasks."""
        if self.learning_system:
            try:
                self.learning_system.record_result(result)
            except Exception:
                pass

    # ── High-level pentest orchestration ──────────────────────────────────────

    def run_pentest(self, target: str, output_dir: str,
                    platform: str = "HackerOne",
                    phases: list[str] | None = None,
                    timeout: int = 3600) -> list[TaskResult]:
        """
        Full autonomous pentest pipeline.

        Default phase order:
            recon → scan → exploit → validate → report
        """
        # Consult learning system for adaptive phase ordering and tool overrides
        adaptive_plan = None
        if self.learning_system and phases is None:
            try:
                adaptive_plan = self.learning_system.plan_for(target)
                # Map adaptive sub-phases (scan_nuclei, triage, etc.) → canonical phases
                _SUB_TO_PHASE = {
                    "scan_nuclei": "scan", "triage": "scan", "scan_xss": "scan",
                    "scan_sqli": "scan", "scan_ssrf": "scan", "scan_secrets": "scan",
                }
                _CANONICAL = {"recon", "scan", "exploit", "validate", "report"}
                seen: set[str] = set()
                normalized: list[str] = []
                for p in adaptive_plan.ordered_phases:
                    if p in adaptive_plan.skip_phases:
                        continue
                    canon = _SUB_TO_PHASE.get(p, p)
                    if canon in _CANONICAL and canon not in seen:
                        normalized.append(canon)
                        seen.add(canon)
                phases = normalized
                print(f"[coordinator] Adaptive plan: {' → '.join(phases)}", flush=True)
                if adaptive_plan.rationale:
                    for note in adaptive_plan.rationale[:3]:
                        print(f"[coordinator]   ℹ {note}", flush=True)
            except Exception as exc:
                print(f"[coordinator] Adaptive planner failed: {exc}", flush=True)

        phases = phases or ["recon", "scan", "exploit", "validate", "report"]
        out_dir = str(Path(output_dir) / target)
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        context_base = {
            "output_dir": out_dir,
            "platform": platform,
            "verify_live": True,
            # Pass tool overrides from adaptive plan into task context
            "tool_overrides": adaptive_plan.tool_overrides if adaptive_plan else {},
            "focus_vuln_types": adaptive_plan.focus_vuln_types if adaptive_plan else [],
        }

        phase_task_map = {
            "recon":    ("recon",    {}),
            "scan":     ("scan",     {}),
            "exploit":  ("exploit",  {}),
            "validate": ("validate", {}),
            "report":   ("report",   {"platform": platform}),
        }

        # Run phases SEQUENTIALLY — each phase must finish before the next starts.
        # The SCAN phase spawns parallel sub-task threads internally.
        deadline = time.time() + timeout
        for phase in phases:
            if time.time() > deadline:
                print(f"[coordinator] Timeout reached — stopping at phase={phase}", flush=True)
                break

            # Scope check
            if self._scope_validator and not self._scope_validator.check(target):
                print(f"[coordinator] Target {target} is out of scope — aborting", flush=True)
                break

            if phase == "scan":
                # Run scan sub-tasks in parallel
                self._run_parallel_scan(target, context_base, deadline)
                continue

            task_type, extra_ctx = phase_task_map.get(phase, (phase, {}))
            ctx = {**context_base, **extra_ctx}
            task = Task(
                task_id=f"{target}:{phase}:{uuid.uuid4().hex[:6]}",
                task_type=task_type,
                target=target,
                context=ctx,
            )
            try:
                tid = self.submit(task)
                print(f"[coordinator] ── Phase: {phase.upper()} (task={tid})", flush=True)
            except RuntimeError as e:
                print(f"[coordinator] Warning: {e}", flush=True)
                continue

            phase_extra = 60
            phase_deadline = min(deadline, time.time() + (timeout // max(len(phases), 1) + phase_extra))
            while time.time() < phase_deadline:
                with self._lock:
                    still_pending = tid in self._pending
                if not still_pending:
                    break
                time.sleep(2)
            else:
                print(f"[coordinator] Phase {phase} timed out", flush=True)

        # Deduplicate findings
        if self._deduplicator:
            with self._lock:
                all_findings = []
                for r in self._results:
                    unique = self._deduplicator.filter_new(r.findings)
                    r.findings = unique
                    all_findings.extend(unique)
            duped = sum(1 for r in self._results for _ in r.findings)
            print(f"[coordinator] Deduplication: {self._deduplicator.stats()['unique']} unique findings", flush=True)

        with self._lock:
            return list(self._results)

    def _run_parallel_scan(self, target: str, context_base: dict, deadline: float) -> None:
        """
        Run nuclei, dalfox, sqlmap scan sub-tasks in parallel using a thread pool.
        Results are collected and merged into self._results.
        """
        profile = self._profile
        max_workers = profile.max_workers if profile else 8
        scan_timeout = profile.scan_timeout if profile else 600

        # Build sub-task list based on profile
        sub_tasks = []

        # Always include nuclei
        sub_tasks.append(("scan_nuclei", {"scan_mode": "nuclei"}))

        if not profile or profile.dalfox_enabled:
            sub_tasks.append(("scan_xss", {"scan_mode": "dalfox"}))

        if not profile or profile.sqlmap_enabled:
            sub_tasks.append(("scan_sqli", {"scan_mode": "sqlmap"}))

        # Add plugin-based vuln sub-tasks
        if self._plugin_registry:
            for entry in self._plugin_registry.list_by_type("vuln"):
                sub_tasks.append(("scan_plugin", {"plugin_name": entry.name}))

        print(f"[coordinator] ── Phase: SCAN ({len(sub_tasks)} sub-tasks, {max_workers} workers)", flush=True)

        submitted_tids: list[str] = []
        for task_type, extra_ctx in sub_tasks:
            ctx = {**context_base, **extra_ctx}
            task = Task(
                task_id=f"{target}:{task_type}:{uuid.uuid4().hex[:6]}",
                task_type=task_type,
                target=target,
                context=ctx,
            )
            try:
                tid = self.submit(task)
                submitted_tids.append(tid)
                print(f"[coordinator]   → Submitted sub-task: {task_type} (tid={tid})", flush=True)
            except RuntimeError as e:
                print(f"[coordinator]   ✗ Sub-task {task_type} failed to submit: {e}", flush=True)

        # Wait for all scan sub-tasks to complete
        scan_deadline = min(deadline, time.time() + scan_timeout)
        while time.time() < scan_deadline:
            with self._lock:
                still_pending = [tid for tid in submitted_tids if tid in self._pending]
            if not still_pending:
                break
            time.sleep(2)
        else:
            remaining = len([tid for tid in submitted_tids if tid in self._pending])
            print(f"[coordinator] Scan phase timed out — {remaining} sub-tasks still running", flush=True)

    # ── Result access ─────────────────────────────────────────────────────────

    def wait_for_all(self, timeout: float = 3600.0) -> list[TaskResult]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if not self._pending:
                    break
            time.sleep(1)
        with self._lock:
            return list(self._results)

    def get_results(self) -> list[TaskResult]:
        with self._lock:
            return list(self._results)

    def findings_summary(self) -> dict:
        all_findings = []
        tools_used: set[str] = set()
        with self._lock:
            for r in self._results:
                all_findings.extend(r.findings)
                tools_used.update(r.tools_used)

        by_severity: dict[str, int] = {}
        for f in all_findings:
            s = f.get("severity", "info")
            by_severity[s] = by_severity.get(s, 0) + 1

        summary = {
            "total_findings": len(all_findings),
            "by_severity": by_severity,
            "tools_used": sorted(tools_used),
            "agents_run": list(self._agents.keys()),
            "tasks_completed": len(self._results),
        }
        if self._deduplicator:
            summary["dedup_stats"] = self._deduplicator.stats()
        return summary

    def write_reports(self, target: str, output_dir: str,
                      platform: str = "hackerone",
                      formats: Optional[List[str]] = None) -> List[str]:
        """Write multi-format reports for all findings. Returns list of file paths."""
        _, Reporter, *_ = _load_core()
        if Reporter is None:
            return []

        formats = formats or ["markdown", "json", "html"]
        out_dir = Path(output_dir) / target
        reporter = Reporter(output_dir=out_dir, target=target, platform=platform)

        all_findings = []
        with self._lock:
            for r in self._results:
                all_findings.extend(r.findings)

        for f in all_findings:
            reporter.add_finding(f)

        paths = reporter.write_all(formats)
        return [str(p) for p in paths]

    def abort_all(self):
        """Signal all agents to abort their current tasks."""
        for agent in self._agents.values():
            agent.abort()

    def status(self) -> dict:
        return {
            aid: agent.state.value
            for aid, agent in self._agents.items()
        }
