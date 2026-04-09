"""
Base Agent — Multi-Agent Autonomous Pentesting System
======================================================
Each agent is a self-contained worker thread with:
  - A task queue (receives work from coordinator)
  - A result queue (sends results back)
  - A specialization set (which vuln classes / tools it handles)
  - A lifecycle (IDLE → RUNNING → PAUSED → STOPPED)
  - Access to ToolRegistry and AttackGraph
"""

from __future__ import annotations

import json
import queue
import threading
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class AgentState(str, Enum):
    IDLE     = "idle"
    RUNNING  = "running"
    PAUSED   = "paused"
    STOPPED  = "stopped"
    ERROR    = "error"


class MessageType(str, Enum):
    TASK       = "task"      # coordinator → agent: new task
    RESULT     = "result"    # agent → coordinator: task result
    STATUS     = "status"    # agent → coordinator: heartbeat
    ABORT      = "abort"     # coordinator → agent: stop current task
    SHUTDOWN   = "shutdown"  # coordinator → agent: terminate
    SPAWN      = "spawn"     # agent → coordinator: request sub-agent


@dataclass
class Message:
    msg_type: MessageType
    sender: str           # agent_id
    recipient: str        # agent_id or "coordinator" or "broadcast"
    payload: dict = field(default_factory=dict)
    msg_id: str = ""
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        if not self.msg_id:
            self.msg_id = f"{self.sender}:{self.timestamp:.4f}"


@dataclass
class Task:
    task_id: str
    task_type: str          # e.g. "recon", "scan_xss", "validate", "report"
    target: str
    context: dict = field(default_factory=dict)
    priority: int = 5       # 1 (highest) → 10 (lowest)
    assigned_to: str = ""
    created_at: float = field(default_factory=time.time)

    def __lt__(self, other):  # for priority queue
        return self.priority < other.priority


@dataclass
class TaskResult:
    task_id: str
    agent_id: str
    task_type: str
    target: str
    success: bool
    data: Any = None
    error: str = ""
    findings: list[dict] = field(default_factory=list)
    duration: float = 0.0
    tools_used: list[str] = field(default_factory=list)


class BaseAgent(threading.Thread):
    """
    Abstract base class for all agents.

    Subclasses must implement:
      - AGENT_ID: str  (unique identifier)
      - SPECIALIZATIONS: list[str]  (task types this agent handles)
      - execute_task(task: Task) -> TaskResult
    """

    AGENT_ID: str = "base_agent"
    SPECIALIZATIONS: list[str] = []
    DESCRIPTION: str = "Base agent"

    def __init__(
        self,
        agent_id: str = None,
        inbox: queue.Queue = None,
        outbox: queue.Queue = None,
        config: dict = None,
        program_dir: str = ".",
    ):
        super().__init__(daemon=True)
        self.agent_id = agent_id or self.AGENT_ID
        self.inbox = inbox or queue.Queue()
        self.outbox = outbox or queue.Queue()
        self.config = config or {}
        self.program_dir = program_dir

        self._state = AgentState.IDLE
        self._current_task: Optional[Task] = None
        self._abort_event = threading.Event()
        self._shutdown_event = threading.Event()
        self._task_count = 0
        self._error_count = 0
        self._start_time = time.time()

        # Shared registry (injected by coordinator)
        self.tool_registry = None
        self.attack_graph = None
        self.knowledge_base = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    @property
    def state(self) -> AgentState:
        return self._state

    def _set_state(self, state: AgentState):
        self._state = state
        self._send_status()

    def stop(self):
        self._shutdown_event.set()
        self._abort_event.set()

    def abort_current(self):
        self._abort_event.set()

    def is_aborted(self) -> bool:
        return self._abort_event.is_set()

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self):
        self._set_state(AgentState.IDLE)
        while not self._shutdown_event.is_set():
            try:
                msg = self.inbox.get(timeout=1.0)
                self._handle_message(msg)
            except queue.Empty:
                continue
            except Exception as exc:
                self._error_count += 1
                self._set_state(AgentState.ERROR)
                self._send(Message(
                    msg_type=MessageType.STATUS,
                    sender=self.agent_id,
                    recipient="coordinator",
                    payload={"error": str(exc), "traceback": traceback.format_exc()},
                ))

    def _handle_message(self, msg: Message):
        if msg.msg_type == MessageType.SHUTDOWN:
            self._shutdown_event.set()
        elif msg.msg_type == MessageType.ABORT:
            self._abort_event.set()
        elif msg.msg_type == MessageType.TASK:
            self._abort_event.clear()
            payload = msg.payload
            if isinstance(payload, Task):
                task = payload
            elif isinstance(payload, dict) and "task" in payload:
                task = payload["task"]
            elif isinstance(payload, dict):
                task = Task(**payload)
            else:
                return
            self._run_task(task)
        elif msg.msg_type == MessageType.STATUS:
            self._send_status()

    def _run_task(self, task: Task):
        self._current_task = task
        self._task_count += 1
        self._set_state(AgentState.RUNNING)
        t0 = time.time()
        try:
            result = self.execute_task(task)
        except Exception as exc:
            result = TaskResult(
                task_id=task.task_id,
                agent_id=self.agent_id,
                task_type=task.task_type,
                target=task.target,
                success=False,
                error=str(exc),
                duration=time.time() - t0,
            )
        result.duration = time.time() - t0
        self._set_state(AgentState.IDLE)
        self._current_task = None
        self._send(Message(
            msg_type=MessageType.RESULT,
            sender=self.agent_id,
            recipient="coordinator",
            payload={"result": result},
        ))

    # ── Communication ─────────────────────────────────────────────────────────

    def _send(self, msg: Message):
        self.outbox.put(msg)

    def _send_status(self):
        self._send(Message(
            msg_type=MessageType.STATUS,
            sender=self.agent_id,
            recipient="coordinator",
            payload={
                "state": self._state.value,
                "task_count": self._task_count,
                "error_count": self._error_count,
                "uptime": time.time() - self._start_time,
                "current_task": self._current_task.task_id if self._current_task else None,
            },
        ))

    def _request_spawn(self, agent_type: str, task: Task):
        """Ask coordinator to spawn a sub-agent for a task."""
        self._send(Message(
            msg_type=MessageType.SPAWN,
            sender=self.agent_id,
            recipient="coordinator",
            payload={"agent_type": agent_type, "task": task.__dict__},
        ))

    # ── Tool access ───────────────────────────────────────────────────────────

    def run_tool(self, tool_name: str, **kwargs) -> dict:
        """Run a tool via ToolRegistry; return data dict or empty dict on failure."""
        if self.tool_registry is None:
            return {}
        if self.is_aborted():
            return {}
        result = self.tool_registry.run(tool_name, **kwargs)
        return result.data if result.success and result.data else {}

    def tool_available(self, tool_name: str) -> bool:
        from oneinfinity.modules.tool_wrappers import is_available
        return is_available(tool_name)

    def best_tool(self, *tools: str) -> Optional[str]:
        for t in tools:
            if self.tool_available(t):
                return t
        return None

    # ── Logging helpers ───────────────────────────────────────────────────────

    def log(self, msg: str, level: str = "info"):
        prefix = {
            "info":    "\033[0;36m[*]\033[0m",
            "ok":      "\033[0;32m[+]\033[0m",
            "warn":    "\033[0;33m[!]\033[0m",
            "error":   "\033[0;31m[-]\033[0m",
        }.get(level, "[*]")
        print(f"  {prefix} [{self.agent_id}] {msg}", flush=True)

    # ── Override in subclasses ────────────────────────────────────────────────

    def execute_task(self, task: Task) -> TaskResult:
        raise NotImplementedError(f"{self.__class__.__name__}.execute_task() not implemented")

    def capabilities(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "specializations": self.SPECIALIZATIONS,
            "description": self.DESCRIPTION,
            "state": self._state.value,
        }
