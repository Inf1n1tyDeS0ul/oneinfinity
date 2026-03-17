"""
agent_execution_fabric.py — Agent Execution Fabric

Dynamic agent pool that:
  - Accepts task submissions from the graph brain / decision engine
  - Routes each task to the correct GraphAgent subclass
  - Runs agents in a ThreadPoolExecutor (graph-aware parallelism)
  - Reports results back via callback → brain.integrate_finding()

Architecture:
  FabricTask submitted
      │
      ▼
  FabricTaskQueue  (asyncio.Queue + priority)
      │
      ▼
  WorkerThread pool (ThreadPoolExecutor, max_workers configurable)
      │
      ├── ReconAgent
      ├── XSSAgent
      ├── SQLiAgent
      ├── IDORAgent
      ├── SSRFAgent
      ├── AuthAgent
      ├── BusinessLogicAgent
      ├── MobileSecurityAgent
      └── AISecurityAgent
      │
      ▼
  on_complete(finding_dict) → EventBus + GraphBrain

All GraphAgent subclasses:
  - Take a FabricTask (node_id, node_label, node_type, target, context)
  - Call tool wrappers via ToolRegistry where available
  - Return a FabricResult
  - Are triggered by the graph, not by CLI commands
"""

from __future__ import annotations

import logging
import queue
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("agent_execution_fabric")

# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class FabricTask:
    task_id:     str
    agent_type:  str
    node_id:     str
    node_label:  str
    node_type:   str
    target:      str
    priority:    float
    context:     Dict[str, Any] = field(default_factory=dict)
    on_complete: Optional[Callable] = field(default=None, repr=False)
    created_at:  float = field(default_factory=time.time)

    def __lt__(self, other: "FabricTask") -> bool:
        return self.priority > other.priority  # max-priority first


@dataclass
class FabricResult:
    task_id:    str
    agent_type: str
    node_id:    str
    node_label: str
    target:     str
    success:    bool
    findings:   List[dict]
    error:      str = ""
    duration_s: float = 0.0
    tools_used: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "task_id":    self.task_id,
            "agent_type": self.agent_type,
            "node_id":    self.node_id,
            "node_label": self.node_label,
            "target":     self.target,
            "success":    self.success,
            "findings":   self.findings,
            "error":      self.error,
            "duration_s": round(self.duration_s, 2),
            "tools_used": self.tools_used,
        }


# ── Base GraphAgent ────────────────────────────────────────────────────────────

class GraphAgent:
    """Base class for all graph-triggered agents."""
    AGENT_TYPE = "base"

    def __init__(self) -> None:
        self._registry = None

    def _get_registry(self):
        if self._registry is None:
            try:
                from modules.tool_wrappers import ToolRegistry
                self._registry = ToolRegistry()
            except Exception:
                pass
        return self._registry

    def _run_tool(self, tool: str, **kwargs) -> dict:
        reg = self._get_registry()
        if reg is None:
            return {"success": False, "data": [], "error": "ToolRegistry unavailable"}
        try:
            result = reg.run(tool, **kwargs)
            return {"success": result.success, "data": result.data,
                    "raw": result.raw, "error": result.error}
        except Exception as e:
            return {"success": False, "data": [], "error": str(e)}

    def _tool_available(self, tool: str) -> bool:
        import shutil
        return shutil.which(tool) is not None

    def execute(self, task: FabricTask) -> FabricResult:
        """Override in subclasses."""
        return FabricResult(task_id=task.task_id, agent_type=self.AGENT_TYPE,
                             node_id=task.node_id, node_label=task.node_label,
                             target=task.target, success=False,
                             findings=[], error="not implemented")

    def _make_finding(self, task: FabricTask, vuln_type: str, severity: str,
                       description: str, evidence: str = "",
                       cvss: float = 0.0, **extra) -> dict:
        return {
            "finding_id":  str(uuid.uuid4())[:10],
            "agent_type":  self.AGENT_TYPE,
            "node_id":     task.node_id,
            "node_label":  task.node_label,
            "target":      task.target,
            "vuln_type":   vuln_type,
            "name":        vuln_type,
            "severity":    severity,
            "description": description,
            "evidence":    evidence,
            "cvss":        cvss,
            "discovered_at": time.time(),
            **extra,
        }

    def _result(self, task: FabricTask, findings: List[dict],
                 tools: List[str], start: float, error: str = "") -> FabricResult:
        return FabricResult(
            task_id=task.task_id, agent_type=self.AGENT_TYPE,
            node_id=task.node_id, node_label=task.node_label,
            target=task.target,
            success=len(findings) > 0,
            findings=findings,
            error=error,
            duration_s=time.time() - start,
            tools_used=tools,
        )


# ── Concrete Agents ────────────────────────────────────────────────────────────

class ReconAgent(GraphAgent):
    AGENT_TYPE = "recon"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []
        target   = task.target

        # Subdomain enumeration
        if self._tool_available("subfinder"):
            tools.append("subfinder")
            r = self._run_tool("subfinder", domain=target)
            if r["success"] and r["data"]:
                for sub in (r["data"] if isinstance(r["data"], list) else []):
                    sub_str = str(sub.get("host", sub) if isinstance(sub, dict) else sub)
                    if sub_str:
                        findings.append(self._make_finding(
                            task, "subdomain_discovered", "info",
                            f"Subdomain: {sub_str}", sub_str,
                            extra_data={"subdomain": sub_str},
                        ))

        # HTTP probing
        if self._tool_available("httpx"):
            tools.append("httpx")
            r = self._run_tool("httpx", urls=[target])
            if r["success"] and r["data"]:
                for h in (r["data"] if isinstance(r["data"], list) else []):
                    url = str(h.get("url", h) if isinstance(h, dict) else h)
                    if url:
                        findings.append(self._make_finding(
                            task, "live_endpoint", "info",
                            f"Live: {url}", url,
                        ))

        # Technology detection via nuclei
        if self._tool_available("nuclei"):
            tools.append("nuclei")
            r = self._run_tool("nuclei", target=target, tags=["tech"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    findings.append(self._make_finding(
                        task, "technology_detected", "info",
                        str(n.get("info", {}).get("name", "tech")),
                        str(n),
                    ))

        return self._result(task, findings, tools, start)


class XSSAgent(GraphAgent):
    AGENT_TYPE = "xss"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []
        label    = task.node_label

        # Extract URL — label might be "param@url" or just a URL
        url = task.context.get("url") or (
            label.split("@")[-1] if "@" in label else label
        )
        if not url.startswith("http"):
            url = f"https://{task.target}"

        if self._tool_available("dalfox"):
            tools.append("dalfox")
            r = self._run_tool("dalfox", url=url)
            if r["success"] and r["data"]:
                for item in (r["data"] if isinstance(r["data"], list) else []):
                    findings.append(self._make_finding(
                        task, "xss", "high",
                        f"XSS found at {url}",
                        str(item),
                        cvss=6.1,
                    ))
        elif self._tool_available("kxss"):
            tools.append("kxss")
            r = self._run_tool("kxss", url=url)
            if r["success"] and r["data"]:
                for item in (r["data"] if isinstance(r["data"], list) else []):
                    findings.append(self._make_finding(
                        task, "xss", "medium",
                        f"Reflected input at {url}", str(item), cvss=4.3,
                    ))

        return self._result(task, findings, tools, start)


class SQLiAgent(GraphAgent):
    AGENT_TYPE = "sqli"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []
        label    = task.node_label
        url = task.context.get("url") or (
            label.split("@")[-1] if "@" in label else label
        )
        if not url.startswith("http"):
            url = f"https://{task.target}"

        if self._tool_available("sqlmap"):
            tools.append("sqlmap")
            r = self._run_tool("sqlmap", url=url, level=1, risk=1)
            if r["success"] and r["data"]:
                for item in (r["data"] if isinstance(r["data"], list) else []):
                    findings.append(self._make_finding(
                        task, "sqli", "critical",
                        f"SQL Injection at {url}",
                        str(item), cvss=9.8,
                    ))

        # Also check via nuclei
        if self._tool_available("nuclei"):
            tools.append("nuclei")
            r = self._run_tool("nuclei", target=url, tags=["sqli"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    findings.append(self._make_finding(
                        task, "sqli", "high",
                        str(n.get("info", {}).get("description", "SQLi indicator")),
                        str(n), cvss=8.5,
                    ))

        return self._result(task, findings, tools, start)


class IDORAgent(GraphAgent):
    AGENT_TYPE = "idor"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []
        url = task.node_label
        if not url.startswith("http"):
            url = f"https://{task.target}"

        # Nuclei IDOR / access-control templates
        if self._tool_available("nuclei"):
            tools.append("nuclei")
            r = self._run_tool("nuclei", target=url,
                                tags=["idor,access-control,privilege-escalation"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    sev = n.get("info", {}).get("severity", "medium")
                    findings.append(self._make_finding(
                        task, "idor", sev,
                        n.get("info", {}).get("description", "IDOR indicator"),
                        str(n), cvss=7.5,
                    ))

        # Try ffuf for ID enumeration if endpoint has numeric ID in path
        import re
        if re.search(r"/\d+", url) and self._tool_available("ffuf"):
            tools.append("ffuf")
            # Replace numeric ID with FUZZ and try range
            fuzz_url = re.sub(r"/\d+", "/FUZZ", url, count=1)
            r = self._run_tool("ffuf", url=fuzz_url, wordlist="1-100")
            if r["success"] and r["data"]:
                findings.append(self._make_finding(
                    task, "idor", "medium",
                    f"IDOR candidates at {fuzz_url}", str(r["data"][:3]),
                    cvss=6.5,
                ))

        return self._result(task, findings, tools, start)


class SSRFAgent(GraphAgent):
    AGENT_TYPE = "ssrf"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []
        url = task.node_label
        if not url.startswith("http"):
            url = f"https://{task.target}"

        if self._tool_available("nuclei"):
            tools.append("nuclei")
            r = self._run_tool("nuclei", target=url, tags=["ssrf"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    sev = n.get("info", {}).get("severity", "high")
                    findings.append(self._make_finding(
                        task, "ssrf", sev,
                        n.get("info", {}).get("description", "SSRF indicator"),
                        str(n), cvss=8.6,
                    ))

        return self._result(task, findings, tools, start)


class AuthAgent(GraphAgent):
    AGENT_TYPE = "auth"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []
        url = task.node_label
        if not url.startswith("http"):
            url = f"https://{task.target}"

        # JWT_tool check
        if self._tool_available("jwt_tool"):
            tools.append("jwt_tool")

        # Nuclei auth bypass templates
        if self._tool_available("nuclei"):
            tools.append("nuclei")
            r = self._run_tool("nuclei", target=url,
                                tags=["auth,default-login,exposed-panels"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    sev = n.get("info", {}).get("severity", "high")
                    findings.append(self._make_finding(
                        task, "auth_bypass", sev,
                        n.get("info", {}).get("description", "Auth issue"),
                        str(n), cvss=8.0,
                    ))

        return self._result(task, findings, tools, start)


class BusinessLogicAgent(GraphAgent):
    AGENT_TYPE = "biz_logic"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []

        try:
            from business_logic_engine import BusinessLogicEngine
            eng = BusinessLogicEngine()
            results = eng.test_endpoint(task.node_label, context=task.context)
            tools.append("business_logic_engine")
            for r in (results or []):
                findings.append(self._make_finding(
                    task, "business_logic", r.get("severity", "medium"),
                    r.get("description", "Business logic issue"),
                    str(r),
                    cvss=float(r.get("cvss", 5.0)),
                ))
        except Exception:
            pass

        # Nuclei rate-limit / logic templates as fallback
        if self._tool_available("nuclei"):
            tools.append("nuclei")
            url = task.node_label
            if not url.startswith("http"):
                url = f"https://{task.target}"
            r = self._run_tool("nuclei", target=url,
                                tags=["logic,rate-limit,workflow"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    findings.append(self._make_finding(
                        task, "business_logic", "medium",
                        str(n.get("info", {}).get("description", "Logic flaw")),
                        str(n), cvss=5.5,
                    ))

        return self._result(task, findings, tools, start)


class SSTIAgent(GraphAgent):
    AGENT_TYPE = "ssti"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []
        url = task.context.get("url") or task.node_label
        if not url.startswith("http"):
            url = f"https://{task.target}"

        if self._tool_available("nuclei"):
            tools.append("nuclei")
            r = self._run_tool("nuclei", target=url, tags=["ssti,template-injection"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    sev = n.get("info", {}).get("severity", "high")
                    findings.append(self._make_finding(
                        task, "ssti", sev,
                        n.get("info", {}).get("description", "SSTI"),
                        str(n), cvss=8.8,
                    ))

        return self._result(task, findings, tools, start)


class OpenRedirectAgent(GraphAgent):
    AGENT_TYPE = "open_redirect"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []
        url = task.context.get("url") or task.node_label
        if not url.startswith("http"):
            url = f"https://{task.target}"

        if self._tool_available("nuclei"):
            tools.append("nuclei")
            r = self._run_tool("nuclei", target=url, tags=["redirect,open-redirect"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    findings.append(self._make_finding(
                        task, "open_redirect", "medium",
                        n.get("info", {}).get("description", "Open redirect"),
                        str(n), cvss=4.7,
                    ))

        return self._result(task, findings, tools, start)


class ExploitAgent(GraphAgent):
    AGENT_TYPE = "exploit"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []
        tools    = []

        try:
            from exploit_chains.chain_patterns import CHAIN_PATTERNS
            vuln_type = task.context.get("vuln_type", "")
            url       = task.node_label
            if not url.startswith("http"):
                url = f"https://{task.target}"

            # Check chain patterns for the vulnerability
            for pattern in CHAIN_PATTERNS:
                if vuln_type in getattr(pattern, "triggers", []):
                    findings.append(self._make_finding(
                        task, "exploit_chain", "critical",
                        f"Chain pattern match: {getattr(pattern, 'name', '?')}",
                        f"vuln_type={vuln_type} → chain",
                        cvss=9.5,
                    ))
                    break
        except Exception:
            pass

        if self._tool_available("nuclei"):
            tools.append("nuclei")
            url = task.node_label
            if not url.startswith("http"):
                url = f"https://{task.target}"
            r = self._run_tool("nuclei", target=url, tags=["cve,exploit"])
            if r["success"] and r["data"]:
                for n in (r["data"] if isinstance(r["data"], list) else []):
                    sev = n.get("info", {}).get("severity", "critical")
                    findings.append(self._make_finding(
                        task, "cve_exploit", sev,
                        n.get("info", {}).get("description", "Known CVE"),
                        str(n), cvss=9.0,
                    ))

        return self._result(task, findings, tools, start)


class MobileSecurityAgent(GraphAgent):
    AGENT_TYPE = "mobile"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []

        try:
            from mobile_security_engine import MobileSecurityEngine
            engine  = MobileSecurityEngine()
            context = task.context
            apk     = context.get("apk_path", "")
            if apk:
                results = engine.run_pipeline(apk)
                for r in (results or []):
                    if isinstance(r, dict):
                        findings.append(self._make_finding(
                            task, r.get("vuln_type", "mobile_issue"),
                            r.get("severity", "medium"),
                            r.get("description", "Mobile finding"),
                            str(r),
                            cvss=float(r.get("cvss", 5.0)),
                        ))
        except Exception:
            pass

        return self._result(task, findings, ["mobile_security_engine"], start)


class AISecurityAgent(GraphAgent):
    AGENT_TYPE = "ai_security"

    def execute(self, task: FabricTask) -> FabricResult:
        start    = time.time()
        findings = []

        try:
            from ai_security_engine import AISecurityEngine
            engine  = AISecurityEngine()
            results = engine.scan_endpoint(task.node_label, context=task.context)
            for r in (results or []):
                if isinstance(r, dict):
                    findings.append(self._make_finding(
                        task, r.get("vuln_type", "ai_vulnerability"),
                        r.get("severity", "high"),
                        r.get("description", "AI security finding"),
                        str(r),
                        cvss=float(r.get("cvss", 7.5)),
                    ))
        except Exception:
            pass

        return self._result(task, findings, ["ai_security_engine"], start)


# ── Agent registry ────────────────────────────────────────────────────────────

_AGENT_CLASSES: Dict[str, type] = {
    "recon":          ReconAgent,
    "xss":            XSSAgent,
    "sqli":           SQLiAgent,
    "idor":           IDORAgent,
    "ssrf":           SSRFAgent,
    "ssti":           SSTIAgent,
    "open_redirect":  OpenRedirectAgent,
    "auth":           AuthAgent,
    "biz_logic":      BusinessLogicAgent,
    "exploit":        ExploitAgent,
    "mobile":         MobileSecurityAgent,
    "ai_security":    AISecurityAgent,
}


def _make_agent(agent_type: str) -> Optional[GraphAgent]:
    cls = _AGENT_CLASSES.get(agent_type)
    if cls is None:
        return None
    return cls()


# ── AgentExecutionFabric ──────────────────────────────────────────────────────

class AgentExecutionFabric:
    """
    Receives FabricTasks from the brain, runs the right agent,
    and delivers findings back via callbacks.
    """

    def __init__(self) -> None:
        self._lock         = threading.RLock()
        self._running      = False
        self._executor: Optional[ThreadPoolExecutor] = None
        self._task_queue:  queue.PriorityQueue = queue.PriorityQueue()
        self._futures:     Dict[str, Future] = {}
        self._max_workers  = 8
        self._dispatcher:  Optional[threading.Thread] = None

        # Counters
        self._submitted  = 0
        self._completed  = 0
        self._failed     = 0

        # Global completion callback
        self._global_on_complete: Optional[Callable] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self, max_workers: int = 8) -> None:
        with self._lock:
            if self._running:
                return
            self._max_workers = max_workers
            self._running     = True
            self._executor    = ThreadPoolExecutor(
                max_workers=max_workers, thread_name_prefix="fabric-worker"
            )
        self._dispatcher = threading.Thread(
            target=self._dispatch_loop, daemon=True, name="fabric-dispatcher"
        )
        self._dispatcher.start()
        log.info("AgentExecutionFabric started with %d workers", max_workers)

    def stop(self) -> None:
        with self._lock:
            self._running = False
        if self._executor:
            self._executor.shutdown(wait=False)

    # ── Task submission ───────────────────────────────────────────────────────

    def submit_task(self, agent_type: str, node_id: str, node_label: str,
                     node_type: str, target: str, context: dict = None,
                     priority: float = 5.0,
                     on_complete: Optional[Callable] = None) -> str:
        task = FabricTask(
            task_id=str(uuid.uuid4())[:12],
            agent_type=agent_type,
            node_id=node_id,
            node_label=node_label,
            node_type=node_type,
            target=target,
            priority=priority,
            context=context or {},
            on_complete=on_complete or self._global_on_complete,
        )
        self._task_queue.put(task)
        with self._lock:
            self._submitted += 1
        log.debug("Task %s submitted: %s on %s", task.task_id, agent_type, node_label)
        return task.task_id

    def set_global_callback(self, cb: Callable) -> None:
        self._global_on_complete = cb

    # ── Dispatch loop ─────────────────────────────────────────────────────────

    def _dispatch_loop(self) -> None:
        while self._running:
            try:
                task: FabricTask = self._task_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if not self._running:
                break
            if self._executor:
                future = self._executor.submit(self._run_task, task)
                with self._lock:
                    self._futures[task.task_id] = future

    def _run_task(self, task: FabricTask) -> FabricResult:
        agent = _make_agent(task.agent_type)
        if agent is None:
            result = FabricResult(
                task_id=task.task_id, agent_type=task.agent_type,
                node_id=task.node_id, node_label=task.node_label,
                target=task.target, success=False,
                findings=[], error=f"No agent registered for type '{task.agent_type}'",
            )
        else:
            try:
                result = agent.execute(task)
            except Exception as exc:
                result = FabricResult(
                    task_id=task.task_id, agent_type=task.agent_type,
                    node_id=task.node_id, node_label=task.node_label,
                    target=task.target, success=False,
                    findings=[], error=str(exc),
                )

        with self._lock:
            if result.success:
                self._completed += 1
            else:
                self._failed += 1
            self._futures.pop(task.task_id, None)

        # Publish to event bus
        self._publish_result(result)

        # Per-task callback
        if task.on_complete:
            for finding in result.findings:
                try:
                    task.on_complete({**finding, "task_id": task.task_id})
                except Exception:
                    pass
        return result

    def _publish_result(self, result: FabricResult) -> None:
        try:
            from event_bus import get_bus, EventType
            bus = get_bus()
            for finding in result.findings:
                severity = finding.get("severity", "info")
                et = EventType.NEW_VULNERABILITY if severity not in ("info",) \
                     else EventType.AGENT_STATUS
                bus.publish(
                    event_type=et,
                    source=f"fabric:{result.agent_type}",
                    data=finding,
                )
            if not result.success and result.error:
                bus.publish(
                    event_type=EventType.AGENT_STATUS,
                    source=f"fabric:{result.agent_type}",
                    data={"task_id": result.task_id, "error": result.error,
                           "node_id": result.node_id},
                )
        except Exception:
            pass

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        with self._lock:
            return {
                "running":       self._running,
                "max_workers":   self._max_workers,
                "queue_depth":   self._task_queue.qsize(),
                "active_tasks":  len(self._futures),
                "submitted":     self._submitted,
                "completed":     self._completed,
                "failed":        self._failed,
                "agent_types":   list(_AGENT_CLASSES.keys()),
            }

    def list_agent_types(self) -> List[str]:
        return list(_AGENT_CLASSES.keys())


# ── Singleton ──────────────────────────────────────────────────────────────────

_fabric: Optional[AgentExecutionFabric] = None
_fabric_lock = threading.Lock()


def get_fabric() -> AgentExecutionFabric:
    global _fabric
    if _fabric is None:
        with _fabric_lock:
            if _fabric is None:
                _fabric = AgentExecutionFabric()
    return _fabric
