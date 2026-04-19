"""
Swarm Worker — Executes scanning modules and reports results to master.

Each worker runs in its own thread, polling the master for tasks.
Module dispatch uses lazy imports with graceful degradation:
  - Missing optional engines (ai_security, mobile) are silently skipped
  - ImportError on any engine logs a warning and returns an empty result
  - All exceptions are caught per-task to keep the worker alive

Thread model:
  - _worker_loop: main loop, polls master.claim_task(), executes, reports
  - _heartbeat_thread: sends periodic heartbeats to master
"""

import uuid
import time
import json
import logging
import threading
import sys
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


# ── Worker Config & Status ────────────────────────────────────────────────────

@dataclass
class WorkerConfig:
    worker_id: str = field(
        default_factory=lambda: f"worker_{uuid.uuid4().hex[:8]}"
    )
    capabilities: list = field(default_factory=lambda: [
        "recon", "vuln_scan", "exploit", "ai_security", "mobile", "full_pipeline"
    ])
    max_concurrent_tasks: int = 2
    poll_interval_s: float = 2.0
    task_timeout_s: int = 1800
    report_progress: bool = True


@dataclass
class WorkerStatus:
    worker_id: str
    status: str                  # idle / working / stopping / stopped
    current_tasks: list          # list of task_ids currently running
    tasks_completed: int
    tasks_failed: int
    started_at: float
    last_heartbeat: float


# ── Swarm Worker ──────────────────────────────────────────────────────────────

class SwarmWorker:
    """
    Worker node: polls master for available tasks, executes the appropriate
    scanning module, then reports the result back.

    Module dispatch map:
      recon         → _run_recon
      vuln_scan     → _run_vuln_scan
      exploit       → _run_exploit
      ai_security   → _run_ai_security
      mobile        → _run_mobile
      full_pipeline → _run_full_pipeline
      *             → _run_full_pipeline (default)
    """

    HEARTBEAT_INTERVAL_S = 15

    def __init__(self, master=None, config: WorkerConfig = None):
        self._master = master
        self.config = config or WorkerConfig()
        self.worker_id = self.config.worker_id

        self._status = "idle"
        self._current_tasks: list = []
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._started_at = 0.0
        self._last_heartbeat = 0.0
        self._running = False

        self._lock = threading.Lock()
        self._worker_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None

        # Semaphore to limit concurrent task execution
        self._task_slots = threading.Semaphore(self.config.max_concurrent_tasks)

        # Optional Redis client for Redis-mode consumption
        self._redis_client = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        """Register with master and start worker + heartbeat threads."""
        if self._master:
            self._master.register_worker(
                self.worker_id, self.config.capabilities
            )

        self._running = True
        self._started_at = time.time()

        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name=f"swarm-worker-{self.worker_id}",
            daemon=True,
        )
        self._worker_thread.start()

        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"swarm-heartbeat-{self.worker_id}",
            daemon=True,
        )
        self._heartbeat_thread.start()

        log.info("[worker:%s] Started (caps=%s)", self.worker_id,
                 self.config.capabilities)

    def stop(self):
        """Signal worker to stop after finishing current task."""
        with self._lock:
            self._status = "stopping"
        self._running = False

        if self._master:
            self._master.unregister_worker(self.worker_id)

        log.info("[worker:%s] Stopped (completed=%d failed=%d)",
                 self.worker_id, self._tasks_completed, self._tasks_failed)

    def get_status(self) -> WorkerStatus:
        with self._lock:
            return WorkerStatus(
                worker_id=self.worker_id,
                status=self._status,
                current_tasks=list(self._current_tasks),
                tasks_completed=self._tasks_completed,
                tasks_failed=self._tasks_failed,
                started_at=self._started_at,
                last_heartbeat=self._last_heartbeat,
            )

    # ── Main Worker Loop ──────────────────────────────────────────────────────

    def _worker_loop(self):
        """
        Main loop: poll master for tasks, execute them in threads,
        report results back.
        """
        with self._lock:
            self._status = "idle"

        while self._running:
            try:
                # Try to acquire a task slot (non-blocking check)
                acquired = self._task_slots.acquire(blocking=False)
                if not acquired:
                    # All slots busy, wait before retrying
                    time.sleep(self.config.poll_interval_s)
                    continue

                task = None

                # Claim from master (threading mode)
                if self._master:
                    try:
                        task = self._master.claim_task(self.worker_id)
                    except Exception as exc:
                        log.debug("[worker:%s] claim_task error: %s",
                                  self.worker_id, exc)

                # Claim from Redis (Redis mode)
                if task is None and self._redis_client:
                    try:
                        from oneinfinity.infra.task_dispatcher import TaskRouter
                        router = TaskRouter()
                        task = router.consume_from_redis(
                            self.worker_id, self._redis_client,
                            self.config.capabilities
                        )
                    except Exception as exc:
                        log.debug("[worker:%s] Redis consume error: %s",
                                  self.worker_id, exc)

                if task is None:
                    # No work available, release slot and wait
                    self._task_slots.release()
                    time.sleep(self.config.poll_interval_s)
                    continue

                # Execute task in a separate thread so we can run concurrently
                with self._lock:
                    self._current_tasks.append(task.task_id)
                    self._status = "working"

                exec_thread = threading.Thread(
                    target=self._execute_and_report,
                    args=(task,),
                    name=f"task-{task.task_id}",
                    daemon=True,
                )
                exec_thread.start()

            except Exception as exc:
                log.error("[worker:%s] Worker loop error: %s", self.worker_id, exc)
                time.sleep(self.config.poll_interval_s)

        with self._lock:
            self._status = "stopped"

    def _execute_and_report(self, task):
        """Execute a task and report result/failure to master. Releases task slot."""
        try:
            result = self._execute_task(task)
            self._update_graph(task, result)
            self._report_result(task.task_id, result)

            with self._lock:
                self._tasks_completed += 1
                self._current_tasks = [t for t in self._current_tasks
                                        if t != task.task_id]
                if not self._current_tasks:
                    self._status = "idle"

        except Exception as exc:
            log.error("[worker:%s] Task %s failed: %s",
                      self.worker_id, task.task_id, exc)
            self._report_failure(task.task_id, str(exc))

            with self._lock:
                self._tasks_failed += 1
                self._current_tasks = [t for t in self._current_tasks
                                        if t != task.task_id]
                if not self._current_tasks:
                    self._status = "idle"
        finally:
            self._task_slots.release()

    # ── Task Dispatch ─────────────────────────────────────────────────────────

    def _execute_task(self, task) -> dict:
        """Dispatch task to the correct module executor."""
        log.info("[worker:%s] Executing task_id=%s target=%s module=%s",
                 self.worker_id, task.task_id, task.target, task.module)

        dispatch = {
            "recon":         self._run_recon,
            "vuln_scan":     self._run_vuln_scan,
            "exploit":       self._run_exploit,
            "ai_security":   self._run_ai_security,
            "mobile":        self._run_mobile,
            "full_pipeline": self._run_full_pipeline,
        }
        fn = dispatch.get(task.module, self._run_full_pipeline)
        return fn(task)

    # ── Module Runners ─────────────────────────────────────────────────────────

    def _run_recon(self, task) -> dict:
        """Run recon phase via UnifiedScanEngine."""
        target = task.target
        log.info("[worker:%s] Recon: %s", self.worker_id, target)
        try:
            from oneinfinity.scan.unified_scan_engine import get_engine
            result = get_engine().scan(target)
            findings = result.findings if result and hasattr(result, "findings") else []
            return {
                "phase": "recon",
                "target": target,
                "findings": findings,
                "subdomains": [],
                "status": "complete",
            }
        except Exception as exc:
            log.error("[worker:%s] Recon error for %s: %s", self.worker_id, target, exc)
            return {"phase": "recon", "target": target, "findings": [],
                    "error": str(exc), "status": "failed"}

    def _stub_recon(self, target: str) -> dict:
        """Minimal recon stub when full pipeline is unavailable."""
        try:
            from oneinfinity.modules.tool_wrappers import ToolRegistry
            registry = ToolRegistry()
            subdomains = []
            try:
                sub_result = registry.run("subfinder", domain=target)
                if sub_result.success and isinstance(sub_result.data, dict):
                    subdomains = sub_result.data.get("subdomains", [])
            except Exception:
                pass
            return {
                "phase": "recon", "target": target,
                "findings": [], "subdomains": subdomains, "status": "complete",
            }
        except Exception as exc:
            return {"phase": "recon", "target": target, "findings": [],
                    "error": str(exc), "status": "failed"}

    def _run_vuln_scan(self, task) -> dict:
        """Run vulnerability scanner via framework/vuln_scanner."""
        target = task.target
        log.info("[worker:%s] Vuln scan: %s", self.worker_id, target)
        try:
            from oneinfinity_framework.vuln_scanner import VulnScanner
            scanner = VulnScanner(target)
            result = scanner.run()
            findings = result if isinstance(result, list) else result.get("findings", [])
            return {
                "phase": "vuln_scan", "target": target,
                "findings": findings, "status": "complete",
            }
        except ImportError:
            log.warning("[worker:%s] framework.vuln_scanner not available, using tool_wrappers",
                        self.worker_id)
            return self._stub_vuln_scan(target, task.config)
        except Exception as exc:
            log.error("[worker:%s] Vuln scan error for %s: %s", self.worker_id, target, exc)
            return {"phase": "vuln_scan", "target": target, "findings": [],
                    "error": str(exc), "status": "failed"}

    def _stub_vuln_scan(self, target: str, config: dict) -> dict:
        """Minimal vuln scan using ToolRegistry when framework is unavailable."""
        findings = []
        try:
            from oneinfinity.modules.tool_wrappers import ToolRegistry
            registry = ToolRegistry()
            try:
                nuclei_result = registry.run("nuclei", target=target,
                                             severity="info,low,medium,high,critical")
                if nuclei_result.success and isinstance(nuclei_result.data, dict):
                    findings.extend(nuclei_result.data.get("findings", []))
            except Exception as exc:
                log.debug("[worker:%s] nuclei stub error: %s", self.worker_id, exc)
        except Exception:
            pass
        return {
            "phase": "vuln_scan", "target": target,
            "findings": findings, "status": "complete",
        }

    def _run_exploit(self, task) -> dict:
        """Run exploit chain detection via autonomous_exploit_engine."""
        target = task.target
        log.info("[worker:%s] Exploit: %s", self.worker_id, target)
        try:
            from oneinfinity.autonomous_exploit_engine import AutonomousExploitEngine
            engine = AutonomousExploitEngine(target)
            prior_findings = task.config.get("findings", [])
            chains = engine.detect_chains(prior_findings) if prior_findings else []
            chain_dicts = [c.to_dict() if hasattr(c, "to_dict") else c for c in chains]
            return {
                "phase": "exploit", "target": target,
                "findings": chain_dicts, "chains": chain_dicts,
                "status": "complete",
            }
        except ImportError:
            log.warning("[worker:%s] autonomous_exploit_engine not available",
                        self.worker_id)
            return {"phase": "exploit", "target": target, "findings": [],
                    "chains": [], "status": "skipped"}
        except Exception as exc:
            log.error("[worker:%s] Exploit error for %s: %s", self.worker_id, target, exc)
            return {"phase": "exploit", "target": target, "findings": [],
                    "error": str(exc), "status": "failed"}

    def _run_ai_security(self, task) -> dict:
        """Run AI security testing via ai_security_engine."""
        target = task.target
        log.info("[worker:%s] AI security: %s", self.worker_id, target)
        try:
            from oneinfinity.ai.ai_security_engine import AISecurityEngine
            engine = AISecurityEngine(target)
            result = engine.run_all_tools()
            findings = result.get("findings", []) if isinstance(result, dict) else []
            return {
                "phase": "ai_security", "target": target,
                "findings": findings, "status": "complete",
            }
        except ImportError:
            log.warning("[worker:%s] ai_security_engine not available", self.worker_id)
            return {"phase": "ai_security", "target": target, "findings": [],
                    "status": "skipped"}
        except Exception as exc:
            log.error("[worker:%s] AI security error for %s: %s", self.worker_id, target, exc)
            return {"phase": "ai_security", "target": target, "findings": [],
                    "error": str(exc), "status": "failed"}

    def _run_mobile(self, task) -> dict:
        """Run mobile security analysis via mobile_security_engine."""
        target = task.target
        log.info("[worker:%s] Mobile: %s", self.worker_id, target)
        try:
            from oneinfinity.mobile.security_engine import MobileSecurityEngine
            apk_path = task.config.get("apk_path") or task.config.get("ipa_path")
            if not apk_path:
                return {"phase": "mobile", "target": target, "findings": [],
                        "status": "skipped", "reason": "no apk_path/ipa_path in task config"}

            engine = MobileSecurityEngine()
            result = engine.analyze(apk_path)
            findings = result.get("findings", []) if isinstance(result, dict) else []
            return {
                "phase": "mobile", "target": target,
                "findings": findings, "status": "complete",
            }
        except ImportError:
            log.warning("[worker:%s] mobile_security_engine not available", self.worker_id)
            return {"phase": "mobile", "target": target, "findings": [],
                    "status": "skipped"}
        except Exception as exc:
            log.error("[worker:%s] Mobile error for %s: %s", self.worker_id, target, exc)
            return {"phase": "mobile", "target": target, "findings": [],
                    "error": str(exc), "status": "failed"}

    def _run_full_pipeline(self, task) -> dict:
        """
        Run the full autonomous scan pipeline for a target.
        This is the default when module is 'full_pipeline' or unknown.
        """
        target = task.target
        modules = task.config.get("modules",
                                   ["recon", "vuln_scan", "exploit"])
        log.info("[worker:%s] Full pipeline: %s modules=%s",
                 self.worker_id, target, modules)

        all_findings = []
        phase_results = {}

        try:
            from oneinfinity.scan.unified_scan_engine import get_engine
            result = get_engine().scan(target)
            if result:
                all_findings = result.findings if hasattr(result, "findings") else []

        except Exception as _pipeline_exc:
            log.warning("[worker:%s] UnifiedScanEngine unavailable, "
                        "running module fallbacks: %s", self.worker_id, _pipeline_exc)
            # Fallback: run each module individually
            for mod in modules:
                sub_task = type("_T", (), {
                    "task_id": task.task_id,
                    "target": target,
                    "module": mod,
                    "config": task.config,
                })()
                dispatch = {
                    "recon":       self._run_recon,
                    "vuln_scan":   self._run_vuln_scan,
                    "exploit":     self._run_exploit,
                    "ai_security": self._run_ai_security,
                    "mobile":      self._run_mobile,
                }
                fn = dispatch.get(mod)
                if fn:
                    try:
                        res = fn(sub_task)
                        all_findings.extend(res.get("findings", []))
                        phase_results[mod] = {"status": res.get("status", "complete")}
                    except Exception as exc:
                        log.error("[worker:%s] Module %s failed: %s",
                                  self.worker_id, mod, exc)
                        phase_results[mod] = {"status": "failed", "error": str(exc)}

        except Exception as exc:
            log.error("[worker:%s] Full pipeline error for %s: %s",
                      self.worker_id, target, exc)
            return {
                "phase": "full_pipeline", "target": target,
                "findings": all_findings, "phases": phase_results,
                "error": str(exc), "status": "failed",
            }

        return {
            "phase":    "full_pipeline",
            "target":   target,
            "findings": all_findings,
            "phases":   phase_results,
            "status":   "complete",
        }

    # ── Graph Update ──────────────────────────────────────────────────────────

    def _update_graph(self, task, result: dict):
        """
        Push findings from a completed task into the attack graph.
        Uses attack_graph.builder.AttackGraphBuilder if available.
        """
        findings = result.get("findings", [])
        if not findings:
            return
        try:
            from oneinfinity.attack_graph_core.builder import AttackGraphBuilder
            from oneinfinity.attack_graph_core.graph import AttackGraph
            graph = AttackGraph(task.target)
            builder = AttackGraphBuilder(target=task.target, graph=graph)
            for finding in findings:
                try:
                    builder.from_finding(finding)
                except Exception:
                    pass

            # Push graph reference to master for persistence
            if self._master and not self._master._graph:
                self._master._graph = graph
            elif self._master and self._master._graph:
                # Merge nodes/edges into existing graph
                for node_id, node in graph.nodes.items():
                    if node_id not in self._master._graph.nodes:
                        self._master._graph.nodes[node_id] = node
                for edge in graph.edges:
                    self._master._graph.edges.append(edge)

            log.debug("[worker:%s] Graph updated: %d findings → graph",
                      self.worker_id, len(findings))
        except ImportError:
            log.debug("[worker:%s] attack_graph not available, skipping graph update",
                      self.worker_id)
        except Exception as exc:
            log.debug("[worker:%s] Graph update error: %s", self.worker_id, exc)

    # ── Reporting ─────────────────────────────────────────────────────────────

    def _report_result(self, task_id: str, result: dict):
        """Send a successful result to master."""
        if self._master:
            try:
                self._master.complete_task(task_id, result)
            except Exception as exc:
                log.error("[worker:%s] report_result error: %s", self.worker_id, exc)

    def _report_failure(self, task_id: str, error: str):
        """Send a failure notification to master."""
        if self._master:
            try:
                self._master.fail_task(task_id, error)
            except Exception as exc:
                log.error("[worker:%s] report_failure error: %s", self.worker_id, exc)

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    def _heartbeat_loop(self):
        """Periodic thread: updates last_heartbeat in master registry."""
        while self._running:
            self._send_heartbeat()
            time.sleep(self.HEARTBEAT_INTERVAL_S)

    def _send_heartbeat(self):
        """Update last heartbeat timestamp in master."""
        self._last_heartbeat = time.time()
        if self._master:
            try:
                self._master.update_heartbeat(self.worker_id)
            except Exception as exc:
                log.debug("[worker:%s] Heartbeat error: %s", self.worker_id, exc)
