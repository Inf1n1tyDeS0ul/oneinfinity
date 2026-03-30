"""
god_mode_engine.py — GOD MODE orchestration for OneInfinity.

Sequences every capability in an adaptive cascade:
  Stage 1: Foundation (doctor + adaptive-recon + analyze-app) — blocking
  Stage 2: FullScanMission starts in a daemon thread
  Stage 3: Event-driven unlocking (research, swarm, chains) via event bus
  Stage 4: Convergence loop — exits on time/cap/convergence/stop
  Stage 5: ReportMission — always runs (finalization)
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("oneinfinity.god_mode")

# ── Constants ──────────────────────────────────────────────────────────────────

GOD_MODE_DIR = Path.home() / ".oneinfinity"
GOD_MODE_LOG_DIR = GOD_MODE_DIR / "logs"
CONVERGENCE_EMPTY_ITERS_REQUIRED = 2   # 2 consecutive research iters with 0 new findings
EVENT_UNLOCK_VULN_THRESHOLD = 3        # NEW_VULNERABILITY events to start ResearchMission
EVENT_UNLOCK_ENDPOINT_THRESHOLD = 10   # NEW_ENDPOINT events to start SwarmMission


class FoundationError(RuntimeError):
    """Raised when doctor --quick fails. Only hard-abort in GOD MODE."""


def _parse_max_time(s: str) -> int:
    """Parse '30m', '2h', '4h' → seconds. Returns 7200 on error. Rejects negative values."""
    s = str(s).strip().lower()
    if s.endswith("h"):
        try:
            result = int(s[:-1]) * 3600
            return result if result > 0 else 7200
        except ValueError:
            return 7200
    if s.endswith("m"):
        try:
            result = int(s[:-1]) * 60
            return result if result > 0 else 7200
        except ValueError:
            return 7200
    try:
        result = int(s)
        return result if result > 0 else 7200
    except ValueError:
        return 7200


# ── GodModeSession ─────────────────────────────────────────────────────────────

@dataclass
class GodModeSession:
    scan_id: str
    target: str
    start_time: float
    max_time_sec: int = 7200
    max_findings: int = 100
    phases_complete: list = field(default_factory=list)
    finding_count: int = 0  # Mutations from multiple threads; relies on CPython GIL atomicity for single += ops
    missions: dict = field(default_factory=dict)   # name → status str
    terminated_by: Optional[str] = None            # "convergence"|"time"|"cap"|"stop"|"error"
    log_path: str = ""
    background: bool = False
    auth_config: dict = field(default_factory=dict)  # session_cookie/bearer_token/auth_header

    def elapsed(self) -> float:
        return time.time() - self.start_time


# ── GodModeStateFile ───────────────────────────────────────────────────────────

class GodModeStateFile:
    """Persists GodModeSession to ~/.oneinfinity/god-mode-<scan_id>.json."""

    def __init__(self, scan_id: str):
        GOD_MODE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = GOD_MODE_DIR / f"god-mode-{scan_id}.json"

    def write(self, session: GodModeSession) -> None:
        try:
            data = asdict(session)
            data["elapsed_seconds"] = round(session.elapsed(), 1)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str))
            tmp.replace(self.path)   # atomic on POSIX
        except Exception as exc:
            log.warning("State file write failed (non-fatal): %s", exc)

    def read(self) -> Optional[dict]:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            return None
        except Exception as exc:
            log.warning("State file read failed: %s", exc)
            return None

    @staticmethod
    def find_latest() -> Optional[Path]:
        """Return the most recently modified god-mode state file, or None."""
        GOD_MODE_DIR.mkdir(parents=True, exist_ok=True)
        files = sorted(GOD_MODE_DIR.glob("god-mode-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        return files[0] if files else None

    @staticmethod
    def stop_sentinel_path(scan_id: str) -> Path:
        return GOD_MODE_DIR / f"god-mode-{scan_id}.stop"


# ── ConvergenceChecker ─────────────────────────────────────────────────────────

class ConvergenceChecker:
    """
    Fires convergence when:
      - 2 consecutive research iterations each produced 0 new findings, AND
      - CapabilityMap shows all known vuln classes are covered in current findings.
    """

    def __init__(self):
        self._last_finding_count: int = 0
        self.research_iters_with_no_new: int = 0
        self._lock = threading.Lock()

    def record_research_iteration(self, current_finding_count: int) -> None:
        """Call after each research iteration completes."""
        with self._lock:
            delta = current_finding_count - self._last_finding_count
            if delta == 0:
                self.research_iters_with_no_new += 1
            else:
                self.research_iters_with_no_new = 0
            self._last_finding_count = current_finding_count

    def is_converged(self, finding_vuln_types: list[str]) -> bool:
        """
        Return True when 2+ consecutive empty research iters AND
        all known vuln classes appear in finding_vuln_types.
        If CapabilityMap unavailable, skip the coverage check.
        """
        with self._lock:
            if self.research_iters_with_no_new < CONVERGENCE_EMPTY_ITERS_REQUIRED:
                return False
        # If no vuln types specified, convergence is just based on empty iters
        if not finding_vuln_types:
            return True
        try:
            from modules.capability_map import CapabilityMap, Vuln
            all_classes = {v for k, v in vars(Vuln).items() if not k.startswith("_") and isinstance(v, str)}
            covered = set(finding_vuln_types)
            return all_classes.issubset(covered)
        except Exception:
            # If capmap unavailable, convergence is just based on empty iters
            return True

# ── Mission base class ─────────────────────────────────────────────────────────

class Mission(ABC):
    """
    Base class for all GOD MODE missions.
    Each mission wraps one engine and runs in a daemon thread.
    """

    def __init__(self, name: str):
        self.name = name
        self.status: str = "pending"    # pending|running|done|failed
        self._thread: Optional[threading.Thread] = None
        self._result: dict = {}
        self._stop_event = threading.Event()

    def start(self, session: GodModeSession) -> None:
        """Start the mission in a daemon thread."""
        self.status = "running"
        self._thread = threading.Thread(
            target=self._safe_run,
            args=(session,),
            name=f"god-mode-{self.name}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def is_done(self) -> bool:
        return self.status in ("done", "failed")

    def result(self) -> dict:
        return dict(self._result)

    def _safe_run(self, session: GodModeSession) -> None:
        try:
            self._run(session)
            self.status = "done"
        except FoundationError:
            self.status = "failed"
            raise   # FoundationError propagates — it's the one hard abort
        except Exception as exc:
            log.warning("Mission '%s' failed (non-fatal): %s", self.name, exc)
            self.status = "failed"

    @abstractmethod
    def _run(self, session: GodModeSession) -> None:
        """Override in each concrete mission."""


# ── FoundationMission ──────────────────────────────────────────────────────────

class FoundationMission(Mission):
    """
    Stage 1 — runs synchronously before any threads start.
    Steps: doctor --quick → adaptive-recon → analyze-app.
    doctor failure → hard abort (FoundationError).
    recon/analyze failures → warn + continue.
    """

    def __init__(self):
        super().__init__("foundation")
        self.recon = None       # ReconIntelligence from AdaptiveReconEngine
        self.app_model = None   # AppModel from ApplicationIntelligenceEngine

    def run_sync(self, session: GodModeSession) -> None:
        """Run foundation synchronously (called from conductor, not in thread)."""
        log.info("[GOD MODE] Stage 1: Foundation starting for %s", session.target)
        self.status = "running"
        try:
            self._run(session)
            self.status = "done"
        except FoundationError:
            self.status = "failed"
            raise

    def _run(self, session: GodModeSession) -> None:
        # ── Step 1: doctor --quick ─────────────────────────────────────────
        log.info("[GOD MODE] Foundation Step 1: doctor --quick")
        try:
            import asyncio as _asyncio
            from core.doctor import DoctorOrchestrator
            _ws = os.getcwd()
            _report = _asyncio.run(DoctorOrchestrator(_ws).run(quick=True))
            _score = _report.get("score", 10.0) if isinstance(_report, dict) else _report.score
            if _score < 10.0:
                raise FoundationError(
                    f"Doctor score {_score:.1f}/10.0 — fix environment before GOD MODE"
                )
            log.info("[GOD MODE] Doctor: %.1f/10.0 — OK", _score)
        except FoundationError:
            raise
        except Exception as exc:
            raise FoundationError(f"Doctor check failed: {exc}") from exc

        # ── Step 2: adaptive-recon --depth deep ───────────────────────────
        log.info("[GOD MODE] Foundation Step 2: adaptive-recon --depth deep")
        try:
            from adaptive_recon_engine import AdaptiveReconEngine
            self.recon = AdaptiveReconEngine(session.target, depth="deep").run()
            log.info("[GOD MODE] Recon complete — subdomains=%s apis=%s",
                     len(getattr(self.recon, "subdomains", []) or []),
                     len(getattr(getattr(self.recon, "api_map", None), "endpoints", []) or []))
        except Exception as exc:
            log.warning("[GOD MODE] Recon failed (non-fatal): %s — continuing with less intel", exc)
            self.recon = None

        # ── Step 3: analyze-app ───────────────────────────────────────────
        log.info("[GOD MODE] Foundation Step 3: analyze-app")
        try:
            from application_intelligence import ApplicationIntelligenceEngine
            tech_profile = None
            if self.recon and hasattr(self.recon, "tech_profile"):
                tech_profile = vars(self.recon.tech_profile) if self.recon.tech_profile else None
            _aie = ApplicationIntelligenceEngine(session.target)
            self.app_model = _aie.analyze_application_structure(tech_profile=tech_profile)
            log.info("[GOD MODE] App model built — endpoints=%s auth_flows=%s",
                     len(getattr(self.app_model, "api_endpoints", []) or []),
                     len(getattr(self.app_model, "auth_flows", []) or []))
        except Exception as exc:
            log.warning("[GOD MODE] App analysis failed (non-fatal): %s — continuing", exc)
            self.app_model = None

        self._result = {
            "recon_ok": self.recon is not None,
            "app_model_ok": self.app_model is not None,
        }


# ── FullScanMission ────────────────────────────────────────────────────────────

class FullScanMission(Mission):
    """
    Runs the canonical 10-phase pipeline via run_canonical_pipeline().
    # TODO: pass recon intel to pipeline when run_canonical_pipeline supports seed_recon param
    """

    def __init__(self, foundation: FoundationMission, auth_config: dict = None):
        super().__init__("full_scan")
        self._foundation = foundation
        self._auth_config = auth_config or {}

    def _run(self, session: GodModeSession) -> None:
        from pipeline.executor import run_canonical_pipeline

        log.info("[GOD MODE] FullScanMission: starting canonical pipeline for %s", session.target)
        if self._auth_config and any(self._auth_config.values()):
            log.info("[GOD MODE] FullScanMission: authenticated scan mode active")

        # Output dir: ~/.oneinfinity/<scan_id>/full_scan/
        out_dir = str(GOD_MODE_DIR / session.scan_id / "full_scan")
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        def _on_progress(phase: str, pct: int, msg: str) -> None:
            log.info("[GOD MODE] full_scan [%d%%] [%s] %s", pct, phase, msg)

        result = run_canonical_pipeline(
            target=session.target,
            output_dir=out_dir,
            mode="subprocess",
            on_progress=_on_progress,
            auth_config=self._auth_config if self._auth_config else None,
        )

        # Update session finding count
        new_count = len(result.findings) if result and result.findings else 0
        session.finding_count += new_count
        session.phases_complete.append("full_scan")

        # Push findings into the ingestion engine so ReportMission can read them
        if result and result.findings:
            try:
                from result_ingestion_engine import get_ingestion_engine, RawResult
                bus = get_ingestion_engine()
                for f in result.findings:
                    fd = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
                    if fd:
                        bus.ingest(RawResult(scan_id=session.scan_id, source="god-mode-full-scan", raw=fd))
            except Exception as exc:
                log.warning("[GOD MODE] FullScanMission ingestion bus publish failed: %s", exc)

        # Fire NEW_VULNERABILITY events so ResearchMission can unlock
        if result and result.findings:
            try:
                from event_bus import get_bus, EventType
                bus = get_bus()
                for f in result.findings:
                    fd = f if isinstance(f, dict) else {}
                    if fd:
                        bus.publish(EventType.NEW_VULNERABILITY, fd, source="god-mode-full-scan")
            except Exception as exc:
                log.warning("[GOD MODE] FullScanMission event bus publish failed: %s", exc)

        log.info("[GOD MODE] FullScanMission complete — %d findings", new_count)
        self._result = {"findings": new_count, "output_dir": out_dir}


# ── ResearchMission ────────────────────────────────────────────────────────────

class ResearchMission(Mission):
    """
    Runs the iterative research loop via ResearchModeController.
    Each completed iteration notifies the ConvergenceChecker.
    Unlocked by: NEW_VULNERABILITY count >= 3.
    """

    def __init__(self, convergence: ConvergenceChecker):
        super().__init__("research")
        self._convergence = convergence
        self._iterations_done: int = 0

    def _run(self, session: GodModeSession) -> None:
        from research_mode_controller import ResearchModeController

        log.info("[GOD MODE] ResearchMission: starting research loop for %s", session.target)

        out_dir = str(GOD_MODE_DIR / session.scan_id / "research")
        Path(out_dir).mkdir(parents=True, exist_ok=True)

        ctrl = ResearchModeController(
            target=session.target,
            output_dir=out_dir,
            max_iterations=5,
            passive_only=False,
        )
        discoveries = ctrl.run_research()

        new_count = len(discoveries) if discoveries else 0
        session.finding_count += new_count
        self._iterations_done += 1
        session.phases_complete.append("research")

        # Notify convergence checker
        self._convergence.record_research_iteration(session.finding_count)
        log.info("[GOD MODE] ResearchMission complete — %d discoveries, iter=%d",
                 new_count, self._iterations_done)
        self._result = {"discoveries": new_count, "iterations": self._iterations_done}


# ── SwarmMission ───────────────────────────────────────────────────────────────

class SwarmMission(Mission):
    """
    Runs all 8 specialized swarm agents in parallel via run_swarm().
    Unlocked by: NEW_ENDPOINT count >= 10.
    """

    def __init__(self):
        super().__init__("swarm")

    def _run(self, session: GodModeSession) -> None:
        import asyncio as _asyncio
        from agent_swarm_coordinator import run_swarm

        log.info("[GOD MODE] SwarmMission: deploying 8 agents against %s", session.target)

        result = _asyncio.run(run_swarm(
            target=session.target,
            context={},
            concurrency=4,
            agent_types=None,   # all 8 agent types
        ))

        new_count = len(result.findings) if result and hasattr(result, "findings") else 0
        session.finding_count += new_count
        session.phases_complete.append("swarm")

        # Publish to ingestion bus
        try:
            from result_ingestion_engine import get_ingestion_engine, RawResult
            sid = session.scan_id
            bus = get_ingestion_engine()
            for f in (result.findings if result and hasattr(result, "findings") else []):
                fd = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
                if fd:
                    bus.ingest(RawResult(scan_id=sid, source="god-mode-swarm", raw=fd))
        except Exception as exc:
            log.warning("[GOD MODE] SwarmMission ingestion bus publish failed: %s", exc)

        log.info("[GOD MODE] SwarmMission complete — %d findings", new_count)
        self._result = {"findings": new_count}


# ── ChainsMission ──────────────────────────────────────────────────────────────

class ChainsMission(Mission):
    """
    Runs exploit chain detection on all accumulated findings.
    Unlocked by: ResearchMission iteration 2+ complete.
    """

    def __init__(self):
        super().__init__("chains")

    def _run(self, session: GodModeSession) -> None:
        from exploit_chains import ExploitChainEngine
        from result_ingestion_engine import get_ingestion_engine

        log.info("[GOD MODE] ChainsMission: running chain analysis for %s", session.target)

        findings = []
        try:
            findings = get_ingestion_engine().get_findings() or []
        except Exception as exc:
            log.warning("[GOD MODE] ChainsMission: could not load findings: %s", exc)

        engine = ExploitChainEngine()
        try:
            chains = engine.detect_chains(findings, session.target)
        except Exception as exc:
            log.warning("[GOD MODE] ChainsMission: chain detection failed: %s", exc)
            chains = None
        finally:
            session.phases_complete.append("chains")

        chain_count = len(chains) if chains else 0
        log.info("[GOD MODE] ChainsMission complete — %d chains detected", chain_count)
        self._result = {"chains": chain_count}


# ── ReportMission ──────────────────────────────────────────────────────────────

class ReportMission(Mission):
    """
    Finalization — always runs regardless of termination condition.
    Steps: validate → dedup → capmap → learn.
    Each step is independently try/except wrapped.
    """

    def __init__(self, report_fmt: str = "markdown"):
        super().__init__("report")
        self._report_fmt = report_fmt

    def run_sync(self, session: GodModeSession) -> None:
        """Run finalization synchronously so conductor waits for it."""
        log.info("[GOD MODE] Stage 5: Finalization starting")
        self.status = "running"
        try:
            self._run(session)
            self.status = "done"
        except Exception as exc:
            log.warning("[GOD MODE] ReportMission failed: %s", exc)
            self.status = "failed"

    def _run(self, session: GodModeSession) -> None:
        # Step 1: validate findings
        try:
            from result_ingestion_engine import get_ingestion_engine
            from enforcement_controller import get_enforcement_controller
            raw_findings = get_ingestion_engine().get_findings() or []
            validated = get_enforcement_controller().validate_findings(raw_findings)
            log.info("[GOD MODE] Report: validated %d/%d findings", len(validated), len(raw_findings))
        except Exception as exc:
            log.warning("[GOD MODE] Report: validation failed (non-fatal): %s", exc)
            validated = []

        # Step 2: dedup
        try:
            from core.deduplicator import Deduplicator
            validated = Deduplicator().filter_new(validated)
            log.info("[GOD MODE] Report: %d unique findings after dedup", len(validated))
        except Exception as exc:
            log.warning("[GOD MODE] Report: dedup failed (non-fatal): %s", exc)

        # Step 3: capmap coverage
        try:
            found_types = [f.get("vuln_type", "") for f in validated if isinstance(f, dict)]
            from modules.capability_map import Vuln
            all_classes = {v for k, v in vars(Vuln).items() if not k.startswith("_") and isinstance(v, str)}
            covered = {vt for vt in found_types if vt}
            uncovered = all_classes - covered
            log.info("[GOD MODE] Capmap: %d/%d vuln classes covered. Uncovered: %s",
                     len(covered), len(all_classes), sorted(uncovered)[:5] if uncovered else "none")
        except Exception as exc:
            log.warning("[GOD MODE] Report: capmap check failed (non-fatal): %s", exc)

        # Step 4: learn
        try:
            import types
            from learning import LearningSystem
            ls = LearningSystem()
            task_result = types.SimpleNamespace(
                target=session.target,
                findings=validated,
                tools_used=[],
                success=True,
                duration=session.elapsed(),
            )
            ls.record_result(task_result)
            ls.close()
            log.info("[GOD MODE] Report: learning system updated")
        except Exception as exc:
            log.warning("[GOD MODE] Report: learning update failed (non-fatal): %s", exc)

        session.phases_complete.append("report")
        self._result = {"validated_findings": len(validated)}


# ── GodModeConductor ───────────────────────────────────────────────────────────

class GodModeConductor:
    """
    Master orchestrator for GOD MODE.
    Manages mission lifecycle and convergence loop.
    """

    def __init__(self):
        self._session: Optional[GodModeSession] = None
        self._state_file: Optional[GodModeStateFile] = None
        self._convergence = ConvergenceChecker()
        self._foundation: Optional[FoundationMission] = None
        self._missions: list[Mission] = []
        self._lock = threading.Lock()
        self._log_handler: Optional[logging.FileHandler] = None

        # Event bus counters (guarded by _lock)
        self._vuln_count: int = 0
        self._endpoint_count: int = 0
        self._research_iters_done: int = 0

        # Event bus unsubscribe handles
        self._bus_handlers: list = []

    # ── Event bus ─────────────────────────────────────────────────────────────

    def _subscribe_to_event_bus(self) -> None:
        try:
            from event_bus import get_bus, EventType

            def _on_vuln(event) -> None:
                with self._lock:
                    self._vuln_count += 1
                    count = self._vuln_count
                if count == EVENT_UNLOCK_VULN_THRESHOLD:
                    log.info("[GOD MODE] %d vulns → unlocking ResearchMission", count)
                    self._unlock_mission("research")

            def _on_endpoint(event) -> None:
                with self._lock:
                    self._endpoint_count += 1
                    count = self._endpoint_count
                if count == EVENT_UNLOCK_ENDPOINT_THRESHOLD:
                    log.info("[GOD MODE] %d endpoints → unlocking SwarmMission", count)
                    self._unlock_mission("swarm")

            bus = get_bus()
            bus.on(EventType.NEW_VULNERABILITY, _on_vuln)
            bus.on(EventType.NEW_ENDPOINT, _on_endpoint)
            self._bus_handlers = [
                (EventType.NEW_VULNERABILITY, _on_vuln),
                (EventType.NEW_ENDPOINT, _on_endpoint),
            ]
            log.info("[GOD MODE] Event bus subscriptions active")
        except Exception as exc:
            log.warning("[GOD MODE] Event bus subscription failed (non-fatal): %s", exc)

    def _unsubscribe_from_event_bus(self) -> None:
        try:
            from event_bus import get_bus
            bus = get_bus()
            for event_type, handler in self._bus_handlers:
                try:
                    bus.off(event_type, handler)
                except Exception:
                    pass
        except Exception as exc:
            log.warning("[GOD MODE] Event bus unsubscribe failed: %s", exc)
        self._bus_handlers = []

    def _unlock_mission(self, name: str) -> None:
        """Start a mission by name if it's still pending."""
        if self._session is None:
            return
        for m in self._missions:
            if m.name == name and m.status == "pending":
                log.info("[GOD MODE] Starting mission: %s", name)
                m.start(self._session)
                self._update_session_missions()
                break

    def _update_session_missions(self) -> None:
        """Sync mission statuses into session and persist."""
        if self._session and self._state_file:
            self._session.missions = {m.name: m.status for m in self._missions}
            self._state_file.write(self._session)

    # ── Status + Stop ─────────────────────────────────────────────────────────

    def status(self, scan_id: Optional[str] = None) -> Optional[dict]:
        """Read state from disk. Returns None if session not found."""
        if scan_id:
            sf = GodModeStateFile(scan_id)
            return sf.read()
        # Find most recent
        latest = GodModeStateFile.find_latest()
        if latest:
            try:
                return json.loads(latest.read_text())
            except Exception:
                return None
        return None

    def stop(self, scan_id: Optional[str] = None) -> bool:
        """Write stop sentinel. Returns True if sentinel written."""
        if scan_id is None and self._session:
            scan_id = self._session.scan_id
        if not scan_id:
            # Find latest
            latest = GodModeStateFile.find_latest()
            if latest:
                scan_id = latest.stem.replace("god-mode-", "")
        if not scan_id:
            return False
        # Verify the session exists on disk OR is the active in-memory session
        state_file_exists = GodModeStateFile(scan_id).path.exists()
        in_memory_match = self._session is not None and self._session.scan_id == scan_id
        if not state_file_exists and not in_memory_match:
            return False
        sentinel = GodModeStateFile.stop_sentinel_path(scan_id)
        sentinel.touch()
        log.info("[GOD MODE] Stop sentinel written for %s", scan_id)
        return True

    # ── Logging setup ─────────────────────────────────────────────────────────

    def _setup_logging(self, scan_id: str) -> str:
        """Set up file logging for GOD MODE session. Returns log path."""
        GOD_MODE_LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = str(GOD_MODE_LOG_DIR / f"god-mode-{scan_id}.log")
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logging.getLogger("oneinfinity").addHandler(fh)
        self._log_handler = fh
        return log_path

    def _teardown_logging(self) -> None:
        if self._log_handler:
            try:
                logging.getLogger("oneinfinity").removeHandler(self._log_handler)
                self._log_handler.close()
            except Exception:
                pass
            self._log_handler = None

    # ── Convergence loop ──────────────────────────────────────────────────────

    def _convergence_loop(self) -> str:
        """
        Polls every 30s for termination conditions.
        Returns the reason: 'convergence'|'time'|'cap'|'stop'|'all_done'.
        """
        if self._session is None:
            raise RuntimeError("_convergence_loop() called before session is initialized")
        session = self._session

        while True:
            time.sleep(30)

            # Stop sentinel
            sentinel = GodModeStateFile.stop_sentinel_path(session.scan_id)
            if sentinel.exists():
                log.info("[GOD MODE] Stop sentinel detected — finalizing")
                return "stop"

            # Time cap
            if session.elapsed() >= session.max_time_sec:
                log.info("[GOD MODE] Time cap reached (%.0fs) — finalizing", session.elapsed())
                return "time"

            # Finding cap
            if session.finding_count >= session.max_findings:
                log.info("[GOD MODE] Finding cap reached (%d) — finalizing", session.finding_count)
                return "cap"

            # Convergence
            found_types: list[str] = []
            try:
                from result_ingestion_engine import get_ingestion_engine
                findings = get_ingestion_engine().get_findings() or []
                found_types = [f.get("vuln_type", "") for f in findings if isinstance(f, dict)]
            except Exception:
                pass
            if self._convergence.is_converged(found_types):
                log.info("[GOD MODE] Convergence detected — finalizing")
                return "convergence"

            # All missions done naturally
            active = [m for m in self._missions if m.status == "running"]
            if not active:
                log.info("[GOD MODE] All missions complete — finalizing")
                return "all_done"

            # Update state
            self._update_session_missions()
            log.debug("[GOD MODE] Convergence loop tick — elapsed=%.0fs findings=%d",
                      session.elapsed(), session.finding_count)

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        max_time: str = "2h",
        max_findings: int = 100,
        background: bool = False,
        no_swarm: bool = False,
        no_research: bool = False,
        report_fmt: str = "markdown",
        auth_config: dict = None,
    ) -> GodModeSession:
        """
        Run GOD MODE against target.
        Blocks until convergence (foreground) or returns after Stage 1 (background).
        """
        # ── Session setup ──────────────────────────────────────────────────
        scan_id = "gm-" + str(uuid.uuid4())[:6]
        log_path = self._setup_logging(scan_id)
        session = GodModeSession(
            scan_id=scan_id,
            target=target,
            start_time=time.time(),
            max_time_sec=_parse_max_time(max_time),
            max_findings=max_findings,
            log_path=log_path,
            background=background,
            auth_config=auth_config or {},
        )
        self._session = session
        self._state_file = GodModeStateFile(scan_id)
        self._state_file.write(session)

        log.info("[GOD MODE] Session %s started — target=%s max_time=%s max_findings=%d",
                 scan_id, target, max_time, max_findings)
        print(f"\n[*] GOD MODE — Session: {scan_id}")
        print(f"    Target:    {target}")
        print(f"    Max time:  {max_time}  |  Max findings: {max_findings}")
        print(f"    Log:       {log_path}")

        # ── Stage 1: Foundation (blocking) ─────────────────────────────────
        print(f"\n[*] Stage 1: Foundation...")
        foundation = FoundationMission()
        self._foundation = foundation
        try:
            foundation.run_sync(session)
        except FoundationError as exc:
            print(f"\n[!] GOD MODE aborted — Foundation failed: {exc}")
            session.terminated_by = "error"
            self._state_file.write(session)
            self._teardown_logging()
            return session

        print(f"    [+] Foundation complete — recon={'ok' if foundation.recon else 'skipped'} "
              f"app_model={'ok' if foundation.app_model else 'skipped'}")

        # ── Background detach ──────────────────────────────────────────────
        if background:
            print(f"\n[+] GOD MODE running in background. Session: {scan_id}")
            print(f"    Status:  oneinfinity god-mode status {scan_id}")
            print(f"    Logs:    oneinfinity god-mode logs --follow")
            print(f"    Stop:    oneinfinity god-mode stop {scan_id}")
            # Start background thread (non-daemon keeps process alive after main thread exits)
            bg_thread = threading.Thread(
                target=self._run_stages_2_to_5,
                args=(session, foundation, no_swarm, no_research, report_fmt),
                name="god-mode-bg",
                daemon=False,   # non-daemon: process stays alive until this thread finishes
            )
            bg_thread.start()
            return session

        # ── Foreground: run stages 2–5 directly ───────────────────────────
        self._run_stages_2_to_5(session, foundation, no_swarm, no_research, report_fmt)
        return session

    def _run_stages_2_to_5(
        self,
        session: GodModeSession,
        foundation: FoundationMission,
        no_swarm: bool,
        no_research: bool,
        report_fmt: str,
    ) -> None:
        """Stages 2-5: pipeline + event missions + convergence + report."""

        # ── Build mission list ─────────────────────────────────────────────
        full_scan = FullScanMission(foundation, auth_config=session.auth_config)
        research = ResearchMission(self._convergence) if not no_research else None
        swarm = SwarmMission() if not no_swarm else None
        chains = ChainsMission()
        report = ReportMission(report_fmt)

        self._missions = [m for m in [full_scan, research, swarm, chains, report] if m is not None]
        self._update_session_missions()

        # ── Stage 2: subscribe to event bus + launch FullScanMission ──────
        print(f"\n[*] Stage 2: Full scan + event bus active")
        self._subscribe_to_event_bus()
        full_scan.start(session)

        # Fire NEW_ENDPOINT events from Foundation recon so SwarmMission can unlock
        try:
            from event_bus import get_bus, EventType
            bus = get_bus()
            recon = foundation.recon
            if recon:
                urls = list(getattr(recon, "all_urls", []) or [])
                api_map = getattr(recon, "api_map", None)
                if api_map:
                    urls += list(getattr(api_map, "endpoints", []) or [])
                for url in urls[:EVENT_UNLOCK_ENDPOINT_THRESHOLD + 5]:
                    bus.publish(EventType.NEW_ENDPOINT, {"url": str(url)}, source="god-mode-foundation")
                if urls:
                    log.info("[GOD MODE] Fired %d NEW_ENDPOINT events from Foundation recon", min(len(urls), EVENT_UNLOCK_ENDPOINT_THRESHOLD + 5))
        except Exception as exc:
            log.warning("[GOD MODE] Foundation endpoint event fire failed: %s", exc)

        self._update_session_missions()

        # ── Stage 3 is automatic (event-driven unlocking from _on_vuln/_on_endpoint)

        # ── Stage 4: Convergence loop ──────────────────────────────────────
        print(f"[*] Stage 4: Convergence loop (checks every 30s)")
        reason = self._convergence_loop()
        session.terminated_by = reason
        self._update_session_missions()

        # Stop all running missions
        for m in self._missions:
            if not m.is_done():
                m.stop()

        # ── Also start ChainsMission if research ran ───────────────────────
        if research and research.status == "done" and chains.status == "pending":
            log.info("[GOD MODE] Triggering ChainsMission post-convergence")
            chains.start(session)
            if chains._thread is not None:
                chains._thread.join(timeout=120)  # wait up to 2 min for chains

        self._unsubscribe_from_event_bus()

        # ── Stage 5: ReportMission (always) ────────────────────────────────
        print(f"\n[*] Stage 5: Finalization...")
        report.run_sync(session)
        self._update_session_missions()

        # Final summary
        print(f"\n[+] GOD MODE complete — Session: {session.scan_id}")
        print(f"    Terminated by: {session.terminated_by}")
        print(f"    Elapsed:       {session.elapsed():.0f}s")
        print(f"    Findings:      {session.finding_count}")
        print(f"    Phases:        {', '.join(session.phases_complete)}")
        print(f"    Report:        {GOD_MODE_DIR / session.scan_id}")

        self._teardown_logging()


# ── Singleton ──────────────────────────────────────────────────────────────────

_conductor_singleton: Optional[GodModeConductor] = None
_conductor_lock = threading.Lock()


def get_god_mode_conductor() -> GodModeConductor:
    global _conductor_singleton
    if _conductor_singleton is None:
        with _conductor_lock:
            if _conductor_singleton is None:
                _conductor_singleton = GodModeConductor()
    return _conductor_singleton
