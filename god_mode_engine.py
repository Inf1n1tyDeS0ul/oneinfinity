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
    finding_count: int = 0
    missions: dict = field(default_factory=dict)   # name → status str
    terminated_by: Optional[str] = None            # "convergence"|"time"|"cap"|"stop"|"error"
    log_path: str = ""
    background: bool = False

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
            if _report.score < 10.0:
                raise FoundationError(
                    f"Doctor score {_report.score:.1f}/10.0 — fix environment before GOD MODE"
                )
            log.info("[GOD MODE] Doctor: %.1f/10.0 — OK", _report.score)
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

    def __init__(self, foundation: FoundationMission):
        super().__init__("full_scan")
        self._foundation = foundation

    def _run(self, session: GodModeSession) -> None:
        from pipeline.executor import run_canonical_pipeline

        log.info("[GOD MODE] FullScanMission: starting canonical pipeline for %s", session.target)

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
        )

        # Update session finding count
        new_count = len(result.findings) if result and result.findings else 0
        session.finding_count += new_count
        session.phases_complete.append("full_scan")
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
