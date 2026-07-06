"""
scan_orchestrator.py — Canonical Execution Facade
===================================================
Single entry-point for ALL scan execution paths:

  CLI  (full-scan command)
  API  (POST /api/scans)
  Worker (TaskExecutor.run())
  God Mode (FullScanMission)

All callers converge here.  This eliminates the dual-path problem
where CLI used ``CanonicalExecutor`` (subprocess-per-phase) while
the API used ``UnifiedScanEngine`` (in-process 21-phase pipeline).

Architecture
------------
``ScanOrchestrator`` is the ONLY public interface.  Internally it
delegates to ``UnifiedScanEngine`` (the canonical implementation):

  ScanOrchestrator.run(target, ...)
    └── UnifiedScanEngine.scan(target, ...)

The ``CanonicalExecutor`` subprocess path is preserved as a
``mode="subprocess"`` option for sandboxed/isolated execution
(e.g. when called from a Docker worker that needs process isolation).

Usage
-----
  from oneinfinity.core.scan_orchestrator import ScanOrchestrator

  # Inline (fast, shares memory with caller process):
  result = ScanOrchestrator().run(target, scan_config={...})

  # Subprocess (isolated, safe for Docker/worker callers):
  result = ScanOrchestrator(mode="subprocess").run(target)

  # Async (returns immediately, caller polls):
  session = ScanOrchestrator().run_async(target, on_progress=cb)

Both paths return a ``ScanResult`` dataclass with a consistent
interface regardless of execution mode.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("oneinfinity.scan_orchestrator")


# ---------------------------------------------------------------------------
# Unified result model
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """
    Canonical scan result returned by all execution paths.
    Identical structure whether scan ran inline or via subprocess.
    """
    scan_id:        str
    target:         str
    status:         str               # running | completed | failed | stopped
    findings:       List[dict] = field(default_factory=list)
    findings_count: int = 0
    phases:         Dict[str, dict] = field(default_factory=dict)
    error:          str = ""
    start_time:     float = 0.0
    end_time:       float = 0.0
    target_type:    str = "web"
    scan_config:    Dict[str, Any] = field(default_factory=dict)

    @property
    def elapsed_s(self) -> float:
        if self.end_time and self.start_time:
            return round(self.end_time - self.start_time, 1)
        return round(time.time() - self.start_time, 1)

    def to_dict(self) -> dict:
        return {
            "scan_id":        self.scan_id,
            "target":         self.target,
            "status":         self.status,
            "findings_count": self.findings_count or len(self.findings),
            "phases":         self.phases,
            "error":          self.error,
            "start_time":     self.start_time,
            "end_time":       self.end_time,
            "elapsed_s":      self.elapsed_s,
            "target_type":    self.target_type,
        }


# ---------------------------------------------------------------------------
# ScanOrchestrator — canonical facade
# ---------------------------------------------------------------------------

class ScanOrchestrator:
    """
    Single canonical scan execution facade.

    All scan entry points (CLI, API, Worker, God Mode) MUST go through here.
    Internally delegates to UnifiedScanEngine for in-process execution or
    CanonicalExecutor for subprocess-isolated execution.
    """

    def __init__(
        self,
        mode: str = "inline",       # "inline" | "subprocess"
        output_dir: str = "",
    ):
        """
        Args:
            mode:       "inline"     — run inside caller's process (fast, default)
                        "subprocess" — run as isolated subprocess (safe for workers)
            output_dir: base output directory (auto-resolved if empty)
        """
        if mode not in ("inline", "subprocess"):
            raise ValueError(f"mode must be 'inline' or 'subprocess', got {mode!r}")
        self._mode = mode
        self._output_dir = output_dir

    # ── Public API ────────────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        scan_config: Optional[dict] = None,
        scan_id: Optional[str] = None,
        on_progress: Optional[Callable[[str, int, str], None]] = None,
        skip_phases: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Run a full scan synchronously and return ``ScanResult``.

        This is the canonical blocking entry point for CLI and Worker callers.
        For the API (which needs non-blocking behaviour), use ``run_async()``.
        """
        scan_id = scan_id or str(uuid.uuid4())
        cfg = dict(scan_config or {})
        if skip_phases:
            cfg["skip_phases"] = skip_phases

        if self._mode == "subprocess":
            return self._run_subprocess(target, scan_id, cfg, on_progress)
        else:
            return self._run_inline(target, scan_id, cfg, on_progress)

    def run_async(
        self,
        target: str,
        scan_config: Optional[dict] = None,
        scan_id: Optional[str] = None,
        on_progress: Optional[Callable[[str, int, str], None]] = None,
    ) -> "ScanSession":
        """
        Start a scan in a background thread and return the live ScanSession.
        Used by the API layer (callers poll the session for status).
        Always uses inline mode (subprocess mode cannot return a live session).
        """
        from oneinfinity.scan.unified_scan_engine import get_engine
        scan_id = scan_id or str(uuid.uuid4())
        return get_engine().scan_async(
            target=target,
            on_progress=on_progress,
        )

    def stop(self, scan_id: str) -> bool:
        """Request graceful stop for a running scan."""
        try:
            from oneinfinity.scan.unified_scan_engine import get_engine
            return get_engine().stop(scan_id)
        except Exception:
            return False

    # ── Internal execution paths ─────────────────────────────────────────────

    def _run_inline(
        self,
        target: str,
        scan_id: str,
        cfg: dict,
        on_progress: Optional[Callable],
    ) -> ScanResult:
        """
        Run via UnifiedScanEngine (in-process).
        This is the canonical runtime path for API, Worker, and God Mode.
        """
        from oneinfinity.scan.unified_scan_engine import get_engine
        try:
            session = get_engine().scan(
                target=target,
                on_progress=on_progress,
            )
            return self._session_to_result(session)
        except Exception as exc:
            log.error("ScanOrchestrator._run_inline failed: %s", exc, exc_info=True)
            return ScanResult(
                scan_id=scan_id, target=target,
                status="failed", error=str(exc),
                start_time=time.time(),
            )

    def _run_subprocess(
        self,
        target: str,
        scan_id: str,
        cfg: dict,
        on_progress: Optional[Callable],
    ) -> ScanResult:
        """
        Run via CanonicalExecutor (subprocess per phase).
        Used for process isolation in Docker worker environments.
        Falls back to inline if CanonicalExecutor is unavailable.
        """
        try:
            from oneinfinity.pipeline.executor import CanonicalExecutor, PipelineResult
            output_dir = self._output_dir or str(
                Path.home() / ".oneinfinity" / scan_id
            )
            # Pass skip_phases and auth_config from cfg if present; ignore unknown keys.
            executor = CanonicalExecutor(
                target=target,
                mode="subprocess",
                skip_phases=cfg.get("skip_phases"),
                auth_config={k: v for k, v in cfg.items()
                             if k in ("username", "password", "token", "cookie", "headers")}
                            or None,
            )
            result: PipelineResult = executor.run(target, output_dir)
            failed = result.status == "failed"
            return ScanResult(
                scan_id=scan_id,
                target=target,
                status=result.status if result.status in ("completed", "failed") else "completed",
                findings=result.findings or [],
                findings_count=len(result.findings or []),
                phases={name: {"status": ph.status, "error": ph.error}
                        for name, ph in result.phases.items()},
                error=result.error or "",
                start_time=result.started_at or time.time(),
                end_time=result.ended_at or time.time(),
            )
        except ImportError:
            log.warning("CanonicalExecutor unavailable — falling back to inline mode")
            return self._run_inline(target, scan_id, cfg, on_progress)
        except Exception as exc:
            log.error("ScanOrchestrator._run_subprocess failed: %s", exc)
            return self._run_inline(target, scan_id, cfg, on_progress)

    @staticmethod
    def _session_to_result(session) -> "ScanResult":
        """Convert UnifiedScanEngine ScanSession → ScanResult."""
        phases = {}
        for name, pr in (session.phases or {}).items():
            phases[name] = {
                "status": pr.status if hasattr(pr, 'status') else str(pr),
                "error":  pr.error  if hasattr(pr, 'error')  else "",
                "duration_s": round(
                    (pr.ended_at - pr.started_at)
                    if (hasattr(pr, 'ended_at') and pr.ended_at and
                        hasattr(pr, 'started_at') and pr.started_at)
                    else 0.0, 2
                ),
                "meta": {
                    k: v for k, v in (getattr(pr, "meta", None) or {}).items()
                    if k in ("reactive_executions", "reactive", "replans",
                             "reactive_drain_actions", "ingested")
                },
            }
        return ScanResult(
            scan_id=session.scan_id,
            target=session.target,
            status=session.status,
            findings=list(session.findings or []),
            findings_count=len(session.findings or []),
            phases=phases,
            error=session.error or "",
            start_time=session.start_time,
            end_time=session.end_time or time.time(),
            target_type=session.target_type or "web",
            scan_config=session.scan_config or {},
        )


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_orchestrator: Optional[ScanOrchestrator] = None


def get_orchestrator(mode: str = "inline") -> ScanOrchestrator:
    """Return (or create) the default ScanOrchestrator singleton."""
    global _default_orchestrator
    if _default_orchestrator is None or _default_orchestrator._mode != mode:
        _default_orchestrator = ScanOrchestrator(mode=mode)
    return _default_orchestrator


def run_scan(
    target: str,
    scan_config: Optional[dict] = None,
    scan_id: Optional[str] = None,
    mode: str = "inline",
    on_progress: Optional[Callable[[str, int, str], None]] = None,
    skip_phases: Optional[List[str]] = None,
) -> ScanResult:
    """
    One-call convenience function.  All callers can use this instead of
    instantiating ScanOrchestrator directly.

    Example (CLI)::
        from oneinfinity.core.scan_orchestrator import run_scan
        result = run_scan("example.com", mode="inline")

    Example (Worker)::
        from oneinfinity.core.scan_orchestrator import run_scan
        result = run_scan(target, mode="subprocess")
    """
    return ScanOrchestrator(mode=mode).run(
        target=target,
        scan_config=scan_config,
        scan_id=scan_id,
        on_progress=on_progress,
        skip_phases=skip_phases,
    )
