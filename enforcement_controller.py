"""
enforcement_controller.py — Enforcement layer for OneInfinity.

Enforces 5 requirements:
  1. Capmap-driven execution   — trigger tools for uncovered vuln classes
  2. Validation pipeline       — HTTP-probe every finding before storage
  3. Recursive scanning        — new endpoints/APIs/vulns trigger re-scan via event bus
  4. Module compliance         — track which required modules ran per session
  5. Ingestion audit           — flag cmd_* functions that bypass get_ingestion_engine()
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("oneinfinity.enforcement")


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class RecursionState:
    scan_id: str
    depth: int = 0
    item_count: int = 0
    max_depth: int = 2
    max_items: int = 100
    _handlers: list = field(default_factory=list)  # [(EventType, handler)] for cleanup


@dataclass
class CoverageReport:
    covered: set
    uncovered: set
    triggered: list  # tool names triggered for uncovered classes


@dataclass
class ComplianceReport:
    status: str    # "ok" | "warn" | "block" | "disabled"
    missing: set


class EnforcementError(Exception):
    """Raised when module_compliance=block and required modules are missing."""
    pass


# ── Required modules for compliance tracking ───────────────────────────────────

REQUIRED_MODULES = {"simulate-attacks", "research", "swarm-scan", "ai-redteam"}


# ── Controller ─────────────────────────────────────────────────────────────────

class EnforcementController:
    """
    Central enforcement coordinator. All methods are non-fatal by default.
    Instantiate once via get_enforcement_controller() (singleton).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._modules_run: set = set()
        self._recursion_states: dict = {}   # scan_id → RecursionState
        self._cfg: Optional[dict] = None

    # ── Config ─────────────────────────────────────────────────────────────────

    def _get_cfg(self) -> dict:
        if self._cfg is None:
            try:
                from core.graph_config import load_graph_config
                self._cfg = load_graph_config().get("enforcement") or {}
            except Exception as exc:
                log.warning("Failed to load enforcement config: %s", exc)
                self._cfg = {}
        return self._cfg

    def _enabled(self) -> bool:
        return bool(self._get_cfg().get("enabled", True))

    # ── Req 4: Module compliance tracking ─────────────────────────────────────

    def register_module(self, module_name: str) -> None:
        """Call at the entry point of each required cmd_* function."""
        with self._lock:
            self._modules_run.add(module_name)
        log.debug("Enforcement: registered module '%s'", module_name)

    def check_module_compliance(self) -> ComplianceReport:
        """
        Compare _modules_run against REQUIRED_MODULES.
        mode=warn  → log warning, return report
        mode=block → raise EnforcementError
        mode=disabled → return ok immediately
        """
        cfg = self._get_cfg()
        mode = cfg.get("module_compliance", "warn")
        if mode == "disabled" or not self._enabled():
            return ComplianceReport(status="disabled", missing=set())
        with self._lock:
            missing = REQUIRED_MODULES - self._modules_run
        if not missing:
            return ComplianceReport(status="ok", missing=set())
        if mode == "warn":
            log.warning(
                "Enforcement: required modules not run this session: %s",
                ", ".join(sorted(missing)),
            )
        elif mode == "block":
            raise EnforcementError(
                f"Required modules skipped — run these before completing: {sorted(missing)}"
            )
        return ComplianceReport(status=mode, missing=missing)
    def validate_findings(self, raw_findings: list) -> list: ...
    def check_capmap_coverage(self, scan_id: str, findings: list) -> CoverageReport: ...
    def start_recursive_watch(self, scan_id: str, target: str = "") -> None: ...
    def stop_recursive_watch(self, scan_id: str) -> None: ...
    def audit_ingestion_compliance(self) -> list: ...


# ── Singleton ──────────────────────────────────────────────────────────────────

_singleton: Optional[EnforcementController] = None
_singleton_lock = threading.Lock()


def get_enforcement_controller() -> EnforcementController:
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = EnforcementController()
    return _singleton
