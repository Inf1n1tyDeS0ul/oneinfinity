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
    # ── Req 2: Validation pipeline ─────────────────────────────────────────────

    def validate_findings(self, raw_findings: list) -> list:
        """
        HTTP-probe each finding via FindingValidationEngine, then dedup.
        Returns validated + deduped list. Non-fatal: on any error, returns raw_findings.

        If all findings time out (target unreachable), passes all through with dedup only.
        """
        cfg = self._get_cfg()
        if not self._enabled() or not cfg.get("validation_pipeline", True):
            return raw_findings
        if not raw_findings:
            return []
        try:
            from finding_validation_engine import FindingValidationEngine
            from core.deduplicator import Deduplicator

            engine = FindingValidationEngine(timeout=15, max_retries=2)
            dedup = Deduplicator()
            kept = []
            timeout_count = 0

            for f in raw_findings:
                if not isinstance(f, dict):
                    # Convert dataclass / object to dict
                    f = f.__dict__ if hasattr(f, "__dict__") else {}
                result = engine.validate(f)
                if result.error and ("timed out" in result.error.lower() or
                                     "urlopen error" in result.error.lower()):
                    timeout_count += 1
                    kept.append(f)   # pass through on network error
                    continue
                if result.validated and result.confidence >= 0.5:
                    kept.append(f)
                else:
                    log.info(
                        "Enforcement: dropped finding url=%s vuln_type=%s "
                        "(validated=%s confidence=%.2f reason=%s)",
                        f.get("url", "?"), f.get("vuln_type", "?"),
                        result.validated, result.confidence, result.error or "low_confidence",
                    )

            if timeout_count == len(raw_findings) and raw_findings:
                log.warning(
                    "Enforcement: target unreachable — all %d finding(s) timed out, "
                    "passing through with dedup only", len(raw_findings)
                )

            validated = dedup.filter_new(kept)
            log.info(
                "Enforcement: %d/%d finding(s) passed validation (dedup removed %d)",
                len(validated), len(raw_findings), len(kept) - len(validated),
            )
            return validated

        except Exception as exc:
            log.warning("Enforcement validation skipped: %s", exc)
            return raw_findings
    # ── Req 1: Capmap coverage enforcement ────────────────────────────────────

    def check_capmap_coverage(self, scan_id: str, findings: list) -> CoverageReport:
        """
        Compare vuln types found in findings against all canonical Vuln classes.
        If capmap_enforcement=true, trigger one available tool per uncovered class.
        """
        cfg = self._get_cfg()
        if not self._enabled():
            return CoverageReport(covered=set(), uncovered=set(), triggered=[])
        try:
            from modules.capability_map import CapabilityMap, Vuln
            from modules.tool_wrappers import is_available

            # All canonical vuln class strings from the Vuln constants
            all_vuln_classes = {
                v for k, v in vars(Vuln).items()
                if not k.startswith("_") and isinstance(v, str)
            }

            # Normalize vuln types found in findings to lowercase
            found_types = set()
            for f in findings:
                if isinstance(f, dict):
                    vt = f.get("vuln_type", f.get("type", "")).lower().strip()
                else:
                    vt = getattr(f, "vuln_type", "").lower().strip()
                if vt:
                    found_types.add(vt)

            # Match: a canonical class is "covered" if any found_type is a substring
            # of the canonical name (case-insensitive) or vice versa
            covered: set = set()
            uncovered: set = set()
            for vuln_class in all_vuln_classes:
                vc_lower = vuln_class.lower()
                if any(ft in vc_lower or vc_lower in ft for ft in found_types):
                    covered.add(vuln_class)
                else:
                    uncovered.add(vuln_class)

            triggered = []
            if cfg.get("capmap_enforcement", True) and uncovered:
                for vuln_class in sorted(uncovered):
                    tools = CapabilityMap.tools_for_vuln(vuln_class)  # [(name, confidence)]
                    for tool_name, _conf in tools:
                        if is_available(tool_name):
                            triggered.append(tool_name)
                            log.info(
                                "Capmap: triggering '%s' for uncovered class '%s'",
                                tool_name, vuln_class,
                            )
                            break  # one tool per uncovered class is enough

            if uncovered:
                log.warning(
                    "Capmap: %d vuln class(es) not covered in scan %s: %s%s",
                    len(uncovered), scan_id,
                    ", ".join(sorted(uncovered)[:5]),
                    " ..." if len(uncovered) > 5 else "",
                )

            return CoverageReport(covered=covered, uncovered=uncovered, triggered=triggered)

        except Exception as exc:
            log.warning("Capmap coverage check skipped: %s", exc)
            return CoverageReport(covered=set(), uncovered=set(), triggered=[])
    # ── Req 3: Recursive scanning ──────────────────────────────────────────────

    def start_recursive_watch(self, scan_id: str, target: str = "") -> None:
        """
        Subscribe to event_bus NEW_ENDPOINT, NEW_API, NEW_VULNERABILITY events.
        Handlers dispatch tool runs in background threads (never blocks the bus loop).
        Respects max_recursion_depth and max_recursive_items caps from config.
        """
        cfg = self._get_cfg()
        if not self._enabled():
            return
        max_depth = int(cfg.get("max_recursion_depth", 2))
        max_items = int(cfg.get("max_recursive_items", 100))

        state = RecursionState(
            scan_id=scan_id, max_depth=max_depth, max_items=max_items
        )
        with self._lock:
            self._recursion_states[scan_id] = state

        try:
            from event_bus import get_bus, EventType
            bus = get_bus()

            def _on_new_endpoint(event):
                with self._lock:
                    s = self._recursion_states.get(scan_id)
                    if not s or s.depth >= s.max_depth or s.item_count >= s.max_items:
                        return
                    s.item_count += 1
                    current_depth = s.depth + 1
                    s.depth = current_depth
                url = event.data.get("url", "")
                if not url:
                    return
                log.info(
                    "Recursive: NEW_ENDPOINT %s — fuzz+vuln-scan (depth=%d, items=%d/%d)",
                    url, current_depth, state.item_count, state.max_items,
                )
                def _run_fuzz():
                    try:
                        from modules.tool_wrappers import run_ffuf, run_nuclei, is_available
                        if is_available("ffuf"):
                            run_ffuf(url, timeout=60)
                        if is_available("nuclei"):
                            run_nuclei(url, timeout=60)
                    except Exception as exc:
                        log.warning("Recursive fuzz+scan failed for %s: %s", url, exc)
                threading.Thread(target=_run_fuzz, daemon=True).start()

            def _on_new_api(event):
                with self._lock:
                    s = self._recursion_states.get(scan_id)
                    if not s or s.item_count >= s.max_items:
                        return
                    s.item_count += 1
                url = event.data.get("url", "")
                if not url:
                    return
                log.info(
                    "Recursive: NEW_API %s — IDOR+privilege tests (items=%d/%d)",
                    url, state.item_count, state.max_items,
                )
                def _run_idor():
                    try:
                        from modules.tool_wrappers import run_nuclei, is_available
                        if is_available("nuclei"):
                            run_nuclei(url, templates="idor,auth-bypass", timeout=60)
                    except Exception as exc:
                        log.warning("Recursive IDOR test failed for %s: %s", url, exc)
                threading.Thread(target=_run_idor, daemon=True).start()

            def _on_new_vulnerability(event):
                finding = event.data or {}
                log.info(
                    "Recursive: NEW_VULNERABILITY vuln_type=%s — attack-graph + chains",
                    finding.get("vuln_type", "?"),
                )
                def _run_graph():
                    try:
                        from attack_graph_brain import get_brain
                        get_brain().integrate_vuln(finding)
                    except Exception as exc:
                        log.warning("Recursive graph update failed: %s", exc)
                threading.Thread(target=_run_graph, daemon=True).start()

            bus.on(EventType.NEW_ENDPOINT, _on_new_endpoint)
            bus.on(EventType.NEW_API, _on_new_api)
            bus.on(EventType.NEW_VULNERABILITY, _on_new_vulnerability)

            state._handlers = [
                (EventType.NEW_ENDPOINT, _on_new_endpoint),
                (EventType.NEW_API, _on_new_api),
                (EventType.NEW_VULNERABILITY, _on_new_vulnerability),
            ]
            log.info(
                "Recursive watch started: scan_id=%s max_depth=%d max_items=%d",
                scan_id, max_depth, max_items,
            )
        except Exception as exc:
            log.warning("Recursive watch setup failed (non-fatal): %s", exc)

    def stop_recursive_watch(self, scan_id: str) -> None:
        """Unregister event handlers and clean up state for this scan_id."""
        with self._lock:
            state = self._recursion_states.pop(scan_id, None)
        if not state:
            return
        try:
            from event_bus import get_bus
            bus = get_bus()
            for event_type, handler in state._handlers:
                bus.off(event_type, handler)
            log.info(
                "Recursive watch stopped: scan_id=%s (processed %d item(s))",
                scan_id, state.item_count,
            )
        except Exception as exc:
            log.warning("Recursive watch teardown failed: %s", exc)

    # ── Req 5: Ingestion audit for doctor ─────────────────────────────────────

    def audit_ingestion_compliance(self) -> list:
        """
        Return list of cmd_* function names in oneinfinity.py that produce findings
        but do not call get_ingestion_engine().

        Uses regex-based per-function body inspection (no AST needed).
        Returns [] on any parse error (non-fatal).
        """
        cfg = self._get_cfg()
        if not self._enabled() or not cfg.get("ingestion_audit", True):
            return []

        # Commands known to produce findings — manually maintained.
        # Add new commands here when they start producing scan output.
        MUST_COMPLY = {
            "cmd_full_scan",
            "cmd_agents",
            "cmd_swarm_scan",
            "cmd_swarm",
            "cmd_simulate_attacks",
            "cmd_research",
            "cmd_ai_redteam",
            "cmd_ai_agent_test",
        }

        try:
            import os
            import re
            # enforcement_controller.py lives next to oneinfinity.py
            base = os.path.dirname(os.path.abspath(__file__))
            main_path = os.path.join(base, "oneinfinity.py")
            if not os.path.exists(main_path):
                log.warning("Ingestion audit: oneinfinity.py not found at %s", main_path)
                return []

            src = open(main_path, encoding="utf-8").read()

            # Split source into per-function blocks by top-level `def` statements
            func_pattern = re.compile(r"^def (\w+)\(", re.MULTILINE)
            matches = list(func_pattern.finditer(src))

            non_compliant = []
            for i, m in enumerate(matches):
                fname = m.group(1)
                if fname not in MUST_COMPLY:
                    continue
                start = m.start()
                end = matches[i + 1].start() if i + 1 < len(matches) else len(src)
                body = src[start:end]
                if "get_ingestion_engine" not in body:
                    non_compliant.append(fname)

            return non_compliant

        except Exception as exc:
            log.warning("Ingestion audit failed (non-fatal): %s", exc)
            return []


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
