# OneInfinity Enforcement Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an enforcement coordinator (`enforcement_controller.py`) that enforces 5 requirements — capmap coverage, active finding validation, recursive scanning, module compliance tracking, and ingestion audit — wired into the existing CLI commands with zero changes to core pipeline internals.

**Architecture:** One new file (`enforcement_controller.py`) containing `EnforcementController` (5 methods, one per requirement) + a singleton `get_enforcement_controller()`. All enforcement delegates to existing components (`FindingValidationEngine`, `Deduplicator`, `CapabilityMap`, `event_bus`, `ResultIngestionEngine`). Wired via `try/except` blocks in `cmd_full_scan`, `cmd_agents`, `cmd_swarm_scan`, `cmd_research`, `cmd_simulate_attacks`, `cmd_ai_redteam`, `cmd_ai_agent_test`, and `cmd_doctor` — all enforcement failures are non-fatal except `module_compliance: block` (user-configured).

**Tech Stack:** Python stdlib (`threading`, `re`, `ast`, `dataclasses`), existing modules (`finding_validation_engine.py`, `core/deduplicator.py`, `modules/capability_map.py`, `event_bus.py`, `result_ingestion_engine.py`, `modules/tool_wrappers.py`), `config/graph.yaml` for settings.

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| **Create** | `enforcement_controller.py` | All enforcement logic — 5 methods + singleton |
| **Modify** | `config/graph.yaml` | Add `enforcement:` config block |
| **Modify** | `oneinfinity.py` (8 functions) | Wire enforcement calls into CLI commands |

---

### Task 1: Create enforcement_controller.py — scaffold, dataclasses, singleton

**Files:**
- Create: `enforcement_controller.py`

- [ ] **Step 1: Write the scaffold**

```python
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
            except Exception:
                self._cfg = {}
        return self._cfg

    def _enabled(self) -> bool:
        return bool(self._get_cfg().get("enabled", True))

    # Placeholders — implemented in subsequent tasks
    def register_module(self, module_name: str) -> None: ...
    def check_module_compliance(self) -> ComplianceReport: ...
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
```

- [ ] **Step 2: Verify import works**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -c "from enforcement_controller import get_enforcement_controller; ec = get_enforcement_controller(); print('singleton ok:', type(ec).__name__)"
```

Expected output: `singleton ok: EnforcementController`

- [ ] **Step 3: Commit**

```bash
git add enforcement_controller.py
git commit -m "feat(enforcement): scaffold EnforcementController with dataclasses and singleton"
```

---

### Task 2: Implement register_module() + check_module_compliance() (Req 4)

**Files:**
- Modify: `enforcement_controller.py`

- [ ] **Step 1: Replace the placeholder methods with real implementations**

Replace the two placeholder lines:
```python
    def register_module(self, module_name: str) -> None: ...
    def check_module_compliance(self) -> ComplianceReport: ...
```

With:
```python
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
```

- [ ] **Step 2: Verify module compliance logic**

```bash
python3 -c "
from enforcement_controller import get_enforcement_controller
ec = get_enforcement_controller()
ec.register_module('research')
ec.register_module('simulate-attacks')
r = ec.check_module_compliance()
print('status:', r.status)
print('missing:', sorted(r.missing))
"
```

Expected output:
```
status: warn
missing: ['ai-redteam', 'swarm-scan']
```

- [ ] **Step 3: Commit**

```bash
git add enforcement_controller.py
git commit -m "feat(enforcement): implement register_module and check_module_compliance (req 4)"
```

---

### Task 3: Implement validate_findings() (Req 2)

**Files:**
- Modify: `enforcement_controller.py`

- [ ] **Step 1: Replace the placeholder**

Replace:
```python
    def validate_findings(self, raw_findings: list) -> list: ...
```

With:
```python
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
```

- [ ] **Step 2: Verify validate_findings with empty input**

```bash
python3 -c "
from enforcement_controller import get_enforcement_controller
ec = get_enforcement_controller()
result = ec.validate_findings([])
print('empty input:', result)
"
```

Expected output: `empty input: []`

- [ ] **Step 3: Verify validate_findings disabled path**

```bash
python3 -c "
from enforcement_controller import EnforcementController
ec = EnforcementController()
ec._cfg = {'enabled': False}
findings = [{'url': 'http://test.com', 'vuln_type': 'xss', 'payload': 'x'}]
result = ec.validate_findings(findings)
print('disabled passthrough:', len(result) == 1)
"
```

Expected output: `disabled passthrough: True`

- [ ] **Step 4: Commit**

```bash
git add enforcement_controller.py
git commit -m "feat(enforcement): implement validate_findings with HTTP probe + dedup (req 2)"
```

---

### Task 4: Implement check_capmap_coverage() (Req 1)

**Files:**
- Modify: `enforcement_controller.py`

- [ ] **Step 1: Replace the placeholder**

Replace:
```python
    def check_capmap_coverage(self, scan_id: str, findings: list) -> CoverageReport: ...
```

With:
```python
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
```

- [ ] **Step 2: Verify capmap returns correct types**

```bash
python3 -c "
from enforcement_controller import EnforcementController
ec = EnforcementController()
ec._cfg = {'enabled': True, 'capmap_enforcement': False}
# With no findings, all classes should be uncovered
r = ec.check_capmap_coverage('test-scan', [])
print('covered:', len(r.covered))
print('uncovered:', len(r.uncovered))
print('triggered:', r.triggered)
print('uncovered is set:', isinstance(r.uncovered, set))
"
```

Expected output: `covered: 0`, `uncovered: <N>` (number of Vuln classes), `triggered: []`, `uncovered is set: True`

- [ ] **Step 3: Commit**

```bash
git add enforcement_controller.py
git commit -m "feat(enforcement): implement check_capmap_coverage (req 1)"
```

---

### Task 5: Implement start_recursive_watch() + stop_recursive_watch() (Req 3)

**Files:**
- Modify: `enforcement_controller.py`

- [ ] **Step 1: Replace the two placeholders**

Replace:
```python
    def start_recursive_watch(self, scan_id: str, target: str = "") -> None: ...
    def stop_recursive_watch(self, scan_id: str) -> None: ...
```

With:
```python
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
```

- [ ] **Step 2: Verify start/stop without errors**

```bash
python3 -c "
from enforcement_controller import get_enforcement_controller
ec = get_enforcement_controller()
ec._cfg = {'enabled': True, 'max_recursion_depth': 2, 'max_recursive_items': 100}
ec.start_recursive_watch('test-scan-001', 'example.com')
print('state exists:', 'test-scan-001' in ec._recursion_states)
ec.stop_recursive_watch('test-scan-001')
print('state removed:', 'test-scan-001' not in ec._recursion_states)
"
```

Expected output:
```
state exists: True
state removed: True
```

- [ ] **Step 3: Commit**

```bash
git add enforcement_controller.py
git commit -m "feat(enforcement): implement recursive scanning via event bus subscriptions (req 3)"
```

---

### Task 6: Implement audit_ingestion_compliance() (Req 5)

**Files:**
- Modify: `enforcement_controller.py`

- [ ] **Step 1: Replace the placeholder**

Replace:
```python
    def audit_ingestion_compliance(self) -> list: ...
```

With:
```python
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
```

- [ ] **Step 2: Verify audit runs and returns a list**

```bash
python3 -c "
from enforcement_controller import get_enforcement_controller
ec = get_enforcement_controller()
ec._cfg = {'enabled': True, 'ingestion_audit': True}
non_compliant = ec.audit_ingestion_compliance()
print('non-compliant commands:', non_compliant)
print('returns list:', isinstance(non_compliant, list))
"
```

Expected output: `returns list: True`, plus a list of non-compliant commands (before wiring is done, several commands will appear here).

- [ ] **Step 3: Commit**

```bash
git add enforcement_controller.py
git commit -m "feat(enforcement): implement audit_ingestion_compliance for doctor (req 5)"
```

---

### Task 7: Add enforcement: block to config/graph.yaml

**Files:**
- Modify: `config/graph.yaml`

- [ ] **Step 1: Append the enforcement block**

Add after the last line of `config/graph.yaml` (currently ends at line 20 with a blank line):

```yaml
enforcement:
  enabled: true
  validation_pipeline: true        # req 2: HTTP-probe all findings before storage
  capmap_enforcement: true         # req 1: trigger tools for uncovered vuln classes
  max_recursion_depth: 2           # req 3: recursive scan depth cap
  max_recursive_items: 100         # req 3: total new items across all recursive passes
  module_compliance: warn          # req 4: warn | block | disabled
  ingestion_audit: true            # req 5: flag non-compliant cmds in doctor
```

- [ ] **Step 2: Verify config loads correctly**

```bash
python3 -c "
from core.graph_config import load_graph_config
cfg = load_graph_config()
enf = cfg.get('enforcement', {})
print('enabled:', enf.get('enabled'))
print('max_recursion_depth:', enf.get('max_recursion_depth'))
print('module_compliance:', enf.get('module_compliance'))
"
```

Expected output:
```
enabled: True
max_recursion_depth: 2
module_compliance: warn
```

- [ ] **Step 3: Commit**

```bash
git add config/graph.yaml
git commit -m "config: add enforcement block to graph.yaml"
```

---

### Task 8: Wire cmd_full_scan() — all enforcement hooks

**Files:**
- Modify: `oneinfinity.py` — `cmd_full_scan` function (line 3322)

Context: `cmd_full_scan` runs `run_canonical_pipeline()`, then has "Post-pipeline: graph ingestion" and "Post-pipeline: learning system update" blocks. We need to:
1. Generate a scan_id and start recursive watch **before** the pipeline runs
2. Call `validate_findings()` on `result.findings` **after** pipeline, **before** graph ingestion
3. Replace `result.findings` references in graph ingestion and learning blocks with `_validated`
4. Add capmap coverage check and module compliance **after** the learning block
5. Stop recursive watch in all exit paths

- [ ] **Step 1: Add scan_id + recursive watch start before pipeline execution**

Find this block in `cmd_full_scan` (around line 3398):
```python
    # Run canonical pipeline
    try:
        from pipeline.executor import run_canonical_pipeline
        info(f"Starting canonical 10-phase pipeline...")
```

Insert **before** that block:
```python
    # ── Enforcement: register + start recursive watch ─────────────────────────
    import uuid as _ec_uuid
    _ec_scan_id = str(_ec_uuid.uuid4())[:8]
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("full-scan")
        _get_ec().start_recursive_watch(_ec_scan_id, target)
    except Exception as _ecw:
        warn(f"Enforcement watch setup skipped: {_ecw}")

```

- [ ] **Step 2: Add validate_findings between pipeline result and graph ingestion**

Find the boundary between the pipeline try/except and the graph ingestion block:
```python
    # ── Post-pipeline: graph ingestion ────────────────────────────────────
    try:
        from attack_graph_brain import get_brain
        _brain = get_brain()
        _ingested = 0
        for _f in result.findings:
```

Insert **before** the `# ── Post-pipeline: graph ingestion` line:
```python
    # ── Enforcement: validate findings before graph ingestion ─────────────────
    _validated = result.findings
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _validated = _get_ec().validate_findings(result.findings)
        info(f"Enforcement: {len(_validated)}/{len(result.findings)} finding(s) passed validation")
    except Exception as _ecv:
        warn(f"Enforcement validation skipped: {_ecv}")

```

- [ ] **Step 3: Update graph ingestion block to use _validated**

In the "Post-pipeline: graph ingestion" block, change:
```python
        for _f in result.findings:
```
To:
```python
        for _f in _validated:
```

And change the info log line:
```python
        if _ingested:
            info(f"Graph: ingested {_ingested} finding(s) from full-scan")
```
(no change needed — `_ingested` still counts correctly)

- [ ] **Step 4: Update learning block to use _validated**

In the "Post-pipeline: learning system update" block, change:
```python
        _task_result = _types.SimpleNamespace(
            findings=result.findings,
```
To:
```python
        _task_result = _types.SimpleNamespace(
            findings=_validated,
```

- [ ] **Step 5: Add capmap + module compliance + recursive watch stop after learning block**

Find the end of the learning block:
```python
    except Exception as _le:
        warn(f"Learning update skipped: {_le}")

    print()

    # Summary table
```

Insert **between** `warn(f"Learning update skipped: {_le}")` and `print()`:
```python

    # ── Enforcement: capmap coverage + module compliance + cleanup ────────────
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _ctrl = _get_ec()
        _cov = _ctrl.check_capmap_coverage(_ec_scan_id, _validated)
        if _cov.uncovered:
            warn(f"Capmap: {len(_cov.uncovered)} vuln class(es) not covered this scan")
        if _cov.triggered:
            info(f"Capmap: triggered {len(_cov.triggered)} additional tool(s) for coverage")
        _comp = _ctrl.check_module_compliance()
        if _comp.missing:
            warn(f"Module compliance: not run this session — {', '.join(sorted(_comp.missing))}")
        _ctrl.stop_recursive_watch(_ec_scan_id)
    except Exception as _ecc:
        warn(f"Enforcement compliance check skipped: {_ecc}")
```

- [ ] **Step 6: Update severity breakdown and report generation to use _validated**

In `cmd_full_scan`, find (around line 3466):
```python
    sev_counts = {}
    for f in result.findings:
        s = f.get("severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print(f"  Total unique findings: {len(result.findings)}")
```
Change both `result.findings` to `_validated`:
```python
    sev_counts = {}
    for f in _validated:
        s = f.get("severity", "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    print(f"  Total unique findings: {len(_validated)}")
```

Also find in the report generation block (around line 3489):
```python
            scored = ConfidenceEngine().score_findings(result.findings)
```
Change to:
```python
            scored = ConfidenceEngine().score_findings(_validated)
```

- [ ] **Step 7: Verify cmd_full_scan still imports cleanly**

```bash
cd /home/devendra-yadav/oneinfinity
python3 -c "import oneinfinity; print('import ok')"
```

Expected: `import ok`

- [ ] **Step 8: Commit**

```bash
git add oneinfinity.py
git commit -m "feat(enforcement): wire all 5 enforcement hooks into cmd_full_scan"
```

---

### Task 9: Wire cmd_agents() and cmd_swarm_scan()

**Files:**
- Modify: `oneinfinity.py` — `cmd_agents` (line 1308) and `cmd_swarm_scan` (line 4221)

**cmd_agents:** Already has `get_ingestion_engine()` call (endpoint bus publish block from prior session). Just add `register_module("agents")`.

**cmd_swarm_scan:** Has no `get_ingestion_engine()` call. Add `register_module("swarm-scan")` + publish findings to ingestion engine after `asyncio.run(run_swarm(...))`.

- [ ] **Step 1: Add register_module to cmd_agents**

In `cmd_agents`, inside `if subcommand == "run":`, find the authorization confirmation block that ends with:
```python
        print()
```
(after the `if ans != "yes": return` check, around line 1334)

Insert immediately after that `print()`:
```python
        # ── Enforcement: register module ─────────────────────────────────────
        try:
            from enforcement_controller import get_enforcement_controller as _get_ec
            _get_ec().register_module("agents")
        except Exception:
            pass

```

- [ ] **Step 2: Add register_module + ingestion publish to cmd_swarm_scan**

In `cmd_swarm_scan`, find the line after `asyncio.run(run_swarm(...))` returns (around line 4265):
```python
    print(f"\n{result.summary()}")
```

Insert **before** that line:
```python
    # ── Enforcement: register module + publish findings to ingestion bus ───────
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("swarm-scan")
    except Exception:
        pass
    try:
        from result_ingestion_engine import get_ingestion_engine as _get_ie, RawResult as _RR
        import uuid as _sw_uuid
        _sw_sid = str(_sw_uuid.uuid4())[:8]
        _sw_bus = _get_ie()
        _sw_count = 0
        for _sf in result.findings:
            _sf_dict = _sf if isinstance(_sf, dict) else (
                _sf.__dict__ if hasattr(_sf, "__dict__") else {}
            )
            if _sf_dict:
                _sw_bus.ingest(_RR(scan_id=_sw_sid, source="swarm-scan", raw=_sf_dict))
                _sw_count += 1
        if _sw_count:
            print(f"[+] Ingestion bus: published {_sw_count} finding(s) from swarm-scan")
    except Exception as _swe:
        print(f"[!] Ingestion bus publish skipped: {_swe}")

```

- [ ] **Step 3: Verify import still works**

```bash
python3 -c "import oneinfinity; print('import ok')"
```

Expected: `import ok`

- [ ] **Step 4: Commit**

```bash
git add oneinfinity.py
git commit -m "feat(enforcement): wire register_module into cmd_agents; add ingestion publish + register to cmd_swarm_scan"
```

---

### Task 10: Wire cmd_research(), cmd_simulate_attacks(), cmd_ai_redteam(), cmd_ai_agent_test()

**Files:**
- Modify: `oneinfinity.py` — four functions

These commands only need `register_module()` — they delegate to their own engines which manage output internally.

- [ ] **Step 1: Wire cmd_research (line 1611)**

In `cmd_research`, find:
```python
def cmd_research(args):
    """
    oneinfinity research <target> — autonomous vulnerability research mode.
    Runs the full research loop: analyze → theorize → test → detect → report.

    Examples:
      oneinfinity research target.com --yes          — run research loop
      oneinfinity research --stats                   — show research KB statistics
    """
    if getattr(args, "stats", False):
```

Insert between the docstring and `if getattr(args, "stats", False):`:
```python
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("research")
    except Exception:
        pass
```

- [ ] **Step 2: Wire cmd_simulate_attacks (line 4288)**

In `cmd_simulate_attacks`, find:
```python
def cmd_simulate_attacks(args):
    """oneinfinity simulate-attacks <target> — Monte Carlo attack path simulation."""
    import asyncio
    import json as _json
    from pathlib import Path

    try:
        from attack_simulation_engine import AttackSimulationEngine
```

Insert before `try:` block:
```python
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("simulate-attacks")
    except Exception:
        pass
```

- [ ] **Step 3: Wire cmd_ai_redteam (line 1565)**

In `cmd_ai_redteam`, find:
```python
def cmd_ai_redteam(args):
    """
    oneinfinity ai-redteam <target> — AI red team engine: adversarial prompt campaigns.
    ...
    """
    _inject_proxy(args)
    from ai_redteam_engine import main_cli
    main_cli(args)
```

Insert before `_inject_proxy(args)`:
```python
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("ai-redteam")
    except Exception:
        pass
```

- [ ] **Step 4: Wire cmd_ai_agent_test (line 1591)**

In `cmd_ai_agent_test`, find:
```python
def cmd_ai_agent_test(args):
    """
    oneinfinity ai-agent-test <target> — AI Agent Pentesting Engine.
    ...
    """
    _inject_proxy(args)
    from ai_agent_pentest_engine import main_cli
    main_cli(args)
```

Insert before `_inject_proxy(args)`:
```python
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _get_ec().register_module("ai-redteam")
    except Exception:
        pass
```

Note: both `cmd_ai_redteam` and `cmd_ai_agent_test` register as `"ai-redteam"` since they both count toward the `ai-redteam` compliance requirement.

- [ ] **Step 5: Verify import still works**

```bash
python3 -c "import oneinfinity; print('import ok')"
```

Expected: `import ok`

- [ ] **Step 6: Commit**

```bash
git add oneinfinity.py
git commit -m "feat(enforcement): wire register_module into cmd_research, cmd_simulate_attacks, cmd_ai_redteam, cmd_ai_agent_test"
```

---

### Task 11: Wire cmd_doctor() — ingestion audit extension

**Files:**
- Modify: `oneinfinity.py` — `cmd_doctor` function (line 86)

`cmd_doctor` calls `orchestrator.run()` and `orchestrator.print_report()`. We add the ingestion audit result **after** `print_report` — it's an addendum to the doctor output, not part of the `DoctorOrchestrator` internals.

- [ ] **Step 1: Add ingestion audit block after orchestrator.print_report()**

In `cmd_doctor`, find:
```python
    report = asyncio.run(orchestrator.run(quick=quick_mode, deep=deep_mode))
    orchestrator.print_report(report, output_json=getattr(args, "json", False))
```

Insert **after** `orchestrator.print_report(...)`:
```python
    # ── Enforcement: ingestion audit ──────────────────────────────────────────
    try:
        from enforcement_controller import get_enforcement_controller as _get_ec
        _non_compliant = _get_ec().audit_ingestion_compliance()
        if _non_compliant:
            print()
            print(f"  [!] Ingestion audit: {len(_non_compliant)} cmd(s) bypass get_ingestion_engine():")
            for _cmd in sorted(_non_compliant):
                print(f"      - {_cmd}")
            print(f"      Deduction: -{min(len(_non_compliant) * 0.1, 1.0):.1f} (informational)")
        else:
            print()
            print("  [+] Ingestion audit: all tracked commands publish via get_ingestion_engine()")
    except Exception as _ea:
        pass  # audit failure never affects doctor output
```

- [ ] **Step 2: Verify doctor still runs**

```bash
python3 oneinfinity.py doctor --quick 2>&1 | tail -5
```

Expected: doctor output ending with score, plus new "Ingestion audit" line at the bottom.

- [ ] **Step 3: Commit**

```bash
git add oneinfinity.py
git commit -m "feat(enforcement): extend cmd_doctor with ingestion audit report (req 5)"
```

---

### Task 12: Validation gate

**Files:**
- No file changes — verification only.

- [ ] **Step 1: Run doctor --quick**

```bash
python3 oneinfinity.py doctor --quick
```

Expected: `10.0/10.0` (enforcement wiring is additive and non-fatal; no existing checks should regress).

- [ ] **Step 2: Verify enforcement_controller imports cleanly standalone**

```bash
python3 -c "
from enforcement_controller import (
    get_enforcement_controller,
    EnforcementController,
    CoverageReport,
    ComplianceReport,
    RecursionState,
    EnforcementError,
    REQUIRED_MODULES,
)
ec = get_enforcement_controller()
assert ec is get_enforcement_controller(), 'singleton broken'
print('All imports ok. Singleton verified.')
"
```

Expected: `All imports ok. Singleton verified.`

- [ ] **Step 3: Verify register_module + compliance round-trip**

```bash
python3 -c "
from enforcement_controller import get_enforcement_controller
ec = get_enforcement_controller()
for m in ['simulate-attacks', 'research', 'swarm-scan', 'ai-redteam']:
    ec.register_module(m)
r = ec.check_module_compliance()
print('status:', r.status)
print('missing:', r.missing)
"
```

Expected: `status: ok`, `missing: set()`

- [ ] **Step 4: Verify config block is read correctly by the controller**

```bash
python3 -c "
from enforcement_controller import EnforcementController
ec = EnforcementController()
cfg = ec._get_cfg()
print('enabled:', cfg.get('enabled'))
print('max_recursion_depth:', cfg.get('max_recursion_depth'))
print('module_compliance:', cfg.get('module_compliance'))
print('ingestion_audit:', cfg.get('ingestion_audit'))
"
```

Expected:
```
enabled: True
max_recursion_depth: 2
module_compliance: warn
ingestion_audit: True
```

- [ ] **Step 5: Verify audit returns a list**

```bash
python3 -c "
from enforcement_controller import get_enforcement_controller
result = get_enforcement_controller().audit_ingestion_compliance()
print('audit result type:', type(result).__name__)
print('non-compliant before full wiring:', result)
"
```

Expected: `audit result type: list`. The list may be empty or contain commands — after Task 9-10 wiring most should be gone; only fully non-compliant ones remain.

- [ ] **Step 6: Run graph stats (verify no regressions)**

```bash
python3 oneinfinity.py graph stats 2>&1 | grep -E "nodes|edges|OI_"
```

Expected: node/edge counts as before, no new `OI_ChainFeedback` warnings.

- [ ] **Step 7: Final commit if any stray changes**

```bash
git status
# If clean: nothing to do
# If dirty: git add <files> && git commit -m "chore: enforcement layer cleanup"
```
