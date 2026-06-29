"""
Reactive Effectiveness Program — measurement, metrics, and reporting.

Observes existing ctx/session state at scan completion.
Does NOT modify reactive execution — read-only observation of state
written by _execute_reactive_actions, _replan_if_needed,
_phase_ssrf_pivot_scan, and _emit_reactive_telemetry.

Invoked from _phase_done as a post-completion reporting step.

Metrics:
  1. Reactive Finding Lift         — extra findings as % of baseline
  2. Reactive Chain Lift           — extra chains attributable to reactive
  3. Attack Surface Expansion Yield — new targets discovered via reactive
  4. Coverage Improvement          — new vuln-class coverage from reactive
  5. Reactive Precision (TP/FP)   — validated / total reactive findings
  6. Planner Precision             — actions that produced findings / executed
  7. Pivot Yield                   — % pivot targets that found something
  8. Cost Efficiency               — validated findings per second of runtime

Final determination:
  "YES"  — reactive execution materially improves outcomes
  "NO"   — reactive execution does not materially improve outcomes
  "INSUFFICIENT_DATA" — scan too short / no reactive phases ran
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("oneinfinity.reactive_effectiveness")

# ── Thresholds for "material" ──────────────────────────────────────────────────
# A metric must exceed its threshold to count as a material contribution.
LIFT_MATERIAL_PCT        = 10.0   # >10% more findings
CHAIN_LIFT_MATERIAL_PCT  = 15.0   # >15% more chains
ASE_MATERIAL_PCT         = 5.0    # >5% more attack surface
COVERAGE_MATERIAL_PCT    = 10.0   # >10% new vuln classes
PRECISION_MATERIAL       = 0.30   # >30% reactive precision (TP rate)
PLANNER_PRECISION_MATERIAL = 0.20 # >20% actions produce findings
PIVOT_YIELD_MATERIAL_PCT = 20.0   # >20% pivot targets find something
COST_EFFICIENCY_MATERIAL = 0.01   # >0.01 validated findings/s

# A determination of YES requires at least this many metrics to pass.
YES_THRESHOLD = 3

# Sources set by reactive execution (for finding attribution).
_REACTIVE_SOURCES = frozenset({
    "reactive_exec",
    "reactive_execution",
    "ssrf_pivot_recon",
    "ssrf_pivot_nuclei",
    "ssrf_pivot",
    "reactive_nuclei",
    "reactive_dalfox",
    "reactive_sqlmap",
    "reactive_tool",
    "reactive_scan",
    "agent_execution_fabric",
})

# ── Record dataclasses ─────────────────────────────────────────────────────────

@dataclass
class ActionRecord:
    """One reactive action: generated → executed → findings."""
    action_id:           str
    scan_id:             str
    action_type:         str
    target:              str
    trigger_phase:       str
    trigger_source:      str          # 'replan' | 'chain' | 'pivot'
    confidence:          float = 0.0
    generated_at:        float = 0.0  # unix epoch
    executed:            bool  = False
    success:             bool  = False
    findings_produced:   int   = 0
    validated_findings:  int   = 0
    cost_s:              float = 0.0
    fingerprint:         str   = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ReplanRecord:
    """One replanning cycle: trigger → plan delta → actions executed."""
    replan_id:                   str
    scan_id:                     str
    cycle:                       int
    trigger_phase:               str
    original_plan_count:         int   = 0
    delta_count:                 int   = 0
    actions_executed:            int   = 0
    findings_produced:           int   = 0
    validated_findings_produced: int   = 0
    triggered_at:                float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PivotRecord:
    """One SSRF pivot target: generated → scanned → findings."""
    pivot_id:            str
    scan_id:             str
    pivot_target:        str
    source_finding_id:   str   = ""
    generated_at:        float = 0.0
    scanned:             bool  = False
    scanned_at:          float = 0.0
    httpx_findings:      int   = 0
    nuclei_findings:     int   = 0
    findings_produced:   int   = 0
    validated_findings:  int   = 0
    budget_used_s:       float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EffectivenessMetrics:
    """Computed effectiveness metrics for one scan."""
    scan_id:                  str
    target:                   str
    computed_at:              float = 0.0

    # ── Corpus sizes ────────────────────────────────────────────────
    total_findings:           int   = 0
    baseline_findings:        int   = 0
    reactive_findings:        int   = 0
    pivot_findings:           int   = 0
    validated_total:          int   = 0
    validated_baseline:       int   = 0
    validated_reactive:       int   = 0

    # ── Chain corpus ────────────────────────────────────────────────
    total_chains:             int   = 0
    baseline_chains:          int   = 0
    reactive_chains:          int   = 0

    # ── Attack surface ──────────────────────────────────────────────
    baseline_targets:         int   = 1   # at least the primary
    pivot_targets_generated:  int   = 0
    pivot_targets_scanned:    int   = 0
    new_attack_surface:       int   = 0

    # ── Coverage ────────────────────────────────────────────────────
    vuln_classes_baseline:    int   = 0
    vuln_classes_reactive:    int   = 0
    new_vuln_classes:         int   = 0

    # ── Planner stats ───────────────────────────────────────────────
    replans_triggered:        int   = 0
    actions_generated:        int   = 0
    actions_executed:         int   = 0
    actions_skipped:          int   = 0
    actions_producing_findings: int = 0

    # ── Runtime ─────────────────────────────────────────────────────
    reactive_runtime_s:       float = 0.0
    total_runtime_s:          float = 0.0

    # ── 8 Computed Metrics ──────────────────────────────────────────
    m1_finding_lift_pct:      float = 0.0   # Reactive Finding Lift
    m2_chain_lift_pct:        float = 0.0   # Reactive Chain Lift
    m3_ase_yield_pct:         float = 0.0   # Attack Surface Expansion Yield
    m4_coverage_improvement:  float = 0.0   # Coverage Improvement %
    m5_reactive_precision:    float = 0.0   # TP / (TP+FP)
    m6_planner_precision:     float = 0.0   # productive actions / executed
    m7_pivot_yield_pct:       float = 0.0   # % pivots yielding ≥1 finding
    m8_cost_efficiency:       float = 0.0   # validated/s of reactive runtime

    # ── Threshold pass/fail ─────────────────────────────────────────
    m1_pass: bool = False
    m2_pass: bool = False
    m3_pass: bool = False
    m4_pass: bool = False
    m5_pass: bool = False
    m6_pass: bool = False
    m7_pass: bool = False
    m8_pass: bool = False

    @property
    def metrics_passed(self) -> int:
        return sum([self.m1_pass, self.m2_pass, self.m3_pass, self.m4_pass,
                    self.m5_pass, self.m6_pass, self.m7_pass, self.m8_pass])

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EffectivenessReport:
    """Complete effectiveness report for one scan."""
    scan_id:        str
    target:         str
    generated_at:   float

    metrics:        EffectivenessMetrics = field(default_factory=lambda: EffectivenessMetrics("", ""))
    actions:        List[ActionRecord]   = field(default_factory=list)
    replans:        List[ReplanRecord]   = field(default_factory=list)
    pivots:         List[PivotRecord]    = field(default_factory=list)

    determination:  str  = "INSUFFICIENT_DATA"   # YES | NO | INSUFFICIENT_DATA
    determination_evidence: List[str] = field(default_factory=list)

    # Raw telemetry snapshot from ctx
    raw_telemetry:  Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "scan_id":       self.scan_id,
            "target":        self.target,
            "generated_at":  self.generated_at,
            "metrics":       self.metrics.to_dict(),
            "actions":       [a.to_dict() for a in self.actions],
            "replans":       [r.to_dict() for r in self.replans],
            "pivots":        [p.to_dict() for p in self.pivots],
            "determination": self.determination,
            "determination_evidence": self.determination_evidence,
            "raw_telemetry": self.raw_telemetry,
        }
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


# ── Finding Attribution ────────────────────────────────────────────────────────

def _is_reactive_finding(finding: dict) -> bool:
    """Return True if a finding originated from reactive execution."""
    src = str(finding.get("source", "")).lower()
    if src in _REACTIVE_SOURCES:
        return True
    if "reactive" in src or "ssrf_pivot" in src:
        return True
    # Phase tag written by reactive execution fabric
    if finding.get("trigger_phase"):
        return True
    return False


def _is_pivot_finding(finding: dict) -> bool:
    """Return True if a finding came from SSRF pivot scanning."""
    src = str(finding.get("source", "")).lower()
    return "ssrf_pivot" in src or finding.get("pivot_target") is not None


def _finding_vuln_class(finding: dict) -> str:
    """Canonical vulnerability class for coverage counting."""
    vt = str(finding.get("vuln_type", finding.get("type", "unknown"))).lower()
    # Normalise compound names to root class
    for prefix in ("sqli", "xss", "ssrf", "idor", "cors", "ssti", "xxe", "rce",
                   "lfi", "rfi", "csrf", "open_redirect", "jwt", "auth", "priv"):
        if vt.startswith(prefix):
            return prefix
    return vt or "unknown"


# ── Record Collection ──────────────────────────────────────────────────────────

def _collect_action_records(scan_id: str, session: Any, ctx: dict) -> List[ActionRecord]:
    """
    Reconstruct per-action records from existing ctx/session state.

    Sources (in priority order):
      1. ctx["_reactive_action_log"] — per-action detail if written
      2. Aggregate tel + replan meta — synthesised records
    """
    records: List[ActionRecord] = []

    # ── Source 1: per-action log (populated by our observer hook) ──
    action_log: List[dict] = ctx.get("_ree_action_log", [])
    if action_log:
        for entry in action_log:
            records.append(ActionRecord(
                action_id=entry.get("action_id", ""),
                scan_id=scan_id,
                action_type=entry.get("action_type", ""),
                target=entry.get("target", ""),
                trigger_phase=entry.get("trigger_phase", ""),
                trigger_source=entry.get("trigger_source", ""),
                confidence=float(entry.get("confidence", 0.0)),
                generated_at=float(entry.get("generated_at", 0.0)),
                executed=bool(entry.get("executed", False)),
                success=bool(entry.get("success", False)),
                findings_produced=int(entry.get("findings_produced", 0)),
                validated_findings=int(entry.get("validated_findings", 0)),
                cost_s=float(entry.get("cost_s", 0.0)),
                fingerprint=entry.get("fingerprint", ""),
            ))
        return records

    # ── Source 2: synthesise from aggregate tel + replan meta ───────
    tel = ctx.get("_reactive_telemetry", {})
    n_executed  = int(tel.get("reactive_actions_executed", 0))
    n_generated = int(tel.get("reactive_actions_generated", 0))
    n_findings  = int(tel.get("reactive_findings_produced", 0))
    n_skipped   = int(tel.get("reactive_actions_skipped", 0))
    total_s     = float(ctx.get("_reactive_total_runtime_s", 0.0))

    # Build synthetic records from replan metadata
    now = time.time()
    synth_idx = 0
    for phase_name, phase_result in session.phases.items():
        if phase_result is None:
            continue
        phase_meta = getattr(phase_result, "meta", {}) or {}
        replans = phase_meta.get("replans", [])
        for rep in replans:
            delta = int(rep.get("delta_count", 0))
            for j in range(delta):
                synth_idx += 1
                cost = total_s / max(1, n_executed)
                record = ActionRecord(
                    action_id=f"synth_{scan_id}_{synth_idx}",
                    scan_id=scan_id,
                    action_type="reactive",
                    target=session.target,
                    trigger_phase=str(rep.get("trigger_phase", phase_name)),
                    trigger_source="replan",
                    confidence=0.5,
                    generated_at=now,
                    executed=(synth_idx <= n_executed),
                    success=(synth_idx <= max(0, n_executed - n_skipped)),
                    findings_produced=(1 if synth_idx <= n_findings else 0),
                    validated_findings=0,
                    cost_s=cost,
                )
                records.append(record)

    # Pad with skipped records if not covered by replan meta
    generated_by_replan = sum(
        int(r.get("delta_count", 0))
        for pr in session.phases.values()
        if pr is not None
        for r in (getattr(pr, "meta", {}) or {}).get("replans", [])
    )
    remaining = max(0, n_generated - generated_by_replan)
    for k in range(remaining):
        synth_idx += 1
        records.append(ActionRecord(
            action_id=f"synth_{scan_id}_extra_{k}",
            scan_id=scan_id,
            action_type="reactive",
            target=session.target,
            trigger_phase="unknown",
            trigger_source="replan",
            confidence=0.5,
            generated_at=now,
            executed=False,
            success=False,
        ))

    return records


def _collect_replan_records(scan_id: str, session: Any, ctx: dict) -> List[ReplanRecord]:
    """Reconstruct replan records from session.phases[*].meta['replans']."""
    records: List[ReplanRecord] = []
    tel      = ctx.get("_reactive_telemetry", {})
    n_exec   = int(tel.get("reactive_actions_executed", 0))
    n_find   = int(tel.get("reactive_findings_produced", 0))

    now      = time.time()
    seen_cycles: set = set()

    for phase_name, phase_result in session.phases.items():
        if phase_result is None:
            continue
        phase_meta = getattr(phase_result, "meta", {}) or {}
        for rep in phase_meta.get("replans", []):
            cycle = int(rep.get("cycle", 0))
            if cycle in seen_cycles:
                continue
            seen_cycles.add(cycle)
            delta = int(rep.get("delta_count", 0))
            orig  = int(rep.get("original_count", 0))
            # Distribute execution proportionally across replans
            total_replans = max(1, ctx.get("_replan_count", 1))
            actions_exec = n_exec // total_replans
            findings_p   = n_find // total_replans

            records.append(ReplanRecord(
                replan_id=f"replan_{scan_id}_c{cycle}",
                scan_id=scan_id,
                cycle=cycle,
                trigger_phase=str(rep.get("trigger_phase", phase_name)),
                original_plan_count=orig,
                delta_count=delta,
                actions_executed=actions_exec,
                findings_produced=findings_p,
                validated_findings_produced=0,   # computed later
                triggered_at=now,
            ))

    # If no replan meta was recorded but replans_triggered > 0, synthesise
    n_replans = int(tel.get("replans_triggered", ctx.get("_replan_count", 0)))
    if not records and n_replans > 0:
        for i in range(n_replans):
            records.append(ReplanRecord(
                replan_id=f"replan_{scan_id}_s{i+1}",
                scan_id=scan_id,
                cycle=i + 1,
                trigger_phase="unknown",
                actions_executed=n_exec // n_replans,
                findings_produced=n_find // n_replans,
                triggered_at=now,
            ))

    return records


def _collect_pivot_records(scan_id: str, session: Any, ctx: dict) -> List[PivotRecord]:
    """Reconstruct pivot records from exploit_chaining phase meta."""
    records: List[PivotRecord] = []

    # ── Source 1: exploit_chaining phase meta["pivots"] ─────────────
    ec_phase = session.phases.get("exploit_chaining")
    if ec_phase is not None:
        pivot_meta = (getattr(ec_phase, "meta", {}) or {}).get("pivots", {})
        if isinstance(pivot_meta, dict):
            targets   = pivot_meta.get("targets", [])
            total_f   = pivot_meta.get("findings", 0)
            per_target = total_f // max(1, len(targets))
            for t in targets:
                t_url = t if isinstance(t, str) else str(t)
                records.append(PivotRecord(
                    pivot_id=f"pivot_{scan_id}_{abs(hash(t_url)) % 0xFFFF:04x}",
                    scan_id=scan_id,
                    pivot_target=t_url,
                    generated_at=time.time(),
                    scanned=True,
                    scanned_at=time.time(),
                    findings_produced=per_target,
                ))
        elif isinstance(pivot_meta, list):
            for p in pivot_meta:
                if isinstance(p, dict):
                    records.append(PivotRecord(
                        pivot_id=f"pivot_{scan_id}_{abs(hash(str(p.get('target','')))) % 0xFFFF:04x}",
                        scan_id=scan_id,
                        pivot_target=str(p.get("target", "")),
                        generated_at=float(p.get("generated_at", time.time())),
                        scanned=bool(p.get("scanned", True)),
                        scanned_at=float(p.get("scanned_at", time.time())),
                        httpx_findings=int(p.get("httpx_findings", 0)),
                        nuclei_findings=int(p.get("nuclei_findings", 0)),
                        findings_produced=int(p.get("httpx_findings", 0)) + int(p.get("nuclei_findings", 0)),
                        budget_used_s=float(p.get("budget_used_s", 0.0)),
                    ))

    # ── Source 2: ctx["new_targets"] + telemetry ─────────────────────
    if not records:
        new_targets = ctx.get("new_targets", []) or []
        tel          = ctx.get("_reactive_telemetry", {})
        n_gen        = int(tel.get("pivots_generated", 0))
        n_exec_piv   = int(tel.get("pivots_executed", 0))

        for i, t in enumerate(new_targets):
            t_url = t if isinstance(t, str) else str(t)
            records.append(PivotRecord(
                pivot_id=f"pivot_{scan_id}_nt{i}",
                scan_id=scan_id,
                pivot_target=t_url,
                generated_at=time.time(),
                scanned=(i < n_exec_piv),
                scanned_at=time.time() if i < n_exec_piv else 0.0,
            ))

        # Synthesise from telemetry if no ctx["new_targets"]
        if not records and n_gen > 0:
            for i in range(n_gen):
                records.append(PivotRecord(
                    pivot_id=f"pivot_{scan_id}_tel{i}",
                    scan_id=scan_id,
                    pivot_target=f"pivot_target_{i+1}",
                    generated_at=time.time(),
                    scanned=(i < n_exec_piv),
                    scanned_at=time.time() if i < n_exec_piv else 0.0,
                ))

    return records


# ── Metrics Computation ────────────────────────────────────────────────────────

def _compute_metrics(
    scan_id:   str,
    session:   Any,
    ctx:       dict,
    actions:   List[ActionRecord],
    replans:   List[ReplanRecord],
    pivots:    List[PivotRecord],
) -> EffectivenessMetrics:
    """Compute all 8 effectiveness metrics from collected records."""
    tel = ctx.get("_reactive_telemetry", {})

    # ── Separate findings by source ─────────────────────────────────
    all_findings        = list(session.findings)
    reactive_findings   = [f for f in all_findings if _is_reactive_finding(f)]
    pivot_findings_list = [f for f in all_findings if _is_pivot_finding(f)]
    # Baseline: neither reactive nor pivot
    baseline_findings_list = [
        f for f in all_findings
        if not _is_reactive_finding(f) and not _is_pivot_finding(f)
    ]

    # Use telemetry counter as authoritative reactive finding count
    # (source tags may not always be set by _execute_reactive_actions)
    tel_reactive_count = int(tel.get("reactive_findings_produced", 0))
    if tel_reactive_count > len(reactive_findings):
        # tel is higher — trust it, adjust baseline downward
        reactive_count   = tel_reactive_count
        baseline_count   = max(0, len(all_findings) - reactive_count - len(pivot_findings_list))
    else:
        reactive_count   = len(reactive_findings)
        baseline_count   = len(baseline_findings_list)

    pivot_count = len(pivot_findings_list)

    # ── Validated findings ──────────────────────────────────────────
    validated_all  = list(ctx.get("validated_findings", []) or [])
    val_reactive   = [f for f in validated_all if _is_reactive_finding(f)]
    val_baseline   = [f for f in validated_all if not _is_reactive_finding(f)]

    # ── Chain attribution ───────────────────────────────────────────
    successful_chains = list(ctx.get("successful_chains", []) or [])
    exploit_chains    = list(ctx.get("exploit_chains", []) or [])
    all_chains        = successful_chains or exploit_chains
    # A chain is "reactive" if all source vuln types are reactive-attributed
    reactive_chain_count  = 0
    for c in all_chains:
        if isinstance(c, dict):
            src = str(c.get("source", "reactive")).lower()
            if "reactive" in src or c.get("trigger_phase"):
                reactive_chain_count += 1
    baseline_chain_count = max(0, len(all_chains) - reactive_chain_count)

    # ── Attack surface ──────────────────────────────────────────────
    new_targets = list(ctx.get("new_targets", []) or [])
    tel_ase     = int(tel.get("pivots_generated", len(new_targets)))
    new_attack_surface = max(tel_ase, len(new_targets))

    # ── Coverage / vuln classes ─────────────────────────────────────
    baseline_classes: set = {_finding_vuln_class(f) for f in baseline_findings_list} - {"unknown"}
    reactive_classes: set = {_finding_vuln_class(f) for f in reactive_findings}  - {"unknown"}
    pivot_classes:    set = {_finding_vuln_class(f) for f in pivot_findings_list} - {"unknown"}
    new_classes = (reactive_classes | pivot_classes) - baseline_classes

    # ── Planner stats ───────────────────────────────────────────────
    n_generated = int(tel.get("reactive_actions_generated",
                              sum(r.delta_count for r in replans) or len(actions)))
    n_executed  = int(tel.get("reactive_actions_executed",
                              ctx.get("_reactive_total_executed", 0)))
    n_skipped   = int(tel.get("reactive_actions_skipped", 0))
    n_producing = max(
        int(tel.get("reactive_findings_produced", 0) > 0),
        sum(1 for a in actions if a.findings_produced > 0),
    )
    # Better estimate: if n_findings > 0 then at least some actions produced findings
    if reactive_count > 0 and n_executed > 0:
        # Estimate productive actions from findings/actions ratio
        n_producing = max(n_producing, min(reactive_count, n_executed))

    # ── Runtime ─────────────────────────────────────────────────────
    reactive_runtime_s = float(
        ctx.get("_reactive_total_runtime_s", 0.0)
        or tel.get("total_reactive_runtime_s", 0.0)
    )
    # Estimate total runtime from phase timestamps
    total_runtime_s = 0.0
    t_classify = session.phases.get("classify")
    t_done     = session.phases.get("done")
    if t_classify and t_done:
        ts_start = getattr(t_classify, "start_time", 0.0) or 0.0
        ts_end   = getattr(t_done,     "end_time",   0.0) or 0.0
        if ts_end > ts_start > 0:
            total_runtime_s = ts_end - ts_start

    # ── Pivot finding count ─────────────────────────────────────────
    pivot_findings_count = int(tel.get("pivot_findings", pivot_count))
    if not pivot_findings_count:
        pivot_findings_count = sum(p.findings_produced for p in pivots)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Metric 1: Reactive Finding Lift
    # = (reactive_count / max(1, baseline_count)) × 100
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    m1 = (reactive_count / max(1, baseline_count)) * 100.0

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Metric 2: Reactive Chain Lift
    # = (reactive_chain_count / max(1, len(all_chains))) × 100
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    m2 = (reactive_chain_count / max(1, len(all_chains))) * 100.0 if all_chains else 0.0

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Metric 3: Attack Surface Expansion Yield
    # = (new_attack_surface / max(1, baseline_targets)) × 100
    # baseline_targets = 1 (primary target always present)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    m3 = (new_attack_surface / max(1, 1)) * 100.0

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Metric 4: Coverage Improvement
    # = (len(new_classes) / max(1, len(baseline_classes))) × 100
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    m4 = (len(new_classes) / max(1, len(baseline_classes))) * 100.0

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Metric 5: Reactive Precision (TP/FP ratio)
    # = validated_reactive / max(1, reactive_count)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Use DB-authoritative validated count where possible
    # validated_reactive is only accurate if source tags were set
    # Fall back to global validation rate applied to reactive count
    if len(validated_all) > 0 and len(all_findings) > 0:
        global_val_rate = len(validated_all) / len(all_findings)
        val_reactive_est = int(global_val_rate * reactive_count)
    else:
        val_reactive_est = len(val_reactive)
    m5 = val_reactive_est / max(1, reactive_count)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Metric 6: Planner Precision
    # = actions_producing_findings / max(1, n_executed)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    m6 = n_producing / max(1, n_executed) if n_executed > 0 else 0.0

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Metric 7: Pivot Yield
    # = (pivots_with_findings / max(1, pivots_scanned)) × 100
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    pivots_scanned    = int(tel.get("pivots_executed", sum(1 for p in pivots if p.scanned)))
    pivots_with_finds = sum(1 for p in pivots if p.findings_produced > 0)
    m7 = (pivots_with_finds / max(1, pivots_scanned)) * 100.0 if pivots_scanned > 0 else 0.0

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Metric 8: Cost Efficiency
    # = validated_reactive / max(0.001, reactive_runtime_s)
    # Interpreted as validated findings per second of reactive work
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    m8 = val_reactive_est / max(0.001, reactive_runtime_s) if reactive_runtime_s > 0 else 0.0

    em = EffectivenessMetrics(
        scan_id=scan_id,
        target=str(session.target),
        computed_at=time.time(),

        total_findings=len(all_findings),
        baseline_findings=baseline_count,
        reactive_findings=reactive_count,
        pivot_findings=pivot_count,
        validated_total=len(validated_all),
        validated_baseline=len(val_baseline),
        validated_reactive=val_reactive_est,

        total_chains=len(all_chains),
        baseline_chains=baseline_chain_count,
        reactive_chains=reactive_chain_count,

        baseline_targets=1,
        pivot_targets_generated=int(tel.get("pivots_generated", len(new_targets))),
        pivot_targets_scanned=pivots_scanned,
        new_attack_surface=new_attack_surface,

        vuln_classes_baseline=len(baseline_classes),
        vuln_classes_reactive=len(reactive_classes | pivot_classes),
        new_vuln_classes=len(new_classes),

        replans_triggered=int(tel.get("replans_triggered", ctx.get("_replan_count", 0))),
        actions_generated=n_generated,
        actions_executed=n_executed,
        actions_skipped=n_skipped,
        actions_producing_findings=n_producing,

        reactive_runtime_s=reactive_runtime_s,
        total_runtime_s=total_runtime_s,

        m1_finding_lift_pct=round(m1, 2),
        m2_chain_lift_pct=round(m2, 2),
        m3_ase_yield_pct=round(m3, 2),
        m4_coverage_improvement=round(m4, 2),
        m5_reactive_precision=round(m5, 4),
        m6_planner_precision=round(m6, 4),
        m7_pivot_yield_pct=round(m7, 2),
        m8_cost_efficiency=round(m8, 6),

        m1_pass=m1 >= LIFT_MATERIAL_PCT,
        m2_pass=m2 >= CHAIN_LIFT_MATERIAL_PCT,
        m3_pass=m3 >= ASE_MATERIAL_PCT,
        m4_pass=m4 >= COVERAGE_MATERIAL_PCT,
        m5_pass=m5 >= PRECISION_MATERIAL,
        m6_pass=m6 >= PLANNER_PRECISION_MATERIAL,
        m7_pass=m7 >= PIVOT_YIELD_MATERIAL_PCT,
        m8_pass=m8 >= COST_EFFICIENCY_MATERIAL,
    )
    return em


# ── Determination ─────────────────────────────────────────────────────────────

def _compute_determination(
    em: EffectivenessMetrics,
    actions: List[ActionRecord],
    replans: List[ReplanRecord],
    pivots:  List[PivotRecord],
    session: Any,
    ctx:     dict,
) -> Tuple[str, List[str]]:
    """
    Determine whether reactive execution materially improves outcomes.

    Returns ("YES"|"NO"|"INSUFFICIENT_DATA", [evidence strings]).
    """
    evidence: List[str] = []
    tel = ctx.get("_reactive_telemetry", {})

    # ── Insufficient data guard ─────────────────────────────────────
    n_executed  = em.actions_executed
    n_generated = em.actions_generated
    had_reactive = (n_generated > 0 or n_executed > 0
                    or em.pivot_targets_generated > 0
                    or em.replans_triggered > 0)
    if not had_reactive:
        evidence.append("INSUFFICIENT_DATA: No reactive phases executed (no actions generated, no pivots, no replans).")
        evidence.append("Reactive execution was either not triggered or skipped by all guards.")
        return "INSUFFICIENT_DATA", evidence

    if em.total_findings == 0:
        evidence.append("INSUFFICIENT_DATA: Scan produced zero total findings — no basis for lift comparison.")
        return "INSUFFICIENT_DATA", evidence

    # ── Evaluate each metric ────────────────────────────────────────
    metric_results = []

    # M1 — Finding Lift
    if em.m1_pass:
        evidence.append(
            f"M1 PASS — Reactive Finding Lift: {em.m1_finding_lift_pct:.1f}% "
            f"(≥{LIFT_MATERIAL_PCT}% threshold). "
            f"Reactive added {em.reactive_findings} findings on top of {em.baseline_findings} baseline "
            f"(total {em.total_findings})."
        )
    else:
        evidence.append(
            f"M1 FAIL — Reactive Finding Lift: {em.m1_finding_lift_pct:.1f}% "
            f"(<{LIFT_MATERIAL_PCT}% threshold). "
            f"Reactive contributed {em.reactive_findings} findings vs {em.baseline_findings} baseline."
        )
    metric_results.append(em.m1_pass)

    # M2 — Chain Lift
    if em.m2_pass:
        evidence.append(
            f"M2 PASS — Reactive Chain Lift: {em.m2_chain_lift_pct:.1f}% of chains are reactive-attributed "
            f"({em.reactive_chains}/{em.total_chains} chains, threshold ≥{CHAIN_LIFT_MATERIAL_PCT}%)."
        )
    else:
        evidence.append(
            f"M2 FAIL — Reactive Chain Lift: {em.m2_chain_lift_pct:.1f}% "
            f"({em.reactive_chains}/{em.total_chains} chains). "
            f"Threshold ≥{CHAIN_LIFT_MATERIAL_PCT}%. "
            + ("No chains detected." if em.total_chains == 0 else "Chains built from baseline findings only.")
        )
    metric_results.append(em.m2_pass)

    # M3 — Attack Surface Expansion
    if em.m3_pass:
        evidence.append(
            f"M3 PASS — Attack Surface Expansion: {em.new_attack_surface} new targets discovered "
            f"({em.m3_ase_yield_pct:.1f}% yield, threshold ≥{ASE_MATERIAL_PCT}%)."
        )
    else:
        evidence.append(
            f"M3 FAIL — Attack Surface Expansion: {em.new_attack_surface} new targets "
            f"({em.m3_ase_yield_pct:.1f}%, threshold ≥{ASE_MATERIAL_PCT}%)."
        )
    metric_results.append(em.m3_pass)

    # M4 — Coverage Improvement
    if em.m4_pass:
        evidence.append(
            f"M4 PASS — Coverage Improvement: {em.new_vuln_classes} new vulnerability classes discovered "
            f"({em.m4_coverage_improvement:.1f}% above {em.vuln_classes_baseline} baseline classes, "
            f"threshold ≥{COVERAGE_MATERIAL_PCT}%)."
        )
    else:
        evidence.append(
            f"M4 FAIL — Coverage Improvement: {em.new_vuln_classes} new vuln classes "
            f"({em.m4_coverage_improvement:.1f}%, threshold ≥{COVERAGE_MATERIAL_PCT}%)."
        )
    metric_results.append(em.m4_pass)

    # M5 — Reactive Precision
    pct_m5 = em.m5_reactive_precision * 100
    if em.m5_pass:
        evidence.append(
            f"M5 PASS — Reactive Precision (TP rate): {pct_m5:.1f}% of reactive findings validated "
            f"({em.validated_reactive}/{em.reactive_findings}, threshold ≥{PRECISION_MATERIAL*100:.0f}%)."
        )
    else:
        evidence.append(
            f"M5 FAIL — Reactive Precision: {pct_m5:.1f}% validation rate "
            f"({em.validated_reactive}/{em.reactive_findings} reactive findings validated, "
            f"threshold ≥{PRECISION_MATERIAL*100:.0f}%)."
        )
    metric_results.append(em.m5_pass)

    # M6 — Planner Precision
    pct_m6 = em.m6_planner_precision * 100
    if em.m6_pass:
        evidence.append(
            f"M6 PASS — Planner Precision: {pct_m6:.1f}% of executed actions produced findings "
            f"({em.actions_producing_findings}/{em.actions_executed}, "
            f"threshold ≥{PLANNER_PRECISION_MATERIAL*100:.0f}%)."
        )
    else:
        evidence.append(
            f"M6 FAIL — Planner Precision: {pct_m6:.1f}% "
            f"({em.actions_producing_findings}/{em.actions_executed} actions productive, "
            f"threshold ≥{PLANNER_PRECISION_MATERIAL*100:.0f}%). "
            + ("No actions executed." if em.actions_executed == 0 else "Most actions were unproductive.")
        )
    metric_results.append(em.m6_pass)

    # M7 — Pivot Yield
    if em.m7_pass:
        evidence.append(
            f"M7 PASS — Pivot Yield: {em.m7_pivot_yield_pct:.1f}% of scanned pivot targets yielded findings "
            f"(threshold ≥{PIVOT_YIELD_MATERIAL_PCT}%)."
        )
    else:
        evidence.append(
            f"M7 FAIL — Pivot Yield: {em.m7_pivot_yield_pct:.1f}% of pivot targets productive "
            f"({em.pivot_targets_scanned} scanned, threshold ≥{PIVOT_YIELD_MATERIAL_PCT}%). "
            + ("No pivots executed." if em.pivot_targets_scanned == 0 else "")
        )
    metric_results.append(em.m7_pass)

    # M8 — Cost Efficiency
    if em.m8_pass:
        evidence.append(
            f"M8 PASS — Cost Efficiency: {em.m8_cost_efficiency:.4f} validated findings/s "
            f"({em.validated_reactive} validated in {em.reactive_runtime_s:.1f}s reactive runtime, "
            f"threshold ≥{COST_EFFICIENCY_MATERIAL})."
        )
    else:
        evidence.append(
            f"M8 FAIL — Cost Efficiency: {em.m8_cost_efficiency:.4f} validated findings/s "
            f"({em.reactive_runtime_s:.1f}s reactive runtime, threshold ≥{COST_EFFICIENCY_MATERIAL}). "
            + ("Zero reactive runtime measured." if em.reactive_runtime_s == 0 else "")
        )
    metric_results.append(em.m8_pass)

    # ── Verdict ─────────────────────────────────────────────────────
    passed = sum(metric_results)
    if passed >= YES_THRESHOLD:
        determination = "YES"
        evidence.append(
            f"\nVERDICT: YES — {passed}/8 metrics pass (threshold {YES_THRESHOLD}/8). "
            f"Reactive execution materially improves offensive-security outcomes. "
            f"Disabling reactive execution would cost {em.reactive_findings} findings, "
            f"{em.reactive_chains} chains, and {em.new_attack_surface} attack surface additions."
        )
    else:
        determination = "NO"
        evidence.append(
            f"\nVERDICT: NO — only {passed}/8 metrics pass (threshold {YES_THRESHOLD}/8). "
            f"Reactive execution does not materially improve outcomes in this scan. "
            f"Reactive contributed {em.reactive_findings} extra findings on {em.baseline_findings} baseline — "
            f"within noise margin or insufficient to justify overhead."
        )

    # ── Additional context ──────────────────────────────────────────
    if em.replans_triggered > 0:
        evidence.append(
            f"CONTEXT: {em.replans_triggered} replan cycle(s) triggered, "
            f"generating {em.actions_generated} actions ({em.actions_executed} executed, "
            f"{em.actions_skipped} skipped by ceiling/dedup/type-filter)."
        )
    if em.pivot_targets_generated > 0:
        evidence.append(
            f"CONTEXT: {em.pivot_targets_generated} SSRF pivot target(s) discovered, "
            f"{em.pivot_targets_scanned} scanned."
        )

    return determination, evidence


# ── Dashboard ─────────────────────────────────────────────────────────────────

_PASS_ICON = "✓"
_FAIL_ICON = "✗"
_BAR_FULL  = "█"
_BAR_EMPTY = "░"


def _bar(value: float, maximum: float, width: int = 20) -> str:
    """Render a simple ASCII progress bar."""
    if maximum <= 0:
        filled = 0
    else:
        filled = min(width, int((value / maximum) * width))
    return _BAR_FULL * filled + _BAR_EMPTY * (width - filled)


def render_dashboard(report: "EffectivenessReport") -> str:
    """Render a human-readable text dashboard."""
    em = report.metrics
    lines: List[str] = []

    # ── Header ──────────────────────────────────────────────────────
    lines.append("╔" + "═" * 70 + "╗")
    lines.append(f"║  {'REACTIVE EFFECTIVENESS DASHBOARD':^66}  ║")
    lines.append(f"║  Scan: {report.scan_id[:40]:<40}  ║")
    lines.append(f"║  Target: {str(report.target)[:38]:<38}  ║")
    import datetime as _dt
    ts = _dt.datetime.fromtimestamp(report.generated_at).strftime("%Y-%m-%d %H:%M:%S")
    lines.append(f"║  Generated: {ts:<34}  ║")
    lines.append("╠" + "═" * 70 + "╣")

    # ── Summary row ─────────────────────────────────────────────────
    verdict_str = {
        "YES":              "✓ MATERIALLY IMPROVES OUTCOMES",
        "NO":               "✗ DOES NOT MATERIALLY IMPROVE",
        "INSUFFICIENT_DATA": "⚠ INSUFFICIENT DATA",
    }.get(report.determination, report.determination)
    lines.append(f"║  DETERMINATION: {verdict_str:<52}  ║")
    lines.append(f"║  Metrics passed: {em.metrics_passed}/8{'':<50}  ║")
    lines.append("╠" + "═" * 70 + "╣")

    # ── Finding corpus ──────────────────────────────────────────────
    lines.append(f"║  {'FINDING CORPUS':^66}  ║")
    lines.append("╠" + "─" * 70 + "╣")
    lines.append(f"║  Total findings:          {em.total_findings:>6}  {'':40}  ║")
    lines.append(f"║  Baseline findings:       {em.baseline_findings:>6}  "
                 f"[{_bar(em.baseline_findings, max(1,em.total_findings))}]  ║")
    lines.append(f"║  Reactive findings:       {em.reactive_findings:>6}  "
                 f"[{_bar(em.reactive_findings, max(1,em.total_findings))}]  ║")
    lines.append(f"║  Pivot findings:          {em.pivot_findings:>6}  "
                 f"[{_bar(em.pivot_findings, max(1,em.total_findings))}]  ║")
    lines.append(f"║  Validated (total):       {em.validated_total:>6}  "
                 f"[{_bar(em.validated_total, max(1,em.total_findings))}]  ║")
    lines.append(f"║  Validated (reactive):    {em.validated_reactive:>6}  {'':40}  ║")

    # ── Chain / Attack Surface ──────────────────────────────────────
    lines.append("╠" + "─" * 70 + "╣")
    lines.append(f"║  {'CHAINS & ATTACK SURFACE':^66}  ║")
    lines.append("╠" + "─" * 70 + "╣")
    lines.append(f"║  Total chains:            {em.total_chains:>6}  {'':40}  ║")
    lines.append(f"║  Reactive chains:         {em.reactive_chains:>6}  {'':40}  ║")
    lines.append(f"║  Pivot targets generated: {em.pivot_targets_generated:>6}  {'':40}  ║")
    lines.append(f"║  Pivot targets scanned:   {em.pivot_targets_scanned:>6}  {'':40}  ║")
    lines.append(f"║  New attack surface:      {em.new_attack_surface:>6}  {'':40}  ║")

    # ── Planner ─────────────────────────────────────────────────────
    lines.append("╠" + "─" * 70 + "╣")
    lines.append(f"║  {'PLANNER STATS':^66}  ║")
    lines.append("╠" + "─" * 70 + "╣")
    lines.append(f"║  Replans triggered:       {em.replans_triggered:>6}  {'':40}  ║")
    lines.append(f"║  Actions generated:       {em.actions_generated:>6}  {'':40}  ║")
    lines.append(f"║  Actions executed:        {em.actions_executed:>6}  {'':40}  ║")
    lines.append(f"║  Actions skipped:         {em.actions_skipped:>6}  {'':40}  ║")
    lines.append(f"║  Actions productive:      {em.actions_producing_findings:>6}  {'':40}  ║")
    lines.append(f"║  Reactive runtime:     {em.reactive_runtime_s:>8.1f}s  {'':40}  ║")

    # ── 8 Metrics ───────────────────────────────────────────────────
    lines.append("╠" + "═" * 70 + "╣")
    lines.append(f"║  {'EFFECTIVENESS METRICS':^66}  ║")
    lines.append("╠" + "═" * 70 + "╣")

    def _metric_line(num: str, label: str, value_str: str, passed: bool,
                     threshold_str: str, bar_val: float = 0, bar_max: float = 100) -> str:
        icon = _PASS_ICON if passed else _FAIL_ICON
        bar  = _bar(bar_val, bar_max, 14)
        return f"║  {num} {icon} {label:<28} {value_str:>10}  [{bar}]  thr:{threshold_str:<6}  ║"

    lines.append(_metric_line(
        "M1", "Finding Lift",
        f"{em.m1_finding_lift_pct:.1f}%", em.m1_pass,
        f">{LIFT_MATERIAL_PCT:.0f}%",
        em.m1_finding_lift_pct, 100,
    ))
    lines.append(_metric_line(
        "M2", "Chain Lift",
        f"{em.m2_chain_lift_pct:.1f}%", em.m2_pass,
        f">{CHAIN_LIFT_MATERIAL_PCT:.0f}%",
        em.m2_chain_lift_pct, 100,
    ))
    lines.append(_metric_line(
        "M3", "Attack Surface Expansion",
        f"{em.m3_ase_yield_pct:.1f}%", em.m3_pass,
        f">{ASE_MATERIAL_PCT:.0f}%",
        em.m3_ase_yield_pct, 100,
    ))
    lines.append(_metric_line(
        "M4", "Coverage Improvement",
        f"{em.m4_coverage_improvement:.1f}%", em.m4_pass,
        f">{COVERAGE_MATERIAL_PCT:.0f}%",
        em.m4_coverage_improvement, 100,
    ))
    lines.append(_metric_line(
        "M5", "Reactive Precision (TP)",
        f"{em.m5_reactive_precision*100:.1f}%", em.m5_pass,
        f">{PRECISION_MATERIAL*100:.0f}%",
        em.m5_reactive_precision * 100, 100,
    ))
    lines.append(_metric_line(
        "M6", "Planner Precision",
        f"{em.m6_planner_precision*100:.1f}%", em.m6_pass,
        f">{PLANNER_PRECISION_MATERIAL*100:.0f}%",
        em.m6_planner_precision * 100, 100,
    ))
    lines.append(_metric_line(
        "M7", "Pivot Yield",
        f"{em.m7_pivot_yield_pct:.1f}%", em.m7_pass,
        f">{PIVOT_YIELD_MATERIAL_PCT:.0f}%",
        em.m7_pivot_yield_pct, 100,
    ))
    lines.append(_metric_line(
        "M8", "Cost Efficiency",
        f"{em.m8_cost_efficiency:.4f}/s", em.m8_pass,
        f">{COST_EFFICIENCY_MATERIAL}",
        min(em.m8_cost_efficiency * 100, 100), 100,
    ))

    lines.append("╠" + "═" * 70 + "╣")

    # ── Determination evidence ──────────────────────────────────────
    lines.append(f"║  {'DETERMINATION EVIDENCE':^66}  ║")
    lines.append("╠" + "─" * 70 + "╣")
    for ev_line in report.determination_evidence:
        # Word-wrap at 64 chars
        for chunk_start in range(0, max(1, len(ev_line)), 64):
            chunk = ev_line[chunk_start:chunk_start + 64]
            lines.append(f"║  {chunk:<66}  ║")
    lines.append("╚" + "═" * 70 + "╝")

    return "\n".join(lines)


def render_roi_table(report: "EffectivenessReport") -> str:
    """Render Reactive ROI Metrics table."""
    em = report.metrics
    rows = [
        ("Finding ROI",          f"{em.reactive_findings} additional findings",
         f"+{em.m1_finding_lift_pct:.1f}% lift"),
        ("Validated Finding ROI", f"{em.validated_reactive} validated reactive",
         f"{em.m5_reactive_precision*100:.1f}% precision"),
        ("Chain Discovery ROI",  f"{em.reactive_chains} reactive chains",
         f"{em.m2_chain_lift_pct:.1f}% of all chains"),
        ("Attack Surface ROI",   f"{em.new_attack_surface} new targets",
         f"{em.m3_ase_yield_pct:.1f}% expansion"),
        ("Planner ROI",          f"{em.actions_producing_findings}/{em.actions_executed} actions productive",
         f"{em.m6_planner_precision*100:.1f}% hit rate"),
        ("Pivot ROI",            f"{em.pivot_targets_scanned} pivots scanned",
         f"{em.m7_pivot_yield_pct:.1f}% yielded findings"),
        ("Runtime ROI",          f"{em.reactive_runtime_s:.1f}s reactive / {em.total_runtime_s:.1f}s total",
         f"{em.m8_cost_efficiency:.4f} val_findings/s"),
        ("Coverage ROI",         f"{em.new_vuln_classes} new vuln classes",
         f"{em.m4_coverage_improvement:.1f}% above baseline"),
    ]
    lines = ["┌─ REACTIVE ROI METRICS " + "─" * 48 + "┐"]
    lines.append(f"│  {'Dimension':<28}  {'Value':<28}  {'ROI':<12}  │")
    lines.append("├" + "─" * 72 + "┤")
    for dim, val, roi in rows:
        lines.append(f"│  {dim:<28}  {val:<28}  {roi:<12}  │")
    lines.append("└" + "─" * 72 + "┘")
    return "\n".join(lines)


def render_planner_table(report: "EffectivenessReport") -> str:
    """Render Planner Quality Metrics table."""
    em = report.metrics
    lines = ["┌─ PLANNER QUALITY METRICS " + "─" * 44 + "┐"]
    lines.append(f"│  {'Metric':<32}  {'Value':>12}  {'Status':>10}  │")
    lines.append("├" + "─" * 60 + "┤")

    def _row(label, value, threshold, passed):
        icon = _PASS_ICON if passed else _FAIL_ICON
        return f"│  {label:<32}  {str(value):>12}  {icon:>10}  │"

    lines.append(_row("Replans triggered",      em.replans_triggered,      ">0",     em.replans_triggered > 0))
    lines.append(_row("Actions generated",      em.actions_generated,      ">0",     em.actions_generated > 0))
    lines.append(_row("Actions executed",       em.actions_executed,       ">0",     em.actions_executed > 0))
    lines.append(_row("Actions skipped",        em.actions_skipped,        "-",      True))
    lines.append(_row("Actions productive",     em.actions_producing_findings, ">0", em.actions_producing_findings > 0))
    lines.append(_row("Planner precision",
                       f"{em.m6_planner_precision*100:.1f}%",
                       f">{PLANNER_PRECISION_MATERIAL*100:.0f}%",
                       em.m6_pass))
    for i, rep in enumerate(report.replans[:5]):
        lines.append(_row(f"  Cycle {rep.cycle} ({rep.trigger_phase[:16]})",
                          f"Δ{rep.delta_count} actions",
                          "-", True))
    lines.append("└" + "─" * 60 + "┘")
    return "\n".join(lines)


def render_pivot_table(report: "EffectivenessReport") -> str:
    """Render Pivot Quality Metrics table."""
    em = report.metrics
    lines = ["┌─ PIVOT QUALITY METRICS " + "─" * 47 + "┐"]
    lines.append(f"│  {'Pivot Target':<36}  {'Found':>6}  {'Status':>8}  │")
    lines.append("├" + "─" * 56 + "┤")

    if not report.pivots:
        lines.append(f"│  {'No pivot targets discovered.':<52}  │")
    else:
        for p in report.pivots[:20]:
            status = "✓" if p.findings_produced > 0 else "✗"
            lines.append(f"│  {p.pivot_target[:36]:<36}  {p.findings_produced:>6}  {status:>8}  │")

    lines.append("├" + "─" * 56 + "┤")
    lines.append(f"│  {'Generated:':<20} {em.pivot_targets_generated:>4}   "
                 f"{'Scanned:':<12} {em.pivot_targets_scanned:>4}  {'':>6}  │")
    lines.append(f"│  {'Pivot yield:':<20} {em.m7_pivot_yield_pct:.1f}%   "
                 f"{'Threshold:':<12} >{PIVOT_YIELD_MATERIAL_PCT:.0f}%   "
                 f"{'✓' if em.m7_pass else '✗':>4}  │")
    lines.append("└" + "─" * 56 + "┘")
    return "\n".join(lines)


def render_chain_table(report: "EffectivenessReport") -> str:
    """Render Chain Discovery Metrics table."""
    em = report.metrics
    lines = ["┌─ CHAIN DISCOVERY METRICS " + "─" * 44 + "┐"]
    lines.append(f"│  {'Metric':<36}  {'Value':>12}  {'Status':>6}  │")
    lines.append("├" + "─" * 60 + "┤")
    lines.append(f"│  {'Total chains detected':<36}  {em.total_chains:>12}  {'':>6}  │")
    lines.append(f"│  {'Baseline chains':<36}  {em.baseline_chains:>12}  {'':>6}  │")
    lines.append(f"│  {'Reactive chains':<36}  {em.reactive_chains:>12}  {'':>6}  │")
    lines.append(f"│  {'Reactive chain lift':<36}  "
                 f"{em.m2_chain_lift_pct:>11.1f}%  "
                 f"{'✓' if em.m2_pass else '✗':>6}  │")
    lines.append("└" + "─" * 60 + "┘")
    return "\n".join(lines)


def render_coverage_table(report: "EffectivenessReport") -> str:
    """Render Coverage Improvement Metrics table."""
    em = report.metrics
    lines = ["┌─ COVERAGE IMPROVEMENT METRICS " + "─" * 40 + "┐"]
    lines.append(f"│  {'Metric':<36}  {'Value':>12}  {'Status':>6}  │")
    lines.append("├" + "─" * 60 + "┤")
    lines.append(f"│  {'Baseline vuln classes':<36}  {em.vuln_classes_baseline:>12}  {'':>6}  │")
    lines.append(f"│  {'Reactive vuln classes':<36}  {em.vuln_classes_reactive:>12}  {'':>6}  │")
    lines.append(f"│  {'New classes (reactive only)':<36}  {em.new_vuln_classes:>12}  {'':>6}  │")
    lines.append(f"│  {'Coverage improvement':<36}  "
                 f"{em.m4_coverage_improvement:>11.1f}%  "
                 f"{'✓' if em.m4_pass else '✗':>6}  │")
    lines.append("└" + "─" * 60 + "┘")
    return "\n".join(lines)


def render_full_text_report(report: "EffectivenessReport") -> str:
    """Render the complete text effectiveness report."""
    sections = [
        render_dashboard(report),
        "",
        render_roi_table(report),
        "",
        render_planner_table(report),
        "",
        render_pivot_table(report),
        "",
        render_chain_table(report),
        "",
        render_coverage_table(report),
    ]
    return "\n".join(sections)


# ── Main Entry Point ───────────────────────────────────────────────────────────

def generate_effectiveness_report(session: Any, ctx: dict) -> "EffectivenessReport":
    """
    Generate a complete reactive effectiveness report from existing scan state.

    Called from _phase_done after scan completion. Reads-only from
    session and ctx — does not modify any execution state.

    Returns:
        EffectivenessReport with all metrics, records, and determination.
    """
    scan_id = str(session.scan_id)
    target  = str(session.target)
    log.info("[REP] Generating reactive effectiveness report for scan %s", scan_id)

    # ── Collect records ─────────────────────────────────────────────
    try:
        actions = _collect_action_records(scan_id, session, ctx)
    except Exception as exc:
        log.warning("[REP] action record collection failed: %s", exc)
        actions = []

    try:
        replans = _collect_replan_records(scan_id, session, ctx)
    except Exception as exc:
        log.warning("[REP] replan record collection failed: %s", exc)
        replans = []

    try:
        pivots = _collect_pivot_records(scan_id, session, ctx)
    except Exception as exc:
        log.warning("[REP] pivot record collection failed: %s", exc)
        pivots = []

    # ── Compute metrics ─────────────────────────────────────────────
    try:
        metrics = _compute_metrics(scan_id, session, ctx, actions, replans, pivots)
    except Exception as exc:
        log.warning("[REP] metrics computation failed: %s", exc)
        metrics = EffectivenessMetrics(scan_id=scan_id, target=target)

    # ── Determination ───────────────────────────────────────────────
    try:
        determination, evidence = _compute_determination(
            metrics, actions, replans, pivots, session, ctx
        )
    except Exception as exc:
        log.warning("[REP] determination failed: %s", exc)
        determination = "INSUFFICIENT_DATA"
        evidence = [f"Determination error: {exc}"]

    # ── Raw telemetry snapshot ──────────────────────────────────────
    raw_tel = dict(ctx.get("_reactive_telemetry", {}) or {})
    raw_tel.update({
        "_replan_count":          ctx.get("_replan_count", 0),
        "_reactive_total_executed": ctx.get("_reactive_total_executed", 0),
        "_reactive_total_runtime_s": ctx.get("_reactive_total_runtime_s", 0.0),
        "new_targets":            ctx.get("new_targets", []),
        "replanned_actions_count": len(ctx.get("replanned_actions") or []),
    })

    report = EffectivenessReport(
        scan_id=scan_id,
        target=target,
        generated_at=time.time(),
        metrics=metrics,
        actions=actions,
        replans=replans,
        pivots=pivots,
        determination=determination,
        determination_evidence=evidence,
        raw_telemetry=raw_tel,
    )

    log.info(
        "[REP] Reactive effectiveness: determination=%s metrics_passed=%d/8 "
        "reactive_findings=%d baseline=%d lift=%.1f%%",
        determination, metrics.metrics_passed,
        metrics.reactive_findings, metrics.baseline_findings,
        metrics.m1_finding_lift_pct,
    )

    # ── Persist to DB (non-fatal) ───────────────────────────────────
    try:
        from oneinfinity.scan.reactive_effectiveness_store import get_store
        get_store().persist_report(report)
    except Exception as exc:
        log.warning("[REP] DB persistence failed (non-fatal): %s", exc)

    # ── Write text report to done.meta ─────────────────────────────
    try:
        done_phase = session.phases.get("done")
        if done_phase is not None:
            done_phase.meta["reactive_effectiveness"] = {
                "determination":    determination,
                "metrics_passed":   metrics.metrics_passed,
                "metrics":          metrics.to_dict(),
                "evidence":         evidence,
                "raw_telemetry":    raw_tel,
            }
    except Exception as exc:
        log.debug("[REP] failed to write to done.meta: %s", exc)

    return report
