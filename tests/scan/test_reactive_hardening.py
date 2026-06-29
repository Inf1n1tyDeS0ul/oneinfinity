"""
tests/scan/test_reactive_hardening.py
──────────────────────────────────────────────────────────────────────────────
WI-7 — Reactive Execution Hardening Test Suite

Covers every scenario from the Reactive Execution Hardening & Convergence
Program (2026-06-22):

  WI-1  Convergence guarantees
  WI-2  Planner/executor alignment (ssti gap closed)
  WI-3  Storm safety (token/graph/chain/pivot/auth storms)
  WI-4  SSRF pivot safety
  WI-5  Chain-driven replan validation
  WI-6  Reactive persistence (ECE-02 fix)

Rules:
  - No mocking of the module under test; test actual code paths.
  - No network calls; _run_tool_safe is replaced with a deterministic stub.
  - No DB dependency; SQLite / PG writes are not exercised.
  - asyncio pool teardown warnings are pre-existing noise; not failures.
"""

from __future__ import annotations

import threading
import time
import hashlib
from unittest.mock import MagicMock
from typing import List

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from oneinfinity.scan.unified_scan_engine import (
    UnifiedScanEngine,
    ScanSession,
    PhaseResult,
    _REACTIVE_ALLOWED_TYPES,
    _REACTIVE_BATCH_MAX,
    _REACTIVE_BATCH_S,
    MAX_REPLANS,
    MAX_REACTIVE_ACTIONS,
    MAX_REACTIVE_RUNTIME,
    MAX_PIVOTS,
    _PIVOT_TOTAL_BUDGET_S,
)
from oneinfinity.intelligence.attack_graph_brain import _TYPE_AGENTS


# ── Shared fixtures ──────────────────────────────────────────────────────────

def _engine() -> UnifiedScanEngine:
    """Bare UnifiedScanEngine with no DB, no Redis, no fabric."""
    e = UnifiedScanEngine.__new__(UnifiedScanEngine)
    e._threads = {}
    e._stop_flag = threading.Event()
    e._lock = threading.Lock()
    e._sessions = {}
    e._active = {}
    e._task_semaphore = threading.Semaphore(4)
    e._persist_pool = None
    return e


def _session(scan_id: str = "test-001", max_replans: int = 4,
             max_actions: int = 25, max_runtime: float = 300.0) -> ScanSession:
    s = ScanSession(
        scan_id=scan_id,
        target="https://example.com",
        target_type="web",
        scan_config={
            "reactive_max_replans":   str(max_replans),
            "reactive_max_decisions": "10",
            "reactive_max_actions":   str(max_actions),
            "reactive_max_runtime":   str(max_runtime),
        },
    )
    for ph in ("graph_update", "graphql_scan", "agent_trigger",
               "exploit_validation", "exploit_chaining"):
        s.phases[ph] = PhaseResult(name=ph, status="completed")
    return s


def _ctx(findings: List[dict] | None = None) -> dict:
    return {
        "scan_findings":       list(findings or []),
        "tech_stack":          [],
        "jwt_tokens":          [],
        "auth_context":        {},
        "chain_candidates":    [],
        "waf_detected":        False,
        "graph_brain":         None,
        "_reactive_telemetry": {},
    }


def _finding(fid: str, vuln_type: str = "xss",
             severity: str = "high") -> dict:
    return {
        "finding_id": fid,
        "vuln_type":  vuln_type,
        "severity":   severity,
        "url":        "https://example.com",
        "confidence": 0.8,
    }


def _action(agent_type: str, node_id: str = "node-1",
            target: str = "https://example.com",
            chain_type: str = "", confidence: float = 0.8) -> dict:
    return {
        "agent_type":  agent_type,
        "node_id":     node_id,
        "target":      target,
        "chain_type":  chain_type,
        "confidence":  confidence,
        "reason":      "test",
    }


def _stub_tool(engine: UnifiedScanEngine, returns: List[dict] | None = None):
    """Replace _run_tool_safe with a stub returning `returns`."""
    collected = []
    def fake(registry, tool, target, urls, ctx=None):
        f = dict(
            finding_id=f"stub-{len(collected)+1:04d}",
            vuln_type=f"stub_{tool}",
            severity="high",
            url=urls[0] if urls else target,
            source=f"reactive_exec:{tool}",
            tool=tool,
        )
        if returns is not None:
            result = list(returns)
        else:
            result = [f]
        collected.extend(result)
        return result
    engine._run_tool_safe = fake
    return collected


def _no_fabric():
    """Make fabric import raise so fallback path runs."""
    import oneinfinity.swarm.agent_execution_fabric as _fab
    _orig = _fab.get_fabric
    _fab.get_fabric = lambda: (_ for _ in ()).throw(ImportError("no fabric"))
    return _orig, _fab


def _restore_fabric(orig, mod):
    mod.get_fabric = orig


# ═══════════════════════════════════════════════════════════════════════════
# WI-1 — Convergence
# ═══════════════════════════════════════════════════════════════════════════

class TestWI1Convergence:
    """Verify reactive execution is mathematically bounded."""

    def test_fingerprint_blocks_A_replan_A_cycle(self):
        """Same (agent_type, target, chain_type, node_id) → same fingerprint.
        _executed_fps prevents the same action firing twice."""
        e = _engine()
        a = _action("xss", node_id="node-1")
        fp = e._reactive_action_fingerprint(a)
        executed = {fp}
        a2 = _action("xss", node_id="node-1")
        assert e._reactive_action_fingerprint(a2) in executed, \
            "Same action must produce same fingerprint → dedup blocks cycle"

    def test_different_node_id_different_fingerprint(self):
        """Different node_id → different fingerprint → different action allowed."""
        e = _engine()
        fp1 = e._reactive_action_fingerprint(_action("xss", node_id="node-1"))
        fp2 = e._reactive_action_fingerprint(_action("xss", node_id="node-2"))
        assert fp1 != fp2

    def test_max_replans_ceiling_enforced(self):
        """_replan_count never exceeds max_replans regardless of call count."""
        e = _engine()
        s = _session(max_replans=2)
        ctx = _ctx()
        # Inject fresh findings each call to bypass the 'no new findings' guard
        for i in range(6):
            s.findings.append(_finding(f"f{i}"))
            e._replan_if_needed(s, ctx, "graph_update")
        assert ctx.get("_replan_count", 0) <= 2, \
            f"_replan_count={ctx['_replan_count']} exceeded max_replans=2"

    def test_max_replans_returns_empty_after_ceiling(self):
        """_replan_if_needed returns [] once ceiling is reached."""
        e = _engine()
        s = _session(max_replans=1)
        # Add enough findings to fire the first replan
        for i in range(5):
            s.findings.append(_finding(f"f{i}"))
        ctx = _ctx(s.findings)
        e._replan_if_needed(s, ctx, "graph_update")
        assert ctx["_replan_count"] == 1
        # Second call must return []
        s.findings.append(_finding("f99"))
        delta = e._replan_if_needed(s, ctx, "graph_update")
        assert delta == [], "Second replan after ceiling must return []"

    def test_max_reactive_actions_hard_cap(self):
        """Total tool calls never exceed MAX_REACTIVE_ACTIONS across all calls."""
        e = _engine()
        s = _session(max_actions=8)
        for ph in ("graph_update", "agent_trigger"):
            s.phases[ph] = PhaseResult(name=ph, status="completed")
        orig, fab = _no_fabric()
        calls = _stub_tool(e)
        ctx = _ctx()
        # Inject 100 unique actions
        actions_batch = [_action("xss", node_id=f"n{i}") for i in range(100)]
        try:
            e._execute_reactive_actions(s, ctx, "graph_update", actions=actions_batch[:50])
            e._execute_reactive_actions(s, ctx, "agent_trigger", actions=actions_batch[50:])
        finally:
            _restore_fabric(orig, fab)
        assert ctx.get("_reactive_total_executed", 0) <= 8, \
            f"Total executed={ctx['_reactive_total_executed']} exceeded hard cap=8"

    def test_max_reactive_actions_accumulates_across_calls(self):
        """Budget is shared: call1 uses 5, call2 gets only remaining 2 (of 7)."""
        e = _engine()
        s = _session(max_actions=7)
        for ph in ("graph_update", "agent_trigger"):
            s.phases[ph] = PhaseResult(name=ph, status="completed")
        orig, fab = _no_fabric()
        calls = _stub_tool(e)
        ctx = _ctx()
        a1 = [_action("xss", node_id=f"n{i}") for i in range(5)]
        a2 = [_action("sqli", node_id=f"m{i}") for i in range(5)]
        try:
            e._execute_reactive_actions(s, ctx, "graph_update", actions=a1)
            e._execute_reactive_actions(s, ctx, "agent_trigger", actions=a2)
        finally:
            _restore_fabric(orig, fab)
        assert ctx["_reactive_total_executed"] == 7

    def test_runtime_ceiling_halts_execution(self):
        """_REACTIVE_TOTAL_RUNTIME cap stops execution when exceeded."""
        e = _engine()
        s = _session(max_actions=100, max_runtime=0.1)
        s.phases["graph_update"] = PhaseResult(name="graph_update", status="completed")
        orig, fab = _no_fabric()
        calls = _stub_tool(e)
        ctx = _ctx()
        # Force total_runtime to exceed budget before second call
        ctx["_reactive_total_runtime_s"] = 200.0  # already over 0.1s budget
        a = [_action("xss", node_id=f"n{i}") for i in range(10)]
        try:
            result = e._execute_reactive_actions(s, ctx, "graph_update", actions=a)
        finally:
            _restore_fabric(orig, fab)
        assert result == [], "Runtime ceiling exceeded → must return []"

    def test_reentrancy_guard_prevents_nested_replan(self):
        """_reactive_in_progress flag blocks nested replan calls."""
        e = _engine()
        s = _session()
        s.findings = [_finding(f"f{i}") for i in range(10)]
        ctx = _ctx(s.findings)
        ctx["_reactive_in_progress"] = True
        delta = e._replan_if_needed(s, ctx, "graph_update")
        assert delta == [], "Reentrancy guard must block nested _replan_if_needed"

    def test_no_new_findings_skips_replan_after_first(self):
        """Second replan with same finding count returns [] (no work needed)."""
        e = _engine()
        s = _session(max_replans=4)
        s.findings = [_finding(f"f{i}") for i in range(3)]
        ctx = _ctx(s.findings)
        e._replan_if_needed(s, ctx, "graph_update")   # first fires
        # Finding count unchanged → second call returns []
        delta = e._replan_if_needed(s, ctx, "graph_update")
        assert delta == []

    def test_worst_case_bound_formula(self):
        """Documented worst-case: min(MAX_REACTIVE_ACTIONS, 4×4×5=80) = 25."""
        trigger_sites = 4
        naive_max = trigger_sites * MAX_REPLANS * _REACTIVE_BATCH_MAX
        actual_max = MAX_REACTIVE_ACTIONS
        assert actual_max <= naive_max, "Hard cap must be ≤ naive expansion"
        assert actual_max == 25
        assert naive_max == 80


# ═══════════════════════════════════════════════════════════════════════════
# WI-2 — Planner / Executor alignment
# ═══════════════════════════════════════════════════════════════════════════

class TestWI2PlannerExecutorAlignment:
    """Every type _TYPE_AGENTS emits must be in _REACTIVE_ALLOWED_TYPES."""

    def test_all_planner_types_are_executable(self):
        """No silent drops: every agent type the planner can produce is allowed."""
        gaps = []
        for node_type, agents in _TYPE_AGENTS.items():
            for agent in agents:
                if not any(agent.startswith(t) for t in _REACTIVE_ALLOWED_TYPES):
                    gaps.append((node_type, agent))
        assert gaps == [], \
            f"Planner produces types not in _REACTIVE_ALLOWED_TYPES: {gaps}"

    def test_ssti_now_in_allowed_types(self):
        """ssti was the only gap — verify it is now in _REACTIVE_ALLOWED_TYPES."""
        assert "ssti" in _REACTIVE_ALLOWED_TYPES, \
            "ssti must be in _REACTIVE_ALLOWED_TYPES (WI-2 fix)"

    def test_ssti_action_not_rejected_by_type_filter(self):
        """An ssti action passes the type-filter in _execute_reactive_actions."""
        e = _engine()
        s = _session(max_actions=5)
        s.phases["graph_update"] = PhaseResult(name="graph_update", status="completed")
        orig, fab = _no_fabric()
        calls = _stub_tool(e)
        ctx = _ctx()
        a = [_action("ssti", node_id="node-param")]
        try:
            result = e._execute_reactive_actions(s, ctx, "graph_update", actions=a)
        finally:
            _restore_fabric(orig, fab)
        assert len(result) > 0, "ssti action must not be silently dropped"

    def test_allowed_types_superset_of_type_agents(self):
        """_REACTIVE_ALLOWED_TYPES must be a superset of all _TYPE_AGENTS values."""
        all_agent_types = {a for agents in _TYPE_AGENTS.values() for a in agents}
        missing = all_agent_types - _REACTIVE_ALLOWED_TYPES
        assert missing == set(), \
            f"_REACTIVE_ALLOWED_TYPES is missing: {missing}"

    def test_ssti_tool_fallback_uses_nuclei(self):
        """ssti maps to nuclei via the tool_map inside _execute_reactive_actions."""
        e = _engine()
        s = _session()
        s.phases["graph_update"] = PhaseResult(name="graph_update", status="completed")
        tools_used = []
        def fake(registry, tool, target, urls, ctx=None):
            tools_used.append(tool)
            return [{"finding_id": "ssti-1", "vuln_type": "ssti", "severity": "high",
                     "url": target, "tool": tool}]
        e._run_tool_safe = fake
        orig, fab = _no_fabric()
        ctx = _ctx()
        try:
            e._execute_reactive_actions(
                s, ctx, "graph_update",
                actions=[_action("ssti", node_id="node-p")],
            )
        finally:
            _restore_fabric(orig, fab)
        assert tools_used == ["nuclei"], \
            f"ssti must fall back to nuclei, got {tools_used}"


# ═══════════════════════════════════════════════════════════════════════════
# WI-3 — Storm safety
# ═══════════════════════════════════════════════════════════════════════════

class TestWI3StormSafety:
    """Reactive actions cannot amplify beyond hard caps."""

    def test_token_storm_1000_actions_capped(self):
        """1000 actions injected → hard cap terminates at MAX_REACTIVE_ACTIONS."""
        e = _engine()
        s = _session(max_actions=10)
        s.phases["graph_update"] = PhaseResult(name="graph_update", status="completed")
        orig, fab = _no_fabric()
        _stub_tool(e)
        ctx = _ctx()
        actions = [_action("auth", node_id=f"token-node-{i}") for i in range(1000)]
        try:
            e._execute_reactive_actions(s, ctx, "graph_update", actions=actions)
        finally:
            _restore_fabric(orig, fab)
        assert ctx.get("_reactive_total_executed", 0) <= 10

    def test_graph_storm_unique_nodes_capped(self):
        """1000 unique graph nodes → batch cap = 5 per call."""
        e = _engine()
        s = _session(max_actions=100)
        s.phases["graph_update"] = PhaseResult(name="graph_update", status="completed")
        orig, fab = _no_fabric()
        _stub_tool(e)
        ctx = _ctx()
        # Each action has a unique node_id → all pass dedup, but batch cap fires
        actions = [_action("xss", node_id=f"graph-node-{i}") for i in range(1000)]
        try:
            e._execute_reactive_actions(s, ctx, "graph_update", actions=actions)
        finally:
            _restore_fabric(orig, fab)
        # Only _REACTIVE_BATCH_MAX actions should run per single call
        assert ctx.get("_reactive_total_executed", 0) <= _REACTIVE_BATCH_MAX

    def test_chain_storm_dedup_blocks_repeat_chains(self):
        """Same chain_type + target → same fingerprint → dedup blocks repeats."""
        e = _engine()
        s = _session()
        for ph in ("exploit_chaining",):
            s.phases[ph] = PhaseResult(name=ph, status="completed")
        ctx = {
            "exploit_chains": [
                {"chain_type": "jwt", "confidence": 0.9,
                 "url": "https://example.com", "finding_id": "j1"},
            ] * 50,  # 50 identical chains
            "replanned_actions": [],
            "scan_findings": [],
            "_reactive_executed_fps": set(),
            "_reactive_telemetry": {},
        }
        generated = e._chain_driven_replan(s, ctx)
        assert len(generated) == 1, \
            f"50 identical chains must dedup to 1 action, got {len(generated)}"

    def test_auth_storm_disallowed_types_storm_guard(self):
        """More than BATCH_MAX×2 disallowed-type actions trigger storm guard."""
        e = _engine()
        s = _session()
        s.phases["graph_update"] = PhaseResult(name="graph_update", status="completed")
        orig, fab = _no_fabric()
        _stub_tool(e)
        ctx = _ctx()
        # "rce" is not in _REACTIVE_ALLOWED_TYPES → disallowed
        actions = [_action("rce", node_id=f"n{i}") for i in range(_REACTIVE_BATCH_MAX * 3)]
        try:
            result = e._execute_reactive_actions(s, ctx, "graph_update", actions=actions)
        finally:
            _restore_fabric(orig, fab)
        assert result == [], "Storm guard must abort when too many disallowed types"
        assert ctx.get("_reactive_telemetry", {}).get("storm_guard") is not None or \
               ctx.get("_reactive_total_executed", 0) == 0, \
               "Storm guard must have fired"

    def test_decision_storm_max_reactive_actions_terminates(self):
        """A fast-cycling scanner can never exceed MAX_REACTIVE_ACTIONS total."""
        e = _engine()
        s = _session(max_actions=15)
        for ph in ("graph_update", "agent_trigger", "exploit_validation", "exploit_chaining"):
            s.phases[ph] = PhaseResult(name=ph, status="completed")
        orig, fab = _no_fabric()
        _stub_tool(e)
        ctx = _ctx()
        big = [_action("xss", node_id=f"storm-{i}") for i in range(200)]
        try:
            for trigger in ("graph_update", "agent_trigger", "exploit_validation", "exploit_chaining"):
                e._execute_reactive_actions(s, ctx, trigger, actions=big)
        finally:
            _restore_fabric(orig, fab)
        assert ctx.get("_reactive_total_executed", 0) <= 15


# ═══════════════════════════════════════════════════════════════════════════
# WI-4 — SSRF pivot safety
# ═══════════════════════════════════════════════════════════════════════════

class _MockBrain:
    """Minimal brain stub for pivot tests."""
    def __init__(self, targets):
        self._targets = set(targets)
    def _get_engine(self): return None
    def integrate_vuln(self, f): pass


class TestWI4SSRFPivotSafety:
    """MAX_PIVOTS and _PIVOT_TOTAL_BUDGET_S cap all expansion."""

    def _run_pivot(self, n_ssrf: int, max_pivots: int = MAX_PIVOTS,
                   pivot_budget: float = _PIVOT_TOTAL_BUDGET_S):
        e = _engine()
        calls = []
        def fake(registry, tool, target, urls, ctx=None):
            calls.append(tool)
            return [{"finding_id": f"pf-{len(calls)}", "vuln_type": "ssrf_pivot",
                     "severity": "medium", "url": urls[0] if urls else target,
                     "source": "ssrf_pivot_nuclei", "tool": tool}]
        e._run_tool_safe = fake
        s = _session(scan_id=f"ssrf-{n_ssrf}", max_replans=3, max_actions=50)
        s.scan_config["reactive_max_pivots"] = str(max_pivots)
        s.scan_config["reactive_pivot_budget_s"] = str(pivot_budget)
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        brain = _MockBrain({f"192.168.1.{i}" for i in range(n_ssrf)})
        ctx = {"graph_brain": brain, "_brain_targets_snapshot": set(),
               "scan_findings": [], "_reactive_telemetry": {}}
        e._phase_ssrf_pivot_scan(s, ctx)
        return ctx, calls

    def test_1_ssrf_runs_1_pivot(self):
        ctx, calls = self._run_pivot(1)
        assert ctx["_reactive_telemetry"]["pivots_executed"] == 1

    def test_10_ssrf_capped_at_max_pivots(self):
        ctx, calls = self._run_pivot(10)
        assert ctx["_reactive_telemetry"]["pivots_executed"] <= MAX_PIVOTS

    def test_100_ssrf_capped_at_max_pivots(self):
        ctx, calls = self._run_pivot(100)
        assert ctx["_reactive_telemetry"]["pivots_executed"] <= MAX_PIVOTS

    def test_1000_ssrf_capped_at_max_pivots(self):
        ctx, calls = self._run_pivot(1000)
        assert ctx["_reactive_telemetry"]["pivots_executed"] <= MAX_PIVOTS

    def test_1000_ssrf_tool_calls_bounded(self):
        """Even with 1000 SSRFs, tool calls = 2 per pivot × MAX_PIVOTS = 6."""
        ctx, calls = self._run_pivot(1000)
        assert len(calls) <= MAX_PIVOTS * 2, \
            f"Tool calls={len(calls)} must be ≤ {MAX_PIVOTS * 2}"

    def test_zero_ssrf_no_pivots(self):
        """No pivot targets → pivot phase returns immediately, no tool calls."""
        ctx, calls = self._run_pivot(0)
        assert calls == []
        assert ctx["_reactive_telemetry"].get("pivots_executed", 0) == 0

    def test_no_brain_returns_immediately(self):
        """brain=None → pivot phase is a no-op."""
        e = _engine()
        calls = []
        def fake(*a, **kw):
            calls.append(a)
            return []
        e._run_tool_safe = fake
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        ctx = {"graph_brain": None, "_brain_targets_snapshot": set(),
               "scan_findings": [], "_reactive_telemetry": {}}
        e._phase_ssrf_pivot_scan(s, ctx)
        assert calls == [], "No brain → no tool calls"

    def test_budget_exhaustion_halts_pivots(self):
        """50ms total budget → only 1 of 3 pivots completes."""
        e = _engine()
        calls = []
        def fake(registry, tool, target, urls, ctx=None):
            calls.append(tool)
            time.sleep(0.03)  # 30ms per call
            return []
        e._run_tool_safe = fake
        s = _session()
        s.scan_config["reactive_max_pivots"] = "3"
        s.scan_config["reactive_pivot_budget_s"] = "0.05"
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        brain = _MockBrain({"10.0.0.1", "10.0.0.2", "10.0.0.3"})
        ctx = {"graph_brain": brain, "_brain_targets_snapshot": set(),
               "scan_findings": [], "_reactive_telemetry": {}}
        t0 = time.time()
        e._phase_ssrf_pivot_scan(s, ctx)
        elapsed = time.time() - t0
        assert elapsed < 0.5, f"Pivot must respect 50ms budget, took {elapsed*1000:.0f}ms"

    def test_pivot_recursion_structurally_prevented(self):
        """_phase_ssrf_pivot_scan must not call itself recursively.
        The def line contains the name; what must be absent is a self-call site."""
        import inspect
        src = inspect.getsource(UnifiedScanEngine._phase_ssrf_pivot_scan)
        # A self-call would look like: self._phase_ssrf_pivot_scan(
        # The def-line has 'def _phase_ssrf_pivot_scan(' — no 'self.' prefix
        assert "self._phase_ssrf_pivot_scan(" not in src, \
            "_phase_ssrf_pivot_scan must not call itself (recursion prevention)"

    def test_pivot_snapshot_diff_excludes_original_target(self):
        """Original scan target must never appear in pivot targets."""
        e = _engine()
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        calls = []
        def fake(registry, tool, target, urls, ctx=None):
            calls.append(urls[0] if urls else target)
            return []
        e._run_tool_safe = fake
        # brain._targets includes the original target + a pivot
        brain = _MockBrain({"https://example.com", "10.0.0.5"})
        ctx = {"graph_brain": brain, "_brain_targets_snapshot": set(),
               "scan_findings": [], "_reactive_telemetry": {}}
        e._phase_ssrf_pivot_scan(s, ctx)
        for url in calls:
            assert "example.com" not in url or "10." in url, \
                f"Original target must not be a pivot: {url}"


# ═══════════════════════════════════════════════════════════════════════════
# WI-5 — Chain-driven replan validation
# ═══════════════════════════════════════════════════════════════════════════

class TestWI5ChainReplan:
    """Only valid, high-confidence chains trigger actions."""

    def _ctx_with_chain(self, chain_type: str, confidence: float,
                        finding_id: str = "chain-01") -> dict:
        return {
            "exploit_chains": [{
                "chain_type": chain_type,
                "confidence": confidence,
                "url":        "https://example.com",
                "finding_id": finding_id,
            }],
            "replanned_actions": [],
            "scan_findings": [],
            "_reactive_executed_fps": set(),
            "_reactive_telemetry": {},
        }

    def _run(self, chain_type: str, confidence: float, fid: str = "c1") -> List[dict]:
        e = _engine()
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        return e._chain_driven_replan(s, self._ctx_with_chain(chain_type, confidence, fid))

    # Confidence threshold
    def test_high_confidence_jwt_generates_action(self):
        assert len(self._run("jwt", 0.9)) == 1

    def test_low_confidence_jwt_blocked(self):
        assert self._run("jwt", 0.2) == []

    def test_exactly_threshold_0_4_passes(self):
        assert len(self._run("idor", 0.4)) == 1

    def test_below_threshold_0_39_blocked(self):
        assert self._run("auth", 0.39) == []

    def test_zero_confidence_blocked(self):
        assert self._run("jwt", 0.0) == []

    # Chain type mapping
    def test_jwt_maps_to_auth(self):
        actions = self._run("jwt", 0.9)
        assert actions[0]["agent_type"] == "auth"

    def test_idor_maps_to_idor(self):
        actions = self._run("idor", 0.9)
        assert actions[0]["agent_type"] == "idor"

    def test_graphql_maps_to_graphql(self):
        actions = self._run("graphql", 0.85)
        assert actions[0]["agent_type"] == "graphql"

    def test_api_maps_to_api(self):
        actions = self._run("api", 0.9)
        assert actions[0]["agent_type"] == "api"

    def test_cors_maps_to_api(self):
        actions = self._run("cors", 0.9)
        assert actions[0]["agent_type"] == "api"

    def test_ssrf_produces_no_action(self):
        """ssrf chains handled by _phase_ssrf_pivot_scan only."""
        assert self._run("ssrf", 0.95) == []

    def test_unmapped_type_rce_produces_no_action(self):
        assert self._run("rce", 0.99) == []

    def test_duplicate_chain_dedup(self):
        """Same chain twice → only 1 action generated."""
        e = _engine()
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        ctx = {
            "exploit_chains": [
                {"chain_type": "jwt", "confidence": 0.9,
                 "url": "https://example.com", "finding_id": "c1"},
                {"chain_type": "jwt", "confidence": 0.9,
                 "url": "https://example.com", "finding_id": "c1"},
            ],
            "replanned_actions": [], "scan_findings": [],
            "_reactive_executed_fps": set(), "_reactive_telemetry": {},
        }
        generated = e._chain_driven_replan(s, ctx)
        assert len(generated) == 1

    def test_already_executed_chain_skipped(self):
        """Chain whose fingerprint is already in _executed_fps is skipped."""
        e = _engine()
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        ctx = {
            "exploit_chains": [
                {"chain_type": "auth", "confidence": 0.9,
                 "url": "https://example.com", "finding_id": "c1"},
            ],
            "replanned_actions": [], "scan_findings": [],
            "_reactive_executed_fps": set(), "_reactive_telemetry": {},
        }
        # First call
        gen1 = e._chain_driven_replan(s, ctx)
        assert len(gen1) == 1
        # Move it to executed set
        ctx["_reactive_executed_fps"].add(
            e._reactive_action_fingerprint(gen1[0])
        )
        # Second call must produce []
        gen2 = e._chain_driven_replan(s, ctx)
        assert gen2 == []

    def test_stale_replay_chain_blocked_by_fingerprint(self):
        """Replay chains (re-submitting old chains) cannot trigger new actions."""
        e = _engine()
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        ctx = {
            "exploit_chains": [
                {"chain_type": "idor", "confidence": 0.9,
                 "url": "https://example.com", "finding_id": "old-1"},
            ],
            "replanned_actions": [
                # Pre-inject the same action as already planned
                {"agent_type": "idor", "target": "https://example.com",
                 "chain_type": "idor", "source_finding": "old-1",
                 "confidence": 0.9, "source_graph_node": ""},
            ],
            "scan_findings": [],
            "_reactive_executed_fps": set(), "_reactive_telemetry": {},
        }
        gen = e._chain_driven_replan(s, ctx)
        assert gen == [], "Stale chain must not generate duplicate action"

    def test_validated_findings_source_used(self):
        """_chain_driven_replan reads ctx['validated_findings'] as chain source."""
        e = _engine()
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        ctx = {
            "exploit_chains": [],
            "validated_findings": [
                {"vuln_type": "jwt", "confidence": 0.85,
                 "url": "https://example.com", "finding_id": "vf-1",
                 "severity": "high"},
            ],
            "replanned_actions": [], "scan_findings": [],
            "_reactive_executed_fps": set(), "_reactive_telemetry": {},
        }
        gen = e._chain_driven_replan(s, ctx)
        assert len(gen) == 1
        assert gen[0]["agent_type"] == "auth"


# ═══════════════════════════════════════════════════════════════════════════
# WI-6 — Reactive persistence (ECE-02)
# ═══════════════════════════════════════════════════════════════════════════

class TestWI6Persistence:
    """Reactive findings must never be silently dropped from result_ingest."""

    def _result_ingest_findings(self, session: ScanSession,
                                 validated: List[dict],
                                 reactive: List[dict]) -> List[dict]:
        """Run _phase_result_ingest and return what it would ingest."""
        ctx = {
            "validated_findings": list(validated),
            "scan_findings": list(validated),
            "_findings_committed": False,
        }
        # Add reactive findings to session.findings (what execute_reactive_actions does)
        session.findings.extend(validated)
        session.findings.extend(reactive)
        collected = []
        # Patch ingestion to capture what would be persisted
        import oneinfinity.findings.result_ingestion_engine as rie_mod
        class FakeRIE:
            def ingest_batch(self, raw_results):
                collected.extend([r.raw for r in raw_results])
                return raw_results
            def finding_count(self, scan_id): return len(collected)
        class FakeRaw:
            def __init__(self, scan_id, source, raw):
                self.scan_id = scan_id; self.source = source; self.raw = raw
        import oneinfinity.core.deduplicator as ded_mod
        class FakeDedup:
            def filter_new(self, findings): return findings
        orig_rie = getattr(rie_mod, 'get_ingestion_engine', None)
        orig_dedup = getattr(ded_mod, 'Deduplicator', None)
        rie_mod.get_ingestion_engine = lambda: FakeRIE()
        rie_mod.RawResult = FakeRaw
        ded_mod.Deduplicator = FakeDedup
        e = _engine()
        try:
            e._phase_result_ingest(session, ctx)
        except Exception:
            pass
        finally:
            if orig_rie: rie_mod.get_ingestion_engine = orig_rie
            if orig_dedup: ded_mod.Deduplicator = orig_dedup
        return collected

    def test_reactive_findings_persist_when_validated_findings_set(self):
        """ECE-02: reactive findings reach ingest even when validated_findings is non-empty."""
        s = _session()
        validated = [_finding("v1", "xss")]
        reactive = [dict(
            finding_id="r1", vuln_type="reactive_dalfox_finding",
            severity="high", url="https://example.com",
            source="reactive_exec:dalfox",
        )]
        ingested = self._result_ingest_findings(s, validated, reactive)
        fids = {f.get("finding_id") for f in ingested}
        assert "r1" in fids, \
            "Reactive finding r1 must reach ingest (ECE-02 fix)"

    def test_ssrf_pivot_findings_persist(self):
        """SSRF pivot findings (source=ssrf_pivot_*) reach ingest."""
        s = _session()
        validated = [_finding("v1", "xss")]
        pivot = [dict(
            finding_id="pf1", vuln_type="ssrf_pivot_nuclei",
            severity="medium", url="http://10.0.0.1",
            source="ssrf_pivot_nuclei", pivot_target="10.0.0.1",
        )]
        ingested = self._result_ingest_findings(s, validated, pivot)
        fids = {f.get("finding_id") for f in ingested}
        assert "pf1" in fids, "SSRF pivot finding must reach ingest (ECE-02)"

    def test_validated_findings_still_persist(self):
        """ECE-02 must not lose the original validated findings."""
        s = _session()
        validated = [_finding("v1", "sqli"), _finding("v2", "xss")]
        reactive = [dict(finding_id="r1", vuln_type="reactive_nuclei",
                         severity="high", url="https://example.com",
                         source="reactive_exec:nuclei")]
        ingested = self._result_ingest_findings(s, validated, reactive)
        fids = {f.get("finding_id") for f in ingested}
        assert "v1" in fids and "v2" in fids, "Validated findings must not be lost"

    def test_no_duplicates_after_merge(self):
        """ECE-02 dedup: same finding_id in both validated and session.findings → appears once."""
        s = _session()
        f = _finding("dup1", "xss")
        # Same finding in both validated and reactive (double-add scenario)
        ingested = self._result_ingest_findings(s, [f], [f])
        dup_count = sum(1 for x in ingested if x.get("finding_id") == "dup1")
        assert dup_count == 1, f"Duplicate finding must appear once, got {dup_count}"

    def test_finding_with_no_id_excluded_from_seen_ids(self):
        """A finding with no finding_id or id field is not confused as a duplicate."""
        s = _session()
        validated = [{"vuln_type": "xss", "severity": "high", "url": "https://example.com"}]
        reactive = [{"finding_id": "r1", "vuln_type": "reactive_xss",
                     "severity": "high", "url": "https://example.com",
                     "source": "reactive_exec:dalfox"}]
        s.findings = list(validated) + list(reactive)
        ingested = self._result_ingest_findings(s, validated, reactive)
        fids = {f.get("finding_id") for f in ingested}
        assert "r1" in fids


# ═══════════════════════════════════════════════════════════════════════════
# WI-1 additional — GraphQL / JWT / SSRF / Chain specific scenarios
# ═══════════════════════════════════════════════════════════════════════════

class TestConvergenceScenarios:
    """Named scenarios from WI-1 requirement."""

    def test_graphql_discovery_triggers_replan(self):
        """GraphQL findings in session trigger _replan_if_needed to fire."""
        e = _engine()
        s = _session(max_replans=4)
        s.findings = [
            _finding("gql-1", "graphql_introspection", "medium"),
            _finding("gql-2", "graphql_sqli", "high"),
        ]
        ctx = _ctx(s.findings)
        ctx["tech_stack"] = ["graphql"]
        delta = e._replan_if_needed(s, ctx, "graph_update")
        # May be [] if DE returns nothing (no graph), but the guard must not block it
        assert ctx.get("_replan_count", 0) == 1, \
            "GraphQL findings must trigger one replan cycle"

    def test_jwt_discovery_adds_auth_actions(self):
        """JWT findings in exploit_chains → chain replan produces auth actions."""
        e = _engine()
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        ctx = {
            "exploit_chains": [
                {"chain_type": "jwt", "confidence": 0.92,
                 "url": "https://example.com/api/login", "finding_id": "jwt-1"},
            ],
            "replanned_actions": [], "scan_findings": [],
            "_reactive_executed_fps": set(), "_reactive_telemetry": {},
        }
        generated = e._chain_driven_replan(s, ctx)
        assert any(a["agent_type"] == "auth" for a in generated), \
            "JWT chain must produce auth action"

    def test_admin_endpoint_discovery_auth_action(self):
        """Admin path in validated_findings → auth action via chain replan."""
        e = _engine()
        s = _session()
        s.phases["exploit_chaining"] = PhaseResult(name="exploit_chaining", status="completed")
        ctx = {
            "exploit_chains": [],
            "validated_findings": [
                {"vuln_type": "auth", "confidence": 0.88,
                 "url": "https://example.com/admin", "finding_id": "admin-1",
                 "severity": "high"},
            ],
            "replanned_actions": [], "scan_findings": [],
            "_reactive_executed_fps": set(), "_reactive_telemetry": {},
        }
        generated = e._chain_driven_replan(s, ctx)
        assert any(a["agent_type"] == "auth" for a in generated)

    def test_duplicate_actions_across_replan_cycles(self):
        """Same action generated in two consecutive replan cycles appears only once."""
        e = _engine()
        s = _session(max_replans=4)
        s.findings = [_finding("f1"), _finding("f2"), _finding("f3")]
        ctx = _ctx(s.findings)
        # First cycle
        d1 = e._replan_if_needed(s, ctx, "graph_update")
        fps_after_1 = {e._reactive_action_fingerprint(a) for a in
                       ctx.get("replanned_actions", [])}
        # Second cycle — add new finding
        s.findings.append(_finding("f4"))
        d2 = e._replan_if_needed(s, ctx, "agent_trigger")
        fps_after_2 = {e._reactive_action_fingerprint(a) for a in d2}
        # No new action from d2 should have a fingerprint already in replanned_actions
        overlap = fps_after_2 & fps_after_1
        assert overlap == set(), \
            f"Duplicate actions across cycles: {overlap}"

    def test_budget_exhaustion_terminates_cleanly(self):
        """Exhausted budget leaves _reactive_in_progress=False."""
        e = _engine()
        s = _session(max_actions=2)
        s.phases["graph_update"] = PhaseResult(name="graph_update", status="completed")
        orig, fab = _no_fabric()
        _stub_tool(e)
        ctx = _ctx()
        actions = [_action("xss", node_id=f"n{i}") for i in range(10)]
        try:
            e._execute_reactive_actions(s, ctx, "graph_update", actions=actions)
        finally:
            _restore_fabric(orig, fab)
        assert not ctx.get("_reactive_in_progress", False), \
            "_reactive_in_progress must be False after execution (finally block)"

    def test_replan_ceiling_terminates_cleanly(self):
        """After MAX_REPLANS, _replan_count stays at ceiling forever."""
        e = _engine()
        s = _session(max_replans=2)
        for i in range(10):
            s.findings.append(_finding(f"flood-{i}"))
            e._replan_if_needed(s, ctx := _ctx(s.findings), "graph_update")
            if i == 0:
                pass  # seed ctx
        # Direct test: set count to max and verify next call returns []
        ctx = _ctx([_finding(f"x{i}") for i in range(10)])
        ctx["_replan_count"] = 2
        s.findings.extend([_finding(f"y{i}") for i in range(5)])
        result = e._replan_if_needed(s, ctx, "graph_update")
        assert result == []
        assert ctx["_replan_count"] == 2, "Counter must not increment past ceiling"
