"""
Regression tests for _replan_if_needed() — snapshot kwarg fix.

Root cause:
    generate_plan() was called with `snapshot=replan_ctx.get("snapshot")`.
    AutonomousDecisionEngine.generate_plan() has no `snapshot` parameter.
    TypeError was swallowed; _replan_if_needed always returned [].
    Fixed by removing the unknown kwarg (unified_scan_engine.py:992-995).

Scenarios covered:
    1. GraphQL discovery → replanning produces actions
    2. JWT discovery    → replanning produces actions
    3. Admin endpoint   → replanning produces actions
    4. generate_plan TypeError no longer occurs after fix
    5. ctx["replanned_actions"] is populated on non-empty delta
    6. _execute_reactive_actions consumes replanned_actions
    7. Reactive telemetry reflects successful replan
"""
import threading
import unittest
from unittest.mock import MagicMock, patch

from oneinfinity.scan.unified_scan_engine import (
    PhaseResult,
    ScanSession,
    UnifiedScanEngine,
    _REACTIVE_ALLOWED_TYPES,
)


def _make_session(scan_id="t-001", target="https://example.com"):
    s = ScanSession(scan_id=scan_id, target=target)
    s.scan_config = {}
    s.phases["graph_update"] = PhaseResult(name="graph_update")
    s.phases["agent_trigger"] = PhaseResult(name="agent_trigger")
    s.phases["done"] = PhaseResult(name="done")
    return s


def _make_ctx():
    return {
        "_phase_stop": threading.Event(),
        "_replan_count": 0,
        "_reactive_in_progress": False,
    }


def _fake_plan(*decisions):
    """Return a MagicMock that looks like a DecisionPlan with given decisions."""
    plan = MagicMock()
    plan.decisions = list(decisions)
    return plan


class TestReplanIfNeededNoTypeError(unittest.TestCase):
    """After the fix, generate_plan must not raise TypeError."""

    def test_no_type_error_on_empty_graph(self):
        """_replan_if_needed returns [] without raising on an empty graph."""
        e = UnifiedScanEngine()
        s = _make_session()
        ctx = _make_ctx()

        # Must not raise; previously always raised TypeError → caught → returned []
        result = e._replan_if_needed(s, ctx, "graph_update")

        self.assertIsInstance(result, list)
        self.assertEqual(ctx["_replan_count"], 1)

    def test_replan_count_increments_from_zero(self):
        """_replan_count increments from 0 to 1 on first call (was never reached)."""
        e = UnifiedScanEngine()
        # Session needs at least one finding so the "no new findings" guard doesn't fire.
        s = _make_session()
        s.findings = [{"vuln_type": "xss", "severity": "high", "url": "https://example.com/x"}]

        ctx = _make_ctx()
        self.assertEqual(ctx["_replan_count"], 0)

        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=_fake_plan(),
        ):
            e._replan_if_needed(s, ctx, "graph_update")

        # Counter must reach 1 — was unreachable before the fix.
        self.assertEqual(ctx["_replan_count"], 1)

    def test_replan_count_respects_new_findings_guard(self):
        """With no new findings and _rc > 0, replan is skipped (guard fires before increment)."""
        e = UnifiedScanEngine()
        s = _make_session()  # empty findings

        ctx = _make_ctx()
        ctx["_replan_count"] = 1  # simulate: one replan already done
        # _replan_finding_count defaults to 0; current findings also 0 → guard fires

        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=_fake_plan(),
        ) as mock_gp:
            result = e._replan_if_needed(s, ctx, "graph_update")

        # Guard fires, returns [] without calling generate_plan
        self.assertEqual(result, [])
        mock_gp.assert_not_called()
        # Counter stays at 1 — increment was skipped by the guard
        self.assertEqual(ctx["_replan_count"], 1)


class TestReplanGraphQLDiscovery(unittest.TestCase):
    """GraphQL endpoint discovery triggers a replan with graphql-type actions."""

    def setUp(self):
        self.engine = UnifiedScanEngine()
        self.session = _make_session()
        self.session.findings = [
            {
                "vuln_type": "graphql_introspection",
                "severity": "high",
                "url": "https://example.com/graphql",
                "title": "GraphQL Introspection Enabled",
            }
        ]

    def _graphql_plan(self):
        return _fake_plan(
            {
                "node_id": "https://example.com/graphql",
                "agent_type": "graphql",
                "confidence": 0.85,
                "reason": "graphql introspection enabled",
                "trigger_phase": "graph_update",
            }
        )

    def test_graphql_discovery_produces_delta(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._graphql_plan(),
        ):
            delta = self.engine._replan_if_needed(self.session, ctx, "graph_update")

        self.assertEqual(len(delta), 1)
        self.assertEqual(delta[0]["agent_type"], "graphql")

    def test_graphql_discovery_populates_ctx_replanned_actions(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._graphql_plan(),
        ):
            self.engine._replan_if_needed(self.session, ctx, "graph_update")

        replanned = ctx.get("replanned_actions", [])
        self.assertEqual(len(replanned), 1)
        self.assertEqual(replanned[0]["agent_type"], "graphql")

    def test_graphql_discovery_updates_replans_triggered_telemetry(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._graphql_plan(),
        ):
            self.engine._replan_if_needed(self.session, ctx, "graph_update")

        tel = ctx.get("_reactive_telemetry", {})
        self.assertEqual(tel.get("replans_triggered"), 1)

    def test_graphql_discovery_graphql_is_allowed_type(self):
        """graphql must be in REACTIVE_ALLOWED_TYPES for execution to proceed."""
        self.assertIn("graphql", _REACTIVE_ALLOWED_TYPES)


class TestReplanJWTDiscovery(unittest.TestCase):
    """JWT weak-secret / missing-validation discovery triggers a replan."""

    def setUp(self):
        self.engine = UnifiedScanEngine()
        self.session = _make_session()
        self.session.findings = [
            {
                "vuln_type": "jwt_weak_secret",
                "severity": "high",
                "url": "https://example.com/api/login",
                "title": "JWT Weak Secret",
            }
        ]

    def _jwt_plan(self):
        return _fake_plan(
            {
                "node_id": "https://example.com/api/login",
                "agent_type": "auth",
                "confidence": 0.80,
                "reason": "jwt_weak_secret finding",
                "trigger_phase": "graph_update",
            }
        )

    def test_jwt_discovery_produces_delta(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._jwt_plan(),
        ):
            delta = self.engine._replan_if_needed(self.session, ctx, "graph_update")

        self.assertEqual(len(delta), 1)
        self.assertEqual(delta[0]["agent_type"], "auth")

    def test_jwt_discovery_populates_ctx_replanned_actions(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._jwt_plan(),
        ):
            self.engine._replan_if_needed(self.session, ctx, "graph_update")

        replanned = ctx.get("replanned_actions", [])
        self.assertEqual(len(replanned), 1)
        self.assertEqual(replanned[0]["node_id"], "https://example.com/api/login")

    def test_jwt_delta_has_trigger_phase_metadata(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._jwt_plan(),
        ):
            delta = self.engine._replan_if_needed(self.session, ctx, "graph_update")

        self.assertEqual(delta[0]["trigger_phase"], "graph_update")
        self.assertIn("reason", delta[0])

    def test_jwt_auth_is_allowed_type(self):
        """auth must be in REACTIVE_ALLOWED_TYPES."""
        self.assertIn("auth", _REACTIVE_ALLOWED_TYPES)


class TestReplanAdminEndpointDiscovery(unittest.TestCase):
    """Admin panel exposure triggers a replan with idor/auth-type actions."""

    def setUp(self):
        self.engine = UnifiedScanEngine()
        self.session = _make_session()
        self.session.findings = [
            {
                "vuln_type": "admin_panel_exposed",
                "severity": "critical",
                "url": "https://example.com/admin",
                "title": "Admin Panel Exposed",
            }
        ]

    def _admin_plan(self):
        return _fake_plan(
            {
                "node_id": "https://example.com/admin",
                "agent_type": "idor",
                "confidence": 0.90,
                "reason": "admin panel exposed",
                "trigger_phase": "agent_trigger",
            },
            {
                "node_id": "https://example.com/admin",
                "agent_type": "auth",
                "confidence": 0.88,
                "reason": "admin panel exposed",
                "trigger_phase": "agent_trigger",
            },
        )

    def test_admin_discovery_produces_delta(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._admin_plan(),
        ):
            delta = self.engine._replan_if_needed(self.session, ctx, "agent_trigger")

        self.assertEqual(len(delta), 2)
        agent_types = {d["agent_type"] for d in delta}
        self.assertIn("idor", agent_types)
        self.assertIn("auth", agent_types)

    def test_admin_discovery_populates_ctx_replanned_actions(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._admin_plan(),
        ):
            self.engine._replan_if_needed(self.session, ctx, "agent_trigger")

        replanned = ctx.get("replanned_actions", [])
        self.assertEqual(len(replanned), 2)
        self.assertTrue(all(a["node_id"] == "https://example.com/admin" for a in replanned))

    def test_admin_idor_is_allowed_type(self):
        """idor must be in REACTIVE_ALLOWED_TYPES."""
        self.assertIn("idor", _REACTIVE_ALLOWED_TYPES)

    def test_admin_replans_triggered_telemetry(self):
        ctx = _make_ctx()
        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=self._admin_plan(),
        ):
            self.engine._replan_if_needed(self.session, ctx, "agent_trigger")

        tel = ctx.get("_reactive_telemetry", {})
        self.assertEqual(tel.get("replans_triggered"), 1)


class TestReplanDeduplication(unittest.TestCase):
    """Actions already in ctx["replanned_actions"] are not duplicated."""

    def test_duplicate_actions_not_added_twice(self):
        e = UnifiedScanEngine()
        s = _make_session()
        existing_action = {
            "node_id": "https://example.com/graphql",
            "agent_type": "graphql",
            "confidence": 0.85,
            "reason": "prior replan",
            "trigger_phase": "graph_update",
        }
        ctx = _make_ctx()
        ctx["replanned_actions"] = [existing_action]

        plan_with_same = _fake_plan(dict(existing_action))

        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=plan_with_same,
        ):
            delta = e._replan_if_needed(s, ctx, "graph_update")

        # Delta must be empty — action already present
        self.assertEqual(len(delta), 0)
        # replanned_actions must still have exactly one entry
        self.assertEqual(len(ctx["replanned_actions"]), 1)


class TestExecuteReactiveActionsIntegration(unittest.TestCase):
    """_execute_reactive_actions consumes replanned_actions after a replan."""

    def test_execute_processes_graphql_action_via_fabric(self):
        e = UnifiedScanEngine()
        s = _make_session()
        s.scan_config = {}
        s.phases["graph_update"] = PhaseResult(name="graph_update")
        s.phases["done"] = PhaseResult(name="done")

        mock_task = MagicMock()
        mock_task.result.return_value = [
            {
                "vuln_type": "graphql_introspection",
                "severity": "high",
                "url": "https://example.com/graphql",
            }
        ]
        mock_fabric = MagicMock()
        mock_fabric.submit_task.return_value = mock_task

        ctx = _make_ctx()
        ctx["_reactive_telemetry"] = {"replans_triggered": 1}
        ctx["replanned_actions"] = [
            {
                "node_id": "https://example.com/graphql",
                "agent_type": "graphql",
                "confidence": 0.85,
                "reason": "graphql endpoint",
                "trigger_phase": "graph_update",
            }
        ]

        with patch(
            "oneinfinity.swarm.agent_execution_fabric.get_fabric",
            return_value=mock_fabric,
        ):
            e._execute_reactive_actions(s, ctx, "graph_update", actions=None)

        tel = ctx.get("_reactive_telemetry", {})
        self.assertEqual(mock_fabric.submit_task.call_count, 1)
        self.assertEqual(tel.get("reactive_actions_executed", 0), 1)

    def test_execute_processes_auth_action_via_fabric(self):
        e = UnifiedScanEngine()
        s = _make_session()
        s.scan_config = {}
        s.phases["graph_update"] = PhaseResult(name="graph_update")
        s.phases["done"] = PhaseResult(name="done")

        mock_fabric = MagicMock()
        mock_fabric.submit_task.return_value = MagicMock()

        ctx = _make_ctx()
        ctx["_reactive_telemetry"] = {"replans_triggered": 1}
        ctx["replanned_actions"] = [
            {
                "node_id": "https://example.com/api/login",
                "agent_type": "auth",
                "confidence": 0.80,
                "reason": "jwt_weak_secret",
                "trigger_phase": "graph_update",
            }
        ]

        with patch(
            "oneinfinity.swarm.agent_execution_fabric.get_fabric",
            return_value=mock_fabric,
        ):
            e._execute_reactive_actions(s, ctx, "graph_update", actions=None)

        self.assertEqual(mock_fabric.submit_task.call_count, 1)

    def test_execute_processes_idor_action_via_fabric(self):
        e = UnifiedScanEngine()
        s = _make_session()
        s.scan_config = {}
        s.phases["agent_trigger"] = PhaseResult(name="agent_trigger")
        s.phases["done"] = PhaseResult(name="done")

        mock_fabric = MagicMock()
        mock_fabric.submit_task.return_value = MagicMock()

        ctx = _make_ctx()
        ctx["_reactive_telemetry"] = {"replans_triggered": 1}
        ctx["replanned_actions"] = [
            {
                "node_id": "https://example.com/admin",
                "agent_type": "idor",
                "confidence": 0.90,
                "reason": "admin panel exposed",
                "trigger_phase": "agent_trigger",
            }
        ]

        with patch(
            "oneinfinity.swarm.agent_execution_fabric.get_fabric",
            return_value=mock_fabric,
        ):
            e._execute_reactive_actions(s, ctx, "agent_trigger", actions=None)

        self.assertEqual(mock_fabric.submit_task.call_count, 1)


class TestReactiveTelemetryEventBus(unittest.TestCase):
    """_emit_reactive_telemetry publishes correct counters to EventBus."""

    def test_telemetry_contains_replans_triggered(self):
        e = UnifiedScanEngine()
        s = _make_session()
        ctx = {
            "_replan_count": 1,
            "_reactive_telemetry": {
                "replans_triggered": 1,
                "reactive_actions_executed": 2,
                "reactive_actions_skipped": 0,
            },
        }

        published = []
        mock_bus = MagicMock()
        mock_bus.publish.side_effect = lambda et, **kw: published.append(kw)

        with patch("oneinfinity.orchestration.event_bus.get_bus", return_value=mock_bus):
            e._emit_reactive_telemetry(s, ctx, "graph_update")

        self.assertEqual(len(published), 1)
        data = published[0].get("data", {})
        self.assertEqual(data.get("replans_triggered"), 1)
        self.assertEqual(data.get("reactive_actions_executed"), 2)

    def test_telemetry_after_graphql_jwt_admin_replan(self):
        """End-to-end: replan → telemetry shows correct replans_triggered."""
        e = UnifiedScanEngine()
        s = _make_session()
        s.findings = [
            {"vuln_type": "graphql_introspection", "severity": "high",
             "url": "https://example.com/graphql"},
            {"vuln_type": "jwt_weak_secret",        "severity": "high",
             "url": "https://example.com/api"},
            {"vuln_type": "admin_panel_exposed",    "severity": "critical",
             "url": "https://example.com/admin"},
        ]

        combined_plan = _fake_plan(
            {"node_id": "https://example.com/graphql", "agent_type": "graphql",
             "confidence": 0.85, "reason": "graphql", "trigger_phase": "graph_update"},
            {"node_id": "https://example.com/api",     "agent_type": "auth",
             "confidence": 0.80, "reason": "jwt",     "trigger_phase": "graph_update"},
            {"node_id": "https://example.com/admin",   "agent_type": "idor",
             "confidence": 0.90, "reason": "admin",   "trigger_phase": "graph_update"},
        )

        ctx = _make_ctx()
        published = []
        mock_bus = MagicMock()
        mock_bus.publish.side_effect = lambda et, **kw: published.append(kw)

        with patch(
            "oneinfinity.orchestration.autonomous_decision_engine"
            ".AutonomousDecisionEngine.generate_plan",
            return_value=combined_plan,
        ), patch("oneinfinity.orchestration.event_bus.get_bus", return_value=mock_bus):
            e._replan_if_needed(s, ctx, "graph_update")
            e._emit_reactive_telemetry(s, ctx, "graph_update")

        self.assertGreaterEqual(len(published), 1)
        data = published[-1].get("data", {})
        self.assertEqual(data.get("replans_triggered"), 1)


if __name__ == "__main__":
    unittest.main()
