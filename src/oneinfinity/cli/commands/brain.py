"""
brain — Attack Graph Brain CLI commands

Provides CLI access to the AttackGraphBrain intelligence engine:
  oneinfinity brain status
  oneinfinity brain actions [--target TARGET] [--limit N]
  oneinfinity brain decisions [--limit N]
  oneinfinity brain priorities [--target TARGET]
  oneinfinity brain paths --target TARGET
  oneinfinity brain plan --target TARGET
"""
from __future__ import annotations
import json


# ── Handlers ──────────────────────────────────────────────────────────────────

def handle_brain(args):
    """Dispatch brain sub-commands."""
    cmd = getattr(args, "brain_cmd", None)
    if cmd == "status":
        _brain_status(args)
    elif cmd == "actions":
        _brain_actions(args)
    elif cmd == "decisions":
        _brain_decisions(args)
    elif cmd == "priorities":
        _brain_priorities(args)
    elif cmd == "paths":
        _brain_paths(args)
    elif cmd == "plan":
        _brain_plan(args)
    else:
        print("Usage: oneinfinity brain [status|actions|decisions|priorities|paths|plan]")


def _brain_status(args):
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        brain = get_brain()
        with brain._lock:
            targets = list(brain._targets)
            status = {
                "running":            brain._running,
                "targets":            targets,
                "action_queue_depth": len(brain._action_queue),
                "node_priorities":    len(brain._node_priorities),
                "decisions_made":     brain._decisions_made,
                "actions_dispatched": brain._actions_dispatched,
                "findings_integrated":brain._findings_integrated,
            }
        print("─── Attack Graph Brain Status ───")
        for k, v in status.items():
            print(f"  {k:<25} {v}")
    except Exception as exc:
        print(f"Error: {exc}")


def _brain_actions(args):
    limit = getattr(args, "limit", 10)
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        brain = get_brain()
        with brain._lock:
            actions = sorted(brain._action_queue, reverse=True)[:limit]
        if not actions:
            print("No pending brain actions.")
            return
        print(f"─── Top {len(actions)} Pending Brain Actions ───")
        for a in actions:
            print(f"\n  [{a.priority:6.3f}] {a.agent_type:<15} → {a.node_label[:50]}")
            print(f"          type={a.node_type}  target={a.target}")
            if a.reasoning:
                print(f"          reasoning: {a.reasoning[:80]}")
    except Exception as exc:
        print(f"Error: {exc}")


def _brain_decisions(args):
    limit = getattr(args, "limit", 20)
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        brain = get_brain()
        with brain._lock:
            decisions = list(brain._decisions)[-limit:]
        if not decisions:
            print("No recorded decisions yet. Run a scan first.")
            return
        print(f"─── Last {len(decisions)} Brain Decisions ───")
        for d in reversed(decisions):
            d_dict = d.to_dict() if hasattr(d, 'to_dict') else (d.__dict__ if hasattr(d, '__dict__') else d)
            print(f"\n  [{d_dict.get('score', 0):5.2f}] {d_dict.get('agent_type','?'):<12} → {d_dict.get('node_label','?')[:40]}")
            impact = d_dict.get("expected_impact", "")
            if impact:
                print(f"          impact: {impact}")
    except Exception as exc:
        print(f"Error: {exc}")


def _brain_priorities(args):
    target = getattr(args, "target", None)
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        brain = get_brain()
        with brain._lock:
            records = list(brain._node_priorities.values())
        if target:
            records = [r for r in records if getattr(r, "target", "") == target]
        records.sort(key=lambda r: getattr(r, "priority", 0), reverse=True)
        if not records:
            print("No priority records found.")
            return
        print(f"─── Node Priorities (top {min(20, len(records))}) ───")
        for r in records[:20]:
            print(f"  [{getattr(r,'priority',0):6.3f}] {getattr(r,'node_type','?'):<15} {getattr(r,'label','?')[:50]}")
    except Exception as exc:
        print(f"Error: {exc}")


def _brain_paths(args):
    target = getattr(args, "target", "")
    if not target:
        print("Error: --target required for paths command")
        return
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        brain = get_brain()
        paths = brain.find_attack_paths(target=target, max_length=4)
        if not paths:
            print(f"No attack paths found for {target}. Ensure a scan has been run first.")
            return
        print(f"─── Attack Paths for {target} ───")
        for i, p in enumerate(paths[:10], 1):
            nodes = p.nodes if hasattr(p, 'nodes') else (p if isinstance(p, list) else [])
            labels = [getattr(n, 'label', str(n))[:30] for n in nodes]
            print(f"  Path {i}: {' → '.join(labels)}")
    except Exception as exc:
        print(f"Error: {exc}")


def _brain_plan(args):
    target = getattr(args, "target", "")
    if not target:
        print("Error: --target required for plan command")
        return
    max_decisions = getattr(args, "limit", 20)
    try:
        from oneinfinity.orchestration.autonomous_decision_engine import AutonomousDecisionEngine
        de = AutonomousDecisionEngine()
        plan = de.generate_plan(target=target, max_decisions=max_decisions)
        print(f"─── Adaptive Plan for {target} ({len(plan.decisions)} decisions) ───")
        for d in plan.decisions[:20]:
            d_dict = d.to_dict()
            print(f"\n  [{d_dict['score']:.2f}] {d_dict['agent_type']:<12} → {d_dict['node_label'][:40]}")
            print(f"          impact={d_dict['expected_impact']}  tool={d_dict.get('suggested_tool','?')}")
            rationale = d_dict.get('rationale', {})
            factors = rationale.get('factors', [])
            if factors:
                print(f"          why: {'; '.join(factors[:3])}")
    except Exception as exc:
        print(f"Error: {exc}")


# ── CLI registration ──────────────────────────────────────────────────────────

def register(subparsers):
    brain_p = subparsers.add_parser("brain", help="Attack Graph Brain intelligence commands")
    brain_sub = brain_p.add_subparsers(dest="brain_cmd", metavar="<command>")

    brain_sub.add_parser("status", help="Show brain status and counters")

    actions_p = brain_sub.add_parser("actions", help="Show pending brain actions")
    actions_p.add_argument("--limit", "-n", type=int, default=10, help="Number of actions to show")
    actions_p.add_argument("--target", metavar="TARGET")

    decisions_p = brain_sub.add_parser("decisions", help="Show recent brain decisions with rationale")
    decisions_p.add_argument("--limit", "-n", type=int, default=20)

    priorities_p = brain_sub.add_parser("priorities", help="Show node priority scores")
    priorities_p.add_argument("--target", metavar="TARGET")

    paths_p = brain_sub.add_parser("paths", help="Show computed attack paths")
    paths_p.add_argument("--target", "-t", required=True, metavar="TARGET")

    plan_p = brain_sub.add_parser("plan", help="Generate adaptive decision plan for target")
    plan_p.add_argument("--target", "-t", required=True, metavar="TARGET")
    plan_p.add_argument("--limit", "-n", type=int, default=20)

    brain_p.set_defaults(func=handle_brain)
    return brain_p


__all__ = ["handle_brain", "register"]
