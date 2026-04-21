"""
CLI command handlers for graph domain.
Each public function is cmd_* (handler) or register() (argparse setup).
"""
from __future__ import annotations
import sys
import os
import asyncio
import logging
from pathlib import Path
from oneinfinity.cli._helpers import (
    CLI_COMMAND, WORKSPACE_DIRNAME, LEGACY_WORKSPACE_DIRNAME,
    get_workspace_root, find_program_dir, get_program_dir,
)
from oneinfinity.infra.path_manager import findings_db_path, raw_dir, resolve_output_dir, workspace_root

log = logging.getLogger(__name__)

def cmd_graph(args):
    """
    oneinfinity graph <verify|stats|neo4j-status>
    """
    from oneinfinity.modules.utils import banner, ok, warn, info, err
    import datetime

    sub = getattr(args, "subcommand", None)

    if sub == "verify":
        banner("Graph Consistency Verify")
        try:
            from oneinfinity.attack_graph_core.graph_engine import get_engine
            from oneinfinity.core.graph_neo4j_bootstrap import compare_inmemory_vs_neo4j
            engine = get_engine()
            result = compare_inmemory_vs_neo4j(engine._store)
            print(f"  In-memory  nodes : {result['inmem_nodes']}")
            print(f"  In-memory  edges : {result['inmem_edges']}")
            if result["neo4j_connected"]:
                print(f"  Neo4j      nodes : {result['neo4j_nodes']}")
                print(f"  Neo4j      edges : {result['neo4j_edges']}")
                print(f"  Node delta       : {result['node_delta']}")
                print(f"  Edge delta       : {result['edge_delta']}")
                if result["match"]:
                    ok("Counts match — in-memory and Neo4j are consistent.")
                else:
                    warn("Count mismatch — Neo4j may be lagging or diverged.")
            else:
                warn("Neo4j not connected — only in-memory counts available.")
        except Exception as exc:
            err(f"verify failed: {exc}")

    elif sub == "stats":
        banner("Graph Metrics")
        try:
            from oneinfinity.attack_graph_core.graph_engine import get_engine
            from oneinfinity.attack_graph_core.exploit_chain_engine import ExploitChainEngine
            engine = get_engine()
            stats = engine._store.get_graph_stats()
            chains = ExploitChainEngine(engine=engine).detect_chains()
            print(f"  nodes      : {stats['total_nodes']}")
            print(f"  edges      : {stats['total_edges']}")
            print(f"  avg_degree : {stats['avg_degree']}")
            print(f"  chains     : {len(chains)}")
            ok("Graph stats complete.")
        except Exception as exc:
            err(f"stats failed: {exc}")

    elif sub == "neo4j-status":
        banner("Neo4j Status")
        try:
            from oneinfinity.attack_graph_core.graph_engine import get_engine as _init_graph
            _init_graph()   # side-effect: populates _neo4j_engine_singleton
            from oneinfinity.core.graph_neo4j_bootstrap import get_neo4j_engine
            eng = get_neo4j_engine()
            if eng is None:
                warn("Neo4j engine not initialised (disabled or not connected).")
                return
            status = eng.get_status()
            print(f"  Connected  : {status['connected']}")
            print(f"  URI        : {status['uri']}")
            print(f"  Database   : {status['database']}")
            print(f"  Nodes      : {status['node_count']}")
            print(f"  Edges      : {status['edge_count']}")
            ts = status.get("last_sync_ts")
            if ts:
                dt = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                print(f"  Last sync  : {dt}")
            else:
                print(f"  Last sync  : never")
            if status["connected"]:
                ok("Neo4j is reachable.")
            else:
                warn("Neo4j not connected.")
        except Exception as exc:
            err(f"neo4j-status failed: {exc}")

    else:
        warn("Usage: oneinfinity graph <verify|stats|neo4j-status>")


def cmd_attack_graph(args):
    """
    oneinfinity attack-graph <target> — build and visualise the attack graph.
    """
    from oneinfinity.modules.utils import banner, section, ok, warn, info
    from pathlib import Path

    target = args.target
    output_dir = resolve_output_dir(args.output, target)
    out_path = Path(output_dir)

    banner(f"Attack Graph — {target}")

    from oneinfinity.attack_graph_core import AttackGraph, AttackGraphBuilder, AttackGraphAnalyzer, AttackGraphVisualizer
    from oneinfinity.attack_graph_core.graph import Node, NodeType

    # Build the graph from recon output
    builder = AttackGraphBuilder(target)
    if out_path.exists():
        info(f"Loading recon data from {output_dir}/ ...")
        builder.from_recon_dir(str(out_path))
        graph = builder.build()
    else:
        warn(f"No recon directory found at {output_dir}/ — creating empty graph")
        graph = AttackGraph(target)
        graph.add_node(Node(node_id=target, node_type=NodeType.TARGET, label=target))

    stats = graph.stats()
    ok(f"Graph: {stats['total_nodes']} nodes, {stats['total_edges']} edges")
    by_type = stats.get('nodes_by_type', {})
    print(f"  Subdomains : {by_type.get('subdomain', 0)}")
    print(f"  Hosts      : {by_type.get('host', 0)}")
    print(f"  Endpoints  : {by_type.get('endpoint', 0)}")
    print(f"  Vulns      : {by_type.get('vulnerability', 0)}")
    print()

    # Analyse
    analyzer = AttackGraphAnalyzer(graph)
    report = analyzer.analyze()

    # Visualise
    viz = AttackGraphVisualizer(graph)
    viz.print_full()

    # Save outputs
    out_path.mkdir(parents=True, exist_ok=True)
    graph_json = str(out_path / "attack_graph.json")
    graph.save(graph_json)
    ok(f"Graph saved: {graph_json}")

    if args.mermaid:
        mmd_file = str(out_path / "attack_graph.mmd")
        viz.save_mermaid(mmd_file)
        ok(f"Mermaid diagram: {mmd_file}")

    if args.dot:
        dot_file = str(out_path / "attack_graph.dot")
        viz.save_dot(dot_file)
        ok(f"DOT diagram: {dot_file}")

    print()


def cmd_brain_start(args):
    """oneinfinity brain-start <target> [target2 ...] — start the graph brain autonomous loop."""
    raw     = getattr(args, 'args', [])
    targets = [t.strip() for r in raw for t in r.split(',') if t.strip()]
    if not targets:
        print("Usage: oneinfinity brain-start <target> [target2 ...]")
        return
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        from oneinfinity.event_driven_engine import get_engine
        from oneinfinity.swarm.agent_execution_fabric import get_fabric

        brain  = get_brain()
        ede    = get_engine()
        fabric = get_fabric()

        brain.start(targets=targets)
        ede.start(targets=targets)
        fabric.start()

        print(f"  [+] Graph Brain started for: {', '.join(targets)}")
        status = brain.status()
        print(f"  [*] Nodes: {status.total_nodes}  Edges: {status.total_edges}")
        print(f"  [*] Queue depth: {status.queue_depth}")
    except Exception as e:
        print(f"  [!] Error starting brain: {e}")


def cmd_brain_stop(args):
    """oneinfinity brain-stop — stop the graph brain and all agents."""
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        from oneinfinity.event_driven_engine import get_engine
        get_brain().stop()
        get_engine().stop()
        print("  [+] Graph Brain stopped.")
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_brain_status(args):
    """oneinfinity brain-status — show graph brain status + top priority nodes."""
    try:
        from oneinfinity.intelligence.attack_graph_brain import get_brain
        from oneinfinity.event_driven_engine import get_engine
        from oneinfinity.swarm.agent_execution_fabric import get_fabric

        b = get_brain().status()
        e = get_engine().status()
        f = get_fabric().status()

        print(f"\n  Attack Graph Brain — {'RUNNING' if b.running else 'STOPPED'}")
        print(f"  Targets:         {', '.join(b.targets) or 'none'}")
        print(f"  Graph nodes:     {b.total_nodes}  edges: {b.total_edges}")
        print(f"  Queue depth:     {b.queue_depth}")
        print(f"  Decisions made:  {b.decisions_made}")
        print(f"  Dispatched:      {b.actions_dispatched}")
        print(f"  Findings in:     {b.findings_integrated}")
        print(f"  Uptime:          {b.uptime_s:.0f}s")
        print(f"\n  EDE — iterations={e.iterations} events={e.events_received} nodes_fed={e.nodes_fed}")
        print(f"  Fabric — queue={f['queue_depth']} active={f['active_tasks']} done={f['completed']}")

        # Top priority nodes
        nodes = get_brain().top_priority_nodes(n=10)
        if nodes:
            print(f"\n  Top Priority Nodes:")
            print(f"  {'Type':<14}  {'Label':<40}  {'Priority':>8}")
            print(f"  {'─'*14}  {'─'*40}  {'─'*8}")
            for n in nodes:
                print(f"  {n.node_type:<14}  {n.node_label[:40]:<40}  {n.priority:>8.2f}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_brain_decide(args):
    """oneinfinity brain-decide <target> — generate and display a decision plan."""
    raw = getattr(args, 'args', [])
    if not raw:
        print("Usage: oneinfinity brain-decide <target>")
        return
    target = raw[0].strip()
    try:
        from oneinfinity.autonomous_decision_engine import get_decision_engine
        plan = get_decision_engine().generate_plan(target, max_decisions=15)
        print(f"\n  Decision Plan for '{target}' ({len(plan.decisions)} decisions)")
        print(f"  {'Agent':<14}  {'Node':<35}  {'Score':>7}  {'Confidence':>10}  Impact")
        print(f"  {'─'*14}  {'─'*35}  {'─'*7}  {'─'*10}  {'─'*20}")
        for d in plan.decisions[:15]:
            print(f"  {d.agent_type:<14}  {d.node_label[:35]:<35}  {d.score:>7.3f}  {d.confidence:>10.0%}  {d.expected_impact}")
        if plan.decisions:
            top = plan.decisions[0]
            print(f"\n  Top pick: [{top.agent_type}] on '{top.node_label}'")
            print(f"  Reasoning: {', '.join(top.rationale.factors[:3])}")
            if top.suggested_tool:
                print(f"  Tool: {top.suggested_tool}")
            if top.suggested_payload:
                print(f"  Payload: {top.suggested_payload}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")


def cmd_brain_triggers(args):
    """oneinfinity brain-triggers [--evaluate] — list trigger rules or evaluate graph."""
    raw = getattr(args, 'args', [])
    evaluate = '--evaluate' in raw or '-e' in raw
    try:
        from oneinfinity.graph_trigger_engine import get_trigger_engine
        te = get_trigger_engine()
        if evaluate:
            count = te.evaluate_graph()
            print(f"  [+] Trigger evaluation complete: {count} firings")
        rules = te.list_rules()
        stats = te.stats()
        print(f"\n  Trigger Engine — {stats['rules']} rules, {stats['total_fired']} total firings")
        print(f"\n  {'Name':<28}  {'Agents':<35}  {'Once':>5}  {'Cooldown':>8}")
        print(f"  {'─'*28}  {'─'*35}  {'─'*5}  {'─'*8}")
        for r in rules:
            agents_str = ', '.join(r['agents'][:4])
            print(f"  {r['name']:<28}  {agents_str:<35}  {str(r['once']):>5}  {r['cooldown_s']:>7.0f}s")
        firings = te.recent_firings(10)
        if firings:
            print(f"\n  Recent firings (last {len(firings)}):")
            for f in firings:
                print(f"  [{f['trigger_name']}] → {f['node_label']} → {', '.join(f['agents'])}")
        print()
    except Exception as e:
        print(f"  [!] Error: {e}")




def register(subparsers):
    """Register graph commands with the CLI argument parser."""
    sub = subparsers
    gr = sub.add_parser("graph", help="Graph observability: verify/stats/neo4j-status")
    grsub = gr.add_subparsers(dest="subcommand")
    grsub.add_parser("verify",       help="Compare in-memory vs Neo4j node/edge counts")
    grsub.add_parser("stats",        help="Show graph metrics (nodes, edges, avg_degree, chains)")
    grsub.add_parser("neo4j-status", help="Show Neo4j connectivity, counts, and last sync time")

    ag = sub.add_parser("attack-graph",
                         help="Build and display the attack graph for a target")
    ag.add_argument("target", help="Target domain")
    ag.add_argument("--output", "-o", metavar="DIR",
                    help="Recon output directory (default: ~/.oneinfinity/raw/<target>)")
    ag.add_argument("--mermaid", action="store_true", help="Save Mermaid diagram file")
    ag.add_argument("--dot",     action="store_true", help="Save GraphViz DOT file")


