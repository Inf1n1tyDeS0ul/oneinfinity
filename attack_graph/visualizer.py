"""
Attack Graph Visualizer
========================
Renders the attack graph as:
  - ASCII tree (terminal output)
  - GraphViz DOT file (render with: dot -Tpng graph.dot -o graph.png)
  - Mermaid diagram (for markdown / GitHub)
  - JSON summary
"""

from __future__ import annotations

from attack_graph.graph import AttackGraph, NodeType, EdgeType
from attack_graph.analyzer import AttackGraphAnalyzer, AnalysisReport


# Severity colour codes (ANSI)
SEV_COLOUR = {
    "critical": "\033[1;31m",  # bold red
    "high":     "\033[0;31m",  # red
    "medium":   "\033[0;33m",  # yellow
    "low":      "\033[0;34m",  # blue
    "info":     "\033[0;37m",  # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"
CYAN  = "\033[0;36m"
GREEN = "\033[0;32m"


def _colour(text: str, sev: str) -> str:
    return f"{SEV_COLOUR.get(sev, '')}{text}{RESET}"


class AttackGraphVisualizer:

    def __init__(self, graph: AttackGraph):
        self.g = graph
        self.analyzer = AttackGraphAnalyzer(graph)

    # ── ASCII overview ────────────────────────────────────────────────────────

    def ascii_summary(self) -> str:
        lines: list[str] = []
        stats = self.g.stats()
        report = self.analyzer.analyze()

        lines.append(f"\n{BOLD}{CYAN}{'═'*68}{RESET}")
        lines.append(f"  {BOLD}Attack Graph — {self.g.target}{RESET}")
        lines.append(f"{BOLD}{CYAN}{'═'*68}{RESET}")
        lines.append("")

        # Stats
        lines.append(f"  Nodes        : {stats['total_nodes']}")
        lines.append(f"  Edges        : {stats['total_edges']}")
        lines.append(f"  Risk Score   : {_colour(f'{report.risk_score:.0f}/100', self._risk_sev(report.risk_score))}")
        lines.append("")

        # Nodes by type
        lines.append(f"  {BOLD}Node Inventory:{RESET}")
        for ntype, count in sorted(stats["nodes_by_type"].items()):
            lines.append(f"    {ntype:<20} {count}")
        lines.append("")

        # Severity distribution
        if stats["vulns_by_severity"]:
            lines.append(f"  {BOLD}Vulnerabilities:{RESET}")
            for sev in ("critical", "high", "medium", "low", "info"):
                count = stats["vulns_by_severity"].get(sev, 0)
                if count:
                    bar = "█" * min(count, 40)
                    lines.append(f"    {_colour(f'{sev:<10}', sev)} {bar} {count}")
            lines.append("")

        return "\n".join(lines)

    def ascii_tree(self, max_depth: int = 4) -> str:
        """BFS tree from root target node."""
        lines: list[str] = []
        root_id = f"target:{self.g.target}"
        if root_id not in self.g._nodes:
            return "No root target node found."

        visited: set[str] = set()
        queue: list[tuple[str, int, str]] = [(root_id, 0, "")]  # (node_id, depth, prefix)

        lines.append(f"\n{BOLD}{CYAN}  Attack Tree — {self.g.target}{RESET}\n")

        node_count = 0
        while queue and node_count < 200:
            nid, depth, prefix = queue.pop(0)
            if nid in visited or depth > max_depth:
                continue
            visited.add(nid)
            node_count += 1

            node = self.g._nodes[nid]
            connector = "└── " if depth > 0 else ""
            icon = self._node_icon(node.node_type)
            label = node.label[:50]
            sev_tag = f" [{_colour(node.severity, node.severity)}]" if node.severity != "info" else ""
            lines.append(f"  {prefix}{connector}{icon} {label}{sev_tag}")

            children = self.g.edges_from(nid)
            for i, edge in enumerate(children[:8]):   # limit fanout display
                child_nid = edge.dst
                is_last = (i == min(len(children), 8) - 1)
                child_prefix = prefix + ("    " if depth > 0 else "")
                queue.append((child_nid, depth + 1, child_prefix))

        return "\n".join(lines)

    def ascii_paths(self, max_paths: int = 5) -> str:
        """Display top attack paths."""
        paths = self.analyzer.all_paths_to_vulns(max_paths=max_paths)
        if not paths:
            return "  No attack paths found."

        lines = [f"\n{BOLD}{CYAN}  Top Attack Paths{RESET}\n"]
        for i, path in enumerate(paths, 1):
            vuln_node = self.g._nodes.get(path.target_node)
            sev = vuln_node.severity if vuln_node else "info"
            lines.append(f"  {BOLD}Path {i}{RESET} [{_colour(sev.upper(), sev)}] "
                         f"weight={path.total_weight:.1f}, hops={path.length}")
            for j, nid in enumerate(path.nodes):
                node = self.g._nodes.get(nid)
                if not node:
                    continue
                indent = "  " + "  " * j
                icon = self._node_icon(node.node_type)
                lines.append(f"  {indent}{'└─' if j == len(path.nodes)-1 else '├─'}"
                              f"{icon} {node.label[:55]}")
            lines.append("")

        return "\n".join(lines)

    def ascii_recommendations(self, report: AnalysisReport = None) -> str:
        if report is None:
            report = self.analyzer.analyze()
        lines = [f"\n{BOLD}{CYAN}  Recommendations{RESET}\n"]
        for rec in report.recommendations:
            prefix = "  ⚠ " if "CRITICAL" in rec or "HIGH" in rec else "  • "
            lines.append(f"{prefix}{rec}")
        lines.append("")
        return "\n".join(lines)

    def print_full(self):
        print(self.ascii_summary())
        print(self.ascii_tree())
        print(self.ascii_paths())
        report = self.analyzer.analyze()
        print(self.ascii_recommendations(report))

    # ── GraphViz DOT export ───────────────────────────────────────────────────

    def to_dot(self) -> str:
        """Generate GraphViz DOT notation."""
        dot_sev_colour = {
            "critical": "#FF0000", "high": "#FF6600",
            "medium": "#FFAA00", "low": "#3399FF", "info": "#AAAAAA",
        }
        dot_node_shape = {
            NodeType.TARGET:        "doubleoctagon",
            NodeType.SUBDOMAIN:     "ellipse",
            NodeType.HOST:          "box",
            NodeType.ENDPOINT:      "note",
            NodeType.SERVICE:       "component",
            NodeType.VULNERABILITY: "diamond",
            NodeType.CREDENTIAL:    "star",
            NodeType.CLOUD_ASSET:   "cylinder",
            NodeType.NETWORK_RANGE: "hexagon",
        }

        lines = ['digraph AttackGraph {', '  rankdir=LR;',
                 '  graph [fontname="Helvetica" fontsize=11];',
                 '  node  [fontname="Helvetica" fontsize=10];',
                 '  edge  [fontname="Helvetica" fontsize=9];', '']

        for node in self.g.nodes():
            nid_safe = node.node_id.replace(":", "_").replace("/", "_").replace(".", "_").replace("?", "_").replace("=", "_").replace("&", "_")
            shape = dot_node_shape.get(node.node_type, "ellipse")
            colour = dot_sev_colour.get(node.severity, "#AAAAAA")
            label = node.label[:40].replace('"', '\\"')
            fillcolour = colour if node.node_type == NodeType.VULNERABILITY else "#F5F5F5"
            lines.append(
                f'  {nid_safe} [label="{label}" shape={shape} '
                f'style=filled fillcolor="{fillcolour}" color="{colour}"];'
            )

        lines.append("")
        for edge in self.g.all_edges():
            src_safe = edge.src.replace(":", "_").replace("/", "_").replace(".", "_").replace("?", "_").replace("=", "_").replace("&", "_")
            dst_safe = edge.dst.replace(":", "_").replace("/", "_").replace(".", "_").replace("?", "_").replace("=", "_").replace("&", "_")
            style = "bold" if edge.edge_type == EdgeType.ENABLES else "solid"
            lbl = edge.label[:20].replace('"', '\\"')
            lines.append(f'  {src_safe} -> {dst_safe} [label="{lbl}" style={style} weight={edge.weight:.0f}];')

        lines.append("}")
        return "\n".join(lines)

    def save_dot(self, path: str):
        with open(path, "w") as f:
            f.write(self.to_dot())

    # ── Mermaid diagram ───────────────────────────────────────────────────────

    def to_mermaid(self, max_nodes: int = 50) -> str:
        """Generate Mermaid flowchart (embed in Markdown)."""
        lines = ["```mermaid", "graph LR"]
        node_ids: dict[str, str] = {}   # node_id → mermaid_id

        def safe_id(nid: str, idx: int) -> str:
            return f"N{idx}"

        nodes = list(self.g.nodes())[:max_nodes]
        for i, node in enumerate(nodes):
            mid = safe_id(node.node_id, i)
            node_ids[node.node_id] = mid
            label = node.label[:30].replace('"', "'")
            shape_open, shape_close = {
                NodeType.VULNERABILITY: ("{{", "}}"),
                NodeType.CREDENTIAL:    ("((", "))"),
                NodeType.TARGET:        ("[\"", "\"]"),
            }.get(node.node_type, ("[", "]"))
            lines.append(f"    {mid}{shape_open}{label}{shape_close}")

        for edge in self.g.all_edges():
            if edge.src in node_ids and edge.dst in node_ids:
                src_mid = node_ids[edge.src]
                dst_mid = node_ids[edge.dst]
                lbl = edge.label[:15] if edge.label else edge.edge_type.value
                arrow = "-->" if edge.edge_type != EdgeType.ENABLES else "==>"
                lines.append(f"    {src_mid} {arrow}|{lbl}| {dst_mid}")

        lines.append("```")
        return "\n".join(lines)

    def save_mermaid(self, path: str, max_nodes: int = 50):
        with open(path, "w") as f:
            f.write(self.to_mermaid(max_nodes))

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _node_icon(ntype: NodeType) -> str:
        return {
            NodeType.TARGET:        "🎯",
            NodeType.SUBDOMAIN:     "🌐",
            NodeType.HOST:          "🖥 ",
            NodeType.ENDPOINT:      "📍",
            NodeType.SERVICE:       "⚙ ",
            NodeType.VULNERABILITY: "🔴",
            NodeType.CREDENTIAL:    "🔑",
            NodeType.CLOUD_ASSET:   "☁ ",
            NodeType.NETWORK_RANGE: "🔗",
        }.get(ntype, "•")

    @staticmethod
    def _risk_sev(score: float) -> str:
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"
