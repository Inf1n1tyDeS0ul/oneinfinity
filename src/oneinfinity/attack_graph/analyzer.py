"""
Attack Graph Analyzer
======================
Algorithms: shortest attack path, reachability, criticality scoring,
            blast radius, bottleneck detection, choke-point identification.

All algorithms are pure Python — no external dependencies.
"""

from __future__ import annotations

import heapq
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from oneinfinity.attack_graph.graph import AttackGraph, Node, Edge, NodeType, EdgeType, SEVERITY_WEIGHT


@dataclass
class AttackPath:
    """A sequence of nodes from attacker to high-value target."""
    nodes: list[str]            # node_ids in order
    edges: list[str]            # edge_ids in order
    total_weight: float
    entry_node: str
    target_node: str
    passes_through: list[str] = field(default_factory=list)   # vuln node_ids on path

    @property
    def length(self) -> int:
        return len(self.nodes)

    @property
    def vuln_count(self) -> int:
        return len(self.passes_through)

    def severity_label(self) -> str:
        """Classify path severity by lowest weight (highest severity) vuln on it."""
        if not self.passes_through:
            return "info"
        min_w = min(
            SEVERITY_WEIGHT.get(
                self.passes_through[i] if isinstance(self.passes_through[i], str) else "info",
                16
            )
            for i in range(len(self.passes_through))
        )
        reverse = {v: k for k, v in SEVERITY_WEIGHT.items()}
        return reverse.get(min_w, "info")

    def summary(self) -> str:
        return (f"Path ({self.length} hops, weight={self.total_weight:.1f}): "
                f"{' → '.join(n.split(':', 1)[-1][:30] for n in self.nodes)}")


@dataclass
class AnalysisReport:
    target: str
    total_nodes: int
    total_edges: int
    attack_paths: list[AttackPath]
    critical_nodes: list[str]          # node_ids that are chokepoints
    blast_radius: dict[str, int]       # node_id → reachable vuln count
    isolated_vulns: list[str]          # vulns with no path to/from anything
    severity_distribution: dict[str, int]
    risk_score: float                  # 0–100
    recommendations: list[str]


class AttackGraphAnalyzer:
    """Performs all graph analysis on an AttackGraph."""

    def __init__(self, graph: AttackGraph):
        self.g = graph

    # ── Dijkstra shortest path ────────────────────────────────────────────────

    def shortest_path(self, src_id: str, dst_id: str) -> Optional[AttackPath]:
        """Find shortest (lowest weight) path from src to dst using Dijkstra."""
        if src_id not in self.g._nodes or dst_id not in self.g._nodes:
            return None

        dist = {src_id: 0.0}
        prev: dict[str, tuple[str, str]] = {}   # node_id → (prev_node_id, edge_id)
        heap = [(0.0, src_id)]
        visited: set[str] = set()

        while heap:
            d, u = heapq.heappop(heap)
            if u in visited:
                continue
            visited.add(u)
            if u == dst_id:
                break
            for edge in self.g.edges_from(u):
                v = edge.dst
                nd = d + edge.weight
                if v not in dist or nd < dist[v]:
                    dist[v] = nd
                    prev[v] = (u, edge.edge_id)
                    heapq.heappush(heap, (nd, v))

        if dst_id not in dist:
            return None

        # Reconstruct path
        path_nodes = []
        path_edges = []
        cur = dst_id
        while cur != src_id:
            path_nodes.append(cur)
            prev_node, prev_edge = prev[cur]
            path_edges.append(prev_edge)
            cur = prev_node
        path_nodes.append(src_id)
        path_nodes.reverse()
        path_edges.reverse()

        vuln_nodes = [nid for nid in path_nodes
                      if self.g._nodes[nid].node_type == NodeType.VULNERABILITY]

        return AttackPath(
            nodes=path_nodes,
            edges=path_edges,
            total_weight=dist[dst_id],
            entry_node=src_id,
            target_node=dst_id,
            passes_through=vuln_nodes,
        )

    def all_paths_to_vulns(self, max_paths: int = 20) -> list[AttackPath]:
        """
        Find shortest paths from the root target node to every exploitable vuln.
        Returns paths sorted by weight (easiest exploits first).
        """
        root = f"target:{self.g.target}"
        paths = []
        seen_dst: set[str] = set()

        for vuln_node in sorted(self.g.exploitable_nodes(),
                                key=lambda n: n.weight()):
            if vuln_node.node_id in seen_dst:
                continue
            path = self.shortest_path(root, vuln_node.node_id)
            if path:
                paths.append(path)
                seen_dst.add(vuln_node.node_id)
            if len(paths) >= max_paths:
                break

        return sorted(paths, key=lambda p: p.total_weight)

    # ── Reachability (BFS) ────────────────────────────────────────────────────

    def reachable_from(self, node_id: str) -> set[str]:
        """Return all node_ids reachable from the given node (BFS)."""
        visited: set[str] = set()
        queue = deque([node_id])
        while queue:
            cur = queue.popleft()
            if cur in visited:
                continue
            visited.add(cur)
            for edge in self.g.edges_from(cur):
                if edge.dst not in visited:
                    queue.append(edge.dst)
        visited.discard(node_id)
        return visited

    def nodes_that_reach(self, node_id: str) -> set[str]:
        """Return all node_ids that can reach the given node (reverse BFS)."""
        visited: set[str] = set()
        queue = deque([node_id])
        while queue:
            cur = queue.popleft()
            if cur in visited:
                continue
            visited.add(cur)
            for edge in self.g.edges_to(cur):
                if edge.src not in visited:
                    queue.append(edge.src)
        visited.discard(node_id)
        return visited

    # ── Criticality scoring ───────────────────────────────────────────────────

    def compute_criticality(self):
        """
        Score each node by how many exploitable vulns are reachable from it
        AND how many nodes can reach it. High score = critical choke-point.
        Updates node.criticality_score in-place.
        """
        all_exploitable = {n.node_id for n in self.g.exploitable_nodes()}

        for node in self.g.nodes():
            reachable = self.reachable_from(node.node_id)
            reachable_vulns = reachable & all_exploitable
            reached_by = self.nodes_that_reach(node.node_id)

            # Score: (vulns reachable from here) × (nodes that feed into this)
            # Normalized to 0–100
            raw = len(reachable_vulns) * (1 + len(reached_by))
            node.criticality_score = min(100.0, float(raw))

    def critical_nodes(self, top_n: int = 10) -> list[Node]:
        """Return top N nodes by criticality score."""
        self.compute_criticality()
        return sorted(
            self.g.nodes(),
            key=lambda n: n.criticality_score,
            reverse=True
        )[:top_n]

    # ── Blast radius ──────────────────────────────────────────────────────────

    def blast_radius(self) -> dict[str, int]:
        """
        For every node, count how many exploitable vulns are reachable from it.
        Returns dict[node_id → count].
        """
        all_exploitable = {n.node_id for n in self.g.exploitable_nodes()}
        result = {}
        for node in self.g.nodes():
            reachable = self.reachable_from(node.node_id)
            result[node.node_id] = len(reachable & all_exploitable)
        return result

    # ── Bottleneck / chokepoint detection ────────────────────────────────────

    def chokepoints(self) -> list[str]:
        """
        Nodes whose removal would disconnect the most paths to exploitable vulns.
        Uses a simple approximation: nodes with highest in-degree × out-degree.
        """
        scores = {}
        for nid in self.g._nodes:
            in_deg = len(self.g.edges_to(nid))
            out_deg = len(self.g.edges_from(nid))
            scores[nid] = in_deg * out_deg
        return sorted(scores, key=lambda k: scores[k], reverse=True)[:10]

    # ── Isolated nodes ────────────────────────────────────────────────────────

    def isolated_vulns(self) -> list[str]:
        """Vulnerability nodes with no incoming edges (orphaned)."""
        return [
            n.node_id for n in self.g.vuln_nodes()
            if not self.g.edges_to(n.node_id)
        ]

    # ── Risk score ────────────────────────────────────────────────────────────

    def risk_score(self) -> float:
        """
        0–100 overall risk score for the target.
        Based on: critical/high vuln count, exploitable paths, credential exposure.
        """
        vulns = self.g.vuln_nodes()
        if not vulns:
            return 0.0

        sev_points = {"critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0}
        raw = sum(sev_points.get(v.severity, 0) for v in vulns)
        cred_nodes = self.g.nodes_by_type(NodeType.CREDENTIAL)
        raw += len(cred_nodes) * 25
        paths = self.all_paths_to_vulns(max_paths=5)
        raw += len(paths) * 5
        return min(100.0, float(raw))

    # ── Recommendations ───────────────────────────────────────────────────────

    def recommendations(self) -> list[str]:
        recs = []
        vulns = self.g.vuln_nodes()
        sev_count = {}
        for v in vulns:
            sev_count[v.severity] = sev_count.get(v.severity, 0) + 1

        if sev_count.get("critical", 0) > 0:
            recs.append(f"CRITICAL: {sev_count['critical']} critical vulns — investigate immediately")
        if sev_count.get("high", 0) > 0:
            recs.append(f"HIGH: {sev_count['high']} high-severity findings — report before medium")
        if self.g.nodes_by_type(NodeType.CREDENTIAL):
            recs.append("CREDENTIAL EXPOSURE: Credentials found — rotate immediately")
        if self.g.nodes_by_type(NodeType.CLOUD_ASSET):
            recs.append("CLOUD ASSETS: Check for public bucket misconfiguration")

        paths = self.all_paths_to_vulns(max_paths=3)
        if paths:
            shortest = paths[0]
            recs.append(
                f"SHORTEST ATTACK PATH: {shortest.length} hops via "
                f"{' → '.join(n.split(':',1)[-1][:20] for n in shortest.nodes[:3])}..."
            )

        chokes = self.chokepoints()[:3]
        if chokes:
            labels = [self.g._nodes[n].label[:30] for n in chokes if n in self.g._nodes]
            recs.append(f"CHOKE-POINTS: Secure these first: {', '.join(labels)}")

        return recs

    # ── Full analysis report ──────────────────────────────────────────────────

    def analyze(self) -> AnalysisReport:
        self.compute_criticality()
        paths = self.all_paths_to_vulns()
        crits = [n.node_id for n in self.critical_nodes()]
        blast = self.blast_radius()
        iso = self.isolated_vulns()

        sev_dist: dict[str, int] = {}
        for v in self.g.vuln_nodes():
            sev_dist[v.severity] = sev_dist.get(v.severity, 0) + 1

        stats = self.g.stats()
        return AnalysisReport(
            target=self.g.target,
            total_nodes=stats["total_nodes"],
            total_edges=stats["total_edges"],
            attack_paths=paths,
            critical_nodes=crits,
            blast_radius=blast,
            isolated_vulns=iso,
            severity_distribution=sev_dist,
            risk_score=self.risk_score(),
            recommendations=self.recommendations(),
        )
