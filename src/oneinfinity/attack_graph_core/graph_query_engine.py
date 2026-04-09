"""
graph_query_engine.py — Graph traversal and structured queries.
Provides attack path discovery, chain detection, and surface analysis.
"""

import logging
import uuid
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .graph_engine import AttackGraphEngine, Node, Edge, NodeType, EdgeType, get_engine

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AttackPath:
    path_id: str
    nodes: list
    edges: list
    total_score: float
    exploitability_score: float
    impact_score: float
    difficulty: str          # easy/medium/hard
    entry_point: str
    final_impact: str
    description: str

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "nodes": [n.to_dict() if hasattr(n, "to_dict") else n for n in self.nodes],
            "edges": [e.to_dict() if hasattr(e, "to_dict") else e for e in self.edges],
            "total_score": self.total_score,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "difficulty": self.difficulty,
            "entry_point": self.entry_point,
            "final_impact": self.final_impact,
            "description": self.description,
        }


@dataclass
class ExploitChain:
    chain_id: str
    name: str
    nodes: list
    edges: list
    combined_severity: str
    chain_score: float
    estimated_bounty: int
    steps: list
    prerequisites: list

    def to_dict(self) -> dict:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "nodes": [n.to_dict() if hasattr(n, "to_dict") else n for n in self.nodes],
            "edges": [e.to_dict() if hasattr(e, "to_dict") else e for e in self.edges],
            "combined_severity": self.combined_severity,
            "chain_score": self.chain_score,
            "estimated_bounty": self.estimated_bounty,
            "steps": self.steps,
            "prerequisites": self.prerequisites,
        }


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

SEVERITY_SCORE = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

IMPACT_NODE_TYPES = {NodeType.IMPACT, NodeType.VULNERABILITY, NodeType.EXPLOIT}
ADMIN_PATTERNS = ["/admin", "/dashboard", "/manage", "/control", "/superuser", "/root"]


class GraphQueryEngine:
    """
    Advanced graph traversal and attack path analysis engine.
    All methods are read-only against the AttackGraphEngine.

    Caching: BFS/DFS results are cached by (start_id, target_types_key, max_depth).
    Cache is invalidated when the underlying engine's node/edge count changes.
    """

    def __init__(self, engine: AttackGraphEngine = None):
        self._engine = engine  # resolved lazily
        self._cache: dict = {}              # key → cached result
        self._cache_snapshot: tuple = (0, 0)  # (node_count, edge_count) at last cache fill

    @property
    def engine(self) -> AttackGraphEngine:
        if self._engine is None:
            self._engine = get_engine()
        return self._engine

    def _cache_key(self, method: str, *args) -> tuple:
        return (method,) + args

    def _cache_valid(self) -> bool:
        """Return True if the graph hasn't changed since last cache fill."""
        try:
            stats = self.engine.get_stats()
            snap = (stats["total_nodes"], stats["total_edges"])
            return snap == self._cache_snapshot
        except Exception:
            return False

    def _cache_get(self, key: tuple):
        if not self._cache_valid():
            self._cache.clear()
            try:
                stats = self.engine.get_stats()
                self._cache_snapshot = (stats["total_nodes"], stats["total_edges"])
            except Exception:
                pass
            return None
        return self._cache.get(key)

    def _cache_set(self, key: tuple, value):
        try:
            stats = self.engine.get_stats()
            self._cache_snapshot = (stats["total_nodes"], stats["total_edges"])
        except Exception:
            pass
        self._cache[key] = value
        # Keep cache bounded
        if len(self._cache) > 256:
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        return value

    def invalidate_cache(self):
        """Force full cache invalidation (call after batch graph mutations)."""
        self._cache.clear()
        self._cache_snapshot = (0, 0)

    # ------------------------------------------------------------------
    # Additional query APIs
    # ------------------------------------------------------------------

    def get_neighbors(self, node_id: str, edge_type: EdgeType = None) -> list:
        """Return immediate neighbor nodes of node_id (thin wrapper over engine)."""
        return self.engine.get_neighbors(node_id, edge_type=edge_type)

    def find_paths(self, source_id: str, target_id: str, max_depth: int = 6) -> list:
        """All paths from source to target (cached DFS)."""
        key = self._cache_key("find_paths", source_id, target_id, max_depth)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        result = self.dfs_paths(source_id, target_id, max_depth)
        return self._cache_set(key, result)

    def filter_nodes(self, node_type: NodeType = None, severity: str = None,
                     exploitable: bool = None, label_contains: str = None) -> list:
        """Convenience wrapper for engine.find_nodes with caching."""
        key = self._cache_key("filter_nodes", node_type, severity, exploitable, label_contains)
        cached = self._cache_get(key)
        if cached is not None:
            return cached
        result = self.engine.find_nodes(
            node_type=node_type, severity=severity,
            exploitable=exploitable, label_contains=label_contains,
        )
        return self._cache_set(key, result)

    # ------------------------------------------------------------------
    # BFS / DFS primitives
    # ------------------------------------------------------------------

    def bfs(
        self,
        start_id: str,
        target_types: list = None,
        max_depth: int = 8,
    ) -> list:
        """
        BFS from start_id. Returns all paths (as node lists) that reach
        a node whose type is in target_types (or all paths if target_types is None).
        Results are cached per (start_id, target_types, max_depth).
        """
        tt_key = tuple(sorted(str(t) for t in target_types)) if target_types else None
        cache_key = self._cache_key("bfs", start_id, tt_key, max_depth)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        all_paths = []
        queue = deque([(start_id, [start_id], 0)])
        visited_states = set()

        while queue:
            current_id, path, depth = queue.popleft()
            state = (current_id, tuple(path))
            if state in visited_states or depth > max_depth:
                continue
            visited_states.add(state)

            current_node = self.engine.get_node(current_id)
            if current_node and target_types:
                if current_node.node_type in target_types and len(path) > 1:
                    node_path = [self.engine.get_node(nid) for nid in path]
                    node_path = [n for n in node_path if n]
                    all_paths.append(node_path)

            for edge in self.engine.get_edges_from(current_id):
                nid = edge.target_id
                if nid not in path:
                    queue.append((nid, path + [nid], depth + 1))

        # If no target_types filter, collect all visited paths
        if not target_types:
            seen_paths = []
            visited_for_all: set = set()
            q2 = deque([(start_id, [start_id], 0)])
            while q2:
                cur, pth, dep = q2.popleft()
                state = (cur, tuple(pth))
                if state in visited_for_all or dep > max_depth:
                    continue
                visited_for_all.add(state)
                if len(pth) > 1:
                    node_path = [self.engine.get_node(nid) for nid in pth]
                    node_path = [n for n in node_path if n]
                    if node_path:
                        seen_paths.append(node_path)
                for edge in self.engine.get_edges_from(cur):
                    nid = edge.target_id
                    if nid not in pth:
                        q2.append((nid, pth + [nid], dep + 1))
            return self._cache_set(cache_key, seen_paths)

        return self._cache_set(cache_key, all_paths)

    def dfs_paths(self, start_id: str, end_id: str, max_depth: int = 6) -> list:
        """DFS to find all paths from start_id to end_id.

        Hybrid: when max_depth exceeds ``hybrid_depth_threshold`` (config/graph.yaml)
        and Neo4j sync is active, try Neo4j variable-length paths first; fall back to
        in-memory DFS if empty or unavailable.
        """
        try:
            from oneinfinity.core.graph_config import load_graph_config
            thr = int((load_graph_config().get("neo4j") or {}).get("hybrid_depth_threshold") or 3)
        except Exception:
            thr = 3

        if max_depth > thr:
            try:
                from oneinfinity.core.graph_neo4j_bootstrap import get_neo4j_sync_backend
                back = get_neo4j_sync_backend()
                if back is not None and hasattr(back, "find_paths_node_ids"):
                    id_paths = back.find_paths_node_ids(
                        start_id, end_id, max_depth=max_depth, max_paths=48
                    )
                    if id_paths:
                        resolved = []
                        for pids in id_paths:
                            node_path = [self.engine.get_node(nid) for nid in pids]
                            node_path = [n for n in node_path if n]
                            if len(node_path) > 1:
                                resolved.append(node_path)
                        if resolved:
                            return resolved
            except Exception:
                pass

        all_paths = []

        def _dfs(current_id: str, path: list, depth: int):
            if depth > max_depth:
                return
            if current_id == end_id and len(path) > 1:
                node_path = [self.engine.get_node(nid) for nid in path]
                all_paths.append([n for n in node_path if n])
                return
            for edge in self.engine.get_edges_from(current_id):
                nid = edge.target_id
                if nid not in path:
                    _dfs(nid, path + [nid], depth + 1)

        _dfs(start_id, [start_id], 0)
        return all_paths

    # ------------------------------------------------------------------
    # Attack path discovery
    # ------------------------------------------------------------------

    def find_attack_paths(self, target_id: str, max_depth: int = 8) -> list:
        """
        BFS from target node to all Impact/Exploit nodes.
        Returns scored AttackPath objects.
        """
        impact_paths = self.bfs(
            target_id,
            target_types=[NodeType.IMPACT, NodeType.EXPLOIT],
            max_depth=max_depth,
        )

        attack_paths = []
        for node_path in impact_paths:
            if len(node_path) < 2:
                continue

            # Collect edges along the path
            path_edges = self._edges_for_path(node_path)

            exp_score = self._exploitability_of_path(node_path)
            imp_score = self._impact_of_path(node_path)
            total = (exp_score * 0.4) + (imp_score * 0.6)

            entry = node_path[0].label if node_path else ""
            final = node_path[-1].label if node_path else ""

            difficulty = "hard"
            if exp_score > 7:
                difficulty = "easy"
            elif exp_score > 4:
                difficulty = "medium"

            ap = AttackPath(
                path_id=str(uuid.uuid4()),
                nodes=node_path,
                edges=path_edges,
                total_score=round(total, 2),
                exploitability_score=round(exp_score, 2),
                impact_score=round(imp_score, 2),
                difficulty=difficulty,
                entry_point=entry,
                final_impact=final,
                description=self._describe_path(node_path),
            )
            attack_paths.append(ap)

        attack_paths.sort(key=lambda p: p.total_score, reverse=True)
        return attack_paths

    def find_privilege_escalation_chains(self) -> list:
        """Find IDOR → auth_bypass → admin_access chains."""
        chains = []
        idor_nodes = self.engine.find_nodes(
            node_type=NodeType.VULNERABILITY,
            label_contains="idor",
        )
        bac_nodes = self.engine.find_nodes(
            node_type=NodeType.VULNERABILITY,
            label_contains="bac",
        )
        auth_bypass_nodes = self.engine.find_nodes(
            node_type=NodeType.VULNERABILITY,
            label_contains="auth_bypass",
        )

        candidate_starts = idor_nodes + bac_nodes + auth_bypass_nodes
        admin_nodes = self.find_reachable_admin_endpoints()

        for start in candidate_starts:
            for admin in admin_nodes:
                paths = self.dfs_paths(start.id, admin.id, max_depth=5)
                for p in paths:
                    ec = self._path_to_exploit_chain(
                        name="Privilege Escalation Chain",
                        nodes=p,
                        severity="high",
                        bounty=5000,
                        steps=["Exploit IDOR/BAC", "Access admin endpoint", "Escalate privileges"],
                        prerequisites=["Valid user session"],
                    )
                    chains.append(ec)

        return chains

    def find_reachable_admin_endpoints(self) -> list:
        """Return URL/API nodes that look like admin endpoints."""
        admin_nodes = []
        for ntype in [NodeType.URL, NodeType.API_ENDPOINT]:
            for pattern in ADMIN_PATTERNS:
                matches = self.engine.find_nodes(node_type=ntype, label_contains=pattern)
                for n in matches:
                    if not n.properties.get("auth_required", False):
                        admin_nodes.append(n)
        return admin_nodes

    def find_exploitable_vulnerability_chains(self) -> list:
        """Find chains where multiple exploitable vulns are connected."""
        chains = []
        exploitable = self.engine.find_nodes(node_type=NodeType.VULNERABILITY, exploitable=True)

        seen_pairs = set()
        for v1 in exploitable:
            for v2 in exploitable:
                if v1.id == v2.id:
                    continue
                pair_key = tuple(sorted([v1.id, v2.id]))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                paths = self.dfs_paths(v1.id, v2.id, max_depth=4)
                for p in paths:
                    ec = self._path_to_exploit_chain(
                        name=f"Exploit Chain: {v1.label} → {v2.label}",
                        nodes=p,
                        severity="high",
                        bounty=4000,
                        steps=[f"Exploit {v1.label}", f"Chain to {v2.label}"],
                        prerequisites=[],
                    )
                    chains.append(ec)

        return chains

    def find_credential_access_paths(self) -> list:
        """Find all attack paths that lead to Credential nodes."""
        cred_nodes = self.engine.find_nodes(node_type=NodeType.CREDENTIAL)
        target_nodes = self.engine.find_nodes(node_type=NodeType.TARGET)
        paths = []

        for target in target_nodes:
            for cred in cred_nodes:
                node_paths = self.dfs_paths(target.id, cred.id, max_depth=7)
                for np_ in node_paths:
                    path_edges = self._edges_for_path(np_)
                    exp_score = self._exploitability_of_path(np_)
                    imp_score = 9.0  # credential access is high impact
                    ap = AttackPath(
                        path_id=str(uuid.uuid4()),
                        nodes=np_,
                        edges=path_edges,
                        total_score=round((exp_score * 0.3) + (imp_score * 0.7), 2),
                        exploitability_score=round(exp_score, 2),
                        impact_score=imp_score,
                        difficulty="medium",
                        entry_point=target.label,
                        final_impact=f"Credential access: {cred.label}",
                        description=self._describe_path(np_),
                    )
                    paths.append(ap)

        return paths

    def find_high_impact_nodes(self) -> list:
        """Return nodes with severity critical or high."""
        results = []
        for sev in ["critical", "high"]:
            results.extend(self.engine.find_nodes(severity=sev))
        return results

    def find_unvalidated_vulnerabilities(self) -> list:
        """Return Vulnerability nodes that have not been validated."""
        all_vulns = self.engine.find_nodes(node_type=NodeType.VULNERABILITY)
        return [v for v in all_vulns if not v.validated]

    def find_chained_exploits(self) -> list:
        """Return groups of exploit nodes connected via CHAINED_WITH edges."""
        exploit_nodes = self.engine.find_nodes(node_type=NodeType.EXPLOIT)
        visited = set()
        chains = []

        for exp in exploit_nodes:
            if exp.id in visited:
                continue
            chain = [exp]
            visited.add(exp.id)
            queue = deque([exp.id])
            while queue:
                eid = queue.popleft()
                for edge in self.engine.get_edges_from(eid):
                    if edge.edge_type == EdgeType.CHAINED_WITH and edge.target_id not in visited:
                        target_node = self.engine.get_node(edge.target_id)
                        if target_node and target_node.node_type == NodeType.EXPLOIT:
                            chain.append(target_node)
                            visited.add(edge.target_id)
                            queue.append(edge.target_id)
            if len(chain) > 1:
                chains.append(chain)

        return chains

    def get_attack_surface(self) -> dict:
        """Return counts of attack surface components."""
        stats = self.engine.get_stats()
        nodes_by_type = stats.get("nodes_by_type", {})
        return {
            "endpoints": nodes_by_type.get("url", 0) + nodes_by_type.get("api_endpoint", 0),
            "parameters": nodes_by_type.get("parameter", 0),
            "vulnerabilities": nodes_by_type.get("vulnerability", 0),
            "exploits": nodes_by_type.get("exploit", 0),
            "credentials": nodes_by_type.get("credential", 0),
            "technologies": nodes_by_type.get("technology", 0),
            "subdomains": nodes_by_type.get("subdomain", 0),
            "targets": nodes_by_type.get("target", 0),
            "impacts": nodes_by_type.get("impact", 0),
        }

    def find_shortest_path_to_rce(self) -> Optional[AttackPath]:
        """Find the shortest attack path leading to RCE."""
        rce_nodes = []
        for ntype in [NodeType.VULNERABILITY, NodeType.EXPLOIT, NodeType.IMPACT]:
            rce_nodes.extend(self.engine.find_nodes(node_type=ntype, label_contains="rce"))
            rce_nodes.extend(self.engine.find_nodes(node_type=ntype, label_contains="remote_code"))
            rce_nodes.extend(self.engine.find_nodes(node_type=ntype, label_contains="command_injection"))

        if not rce_nodes:
            return None

        targets = self.engine.find_nodes(node_type=NodeType.TARGET)
        best_path = None

        for target in targets:
            for rce in rce_nodes:
                paths = self.dfs_paths(target.id, rce.id, max_depth=6)
                for p in paths:
                    path_edges = self._edges_for_path(p)
                    exp_score = self._exploitability_of_path(p)
                    ap = AttackPath(
                        path_id=str(uuid.uuid4()),
                        nodes=p,
                        edges=path_edges,
                        total_score=10.0,  # RCE is always max priority
                        exploitability_score=round(exp_score, 2),
                        impact_score=10.0,
                        difficulty="hard" if exp_score < 5 else "medium",
                        entry_point=target.label,
                        final_impact="Remote Code Execution",
                        description=self._describe_path(p),
                    )
                    if best_path is None or len(p) < len(best_path.nodes):
                        best_path = ap

        return best_path

    def find_ssrf_to_cloud_chains(self) -> list:
        """Find SSRF → cloud metadata → credential chains."""
        chains = []
        ssrf_nodes = self.engine.find_nodes(node_type=NodeType.VULNERABILITY, label_contains="ssrf")
        cred_nodes = self.engine.find_nodes(node_type=NodeType.CREDENTIAL)

        for ssrf in ssrf_nodes:
            # Direct credential leakage paths
            for cred in cred_nodes:
                paths = self.dfs_paths(ssrf.id, cred.id, max_depth=5)
                for p in paths:
                    ec = self._path_to_exploit_chain(
                        name="SSRF → Cloud Metadata → Credential Leak",
                        nodes=p,
                        severity="critical",
                        bounty=10000,
                        steps=["Exploit SSRF", "Access cloud metadata endpoint", "Extract credentials"],
                        prerequisites=["SSRF-vulnerable parameter"],
                    )
                    chains.append(ec)

            # Check for cloud metadata in properties
            if "169.254.169.254" in str(ssrf.properties) or "metadata" in ssrf.label.lower():
                ec = self._path_to_exploit_chain(
                    name="SSRF → Cloud Metadata",
                    nodes=[ssrf],
                    severity="critical",
                    bounty=10000,
                    steps=["Exploit SSRF to reach 169.254.169.254", "Extract IAM credentials"],
                    prerequisites=["SSRF-vulnerable parameter"],
                )
                chains.append(ec)

        return chains

    def find_xss_to_takeover_chains(self) -> list:
        """Find XSS → ATO chains."""
        chains = []
        xss_nodes = self.engine.find_nodes(node_type=NodeType.VULNERABILITY, label_contains="xss")
        ato_impacts = self.engine.find_nodes(node_type=NodeType.IMPACT, label_contains="account_takeover")
        ato_impacts += self.engine.find_nodes(node_type=NodeType.IMPACT, label_contains="ato")

        for xss in xss_nodes:
            for ato in ato_impacts:
                paths = self.dfs_paths(xss.id, ato.id, max_depth=5)
                for p in paths:
                    ec = self._path_to_exploit_chain(
                        name="XSS → Session Hijacking → Account Takeover",
                        nodes=p,
                        severity="high",
                        bounty=3000,
                        steps=["Inject XSS payload", "Steal session cookie", "Replay session"],
                        prerequisites=["User interaction required"],
                    )
                    chains.append(ec)

            # Even without a confirmed ATO impact, flag standalone stored XSS
            if "stored" in xss.label.lower() or xss.properties.get("xss_type") == "stored":
                ec = self._path_to_exploit_chain(
                    name="Stored XSS → Potential ATO",
                    nodes=[xss],
                    severity="high",
                    bounty=2500,
                    steps=["Stored XSS executes on victim browser", "Cookie/session theft possible"],
                    prerequisites=["Victim must visit infected page"],
                )
                chains.append(ec)

        return chains

    def subgraph_for_target(self, target_domain: str) -> dict:
        """Return all nodes and edges reachable from the given target domain."""
        target_id = self.engine._label_index.get((NodeType.TARGET, target_domain))
        if target_id is None:
            # Try subdomain
            target_id = self.engine._label_index.get((NodeType.SUBDOMAIN, target_domain))
        if target_id is None:
            return {"nodes": [], "edges": [], "error": f"Target {target_domain} not found"}
        return self.engine.get_subgraph(target_id, depth=8)

    def get_top_risk_paths(self, n: int = 10) -> list:
        """Return the top-N highest scoring attack paths across all targets."""
        targets = self.engine.find_nodes(node_type=NodeType.TARGET)
        all_paths = []
        for target in targets:
            paths = self.find_attack_paths(target.id, max_depth=7)
            all_paths.extend(paths)
        all_paths.sort(key=lambda p: p.total_score, reverse=True)
        return all_paths[:n]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _edges_for_path(self, node_path: list) -> list:
        """Return the edges that connect sequential nodes in a path."""
        edges = []
        for i in range(len(node_path) - 1):
            src = node_path[i]
            dst = node_path[i + 1]
            if src is None or dst is None:
                continue
            ekey = (src.id, dst.id)
            # Find matching edge
            for edge in self.engine.get_edges_from(src.id):
                if edge.target_id == dst.id:
                    edges.append(edge)
                    break
        return edges

    def _exploitability_of_path(self, node_path: list) -> float:
        """Score a path by the average exploitability of its vuln nodes."""
        scores = []
        for node in node_path:
            if node is None:
                continue
            if node.node_type == NodeType.VULNERABILITY:
                sev = node.severity or "medium"
                scores.append(SEVERITY_SCORE.get(sev, 5.0))
                if node.exploitable:
                    scores.append(2.0)  # bonus
            elif node.node_type == NodeType.EXPLOIT:
                scores.append(9.0)
        return sum(scores) / len(scores) if scores else 3.0

    def _impact_of_path(self, node_path: list) -> float:
        """Score impact based on final node type and severity."""
        if not node_path:
            return 0.0
        final = node_path[-1]
        if final is None:
            return 0.0
        if final.node_type == NodeType.IMPACT:
            impact_type = final.properties.get("impact_type", "")
            high_impacts = {"rce", "account_takeover", "data_exfil", "full_compromise"}
            if any(h in impact_type.lower() for h in high_impacts):
                return 9.5
            return 6.0
        if final.node_type == NodeType.EXPLOIT:
            return 8.0
        sev = final.severity or "medium"
        return SEVERITY_SCORE.get(sev, 5.0)

    def _describe_path(self, node_path: list) -> str:
        """Generate a human-readable description of an attack path."""
        if not node_path:
            return "Empty path"
        parts = []
        for node in node_path:
            if node is None:
                continue
            nt = node.node_type.value if hasattr(node.node_type, "value") else str(node.node_type)
            parts.append(f"[{nt}] {node.label}")
        return " -> ".join(parts)

    def _path_to_exploit_chain(
        self,
        name: str,
        nodes: list,
        severity: str,
        bounty: int,
        steps: list,
        prerequisites: list,
    ) -> ExploitChain:
        """Wrap a node list into an ExploitChain."""
        path_edges = self._edges_for_path(nodes)
        score = SEVERITY_SCORE.get(severity, 5.0)
        return ExploitChain(
            chain_id=str(uuid.uuid4()),
            name=name,
            nodes=nodes,
            edges=path_edges,
            combined_severity=severity,
            chain_score=round(score, 2),
            estimated_bounty=bounty,
            steps=steps,
            prerequisites=prerequisites,
        )


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

graph_query_engine = GraphQueryEngine()
