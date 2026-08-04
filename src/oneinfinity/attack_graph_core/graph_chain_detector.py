"""
Graph-based attack chain detector.

Detects multi-hop attack chains using BFS graph traversal with confidence pruning.
"""
from collections import deque
from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class ChainNode:
    """Single node in attack chain."""
    node_id: str
    vuln_type: str
    severity: str
    confidence: float
    cvss_score: float
    metadata: Dict


@dataclass
class AttackChain:
    """Complete attack chain from entry to objective."""
    chain_id: str
    nodes: List[ChainNode]
    edges: List[Tuple[str, str]]
    total_confidence: float
    cvss_escalation: float
    exploitability_score: float
    objective: str
    length: int

    def to_dict(self) -> Dict:
        """Convert chain to dict for API response."""
        return {
            "chain_id": self.chain_id,
            "nodes": [
                {
                    "id": n.node_id,
                    "type": n.vuln_type,
                    "severity": n.severity,
                    "confidence": n.confidence,
                    "cvss": n.cvss_score,
                    "metadata": n.metadata,
                }
                for n in self.nodes
            ],
            "edges": [{"from": e[0], "to": e[1]} for e in self.edges],
            "confidence": self.total_confidence,
            "cvss_escalation": self.cvss_escalation,
            "exploitability": self.exploitability_score,
            "objective": self.objective,
            "length": self.length,
        }


class GraphChainDetector:
    """
    Detect attack chains in vulnerability graph using BFS pathfinding.

    Features:
    - BFS traversal from entry nodes to objectives
    - Confidence-based path pruning (threshold: 0.6)
    - CVSS escalation scoring
    - Novel chain detection beyond hardcoded patterns
    - Maximum chain length: 5 hops
    """

    CONFIDENCE_THRESHOLD = 0.6
    MAX_CHAIN_LENGTH = 5

    # Objective types mapped to vulnerability types that achieve them
    OBJECTIVE_VULN_MAP = {
        "rce": ["rce", "command_injection", "code_injection", "deserialization", "ssrf_internal"],
        "ato": ["ato", "auth_bypass", "session_fixation", "idor", "broken_auth"],
        "data_exfil": ["data_exfil", "sqli", "path_traversal", "xxe", "idor", "ssrf"],
        "privilege_escalation": ["idor", "auth_bypass", "race_condition"],
        "lateral_movement": ["ssrf_internal", "command_injection", "credential_leak"],
    }

    def __init__(self, graph):
        """
        Initialize detector with vulnerability graph.

        Args:
            graph: AttackGraph instance with nodes and edges
        """
        self.graph = graph
        self.chains: List[AttackChain] = []

    def detect_chains(
        self,
        objectives: List[str],
        entry_nodes: Optional[List[str]] = None,
    ) -> List[AttackChain]:
        """
        Detect all attack chains leading to specified objectives.

        Args:
            objectives: Target objectives (e.g., ["rce", "ato"])
            entry_nodes: Starting nodes (if None, use all low-severity nodes)

        Returns:
            List of detected AttackChain objects
        """
        if entry_nodes is None:
            entry_nodes = self._get_entry_nodes()

        logger.info(f"Detecting chains from {len(entry_nodes)} entry nodes to objectives: {objectives}")

        for objective in objectives:
            target_nodes = self._get_target_nodes_for_objective(objective)

            for entry in entry_nodes:
                # BFS from entry to each target
                for target in target_nodes:
                    paths = self._bfs_find_paths(entry, target)

                    for path in paths:
                        chain = self._build_chain_from_path(path, objective)
                        if chain and self._is_valid_chain(chain):
                            self.chains.append(chain)

        # Deduplicate and sort by exploitability
        self.chains = self._deduplicate_chains(self.chains)
        self.chains.sort(key=lambda c: c.exploitability_score, reverse=True)

        logger.info(f"Detected {len(self.chains)} unique attack chains")
        return self.chains

    def _get_entry_nodes(self) -> List[str]:
        """Get entry point nodes (low CVSS, high confidence)."""
        entry_nodes = []

        for node_id, node in self.graph._nodes.items():
            cvss = float(node.properties.get("cvss_score", 0))
            confidence_val = node.properties.get("confidence", 0)

            # Handle confidence as string ("high", "medium", "low") or float
            if isinstance(confidence_val, str):
                confidence_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
                confidence = confidence_map.get(confidence_val.lower(), 0.5)
            else:
                confidence = float(confidence_val)

            severity = node.severity

            # Entry criteria: low/medium severity, high confidence
            if cvss <= 6.0 and confidence >= 0.7 and severity in ["low", "medium"]:
                entry_nodes.append(node_id)

        # If no entries found, use all info/low severity
        if not entry_nodes:
            entry_nodes = [
                nid for nid, node in self.graph._nodes.items()
                if node.severity in ["info", "low"]
            ]

        return entry_nodes

    def _get_target_nodes_for_objective(self, objective: str) -> List[str]:
        """Get nodes that satisfy the objective."""
        target_vuln_types = self.OBJECTIVE_VULN_MAP.get(objective, [])
        target_nodes = []

        for node_id, node in self.graph._nodes.items():
            vuln_type = node.properties.get("vuln_type", "")

            # Check if vuln type matches objective
            if any(t in vuln_type for t in target_vuln_types):
                target_nodes.append(node_id)

        return target_nodes

    def _bfs_find_paths(
        self,
        start: str,
        target: str,
    ) -> List[List[str]]:
        """
        BFS pathfinding from start to target with confidence pruning.

        Returns:
            List of paths (each path is list of node IDs)
        """
        if start == target:
            return [[start]]

        queue = deque([(start, [start])])
        visited = set()
        paths = []

        while queue:
            current, path = queue.popleft()

            # Skip if path too long
            if len(path) >= self.MAX_CHAIN_LENGTH:
                continue

            # Mark visited
            if current in visited:
                continue
            visited.add(current)

            # Get neighbors
            neighbors = self._get_neighbors(current)

            for neighbor in neighbors:
                # Skip low confidence edges
                edge_confidence = self._get_edge_confidence(current, neighbor)
                if edge_confidence < self.CONFIDENCE_THRESHOLD:
                    continue

                new_path = path + [neighbor]

                if neighbor == target:
                    # Found path to target
                    paths.append(new_path)
                else:
                    # Continue searching
                    queue.append((neighbor, new_path))

        return paths

    def _get_neighbors(self, node_id: str) -> List[str]:
        """Get neighbor node IDs connected by outgoing edges."""
        neighbors = []
        # AttackGraphEngine stores edge IDs in _adj_out, not _adj.
        # Each entry is an edge ID; look up the edge to get target_id.
        for eid in self.graph._adj_out.get(node_id, []):
            edge = self.graph._edges.get(eid)
            if edge is not None:
                neighbors.append(edge.target_id)
        return neighbors

    def _get_edge_confidence(self, from_node: str, to_node: str) -> float:
        """Get confidence score for edge between from_node and to_node."""
        for eid in self.graph._adj_out.get(from_node, []):
            edge = self.graph._edges.get(eid)
            if edge is None:
                continue
            if edge.target_id == to_node:
                # Try edge.probability first (used by AttackGraphEngine), then properties
                conf_val = getattr(edge, "probability", None) or edge.properties.get("confidence", 0.5)
                if isinstance(conf_val, str):
                    confidence_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
                    return confidence_map.get(conf_val.lower(), 0.5)
                return float(conf_val)
        return 0.0

    def _build_chain_from_path(self, path: List[str], objective: str) -> Optional[AttackChain]:
        """Convert node path to AttackChain object."""
        if not path:
            return None

        nodes = []
        edges = []
        total_confidence = 1.0

        for i, node_id in enumerate(path):
            node = self.graph._nodes.get(node_id)
            if not node:
                continue

            # Handle confidence as string or float
            confidence_val = node.properties.get("confidence", 0.5)
            if isinstance(confidence_val, str):
                confidence_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
                confidence = confidence_map.get(confidence_val.lower(), 0.5)
            else:
                confidence = float(confidence_val)

            chain_node = ChainNode(
                node_id=node_id,
                vuln_type=node.properties.get("vuln_type", "unknown"),
                severity=node.severity,
                confidence=confidence,
                cvss_score=float(node.properties.get("cvss_score", 0.0)),
                metadata=node.properties.get("metadata", {}),
            )
            nodes.append(chain_node)

            # Multiply confidences
            total_confidence *= chain_node.confidence

            # Add edge
            if i < len(path) - 1:
                edges.append((path[i], path[i + 1]))

        # Calculate CVSS escalation
        cvss_scores = [n.cvss_score for n in nodes]
        cvss_escalation = max(cvss_scores) - min(cvss_scores) if cvss_scores else 0.0

        # Calculate exploitability score
        exploitability = self._calculate_exploitability(nodes, total_confidence, cvss_escalation)

        chain_id = f"chain_{objective}_{len(self.chains)}"

        return AttackChain(
            chain_id=chain_id,
            nodes=nodes,
            edges=edges,
            total_confidence=total_confidence,
            cvss_escalation=cvss_escalation,
            exploitability_score=exploitability,
            objective=objective,
            length=len(nodes),
        )

    def _calculate_exploitability(
        self,
        nodes: List[ChainNode],
        confidence: float,
        cvss_escalation: float,
    ) -> float:
        """
        Calculate exploitability score for chain.

        Formula: (avg_cvss * confidence * escalation_bonus) / chain_length
        """
        if not nodes:
            return 0.0

        avg_cvss = sum(n.cvss_score for n in nodes) / len(nodes)
        escalation_bonus = 1.0 + (cvss_escalation / 10.0)  # Max 2.0x bonus
        length_penalty = 1.0 / (1.0 + len(nodes) * 0.2)  # Longer chains = lower score

        score = (avg_cvss * confidence * escalation_bonus * length_penalty) / 10.0
        return min(score, 1.0)  # Cap at 1.0

    def _is_valid_chain(self, chain: AttackChain) -> bool:
        """Validate chain meets minimum requirements."""
        if chain.length < 2:
            return False

        if chain.total_confidence < self.CONFIDENCE_THRESHOLD:
            return False

        if chain.exploitability_score < 0.1:
            return False

        return True

    def _deduplicate_chains(self, chains: List[AttackChain]) -> List[AttackChain]:
        """Remove duplicate chains based on node sequence."""
        seen = set()
        unique = []

        for chain in chains:
            node_ids = tuple(n.node_id for n in chain.nodes)

            if node_ids not in seen:
                seen.add(node_ids)
                unique.append(chain)

        return unique

    def get_chains_by_objective(self, objective: str) -> List[AttackChain]:
        """Filter chains by objective."""
        return [c for c in self.chains if c.objective == objective]

    def get_high_risk_chains(self, threshold: float = 0.7) -> List[AttackChain]:
        """Get chains with exploitability above threshold."""
        return [c for c in self.chains if c.exploitability_score >= threshold]
