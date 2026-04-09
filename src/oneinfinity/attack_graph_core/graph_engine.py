"""
graph_engine.py — Central attack graph manager.
The AttackGraphEngine is the single source of truth for all discovered assets,
vulnerabilities, exploits, and relationships.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Any, Callable
import uuid
import time
import json
import logging
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class NodeType(str, Enum):
    TARGET       = "target"
    SUBDOMAIN    = "subdomain"
    URL          = "url"
    PARAMETER    = "parameter"
    API_ENDPOINT = "api_endpoint"
    CREDENTIAL   = "credential"
    VULNERABILITY = "vulnerability"
    EXPLOIT      = "exploit"
    IMPACT       = "impact"
    SERVICE      = "service"
    TECHNOLOGY   = "technology"
    AUTH_FLOW    = "auth_flow"
    # Token/session graph nodes
    TOKEN        = "token"      # JWT, API key, OAuth token
    SESSION      = "session"    # HTTP session, cookie-based session


class EdgeType(str, Enum):
    # Legacy / general
    HOSTS            = "hosts"
    EXPOSES          = "exposes"
    LEADS_TO         = "leads_to"
    ENABLES          = "enables"
    REQUIRES         = "requires"
    AUTHENTICATED_BY = "authenticated_by"
    DISCOVERED_VIA   = "discovered_via"
    CHAINED_WITH     = "chained_with"
    PART_OF          = "part_of"
    # Canonical structural edges (explicit, typed)
    HAS_TARGET       = "has_target"     # root → target
    HAS_ENDPOINT     = "has_endpoint"   # target/subdomain → url/api_endpoint
    HAS_PARAM        = "has_param"      # url/endpoint → parameter
    HAS_VULNERABILITY = "has_vulnerability"  # endpoint/param → vulnerability
    CALLS            = "calls"          # endpoint → endpoint (API call chain)
    AUTH_FOR         = "auth_for"       # token/credential → endpoint/service
    ISSUES_TOKEN     = "issues_token"   # auth_flow/service → token


@dataclass
class Node:
    id: str
    node_type: NodeType
    label: str
    properties: dict = field(default_factory=dict)
    severity: Optional[str] = None          # critical/high/medium/low/info
    risk_score: float = 0.0
    exploitable: bool = False
    validated: bool = False
    discovered_at: str = field(default_factory=lambda: str(time.time()))
    updated_at: str = field(default_factory=lambda: str(time.time()))
    source: str = ""                         # which engine added this node
    tags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "node_type": self.node_type.value if isinstance(self.node_type, NodeType) else self.node_type,
            "label": self.label,
            "properties": self.properties,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "exploitable": self.exploitable,
            "validated": self.validated,
            "discovered_at": self.discovered_at,
            "updated_at": self.updated_at,
            "source": self.source,
            "tags": self.tags,
        }

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at = str(time.time())


@dataclass
class Edge:
    id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""
    properties: dict = field(default_factory=dict)
    probability: float = 1.0               # 0.0-1.0 confidence
    weight: float = 1.0                    # for path scoring
    requires_auth: bool = False
    created_at: str = field(default_factory=lambda: str(time.time()))
    source_engine: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value if isinstance(self.edge_type, EdgeType) else self.edge_type,
            "label": self.label,
            "properties": self.properties,
            "probability": self.probability,
            "weight": self.weight,
            "requires_auth": self.requires_auth,
            "created_at": self.created_at,
            "source_engine": self.source_engine,
        }


class AttackGraphEngine:
    """
    Central attack graph manager. All other engines read from and write to this.
    Supports event subscriptions, BFS path finding, and full serialization.
    """

    def __init__(self, store=None):
        # store is an optional GraphStore instance for persistence
        self._store = store
        # Primary in-memory index: node_id -> Node
        self._nodes: dict[str, Node] = {}
        # Primary in-memory index: edge_id -> Edge
        self._edges: dict[str, Edge] = {}
        # Adjacency: node_id -> list of edge_ids going OUT
        self._adj_out: dict[str, list] = defaultdict(list)
        # Adjacency: node_id -> list of edge_ids coming IN
        self._adj_in: dict[str, list] = defaultdict(list)
        # Dedup index: (node_type, label) -> node_id
        self._label_index: dict[tuple, str] = {}
        # Edge dedup: (source_id, target_id, edge_type) -> edge_id
        self._edge_index: dict[tuple, str] = {}
        # Event subscribers: event_type -> list of callbacks
        self._subscribers: dict[str, list] = defaultdict(list)

        # Load from store if provided
        if self._store:
            self._load_from_store()

    def _load_from_store(self):
        """Load all nodes and edges from persistent store into memory."""
        try:
            nodes = self._store.load_all_nodes()
            for node in nodes:
                self._nodes[node.id] = node
                self._label_index[(node.node_type, node.label)] = node.id

            edges = self._store.load_all_edges()
            for edge in edges:
                self._edges[edge.id] = edge
                self._adj_out[edge.source_id].append(edge.id)
                self._adj_in[edge.target_id].append(edge.id)
                self._edge_index[(edge.source_id, edge.target_id, edge.edge_type)] = edge.id

            logger.info(f"Loaded {len(nodes)} nodes and {len(edges)} edges from store.")
        except Exception as e:
            logger.error(f"Failed to load from store: {e}")

    # -------------------------------------------------------------------------
    # Node operations
    # -------------------------------------------------------------------------

    def add_node(self, node_type: NodeType, label: str, properties: dict = None, **kwargs) -> "Node":
        """
        Create and add a new node. If a node with the same (type, label) already
        exists, returns the existing node without creating a duplicate.
        """
        if properties is None:
            properties = {}

        key = (node_type, label)
        if key in self._label_index:
            existing_id = self._label_index[key]
            existing = self._nodes[existing_id]
            # Merge any new properties
            if properties:
                existing.properties.update(properties)
                existing.updated_at = str(time.time())
                if self._store:
                    self._store.save_node(existing)
            return existing

        node_id = kwargs.pop("id", str(uuid.uuid4()))
        node = Node(
            id=node_id,
            node_type=node_type,
            label=label,
            properties=properties,
            **kwargs,
        )

        self._nodes[node.id] = node
        self._label_index[key] = node.id

        if self._store:
            self._store.save_node(node)

        self._emit("node_added", {"node": node.to_dict()})
        logger.debug(f"Added node [{node_type.value}] '{label}' id={node.id}")
        return node

    def get_node(self, node_id: str) -> Optional[Node]:
        """Retrieve a node by its ID."""
        node = self._nodes.get(node_id)
        if node is None and self._store:
            node = self._store.load_node(node_id)
            if node:
                self._nodes[node.id] = node
        return node

    def get_or_create_node(self, node_type: NodeType, label: str, **kwargs) -> tuple:
        """
        Returns (node, was_created). If a node with this (type, label) exists,
        returns it with was_created=False.
        """
        key = (node_type, label)
        if key in self._label_index:
            return self._nodes[self._label_index[key]], False
        node = self.add_node(node_type, label, **kwargs)
        return node, True

    def update_node(self, node_id: str, **kwargs) -> Optional[Node]:
        """Update node attributes in place."""
        node = self.get_node(node_id)
        if node is None:
            logger.warning(f"update_node: node {node_id} not found")
            return None

        node.update(**kwargs)

        if self._store:
            self._store.save_node(node)

        self._emit("node_updated", {"node": node.to_dict()})
        return node

    def delete_node(self, node_id: str) -> bool:
        """Delete node and cascade-delete all its incident edges."""
        if node_id not in self._nodes:
            return False

        node = self._nodes[node_id]
        key = (node.node_type, node.label)
        self._label_index.pop(key, None)

        # Collect edges to delete
        edge_ids_to_delete = set(self._adj_out.get(node_id, [])) | set(self._adj_in.get(node_id, []))
        for eid in edge_ids_to_delete:
            edge = self._edges.pop(eid, None)
            if edge:
                ekey = (edge.source_id, edge.target_id, edge.edge_type)
                self._edge_index.pop(ekey, None)
                if self._store:
                    self._store.delete_edge(eid)

        self._adj_out.pop(node_id, None)
        self._adj_in.pop(node_id, None)
        del self._nodes[node_id]

        if self._store:
            self._store.delete_node(node_id)

        logger.debug(f"Deleted node {node_id} and {len(edge_ids_to_delete)} incident edges")
        return True

    # -------------------------------------------------------------------------
    # Edge operations
    # -------------------------------------------------------------------------

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType, **kwargs) -> Optional[Edge]:
        """
        Add a directed edge from source to target. Deduplicates by
        (source_id, target_id, edge_type).
        """
        if source_id not in self._nodes:
            logger.warning(f"add_edge: source node {source_id} not found")
            return None
        if target_id not in self._nodes:
            logger.warning(f"add_edge: target node {target_id} not found")
            return None

        ekey = (source_id, target_id, edge_type)
        if ekey in self._edge_index:
            return self._edges[self._edge_index[ekey]]

        edge_id = kwargs.pop("id", str(uuid.uuid4()))
        edge = Edge(
            id=edge_id,
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            **kwargs,
        )

        self._edges[edge.id] = edge
        self._adj_out[source_id].append(edge.id)
        self._adj_in[target_id].append(edge.id)
        self._edge_index[ekey] = edge.id

        if self._store:
            self._store.save_edge(edge)

        self._emit("edge_added", {"edge": edge.to_dict()})
        logger.debug(f"Added edge [{edge_type.value}] {source_id} -> {target_id}")
        return edge

    def get_edges_from(self, node_id: str) -> list:
        """Return all edges originating from node_id."""
        return [self._edges[eid] for eid in self._adj_out.get(node_id, []) if eid in self._edges]

    def get_edges_to(self, node_id: str) -> list:
        """Return all edges terminating at node_id."""
        return [self._edges[eid] for eid in self._adj_in.get(node_id, []) if eid in self._edges]

    def get_neighbors(self, node_id: str, edge_type: EdgeType = None) -> list:
        """Return neighbor nodes reachable from node_id, optionally filtered by edge_type."""
        neighbors = []
        for edge in self.get_edges_from(node_id):
            if edge_type is not None and edge.edge_type != edge_type:
                continue
            neighbor = self.get_node(edge.target_id)
            if neighbor:
                neighbors.append(neighbor)
        return neighbors

    # -------------------------------------------------------------------------
    # Query / search
    # -------------------------------------------------------------------------

    def find_nodes(
        self,
        node_type: NodeType = None,
        label_contains: str = None,
        severity: str = None,
        exploitable: bool = None,
        tags: list = None,
    ) -> list:
        """Flexible node search with multiple optional filters."""
        results = []
        for node in self._nodes.values():
            if node_type is not None and node.node_type != node_type:
                continue
            if label_contains is not None and label_contains.lower() not in node.label.lower():
                continue
            if severity is not None and node.severity != severity:
                continue
            if exploitable is not None and node.exploitable != exploitable:
                continue
            if tags is not None:
                if not any(t in node.tags for t in tags):
                    continue
            results.append(node)
        return results

    def find_path(self, source_id: str, target_id: str, max_depth: int = 8) -> list:
        """
        BFS to find all paths from source to target up to max_depth.
        Returns list of node-lists.
        """
        all_paths = []
        # BFS queue: (current_node_id, path_so_far)
        queue = deque([(source_id, [source_id])])
        while queue:
            current_id, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for edge in self.get_edges_from(current_id):
                nid = edge.target_id
                if nid == target_id:
                    full_path = path + [nid]
                    node_path = [self.get_node(n) for n in full_path]
                    node_path = [n for n in node_path if n is not None]
                    all_paths.append(node_path)
                elif nid not in path:
                    queue.append((nid, path + [nid]))
        return all_paths

    def get_subgraph(self, root_node_id: str, depth: int = 3) -> dict:
        """
        BFS from root_node_id up to `depth` hops.
        Returns {"nodes": [...], "edges": [...]} serializable dict.
        """
        visited_nodes = set()
        visited_edges = set()
        queue = deque([(root_node_id, 0)])

        while queue:
            current_id, current_depth = queue.popleft()
            if current_id in visited_nodes:
                continue
            visited_nodes.add(current_id)
            if current_depth >= depth:
                continue
            for edge in self.get_edges_from(current_id):
                visited_edges.add(edge.id)
                if edge.target_id not in visited_nodes:
                    queue.append((edge.target_id, current_depth + 1))

        nodes_out = []
        for nid in visited_nodes:
            n = self.get_node(nid)
            if n:
                nodes_out.append(n.to_dict())

        edges_out = []
        for eid in visited_edges:
            e = self._edges.get(eid)
            if e:
                edges_out.append(e.to_dict())

        return {"nodes": nodes_out, "edges": edges_out}

    def get_stats(self) -> dict:
        """Return counts of nodes and edges broken down by type."""
        node_counts = defaultdict(int)
        for node in self._nodes.values():
            nt = node.node_type.value if isinstance(node.node_type, NodeType) else node.node_type
            node_counts[nt] += 1

        edge_counts = defaultdict(int)
        for edge in self._edges.values():
            et = edge.edge_type.value if isinstance(edge.edge_type, EdgeType) else edge.edge_type
            edge_counts[et] += 1

        exploitable_count = sum(1 for n in self._nodes.values() if n.exploitable)
        validated_count = sum(1 for n in self._nodes.values() if n.validated)
        vuln_nodes = [n for n in self._nodes.values() if n.node_type == NodeType.VULNERABILITY]
        severity_counts = defaultdict(int)
        for n in vuln_nodes:
            if n.severity:
                severity_counts[n.severity] += 1

        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_type": dict(node_counts),
            "edges_by_type": dict(edge_counts),
            "exploitable_nodes": exploitable_count,
            "validated_nodes": validated_count,
            "vulnerabilities_by_severity": dict(severity_counts),
        }

    def merge_graph(self, other: "AttackGraphEngine") -> dict:
        """
        Merge nodes and edges from `other` into this engine.
        New nodes/edges are added; existing ones are updated (properties merged).
        Returns {"nodes_added": int, "edges_added": int}.
        """
        nodes_added = 0
        edges_added = 0

        for node in other._nodes.values():
            key = (node.node_type, node.label)
            if key not in self._label_index:
                # New node — deep copy and insert
                new_node = Node(
                    id=node.id,
                    node_type=node.node_type,
                    label=node.label,
                    properties=dict(node.properties),
                    severity=node.severity,
                    risk_score=node.risk_score,
                    exploitable=node.exploitable,
                    validated=node.validated,
                    discovered_at=node.discovered_at,
                    updated_at=node.updated_at,
                    source=node.source,
                    tags=list(node.tags),
                )
                self._nodes[new_node.id] = new_node
                self._label_index[key] = new_node.id
                if self._store:
                    self._store.save_node(new_node)
                nodes_added += 1
            else:
                # Existing node — merge properties and upgrade severity/exploitable
                existing_id = self._label_index[key]
                existing = self._nodes[existing_id]
                if node.properties:
                    existing.properties.update(node.properties)
                if node.exploitable:
                    existing.exploitable = True
                if node.severity and (
                    not existing.severity or
                    _SEVERITY_ORDER.get(node.severity, 0) > _SEVERITY_ORDER.get(existing.severity, 0)
                ):
                    existing.severity = node.severity
                existing.updated_at = str(time.time())
                if self._store:
                    self._store.save_node(existing)

        for edge in other._edges.values():
            # Remap node IDs — source/target may have different IDs in this engine
            src_node = other._nodes.get(edge.source_id)
            tgt_node = other._nodes.get(edge.target_id)
            if src_node is None or tgt_node is None:
                continue

            src_key = (src_node.node_type, src_node.label)
            tgt_key = (tgt_node.node_type, tgt_node.label)
            mapped_src = self._label_index.get(src_key)
            mapped_tgt = self._label_index.get(tgt_key)
            if mapped_src is None or mapped_tgt is None:
                continue

            ekey = (mapped_src, mapped_tgt, edge.edge_type)
            if ekey not in self._edge_index:
                new_edge = Edge(
                    id=str(uuid.uuid4()),
                    source_id=mapped_src,
                    target_id=mapped_tgt,
                    edge_type=edge.edge_type,
                    label=edge.label,
                    properties=dict(edge.properties),
                    probability=edge.probability,
                    weight=edge.weight,
                    requires_auth=edge.requires_auth,
                    source_engine=edge.source_engine,
                )
                self._edges[new_edge.id] = new_edge
                self._adj_out[mapped_src].append(new_edge.id)
                self._adj_in[mapped_tgt].append(new_edge.id)
                self._edge_index[ekey] = new_edge.id
                if self._store:
                    self._store.save_edge(new_edge)
                edges_added += 1

        logger.info("merge_graph: +%d nodes, +%d edges", nodes_added, edges_added)
        return {"nodes_added": nodes_added, "edges_added": edges_added}

    def to_dict(self) -> dict:
        """Full serialization for frontend or export."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
            "stats": self.get_stats(),
            "exported_at": str(time.time()),
        }

    def from_dict(self, data: dict):
        """Deserialize from dict (replaces current graph state)."""
        self._nodes.clear()
        self._edges.clear()
        self._adj_out.clear()
        self._adj_in.clear()
        self._label_index.clear()
        self._edge_index.clear()

        for nd in data.get("nodes", []):
            node = Node(
                id=nd["id"],
                node_type=NodeType(nd["node_type"]),
                label=nd["label"],
                properties=nd.get("properties", {}),
                severity=nd.get("severity"),
                risk_score=nd.get("risk_score", 0.0),
                exploitable=nd.get("exploitable", False),
                validated=nd.get("validated", False),
                discovered_at=nd.get("discovered_at", str(time.time())),
                updated_at=nd.get("updated_at", str(time.time())),
                source=nd.get("source", ""),
                tags=nd.get("tags", []),
            )
            self._nodes[node.id] = node
            self._label_index[(node.node_type, node.label)] = node.id

        for ed in data.get("edges", []):
            edge = Edge(
                id=ed["id"],
                source_id=ed["source_id"],
                target_id=ed["target_id"],
                edge_type=EdgeType(ed["edge_type"]),
                label=ed.get("label", ""),
                properties=ed.get("properties", {}),
                probability=ed.get("probability", 1.0),
                weight=ed.get("weight", 1.0),
                requires_auth=ed.get("requires_auth", False),
                created_at=ed.get("created_at", str(time.time())),
                source_engine=ed.get("source_engine", ""),
            )
            self._edges[edge.id] = edge
            self._adj_out[edge.source_id].append(edge.id)
            self._adj_in[edge.target_id].append(edge.id)
            self._edge_index[(edge.source_id, edge.target_id, edge.edge_type)] = edge.id

        logger.info(f"Loaded {len(self._nodes)} nodes, {len(self._edges)} edges from dict")

    # -------------------------------------------------------------------------
    # Event system
    # -------------------------------------------------------------------------

    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to graph events: node_added, edge_added, node_updated."""
        self._subscribers[event_type].append(callback)

    def _emit(self, event_type: str, data: dict):
        """Emit an event to all registered subscribers."""
        for cb in self._subscribers.get(event_type, []):
            try:
                cb(event_type, data)
            except Exception as e:
                logger.error(f"Event subscriber error [{event_type}]: {e}")


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_global_engine: Optional[AttackGraphEngine] = None


def get_engine() -> AttackGraphEngine:
    """Return (or lazily create) the global AttackGraphEngine singleton."""
    global _global_engine
    if _global_engine is None:
        try:
            try:
                from oneinfinity.core.graph_neo4j_bootstrap import (
                    create_default_graph_store,
                    maybe_merge_neo4j_into_store,
                )
                store, _ = create_default_graph_store()
            except Exception:
                from .graph_store import GraphStore
                store = GraphStore()
            store.initialize()
            try:
                from oneinfinity.core.graph_neo4j_bootstrap import maybe_merge_neo4j_into_store
                maybe_merge_neo4j_into_store(store)
            except Exception:
                pass
            _global_engine = AttackGraphEngine(store=store)
            logger.info("Global AttackGraphEngine initialised (SQLite + optional Neo4j sync).")
        except Exception as e:
            logger.warning(f"Could not initialise GraphStore, running in-memory only: {e}")
            _global_engine = AttackGraphEngine()
    return _global_engine
