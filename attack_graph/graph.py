"""
Attack Graph — Core Data Structure
====================================
Pure-Python adjacency-list graph. No external dependencies.

Node types  : TARGET | SUBDOMAIN | HOST | ENDPOINT | SERVICE
              VULNERABILITY | CREDENTIAL | CLOUD_ASSET | NETWORK_RANGE

Edge types  : RESOLVES_TO | HOSTS | HAS_ENDPOINT | EXPOSES_PORT
              HAS_VULN | ENABLES | ESCALATES_TO | REACHES | TRUSTS
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class NodeType(str, Enum):
    TARGET         = "target"
    SUBDOMAIN      = "subdomain"
    HOST           = "host"
    ENDPOINT       = "endpoint"
    SERVICE        = "service"
    VULNERABILITY  = "vulnerability"
    CREDENTIAL     = "credential"
    CLOUD_ASSET    = "cloud_asset"
    NETWORK_RANGE  = "network_range"


class EdgeType(str, Enum):
    RESOLVES_TO  = "resolves_to"    # subdomain → host (DNS)
    HOSTS        = "hosts"          # host → endpoint
    HAS_ENDPOINT = "has_endpoint"   # target → endpoint
    EXPOSES_PORT = "exposes_port"   # host → service
    HAS_VULN     = "has_vuln"       # endpoint/host → vulnerability
    ENABLES      = "enables"        # vuln A enables attack on B
    ESCALATES_TO = "escalates_to"   # vuln → higher-severity vuln
    REACHES      = "reaches"        # attacker can reach node
    TRUSTS       = "trusts"         # host A trusts host B (SSRF, CORS)
    EXPOSES      = "exposes"        # vuln exposes credential/data


# Severity → numeric weight (lower = more valuable attack step)
SEVERITY_WEIGHT = {
    "critical": 1,
    "high":     2,
    "medium":   4,
    "low":      8,
    "info":     16,
}


@dataclass
class Node:
    node_id: str
    node_type: NodeType
    label: str
    properties: dict = field(default_factory=dict)
    # Attack-graph attributes
    severity: str = "info"       # highest vuln severity associated
    exploitable: bool = False
    discovered_at: float = field(default_factory=time.time)
    # Computed by analyzer
    criticality_score: float = 0.0
    reachable_from_internet: bool = True

    def weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity, 16)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["node_type"] = self.node_type.value
        return d


@dataclass
class Edge:
    edge_id: str
    src: str           # node_id
    dst: str           # node_id
    edge_type: EdgeType
    label: str = ""
    weight: float = 1.0
    properties: dict = field(default_factory=dict)
    confidence: str = "medium"   # low | medium | high

    def to_dict(self) -> dict:
        d = asdict(self)
        d["edge_type"] = self.edge_type.value
        return d


class AttackGraph:
    """
    Directed weighted graph representing attack surface and exploitation paths.

    Internal structure:
      _nodes: dict[node_id, Node]
      _adj:   dict[node_id, list[Edge]]   (outgoing edges)
      _radj:  dict[node_id, list[Edge]]   (incoming edges — for reverse traversal)
    """

    def __init__(self, target: str):
        self.target = target
        self._nodes: dict[str, Node] = {}
        self._adj:  dict[str, list[Edge]] = {}   # src → edges
        self._radj: dict[str, list[Edge]] = {}   # dst → edges
        self._edge_set: set[str] = set()

        # Add root target node
        self.add_node(Node(
            node_id=f"target:{target}",
            node_type=NodeType.TARGET,
            label=target,
        ))

    # ── Node operations ───────────────────────────────────────────────────────

    def add_node(self, node: Node) -> Node:
        if node.node_id not in self._nodes:
            self._nodes[node.node_id] = node
            self._adj[node.node_id] = []
            self._radj[node.node_id] = []
        else:
            # Merge: update severity if higher
            existing = self._nodes[node.node_id]
            if SEVERITY_WEIGHT.get(node.severity, 16) < SEVERITY_WEIGHT.get(existing.severity, 16):
                existing.severity = node.severity
            existing.properties.update(node.properties)
        return self._nodes[node.node_id]

    def get_node(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    def nodes_by_type(self, ntype: NodeType) -> list[Node]:
        return [n for n in self._nodes.values() if n.node_type == ntype]

    def vuln_nodes(self) -> list[Node]:
        return self.nodes_by_type(NodeType.VULNERABILITY)

    def exploitable_nodes(self) -> list[Node]:
        return [n for n in self._nodes.values() if n.exploitable]

    # ── Edge operations ───────────────────────────────────────────────────────

    def add_edge(self, edge: Edge) -> bool:
        """Add directed edge. Returns False if duplicate."""
        key = f"{edge.src}→{edge.dst}:{edge.edge_type}"
        if key in self._edge_set:
            return False
        # Ensure nodes exist
        for nid in (edge.src, edge.dst):
            if nid not in self._nodes:
                return False
        self._edge_set.add(key)
        self._adj[edge.src].append(edge)
        self._radj[edge.dst].append(edge)
        return True

    def edges_from(self, node_id: str) -> list[Edge]:
        return self._adj.get(node_id, [])

    def edges_to(self, node_id: str) -> list[Edge]:
        return self._radj.get(node_id, [])

    def all_edges(self) -> list[Edge]:
        return [e for edges in self._adj.values() for e in edges]

    # ── Convenience builders ──────────────────────────────────────────────────

    def add_subdomain(self, fqdn: str) -> Node:
        n = Node(
            node_id=f"subdomain:{fqdn}",
            node_type=NodeType.SUBDOMAIN,
            label=fqdn,
        )
        node = self.add_node(n)
        eid = f"e:target→sub:{fqdn}"
        self.add_edge(Edge(
            edge_id=eid,
            src=f"target:{self.target}",
            dst=node.node_id,
            edge_type=EdgeType.RESOLVES_TO,
            label="resolves",
            weight=1.0,
        ))
        return node

    def add_host(self, url: str, status: int = 200,
                 tech: list = None, title: str = "") -> Node:
        n = Node(
            node_id=f"host:{url}",
            node_type=NodeType.HOST,
            label=url,
            properties={"status": status, "tech": tech or [], "title": title},
        )
        return self.add_node(n)

    def add_service(self, host: str, port: int, service: str,
                    version: str = "") -> Node:
        nid = f"service:{host}:{port}"
        n = Node(
            node_id=nid,
            node_type=NodeType.SERVICE,
            label=f"{service}:{port}",
            properties={"host": host, "port": port,
                        "service": service, "version": version},
        )
        node = self.add_node(n)
        host_nid = f"host:https://{host}"
        if host_nid in self._nodes:
            self.add_edge(Edge(
                edge_id=f"e:{host_nid}→{nid}",
                src=host_nid, dst=nid,
                edge_type=EdgeType.EXPOSES_PORT,
                label=str(port), weight=1.0,
            ))
        return node

    def add_endpoint(self, url: str, method: str = "GET",
                     params: list = None) -> Node:
        nid = f"endpoint:{method}:{url}"
        n = Node(
            node_id=nid,
            node_type=NodeType.ENDPOINT,
            label=f"{method} {url}",
            properties={"url": url, "method": method, "params": params or []},
        )
        return self.add_node(n)

    def add_vulnerability(self, vuln_id: str, vuln_type: str,
                          host: str, endpoint: str,
                          severity: str, evidence: str = "",
                          parameter: str = "", confidence: str = "medium",
                          finding_db_id: int = None) -> Node:
        nid = f"vuln:{vuln_id}"
        n = Node(
            node_id=nid,
            node_type=NodeType.VULNERABILITY,
            label=f"{vuln_type} @ {endpoint}",
            severity=severity,
            exploitable=severity in ("critical", "high"),
            properties={
                "vuln_type": vuln_type,
                "host": host,
                "endpoint": endpoint,
                "parameter": parameter,
                "evidence": evidence[:200],
                "confidence": confidence,
                "finding_db_id": finding_db_id,
            },
        )
        node = self.add_node(n)

        # Connect: host → vuln
        host_nid = f"host:https://{host}" if not host.startswith("http") else f"host:{host}"
        if host_nid in self._nodes:
            self.add_edge(Edge(
                edge_id=f"e:{host_nid}→{nid}",
                src=host_nid, dst=nid,
                edge_type=EdgeType.HAS_VULN,
                label=severity,
                weight=float(SEVERITY_WEIGHT.get(severity, 8)),
                confidence=confidence,
            ))
        return node

    def add_credential(self, cred_id: str, cred_type: str,
                       value_hint: str, source_node: str) -> Node:
        nid = f"cred:{cred_id}"
        n = Node(
            node_id=nid,
            node_type=NodeType.CREDENTIAL,
            label=f"{cred_type} credential",
            severity="critical",
            exploitable=True,
            properties={"type": cred_type, "hint": value_hint[:30]},
        )
        node = self.add_node(n)
        if source_node in self._nodes:
            self.add_edge(Edge(
                edge_id=f"e:{source_node}→{nid}",
                src=source_node, dst=nid,
                edge_type=EdgeType.EXPOSES,
                label="exposes credential",
                weight=1.0,
            ))
        return node

    # ── Graph stats ───────────────────────────────────────────────────────────

    def stats(self) -> dict:
        nodes = list(self._nodes.values())
        by_type = {}
        for n in nodes:
            by_type[n.node_type.value] = by_type.get(n.node_type.value, 0) + 1
        by_sev = {}
        for n in self.vuln_nodes():
            by_sev[n.severity] = by_sev.get(n.severity, 0) + 1
        return {
            "target": self.target,
            "total_nodes": len(nodes),
            "total_edges": len(self.all_edges()),
            "nodes_by_type": by_type,
            "vulns_by_severity": by_sev,
            "exploitable_nodes": len(self.exploitable_nodes()),
        }

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self.all_edges()],
            "stats": self.stats(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save(self, path: str):
        with open(path, "w") as f:
            f.write(self.to_json())

    @classmethod
    def load(cls, path: str) -> "AttackGraph":
        with open(path) as f:
            data = json.load(f)
        g = cls(data["target"])
        for nd in data.get("nodes", []):
            nd["node_type"] = NodeType(nd["node_type"])
            nd.pop("criticality_score", None)
            nd.pop("reachable_from_internet", None)
            node = Node(**nd)
            g._nodes[node.node_id] = node
            g._adj.setdefault(node.node_id, [])
            g._radj.setdefault(node.node_id, [])
        for ed in data.get("edges", []):
            ed["edge_type"] = EdgeType(ed["edge_type"])
            edge = Edge(**ed)
            key = f"{edge.src}→{edge.dst}:{edge.edge_type}"
            g._edge_set.add(key)
            g._adj.setdefault(edge.src, []).append(edge)
            g._radj.setdefault(edge.dst, []).append(edge)
        return g
