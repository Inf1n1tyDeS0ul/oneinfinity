"""
graph_store.py — Dual-mode storage: in-memory dict (fast analysis) + PG persistence.
GraphStore delegates to InMemoryStore for speed and PostgreSQL for durability.
PostgreSQL is a hard requirement.
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional

from path_manager import attack_graph_db_path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enum-safe helpers
# ---------------------------------------------------------------------------

def _enum_to_str(value) -> str:
    """
    Safely convert any value to its canonical string form.

    Handles three cases:
    1. Standard Enum  → returns .value  (e.g. NodeType.vulnerability → "vulnerability")
    2. Repr strings   → strips angle-bracket repr
                        "<NodeType.vulnerability: 'vulnerability'>" → "vulnerability"
    3. Plain string   → returned as-is (lowercased)
    """
    if hasattr(value, "value"):          # Enum instance
        return str(value.value).lower()
    s = str(value).lower()
    # Handle Python repr format: <classname.member: 'value'>
    if s.startswith("<") and ": '" in s:
        try:
            return s.split(": '")[1].rstrip("'>").strip()
        except IndexError:
            pass
    return s


# ---------------------------------------------------------------------------
# InMemoryStore — fast dict-based backend
# ---------------------------------------------------------------------------

class InMemoryStore:
    """Pure in-memory storage for nodes and edges."""

    def __init__(self):
        self._nodes: dict = {}   # id -> dict
        self._edges: dict = {}   # id -> dict

    def save_node(self, node_dict: dict):
        self._nodes[node_dict["id"]] = dict(node_dict)

    def save_edge(self, edge_dict: dict):
        self._edges[edge_dict["id"]] = dict(edge_dict)

    def load_node(self, node_id: str) -> Optional[dict]:
        return self._nodes.get(node_id)

    def load_edge(self, edge_id: str) -> Optional[dict]:
        return self._edges.get(edge_id)

    def load_all_nodes(self, node_type: str = None) -> list:
        if node_type is None:
            return list(self._nodes.values())
        return [n for n in self._nodes.values() if n.get("node_type") == node_type]

    def load_all_edges(self) -> list:
        return list(self._edges.values())

    def delete_node(self, node_id: str):
        self._nodes.pop(node_id, None)

    def delete_edge(self, edge_id: str):
        self._edges.pop(edge_id, None)

    def search_nodes(self, query: str, node_type: str = None) -> list:
        q = query.lower()
        results = []
        for n in self._nodes.values():
            if node_type and n.get("node_type") != node_type:
                continue
            label = n.get("label", "").lower()
            props = json.dumps(n.get("properties", {})).lower()
            if q in label or q in props:
                results.append(n)
        return results

    def get_node_by_label(self, label: str, node_type: str) -> Optional[dict]:
        for n in self._nodes.values():
            if n.get("label") == label and n.get("node_type") == node_type:
                return n
        return None

    def count_nodes(self) -> int:
        return len(self._nodes)

    def count_edges(self) -> int:
        return len(self._edges)

    def clear(self):
        self._nodes.clear()
        self._edges.clear()


# ---------------------------------------------------------------------------
# PGStore — durable persistence backend (PostgreSQL only)
# ---------------------------------------------------------------------------

class SQLiteStore:
    """
    PostgreSQL-backed persistence for nodes and edges.
    Class name kept as SQLiteStore for compatibility with GraphStore references.
    PostgreSQL is a hard requirement — raises RuntimeError if unavailable.
    """

    def __init__(self, db_path: str):
        pass  # db_path kept for API compatibility only

    @staticmethod
    def _get_pg():
        """Return DBManager in PG mode, or raise if unavailable."""
        try:
            from core.db_manager import get_db_manager_sync
            mgr = get_db_manager_sync()
            if mgr is not None and mgr.mode in ("postgres", "distributed"):
                return mgr
        except Exception as exc:
            raise RuntimeError(f"PostgreSQL is required but DBManager unavailable: {exc}") from exc
        raise RuntimeError(
            "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
        )

    def initialize(self):
        """Schema already applied via db/schema.sql at startup."""
        logger.info("SQLiteStore.initialize: PG mode — schema managed by db/schema.sql")

    # ── Row conversion helpers (shared by both backends) ───────────────────

    def _node_to_row(self, node_dict: dict) -> tuple:
        return (
            node_dict["id"],
            _enum_to_str(node_dict.get("node_type", "")),
            node_dict.get("label", ""),
            json.dumps(node_dict.get("properties", {})),
            node_dict.get("severity"),
            node_dict.get("risk_score", 0.0),
            int(node_dict.get("exploitable", False)),
            int(node_dict.get("validated", False)),
            node_dict.get("discovered_at", str(time.time())),
            node_dict.get("updated_at", str(time.time())),
            node_dict.get("source", ""),
            json.dumps(node_dict.get("tags", [])),
        )

    def _row_to_node(self, row: dict) -> dict:
        return {
            "id": row["id"],
            "node_type": row["node_type"],
            "label": row["label"],
            "properties": json.loads(row["properties_json"] or "{}"),
            "severity": row["severity"],
            "risk_score": row["risk_score"],
            "exploitable": bool(row["exploitable"]),
            "validated": bool(row["validated"]),
            "discovered_at": row["discovered_at"],
            "updated_at": row["updated_at"],
            "source": row["source"],
            "tags": json.loads(row["tags_json"] or "[]"),
        }

    def _edge_to_row(self, edge_dict: dict) -> tuple:
        return (
            edge_dict["id"],
            edge_dict.get("source_id", ""),
            edge_dict.get("target_id", ""),
            edge_dict.get("edge_type", ""),
            edge_dict.get("label", ""),
            json.dumps(edge_dict.get("properties", {})),
            edge_dict.get("probability", 1.0),
            edge_dict.get("weight", 1.0),
            int(edge_dict.get("requires_auth", False)),
            edge_dict.get("created_at", str(time.time())),
            edge_dict.get("source_engine", ""),
        )

    def _row_to_edge(self, row) -> dict:
        return {
            "id": row["id"],
            "source_id": row["source_id"],
            "target_id": row["target_id"],
            "edge_type": row["edge_type"],
            "label": row["label"],
            "properties": json.loads(row["properties_json"] or "{}"),
            "probability": row["probability"],
            "weight": row["weight"],
            "requires_auth": bool(row["requires_auth"]),
            "created_at": row["created_at"],
            "source_engine": row["source_engine"],
        }

    # ── Write operations ────────────────────────────────────────────────────

    def save_node(self, node_dict: dict):
        self._get_pg().sync_pg_execute_write(
            """INSERT INTO graph_nodes
                   (id, node_type, label, properties_json, severity, risk_score,
                    exploitable, validated, discovered_at, updated_at, source, tags_json)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (id) DO UPDATE SET
                   node_type=EXCLUDED.node_type, label=EXCLUDED.label,
                   properties_json=EXCLUDED.properties_json, severity=EXCLUDED.severity,
                   risk_score=EXCLUDED.risk_score, exploitable=EXCLUDED.exploitable,
                   validated=EXCLUDED.validated, discovered_at=EXCLUDED.discovered_at,
                   updated_at=EXCLUDED.updated_at, source=EXCLUDED.source,
                   tags_json=EXCLUDED.tags_json""",
            self._node_to_row(node_dict),
        )

    def save_edge(self, edge_dict: dict):
        self._get_pg().sync_pg_execute_write(
            """INSERT INTO graph_edges
                   (id, source_id, target_id, edge_type, label, properties_json,
                    probability, weight, requires_auth, created_at, source_engine)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (id) DO UPDATE SET
                   source_id=EXCLUDED.source_id, target_id=EXCLUDED.target_id,
                   edge_type=EXCLUDED.edge_type, label=EXCLUDED.label,
                   properties_json=EXCLUDED.properties_json, probability=EXCLUDED.probability,
                   weight=EXCLUDED.weight, requires_auth=EXCLUDED.requires_auth,
                   created_at=EXCLUDED.created_at, source_engine=EXCLUDED.source_engine""",
            self._edge_to_row(edge_dict),
        )

    def delete_node(self, node_id: str):
        self._get_pg().sync_pg_execute_write(
            "DELETE FROM graph_nodes WHERE id = %s", (node_id,)
        )

    def delete_edge(self, edge_id: str):
        self._get_pg().sync_pg_execute_write(
            "DELETE FROM graph_edges WHERE id = %s", (edge_id,)
        )

    # ── Read operations ─────────────────────────────────────────────────────

    def load_node(self, node_id: str) -> Optional[dict]:
        rows = self._get_pg().sync_pg_execute_read(
            "SELECT * FROM graph_nodes WHERE id = %s", (node_id,)
        )
        return self._row_to_node(rows[0]) if rows else None

    def load_edge(self, edge_id: str) -> Optional[dict]:
        rows = self._get_pg().sync_pg_execute_read(
            "SELECT * FROM graph_edges WHERE id = %s", (edge_id,)
        )
        return self._row_to_edge(rows[0]) if rows else None

    def load_all_nodes(self, node_type: str = None) -> list:
        if node_type:
            rows = self._get_pg().sync_pg_execute_read(
                "SELECT * FROM graph_nodes WHERE node_type = %s", (node_type,)
            )
        else:
            rows = self._get_pg().sync_pg_execute_read("SELECT * FROM graph_nodes", ())
        return [self._row_to_node(r) for r in rows]

    def load_all_edges(self) -> list:
        rows = self._get_pg().sync_pg_execute_read("SELECT * FROM graph_edges", ())
        return [self._row_to_edge(r) for r in rows]

    def search_nodes(self, query: str, node_type: str = None) -> list:
        q = f"%{query}%"
        if node_type:
            rows = self._get_pg().sync_pg_execute_read(
                "SELECT * FROM graph_nodes WHERE (label LIKE %s OR properties_json LIKE %s) AND node_type = %s",
                (q, q, node_type),
            )
        else:
            rows = self._get_pg().sync_pg_execute_read(
                "SELECT * FROM graph_nodes WHERE label LIKE %s OR properties_json LIKE %s",
                (q, q),
            )
        return [self._row_to_node(r) for r in rows]

    def get_node_by_label(self, label: str, node_type: str) -> Optional[dict]:
        rows = self._get_pg().sync_pg_execute_read(
            "SELECT * FROM graph_nodes WHERE label = %s AND node_type = %s",
            (label, node_type),
        )
        return self._row_to_node(rows[0]) if rows else None

    def count_nodes(self) -> int:
        rows = self._get_pg().sync_pg_execute_read("SELECT COUNT(*) AS cnt FROM graph_nodes", ())
        return rows[0]["cnt"] if rows else 0

    def count_edges(self) -> int:
        rows = self._get_pg().sync_pg_execute_read("SELECT COUNT(*) AS cnt FROM graph_edges", ())
        return rows[0]["cnt"] if rows else 0


# ---------------------------------------------------------------------------
# GraphStore — facade over InMemoryStore + SQLiteStore
# ---------------------------------------------------------------------------

class GraphStore:
    """
    Dual-mode graph store. Writes go to both memory and PostgreSQL.
    Reads prefer memory; fall back to PostgreSQL on miss.

    Optional ``sync_backend`` (e.g. Neo4j batched write-through) receives the same
    node/edge dicts after local persistence — failures are logged and never break PG.
    """

    def __init__(
        self,
        db_path: str = str(attack_graph_db_path()),
        use_memory: bool = True,
        sync_backend=None,
    ):
        self._db_path = str(Path(db_path).expanduser())
        self._use_memory = use_memory
        self._memory = InMemoryStore() if use_memory else None
        self._sqlite = SQLiteStore(self._db_path)
        self._sync_backend = sync_backend
        self._initialised = False

    def initialize(self):
        """Warm memory cache from PostgreSQL."""
        self._sqlite.initialize()
        if self._use_memory and self._memory:
            # Warm memory cache from SQLite
            for nd in self._sqlite.load_all_nodes():
                self._memory.save_node(nd)
            for ed in self._sqlite.load_all_edges():
                self._memory.save_edge(ed)
        self._initialised = True
        logger.info("GraphStore initialised.")

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def save_node(self, node):
        """Accept a Node object or dict, persist to both stores."""
        nd = node.to_dict() if hasattr(node, "to_dict") else node
        if self._use_memory:
            self._memory.save_node(nd)
        self._sqlite.save_node(nd)
        if self._sync_backend:
            try:
                self._sync_backend.on_node_saved(nd)
            except Exception as exc:
                logger.debug("GraphStore sync_backend on_node_saved: %s", exc)

    def load_node(self, node_id: str):
        """Load a Node; prefer memory, fall back to SQLite."""
        if self._use_memory:
            nd = self._memory.load_node(node_id)
            if nd:
                return self._dict_to_node(nd)
        nd = self._sqlite.load_node(node_id)
        if nd:
            if self._use_memory:
                self._memory.save_node(nd)
            return self._dict_to_node(nd)
        return None

    def load_all_nodes(self, node_type=None) -> list:
        """Load all nodes, optionally filtered by NodeType."""
        nt_str = node_type.value if hasattr(node_type, "value") else node_type
        if self._use_memory:
            raw = self._memory.load_all_nodes(nt_str)
        else:
            raw = self._sqlite.load_all_nodes(nt_str)
        return [self._dict_to_node(nd) for nd in raw]

    def delete_node(self, node_id: str):
        if self._use_memory:
            self._memory.delete_node(node_id)
        self._sqlite.delete_node(node_id)
        if self._sync_backend:
            try:
                self._sync_backend.on_node_deleted(node_id)
            except Exception as exc:
                logger.debug("GraphStore sync_backend on_node_deleted: %s", exc)

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def save_edge(self, edge):
        """Accept an Edge object or dict."""
        ed = edge.to_dict() if hasattr(edge, "to_dict") else edge
        if self._use_memory:
            self._memory.save_edge(ed)
        self._sqlite.save_edge(ed)
        if self._sync_backend:
            try:
                self._sync_backend.on_edge_saved(ed)
            except Exception as exc:
                logger.debug("GraphStore sync_backend on_edge_saved: %s", exc)

    def load_edge(self, edge_id: str):
        if self._use_memory:
            ed = self._memory.load_edge(edge_id)
            if ed:
                return self._dict_to_edge(ed)
        ed = self._sqlite.load_edge(edge_id)
        if ed:
            if self._use_memory:
                self._memory.save_edge(ed)
            return self._dict_to_edge(ed)
        return None

    def load_all_edges(self) -> list:
        if self._use_memory:
            raw = self._memory.load_all_edges()
        else:
            raw = self._sqlite.load_all_edges()
        return [self._dict_to_edge(ed) for ed in raw]

    def delete_edge(self, edge_id: str):
        if self._use_memory:
            self._memory.delete_edge(edge_id)
        self._sqlite.delete_edge(edge_id)
        if self._sync_backend:
            try:
                self._sync_backend.on_edge_deleted(edge_id)
            except Exception as exc:
                logger.debug("GraphStore sync_backend on_edge_deleted: %s", exc)

    def flush_sync_backend(self):
        """Flush optional secondary graph backend (e.g. batched Neo4j writes)."""
        if self._sync_backend:
            try:
                self._sync_backend.flush()
            except Exception as exc:
                logger.debug("GraphStore flush_sync_backend: %s", exc)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search_nodes(self, query: str, node_type=None) -> list:
        nt_str = node_type.value if hasattr(node_type, "value") else node_type
        if self._use_memory:
            raw = self._memory.search_nodes(query, nt_str)
        else:
            raw = self._sqlite.search_nodes(query, nt_str)
        return [self._dict_to_node(nd) for nd in raw]

    def get_node_by_label(self, label: str, node_type) -> "Optional[Node]":
        nt_str = node_type.value if hasattr(node_type, "value") else node_type
        if self._use_memory:
            nd = self._memory.get_node_by_label(label, nt_str)
            if nd:
                return self._dict_to_node(nd)
        nd = self._sqlite.get_node_by_label(label, nt_str)
        if nd:
            if self._use_memory:
                self._memory.save_node(nd)
            return self._dict_to_node(nd)
        return None

    # ------------------------------------------------------------------
    # Stats / Export / Import
    # ------------------------------------------------------------------

    def get_graph_stats(self) -> dict:
        if self._use_memory:
            n = self._memory.count_nodes()
            e = self._memory.count_edges()
        else:
            n = self._sqlite.count_nodes()
            e = self._sqlite.count_edges()
        avg_degree = round((2 * e) / n, 4) if n > 0 else 0.0
        return {
            "total_nodes": n,
            "total_edges": e,
            "avg_degree": avg_degree,
        }

    def export_json(self, path: str):
        """Export full graph to JSON file."""
        nodes = self._sqlite.load_all_nodes()
        edges = self._sqlite.load_all_edges()
        data = {
            "nodes": nodes,
            "edges": edges,
            "exported_at": str(time.time()),
        }
        out_path = Path(path).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Graph exported to {out_path} ({len(nodes)} nodes, {len(edges)} edges)")

    def import_json(self, path: str):
        """Import graph from JSON file (merges with existing data)."""
        in_path = Path(path).expanduser()
        with open(in_path, "r") as f:
            data = json.load(f)
        for nd in data.get("nodes", []):
            self.save_node(nd)
        for ed in data.get("edges", []):
            self.save_edge(ed)
        self.flush_sync_backend()
        logger.info(f"Imported {len(data.get('nodes', []))} nodes and {len(data.get('edges', []))} edges from {in_path}")

    # ------------------------------------------------------------------
    # Private helpers — dict <-> Node/Edge reconstruction
    # ------------------------------------------------------------------

    @staticmethod
    def _dict_to_node(nd: dict):
        """Reconstruct a Node dataclass from a plain dict."""
        from .graph_engine import Node, NodeType
        # Normalise — handles plain strings, uppercase, and Enum repr strings
        _nt_raw = _enum_to_str(nd.get("node_type") or "target")
        # Guard: fallback to "target" if the normalised value is not a valid NodeType member
        try:
            _node_type = NodeType(_nt_raw)
        except (ValueError, KeyError):
            _node_type = NodeType("target")
        return Node(
            id=nd["id"],
            node_type=_node_type,
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

    @staticmethod
    def _dict_to_edge(ed: dict):
        """Reconstruct an Edge dataclass from a plain dict."""
        from .graph_engine import Edge, EdgeType
        # Normalise to lowercase for enum safety
        _et_raw = (ed.get("edge_type") or "leads_to").lower()
        return Edge(
            id=ed["id"],
            source_id=ed["source_id"],
            target_id=ed["target_id"],
            edge_type=EdgeType(_et_raw),
            label=ed.get("label", ""),
            properties=ed.get("properties", {}),
            probability=ed.get("probability", 1.0),
            weight=ed.get("weight", 1.0),
            requires_auth=ed.get("requires_auth", False),
            created_at=ed.get("created_at", str(time.time())),
            source_engine=ed.get("source_engine", ""),
        )
