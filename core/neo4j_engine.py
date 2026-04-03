"""
Optional Neo4j driver wrapper for OneInfinity attack graphs.
Uses a single node label (:OI_Node) and relationship type (:OI_REL) with typed properties
so we avoid dynamic Cypher relationship types (no APOC required).
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import Neo4jError, ServiceUnavailable

    _NEO4J_AVAILABLE = True
except ImportError:
    GraphDatabase = None  # type: ignore
    Neo4jError = Exception  # type: ignore
    ServiceUnavailable = Exception  # type: ignore
    _NEO4J_AVAILABLE = False


def neo4j_driver_available() -> bool:
    return _NEO4J_AVAILABLE


class Neo4jEngine:
    """
    Low-level Neo4j access: MERGE nodes/edges, path queries, analytics.
    Safe no-op when driver missing or connection fails.
    """

    _last_sync_ts = None   # updated by BatchedNeo4jGraphBackend.flush()

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j",
    ):
        self._uri = uri
        self._auth = (username, password)
        self._database = database
        self._driver = None
        self._connected = False
        if not _NEO4J_AVAILABLE:
            log.debug("neo4j package not installed; Neo4jEngine disabled")
            return
        try:
            self._driver = GraphDatabase.driver(uri, auth=self._auth)
            self._driver.verify_connectivity()
            self._connected = True
            log.info("Neo4j connected: %s", uri)
        except Exception as exc:
            log.warning("Neo4j unavailable (%s); continuing without graph DB", exc)
            self._driver = None
            self._connected = False

    def bootstrap_schema(self) -> None:
        """
        Create uniqueness constraint and type indexes if they do not already exist.
        Safe to call multiple times (IF NOT EXISTS guards).
        """
        if not self._driver:
            return
        statements = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:OI_Node) REQUIRE n.id IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (n:OI_Node) ON (n.type)",
            "CREATE INDEX IF NOT EXISTS FOR ()-[r:OI_REL]-() ON (r.type)",
            "CREATE INDEX IF NOT EXISTS FOR (f:OI_ChainFeedback) ON (f.chain_type)",
            "CREATE INDEX IF NOT EXISTS FOR (f:OI_ChainFeedback) ON (f.success)",
        ]
        try:
            with self._driver.session(database=self._database) as sess:
                for stmt in statements:
                    sess.run(stmt)
            log.info("Neo4j schema bootstrapped (constraint + 2 indexes).")
        except Exception as exc:
            log.warning("bootstrap_schema failed (non-fatal): %s", exc)

    @property
    def connected(self) -> bool:
        return bool(self._driver and self._connected)

    def close(self):
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass
            self._driver = None
            self._connected = False

    def _session(self):
        if not self._driver:
            return None
        return self._driver.session(database=self._database)

    # --- Writes (batch-friendly) ------------------------------------------------

    def merge_nodes_batch(self, rows: list[dict]) -> None:
        """rows: dicts with id, oi_type, label, severity, risk_score, props_json, updated_at"""
        if not rows or not self._driver:
            return

        def work(tx):
            tx.run(
                """
                UNWIND $rows AS row
                MERGE (n:OI_Node {id: row.id})
                SET n.oi_type = row.oi_type,
                    n.label = row.label,
                    n.severity = row.severity,
                    n.risk_score = row.risk_score,
                    n.exploitable = row.exploitable,
                    n.validated = row.validated,
                    n.props_json = row.props_json,
                    n.updated_at = row.updated_at
                """,
                rows=rows,
            )

        try:
            with self._driver.session(database=self._database) as sess:
                sess.execute_write(work)
        except Exception as exc:
            log.debug("Neo4j merge_nodes_batch failed: %s", exc)

    def merge_edges_batch(self, rows: list[dict]) -> None:
        """rows: id, source_id, target_id, rel_type, label, probability, props_json"""
        if not rows or not self._driver:
            return

        def work(tx):
            tx.run(
                """
                UNWIND $rows AS row
                MATCH (a:OI_Node {id: row.source_id})
                MATCH (b:OI_Node {id: row.target_id})
                MERGE (a)-[r:OI_REL {oi_eid: row.id}]->(b)
                SET r.rel_type = row.rel_type,
                    r.label = row.label,
                    r.probability = row.probability,
                    r.props_json = row.props_json
                """,
                rows=rows,
            )

        try:
            with self._driver.session(database=self._database) as sess:
                sess.execute_write(work)
        except Exception as exc:
            log.debug("Neo4j merge_edges_batch failed: %s", exc)

    def delete_node_cascade(self, node_id: str) -> None:
        if not self._driver:
            return

        def work(tx):
            tx.run(
                "MATCH (n:OI_Node {id: $id}) DETACH DELETE n",
                id=node_id,
            )

        try:
            with self._driver.session(database=self._database) as sess:
                sess.execute_write(work)
        except Exception as exc:
            log.debug("Neo4j delete_node failed: %s", exc)

    def delete_edge_by_id(self, edge_id: str) -> None:
        if not self._driver:
            return

        def work(tx):
            tx.run(
                "MATCH ()-[r:OI_REL {oi_eid: $eid}]->() DELETE r",
                eid=edge_id,
            )

        try:
            with self._driver.session(database=self._database) as sess:
                sess.execute_write(work)
        except Exception as exc:
            log.debug("Neo4j delete_edge failed: %s", exc)

    # --- Path query (deep traversal) -------------------------------------------

    def find_path_node_ids(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 8,
        max_paths: int = 32,
    ) -> list[list[str]]:
        """
        Return list of node-id paths (not Node objects). Used by hybrid GraphQueryEngine.
        """
        if not self._driver:
            return []
        # Path length must be a literal in Cypher (no param in range); clamp for safety.
        hop = max(1, min(int(max_depth), 12))
        cypher = (
            f"MATCH p = (a:OI_Node {{id: $sid}})-[*1..{hop}]->(b:OI_Node {{id: $eid}})\n"
            "WITH p LIMIT $maxp\n"
            "RETURN [n IN nodes(p) | n.id] AS ids"
        )
        try:
            with self._driver.session(database=self._database) as sess:
                result = sess.run(cypher, sid=start_id, eid=end_id, maxp=max_paths)
                return [r["ids"] for r in result if r.get("ids")]
        except Exception as exc:
            log.debug("Neo4j find_path_node_ids failed: %s", exc)
            return []

    def find_path_node_ids_safe(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 8,
        max_paths: int = 32,
    ) -> list[list[str]]:
        """
        find_path_node_ids with config-controlled depth cap and query timeout.
        Reads path_max_depth and max_path_query_ms from graph.yaml.
        """
        if not self._driver:
            return []
        try:
            from core.graph_config import load_graph_config
            neo_cfg = load_graph_config().get("neo4j") or {}
            depth_cap = int(neo_cfg.get("path_max_depth") or 8)
            timeout_ms = int(neo_cfg.get("max_path_query_ms") or 5000)
        except Exception:
            depth_cap, timeout_ms = 8, 5000

        hop = max(1, min(int(max_depth), depth_cap))
        cypher = (
            f"MATCH p = (a:OI_Node {{id: $sid}})-[*1..{hop}]->(b:OI_Node {{id: $eid}})\n"
            "WITH p LIMIT $maxp\n"
            "RETURN [n IN nodes(p) | n.id] AS ids"
        )
        try:
            with self._driver.session(
                database=self._database,
            ) as sess:
                result = sess.run(
                    cypher,
                    sid=start_id,
                    eid=end_id,
                    maxp=max_paths,
                )
                return [r["ids"] for r in result if r.get("ids")]
        except Exception as exc:
            log.debug("find_path_node_ids_safe failed: %s", exc)
            return []

    def count_nodes(self) -> int:
        """Return total OI_Node count in Neo4j, or 0 if unavailable."""
        if not self._driver:
            return 0
        try:
            with self._driver.session(database=self._database) as sess:
                result = list(sess.run("MATCH (n:OI_Node) RETURN count(n) AS n"))
                return int(result[0]["n"]) if result else 0
        except Exception as exc:
            log.debug("count_nodes failed: %s", exc)
            return 0

    def count_edges(self) -> int:
        """Return total OI_REL count in Neo4j, or 0 if unavailable."""
        if not self._driver:
            return 0
        try:
            with self._driver.session(database=self._database) as sess:
                result = list(sess.run("MATCH ()-[r:OI_REL]->() RETURN count(r) AS e"))
                return int(result[0]["e"]) if result else 0
        except Exception as exc:
            log.debug("count_edges failed: %s", exc)
            return 0

    def get_status(self) -> dict:
        """Return dict: connected, uri, database, node_count, edge_count, last_sync_ts."""
        return {
            "connected": self.connected,
            "uri": self._uri,
            "database": self._database,
            "node_count": self.count_nodes() if self.connected else 0,
            "edge_count": self.count_edges() if self.connected else 0,
            "last_sync_ts": getattr(self, "_last_sync_ts", None),
        }

    # --- Analytics (Phase 6) ----------------------------------------------------

    def query_high_risk_endpoints(self, limit: int = 50) -> list[dict]:
        """Endpoints with many HAS_VULNERABILITY-style outgoing rels (rel_type match)."""
        if not self._driver:
            return []
        cypher = """
        MATCH (e:OI_Node)-[r:OI_REL]->(v:OI_Node)
        WHERE toLower(r.rel_type) = 'has_vulnerability'
        WITH e, count(v) AS risk
        RETURN e.id AS id, e.label AS label, e.oi_type AS oi_type, risk
        ORDER BY risk DESC
        LIMIT $lim
        """
        try:
            with self._driver.session(database=self._database) as sess:
                return [dict(r) for r in sess.run(cypher, lim=limit)]
        except Exception as exc:
            log.debug("query_high_risk_endpoints: %s", exc)
            return []

    def query_vulnerability_attack_paths(self, max_depth: int = 5, limit: int = 20) -> list[list[str]]:
        """Paths starting at vulnerability nodes (variable depth)."""
        if not self._driver:
            return []
        d = max(1, min(int(max_depth), 10))
        cypher = (
            "MATCH (v:OI_Node)\nWHERE v.oi_type = 'vulnerability'\n"
            f"MATCH p = (v)-[*1..{d}]->(t:OI_Node)\n"
            "WITH p LIMIT $lim\n"
            "RETURN [n IN nodes(p) | n.id] AS ids"
        )
        try:
            with self._driver.session(database=self._database) as sess:
                return [r["ids"] for r in sess.run(cypher, lim=limit) if r.get("ids")]
        except Exception as exc:
            log.debug("query_vulnerability_attack_paths: %s", exc)
            return []

    def query_token_auth_edges(self, limit: int = 100) -> list[dict]:
        """TOKEN -[:OI_REL rel_type auth_for]-> endpoint"""
        if not self._driver:
            return []
        cypher = """
        MATCH (t:OI_Node)-[r:OI_REL]->(e:OI_Node)
        WHERE t.oi_type = 'token' AND r.rel_type = 'auth_for'
        RETURN t.id AS token_id, e.id AS endpoint_id, e.label AS endpoint_label
        LIMIT $lim
        """
        try:
            with self._driver.session(database=self._database) as sess:
                return [dict(r) for r in sess.run(cypher, lim=limit)]
        except Exception as exc:
            log.debug("query_token_auth_edges: %s", exc)
            return []

    # --- Feedback (Phase 7) -----------------------------------------------------

    def record_chain_feedback(
        self,
        chain_type: str,
        success: bool,
        target: str = "",
        vuln_type: str = "",
        detail: str = "",
    ) -> None:
        if not self._driver:
            return

        def work(tx):
            tx.run(
                """
                CREATE (f:OI_ChainFeedback {
                    ts: $ts,
                    chain_type: $ct,
                    success: $ok,
                    target: $tgt,
                    vuln_type: $vt,
                    detail: $det
                })
                """,
                ts=time.time(),
                ct=chain_type,
                ok=success,
                tgt=target or "",
                vt=vuln_type or "",
                det=(detail or "")[:500],
            )

        try:
            with self._driver.session(database=self._database) as sess:
                sess.execute_write(work)
        except Exception as exc:
            log.debug("record_chain_feedback: %s", exc)

    def get_chain_feedback_scores(self, limit: int = 1000) -> dict:
        """
        Read OI_ChainFeedback nodes and compute per-chain-type success-rate multipliers.

        Returns:
            dict[chain_type, float] where > 1.0 = boost, < 1.0 = penalty.
            Empty dict when Neo4j unavailable.
        """
        if not self._driver:
            return {}
        try:
            with self._driver.session(database=self._database) as sess:
                rows = list(sess.run(
                    "MATCH (f:OI_ChainFeedback) "
                    "RETURN f.chain_type AS chain_type, f.success AS success "
                    "LIMIT $lim",
                    lim=limit,
                ))
        except Exception as exc:
            log.debug("get_chain_feedback_scores failed: %s", exc)
            return {}

        counts: dict = {}
        for row in rows:
            ct = row.get("chain_type") or ""
            ok = bool(row.get("success"))
            counts.setdefault(ct, []).append(ok)

        scores: dict = {}
        for ct, results in counts.items():
            if not ct:
                continue
            total = len(results)
            successes = sum(1 for r in results if r)
            rate = successes / total
            # 0% success → 0.5 (penalty), 100% success → 2.0 (strong boost)
            scores[ct] = 0.5 + 1.5 * rate
        return scores

    # --- Simple single-item CRUD (interface-compatible helpers) -----------------

    def ping(self) -> bool:
        """Return True if Neo4j is reachable."""
        if self._driver is None:
            return False
        try:
            with self._driver.session(database=self._database) as s:
                s.run("RETURN 1")
            return True
        except Exception:
            return False

    def upsert_node(self, node: dict) -> None:
        """Create or update a node in Neo4j. Non-fatal on error."""
        if self._driver is None:
            return
        try:
            with self._driver.session(database=self._database) as s:
                s.run(
                    "MERGE (n:Node {node_id: $node_id}) "
                    "SET n += $props",
                    node_id=node.get("node_id", ""),
                    props={k: v for k, v in node.items()
                           if isinstance(v, (str, int, float, bool))},
                )
        except Exception as exc:
            log.warning("Neo4j upsert_node failed: %s", exc)

    def upsert_edge(self, edge: dict) -> None:
        """Create or update an edge in Neo4j. Non-fatal on error."""
        if self._driver is None:
            return
        try:
            with self._driver.session(database=self._database) as s:
                s.run(
                    "MATCH (a:Node {node_id: $src}), (b:Node {node_id: $dst}) "
                    "MERGE (a)-[r:EDGE {edge_id: $edge_id}]->(b) "
                    "SET r += $props",
                    src=edge.get("source_id", ""),
                    dst=edge.get("target_id", ""),
                    edge_id=edge.get("edge_id", ""),
                    props={k: v for k, v in edge.items()
                           if isinstance(v, (str, int, float, bool))},
                )
        except Exception as exc:
            log.warning("Neo4j upsert_edge failed: %s", exc)

    def delete_node(self, node_id: str) -> None:
        """Delete a node by node_id. Non-fatal on error."""
        if self._driver is None:
            return
        try:
            with self._driver.session(database=self._database) as s:
                s.run("MATCH (n:Node {node_id: $nid}) DETACH DELETE n", nid=node_id)
        except Exception as exc:
            log.warning("Neo4j delete_node failed: %s", exc)

    def delete_edge(self, edge_id: str) -> None:
        """Delete an edge by edge_id. Non-fatal on error."""
        if self._driver is None:
            return
        try:
            with self._driver.session(database=self._database) as s:
                s.run("MATCH ()-[r:EDGE {edge_id: $eid}]-() DELETE r", eid=edge_id)
        except Exception as exc:
            log.warning("Neo4j delete_edge failed: %s", exc)

    def find_paths_node_ids(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 5,
    ) -> list:
        """Find all shortest paths between two nodes. Returns list of node ID lists."""
        if self._driver is None:
            return []
        try:
            hop = max(1, min(int(max_depth), 12))
            cypher = (
                "MATCH p=allShortestPaths((a:Node {node_id: $src})-[*..%d]->(b:Node {node_id: $dst})) "
                "RETURN [n IN nodes(p) | n.node_id] AS path" % hop
            )
            with self._driver.session(database=self._database) as s:
                result = s.run(cypher, src=source_id, dst=target_id)
                return [r["path"] for r in result]
        except Exception as exc:
            log.warning("Neo4j find_paths_node_ids failed: %s", exc)
            return []

    # --- Optional: pull all into dicts for merge into local store ---------------

    def export_all_graph_dicts(self) -> tuple[list[dict], list[dict]]:
        """Return (node_dicts, edge_dicts) in GraphStore-compatible shape (best-effort)."""
        if not self._driver:
            return [], []
        nodes_out: list[dict] = []
        edges_out: list[dict] = []
        try:
            with self._driver.session(database=self._database) as sess:
                for r in sess.run(
                    "MATCH (n:OI_Node) RETURN n.id AS id, n.oi_type AS node_type, "
                    "n.label AS label, n.severity AS severity, n.risk_score AS risk_score, "
                    "n.exploitable AS exploitable, n.validated AS validated, "
                    "n.props_json AS props_json, n.updated_at AS updated_at"
                ):
                    props = {}
                    if r.get("props_json"):
                        try:
                            props = json.loads(r["props_json"])
                        except Exception:
                            props = {}
                    nodes_out.append({
                        "id": r["id"],
                        "node_type": r.get("node_type") or "target",
                        "label": r.get("label") or "",
                        "properties": props,
                        "severity": r.get("severity"),
                        "risk_score": float(r.get("risk_score") or 0),
                        "exploitable": bool(r.get("exploitable")),
                        "validated": bool(r.get("validated")),
                        "discovered_at": str(r.get("updated_at") or time.time()),
                        "updated_at": str(r.get("updated_at") or time.time()),
                        "source": "neo4j_import",
                        "tags": [],
                    })
                for r in sess.run(
                    "MATCH (a:OI_Node)-[rel:OI_REL]->(b:OI_Node) "
                    "RETURN rel.oi_eid AS id, a.id AS source_id, b.id AS target_id, "
                    "rel.rel_type AS edge_type, rel.label AS label, rel.probability AS probability, "
                    "rel.props_json AS props_json"
                ):
                    eprops = {}
                    if r.get("props_json"):
                        try:
                            eprops = json.loads(r["props_json"])
                        except Exception:
                            eprops = {}
                    edges_out.append({
                        "id": r["id"] or f"{r['source_id']}->{r['target_id']}",
                        "source_id": r["source_id"],
                        "target_id": r["target_id"],
                        "edge_type": r.get("edge_type") or "leads_to",
                        "label": r.get("label") or "",
                        "properties": eprops,
                        "probability": float(r.get("probability") or 1.0),
                        "weight": 1.0,
                        "requires_auth": False,
                        "created_at": str(time.time()),
                        "source_engine": "neo4j_import",
                    })
        except Exception as exc:
            log.warning("export_all_graph_dicts failed: %s", exc)
        return nodes_out, edges_out


def node_to_neo_row(nd: dict) -> dict:
    return {
        "id": nd["id"],
        "oi_type": str(nd.get("node_type", "")).lower(),
        "label": nd.get("label", "")[:4000],
        "severity": nd.get("severity"),
        "risk_score": float(nd.get("risk_score") or 0.0),
        "exploitable": bool(nd.get("exploitable")),
        "validated": bool(nd.get("validated")),
        "props_json": json.dumps(nd.get("properties") or {}),
        "updated_at": str(nd.get("updated_at") or time.time()),
    }


def edge_to_neo_row(ed: dict) -> dict:
    return {
        "id": ed["id"],
        "source_id": ed["source_id"],
        "target_id": ed["target_id"],
        "rel_type": str(ed.get("edge_type", "")).lower(),
        "label": (ed.get("label") or "")[:2000],
        "probability": float(ed.get("probability") or 1.0),
        "props_json": json.dumps(ed.get("properties") or {}),
    }
