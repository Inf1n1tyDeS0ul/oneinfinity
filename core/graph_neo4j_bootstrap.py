"""
Wire optional Neo4j into GraphStore / global helpers for hybrid queries and feedback.
"""

from __future__ import annotations

import atexit
import logging
from typing import Any, Tuple

log = logging.getLogger(__name__)

_neo4j_engine_singleton: Any = None
_neo4j_backend_singleton: Any = None


def get_neo4j_engine():
    """Shared Neo4jEngine instance when enabled and connected; else None."""
    return _neo4j_engine_singleton


def get_neo4j_sync_backend():
    """BatchedNeo4jGraphBackend used by GraphStore, or None."""
    return _neo4j_backend_singleton


def create_default_graph_store() -> Tuple[Any, dict]:
    """
    Build GraphStore with optional Neo4j write-through.
    Called from attack_graph_core.get_engine() — keep imports lazy.
    """
    from attack_graph_core.graph_store import GraphStore
    from path_manager import attack_graph_db_path

    global _neo4j_engine_singleton, _neo4j_backend_singleton

    db = str(attack_graph_db_path())

    try:
        from core.graph_config import load_graph_config
        from core.graph_storage import BatchedNeo4jGraphBackend
        from core.neo4j_engine import Neo4jEngine, neo4j_driver_available
    except Exception as exc:
        log.debug("Neo4j modules unavailable: %s", exc)
        return GraphStore(db_path=db, use_memory=True), {}

    cfg = load_graph_config()
    neo_cfg = cfg.get("neo4j") or {}
    backend = None

    if neo_cfg.get("enabled") and neo4j_driver_available():
        eng = Neo4jEngine(
            uri=str(neo_cfg.get("uri") or "bolt://localhost:7687"),
            username=str(neo_cfg.get("username") or "neo4j"),
            password=str(neo_cfg.get("password") or ""),
            database=str(neo_cfg.get("database") or "neo4j"),
        )
        if eng.connected:
            _neo4j_engine_singleton = eng
            eng.bootstrap_schema()          # bootstrap constraint + indexes
            backend = BatchedNeo4jGraphBackend(
                eng,
                batch_size=int(neo_cfg.get("batch_size") or 100),
                flush_interval_sec=float(neo_cfg.get("flush_interval_sec") or 2.0),
            )
            _neo4j_backend_singleton = backend

            def _flush_atexit():
                try:
                    backend.flush()
                except Exception:
                    pass

            atexit.register(_flush_atexit)
            log.info("GraphStore will sync to Neo4j (batched write-through).")
        else:
            eng.close()

    store = GraphStore(db_path=db, use_memory=True, sync_backend=backend)
    return store, cfg


def maybe_merge_neo4j_into_store(store) -> None:
    """If load_on_startup, pull Neo4j OI_* graph into SQLite/memory (merge)."""
    try:
        from core.graph_config import load_graph_config
        cfg = load_graph_config()
        neo_cfg = cfg.get("neo4j") or {}
        if not neo_cfg.get("load_on_startup"):
            return
        eng = get_neo4j_engine()
        if not eng or not eng.connected:
            return
        nodes, edges = eng.export_all_graph_dicts()
        for nd in nodes:
            store.save_node(nd)
        for ed in edges:
            store.save_edge(ed)
        store.flush_sync_backend()
        log.info("Merged %d nodes, %d edges from Neo4j into local store", len(nodes), len(edges))
    except Exception as exc:
        log.warning("Neo4j load_on_startup merge failed: %s", exc)


def compare_inmemory_vs_neo4j(store, neo4j_engine=None) -> dict:
    """
    Compare node and edge counts between the in-memory/SQLite store and Neo4j.

    Args:
        store: GraphStore instance with get_graph_stats().
        neo4j_engine: Neo4jEngine instance, or None to auto-detect singleton.

    Returns:
        dict with: neo4j_connected, inmem_nodes, inmem_edges,
        neo4j_nodes, neo4j_edges, node_delta, edge_delta, match
    """
    if neo4j_engine is None:
        neo4j_engine = get_neo4j_engine()

    local_stats = store.get_graph_stats()
    inmem_nodes = int(local_stats.get("total_nodes") or 0)
    inmem_edges = int(local_stats.get("total_edges") or 0)

    if neo4j_engine is None or not neo4j_engine.connected:
        return {
            "neo4j_connected": False,
            "inmem_nodes": inmem_nodes,
            "inmem_edges": inmem_edges,
            "neo4j_nodes": 0,
            "neo4j_edges": 0,
            "node_delta": inmem_nodes,
            "edge_delta": inmem_edges,
            "match": False,
        }

    neo_nodes = neo4j_engine.count_nodes()
    neo_edges = neo4j_engine.count_edges()
    node_delta = abs(inmem_nodes - neo_nodes)
    edge_delta = abs(inmem_edges - neo_edges)

    return {
        "neo4j_connected": True,
        "inmem_nodes": inmem_nodes,
        "inmem_edges": inmem_edges,
        "neo4j_nodes": neo_nodes,
        "neo4j_edges": neo_edges,
        "node_delta": node_delta,
        "edge_delta": edge_delta,
        "match": node_delta == 0 and edge_delta == 0,
    }


def publish_chain_feedback_neo4j(
    chain_type: str,
    success: bool,
    target: str = "",
    vuln_type: str = "",
    detail: str = "",
) -> None:
    try:
        from core.graph_config import load_graph_config
        cfg = load_graph_config()
        if not (cfg.get("neo4j") or {}).get("record_chain_feedback", True):
            return
        eng = get_neo4j_engine()
        if eng and eng.connected:
            eng.record_chain_feedback(chain_type, success, target, vuln_type, detail)
    except Exception:
        pass
