"""
Graph storage abstraction: optional secondary backends (Neo4j) for write-through sync.
Primary graph logic remains attack_graph_core (SQLite + in-memory).
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod

from core.neo4j_engine import edge_to_neo_row, node_to_neo_row

log = logging.getLogger(__name__)


class GraphStorageBackend(ABC):
    """
    Secondary sync contract — called by GraphStore after SQLite/memory writes.
    """

    @abstractmethod
    def on_node_saved(self, node_dict: dict) -> None:
        pass

    @abstractmethod
    def on_edge_saved(self, edge_dict: dict) -> None:
        pass

    @abstractmethod
    def on_node_deleted(self, node_id: str) -> None:
        pass

    @abstractmethod
    def on_edge_deleted(self, edge_id: str) -> None:
        pass

    def flush(self) -> None:
        """Push any batched operations to remote storage."""
        pass

    def close(self) -> None:
        pass

    # Optional read APIs (Neo4j analytics / deep paths)
    def find_paths_node_ids(
        self, start_id: str, end_id: str, max_depth: int, max_paths: int = 32
    ) -> list[list[str]]:
        return []


class NullGraphStorageBackend(GraphStorageBackend):
    """No-op backend (Neo4j disabled or unavailable)."""

    def on_node_saved(self, node_dict: dict) -> None:
        return

    def on_edge_saved(self, edge_dict: dict) -> None:
        return

    def on_node_deleted(self, node_id: str) -> None:
        return

    def on_edge_deleted(self, edge_id: str) -> None:
        return


class BatchedNeo4jGraphBackend(GraphStorageBackend):
    """
    Write-through to Neo4j with batching to limit round-trips.
    """

    def __init__(self, engine, batch_size: int = 100, flush_interval_sec: float = 2.0):
        self._engine = engine
        self._batch_size = max(1, int(batch_size))
        self._flush_interval_sec = float(flush_interval_sec)
        self._node_to_row = node_to_neo_row
        self._edge_to_row = edge_to_neo_row
        self._lock = threading.Lock()
        self._node_buf: list[dict] = []
        self._edge_buf: list[dict] = []
        self._pending_deletes_n: list[str] = []
        self._pending_deletes_e: list[str] = []
        self._last_flush = time.monotonic()

    def _maybe_flush(self, force: bool = False) -> None:
        if not self._engine or not self._engine.connected:
            return
        now = time.monotonic()
        with self._lock:
            should = force
            if len(self._node_buf) >= self._batch_size:
                should = True
            if len(self._edge_buf) >= self._batch_size:
                should = True
            if (now - self._last_flush) >= self._flush_interval_sec and (
                self._node_buf or self._edge_buf or self._pending_deletes_n or self._pending_deletes_e
            ):
                should = True
            if not should:
                return
            nodes = self._node_buf[:]
            edges = self._edge_buf[:]
            dn = self._pending_deletes_n[:]
            de = self._pending_deletes_e[:]
            self._node_buf.clear()
            self._edge_buf.clear()
            self._pending_deletes_n.clear()
            self._pending_deletes_e.clear()
            self._last_flush = now

        for nid in dn:
            self._engine.delete_node_cascade(nid)
        for eid in de:
            self._engine.delete_edge_by_id(eid)
        if nodes:
            self._engine.merge_nodes_batch(nodes)
        if edges:
            self._engine.merge_edges_batch(edges)
        if nodes or edges:
            import time as _time_mod
            self._engine._last_sync_ts = _time_mod.time()

    def on_node_saved(self, node_dict: dict) -> None:
        if not self._engine.connected:
            return
        try:
            with self._lock:
                self._node_buf.append(self._node_to_row(dict(node_dict)))
            self._maybe_flush()
        except Exception as exc:
            log.debug("Neo4j on_node_saved: %s", exc)

    def on_edge_saved(self, edge_dict: dict) -> None:
        if not self._engine.connected:
            return
        try:
            with self._lock:
                self._edge_buf.append(self._edge_to_row(dict(edge_dict)))
            self._maybe_flush()
        except Exception as exc:
            log.debug("Neo4j on_edge_saved: %s", exc)

    def on_node_deleted(self, node_id: str) -> None:
        if not self._engine.connected:
            return
        with self._lock:
            self._pending_deletes_n.append(node_id)
        self._maybe_flush()

    def on_edge_deleted(self, edge_id: str) -> None:
        if not self._engine.connected:
            return
        with self._lock:
            self._pending_deletes_e.append(edge_id)
        self._maybe_flush()

    def flush(self) -> None:
        self._maybe_flush(force=True)

    def close(self) -> None:
        self.flush()
        self._engine.close()

    def find_paths_node_ids(
        self, start_id: str, end_id: str, max_depth: int, max_paths: int = 32
    ) -> list[list[str]]:
        if not self._engine.connected:
            return []
        return self._engine.find_path_node_ids(
            start_id, end_id, max_depth=max_depth, max_paths=max_paths
        )


class Neo4jPrimaryBackend(GraphStorageBackend):
    """
    Neo4j as the sole graph store — no SQLite duplication.
    Used when NEO4J_ENABLED=true or Neo4j is available.
    All writes go directly to Neo4j. Non-fatal on errors (logs warning).
    """

    def __init__(self, engine):
        self._engine = engine

    def on_node_saved(self, node_dict: dict) -> None:
        try:
            self._engine.upsert_node(node_dict)
        except Exception as exc:
            log.warning("Neo4jPrimaryBackend.on_node_saved failed: %s", exc)

    def on_edge_saved(self, edge_dict: dict) -> None:
        try:
            self._engine.upsert_edge(edge_dict)
        except Exception as exc:
            log.warning("Neo4jPrimaryBackend.on_edge_saved failed: %s", exc)

    def on_node_deleted(self, node_id: str) -> None:
        try:
            self._engine.delete_node(node_id)
        except Exception as exc:
            log.warning("Neo4jPrimaryBackend.on_node_deleted failed: %s", exc)

    def on_edge_deleted(self, edge_id: str) -> None:
        try:
            self._engine.delete_edge(edge_id)
        except Exception as exc:
            log.warning("Neo4jPrimaryBackend.on_edge_deleted failed: %s", exc)
