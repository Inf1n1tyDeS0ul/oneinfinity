"""
learning/graph_schema.py — Bootstrap Neo4j constraints and indexes for learning graph.

Call bootstrap_learning_schema(driver, database) once at startup.
All labels are prefixed LN_ to avoid collision with attack graph (OI_Node / OI_REL).
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("oneinfinity.learning.graph_schema")

# Uniqueness constraints — one per node label on its natural key
_CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Target)   REQUIRE n.domain    IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Tech)     REQUIRE n.name      IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_VulnType) REQUIRE n.name      IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Tool)     REQUIRE n.name      IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Payload)  REQUIRE n.key       IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (n:LN_Meta)     REQUIRE n.key       IS UNIQUE",
]

# Lookup indexes
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS FOR (n:LN_VulnType) ON (n.ema_score)",
    "CREATE INDEX IF NOT EXISTS FOR (n:LN_Target)   ON (n.last_scanned)",
]


def bootstrap_learning_schema(driver: Any, database: str = "neo4j") -> None:
    """Apply constraints and indexes. Safe to call multiple times."""
    if driver is None:
        return
    try:
        with driver.session(database=database) as sess:
            for stmt in _CONSTRAINTS + _INDEXES:
                sess.run(stmt)
        log.info("Learning graph schema bootstrapped (%d constraints, %d indexes)",
                 len(_CONSTRAINTS), len(_INDEXES))
    except Exception:
        log.warning("bootstrap_learning_schema failed (non-fatal)", exc_info=True)
