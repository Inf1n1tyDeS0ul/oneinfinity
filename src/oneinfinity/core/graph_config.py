"""
Load graph backend configuration (Neo4j optional).
Environment overrides: NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, NEO4J_ENABLED
"""

from __future__ import annotations

import copy
import os
import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

_DEFAULTS: dict[str, Any] = {
    "neo4j": {
        "enabled": False,
        "uri": "bolt://localhost:47296",
        "username": "neo4j",
        "password": "password",
        "database": "neo4j",
        "batch_size": 100,
        "flush_interval_sec": 2.0,
        "hybrid_depth_threshold": 3,
        "load_on_startup": False,
        "record_chain_feedback": True,
        "path_max_depth": 8,
        "max_path_query_ms": 5000,
    },
    "enforcement": {
        "enabled": False,
        "validation_pipeline": False,
        "capmap_enforcement": False,
        "max_recursion_depth": 2,
        "max_recursive_items": 100,
        "module_compliance": "warn",
        "ingestion_audit": False,
    },
    "redis": {
        "url": "",
    },
    "postgres": {
        "url": "",
    },
    "storage_mode": "auto",  # auto | distributed | sqlite | memory
}


def graph_config_path() -> Path:
    return Path(__file__).resolve().parent.parent / "config" / "graph.yaml"


def load_graph_config() -> dict[str, Any]:
    cfg = copy.deepcopy(_DEFAULTS)
    path = graph_config_path()
    if path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                user = yaml.safe_load(f) or {}
            if "neo4j" in user and isinstance(user["neo4j"], dict):
                cfg["neo4j"].update(user["neo4j"])
            if "enforcement" in user and isinstance(user["enforcement"], dict):
                cfg["enforcement"].update(user["enforcement"])
        except Exception as exc:
            log.warning("graph.yaml read failed (%s); using defaults", exc)

    neo = cfg["neo4j"]
    if os.environ.get("NEO4J_ENABLED", "").lower() in ("1", "true", "yes"):
        neo["enabled"] = True
    if os.environ.get("NEO4J_URI"):
        neo["uri"] = os.environ["NEO4J_URI"]
    if os.environ.get("NEO4J_USERNAME"):
        neo["username"] = os.environ["NEO4J_USERNAME"]
    if os.environ.get("NEO4J_PASSWORD"):
        neo["password"] = os.environ["NEO4J_PASSWORD"]
    if os.environ.get("NEO4J_DATABASE"):
        neo["database"] = os.environ["NEO4J_DATABASE"]

    # Redis
    if os.environ.get("REDIS_URL"):
        cfg["redis"]["url"] = os.environ["REDIS_URL"]

    # PostgreSQL
    if os.environ.get("POSTGRES_URL"):
        cfg["postgres"]["url"] = os.environ["POSTGRES_URL"]

    # Storage mode
    mode = os.environ.get("ONEINFINITY_STORAGE_MODE", "").lower()
    if mode in ("auto", "distributed", "sqlite", "memory"):
        cfg["storage_mode"] = mode

    return cfg
