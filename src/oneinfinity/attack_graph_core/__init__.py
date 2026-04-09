"""
attack_graph_core — Central intelligence engine for the autonomous security platform.
All engines interact with this package. The graph IS the system state.

Also provides the lightweight graph data-model layer (formerly attack_graph/):
  AttackGraph, AttackGraphBuilder, AttackGraphAnalyzer, AttackGraphVisualizer
"""
from .graph_engine import AttackGraphEngine, Node, Edge, NodeType, EdgeType
from .graph_store import GraphStore, _enum_to_str
from .graph_updater import GraphUpdater
from .graph_query_engine import GraphQueryEngine
from .attack_planner import AttackPlanner
from .exploit_chain_engine import ExploitChainEngine
from .risk_analyzer import RiskAnalyzer
# Data-model layer (moved from attack_graph/)
from .graph import AttackGraph
from .builder import AttackGraphBuilder
from .analyzer import AttackGraphAnalyzer
from .visualizer import AttackGraphVisualizer

__all__ = [
    "AttackGraphEngine", "Node", "Edge", "NodeType", "EdgeType",
    "GraphStore", "GraphUpdater", "GraphQueryEngine",
    "AttackPlanner", "ExploitChainEngine", "RiskAnalyzer",
    "_enum_to_str",
    "AttackGraph", "AttackGraphBuilder", "AttackGraphAnalyzer", "AttackGraphVisualizer",
]
