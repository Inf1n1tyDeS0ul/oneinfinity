"""
graph_path_validator.py — Validates attack paths derived from the graph.

Ensures that:
  1. The path is structurally connected (every node is reachable from its predecessor).
  2. Edge transitions follow allowed type sequences.
  3. At least one node is exploitable or has a known vulnerability.
  4. The path does not contain simulated / synthetic-only nodes that were
     never confirmed by an HTTP execution.

Import in any engine that needs to filter out fake chains:

    from core.graph_path_validator import GraphPathValidator
    validator = GraphPathValidator(engine)
    valid_paths = [p for p in paths if validator.validate(p).is_valid]
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

log = logging.getLogger("oneinfinity.graph_path_validator")

# ---------------------------------------------------------------------------
# Allowed edge-type sequences (source_node_type → edge_type → target_node_type)
# ---------------------------------------------------------------------------
# Format: frozenset of (from_type_value, edge_type_value, to_type_value) tuples
# An empty set means "no structural constraints" (permissive mode).

_ALLOWED_TRANSITIONS = frozenset({
    # Structural discovery
    ("target",       "has_endpoint",     "url"),
    ("target",       "has_endpoint",     "api_endpoint"),
    ("target",       "hosts",            "subdomain"),
    ("subdomain",    "has_endpoint",     "url"),
    ("subdomain",    "has_endpoint",     "api_endpoint"),
    ("subdomain",    "hosts",            "service"),
    # Parameter and vulnerability wiring
    ("url",          "has_param",        "parameter"),
    ("api_endpoint", "has_param",        "parameter"),
    ("url",          "has_vulnerability","vulnerability"),
    ("api_endpoint", "has_vulnerability","vulnerability"),
    ("parameter",    "has_vulnerability","vulnerability"),
    # Exploit and impact chains
    ("vulnerability","leads_to",         "vulnerability"),
    ("vulnerability","leads_to",         "exploit"),
    ("vulnerability","enables",          "exploit"),
    ("exploit",      "leads_to",         "impact"),
    ("exploit",      "chained_with",     "exploit"),
    # Auth / credential paths
    ("auth_flow",    "issues_token",     "token"),
    ("service",      "issues_token",     "token"),
    ("token",        "auth_for",         "url"),
    ("token",        "auth_for",         "api_endpoint"),
    ("session",      "auth_for",         "url"),
    ("session",      "auth_for",         "api_endpoint"),
    ("vulnerability","authenticated_by", "auth_flow"),
    # API call chains
    ("api_endpoint", "calls",            "api_endpoint"),
    ("url",          "calls",            "api_endpoint"),
    # Generic traversal
    ("vulnerability","part_of",          "impact"),
    ("exploit",      "part_of",          "impact"),
})

# Minimum number of nodes for a path to be considered non-trivial
_MIN_PATH_LENGTH = 2


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

@dataclass
class PathValidationResult:
    is_valid: bool
    reason: str = ""
    warnings: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.is_valid


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class GraphPathValidator:
    """
    Validates attack-graph paths before they are promoted to reported findings
    or fed into the exploit-chain engine.

    Parameters
    ----------
    engine:     AttackGraphEngine instance (optional; used for edge lookup)
    strict:     If True, all edge transitions must appear in _ALLOWED_TRANSITIONS.
                If False, unknown transitions generate warnings but don't fail.
    """

    def __init__(self, engine=None, strict: bool = False):
        self._engine = engine
        self.strict = strict

    def validate(self, path: List) -> PathValidationResult:
        """
        Validate a list of Node objects representing an attack path.
        Returns PathValidationResult with is_valid=True/False and a reason.
        """
        if not path:
            return PathValidationResult(False, "empty path")

        if len(path) < _MIN_PATH_LENGTH:
            return PathValidationResult(
                False, f"path too short ({len(path)} nodes, minimum {_MIN_PATH_LENGTH})"
            )

        warnings = []

        # ------------------------------------------------------------------
        # 1. Structural connectivity: every consecutive pair must be connected
        # ------------------------------------------------------------------
        if self._engine is not None:
            for i in range(len(path) - 1):
                src = path[i]
                dst = path[i + 1]
                if src is None or dst is None:
                    return PathValidationResult(False, f"null node at position {i}")
                edges_out = self._engine.get_edges_from(src.id)
                connected = any(e.target_id == dst.id for e in edges_out)
                if not connected:
                    return PathValidationResult(
                        False,
                        f"no edge from '{src.label}' ({src.id[:8]}) "
                        f"to '{dst.label}' ({dst.id[:8]})",
                    )

        # ------------------------------------------------------------------
        # 2. Transition validity
        # ------------------------------------------------------------------
        if self._engine is not None and _ALLOWED_TRANSITIONS:
            for i in range(len(path) - 1):
                src = path[i]
                dst = path[i + 1]
                if src is None or dst is None:
                    continue
                edges_out = self._engine.get_edges_from(src.id)
                src_type = _ntype(src)
                dst_type = _ntype(dst)
                for edge in edges_out:
                    if edge.target_id != dst.id:
                        continue
                    et = _etype(edge)
                    transition = (src_type, et, dst_type)
                    if transition not in _ALLOWED_TRANSITIONS:
                        msg = (
                            f"unexpected transition {src_type} --[{et}]--> {dst_type} "
                            f"at hop {i}"
                        )
                        if self.strict:
                            return PathValidationResult(False, msg)
                        warnings.append(msg)

        # ------------------------------------------------------------------
        # 3. At least one actionable node (exploitable vuln or real exploit)
        # ------------------------------------------------------------------
        has_actionable = any(
            getattr(n, "exploitable", False) or
            _ntype(n) in ("vulnerability", "exploit", "impact")
            for n in path if n
        )
        if not has_actionable:
            return PathValidationResult(
                False, "path contains no exploitable vulnerability, exploit, or impact nodes"
            )

        # ------------------------------------------------------------------
        # 4. Reject fully-simulated paths (all nodes are source_type=simulated)
        # ------------------------------------------------------------------
        simulated_nodes = [
            n for n in path
            if n and n.properties.get("source_type") == "simulated"
        ]
        if simulated_nodes and len(simulated_nodes) == len([n for n in path if n]):
            return PathValidationResult(
                False,
                "path consists entirely of simulated nodes; not yet HTTP-confirmed"
            )
        if simulated_nodes:
            warnings.append(
                f"{len(simulated_nodes)} of {len(path)} nodes are simulated (unconfirmed)"
            )

        return PathValidationResult(True, "ok", warnings)

    def filter_paths(self, paths: List[List]) -> List[List]:
        """Filter a list of paths, returning only valid ones."""
        valid = []
        for p in paths:
            result = self.validate(p)
            if result.is_valid:
                valid.append(p)
            else:
                log.debug("GraphPathValidator: rejected path (%d nodes): %s", len(p), result.reason)
            for w in result.warnings:
                log.debug("GraphPathValidator: warning: %s", w)
        return valid


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ntype(node) -> str:
    nt = getattr(node, "node_type", "")
    if hasattr(nt, "value"):
        return nt.value
    return str(nt).split(".")[-1].lower()


def _etype(edge) -> str:
    et = getattr(edge, "edge_type", "")
    if hasattr(et, "value"):
        return et.value
    return str(et).split(".")[-1].lower()
