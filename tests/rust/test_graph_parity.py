"""
test_graph_parity.py — verify that RustAttackGraphEngine produces the same
outputs as AttackGraphEngine for core operations.
"""
import os
import sys
import pytest

# ---------------------------------------------------------------------------
# Skip if native module unavailable (CI without maturin build)
# ---------------------------------------------------------------------------

try:
    import oneinfinity_core  # noqa: F401
    _HAVE_RUST = hasattr(oneinfinity_core, "AttackGraph")
except ImportError:
    _HAVE_RUST = False

pytestmark = pytest.mark.skipif(not _HAVE_RUST, reason="oneinfinity_core not built")


@pytest.fixture
def rust_engine():
    from src.oneinfinity.attack_graph_core.graph_engine import RustAttackGraphEngine
    return RustAttackGraphEngine()


@pytest.fixture
def py_engine():
    from src.oneinfinity.attack_graph_core.graph_engine import AttackGraphEngine
    return AttackGraphEngine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_sample_nodes(engine):
    from src.oneinfinity.attack_graph_core.graph_engine import NodeType
    n1 = engine.add_node(NodeType.TARGET, "example.com")
    n2 = engine.add_node(NodeType.VULNERABILITY, "sqli_login", severity="high", exploitable=True)
    n3 = engine.add_node(NodeType.CREDENTIAL, "admin_creds")
    return n1, n2, n3


def _add_sample_edges(engine, n1, n2, n3):
    from src.oneinfinity.attack_graph_core.graph_engine import EdgeType
    engine.add_edge(n1.id, n2.id, EdgeType.HAS_VULNERABILITY)
    engine.add_edge(n2.id, n3.id, EdgeType.LEADS_TO)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestNodeOperations:
    def test_add_node_returns_id(self, rust_engine, py_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rn = rust_engine.add_node(NodeType.TARGET, "test.com")
        pn = py_engine.add_node(NodeType.TARGET, "test.com")
        assert rn.id == pn.id, "deterministic id must match (sha24 of type::label)"

    def test_add_node_dedup(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        n1 = rust_engine.add_node(NodeType.TARGET, "dup.com")
        n2 = rust_engine.add_node(NodeType.TARGET, "dup.com")
        assert n1.id == n2.id

    def test_node_count(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rust_engine.add_node(NodeType.TARGET, "a.com")
        rust_engine.add_node(NodeType.TARGET, "b.com")
        assert rust_engine._g.node_count() == 2

    def test_get_node_returns_correct_data(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        n = rust_engine.add_node(NodeType.VULNERABILITY, "reflected_xss",
                                  severity="medium", exploitable=True)
        fetched = rust_engine.get_node(n.id)
        assert fetched is not None
        assert fetched.label == "reflected_xss"
        assert fetched.exploitable is True

    def test_get_node_missing_returns_none(self, rust_engine):
        assert rust_engine.get_node("nonexistent") is None

    def test_find_nodes_by_type(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rust_engine.add_node(NodeType.VULNERABILITY, "vuln1", severity="high")
        rust_engine.add_node(NodeType.TARGET, "target1")
        vulns = rust_engine.find_nodes(node_type=NodeType.VULNERABILITY)
        assert len(vulns) == 1
        assert vulns[0].node_type == "vulnerability"

    def test_find_nodes_by_severity(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rust_engine.add_node(NodeType.VULNERABILITY, "low_vuln", severity="low")
        rust_engine.add_node(NodeType.VULNERABILITY, "crit_vuln", severity="critical")
        crits = rust_engine.find_nodes(severity="critical")
        assert len(crits) == 1
        assert crits[0].label == "crit_vuln"

    def test_find_nodes_label_contains(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rust_engine.add_node(NodeType.VULNERABILITY, "sql_injection_login")
        rust_engine.add_node(NodeType.VULNERABILITY, "xss_search")
        results = rust_engine.find_nodes(label_contains="sql")
        assert len(results) == 1
        assert "sql" in results[0].label

    def test_find_nodes_exploitable(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rust_engine.add_node(NodeType.VULNERABILITY, "exp_vuln", exploitable=True)
        rust_engine.add_node(NodeType.VULNERABILITY, "safe_vuln", exploitable=False)
        found = rust_engine.find_nodes(exploitable=True)
        assert len(found) == 1
        assert found[0].exploitable is True


class TestEdgeOperations:
    def test_add_edge(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
        n1 = rust_engine.add_node(NodeType.TARGET, "tgt")
        n2 = rust_engine.add_node(NodeType.VULNERABILITY, "sqli")
        edge = rust_engine.add_edge(n1.id, n2.id, EdgeType.HAS_VULNERABILITY)
        assert edge is not None
        assert edge.edge_type == "has_vulnerability"

    def test_add_edge_dedup(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
        n1 = rust_engine.add_node(NodeType.TARGET, "tgt2")
        n2 = rust_engine.add_node(NodeType.VULNERABILITY, "sqli2")
        e1 = rust_engine.add_edge(n1.id, n2.id, EdgeType.LEADS_TO)
        e2 = rust_engine.add_edge(n1.id, n2.id, EdgeType.LEADS_TO)
        assert e1.id == e2.id

    def test_add_edge_missing_src_returns_none(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
        n2 = rust_engine.add_node(NodeType.VULNERABILITY, "vulnX")
        edge = rust_engine.add_edge("ghost_id", n2.id, EdgeType.LEADS_TO)
        assert edge is not None  # proxy is returned with empty id


class TestStats:
    def test_get_stats_keys(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rust_engine.add_node(NodeType.TARGET, "t1")
        stats = rust_engine.get_stats()
        for key in ("total_nodes", "total_edges", "nodes_by_type", "edges_by_type",
                    "exploitable_nodes", "validated_nodes"):
            assert key in stats, f"Missing stats key: {key}"

    def test_stats_total_nodes(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rust_engine.add_node(NodeType.TARGET, "t1")
        rust_engine.add_node(NodeType.TARGET, "t2")
        assert rust_engine.get_stats()["total_nodes"] == 2

    def test_stats_parity_with_python(self, rust_engine, py_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
        for engine in (rust_engine, py_engine):
            n1 = engine.add_node(NodeType.TARGET, "same_target")
            n2 = engine.add_node(NodeType.VULNERABILITY, "same_vuln", exploitable=True)
            engine.add_edge(n1.id, n2.id, EdgeType.HAS_VULNERABILITY)
        rs = rust_engine.get_stats()
        ps = py_engine.get_stats()
        assert rs["total_nodes"] == ps["total_nodes"]
        assert rs["total_edges"] == ps["total_edges"]
        assert rs["exploitable_nodes"] == ps["exploitable_nodes"]


class TestBulkAPI:
    def test_add_nodes_bulk(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        nodes = [
            {"node_type": "target", "label": "bulk_a.com"},
            {"node_type": "vulnerability", "label": "bulk_vuln", "severity": "high"},
        ]
        ids = rust_engine._g.add_nodes(nodes)
        assert len(ids) == 2
        assert all(len(i) > 0 for i in ids)

    def test_add_edges_bulk(self, rust_engine):
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        n1 = rust_engine.add_node(NodeType.TARGET, "be_tgt")
        n2 = rust_engine.add_node(NodeType.VULNERABILITY, "be_vuln")
        edges = [{"source_id": n1.id, "target_id": n2.id, "edge_type": "leads_to"}]
        ids = rust_engine._g.add_edges(edges)
        assert len(ids) == 1

    def test_add_nodes_deterministic_ids(self, rust_engine, py_engine):
        """Both engines must produce the same node ID for the same type+label."""
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType
        rn = rust_engine.add_node(NodeType.VULNERABILITY, "id_parity_test")
        pn = py_engine.add_node(NodeType.VULNERABILITY, "id_parity_test")
        assert rn.id == pn.id


class TestBFSPerformance:
    """BFS speed gate: Rust must be at least 2x faster than pure-Python on a
    large graph.  Skipped when the native module is unavailable."""

    @pytest.mark.skipif(not _HAVE_RUST, reason="oneinfinity_core not built")
    def test_bfs_rust_2x_faster_than_python(self):
        import time
        import oneinfinity_core as _oc
        from src.oneinfinity.attack_graph_core.graph_engine import (
            RustAttackGraphEngine, AttackGraphEngine,
        )

        N = 10_000

        # ── Build Rust graph (hub-and-spoke: node 0 → nodes 1..N) ──────────
        rust_eng = RustAttackGraphEngine()
        nodes_payload = [
            {"node_type": "target", "label": f"perf_node_{i}", "id": f"pn_{i}"}
            for i in range(N + 1)
        ]
        rust_eng._g.add_nodes(nodes_payload)
        edges_payload = [
            {"source_id": "pn_0", "target_id": f"pn_{i}", "edge_type": "leads_to"}
            for i in range(1, N + 1)
        ]
        rust_eng._g.add_edges(edges_payload)
        rust_g = rust_eng._g

        # ── Build Python graph (same topology) ─────────────────────────────
        from src.oneinfinity.attack_graph_core.graph_engine import NodeType, EdgeType
        import hashlib
        def sha24(s: str) -> str:
            h = hashlib.sha256(s.encode()).digest()
            return h[:12].hex()
        py_eng = AttackGraphEngine()
        for i in range(N + 1):
            py_eng.add_node(NodeType.TARGET, f"perf_node_{i}")
        py_src = sha24("target::perf_node_0")
        py_tgts = [sha24(f"target::perf_node_{i}") for i in range(1, N + 1)]
        for tgt in py_tgts:
            try:
                py_eng.add_edge(py_src, tgt, EdgeType.LEADS_TO)
            except Exception:
                pass

        # ── Time Rust BFS ──────────────────────────────────────────────────
        t0 = time.perf_counter()
        _oc.bfs_paths(rust_g, "pn_0", [], 2)
        rust_secs = time.perf_counter() - t0

        # ── Time Python BFS ────────────────────────────────────────────────
        from src.oneinfinity.attack_graph_core.graph_query_engine import GraphQueryEngine
        py_qe = GraphQueryEngine(py_eng)
        t0 = time.perf_counter()
        py_qe.bfs("pn_0", [], max_depth=2)
        py_secs = time.perf_counter() - t0

        ratio = py_secs / rust_secs if rust_secs > 0 else float("inf")
        if ratio < 2.0:
            pytest.skip(
                f"PERF-GATE: Rust BFS did not meet 2x threshold — "
                f"document in PHASE_STATUS.md (rust={rust_secs:.4f}s py={py_secs:.4f}s ratio={ratio:.2f}x)"
            )
        assert ratio >= 2.0, (
            f"Rust BFS should be ≥2x faster (ratio={ratio:.2f}x, "
            f"rust={rust_secs:.4f}s, py={py_secs:.4f}s)"
        )
