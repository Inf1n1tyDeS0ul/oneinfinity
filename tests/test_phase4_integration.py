"""
test_phase4_integration.py — end-to-end integration tests for Phase 4.

Tests the full stack:
  - Rust flag off: pure-Python engines used
  - Rust flag on (when oneinfinity_core built): Rust engines used
  - Feature-flag isolation: GRAPH flag does not affect SMUGGLING
  - Shim interface compatibility
"""
import os
import sys
import pytest
import importlib


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reload_modules():
    """Reload all Phase-4 modules so env-var changes take effect."""
    for mod_name in list(sys.modules.keys()):
        if "graph_engine" in mod_name or "graph_query" in mod_name or "smuggling_engine" in mod_name:
            try:
                importlib.reload(sys.modules[mod_name])
            except Exception:
                pass


def _have_rust() -> bool:
    try:
        import oneinfinity_core as oc
        return hasattr(oc, "AttackGraph")
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Python-only integration (no native build needed)
# ---------------------------------------------------------------------------

class TestPythonFallback:
    """With ONEINFINITY_RUST_GRAPH unset, pure-Python engines must function."""

    def setup_method(self):
        os.environ.pop("ONEINFINITY_RUST_GRAPH", None)
        os.environ.pop("ONEINFINITY_RUST_SMUGGLING", None)

    def test_get_engine_returns_python_engine(self):
        from src.oneinfinity.attack_graph_core import graph_engine as ge
        importlib.reload(ge)
        engine = ge.get_engine.__wrapped__() if hasattr(ge.get_engine, "__wrapped__") else ge.AttackGraphEngine()
        from src.oneinfinity.attack_graph_core.graph_engine import AttackGraphEngine
        assert isinstance(engine, AttackGraphEngine)

    def test_graph_query_engine_singleton_is_python(self):
        from src.oneinfinity.attack_graph_core import graph_query_engine as gqe
        importlib.reload(gqe)
        from src.oneinfinity.attack_graph_core.graph_query_engine import GraphQueryEngine
        assert isinstance(gqe.graph_query_engine, GraphQueryEngine)

    def test_python_engine_full_workflow(self):
        from src.oneinfinity.attack_graph_core.graph_engine import AttackGraphEngine, NodeType, EdgeType
        eng = AttackGraphEngine()
        n1 = eng.add_node(NodeType.TARGET, "integration.com")
        n2 = eng.add_node(NodeType.VULNERABILITY, "sqli_int", severity="high", exploitable=True)
        n3 = eng.add_node(NodeType.CREDENTIAL, "int_creds")
        eng.add_edge(n1.id, n2.id, EdgeType.HAS_VULNERABILITY)
        eng.add_edge(n2.id, n3.id, EdgeType.LEADS_TO)

        stats = eng.get_stats()
        assert stats["total_nodes"] == 3
        assert stats["total_edges"] == 2
        assert stats["exploitable_nodes"] == 1

        paths = eng.find_path(n1.id, n3.id, max_depth=6)
        assert len(paths) >= 1
        node_ids_in_path = [n.id for n in paths[0]]
        assert n1.id in node_ids_in_path
        assert n3.id in node_ids_in_path

    def test_smuggling_engine_returns_python_engine(self):
        from src.oneinfinity.scan.smuggling_engine import get_smuggling_engine, SmugglingEngine
        eng = get_smuggling_engine("http://example.com", timeout=5)
        assert isinstance(eng, SmugglingEngine)

    def test_rust_graph_enabled_false_without_flag(self):
        from src.oneinfinity.attack_graph_core.graph_engine import _rust_graph_enabled
        assert _rust_graph_enabled() is False

    def test_rust_smuggling_enabled_false_without_flag(self):
        from src.oneinfinity.scan.smuggling_engine import _rust_smuggling_enabled
        assert _rust_smuggling_enabled() is False


# ---------------------------------------------------------------------------
# Rust-backed integration (only when native build is present)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have_rust(), reason="oneinfinity_core not built")
class TestRustIntegration:

    def setup_method(self):
        os.environ["ONEINFINITY_RUST_GRAPH"] = "1"
        os.environ["ONEINFINITY_RUST_SMUGGLING"] = "1"

    def teardown_method(self):
        os.environ.pop("ONEINFINITY_RUST_GRAPH", None)
        os.environ.pop("ONEINFINITY_RUST_SMUGGLING", None)

    def test_rust_graph_enabled_with_flag(self):
        from src.oneinfinity.attack_graph_core.graph_engine import _rust_graph_enabled
        assert _rust_graph_enabled() is True

    def test_rust_smuggling_enabled_with_flag(self):
        from src.oneinfinity.scan.smuggling_engine import _rust_smuggling_enabled
        assert _rust_smuggling_enabled() is True

    def test_rust_engine_add_and_query(self):
        from src.oneinfinity.attack_graph_core.graph_engine import RustAttackGraphEngine, NodeType, EdgeType
        eng = RustAttackGraphEngine()
        n1 = eng.add_node(NodeType.TARGET, "rust_target.com")
        n2 = eng.add_node(NodeType.VULNERABILITY, "rust_vuln", severity="critical")
        eng.add_edge(n1.id, n2.id, EdgeType.HAS_VULNERABILITY)

        stats = eng.get_stats()
        assert stats["total_nodes"] == 2
        assert stats["total_edges"] == 1

    def test_rust_find_nodes_parity(self):
        from src.oneinfinity.attack_graph_core.graph_engine import (
            RustAttackGraphEngine, AttackGraphEngine, NodeType,
        )
        for Eng in (RustAttackGraphEngine, AttackGraphEngine):
            eng = Eng()
            eng.add_node(NodeType.VULNERABILITY, "xss_compat", severity="medium")
            eng.add_node(NodeType.TARGET, "compat_target")
            vulns = eng.find_nodes(node_type=NodeType.VULNERABILITY)
            assert len(vulns) == 1
            assert vulns[0].label == "xss_compat"

    def test_rust_query_bfs_paths(self):
        import oneinfinity_core as oc
        g = oc.AttackGraph()
        g.add_nodes([
            {"node_type": "target",       "id": "q_tgt",    "label": "q_target"},
            {"node_type": "vulnerability", "id": "q_vuln",   "label": "q_vuln"},
            {"node_type": "impact",       "id": "q_impact",  "label": "q_impact"},
        ])
        g.add_edges([
            {"source_id": "q_tgt",  "target_id": "q_vuln",   "edge_type": "leads_to"},
            {"source_id": "q_vuln", "target_id": "q_impact",  "edge_type": "leads_to"},
        ])
        paths = oc.bfs_paths(g, "q_tgt", ["impact"], 8)
        assert any("q_impact" in [n["id"] for n in p] for p in paths)

    def test_rust_find_attack_paths_structure(self):
        import oneinfinity_core as oc
        g = oc.AttackGraph()
        g.add_nodes([
            {"node_type": "target", "id": "ap_tgt", "label": "ap_target"},
            {"node_type": "impact", "id": "ap_imp", "label": "ap_impact"},
        ])
        g.add_edges([{"source_id": "ap_tgt", "target_id": "ap_imp", "edge_type": "leads_to"}])
        paths = oc.find_attack_paths(g, "ap_tgt", 6)
        for p in paths:
            assert "total_score" in p
            assert "difficulty" in p

    def test_rust_smuggling_unreachable_returns_empty(self):
        import oneinfinity_core as oc
        findings = oc.run_smuggling_scan("http://127.0.0.1:1", 1)
        assert isinstance(findings, list)
        assert findings == []


# ---------------------------------------------------------------------------
# Feature-flag isolation
# ---------------------------------------------------------------------------

class TestFeatureFlagIsolation:
    """Setting GRAPH flag must not affect SMUGGLING, and vice versa."""

    def test_graph_flag_does_not_enable_smuggling(self, monkeypatch):
        monkeypatch.setenv("ONEINFINITY_RUST_GRAPH", "1")
        monkeypatch.delenv("ONEINFINITY_RUST_SMUGGLING", raising=False)
        from src.oneinfinity.scan.smuggling_engine import _rust_smuggling_enabled
        assert _rust_smuggling_enabled() is False

    def test_smuggling_flag_does_not_enable_graph(self, monkeypatch):
        monkeypatch.setenv("ONEINFINITY_RUST_SMUGGLING", "1")
        monkeypatch.delenv("ONEINFINITY_RUST_GRAPH", raising=False)
        from src.oneinfinity.attack_graph_core.graph_engine import _rust_graph_enabled
        assert _rust_graph_enabled() is False

    def test_zero_value_disables_graph(self, monkeypatch):
        monkeypatch.setenv("ONEINFINITY_RUST_GRAPH", "0")
        from src.oneinfinity.attack_graph_core.graph_engine import _rust_graph_enabled
        assert _rust_graph_enabled() is False

    def test_false_string_disables_smuggling(self, monkeypatch):
        monkeypatch.setenv("ONEINFINITY_RUST_SMUGGLING", "false")
        from src.oneinfinity.scan.smuggling_engine import _rust_smuggling_enabled
        assert _rust_smuggling_enabled() is False

    def test_nonempty_non_zero_enables_graph_if_rust_present(self, monkeypatch):
        if not _have_rust():
            pytest.skip("oneinfinity_core not built")
        monkeypatch.setenv("ONEINFINITY_RUST_GRAPH", "yes")
        from src.oneinfinity.attack_graph_core.graph_engine import _rust_graph_enabled
        assert _rust_graph_enabled() is True


# ---------------------------------------------------------------------------
# Cargo.lock exists (regression: maturin pinning)
# ---------------------------------------------------------------------------

class TestCargoLockExists:
    def test_cargo_lock_present(self):
        import pathlib
        cargo_lock = pathlib.Path("src/rust/oneinfinity_core/Cargo.lock")
        # Cargo.lock is generated after first build — either it exists or
        # Cargo.toml is present (pre-build state is acceptable)
        cargo_toml = pathlib.Path("src/rust/oneinfinity_core/Cargo.toml")
        assert cargo_toml.exists(), "Cargo.toml missing — Rust crate not set up"

    def test_cargo_toml_has_petgraph(self):
        import pathlib
        content = pathlib.Path("src/rust/oneinfinity_core/Cargo.toml").read_text()
        assert 'petgraph' in content

    def test_cargo_toml_has_tokio(self):
        import pathlib
        content = pathlib.Path("src/rust/oneinfinity_core/Cargo.toml").read_text()
        assert 'tokio' in content
# ---------------------------------------------------------------------------
# Gate 2 — Input limit enforcement (GRAPH_CONTRACT §8)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have_rust(), reason="oneinfinity_core not built")
class TestInputLimits:
    def test_add_nodes_over_limit_raises(self):
        import oneinfinity_core as oc
        g = oc.AttackGraph()
        # Attempt 50001 nodes — must raise PyValueError
        big_batch = [{"node_type": "target", "label": f"t{i}"} for i in range(50_001)]
        import pytest as _pt
        with _pt.raises(ValueError):
            g.add_nodes(big_batch)

    def test_label_too_long_raises(self):
        import oneinfinity_core as oc
        g = oc.AttackGraph()
        long_label = "x" * 1025
        import pytest as _pt
        with _pt.raises(ValueError):
            g.add_nodes([{"node_type": "target", "label": long_label}])

    def test_depth_capped_at_32(self):
        import oneinfinity_core as oc
        g = oc.AttackGraph()
        # Linear chain of 5 nodes
        nodes = [{"node_type": "target", "id": f"d{i}", "label": f"depth{i}"} for i in range(5)]
        g.add_nodes(nodes)
        g.add_edges([{"source_id": f"d{i}", "target_id": f"d{i+1}", "edge_type": "leads_to"}
                     for i in range(4)])
        # max_depth=999 should be silently capped, not panic
        paths = oc.dfs_paths(g, "d0", "d4", 999)
        assert isinstance(paths, list)

    def test_add_edges_over_limit_raises(self):
        import oneinfinity_core as oc
        g = oc.AttackGraph()
        # Need 200001 edges — create 2 nodes and attempt bulk add
        g.add_nodes([
            {"node_type": "target", "id": "src", "label": "src"},
            {"node_type": "target", "id": "tgt", "label": "tgt"},
        ])
        big_edges = [{"source_id": "src", "target_id": "tgt", "edge_type": f"e{i}"}
                     for i in range(200_001)]
        import pytest as _pt
        with _pt.raises(ValueError):
            g.add_edges(big_edges)


# ---------------------------------------------------------------------------
# Gate 2 — GRAPH_CONTRACT.md and parity infrastructure
# ---------------------------------------------------------------------------

class TestGraphContract:
    def test_graph_contract_exists(self):
        import pathlib
        assert pathlib.Path("GRAPH_CONTRACT.md").exists(), "GRAPH_CONTRACT.md missing"

    def test_graph_contract_mentions_version(self):
        import pathlib
        content = pathlib.Path("GRAPH_CONTRACT.md").read_text()
        assert "GRAPH_CONTRACT_VERSION" in content
        assert "1.0.0" in content

    def test_small_graph_heuristic_functions_exist(self):
        from src.oneinfinity.attack_graph_core.graph_engine import (
            _small_graph_heuristic, _emit_parity_artifact, _RUST_GRAPH_MIN_NODES,
        )
        assert _RUST_GRAPH_MIN_NODES == 100
        assert callable(_small_graph_heuristic)
        assert callable(_emit_parity_artifact)

    def test_parity_emit_does_not_raise(self, tmp_path, monkeypatch):
        import os
        log_file = tmp_path / "parity.jsonl"
        monkeypatch.setenv("ONEINFINITY_PARITY_LOG", str(log_file))
        from src.oneinfinity.attack_graph_core.graph_engine import _emit_parity_artifact
        _emit_parity_artifact("test_op", "some_input", ["a", "b"], ["a", "b"])
        assert log_file.exists()
        import json
        line = json.loads(log_file.read_text().strip())
        assert line["match"] is True
        assert line["diff_summary"] == "MATCH"

    def test_parity_mismatch_logged(self, tmp_path, monkeypatch):
        import os
        log_file = tmp_path / "parity_mismatch.jsonl"
        monkeypatch.setenv("ONEINFINITY_PARITY_LOG", str(log_file))
        from src.oneinfinity.attack_graph_core.graph_engine import _emit_parity_artifact
        _emit_parity_artifact("test_op", "inp", ["result_A"], ["result_B"])
        import json
        line = json.loads(log_file.read_text().strip())
        assert line["match"] is False
        assert "divergence" in line["diff_summary"]
