"""
test_graph_query.py — parity tests for the five Rust graph-query free functions.
"""
import pytest

try:
    import oneinfinity_core as _oc
    _HAVE_RUST = (
        hasattr(_oc, "AttackGraph")
        and hasattr(_oc, "bfs_paths")
        and hasattr(_oc, "dfs_paths")
        and hasattr(_oc, "find_attack_paths")
        and hasattr(_oc, "find_privilege_escalation_chains")
        and hasattr(_oc, "find_credential_access_paths")
    )
except ImportError:
    _HAVE_RUST = False

pytestmark = pytest.mark.skipif(not _HAVE_RUST, reason="oneinfinity_core not built")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def simple_graph():
    """target -> vulnerability -> credential"""
    g = _oc.AttackGraph()
    nodes = [
        {"node_type": "target",        "id": "n_tgt",  "label": "example.com"},
        {"node_type": "vulnerability",  "id": "n_vuln", "label": "sqli_login",
         "severity": "high", "exploitable": "true"},
        {"node_type": "credential",     "id": "n_cred", "label": "admin_pw"},
    ]
    g.add_nodes(nodes)
    edges = [
        {"source_id": "n_tgt",  "target_id": "n_vuln", "edge_type": "has_vulnerability"},
        {"source_id": "n_vuln", "target_id": "n_cred", "edge_type": "leads_to"},
    ]
    g.add_edges(edges)
    return g


@pytest.fixture
def impact_graph():
    """target -> vulnerability -> impact (for find_attack_paths)"""
    g = _oc.AttackGraph()
    nodes = [
        {"node_type": "target",       "id": "at_tgt",    "label": "target.com"},
        {"node_type": "vulnerability", "id": "at_vuln",   "label": "rce_vuln",
         "severity": "critical"},
        {"node_type": "impact",       "id": "at_impact",  "label": "rce_impact"},
    ]
    g.add_nodes(nodes)
    edges = [
        {"source_id": "at_tgt",  "target_id": "at_vuln",   "edge_type": "has_vulnerability"},
        {"source_id": "at_vuln", "target_id": "at_impact",  "edge_type": "leads_to"},
    ]
    g.add_edges(edges)
    return g


@pytest.fixture
def privesc_graph():
    """idor_vuln -> admin_endpoint (no auth_required)"""
    g = _oc.AttackGraph()
    nodes = [
        {"node_type": "vulnerability", "id": "pe_idor",  "label": "idor_user_profile"},
        {"node_type": "url",           "id": "pe_admin", "label": "/admin/users",
         "properties": {"auth_required": False}},
    ]
    g.add_nodes(nodes)
    g.add_edges([
        {"source_id": "pe_idor", "target_id": "pe_admin", "edge_type": "leads_to"}
    ])
    return g


@pytest.fixture
def cred_access_graph():
    """target -> vulnerability -> credential"""
    g = _oc.AttackGraph()
    nodes = [
        {"node_type": "target",       "id": "ca_tgt",  "label": "ca_target.com"},
        {"node_type": "vulnerability", "id": "ca_vuln", "label": "ssrf"},
        {"node_type": "credential",   "id": "ca_cred", "label": "aws_access_key"},
    ]
    g.add_nodes(nodes)
    g.add_edges([
        {"source_id": "ca_tgt",  "target_id": "ca_vuln", "edge_type": "leads_to"},
        {"source_id": "ca_vuln", "target_id": "ca_cred", "edge_type": "leads_to"},
    ])
    return g


# ---------------------------------------------------------------------------
# bfs_paths
# ---------------------------------------------------------------------------

class TestBfsPaths:
    def test_bfs_finds_credential_path(self, simple_graph):
        paths = _oc.bfs_paths(simple_graph, "n_tgt", ["credential"], 8)
        assert any("n_cred" in _node_ids(p) for p in paths)

    def test_bfs_no_target_types_returns_all(self, simple_graph):
        paths = _oc.bfs_paths(simple_graph, "n_tgt", [], 8)
        assert len(paths) >= 2  # at least [n_tgt,n_vuln] and [n_tgt,n_vuln,n_cred]

    def test_bfs_max_depth_one_stops_early(self, simple_graph):
        paths = _oc.bfs_paths(simple_graph, "n_tgt", ["credential"], 1)
        # credential is 2 hops away, should not be reachable at depth 1
        assert all("n_cred" not in _node_ids(p) for p in paths)

    def test_bfs_returns_list_of_lists(self, simple_graph):
        paths = _oc.bfs_paths(simple_graph, "n_tgt", [], 4)
        assert isinstance(paths, list)
        for p in paths:
            assert isinstance(p, list)

    def test_bfs_unknown_start_returns_empty(self, simple_graph):
        paths = _oc.bfs_paths(simple_graph, "ghost", [], 4)
        assert paths == []

    def test_bfs_deterministic(self, simple_graph):
        """Two calls must return the same sorted result."""
        p1 = _oc.bfs_paths(simple_graph, "n_tgt", [], 8)
        p2 = _oc.bfs_paths(simple_graph, "n_tgt", [], 8)
        assert _path_set(p1) == _path_set(p2)


# ---------------------------------------------------------------------------
# dfs_paths
# ---------------------------------------------------------------------------

class TestDfsPaths:
    def test_dfs_finds_direct_path(self, simple_graph):
        paths = _oc.dfs_paths(simple_graph, "n_tgt", "n_cred", 6)
        assert len(paths) >= 1
        found = any(
            _node_ids(p)[0] == "n_tgt" and _node_ids(p)[-1] == "n_cred"
            for p in paths
        )
        assert found

    def test_dfs_no_path_returns_empty(self, simple_graph):
        # reverse direction — no edges go cred -> tgt
        paths = _oc.dfs_paths(simple_graph, "n_cred", "n_tgt", 6)
        assert paths == []

    def test_dfs_same_source_and_target_empty(self, simple_graph):
        paths = _oc.dfs_paths(simple_graph, "n_tgt", "n_tgt", 6)
        assert paths == []

    def test_dfs_deterministic(self, simple_graph):
        p1 = _oc.dfs_paths(simple_graph, "n_tgt", "n_cred", 6)
        p2 = _oc.dfs_paths(simple_graph, "n_tgt", "n_cred", 6)
        assert _path_set(p1) == _path_set(p2)

    def test_dfs_max_depth_respected(self, simple_graph):
        # depth=1 means at most 2 nodes; can't reach cred (3 nodes away)
        paths = _oc.dfs_paths(simple_graph, "n_tgt", "n_cred", 1)
        assert paths == []


# ---------------------------------------------------------------------------
# find_attack_paths
# ---------------------------------------------------------------------------

class TestFindAttackPaths:
    def test_returns_sorted_by_score(self, impact_graph):
        paths = _oc.find_attack_paths(impact_graph, "at_tgt", 8)
        if len(paths) >= 2:
            scores = [p["total_score"] for p in paths]
            assert scores == sorted(scores, reverse=True)

    def test_path_has_required_keys(self, impact_graph):
        paths = _oc.find_attack_paths(impact_graph, "at_tgt", 8)
        assert len(paths) >= 1
        p = paths[0]
        for key in ("path_id", "node_ids", "total_score", "exploitability_score",
                    "impact_score", "difficulty", "entry_point", "final_impact"):
            assert key in p, f"Missing key in attack path: {key}"

    def test_difficulty_values(self, impact_graph):
        paths = _oc.find_attack_paths(impact_graph, "at_tgt", 8)
        valid = {"easy", "medium", "hard"}
        for p in paths:
            assert p["difficulty"] in valid

    def test_unknown_target_returns_empty(self, impact_graph):
        paths = _oc.find_attack_paths(impact_graph, "ghost", 8)
        assert paths == []

    def test_deterministic_output(self, impact_graph):
        p1 = _oc.find_attack_paths(impact_graph, "at_tgt", 8)
        p2 = _oc.find_attack_paths(impact_graph, "at_tgt", 8)
        ids1 = [p["node_ids"] for p in p1]
        ids2 = [p["node_ids"] for p in p2]
        assert ids1 == ids2


# ---------------------------------------------------------------------------
# find_privilege_escalation_chains
# ---------------------------------------------------------------------------

class TestPrivEscChains:
    def test_finds_idor_to_admin_chain(self, privesc_graph):
        chains = _oc.find_privilege_escalation_chains(privesc_graph)
        assert len(chains) >= 1

    def test_chain_has_required_keys(self, privesc_graph):
        chains = _oc.find_privilege_escalation_chains(privesc_graph)
        if chains:
            c = chains[0]
            for key in ("chain_id", "name", "node_ids"):
                assert key in c

    def test_empty_graph_returns_empty(self):
        g = _oc.AttackGraph()
        chains = _oc.find_privilege_escalation_chains(g)
        assert chains == []

    def test_no_admin_endpoint_returns_empty(self):
        g = _oc.AttackGraph()
        g.add_nodes([
            {"node_type": "vulnerability", "id": "v1", "label": "idor_something"},
            {"node_type": "url", "id": "u1", "label": "/safe_endpoint"},
        ])
        chains = _oc.find_privilege_escalation_chains(g)
        assert chains == []


# ---------------------------------------------------------------------------
# find_credential_access_paths
# ---------------------------------------------------------------------------

class TestCredentialAccessPaths:
    def test_finds_path_to_credential(self, cred_access_graph):
        paths = _oc.find_credential_access_paths(cred_access_graph)
        assert len(paths) >= 1

    def test_path_has_required_keys(self, cred_access_graph):
        paths = _oc.find_credential_access_paths(cred_access_graph)
        p = paths[0]
        for key in ("path_id", "node_ids", "total_score", "entry_point", "final_impact"):
            assert key in p

    def test_final_impact_mentions_credential(self, cred_access_graph):
        paths = _oc.find_credential_access_paths(cred_access_graph)
        assert any("credential" in p["final_impact"].lower() or
                   "aws" in p["final_impact"].lower()
                   for p in paths)

    def test_empty_graph_returns_empty(self):
        g = _oc.AttackGraph()
        assert _oc.find_credential_access_paths(g) == []

    def test_deterministic(self, cred_access_graph):
        p1 = _oc.find_credential_access_paths(cred_access_graph)
        p2 = _oc.find_credential_access_paths(cred_access_graph)
        ids1 = [p["node_ids"] for p in p1]
        ids2 = [p["node_ids"] for p in p2]
        assert ids1 == ids2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _node_ids(node_list) -> list:
    """Extract id strings from a list of node dicts."""
    return [n["id"] if isinstance(n, dict) else getattr(n, "id", "") for n in node_list]


def _path_set(paths) -> frozenset:
    """Convert list of paths to a frozenset of tuples for order-independent comparison."""
    return frozenset(tuple(_node_ids(p)) for p in paths)
