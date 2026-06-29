//! Graph query free functions exposed to Python.
//!
//! Five functions:
//!   bfs_paths, dfs_paths, find_attack_paths,
//!   find_privilege_escalation_chains, find_credential_access_paths
//!
//! All accept a `&AttackGraph`, return deterministic (sorted) Python objects,
//! and are wrapped in `catch_unwind`.

use std::collections::BTreeMap;
use std::panic::catch_unwind;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyList;

use super::engine::{json_val_to_py, AttackGraph};

const ADMIN_PATTERNS: &[&str] = &[
    "/admin", "/dashboard", "/manage", "/control", "/superuser", "/root",
];

const SEVERITY_SCORE: &[(&str, f64)] = &[
    ("info", 1.0),
    ("low", 3.0),
    ("medium", 5.0),
    ("high", 8.0),
    ("critical", 10.0),
];

fn severity_to_score(sev: &Option<String>) -> f64 {
    match sev {
        None => 1.0,
        Some(s) => SEVERITY_SCORE
            .iter()
            .find(|(k, _)| *k == s.as_str())
            .map(|(_, v)| *v)
            .unwrap_or(1.0),
    }
}

/// Convert a list of node-id paths into Python dicts.
fn paths_to_py<'py>(
    py: Python<'py>,
    graph: &AttackGraph,
    id_paths: &[Vec<String>],
) -> PyResult<Vec<PyObject>> {
    let mut out = Vec::with_capacity(id_paths.len());
    for path in id_paths {
        let list = PyList::empty_bound(py);
        for nid in path {
            match graph.inner.get_node_data(nid) {
                Some(nd) => list.append(nd.to_pydict(py)?)?,
                None => list.append(py.None())?,
            }
        }
        out.push(list.into_py(py));
    }
    Ok(out)
}

/// Score an id-path by exploitability (avg severity of vuln/exploit nodes).
fn exploitability_score(graph: &AttackGraph, path: &[String]) -> f64 {
    let scores: Vec<f64> = path
        .iter()
        .filter_map(|id| graph.inner.get_node_data(id))
        .filter(|nd| nd.node_type == "vulnerability" || nd.node_type == "exploit")
        .map(|nd| severity_to_score(&nd.severity))
        .collect();
    if scores.is_empty() {
        1.0
    } else {
        scores.iter().sum::<f64>() / scores.len() as f64
    }
}

/// Score a path by impact (max severity of impact nodes, else 5.0).
fn impact_score(graph: &AttackGraph, path: &[String]) -> f64 {
    path.iter()
        .filter_map(|id| graph.inner.get_node_data(id))
        .filter(|nd| nd.node_type == "impact" || nd.node_type == "vulnerability")
        .map(|nd| severity_to_score(&nd.severity))
        .fold(5.0_f64, f64::max)
}

// ---------------------------------------------------------------------------
// Public free functions
// ---------------------------------------------------------------------------

/// BFS from `start_id`.  `target_types`: list of node_type strings to stop at
/// (empty = return all paths).  Returns list-of-list-of-node-dicts.
#[pyfunction]
pub fn bfs_paths<'py>(
    py: Python<'py>,
    graph: &AttackGraph,
    start_id: &str,
    target_types: Vec<String>,
    max_depth: usize,
) -> PyResult<Vec<PyObject>> {
    catch_unwind(std::panic::AssertUnwindSafe(|| {
        let depth = max_depth.min(32);
        let mut id_paths = graph.inner.bfs_paths(start_id, &target_types, depth);
        id_paths.truncate(10_000);
        paths_to_py(py, graph, &id_paths)
    }))
    .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in bfs_paths"))?
}

/// DFS from `start_id` to `end_id`.  Returns list-of-list-of-node-dicts.
#[pyfunction]
pub fn dfs_paths<'py>(
    py: Python<'py>,
    graph: &AttackGraph,
    start_id: &str,
    end_id: &str,
    max_depth: usize,
) -> PyResult<Vec<PyObject>> {
    catch_unwind(std::panic::AssertUnwindSafe(|| {
        let depth = max_depth.min(32);
        let mut id_paths = graph.inner.dfs_paths(start_id, end_id, depth);
        id_paths.truncate(10_000);
        paths_to_py(py, graph, &id_paths)
    }))
    .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in dfs_paths"))?
}

/// Find scored attack paths from `target_id` toward impact/exploit nodes.
/// Returns list of dicts with keys: path_id, nodes, total_score, …
#[pyfunction]
pub fn find_attack_paths<'py>(
    py: Python<'py>,
    graph: &AttackGraph,
    target_id: &str,
    max_depth: usize,
) -> PyResult<Vec<PyObject>> {
    catch_unwind(std::panic::AssertUnwindSafe(|| {
        let id_paths = graph.inner.bfs_paths(
            target_id,
            &["impact".to_string(), "exploit".to_string()],
            max_depth,
        );

        let mut attack_paths: Vec<BTreeMap<String, serde_json::Value>> = Vec::new();
        for path in &id_paths {
            if path.len() < 2 {
                continue;
            }
            let exp_score = exploitability_score(graph, path);
            let imp_score = impact_score(graph, path);
            let total = (exp_score * 0.4) + (imp_score * 0.6);
            let difficulty = if exp_score > 7.0 {
                "easy"
            } else if exp_score > 4.0 {
                "medium"
            } else {
                "hard"
            };
            let entry = graph.inner.get_node_data(&path[0])
                .map(|n| n.label.clone())
                .unwrap_or_default();
            let last = graph.inner.get_node_data(path.last().unwrap())
                .map(|n| n.label.clone())
                .unwrap_or_default();

            let mut ap: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            ap.insert("path_id".into(), serde_json::json!(uuid_str()));
            ap.insert("node_ids".into(), serde_json::json!(path));
            ap.insert("total_score".into(), serde_json::json!((total * 100.0).round() / 100.0));
            ap.insert("exploitability_score".into(), serde_json::json!((exp_score * 100.0).round() / 100.0));
            ap.insert("impact_score".into(), serde_json::json!((imp_score * 100.0).round() / 100.0));
            ap.insert("difficulty".into(), serde_json::json!(difficulty));
            ap.insert("entry_point".into(), serde_json::json!(entry));
            ap.insert("final_impact".into(), serde_json::json!(last));
            ap.insert("source_engine".into(), serde_json::json!("rust"));
            attack_paths.push(ap);
        }

        // Sort by total_score descending, then by node_ids for determinism.
        attack_paths.sort_by(|a, b| {
            let sa = a["total_score"].as_f64().unwrap_or(0.0);
            let sb = b["total_score"].as_f64().unwrap_or(0.0);
            sb.partial_cmp(&sa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a["node_ids"].to_string().cmp(&b["node_ids"].to_string()))
        });

        let mut out = Vec::new();
        for ap in &attack_paths {
            let val = serde_json::to_value(ap).unwrap_or_default();
            out.push(json_val_to_py(py, &val)?);
        }
        Ok(out)
    }))
    .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in find_attack_paths"))?
}

/// Find privilege escalation chains (IDOR/BAC → admin endpoint).
/// Returns sorted list of chain dicts.
#[pyfunction]
pub fn find_privilege_escalation_chains<'py>(
    py: Python<'py>,
    graph: &AttackGraph,
) -> PyResult<Vec<PyObject>> {
    catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Collect candidate start nodes (idor / bac / auth_bypass)
        let mut candidates: Vec<String> = Vec::new();
        for nidx in graph.inner.graph.node_indices() {
            let nd = &graph.inner.graph[nidx];
            if nd.node_type == "vulnerability" {
                let lbl = nd.label.to_lowercase();
                if lbl.contains("idor") || lbl.contains("bac") || lbl.contains("auth_bypass") {
                    candidates.push(nd.id.clone());
                }
            }
        }

        // Collect admin endpoint targets
        let mut admin_targets: Vec<String> = Vec::new();
        for nidx in graph.inner.graph.node_indices() {
            let nd = &graph.inner.graph[nidx];
            if nd.node_type == "url" || nd.node_type == "api_endpoint" {
                let lbl = nd.label.to_lowercase();
                if ADMIN_PATTERNS.iter().any(|p| lbl.contains(p)) {
                    let auth_required = nd.properties.get("auth_required")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !auth_required {
                        admin_targets.push(nd.id.clone());
                    }
                }
            }
        }

        let mut chains: Vec<BTreeMap<String, serde_json::Value>> = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = Default::default();

        for start in &candidates {
            for admin in &admin_targets {
                let paths = graph.inner.dfs_paths(start, admin, 5);
                for path in &paths {
                    let key = format!("{start}:{admin}:{path:?}");
                    if seen.contains(&key) { continue; }
                    seen.insert(key);
                    let mut chain: BTreeMap<String, serde_json::Value> = BTreeMap::new();
                    chain.insert("chain_id".into(), serde_json::json!(uuid_str()));
                    chain.insert("name".into(), serde_json::json!("Privilege Escalation Chain"));
                    chain.insert("node_ids".into(), serde_json::json!(path));
                    chain.insert("severity".into(), serde_json::json!("high"));
                    chain.insert("source_engine".into(), serde_json::json!("rust"));
                    chains.push(chain);
                }
            }
        }

        chains.sort_by_key(|c| c["node_ids"].to_string());

        let mut out = Vec::new();
        for c in &chains {
            let val = serde_json::to_value(c).unwrap_or_default();
            out.push(json_val_to_py(py, &val)?);
        }
        Ok(out)
    }))
    .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in find_privilege_escalation_chains"))?
}

/// Find all paths from target nodes to credential nodes.
/// Returns sorted list of path dicts.
#[pyfunction]
pub fn find_credential_access_paths<'py>(
    py: Python<'py>,
    graph: &AttackGraph,
) -> PyResult<Vec<PyObject>> {
    catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut target_ids: Vec<String> = Vec::new();
        let mut cred_ids: Vec<String> = Vec::new();
        for nidx in graph.inner.graph.node_indices() {
            let nd = &graph.inner.graph[nidx];
            if nd.node_type == "target" { target_ids.push(nd.id.clone()); }
            if nd.node_type == "credential" { cred_ids.push(nd.id.clone()); }
        }
        target_ids.sort();
        cred_ids.sort();

        let mut results: Vec<BTreeMap<String, serde_json::Value>> = Vec::new();
        for tgt in &target_ids {
            for cred in &cred_ids {
                let paths = graph.inner.dfs_paths(tgt, cred, 7);
                for path in &paths {
                    let cred_label = graph.inner.get_node_data(cred)
                        .map(|n| n.label.clone())
                        .unwrap_or_default();
                    let tgt_label = graph.inner.get_node_data(tgt)
                        .map(|n| n.label.clone())
                        .unwrap_or_default();
                    let exp_score = exploitability_score(graph, path);
                    let total = ((exp_score * 0.3) + (9.0 * 0.7) * 100.0).round() / 100.0;
                    let mut ap: BTreeMap<String, serde_json::Value> = BTreeMap::new();
                    ap.insert("path_id".into(), serde_json::json!(uuid_str()));
                    ap.insert("node_ids".into(), serde_json::json!(path));
                    ap.insert("total_score".into(), serde_json::json!(total));
                    ap.insert("exploitability_score".into(), serde_json::json!((exp_score * 100.0).round() / 100.0));
                    ap.insert("impact_score".into(), serde_json::json!(9.0));
                    ap.insert("entry_point".into(), serde_json::json!(tgt_label));
                    ap.insert("final_impact".into(), serde_json::json!(format!("Credential access: {cred_label}")));
                    ap.insert("source_engine".into(), serde_json::json!("rust"));
                    results.push(ap);
                }
            }
        }

        results.sort_by_key(|r| r["node_ids"].to_string());

        let mut out = Vec::new();
        for r in &results {
            let val = serde_json::to_value(r).unwrap_or_default();
            out.push(json_val_to_py(py, &val)?);
        }
        Ok(out)
    }))
    .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in find_credential_access_paths"))?
}

// ---------------------------------------------------------------------------
// Minimal UUID-like unique id (no uuid crate needed)
// ---------------------------------------------------------------------------

fn uuid_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Mix with a thread_local counter for uniqueness within same nanosecond.
    use std::cell::Cell;
    thread_local! {
        static CTR: Cell<u64> = const { Cell::new(0) };
    }
    let ctr = CTR.with(|c| { let v = c.get(); c.set(v + 1); v });
    format!("{t:016x}{ctr:08x}")
}

// ---------------------------------------------------------------------------
// Register into PyModule
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(bfs_paths, m)?)?;
    m.add_function(wrap_pyfunction!(dfs_paths, m)?)?;
    m.add_function(wrap_pyfunction!(find_attack_paths, m)?)?;
    m.add_function(wrap_pyfunction!(find_privilege_escalation_chains, m)?)?;
    m.add_function(wrap_pyfunction!(find_credential_access_paths, m)?)?;
    Ok(())
}
