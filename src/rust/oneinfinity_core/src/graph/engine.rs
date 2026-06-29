//! petgraph-backed attack graph — PyO3 entry point.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::panic::catch_unwind;
use std::time::{SystemTime, UNIX_EPOCH};

use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef as _;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use sha2::{Digest as _, Sha256};

// ---------------------------------------------------------------------------
// Input limits (GRAPH_CONTRACT.md §8)
// ---------------------------------------------------------------------------

const MAX_NODES_PER_CALL: usize = 50_000;
const MAX_EDGES_PER_CALL: usize = 200_000;
const MAX_LABEL_BYTES: usize = 1_024;
const MAX_DEPTH: usize = 32;
const MAX_PATH_RESULTS: usize = 10_000;

// ---------------------------------------------------------------------------
// Internal data types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct NodeData {
    pub id: String,
    pub node_type: String,
    pub label: String,
    pub properties: BTreeMap<String, serde_json::Value>,
    pub severity: Option<String>,
    pub risk_score: f64,
    pub exploitable: bool,
    pub validated: bool,
    pub discovered_at: String,
    pub updated_at: String,
    pub source: String,
    pub tags: Vec<String>,
}

impl NodeData {
    pub fn to_pydict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new_bound(py);
        d.set_item("id", &self.id)?;
        d.set_item("node_type", &self.node_type)?;
        d.set_item("label", &self.label)?;
        let props = json_val_to_py(py, &serde_json::to_value(&self.properties).unwrap_or_default())?;
        d.set_item("properties", props)?;
        match &self.severity {
            Some(s) => d.set_item("severity", s)?,
            None => d.set_item("severity", py.None())?,
        }
        d.set_item("risk_score", self.risk_score)?;
        d.set_item("exploitable", self.exploitable)?;
        d.set_item("validated", self.validated)?;
        d.set_item("discovered_at", &self.discovered_at)?;
        d.set_item("updated_at", &self.updated_at)?;
        d.set_item("source", &self.source)?;
        let tags_vec: Vec<&str> = self.tags.iter().map(|s| s.as_str()).collect();
        let tags_list = PyList::new_bound(py, &tags_vec);
        d.set_item("tags", tags_list)?;
        Ok(d)
    }
}

#[derive(Clone, Debug)]
pub struct EdgeData {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub edge_type: String,
    pub label: String,
    pub properties: BTreeMap<String, serde_json::Value>,
    pub probability: f64,
    pub weight: f64,
    pub requires_auth: bool,
    pub created_at: String,
    pub source_engine: String,
}

impl EdgeData {
    pub fn to_pydict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new_bound(py);
        d.set_item("id", &self.id)?;
        d.set_item("source_id", &self.source_id)?;
        d.set_item("target_id", &self.target_id)?;
        d.set_item("edge_type", &self.edge_type)?;
        d.set_item("label", &self.label)?;
        let props = json_val_to_py(py, &serde_json::to_value(&self.properties).unwrap_or_default())?;
        d.set_item("properties", props)?;
        d.set_item("probability", self.probability)?;
        d.set_item("weight", self.weight)?;
        d.set_item("requires_auth", self.requires_auth)?;
        d.set_item("created_at", &self.created_at)?;
        d.set_item("source_engine", &self.source_engine)?;
        Ok(d)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_ts() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn sha24(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let result = h.finalize();
    result[..12].iter().map(|b| format!("{b:02x}")).collect()
}

/// Recursively convert serde_json::Value into a Python object.
pub fn json_val_to_py<'py>(py: Python<'py>, v: &serde_json::Value) -> PyResult<PyObject> {
    use serde_json::Value::*;
    match v {
        Null => Ok(py.None()),
        Bool(b) => Ok(b.into_py(py)),
        Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else {
                Ok(n.as_f64().unwrap_or(0.0).into_py(py))
            }
        }
        String(s) => Ok(s.into_py(py)),
        Array(arr) => {
            let list = PyList::empty_bound(py);
            for item in arr {
                list.append(json_val_to_py(py, item)?)?;
            }
            Ok(list.into_py(py))
        }
        Object(map) => {
            let dict = PyDict::new_bound(py);
            let mut keys: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
            keys.sort_unstable();
            for k in keys {
                dict.set_item(k, json_val_to_py(py, &map[k])?)?;
            }
            Ok(dict.into_py(py))
        }
    }
}

fn str_from_dict(d: &Bound<'_, PyDict>, key: &str) -> String {
    d.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.extract::<String>().ok())
        .unwrap_or_default()
}

fn bool_from_dict(d: &Bound<'_, PyDict>, key: &str) -> bool {
    d.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.extract::<bool>().ok())
        .unwrap_or(false)
}

fn f64_from_dict(d: &Bound<'_, PyDict>, key: &str, default: f64) -> f64 {
    d.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.extract::<f64>().ok())
        .unwrap_or(default)
}

fn tags_from_dict(d: &Bound<'_, PyDict>) -> Vec<String> {
    d.get_item("tags")
        .ok()
        .flatten()
        .and_then(|v| v.extract::<Vec<String>>().ok())
        .unwrap_or_default()
}

fn props_from_dict(
    d: &Bound<'_, PyDict>,
) -> PyResult<BTreeMap<String, serde_json::Value>> {
    if let Some(props_obj) = d.get_item("properties").ok().flatten() {
        if let Ok(props_dict) = props_obj.downcast::<PyDict>() {
            let mut out = BTreeMap::new();
            for (k, v) in props_dict.iter() {
                let key: String = k.extract()?;
                let val: serde_json::Value = if let Ok(b) = v.extract::<bool>() {
                    serde_json::Value::Bool(b)
                } else if let Ok(s) = v.extract::<String>() {
                    serde_json::Value::String(s)
                } else if let Ok(f) = v.extract::<f64>() {
                    serde_json::json!(f)
                } else {
                    serde_json::Value::String(v.str()?.to_string())
                };
                out.insert(key, val);
            }
            return Ok(out);
        }
    }
    Ok(BTreeMap::new())
}

// ---------------------------------------------------------------------------
// Core graph struct
// ---------------------------------------------------------------------------

pub struct InnerGraph {
    pub graph: DiGraph<NodeData, EdgeData>,
    pub idx_by_id: HashMap<String, NodeIndex>,
    pub id_by_label: HashMap<(String, String), String>,
    pub eidx_by_key: HashMap<(String, String, String), EdgeIndex>,
}

impl InnerGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            idx_by_id: HashMap::new(),
            id_by_label: HashMap::new(),
            eidx_by_key: HashMap::new(),
        }
    }

    pub fn add_node_inner(&mut self, nd: NodeData) -> String {
        let label_key = (nd.node_type.clone(), nd.label.clone());
        if let Some(existing_id) = self.id_by_label.get(&label_key) {
            return existing_id.clone();
        }
        let id = nd.id.clone();
        let nidx = self.graph.add_node(nd);
        self.idx_by_id.insert(id.clone(), nidx);
        self.id_by_label.insert(label_key, id.clone());
        id
    }

    pub fn get_node_data(&self, id: &str) -> Option<&NodeData> {
        let nidx = self.idx_by_id.get(id)?;
        self.graph.node_weight(*nidx)
    }

    pub fn get_node_data_mut(&mut self, id: &str) -> Option<&mut NodeData> {
        let nidx = *self.idx_by_id.get(id)?;
        self.graph.node_weight_mut(nidx)
    }

    pub fn add_edge_inner(&mut self, ed: EdgeData) -> Option<String> {
        let src_idx = *self.idx_by_id.get(&ed.source_id)?;
        let tgt_idx = *self.idx_by_id.get(&ed.target_id)?;
        let ekey = (ed.source_id.clone(), ed.target_id.clone(), ed.edge_type.clone());
        if self.eidx_by_key.contains_key(&ekey) {
            let eidx = self.eidx_by_key[&ekey];
            return self.graph.edge_weight(eidx).map(|e| e.id.clone());
        }
        let id = ed.id.clone();
        let eidx = self.graph.add_edge(src_idx, tgt_idx, ed);
        self.eidx_by_key.insert(ekey, eidx);
        Some(id)
    }

    pub fn out_neighbors(&self, node_id: &str) -> Vec<(String, String)> {
        let nidx = match self.idx_by_id.get(node_id) {
            Some(i) => *i,
            None => return Vec::new(),
        };
        let mut out: Vec<(String, String)> = self
            .graph
            .edges(nidx)
            .filter_map(|er| {
                let tgt_data = self.graph.node_weight(er.target())?;
                Some((er.weight().edge_type.clone(), tgt_data.id.clone()))
            })
            .collect();
        out.sort_unstable();
        out
    }

    pub fn bfs_paths(
        &self,
        start_id: &str,
        target_types: &[String],
        max_depth: usize,
    ) -> Vec<Vec<String>> {
        let mut queue: VecDeque<(String, Vec<String>, usize)> =
            VecDeque::from([(start_id.to_string(), vec![start_id.to_string()], 0)]);
        let mut results: Vec<Vec<String>> = Vec::new();
        let mut visited_states: HashSet<(String, Vec<String>)> = HashSet::new();

        while let Some((cur, path, depth)) = queue.pop_front() {
            let state = (cur.clone(), path.clone());
            if visited_states.contains(&state) || depth > max_depth {
                continue;
            }
            visited_states.insert(state);

            if depth > 0 {
                if target_types.is_empty() {
                    results.push(path.clone());
                } else if let Some(nd) = self.get_node_data(&cur) {
                    if target_types.contains(&nd.node_type) {
                        results.push(path.clone());
                    }
                }
            }

            for (_, nid) in self.out_neighbors(&cur) {
                if !path.contains(&nid) {
                    let mut new_path = path.clone();
                    new_path.push(nid.clone());
                    queue.push_back((nid, new_path, depth + 1));
                }
            }
        }
        results.sort();
        results.dedup();
        results
    }

    pub fn dfs_paths(
        &self,
        start_id: &str,
        end_id: &str,
        max_depth: usize,
    ) -> Vec<Vec<String>> {
        let mut results = Vec::new();
        let mut path = vec![start_id.to_string()];
        self.dfs_recurse(start_id, end_id, max_depth, &mut path, &mut results);
        results.sort();
        results
    }

    fn dfs_recurse(
        &self,
        cur: &str,
        end_id: &str,
        max_depth: usize,
        path: &mut Vec<String>,
        results: &mut Vec<Vec<String>>,
    ) {
        if path.len() > max_depth + 1 {
            return;
        }
        if cur == end_id && path.len() > 1 {
            results.push(path.clone());
            return;
        }
        for (_, nid) in self.out_neighbors(cur) {
            if !path.contains(&nid) {
                path.push(nid.clone());
                self.dfs_recurse(&nid, end_id, max_depth, path, results);
                path.pop();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PyO3 class
// ---------------------------------------------------------------------------

#[pyclass(module = "oneinfinity_core")]
pub struct AttackGraph {
    pub inner: InnerGraph,
}

#[pymethods]
impl AttackGraph {
    #[new]
    fn new() -> Self {
        AttackGraph {
            inner: InnerGraph::new(),
        }
    }

    fn add_nodes(&mut self, nodes: &Bound<'_, PyList>) -> PyResult<Vec<String>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            if nodes.len() > MAX_NODES_PER_CALL {
                return Err(PyValueError::new_err(format!(
                    "OI_ERR_BATCH_TOO_LARGE: add_nodes: batch size {} exceeds limit {MAX_NODES_PER_CALL}",
                    nodes.len()
                )));
            }
            let mut ids = Vec::with_capacity(nodes.len());
            for item in nodes.iter() {
                let d: &Bound<'_, PyDict> = item
                    .downcast()
                    .map_err(|_| PyValueError::new_err("each node must be a dict"))?;

                let node_type = str_from_dict(d, "node_type");
                let label = str_from_dict(d, "label");
                if label.len() > MAX_LABEL_BYTES {
                    return Err(PyValueError::new_err(format!(
                        "OI_ERR_LABEL_TOO_LONG: add_nodes: label '{}'... exceeds {MAX_LABEL_BYTES} bytes",
                        &label[..label.len().min(64)]
                    )));
                }
                let id_hint = str_from_dict(d, "id");
                let id = if id_hint.is_empty() {
                    sha24(&format!("{node_type}::{label}"))
                } else {
                    id_hint
                };

                let nd = NodeData {
                    id: id.clone(),
                    node_type,
                    label,
                    properties: props_from_dict(d)?,
                    severity: {
                        let s = str_from_dict(d, "severity");
                        if s.is_empty() { None } else { Some(s) }
                    },
                    risk_score: f64_from_dict(d, "risk_score", 0.0),
                    exploitable: bool_from_dict(d, "exploitable"),
                    validated: bool_from_dict(d, "validated"),
                    discovered_at: {
                        let s = str_from_dict(d, "discovered_at");
                        if s.is_empty() { unix_ts() } else { s }
                    },
                    updated_at: {
                        let s = str_from_dict(d, "updated_at");
                        if s.is_empty() { unix_ts() } else { s }
                    },
                    source: str_from_dict(d, "source"),
                    tags: tags_from_dict(d),
                };
                let actual_id = self.inner.add_node_inner(nd);
                ids.push(actual_id);
            }
            Ok(ids)
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in add_nodes"))?
    }

    fn add_edges(&mut self, edges: &Bound<'_, PyList>) -> PyResult<Vec<String>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            if edges.len() > MAX_EDGES_PER_CALL {
                return Err(PyValueError::new_err(format!(
                    "OI_ERR_BATCH_TOO_LARGE: add_edges: batch size {} exceeds limit {MAX_EDGES_PER_CALL}",
                    edges.len()
                )));
            }
            let mut ids = Vec::with_capacity(edges.len());
            for item in edges.iter() {
                let d: &Bound<'_, PyDict> = item
                    .downcast()
                    .map_err(|_| PyValueError::new_err("each edge must be a dict"))?;

                let source_id = str_from_dict(d, "source_id");
                let target_id = str_from_dict(d, "target_id");
                let edge_type = str_from_dict(d, "edge_type");
                let id_hint = str_from_dict(d, "id");
                let id = if id_hint.is_empty() {
                    sha24(&format!("{source_id}::{target_id}::{edge_type}"))
                } else {
                    id_hint
                };

                let ed = EdgeData {
                    id,
                    source_id,
                    target_id,
                    edge_type,
                    label: str_from_dict(d, "label"),
                    properties: props_from_dict(d)?,
                    probability: f64_from_dict(d, "probability", 1.0),
                    weight: f64_from_dict(d, "weight", 1.0),
                    requires_auth: bool_from_dict(d, "requires_auth"),
                    created_at: {
                        let s = str_from_dict(d, "created_at");
                        if s.is_empty() { unix_ts() } else { s }
                    },
                    source_engine: str_from_dict(d, "source_engine"),
                };

                match self.inner.add_edge_inner(ed) {
                    Some(eid) => ids.push(eid),
                    None => ids.push(String::new()),
                }
            }
            Ok(ids)
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in add_edges"))?
    }

    fn get_node<'py>(&self, py: Python<'py>, node_id: &str) -> PyResult<PyObject> {
        catch_unwind(std::panic::AssertUnwindSafe(|| match self.inner.get_node_data(node_id) {
            Some(nd) => nd.to_pydict(py).map(|d| d.into_py(py)),
            None => Ok(py.None()),
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in get_node"))?
    }

    fn node_count(&self) -> usize {
        self.inner.idx_by_id.len()
    }

    fn edge_count(&self) -> usize {
        self.inner.eidx_by_key.len()
    }

    #[pyo3(signature = (node_type=None, severity=None, exploitable=None, label_contains=None))]
    fn find_nodes<'py>(
        &self,
        py: Python<'py>,
        node_type: Option<&str>,
        severity: Option<&str>,
        exploitable: Option<bool>,
        label_contains: Option<&str>,
    ) -> PyResult<Vec<PyObject>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            let lc_label = label_contains.map(|s| s.to_lowercase());
            let mut results: Vec<(String, PyObject)> = Vec::new();
            for nidx in self.inner.graph.node_indices() {
                let nd = &self.inner.graph[nidx];
                if let Some(nt) = node_type {
                    if nd.node_type != nt { continue; }
                }
                if let Some(sev) = severity {
                    if nd.severity.as_deref() != Some(sev) { continue; }
                }
                if let Some(exp) = exploitable {
                    if nd.exploitable != exp { continue; }
                }
                if let Some(ref lc) = lc_label {
                    if !nd.label.to_lowercase().contains(lc.as_str()) { continue; }
                }
                let obj = nd.to_pydict(py)?.into_py(py);
                results.push((nd.id.clone(), obj));
            }
            results.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(results.into_iter().map(|(_, o)| o).collect())
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in find_nodes"))?
    }

    #[pyo3(signature = (node_id, edge_type=None))]
    fn get_neighbors<'py>(
        &self,
        py: Python<'py>,
        node_id: &str,
        edge_type: Option<&str>,
    ) -> PyResult<Vec<PyObject>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            let nidx = match self.inner.idx_by_id.get(node_id) {
                Some(i) => *i,
                None => return Ok(Vec::new()),
            };
            let mut neighbors: Vec<(String, PyObject)> = Vec::new();
            for er in self.inner.graph.edges(nidx) {
                let ed = er.weight();
                if let Some(et) = edge_type {
                    if ed.edge_type != et { continue; }
                }
                if let Some(tgt) = self.inner.graph.node_weight(er.target()) {
                    let obj = tgt.to_pydict(py)?.into_py(py);
                    neighbors.push((tgt.id.clone(), obj));
                }
            }
            neighbors.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(neighbors.into_iter().map(|(_, o)| o).collect())
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in get_neighbors"))?
    }

    fn find_path(
        &self,
        source_id: &str,
        target_id: &str,
        max_depth: usize,
    ) -> PyResult<Vec<Vec<String>>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            let depth = max_depth.min(MAX_DEPTH);
            let mut results = self.inner.dfs_paths(source_id, target_id, depth);
            results.truncate(MAX_PATH_RESULTS);
            Ok(results)
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in find_path"))?
    }

    fn get_subgraph<'py>(
        &self,
        py: Python<'py>,
        root_node_id: &str,
        depth: usize,
    ) -> PyResult<Bound<'py, PyDict>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut visited_nodes: HashSet<String> = HashSet::new();
            let mut visited_edges: HashSet<String> = HashSet::new();
            let mut queue: VecDeque<(String, usize)> =
                VecDeque::from([(root_node_id.to_string(), 0)]);

            while let Some((cur_id, cur_depth)) = queue.pop_front() {
                if visited_nodes.contains(&cur_id) { continue; }
                visited_nodes.insert(cur_id.clone());
                if cur_depth >= depth { continue; }

                let nidx = match self.inner.idx_by_id.get(&cur_id) {
                    Some(i) => *i,
                    None => continue,
                };
                for er in self.inner.graph.edges(nidx) {
                    let ed = er.weight();
                    visited_edges.insert(ed.id.clone());
                    if let Some(tgt) = self.inner.graph.node_weight(er.target()) {
                        if !visited_nodes.contains(&tgt.id) {
                            queue.push_back((tgt.id.clone(), cur_depth + 1));
                        }
                    }
                }
            }

            let mut node_ids: Vec<String> = visited_nodes.into_iter().collect();
            node_ids.sort();
            let nodes_list = PyList::empty_bound(py);
            for nid in &node_ids {
                if let Some(nd) = self.inner.get_node_data(nid) {
                    nodes_list.append(nd.to_pydict(py)?)?;
                }
            }

            let mut edge_ids: Vec<String> = visited_edges.into_iter().collect();
            edge_ids.sort();
            let edges_list = PyList::empty_bound(py);
            for nidx in self.inner.graph.node_indices() {
                for er in self.inner.graph.edges(nidx) {
                    let ed = er.weight();
                    if edge_ids.contains(&ed.id) {
                        edges_list.append(ed.to_pydict(py)?)?;
                    }
                }
            }

            let d = PyDict::new_bound(py);
            d.set_item("nodes", nodes_list)?;
            d.set_item("edges", edges_list)?;
            Ok(d)
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in get_subgraph"))?
    }

    fn get_stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut node_counts: BTreeMap<String, i64> = BTreeMap::new();
            let mut edge_counts: BTreeMap<String, i64> = BTreeMap::new();
            let mut severity_counts: BTreeMap<String, i64> = BTreeMap::new();
            let mut exploitable = 0i64;
            let mut validated = 0i64;

            for nidx in self.inner.graph.node_indices() {
                let nd = &self.inner.graph[nidx];
                *node_counts.entry(nd.node_type.clone()).or_insert(0) += 1;
                if nd.exploitable { exploitable += 1; }
                if nd.validated { validated += 1; }
                if nd.node_type == "vulnerability" {
                    if let Some(sev) = &nd.severity {
                        *severity_counts.entry(sev.clone()).or_insert(0) += 1;
                    }
                }
            }

            for eidx in self.inner.graph.edge_indices() {
                let ed = &self.inner.graph[eidx];
                *edge_counts.entry(ed.edge_type.clone()).or_insert(0) += 1;
            }

            let d = PyDict::new_bound(py);
            d.set_item("total_nodes", self.inner.idx_by_id.len())?;
            d.set_item("total_edges", self.inner.eidx_by_key.len())?;

            let nbt = PyDict::new_bound(py);
            for (k, v) in &node_counts { nbt.set_item(k, v)?; }
            d.set_item("nodes_by_type", nbt)?;

            let ebt = PyDict::new_bound(py);
            for (k, v) in &edge_counts { ebt.set_item(k, v)?; }
            d.set_item("edges_by_type", ebt)?;

            d.set_item("exploitable_nodes", exploitable)?;
            d.set_item("validated_nodes", validated)?;

            let sbt = PyDict::new_bound(py);
            for (k, v) in &severity_counts { sbt.set_item(k, v)?; }
            d.set_item("vulnerabilities_by_severity", sbt)?;

            Ok(d)
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in get_stats"))?
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut nids: Vec<String> = self.inner.idx_by_id.keys().cloned().collect();
            nids.sort();
            let nodes_list = PyList::empty_bound(py);
            for nid in &nids {
                if let Some(nd) = self.inner.get_node_data(nid) {
                    nodes_list.append(nd.to_pydict(py)?)?;
                }
            }

            let mut edge_keys: Vec<String> = self
                .inner
                .graph
                .edge_indices()
                .map(|ei| self.inner.graph[ei].id.clone())
                .collect();
            edge_keys.sort();
            let edges_list = PyList::empty_bound(py);
            for ek in &edge_keys {
                for eidx in self.inner.graph.edge_indices() {
                    if self.inner.graph[eidx].id == *ek {
                        edges_list.append(self.inner.graph[eidx].to_pydict(py)?)?;
                        break;
                    }
                }
            }

            let d = PyDict::new_bound(py);
            d.set_item("nodes", nodes_list)?;
            d.set_item("edges", edges_list)?;
            d.set_item("stats", self.get_stats(py)?)?;
            Ok(d)
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in to_dict"))?
    }

    fn get_edges_from<'py>(&self, py: Python<'py>, node_id: &str) -> PyResult<Vec<PyObject>> {
        catch_unwind(std::panic::AssertUnwindSafe(|| {
            let nidx = match self.inner.idx_by_id.get(node_id) {
                Some(i) => *i,
                None => return Ok(Vec::new()),
            };
            let mut edges: Vec<(String, PyObject)> = Vec::new();
            for er in self.inner.graph.edges(nidx) {
                let ed = er.weight();
                let obj = ed.to_pydict(py)?.into_py(py);
                edges.push((ed.id.clone(), obj));
            }
            edges.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(edges.into_iter().map(|(_, o)| o).collect())
        }))
        .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in get_edges_from"))?
    }
}
