//! normalizer.rs — PyO3 finding normalization.
//!
//! Replicates tool_wrappers.py normalize_finding / _finding_key /
//! merge_normalized / normalize_results with byte-identical output schema.
//!
//! SAFETY: every PyO3 entry point is wrapped in catch_unwind.
//! Feature flags: ONEINFINITY_RUST and ONEINFINITY_RUST_NORMALIZER env vars.

use std::collections::BTreeMap;
use std::panic;

use md5::{Digest as Md5Digest, Md5};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

// ── Severity ordering ─────────────────────────────────────────────────────────

fn severity_order(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

/// Replicate Python _canonical_severity: iterate known keys, return first match.
pub(crate) fn canonical_severity(raw: &str) -> &'static str {
    let s = raw.to_lowercase();
    let s = s.trim();
    for k in &["critical", "high", "medium", "low", "info"] {
        if s.contains(k) {
            return k;
        }
    }
    "unknown"
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract a string from a PyDict key, returning empty string on miss/error.
fn dict_str(d: &Bound<'_, PyDict>, key: &str) -> String {
    d.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.extract::<String>().ok())
        .unwrap_or_default()
}

/// dict_str with multiple fallback keys — first non-empty wins.
fn dict_str_any(d: &Bound<'_, PyDict>, keys: &[&str]) -> String {
    for key in keys {
        let v = dict_str(d, key);
        if !v.is_empty() {
            return v;
        }
    }
    String::new()
}

/// Build the canonical output dict from extracted components.
fn build_output<'py>(
    py: Python<'py>,
    url: String,
    parameter: String,
    vulnerability: String,
    severity: &'static str,
    source_tool: &str,
    extra: BTreeMap<String, PyObject>,
) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new_bound(py);
    out.set_item("url", &url)?;
    out.set_item("parameter", &parameter)?;
    out.set_item("vulnerability", &vulnerability)?;
    out.set_item("severity", severity)?;
    out.set_item("source_tool", source_tool)?;
    // extra fields
    let extra_dict = PyDict::new_bound(py);
    for (k, v) in &extra {
        extra_dict.set_item(k, v)?;
    }
    out.set_item("extra", extra_dict)?;
    Ok(out)
}

// ── normalize_finding ─────────────────────────────────────────────────────────

/// Map any tool-specific dict/string to the canonical finding schema.
/// Replicates tool_wrappers.normalize_finding exactly.
///
/// Feature-gated: if ONEINFINITY_RUST or ONEINFINITY_RUST_NORMALIZER is unset,
/// callers should fall through to the Python implementation instead.
#[pyfunction]
pub fn normalize_finding<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyAny>,
    source_tool: &str,
) -> PyResult<Bound<'py, PyDict>> {
    panic::catch_unwind(panic::AssertUnwindSafe(|| {
        _normalize_finding_inner(py, raw, source_tool)
    }))
    .unwrap_or_else(|_| {
        Err(PyRuntimeError::new_err(
            "normalize_finding: internal panic — falling back to Python",
        ))
    })
}

fn _normalize_finding_inner<'py>(
    py: Python<'py>,
    raw: &Bound<'py, PyAny>,
    source_tool: &str,
) -> PyResult<Bound<'py, PyDict>> {
    // ── Case 1: raw is a str ──────────────────────────────────────────────
    if let Ok(s) = raw.extract::<String>() {
        let url = if s.starts_with("http://") || s.starts_with("https://") {
            s.clone()
        } else {
            String::new()
        };
        let out = PyDict::new_bound(py);
        out.set_item("url", &url)?;
        out.set_item("parameter", "")?;
        out.set_item("vulnerability", &s)?;
        out.set_item("severity", "info")?;
        out.set_item("source_tool", source_tool)?;
        out.set_item("extra", PyDict::new_bound(py))?;
        return Ok(out);
    }

    // ── Case 2: raw is None or not a dict ────────────────────────────────
    if raw.is_none() {
        let out = PyDict::new_bound(py);
        out.set_item("url", "")?;
        out.set_item("parameter", "")?;
        out.set_item("vulnerability", "None")?;
        out.set_item("severity", "unknown")?;
        out.set_item("source_tool", source_tool)?;
        out.set_item("extra", PyDict::new_bound(py))?;
        return Ok(out);
    }

    let dict = match raw.downcast::<PyDict>() {
        Ok(d) => d,
        Err(_) => {
            // Anything else: str(raw)
            let s = raw.str()?.to_string();
            let out = PyDict::new_bound(py);
            out.set_item("url", "")?;
            out.set_item("parameter", "")?;
            out.set_item("vulnerability", &s)?;
            out.set_item("severity", "unknown")?;
            out.set_item("source_tool", source_tool)?;
            out.set_item("extra", PyDict::new_bound(py))?;
            return Ok(out);
        }
    };

    // ── Case 3: raw is a dict ─────────────────────────────────────────────
    let url = dict_str_any(
        dict,
        &["url", "URL", "matched-at", "host", "target", "endpoint"],
    );
    let parameter = dict_str_any(dict, &["parameter", "param", "name"]);

    // info sub-dict for nuclei-style findings
    let info_name: String = dict
        .get_item("info")
        .ok()
        .flatten()
        .and_then(|v| v.downcast::<PyDict>().ok().map(|d| dict_str(&d, "name")))
        .unwrap_or_default();

    let vulnerability = {
        let v = dict_str_any(
            dict,
            &[
                "vulnerability",
                "name",
                "type",
                "title",
                "template-id",
                "description",
                "check",
            ],
        );
        if v.is_empty() { info_name } else { v }
    };

    // Severity — replicate Python chain: severity > risk > cvss > info.severity
    let sev_raw = {
        let s = dict_str(dict, "severity");
        if !s.is_empty() {
            s
        } else {
            let r = dict_str(dict, "risk");
            if !r.is_empty() {
                r
            } else {
                let c = dict_str(dict, "cvss");
                if !c.is_empty() {
                    c
                } else {
                    dict
                        .get_item("info")
                        .ok()
                        .flatten()
                        .and_then(|v| v.downcast::<PyDict>().ok().map(|d| dict_str(&d, "severity")))
                        .unwrap_or_default()
                }
            }
        }
    };
    let severity = if sev_raw.is_empty() {
        "unknown"
    } else {
        canonical_severity(&sev_raw)
    };

    // extra — keys NOT in the known set
    const KNOWN: &[&str] = &[
        "url",
        "URL",
        "matched-at",
        "host",
        "target",
        "endpoint",
        "parameter",
        "param",
        "name",
        "vulnerability",
        "type",
        "title",
        "info",
        "template-id",
        "description",
        "severity",
        "risk",
        "cvss",
        "check",
    ];
    let mut extra: BTreeMap<String, PyObject> = BTreeMap::new();
    for item in dict.iter() {
        let k: String = item.0.extract()?;
        if !KNOWN.contains(&k.as_str()) {
            extra.insert(k, item.1.into_py(py));
        }
    }

    build_output(
        py,
        url,
        parameter,
        vulnerability,
        severity,
        source_tool,
        extra,
    )
}

// ── finding_key ───────────────────────────────────────────────────────────────

/// MD5 of 'url|parameter|vulnerability' — replicates Python _finding_key.
#[pyfunction]
pub fn finding_key(py: Python<'_>, f: &Bound<'_, PyDict>) -> PyResult<String> {
    panic::catch_unwind(panic::AssertUnwindSafe(|| _finding_key_inner(py, f)))
        .unwrap_or_else(|_| {
            Err(PyRuntimeError::new_err(
                "finding_key: internal panic",
            ))
        })
}

fn _finding_key_inner(_py: Python<'_>, f: &Bound<'_, PyDict>) -> PyResult<String> {
    let url = dict_str(f, "url");
    let parameter = dict_str(f, "parameter");
    let vulnerability = dict_str(f, "vulnerability");
    let parts = format!("{url}|{parameter}|{vulnerability}");
    let mut hasher = Md5::new();
    hasher.update(parts.as_bytes());
    let result = hasher.finalize();
    Ok(format!("{result:x}"))
}

// ── merge_normalized ──────────────────────────────────────────────────────────

/// Merge multiple normalised finding lists, deduplicating across all.
/// Signature accepts a PyList of PyLists — each inner list is a finding_list.
/// Dedup by finding_key; keep highest severity; sort by (severity_order, url).
#[pyfunction]
pub fn merge_normalized(py: Python<'_>, lists: &Bound<'_, PyList>) -> PyResult<Vec<PyObject>> {
    panic::catch_unwind(panic::AssertUnwindSafe(|| _merge_normalized_inner(py, lists)))
        .unwrap_or_else(|_| {
            Err(PyRuntimeError::new_err(
                "merge_normalized: internal panic",
            ))
        })
}

fn _merge_normalized_inner(
    py: Python<'_>,
    lists: &Bound<'_, PyList>,
) -> PyResult<Vec<PyObject>> {
    // BTreeMap ensures deterministic key iteration order
    let mut combined: BTreeMap<String, Bound<'_, PyDict>> = BTreeMap::new();

    for lst_item in lists.iter() {
        let lst = lst_item.downcast::<PyList>()?;
        for item in lst.iter() {
            let f = item.downcast::<PyDict>()?;
            let key = _finding_key_inner(py, f)?;
            if let Some(existing) = combined.get(&key) {
                let existing_sev = dict_str(existing, "severity");
                let new_sev = dict_str(f, "severity");
                if severity_order(&new_sev) < severity_order(&existing_sev) {
                    combined.insert(key, f.clone());
                }
            } else {
                combined.insert(key, f.clone());
            }
        }
    }

    // Collect and sort by (severity_order, url)
    let mut findings: Vec<Bound<'_, PyDict>> = combined.into_values().collect();
    findings.sort_by(|a, b| {
        let sa = severity_order(&dict_str(a, "severity"));
        let sb = severity_order(&dict_str(b, "severity"));
        let ua = dict_str(a, "url");
        let ub = dict_str(b, "url");
        sa.cmp(&sb).then_with(|| ua.cmp(&ub))
    });

    Ok(findings.into_iter().map(|d| d.into_py(py)).collect())
}

// ── normalize_results ─────────────────────────────────────────────────────────

/// Normalize each finding in results and dedup by finding_key.
#[pyfunction]
pub fn normalize_results(
    py: Python<'_>,
    results: &Bound<'_, PyList>,
    source_tool: &str,
) -> PyResult<Vec<PyObject>> {
    panic::catch_unwind(panic::AssertUnwindSafe(|| {
        _normalize_results_inner(py, results, source_tool)
    }))
    .unwrap_or_else(|_| {
        Err(PyRuntimeError::new_err(
            "normalize_results: internal panic",
        ))
    })
}

fn _normalize_results_inner(
    py: Python<'_>,
    results: &Bound<'_, PyList>,
    source_tool: &str,
) -> PyResult<Vec<PyObject>> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<PyObject> = Vec::new();

    for item in results.iter() {
        let finding = _normalize_finding_inner(py, &item, source_tool)?;
        let key = _finding_key_inner(py, &finding)?;
        if seen.insert(key) {
            out.push(finding.into_py(py));
        }
    }
    Ok(out)
}

// ── PyString helper for module registration ───────────────────────────────────

/// Expose the canonical_severity function directly for testing.
#[pyfunction]
pub fn canonical_severity_py(_py: Python<'_>, raw: &str) -> String {
    canonical_severity(raw).to_string()
}

/// Return the feature-flag state.
#[pyfunction]
pub fn rust_normalizer_enabled(_py: Python<'_>) -> bool {
    std::env::var("ONEINFINITY_RUST").is_ok()
        || std::env::var("ONEINFINITY_RUST_NORMALIZER").is_ok()
}

// ── module registration (called from lib.rs) ──────────────────────────────────

pub fn register(m: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(normalize_finding, m)?)?;
    m.add_function(wrap_pyfunction!(finding_key, m)?)?;
    m.add_function(wrap_pyfunction!(merge_normalized, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_results, m)?)?;
    m.add_function(wrap_pyfunction!(canonical_severity_py, m)?)?;
    m.add_function(wrap_pyfunction!(rust_normalizer_enabled, m)?)?;
    Ok(())
}
