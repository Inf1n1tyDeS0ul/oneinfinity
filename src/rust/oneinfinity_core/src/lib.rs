use pyo3::prelude::*;

pub mod finding_dedup;
pub mod graph;
pub mod normalizer;
pub mod payload_mutate;
pub mod scope_check;
pub mod smuggling;
pub mod fuzzer;

/// Global feature flag: ONEINFINITY_RUST must be set (non-empty, not '0', not 'false').
pub fn rust_enabled() -> bool {
    std::env::var("ONEINFINITY_RUST")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
}

/// Per-module feature flag. Inherits global if per-module var absent.
pub fn module_enabled(module: &str) -> bool {
    if !rust_enabled() {
        return false;
    }
    let key = format!("ONEINFINITY_RUST_{}", module.to_uppercase());
    std::env::var(&key)
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true)
}

#[pymodule]
fn oneinfinity_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // scope_check
    m.add_class::<scope_check::ScopeValidator>()?;
    // normalizer
    normalizer::register(m)?;
    // finding_dedup
    finding_dedup::register(m)?;
    // payload_mutate
    payload_mutate::register(m)?;
    // attack graph (petgraph-backed)
    m.add_class::<graph::AttackGraph>()?;
    graph::query::register(m)?;
    // smuggling engine (tokio-backed)
    smuggling::register(m)?;
    // fuzzer (HTTP-aware mutation engine)
    fuzzer::register(m)?;
    Ok(())
}
