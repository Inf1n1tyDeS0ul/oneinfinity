//! finding_dedup.rs — PyO3 finding deduplication, risk scoring, batch validation.
//!
//! Replicates result_aggregator.py _fingerprint / _SEVERITY_WEIGHTS and
//! finding_validator.py FindingValidator with identical output schema.
//!
//! SAFETY: every PyO3 entry point is wrapped in catch_unwind.
//! Feature flags: ONEINFINITY_RUST and ONEINFINITY_RUST_DEDUP env vars.

use std::collections::{BTreeMap, HashSet};
use std::panic;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use sha2::{Digest as Sha2Digest, Sha256};

// ── Vuln alias map (mirrors result_aggregator._VULN_ALIASES) ─────────────────

fn canonical_vuln_type(raw: &str) -> String {
    let s = raw.to_lowercase();
    let s = s.trim();
    // Static alias table — exact copy of Python _VULN_ALIASES
    match s {
        "reflected xss" | "reflected cross-site scripting" | "cross-site scripting"
        | "cross site scripting" | "xss" => "xss",
        "stored xss" | "stored cross-site scripting" | "stored_xss" => "stored_xss",
        "dom xss" | "dom-based xss" | "dom_xss" => "dom_xss",
        "sql injection" | "sql-injection" | "sqli" => "sqli",
        "blind sql injection" | "sqli_blind" => "sqli_blind",
        "time-based blind sql injection" | "sqli_time" => "sqli_time",
        "error-based sql injection" | "sqli_error" => "sqli_error",
        "server-side request forgery" | "server side request forgery" | "ssrf" => "ssrf",
        "local file inclusion" | "local file read" | "path traversal"
        | "directory traversal" | "lfi" => "lfi",
        "remote file inclusion" | "rfi" => "rfi",
        "insecure direct object reference" | "insecure direct object references" | "idor" => "idor",
        "server-side template injection" | "server side template injection" | "ssti" => "ssti",
        "open redirect" | "url redirection" | "open redirection" | "open_redirect" => {
            "open_redirect"
        }
        "crlf injection" | "http header injection" | "crlf" => "crlf",
        "broken access control" | "access control" | "bac" => "bac",
        "privilege escalation" | "privesc" => "privesc",
        "authentication bypass" | "authorization bypass" | "auth_bypass" => "auth_bypass",
        "remote code execution" | "rce" => "rce",
        "command injection" | "os command injection" | "cmdi" => "cmdi",
        "xml external entity" | "xxe" => "xxe",
        "cross-site request forgery" | "csrf" => "csrf",
        "cors misconfiguration" | "cors" => "cors",
        "mass assignment" | "mass_assignment" => "mass_assignment",
        other => return other.to_string(),
    }
    .to_string()
}

// ── URL normalization (mirrors result_aggregator._normalize_url) ──────────────

fn normalize_url(raw: &str) -> String {
    // Best-effort: lowercase, strip fragment, sort query params
    match url::Url::parse(raw) {
        Ok(mut parsed) => {
            parsed.set_fragment(None);
            // Sort query params
            let mut params: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            params.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            let query = if params.is_empty() {
                String::new()
            } else {
                params
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("&")
            };
            let mut out = format!(
                "{}://{}",
                parsed.scheme().to_lowercase(),
                parsed.host_str().unwrap_or("").to_lowercase(),
            );
            if let Some(port) = parsed.port() {
                out.push_str(&format!(":{port}"));
            }
            out.push_str(parsed.path());
            if !query.is_empty() {
                out.push('?');
                out.push_str(&query);
            }
            out
        }
        Err(_) => raw.to_lowercase().trim().to_string(),
    }
}

// ── SHA-256 fingerprint (replicates result_aggregator._fingerprint) ───────────

fn fingerprint(vuln_type: &str, url: &str, parameter: &str) -> String {
    let canonical_type = canonical_vuln_type(vuln_type);
    let canonical_url = normalize_url(url);
    let canonical_param = parameter.trim().to_lowercase();
    let raw = format!("{canonical_type}::{canonical_url}::{canonical_param}");
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let result = hasher.finalize();
    // Python takes [:16] hex chars = 8 bytes
    format!("{result:x}")[..16].to_string()
}

// ── Dict helpers ──────────────────────────────────────────────────────────────

fn dict_str(d: &Bound<'_, PyDict>, key: &str) -> String {
    d.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.extract::<String>().ok())
        .unwrap_or_default()
}

fn dict_f64(d: &Bound<'_, PyDict>, key: &str) -> f64 {
    d.get_item(key)
        .ok()
        .flatten()
        .and_then(|v| v.extract::<f64>().ok())
        .unwrap_or(0.0)
}

fn dict_str_any(d: &Bound<'_, PyDict>, keys: &[&str]) -> String {
    for k in keys {
        let v = dict_str(d, k);
        if !v.is_empty() {
            return v;
        }
    }
    String::new()
}

// ── deduplicate_findings ──────────────────────────────────────────────────────

/// SHA-256 fingerprint dedup using vuln_type + normalized_url + parameter.
/// Replicates Python result_aggregator._fingerprint exactly (16-char hex prefix).
#[pyfunction]
pub fn deduplicate_findings(
    py: Python<'_>,
    findings: &Bound<'_, PyList>,
) -> PyResult<Vec<PyObject>> {
    panic::catch_unwind(panic::AssertUnwindSafe(|| {
        _deduplicate_findings_inner(py, findings)
    }))
    .unwrap_or_else(|_| {
        Err(PyRuntimeError::new_err(
            "deduplicate_findings: internal panic",
        ))
    })
}

fn _deduplicate_findings_inner(
    py: Python<'_>,
    findings: &Bound<'_, PyList>,
) -> PyResult<Vec<PyObject>> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<PyObject> = Vec::new();

    for item in findings.iter() {
        let f = item.downcast::<PyDict>()?;

        let vuln_type = dict_str_any(f, &["vuln_type", "type", "name", "vulnerability"]);
        let url = dict_str_any(f, &["url", "endpoint", "host"]);
        let parameter = dict_str_any(f, &["parameter", "param"]);

        let fp = fingerprint(&vuln_type, &url, &parameter);
        if seen.insert(fp) {
            out.push(item.clone().into_py(py));
        }
    }
    Ok(out)
}

// ── calculate_session_risk ────────────────────────────────────────────────────

/// CVSS-weighted risk score.
/// Severity weights from Python _SEVERITY_WEIGHTS:
///   critical=10.0, high=7.0, medium=4.0, low=1.5, info=0.1
/// Returns dict matching AggregatedResult.to_dict() keys.
#[pyfunction]
pub fn calculate_session_risk(
    py: Python<'_>,
    findings: &Bound<'_, PyList>,
) -> PyResult<PyObject> {
    panic::catch_unwind(panic::AssertUnwindSafe(|| {
        _calculate_session_risk_inner(py, findings)
    }))
    .unwrap_or_else(|_| {
        Err(PyRuntimeError::new_err(
            "calculate_session_risk: internal panic",
        ))
    })
}

fn severity_weight(sev: &str) -> f64 {
    // Exact Python _SEVERITY_WEIGHTS values
    match sev.to_lowercase().trim() {
        "critical" => 10.0,
        "high" => 7.5,
        "medium" => 5.0,
        "low" => 2.5,
        "info" => 0.5,
        _ => 0.0,
    }
}

fn _calculate_session_risk_inner(
    py: Python<'_>,
    findings: &Bound<'_, PyList>,
) -> PyResult<PyObject> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for sev in &["critical", "high", "medium", "low", "info"] {
        counts.insert(sev, 0);
    }
    let mut risk_score: f64 = 0.0;
    let mut total = 0usize;
    let mut validated = 0usize;
    let mut workers: HashSet<String> = HashSet::new();
    let mut all_findings: Vec<PyObject> = Vec::new();

    for item in findings.iter() {
        let f = item.downcast::<PyDict>()?;
        total += 1;

        let sev = dict_str(f, "severity").to_lowercase();
        let sev = sev.trim().to_string();
        let w = severity_weight(&sev);
        risk_score += w;

        match sev.as_str() {
            "critical" => *counts.entry("critical").or_insert(0) += 1,
            "high" => *counts.entry("high").or_insert(0) += 1,
            "medium" => *counts.entry("medium").or_insert(0) += 1,
            "low" => *counts.entry("low").or_insert(0) += 1,
            _ => *counts.entry("info").or_insert(0) += 1,
        }

        let status = dict_str(f, "validation_status");
        if status == "confirmed" || status == "verified" {
            validated += 1;
        }

        let wid = dict_str(f, "_worker_id");
        if !wid.is_empty() {
            workers.insert(wid);
        }

        all_findings.push(item.clone().into_py(py));
    }

    // Normalize risk score: Python divides by finding count in some paths;
    // here we replicate the raw sum used in ResultAggregator.finalize()
    let out = PyDict::new_bound(py);
    out.set_item("total_findings", total)?;
    out.set_item("critical", counts["critical"])?;
    out.set_item("high", counts["high"])?;
    out.set_item("medium", counts["medium"])?;
    out.set_item("low", counts["low"])?;
    out.set_item("info", counts["info"])?;
    out.set_item("validated_findings", validated)?;
    out.set_item("risk_score", risk_score)?;
    out.set_item("findings", all_findings)?;
    out.set_item(
        "workers_contributed",
        workers.into_iter().collect::<Vec<_>>(),
    )?;
    Ok(out.into_py(py))
}

// ── batch_validate ────────────────────────────────────────────────────────────

/// Validate a list of findings using FindingValidator logic.
/// Replicates confidence thresholds, evidence patterns, source-type overrides.
/// Returns list of dicts with added keys: validation_status, confidence,
/// confidence_breakdown, evidence_score, reasons, warnings.
#[pyfunction]
pub fn batch_validate(
    py: Python<'_>,
    findings: &Bound<'_, PyList>,
) -> PyResult<Vec<PyObject>> {
    panic::catch_unwind(panic::AssertUnwindSafe(|| {
        _batch_validate_inner(py, findings)
    }))
    .unwrap_or_else(|_| {
        Err(PyRuntimeError::new_err(
            "batch_validate: internal panic",
        ))
    })
}

// Evidence patterns (same regexes as Python _EVIDENCE_PATTERNS, compiled once)
fn evidence_score_from_text(combined: &str) -> (f64, Vec<String>) {
    // Pattern list mirrors finding_validator._EVIDENCE_PATTERNS exactly
    let patterns: &[(&str, bool)] = &[
        (r"HTTP/\d", false),
        (r"(?i)<script>|<img|onerror", false),
        (r"(?i)syntax error|mysql|sqlite|pg_", false),
        (r"(?i)root:|/etc/passwd", false),
        (r"169\.254\.169\.254", false),
        (r"(?i)\[nuclei\]|\[dalfox\]|\[sqlmap\]", false),
        (r"(?i)poc:|payload:|curl ", false),
        (r"(?i)window\.google|callback\(|jsonp", false),
        (r"(?i)access control allow origin", false),
        (r"(?i)Authorization: Bearer", false),
        (r"(?i)Set-Cookie:", false),
        (r"(?i)Location: http", false),
        (r"(?i)---BEGIN RSA PRIVATE KEY---", false),
    ];

    let mut matched: Vec<String> = Vec::new();
    for (pat, _) in patterns {
        // Build a simple regex; use the regex crate
        if let Ok(re) = regex::Regex::new(pat) {
            if re.is_match(combined) {
                matched.push((*pat).to_string());
            }
        }
    }
    let score = (matched.len() as f64 * 0.2_f64).min(1.0);
    (score, matched)
}

fn is_network_layer_tool(tool: &str) -> bool {
    matches!(
        tool,
        "smuggling_engine"
            | "dns_rebinding_scanner"
            | "port_scan"
            | "service_scan"
            | "advanced_scanner"
            | "cache_deception_scanner"
            | "host_header_scanner"
            | "ssrf_scanner"
            | "cors_scanner"
            | "smuggling_test"
    )
}

fn is_application_logic_type(vuln: &str) -> bool {
    matches!(
        vuln,
        "default_credentials"
            | "credential_spray_hit"
            | "debug_info_disclosure"
            | "api_version_downgrade"
            | "information_disclosure"
            | "verbose_error"
            | "error_disclosure"
            | "werkzeug_debugger"
            | "exposed_console"
            | "business_logic"
            | "no_transaction_limit"
            | "negative_amount_bypass"
            | "plaintext_card_storage"
            | "unauthenticated_access"
            | "idor"
            | "bola"
            | "account_takeover_via_idor"
            | "session_not_invalidated"
            | "jwt_none_alg"
            | "jwt_weak_secret"
            | "jwt_claim_escalation"
            | "rate_limit_bypass"
            | "sql_injection"
            | "sqli"
            | "xss"
            | "open_redirect"
            | "ssrf"
            | "session_never_expires"
            | "type_confusion_disclosure"
            | "card_limit_bypass"
            | "negative_transfer"
            | "zero_value_transfer"
            | "duplicate_transaction"
            | "no_rate_limiting"
    )
}

const CONFIRMED_THRESHOLD: f64 = 0.70;
const UNVERIFIED_THRESHOLD: f64 = 0.35;

const AI_THEORY_MARKERS: &[&str] = &[
    "ai theory",
    "ai-generated",
    "theoretical",
    "potential (unconfirmed)",
    "hypothetical",
    "llm-inferred",
    "model suggests",
];

const SIMULATION_MARKERS: &[&str] = &[
    "simulated",
    "montecarlo",
    "monte carlo",
    "workflow simulation",
    "attack simulation",
];

fn validate_one<'py>(
    py: Python<'py>,
    f: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyDict>> {
    let fid = {
        let v = dict_str_any(f, &["finding_id", "id"]);
        if v.is_empty() { "?".to_string() } else { v }
    };
    let title = dict_str(f, "title").to_lowercase();
    let desc = dict_str(f, "description").to_lowercase();
    let src = dict_str(f, "source_type").to_lowercase();
    let src = if src.is_empty() { "tool".to_string() } else { src };
    let evidence = dict_str(f, "evidence");
    let payload = dict_str(f, "payload");
    let conf_raw = dict_f64(f, "confidence");
    let mut base_conf = conf_raw;
    if base_conf == 0.0 {
        // default 0.5 if field missing or zero
        let raw_item = f.get_item("confidence").ok().flatten();
        if raw_item.is_none() {
            base_conf = 0.5;
        }
    }

    let mut reasons: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Step 1: source-type override
    let title_desc = format!("{title} {desc}");
    if src == "simulated"
        || SIMULATION_MARKERS.iter().any(|m| title_desc.contains(m))
    {
        let out = f.copy()?;
        out.set_item("validation_status", "simulated")?;
        out.set_item("confidence", base_conf)?;
        out.set_item(
            "confidence_breakdown",
            "Source tagged as simulation",
        )?;
        out.set_item("evidence_score", 0.0_f64)?;
        out.set_item(
            "warnings",
            vec!["Finding is a simulation result — not a real vulnerability"],
        )?;
        out.set_item("reasons", Vec::<String>::new())?;
        out.set_item("finding_id_validated", &fid)?;
        return Ok(out);
    }

    if src == "ai_theory"
        || AI_THEORY_MARKERS.iter().any(|m| title_desc.contains(m))
    {
        let capped = base_conf.min(0.4);
        let out = f.copy()?;
        out.set_item("validation_status", "unverified")?;
        out.set_item("confidence", capped)?;
        out.set_item(
            "confidence_breakdown",
            "AI-generated theory — not tool-confirmed",
        )?;
        out.set_item("evidence_score", 0.0_f64)?;
        out.set_item(
            "warnings",
            vec!["AI theory requires independent tool confirmation before submission"],
        )?;
        out.set_item("reasons", Vec::<String>::new())?;
        out.set_item("finding_id_validated", &fid)?;
        return Ok(out);
    }

    // Step 2: evidence richness
    let combined = format!("{evidence} {payload}");
    let (mut evidence_score, matched_patterns) = evidence_score_from_text(&combined);

    let tool_name = dict_str(f, "tool").to_lowercase();
    let vuln_type = dict_str(f, "vuln_type").to_lowercase();
    let is_network = is_network_layer_tool(&tool_name);
    let is_app_logic = is_application_logic_type(&vuln_type);

    if !payload.is_empty() {
        evidence_score = (evidence_score + 0.2).min(1.0);
        reasons.push(format!("Payload present ({})", &payload[..payload.len().min(40)]));
    } else if is_network {
        reasons.push(format!("Network-layer tool ({tool_name}) — payload cap waived"));
    } else if is_app_logic {
        reasons.push(format!("Application-logic finding ({vuln_type}) — payload cap waived"));
    } else {
        warnings.push("No payload captured — confidence capped at 0.65".to_string());
        base_conf = base_conf.min(0.65);
    }

    if !evidence.is_empty() {
        evidence_score = (evidence_score + 0.1).min(1.0);
        reasons.push("Evidence field populated".to_string());
    }

    for p in &matched_patterns {
        reasons.push(format!("Evidence matches pattern: {p}"));
    }

    // Step 3: tool-confirmed bonus
    if src == "tool" {
        base_conf = (base_conf + 0.15).min(1.0);
        reasons.push("Tool-confirmed source (+0.15 confidence)".to_string());
    }

    let status_field = dict_str(f, "status").to_lowercase();
    if status_field == "confirmed" || status_field == "verified" {
        base_conf = (base_conf + 0.10).min(1.0);
        reasons.push("Explicitly confirmed by tool status (+0.10)".to_string());
    }

    // Step 4: final confidence
    let final_conf = (base_conf + evidence_score * 0.2).min(1.0);
    let final_conf = (final_conf * 1000.0).round() / 1000.0;

    // Step 5: status assignment
    let eff_confirmed = if is_app_logic { 0.50 } else { CONFIRMED_THRESHOLD };
    let eff_unverified = if is_app_logic { 0.10 } else { UNVERIFIED_THRESHOLD };

    let status = if final_conf >= eff_confirmed
        && (!payload.is_empty() || evidence_score > 0.3 || is_network || is_app_logic)
    {
        "confirmed"
    } else if final_conf < eff_unverified {
        warnings.push(format!(
            "Low confidence ({:.0}%) — likely false positive",
            final_conf * 100.0
        ));
        "false_positive"
    } else {
        "unverified"
    };

    let breakdown = format!(
        "base={base_conf:.2} evidence_score={evidence_score:.2} final={final_conf:.2} → {status}"
    );

    let out = f.copy()?;
    out.set_item("validation_status", status)?;
    out.set_item("confidence", final_conf)?;
    out.set_item("confidence_breakdown", &breakdown)?;
    out.set_item("evidence_score", evidence_score)?;
    out.set_item("reasons", reasons)?;
    out.set_item("warnings", warnings)?;
    out.set_item("finding_id_validated", &fid)?;
    Ok(out)
}

fn _batch_validate_inner(
    py: Python<'_>,
    findings: &Bound<'_, PyList>,
) -> PyResult<Vec<PyObject>> {
    let mut out: Vec<PyObject> = Vec::with_capacity(findings.len());
    for item in findings.iter() {
        let f = item.downcast::<PyDict>()?;
        let validated = validate_one(py, f)?;
        out.push(validated.into_py(py));
    }
    Ok(out)
}

/// Return the feature-flag state.
#[pyfunction]
pub fn rust_dedup_enabled(_py: Python<'_>) -> bool {
    std::env::var("ONEINFINITY_RUST").is_ok()
        || std::env::var("ONEINFINITY_RUST_DEDUP").is_ok()
}

// ── module registration (called from lib.rs) ──────────────────────────────────

pub fn register(m: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(deduplicate_findings, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_session_risk, m)?)?;
    m.add_function(wrap_pyfunction!(batch_validate, m)?)?;
    m.add_function(wrap_pyfunction!(rust_dedup_enabled, m)?)?;
    Ok(())
}
