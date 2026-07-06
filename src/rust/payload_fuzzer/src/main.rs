//! payload_fuzzer — Fast async HTTP payload fuzzer for OneInfinity active testing.
//!
//! Takes a target URL and payload list via stdin (one payload per line, or JSON array),
//! fires all payloads concurrently using Tokio + reqwest, and returns JSON findings
//! to stdout (NDJSON: one object per line).
//!
//! # Usage
//! ```
//! echo '["<script>alert(1)</script>", "OR 1=1"]' | payload-fuzzer \
//!     --target "https://example.com/search?q=FUZZ" \
//!     --method GET --workers 50 --timeout 10
//! ```
//! Or line-delimited:
//! ```
//! cat payloads.txt | payload-fuzzer --target "https://example.com/api/v1/item?id=FUZZ"
//! ```
//!
//! # Output (NDJSON)
//! ```json
//! {"vuln_type":"xss","url":"...","payload":"...","status":200,"evidence":"...","confidence":0.85,"scan_id":"...","ts":"..."}
//! {"type":"stats","total":100,"findings":3,"duration_ms":1200,"ts":"..."}
//! ```
//!
//! FUZZ marker in --target URL is replaced with each payload.
//! When no FUZZ marker is present, payloads are sent as POST body with Content-Type: application/x-www-form-urlencoded.

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use futures::{stream, StreamExt};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT},
    Client, Method, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use uuid::Uuid;

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "payload-fuzzer", about = "Fast async HTTP payload fuzzer for OneInfinity")]
struct Args {
    /// Target URL; use FUZZ marker for injection point (e.g. https://host/path?q=FUZZ)
    #[arg(short, long)]
    target: String,

    /// HTTP method
    #[arg(short, long, default_value = "GET")]
    method: String,

    /// Maximum concurrent workers
    #[arg(short, long, default_value_t = 50)]
    workers: usize,

    /// Per-request timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Optional scan correlation ID
    #[arg(long, default_value = "")]
    scan_id: String,

    /// Custom headers (repeatable): "Name: Value"
    #[arg(long)]
    header: Vec<String>,

    /// POST body template; FUZZ replaced with payload (used when method=POST and no FUZZ in URL)
    #[arg(long, default_value = "q=FUZZ")]
    body_template: String,

    /// Content-Type for POST requests
    #[arg(long, default_value = "application/x-www-form-urlencoded")]
    content_type: String,

    /// Follow redirects
    #[arg(long, default_value_t = true)]
    follow_redirects: bool,

    /// Minimum confidence threshold to emit a finding (0.0–1.0)
    #[arg(long, default_value_t = 0.6)]
    min_confidence: f64,

    /// Skip TLS certificate verification
    #[arg(long, default_value_t = true)]
    insecure: bool,
}

// ── Output types ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Finding {
    vuln_type: String,
    url: String,
    payload: String,
    status: u16,
    evidence: String,
    confidence: f64,
    scan_id: String,
    response_length: usize,
    duration_ms: u64,
    ts: String,
}

// ── Vuln detection heuristics ──────────────────────────────────────────────────

fn detect_vuln_type(payload: &str) -> &'static str {
    let p = payload.to_lowercase();
    if p.contains("<script") || p.contains("onerror=") || p.contains("javascript:") {
        "xss"
    } else if p.contains("or 1=1") || p.contains("union select") || p.contains("drop table")
        || p.contains("' or ") || p.contains("\" or ")
    {
        "sqli"
    } else if p.contains("{{") || p.contains("${") || p.contains("<%=") {
        "ssti"
    } else if p.contains("../") || p.contains("..%2f") || p.contains("/etc/passwd") {
        "path_traversal"
    } else if p.contains("169.254.169.254") || p.contains("localhost") || p.contains("jndi:") {
        "ssrf"
    } else if p.contains("; id") || p.contains("| cat ") || p.contains("$(") {
        "cmdi"
    } else {
        "injection"
    }
}

/// Analyze response to determine if the payload triggered a vulnerability.
/// Returns (confidence, evidence_string).
fn analyze_response(
    payload: &str,
    status: StatusCode,
    body: &str,
    original_status: Option<StatusCode>,
    original_body_len: Option<usize>,
) -> (f64, String) {
    let mut confidence = 0.0_f64;
    let mut evidence_parts: Vec<String> = Vec::new();

    let body_lower = body.to_lowercase();
    let vuln_type = detect_vuln_type(payload);

    // ── XSS reflection detection ──────────────────────────────────────────────
    if vuln_type == "xss" {
        // Check if payload is reflected verbatim
        if body.contains(payload) {
            confidence = confidence.max(0.85);
            evidence_parts.push(format!("payload reflected verbatim in response"));
        }
        // Check for partial reflection (unescaped angle brackets)
        if body_lower.contains("<script") && !payload.to_lowercase().eq(&payload) {
            confidence = confidence.max(0.7);
            evidence_parts.push("script tag present in response".to_string());
        }
        // Check Content-Type mismatch (text/html when JSON expected)
        if body_lower.contains("alert(") || body_lower.contains("onerror=") {
            confidence = confidence.max(0.9);
            evidence_parts.push("JavaScript execution vector present in response".to_string());
        }
    }

    // ── SQLi error detection ──────────────────────────────────────────────────
    if vuln_type == "sqli" {
        let sql_errors = [
            "you have an error in your sql syntax",
            "sqlite_exception",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "syntax error",
            "ora-01756",
            "pg::syntaxerror",
            "mysql_fetch_array",
            "mssql_query",
            "jdbc",
        ];
        for err in &sql_errors {
            if body_lower.contains(err) {
                confidence = confidence.max(0.95);
                evidence_parts.push(format!("SQL error indicator: {}", err));
                break;
            }
        }
        // Timing-independent: if status 500 with DB keywords
        if status == StatusCode::INTERNAL_SERVER_ERROR
            && (body_lower.contains("database") || body_lower.contains("query"))
        {
            confidence = confidence.max(0.75);
            evidence_parts.push("500 with database keyword in response".to_string());
        }
    }

    // ── SSTI detection ────────────────────────────────────────────────────────
    if vuln_type == "ssti" {
        if body.contains("49") && payload.contains("{{7*7}}") {
            confidence = confidence.max(0.95);
            evidence_parts.push("SSTI: {{7*7}} evaluated to 49".to_string());
        }
        if body.contains("49") && payload.contains("${7*7}") {
            confidence = confidence.max(0.90);
            evidence_parts.push("SSTI: ${7*7} evaluated to 49".to_string());
        }
    }

    // ── Path traversal detection ──────────────────────────────────────────────
    if vuln_type == "path_traversal" {
        if body_lower.contains("root:") || body_lower.contains("/bin/bash") || body_lower.contains("daemon:") {
            confidence = confidence.max(0.95);
            evidence_parts.push("path traversal: /etc/passwd content in response".to_string());
        }
    }

    // ── SSRF detection ────────────────────────────────────────────────────────
    if vuln_type == "ssrf" {
        if body_lower.contains("ami-id") || body_lower.contains("instance-id")
            || body_lower.contains("169.254") || body_lower.contains("metadata")
        {
            confidence = confidence.max(0.9);
            evidence_parts.push("SSRF: cloud metadata content in response".to_string());
        }
    }

    // ── Generic anomaly detection ─────────────────────────────────────────────
    // Unusual status codes can indicate issues
    match status.as_u16() {
        500 | 502 | 503 => {
            if let Some(orig) = original_status {
                if orig != status {
                    confidence = confidence.max(0.55);
                    evidence_parts.push(format!("status changed from {} to {} with payload", orig, status));
                }
            }
        }
        200 => {
            // Response length difference from baseline
            if let Some(orig_len) = original_body_len {
                let body_len = body.len();
                let diff_ratio = if orig_len > 0 {
                    (body_len as f64 - orig_len as f64).abs() / orig_len as f64
                } else {
                    0.0
                };
                if diff_ratio > 0.5 && body_len > orig_len + 50 {
                    confidence = confidence.max(0.6);
                    evidence_parts.push(format!(
                        "response length increased significantly: {} → {} ({:.0}%)",
                        orig_len, body_len, diff_ratio * 100.0
                    ));
                }
            }
        }
        _ => {}
    }

    // Error disclosure patterns (generic)
    let error_patterns = ["stack trace", "exception", "traceback", "fatal error", "warning:"];
    for pat in &error_patterns {
        if body_lower.contains(pat) {
            confidence = confidence.max(0.5);
            evidence_parts.push(format!("error disclosure: '{}' in response", pat));
            break;
        }
    }

    let evidence = if evidence_parts.is_empty() {
        format!("status={}, body_len={}", status, body.len())
    } else {
        evidence_parts.join("; ")
    };

    (confidence, evidence)
}

// ── Core fuzzing logic ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ProbeConfig {
    target: String,
    method: Method,
    body_template: String,
    content_type: String,
    scan_id: String,
    min_confidence: f64,
    /// Baseline status and body length from a benign request
    baseline_status: Option<StatusCode>,
    baseline_body_len: Option<usize>,
}

async fn probe_payload(
    client: Arc<Client>,
    cfg: Arc<ProbeConfig>,
    payload: String,
    semaphore: Arc<Semaphore>,
) -> Option<Finding> {
    let _permit = semaphore.acquire().await.ok()?;

    // Build URL: replace FUZZ marker in target or append to query string
    let url = if cfg.target.contains("FUZZ") {
        cfg.target.replace("FUZZ", &urlencoding_encode(&payload))
    } else {
        cfg.target.clone()
    };

    let start = Instant::now();

    let mut req = client.request(cfg.method.clone(), &url);

    // POST body if method is POST and FUZZ not in URL
    if cfg.method == Method::POST && !cfg.target.contains("FUZZ") {
        let body = cfg.body_template.replace("FUZZ", &payload);
        req = req
            .header(CONTENT_TYPE, &cfg.content_type)
            .body(body);
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(_) => return None,
    };

    let status = response.status();
    let duration_ms = start.elapsed().as_millis() as u64;
    let body = response.text().await.unwrap_or_default();
    let body_len = body.len();

    let (confidence, evidence) = analyze_response(
        &payload,
        status,
        &body,
        cfg.baseline_status,
        cfg.baseline_body_len,
    );

    if confidence < cfg.min_confidence {
        return None;
    }

    let vuln_type = detect_vuln_type(&payload).to_string();

    Some(Finding {
        vuln_type,
        url,
        payload,
        status: status.as_u16(),
        evidence,
        confidence,
        scan_id: cfg.scan_id.clone(),
        response_length: body_len,
        duration_ms,
        ts: Utc::now().to_rfc3339(),
    })
}

/// Percent-encode a payload for URL injection.
fn urlencoding_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

// ── Baseline probe ─────────────────────────────────────────────────────────────

async fn baseline_probe(client: &Client, target: &str) -> (Option<StatusCode>, Option<usize>) {
    // Use a safe, benign request to establish baseline
    let url = if target.contains("FUZZ") {
        target.replace("FUZZ", "safe_baseline_test")
    } else {
        target.to_string()
    };
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            (Some(status), Some(body.len()))
        }
        Err(_) => (None, None),
    }
}

// ── Main ───────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let scan_id = if args.scan_id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        args.scan_id.clone()
    };

    // Parse custom headers
    let mut header_map = HeaderMap::new();
    header_map.insert(
        USER_AGENT,
        HeaderValue::from_static("Mozilla/5.0 (compatible; OneInfinity/2.0; payload-fuzzer)"),
    );
    for h in &args.header {
        if let Some((name, value)) = h.split_once(": ") {
            if let (Ok(n), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                header_map.insert(n, v);
            }
        }
    }

    let method = Method::from_bytes(args.method.to_uppercase().as_bytes())
        .context("Invalid HTTP method")?;

    // Build reqwest client
    let client = Client::builder()
        .default_headers(header_map)
        .timeout(Duration::from_secs(args.timeout))
        .danger_accept_invalid_certs(args.insecure)
        .redirect(if args.follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()
        .context("Failed to build HTTP client")?;

    // Establish baseline
    let (baseline_status, baseline_body_len) = baseline_probe(&client, &args.target).await;

    let cfg = Arc::new(ProbeConfig {
        target: args.target.clone(),
        method,
        body_template: args.body_template.clone(),
        content_type: args.content_type.clone(),
        scan_id: scan_id.clone(),
        min_confidence: args.min_confidence,
        baseline_status,
        baseline_body_len,
    });

    let client = Arc::new(client);
    let semaphore = Arc::new(Semaphore::new(args.workers));

    // Read payloads from stdin: either JSON array or line-delimited
    let stdin = io::stdin();
    let mut raw = String::new();
    for line in stdin.lock().lines() {
        let line = line.context("stdin read error")?;
        raw.push_str(&line);
        raw.push('\n');
    }
    raw = raw.trim().to_string();

    let payloads: Vec<String> = if raw.starts_with('[') {
        // JSON array
        serde_json::from_str::<Vec<Value>>(&raw)
            .map(|v| v.into_iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default()
    } else {
        // Line-delimited
        raw.lines()
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .map(String::from)
            .collect()
    };

    if payloads.is_empty() {
        eprintln!("No payloads provided via stdin");
        std::process::exit(1);
    }

    let total = payloads.len();
    let start = Instant::now();
    let mut findings = 0usize;

    // Run all probes concurrently with worker limit
    let results: Vec<Option<Finding>> = stream::iter(payloads.into_iter())
        .map(|payload| {
            let client = Arc::clone(&client);
            let cfg = Arc::clone(&cfg);
            let sema = Arc::clone(&semaphore);
            async move { probe_payload(client, cfg, payload, sema).await }
        })
        .buffer_unordered(args.workers)
        .collect()
        .await;

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    use std::io::Write;

    for finding in results.into_iter().flatten() {
        findings += 1;
        let json = serde_json::to_string(&finding)?;
        writeln!(out, "{}", json)?;
    }

    // Emit stats line
    let duration_ms = start.elapsed().as_millis() as u64;
    let stats = json!({
        "type": "stats",
        "total_payloads": total,
        "findings": findings,
        "duration_ms": duration_ms,
        "target": args.target,
        "scan_id": scan_id,
        "ts": Utc::now().to_rfc3339(),
    });
    writeln!(out, "{}", stats)?;
    out.flush()?;

    Ok(())
}
