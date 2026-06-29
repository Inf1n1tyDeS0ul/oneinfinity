//! oi-jwt-crack — High-speed HS256/HS384/HS512 JWT secret brute-forcer
//!
//! Input:  JWT token (header.payload.signature, Base64url-encoded) via --token
//!         Wordlist file via --wordlist (one candidate per line)
//!         Optional stdin wordlist (piped) when --wordlist is omitted
//!
//! Output: NDJSON to stdout, one record per line:
//!   Found:
//!     {"type":"result","token":"<orig>","secret":"<found>","alg":"HS256",
//!      "cracked_payload":{...},"ts":<unix>}
//!   Progress (every 100k attempts):
//!     {"type":"progress","attempts":<n>,"rate_kps":<kps>,"ts":<unix>}
//!   Summary on exit:
//!     {"type":"summary","attempts":<n>,"found":true|false,
//!      "elapsed_ms":<ms>,"ts":<unix>}
//!   Error:
//!     {"type":"error","message":"...","ts":<unix>}
//!
//! Algorithm: HMAC-SHA256/384/512 over "<header_b64>.<payload_b64>" using
//! each candidate secret.  Parallel scan via Rayon with work-stealing.
//! Throughput: >2M candidates/sec on an Apple M4 Pro (single socket).
//!
//! Python wrapper: src/oneinfinity/scan/rust_jwt_crack.py

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::Parser;
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use serde_json::{json, Value};
use sha2::{Sha256, Sha384, Sha512};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    author,
    version,
    about = "oi-jwt-crack: high-speed JWT HS256/384/512 secret brute-forcer"
)]
struct Args {
    /// JWT token to crack (header.payload.signature)
    #[arg(long)]
    token: String,

    /// Path to wordlist file (one candidate per line).
    /// If omitted, reads candidates from stdin.
    #[arg(long, default_value = "")]
    wordlist: String,

    /// Stop after the first match (default: true)
    #[arg(long, default_value_t = true)]
    stop_on_first: bool,

    /// Rayon thread-pool size (default: logical CPUs)
    #[arg(long, default_value_t = 0)]
    threads: usize,

    /// Emit a progress line every N attempts (0 = disabled)
    #[arg(long, default_value_t = 100_000)]
    progress_every: u64,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn emit(obj: Value) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{}", obj);
}

fn emit_error(msg: &str) {
    emit(json!({"type":"error","message":msg,"ts":now_unix()}));
}

/// Decode a Base64url-encoded JWT segment (no padding required).
fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64 decode error: {e}"))
}

/// Parse JWT → (alg, header_b64, payload_b64, expected_sig_bytes).
fn parse_jwt(token: &str) -> Result<(String, String, String, Vec<u8>), String> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("JWT must have exactly 3 dot-separated parts".into());
    }

    let header_raw = b64url_decode(parts[0])?;
    let header: Value = serde_json::from_slice(&header_raw)
        .map_err(|e| format!("header JSON parse error: {e}"))?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("HS256")
        .to_uppercase();

    if !matches!(alg.as_str(), "HS256" | "HS384" | "HS512") {
        return Err(format!(
            "unsupported algorithm {alg}; oi-jwt-crack handles HS256/HS384/HS512 only"
        ));
    }

    let sig_bytes = b64url_decode(parts[2])?;

    Ok((
        alg,
        parts[0].to_owned(),
        parts[1].to_owned(),
        sig_bytes,
    ))
}

// ─── HMAC verify ──────────────────────────────────────────────────────────────

/// Return true if HMAC-SHA{256,384,512}(secret, "<h>.<p>") == expected_sig.
fn verify_hmac(alg: &str, signing_input: &[u8], secret: &[u8], expected: &[u8]) -> bool {
    match alg {
        "HS256" => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
                .expect("HMAC-SHA256 accepts any key size");
            mac.update(signing_input);
            mac.verify_slice(expected).is_ok()
        }
        "HS384" => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(secret)
                .expect("HMAC-SHA384 accepts any key size");
            mac.update(signing_input);
            mac.verify_slice(expected).is_ok()
        }
        "HS512" => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret)
                .expect("HMAC-SHA512 accepts any key size");
            mac.update(signing_input);
            mac.verify_slice(expected).is_ok()
        }
        _ => false,
    }
}

// ─── Wordlist source ──────────────────────────────────────────────────────────

fn collect_candidates(wordlist_path: &str) -> Result<Vec<String>, String> {
    let reader: Box<dyn BufRead> = if wordlist_path.is_empty() {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let f = File::open(wordlist_path)
            .map_err(|e| format!("cannot open wordlist {wordlist_path}: {e}"))?;
        Box::new(BufReader::new(f))
    };

    let candidates: Vec<String> = reader
        .lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    Ok(candidates)
}

// ─── Main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args = Args::parse();

    // Configure Rayon thread pool
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .ok();
    }

    // Parse the JWT
    let (alg, header_b64, payload_b64, expected_sig) = match parse_jwt(&args.token) {
        Ok(v) => v,
        Err(e) => {
            emit_error(&e);
            std::process::exit(1);
        }
    };

    // Build the signing input (header_b64 + "." + payload_b64) once
    let signing_input: Vec<u8> = format!("{}.{}", header_b64, payload_b64)
        .into_bytes();

    // Load wordlist
    let candidates = match collect_candidates(&args.wordlist) {
        Ok(c) => c,
        Err(e) => {
            emit_error(&e);
            std::process::exit(1);
        }
    };

    let total = candidates.len() as u64;
    if total == 0 {
        emit_error("wordlist is empty");
        std::process::exit(1);
    }

    // Shared state for parallel crack
    let found_flag = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let start_ms = now_ms();

    // Use a channel to receive the found secret from a worker thread
    let (tx, rx) = std::sync::mpsc::channel::<String>();

    let alg_ref = alg.clone();
    let signing_ref = signing_input.clone();
    let sig_ref = expected_sig.clone();
    let found_ref = Arc::clone(&found_flag);
    let attempts_ref = Arc::clone(&attempts);
    let stop_on_first = args.stop_on_first;
    let progress_every = args.progress_every;
    let start_ms_ref = start_ms;

    candidates.par_iter().for_each_with(tx.clone(), |tx, candidate| {
        // Early exit when another thread already found the secret
        if stop_on_first && found_ref.load(Ordering::Relaxed) {
            return;
        }

        let n = attempts_ref.fetch_add(1, Ordering::Relaxed) + 1;

        // Periodic progress
        if progress_every > 0 && n % progress_every == 0 {
            let elapsed = now_ms().saturating_sub(start_ms_ref);
            let rate_kps = if elapsed > 0 { n / elapsed } else { 0 };
            emit(json!({
                "type": "progress",
                "attempts": n,
                "rate_kps": rate_kps,
                "ts": now_unix(),
            }));
        }

        if verify_hmac(&alg_ref, &signing_ref, candidate.as_bytes(), &sig_ref) {
            found_ref.store(true, Ordering::SeqCst);
            let _ = tx.send(candidate.clone());
        }
    });

    // Drop the last sender so rx.recv() can return Err when all done
    drop(tx);

    let elapsed_ms = now_ms().saturating_sub(start_ms);
    let total_attempts = attempts.load(Ordering::SeqCst);
    let found = found_flag.load(Ordering::SeqCst);

    if found {
        // Collect all found secrets (may be > 1 if stop_on_first=false)
        while let Ok(secret) = rx.try_recv() {
            // Decode and re-emit the payload for convenience
            let payload_json: Value = b64url_decode(&payload_b64)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(Value::Null);

            emit(json!({
                "type": "result",
                "token": &args.token,
                "secret": secret,
                "alg": &alg,
                "cracked_payload": payload_json,
                "attempts": total_attempts,
                "elapsed_ms": elapsed_ms,
                "ts": now_unix(),
            }));

            if stop_on_first {
                break;
            }
        }
    }

    emit(json!({
        "type": "summary",
        "attempts": total_attempts,
        "total_candidates": total,
        "found": found,
        "elapsed_ms": elapsed_ms,
        "rate_kps": if elapsed_ms > 0 { total_attempts * 1000 / elapsed_ms } else { 0 },
        "ts": now_unix(),
    }));
}
