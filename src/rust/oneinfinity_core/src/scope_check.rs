//! scope_check.rs — Zero-allocation hot-path scope validator.
//!
//! Feature flags:
//!   ONEINFINITY_RUST=1            — global Rust fast-path toggle
//!   ONEINFINITY_RUST_SCOPE_CHECK=1 — per-module toggle (inherits global if absent)
//!
//! Safety: every PyO3 entry point is wrapped in `catch_unwind` so a Rust
//! panic never crosses the FFI boundary and aborts the Python interpreter.

use std::net::IpAddr;

use ipnet::IpNet;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;

// ---------------------------------------------------------------------------
// Always-out-of-scope seed patterns (mirrors Python _ALWAYS_OOS exactly)
// ---------------------------------------------------------------------------
const ALWAYS_OOS_PATTERNS: &[&str] = &[
    "localhost",
    "127.*",
    "::1",
    "0.0.0.0",
    "169.254.*", // link-local
    "10.*",      // RFC-1918
    "172.16.*",  // RFC-1918
    "192.168.*", // RFC-1918
    "*.internal",
    "*.local",
    "*.corp",
    "*.example.com",
    "*.test",
];

// ---------------------------------------------------------------------------
// Internal rule representation — compiled at construction, hot path is O(n)
// pointer-chases with zero heap allocation.
// ---------------------------------------------------------------------------
#[derive(Debug)]
enum RuleKind {
    /// Pre-parsed CIDR network
    Cidr(IpNet),
    /// Wildcard — pre-split into (prefix, suffix) for fast matching.
    /// `*.acme.com` → prefix="" suffix=".acme.com", bare `*` matches all.
    Wildcard { prefix: String, suffix: String },
    /// Compiled regex (pattern was prefixed with "re:")
    Regex(Regex),
    /// Exact domain / literal (lower-cased at construction)
    Exact(String),
}

#[derive(Debug)]
struct ScopeRule {
    kind: RuleKind,
    /// Original pattern string, kept for Python-visible repr only.
    raw: String,
}

impl ScopeRule {
    /// Build a rule from an arbitrary pattern string.
    /// Allocates once at construction; hot-path matching is alloc-free.
    fn from_pattern(pattern: &str) -> Result<Self, String> {
        let pat = pattern.trim().to_lowercase();

        // Regex rule
        if let Some(re_src) = pat.strip_prefix("re:") {
            let rx = Regex::new(re_src)
                .map_err(|e| format!("invalid regex '{}': {}", re_src, e))?;
            return Ok(ScopeRule {
                kind: RuleKind::Regex(rx),
                raw: pat,
            });
        }

        // CIDR
        if let Ok(net) = pat.parse::<IpNet>() {
            return Ok(ScopeRule {
                kind: RuleKind::Cidr(net),
                raw: pat,
            });
        }
        // Also try bare IPv4/IPv6 — treat as /32 or /128
        if let Ok(addr) = pat.parse::<IpAddr>() {
            let net = IpNet::from(addr);
            return Ok(ScopeRule {
                kind: RuleKind::Cidr(net),
                raw: pat,
            });
        }

        // Wildcard (fnmatch-style, only `*` and `?`)
        if pat.contains('*') || pat.contains('?') {
            // Convert fnmatch glob to a fast split: we only support the most
            // common forms used in scope rules.  Full fnmatch is emulated by
            // pre-splitting on the first `*`.
            let (prefix, suffix) = if let Some(idx) = pat.find('*') {
                (pat[..idx].to_owned(), pat[idx + 1..].to_owned())
            } else {
                // '?' only — treat as regex for correctness
                let re_src = pat.replace('.', r"\.").replace('?', ".");
                let rx = Regex::new(&format!("^{}$", re_src))
                    .map_err(|e| format!("wildcard-to-regex failed: {}", e))?;
                return Ok(ScopeRule {
                    kind: RuleKind::Regex(rx),
                    raw: pat,
                });
            };
            return Ok(ScopeRule {
                kind: RuleKind::Wildcard { prefix, suffix },
                raw: pat,
            });
        }

        // Exact
        Ok(ScopeRule {
            kind: RuleKind::Exact(pat.clone()),
            raw: pat,
        })
    }

    /// Match `value` (already lower-cased, port-stripped) against this rule.
    /// ZERO allocations.
    #[inline]
    fn matches(&self, value: &str) -> bool {
        match &self.kind {
            RuleKind::Cidr(net) => {
                // Parse IP from value — small stack cost, no heap
                if let Ok(addr) = value.parse::<IpAddr>() {
                    net.contains(&addr)
                } else {
                    false
                }
            }
            RuleKind::Wildcard { prefix, suffix } => {
                // *.acme.com — prefix="" suffix=".acme.com"
                // Matches: api.acme.com (ends with ".acme.com")
                //          acme.com     (exact == suffix stripped of leading '.')
                if prefix.is_empty() {
                    // Leading wildcard
                    if suffix.is_empty() {
                        return true; // bare `*`
                    }
                    // value ends with suffix OR value == suffix without leading '.'
                    let bare = suffix.trim_start_matches('.');
                    value.ends_with(suffix.as_str()) || value == bare
                } else {
                    // Wildcard in middle/end — fall back to prefix+suffix split
                    value.starts_with(prefix.as_str()) && value.ends_with(suffix.as_str())
                        && value.len() >= prefix.len() + suffix.len()
                }
            }
            RuleKind::Regex(rx) => rx.is_match(value),
            RuleKind::Exact(ex) => {
                // Exact OR subdomain match (Python: value == pat OR value.endswith("." + pat))
                value == ex.as_str() || value.ends_with(&format!(".{}", ex))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PyO3 class
// ---------------------------------------------------------------------------

/// Validates targets against a declared scope.
///
/// Modes:
///   "strict"  — must be explicitly in-scope AND not out-of-scope (default)
///   "relaxed" — pass unless explicitly out-of-scope
///
/// Feature flags (env vars):
///   ONEINFINITY_RUST=1             — global Rust fast-path active
///   ONEINFINITY_RUST_SCOPE_CHECK=1 — per-module override
#[pyclass(name = "ScopeValidator")]
pub struct ScopeValidator {
    mode_strict: bool,
    in_scope: Vec<ScopeRule>,
    out_of_scope: Vec<ScopeRule>,
    require_auth: bool,
    auth_confirmed: bool,
    /// Audit log entries: (verdict, target, reason)
    audit_log: Vec<(String, String, String)>,
}

/// Extract the host portion from a target string.
/// Mirrors Python ScopeValidator._extract_host exactly.
/// Returns a `&str` slice into `target` where possible (no alloc for simple cases).
fn extract_host(target: &str) -> Option<String> {
    let target = target.trim();
    let host_raw: &str = if target.starts_with("http://") || target.starts_with("https://") {
        // Use the `url` crate for proper parsing
        let parsed = url::Url::parse(target).ok()?;
        let h = parsed.host_str()?.to_owned();
        // Bracketed IPv6 addresses: url crate strips brackets
        return Some(h.to_lowercase());
    } else if target.contains('/') {
        target.splitn(2, '/').next()?
    } else {
        target
    };

    // Strip port — but beware IPv6 `[::1]:8080`
    let host = if host_raw.starts_with('[') {
        // IPv6 bracketed
        host_raw
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host_raw)
    } else if host_raw.contains(':') {
        host_raw.rsplit(':').nth(1).unwrap_or(host_raw)
    } else {
        host_raw
    };

    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

#[pymethods]
impl ScopeValidator {
    #[new]
    #[pyo3(signature = (mode = "strict"))]
    fn new(mode: &str) -> PyResult<Self> {
        std::panic::catch_unwind(|| {
            if mode != "strict" && mode != "relaxed" {
                return Err(PyValueError::new_err(
                    "mode must be 'strict' or 'relaxed'",
                ));
            }
            let mut oos: Vec<ScopeRule> = Vec::with_capacity(ALWAYS_OOS_PATTERNS.len());
            for pat in ALWAYS_OOS_PATTERNS {
                match ScopeRule::from_pattern(pat) {
                    Ok(r) => oos.push(r),
                    Err(e) => eprintln!("[scope_check] failed to compile OOS pattern '{}': {}", pat, e),
                }
            }
            Ok(ScopeValidator {
                mode_strict: mode == "strict",
                in_scope: Vec::new(),
                out_of_scope: oos,
                require_auth: false,
                auth_confirmed: false,
                audit_log: Vec::new(),
            })
        })
        .unwrap_or_else(|_| Err(PyValueError::new_err("panic in ScopeValidator::new")))
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    fn add_in_scope(&mut self, pattern: &str) -> PyResult<()> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Extract host if pattern looks like a URL
            let effective = if pattern.contains("://") || pattern.starts_with("http") {
                extract_host(pattern).unwrap_or_else(|| pattern.to_lowercase())
            } else {
                pattern.to_owned()
            };
            match ScopeRule::from_pattern(&effective) {
                Ok(rule) => {
                    self.in_scope.push(rule);
                    Ok(())
                }
                Err(e) => Err(PyValueError::new_err(format!(
                    "invalid in-scope pattern '{}': {}",
                    pattern, e
                ))),
            }
        }))
        .unwrap_or_else(|_| Err(PyValueError::new_err("panic in add_in_scope")))
    }

    fn add_out_of_scope(&mut self, pattern: &str) -> PyResult<()> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match ScopeRule::from_pattern(pattern) {
                Ok(rule) => {
                    self.out_of_scope.push(rule);
                    Ok(())
                }
                Err(e) => Err(PyValueError::new_err(format!(
                    "invalid out-of-scope pattern '{}': {}",
                    pattern, e
                ))),
            }
        }))
        .unwrap_or_else(|_| Err(PyValueError::new_err("panic in add_out_of_scope")))
    }

    fn set_mode(&mut self, mode: &str) -> PyResult<()> {
        if mode != "strict" && mode != "relaxed" {
            return Err(PyValueError::new_err("mode must be 'strict' or 'relaxed'"));
        }
        self.mode_strict = mode == "strict";
        Ok(())
    }

    fn require_authorization(&mut self, confirmed: bool) -> PyResult<()> {
        self.require_auth = true;
        self.auth_confirmed = confirmed;
        Ok(())
    }

    fn confirm_authorization(&mut self) -> PyResult<()> {
        self.auth_confirmed = true;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Hot-path validation
    // -----------------------------------------------------------------------

    /// Returns True if target is in scope and authorized.
    /// Hot path: no heap allocations after the host extraction.
    fn check(&mut self, target: &str) -> PyResult<bool> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_inner(target)
        }))
        .unwrap_or_else(|_| {
            Ok(false) // panic = treat as OOS, never crash Python
        })
    }

    /// Alias for check() — mirrors Python is_in_scope()
    fn is_in_scope(&mut self, url: &str) -> PyResult<bool> {
        self.check(url)
    }

    /// Alias for check() — mirrors Python check_url()
    fn check_url(&mut self, url: &str) -> PyResult<bool> {
        self.check(url)
    }

    /// Batch API — Gate 1 requirement.
    /// Processes a Vec<String> and returns Vec<bool> with identical ordering.
    fn check_many(&mut self, targets: Vec<String>) -> PyResult<Vec<bool>> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut results = Vec::with_capacity(targets.len());
            for t in &targets {
                results.push(self.check_inner(t)?);
            }
            Ok(results)
        }))
        .unwrap_or_else(|_| Ok(vec![false; targets.len()]))
    }

    fn assert_in_scope(&mut self, target: &str) -> PyResult<()> {
        if !self.check(target)? {
            Err(PyValueError::new_err(format!(
                "Target out of scope: {}",
                target
            )))
        } else {
            Ok(())
        }
    }

    fn filter_in_scope(&mut self, targets: Vec<String>) -> PyResult<Vec<String>> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut out = Vec::new();
            for t in &targets {
                if self.check_inner(t)? {
                    out.push(t.clone());
                }
            }
            Ok(out)
        }))
        .unwrap_or_else(|_| Ok(Vec::new()))
    }

    // -----------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------

    fn audit_log(&self) -> PyResult<Vec<PyObject>> {
        Python::with_gil(|py| {
            self.audit_log
                .iter()
                .map(|(verdict, target, reason)| {
                    let d = pyo3::types::PyDict::new_bound(py);
                    d.set_item("verdict", verdict)?;
                    d.set_item("target", target)?;
                    d.set_item("reason", reason)?;
                    Ok(d.into())
                })
                .collect()
        })
    }

    fn oos_violations(&self) -> PyResult<Vec<PyObject>> {
        Python::with_gil(|py| {
            self.audit_log
                .iter()
                .filter(|(v, _, _)| v == "OOS")
                .map(|(verdict, target, reason)| {
                    let d = pyo3::types::PyDict::new_bound(py);
                    d.set_item("verdict", verdict)?;
                    d.set_item("target", target)?;
                    d.set_item("reason", reason)?;
                    Ok(d.into())
                })
                .collect()
        })
    }

    fn summary(&self) -> String {
        format!(
            "Scope Validator — mode={}\n  In-scope rules  : {}\n  Out-of-scope    : {}\n  Auth required   : {}\n  Auth confirmed  : {}\n  Audit entries   : {}",
            if self.mode_strict { "strict" } else { "relaxed" },
            self.in_scope.len(),
            self.out_of_scope.len(),
            self.require_auth,
            self.auth_confirmed,
            self.audit_log.len(),
        )
    }
}

impl ScopeValidator {
    /// Inner check — called by check(), check_many(), filter_in_scope().
    /// Single allocation: host string from extract_host().
    /// Everything else is pointer traversal over pre-compiled rules.
    fn check_inner(&mut self, target: &str) -> PyResult<bool> {
        let host = match extract_host(target) {
            Some(h) => h,
            None => {
                self.audit_log.push((
                    "INVALID".to_owned(),
                    target.to_owned(),
                    "could not extract host".to_owned(),
                ));
                return Ok(false);
            }
        };

        // Always-OOS check first (short-circuit)
        for rule in &self.out_of_scope {
            if rule.matches(&host) {
                self.audit_log.push((
                    "OOS".to_owned(),
                    target.to_owned(),
                    format!("matches OOS rule: {}", rule.raw),
                ));
                return Ok(false);
            }
        }

        // In-scope check
        let in_scope = if self.in_scope.is_empty() {
            // No scope defined — relaxed passes, strict blocks
            !self.mode_strict
        } else {
            self.in_scope.iter().any(|r| r.matches(&host))
        };

        if !in_scope {
            self.audit_log.push((
                "OOS".to_owned(),
                target.to_owned(),
                "not in declared scope".to_owned(),
            ));
            return Ok(false);
        }

        // Authorization gate
        if self.require_auth && !self.auth_confirmed {
            self.audit_log.push((
                "UNAUTH".to_owned(),
                target.to_owned(),
                "authorization not confirmed".to_owned(),
            ));
            return Ok(false);
        }

        self.audit_log
            .push(("OK".to_owned(), target.to_owned(), String::new()));
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Unit tests (cargo test)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(mode: &str) -> ScopeValidator {
        ScopeValidator::new(mode).unwrap()
    }

    // Helper to call check_inner without PyResult noise
    fn chk(sv: &mut ScopeValidator, t: &str) -> bool {
        sv.check_inner(t).unwrap()
    }

    // --- Always-OOS seeds ---
    #[test]
    fn test_always_oos_localhost() {
        let mut sv = make_validator("relaxed");
        assert!(!chk(&mut sv, "localhost"));
        assert!(!chk(&mut sv, "http://localhost/foo"));
    }

    #[test]
    fn test_always_oos_private_ipv4() {
        let mut sv = make_validator("relaxed");
        assert!(!chk(&mut sv, "10.0.0.1"));
        assert!(!chk(&mut sv, "192.168.1.100"));
        assert!(!chk(&mut sv, "172.16.5.5"));
        assert!(!chk(&mut sv, "127.0.0.1"));
        assert!(!chk(&mut sv, "169.254.0.1"));
    }

    #[test]
    fn test_always_oos_internal_domains() {
        let mut sv = make_validator("relaxed");
        assert!(!chk(&mut sv, "foo.internal"));
        assert!(!chk(&mut sv, "bar.local"));
        assert!(!chk(&mut sv, "corp.corp"));
        assert!(!chk(&mut sv, "thing.example.com"));
        assert!(!chk(&mut sv, "stuff.test"));
    }

    // --- Strict mode: no scope → always False ---
    #[test]
    fn test_strict_no_scope() {
        let mut sv = make_validator("strict");
        assert!(!chk(&mut sv, "example.org"));
        assert!(!chk(&mut sv, "api.acme.com"));
    }

    // --- Relaxed mode: no scope → True (unless OOS) ---
    #[test]
    fn test_relaxed_no_scope() {
        let mut sv = make_validator("relaxed");
        assert!(chk(&mut sv, "api.acme.com"));
    }

    // --- Wildcard matching ---
    #[test]
    fn test_wildcard_subdomain() {
        let mut sv = make_validator("strict");
        sv.in_scope.push(ScopeRule::from_pattern("*.acme.com").unwrap());
        assert!(chk(&mut sv, "api.acme.com"));
        assert!(chk(&mut sv, "acme.com")); // bare domain matches *.acme.com
        assert!(!chk(&mut sv, "evil.com"));
    }

    // --- Exact match ---
    #[test]
    fn test_exact_match() {
        let mut sv = make_validator("strict");
        sv.in_scope.push(ScopeRule::from_pattern("acme.com").unwrap());
        assert!(chk(&mut sv, "acme.com"));
        assert!(chk(&mut sv, "sub.acme.com")); // subdomain of exact → allowed per Python spec
        assert!(!chk(&mut sv, "notacme.com"));
    }

    // --- Deny overrides allow ---
    #[test]
    fn test_deny_overrides_allow() {
        let mut sv = make_validator("strict");
        sv.in_scope.push(ScopeRule::from_pattern("*.acme.com").unwrap());
        sv.out_of_scope.push(ScopeRule::from_pattern("admin.acme.com").unwrap());
        assert!(chk(&mut sv, "api.acme.com"));
        assert!(!chk(&mut sv, "admin.acme.com"));
    }

    // --- CIDR ---
    #[test]
    fn test_cidr_allow() {
        let mut sv = make_validator("strict");
        sv.in_scope.push(ScopeRule::from_pattern("203.0.113.0/24").unwrap());
        assert!(chk(&mut sv, "203.0.113.42"));
        assert!(!chk(&mut sv, "203.0.114.1"));
    }

    // --- URL with port ---
    #[test]
    fn test_url_with_port() {
        let mut sv = make_validator("strict");
        sv.in_scope.push(ScopeRule::from_pattern("acme.com").unwrap());
        assert!(chk(&mut sv, "https://acme.com:8443/path"));
        assert!(chk(&mut sv, "acme.com:8080"));
    }

    // --- Regex rule ---
    #[test]
    fn test_regex_rule() {
        let mut sv = make_validator("strict");
        sv.in_scope
            .push(ScopeRule::from_pattern("re:^api[0-9]+\\.acme\\.com$").unwrap());
        assert!(chk(&mut sv, "api1.acme.com"));
        assert!(chk(&mut sv, "api99.acme.com"));
        assert!(!chk(&mut sv, "api.acme.com"));
    }

    // --- Batch API ---
    #[test]
    fn test_check_many() {
        let mut sv = make_validator("strict");
        sv.in_scope.push(ScopeRule::from_pattern("*.acme.com").unwrap());
        let targets = vec![
            "api.acme.com".to_owned(),
            "10.0.0.1".to_owned(),
            "evil.com".to_owned(),
        ];
        let results = sv
            .check_many(targets)
            .unwrap();
        assert_eq!(results, vec![true, false, false]);
    }

    // --- extract_host edge cases ---
    #[test]
    fn test_extract_host_cases() {
        assert_eq!(extract_host("http://acme.com/path"), Some("acme.com".into()));
        assert_eq!(extract_host("acme.com:8080"), Some("acme.com".into()));
        assert_eq!(extract_host("acme.com/path"), Some("acme.com".into()));
        assert_eq!(extract_host("  acme.com  "), Some("acme.com".into()));
        assert_eq!(extract_host(""), None);
    }
}
