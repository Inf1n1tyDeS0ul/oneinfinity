//! Criterion benchmark: scope_check hot path.
//!
//! Run:  cargo bench --bench scope_bench
//!
//! Target: check() on 10 000 domains ≥5× faster than Python equivalent.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use oneinfinity_core::scope_check::ScopeValidator;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn build_validator() -> ScopeValidator {
    let mut sv = ScopeValidator::new("strict").unwrap();
    // Typical scope configuration
    sv.add_in_scope("*.acme.com").unwrap();
    sv.add_in_scope("acme.com").unwrap();
    sv.add_in_scope("203.0.113.0/24").unwrap();
    sv.add_in_scope("re:^api[0-9]+\\.acme\\.com$").unwrap();
    sv.add_out_of_scope("admin.acme.com").unwrap();
    sv
}

/// Mix of in-scope, OOS seeds, explicit deny, and unrecognised domains.
/// Deterministic order (sorted alphabetically for reproducibility).
fn targets_10k() -> Vec<String> {
    let base: Vec<&str> = vec![
        "api.acme.com",
        "www.acme.com",
        "acme.com",
        "api1.acme.com",
        "api99.acme.com",
        "admin.acme.com",    // explicit deny
        "10.0.0.1",          // always OOS
        "192.168.1.1",       // always OOS
        "localhost",         // always OOS
        "evil.com",          // not in scope
        "203.0.113.42",      // CIDR in-scope
        "203.0.114.1",       // CIDR miss
        "sub.evil.org",      // not in scope
        "foo.internal",      // always OOS
        "bar.corp",          // always OOS
    ];
    // Repeat to reach 10 000
    let mut out = Vec::with_capacity(10_000);
    let mut i = 0usize;
    while out.len() < 10_000 {
        out.push(base[i % base.len()].to_owned());
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_check_single(c: &mut Criterion) {
    let mut sv = build_validator();
    let mut group = c.benchmark_group("scope_check/single");
    group.throughput(Throughput::Elements(1));

    group.bench_function("in_scope_wildcard", |b| {
        b.iter(|| sv.check_inner(black_box("api.acme.com")).unwrap())
    });
    group.bench_function("always_oos_private_ip", |b| {
        b.iter(|| sv.check_inner(black_box("10.0.0.1")).unwrap())
    });
    group.bench_function("explicit_deny", |b| {
        b.iter(|| sv.check_inner(black_box("admin.acme.com")).unwrap())
    });
    group.bench_function("cidr_hit", |b| {
        b.iter(|| sv.check_inner(black_box("203.0.113.42")).unwrap())
    });
    group.bench_function("regex_rule", |b| {
        b.iter(|| sv.check_inner(black_box("api42.acme.com")).unwrap())
    });
    group.finish();
}

fn bench_check_many(c: &mut Criterion) {
    let targets = targets_10k();
    let mut group = c.benchmark_group("scope_check/batch");
    group.throughput(Throughput::Elements(targets.len() as u64));

    for size in [100usize, 1_000, 10_000] {
        let batch: Vec<String> = targets[..size].to_vec();
        group.bench_with_input(
            BenchmarkId::new("check_many", size),
            &batch,
            |b, batch| {
                let mut sv = build_validator();
                b.iter(|| sv.check_many(black_box(batch.clone())).unwrap())
            },
        );
    }
    group.finish();
}

fn bench_check_loop_10k(c: &mut Criterion) {
    // Simulates calling check() 10 000 times individually (baseline for Python comparison).
    let targets = targets_10k();
    let mut group = c.benchmark_group("scope_check/loop_10k");
    group.throughput(Throughput::Elements(10_000));

    group.bench_function("sequential_check", |b| {
        b.iter(|| {
            let mut sv = build_validator();
            for t in &targets {
                let _ = sv.check_inner(black_box(t.as_str())).unwrap();
            }
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_check_single,
    bench_check_many,
    bench_check_loop_10k,
);
criterion_main!(benches);
