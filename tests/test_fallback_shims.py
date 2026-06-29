"""
Fallback shim test — verifies that Python implementations work
even when oneinfinity_core (Rust PyO3 extension) is unavailable.

Since the Python files do NOT yet have try/except ImportError shim wrappers,
this test exercises the raw Python implementations directly to confirm they
are functionally correct and will serve as the fallback.

Run: cd /path/to/oneinfinity && python3 tests/test_fallback_shims.py
"""
import sys
import types
import traceback

PASS_COUNT = 0
FAIL_COUNT = 0
FAILURES = []


def check(name, fn):
    global PASS_COUNT, FAIL_COUNT
    try:
        fn()
        print(f"  PASS  {name}")
        PASS_COUNT += 1
    except Exception as exc:
        print(f"  FAIL  {name}: {exc}")
        FAIL_COUNT += 1
        FAILURES.append((name, traceback.format_exc()))


# ── Block oneinfinity_core to simulate ImportError ────────────────────────────
# Install a sentinel that raises ImportError on any submodule access
class _BlockedModule(types.ModuleType):
    def __getattr__(self, name):
        raise ImportError(f"oneinfinity_core is not available (simulated)")


# ── 1. tool_wrappers: normalize_finding, normalize_results, merge_normalized ──

def test_normalize_finding():
    from oneinfinity.modules.tool_wrappers import normalize_finding
    result = normalize_finding({"name": "XSS", "severity": "HIGH", "url": "http://a.com/x"}, "nuclei")
    assert isinstance(result, dict), "Expected dict"
    assert "vulnerability" in result, "Missing 'vulnerability' key"
    assert "severity" in result, "Missing 'severity' key"
    assert result["severity"] in ("critical", "high", "medium", "low", "info", "unknown")

def test_normalize_results():
    from oneinfinity.modules.tool_wrappers import normalize_results
    raw = [
        {"name": "SQLi", "severity": "critical", "url": "http://b.com/q"},
        {"name": "SQLi", "severity": "critical", "url": "http://b.com/q"},  # duplicate
    ]
    out = normalize_results(raw, "sqlmap")
    assert isinstance(out, list), "Expected list"
    assert len(out) == 1, f"Expected 1 deduplicated finding, got {len(out)}"

def test_merge_normalized():
    from oneinfinity.modules.tool_wrappers import normalize_finding, merge_normalized
    a = [normalize_finding({"name": "XSS", "severity": "high", "url": "http://a.com/p"}, "dalfox")]
    b = [normalize_finding({"name": "SQLi", "severity": "critical", "url": "http://b.com/q"}, "sqlmap")]
    merged = merge_normalized(a, b)
    assert isinstance(merged, list), "Expected list"
    assert len(merged) == 2, f"Expected 2 merged findings, got {len(merged)}"
    severities = [f["severity"] for f in merged]
    # critical should sort before high
    assert severities[0] == "critical", f"Expected critical first, got {severities}"


# ── 2. scope_validator: ScopeValidator.check ──────────────────────────────────

def test_scope_validator_basic():
    from oneinfinity.core.scope_validator import ScopeValidator
    sv = ScopeValidator()
    sv.add_in_scope("*.acme-pentest.io")
    assert sv.check("api.acme-pentest.io") is True, "Expected in-scope"
    assert sv.check("evil.com") is False, "Expected out-of-scope"

def test_scope_validator_wildcard():
    from oneinfinity.core.scope_validator import ScopeValidator
    sv = ScopeValidator()
    sv.add_in_scope("*.target.io")
    sv.add_out_of_scope("admin.target.io")
    assert sv.check("www.target.io") is True
    assert sv.check("admin.target.io") is False, "Explicitly out-of-scope"

def test_scope_validator_relaxed():
    from oneinfinity.core.scope_validator import ScopeValidator
    sv = ScopeValidator(mode="relaxed")
    # In relaxed mode, anything not explicitly OOS passes
    result = sv.check("anything.example.com")
    # Should not raise; result is bool
    assert isinstance(result, bool)


# ── 3. finding_validator — FindingValidator ───────────────────────────────────

def test_finding_validator_basic():
    from oneinfinity.core.finding_validator import FindingValidator
    fv = FindingValidator()
    finding = {
        "vulnerability": "XSS",
        "url": "http://t.com/x",
        "severity": "high",
        "confidence": 0.9,
        "evidence": "Reflected <script>alert(1)</script> in response",
        "source_tool": "dalfox",
    }
    result = fv.validate(finding)
    assert hasattr(result, "status"), "Expected ValidationResult with .status"
    assert result.status in ("confirmed", "unverified", "potential_false_positive")

def test_finding_validator_batch():
    from oneinfinity.core.finding_validator import FindingValidator
    fv = FindingValidator()
    findings = [
        {"vulnerability": "SQLi", "url": "http://t.com/q", "severity": "critical",
         "confidence": 0.85, "evidence": "Error: You have an error in your SQL syntax",
         "source_tool": "sqlmap"},
        {"vulnerability": "Info Disclosure", "url": "http://t.com/debug", "severity": "low",
         "confidence": 0.2, "source_tool": "nuclei"},
    ]
    results = fv.validate_batch(findings)
    assert isinstance(results, list), "Expected list"
    assert len(results) == 2, f"Expected 2 results, got {len(results)}"


# ── 4. result_aggregator — deduplicate_findings, calculate_session_risk ───────

def test_deduplicate_findings():
    from oneinfinity.findings.result_aggregator import ResultAggregator
    agg = ResultAggregator()
    findings = [
        {"vuln_type": "xss", "url": "http://a.com/x", "parameter": "q", "severity": "high"},
        {"vuln_type": "xss", "url": "http://a.com/x", "parameter": "q", "severity": "high"},  # dup
        {"vuln_type": "sqli", "url": "http://a.com/y", "parameter": "id", "severity": "critical"},
    ]
    unique = agg.deduplicate_findings(findings)
    assert isinstance(unique, list), "Expected list"
    assert len(unique) == 2, f"Expected 2 unique findings, got {len(unique)}"

def test_calculate_session_risk():
    from oneinfinity.findings.result_aggregator import ResultAggregator
    agg = ResultAggregator()
    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "medium"},
    ]
    risk = agg.calculate_session_risk(findings)
    assert isinstance(risk, float), f"Expected float, got {type(risk)}"
    assert 0.0 <= risk <= 10.0, f"Risk {risk} out of range [0, 10]"
    assert risk > 0.0, "Risk should be > 0 with findings present"


# ── 5. mutation_engine — MutationEngine.mutate ────────────────────────────────

def test_mutation_engine_mutate():
    from oneinfinity.arsenal.mutation_engine import MutationEngine
    engine = MutationEngine()
    payload = "<script>alert(1)</script>"
    mutations = engine.mutate(payload, waf_vendor="cloudflare", vuln_type="xss")
    assert isinstance(mutations, list), "Expected list"
    assert len(mutations) > 0, "Expected at least one mutation"
    contents = [m.content for m in mutations]
    assert payload not in contents or len(contents) > 1, "Expected actual mutations, not just original"

def test_mutation_engine_waf_bypass():
    from oneinfinity.arsenal.mutation_engine import MutationEngine
    engine = MutationEngine()
    results = engine.mutate("' OR 1=1--", waf_vendor="imperva", vuln_type="sqli")
    assert len(results) > 0, "Expected bypass variants"
    strategies = {m.strategy for m in results}
    assert len(strategies) > 1, f"Expected multiple strategies, got: {strategies}"


# ── 6. payload_mutation_engine — PayloadMutationEngine.mutate_payload ─────────

def test_payload_mutation_engine():
    from oneinfinity.scan.payload_mutation_engine import PayloadMutationEngine
    pme = PayloadMutationEngine()
    mutations = pme.mutate_payload("' OR 1=1--", "string", "id")
    assert isinstance(mutations, list), "Expected list"
    assert len(mutations) > 0, "Expected at least one mutation"

def test_payload_mutation_dedup():
    from oneinfinity.scan.payload_mutation_engine import PayloadMutationEngine
    pme = PayloadMutationEngine()
    mutations = pme.mutate_payload("<img src=x onerror=alert(1)>", "string", "q")
    # Confirm deduplication (list(set(...)) applied internally)
    assert len(mutations) == len(set(mutations)), "Expected deduplicated mutation list"


if __name__ == "__main__":
    sys.modules["oneinfinity_core"] = _BlockedModule("oneinfinity_core")

    print("=" * 60)
    print("Fallback Shim Test — oneinfinity_core blocked")
    print("=" * 60)

    # ── 1. tool_wrappers ──────────────────────────────────────────────────────
    print("\n[1] tool_wrappers — normalize_finding / normalize_results / merge_normalized")
    check("normalize_finding", test_normalize_finding)
    check("normalize_results (dedup)", test_normalize_results)
    check("merge_normalized (sorted)", test_merge_normalized)

    # ── 2. scope_validator ────────────────────────────────────────────────────
    print("\n[2] scope_validator — ScopeValidator / check_scope")
    check("ScopeValidator basic in/out-of-scope", test_scope_validator_basic)
    check("ScopeValidator wildcard + explicit OOS", test_scope_validator_wildcard)
    check("ScopeValidator relaxed mode", test_scope_validator_relaxed)

    # ── 3. finding_validator ──────────────────────────────────────────────────
    print("\n[3] finding_validator — FindingValidator / batch_validate")
    check("FindingValidator.validate", test_finding_validator_basic)
    check("FindingValidator.validate_batch", test_finding_validator_batch)

    # ── 4. result_aggregator ──────────────────────────────────────────────────
    print("\n[4] result_aggregator — deduplicate_findings / calculate_session_risk")
    check("ResultAggregator.deduplicate_findings", test_deduplicate_findings)
    check("ResultAggregator.calculate_session_risk", test_calculate_session_risk)

    # ── 5. mutation_engine ────────────────────────────────────────────────────
    print("\n[5] mutation_engine — MutationEngine.mutate / generate_waf_bypass")
    check("MutationEngine.mutate basic", test_mutation_engine_mutate)
    check("MutationEngine WAF bypass variants", test_mutation_engine_waf_bypass)

    # ── 6. payload_mutation_engine ────────────────────────────────────────────
    print("\n[6] payload_mutation_engine — PayloadMutationEngine.mutate_payload")
    check("PayloadMutationEngine.mutate_payload", test_payload_mutation_engine)
    check("PayloadMutationEngine deduplication", test_payload_mutation_dedup)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    total = PASS_COUNT + FAIL_COUNT
    print(f"Results: {PASS_COUNT}/{total} PASS, {FAIL_COUNT}/{total} FAIL")
    if FAILURES:
        print("\nFailure details:")
        for name, tb in FAILURES:
            print(f"\n--- {name} ---")
            print(tb)
    print("=" * 60)
    sys.exit(0 if FAIL_COUNT == 0 else 1)
