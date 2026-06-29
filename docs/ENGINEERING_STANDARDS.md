# Engineering Standards — One&Infinity

This document defines the engineering principles, quality gates, and implementation protocols that govern all contributions to the One&Infinity offensive security platform. It is the authoritative reference for code quality, test discipline, integration requirements, and production readiness.

---

## Test Engineering Standards

Sound test hygiene is mandatory. The following rules apply to every test file in `tests/`.

### pytest-asyncio

All async tests run under `asyncio_mode = "auto"` (configured in `pyproject.toml`). Write async test functions directly — no decorator needed:

```python
async def test_scanner_returns_findings():
    result = await scanner.scan("http://testphp.vulnweb.com/")
    assert result
```

Do not add `@pytest.mark.asyncio` unless you have a file-level reason to override the global mode.

### Optional-Dependency Guards

If a test file imports a package that may not be installed (e.g. `adbutils`, `frida`, `slither`, `libafl`), add an `importorskip` guard at the very top of the file, before any other imports:

```python
adbutils = pytest.importorskip("adbutils")
```

This produces a clean skip rather than a collection error. **Never** let an `ImportError` reach pytest collection.

### `__main__` Guard and `sys.exit`

Standalone scripts that are also imported by tests must protect top-level execution:

```python
if __name__ == "__main__":
    main()
```

**Never** call `sys.exit()` at module level. It terminates the pytest process during collection.

### Collection Health

Before every PR, verify zero collection errors:

```bash
python3 -m pytest tests/ --collect-only -q
```

The output must show 0 errors. Skips for missing optional deps are expected and acceptable.

---

## Elite Security Engineering Standards

### Council Audit Loop (Audit -> Integrate -> Validate)

Every change runs through a repeatable council loop:

1. **Audit:** review code paths, integrations, and tool wrappers for gaps or drift.
2. **Integrate:** wire fixes into normal, deep, or god-mode pipelines and store all findings in the database.
3. **Validate:** verify UI + CLI behavior, then run targeted regression checks.

Operational rules:

- Use `scripts/audit_cycle.sh` to drive rounds and keep outputs fresh.
- Place audit artifacts under `logs/audit_cycle/` and wipe them before each round.
- Any tool dependency must be captured in install scripts (native + hybrid stack).
- Findings must be normalized and stored so attack chains can be built.

### Test-First Development (Mandatory)

**Before writing ANY production code, write the test first.**

1. Write `tests/test_feature.py` first
2. Run test (should fail — code doesn't exist yet)
3. Write production code
4. Run test (should pass)

Every scanner MUST have: positive test, negative test (no false positives), edge cases (timeouts/WAF), performance test (< 30s).

```python
# tests/test_xxe_scanner.py
def test_xxe_detection_on_vulnerable_endpoint():
    scanner = XXEScanner()
    results = scanner.scan("http://testphp.vulnweb.com/xml.php")
    assert len(results) > 0
    assert results[0]['vuln_type'] == 'xxe'
    assert '/etc/passwd' in results[0]['evidence']

def test_xxe_no_false_positive_on_safe_endpoint():
    scanner = XXEScanner()
    results = scanner.scan("https://google.com")
    assert len(results) == 0
```

---

### Security Finding Validation (Critical)

Every finding MUST include:
1. **PoC:** Exact payload that triggers vulnerability
2. **Evidence:** Response showing vulnerability
3. **Reproduction:** Step-by-step curl/commands
4. **Impact:** What attacker can do
5. **Confidence Score:** 0.0-1.0

```python
finding = {
    'vuln_type': 'xss',
    'url': 'https://target.com/search?q=...',
    'payload': '<script>alert(1)</script>',
    'param': 'q',
    'evidence': '... <script>alert(1)</script> in response body ...',
    'reproduction_cmd': 'curl "https://target.com/search?q=%3Cscript%3E..."',
    'confidence': 0.95,
    'impact': 'Stored XSS - session hijacking possible',
}
```

**Do NOT report if:** payload HTML-encoded, WAF blocked (403/406), timeout without confirmation, generic error.
**DO report if:** payload executed, sensitive data leaked, privilege escalation confirmed, command execution proven.

**Confidence scoring:**
```
1.0 - Exploit confirmed (RCE shell obtained)
0.9 - High confidence (payload executed, clear evidence)
0.8 - Strong indication (error messages reveal vulnerability)
0.7 - Likely vulnerable (suspicious behavior, needs manual check)
<0.7 - Informational only (not reportable)
```

**Minimum reportable confidence: 0.7**

---

### Performance & Detection Benchmarks

**Benchmark targets:** DVWA, WebGoat, testphp.vulnweb.com, OWASP Juice Shop, bWAPP

**Performance budgets:**
```python
PERFORMANCE_BUDGETS = {
    'unified_scan': {'time': 300, 'memory': 512*1024*1024, 'db_queries': 100},
    'mobile_static_analysis': {'time': 180, 'memory': 256*1024*1024},
    'graph_sync': {'time': 10, 'db_queries': 50},
}
```

**Detection rate targets:**
| Scanner | Target | Compare |
|---------|--------|---------|
| XSS | 90%+ | Match Burp Pro |
| SQLi | 85%+ | Match OWASP ZAP |
| XXE | 80%+ | Exceed baseline |
| SSRF | 85%+ | Match industry |

After modifying scanner: run against test suite, record in `benchmarks/scanner_performance.md`, regression check.

---

### Exploit Chain Verification

```python
finding = {
    'vuln_type': 'exploit_chain',
    'chain': [
        {'step': 1, 'vulnerability': 'IDOR', 'endpoint': '/api/users/{id}', 'payload': 'user_id=2', 'result': 'Retrieved victim email'},
        {'step': 2, 'vulnerability': 'Password reset token leak', 'endpoint': '/api/password-reset', 'result': 'Token in response'},
        {'step': 3, 'vulnerability': 'Account takeover', 'endpoint': '/api/password-reset/confirm', 'result': 'Password changed'},
    ],
    'impact': 'Full account takeover via IDOR → Password Reset',
    'automated_poc': 'python exploits/idor_to_account_takeover.py --target https://victim.com',
    'confidence': 1.0
}
```

Generate working exploit script in `exploits/` for every chain.

---

### CVE & Threat Intel Integration

```python
finding = {
    'vuln_type': 'spring4shell',
    'cve_id': 'CVE-2022-22965',
    'cvss': 9.8,
    'cwe_id': 'CWE-94',
    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
    'mitre_attack': {'tactic': 'TA0002', 'technique': 'T1059.007'},
}
```

Intel sources: NVD, Exploit-DB, MITRE ATT&CK, CISA KEV, GitHub security advisories.

---

### Responsible Disclosure Protocol

1. Confirm exploitability (run PoC 3x)
2. Assess severity (CVSS)
3. Check bug bounty scope
4. Timelines: Critical (9.0+) = 7 days, High (7.0-8.9) = 30 days, Medium (4.0-6.9) = 90 days

---

## Development Harness

### Architecture Decision Records (ADRs)

Location: `docs/adr/ADR-NNN.md`

```markdown
# ADR-NNN: [Title]
**Status:** Accepted/Rejected/Superseded
**Date:** YYYY-MM-DD
**Context:** [Why this decision needed]
**Decision:** [What was decided]
**Consequences:** [Benefits / Drawbacks]
**Alternatives:** [Why rejected]
```

Create ADR for: new scanner architecture, DB schema change, API design, performance trade-offs, third-party integrations.

---

### Feature Flags

```python
# src/oneinfinity/core/feature_flags.py
class FeatureFlags:
    @staticmethod
    def is_enabled(feature: str) -> bool:
        flags = {
            'advanced_xxe_detection': True,
            'graphql_introspection_v2': False,
            'llm_business_logic': False,
            'mobile_frida_automation': True,
            'neo4j_graph_sync': True,
        }
        return flags.get(feature, False)
```

Use for: new scanners, breaking API changes, performance-heavy features, experimental algorithms.

---

### Instrumentation & Observability

```python
import structlog
log = structlog.get_logger("oneinfinity.scan.xss")
log.info("xss_scan_start", target=target, param_count=len(params), scan_id=scan_id)
log.info("xss_scan_complete", duration_ms=duration*1000, findings_count=len(findings))
```

```python
from prometheus_client import Counter, Histogram
SCANS_TOTAL = Counter('oneinfinity_scans_total', 'Total scans', ['scanner', 'status'])
SCAN_DURATION = Histogram('oneinfinity_scan_duration_seconds', 'Scan duration', ['scanner'])
FINDINGS_TOTAL = Counter('oneinfinity_findings_total', 'Total findings', ['vuln_type', 'severity'])
```

---

### Database Migration Safety

Before any migration:
- [ ] Backward compatible (old code works with new schema)
- [ ] Forward compatible (new code works with old schema)
- [ ] Rollback plan documented
- [ ] Large table? Use batched updates
- [ ] Adds index? Create CONCURRENTLY
- [ ] Drops column? Two-phase (deprecate first, drop after old code removed)

```sql
-- SAFE: Adding column
ALTER TABLE findings ADD COLUMN risk_score INTEGER DEFAULT 0;

-- UNSAFE (breaks old code): DROP COLUMN in one step
-- SAFE: Two-phase migration
-- Phase 1: Stop writing to column in code (deploy)
-- Phase 2: ALTER TABLE findings DROP COLUMN old_field;
```

---

### Graceful Degradation

```python
from oneinfinity.core.circuit_breaker import CircuitBreaker

neo4j_breaker = CircuitBreaker(failure_threshold=5, timeout=60)

@neo4j_breaker
def sync_to_neo4j(data):
    neo4j_client.create_nodes(data)

def save_finding(finding):
    db.save(finding)  # Critical path — always runs
    try:
        sync_to_neo4j(finding)
    except CircuitBreakerOpen:
        log.warning("Neo4j unavailable, skipping graph sync")
```

---

### SLOs & Error Budgets

```python
SLOs = {
    'api_availability': 0.999,   # 99.9% uptime
    'scan_success_rate': 0.95,   # 95% succeed
    'api_p95_latency': 500,      # p95 < 500ms
    'false_positive_rate': 0.05, # < 5% FP
}
ERROR_BUDGET = {
    'api_availability': 43.2,    # minutes downtime/month
    'scan_failures': 5,          # % scans allowed to fail
}
```

---

## Implementation Protocol (Full Detail)

### Phase 1: Pre-Implementation Audit

Before ANY code:
1. `semantic_search_nodes("feature name")` via graph
2. `grep -r "feature" src/oneinfinity/`
3. Check `unified_scan_engine.py` for existing scanners
4. Check `web/backend/main.py` for existing endpoints
5. Review `INTEGRATION_AUDIT_REPORT.md`

Decision: EXISTS+WORKS → enhance | EXISTS+BROKEN → fix first | NOT EXISTS → build new

### Phase 2: Innovation Requirements

Your implementation MUST have at least 3 of:
- Automation (automate manual steps)
- Intelligence (ML/heuristics to cut false positives)
- Speed (10x faster)
- Coverage (edge cases others miss)
- Chain Detection (link vulns into attack chains)
- Proof Generation (working exploits auto-generated)
- Evasion (WAF/rate limit bypass)
- Context Awareness (application logic understanding)
- Visual Proof (screenshots/videos)

### Phase 3: Integration Validation

For every new feature, verify ALL 5 integration points:
1. `unified_scan_engine.py` calls the scanner
2. API endpoint exists in `web/backend/main.py`
3. UI can trigger it in `web/frontend/src/`
4. Findings saved to database
5. Test file exists in `tests/`

Missing any = STOP and add it.

### Phase 4: Post-Implementation Verification

1. Test CLI: `python cli_scan.py target.com`
2. Test API: `curl -X POST /api/scans`
3. Test UI in browser
4. Validate on real target: `python cli_scan.py http://testphp.vulnweb.com`
5. False positive check: `python cli_scan.py https://google.com` (expect 0 findings)
6. Performance: `time python cli_scan.py target.com` (expect < 5 min)
7. Regression: `python3 -m pytest tests/ -x`

### Phase 5: Documentation & Evidence

1. Count scanners: `grep -c "class.*Scanner" src/oneinfinity/scan/*.py`
2. Update scanner count in `docs/` if changed
3. Update `README.md`, `SCANNER_ARCHITECTURE.md`, `docs/SKILLS.md`

### The 5 Absolute Principles

1. **No assumptions** — grep before calling; verify file/function/table exists
2. **No missing pieces** — CLI + API + UI + DB + tests + docs, all updated
3. **No breakage** — full test suite passes; check all callers; verify backward compat
4. **Perfect integration** — scanner in unified engine; findings in DB; UI can trigger
5. **No hallucinations** — grep before claiming; run before saying "it works"; count before stating numbers

**Failure recovery:** Stop → announce violation → verify actual state → fix → re-audit → continue

### Pre-Completion Checks (Mandatory)

```bash
mypy src/oneinfinity/ || exit 1
ruff check src/ || exit 1
bandit -r src/ -ll || exit 1
python3 -m pytest tests/ --cov=src --cov-fail-under=80 || exit 1
```

### Production Readiness Checklist

- [ ] Feature flag added (if experimental)
- [ ] Metrics instrumented
- [ ] ADR created (if architectural change)
- [ ] Test coverage ≥ 80%
- [ ] Rollback plan exists
- [ ] Documentation updated
- [ ] Benchmark recorded (if scanner)
- [ ] Contract tests passing (if API change)
