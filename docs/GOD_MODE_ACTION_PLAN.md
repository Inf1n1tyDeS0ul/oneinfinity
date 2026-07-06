# God Mode Action Plan — Dead Code & Integration Gaps

> **Source**: Council-of-Councils audit, 6 specialist agents, 492 Python files analyzed.
> **Verdict**: 70% of the codebase (310 files) is never called during a god mode scan.
> Most of it is fully built, tested, and ready — just never wired in.

---

## How Bad Is It?

```
Total Python source files:       492
Called during god mode:          133   (27%)
Never called during god mode:    310   (63%)
Partially wired / misfiring:      49   (10%)

scan/:        90% dead
mobile/:      94% dead
web3/:       100% dead
arsenal/:     89% dead
recon/:       94% dead
ai_security/: 89% dead
tool_wrappers: 73% of run_* functions dead
```

The canonical pipeline calls roughly **14 phases → ~30 modules**.
Everything else is dead code from god mode's perspective.

---

## Immediate Fixes (1–10 lines each, no new code)

These activate fully-built capabilities that are just missing a call.

### Fix 1 — Bypass403Engine result never collected

**File**: `src/oneinfinity/orchestration/god_mode_engine.py` ~line 442

**Problem**: `Bypass403Engine` is instantiated and logged but `.scan()` is never called.
The engine runs, the findings are thrown away.

```python
# CURRENT (broken)
_bypass_engine = Bypass403Engine(waf_vendor=session.waf_vendor, ...)
log.info("[GOD MODE] Bypass403Engine ready for %s", session.waf_vendor)
# ^ instance immediately dropped, zero findings collected

# FIX — add two lines after instantiation
bypass_findings = _bypass_engine.scan(endpoints=discovered_endpoints)
session.add_findings(len(bypass_findings))
```

---

### Fix 2 — WAF bypass only generates sqli payloads

**File**: `src/oneinfinity/orchestration/god_mode_engine.py` ~line 383

**Problem**: `AdversarialWAFEngine` is constructed once with `vuln_type="sqli"`.
The five other vuln types (xss, ssrf, ssti, cmdi, lfi) never get bypass payloads generated.

```python
# CURRENT (broken)
adv_engine = AdversarialWAFEngine(vuln_type="sqli", ...)
bypass_payloads = adv_engine.generate_all_types(...)

# FIX — loop over all vuln types
bypass_payloads = {}
for vtype in ["sqli", "xss", "ssrf", "ssti", "cmdi", "lfi"]:
    engine = AdversarialWAFEngine(vuln_type=vtype, waf_vendor=session.waf_vendor)
    bypass_payloads[vtype] = engine.generate_all_types(
        endpoint="/", vuln_types=[vtype]
    )
session.waf_bypass_payloads = bypass_payloads
```

---

### Fix 3 — CORS and JWT agents never run in pipeline mode

**File**: `src/oneinfinity/pipeline/canonical.py` ~line 127

**Problem**: The `active_testing` phase passes `--agents` to the swarm CLI.
`cors` and `jwt` are absent from that list. Both agents are fully implemented.
They only fire if SwarmMission runs (Stage 3), which requires hitting the endpoint threshold.

```python
# CURRENT (broken)
cli_extra_args=["--agents", "sqli", "xss", "ssrf", "idor",
                "auth", "api", "deserialization", "race_condition",
                "file_upload", "oauth", "prototype_pollution", "clickjacking"]

# FIX — add cors and jwt
cli_extra_args=["--agents", "sqli", "xss", "ssrf", "idor",
                "auth", "cors", "jwt", "api", "deserialization",
                "race_condition", "file_upload", "oauth",
                "prototype_pollution", "clickjacking"]
```

---

### Fix 4 — ResearchMission discards auth context

**File**: `src/oneinfinity/orchestration/research_mode_controller.py`

**Problem**: `auth_config` is stored in `ResearchModeController.__init__` but never
forwarded to `AdaptiveReconEngine`, `ApplicationIntelligenceEngine`, or any sub-engine.
Research iterations run unauthenticated even when credentials exist.

```python
# CURRENT (broken) — auth_config stored but not passed down
engine = AdaptiveReconEngine(target=self.target)

# FIX — forward auth context
engine = AdaptiveReconEngine(
    target=self.target,
    auth_context=self.auth_config if self.auth_config else None,
)
```

---

### Fix 5 — XSSStrike and Commix never run (wrong key names)

**File**: `src/oneinfinity/scan/unified_scan_engine.py` — `_AGENT_TO_TOOL` dict

**Problem**: The decision engine emits `"xss_agent"` and `"cmdi_agent"` as agent types.
`_AGENT_TO_TOOL` maps `"xssstrike": "xssstrike"` — an identity entry that only matches
if the DE literally returns the string `"xssstrike"`, which it never does.
XSSStrike and Commix are installed but never dispatched.

```python
# CURRENT (broken)
_AGENT_TO_TOOL = {
    "xssstrike": "xssstrike",   # ← DE never emits this key
    "commix":    "commix",      # ← DE never emits this key
    ...
}

# FIX
_AGENT_TO_TOOL = {
    "xss_agent":  "xssstrike",
    "cmdi_agent": "commix",
    ...
}
```

---

### Fix 6 — Race condition silently skipped in unified pipeline

**File**: `src/oneinfinity/scan/unified_scan_engine.py` ~line 1319

**Problem**: The extended OWASP test loop enumerates 7 test functions explicitly.
`run_race_condition_test` is implemented and used in `pipeline/executor.py` but
is not in this list. Race condition coverage is silently absent from the main pipeline.

```python
# FIX — add to _ext_tests list
_ext_tests = [
    run_cors_check,
    run_jwt_test,
    run_deserialization_test,
    run_race_condition_test,    # ← add this line
    run_oauth_test,
    run_prototype_pollution_test,
    run_clickjacking_test,
]
```

---

## Short-Term Work (days, new wiring required)

### Wire `unified_advanced_scanner.py` as a new pipeline phase

**This is the single biggest gain.** One orphaned orchestrator holds 18 specialist scanners,
none of which are reachable from god mode today.

Scanners that activate immediately:
- NoSQL injection (MongoDB, CouchDB, Redis)
- SSTI (Jinja2, Twig, Mako, Freemarker)
- LDAP injection
- SAML authentication flaws
- Prototype pollution (deep scan)
- gRPC endpoint attacks
- Path traversal / LFI
- XXE injection
- Subdomain takeover
- HTTP Parameter Pollution
- Client-side attacks (DOM clobbering, postMessage)
- OAuth token leakage in logs/URLs
- PDF SSRF via file upload
- Redis injection via SSRF pivot
- Cache poisoning / Web Cache Deception
- DNS rebinding
- Unicode normalization attacks
- LLM business logic analysis

**What to do:**

1. Add a phase to `canonical.py`:
```python
PhaseConfig(
    name="advanced_scan",
    display_name="Advanced Specialist Scan",
    description="18 specialist scanners: NoSQL, SSTI, XXE, path traversal, cache poisoning, DNS rebinding...",
    cli_command="_internal_advanced_scan",
    mandatory=False,
    timeout_s=3600,
    pct_complete=72,
    waf_adapt=True,
    source_type="tool",
    skip_on_waf_passive=False,
)
```

2. Add `_inline_advanced_scan()` in `pipeline/executor.py`:
```python
def _inline_advanced_scan(self, target, out, waf, ...):
    from oneinfinity.scan.unified_advanced_scanner import UnifiedAdvancedScanner
    scanner = UnifiedAdvancedScanner(target=target, waf_vendor=waf)
    return scanner.run_full_scan()
```

---

### Wire GitHub OSINT into FoundationMission

**Files**: `src/oneinfinity/recon/github_*.py` (all 7, none called)

Activating these in `FoundationMission` Step 2 provides:
- Exposed API keys, credentials, secrets committed to GitHub
- Internal architecture leaks (DB schemas, infra configs)
- Employee names → password spray target list for the auth phase
- Tech stack confirmation for payload selection

```python
# In FoundationMission._run(), after Step 2 (AppIntelligenceEngine)
from oneinfinity.recon.github_secrets_scanner import GitHubSecretsScanner
from oneinfinity.recon.github_deep_intel import GitHubDeepIntel

gh_intel = GitHubDeepIntel(target=session.target)
gh_results = gh_intel.run()
session.add_findings(len(gh_results.secrets))

gh_scanner = GitHubSecretsScanner(org=session.target)
exposed = gh_scanner.scan()
session.add_findings(len(exposed))
```

---

### Fix run_garak and run_pyrit stubs

**File**: `src/oneinfinity/scan/tool_wrappers.py` lines 1469–1473

**Problem**: Both functions return `ToolResult(success=True)` with no data.
They are called for `ai` target type in unified_scan_engine but silently produce
zero findings. The entire AI target scan path is a no-op.

```python
# CURRENT (broken)
def run_garak(target, **kwargs):
    return ToolResult(success=True, data={})   # ← stub

# FIX — call the actual Garak binary (already installed)
def run_garak(target, **kwargs):
    import subprocess, json
    result = subprocess.run(
        ["garak", "--model_type", "rest", "--model_name", target,
         "--probes", "all", "--report_prefix", "/tmp/garak_out"],
        capture_output=True, text=True, timeout=300
    )
    findings = _parse_garak_report("/tmp/garak_out.report.jsonl")
    return ToolResult(success=result.returncode == 0, data={"findings": findings})
```

---

## Medium-Term Work (weeks, new capabilities)

### AI Red Team Mission for AI-Powered Targets

When god mode detects an AI chatbot, LLM API, or RAG system as the target,
spin up a dedicated `AIRedTeamMission`:

| Component | File | What it adds |
|-----------|------|-------------|
| Multi-turn chainer | `ai_security/multi_turn_chainer.py` | 7-strategy jailbreak escalation |
| RAG poisoning | `ai_security/rag_poisoning_engine.py` | Retrieval injection, knowledge-base poisoning |
| Agent hijacking | `ai/agent_hijack_harness.py` | SSRF/file-exfil via AI tool calls |
| Model extraction | `ai/model_extraction_engine.py` | System prompt leakage, architecture fingerprinting |
| LLM DoS | `ai_security/llm_dos_engine.py` | Token flooding, infinite loop injection |
| Supply chain | `ai_security/llm_supply_chain_scanner.py` | Plugin hijacking, provenance disclosure |

These modules are fully implemented. None have any callers.

```python
# In GodModeConductor._maybe_unlock_missions()
if session.target_type in ("ai_agent", "llm_api", "chatbot"):
    self._unlock_mission("ai_redteam")
```

---

### Zero-Day Hypothesis Phase

**File**: `src/oneinfinity/intelligence/zero_day_hypothesis.py` (no callers in god mode)

Add a `ZeroHypothesisMission` that runs after `FullScanMission` completes.
It takes the application model built during recon (tech stack, endpoint patterns, auth flows)
and uses LLM reasoning to generate hypotheses for novel vulnerability combinations
not in any CVE database.

Example output: *"Target uses JWT RS256 + GraphQL variables + a legacy XML renderer.
The combination creates a SSRF-via-XXE-via-GraphQL-variable injection path.
Confidence: HIGH. No existing nuclei template covers this chain."*

---

### Semantic Differential Auth Scanner

**File**: `src/oneinfinity/scan/differential_scanner.py` (no callers)

Add to the `exploit_validation` phase. For every confirmed finding, replay the
request with different auth states and use LLM semantic comparison on the responses.

Traditional scanners compare HTTP status codes and body lengths.
This catches authorization leakage when the status is `200` in both cases but the
response bodies contain different data — something no regex can detect.

---

### Adaptive Payload Evolution Against Live WAF

**File**: `src/oneinfinity/ai_security/adversarial_prompt_evolution.py`

Currently excluded from the pipeline. Wire it as the payload supplier for the
`active_testing` phase when WAF bypass mode is active:

1. Active testing fires a probe → WAF blocks it (429 / 403)
2. Evolution engine receives the blocked payload + WAF response
3. LLM mutates the payload using genetic algorithm over 10 generations
4. Re-probe with evolved payload
5. Repeat until blocked or finding confirmed

This replaces the static bypass payload list with a live, adaptive loop.

---

## Low Priority / Background Cleanup

### Remove or Implement — These are Dead Infrastructure

| Component | Recommendation |
|-----------|---------------|
| `frida_scripts/*.js` (5 files) | **Delete** — exact duplicates of inline Python constants in `mobile/dynamic_analysis.py`. No code loads them from disk. |
| `go_oob_bridge.py` | **Implement or delete** — zero call-sites anywhere. Either wire it to replace OOBEngine or remove it. |
| `go_target_disc_bridge.py` | **Delete** — zero call-sites even outside god mode. Binary unclear. |
| `run_smuggling_python` in TOOL_REGISTRY | **Remove registry entry** — `SmugglingEngine` supersedes it. Two parallel implementations; the wrapper never fires. |
| `httpx`, `subfinder`, `kxss` dispatch branches in `_run_tool_safe` | **Delete dead branches** — never added to plan by any rule; unreachable code. |

### tool_wrappers.py — 43 Dead `run_*` Functions

God mode bypasses them entirely by calling CLI subprocesses directly.
The Python wrapper layer is completely unused.

**Options:**
1. **Keep as library API** — document clearly that these are a public API for external callers, not internal pipeline calls. Add `# Not called by god mode — public API only` docstring.
2. **Delete all 43** — reduces 108KB file to ~30KB. Callers: zero in `src/`. Risk: low.
3. **Wire 6 high-value ones** — `run_nuclei`, `run_sqlmap`, `run_dalfox`, `run_nmap`, `run_nikto`, `run_ffuf` through `_run_tool_safe` to give richer structured output vs raw CLI stdout.

---

## Priority Order

```
Week 1 — Apply the 6 immediate fixes (no new code, 1–10 lines each)
  ✓ Fix Bypass403Engine scan() call
  ✓ Fix AdversarialWAFEngine vuln type loop
  ✓ Add cors + jwt to active_testing agents list
  ✓ Fix ResearchModeController auth forwarding
  ✓ Fix _AGENT_TO_TOOL key names for xssstrike + commix
  ✓ Add run_race_condition_test to _ext_tests

Week 2 — Wire unified_advanced_scanner (18 scanners, one integration point)
  ✓ Add advanced_scan phase to canonical.py
  ✓ Add _inline_advanced_scan() to executor.py
  ✓ Test on staging target

Week 3 — GitHub OSINT + fix garak/pyrit stubs
  ✓ Wire FoundationMission Step 2 → github_secrets_scanner + github_deep_intel
  ✓ Implement run_garak() and run_pyrit() properly

Week 4+ — AI Red Team Mission
  ✓ AIRedTeamMission class in god_mode_engine.py
  ✓ Wire multi_turn_chainer, rag_poisoning_engine, agent_hijack_harness
  ✓ Trigger condition: ai_agent / llm_api target type detected

Month 2 — Zero-day hypothesis + differential scanner + payload evolution
```

---

## Vulnerability Classes Currently Missing from God Mode

These vulnerability classes have **no coverage** in the canonical pipeline.
Each has a scanner in `src/` that is never called:

| Vulnerability Class | Scanner File | OWASP / Impact |
|--------------------|-------------|----------------|
| SSTI | `scan/ssti_scanner.py` | Critical — RCE on template engines |
| NoSQL Injection | `scan/nosql_injection_scanner.py` | High — auth bypass on MongoDB targets |
| XXE | `scan/xxe_scanner.py` | High — SSRF + file read via XML |
| Path Traversal / LFI | `scan/path_traversal_scanner.py` | High — file read, source disclosure |
| Host Header Injection | `scan/host_header_scanner.py` | Medium/High — password reset poisoning |
| Web Cache Deception | `scan/cache_deception_scanner.py` | High — cached sensitive pages |
| DNS Rebinding | `scan/dns_rebinding_scanner.py` | High — SSRF pivot via DNS |
| Subdomain Takeover | `scan/subdomain_takeover_scanner.py` | High — account takeover via DNS |
| HTTP Smuggling (deep) | `scan/h2c_scanner.py` | Critical — request smuggling via H2C |
| Mass Assignment | `scan/mass_assignment_scanner.py` | High — privilege escalation via API |
| WebSocket Security | `scan/websocket_scanner.py` | Medium — auth bypass, injection |
| Supply Chain (JS) | `scan/supply_chain_attack_engine.py` | High — typosquatting, dependency hijack |
| CI/CD Attacks | `scan/cicd_vuln_scanner.py` | Critical — pipeline RCE |
| Container Escape | `scan/container_escape_scanner.py` | Critical — host breakout |
| Blind XSS (stored) | `scan/blind_xss_engine.py` | High — stored XSS with OOB callbacks |
| Multi-turn LLM attacks | `ai_security/multi_turn_chainer.py` | Critical for AI targets |
| RAG poisoning | `ai_security/rag_poisoning_engine.py` | Critical for AI targets |
| Agent hijacking | `ai/agent_hijack_harness.py` | Critical for AI targets |
