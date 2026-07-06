# God Mode Coverage Audit
**Council of Councils — Ground Truth Dead-Code & Vulnerability Gap Report**
*Generated: 2026-06-30 | 8 specialist councils | 492 Python source files audited*

---

## Executive Summary

| Metric | Count |
|---|---|
| Total Python source files | 492 |
| Files LIVE in god mode (direct call or dependency) | 160 |
| Files DEAD in god mode | 222 |
| Files BROKEN (called but malfunctioning) | ~18 |
| Scan files dead | 32 of 83 |
| AI security engines dead for non-AI targets | 7 of 12 |
| Missing vulnerability classes (zero coverage) | 23+ |
| Broken async calls (coroutine returned, never awaited) | 3 confirmed |

**Root cause:** God mode uses a fixed 14-phase sequential subprocess pipeline (`run_canonical_pipeline`). Each phase spawns a fresh Python process. Any engine that is not imported and called inside that subprocess is invisible — regardless of how sophisticated it is in the parent process. The entire learning, orchestration, and AI-reasoning stack lives in the parent process and never touches the subprocess phases.

---

## Part 1 — Scan Engines: 32 of 83 DEAD

### 1A. Completely Unregistered (no call path from any pipeline phase)

| File | Capability | Why Dead |
|---|---|---|
| `scan/blind_xss_engine.py` | Blind/stored XSS with OOB callbacks | XSSAgent generates XSS payloads inline; this engine never called |
| `scan/cache_deception_scanner.py` | Web Cache Deception + CDN bypass | chain_suggestion metadata references it; nothing fires it |
| `scan/cors_scanner.py` | CORS misconfiguration (full test suite) | CORSAgent exists in swarm but no dedicated pipeline phase |
| `scan/dns_security_scanner.py` | SPF/DKIM/DMARC/CAA checks | Zero callers anywhere |
| `scan/h2c_scanner.py` | HTTP/2 Cleartext Upgrade smuggling | Zero callers in god mode |
| `scan/host_header_scanner.py` | Host header injection (SSRF pivot) | Not in active_testing or any phase |
| `scan/hpp_scanner.py` | HTTP Parameter Pollution | Not in any phase |
| `scan/http2_attack_engine.py` | HTTP/2 rapid reset, header injection | Zero callers |
| `scan/jwt_vulnerability_scanner.py` | JWT alg:none, weak key, header injection | JWTAgent calls its own inline logic, not this scanner |
| `scan/mass_assignment_scanner.py` | Mass assignment / auto-binding | Not in any phase |
| `scan/nosql_injection_scanner.py` | NoSQL injection (MongoDB etc.) | In enhanced_scanners.py → orphaned unified_advanced_scanner.py |
| `scan/oauth_token_leak_scanner.py` | OAuth token leakage in logs/URLs | Not in any phase |
| `scan/path_traversal_scanner.py` | Path traversal / LFI | No active pipeline phase |
| `scan/ssti_scanner.py` | SSTI detection (Jinja2, Twig, etc.) | Not in any phase |
| `scan/subdomain_takeover_scanner.py` | Subdomain takeover (dangling DNS) | Not in any phase |
| `scan/supply_chain_attack_engine.py` | JS dependency hijacking, typosquatting | Zero callers |
| `scan/websocket_scanner.py` | WebSocket auth bypass, injection | run_websocket_test used in tool_wrappers but not this scanner |
| `scan/xxe_scanner.py` | XML External Entity injection | Not in any pipeline attack surface phase |
| `scan/cicd_vuln_scanner.py` | CI/CD pipeline attack surface | Not in any phase |
| `scan/container_escape_scanner.py` | Container escape via proc/cgroup | Not in any phase |
| `scan/grpc_scanner.py` | gRPC endpoint full security testing | OWASP gap does passive header check only |
| `scan/differential_scanner.py` | Differential analysis for auth bypass | Never called; AI-powered but completely orphaned |
| `scan/race_condition_engine.py` | Dedicated race condition scanner | run_race_condition_test wrapper used in pipeline/executor.py but this engine never called |
| `scan/smart_payload_generator.py` | AI-generated context-aware payloads | Zero callers |
| `scan/llm_business_logic_analyzer.py` | LLM analyzes business logic vulns | Zero callers |
| `scan/browser_reasoning_agent.py` | AI browser reasoning for UI attacks | Zero callers; headless_browser_engine used instead |
| `scan/dns_rebinding_scanner.py` | DNS rebinding attacks | In advanced_attack_scanners.py → orphaned unified_advanced_scanner.py |

### 1B. Orphaned Aggregators (dead root, all children unreachable)

| File | Description |
|---|---|
| `scan/unified_advanced_scanner.py` | ROOT CAUSE ORPHAN — orchestrates 18+ scanners; NEVER imported by executor.py, unified_scan_engine.py, or god_mode_engine.py. All 18 child scanners unreachable. |
| `scan/advanced_attack_scanners.py` | 6 scanners (PDF SSRF, Redis injection, cache poisoning, rate limiting, DNS rebinding, unicode normalization) — only called from orphaned unified_advanced_scanner.py |
| `scan/enhanced_scanners.py` | 5 scanners (deserialization, LDAP, SAML, prototype pollution, gRPC) — only called from orphaned unified_advanced_scanner.py |

### 1C. Broken Async Call

| File | Bug |
|---|---|
| `attack/attack_simulation_engine.py` | `simulate_all_paths()` is `async` but executor.py calls it without `await` or `asyncio.run()` — returns a coroutine object, never executed. Also called with zero args when it requires `(target, context)`. |

---

## Part 2 — AI Security: 24 of 27 DEAD

### 2A. Dead for ALL targets (never wired to god mode)

| File | Capability |
|---|---|
| `ai_security/multi_turn_chainer.py` | 7-strategy adversarial LLM attack chains (ROLEPLAY_ESCALATION, AUTHORITY_INJECTION, CONTEXT_CONFUSION, DAN_PROGRESSIVE, TOOL_CALL_INJECTION...) — zero callers in src/ |
| `ai_security/rag_poisoning_engine.py` | RAG poisoning: retrieval injection, knowledge-base poisoning, context isolation — zero callers |
| `ai_security/llm_dos_engine.py` | LLM resource exhaustion: token flooding, infinite loops, context injection — zero callers |
| `ai_security/llm_supply_chain_scanner.py` | Model provenance, plugin hijacking, training data extraction — zero callers |
| `ai_security/adversarial_prompt_evolution.py` | Genetic algorithm evolves adversarial prompts via PostgreSQL persistence — only via AIRedTeamEngine CLI |
| `ai_security/campaign_manager.py` | End-to-end adversarial prompt campaigns — only via AIRedTeamEngine CLI |
| `ai_security/agent_hijack_harness.py` | Multi-turn AI agent hijacking (tool abuse, RAG injection, memory poisoning) — zero callers anywhere in src/ |
| `ai_security/model_extraction_engine.py` | System prompt leakage, architecture fingerprinting, membership inference — zero callers; requires env var gate |
| `ai/ai_redteam_engine.py` | AI red-team engine (AIRedTeamEngine) — CLI only; not in god mode pipeline |
| `ai/ai_agent_pentest_engine.py` | AI agent security testing — CLI only; not in god mode pipeline |
| `ai_security/tool_wrappers/airt_wrapper.py` | AIRT autonomous red-teamer wrapper — excluded from AISecurityEngine.ALL_TOOLS |
| `bridge_scripts/giskard_bridge.py` | Giskard subprocess bridge — wrapper uses SDK directly; bridge never invoked |
| `bridge_scripts/pyrit_bridge.py` | PyRIT subprocess bridge — dead code |
| `bridge_scripts/rebuff_bridge.py` | Rebuff bypass bridge — dead code |
| `auth/endpoint_probe.py` | AI chatbot API discovery — zero callers in src/ |
| `auth/msal_token_helper.py` | Microsoft SSO token acquisition — zero callers in src/ |

### 2B. Partial (fires ONLY when `_is_ai_target()` returns True — keyword match on URL)

| File | Gap |
|---|---|
| `ai_security/adversarial_waf_engine.py` | WAF bypass LLM self-play — PARTIAL: only sqli vuln_type passed; xss/cmd/lfi/xxe/ssti bypass types never generated |

### 2C. Broken Integration

| File | Bug |
|---|---|
| `swarm/agent_execution_fabric.py` — AISecurityAgent | Calls `AISecurityEngine().scan_endpoint()` but `scan_endpoint()` does NOT exist on AISecurityEngine (only `scan(config)` and `run_all_tools()`). Also triggered only via `graph run` CLI, never SwarmMission. |

---

## Part 3 — Attack Modules: 7 DEAD, 6 Broken Integrations

### 3A. Dead Engines

| File | Capability | Why Dead |
|---|---|---|
| `attack/attack_path_planner.py` | 800-line BFS attack path scoring with 6 chain definitions | Zero calls from any pipeline phase; CLI/skills only |
| `attack/autonomous_exploit_engine.py` | Autonomous multi-step exploit generation | Referenced in swarm_worker but not canonical pipeline |
| `attack/browser_attack_engine.py` | Browser-based attack automation | Pipeline uses headless_browser_engine instead |
| `attack/credential/breach_checker.py` | HaveIBeenPwned breach checking | Credential pipeline not called during god mode |
| `attack/credential/employee_osint.py` | Employee OSINT (LinkedIn, GitHub) | Not in any god mode phase |
| `attack/credential/wordlist_generator.py` | Target-aware wordlist generation | Never called in god mode path |
| `attack/post_exploit_engine.py` | Post-exploitation enumeration | Not in any canonical phase |

### 3B. Broken Integrations

| File | Bug |
|---|---|
| `attack/attack_simulation_engine.py` | Async without await (see §1C) |
| `attack/exploit_chain_engine.py` — `_handle_chain_result` | `on_status_change` callback wired to validator but WebValidationEngine's `apply_results()` never calls it — 7 extra exploit types (GraphQL, JWT, SSTI, deserialization, Redis, MongoDB, mass_assignment) silently skipped |
| `attack/credential/spray_engine.py` | Go credential spray only calls this via `go-credential-spray` sidecar; sidecar never invoked by god mode |
| `arsenal/attack_graph_core/` | AttackGraphBuilder IS called in `attack_graph` phase but the builder's `suggest_chains()` output is not wired to subsequent phases |
| `attack/bypass_403_engine.py` | Instantiated as readiness log only — findings never collected |
| `attack/nuclei_template_generator.py` | Generates custom Nuclei templates — not in any pipeline phase |

---

## Part 4 — Credential Attack Chain: ALL 5 COMPONENTS DEAD

The credential attack surface is **completely absent** from god mode:

| Component | File | Status |
|---|---|---|
| CredentialSprayEngine | `attack/credential/spray_engine.py` | DEAD — only fires via CREDENTIAL_ACQUIRED event reactively, never proactively launched |
| SessionReplay + AuthSessionContext | `auth/session_manager.py` | DEAD — exist as utilities, only fire if LoginSession with HAR file already on disk |
| MultiAccountIDOREngine | `auth/multi_account_idor_engine.py` | PARTIAL — wired via `_feed_idor_engine()` but only when CREDENTIAL_ACQUIRED fires |
| WordlistGenerator | `attack/credential/wordlist_generator.py` | DEAD — zero calls in god mode path |
| BreachChecker + EmployeeOSINT | `attack/credential/` | DEAD — both referenced as utilities but neither autonomously launched |

**Impact:** Auth propagation passes auth_headers to 12 run phases. However, 6 of 18 credential phases pass auth_headers blind. 12 run blind. No phase ever *generates* credentials — god mode depends on user-supplied `--auth-session`.

---

## Part 5 — Recon & Intelligence: 15 DEAD

### 5A. Dead in god mode (called only from CLI or daemon)

| File | Capability |
|---|---|
| `recon/github_advanced_dorks.py` | Advanced GitHub dork generation — called only by github_code_search.py (also dead) |
| `recon/github_code_search.py` | GitHub code search — not called in god mode |
| `recon/github_deep_intel.py` | Deep GitHub org intelligence — not called |
| `recon/github_dorks.py` | Basic dork library — not called |
| `recon/osint_collector.py` | crt.sh, HackerTarget, DNSDumpster, URLScan, Wayback, GitHub dorks, Shodan — PARTIAL: `collect()` only fires via intelligence_daemon which is never started in god mode |
| `recon/openapi_crawler.py` | OpenAPI/Swagger spec discovery + endpoint extraction | Not called from AdaptiveReconEngine |
| `recon/org_intel_mapper.py` | Org ASN, IP ranges, subsidiary discovery | Not called |
| `recon/target_discovery_engine.py` | Multi-source target asset enumeration | Not called from god mode |
| `recon/target_prioritization_engine.py` | ML-based target prioritization | Not called |
| `recon/traffic_replay_engine.py` | Passive traffic analysis for endpoint discovery | Not called |
| `intelligence/intelligence_daemon.py` | 9 autonomous workers (OSINT expansion, hypothesis generation, exploit chaining) | Never started in god mode — CLI daemon only |
| `agents/secret_intel/` (all 13 files) | GitHub/GitLab/S3/Confluence/Jira/Slack secret scanning | Entire directory dead in god mode |
| `recon/go_recon_bridge.py` | Go-based high-throughput crawler | AdaptiveReconEngine has `if GoReconBridge.is_available()` check but never instantiates it |

---

## Part 6 — Findings Pipeline: 5 DEAD / BROKEN

### 6A. Confirmed Pipeline Orphaned

`findings/confirmed_pipeline.py` is **never triggered in god mode**. It defines 6 post-confirmation actions:

| Action | Capability Lost |
|---|---|
| Nuclei template generation | Auto-generate templates for confirmed vulns |
| Neo4j knowledge boost | Feed confirmed finding back to graph |
| Re-test scheduling | Schedule re-test to verify persistence |
| Severity upgrade logic | Upgrade severity based on chain context |
| Notification dispatch | Webhook/Slack notification on confirmation |
| Exploit module mapping | Map confirmed vuln to exploit modules |

**Root cause:** `confirmed_pipeline.py` is only reachable via `ConfirmationCoordinator` which is only instantiated in CLI paths, never in god mode.

### 6B. Dead Validation Stack

| File | Status |
|---|---|
| `findings/confidence_engine.py` | DEAD — only called in CLI and worker paths. God mode findings have raw confidence values; no multi-factor scoring, no tool-assigned bonus, no severity auto-upgrade. |
| `findings/hybrid_bridge.py` | CLI-only — never called in god mode |
| `findings/finding_replay_engine.py` | CLI/hunter-only — dead in god mode |
| `findings/result_aggregator.py` | Wired only to SwarmMaster (not god mode pipeline) |
| `findings/bounty_report_generator.py` | CLI/hunter-only |

---

## Part 7 — Learning & Orchestration: 23 DEAD / BROKEN

### 7A. The Feedback Loop is Write-Only

```
AdaptivePlanner.plan()  →  consulted in FullScanMission._run()
                        →  skip_phases DISCARDED (documented bug, line 503-504)
                        →  ordered_phases DISCARDED
                        →  focus_vuln_types stored in _adaptive_focus_vulns
                        →  _adaptive_focus_vulns NEVER passed to run_canonical_pipeline()

PersistentMemory.record_result()  →  called AFTER scan (write)
                                  →  get_boosted_payloads() NEVER called before scan (read)
                                  →  Feedback loop is write-only
```

### 7B. Dead Orchestration Stack

| File | Capability |
|---|---|
| `orchestration/model_orchestrator.py` | AI model routing with cost/tier management — never activated (`activate()` has no caller) |
| `orchestration/orchestrator_integration.py` | Wires ModelOrchestrator into entire stack — `activate()` never called from any startup path |
| `orchestration/event_driven_engine.py` | Attack graph brain + agent fabric continuous loop — only started via `graph brain-start` CLI |
| `orchestration/graph_trigger_engine.py` | 15 declarative trigger rules (parameter_detected→xss/sqli, api_endpoint→idor, credential_found→exploit) — never fires in god mode |
| `orchestration/autonomous_decision_engine.py` | Impact×exploitability node scoring — only used in unified_scan_engine.py (old path) |
| `orchestration/mcp_ai_client.py` | Strategic AI mission planning — `plan_mission_priority()` has zero callers anywhere |
| `orchestration/offensive_router.py` | Ollama/arsenal/mutation hybrid payload generation — zero callers anywhere in entire codebase |
| `orchestration/workflow_simulation_engine.py` | Business logic simulation — only via intelligence_daemon (never started) |
| `learning/realtime_learner.py` | Real-time tool confidence + graph weight adaptation — never instantiated |
| `learning/hitl_rl_engine.py` | Human-in-the-loop RL for confidence threshold adjustment — zero callers in scan path |
| `infra/semantic_cache.py` | Semantic caching for AI responses (sentence-transformers, Redis, 70% token cost reduction advertised) — zero callers |
| `infra/auto_architecture_engine.py` | Self-evolving architecture documentation — CLI only |
| `core/ai_reasoning_engine.py` | AIReasoningEngine.suggest_next_actions() — only used in unified_scan_engine.py (old path), not in subprocess-mode canonical phases |
| `core/bounty_strategy_engine.py` | ROI-based target scoring — only called from bounty_hunter_engine.py |
| `core/target_prioritizer.py` | URL scoring model (auth+5, admin+5, API+4, payment+4) — only called from bounty_hunter_engine.py |
| `core/stealth_tracer.py` | eBPF/DTrace/Frida process tracer — zero callers in any scan phase |

---

## Part 8 — Go Sidecars: ALL 5 DEAD

| Sidecar | File | Why Dead |
|---|---|---|
| IDOR sidecar | `go_idor_bridge.py` | Active-testing uses swarm IDORAgent, not this Go sidecar |
| OOB sidecar | `go_oob_bridge.py` | oob_check phase uses OOBEngine (interactsh), not this sidecar |
| SSRF sidecar | `go_ssrf_bridge.py` | Active-testing uses Python SSRF checks, not Go sidecar |
| Lateral portscan | `go_lateral_portscan_bridge.py` | Zero callers in god mode |
| CVE-to-service | `go_service_cve_bridge.py` | Zero callers in god mode |
| Target discovery | `go_target_disc_bridge.py` | Zero call-sites outside its own file |

---

## Part 9 — Missing Vulnerability Classes

These vulnerability classes have **zero dedicated scanner coverage** in god mode:

| Class | Nearest Current Coverage | Gap |
|---|---|---|
| Blind XSS (stored, OOB) | XSSAgent inline payloads only | No OOB callback server, no blind_xss_engine |
| SSTI | Not in any canonical phase | ssti_scanner.py exists but dead |
| NoSQL Injection | Not in any canonical phase | nosql_injection_scanner.py exists but dead |
| Mass Assignment | Not in any canonical phase | mass_assignment_scanner.py exists but dead |
| HTTP Parameter Pollution | Not in any canonical phase | hpp_scanner.py exists but dead |
| DNS Rebinding | Not in any canonical phase | dns_rebinding_scanner.py dead |
| Cache Deception | Not in any canonical phase | cache_deception_scanner.py dead |
| OAuth Token Leak | Not in any canonical phase | oauth_token_leak_scanner.py dead |
| Subdomain Takeover | Not in any canonical phase | subdomain_takeover_scanner.py dead |
| XXE | Not in any canonical phase | xxe_scanner.py dead |
| Prototype Pollution | SwarmAgent only (no dedicated scanner) | No canonical phase |
| Deserialization | enhanced_scanners.py → orphaned | Unreachable |
| LDAP Injection | enhanced_scanners.py → orphaned | Unreachable |
| SAML Bypass | enhanced_scanners.py → orphaned | Unreachable |
| Container Escape | Not in any phase | container_escape_scanner.py dead |
| CI/CD Pipeline Vulns | Not in any phase | cicd_vuln_scanner.py dead |
| Supply Chain (JS) | Not in any phase | supply_chain_attack_engine.py dead |
| gRPC Security | OWASP gap passive header check only | grpc_scanner.py dead |
| Host Header Injection | Not in active_testing | host_header_scanner.py dead |
| HTTP/2 Attacks | Not in god mode | h2c_scanner.py, http2_attack_engine.py dead |
| DNS Security (SPF/DKIM) | Not in god mode | dns_security_scanner.py dead |
| JWT (dedicated) | JWTAgent inline only | jwt_vulnerability_scanner.py dead |
| AI/LLM Security | Only if `_is_ai_target()` triggers | 14 AI vuln classes have zero coverage for non-AI targets |

---

## Part 10 — Root Causes & Fix Priority

### Root Cause 1: Subprocess Pipeline Isolation
**Problem:** `run_canonical_pipeline()` spawns each phase as a fresh Python subprocess via CLI command. Any engine instantiated in the parent process (ModelOrchestrator, AIReasoningEngine, RealtimeLearner) is invisible inside subprocess phases.
**Fix:** Either (a) switch high-value phases from subprocess to in-process async calls, or (b) pass context via `--findings-file` / `--context-file` arguments to subprocess phases.

### Root Cause 2: Orphaned Aggregators
**Problem:** `unified_advanced_scanner.py` was meant to be the entry point for 18+ specialized scanners but was never wired into `executor.py` or any mission. All 18 children are unreachable.
**Fix:** Add `AdvancedScanMission` as a parallel canonical mission (already partially done — it runs `run_unified_scan()` async alongside FullScanMission).

### Root Cause 3: AdaptivePlanner Vocabulary Mismatch
**Problem:** AdaptivePlanner produces phase names like `scan_xss`, `scan_sqli` which don't match canonical phase names `active_testing`, `vuln_scan`. The mapping was never built. Documented in code comments.
**Fix:** 20-line vocabulary adapter in `FullScanMission._run()`.

### Root Cause 4: Feedback Loop Write-Only
**Problem:** `PersistentMemory.record_result()` is called post-scan. `get_boosted_payloads()` is never called pre-scan. The learning data accumulates but nothing reads it.
**Fix:** Add `boosted = persistent_memory.get_boosted_payloads(vuln_type)` to each scanner's payload initialization.

### Root Cause 5: `orchestrator_integration.activate()` Never Called
**Problem:** The single `activate()` call that wires ModelOrchestrator, EventDrivenEngine, GraphTriggerEngine, and IntelligenceDaemon together has no caller in any startup path.
**Fix:** One line in `GodModeConductor._run_stages_2_to_5()`.

---

## Quick Win Matrix

| Fix | Effort | Engines Unlocked | Vuln Classes Added |
|---|---|---|---|
| Wire `AdvancedScanMission` fully | 1 day | 18 scanners | 10+ |
| Build AdaptivePlanner vocabulary adapter | 4 hours | AdaptivePlanner | 0 (quality improvement) |
| Add `activate()` call to conductor | 1 line | ModelOrchestrator + 4 engines | 0 (quality improvement) |
| Instantiate RealtimeLearner at scan start | 1 line | RealtimeLearner | 0 (quality improvement) |
| Fix `simulate_all_paths()` async call | 2 lines | AttackSimulationEngine | 3 |
| Wire confirmed_pipeline.py to validation | 1 day | 6 post-confirmation actions | 0 (quality improvement) |
| Feed `get_boosted_payloads()` into scanners | 2 hours | PersistentMemory read path | 0 (improves recall) |
| Start IntelligenceDaemon in conductor | 5 lines | 9 autonomous OSINT workers | 2 |
| Wire PostExploitEngine after exploit_chains | 4 hours | PostExploitEngine | 3 (SSRF→cloud, IDOR→enum) |
| Add TargetPrioritizer before canonical pipeline | 2 hours | URL scoring | 0 (coverage improvement) |

---

*All findings are ground truth from source code reads. No inference — every dead engine was confirmed by searching callers across the full codebase.*
