# One&Infinity — System Memory

Internal learnings, design decisions, known edge cases, and fix history.
Updated during the full-system backtesting audit (2026-03-19).

---

## Design Decisions

### D1 — Singleton Ingestion Engine
`ResultIngestionEngine` is a module-level singleton (`get_ingestion_engine()`). This ensures one DB connection pool and one broadcast callback across all scan phases. Trade-off: no per-scan isolation; all findings share the same findings.db.

### D2 — Simulate Mode Only for Doctor Audit
`core/audit/executor.py` supports both "simulate" and "import" mode. Doctor always uses "simulate" because "import" mode tries to instantiate all 99 discovered classes, most of which require constructor arguments, causing false "broken" reports. Import mode is reserved for targeted debugging.

### D3 — Deduplication Excludes Tool Name
`core/deduplicator.py` fingerprint intentionally excludes the `tool` field so that the same vulnerability found by multiple tools (e.g., dalfox + nuclei both finding XSS) deduplicates to one finding. This was a bug (fixed 2026-03-19): the original fingerprint included `tool`, defeating cross-tool dedup.

### D4 — Atomic Check-and-Store for Findings
`result_ingestion_engine.py` uses `_check_and_store()` which combines the duplicate check and DB write inside a single `threading.Lock()` acquisition. This prevents the TOCTOU race condition where two threads could both pass the duplicate check before either stored the finding.

### D5 — Prod Context Preserves Severity for High-Specificity Secrets
`scorer.py`: for HIGH-specificity secret types (AWS keys, GitHub PATs, etc.) found in a "prod/live" code context, the LOW-ownership tier-down is suppressed. A production-flagged AWS key is always at least "high" even if ownership is unknown. Generic keys get a tier-up (low → medium) in prod context.

### D6 — PoC Generator Uses Step-Best-Match
`exploit_chains/poc_generator.py`: each chain step tries to find a finding whose `vuln_type` matches the step name. If no match, it falls back to the trigger finding. This produces more accurate PoCs than using the trigger finding for all steps.

### D7 — Payload Dictionaries Live in exploit_generator.py
`finding_validation_engine.py` imports `SQLI_PAYLOADS`, `XSS_PAYLOADS`, `SSRF_PAYLOADS`, `LFI_PAYLOADS`, `CMDI_PAYLOADS`, and `AUTH_BYPASS_PAYLOADS` from `exploit_generator.py`. These must remain in sync — if the validation engine is updated to use new payload structures, `exploit_generator.py` must be updated accordingly.

---

## Known Edge Cases

### E1 — GitHub Rate Limit on Test Tokens
`GitHubSearchClient` uses `safe_request` from `core.http_client`, NOT `requests.request` directly. Tests must patch `agents.secret_intel.github_client.safe_request`, not `requests.request`.

### E2 — Chain Pattern Trigger Types Must Be Canonical
`exploit_chains/chain_patterns.py` trigger types must match the canonical vuln_type values produced by `result_ingestion_engine.py` parsers (e.g., "sqli" not "sql injection"). Non-canonical aliases were removed (2026-03-19) to prevent silent chain detection failures.

### E3 — CSV Export Key Ordering
`modules/findings.py` `export_csv()` uses `sorted(keys)` for fieldnames. This ensures deterministic column ordering. Older versions used `list(set())` which was non-deterministic.

### E4 — Mutable Default in ingest_recon_asset
Fixed (2026-03-19): `metadata: dict = {}` changed to `metadata: Optional[dict] = None` with `if metadata is None: metadata = {}` guard.

### E5 — F-String Format Bug in github_client
Fixed (2026-03-19): `{delay:.2fs}` was an invalid format spec (should be `{delay:.2f}s`). Python 3.12+ would raise `ValueError`; earlier versions silently formatted incorrectly.

### E6 — Finding Validation Engine Payload Import
Fixed (2026-03-19): `exploit_generator.py` was missing payload dictionaries (`SQLI_PAYLOADS`, etc.) that `finding_validation_engine.py` imports at runtime inside each `_validate_*` method. Imports would raise `ImportError`, causing silent validation failure. All payload dictionaries added.

### E7 — SKILLS.md Chain Count
Fixed (2026-03-19): SKILLS.md incorrectly claimed "16 ChainPatterns". Actual count is 6. Count must be updated if new chain patterns are added to `exploit_chains/chain_patterns.py`.

---

## Fix History Summary

| Date | File | Bug | Fix |
|------|------|-----|-----|
| 2026-03-19 | `core/deduplicator.py` | Tool name in fingerprint prevented cross-tool dedup | Removed `tool` from `_make_fingerprint` |
| 2026-03-19 | `modules/findings.py` | `set()` for CSV fieldnames → non-deterministic columns | Changed to `sorted(keys)` |
| 2026-03-19 | `result_ingestion_engine.py` | Mutable default `metadata: dict = {}` | Changed to `Optional[dict] = None` with guard |
| 2026-03-19 | `result_ingestion_engine.py` | TOCTOU race: dup check and store not atomic | Merged into `_check_and_store()` under single lock |
| 2026-03-19 | `exploit_chains/poc_generator.py` | All chain steps used same trigger finding | Each step now finds best-match finding by step type |
| 2026-03-19 | `exploit_chains/chain_patterns.py` | Non-canonical trigger aliases never matched | Replaced with canonical vuln_type values |
| 2026-03-19 | `agents/secret_intel/scorer.py` | Prod context didn't prevent severity tier-down | Added `is_prod_ctx` guard for HIGH-specificity types |
| 2026-03-19 | `agents/secret_intel/scorer.py` | Generic keys in prod context stayed LOW | Added tier-up for generic + prod context |
| 2026-03-19 | `agents/secret_intel/github_client.py` | Invalid f-string `{:.2fs}` | Fixed to `{:.2f}s` |
| 2026-03-19 | `tests/test_secret_intel.py` | Tests patched `requests.request` not `safe_request` | Updated mock target to `agents.secret_intel.github_client.safe_request` |
| 2026-03-19 | `exploit_generator.py` | Missing payload dicts caused ImportError in validation engine | Added all 6 payload dictionaries |
| 2026-03-19 | `core/doctor.py` | `--deep` used import-mode audit → 65 false broken | Changed to always use simulate mode |
| 2026-03-19 | `web/backend/main.py` | Hard-coded `0.0.0.0` binding, ephemeral key logged | Env-var controlled host/port, key removed from log |
| 2026-03-19 | `gen_report.py` | Hard-coded `/home/devendra-yadav/...` DB path | Replaced with `path_manager.findings_db_path()` |

---

## Architecture Notes

- **Primary DB**: `~/.oneinfinity/databases/findings.db` — SQLite with WAL mode
- **Singleton pattern**: `ResultIngestionEngine`, `SafetyGuard`, `OneInfinityHTTPClient` — all use double-checked locking
- **Agent message protocol**: Async-compatible `queue.Queue` inbox/outbox; coordinator routes by agent specialization
- **Secret pipeline**: 9 phases — scope → dork → dedup URLs → org graph → fetch+detect → dedup findings → validate → AI validate → normalize
- **Chain detection**: Runs on confirmed (medium+) findings only; 6 predefined patterns; PoC synthesized per step

---

## Trade-Offs

| Decision | Pro | Con |
|---------|-----|-----|
| Simulate mode for audit | Fast, no false positives | Doesn't catch real import errors |
| SQLite (not Postgres) | Zero-config, portable | Single-writer bottleneck under high concurrency |
| ThreadPoolExecutor for parallelism | Simple, no broker needed | GIL limits CPU-bound work |
| Fingerprint dedup without tool | Cross-tool dedup works | Two different params with same vuln type deduplicated incorrectly |
| 4-second timing threshold for SQLi | Reduces false positives | Misses payloads with 2-3s delays |


---


# System Memory and Intelligence Architecture

This document outlines the mechanisms for learning, adaptation, and intelligence persistence within the One&Infinity platform.

## 1. Learning System (EMA & Experience)
The platform uses an Exponential Moving Average (EMA) learning system across Swarm Agents and the Adaptive Attack Strategy.
- **Agent Success Rates**: Agents adjust their likelihood of being selected based on previous successes against specific technology stacks and target shapes. 
- **Learning Feedback Loop**: Every exploit attempt (success or failure) is recorded via `record_outcome()`. Successes boost the `exploitability_estimate` for the agent-vector pair, while failures decay it (α=0.30).
- **Bounty Optimization**: The system tracks the financial impact (ROI) of successful exploits, updating the priority weighting of attack paths that historically lead to higher payout chains.
- **Pattern Mining**: The system continuously analyzes successful vulnerability triggers and correlates them with detected technologies (e.g., `django` + `postgres` → `sqli` probability increases).
- **Knowledge Base (KB)**: All learned intelligence is persisted in a localized SQLite database (`knowledge_base.db`), keeping a persistent record of tool runs, payload efficacy, and target profiles.

## 2. Mutation Strategies & WAF Evasion
The `ExploitGenerator` and `PayloadMutator` apply dynamically scaled mutations when Web Application Firewalls (WAF) are detected or when testing AI boundaries.
- **AI Mutations**: 18 specific AI mutation strategies exist (synonym replacement, leetspeak, homoglyphs, json injection, etc.) to evade LLM safety filters.
- **WAF Mutations**: Standard payloads are automatically wrapped in encoding chains (Base64, URL encoding, Double URL encoding) or obfuscated to bypass identified WAF rules.
- **Feedback Loop**: When an exploit fails or triggers a WAF, the ExploitChainEngine marks the strategy as ineffective for that target and switches to alternate permutations (e.g. whitespace injection, comment obfuscation).

## 3. Execution Context & Decision Making
- **Graph Brain**: The `AttackGraphBrain` centrally orchestrates execution by maintaining an active priority queue of test nodes.
- **Priority Boosting**: Nodes receive priority boosts based on connectivity (more connections = +0.5x), vulnerability status (exploitable = +0.5x), and severity (critical/high boost).
- **Decisions**: Decisions (which agent to deploy, which payload to try) are ranked by the `AutonomousDecisionEngine` using a `Score = Impact × Exploitability × Novelty / Effort` formula. These are fully visible via the UI (e.g., `BrainDashboard`, `SwarmIntelligence`).
- **Chain Execution**: Complex multi-step attacks are executed via the `ChainExecutor` using a structured `ExecutionContext` to pass tokens, credentials, and state between steps.
- **Attack Paths**: Attack paths and exploit chains are derived from a real-time `AttackGraphData` structure, bridging the gap between isolated findings and multi-step exploitation.

## 4. Safety Guard
- **Enforcement**: The `SafetyGuard` is enabled by default to prevent destructive actions (reboot, format, destructive deletion) during autonomous execution.
- **Pattern Filtering**: It filters all outgoing payloads and shell commands against a list of dangerous patterns before they reach the target. 
- **Manual Override**: Safety restrictions can be adjusted in the `config/` but require explicit acknowledgement for high-risk operations.