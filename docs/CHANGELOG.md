# Changelog

All notable changes to this project will be documented in this file.

## [v2.2.0] — 2026-06-30
### Phase 0 — Council-Approved Bug Fixes & Security Hardening

**Council of Councils review:** 5 specialist councils (Safety, Performance, Deduplication, Security Risk, Architecture) reviewed all 6 proposed fixes. FIX-3 and FIX-5 rejected (FIX-3 was already implemented; FIX-5 bug did not exist). All others approved with mandatory security corrections applied.

#### FIX-1 — CORS + JWT Agents Now Reachable in Pipeline Mode (3 files)
- `src/oneinfinity/pipeline/canonical.py`: Added `"cors"` and `"jwt"` to `active_testing` phase `cli_extra_args` — both were in the phase description but absent from the args list
- `src/oneinfinity/cli/main.py` + `src/oneinfinity/cli/commands/swarm.py`: Added `"cors"` and `"jwt"` to `--agents` choices list (Perf council confirmed they were unreachable without this change)
- **Security hardening (mandatory):** `GodModeConductor._setup_logging()` now adds `_TokenRedactFilter` to the file log handler — redacts `Bearer <token>` and API key patterns from all DEBUG-level log records before writing to disk
- **Dedup hardening (mandatory):** `JWTAgent.execute_tests()` now maps legacy vuln_type strings to canonical scanner names: `jwt_rs256_hs256` → `jwt_algorithm_confusion`, `jwt_jku_inject` → `jwt_jwks_uri_confusion`, `jwt_expiry_bypass` → `jwt_expiry_manipulation`, `jwt_kid_sqli`/`jwt_kid_path` → `jwt_kid_injection` — prevents 5 near-duplicate finding pairs from surviving pipeline dedup
- **Security hardening (mandatory):** `JWTAgent.generate_hypotheses()` strips `original_token` from all Hypothesis context dicts — raw JWT credentials no longer propagate into finding artifacts or log files

#### FIX-2 — `_AGENT_TO_TOOL` Key Collision Fix
- `src/oneinfinity/scan/unified_scan_engine.py`: Renamed stale tool-name keys to proper agent_type identifiers: `"xssstrike"` → `"xss_strike_agent"`, `"commix"` → `"commix_agent"`. The existing `"cmdi_agent": "nuclei"` mapping is preserved (no collision). XSSStrike and Commix now dispatch correctly when the decision engine emits their agent types.

#### FIX-4 — Bypass403Engine Actually Executes (Security-Hardened)
- `src/oneinfinity/attack/bypass_403_engine.py`: Added `max_requests=100` parameter cap (aborts technique loop when reached) and `_request_count` counter. Added `ScopeValidator` check at start of `test()` — refuses to probe out-of-scope targets and logs a warning.
- `src/oneinfinity/orchestration/god_mode_engine.py` (`FullScanMission._run()`): The Bypass403Engine was instantiated and logged but `.test()` was never called. Now calls `_bypass_engine.test(session.target)` and stores `BypassReport` results in `waf_profile["bypass_403_findings"]`. Findings are non-fatal (try/except guarded).

#### FIX-6 — AIRTWrapper Registered in AISecurityEngine (Security-Hardened)
- `src/oneinfinity/ai/ai_security_engine.py`: Added `"airt"` to `_ALL_TOOLS`. Added guarded import of `AIRTWrapper` in `_load_wrappers()` with `try/except ImportError` — startup does not fail if `ai_red_teamer` package is absent (Architecture council rejected unguarded import).
- `src/oneinfinity/ai_security/tool_wrappers/airt_wrapper.py`:
  - Added `allow_data_exfil_objective: bool = False` parameter — data-exfiltration objective disabled by default (Security council: legal risk without explicit consent)
  - Stores only category keys from `result.extracted_data`, never raw exfiltrated content in finding artifacts
  - Added `asyncio.wait_for(timeout=120)` per objective (Perf council: no timeout existed — could block indefinitely on hung Ollama)
  - Replaced deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()` (Python 3.10+ safe)

#### Rejected Fixes (with reasons)
- **FIX-3 (race_condition in active_testing):** `run_race_condition_test` already runs at `executor.py:1109` in `business_logic` phase on 5 commerce paths. Adding it to `active_testing` would create triple-source noise and 3 dedup-surviving race condition variants. Dropped.
- **FIX-5 (WAF memory label bug):** `generate_all_types()` sub-engines correctly call `self._store_successful_patterns()` on themselves. The described mislabeling bug does not exist in the current code. Dropped.

---

### Phase 1 — Engine Wirings into Existing Phases (Council-Approved)

**Council review:** 2 Safety councils (A: P1.1-P1.4, B: P1.5-P1.8). P1.7 (RealtimeLearner) rejected — constructor-time subscription creates zombie handlers, async bus handlers silently dropped in sync dispatch. P1.9 (SemanticTrafficAnalyzer) deferred for re-review. All other wirings approved with mandatory corrections applied.

#### P1.1 — ResearchModeController auth_config forwarding (2 files)
- `src/oneinfinity/attack/custom_test_engine.py`: Added `auth_config: dict = None` parameter to `__init__`, stored as `self.auth_config`, added `_build_auth_headers()` method. In `_execute_http()`, merged auth headers before test headers (test overrides auth) via `{**self._build_auth_headers(), **(test.headers or {})}`.
- `src/oneinfinity/orchestration/research_mode_controller.py`: Now passes `auth_config=self.auth_config` to `CustomTestEngine(...)`. Research loop attack tests now run authenticated when credentials are available.
- **Impact:** IDOR, privilege escalation, mass-assignment, and auth bypass tests in research mode now operate on real authenticated surfaces.

#### P1.2 — CORS/JWT/BlindXSS Scanners wired into active_testing (1 file)
- `src/oneinfinity/pipeline/executor.py` (`_inline_active_testing`): Added `_run_p12_scanners()` async coroutine (bridged via `asyncio.run()`) that runs `CORSScanner`, `JWTVulnerabilityScanner`, `BlindXSSEngine` after OWASP gap checks.
- **Corrections applied:** `asyncio.run()` bridge (executor is fully synchronous); `.to_dict()` on `CORSFinding`/`JWTFinding`; `inject_and_monitor()` for BlindXSS (no `.scan()` method); `await scanner.close()` in finally for httpx client cleanup; `asyncio.wait_for(timeout=12)` per BlindXSS param attempt.

#### P1.3 — DNSSecurityScanner wired into deep_recon (1 file)
- `src/oneinfinity/pipeline/executor.py` (`_inline_deep_recon`): Added `DNSSecurityScanner` after OWASP gap checks, wrapped in `asyncio.run()`. Passes extracted hostname (not full URL). Forwards subdomains from `adaptive_recon.json` for dangling-CNAME detection.
- **Returns:** `list[dict]` directly — no `.to_dict()` step needed.

#### P1.4 — LLMBusinessLogicAnalyzer wired into business_logic (1 file)
- `src/oneinfinity/pipeline/executor.py` (`_inline_business_logic`): Added after payment tampering block, before `return findings`. Bridged via `asyncio.run()`. Calls `.to_dict()` on `BusinessLogicVulnerability` objects. `enable_validation=False` to avoid double-execution (exploit_validation runs after this phase). Skipped if no LLM API key — graceful.
- **Note:** Bypassed when `attack_simulation.json` is pre-seeded (early-return at line 1192).

#### P1.5 — DifferentialScanner wired into exploit_validation (1 file, rewrite)
- `src/oneinfinity/pipeline/executor.py` (`_inline_exploit_validation`): Rewrote to collect `WebValidationEngine` confirmed findings into `findings.extend()` (not early return), then run `DifferentialScanner` in `asyncio.run()` if auth_headers is non-empty.
- **Mandatory auth guard:** `if not _auth_hdrs: skip` — without credentials, both sides of the comparison are unauthenticated and the scanner produces zero real signal.
- **Endpoint source:** URLs extracted from loaded findings (not hardcoded), capped to 30.

#### P1.6 — BrowserReasoningAgent wired into browser_analysis (1 file)
- `src/oneinfinity/pipeline/executor.py` (`_inline_browser_analysis`): Added before final JSON write. Bridged via `asyncio.run()`. Triple-layered fallback: Playwright → BeautifulSoup → empty list. Graceful on no LLM provider.

#### P1.7 — RealtimeLearner REJECTED
- **Reason:** Constructor-time `_subscribe_to_events()` call creates live event bus subscriptions before `run()` is invoked — zombie subscriptions on status-check instantiations. All `RealtimeLearner` handlers are `async def` while the event bus dispatches synchronously — handlers return unawaited coroutines silently doing nothing. No cleanup path (not tracked in `_bus_handlers`). Requires rearchitecting handler dispatch before this can be wired safely.

#### P1.8 — GitHub OSINT: REVERTED — UI-feature, dedicated page already exists
- Originally wired into `FoundationMission` Step 5. Reverted on user review.
- **Reason:** A dedicated GitHub OSINT page already exists in the UI, giving the operator full control over org name, token scope, and depth. Automatic heuristic org extraction from target domain (e.g. `example.com` → org `example`) is unreliable. Silently consuming GitHub API quota during a background god mode run is unexpected behavior. This feature belongs in the UI where the user explicitly provides the target org and authenticates — not in god mode where inputs are inferred.
- `GodModeSession.github_osint` field removed. `FoundationMission` Step 5 removed. No net change to any files from P1.8.

---

### Phase 2 — Unified Advanced Scanner as New Pipeline Phase (Council-Approved)

**Council:** CouncilB from master plan. Interface confirmed from source reads: `UnifiedAdvancedScanner(target).run_full_scan()` is async, returns `AdvancedScanResult` with 31 per-category findings lists + attack chains, all accessed via `.to_dict()`.

#### New Phase: `advanced_scan` (non-mandatory, pct_complete=50, timeout=2400s)
- **`src/oneinfinity/pipeline/canonical.py`**: Added `PhaseConfig(name="advanced_scan", ...)` between `vuln_scan` and `active_testing`. Added `"_internal_advanced_scan"` to `_no_output_flag`.
- **`src/oneinfinity/pipeline/executor.py`**: Added `elif pname == "advanced_scan": return self._inline_advanced_scan(target, out_path)` dispatch branch. Added `_inline_advanced_scan()` method (~75 lines) that bridges via `asyncio.run()`, flattens 31 finding categories via `to_dict()`, surfaces attack chains as `source_type=simulated` findings, writes `advanced_findings.json`.
- **Activates 32 scanners:** IDOR, race conditions, CAPTCHA bypass, JWT, NoSQL, SSTI, deserialization, LDAP, SAML, prototype pollution, gRPC, SQLi, SSRF, path traversal, CORS, XXE, subdomain takeover, HPP, client-side attacks, OAuth token leakage, PDF-SSRF, Redis injection, cache poisoning, DNS rebinding, rate-limit bypass, unicode normalization, plus integrated attack chain detection.
- **Note:** `unified_advanced_scanner.py` header says DEPRECATED (merged into `unified_scan_engine.py`) but the class `UnifiedAdvancedScanner` with `run_full_scan()` is still fully implemented and functional. Phase 4 will add `AdvancedScanMission` using `run_unified_scan()` from the replacement engine as a parallel mission.

---

### Phase 3 — Three New Canonical Phases: cicd_scan, container_scan, grpc_scan

All three scanners are **synchronous** (no asyncio bridge needed). All three are non-mandatory, timeout_s=180, skip gracefully on ImportError.

#### New Phase: `cicd_scan` (after graphql_scan, pct_complete=95)
- `src/oneinfinity/pipeline/canonical.py`: Added PhaseConfig. Added to `_no_output_flag`.
- `src/oneinfinity/pipeline/executor.py`: Added `_inline_cicd_scan()` — calls `CICDVulnerabilityScanner().scan_github_repo()`. Derives GitHub org name heuristically from target hostname. Gated on GITHUB_TOKEN presence for useful results. Returns findings as `CICDFinding.to_dict()` list.

#### New Phase: `container_scan` (after cicd_scan, pct_complete=95)
- `src/oneinfinity/pipeline/executor.py`: Added `_inline_container_scan()` — calls `ContainerEscapeScanner(target).run()`. Returns `ContainerFinding.to_dict()` list. Detects: privileged containers, hostPath mounts, RBAC wildcard, exposed etcd (2379), API server insecure mode, Docker socket, kubelet read-only port.

#### New Phase: `grpc_scan` (after container_scan, pct_complete=96)
- `src/oneinfinity/pipeline/executor.py`: Added `_inline_grpc_scan()` — calls `GRPCScanner(target).run()`. Returns `GRPCFinding.to_dict()` list. Tests: reflection API, proto field fuzzing, auth bypass via empty metadata, gRPC-Web detection, plaintext gRPC, unknown field injection.

---

### Phase 4 — Three New God Mode Mission Classes

All three missions run in `_run_stages_2_to_5` alongside the existing missions. All use the `Mission` base class pattern with non-fatal exception handling.

#### `_is_ai_target()` helper (module-level)
- Added to `god_mode_engine.py` after constants block. Detects AI/LLM/chatbot targets by keyword matching on URL, app_context, and recon API endpoints.

#### `AIRedTeamMission` (conditional on AI target detected)
- Runs: `MultiTurnChainer` (6 strategies via `asyncio.wait_for(timeout=90)` each), `RAGPoisoningEngine`, `LLMDoSEngine`, `LLMSupplyChainScanner` in a single async coroutine (`asyncio.run(asyncio.wait_for(..., 600))`), plus `AgentHijackHarness` (synchronous).
- Unlocked: (1) Immediately if `_is_ai_target()` is True at scan start. (2) Via `_on_endpoint` event bus handler if a discovered endpoint URL matches `/v1/chat`, `/completions`, `/llm/`, etc.
- All engines are optional (`try/except ImportError`) — mission degrades gracefully if packages are absent.

#### `ZeroHypothesisMission` (post-FullScan)
- Starts alongside `FullScanMission` but blocks internally via `while not self._full_scan.is_done() and not self._stop_event.is_set(): sleep(5)`.
- On FullScan completion, calls `ZeroDayHypothesisEngine().generate(target, top_n=25)` — synchronous graph-clustering-based hypothesis generation.
- Emits `NEW_VULNERABILITY` events for each hypothesis so `ResearchMission` can act on them.

#### `AdvancedScanMission` (always-on parallel cross-validation)
- Starts immediately alongside `FullScanMission`. Runs `UnifiedAdvancedScanner.run_full_scan()` in `asyncio.run(asyncio.wait_for(..., 1800s))`.
- Acts as a "second opinion" parallel scanner independent of the canonical 14-phase pipeline.
- **Note:** P1.7 (RealtimeLearner) was rejected — constructor-time subscriptions create zombie handlers; async handlers silently dropped in sync event bus dispatch. Deferred for rearchitecting.

---

### Phase 5 — AdaptivePlanner + Stubs Cleanup

#### AdaptivePlanner wired into FullScanMission (informational)
- `src/oneinfinity/orchestration/god_mode_engine.py` (`FullScanMission._run()`): Added AdaptivePlanner call before `run_canonical_pipeline`. Logs `focus_vuln_types` and `rationale`. **Advisory only** — `skip_phases` result not forwarded because AdaptivePlanner uses legacy phase vocabulary (`scan_xss`, `scan_sqli`) incompatible with canonical pipeline phase names (`active_testing`, `vuln_scan`). Full integration pending a vocabulary mapping adapter.

#### run_garak and run_pyrit stubs replaced (1 file)
- `src/oneinfinity/modules/tool_wrappers.py`: `run_garak()` and `run_pyrit()` were single-line stubs returning `ToolResult(success=True)` with no data — making the AI scan path a silent no-op. Both now delegate to `AISecurityEngine.scan(config)` with `tools=["garak"]` / `tools=["pyrit"]` respectively, returning actual findings via `data["findings"]`.

#### Deferred items (require further work)
- **P1.7 RealtimeLearner:** Rejected — constructor-time subscriptions + async handlers in sync event bus. Requires event bus to support async dispatch before this can be wired.
- **P1.9 SemanticTrafficAnalyzer in ResearchModeController:** AI Strategy council timed out. Code reviewed — interface confirmed (`analyze_endpoints(urls, max_predictions=20) -> list[PredictedEndpoint]`). Manual wire-up deferred to next sprint.
- **AdaptivePlanner vocabulary mapping:** Full `skip_phases` forwarding requires mapping adapter from legacy (`scan_xss`) to canonical (`active_testing`) phase names.
- **Frida JS scripts deletion:** `frida_scripts/*.js` were assessed as duplicates but are actually loaded by `security_engine.py` mobile phase. Retained.

---

## [v2.1.0] — 2026-06-30
### Auth-Tiered Surface Expansion (Council-Approved, Phases A-F)

#### New Event Types (Phase A)
- `CREDENTIAL_ACQUIRED` — emitted per valid credential by GoCredentialSpray; triggers scoped auth-tiered recon
- `SURFACE_ENRICHED` — emitted when auth recon finds URLs absent from tier-0 surface; delta = potential auth bypass surface
- `RECON_CONFIDENCE` — emitted every 30s by AdaptiveReconEngine with coverage score and surface stats
- `AUTH_TIER_UNLOCKED` — emitted on completion of each auth-tier scoped recon run

#### Auth Injection (Phase B)
- `HeadlessBrowserEngine`: `auth_context` param; injects `AuthSessionContext` into Playwright `BrowserContext` before first navigation; also injects into `requests.Session` for static fallback
- SPA pushState/replaceState route interception — captures lazy-loaded routes never seen in static crawl
- XHR response body scanning for secrets (JSON responses scanned for JWT/API key patterns)
- `AdaptiveReconEngine`: `auth_context` param; runs authenticated Playwright crawl when credentials available
- `_katana_crawl`: `extra_env` param for session cookie injection via subprocess env

#### Credential Loop (Phase C)
- `GoCredentialSpray.run()`: emits `CREDENTIAL_ACQUIRED` per credential INSIDE streaming loop — scoped recon starts without waiting for full spray
- `GoCredentialSpray.run_sync()`: replaced `get_event_loop().run_until_complete()` with `asyncio.run()` — fixes deadlock when called from EventBus worker threads
- `GodModeConductor`: subscribes `_on_credential_acquired()` handler; spawns `_run_scoped_auth_recon()` per new credential
- Scoped recon copies tier-0 artifacts to skip phases 1-3, runs auth-aware crawl only

#### Parallel Foundation (Phase D)
- `AdaptiveReconEngine.run()` now uses `ThreadPoolExecutor` with wave-based dependency scheduling:
  - Wave 1: subdomain enum + gau in parallel
  - Wave 2: HTTP probe (sequential)
  - Wave 3: katana + tech detection + cloud intel in parallel
  - Wave 4: API intelligence + JS intelligence in parallel
  - Wave 5: strategy + scoring (sequential)

#### Validation Pipeline (Phase E)
- `ResultIngestionEngine.ingest()`: synchronous `FindingValidationEngine` pre-filter for `{xss, sqli, ssti, lfi, open_redirect, xxe}` — suppresses confirmed FPs before storage
- Async fire-and-forget validation for `{ssrf, cmdi, rce, auth_bypass, idor}` — non-blocking
- Path-template URL normalization: `/users/123` and `/users/456` dedup to `/users/{id}` — eliminates duplicate findings for same injection point
- Fail-open: validation errors let finding through (TP preservation)

#### IDOR Wiring (Phase F)
- `GodModeConductor._feed_idor_engine()`: feeds `MultiAccountIDOREngine` on `CREDENTIAL_ACQUIRED`
- Adds anonymous baseline account when only 1 credential found — ensures >=2 for cross-account IDOR

#### Bug Fix
- **CRITICAL**: `AdaptiveReconEngine._phase_tech_detection()` — `self._tech_profile = profile` was unreachable dead code (placed after `return` in `_filter_urls()`). Tech detection results were silently lost on every scan since initial implementation. Fixed.

#### Multi-Language Philosophy
- Codified: use best language for each job. Python for orchestration/ML/AI, Go for performance-critical network tools, Rust for CPU-intensive scanners, Nim for payload generation, eBPF for kernel capture, TypeScript for frontend.

---

## [1.3.0] - 2026-04-16

### Added

- **AI Model Orchestration layer** — `ModelOrchestrator` with 3-tier cost-aware routing (FAST → STANDARD → PREMIUM). All LLM calls now go through a single engine; no subsystem calls a provider API directly.
- **Ollama backend** (`orchestration/backends/ollama.py`) — Local LLM support via Ollama's OpenAI-compatible API. Models are auto-discovered from the running Ollama daemon at startup; tier assigned by parameter-count heuristic (≥70B → PREMIUM, 27–34B → STANDARD, else FAST). Explicit `models.yaml` entries take precedence.
- **CLI fallback backends** (`orchestration/backends/cli.py`) — `CodexCliBackend` (`codex exec`) and `ClaudeCliBackend` (`claude -p`) registered automatically when their binaries are on `PATH`. Activate on API auth errors or budget exhaustion.
- **Backend registry** (`orchestration/backends/__init__.py`) — `BaseBackend` interface + `register_backend` decorator; backends self-register at import time.
- **`ModelConfig.fallback_provider`** — Per-model fallback chain (e.g. `anthropic → claude-cli`) for auth/quota failures.
- **`config/models.yaml` — `ollama:` section** — `host`, `auto_discover`, `prefer_over_api`, `discovery_timeout_s` controls.
- **`config/models.yaml` — `cli_fallback:` section** — `enabled`, `codex_model`, `claude_model`, `max_budget_usd`, `on_errors` controls.
- **Google Gemini provider** — `gemini-2.0-flash` and `gemini-2.5-pro-preview` entries in `models.yaml` (free tier via Gemini CLI OAuth).
- **PostgreSQL storage mode** — `DBManager` and `PgClient` support `POSTGRES_URL` env var; auto-falls back to SQLite when unset.
- **Scan-filtered findings** — Result ingestion filters false-positive and simulated findings before persistence.
- **Codebase reorganization (phases 4–12)** — All flat root-level modules split into typed subpackages under `src/oneinfinity/`: `cli/`, `orchestration/`, `recon/`, `scan/`, `attack/`, `attack_graph_core/`, `swarm/`, `intelligence/`, `findings/`, `exploit_chains/`, `bounty/`, `ai_security/`, `mobile/`, `infra/`, `learning/`, `pipeline/`, `agents/`, `modules/`, `core/`, `framework/`, `plugins/`.
- **Single `pyproject.toml`** — All dependency declarations consolidated; `pip install -e ".[ai,mobile,web]"` installs everything.

### Changed

- **Architecture diagram** (README + DOCUMENTATION.md) — New `AI MODEL ORCHESTRATION` layer shown between AI Decision Engine and Agent Swarm.
- **ARCHITECTURE.md Section 2** — Directory listing updated to reflect actual `src/oneinfinity/` subpackage layout.
- **ARCHITECTURE.md Section 21** (new) — Full AI Model Orchestration documentation: routing tiers, backends, Ollama auto-discovery, CLI fallbacks, budget tracking, `models.yaml` config, and web UI.
- **DOCUMENTATION.md Section 3.34** (new) — User-facing guide: Ollama setup, CLI fallback installation, budget YAML config, routing tiers, and `doctor` verification command.
- **Web UI — AI Models page** — Fixed model/history response shape handling (array vs. wrapped object), corrected budget field names (`today_usd`, `daily_pct`, `projected_monthly`), added split cost display (`$in/$out` per 1k tokens).

### Fixed

- **`model_orchestrator.py`** — `_load_from_file` now also calls `_auto_discover_ollama`, `_register_cli_models`, and `_assign_cli_fallbacks`; `_load_defaults` likewise wires all backends so defaults and file-loaded configs behave identically.
- **`model_budget_manager.py`** — Field names aligned with web UI expectations (`today_usd`, `month_usd`, `daily_pct`, `projected_monthly`).
- **`upload_manager.py`** — Mobile APK upload dedup path corrected.
- **`db_manager.py` / `pg_client.py`** — Connection pool hardening and error handling improvements.
- **Web backend API responses** — `daemon_api`, `graph_api`, `graph_brain_api`, `orchestrator_api`, `swarm_intel_api`, `system_evolution_api` response shapes corrected to match frontend expectations.

## [1.2.0] - 2026-03-20
### Added
- **Distributed Docker stack** (`docker-compose.distributed.yml`) — 15 services including Redis, orchestrator, nginx, frontend, Prometheus, Grafana, and Watchtower.
- **Worker swarm** — `worker-recon`, `worker-vuln`, `worker-exploit`, `worker-ai`, `worker-secrets` containers; horizontally scalable via `make scale-recon N=4`.
- **`Dockerfile`** — 3-stage multi-arch build (Go tools, Python wheels, slim runtime); non-root `oi` user; `ONEINFINITY_HOME=/data`.
- **`Dockerfile.worker`** — Purpose-built worker image with `CAPABILITIES` build arg.
- **`docker-entrypoint.sh`** — Entrypoint with Nuclei template sync and `shell` subcommand.
- **`scripts/worker-entrypoint.sh`** — Worker startup with Redis readiness wait and plugin requirement install.
- **`scripts/auto-update.sh`** — Scheduled updater for Nuclei templates, GF patterns, community plugins, and container images; `--cron` flag installs crontab.
- **`scripts/plugin-install.sh`** — Plugin manager: install from GitHub/PyPI/local, remove, update, list, validate; writes `plugins/community/registry.yaml`; triggers hot-reload.
- **`worker/main.py`** — Worker daemon: Redis registration, heartbeat, BLPOP task polling, result publishing.
- **`worker/executor.py`** — Task executor with module-specific handlers and CLI subprocess fallback.
- **`services/redis/redis.conf`** — Hardened Redis config (512 MB cap, LRU eviction, disabled destructive commands).
- **`services/nginx/nginx.conf`** — Reverse proxy with rate limiting, WebSocket upgrade, and security headers.
- **`services/prometheus/prometheus.yml`** — Prometheus scrape config for all services.
- **`Makefile`** — 30 convenience targets: setup, build, up, scale, scan, workers-status, queue-status, plugin management, and purge.
- **`plugins/PLUGIN_SPEC.md`** — Full plugin interface specification with working examples.
- **`DOCKER.md`** — Complete Docker reference guide (image variants, volumes, networking, CI/CD).
- **`requirements-core.txt`**, **`requirements-ai.txt`**, **`requirements-mobile.txt`**, **`requirements-web.txt`** — Split requirements for targeted Docker layer caching.
- **`.github/workflows/docker-publish.yml`** — Multi-arch GHCR CI/CD (core + AI images, smoke tests).
- **`.dockerignore`** — Excludes virtualenvs, output data, secrets, and git history from Docker build context.

### Fixed
- **`application_intelligence.py`** — Research mode returned 0 paths on all targets because `_load_urls()`, `_load_alive_hosts()`, and `_load_tech_profile()` only searched `output_dir` — recon data lives in `output_dir/recon/`. All three methods now search `[output_dir, output_dir/recon]`.

## [1.1.0] - 2026-03-19
### Added
- Single-container `docker-compose.yml` with `cli`, `backend`, and `frontend` services.
- `.env.example` extended with distributed Docker variables (`DATA_DIR`, `PLUGIN_DIR`, `IMAGE_TAG`, `HTTP_PORT`, worker concurrency, resource limits, update schedule, GHCR registry tokens, Grafana admin password, and Prometheus retention settings).

## [1.0.0] - 2026-03-17
### Added
- Initial public release of One&Infinity framework.
- Autonomous 7-phase scan pipeline.
- Swarm Intelligence multi-agent orchestration.
- Attack Graph Brain with lateral movement simulation.
- 12-phase Mobile Security pipeline.
- AI Security testing (Garak, PyRIT integration).
- Exploit Chaining and PoC generation engine.
- Bug Bounty ROI ranking and auto-reporting.
- React-based Web UI for system-wide observability.
- EMA-based continuous learning system.

### Changed
- Refactored project structure for better organization.
- Hardened security guardrails (SafetyGuard, ScopeValidator).
- Standardized configuration via environment variables.

### Fixed
- Cleaned up sensitive data and hardcoded paths.
- Fixed aggressive polling issues in the Web UI.
- Improved error handling and logging across all modules.