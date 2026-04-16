# Changelog

All notable changes to this project will be documented in this file.

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