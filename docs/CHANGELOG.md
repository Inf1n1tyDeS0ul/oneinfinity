# Changelog

All notable changes to this project will be documented in this file.

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