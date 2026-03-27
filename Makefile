# ==============================================================
# OneInfinity — Makefile
# Convenience targets for building, running, scaling, and
# maintaining the distributed Docker environment.
#
# Usage:
#   make help          — show this help
#   make up            — start full distributed stack
#   make scan T=vulnbank.org  — submit a scan to the cluster
# ==============================================================

.DEFAULT_GOAL := help
.PHONY: help build up down restart logs status scale clean purge \
        scan recon vuln-scan research ai-test secrets \
        workers-status queue-status findings \
        plugin-install plugin-list plugin-update \
        update image-push shell test

# ── Embedded scripts (define avoids "missing separator" for multi-line -c args) ─
define WORKERS_PY
import sys, json
lines = sys.stdin.read().strip().split('\n')
pairs = list(zip(lines[::2], lines[1::2]))
for wid, info in pairs:
    try:
        d = json.loads(info)
        caps = json.loads(d.get('capabilities', '[]'))
        print('  %s: status=%s, caps=%s, load=%s, active=%s' % (wid, d.get('status','?'), caps, d.get('load','?'), d.get('active_tasks',0)))
    except:
        print('  %s: %s' % (wid, info[:80]))
endef
export WORKERS_PY

# ── Configuration ─────────────────────────────────────────────
COMPOSE       := docker compose -f docker-compose.distributed.yml
COMPOSE_FULL  := $(COMPOSE) --profile monitoring --profile updater
IMAGE         := ghcr.io/inf1n1tydes0ul/oneinfinity
API_URL       := http://localhost/api
API_KEY       ?= $(shell grep ONEINFINITY_API_KEY .env 2>/dev/null | cut -d= -f2 | head -1)
CURL          := curl -sf -H "X-API-Key: $(API_KEY)"

# Scan target (set via: make scan T=example.com)
T ?= example.com

# ── Help ──────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  OneInfinity — Distributed Docker Management"
	@echo ""
	@echo "  ── Stack Control ────────────────────────────────────"
	@echo "  make setup          First-time setup (dirs + .env)"
	@echo "  make build          Build all Docker images"
	@echo "  make up             Start full distributed stack"
	@echo "  make up-min         Start minimal stack (no monitoring)"
	@echo "  make down           Stop all services"
	@echo "  make restart        Restart all services"
	@echo "  make logs           Tail all logs"
	@echo "  make status         Show service status"
	@echo ""
	@echo "  ── Worker Scaling ───────────────────────────────────"
	@echo "  make scale-recon N=4    Scale recon workers to N"
	@echo "  make scale-vuln N=3     Scale vuln workers to N"
	@echo "  make workers-status     Show worker registry (Redis)"
	@echo "  make queue-status       Show task queue lengths"
	@echo ""
	@echo "  ── Scanning ─────────────────────────────────────────"
	@echo "  make scan T=example.com             Full scan"
	@echo "  make recon T=example.com            Recon only"
	@echo "  make vuln-scan T=example.com        Vuln scan only"
	@echo "  make research T=example.com         Research mode"
	@echo "  make ai-test T=http://llm.local     AI security test"
	@echo "  make secrets T=my-github-org        Secret scanning"
	@echo "  make findings                       Show all findings"
	@echo ""
	@echo "  ── Plugins ──────────────────────────────────────────"
	@echo "  make plugin-install P=org/repo      Install plugin"
	@echo "  make plugin-list                    List plugins"
	@echo "  make plugin-update                  Update all plugins"
	@echo ""
	@echo "  ── Maintenance ──────────────────────────────────────"
	@echo "  make update         Run auto-updater now"
	@echo "  make build-push     Build and push images to GHCR"
	@echo "  make shell          Open shell in orchestrator"
	@echo "  make clean          Remove stopped containers"
	@echo "  make purge          Remove all data volumes (DESTRUCTIVE)"
	@echo ""

# ── First-time setup ──────────────────────────────────────────
setup:
	@echo "[setup] Creating directories…"
	mkdir -p data plugins/community logs
	@if [ ! -f .env ]; then \
	    cp .env.example .env; \
	    echo "[setup] Created .env from .env.example"; \
	    echo "[setup] IMPORTANT: Edit .env and set ONEINFINITY_API_KEY"; \
	else \
	    echo "[setup] .env already exists"; \
	fi
	@echo "[setup] Done. Run 'make build && make up' to start."

# ── Build ─────────────────────────────────────────────────────
build:
	@echo "[build] Building core image…"
	docker build -t $(IMAGE):latest .
	@echo "[build] Building worker image…"
	docker build -f Dockerfile.worker -t $(IMAGE)-worker:latest .

build-ai:
	@echo "[build] Building AI image (slow)…"
	docker build --build-arg INSTALL_AI=1 -t $(IMAGE):latest-ai .

# ── Stack control ─────────────────────────────────────────────
up: _check_env
	@echo "[up] Starting distributed stack…"
	$(COMPOSE_FULL) up -d
	@echo "[up] Stack is running. Dashboard: http://localhost"

up-min: _check_env
	@echo "[up] Starting minimal stack (no monitoring/updater)…"
	$(COMPOSE) up -d
	@echo "[up] Minimal stack is running. Dashboard: http://localhost"

up-ai: _check_env
	@echo "[up] Starting stack with AI workers…"
	$(COMPOSE_FULL) --profile ai up -d

down:
	$(COMPOSE_FULL) --profile ai --profile watchtower down

restart:
	$(COMPOSE_FULL) restart

logs:
	$(COMPOSE) logs -f --tail=100

logs-workers:
	$(COMPOSE) logs -f --tail=50 worker-recon worker-vuln worker-exploit

logs-orchestrator:
	$(COMPOSE) logs -f --tail=100 orchestrator

status:
	$(COMPOSE) ps

# ── Worker scaling ────────────────────────────────────────────
N ?= 2

scale-recon:
	@echo "[scale] Scaling recon workers to $(N)…"
	$(COMPOSE) up -d --scale worker-recon=$(N) --no-recreate worker-recon

scale-vuln:
	@echo "[scale] Scaling vuln workers to $(N)…"
	$(COMPOSE) up -d --scale worker-vuln=$(N) --no-recreate worker-vuln

scale-exploit:
	$(COMPOSE) up -d --scale worker-exploit=$(N) --no-recreate worker-exploit

workers-status:
	@echo "[workers] Registered workers in Redis:"
	@docker exec oneinfinity-redis redis-cli HGETALL swarm:workers 2>/dev/null | \
	    python3 -c "$${WORKERS_PY}" \
	    || echo "  (Redis not running or no workers registered)"

queue-status:
	@echo "[queue] Task queue lengths:"
	@docker exec oneinfinity-redis redis-cli \
	    LLEN swarm:tasks:recon \
	    LLEN swarm:tasks:vuln_scan \
	    LLEN swarm:tasks:exploit \
	    LLEN swarm:tasks:ai_security \
	    LLEN swarm:tasks:secrets \
	    LLEN swarm:tasks:default 2>/dev/null | \
	paste - - - - - - | \
	awk '{print "  recon="$$1" vuln_scan="$$2" exploit="$$3" ai_security="$$4" secrets="$$5" default="$$6}' \
	|| echo "  (Redis not running)"

# ── Scanning ──────────────────────────────────────────────────
scan: _check_env
	@echo "[scan] Submitting full scan for $(T)…"
	@$(CURL) -X POST $(API_URL)/scan/start \
	    -H "Content-Type: application/json" \
	    -d '{"target":"$(T)","scan_type":"full","profile":"deep"}' | \
	    python3 -m json.tool

recon: _check_env
	@$(CURL) -X POST $(API_URL)/scan/start \
	    -H "Content-Type: application/json" \
	    -d '{"target":"$(T)","scan_type":"recon","profile":"quick"}' | \
	    python3 -m json.tool

vuln-scan: _check_env
	@$(CURL) -X POST $(API_URL)/scan/start \
	    -H "Content-Type: application/json" \
	    -d '{"target":"$(T)","scan_type":"vuln_scan","profile":"deep"}' | \
	    python3 -m json.tool

research: _check_env
	@$(CURL) -X POST $(API_URL)/scan/start \
	    -H "Content-Type: application/json" \
	    -d '{"target":"$(T)","scan_type":"research","options":{"iterations":5,"active":true}}' | \
	    python3 -m json.tool

ai-test: _check_env
	@$(CURL) -X POST $(API_URL)/scan/start \
	    -H "Content-Type: application/json" \
	    -d '{"target":"$(T)","scan_type":"ai_test"}' | \
	    python3 -m json.tool

secrets: _check_env
	@$(CURL) -X POST $(API_URL)/scan/start \
	    -H "Content-Type: application/json" \
	    -d '{"target":"$(T)","scan_type":"secrets","options":{"mode":"thorough"}}' | \
	    python3 -m json.tool

findings: _check_env
	@$(CURL) $(API_URL)/vulnerabilities | python3 -m json.tool

scan-status: _check_env
	@$(CURL) $(API_URL)/stats | python3 -m json.tool

# ── Plugins ───────────────────────────────────────────────────
P ?= org/repo-name

plugin-install:
	@echo "[plugins] Installing $(P)…"
	docker exec oneinfinity-orchestrator \
	    /app/scripts/plugin-install.sh install $(P)

plugin-list:
	docker exec oneinfinity-orchestrator \
	    /app/scripts/plugin-install.sh list

plugin-update:
	docker exec oneinfinity-orchestrator \
	    /app/scripts/plugin-install.sh update

# ── Maintenance ───────────────────────────────────────────────
update:
	@echo "[update] Running auto-updater now…"
	$(COMPOSE) run --rm update-manager /app/scripts/auto-update.sh

build-push: build
	docker tag $(IMAGE):latest $(IMAGE):latest
	docker push $(IMAGE):latest
	@echo "[push] Image pushed to GHCR"

shell:
	docker exec -it oneinfinity-orchestrator /bin/bash

shell-worker:
	docker exec -it $$(docker ps -qf "name=worker-recon" | head -1) /bin/bash

redis-cli:
	docker exec -it oneinfinity-redis redis-cli

test:
	@echo "[test] Running smoke tests…"
	docker run --rm $(IMAGE):latest --help > /dev/null && echo "  ✓ help"
	docker run --rm $(IMAGE):latest toolcheck > /dev/null && echo "  ✓ toolcheck"
	@echo "[test] All smoke tests passed"

clean:
	$(COMPOSE) rm -f
	docker system prune -f

purge: down
	@echo "WARNING: This will delete ALL scan data, findings, and plugin data!"
	@read -p "Type 'yes' to confirm: " c && [ "$$c" = "yes" ] || exit 1
	docker volume rm $$(docker volume ls -q | grep oneinfinity) 2>/dev/null || true
	@echo "Purge complete."

_check_env:
	@[ -f .env ] || (echo "ERROR: .env not found. Run 'make setup' first." && exit 1)
	@[ -n "$(API_KEY)" ] || echo "WARN: ONEINFINITY_API_KEY not set in .env — API calls may fail"
