#!/usr/bin/env bash
# oi-start.sh — OneInfinity one-command launcher
# Usage: oi  (via alias)  or  bash scripts/oi-start.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Load .env ─────────────────────────────────────────────────────────────────
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    set -a; source "$PROJECT_ROOT/.env"; set +a
fi

# ── Port defaults ──────────────────────────────────────────────────────────────
API_PORT="${API_PORT:-47291}"
FRONTEND_PORT="${FRONTEND_PORT:-47292}"
PG_PORT="${PG_PORT:-47293}"
REDIS_PORT="${REDIS_PORT:-47294}"
NEO4J_HTTP_PORT="${NEO4J_HTTP_PORT:-47295}"
NEO4J_BOLT_PORT="${NEO4J_BOLT_PORT:-47296}"
MOBSF_PORT="${MOBSF_PORT:-47297}"

# ── Colors ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "  ██████╗ ███╗   ██╗███████╗"
echo "  ██╔═══██╗████╗  ██║██╔════╝"
echo "  ██║   ██║██╔██╗ ██║█████╗"
echo "  ██║   ██║██║╚██╗██║██╔══╝"
echo "  ╚██████╔╝██║ ╚████║███████╗"
echo "  ╚═════╝ ╚═╝  ╚═══╝╚══════╝  OneInfinity"
echo -e "${NC}"

echo -e "${BLUE}Ports:${NC}"
echo -e "  Backend   → ${BOLD}http://localhost:${API_PORT}${NC}"
echo -e "  Frontend  → ${BOLD}http://localhost:${FRONTEND_PORT}${NC}"
echo -e "  MobSF     → ${BOLD}http://localhost:${MOBSF_PORT}${NC}"
echo -e "  Neo4j     → ${BOLD}http://localhost:${NEO4J_HTTP_PORT}${NC}"
echo -e "  Postgres  → ${BOLD}localhost:${PG_PORT}${NC}"
echo -e "  Redis     → ${BOLD}localhost:${REDIS_PORT}${NC}"
echo ""

# ── PATH ──────────────────────────────────────────────────────────────────────
export PATH="/opt/homebrew/bin:$HOME/.cargo/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"

# ── 1. Docker services ────────────────────────────────────────────────────────
echo -e "${BLUE}[1/4] Starting Docker services...${NC}"

# Ensure Docker is running
if ! docker info &>/dev/null; then
    echo -e "  → Docker not running — starting Docker Desktop..."
    open -a Docker 2>/dev/null || true
    for i in $(seq 1 30); do
        docker info &>/dev/null && break
        sleep 2
    done
fi

docker compose -f "$PROJECT_ROOT/docker-compose.db.yml" \
    --env-file "$PROJECT_ROOT/.env" up -d --quiet-pull 2>&1 \
    | grep -vE "^$|Pulling|Pull" || true
echo -e "  ${GREEN}✓${NC} DB containers (postgres:${PG_PORT}, redis:${REDIS_PORT}, neo4j:${NEO4J_HTTP_PORT}/${NEO4J_BOLT_PORT})"

# MobSF
if ! docker ps --filter name=oneinfinity-mobsf --filter status=running -q | grep -q .; then
    echo -e "  → Starting MobSF..."
    docker run --rm -v oneinfinity-mobsf-data:/home/mobsf/.MobSF \
        alpine chown -R 9901:9901 /home/mobsf/.MobSF &>/dev/null || true
    docker rm -f oneinfinity-mobsf &>/dev/null || true
    docker run -d --name oneinfinity-mobsf \
        -p "${MOBSF_PORT}:8008" \
        -e MOBSF_HOME=/home/mobsf/.MobSF \
        -v oneinfinity-mobsf-data:/home/mobsf/.MobSF \
        --restart unless-stopped \
        opensecurity/mobile-security-framework-mobsf:latest &>/dev/null
    echo -e "  ${GREEN}✓${NC} MobSF started on port ${MOBSF_PORT}"
else
    echo -e "  ${GREEN}✓${NC} MobSF already running on port ${MOBSF_PORT}"
fi

# ── 2. Ollama ─────────────────────────────────────────────────────────────────
echo -e "${BLUE}[2/4] Ollama...${NC}"
if ! pgrep -x ollama &>/dev/null; then
    brew services start ollama &>/dev/null || true
    echo -e "  ${GREEN}✓${NC} Ollama service started"
else
    echo -e "  ${GREEN}✓${NC} Ollama already running"
fi

# ── 3. Kill stale app processes ───────────────────────────────────────────────
echo -e "${BLUE}[3/4] Cleaning up stale processes...${NC}"
pkill -f "uvicorn web.backend.main:app" 2>/dev/null || true
pkill -f "npm run dev" 2>/dev/null || true
pkill -f "oneinfinity/worker/main.py" 2>/dev/null || true
lsof -t -i :"${API_PORT}"      2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -t -i :"${FRONTEND_PORT}" 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

# ── 4. App stack ──────────────────────────────────────────────────────────────
echo -e "${BLUE}[4/4] Launching app stack...${NC}"

PYTHON="$PROJECT_ROOT/.venv/bin/python3"
[[ -x "$PYTHON" ]] || PYTHON="python3"

mkdir -p "$PROJECT_ROOT/logs"

# Backend
nohup "$PYTHON" -m uvicorn web.backend.main:app \
    --host 0.0.0.0 --port "${API_PORT}" \
    > "$PROJECT_ROOT/logs/backend.log" 2>&1 &
BACKEND_PID=$!
echo -e "  ${GREEN}✓${NC} Backend PID ${BACKEND_PID} → http://localhost:${API_PORT}"

# Worker
nohup "$PYTHON" src/oneinfinity/worker/main.py \
    > "$PROJECT_ROOT/logs/worker.log" 2>&1 &
WORKER_PID=$!
echo -e "  ${GREEN}✓${NC} Worker PID ${WORKER_PID}"

# Frontend
if [[ -d "$PROJECT_ROOT/web/frontend" ]]; then
    cd "$PROJECT_ROOT/web/frontend"
    [[ -d node_modules ]] || npm install --silent
    VITE_BACKEND_URL="http://localhost:${API_PORT}" \
    VITE_API_PORT="${API_PORT}" \
    VITE_FRONTEND_PORT="${FRONTEND_PORT}" \
    nohup npx vite --host 0.0.0.0 --port "${FRONTEND_PORT}" \
        > "$PROJECT_ROOT/logs/frontend.log" 2>&1 &
    FRONTEND_PID=$!
    echo -e "  ${GREEN}✓${NC} Frontend PID ${FRONTEND_PID} → http://localhost:${FRONTEND_PORT}"
    cd "$PROJECT_ROOT"
fi

# ── Ready ──────────────────────────────────────────────────────────────────────
sleep 3
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  OneInfinity is up!${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Dashboard  →  ${BOLD}http://localhost:${FRONTEND_PORT}${NC}"
echo -e "  API        →  ${BOLD}http://localhost:${API_PORT}/docs${NC}"
echo -e "  MobSF      →  ${BOLD}http://localhost:${MOBSF_PORT}${NC}"
echo -e "  Neo4j      →  ${BOLD}http://localhost:${NEO4J_HTTP_PORT}${NC}"
echo ""
echo -e "  Logs:  tail -f ~/oneinfinity/logs/*.log"
echo -e "  Stop:  pkill -f 'uvicorn|npm run dev|worker/main'; docker compose -f docker-compose.db.yml down"
echo ""
