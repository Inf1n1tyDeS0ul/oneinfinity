#!/bin/bash

# OneInfinity Native Startup Script
# Starts Docker DB services + backend + frontend + worker

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" || exit 1

# Load .env so all port/config vars are available
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    set -a; source "$PROJECT_ROOT/.env"; set +a
fi

# Port defaults (fall through to uncommon values if .env absent)
API_PORT="${API_PORT:-47291}"
FRONTEND_PORT="${FRONTEND_PORT:-47292}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== OneInfinity Startup ===${NC}"
echo -e "  Project root: $PROJECT_ROOT"
echo -e "  Backend  → http://localhost:${API_PORT}"
echo -e "  Frontend → http://localhost:${FRONTEND_PORT}"

# Python: prefer venv
if [[ -d "$PROJECT_ROOT/.venv" ]]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python3"
else
    PYTHON="python3"
fi

# 1. Docker DB services
echo -e "\n${BLUE}[1/3] Docker DB services...${NC}"
docker compose -f "$PROJECT_ROOT/docker-compose.db.yml" \
    --env-file "$PROJECT_ROOT/.env" up -d 2>&1 | grep -E "Started|Running|healthy|error" || true

# 2. Kill stale processes on configured ports
echo -e "\n${BLUE}[2/3] Cleaning up stale processes...${NC}"
pkill -f "uvicorn web.backend.main:app" 2>/dev/null || true
pkill -f "npm run dev" 2>/dev/null || true
pkill -f "oneinfinity/worker/main.py" 2>/dev/null || true
lsof -t -i :"${API_PORT}"      | xargs kill -9 2>/dev/null || true
lsof -t -i :"${FRONTEND_PORT}" | xargs kill -9 2>/dev/null || true

BACKEND_PORT="${API_PORT}"
echo -e "  → Backend will use port ${BACKEND_PORT}"

# 3. Start Application Stack
echo -e "\n${BLUE}[3/3] Launching OneInfinity Stack...${NC}"
mkdir -p "$PROJECT_ROOT/logs"

# Backend
echo -e "  → Starting Backend (port ${BACKEND_PORT})..."
if nohup "$PYTHON" -m uvicorn web.backend.main:app \
        --host 0.0.0.0 --port "${BACKEND_PORT}" > logs/backend.log 2>&1 &
then
    BACKEND_PID=$!
    echo -e "    ${GREEN}✓${NC} Backend started (PID: $BACKEND_PID)"
else
    echo -e "    ${RED}✗${NC} Backend failed to start"
fi

# Worker
echo -e "  → Starting Worker..."
if nohup "$PYTHON" src/oneinfinity/worker/main.py > logs/worker.log 2>&1 &
then
    WORKER_PID=$!
    echo -e "    ${GREEN}✓${NC} Worker started (PID: $WORKER_PID)"
else
    echo -e "    ${RED}✗${NC} Worker failed to start"
fi

# Frontend
echo -e "  → Starting Frontend (port ${FRONTEND_PORT})..."
if [[ -d "web/frontend" ]]; then
    cd web/frontend || exit 1
    if VITE_BACKEND_URL="http://localhost:${BACKEND_PORT}" \
       VITE_API_PORT="${BACKEND_PORT}" \
       VITE_FRONTEND_PORT="${FRONTEND_PORT}" \
       nohup npm run dev -- --host 0.0.0.0 --port "${FRONTEND_PORT}" \
           > ../../logs/frontend.log 2>&1 &
    then
        FRONTEND_PID=$!
        echo -e "    ${GREEN}✓${NC} Frontend started (PID: $FRONTEND_PID)"
    else
        echo -e "    ${RED}✗${NC} Frontend failed to start"
    fi
    cd ../.. || exit 1
else
    echo -e "    ${RED}✗${NC} web/frontend directory not found"
fi

sleep 3

# Verify
echo -e "\n${BLUE}Verifying processes...${NC}"
FAILED=0
for desc_pid in "Backend:$BACKEND_PID" "Worker:$WORKER_PID" "Frontend:$FRONTEND_PID"; do
    desc="${desc_pid%%:*}"
    pid="${desc_pid##*:}"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $desc running (PID: $pid)"
    else
        echo -e "  ${RED}✗${NC} $desc not running (check logs/${desc,,}.log)"
        FAILED=1
    fi
done

if [[ $FAILED -eq 0 ]]; then
    echo -e "\n${GREEN}=== Startup Complete ===${NC}"
    echo -e "  Dashboard: ${BLUE}http://localhost:${FRONTEND_PORT}${NC}"
    echo -e "  API:       ${BLUE}http://localhost:${BACKEND_PORT}${NC}"
    echo -e "  MobSF:     ${BLUE}http://localhost:${MOBSF_PORT:-47297}${NC}"
    echo -e "  Neo4j:     ${BLUE}http://localhost:${NEO4J_HTTP_PORT:-47295}${NC}"
    echo -e "  Logs:      tail -f logs/*.log"
else
    echo -e "\n${RED}=== Startup Completed with Errors ===${NC}"
    echo -e "  Check logs: tail -f logs/*.log"
    exit 1
fi
