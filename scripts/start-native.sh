#!/bin/bash

# OneInfinity Native Startup Script
# Starts Redis, Postgres, Neo4j (via brew) and Backend, Frontend, Worker (natively)

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Change to project root
cd "$PROJECT_ROOT" || exit 1

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== OneInfinity Startup ===${NC}"
echo -e "  Project root: $PROJECT_ROOT"

# Set Python path (venv or system)
if [ -d "$PROJECT_ROOT/.venv" ]; then
    echo -e "${BLUE}  Using venv Python...${NC}"
    PYTHON="$PROJECT_ROOT/.venv/bin/python3"
else
    echo -e "${RED}  Warning: .venv not found, using system Python${NC}"
    PYTHON="python3"
fi

# 1. Check/Start Databases via Homebrew
echo -e "${BLUE}[1/3] Checking Databases...${NC}"

services=("redis" "postgresql@14" "neo4j")
for service in "${services[@]}"; do
    if brew services list | grep "$service" | grep -q "started"; then
        echo -e "${GREEN}  ✓ $service is already running${NC}"
    else
        echo -e "  → Starting $service..."
        brew services start "$service"
    fi
done

# 2. Kill existing app processes to avoid port conflicts
echo -e "${BLUE}[2/3] Cleaning up old processes...${NC}"
pkill -f "uvicorn web.backend.main:app" 2>/dev/null
pkill -f "npm run dev" 2>/dev/null
pkill -f "src/oneinfinity/worker/main.py" 2>/dev/null
# Port-based kill as fallback
lsof -t -i :3000 | xargs kill -9 2>/dev/null || true
lsof -t -i :8000 | xargs kill -9 2>/dev/null || true
lsof -t -i :5001 | xargs kill -9 2>/dev/null || true

# Determine available backend port (8000 or 5001)
BACKEND_PORT=8000
if lsof -i :8000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "  ${RED}⚠${NC}  Port 8000 occupied (likely macOS ControlCenter), using 5001"
    BACKEND_PORT=5001
    # Check if 5001 also occupied
    if lsof -i :5001 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "  ${RED}✗${NC} Port 5001 also occupied, attempting kill..."
        lsof -t -i :5001 | xargs kill -9 2>/dev/null || true
        sleep 1
    fi
fi
echo -e "  → Backend will use port ${BACKEND_PORT}"

# 3. Start Application Stack
echo -e "${BLUE}[3/3] Launching OneInfinity Stack...${NC}"

# Ensure logs directory exists
mkdir -p "$PROJECT_ROOT/logs"

# Start Backend
echo -e "  → Starting Backend (port ${BACKEND_PORT})..."
if nohup "$PYTHON" -m uvicorn web.backend.main:app --host 0.0.0.0 --port ${BACKEND_PORT} > logs/backend.log 2>&1 & then
    BACKEND_PID=$!
    echo -e "    ${GREEN}✓${NC} Backend started (PID: $BACKEND_PID)"
else
    echo -e "    ${RED}✗${NC} Backend failed to start"
fi

# Start Worker
echo -e "  → Starting Worker..."
if nohup "$PYTHON" src/oneinfinity/worker/main.py > logs/worker.log 2>&1 & then
    WORKER_PID=$!
    echo -e "    ${GREEN}✓${NC} Worker started (PID: $WORKER_PID)"
else
    echo -e "    ${RED}✗${NC} Worker failed to start"
fi

# Start Frontend
echo -e "  → Starting Frontend (port 3000)..."
if [ -d "web/frontend" ]; then
    cd web/frontend || exit 1
    if VITE_BACKEND_URL="http://localhost:${BACKEND_PORT}" nohup npm run dev -- --host 0.0.0.0 --port 3000 > ../../logs/frontend.log 2>&1 & then
        FRONTEND_PID=$!
        echo -e "    ${GREEN}✓${NC} Frontend started (PID: $FRONTEND_PID)"
    else
        echo -e "    ${RED}✗${NC} Frontend failed to start"
    fi
    cd ../.. || exit 1
else
    echo -e "    ${RED}✗${NC} web/frontend directory not found"
fi

# Wait for processes to start
sleep 2

# Verify processes are running
echo -e "\n${BLUE}Verifying processes...${NC}"
FAILED=0

if [ -n "$BACKEND_PID" ] && kill -0 $BACKEND_PID 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Backend running (PID: $BACKEND_PID)"
else
    echo -e "  ${RED}✗${NC} Backend not running (check logs/backend.log)"
    FAILED=1
fi

if [ -n "$WORKER_PID" ] && kill -0 $WORKER_PID 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Worker running (PID: $WORKER_PID)"
else
    echo -e "  ${RED}✗${NC} Worker not running (check logs/worker.log)"
    FAILED=1
fi

if [ -n "$FRONTEND_PID" ] && kill -0 $FRONTEND_PID 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Frontend running (PID: $FRONTEND_PID)"
else
    echo -e "  ${RED}✗${NC} Frontend not running (check logs/frontend.log)"
    FAILED=1
fi

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}=== Startup Complete ===${NC}"
    echo -e "Dashboard: ${BLUE}http://localhost:3000${NC}"
    echo -e "API:       ${BLUE}http://localhost:${BACKEND_PORT}${NC}"
    echo -e "Logs:      tail -f logs/*.log"
else
    echo -e "\n${RED}=== Startup Completed with Errors ===${NC}"
    echo -e "Check logs: tail -f logs/*.log"
    exit 1
fi
