#!/bin/bash
# One&Infinity Web UI — Start both backend and frontend
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   One&Infinity Web UI                       ║"
echo "║   Backend : http://localhost:${BACKEND_PORT}            ║"
echo "║   Frontend: http://localhost:${FRONTEND_PORT}            ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Kill on ctrl+c
cleanup() {
    echo ""
    echo "[*] Stopping servers..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 0
}
trap cleanup INT TERM

# Backend
echo "[*] Starting FastAPI backend..."
cd "$ROOT/backend"
pip install -r requirements.txt -q
# Install AI/model deps from repo root if present
ROOT_REQ="$(dirname "$ROOT")/requirements-ai.txt"
[ -f "$ROOT_REQ" ] && pip install -r "$ROOT_REQ" -q && echo "[+] AI requirements installed"
API_PORT="$BACKEND_PORT" python3 main.py &
BACKEND_PID=$!
echo "[+] Backend PID: $BACKEND_PID"

# Wait for backend to be ready
sleep 2

# Frontend
echo "[*] Starting React frontend..."
cd "$ROOT/frontend"

if [ ! -d "node_modules" ]; then
    echo "[*] Installing frontend dependencies (first run)..."
    npm install
fi

npm run dev -- --port "$FRONTEND_PORT" &
FRONTEND_PID=$!
echo "[+] Frontend PID: $FRONTEND_PID"

echo ""
echo "[+] Both servers running."
echo "    Open http://localhost:${FRONTEND_PORT} in your browser"
echo "    Press Ctrl+C to stop"
echo ""

wait $BACKEND_PID $FRONTEND_PID
