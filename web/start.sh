#!/bin/bash
# One&Infinity Web UI — Start both backend and frontend
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   One&Infinity Web UI                       ║"
echo "║   Backend : http://localhost:8000            ║"
echo "║   Frontend: http://localhost:3000            ║"
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
python3 main.py &
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

npm run dev &
FRONTEND_PID=$!
echo "[+] Frontend PID: $FRONTEND_PID"

echo ""
echo "[+] Both servers running."
echo "    Open http://localhost:3000 in your browser"
echo "    Press Ctrl+C to stop"
echo ""

wait $BACKEND_PID $FRONTEND_PID
