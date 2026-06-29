#!/usr/bin/env bash
# scripts/setup_redis_macos.sh — OneInfinity native Redis setup for macOS
# Idempotent: safe to re-run.
set -euo pipefail

REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_DB="${REDIS_DB:-0}"

echo ""
echo "=== OneInfinity Redis Setup (macOS) ==="
echo "Port: $REDIS_PORT"
echo "DB:   $REDIS_DB"
echo ""

# ── 1. Install Homebrew (if not present) ──────────────────────────────────────
if ! command -v brew &>/dev/null; then
  echo "[→] Homebrew not found — installing..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

  # Add Homebrew to PATH (for Apple Silicon Macs)
  if [[ -f /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  fi
  echo "[✓] Homebrew installed"
else
  echo "[✓] Homebrew already installed ($(brew --version | head -1))"
fi

# ── 2. Install Redis ──────────────────────────────────────────────────────────
if command -v redis-server &>/dev/null; then
  echo "[✓] Redis already installed ($(redis-server --version | head -1))"
else
  echo "[→] Installing Redis via Homebrew..."
  brew install redis
  echo "[✓] Redis installed"
fi

# ── 3. Start Redis service ────────────────────────────────────────────────────
if brew services list | grep redis | grep -q "started"; then
  echo "[✓] Redis service already running"
else
  echo "[→] Starting Redis service..."
  brew services start redis
  echo "[✓] Redis service started (will auto-start on login)"
fi

# ── 4. Wait for Redis to be ready ────────────────────────────────────────────
echo "[→] Waiting for Redis to accept connections..."
for i in $(seq 1 10); do
  if redis-cli -p "$REDIS_PORT" ping &>/dev/null; then
    echo "[✓] Redis responding on port $REDIS_PORT"
    break
  fi
  if [[ $i -eq 10 ]]; then
    echo "[✗] Redis not responding after 10s — check: brew services list"
    exit 1
  fi
  sleep 1
done

# ── 5. Verify connection ──────────────────────────────────────────────────────
PONG=$(redis-cli -p "$REDIS_PORT" ping 2>/dev/null || true)
if [[ "$PONG" == "PONG" ]]; then
  echo "[✓] Redis connection verified"
else
  echo "[✗] Redis not responding on port $REDIS_PORT"
  echo "    Check logs: brew services info redis"
  exit 1
fi

# ── 6. Print connection string ────────────────────────────────────────────────
REDIS_URL="redis://localhost:${REDIS_PORT}/${REDIS_DB}"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Add the following to your ~/.zshrc (or ~/.bashrc):"
echo ""
echo "  export REDIS_URL=\"$REDIS_URL\""
echo ""
echo "Then reload your shell:"
echo "  source ~/.zshrc"
echo ""
echo "Verify oneinfinity uses Redis:"
echo "  python3 -c \"from core.redis_client import get_redis; r=get_redis(); print('Redis OK:', r.ping())\""
echo ""
echo "Redis management commands:"
echo "  brew services start redis    # Start Redis"
echo "  brew services stop redis     # Stop Redis"
echo "  brew services restart redis  # Restart Redis"
echo "  brew services list           # List all services"
echo ""
