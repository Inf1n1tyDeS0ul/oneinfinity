#!/usr/bin/env bash
# scripts/setup_redis.sh — OneInfinity native Redis setup
# Idempotent: safe to re-run.
set -euo pipefail

REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_DB="${REDIS_DB:-0}"

echo ""
echo "=== OneInfinity Redis Setup ==="
echo "Port: $REDIS_PORT"
echo "DB:   $REDIS_DB"
echo ""

# ── 1. Install Redis ──────────────────────────────────────────────────────────
if command -v redis-server &>/dev/null; then
  echo "[✓] Redis already installed ($(redis-server --version | head -1))"
else
  echo "[→] Installing Redis..."
  sudo apt-get update -qq
  sudo apt-get install -y redis-server
  echo "[✓] Redis installed"
fi

# ── 2. Start service ──────────────────────────────────────────────────────────
if systemctl is-active --quiet redis-server; then
  echo "[✓] Redis service already running"
else
  echo "[→] Starting Redis service..."
  sudo systemctl start redis-server
  sudo systemctl enable redis-server
  echo "[✓] Redis service started and enabled"
fi

# ── 3. Verify connection ──────────────────────────────────────────────────────
PONG=$(redis-cli -p "$REDIS_PORT" ping 2>/dev/null || true)
if [[ "$PONG" == "PONG" ]]; then
  echo "[✓] Redis responding on port $REDIS_PORT"
else
  echo "[✗] Redis not responding on port $REDIS_PORT — check logs: journalctl -u redis-server"
  exit 1
fi

# ── 4. Print connection string ────────────────────────────────────────────────
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
