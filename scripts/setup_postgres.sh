#!/usr/bin/env bash
# scripts/setup_postgres.sh — OneInfinity native PostgreSQL setup
# Idempotent: safe to re-run. Requires sudo for apt install and service start.
set -euo pipefail

DB_USER="${POSTGRES_USER:-oneinfinity}"
DB_NAME="${POSTGRES_DB:-oneinfinity}"
DB_PORT="${POSTGRES_PORT:-5432}"

# ── Password ──────────────────────────────────────────────────────────────────
if [[ -z "${POSTGRES_PASSWORD:-}" ]]; then
  read -rsp "Enter password for PostgreSQL role '$DB_USER': " POSTGRES_PASSWORD
  echo
fi

SCHEMA="$(cd "$(dirname "$0")/.." && pwd)/db/schema.sql"

echo ""
echo "=== OneInfinity PostgreSQL Setup ==="
echo "User:     $DB_USER"
echo "Database: $DB_NAME"
echo "Port:     $DB_PORT"
echo "Schema:   $SCHEMA"
echo ""

# ── 1. Install PostgreSQL ─────────────────────────────────────────────────────
if command -v psql &>/dev/null; then
  echo "[✓] PostgreSQL already installed ($(psql --version | head -1))"
else
  echo "[→] Installing PostgreSQL..."
  sudo apt-get update -qq
  sudo apt-get install -y postgresql postgresql-contrib
  echo "[✓] PostgreSQL installed"
fi

# ── 2. Start service ──────────────────────────────────────────────────────────
if systemctl is-active --quiet postgresql; then
  echo "[✓] PostgreSQL service already running"
else
  echo "[→] Starting PostgreSQL service..."
  sudo systemctl start postgresql
  sudo systemctl enable postgresql
  echo "[✓] PostgreSQL service started and enabled"
fi

# ── 3. Create role ────────────────────────────────────────────────────────────
ROLE_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null || true)
if [[ "$ROLE_EXISTS" == "1" ]]; then
  echo "[✓] Role '$DB_USER' already exists — updating password"
  sudo -u postgres psql -c "ALTER ROLE $DB_USER WITH LOGIN PASSWORD '$POSTGRES_PASSWORD';" >/dev/null
else
  echo "[→] Creating role '$DB_USER'..."
  sudo -u postgres psql -c "CREATE ROLE $DB_USER WITH LOGIN PASSWORD '$POSTGRES_PASSWORD';" >/dev/null
  echo "[✓] Role '$DB_USER' created"
fi

# ── 4. Create database ────────────────────────────────────────────────────────
DB_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null || true)
if [[ "$DB_EXISTS" == "1" ]]; then
  echo "[✓] Database '$DB_NAME' already exists"
else
  echo "[→] Creating database '$DB_NAME'..."
  sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;" >/dev/null
  echo "[✓] Database '$DB_NAME' created"
fi

# ── 5. Grant privileges ───────────────────────────────────────────────────────
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" >/dev/null
sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO $DB_USER;" >/dev/null
echo "[✓] Privileges granted"

# ── 6. Apply schema ───────────────────────────────────────────────────────────
if [[ ! -f "$SCHEMA" ]]; then
  echo "[✗] Schema file not found at: $SCHEMA"
  exit 1
fi
echo "[→] Applying schema..."
PGPASSWORD="$POSTGRES_PASSWORD" psql \
  -h localhost -p "$DB_PORT" \
  -U "$DB_USER" -d "$DB_NAME" \
  -f "$SCHEMA" >/dev/null
echo "[✓] Schema applied"

# ── 7. Print connection string ────────────────────────────────────────────────
POSTGRES_URL="postgresql://${DB_USER}:${POSTGRES_PASSWORD}@localhost:${DB_PORT}/${DB_NAME}"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Add the following to your ~/.bashrc (or ~/.zshrc):"
echo ""
echo "  export POSTGRES_URL=\"$POSTGRES_URL\""
echo ""
echo "Then reload your shell:"
echo "  source ~/.bashrc"
echo ""
echo "Verify oneinfinity uses Postgres:"
echo "  oneinfinity doctor"
echo "  # Look for: [DBManager] Running in POSTGRES MODE"
echo ""
