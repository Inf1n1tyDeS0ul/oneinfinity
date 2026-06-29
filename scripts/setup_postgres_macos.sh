#!/usr/bin/env bash
# scripts/setup_postgres_macos.sh — OneInfinity native PostgreSQL setup for macOS
# Idempotent: safe to re-run.
set -euo pipefail

DB_USER="${POSTGRES_USER:-oneinfinity}"
DB_NAME="${POSTGRES_DB:-oneinfinity}"
DB_PORT="${POSTGRES_PORT:-5432}"

# ── Validate inputs ───────────────────────────────────────────────────────────
if [[ ! "$DB_USER" =~ ^[a-zA-Z_][a-zA-Z0-9_]{0,62}$ ]]; then
  echo "[✗] POSTGRES_USER contains invalid characters: $DB_USER"; exit 1
fi
if [[ ! "$DB_NAME" =~ ^[a-zA-Z_][a-zA-Z0-9_]{0,62}$ ]]; then
  echo "[✗] POSTGRES_DB contains invalid characters: $DB_NAME"; exit 1
fi
if [[ ! "$DB_PORT" =~ ^[0-9]+$ ]]; then
  echo "[✗] POSTGRES_PORT must be numeric: $DB_PORT"; exit 1
fi

# ── Password ──────────────────────────────────────────────────────────────────
if [[ -z "${POSTGRES_PASSWORD:-}" ]]; then
  read -rsp "Enter password for PostgreSQL role '$DB_USER': " POSTGRES_PASSWORD
  echo
fi

SCHEMA="$(cd "$(dirname "$0")/.." && pwd)/db/schema.sql"

echo ""
echo "=== OneInfinity PostgreSQL Setup (macOS) ==="
echo "User:     $DB_USER"
echo "Database: $DB_NAME"
echo "Port:     $DB_PORT"
echo "Schema:   $SCHEMA"
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

# ── 2. Install PostgreSQL ─────────────────────────────────────────────────────
if command -v psql &>/dev/null; then
  echo "[✓] PostgreSQL already installed ($(psql --version | head -1))"
else
  echo "[→] Installing PostgreSQL 14 via Homebrew..."
  brew install postgresql@14
  echo "[✓] PostgreSQL 14 installed"
fi

# ── 3. Add PostgreSQL to PATH ─────────────────────────────────────────────────
# Homebrew PostgreSQL needs explicit PATH addition
if [[ -d /opt/homebrew/opt/postgresql@14/bin ]]; then
  export PATH="/opt/homebrew/opt/postgresql@14/bin:$PATH"
elif [[ -d /usr/local/opt/postgresql@14/bin ]]; then
  export PATH="/usr/local/opt/postgresql@14/bin:$PATH"
fi

# ── 4. Start PostgreSQL service ───────────────────────────────────────────────
if brew services list | grep postgresql@14 | grep -q "started"; then
  echo "[✓] PostgreSQL service already running"
else
  echo "[→] Starting PostgreSQL service..."
  brew services start postgresql@14
  echo "[✓] PostgreSQL service started (will auto-start on login)"
fi

# ── 5. Wait for PostgreSQL to be ready ───────────────────────────────────────
echo "[→] Waiting for PostgreSQL to accept connections..."
for i in $(seq 1 15); do
  if psql -U "$USER" -d postgres -c "SELECT 1" &>/dev/null; then
    echo "[✓] PostgreSQL accepting connections"
    break
  fi
  if [[ $i -eq 15 ]]; then
    echo "[✗] PostgreSQL not ready after 15s — check: brew services list"
    exit 1
  fi
  sleep 1
done

# ── 6. Create role ────────────────────────────────────────────────────────────
ROLE_EXISTS=$(psql -U "$USER" -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null || true)
if [[ "$ROLE_EXISTS" == "1" ]]; then
  echo "[✓] Role '$DB_USER' already exists — updating password"
  psql -U "$USER" -d postgres >/dev/null <<SQL
ALTER ROLE "$DB_USER" WITH LOGIN PASSWORD '$POSTGRES_PASSWORD';
SQL
else
  echo "[→] Creating role '$DB_USER'..."
  psql -U "$USER" -d postgres >/dev/null <<SQL
CREATE ROLE "$DB_USER" WITH LOGIN PASSWORD '$POSTGRES_PASSWORD';
SQL
  echo "[✓] Role '$DB_USER' created"
fi

# ── 7. Create database ────────────────────────────────────────────────────────
DB_EXISTS=$(psql -U "$USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null || true)
if [[ "$DB_EXISTS" == "1" ]]; then
  echo "[✓] Database '$DB_NAME' already exists"
else
  echo "[→] Creating database '$DB_NAME'..."
  psql -U "$USER" -d postgres -c "CREATE DATABASE \"$DB_NAME\" OWNER \"$DB_USER\";" >/dev/null
  echo "[✓] Database '$DB_NAME' created"
fi

# ── 8. Grant privileges ───────────────────────────────────────────────────────
psql -U "$USER" -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON DATABASE \"$DB_NAME\" TO \"$DB_USER\";" >/dev/null
psql -U "$USER" -d "$DB_NAME" -c "GRANT ALL ON SCHEMA public TO \"$DB_USER\";" >/dev/null
echo "[✓] Privileges granted"

# ── 9. Apply schema ───────────────────────────────────────────────────────────
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

# ── 10. Print connection string ───────────────────────────────────────────────
POSTGRES_URL="postgresql://${DB_USER}:${POSTGRES_PASSWORD}@localhost:${DB_PORT}/${DB_NAME}"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Add the following to your ~/.zshrc (or ~/.bashrc):"
echo ""
echo "  # SECURITY: Treat this URL as a secret — do not commit to version control."
echo "  export POSTGRES_URL=\"$POSTGRES_URL\""
echo ""
echo "  # Add PostgreSQL 14 to PATH (required for psql command)"
if [[ -d /opt/homebrew/opt/postgresql@14/bin ]]; then
  echo "  export PATH=\"/opt/homebrew/opt/postgresql@14/bin:\$PATH\""
elif [[ -d /usr/local/opt/postgresql@14/bin ]]; then
  echo "  export PATH=\"/usr/local/opt/postgresql@14/bin:\$PATH\""
fi
echo ""
echo "Then reload your shell:"
echo "  source ~/.zshrc"
echo ""
echo "Verify oneinfinity uses Postgres:"
echo "  oneinfinity doctor"
echo "  # Look for: [DBManager] Running in POSTGRES MODE"
echo ""
echo "PostgreSQL management commands:"
echo "  brew services start postgresql@14    # Start PostgreSQL"
echo "  brew services stop postgresql@14     # Stop PostgreSQL"
echo "  brew services restart postgresql@14  # Restart PostgreSQL"
echo "  brew services list                   # List all services"
echo ""
