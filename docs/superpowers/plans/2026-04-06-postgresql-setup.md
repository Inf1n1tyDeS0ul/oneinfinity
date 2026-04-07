# PostgreSQL Native Setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install native PostgreSQL on the local machine, create the oneinfinity database user and schema, and document the setup for GitHub users via a setup script and README section.

**Architecture:** A self-contained bash script (`scripts/setup_postgres.sh`) handles apt install, role/database creation, and schema application. `POSTGRES_URL` is added to `~/.bashrc` to activate Postgres mode in `core/db_manager.py`. README gets a new section pointing users to the script.

**Tech Stack:** PostgreSQL 16 (apt), psql CLI, bash, psycopg (already in requirements), existing `db/schema.sql` + `core/pg_client.py`.

---

### Task 1: Create `scripts/setup_postgres.sh`

**Files:**
- Create: `scripts/setup_postgres.sh`

- [ ] **Step 1: Create the script**

```bash
mkdir -p /home/devendra-yadav/oneinfinity/scripts
```

Write `scripts/setup_postgres.sh` with this exact content:

```bash
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
```

- [ ] **Step 2: Make it executable**

```bash
chmod +x scripts/setup_postgres.sh
```

- [ ] **Step 3: Verify the script syntax**

```bash
bash -n scripts/setup_postgres.sh
echo "Syntax OK"
```

Expected output: `Syntax OK`

- [ ] **Step 4: Commit the script**

```bash
git add scripts/setup_postgres.sh
git commit -m "feat(db): add native PostgreSQL setup script"
```

---

### Task 2: Run the script to install and configure PostgreSQL locally

**Files:** (no file changes — runtime step)

- [ ] **Step 1: Run the setup script**

```bash
cd /home/devendra-yadav/oneinfinity
bash scripts/setup_postgres.sh
```

Enter a password when prompted (or set `POSTGRES_PASSWORD=yourpass` beforehand).

Expected output (abridged):
```
=== OneInfinity PostgreSQL Setup ===
[→] Installing PostgreSQL...
[✓] PostgreSQL installed
[✓] PostgreSQL service started and enabled
[✓] Role 'oneinfinity' created
[✓] Database 'oneinfinity' created
[✓] Privileges granted
[✓] Schema applied
=== Setup Complete ===
export POSTGRES_URL="postgresql://oneinfinity:<password>@localhost:5432/oneinfinity"
```

- [ ] **Step 2: Add `POSTGRES_URL` to `~/.bashrc`**

```bash
echo 'export POSTGRES_URL="postgresql://oneinfinity:<your-password>@localhost:5432/oneinfinity"' >> ~/.bashrc
source ~/.bashrc
```

Replace `<your-password>` with the password you entered in Step 1.

- [ ] **Step 3: Verify PostgreSQL is accepting connections**

```bash
PGPASSWORD="<your-password>" psql -h localhost -U oneinfinity -d oneinfinity -c "\dt"
```

Expected: list of tables (`scans`, `findings`, `agents`, `events`, `knowledge_base`, `recon_assets`).

- [ ] **Step 4: Verify oneinfinity detects Postgres mode**

```bash
source ~/.bashrc
python3 -c "
import asyncio, logging
logging.basicConfig(level=logging.INFO)
from core.db_manager import get_db_manager
async def main():
    mgr = await get_db_manager()
    print('Mode:', mgr.mode)
asyncio.run(main())
"
```

Expected output contains: `[DBManager] Running in POSTGRES MODE` and `Mode: postgres`

---

### Task 3: Add PostgreSQL section to `README.md`

**Files:**
- Modify: `README.md` (after line 118, after the `---` that closes Quick Start)

- [ ] **Step 1: Insert the new section**

In `README.md`, find the `---` separator at line 118 (after the Native Python block) and insert the following section immediately after it:

```markdown
## 🗄️ PostgreSQL Setup (Optional — Recommended)

By default, OneInfinity stores findings in a local SQLite file (`~/.oneinfinity/findings.db`). This works well for solo use.

For **distributed scanning**, **persistent data across Docker restarts**, or running the **web dashboard with multiple workers**, switch to PostgreSQL.

### Native Install (Linux)

```bash
# From the repo root:
bash scripts/setup_postgres.sh
```

The script will:
- Install PostgreSQL via `apt` (skipped if already installed)
- Create an `oneinfinity` user and database
- Apply the schema (`db/schema.sql`)
- Print the `POSTGRES_URL` to add to your shell config

Then add to `~/.bashrc` (or `~/.zshrc`):

```bash
export POSTGRES_URL="postgresql://oneinfinity:<password>@localhost:5432/oneinfinity"
```

Reload your shell and verify:

```bash
source ~/.bashrc
oneinfinity doctor
# Look for: [DBManager] Running in POSTGRES MODE
```

### Docker

PostgreSQL is included in the `full` and `distributed` Docker Compose profiles — no manual setup needed:

```bash
docker compose --profile full up
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_URL` | unset | Full DSN — activates Postgres mode when set |
| `ONEINFINITY_STORAGE_MODE` | `auto` | Force mode: `postgres`, `sqlite`, `distributed`, `memory` |

> **Note:** If `POSTGRES_URL` is not set, the tool automatically falls back to SQLite. No data is lost — SQLite findings can be exported and imported into Postgres later.

---
```

- [ ] **Step 2: Verify README renders correctly**

```bash
# Quick sanity check — confirm section exists
grep -n "PostgreSQL Setup" README.md
grep -n "setup_postgres.sh" README.md
```

Expected: both lines found with correct line numbers.

- [ ] **Step 3: Commit the README update**

```bash
git add README.md
git commit -m "docs: add PostgreSQL setup section to README"
```

---

## Self-Review

**Spec coverage:**
- [x] `scripts/setup_postgres.sh` — Task 1
- [x] Local machine install & verify — Task 2
- [x] README PostgreSQL section — Task 3
- [x] Idempotent script — handled via `IF NOT EXISTS` checks in Task 1
- [x] `POSTGRES_URL` env var instructions — Task 2 Step 2 + Task 3
- [x] SQLite fallback note — Task 3 Step 1

**Placeholder scan:** No TBDs, TODOs, or vague steps. All code blocks are complete.

**Type consistency:** No shared types across tasks — bash script and README only.
