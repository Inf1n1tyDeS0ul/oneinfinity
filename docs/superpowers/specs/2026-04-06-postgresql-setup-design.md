# PostgreSQL Setup — Design Spec

**Date:** 2026-04-06  
**Status:** Approved

---

## Goal

Install and configure native PostgreSQL on the local machine for oneinfinity, and document the setup for GitHub users via a reusable setup script and README section.

## Approach

Option B: native `apt` install + `scripts/setup_postgres.sh` that doubles as documentation for GitHub users.

---

## Deliverables

### 1. `scripts/setup_postgres.sh`

Idempotent bash script. Safe to re-run. Covers:

- Detect if `postgresql` is already installed; install via `apt` if not
- Start and enable the `postgresql` systemd service
- Create PostgreSQL role `oneinfinity` if it does not exist (with a password read from `POSTGRES_PASSWORD` env var or a printed default)
- Create database `oneinfinity` owned by `oneinfinity` if it does not exist
- Apply `db/schema.sql` via `psql`
- Print the `POSTGRES_URL` string and instructions for adding it to `~/.bashrc`

Script outputs clear success/failure messages at each step. Exits on first unrecoverable error (`set -e`).

### 2. Local machine setup

Run `scripts/setup_postgres.sh` on the current machine (as part of implementation) to install and configure PostgreSQL and verify it connects via the tool.

### 3. `README.md` — PostgreSQL section

New section titled `## 🗄️ PostgreSQL Setup (Optional — Recommended for Power Users)` inserted after the Quick Start section. Contents:

- When to use Postgres vs SQLite (scale, persistence across Docker restarts, distributed workers)
- Single command: `bash scripts/setup_postgres.sh`
- Set `POSTGRES_URL` in shell config
- Verify: check log output for `[DBManager] Running in POSTGRES MODE`
- Note: SQLite remains the default when `POSTGRES_URL` is not set — no breakage for users who skip this

---

## Not In Scope

- `docker-compose.yml` — already has Postgres configured for `full`/`distributed` profiles
- `core/pg_client.py`, `core/db_manager.py`, `db/schema.sql` — no changes needed
- Makefile targets
- Alembic/migrations (schema is applied via raw SQL, idempotent `CREATE IF NOT EXISTS`)

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `POSTGRES_URL` | Yes (to activate Postgres mode) | unset | Full connection DSN |
| `POSTGRES_PASSWORD` | No | prompted/printed by script | Password for `oneinfinity` role |
| `ONEINFINITY_STORAGE_MODE` | No | `auto` | Force mode: `postgres`, `sqlite`, `distributed`, `memory` |

---

## Verification

After setup, run:
```bash
oneinfinity doctor
```
Log should contain: `[DBManager] Running in POSTGRES MODE`
