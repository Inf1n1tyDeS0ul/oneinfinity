#!/usr/bin/env sh
# ==============================================================
# OneInfinity Worker Entrypoint
# Waits for Redis, syncs Nuclei templates, then starts worker.
# ==============================================================
set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
info()  { printf "${CYAN}[worker]${RESET} %s\n" "$*"; }
ok()    { printf "${GREEN}[worker]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[worker]${RESET} %s\n" "$*"; }
die()   { printf "${RED}[worker]${RESET} %s\n" "$*" >&2; exit 1; }

# ── Identity ─────────────────────────────────────────────────
info "ID:   ${WORKER_ID:-auto}"
info "Caps: ${WORKER_CAPABILITIES:-recon,vuln_scan,exploit}"
info "Redis: ${REDIS_URL:-redis://redis:6379/0}"

# ── Wait for Redis ─────────────────────────────────────────────
REDIS_HOST=$(echo "${REDIS_URL:-redis://redis:6379}" | sed 's|redis://||' | cut -d: -f1)
REDIS_PORT=$(echo "${REDIS_URL:-redis://redis:6379}" | sed 's|redis://||' | cut -d: -f2 | cut -d/ -f1)
REDIS_PORT=${REDIS_PORT:-6379}

info "Waiting for Redis at ${REDIS_HOST}:${REDIS_PORT}…"
RETRIES=30
while ! nc -z "${REDIS_HOST}" "${REDIS_PORT}" 2>/dev/null; do
    RETRIES=$((RETRIES - 1))
    if [ $RETRIES -le 0 ]; then
        die "Redis not reachable after 30 attempts"
    fi
    sleep 2
done
ok "Redis is up"

# ── Ensure data dirs ──────────────────────────────────────────
mkdir -p "${ONEINFINITY_HOME:-/data}/raw" \
         "${NUCLEI_TEMPLATES_PATH:-/data/.nuclei-templates}"

# ── Nuclei template sync ──────────────────────────────────────
if [ "${NUCLEI_UPDATE:-1}" = "1" ] && command -v nuclei > /dev/null 2>&1; then
    TMPL_DIR="${NUCLEI_TEMPLATES_PATH:-/data/.nuclei-templates}"
    if [ ! -d "${TMPL_DIR}/http" ]; then
        info "Syncing Nuclei templates (first run)…"
        nuclei -update-templates -update-template-dir "${TMPL_DIR}" \
               > /dev/null 2>&1 && ok "Templates synced" \
               || warn "Template sync failed (offline?)"
    else
        info "Nuclei templates present, skipping sync (set NUCLEI_UPDATE=0 to always skip)"
    fi
fi

# ── Plugin hot-reload setup ───────────────────────────────────
PLUGIN_DIR="/app/plugins"
if [ -d "${PLUGIN_DIR}" ]; then
    info "Plugin dir mounted at ${PLUGIN_DIR}"
    # Install any plugin requirements
    if [ -f "${PLUGIN_DIR}/requirements.txt" ]; then
        info "Installing plugin dependencies…"
        pip install --quiet -r "${PLUGIN_DIR}/requirements.txt" 2>/dev/null || \
            warn "Some plugin deps failed to install"
    fi
fi

# ── Passthrough ───────────────────────────────────────────────
if [ $# -eq 0 ] || [ "$1" = "worker" ]; then
    ok "Starting worker process…"
    exec python /app/worker/main.py
elif [ "$1" = "shell" ]; then
    exec /bin/bash
else
    exec python /app/oneinfinity.py "$@"
fi
