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

info "Redis connectivity will be verified by worker/main.py (built-in retry, 10 attempts × 3 s)"
# NOTE: nc/netcat is not available in python:slim images.
# worker/main.py._connect_redis() already retries 10× with 3 s backoff,
# so a duplicate shell-level wait-loop here is unnecessary and fragile.

# ── Ensure data dirs ──────────────────────────────────────────
mkdir -p "${ONEINFINITY_HOME:-/data}/raw" \
         "${NUCLEI_TEMPLATES_PATH:-/data/.nuclei-templates}"

# ── Nuclei template sync ──────────────────────────────────────
if [ "${NUCLEI_UPDATE:-1}" = "1" ] && command -v nuclei > /dev/null 2>&1; then
    TMPL_DIR="${NUCLEI_TEMPLATES_PATH:-/data/.nuclei-templates}"
    mkdir -p "${TMPL_DIR}"
    TEMPLATE_COUNT=$(find "${TMPL_DIR}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
    if [ ! -d "${TMPL_DIR}/http" ] || [ "${TEMPLATE_COUNT:-0}" -lt 100 ]; then
        info "Syncing Nuclei templates (count=${TEMPLATE_COUNT})…"
        nuclei -update-templates -update-template-dir "${TMPL_DIR}" \
               > /dev/null 2>&1 && ok "Templates synced" \
               || warn "Template sync failed (offline?)"
    else
        info "Nuclei templates present (${TEMPLATE_COUNT} templates, set NUCLEI_UPDATE=0 to skip)"
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
