#!/usr/bin/env sh
# ==============================================================
# OneInfinity Docker Entrypoint
# Handles: first-run setup, nuclei template sync,
#          data directory initialisation, and CLI passthrough.
# ==============================================================
set -e

# ── Colour helpers ────────────────────────────────────────────
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RESET='\033[0m'
info()  { printf "${CYAN}[*]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${RESET} %s\n" "$*"; }

# ── Ensure data directory exists ──────────────────────────────
# ONEINFINITY_HOME is set to /data in the Dockerfile.
# Users bind-mount a host directory to /data for persistence.
mkdir -p "${ONEINFINITY_HOME:-/data}"

# ── Nuclei template auto-update (first run or explicit flag) ──
# Controlled by NUCLEI_UPDATE env var (default: 1 = auto-update).
# Set NUCLEI_UPDATE=0 to skip (useful in air-gapped environments).
if [ "${NUCLEI_UPDATE:-1}" = "1" ]; then
    if command -v nuclei > /dev/null 2>&1; then
        TEMPLATES_DIR="${ONEINFINITY_HOME:-/data}/.nuclei-templates"
        if [ ! -d "$TEMPLATES_DIR" ]; then
            info "Downloading Nuclei templates (first run)..."
            nuclei -update-templates -update-template-dir "$TEMPLATES_DIR" \
                   > /dev/null 2>&1 || warn "Nuclei template update failed (offline?)"
        fi
    fi
fi

# ── Passthrough: if no arguments, show help ───────────────────
if [ $# -eq 0 ]; then
    exec python /app/oneinfinity.py --help
fi

# ── Special sub-command: shell ────────────────────────────────
# `docker run -it oneinfinity shell` drops into bash for debugging
if [ "$1" = "shell" ]; then
    exec /bin/bash
fi

# ── Special sub-command: toolcheck ───────────────────────────
# Shortcut preserved (also works as: docker run oneinfinity toolcheck)
exec python /app/oneinfinity.py "$@"
