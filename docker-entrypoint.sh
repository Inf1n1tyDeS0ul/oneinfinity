#!/usr/bin/env sh
# ==============================================================
# OneInfinity Docker Entrypoint
# Handles: first-run setup, nuclei template sync,
#          data directory initialisation, and CLI passthrough.
# ==============================================================
set -e

# ── Colour helpers ────────────────────────────────────────────
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
info()  { printf "${CYAN}[*]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${RESET} %s\n" "$*"; }
die()   { printf "${RED}[FATAL]${RESET} %s\n" "$*" >&2; exit 1; }

# ── Ensure data directory is writable ────────────────────────
# ONEINFINITY_HOME is set to /data in the Dockerfile.
# Users bind-mount a host directory to /data for persistence.
DATA_DIR="${ONEINFINITY_HOME:-/data}"
if ! mkdir -p "$DATA_DIR" 2>/dev/null; then
    warn "Cannot create $DATA_DIR — check volume mount permissions"
fi

# Ensure required subdirectories exist under data root
for sub in raw databases logs memory reports; do
    mkdir -p "$DATA_DIR/$sub" 2>/dev/null || true
done

# ── Nuclei template auto-update (first run or explicit flag) ──
# Controlled by NUCLEI_UPDATE env var (default: 1 = auto-update).
# Set NUCLEI_UPDATE=0 to skip (useful in air-gapped environments).
if [ "${NUCLEI_UPDATE:-1}" = "1" ]; then
    if command -v nuclei > /dev/null 2>&1; then
        TEMPLATES_DIR="$DATA_DIR/.nuclei-templates"

        # Create templates dir only if writable
        if mkdir -p "$TEMPLATES_DIR" 2>/dev/null; then
            # Check for healthy template tree: require the http/ subdir
            # (more reliable than counting yaml files — count varies by nuclei version)
            if [ ! -d "$TEMPLATES_DIR/http" ]; then
                info "Downloading Nuclei templates to $TEMPLATES_DIR ..."
                if nuclei -update-templates -update-template-dir "$TEMPLATES_DIR" \
                          > /dev/null 2>&1; then
                    TCOUNT=$(find "$TEMPLATES_DIR" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
                    info "Nuclei templates downloaded (${TCOUNT} files)"
                else
                    warn "Nuclei template update failed — using bundled templates if available"
                fi
            else
                TCOUNT=$(find "$TEMPLATES_DIR" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
                info "Nuclei templates present (${TCOUNT} templates)"
            fi
        else
            warn "Templates directory not writable: $TEMPLATES_DIR — skipping update"
        fi
    fi
fi

# ── Python path sanity check ─────────────────────────────────
# Verify that the main module is importable before handing off.
# Catches PYTHONPATH misconfigurations early rather than mid-scan.
if ! python -c "import oneinfinity" > /dev/null 2>&1; then
    # Not fatal — oneinfinity.py may be run directly; just warn
    warn "Module 'oneinfinity' not importable via PYTHONPATH — using direct path"
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
