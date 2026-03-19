#!/usr/bin/env bash
# ==============================================================
# OneInfinity Auto-Update Script
# Runs as a dedicated container (update-manager service) on
# a configurable cron schedule.
#
# What it updates:
#   1. Nuclei templates         (always — lightweight)
#   2. GF patterns              (always)
#   3. Community plugins        (if PLUGIN_DIR is mounted)
#   4. Container images         (if DOCKER_UPDATE=1)
#   5. Python packages          (if PKG_UPDATE=1)
#
# Environment variables:
#   UPDATE_SCHEDULE   Cron expression (default: "0 4 * * *" = 4 AM daily)
#   NUCLEI_UPDATE     1/0 — update Nuclei templates (default: 1)
#   GF_UPDATE         1/0 — update GF patterns (default: 1)
#   PLUGIN_UPDATE     1/0 — pull community plugin updates (default: 1)
#   DOCKER_UPDATE     1/0 — pull new container images (default: 0)
#   PKG_UPDATE        1/0 — upgrade Python packages (default: 0)
#   SLACK_WEBHOOK     Optional Slack webhook URL for update notifications
#   GITHUB_TOKEN      For authenticated GitHub API calls
# ==============================================================
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[update]${RESET} $(date '+%H:%M:%S') $*"; }
ok()      { echo -e "${GREEN}[update]${RESET} $(date '+%H:%M:%S') $*"; }
warn()    { echo -e "${YELLOW}[update]${RESET} $(date '+%H:%M:%S') $*"; }
section() { echo -e "\n${CYAN}══ $* ══${RESET}"; }

ONEINFINITY_HOME="${ONEINFINITY_HOME:-/data}"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES_PATH:-${ONEINFINITY_HOME}/.nuclei-templates}"
GF_PATTERNS="${GF_PATTERNS_DIR:-${HOME}/.gf}"
PLUGIN_DIR="${PLUGIN_DIR:-/app/plugins/community}"
UPDATE_LOG="${ONEINFINITY_HOME}/logs/auto-update.log"

mkdir -p "${ONEINFINITY_HOME}/logs"
exec > >(tee -a "${UPDATE_LOG}") 2>&1

UPDATED_COMPONENTS=()
FAILED_COMPONENTS=()

# ── Helper: notify Slack ──────────────────────────────────────
notify_slack() {
    local msg="$1"
    if [ -n "${SLACK_WEBHOOK:-}" ]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"[OneInfinity Update] ${msg}\"}" \
            "${SLACK_WEBHOOK}" > /dev/null 2>&1 || true
    fi
}

# ── 1. Nuclei templates ───────────────────────────────────────
update_nuclei() {
    section "Nuclei Templates"
    if ! command -v nuclei &>/dev/null; then
        warn "nuclei not found, skipping"
        return
    fi

    local before_count after_count
    before_count=$(find "${NUCLEI_TEMPLATES}" -name "*.yaml" 2>/dev/null | wc -l)

    if nuclei -update-templates \
              -update-template-dir "${NUCLEI_TEMPLATES}" \
              -timeout 120 2>&1 | grep -v "^$"; then

        after_count=$(find "${NUCLEI_TEMPLATES}" -name "*.yaml" 2>/dev/null | wc -l)
        local delta=$((after_count - before_count))
        ok "Nuclei templates updated: ${before_count} → ${after_count} (${delta:+${delta} new})"
        UPDATED_COMPONENTS+=("nuclei-templates:+${delta}")
    else
        warn "Nuclei template update failed (network issue?)"
        FAILED_COMPONENTS+=("nuclei-templates")
    fi
}

# ── 2. GF patterns ───────────────────────────────────────────
update_gf_patterns() {
    section "GF Patterns"
    if ! command -v git &>/dev/null; then
        warn "git not found, skipping GF patterns update"
        return
    fi

    mkdir -p "${GF_PATTERNS}"

    # 1Linkan/Bug-Bounty-Wordlists GF patterns
    local repos=(
        "https://github.com/tomnomnom/gf"
        "https://github.com/1ndianl33t/Gf-Patterns"
        "https://github.com/coffinxp/gf-patterns"
    )

    for repo in "${repos[@]}"; do
        local name
        name=$(basename "${repo}")
        local dest="${GF_PATTERNS}/.src/${name}"

        if [ -d "${dest}/.git" ]; then
            info "Updating ${name}…"
            git -C "${dest}" pull --quiet 2>&1 || warn "Failed to pull ${name}"
        else
            info "Cloning ${name}…"
            git clone --quiet --depth 1 "${repo}" "${dest}" 2>&1 || {
                warn "Failed to clone ${name}"
                continue
            }
        fi

        # Copy .json pattern files to GF patterns dir
        find "${dest}" -name "*.json" -exec cp -f {} "${GF_PATTERNS}/" \; 2>/dev/null
    done

    local pattern_count
    pattern_count=$(find "${GF_PATTERNS}" -name "*.json" 2>/dev/null | wc -l)
    ok "GF patterns: ${pattern_count} patterns available"
    UPDATED_COMPONENTS+=("gf-patterns:${pattern_count}")
}

# ── 3. Community plugins ──────────────────────────────────────
update_plugins() {
    section "Community Plugins"

    if [ ! -d "${PLUGIN_DIR}" ]; then
        info "No community plugin directory mounted at ${PLUGIN_DIR}, skipping"
        return
    fi

    local updated=0 failed=0

    # Each subdirectory with a .git folder is an updatable plugin
    while IFS= read -r plugin_git_dir; do
        local plugin_dir
        plugin_dir=$(dirname "${plugin_git_dir}")
        local plugin_name
        plugin_name=$(basename "${plugin_dir}")

        info "Updating plugin: ${plugin_name}"
        if git -C "${plugin_dir}" pull --quiet 2>&1; then
            # Reinstall plugin requirements if they changed
            if [ -f "${plugin_dir}/requirements.txt" ]; then
                pip install --quiet -r "${plugin_dir}/requirements.txt" 2>/dev/null || \
                    warn "  Failed to install ${plugin_name} requirements"
            fi
            ok "  ${plugin_name}: updated"
            ((updated++)) || true
        else
            warn "  ${plugin_name}: update failed"
            ((failed++)) || true
        fi
    done < <(find "${PLUGIN_DIR}" -name ".git" -type d 2>/dev/null)

    # Also check for a plugins.yaml registry file listing remote plugins
    local registry="${PLUGIN_DIR}/registry.yaml"
    if [ -f "${registry}" ]; then
        info "Processing plugin registry at ${registry}…"
        python3 /app/scripts/plugin-install.py --update --registry "${registry}" 2>/dev/null || \
            warn "Plugin registry update failed"
    fi

    ok "Plugins: ${updated} updated, ${failed} failed"
    UPDATED_COMPONENTS+=("plugins:${updated}")
}

# ── 4. Container images (optional) ───────────────────────────
update_containers() {
    section "Container Images"

    if [ "${DOCKER_UPDATE:-0}" != "1" ]; then
        info "DOCKER_UPDATE=0, skipping container image updates"
        return
    fi

    if ! command -v docker &>/dev/null; then
        warn "docker CLI not available (is /var/run/docker.sock mounted?)"
        return
    fi

    local images=(
        "ghcr.io/inf1n1tydes0ul/oneinfinity:latest"
        "ghcr.io/inf1n1tydes0ul/oneinfinity:latest-ai"
    )

    for img in "${images[@]}"; do
        info "Pulling ${img}…"
        if docker pull "${img}" 2>&1 | tail -1; then
            ok "${img}: up to date"
            UPDATED_COMPONENTS+=("image:${img##*/}")
        else
            warn "${img}: pull failed"
            FAILED_COMPONENTS+=("image:${img##*/}")
        fi
    done

    # Signal running containers to restart with new images
    # (Works with Watchtower or manual restart)
    docker ps --format '{{.Names}}' | grep "oneinfinity" | while read -r cname; do
        info "Container ${cname} may need restart for new image"
    done
}

# ── 5. Python package updates (optional) ─────────────────────
update_packages() {
    section "Python Packages"

    if [ "${PKG_UPDATE:-0}" != "1" ]; then
        info "PKG_UPDATE=0, skipping Python package updates"
        return
    fi

    info "Upgrading core Python packages…"
    pip install --quiet --upgrade \
        requests urllib3 beautifulsoup4 rich networkx \
        2>&1 | tail -5 || warn "Package upgrade partially failed"

    ok "Python packages upgraded"
    UPDATED_COMPONENTS+=("python-packages")
}

# ── 6. Version check and changelog ───────────────────────────
check_new_release() {
    section "Release Check"

    local api_url="https://api.github.com/repos/Inf1n1tyDeS0ul/oneinfinity/releases/latest"
    local auth_header=""
    [ -n "${GITHUB_TOKEN:-}" ] && auth_header="-H 'Authorization: token ${GITHUB_TOKEN}'"

    local latest_tag
    latest_tag=$(curl -sf ${auth_header} "${api_url}" 2>/dev/null | \
                 python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tag_name','unknown'))" \
                 2>/dev/null || echo "unknown")

    local current_version
    current_version=$(python3 /app/oneinfinity.py --version 2>/dev/null | head -1 || echo "unknown")

    info "Current version: ${current_version}"
    info "Latest release:  ${latest_tag}"

    if [ "${current_version}" != "${latest_tag}" ] && [ "${latest_tag}" != "unknown" ]; then
        warn "New version available: ${latest_tag}"
        notify_slack "New version available: ${latest_tag} (current: ${current_version}). Pull new image to upgrade."
    else
        ok "Up to date"
    fi
}

# ── Summary ───────────────────────────────────────────────────
print_summary() {
    section "Update Summary"
    echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Updated:   ${UPDATED_COMPONENTS[*]:-none}"
    echo "Failed:    ${FAILED_COMPONENTS[*]:-none}"

    if [ ${#FAILED_COMPONENTS[@]} -gt 0 ]; then
        notify_slack "Update completed with failures: ${FAILED_COMPONENTS[*]}"
    else
        notify_slack "Update completed successfully: ${UPDATED_COMPONENTS[*]}"
    fi
}

# ── Main ──────────────────────────────────────────────────────
main() {
    info "OneInfinity Auto-Update starting"
    info "Schedule: ${UPDATE_SCHEDULE:-0 4 * * *}"

    [ "${NUCLEI_UPDATE:-1}" = "1" ]  && update_nuclei
    [ "${GF_UPDATE:-1}" = "1" ]      && update_gf_patterns
    [ "${PLUGIN_UPDATE:-1}" = "1" ]  && update_plugins
    [ "${DOCKER_UPDATE:-0}" = "1" ]  && update_containers
    [ "${PKG_UPDATE:-0}" = "1" ]     && update_packages
    check_new_release
    print_summary

    ok "All updates complete"
}

# ── If run with --cron flag, start the cron daemon ───────────
if [ "${1:-}" = "--cron" ]; then
    SCHEDULE="${UPDATE_SCHEDULE:-0 4 * * *}"
    info "Running in cron mode — schedule: ${SCHEDULE}"

    # Install cron job
    echo "${SCHEDULE} /app/scripts/auto-update.sh >> ${ONEINFINITY_HOME}/logs/auto-update.log 2>&1" \
        | crontab -

    # Run once immediately on startup
    main

    # Start cron daemon in foreground
    exec crond -f -l 8
else
    main
fi
