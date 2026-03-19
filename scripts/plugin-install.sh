#!/usr/bin/env bash
# ==============================================================
# OneInfinity Plugin Installer
#
# Installs, updates, removes, and lists plugins from:
#   - GitHub repos      (git clone)
#   - PyPI packages     (pip install)
#   - Local paths       (copy to plugin dir)
#   - Plugin registry   (registry.yaml)
#
# Usage:
#   plugin-install.sh install github.com/org/oi-plugin-ssrf
#   plugin-install.sh install pypi:oi-plugin-graphql
#   plugin-install.sh update
#   plugin-install.sh remove oi-plugin-ssrf
#   plugin-install.sh list
# ==============================================================
set -euo pipefail

PLUGIN_DIR="${PLUGIN_DIR:-/app/plugins/community}"
ONEINFINITY_HOME="${ONEINFINITY_HOME:-/data}"
REGISTRY_FILE="${PLUGIN_DIR}/registry.yaml"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
info() { echo -e "${CYAN}[plugins]${RESET} $*"; }
ok()   { echo -e "${GREEN}[plugins]${RESET} $*"; }
warn() { echo -e "${YELLOW}[plugins]${RESET} $*"; }
die()  { echo -e "${RED}[plugins]${RESET} $*" >&2; exit 1; }

mkdir -p "${PLUGIN_DIR}"

# ── Validate plugin structure ─────────────────────────────────
validate_plugin() {
    local dir="$1"
    local name
    name=$(basename "${dir}")

    # Must have plugin.py or __init__.py
    if [ ! -f "${dir}/plugin.py" ] && [ ! -f "${dir}/__init__.py" ]; then
        warn "  ${name}: missing plugin.py or __init__.py"
        return 1
    fi

    # Must have PLUGIN_META defined
    if ! python3 -c "
import sys; sys.path.insert(0,'${dir}')
try:
    import importlib.util, os
    spec = importlib.util.spec_from_file_location('p',
        '${dir}/plugin.py' if os.path.exists('${dir}/plugin.py') else '${dir}/__init__.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert hasattr(m, 'PLUGIN_META'), 'No PLUGIN_META'
    assert hasattr(m, 'Plugin'), 'No Plugin class'
    print('  type:', m.PLUGIN_META.get('type','unknown'))
    print('  version:', m.PLUGIN_META.get('version','?'))
except Exception as e:
    print('INVALID:', e, file=sys.stderr)
    sys.exit(1)
" 2>&1; then
        warn "  ${name}: validation failed"
        return 1
    fi

    return 0
}

# ── Register plugin in registry.yaml ─────────────────────────
register_plugin() {
    local name="$1" source="$2" type="${3:-unknown}"
    local entry="- name: ${name}\n  source: ${source}\n  type: ${type}\n  installed_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

    if [ ! -f "${REGISTRY_FILE}" ]; then
        echo "plugins:" > "${REGISTRY_FILE}"
    fi

    # Remove existing entry for this plugin name (avoid duplicates)
    python3 -c "
import yaml, sys
with open('${REGISTRY_FILE}') as f:
    data = yaml.safe_load(f) or {'plugins': []}
data['plugins'] = [p for p in data.get('plugins', []) if p.get('name') != '${name}']
data['plugins'].append({'name': '${name}', 'source': '${source}', 'type': '${type}',
    'installed_at': '$(date -u +%Y-%m-%dT%H:%M:%SZ)'})
with open('${REGISTRY_FILE}', 'w') as f:
    yaml.dump(data, f, default_flow_style=False)
" 2>/dev/null || echo -e "${entry}" >> "${REGISTRY_FILE}"
}

# ── Reload plugin registry in running OneInfinity ─────────────
reload_registry() {
    local api_url="http://${ORCHESTRATOR_HOST:-orchestrator}:${ORCHESTRATOR_PORT:-8000}/api/plugins/reload"
    if curl -sf -X POST \
            -H "X-API-Key: ${ONEINFINITY_API_KEY:-}" \
            "${api_url}" > /dev/null 2>&1; then
        ok "Plugin registry reloaded in running instance"
    else
        info "Could not auto-reload (orchestrator not running or API key missing)"
        info "Restart the orchestrator to load new plugins"
    fi
}

# ── Install from GitHub ───────────────────────────────────────
install_github() {
    local repo="$1"
    # Normalise: allow github.com/org/repo or org/repo
    repo="${repo#https://github.com/}"
    repo="${repo#github.com/}"
    local name
    name=$(echo "${repo}" | cut -d/ -f2)
    local dest="${PLUGIN_DIR}/${name}"

    info "Installing ${name} from github.com/${repo}…"

    if [ -d "${dest}/.git" ]; then
        info "  Already installed — updating"
        git -C "${dest}" pull --quiet
    else
        git clone --quiet --depth 1 "https://github.com/${repo}.git" "${dest}"
    fi

    # Install plugin dependencies
    if [ -f "${dest}/requirements.txt" ]; then
        info "  Installing plugin requirements…"
        pip install --quiet -r "${dest}/requirements.txt"
    fi

    # Validate
    if validate_plugin "${dest}"; then
        register_plugin "${name}" "github:${repo}" "auto"
        ok "${name} installed successfully"
        reload_registry
    else
        rm -rf "${dest}"
        die "${name}: plugin validation failed — installation rolled back"
    fi
}

# ── Install from PyPI ─────────────────────────────────────────
install_pypi() {
    local package="${1#pypi:}"
    local name="${package}"
    info "Installing ${name} from PyPI…"

    if pip install --quiet "${package}"; then
        # PyPI plugins install themselves into the Python path
        # No need to copy to PLUGIN_DIR, but register them
        register_plugin "${name}" "pypi:${package}" "pypi"
        ok "${name} installed from PyPI"
        reload_registry
    else
        die "Failed to install ${name} from PyPI"
    fi
}

# ── Install from local path ───────────────────────────────────
install_local() {
    local src="$1"
    local name
    name=$(basename "${src}")
    local dest="${PLUGIN_DIR}/${name}"

    info "Installing ${name} from local path ${src}…"
    cp -r "${src}" "${dest}"

    if [ -f "${dest}/requirements.txt" ]; then
        pip install --quiet -r "${dest}/requirements.txt"
    fi

    if validate_plugin "${dest}"; then
        register_plugin "${name}" "local:${src}" "auto"
        ok "${name} installed from local path"
        reload_registry
    else
        rm -rf "${dest}"
        die "${name}: validation failed"
    fi
}

# ── Remove plugin ─────────────────────────────────────────────
remove_plugin() {
    local name="$1"
    local dest="${PLUGIN_DIR}/${name}"

    if [ ! -d "${dest}" ]; then
        die "Plugin '${name}' not found at ${dest}"
    fi

    rm -rf "${dest}"

    # Remove from registry
    python3 -c "
import yaml
with open('${REGISTRY_FILE}') as f:
    data = yaml.safe_load(f) or {'plugins': []}
data['plugins'] = [p for p in data.get('plugins', []) if p.get('name') != '${name}']
with open('${REGISTRY_FILE}', 'w') as f:
    yaml.dump(data, f, default_flow_style=False)
" 2>/dev/null || true

    ok "Plugin '${name}' removed"
    reload_registry
}

# ── List plugins ──────────────────────────────────────────────
list_plugins() {
    info "Installed plugins:"
    printf "%-30s %-10s %-40s %s\n" "NAME" "TYPE" "SOURCE" "STATUS"
    printf "%-30s %-10s %-40s %s\n" "────" "────" "──────" "──────"

    local found=0
    while IFS= read -r plugin_dir; do
        local name
        name=$(basename "${plugin_dir}")
        local status="✓ valid"
        validate_plugin "${plugin_dir}" 2>/dev/null || status="✗ invalid"

        # Get source from registry
        local source="unknown"
        if [ -f "${REGISTRY_FILE}" ]; then
            source=$(python3 -c "
import yaml
with open('${REGISTRY_FILE}') as f:
    data = yaml.safe_load(f) or {}
plugins = data.get('plugins', [])
p = next((p for p in plugins if p.get('name') == '${name}'), {})
print(p.get('source', 'unknown'))
" 2>/dev/null || echo "unknown")
        fi

        printf "%-30s %-10s %-40s %s\n" "${name}" "dir" "${source}" "${status}"
        ((found++)) || true
    done < <(find "${PLUGIN_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)

    if [ ${found} -eq 0 ]; then
        echo "  (no plugins installed)"
    fi
    echo ""
    info "Plugin directory: ${PLUGIN_DIR}"
}

# ── Update all installed plugins ─────────────────────────────
update_all() {
    info "Updating all installed plugins…"
    local updated=0 failed=0

    while IFS= read -r plugin_dir; do
        local name
        name=$(basename "${plugin_dir}")
        if [ -d "${plugin_dir}/.git" ]; then
            info "Updating ${name}…"
            git -C "${plugin_dir}" pull --quiet && ok "  ${name}: updated" && ((updated++)) || \
                { warn "  ${name}: update failed"; ((failed++)) || true; }
        fi
    done < <(find "${PLUGIN_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)

    ok "Update complete: ${updated} updated, ${failed} failed"
    [ ${updated} -gt 0 ] && reload_registry
}

# ── Main dispatch ─────────────────────────────────────────────
CMD="${1:-list}"
shift || true

case "${CMD}" in
    install)
        TARGET="${1:-}"
        [ -z "${TARGET}" ] && die "Usage: plugin-install.sh install <github:org/repo|pypi:pkg|/local/path>"
        if echo "${TARGET}" | grep -q "^pypi:"; then
            install_pypi "${TARGET}"
        elif [ -d "${TARGET}" ]; then
            install_local "${TARGET}"
        else
            install_github "${TARGET}"
        fi
        ;;
    remove|uninstall)
        remove_plugin "${1:-}"
        ;;
    update)
        update_all
        ;;
    list|ls)
        list_plugins
        ;;
    validate)
        validate_plugin "${1:-}" && ok "Plugin valid" || die "Plugin invalid"
        ;;
    *)
        echo "Usage: plugin-install.sh <install|remove|update|list|validate> [args]"
        exit 1
        ;;
esac
