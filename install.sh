#!/usr/bin/env bash
# ============================================================================
# OneInfinity — Master One-Click Installer / Updater
# https://github.com/Inf1n1tyDeS0ul/oneinfinity
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Inf1n1tyDeS0ul/oneinfinity/main/install.sh | bash
#   OR: bash install.sh [--no-docker] [--skip-tools] [--update-only] [--help]
#
# Supports: macOS 12+ (arm64/x86_64), Ubuntu 20.04+, Debian 11+, Kali Linux,
#           Fedora 36+, RHEL/CentOS 8+, Arch Linux
# ============================================================================

set -uo pipefail

# ============================================================================
# SECTION 3 — Color definitions and logging functions
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Ensure log dir exists before any logging (may be overridden later)
_ensure_log() {
    if [[ -n "${ONEINFINITY_LOG:-}" ]]; then
        mkdir -p "$(dirname "$ONEINFINITY_LOG")" 2>/dev/null || true
        touch "$ONEINFINITY_LOG" 2>/dev/null || true
    fi
}

_log_to_file() {
    if [[ -n "${ONEINFINITY_LOG:-}" ]]; then
        echo "$*" >> "$ONEINFINITY_LOG" 2>/dev/null || true
    fi
}

ok() {
    local msg="[OK] $*"
    printf "${GREEN}${BOLD}✔${NC}  ${GREEN}%s${NC}\n" "$*"
    _log_to_file "$msg"
}

info() {
    local msg="[INFO] $*"
    printf "${CYAN}ℹ${NC}  %s\n" "$*"
    _log_to_file "$msg"
}

warn() {
    local msg="[WARN] $*"
    printf "${YELLOW}${BOLD}⚠${NC}  ${YELLOW}%s${NC}\n" "$*" >&2
    _log_to_file "$msg"
}

err() {
    local msg="[ERROR] $*"
    printf "${RED}${BOLD}✖${NC}  ${RED}%s${NC}\n" "$*" >&2
    _log_to_file "$msg"
}

section() {
    local line="════════════════════════════════════════════════════════════════════════════"
    printf "\n${BOLD}${CYAN}%s${NC}\n" "$line"
    printf "${BOLD}${CYAN}  ❯ %s${NC}\n" "$*"
    printf "${BOLD}${CYAN}%s${NC}\n\n" "$line"
    _log_to_file ""
    _log_to_file "=== $* ==="
}

banner() {
    printf "${BOLD}${CYAN}"
    cat <<'BANNER'

  ██████╗ ███╗   ██╗███████╗    ██╗███╗   ██╗███████╗██╗███╗   ██╗██╗████████╗██╗   ██╗
 ██╔═══██╗████╗  ██║██╔════╝    ██║████╗  ██║██╔════╝██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝
 ██║   ██║██╔██╗ ██║█████╗      ██║██╔██╗ ██║█████╗  ██║██╔██╗ ██║██║   ██║    ╚████╔╝
 ██║   ██║██║╚██╗██║██╔══╝      ██║██║╚██╗██║██╔══╝  ██║██║╚██╗██║██║   ██║     ╚██╔╝
 ╚██████╔╝██║ ╚████║███████╗    ██║██║ ╚████║██║     ██║██║ ╚████║██║   ██║      ██║
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝

                        Master One-Click Installer v2.0.0
               https://github.com/Inf1n1tyDeS0ul/oneinfinity
BANNER
    printf "${NC}\n"
    _log_to_file "OneInfinity installer started at $(date)"
}

step() {
    printf "  ${BOLD}→${NC}  %s ... " "$*"
    _log_to_file "[STEP] $*"
}

ask_user() {
    # ask_user <variable_name> <prompt> [default]
    local varname="$1"
    local prompt="$2"
    local default="${3:-}"

    if [[ "${NON_INTERACTIVE:-0}" -eq 1 ]]; then
        printf -v "$varname" '%s' "$default"
        return 0
    fi

    local answer
    if [[ -n "$default" ]]; then
        printf "${BOLD}%s${NC} [%s]: " "$prompt" "$default"
    else
        printf "${BOLD}%s${NC}: " "$prompt"
    fi
    read -r answer
    if [[ -z "$answer" && -n "$default" ]]; then
        answer="$default"
    fi
    printf -v "$varname" '%s' "$answer"
}

# ============================================================================
# SECTION 5 — Global constants
# ============================================================================

OI_VERSION="2.0.0"
OI_REPO="https://github.com/Inf1n1tyDeS0ul/oneinfinity"
ONEINFINITY_HOME="${ONEINFINITY_HOME:-$HOME/.oneinfinity}"
OI_DEFAULT_INSTALL_DIR="$HOME/oneinfinity"
ONEINFINITY_LOG="$ONEINFINITY_HOME/install.log"

PG_USER="oneinfinity"
PG_PASS="oneinfinity123"
PG_DB="oneinfinity"
PG_PORT=5432

REDIS_PASS="oneinfinity_redis"
REDIS_PORT=6379

NEO4J_USER="neo4j"
NEO4J_PASS="neo4j123"
NEO4J_BOLT=7687
NEO4J_HTTP=7474

MOBSF_PORT=8008
WEB_BACKEND_PORT=8000
WEB_FRONTEND_PORT=3000

# Runtime state (populated by detect_os / detect_install_mode)
OS=""
ARCH=""
IS_MAC=false
IS_LINUX=false
PKG_MGR=""
PKG_UPDATE=""
PKG_INSTALL=""
DISTRO=""
OS_TYPE=""
DISTRO_FAMILY=""
INSTALL_MODE=""
REPO_DIR=""

# ============================================================================
# SECTION 4 — Argument parsing
# ============================================================================

NO_DOCKER=0
SKIP_TOOLS=0
SKIP_DB=0
UPDATE_ONLY=0
NON_INTERACTIVE=0

_usage() {
    cat <<EOF
${BOLD}OneInfinity Installer v${OI_VERSION}${NC}

Usage: bash install.sh [OPTIONS]

Options:
  --no-docker         Skip Docker-based services (PostgreSQL, Redis, Neo4j, MobSF)
  --skip-tools        Skip offensive tool installations
  --skip-db           Skip database initialisation steps
  --update-only       Run in update mode even if no .git dir is detected
  --non-interactive   Suppress all prompts; use defaults
  --help              Show this help and exit

Examples:
  bash install.sh
  bash install.sh --update-only
  bash install.sh --no-docker --skip-tools
EOF
}

_parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --no-docker)       NO_DOCKER=1 ;;
            --skip-tools)      SKIP_TOOLS=1 ;;
            --skip-db)         SKIP_DB=1 ;;
            --update-only)     UPDATE_ONLY=1 ;;
            --non-interactive) NON_INTERACTIVE=1 ;;
            --help|-h)
                _usage
                exit 0
                ;;
            *)
                warn "Unknown flag: $1 (ignored)"
                ;;
        esac
        shift
    done
}

# ============================================================================
# SECTION 6 — OS detection
# ============================================================================

detect_os() {
    section "Detecting operating system"

    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Darwin)
            IS_MAC=true
            IS_LINUX=false
            DISTRO="macos"
            PKG_MGR="brew"
            PKG_UPDATE="brew update"
            PKG_INSTALL="brew install"

            # Verify Homebrew is available; prompt to install if missing
            if ! command -v brew &>/dev/null; then
                warn "Homebrew not found. Installing Homebrew..."
                step "Installing Homebrew"
                if /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; then
                    # Add brew to PATH for the current shell session (Apple Silicon vs Intel)
                    if [[ "$ARCH" == "arm64" ]]; then
                        eval "$(/opt/homebrew/bin/brew shellenv)" || true
                    else
                        eval "$(/usr/local/bin/brew shellenv)" || true
                    fi
                    ok "Homebrew installed"
                else
                    err "Failed to install Homebrew. Please install it manually: https://brew.sh"
                    exit 1
                fi
            fi

            # Check macOS version (require 12+)
            local osx_ver
            osx_ver="$(sw_vers -productVersion 2>/dev/null || echo "0.0")"
            local osx_major
            osx_major="${osx_ver%%.*}"
            if [[ "$osx_major" -lt 12 ]]; then
                warn "macOS ${osx_ver} detected. OneInfinity requires macOS 12+. Proceeding anyway..."
            fi

            ok "macOS ${osx_ver} (${ARCH})"
            ;;

        Linux)
            IS_MAC=false
            IS_LINUX=true

            if [[ -f /etc/os-release ]]; then
                # shellcheck source=/dev/null
                source /etc/os-release
                local os_id="${ID:-unknown}"
                local os_id_like="${ID_LIKE:-}"

                case "$os_id" in
                    ubuntu|debian)
                        DISTRO="$os_id"
                        PKG_MGR="apt-get"
                        PKG_UPDATE="apt-get update -qq"
                        PKG_INSTALL="apt-get install -y -qq"
                        ;;
                    kali)
                        DISTRO="kali"
                        PKG_MGR="apt-get"
                        PKG_UPDATE="apt-get update -qq"
                        PKG_INSTALL="apt-get install -y -qq"
                        ;;
                    fedora)
                        DISTRO="fedora"
                        PKG_MGR="dnf"
                        PKG_UPDATE="dnf check-update -q || true"
                        PKG_INSTALL="dnf install -y -q"
                        ;;
                    rhel|centos|rocky|almalinux)
                        DISTRO="rhel"
                        PKG_MGR="dnf"
                        PKG_UPDATE="dnf check-update -q || true"
                        PKG_INSTALL="dnf install -y -q"
                        ;;
                    arch|manjaro|endeavouros)
                        DISTRO="arch"
                        PKG_MGR="pacman"
                        PKG_UPDATE="pacman -Sy --noconfirm"
                        PKG_INSTALL="pacman -S --noconfirm --needed"
                        ;;
                    *)
                        # Fallback: check ID_LIKE
                        case "$os_id_like" in
                            *debian*|*ubuntu*)
                                DISTRO="debian"
                                PKG_MGR="apt-get"
                                PKG_UPDATE="apt-get update -qq"
                                PKG_INSTALL="apt-get install -y -qq"
                                ;;
                            *fedora*|*rhel*)
                                DISTRO="fedora"
                                PKG_MGR="dnf"
                                PKG_UPDATE="dnf check-update -q || true"
                                PKG_INSTALL="dnf install -y -q"
                                ;;
                            *arch*)
                                DISTRO="arch"
                                PKG_MGR="pacman"
                                PKG_UPDATE="pacman -Sy --noconfirm"
                                PKG_INSTALL="pacman -S --noconfirm --needed"
                                ;;
                            *)
                                err "Unsupported Linux distribution: ${os_id}. Supported: Ubuntu, Debian, Kali, Fedora, RHEL/CentOS, Arch."
                                exit 1
                                ;;
                        esac
                        ;;
                esac
                ok "Linux/${DISTRO} (${ARCH}) — package manager: ${PKG_MGR}"
            else
                err "/etc/os-release not found. Cannot determine Linux distribution."
                exit 1
            fi
            ;;

        *)
            err "Unsupported OS: ${OS}. OneInfinity supports macOS and Linux only."
            exit 1
            ;;
    esac

    # Set OS_TYPE and DISTRO_FAMILY used by install_system_deps and downstream sections
    if $IS_MAC; then
        OS_TYPE="macos"
        DISTRO_FAMILY="macos"
    else
        OS_TYPE="$DISTRO"  # ubuntu | debian | kali | fedora | rhel | arch
        case "$DISTRO" in
            ubuntu|debian|kali) DISTRO_FAMILY="debian" ;;
            fedora|rhel|centos) DISTRO_FAMILY="redhat" ;;
            arch)               DISTRO_FAMILY="arch"   ;;
            *)                  DISTRO_FAMILY="$DISTRO" ;;
        esac
    fi
    _log_to_file "OS=${OS} ARCH=${ARCH} DISTRO=${DISTRO} OS_TYPE=${OS_TYPE} DISTRO_FAMILY=${DISTRO_FAMILY} PKG_MGR=${PKG_MGR}"
}

# ============================================================================
# SECTION 7 — Update vs fresh install detection
# ============================================================================

detect_install_mode() {
    section "Detecting install mode"

    # --update-only flag forces UPDATE mode regardless of directory state
    if [[ "$UPDATE_ONLY" -eq 1 ]]; then
        INSTALL_MODE="update"
        # Resolve REPO_DIR: prefer current dir if it looks like the repo, else default
        if [[ -f "$PWD/pyproject.toml" ]] && grep -q "oneinfinity" "$PWD/pyproject.toml" 2>/dev/null; then
            REPO_DIR="$(cd "$PWD" && pwd)"
        elif [[ -d "$OI_DEFAULT_INSTALL_DIR" ]]; then
            REPO_DIR="$(cd "$OI_DEFAULT_INSTALL_DIR" && pwd)"
        else
            err "--update-only specified but no existing OneInfinity installation found at $OI_DEFAULT_INSTALL_DIR or current directory."
            exit 1
        fi
        info "Mode: UPDATE (forced via --update-only) — $REPO_DIR"
        _log_to_file "INSTALL_MODE=update REPO_DIR=$REPO_DIR (forced)"
        return 0
    fi

    # Auto-detect: check current working directory first, then default install dir
    local candidate_dirs=("$PWD" "$OI_DEFAULT_INSTALL_DIR")
    local detected_repo=""

    for candidate in "${candidate_dirs[@]}"; do
        if [[ -d "$candidate/.git" ]]; then
            local remote_url
            remote_url="$(git -C "$candidate" remote get-url origin 2>/dev/null || echo "")"
            if echo "$remote_url" | grep -qi "Inf1n1tyDeS0ul/oneinfinity"; then
                detected_repo="$(cd "$candidate" && pwd)"
                break
            fi
        fi
    done

    if [[ -n "$detected_repo" ]]; then
        INSTALL_MODE="update"
        REPO_DIR="$detected_repo"
        info "Mode: UPDATE — existing repo found at $REPO_DIR"
        _log_to_file "INSTALL_MODE=update REPO_DIR=$REPO_DIR"
    else
        INSTALL_MODE="fresh"
        REPO_DIR="$OI_DEFAULT_INSTALL_DIR"
        info "Mode: FRESH INSTALL — will clone into $REPO_DIR"
        _log_to_file "INSTALL_MODE=fresh REPO_DIR=$REPO_DIR"
    fi
}

# ============================================================================
# SECTION 8 — Preflight checks
# ============================================================================

preflight_checks() {
    section "Preflight checks"

    # --- Root warning (don't fail; CI pipelines often run as root) ---
    if [[ "$(id -u)" -eq 0 ]]; then
        warn "Running as root. This is not recommended for a user installation."
        warn "Press Ctrl-C within 5 seconds to abort, or wait to continue..."
        sleep 5
    fi

    # --- Minimum RAM: 4 GB ---
    local ram_kb=0
    if $IS_MAC; then
        ram_kb=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 ))
    elif $IS_LINUX; then
        ram_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
    fi
    local ram_gb=$(( ram_kb / 1024 / 1024 ))
    if [[ "$ram_kb" -gt 0 && "$ram_gb" -lt 4 ]]; then
        warn "Only ~${ram_gb}GB RAM detected. 4GB minimum recommended. Proceeding anyway..."
    else
        ok "RAM: ~${ram_gb}GB"
    fi

    # --- Disk space: 10 GB free ---
    local free_kb=0
    local check_path="${HOME}"
    if $IS_MAC; then
        free_kb=$(df -k "$check_path" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    else
        free_kb=$(df -k "$check_path" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    fi
    local free_gb=$(( free_kb / 1024 / 1024 ))
    if [[ "$free_kb" -gt 0 && "$free_gb" -lt 10 ]]; then
        warn "Only ~${free_gb}GB free disk space detected. 10GB minimum recommended. Proceeding anyway..."
    else
        ok "Disk space: ~${free_gb}GB free"
    fi

    # --- Internet connectivity ---
    step "Checking internet connectivity"
    if curl -fsSL --max-time 10 https://github.com &>/dev/null; then
        printf "${GREEN}ok${NC}\n"
        ok "Internet: reachable"
    else
        printf "${RED}FAIL${NC}\n"
        err "Cannot reach github.com. Please check your internet connection."
        exit 1
    fi

    # --- macOS version check (already done in detect_os; repeated here for report) ---
    if $IS_MAC; then
        local osx_ver
        osx_ver="$(sw_vers -productVersion 2>/dev/null || echo "unknown")"
        ok "macOS version: ${osx_ver}"
    fi

    # --- Report what will be installed ---
    info "──────────────────────────────────────────"
    info "  Install plan:"
    info "    Mode         : ${INSTALL_MODE}"
    info "    Target dir   : ${REPO_DIR}"
    info "    Docker svcs  : $([ "$NO_DOCKER" -eq 0 ] && echo "PostgreSQL, Redis, Neo4j, MobSF" || echo "SKIPPED")"
    info "    Offensive tools: $([ "$SKIP_TOOLS" -eq 0 ] && echo "YES" || echo "SKIPPED")"
    info "    Database init: $([ "$SKIP_DB" -eq 0 ] && echo "YES" || echo "SKIPPED")"
    info "──────────────────────────────────────────"
    _log_to_file "Preflight checks passed"
}

# ============================================================================
# SECTION 10 — clone_or_setup_repo()
# ============================================================================

clone_or_setup_repo() {
    section "Repository setup"

    if [[ "$INSTALL_MODE" == "fresh" ]]; then
        if [[ -d "$REPO_DIR" ]]; then
            warn "Target directory $REPO_DIR already exists."
            if [[ "$NON_INTERACTIVE" -eq 0 ]]; then
                ask_user _overwrite "Remove and re-clone? [y/N]" "N"
                if [[ "$_overwrite" =~ ^[Yy]$ ]]; then
                    step "Removing existing directory"
                    rm -rf "$REPO_DIR"
                    printf "${GREEN}ok${NC}\n"
                else
                    err "Aborting. Remove $REPO_DIR manually or use --update-only."
                    exit 1
                fi
            else
                warn "Non-interactive mode: removing existing $REPO_DIR"
                rm -rf "$REPO_DIR"
            fi
        fi

        step "Cloning OneInfinity repository"
        if git clone --depth=1 "$OI_REPO" "$REPO_DIR" 2>&1 | tee -a "${ONEINFINITY_LOG:-/dev/null}" | grep -E "(Cloning|done\.|error)" >&2; then
            printf "${GREEN}ok${NC}\n"
            ok "Cloned into $REPO_DIR"
        else
            printf "${RED}FAIL${NC}\n"
            err "Failed to clone $OI_REPO"
            exit 1
        fi
    fi

    # Resolve to absolute path and cd into repo
    if [[ ! -d "$REPO_DIR" ]]; then
        err "Repository directory $REPO_DIR does not exist after clone."
        exit 1
    fi

    REPO_DIR="$(cd "$REPO_DIR" && pwd)"
    cd "$REPO_DIR"
    ok "Working directory: $REPO_DIR"
    _log_to_file "REPO_DIR resolved to $REPO_DIR"
}

# ============================================================================
# SECTION 11 — update_repo()
# ============================================================================

update_repo() {
    section "Updating repository"

    if [[ ! -d "$REPO_DIR" ]]; then
        err "REPO_DIR ($REPO_DIR) does not exist. Cannot update."
        exit 1
    fi

    cd "$REPO_DIR"

    # Stash any local modifications so pull doesn't fail
    local stashed=false
    if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
        warn "Local changes detected. Stashing before pull..."
        if git stash push -m "oneinfinity-installer-autostash-$(date +%s)"; then
            stashed=true
            ok "Changes stashed"
        else
            warn "Could not stash changes. Proceeding with pull anyway..."
        fi
    fi

    step "Fetching from origin"
    if git fetch origin 2>&1 | tee -a "${ONEINFINITY_LOG:-/dev/null}" >/dev/null; then
        printf "${GREEN}ok${NC}\n"
    else
        printf "${YELLOW}warn${NC}\n"
        warn "git fetch returned non-zero; continuing..."
    fi

    step "Pulling origin/main"
    if git pull origin main 2>&1 | tee -a "${ONEINFINITY_LOG:-/dev/null}" >/dev/null; then
        printf "${GREEN}ok${NC}\n"
        ok "Repository updated to latest main"
    else
        printf "${RED}FAIL${NC}\n"
        err "git pull failed. Check $ONEINFINITY_LOG for details."
        if $stashed; then
            warn "Restoring stash..."
            git stash pop || warn "Could not restore stash. Run: git stash pop"
        fi
        exit 1
    fi

    if $stashed; then
        step "Restoring stashed changes"
        if git stash pop 2>/dev/null; then
            printf "${GREEN}ok${NC}\n"
        else
            printf "${YELLOW}skipped${NC}\n"
            warn "Could not restore stash automatically. Run: git stash pop"
        fi
    fi

    REPO_DIR="$(cd "$REPO_DIR" && pwd)"
    _log_to_file "Repository updated: $REPO_DIR"
}

# ============================================================================
# SECTION 9 — do_update() / do_fresh_install() / main()
# (Stub implementations — called here; actual section logic lives in B–J)
# ============================================================================



# ============================================================================
# SECTION B — Language Runtime Installation
# ============================================================================
# section_B_runtimes.sh — Language Runtime Installation
# Part of OneInfinity installer. Sourced by install.sh.
# Requires: ok() warn() err() info() section() banner() step() functions,
#           $ONEINFINITY_LOG, $REPO_DIR, $OS_TYPE, $PKG_MGR variables from scaffold.

# ---------------------------------------------------------------------------
# install_system_deps
# ---------------------------------------------------------------------------
install_system_deps() {
    section "System Dependencies"

    if [[ "$OS_TYPE" == "macos" ]]; then
        # ── Xcode CLI tools ────────────────────────────────────────────────
        if ! xcode-select -p &>/dev/null; then
            step "Installing Xcode Command Line Tools…"
            xcode-select --install 2>>"$ONEINFINITY_LOG" || true
            # Wait for the install to complete (non-interactive fallback via softwareupdate)
            until xcode-select -p &>/dev/null; do
                sleep 5
            done
            ok "Xcode CLI tools installed"
        else
            ok "Xcode CLI tools already present"
        fi

        # ── Homebrew ───────────────────────────────────────────────────────
        if ! command -v brew &>/dev/null; then
            step "Installing Homebrew…"
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
                2>>"$ONEINFINITY_LOG" && ok "Homebrew installed" || { err "Homebrew install failed"; return 1; }
            # Populate PATH for the current session (Apple Silicon vs Intel)
            if [[ -f /opt/homebrew/bin/brew ]]; then
                eval "$(/opt/homebrew/bin/brew shellenv)"
            elif [[ -f /usr/local/bin/brew ]]; then
                eval "$(/usr/local/bin/brew shellenv)"
            fi
        else
            ok "Homebrew already present ($(brew --version 2>/dev/null | head -1))"
        fi

    elif [[ "$OS_TYPE" == "ubuntu" || "$OS_TYPE" == "debian" || "$OS_TYPE" == "kali" ]]; then
        step "Running apt-get update…"
        sudo apt-get update -qq 2>>"$ONEINFINITY_LOG" && ok "apt cache refreshed" \
            || warn "apt-get update returned non-zero (continuing)"

        local APT_PKGS=(
            build-essential git curl wget unzip tar jq
            ca-certificates gnupg lsb-release software-properties-common
            libssl-dev libffi-dev libpq-dev pkg-config cmake clang llvm
        )
        step "Installing apt packages…"
        sudo apt-get install -y "${APT_PKGS[@]}" >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "apt packages installed" || warn "Some apt packages may have failed (check log)"

    elif [[ "$OS_TYPE" == "fedora" || "$OS_TYPE" == "rhel" || "$OS_TYPE" == "centos" ]]; then
        step "Installing dnf packages…"
        local DNF_PKGS=(
            gcc gcc-c++ make git curl wget unzip tar jq
            ca-certificates gnupg2 redhat-lsb-core
            openssl-devel libffi-devel libpq-devel pkgconfig cmake clang llvm
        )
        sudo dnf install -y "${DNF_PKGS[@]}" >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "dnf packages installed" || warn "Some dnf packages may have failed (check log)"

    elif [[ "$OS_TYPE" == "arch" ]]; then
        step "Installing pacman packages…"
        local PACMAN_PKGS=(
            base-devel git curl wget unzip tar jq
            ca-certificates gnupg lsb-release
            openssl libffi libpq pkgconf cmake clang llvm
        )
        sudo pacman -Sy --noconfirm "${PACMAN_PKGS[@]}" >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "pacman packages installed" || warn "Some pacman packages may have failed (check log)"

    else
        warn "Unknown OS type '$OS_TYPE' — skipping system dep install"
    fi
}

# ---------------------------------------------------------------------------
# _version_gte  CURRENT  REQUIRED
# Returns 0 if CURRENT >= REQUIRED (semver, first two components)
# ---------------------------------------------------------------------------
_version_gte() {
    local cur="$1" req="$2"
    # Strip leading non-numeric (e.g. "go1.22.0" → "1.22.0", "v3.11.2" → "3.11.2")
    cur="${cur#[a-zA-Z]}"
    req="${req#[a-zA-Z]}"
    local IFS='.'
    read -ra C <<<"$cur"
    read -ra R <<<"$req"
    local i
    for (( i = 0; i < ${#R[@]}; i++ )); do
        local cv="${C[$i]:-0}" rv="${R[$i]:-0}"
        # Strip anything after '-' (pre-release suffix)
        cv="${cv%%-*}"; rv="${rv%%-*}"
        if (( cv > rv )); then return 0; fi
        if (( cv < rv )); then return 1; fi
    done
    return 0
}

# ---------------------------------------------------------------------------
# install_python
# ---------------------------------------------------------------------------
_install_python() {
    section "Python 3.11+"
    local NEED_VER="3.11"

    # Check existing
    if command -v python3 &>/dev/null; then
        local cur_ver
        cur_ver=$(python3 --version 2>&1 | awk '{print $2}')
        if _version_gte "$cur_ver" "$NEED_VER"; then
            ok "Python $cur_ver already installed (>= $NEED_VER)"
        else
            warn "Python $cur_ver found but < $NEED_VER — installing newer version"
            _do_install_python
        fi
    else
        _do_install_python
    fi

    _setup_venv
    _upgrade_pip
}

_do_install_python() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        step "brew install python@3.11"
        brew install python@3.11 >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Python 3.11 installed via brew" || { err "brew install python@3.11 failed"; return 1; }
        # Ensure python3 resolves to the brew-managed version
        brew link --overwrite python@3.11 >>"$ONEINFINITY_LOG" 2>&1 || true

    elif [[ "$OS_TYPE" == "ubuntu" || "$OS_TYPE" == "debian" || "$OS_TYPE" == "kali" ]]; then
        step "Adding deadsnakes PPA for Python 3.11…"
        if sudo add-apt-repository -y ppa:deadsnakes/ppa >>"$ONEINFINITY_LOG" 2>&1; then
            sudo apt-get update -qq >>"$ONEINFINITY_LOG" 2>&1
            sudo apt-get install -y python3.11 python3.11-venv python3.11-dev >>"$ONEINFINITY_LOG" 2>&1 \
                && ok "Python 3.11 installed via deadsnakes" || _fallback_pyenv
        else
            warn "deadsnakes PPA unavailable — falling back to pyenv"
            _fallback_pyenv
        fi

    elif [[ "$OS_TYPE" == "fedora" || "$OS_TYPE" == "rhel" || "$OS_TYPE" == "centos" ]]; then
        sudo dnf install -y python3.11 python3.11-devel >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Python 3.11 installed via dnf" || _fallback_pyenv

    elif [[ "$OS_TYPE" == "arch" ]]; then
        sudo pacman -Sy --noconfirm python >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Python installed via pacman" || _fallback_pyenv

    else
        _fallback_pyenv
    fi
}

_fallback_pyenv() {
    warn "Using pyenv as Python install fallback"
    if ! command -v pyenv &>/dev/null; then
        step "Installing pyenv…"
        curl -fsSL https://pyenv.run | bash >>"$ONEINFINITY_LOG" 2>&1
    fi
    export PYENV_ROOT="$HOME/.pyenv"
    export PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)" 2>/dev/null || true
    step "pyenv install 3.11.9"
    pyenv install -s 3.11.9 >>"$ONEINFINITY_LOG" 2>&1 \
        && pyenv global 3.11.9 \
        && ok "Python 3.11.9 installed via pyenv" \
        || err "pyenv install 3.11.9 failed — manual intervention required"
}

_setup_venv() {
    local VENV_DIR="$REPO_DIR/.venv"
    # Ubuntu 24.04 (PEP 668) requires python3-venv to be installed separately
    # when the system Python is already at the required version and _do_install_python was skipped
    if [[ "${DISTRO_FAMILY:-}" == "debian" ]] && ! python3 -m venv --help &>/dev/null 2>&1; then
        step "Installing python3-venv (required for Ubuntu 24.04+ / PEP 668)…"
        sudo apt-get install -y python3-venv python3-pip >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "python3-venv installed" || warn "python3-venv install failed — venv may not work"
    fi
    if [[ ! -d "$VENV_DIR" ]]; then
        step "Creating venv at $VENV_DIR"
        python3 -m venv "$VENV_DIR" >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "venv created" || { err "Failed to create venv at $VENV_DIR"; return 1; }
    else
        ok "venv already exists at $VENV_DIR"
    fi
    # Activate for this install session
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
    ok "venv activated"
}

_upgrade_pip() {
    step "Upgrading pip / setuptools / wheel / maturin"
    pip install --upgrade pip setuptools wheel maturin >>"$ONEINFINITY_LOG" 2>&1 \
        && ok "pip core tools upgraded" || warn "pip upgrade reported errors (check log)"
}

# ---------------------------------------------------------------------------
# install_go
# ---------------------------------------------------------------------------
_install_go() {
    section "Go 1.22+"
    local NEED_VER="1.22"

    if command -v go &>/dev/null; then
        local cur_ver
        cur_ver=$(go version 2>&1 | awk '{print $3}' | sed 's/go//')
        if _version_gte "$cur_ver" "$NEED_VER"; then
            ok "Go $cur_ver already installed (>= $NEED_VER)"
            _set_gopath
            return 0
        else
            warn "Go $cur_ver found but < $NEED_VER — upgrading"
        fi
    fi

    if [[ "$OS_TYPE" == "macos" ]]; then
        step "brew install go"
        brew install go >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Go installed via brew" || { err "brew install go failed"; return 1; }

    else
        # Fetch the latest stable Go version from the official API
        step "Fetching latest Go release from go.dev/dl…"
        local GO_VER
        GO_VER=$(curl -fsSL "https://go.dev/dl/?mode=json" 2>>"$ONEINFINITY_LOG" \
            | python3 -c "import sys,json; data=json.load(sys.stdin); print(data[0]['version'])" 2>>"$ONEINFINITY_LOG")
        if [[ -z "$GO_VER" ]]; then
            warn "Could not determine latest Go version via API; falling back to go1.22.4"
            GO_VER="go1.22.4"
        fi

        local ARCH
        case "$(uname -m)" in
            x86_64)  ARCH="amd64" ;;
            aarch64|arm64) ARCH="arm64" ;;
            *) ARCH="amd64" ;;
        esac

        local TARBALL="${GO_VER}.linux-${ARCH}.tar.gz"
        local URL="https://go.dev/dl/${TARBALL}"
        step "Downloading $URL"
        curl -fSL "$URL" -o "/tmp/${TARBALL}" >>"$ONEINFINITY_LOG" 2>&1 \
            || { err "Failed to download Go tarball from $URL"; return 1; }

        step "Installing Go to /usr/local/go"
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf "/tmp/${TARBALL}" >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Go ${GO_VER} installed to /usr/local/go" \
            || { err "Go tarball extraction failed"; return 1; }
        rm -f "/tmp/${TARBALL}"

        # Make go available immediately in this session
        export PATH="/usr/local/go/bin:$PATH"
    fi

    _set_gopath
}

_set_gopath() {
    export GOPATH="$HOME/go"
    export PATH="$HOME/go/bin:$PATH"
    ok "GOPATH=$GOPATH  PATH includes \$HOME/go/bin"
}

# ---------------------------------------------------------------------------
# install_rust
# ---------------------------------------------------------------------------
_install_rust() {
    section "Rust / Cargo"

    if command -v cargo &>/dev/null; then
        ok "Rust/Cargo already installed ($(cargo --version 2>/dev/null))"
        # Still source env to ensure it's on PATH for this session
        # shellcheck disable=SC1091
        [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
        return 0
    fi

    step "Installing Rust via rustup…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path >>"$ONEINFINITY_LOG" 2>&1 \
        && ok "Rust installed" || { err "rustup install failed"; return 1; }

    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    ok "Cargo available: $(cargo --version 2>/dev/null)"
}

# ---------------------------------------------------------------------------
# install_nodejs
# ---------------------------------------------------------------------------
_install_nodejs() {
    section "Node.js 20+ / npm"
    local NEED_VER="20"

    if command -v node &>/dev/null; then
        local cur_ver
        cur_ver=$(node --version 2>&1 | sed 's/v//')
        local major="${cur_ver%%.*}"
        if (( major >= NEED_VER )); then
            ok "Node.js v$cur_ver already installed (>= $NEED_VER)"
            return 0
        else
            warn "Node.js v$cur_ver found but < $NEED_VER — upgrading"
        fi
    fi

    if [[ "$OS_TYPE" == "macos" ]]; then
        # Prefer the versioned formula; fall back to `node` (latest LTS)
        if brew list node@20 &>/dev/null 2>&1 || brew install node@20 >>"$ONEINFINITY_LOG" 2>&1; then
            brew link --overwrite --force node@20 >>"$ONEINFINITY_LOG" 2>&1 || true
            ok "Node.js 20 installed via brew"
        else
            brew install node >>"$ONEINFINITY_LOG" 2>&1 \
                && ok "Node.js installed via brew (latest)" \
                || err "brew install node failed"
        fi

    elif [[ "$OS_TYPE" == "ubuntu" || "$OS_TYPE" == "debian" || "$OS_TYPE" == "kali" ]]; then
        step "Setting up NodeSource repository for Node.js 20…"
        curl -fsSL https://deb.nodesource.com/setup_20.x \
            | sudo -E bash - >>"$ONEINFINITY_LOG" 2>&1 \
            && sudo apt-get install -y nodejs >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Node.js 20 installed via NodeSource" \
            || err "NodeSource Node.js install failed"

    elif [[ "$OS_TYPE" == "fedora" || "$OS_TYPE" == "rhel" || "$OS_TYPE" == "centos" ]]; then
        step "Enabling nodejs:20 module stream…"
        sudo dnf module enable -y nodejs:20 >>"$ONEINFINITY_LOG" 2>&1 || true
        sudo dnf install -y nodejs npm >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Node.js 20 installed via dnf" \
            || err "dnf install nodejs failed"

    elif [[ "$OS_TYPE" == "arch" ]]; then
        sudo pacman -Sy --noconfirm nodejs npm >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Node.js installed via pacman" \
            || err "pacman install nodejs failed"

    else
        warn "Unknown OS type '$OS_TYPE' — cannot install Node.js automatically"
    fi
}

# ---------------------------------------------------------------------------
# install_java
# ---------------------------------------------------------------------------
_install_java() {
    section "Java 11+"
    local NEED_MAJOR=11

    if command -v java &>/dev/null; then
        # `java -version` outputs to stderr
        local ver_str
        ver_str=$(java -version 2>&1 | head -1)
        # Extract major version: handles both "1.8.0_xxx" and "17.0.x" style
        local major
        major=$(echo "$ver_str" | sed -E 's/.*"([0-9]+)(\.[0-9]+)*.*/\1/')
        # Handle old-style 1.x versioning
        if [[ "$major" == "1" ]]; then
            major=$(echo "$ver_str" | sed -E 's/.*"1\.([0-9]+).*/\1/')
        fi
        if (( major >= NEED_MAJOR )); then
            ok "Java $major already installed (>= $NEED_MAJOR)"
            return 0
        else
            warn "Java $major found but < $NEED_MAJOR — installing newer version"
        fi
    fi

    if [[ "$OS_TYPE" == "macos" ]]; then
        step "brew install openjdk@17"
        brew install openjdk@17 >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "OpenJDK 17 installed via brew" || warn "brew install openjdk@17 failed"
        # Symlink for system Java wrappers
        sudo ln -sfn "$(brew --prefix)/opt/openjdk@17/libexec/openjdk.jdk" \
            /Library/Java/JavaVirtualMachines/openjdk-17.jdk 2>/dev/null || true

    elif [[ "$OS_TYPE" == "ubuntu" || "$OS_TYPE" == "debian" || "$OS_TYPE" == "kali" ]]; then
        sudo apt-get install -y openjdk-17-jdk >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "OpenJDK 17 installed" || warn "apt install openjdk-17-jdk failed"

    elif [[ "$OS_TYPE" == "fedora" || "$OS_TYPE" == "rhel" || "$OS_TYPE" == "centos" ]]; then
        sudo dnf install -y java-17-openjdk-devel >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "OpenJDK 17 installed" || warn "dnf install java-17-openjdk-devel failed"

    elif [[ "$OS_TYPE" == "arch" ]]; then
        sudo pacman -Sy --noconfirm jdk17-openjdk >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "OpenJDK 17 installed" || warn "pacman install jdk17-openjdk failed"

    else
        warn "Unknown OS type '$OS_TYPE' — cannot install Java automatically"
    fi
}

# ---------------------------------------------------------------------------
# Public entry point: install_language_runtimes
# Installs all runtimes in dependency order.
# ---------------------------------------------------------------------------
install_language_runtimes() {
    banner "Language Runtimes"

    _install_python
    _install_go
    _install_rust
    _install_nodejs
    _install_java

    info "All language runtimes processed."
}

# ============================================================================
# SECTION C — Go Tools Installation
# ============================================================================
# section_C_go_tools.sh — Go Tools Installation
# Part of OneInfinity installer. Sourced by install.sh.
# Requires: ok() warn() err() info() section() banner() step() functions,
#           $ONEINFINITY_LOG, $GOPATH, go binary in PATH

# ---------------------------------------------------------------------------
# Internal helper: install a single Go tool
#   _go_install_tool  BINARY  MODULE@latest  [FORCE]
#   FORCE=1  →  always install (used by update_go_tools)
# ---------------------------------------------------------------------------
_go_install_tool() {
    local bin="$1"
    local pkg="$2"
    local force="${3:-0}"

    if [[ "$force" -ne 1 ]] && command -v "$bin" &>/dev/null; then
        info "  skip  $bin (already in PATH)"
        return 0
    fi

    step "go install ${pkg}"
    if go install "${pkg}" >>"$ONEINFINITY_LOG" 2>&1; then
        ok "  $bin installed"
    else
        warn "  $bin install FAILED (${pkg}) — continuing"
    fi
}

# ---------------------------------------------------------------------------
# install_go_tools
# Installs all Go-based offensive / recon / utility tools.
# Idempotent: skips any binary already present in PATH unless --update-only
# was passed to the top-level installer (detected via $OI_UPDATE_MODE=1).
# ---------------------------------------------------------------------------
install_go_tools() {
    banner "Go Tools"

    # Ensure GOPATH/bin is in PATH for this session
    export GOPATH="${GOPATH:-$HOME/go}"
    export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"

    if ! command -v go &>/dev/null; then
        err "go binary not found — cannot install Go tools. Run install_language_runtimes first."
        return 1
    fi

    local FORCE=0
    [[ "${OI_UPDATE_MODE:-0}" == "1" ]] && FORCE=1

    section "Web / Recon tools (ProjectDiscovery)"
    _go_install_tool nuclei             "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"          $FORCE
    _go_install_tool subfinder          "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"     $FORCE
    _go_install_tool httpx              "github.com/projectdiscovery/httpx/cmd/httpx@latest"                $FORCE
    _go_install_tool katana             "github.com/projectdiscovery/katana/cmd/katana@latest"              $FORCE
    _go_install_tool naabu              "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"             $FORCE
    _go_install_tool dnsx               "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"                  $FORCE
    _go_install_tool interactsh-client  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" $FORCE
    _go_install_tool tlsx               "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"                  $FORCE
    _go_install_tool mapcidr            "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"             $FORCE
    _go_install_tool cdncheck           "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"           $FORCE
    _go_install_tool asnmap             "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"               $FORCE
    _go_install_tool cloudlist          "github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"         $FORCE
    _go_install_tool alterx             "github.com/projectdiscovery/alterx/cmd/alterx@latest"               $FORCE
    _go_install_tool shuffledns         "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"       $FORCE
    _go_install_tool notify             "github.com/projectdiscovery/notify/cmd/notify@latest"               $FORCE

    section "Web / Recon tools (community)"
    _go_install_tool hakrawler   "github.com/hakluke/hakrawler@latest"           $FORCE
    _go_install_tool gospider    "github.com/jaeles-project/gospider@latest"      $FORCE
    _go_install_tool waybackurls "github.com/tomnomnom/waybackurls@latest"        $FORCE
    _go_install_tool gau         "github.com/lc/gau/v2/cmd/gau@latest"           $FORCE
    _go_install_tool subjs       "github.com/lc/subjs@latest"                    $FORCE
    _go_install_tool getJS       "github.com/003random/getJS@latest"              $FORCE
    _go_install_tool cariddi     "github.com/edoardottt/cariddi/cmd/cariddi@latest" $FORCE
    _go_install_tool gowitness   "github.com/sensepost/gowitness/v3@latest"       $FORCE

    section "Fuzzing / Directory brute-force"
    _go_install_tool ffuf      "github.com/ffuf/ffuf/v2@latest"         $FORCE
    _go_install_tool gobuster  "github.com/OJ/gobuster/v3@latest"       $FORCE

    section "XSS / Injection tools"
    _go_install_tool dalfox  "github.com/hahwul/dalfox/v2@latest"  $FORCE
    _go_install_tool kxss    "github.com/Emoe/kxss@latest"          $FORCE
    _go_install_tool Gxss    "github.com/KathanP19/Gxss@latest"     $FORCE

    section "OSINT / DNS"
    # amass uses the /... wildcard to install all sub-commands
    _go_install_tool amass  "github.com/owasp-amass/amass/v4/...@latest"  $FORCE

    section "Network / Tunneling (Go)"
    # ligolo-ng and nmap are system packages — handled in section_E
    _go_install_tool chisel  "github.com/jpillora/chisel@latest"  $FORCE

    section "tomnomnom utility suite"
    _go_install_tool gf          "github.com/tomnomnom/gf@latest"          $FORCE
    _go_install_tool qsreplace   "github.com/tomnomnom/qsreplace@latest"   $FORCE
    _go_install_tool anew        "github.com/tomnomnom/anew@latest"         $FORCE
    _go_install_tool unfurl      "github.com/tomnomnom/unfurl@latest"       $FORCE
    _go_install_tool gron        "github.com/tomnomnom/gron@latest"         $FORCE

    section "Misc utility"
    # rush: parallel command runner
    _go_install_tool rush  "github.com/shenwei356/rush@latest"       $FORCE
    # freq: word frequency analysis
    _go_install_tool freq  "github.com/takshal/freq@latest"          $FORCE
    # gauplus: archived URLs + params (gaplus wraps gau with more sources)
    _go_install_tool gauplus "github.com/bp0lr/gauplus@latest"        $FORCE
    # jsluice: JavaScript secret + URL extraction
    _go_install_tool jsluice "github.com/BishopFox/jsluice/cmd/jsluice@latest" $FORCE

    # ── Skipped (not Go) ───────────────────────────────────────────────────
    # massdns      → system package (section_E)
    # paramspider  → Python tool (section_D)
    # ligolo-ng    → complex system install (section_E)
    # nmap         → system package (section_E)
    # feroxbuster  → handled in section_E (cargo or brew)

    # ── Post-install: update Nuclei templates ─────────────────────────────
    section "Nuclei template update"
    if command -v nuclei &>/dev/null; then
        step "nuclei -update-templates"
        nuclei -update-templates >>"$ONEINFINITY_LOG" 2>&1 \
            && ok "Nuclei templates updated" \
            || warn "Nuclei template update failed (non-fatal)"
    else
        warn "nuclei binary not found — skipping template update"
    fi

    ok "Go tools installation complete"
}

# ---------------------------------------------------------------------------
# update_go_tools
# Called in UPDATE MODE. Forces go install @latest for every tool regardless
# of whether the binary is already present — fetches the newest release.
# ---------------------------------------------------------------------------
update_go_tools() {
    banner "Updating Go Tools"
    info "Forcing re-install of all Go tools at @latest…"
    OI_UPDATE_MODE=1 install_go_tools
    ok "Go tools update complete"
}

# ============================================================================
# SECTION D — Python Security Tools
# ============================================================================
# section_D_python_tools.sh — Python Security Tools
# Part of the OneInfinity installer. Sourced by install.sh.
# Requires: ok(), warn(), err(), info(), section(), step() from scaffold.
# Requires: $REPO_DIR, $ONEINFINITY_HOME, $ONEINFINITY_LOG, $OS_TYPE

# ---------------------------------------------------------------------------
# Internal helper — pip install a single package, warn-and-continue on failure
# Usage: _pip_install <display-name> <pip-package-spec>
# ---------------------------------------------------------------------------
_pip_install() {
    local display="$1"
    local pkg="$2"
    step "pip: $display"
    if pip install "$pkg" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "Installed python package: $display"
    else
        warn "Failed to install python package: $display — skipping"
    fi
}

# ---------------------------------------------------------------------------
# _pip_install_idempotent — skip if already importable at any version
# Usage: _pip_install_idempotent <display-name> <pip-package-spec> <import-name>
# ---------------------------------------------------------------------------
_pip_install_idempotent() {
    local display="$1"
    local pkg="$2"
    local import_name="$3"
    step "pip (idempotent): $display"
    if pip show "$import_name" &>/dev/null 2>&1; then
        info "$display already installed — upgrading"
        if pip install --upgrade "$pkg" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
            ok "Upgraded python package: $display"
        else
            warn "Failed to upgrade python package: $display — keeping existing"
        fi
    else
        if pip install "$pkg" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
            ok "Installed python package: $display"
        else
            warn "Failed to install python package: $display — skipping"
        fi
    fi
}

# ---------------------------------------------------------------------------
# _resolve_pip — return the right pip executable (venv or system)
# ---------------------------------------------------------------------------
_resolve_pip() {
    if [[ -f "$REPO_DIR/.venv/bin/pip" ]]; then
        echo "$REPO_DIR/.venv/bin/pip"
    elif command -v pip3 &>/dev/null; then
        echo "pip3"
    elif command -v pip &>/dev/null; then
        echo "pip"
    else
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# install_python_tools — main entry point
# ---------------------------------------------------------------------------
install_python_tools() {
    section "Python Security Tools"

    # Activate venv if present
    if [[ -f "$REPO_DIR/.venv/bin/activate" ]]; then
        info "Activating virtual environment: $REPO_DIR/.venv"
        # shellcheck disable=SC1091
        source "$REPO_DIR/.venv/bin/activate"
    else
        warn "No .venv found under $REPO_DIR — using system pip"
    fi

    # Resolve pip
    local PIP
    PIP="$(_resolve_pip)"
    if [[ -z "$PIP" ]]; then
        err "No pip executable found — cannot install Python tools"
        return 1
    fi
    info "Using pip: $PIP"

    # Convenience wrapper that honours the resolved pip
    pip() { "$PIP" "$@"; }

    # -------------------------------------------------------------------------
    # 1. Install OneInfinity itself first
    # -------------------------------------------------------------------------
    step "Installing OneInfinity (pip install -e '[ai,mobile,web]')"
    if (cd "$REPO_DIR" && pip install -e ".[ai,mobile,web]" 2>&1 | tee -a "$ONEINFINITY_LOG"); then
        ok "OneInfinity installed (editable, all extras)"
    else
        warn "OneInfinity editable install reported errors — check $ONEINFINITY_LOG"
    fi

    # -------------------------------------------------------------------------
    # 1b. Install web/backend runtime dependencies (qrcode, zeroconf, psutil, etc.)
    # -------------------------------------------------------------------------
    local BACKEND_REQS="$REPO_DIR/web/backend/requirements.txt"
    if [[ -f "$BACKEND_REQS" ]]; then
        step "Installing web/backend/requirements.txt"
        if (pip install -r "$BACKEND_REQS" 2>&1 | tee -a "$ONEINFINITY_LOG"); then
            ok "web/backend dependencies installed"
        else
            warn "web/backend requirements reported errors — check $ONEINFINITY_LOG"
        fi
    else
        warn "web/backend/requirements.txt not found — skipping"
    fi

    # -------------------------------------------------------------------------
    # 2. Web / API pentesting
    # -------------------------------------------------------------------------
    section "Python Tools — Web/API Pentesting"

    _pip_install_idempotent "sqlmap"      "sqlmap"        "sqlmap"
    _pip_install_idempotent "wfuzz"       "wfuzz"         "wfuzz"
    _pip_install_idempotent "XSStrike"    "xsstrike"      "xsstrike"
    _pip_install_idempotent "commix"      "commix"        "commix"
    _pip_install_idempotent "paramspider" "paramspider"   "paramspider"
    _pip_install_idempotent "corsy"       "corsy"         "corsy"
    _pip_install_idempotent "wafw00f"     "wafw00f"       "wafw00f"
    _pip_install_idempotent "wapiti"      "wapiti3"       "wapitiCore"
    _pip_install_idempotent "theHarvester" "theHarvester" "theHarvester"
    _pip_install_idempotent "sublist3r"   "sublist3r"     "sublist3r"
    _pip_install_idempotent "dnsrecon"    "dnsrecon"      "dnsrecon"
    _pip_install_idempotent "shodan"      "shodan"        "shodan"
    _pip_install_idempotent "semgrep"     "semgrep"       "semgrep"
    _pip_install_idempotent "linkfinder"  "linkfinder"    "linkfinder"
    _pip_install_idempotent "arjun"       "arjun"         "arjun"

    # -------------------------------------------------------------------------
    # 2b. Core Python runtime deps not covered by editable install
    # -------------------------------------------------------------------------
    section "Python Tools — Core Runtime Deps"

    # Async HTTP + WebSocket
    _pip_install_idempotent "aiohttp"            "aiohttp>=3.9.0"            "aiohttp"
    _pip_install_idempotent "websocket-client"   "websocket-client>=1.8.0"   "websocket"
    # Async SQLite (agent state)
    _pip_install_idempotent "aiosqlite"          "aiosqlite>=0.20.0"         "aiosqlite"
    # DNS resolution
    _pip_install_idempotent "dnspython"          "dnspython>=2.6.0"          "dns"
    # Numerical computing
    _pip_install_idempotent "numpy"              "numpy>=1.26.0"             "numpy"
    # Semantic embeddings
    _pip_install_idempotent "sentence-transformers" "sentence-transformers>=3.0.0" "sentence_transformers"
    # LLM API clients
    _pip_install_idempotent "openai"             "openai>=1.35.0"            "openai"
    _pip_install_idempotent "anthropic"          "anthropic>=0.30.0"         "anthropic"
    _pip_install_idempotent "google-generativeai" "google-generativeai>=0.7.0" "google.generativeai"
    _pip_install_idempotent "msal"               "msal>=1.29.0"              "msal"
    # PostgreSQL (legacy psycopg2 shim used by some modules)
    _pip_install_idempotent "psycopg2-binary"    "psycopg2-binary>=2.9.0"    "psycopg2"
    # gRPC (oi-ssrf / oi-oob inter-service)
    _pip_install_idempotent "grpcio"             "grpcio>=1.64.0"            "grpc"
    _pip_install_idempotent "grpcio-tools"       "grpcio-tools>=1.64.0"      "grpc_tools"
    # mitmproxy Python API (traffic capture/replay)
    _pip_install_idempotent "mitmproxy"          "mitmproxy>=10.3.0"         "mitmproxy"
    # Android device control
    _pip_install_idempotent "adbutils"           "adbutils>=2.7.0"           "adbutils"

    # nomore403 is a Go binary; clone + build under $ONEINFINITY_HOME/tools
    step "nomore403 (Go binary, not pip)"
    local nomore403_dir="$ONEINFINITY_HOME/tools/nomore403"
    if [[ -d "$nomore403_dir" ]]; then
        info "nomore403 already cloned — pulling latest"
        if (cd "$nomore403_dir" && git pull 2>&1 | tee -a "$ONEINFINITY_LOG"); then
            ok "nomore403 updated"
        else
            warn "nomore403 git pull failed — keeping existing"
        fi
    else
        if git clone https://github.com/devploit/nomore403 "$nomore403_dir" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
            ok "nomore403 cloned"
        else
            warn "nomore403 git clone failed — skipping"
            nomore403_dir=""
        fi
    fi
    if [[ -n "$nomore403_dir" && -d "$nomore403_dir" ]]; then
        step "Building nomore403"
        if (cd "$nomore403_dir" && go build -o "$HOME/.local/bin/nomore403" . 2>&1 | tee -a "$ONEINFINITY_LOG"); then
            ok "nomore403 built → $HOME/.local/bin/nomore403"
        else
            warn "nomore403 build failed — skipping"
        fi
    fi

    # -------------------------------------------------------------------------
    # 3. Mobile security
    # -------------------------------------------------------------------------
    section "Python Tools — Mobile Security"

    _pip_install_idempotent "frida-tools" "frida-tools>=12.5.0" "frida"
    _pip_install_idempotent "objection"   "objection"           "objection"
    _pip_install_idempotent "apkleaks"    "apkleaks"            "apkleaks"
    # androguard — managed by pyproject.toml
    info "androguard — managed by pyproject.toml, skipping direct install"

    # hbctool: Hermes bytecode disassembler (React Native APK analysis)
    _pip_install_idempotent "hbctool"  "hbctool"  "hbctool"

    # hermes-dec: Hermes decompiler (React Native)
    step "hermes-dec"
    if command -v hermes-dec &>/dev/null; then
        info "hermes-dec already installed"
    elif command -v npm &>/dev/null; then
        if npm install -g hermes-dec >>"$ONEINFINITY_LOG" 2>&1; then
            ok "hermes-dec installed (global npm)"
        else
            warn "hermes-dec npm install failed — skipping"
        fi
    else
        warn "npm not found — cannot install hermes-dec; install Node.js first"
    fi

    # frida-compile: TypeScript → Frida script compiler (required for frida-hooks build)
    step "frida-compile"
    if command -v frida-compile &>/dev/null; then
        info "frida-compile already installed"
    elif command -v npm &>/dev/null; then
        if npm install -g @frida/compile >>"$ONEINFINITY_LOG" 2>&1; then
            ok "frida-compile installed (global npm)"
        else
            warn "frida-compile npm install failed — skipping"
        fi
    else
        warn "npm not found — cannot install frida-compile; install Node.js first"
    fi

    # drozer: Android security testing framework
    _pip_install_idempotent "drozer" "drozer" "drozer"

    # idb: iOS Debug Bridge — iOS device interaction (frida_dtrace_tracer.py, ios_security_tester.py)
    _pip_install_idempotent "fb-idb" "fb-idb" "idb"

    # playwright: headless browser automation (browser_attack_engine.py)
    step "playwright"
    if command -v playwright &>/dev/null; then
        info "playwright already installed"
    else
        if "$PIP" install "playwright>=1.44.0" >>"$ONEINFINITY_LOG" 2>&1; then
            ok "playwright Python package installed"
            # Install browser binaries (Chromium covers chromedriver; Firefox covers geckodriver)
            if python3 -m playwright install chromium firefox >>"$ONEINFINITY_LOG" 2>&1; then
                ok "playwright browsers (Chromium + Firefox) installed"
            else
                warn "playwright browser install failed — run: python3 -m playwright install chromium firefox"
            fi
        else
            warn "playwright install failed — skipping"
        fi
    fi

    # -------------------------------------------------------------------------
    # 4. AI / ML pentesting
    # -------------------------------------------------------------------------
    section "Python Tools — AI/ML Pentesting"

    _pip_install_idempotent "garak"  "garak"  "garak"
    _pip_install_idempotent "pyrit"  "pyrit"  "pyrit"
    # adversarial-robustness-toolbox — in pyproject.toml; skip
    info "adversarial-robustness-toolbox — managed by pyproject.toml, skipping direct install"

    # -------------------------------------------------------------------------
    # 5. Network / Auth
    # -------------------------------------------------------------------------
    section "Python Tools — Network/Auth"

    _pip_install_idempotent "impacket"       "impacket"       "impacket"
    _pip_install_idempotent "bloodhound"     "bloodhound"     "bloodhound"
    _pip_install_idempotent "netexec"        "netexec"        "netexec"

    # crackmapexec: Linux-only (complex C deps may fail on macOS)
    step "crackmapexec (Linux-only)"
    if [[ "${OS_TYPE:-}" == "linux" ]]; then
        _pip_install_idempotent "crackmapexec" "crackmapexec" "crackmapexec"
    else
        warn "crackmapexec: Linux-only package — skipping on macOS"
    fi

    # -------------------------------------------------------------------------
    # 6. Miscellaneous
    # -------------------------------------------------------------------------
    section "Python Tools — Miscellaneous"

    _pip_install_idempotent "pwntools" "pwntools" "pwn"
    _pip_install_idempotent "scapy"    "scapy"    "scapy"

    # -------------------------------------------------------------------------
    # 7. Web3 / Smart Contract security
    # -------------------------------------------------------------------------
    section "Python Tools — Web3/Smart Contracts"

    # slither-analyzer: Solidity static analysis (requires solc)
    _pip_install_idempotent "slither-analyzer" "slither-analyzer" "slither"

    # -------------------------------------------------------------------------
    # 8. JS analysis tools (npm global)
    # -------------------------------------------------------------------------
    section "Python Tools — JS Analysis (npm globals)"

    # js-beautify: used by scan/js_secret_scanner.py to deobfuscate JS
    step "js-beautify"
    if command -v js-beautify &>/dev/null; then
        info "js-beautify already installed"
    elif command -v npm &>/dev/null; then
        if npm install -g js-beautify >>"$ONEINFINITY_LOG" 2>&1; then
            ok "js-beautify installed (global npm)"
        else
            warn "js-beautify npm install failed — skipping"
        fi
    else
        warn "npm not found — cannot install js-beautify"
    fi

    # gitleaks — Go binary; handled in section_E (system tools) via go install
    info "gitleaks — Go binary; installed in section_E"

    # trufflehog — binary download; handled in section_E
    info "trufflehog — binary download; installed in section_E"

    section "Python Tools — Complete"
    ok "All Python security tools processed"
}

# ============================================================================
# SECTION E — System Package Tools
# ============================================================================
# section_E_system_tools.sh — System Package Tools
# Part of the OneInfinity installer. Sourced by install.sh.
# Requires: ok(), warn(), err(), info(), section(), step() from scaffold.
# Requires: $OS_TYPE (linux|macos), $PKG_MGR, $DISTRO_FAMILY, $HOME, $ONEINFINITY_LOG
# $OS_TYPE set by scaffold: "macos" | "linux"
# $DISTRO_FAMILY set by scaffold: "debian" | "redhat" | "arch" | ""
# $INTERACTIVE set by scaffold: "true" | "false" (--non-interactive flag)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# _brew_install <pkg> [<extra-brew-args>...]
_brew_install() {
    local pkg="$1"; shift
    step "brew install $pkg"
    if brew list "$pkg" &>/dev/null 2>&1; then
        info "$pkg already installed via brew — upgrading"
        brew upgrade "$pkg" "$@" 2>&1 | tee -a "$ONEINFINITY_LOG" || true
    else
        if brew install "$pkg" "$@" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
            ok "brew: $pkg installed"
        else
            warn "brew install $pkg failed — skipping"
        fi
    fi
}

# _apt_install <pkg> [<pkg2>...]
_apt_install() {
    step "apt install $*"
    if DEBIAN_FRONTEND=noninteractive sudo apt-get install -y "$@" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "apt: $* installed"
    else
        warn "apt install $* failed — skipping"
    fi
}

# _dnf_install <pkg> [<pkg2>...]
_dnf_install() {
    step "dnf install $*"
    if sudo dnf install -y "$@" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "dnf: $* installed"
    else
        warn "dnf install $* failed — skipping"
    fi
}

# _pacman_install <pkg> [<pkg2>...]
_pacman_install() {
    step "pacman -S $*"
    if sudo pacman -S --noconfirm "$@" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "pacman: $* installed"
    else
        warn "pacman install $* failed — skipping"
    fi
}

# _pkg_install <brew-pkg> <apt-pkg> [<dnf-pkg>] [<pacman-pkg>]
# Installs the right package for current OS/distro.
_pkg_install() {
    local brew_pkg="$1"
    local apt_pkg="${2:-$1}"
    local dnf_pkg="${3:-$1}"
    local pacman_pkg="${4:-$1}"
    if [[ "${OS_TYPE:-}" == "macos" ]]; then
        _brew_install "$brew_pkg"
    elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
        _apt_install "$apt_pkg"
    elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
        _dnf_install "$dnf_pkg"
    elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
        _pacman_install "$pacman_pkg"
    else
        warn "_pkg_install: unknown OS/distro — cannot install $brew_pkg"
    fi
}

# _cargo_install <crate>
_cargo_install() {
    local crate="$1"
    step "cargo install $crate"
    if cargo install "$crate" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "cargo: $crate installed"
    else
        warn "cargo install $crate failed — skipping"
    fi
}

# _go_install <import-path>
_go_install() {
    local pkg="$1"
    step "go install $pkg"
    if go install "$pkg" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "go install: $pkg"
    else
        warn "go install $pkg failed — skipping"
    fi
}

# _pip_install_sys <display> <pip-pkg>
_pip_install_sys() {
    local display="$1"
    local pkg="$2"
    step "pip install $display"
    local PIP
    if command -v pip3 &>/dev/null; then PIP=pip3; elif command -v pip &>/dev/null; then PIP=pip; else warn "pip not found — skipping $display"; return; fi
    if "$PIP" install "$pkg" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "pip: $display installed"
    else
        warn "pip install $display failed — skipping"
    fi
}

# _ensure_local_bin — make sure $HOME/.local/bin exists and is in PATH for this session
_ensure_local_bin() {
    mkdir -p "$HOME/.local/bin"
    case ":${PATH}:" in
        *":$HOME/.local/bin:"*) ;;
        *) export PATH="$HOME/.local/bin:$PATH" ;;
    esac
}

# ---------------------------------------------------------------------------
# install_system_tools — main entry point
# ---------------------------------------------------------------------------
install_system_tools() {
    section "System Package Tools"
    _ensure_local_bin

    # -------------------------------------------------------------------------
    # Network scanning
    # -------------------------------------------------------------------------
    section "System Tools — Network Scanning"

    # nmap
    step "nmap"
    if command -v nmap &>/dev/null; then
        info "nmap already installed — $(nmap --version 2>&1 | head -1)"
    else
        _pkg_install nmap nmap nmap nmap
    fi

    # masscan
    step "masscan"
    if command -v masscan &>/dev/null; then
        info "masscan already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install masscan
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _apt_install masscan
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            _dnf_install masscan
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install masscan
        fi
    fi

    # rustscan — cargo install (cross-platform)
    step "rustscan"
    if command -v rustscan &>/dev/null; then
        info "rustscan already installed"
    else
        if command -v cargo &>/dev/null; then
            _cargo_install rustscan
        else
            warn "cargo not found — cannot install rustscan; install Rust first"
        fi
    fi

    # naabu — handled in section_C (Go tools), referenced here for completeness
    info "naabu — installed via Go in section_C"

    # -------------------------------------------------------------------------
    # Password / Auth tools
    # -------------------------------------------------------------------------
    section "System Tools — Password/Auth"

    # hydra
    step "hydra"
    if command -v hydra &>/dev/null; then
        info "hydra already installed"
    else
        _pkg_install hydra hydra hydra hydra
    fi

    # john (john the ripper)
    step "john"
    if command -v john &>/dev/null; then
        info "john already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install john
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _apt_install john
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            _dnf_install john
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install john
        fi
    fi

    # hashcat
    step "hashcat"
    if command -v hashcat &>/dev/null; then
        info "hashcat already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install hashcat
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _apt_install hashcat
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            _dnf_install hashcat
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install hashcat
        fi
    fi

    # -------------------------------------------------------------------------
    # Web tools
    # -------------------------------------------------------------------------
    section "System Tools — Web"

    # feroxbuster
    step "feroxbuster"
    if command -v feroxbuster &>/dev/null; then
        info "feroxbuster already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install feroxbuster
        elif command -v cargo &>/dev/null; then
            _cargo_install feroxbuster
        else
            # Binary fallback from GitHub releases
            step "feroxbuster — binary download fallback"
            local _fb_url _fb_arch _fb_bin
            _fb_arch="$(uname -m)"
            case "$_fb_arch" in
                x86_64)  _fb_url="https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.zip" ;;
                aarch64) _fb_url="https://github.com/epi052/feroxbuster/releases/latest/download/aarch64-linux-feroxbuster.zip" ;;
                *)       _fb_url="" ;;
            esac
            if [[ -n "$_fb_url" ]]; then
                _fb_bin="$HOME/.local/bin/feroxbuster"
                if curl -sSL "$_fb_url" -o /tmp/feroxbuster.zip 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && unzip -o /tmp/feroxbuster.zip feroxbuster -d "$HOME/.local/bin/" 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && chmod +x "$_fb_bin"; then
                    ok "feroxbuster binary installed → $_fb_bin"
                else
                    warn "feroxbuster binary download failed — skipping"
                fi
                rm -f /tmp/feroxbuster.zip
            else
                warn "feroxbuster: unsupported architecture $_fb_arch — skipping"
            fi
        fi
    fi

    # dirsearch
    step "dirsearch"
    _pip_install_sys "dirsearch" "dirsearch"

    # testssl.sh — download latest release
    step "testssl.sh"
    local testssl_bin="$HOME/.local/bin/testssl.sh"
    if [[ -x "$testssl_bin" ]]; then
        info "testssl.sh already at $testssl_bin"
    else
        local testssl_tag
        testssl_tag="$(curl -sSf https://api.github.com/repos/drwetter/testssl.sh/releases/latest 2>/dev/null \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
        if [[ -z "$testssl_tag" ]]; then
            warn "testssl.sh: could not determine latest release tag — skipping"
        else
            local testssl_url="https://github.com/drwetter/testssl.sh/releases/download/${testssl_tag}/testssl.sh"
            if curl -sSL "$testssl_url" -o "$testssl_bin" 2>&1 | tee -a "$ONEINFINITY_LOG" \
                && chmod +x "$testssl_bin"; then
                ok "testssl.sh installed → $testssl_bin (${testssl_tag})"
            else
                warn "testssl.sh download failed — skipping"
                rm -f "$testssl_bin"
            fi
        fi
    fi

    # whatweb
    step "whatweb"
    if command -v whatweb &>/dev/null; then
        info "whatweb already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install whatweb
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _apt_install whatweb
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            warn "whatweb not in default dnf repos — install manually or via gem install whatweb"
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install whatweb
        fi
    fi

    # wafw00f — already installed in section_D via pip; note here
    info "wafw00f — installed via pip in section_D"

    # nikto: web server vulnerability scanner (referenced in scan modules)
    step "nikto"
    if command -v nikto &>/dev/null; then
        info "nikto already installed — $(nikto -Version 2>&1 | head -1)"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install nikto
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _apt_install nikto
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            _dnf_install nikto
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install nikto
        fi
    fi

    # chromedriver / geckodriver: browser automation drivers (browser_attack_engine.py)
    # playwright install (section_D) provides the managed browser binaries;
    # system chromedriver/geckodriver are a fallback for selenium-style workflows.
    step "chromedriver (system fallback)"
    if command -v chromedriver &>/dev/null; then
        info "chromedriver already in PATH — $(chromedriver --version 2>&1 | head -1)"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install chromedriver || warn "chromedriver brew install failed — playwright chromium is the recommended driver"
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _apt_install chromium-driver || _apt_install chromium-chromedriver || \
                warn "chromedriver apt install failed — playwright chromium is the recommended driver"
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            _dnf_install chromedriver || warn "chromedriver dnf install failed — playwright chromium is the recommended driver"
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install chromedriver || warn "chromedriver pacman install failed — playwright chromium is the recommended driver"
        fi
    fi

    step "geckodriver (system fallback)"
    if command -v geckodriver &>/dev/null; then
        info "geckodriver already in PATH — $(geckodriver --version 2>&1 | head -1)"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install geckodriver || warn "geckodriver brew install failed — playwright firefox is the recommended driver"
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            # Ubuntu/Debian: geckodriver is not in apt; download from GitHub releases
            local gd_tag gd_arch gd_url gd_bin
            gd_tag="$(curl -sSf https://api.github.com/repos/mozilla/geckodriver/releases/latest 2>/dev/null \
                | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
            gd_arch="$(uname -m)"
            case "$gd_arch" in
                x86_64)  gd_arch="linux64" ;;
                aarch64) gd_arch="linux-aarch64" ;;
                *)       gd_arch="" ;;
            esac
            if [[ -n "$gd_tag" && -n "$gd_arch" ]]; then
                gd_url="https://github.com/mozilla/geckodriver/releases/download/${gd_tag}/geckodriver-${gd_tag}-${gd_arch}.tar.gz"
                gd_bin="$HOME/.local/bin/geckodriver"
                if curl -sSL "$gd_url" -o /tmp/geckodriver.tar.gz >>"$ONEINFINITY_LOG" 2>&1 \
                    && tar -xzf /tmp/geckodriver.tar.gz -C "$HOME/.local/bin/" geckodriver >>"$ONEINFINITY_LOG" 2>&1 \
                    && chmod +x "$gd_bin"; then
                    ok "geckodriver installed → $gd_bin (${gd_tag})"
                else
                    warn "geckodriver download failed — playwright firefox is the recommended driver"
                fi
                rm -f /tmp/geckodriver.tar.gz
            else
                warn "geckodriver: could not determine release or arch — playwright firefox is the recommended driver"
            fi
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            warn "geckodriver: not in default repos — download manually from https://github.com/mozilla/geckodriver/releases"
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install geckodriver || warn "geckodriver pacman install failed"
        fi
    fi

    # -------------------------------------------------------------------------
    # Traffic analysis
    # -------------------------------------------------------------------------
    section "System Tools — Traffic Analysis"

    # tshark / wireshark
    step "tshark"
    if command -v tshark &>/dev/null; then
        info "tshark already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install wireshark
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _apt_install tshark
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            _dnf_install wireshark-cli
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install wireshark-cli
        fi
    fi

    # tcpdump
    step "tcpdump"
    if command -v tcpdump &>/dev/null; then
        info "tcpdump already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install tcpdump
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            _apt_install tcpdump
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            _dnf_install tcpdump
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install tcpdump
        fi
    fi

    # -------------------------------------------------------------------------
    # Mobile tools
    # -------------------------------------------------------------------------
    section "System Tools — Mobile"

    # jadx
    step "jadx"
    if command -v jadx &>/dev/null; then
        info "jadx already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install jadx
        else
            # Linux: download release zip and symlink
            local jadx_tag jadx_url jadx_dir
            jadx_tag="$(curl -sSf https://api.github.com/repos/skylot/jadx/releases/latest 2>/dev/null \
                | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
            if [[ -z "$jadx_tag" ]]; then
                warn "jadx: could not determine latest release tag — skipping"
            else
                jadx_url="https://github.com/skylot/jadx/releases/download/${jadx_tag}/jadx-${jadx_tag#v}.zip"
                jadx_dir="$HOME/.local/share/jadx"
                mkdir -p "$jadx_dir"
                if curl -sSL "$jadx_url" -o /tmp/jadx.zip 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && unzip -o /tmp/jadx.zip -d "$jadx_dir" 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && chmod +x "$jadx_dir/bin/jadx" "$jadx_dir/bin/jadx-gui"; then
                    ln -sf "$jadx_dir/bin/jadx" "$HOME/.local/bin/jadx"
                    ln -sf "$jadx_dir/bin/jadx-gui" "$HOME/.local/bin/jadx-gui"
                    ok "jadx installed → $HOME/.local/bin/jadx (${jadx_tag})"
                else
                    warn "jadx download/extract failed — skipping"
                fi
                rm -f /tmp/jadx.zip
            fi
        fi
    fi

    # apktool
    step "apktool"
    if command -v apktool &>/dev/null; then
        info "apktool already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install apktool
        else
            # Linux: download from apktool.org (GitHub-backed)
            local apktool_ver apktool_url apktool_jar apktool_wrapper
            apktool_ver="$(curl -sSf https://api.github.com/repos/iBotPeaches/Apktool/releases/latest 2>/dev/null \
                | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/')"
            if [[ -z "$apktool_ver" ]]; then
                warn "apktool: could not determine latest release — skipping"
            else
                apktool_jar="/usr/local/lib/apktool.jar"
                apktool_wrapper="/usr/local/bin/apktool"
                apktool_url="https://github.com/iBotPeaches/Apktool/releases/download/v${apktool_ver}/apktool_${apktool_ver}.jar"
                # Wrapper script URL from apktool docs
                local apktool_wrapper_url="https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool"
                if curl -sSL "$apktool_url" -o /tmp/apktool.jar 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && curl -sSL "$apktool_wrapper_url" -o /tmp/apktool_wrapper 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                    if sudo cp /tmp/apktool.jar "$apktool_jar" \
                        && sudo cp /tmp/apktool_wrapper "$apktool_wrapper" \
                        && sudo chmod +x "$apktool_wrapper"; then
                        ok "apktool installed → $apktool_wrapper (${apktool_ver})"
                    else
                        warn "apktool: sudo cp failed — trying user-local install"
                        cp /tmp/apktool.jar "$HOME/.local/lib/apktool.jar" 2>/dev/null || true
                        # Write a minimal wrapper to ~/.local/bin/apktool
                        cat > "$HOME/.local/bin/apktool" <<'WRAPPER'
exec java -jar "$HOME/.local/lib/apktool.jar" "$@"
WRAPPER
                        chmod +x "$HOME/.local/bin/apktool"
                        ok "apktool installed (user-local) → $HOME/.local/bin/apktool"
                    fi
                else
                    warn "apktool download failed — skipping"
                fi
                rm -f /tmp/apktool.jar /tmp/apktool_wrapper
            fi
        fi
    fi

    # Android SDK (aapt / aapt2)
    step "Android SDK (aapt/aapt2)"
    local android_home="${ANDROID_HOME:-$HOME/android-sdk}"
    local aapt2_bin="$android_home/build-tools/34.0.0/aapt2"
    if [[ -x "$aapt2_bin" ]]; then
        info "Android build-tools 34.0.0 already at $android_home"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            # macOS: brew cask + sdkmanager
            step "Android SDK — macOS"
            if brew list --cask android-commandlinetools &>/dev/null 2>&1; then
                info "android-commandlinetools cask already installed"
            else
                if brew install --cask android-commandlinetools 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                    ok "android-commandlinetools installed"
                else
                    warn "android-commandlinetools install failed — skipping SDK setup"
                fi
            fi
            local sdkmanager_bin
            sdkmanager_bin="$(find /usr/local /opt/homebrew -name sdkmanager 2>/dev/null | head -1)"
            if [[ -z "$sdkmanager_bin" ]]; then
                sdkmanager_bin="$(command -v sdkmanager 2>/dev/null)"
            fi
            if [[ -n "$sdkmanager_bin" ]]; then
                export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
                mkdir -p "$ANDROID_HOME"
                step "sdkmanager install build-tools;34.0.0"
                if echo "y" | "$sdkmanager_bin" --sdk_root="$ANDROID_HOME" 'build-tools;34.0.0' 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                    ok "Android build-tools 34.0.0 installed"
                    echo "export ANDROID_HOME=\"$ANDROID_HOME\"" >> "$HOME/.oneinfinity_env" 2>/dev/null || true
                    echo "export aapt=\"$ANDROID_HOME/build-tools/34.0.0/aapt2\"" >> "$HOME/.oneinfinity_env" 2>/dev/null || true
                else
                    warn "sdkmanager build-tools install failed"
                fi
            else
                warn "sdkmanager not found — cannot install Android build-tools automatically"
            fi
        else
            # Linux: download cmdline-tools and run sdkmanager
            step "Android SDK — Linux download"
            local cmdline_url="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
            local cmdline_zip="/tmp/android-cmdline-tools.zip"
            export ANDROID_HOME="$android_home"
            mkdir -p "$ANDROID_HOME/cmdline-tools/latest"
            if [[ "${INTERACTIVE:-true}" == "false" ]]; then
                info "Non-interactive mode: skipping Android SDK download (run manually: sdkmanager 'build-tools;34.0.0')"
            else
                if curl -sSL "$cmdline_url" -o "$cmdline_zip" 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && unzip -o "$cmdline_zip" -d /tmp/android-cmdline-unzip 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && cp -r /tmp/android-cmdline-unzip/cmdline-tools/. "$ANDROID_HOME/cmdline-tools/latest/" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                    ok "Android cmdline-tools extracted"
                    local sdkmanager_linux="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
                    if [[ -x "$sdkmanager_linux" ]]; then
                        step "sdkmanager install build-tools;34.0.0 (Linux)"
                        if echo "y" | "$sdkmanager_linux" 'build-tools;34.0.0' 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                            ok "Android build-tools 34.0.0 installed → $ANDROID_HOME"
                            echo "export ANDROID_HOME=\"$ANDROID_HOME\"" >> "$HOME/.oneinfinity_env" 2>/dev/null || true
                            echo "export PATH=\"\$ANDROID_HOME/cmdline-tools/latest/bin:\$ANDROID_HOME/build-tools/34.0.0:\$PATH\"" >> "$HOME/.oneinfinity_env" 2>/dev/null || true
                            echo "export aapt=\"$ANDROID_HOME/build-tools/34.0.0/aapt2\"" >> "$HOME/.oneinfinity_env" 2>/dev/null || true
                        else
                            warn "sdkmanager build-tools install failed on Linux"
                        fi
                    else
                        warn "sdkmanager binary not found after extraction — skipping"
                    fi
                else
                    warn "Android cmdline-tools download/extract failed — skipping SDK setup"
                fi
                rm -f "$cmdline_zip"
                rm -rf /tmp/android-cmdline-unzip
            fi
        fi
    fi

    # -------------------------------------------------------------------------
    # Container: Docker + docker-compose
    # -------------------------------------------------------------------------
    section "System Tools — Docker"

    step "docker"
    if command -v docker &>/dev/null; then
        info "docker already installed — $(docker --version 2>&1)"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            step "Docker Desktop (macOS)"
            if brew list --cask docker &>/dev/null 2>&1; then
                info "Docker Desktop cask already installed"
            else
                if brew install --cask docker 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                    ok "Docker Desktop installed"
                else
                    warn "Docker Desktop install failed — install manually from https://www.docker.com/products/docker-desktop/"
                fi
            fi
            warn "ACTION REQUIRED: Open Docker Desktop and complete the initial setup before continuing."
        elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
            step "Docker Engine (Linux/Debian)"
            if curl -fsSL https://get.docker.com -o /tmp/get-docker.sh 2>&1 | tee -a "$ONEINFINITY_LOG" \
                && sh /tmp/get-docker.sh 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                ok "Docker Engine installed"
                # Add current user to docker group
                if id -nG "$USER" | grep -qw docker 2>/dev/null; then
                    info "User $USER already in docker group"
                else
                    sudo usermod -aG docker "$USER" 2>&1 | tee -a "$ONEINFINITY_LOG" || warn "Could not add $USER to docker group"
                    warn "Log out and back in (or run 'newgrp docker') for docker group to take effect"
                fi
                rm -f /tmp/get-docker.sh
            else
                warn "get-docker.sh failed — install Docker manually from https://docs.docker.com/engine/install/"
                rm -f /tmp/get-docker.sh
            fi
        elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
            step "Docker Engine (Linux/RHEL)"
            _dnf_install yum-utils
            if sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo 2>&1 | tee -a "$ONEINFINITY_LOG" \
                && sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>&1 | tee -a "$ONEINFINITY_LOG" \
                && sudo systemctl enable --now docker 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                ok "Docker Engine installed (RHEL)"
            else
                warn "Docker install (RHEL) failed — install manually"
            fi
        elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
            _pacman_install docker docker-compose
            sudo systemctl enable --now docker 2>&1 | tee -a "$ONEINFINITY_LOG" || warn "Could not enable docker service"
        fi
    fi

    # docker compose plugin check
    step "docker compose plugin"
    if docker compose version &>/dev/null 2>&1; then
        ok "docker compose plugin available — $(docker compose version 2>&1)"
    elif command -v docker-compose &>/dev/null; then
        ok "docker-compose (standalone) available — $(docker-compose --version 2>&1)"
        warn "Consider upgrading to the docker compose plugin for full compatibility"
    else
        warn "docker compose not found — install the docker compose plugin"
    fi

    # -------------------------------------------------------------------------
    # Exploitation / Post-exploitation
    # -------------------------------------------------------------------------
    section "System Tools — Exploitation/Post-Exploitation"

    # socat
    step "socat"
    if command -v socat &>/dev/null; then
        info "socat already installed"
    else
        _pkg_install socat socat socat socat
    fi

    # smbclient (Linux-primary; warn on macOS)
    step "smbclient"
    if command -v smbclient &>/dev/null; then
        info "smbclient already installed"
    elif [[ "${OS_TYPE:-}" == "macos" ]]; then
        warn "smbclient: install via 'brew install samba' if needed (optional on macOS)"
        # Offer anyway but do not force
    elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
        _apt_install smbclient
    elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
        _dnf_install samba-client
    elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
        _pacman_install smbclient
    fi

    # enum4linux-ng
    step "enum4linux-ng"
    _pip_install_sys "enum4linux-ng" "enum4linux-ng"

    # msfvenom / Metasploit — too complex for auto-install
    step "Metasploit / msfvenom"
    if command -v msfvenom &>/dev/null 2>&1; then
        info "msfvenom already available — $(msfvenom --version 2>&1 | head -1)"
    else
        warn "Metasploit is NOT installed automatically (complex dependency chain)."
        warn "  macOS : brew install metasploit"
        warn "  Kali  : apt install metasploit-framework (pre-installed on Kali Linux)"
        warn "  Other : https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
    fi

    # -------------------------------------------------------------------------
    # Secret scanning
    # -------------------------------------------------------------------------
    section "System Tools — Secret Scanning"

    # gitleaks — Go binary
    step "gitleaks"
    if command -v gitleaks &>/dev/null; then
        info "gitleaks already installed"
    else
        _go_install "github.com/gitleaks/gitleaks/v8@latest"
    fi

    # trufflehog
    step "trufflehog"
    if command -v trufflehog &>/dev/null; then
        info "trufflehog already installed"
    else
        if [[ "${OS_TYPE:-}" == "macos" ]]; then
            _brew_install trufflehog
        else
            # Linux: binary download from GitHub releases
            local th_arch th_url th_bin th_tag
            th_tag="$(curl -sSf https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest 2>/dev/null \
                | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/')"
            th_arch="$(uname -m)"
            case "$th_arch" in
                x86_64)  th_arch="amd64" ;;
                aarch64) th_arch="arm64" ;;
                armv7*)  th_arch="arm" ;;
            esac
            if [[ -z "$th_tag" ]]; then
                warn "trufflehog: could not determine latest release — skipping"
            else
                th_url="https://github.com/trufflesecurity/trufflehog/releases/download/v${th_tag}/trufflehog_${th_tag}_linux_${th_arch}.tar.gz"
                th_bin="$HOME/.local/bin/trufflehog"
                if curl -sSL "$th_url" -o /tmp/trufflehog.tar.gz 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && tar -xzf /tmp/trufflehog.tar.gz -C /tmp trufflehog 2>&1 | tee -a "$ONEINFINITY_LOG" \
                    && mv /tmp/trufflehog "$th_bin" \
                    && chmod +x "$th_bin"; then
                    ok "trufflehog installed → $th_bin (v${th_tag})"
                else
                    warn "trufflehog download failed — skipping"
                fi
                rm -f /tmp/trufflehog.tar.gz
            fi
        fi
    fi

    # -------------------------------------------------------------------------
    # eBPF tools (Linux only)
    # -------------------------------------------------------------------------
    section "System Tools — eBPF (Linux only)"

    if [[ "${OS_TYPE:-}" == "macos" ]]; then
        info "eBPF tools: macOS uses DTrace — skipping clang/llvm/bpftool"
    elif [[ "${DISTRO_FAMILY:-}" == "debian" ]]; then
        step "clang + llvm + bpftool (Ubuntu/Debian)"
        _apt_install clang llvm linux-tools-generic
    elif [[ "${DISTRO_FAMILY:-}" == "redhat" ]]; then
        step "clang + llvm + bpftool (RHEL/Fedora)"
        _dnf_install clang llvm bpftool
    elif [[ "${DISTRO_FAMILY:-}" == "arch" ]]; then
        step "clang + llvm + bpftool (Arch)"
        _pacman_install clang llvm bpftool
    else
        warn "eBPF tools: unknown Linux distro — install clang llvm bpftool manually"
    fi

    section "System Tools — Complete"
    ok "All system tools processed"
}

# ============================================================================
# SECTION F — Custom OneInfinity Go Binaries
# ============================================================================
# section_F_custom_go.sh — Build OneInfinity Custom Go Binaries
# Part of the OneInfinity master installer.
# Requires: REPO_DIR, ONEINFINITY_LOG, ok(), warn(), err(), info(), step(), section()
# Color vars: RED GREEN YELLOW CYAN BOLD NC

# ---------------------------------------------------------------------------
# build_custom_go_binaries
# ---------------------------------------------------------------------------
build_custom_go_binaries() {
    section "Custom Go Binaries"

    if ! command -v go &>/dev/null; then
        err "Go not found — skipping custom binary builds"
        return 1
    fi

    local go_src_dir="$REPO_DIR/src/go"

    if [[ ! -d "$go_src_dir" ]]; then
        err "Go source directory not found: $go_src_dir"
        return 1
    fi

    # Ensure output directory exists and is on PATH
    local out_dir="$HOME/.local/bin"
    mkdir -p "$out_dir"

    cd "$go_src_dir" || { err "Cannot cd into $go_src_dir"; return 1; }

    # Verify go.work exists — all sub-modules share the workspace
    if [[ ! -f "go.work" ]]; then
        warn "go.work not found in $go_src_dir — workspace may not resolve dependencies correctly"
    fi

    # Map: module_dir → output_binary_name (+ optional sub-package suffix)
    local -a BUILD_TARGETS=(
        "oi-credential-spray:oi-credential-spray:./oi-credential-spray/"
        "oi-service-cve-mapper:oi-service-cve-mapper:./oi-service-cve-mapper/"
        "oi-ssrf:oi-ssrf:./oi-ssrf/"
        "oi-recon-probe:oi-recon-probe:./oi-recon-probe/"
        "oi-idor-engine:oi-idor-engine:./oi-idor-engine/"
        "oi-target-disc:oi-target-disc:./oi-target-disc/"
        "oi-crawler:oi-crawler:./oi-crawler/cmd/"
        "oi-oob-listener:oi-oob-listener:./oi-oob-listener/"
        "oi-lateral-portscan:oi-lateral-portscan:./oi-lateral-portscan/"
    )
    # oi-ebpf-trace: Linux-only (uses BPF syscall; skipped on macOS where DTrace is used)
    if [[ "${OS_TYPE:-}" == "linux" ]]; then
        BUILD_TARGETS+=("oi-ebpf-trace:oi-ebpf-trace:./oi-ebpf-trace/")
    else
        info "oi-ebpf-trace: Linux-only — skipping on macOS (StealthTracer uses DTrace/Frida)"
    fi

    local built=0
    local failed=0

    for entry in "${BUILD_TARGETS[@]}"; do
        local mod_dir  bin_name  pkg_path
        IFS=':' read -r mod_dir bin_name pkg_path <<< "$entry"

        step "Building $bin_name"

        if [[ ! -d "$go_src_dir/$mod_dir" ]]; then
            warn "Module directory not found: $go_src_dir/$mod_dir — skipping $bin_name"
            (( failed++ )) || true
            continue
        fi

        local out_bin="$out_dir/$bin_name"

        # Build from workspace root so go.work resolution applies
        if go build -o "$out_bin" "$pkg_path" >> "$ONEINFINITY_LOG" 2>&1; then
            chmod +x "$out_bin"
            ok "$bin_name → $out_bin"
            (( built++ )) || true
        else
            warn "Build failed for $bin_name — check $ONEINFINITY_LOG"
            (( failed++ )) || true
        fi
    done

    if (( built > 0 )); then
        ok "Custom Go binaries: $built built, $failed failed"
    else
        warn "No custom Go binaries were built successfully"
    fi

    # ---------------------------------------------------------------------------
    # Frida TypeScript hooks
    # ---------------------------------------------------------------------------
    section "Frida TypeScript Hooks"

    local frida_dir="$REPO_DIR/src/frida-hooks"

    if [[ ! -d "$frida_dir" ]]; then
        warn "Frida hooks directory not found: $frida_dir — skipping"
        return 0
    fi

    if ! command -v node &>/dev/null; then
        warn "Node.js not found — skipping Frida hooks build"
        return 0
    fi

    if ! command -v npm &>/dev/null; then
        warn "npm not found — skipping Frida hooks build"
        return 0
    fi

    cd "$frida_dir" || { warn "Cannot cd into $frida_dir"; return 0; }

    step "Installing Frida hooks npm dependencies"
    if npm install >> "$ONEINFINITY_LOG" 2>&1; then
        ok "npm install complete"
    else
        warn "npm install failed for Frida hooks — check $ONEINFINITY_LOG"
        return 0
    fi

    step "Compiling Frida TypeScript hooks"
    if npm run build >> "$ONEINFINITY_LOG" 2>&1; then
        ok "Frida TypeScript hooks compiled"
    else
        warn "Frida hooks build failed — hooks will not be available"
    fi
}

# ============================================================================
# SECTION G — Database Setup (Docker: PostgreSQL + Redis + Neo4j)
# ============================================================================
# section_G_databases.sh — Database Setup via Docker
# Part of the OneInfinity master installer.
# Requires: REPO_DIR, ONEINFINITY_LOG, PG_USER, PG_PASS, PG_DB, PG_PORT,
#           REDIS_PASS, REDIS_PORT, NEO4J_USER, NEO4J_PASS, NEO4J_BOLT, NEO4J_HTTP
# Functions expected from scaffold: ok() warn() err() info() step() section()

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Poll until postgres is ready or timeout
wait_for_postgres() {
    local timeout="${1:-60}"
    local elapsed=0
    step "Waiting for PostgreSQL to be ready (up to ${timeout}s)…"
    while (( elapsed < timeout )); do
        if docker exec oneinfinity-postgres pg_isready -U "$PG_USER" -d "$PG_DB" \
               -h localhost -p "$PG_PORT" &>/dev/null; then
            ok "PostgreSQL is ready"
            return 0
        fi
        sleep 2
        (( elapsed += 2 )) || true
    done
    err "PostgreSQL did not become ready within ${timeout}s"
    return 1
}

# Poll until redis responds to PING
wait_for_redis() {
    local timeout="${1:-60}"
    local elapsed=0
    step "Waiting for Redis to be ready (up to ${timeout}s)…"
    while (( elapsed < timeout )); do
        local pong
        pong=$(docker exec oneinfinity-redis redis-cli -a "$REDIS_PASS" --no-auth-warning \
                   ping 2>/dev/null | tr -d '[:space:]')
        if [[ "$pong" == "PONG" ]]; then
            ok "Redis is ready"
            return 0
        fi
        sleep 2
        (( elapsed += 2 )) || true
    done
    err "Redis did not become ready within ${timeout}s"
    return 1
}

# Poll until Neo4j HTTP endpoint returns 200
wait_for_neo4j() {
    local timeout="${1:-60}"
    local elapsed=0
    step "Waiting for Neo4j to be ready (up to ${timeout}s)…"
    while (( elapsed < timeout )); do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                        "http://localhost:${NEO4J_HTTP}" 2>/dev/null)
        if [[ "$http_code" == "200" ]]; then
            ok "Neo4j is ready"
            return 0
        fi
        sleep 2
        (( elapsed += 2 )) || true
    done
    err "Neo4j did not become ready within ${timeout}s"
    return 1
}

# ---------------------------------------------------------------------------
# Write docker-compose.db.yml
# ---------------------------------------------------------------------------
_write_db_compose() {
    local compose_file="$REPO_DIR/docker-compose.db.yml"

    info "Writing $compose_file"

    cat > "$compose_file" << COMPOSE_EOF
# docker-compose.db.yml — OneInfinity databases (standalone subset)
# Generated by install.sh — edit to override defaults.
version: "3.9"

services:

  postgres:
    image: postgres:16
    container_name: oneinfinity-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: "${PG_USER}"
      POSTGRES_PASSWORD: "${PG_PASS}"
      POSTGRES_DB: "${PG_DB}"
    ports:
      - "${PG_PORT}:5432"
    volumes:
      - oneinfinity-pg-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${PG_USER} -d ${PG_DB}"]
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 20s

  redis:
    image: redis:7-alpine
    container_name: oneinfinity-redis
    restart: unless-stopped
    command: redis-server --requirepass "${REDIS_PASS}"
    ports:
      - "${REDIS_PORT}:6379"
    volumes:
      - oneinfinity-redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "${REDIS_PASS}", "--no-auth-warning", "ping"]
      interval: 10s
      timeout: 5s
      retries: 6
      start_period: 10s

  neo4j:
    image: neo4j:5
    container_name: oneinfinity-neo4j
    restart: unless-stopped
    environment:
      NEO4J_AUTH: "${NEO4J_USER}/${NEO4J_PASS}"
      NEO4J_PLUGINS: '["apoc"]'
      NEO4J_apoc_export_file_enabled: "true"
      NEO4J_apoc_import_file_enabled: "true"
      NEO4J_dbms_security_procedures_unrestricted: "apoc.*"
    ports:
      - "${NEO4J_HTTP}:7474"
      - "${NEO4J_BOLT}:7687"
    volumes:
      - oneinfinity-neo4j-data:/data
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:7474 || exit 1"]
      interval: 15s
      timeout: 10s
      retries: 8
      start_period: 30s

volumes:
  oneinfinity-pg-data:
  oneinfinity-redis-data:
  oneinfinity-neo4j-data:
COMPOSE_EOF

    ok "docker-compose.db.yml written"
}

# ---------------------------------------------------------------------------
# setup_databases  (fresh install)
# ---------------------------------------------------------------------------
setup_databases() {
    section "Database Services (Docker)"

    # -- Verify Docker is running -----------------------------------------
    step "Checking Docker daemon"
    if ! docker info &>/dev/null; then
        warn "Docker daemon not running — attempting to start…"

        if [[ "$(uname -s)" == "Darwin" ]]; then
            # macOS: start Docker Desktop if the app bundle exists
            if [[ -d "/Applications/Docker.app" ]]; then
                open -a Docker
                info "Waiting up to 60s for Docker Desktop to start…"
                local d=0
                while (( d < 60 )); do
                    sleep 3; (( d += 3 )) || true
                    docker info &>/dev/null && break
                done
            fi
        else
            # Linux: try systemctl
            if command -v systemctl &>/dev/null; then
                sudo systemctl start docker 2>/dev/null || true
                sleep 3
            fi
        fi

        if ! docker info &>/dev/null; then
            err "Docker is not running and could not be started automatically."
            err "Please start Docker and re-run the installer."
            echo ""
            echo "  macOS:   open -a Docker"
            echo "  Linux:   sudo systemctl start docker"
            return 1
        fi
        ok "Docker is now running"
    else
        ok "Docker daemon running"
    fi

    # -- Write compose file -----------------------------------------------
    _write_db_compose

    # -- Launch containers ------------------------------------------------
    step "Starting database containers"
    if ! docker compose -f "$REPO_DIR/docker-compose.db.yml" up -d \
           >> "$ONEINFINITY_LOG" 2>&1; then
        err "docker compose up failed — check $ONEINFINITY_LOG"
        return 1
    fi
    ok "Containers started"

    # -- Wait for readiness -----------------------------------------------
    wait_for_postgres 60 || return 1
    wait_for_redis    60 || return 1
    wait_for_neo4j    60 || return 1

    # -- Apply schema ---------------------------------------------------------
    step "Applying PostgreSQL schema"
    local schema_file="$REPO_DIR/db/schema.sql"
    if [[ -f "$schema_file" ]]; then
        if PGPASSWORD="$PG_PASS" docker exec -i oneinfinity-postgres \
               psql -U "$PG_USER" -d "$PG_DB" \
               < "$schema_file" >> "$ONEINFINITY_LOG" 2>&1; then
            ok "PostgreSQL schema applied"
        else
            warn "Schema apply returned non-zero — tables may already exist (safe to ignore on re-run)"
        fi
    else
        warn "Schema file not found at $schema_file — skipping"
    fi
}

# ---------------------------------------------------------------------------
# update_docker_images  (update mode)
# ---------------------------------------------------------------------------
update_docker_images() {
    section "Updating Database Docker Images"

    if [[ ! -f "$REPO_DIR/docker-compose.db.yml" ]]; then
        warn "docker-compose.db.yml not found — running setup instead"
        setup_databases
        return
    fi

    step "Pulling latest database images"
    docker compose -f "$REPO_DIR/docker-compose.db.yml" pull \
        >> "$ONEINFINITY_LOG" 2>&1 || warn "Image pull had warnings"

    step "Restarting containers with updated images"
    if docker compose -f "$REPO_DIR/docker-compose.db.yml" up -d \
           >> "$ONEINFINITY_LOG" 2>&1; then
        ok "Database containers updated and restarted"
    else
        warn "docker compose up had warnings — check $ONEINFINITY_LOG"
    fi
}

# ============================================================================
# SECTION H — MobSF Setup (Docker)
# ============================================================================
# section_H_mobsf.sh — MobSF Container Setup
# Part of the OneInfinity master installer.
# Requires: REPO_DIR, ONEINFINITY_LOG, MOBSF_PORT
# Functions expected from scaffold: ok() warn() err() info() step() section()

# ---------------------------------------------------------------------------
# Internal: poll MobSF HTTP until ready
# ---------------------------------------------------------------------------
_wait_for_mobsf() {
    local timeout="${1:-90}"
    local elapsed=0
    step "Waiting for MobSF to start (up to ${timeout}s)…"
    while (( elapsed < timeout )); do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                        "http://localhost:${MOBSF_PORT}" 2>/dev/null)
        if [[ "$http_code" =~ ^(200|301|302)$ ]]; then
            ok "MobSF is responding on port ${MOBSF_PORT}"
            return 0
        fi
        sleep 3
        (( elapsed += 3 )) || true
    done
    warn "MobSF did not respond within ${timeout}s"
    return 1
}

# ---------------------------------------------------------------------------
# Internal: attempt to extract API key from container logs
# ---------------------------------------------------------------------------
_extract_mobsf_api_key() {
    local timeout="${1:-90}"
    local elapsed=0
    local api_key=""

    step "Extracting MobSF REST API key from container logs (up to ${timeout}s)…"
    while (( elapsed < timeout )); do
        api_key=$(docker logs oneinfinity-mobsf 2>&1 \
                  | grep -oE 'REST API Key\s*:\s*[A-Za-z0-9_-]+' \
                  | head -1 \
                  | sed 's/.*:\s*//')
        # Also try alternate log format used in newer MobSF builds
        if [[ -z "$api_key" ]]; then
            api_key=$(docker logs oneinfinity-mobsf 2>&1 \
                      | grep -oP '(?<=REST API Key: )\w+' \
                      | head -1)
        fi
        if [[ -n "$api_key" ]]; then
            echo "$api_key"
            return 0
        fi
        sleep 3
        (( elapsed += 3 )) || true
    done
    return 1
}

# ---------------------------------------------------------------------------
# Internal: persist API key into $REPO_DIR/.env (merge, never overwrite)
# ---------------------------------------------------------------------------
_store_mobsf_api_key() {
    local key="$1"
    local env_file="$REPO_DIR/.env"

    [[ -z "$key" ]] && return 0

    if grep -q "^MOBSF_API_KEY=" "$env_file" 2>/dev/null; then
        # Replace existing placeholder/empty value only
        local existing
        existing=$(grep "^MOBSF_API_KEY=" "$env_file" | cut -d'=' -f2-)
        if [[ -z "$existing" || "$existing" == "your-mobsf-api-key" ]]; then
            # Use portable in-place sed (works on both macOS and Linux)
            sed -i.bak "s|^MOBSF_API_KEY=.*|MOBSF_API_KEY=${key}|" "$env_file" \
                && rm -f "${env_file}.bak"
            ok "MOBSF_API_KEY updated in .env"
        else
            info "MOBSF_API_KEY already set in .env — not overwriting"
        fi
    else
        echo "MOBSF_API_KEY=${key}" >> "$env_file"
        ok "MOBSF_API_KEY appended to .env"
    fi

    # Export for this session so downstream steps can use it
    export MOBSF_API_KEY="$key"
}

# ---------------------------------------------------------------------------
# setup_mobsf  (main entry point)
# ---------------------------------------------------------------------------
setup_mobsf() {
    section "MobSF Mobile Security Framework"

    # -- Verify Docker is running ------------------------------------------
    if ! docker info &>/dev/null; then
        err "Docker is not running — cannot set up MobSF"
        return 1
    fi

    # -- Pull latest image -------------------------------------------------
    step "Pulling MobSF image (opensecurity/mobile-security-framework-mobsf:latest)"
    if ! docker pull opensecurity/mobile-security-framework-mobsf:latest \
           >> "$ONEINFINITY_LOG" 2>&1; then
        warn "docker pull had warnings — trying to use cached image"
    else
        ok "MobSF image up to date"
    fi

    # -- Remove any stale container ----------------------------------------
    step "Removing stale MobSF container (if any)"
    docker rm -f oneinfinity-mobsf >> "$ONEINFINITY_LOG" 2>&1 || true

    # -- Start container ---------------------------------------------------
    step "Starting MobSF container on port ${MOBSF_PORT}"
    if ! docker run -d \
            --name oneinfinity-mobsf \
            -p "${MOBSF_PORT}:8008" \
            -v oneinfinity-mobsf-data:/home/mobsf/.MobSF \
            --restart unless-stopped \
            opensecurity/mobile-security-framework-mobsf:latest \
            >> "$ONEINFINITY_LOG" 2>&1; then
        err "Failed to start MobSF container — check $ONEINFINITY_LOG"
        return 1
    fi
    ok "MobSF container started"

    # -- Wait for HTTP readiness -------------------------------------------
    _wait_for_mobsf 90 || true   # non-fatal; key extraction can still succeed

    # -- Extract API key ---------------------------------------------------
    local api_key=""
    api_key=$(_extract_mobsf_api_key 90) && true   # capture even if grep finds nothing

    if [[ -n "$api_key" ]]; then
        ok "MobSF REST API Key extracted: ${BOLD}${api_key:0:8}…${NC}"
        _store_mobsf_api_key "$api_key"
    else
        warn "Could not auto-extract MobSF API key."
        echo ""
        echo -e "  ${CYAN}Please open:${NC}  http://localhost:${MOBSF_PORT}"
        echo -e "  ${CYAN}Log in with:${NC}  admin / mobsf"
        echo -e "  ${CYAN}Go to:${NC}        Settings > REST API Key"
        echo -e "  ${CYAN}Then paste it here${NC} (or press Enter to skip):"
        printf "  API Key: "
        local user_key=""
        read -r user_key
        if [[ -n "$user_key" ]]; then
            _store_mobsf_api_key "$user_key"
            ok "MobSF API key saved from user input"
        else
            warn "MobSF API key not configured — set MOBSF_API_KEY in .env manually"
        fi
    fi
}

# ---------------------------------------------------------------------------
# update_mobsf  (update mode — pull new image, restart)
# ---------------------------------------------------------------------------
update_mobsf() {
    section "Updating MobSF"

    step "Pulling latest MobSF image"
    docker pull opensecurity/mobile-security-framework-mobsf:latest \
        >> "$ONEINFINITY_LOG" 2>&1 || warn "MobSF image pull had warnings"

    step "Restarting MobSF container"
    docker rm -f oneinfinity-mobsf >> "$ONEINFINITY_LOG" 2>&1 || true

    # Re-run startup with existing data volume (preserves scans/settings)
    docker run -d \
        --name oneinfinity-mobsf \
        -p "${MOBSF_PORT}:8008" \
        -v oneinfinity-mobsf-data:/home/mobsf/.MobSF \
        --restart unless-stopped \
        opensecurity/mobile-security-framework-mobsf:latest \
        >> "$ONEINFINITY_LOG" 2>&1 && ok "MobSF updated and restarted" \
        || warn "MobSF restart had issues — check $ONEINFINITY_LOG"
}

# ============================================================================
# SECTION I — Rust Core Build (oneinfinity_core / PyO3 / maturin)
# ============================================================================
# section_I_rust.sh — Rust Core Build (maturin / PyO3)
# Part of the OneInfinity master installer.
# Requires: REPO_DIR, ONEINFINITY_LOG
# Functions expected from scaffold: ok() warn() err() info() step() section()

# ---------------------------------------------------------------------------
# build_rust_core
# ---------------------------------------------------------------------------
build_rust_core() {
    section "Rust Core (oneinfinity_core)"

    local rust_dir="$REPO_DIR/src/rust/oneinfinity_core"

    if [[ ! -d "$rust_dir" ]]; then
        err "Rust core directory not found: $rust_dir"
        return 1
    fi

    # -- Verify Rust toolchain ---------------------------------------------
    if ! command -v cargo &>/dev/null; then
        err "cargo not found — install Rust via https://rustup.rs and re-run"
        return 1
    fi

    local rust_ver
    rust_ver=$(rustc --version 2>/dev/null)
    info "Rust: $rust_ver"

    # -- Verify Python -----------------------------------------------------
    if ! command -v python &>/dev/null && ! command -v python3 &>/dev/null; then
        err "Python not found — required for maturin"
        return 1
    fi
    local python_bin
    python_bin=$(command -v python3 2>/dev/null || command -v python)

    # -- Ensure maturin is available (standalone binary takes priority) ----
    step "Ensuring maturin is installed"
    local maturin_cmd=""
    if command -v maturin &>/dev/null; then
        maturin_cmd="maturin"
        ok "maturin (standalone): $(maturin --version 2>/dev/null)"
    elif "$python_bin" -m maturin --version &>/dev/null 2>&1; then
        maturin_cmd="$python_bin -m maturin"
        ok "maturin (python module): $($python_bin -m maturin --version 2>/dev/null)"
    else
        "$python_bin" -m pip install --quiet maturin 2>&1 | tee -a "$ONEINFINITY_LOG"
        if command -v maturin &>/dev/null; then
            maturin_cmd="maturin"
        elif "$python_bin" -m maturin --version &>/dev/null 2>&1; then
            maturin_cmd="$python_bin -m maturin"
        else
            err "maturin install failed — install manually: pip install maturin  OR  brew install maturin"
            return 1
        fi
        ok "maturin installed: $($maturin_cmd --version 2>/dev/null || true)"
    fi

    cd "$rust_dir" || { err "Cannot cd into $rust_dir"; return 1; }

    # -- Build with ABI3 forward compatibility ----------------------------
    # Required for Python 3.14+ because PyO3 >= 0.22 targets the stable ABI.
    step "Building oneinfinity_core with maturin (release mode)"
    local _saved_pyo3="${PYO3_USE_ABI3_FORWARD_COMPATIBILITY:-__unset__}"
    export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1

    if $maturin_cmd develop --release 2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "maturin develop --release succeeded"
    else
        [[ "$_saved_pyo3" == "__unset__" ]] && unset PYO3_USE_ABI3_FORWARD_COMPATIBILITY || export PYO3_USE_ABI3_FORWARD_COMPATIBILITY="$_saved_pyo3"
        warn "maturin develop --release returned non-zero — see $ONEINFINITY_LOG"
        warn "Python fallback will be used where available"
        return 0   # non-fatal
    fi
    [[ "$_saved_pyo3" == "__unset__" ]] && unset PYO3_USE_ABI3_FORWARD_COMPATIBILITY || export PYO3_USE_ABI3_FORWARD_COMPATIBILITY="$_saved_pyo3"

    # -- Verify the .so is importable --------------------------------------
    step "Verifying Rust core is importable"
    if "$python_bin" -c "import oneinfinity_core; print('Rust core loaded OK')" \
           2>&1 | tee -a "$ONEINFINITY_LOG"; then
        ok "Rust core built and importable"
    else
        warn "Rust core build succeeded but import check failed — Python fallback will be used"
    fi
}

# ---------------------------------------------------------------------------
# build_rust_fuzzer
# Build the oi-fuzzer binary (LibAFL-based HTTP fuzzer) from src/rust/oi-fuzzer
# ---------------------------------------------------------------------------
build_rust_fuzzer() {
    section "Rust oi-fuzzer (LibAFL)"

    local fuzzer_dir="$REPO_DIR/src/rust/oi-fuzzer"

    if [[ ! -d "$fuzzer_dir" ]]; then
        warn "oi-fuzzer directory not found: $fuzzer_dir — skipping"
        return 0
    fi

    if ! command -v cargo &>/dev/null; then
        warn "cargo not found — skipping oi-fuzzer build"
        return 0
    fi

    local out_dir="$HOME/.local/bin"
    mkdir -p "$out_dir"

    step "Building oi-fuzzer (release)"
    if (cd "$fuzzer_dir" && \
        cargo build --release 2>&1 | tee -a "$ONEINFINITY_LOG"); then
        if [[ -f "$fuzzer_dir/target/release/oi-fuzzer" ]]; then
            cp "$fuzzer_dir/target/release/oi-fuzzer" "$out_dir/oi-fuzzer"
            chmod +x "$out_dir/oi-fuzzer"
            ok "oi-fuzzer built → $out_dir/oi-fuzzer"
        else
            warn "oi-fuzzer binary not found after build — check $ONEINFINITY_LOG"
        fi
    else
        warn "oi-fuzzer cargo build failed — check $ONEINFINITY_LOG (non-fatal)"
    fi
}

# ---------------------------------------------------------------------------
# build_rust_jwt_crack
# Build the oi-jwt-crack binary (Rayon-parallel JWT secret brute-forcer)
# ---------------------------------------------------------------------------
build_rust_jwt_crack() {
    section "Rust oi-jwt-crack (JWT brute-forcer)"

    local crack_dir="$REPO_DIR/src/rust/oi-jwt-crack"

    if [[ ! -d "$crack_dir" ]]; then
        warn "oi-jwt-crack directory not found: $crack_dir — skipping"
        return 0
    fi

    if ! command -v cargo &>/dev/null; then
        warn "cargo not found — skipping oi-jwt-crack build"
        return 0
    fi

    local out_dir="$HOME/.local/bin"
    mkdir -p "$out_dir"

    step "Building oi-jwt-crack (release)"
    if (cd "$crack_dir" && \
        cargo build --release 2>&1 | tee -a "$ONEINFINITY_LOG"); then
        if [[ -f "$crack_dir/target/release/oi-jwt-crack" ]]; then
            cp "$crack_dir/target/release/oi-jwt-crack" "$out_dir/oi-jwt-crack"
            chmod +x "$out_dir/oi-jwt-crack"
            ok "oi-jwt-crack built → $out_dir/oi-jwt-crack (>2M candidates/sec)"
        else
            warn "oi-jwt-crack binary not found after build — check $ONEINFINITY_LOG"
        fi
    else
        warn "oi-jwt-crack cargo build failed — check $ONEINFINITY_LOG (non-fatal)"
    fi
}

# ---------------------------------------------------------------------------
# update_rust_core  (update mode — rebuild in place)
# ---------------------------------------------------------------------------
update_rust_core() {
    section "Rebuilding Rust Core (update)"
    build_rust_core
}

# ============================================================================
# SECTION J — Environment, Alias, Verification, Summary
# ============================================================================
# section_J_env_alias_verify.sh — Env Generation, Alias Setup, Verification
# Part of the OneInfinity master installer.
# Requires: REPO_DIR, ONEINFINITY_HOME, ONEINFINITY_LOG, INSTALL_MODE,
#           PG_USER, PG_PASS, PG_DB, PG_PORT, REDIS_PASS, REDIS_PORT,
#           NEO4J_USER, NEO4J_PASS, NEO4J_BOLT, NEO4J_HTTP,
#           MOBSF_PORT, WEB_BACKEND_PORT, IS_MAC, IS_LINUX
# Functions from scaffold: ok() warn() err() info() step() section() _log_to_file()

# ---------------------------------------------------------------------------
# _env_set_key  — write key=value to .env only if key is absent or blank
# ---------------------------------------------------------------------------
_env_set_key() {
    local key="$1"
    local value="$2"
    local env_file="$3"

    if grep -q "^${key}=" "$env_file" 2>/dev/null; then
        local existing
        existing=$(grep "^${key}=" "$env_file" | head -1 | cut -d'=' -f2-)
        if [[ -z "$existing" || "$existing" == "changeme" \
                              || "$existing" == "your-mobsf-api-key" \
                              || "$existing" == "~/.oneinfinity" ]]; then
            sed -i.bak "s|^${key}=.*|${key}=${value}|" "$env_file" \
                && rm -f "${env_file}.bak"
        fi
        # key present with a real value → leave it alone (never overwrite)
    else
        echo "${key}=${value}" >> "$env_file"
    fi
}

# ---------------------------------------------------------------------------
# install_ai_providers
# Detect + install free AI providers so users have AI features out of the box.
# Priority mirrors the orchestrator: Ollama > Antigravity (free) > Groq > paid APIs.
# Never fails — all steps are best-effort with actionable warnings.
# ---------------------------------------------------------------------------
install_ai_providers() {
    section "AI Provider Setup"

    local env_file="${REPO_DIR:-$PWD}/.env"

    # ── 1. Ollama (fully offline, zero cost) ────────────────────────────────
    step "Ollama (local LLM — fully offline)"
    if command -v ollama &>/dev/null; then
        local ollama_ver; ollama_ver="$(ollama --version 2>/dev/null | head -1)"
        ok "Ollama already installed: ${ollama_ver}"
    else
        info "Installing Ollama (free, runs models 100% locally)..."
        if curl -fsSL https://ollama.com/install.sh | sh >>"$ONEINFINITY_LOG" 2>&1; then
            ok "Ollama installed"
        else
            warn "Ollama install failed — install manually: https://ollama.com"
        fi
    fi

    # Pull a small default model if Ollama is available and nothing is pulled yet
    if command -v ollama &>/dev/null; then
        local pulled_models; pulled_models="$(ollama list 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
        if [[ "${pulled_models:-0}" -eq 0 ]]; then
            info "Pulling default model: llama3.2:3b (~2GB, good balance of speed/quality)"
            info "This runs in background — you can cancel with Ctrl-C and pull manually:"
            info "  ollama pull llama3.2:3b          (fast, ~2GB)"
            info "  ollama pull deepseek-r1:7b        (smarter reasoning, ~4GB)"
            if [[ "${NON_INTERACTIVE:-0}" -eq 1 ]]; then
                ollama pull llama3.2:3b >>"$ONEINFINITY_LOG" 2>&1 \
                    && ok "llama3.2:3b pulled" \
                    || warn "Model pull failed — run: ollama pull llama3.2:3b"
            else
                local _pull_model
                ask_user _pull_model "Pull llama3.2:3b now? (~2GB download) [Y/n]" "Y"
                if [[ "$_pull_model" =~ ^[Yy]$ || -z "$_pull_model" ]]; then
                    ollama pull llama3.2:3b 2>&1 | tee -a "$ONEINFINITY_LOG" \
                        && ok "llama3.2:3b ready" \
                        || warn "Model pull failed — run: ollama pull llama3.2:3b"
                else
                    info "Skipped — pull later: ollama pull llama3.2:3b"
                fi
            fi
        else
            ok "Ollama: ${pulled_models} model(s) already available"
        fi
    fi

    # ── 2. Antigravity CLI — free Gemini 2.0/2.5 via Google account ─────────
    step "Antigravity CLI (free Gemini via Google account)"
    if command -v agy &>/dev/null; then
        local agy_ver; agy_ver="$(agy --version 2>/dev/null | head -1)"
        ok "Antigravity CLI already installed: ${agy_ver:-unknown version}"
        # Check if authenticated
        if [[ -s "$HOME/.gemini/antigravity-cli/credentials.json" ]] \
            || [[ -s "$HOME/.gemini/oauth_creds.json" ]]; then
            ok "Antigravity: authenticated (Gemini 2.0 Flash + 2.5 Pro ready)"
        else
            warn "Antigravity CLI installed but not authenticated."
            warn "Run: agy   (opens browser for Google Sign-In — takes 30 seconds)"
        fi
    else
        info "Installing Antigravity CLI (free Gemini 2.0 Flash + 2.5 Pro, 1M context)..."
        if curl -fsSL https://antigravity.google/cli/install.sh | bash >>"$ONEINFINITY_LOG" 2>&1; then
            # Ensure ~/.local/bin is on PATH for this session
            export PATH="$HOME/.local/bin:$PATH"
            if command -v agy &>/dev/null; then
                ok "Antigravity CLI installed → $(agy --version 2>/dev/null | head -1)"
                echo ""
                echo -e "  ${BOLD}${YELLOW}ACTION REQUIRED — Free Gemini setup (30 seconds):${NC}"
                echo -e "    ${CYAN}agy${NC}   ← opens browser for Google Sign-In"
                echo -e "    Sign in with any Google account → credentials saved to ~/.gemini/"
                echo -e "    Close agy with Ctrl-C after login — OneInfinity will use it automatically."
                echo ""
                if [[ "${NON_INTERACTIVE:-0}" -eq 0 ]]; then
                    local _do_login
                    ask_user _do_login "Run agy now to authenticate? [Y/n]" "Y"
                    if [[ "$_do_login" =~ ^[Yy]$ || -z "$_do_login" ]]; then
                        info "Opening Antigravity CLI for authentication — close with Ctrl-C when done..."
                        agy || true
                        if [[ -s "$HOME/.gemini/antigravity-cli/credentials.json" ]] \
                            || [[ -s "$HOME/.gemini/oauth_creds.json" ]]; then
                            ok "Antigravity: authenticated ✓"
                        else
                            warn "No credentials file found — run: agy  (to complete sign-in)"
                        fi
                    else
                        info "Run: agy  (after installation to activate free Gemini access)"
                    fi
                fi
            else
                warn "Antigravity CLI install script ran but agy not in PATH yet."
                warn "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\""
                warn "Then run: agy  (to authenticate)"
            fi
        elif [[ "${IS_MAC:-false}" == "true" ]] && command -v brew &>/dev/null; then
            info "Trying Homebrew cask as fallback..."
            if brew install --cask antigravity-cli >>"$ONEINFINITY_LOG" 2>&1 \
                && command -v agy &>/dev/null; then
                ok "Antigravity CLI installed via Homebrew → run: agy  (to authenticate)"
            else
                warn "Antigravity install failed. Install manually:"
                warn "  curl -fsSL https://antigravity.google/cli/install.sh | bash"
                warn "  brew install --cask antigravity-cli"
            fi
        else
            warn "Antigravity install failed. Install manually:"
            warn "  curl -fsSL https://antigravity.google/cli/install.sh | bash"
            warn "  Provides free Gemini 2.0 Flash + 2.5 Pro (1M context, Google account only)"
        fi
    fi

    # ── 3. Groq free-tier API key (optional prompt) ──────────────────────────
    step "Groq free API (LLaMA3 70B, Mixtral — optional)"
    local existing_groq; existing_groq="$(grep '^GROQ_API_KEY=' "$env_file" 2>/dev/null | cut -d= -f2-)"
    if [[ -n "$existing_groq" && "$existing_groq" != "your-groq-key" ]]; then
        ok "Groq API key already configured"
    elif [[ "${NON_INTERACTIVE:-0}" -eq 1 ]]; then
        info "Non-interactive: skipping Groq key prompt. Add GROQ_API_KEY= to .env manually."
        info "  Sign up free at https://console.groq.com (no credit card required)"
    else
        echo ""
        echo -e "  ${CYAN}Groq (free cloud AI):${NC} LLaMA3 70B, Mixtral — generous free daily limits"
        echo -e "  Sign up free at ${BOLD}https://console.groq.com${NC} (no credit card required)"
        echo ""
        local _groq_key
        ask_user _groq_key "Paste your GROQ_API_KEY (or press Enter to skip)" ""
        if [[ -n "$_groq_key" ]]; then
            _env_set_key "GROQ_API_KEY" "$_groq_key" "$env_file"
            ok "GROQ_API_KEY saved to .env"
        else
            info "Skipped — add later: GROQ_API_KEY=gsk_... in ${REPO_DIR}/.env"
        fi
    fi

    # ── 4. WhiteRabbitNeo (optional — pentest-specific uncensored model) ──────
    # Best lightweight model purpose-built for penetration testing.
    # Fine-tuned on: CVEs, exploit code, MITRE ATT&CK, malware analysis, red team ops.
    # Requires Ollama. Fully optional — only offered when RAM supports it.
    if command -v ollama &>/dev/null && [[ "${NON_INTERACTIVE:-0}" -eq 0 ]]; then
        echo ""
        echo -e "  ${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${BOLD}  🐇  WhiteRabbitNeo — Pentest AI Model (Optional)${NC}"
        echo -e "  ${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  Purpose-built for penetration testing. No guardrails."
        echo -e "  Trained on: CVEs, exploit code, MITRE ATT&CK, shellcode, red team ops."
        echo -e "  ${YELLOW}Use only against systems you own or have written authorisation to test.${NC}"
        echo ""

        # ── Detect available RAM ─────────────────────────────────────────────
        local ram_kb=0
        if [[ "$IS_MAC" == "true" ]]; then
            ram_kb=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024 ))
        else
            ram_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
        fi
        local ram_gb=$(( ram_kb / 1024 / 1024 ))

        # ── Pick model tier based on RAM ─────────────────────────────────────
        # All variants are ~5-6GB model weight; RAM floor includes OS + Ollama overhead.
        local wrn_model=""
        local wrn_size=""
        local wrn_ram_needed=""

        if [[ $ram_gb -ge 10 ]]; then
            # Primary recommendation: v2.5 on Qwen2.5-Coder 7B — best current version
            wrn_model="lazarevtill/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B"
            wrn_size="~5.0GB download"
            wrn_ram_needed="8GB+"
        elif [[ $ram_gb -ge 8 ]]; then
            # v2.0 on Llama3 8B — still excellent, slightly older
            wrn_model="lazarevtill/Llama-3-WhiteRabbitNeo-8B-v2.0"
            wrn_size="~4.7GB download"
            wrn_ram_needed="8GB+"
        elif [[ $ram_gb -ge 6 ]]; then
            # v1.5a — lightest official build
            wrn_model="monotykamary/whiterabbitneo-v1.5a"
            wrn_size="~4.1GB download"
            wrn_ram_needed="6GB+"
        else
            echo -e "  ${YELLOW}⚠️  ${ram_gb}GB RAM detected — WhiteRabbitNeo requires at least 6GB.${NC}"
            echo -e "  ${YELLOW}   Skipping. Pull manually when you have more RAM:${NC}"
            echo -e "    ${CYAN}ollama pull lazarevtill/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B${NC}"
            echo ""
        fi

        if [[ -n "$wrn_model" ]]; then
            echo -e "  ${BOLD}Detected RAM: ${GREEN}${ram_gb}GB${NC}  →  Recommended: ${BOLD}${wrn_model}${NC}"
            echo -e "  Size: ${wrn_size}   Min RAM: ${wrn_ram_needed}"
            echo ""
            echo -e "  ${CYAN}Model tiers available:${NC}"
            echo -e "    ${BOLD}v2.5 Qwen2.5-Coder 7B${NC}  (best, ~5.0GB)  —  lazarevtill/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B  [10GB+ RAM]"
            echo -e "    ${BOLD}v2.0 Llama3 8B       ${NC}  (solid, ~4.7GB) —  lazarevtill/Llama-3-WhiteRabbitNeo-8B-v2.0         [8GB+ RAM]"
            echo -e "    ${BOLD}v1.5a 7B             ${NC}  (light, ~4.1GB) —  monotykamary/whiterabbitneo-v1.5a                   [6GB+ RAM]"
            echo ""

            # Check if already pulled
            local wrn_short_name; wrn_short_name="${wrn_model##*/}"
            local already_pulled=false
            if ollama list 2>/dev/null | grep -qi "whiterabbitneo"; then
                already_pulled=true
                ok "WhiteRabbitNeo already present in Ollama"
            fi

            if [[ "$already_pulled" == "false" ]]; then
                local _wrn_choice
                ask_user _wrn_choice "Pull ${wrn_model} now? [y/N]" "N"
                if [[ "$_wrn_choice" =~ ^[Yy]$ ]]; then
                    echo ""
                    info "Pulling ${wrn_model} (${wrn_size}) — this may take a few minutes..."
                    if ollama pull "$wrn_model" 2>&1 | tee -a "$ONEINFINITY_LOG"; then
                        echo ""
                        ok "WhiteRabbitNeo ready → ollama run ${wrn_model}"
                        info "OneInfinity will automatically route EXPLOIT_GEN and PAYLOAD_MUTATION tasks to it."
                    else
                        warn "Pull failed — try manually: ollama pull ${wrn_model}"
                    fi
                else
                    info "Skipped. Pull later with:"
                    info "  ollama pull ${wrn_model}"
                    info "  (or choose a different tier from the list above)"
                fi
            fi
        fi
        echo -e "  ${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    fi

    # ── 5. Summary ────────────────────────────────────────────────────────────
    echo ""
    local ai_count=0
    command -v ollama &>/dev/null && (( ai_count++ )) || true
    { command -v agy &>/dev/null \
        && { [[ -s "$HOME/.gemini/antigravity-cli/credentials.json" ]] \
             || [[ -s "$HOME/.gemini/oauth_creds.json" ]]; }; } \
        && (( ai_count++ )) || true
    [[ -n "$(grep '^GROQ_API_KEY=[^[:space:]]' "$env_file" 2>/dev/null)" ]] \
        && (( ai_count++ )) || true

    if [[ $ai_count -ge 1 ]]; then
        ok "AI providers ready: ${ai_count} free provider(s) configured"
    else
        warn "No AI providers configured. AI features will be disabled."
        warn "Options (all free):"
        warn "  • Ollama:      https://ollama.com  then: ollama pull llama3.2:3b"
        warn "  • Antigravity: curl -fsSL https://antigravity.google/cli/install.sh | bash  then: agy"
        warn "  • Groq:        https://console.groq.com  then: add GROQ_API_KEY to .env"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# setup_env_and_alias
# ---------------------------------------------------------------------------
setup_env_and_alias() {
    section "Environment & Alias Configuration"

    local env_file="$REPO_DIR/.env"
    local env_example="$REPO_DIR/.env.example"

    # ── .env bootstrap ────────────────────────────────────────────────────
    step "Configuring .env"
    if [[ ! -f "$env_file" ]]; then
        if [[ -f "$env_example" ]]; then
            cp "$env_example" "$env_file"
            info "Created .env from .env.example"
        else
            touch "$env_file"
            info "Created empty .env"
        fi
    fi

    # Set / merge only keys that are absent or still at placeholder values.
    # Database connection strings use the canonical default creds.
    _env_set_key "ONEINFINITY_HOME"  "$ONEINFINITY_HOME"                              "$env_file"
    _env_set_key "POSTGRES_HOST"     "localhost"                                       "$env_file"
    _env_set_key "POSTGRES_PORT"     "$PG_PORT"                                        "$env_file"
    _env_set_key "POSTGRES_DB"       "$PG_DB"                                          "$env_file"
    _env_set_key "POSTGRES_USER"     "$PG_USER"                                        "$env_file"
    _env_set_key "POSTGRES_PASSWORD" "$PG_PASS"                                        "$env_file"
    _env_set_key "POSTGRES_URL"           "postgresql://${PG_USER}:${PG_PASS}@localhost:${PG_PORT}/${PG_DB}" "$env_file"
    _env_set_key "DATABASE_URL"           "postgresql://${PG_USER}:${PG_PASS}@localhost:${PG_PORT}/${PG_DB}" "$env_file"
    _env_set_key "ONEINFINITY_STORAGE_MODE" "postgres"                                "$env_file"
    _env_set_key "REDIS_HOST"        "localhost"                                        "$env_file"
    _env_set_key "REDIS_PORT"        "$REDIS_PORT"                                      "$env_file"
    _env_set_key "REDIS_PASSWORD"    "$REDIS_PASS"                                      "$env_file"
    _env_set_key "REDIS_URL"         "redis://:${REDIS_PASS}@localhost:${REDIS_PORT}/0" "$env_file"
    _env_set_key "NEO4J_HOST"        "localhost"                                        "$env_file"
    _env_set_key "NEO4J_USER"        "$NEO4J_USER"                                      "$env_file"
    _env_set_key "NEO4J_PASSWORD"    "$NEO4J_PASS"                                      "$env_file"
    _env_set_key "NEO4J_URI"         "bolt://localhost:${NEO4J_BOLT}"                   "$env_file"
    _env_set_key "NEO4J_BOLT_PORT"   "$NEO4J_BOLT"                                      "$env_file"
    _env_set_key "NEO4J_ENABLED"     "true"                                             "$env_file"
    _env_set_key "MOBSF_URL"         "http://localhost:${MOBSF_PORT}"                   "$env_file"

    # MOBSF_API_KEY: keep whatever was stored by section_H (non-blank) or leave blank
    if [[ -n "${MOBSF_API_KEY:-}" ]]; then
        _env_set_key "MOBSF_API_KEY" "$MOBSF_API_KEY" "$env_file"
    fi

    ok ".env configured (keys merged, no existing values overwritten)"

    # ── ~/.oneinfinity subdirectories ────────────────────────────────────
    step "Creating ONEINFINITY_HOME subdirectories"
    local -a OI_DIRS=(
        wordlists reports raw databases logs sessions templates
    )
    for d in "${OI_DIRS[@]}"; do
        mkdir -p "$ONEINFINITY_HOME/$d"
    done
    ok "Directories created under $ONEINFINITY_HOME"

    # ── Default wordlist ─────────────────────────────────────────────────
    local wordlist="$ONEINFINITY_HOME/wordlists/common.txt"
    if [[ ! -f "$wordlist" ]]; then
        step "Downloading default wordlist (SecLists/common.txt)"
        curl -fsSL \
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
            -o "$wordlist" 2>>"$ONEINFINITY_LOG" \
            && ok "Default wordlist saved to $wordlist" \
            || warn "Could not download default wordlist — add one manually to $wordlist"
    else
        info "Default wordlist already present — skipping download"
    fi

    # ── Terminal alias ────────────────────────────────────────────────────
    step "Configuring 'oneinfinity' shell alias"

    # The alias starts the web backend in the background, waits a moment,
    # then opens the browser at the correct port variable.
    # Using single quotes inside double quotes to embed the open/xdg-open fallback.
    local ALIAS_CMD
    # shellcheck disable=SC2089
    ALIAS_CMD="alias oneinfinity='cd \"${REPO_DIR}\" && python -m uvicorn web.backend.main:app --host 0.0.0.0 --port ${WEB_BACKEND_PORT} &>/dev/null & sleep 2 && open http://localhost:${WEB_BACKEND_PORT} 2>/dev/null || xdg-open http://localhost:${WEB_BACKEND_PORT} 2>/dev/null; echo \"OneInfinity UI at http://localhost:${WEB_BACKEND_PORT}\"'"

    local SHELL_NAME
    SHELL_NAME=$(basename "${SHELL:-bash}")
    local rc_file=""

    case "$SHELL_NAME" in
        zsh)
            rc_file="$HOME/.zshrc"
            ;;
        bash)
            rc_file="$HOME/.bashrc"
            ;;
        fish)
            # Fish uses a different alias syntax — write a function instead
            local fish_conf_dir="$HOME/.config/fish"
            mkdir -p "$fish_conf_dir"
            rc_file="$fish_conf_dir/config.fish"
            # Build fish-compatible function
            local FISH_FUNC="
# OneInfinity launcher (added by install.sh)
function oneinfinity
    cd \"${REPO_DIR}\"
    python -m uvicorn web.backend.main:app --host 0.0.0.0 --port ${WEB_BACKEND_PORT} &>/dev/null &
    sleep 2
    open http://localhost:${WEB_BACKEND_PORT} 2>/dev/null; or xdg-open http://localhost:${WEB_BACKEND_PORT} 2>/dev/null
    echo \"OneInfinity UI at http://localhost:${WEB_BACKEND_PORT}\"
end"
            if ! grep -q "function oneinfinity" "$rc_file" 2>/dev/null; then
                echo "$FISH_FUNC" >> "$rc_file"
                ok "Fish function 'oneinfinity' added to $rc_file"
            else
                info "Fish function 'oneinfinity' already in $rc_file"
            fi
            # Skip the generic alias block below
            rc_file=""
            ;;
        *)
            # Unknown shell — default to .bashrc
            rc_file="$HOME/.bashrc"
            warn "Unknown shell '$SHELL_NAME' — adding alias to ~/.bashrc"
            ;;
    esac

    # For bash / zsh (non-fish):
    if [[ -n "$rc_file" ]]; then
        touch "$rc_file"
        if ! grep -q "alias oneinfinity=" "$rc_file" 2>/dev/null; then
            {
                echo ""
                echo "# OneInfinity launcher (added by install.sh)"
                echo "$ALIAS_CMD"
            } >> "$rc_file"
            ok "Alias 'oneinfinity' added to $rc_file"
        else
            info "Alias 'oneinfinity' already present in $rc_file"
        fi
    fi

    # ── PATH entries ──────────────────────────────────────────────────────
    step "Ensuring ~/.local/bin and ~/go/bin are on PATH"

    local path_rc="${rc_file:-$HOME/.bashrc}"
    if [[ "$(basename "${SHELL:-bash}")" == "fish" ]]; then
        path_rc="$HOME/.config/fish/config.fish"
    fi

    local -a PATH_DIRS=("$HOME/.local/bin" "$HOME/go/bin")
    for pdir in "${PATH_DIRS[@]}"; do
        mkdir -p "$pdir"
        local escaped_dir="${pdir//\//\\/}"
        if ! grep -q "$pdir" "$path_rc" 2>/dev/null; then
            if [[ "$(basename "${SHELL:-bash}")" == "fish" ]]; then
                echo "fish_add_path $pdir" >> "$path_rc"
            else
                echo "export PATH=\"\$PATH:${pdir}\"" >> "$path_rc"
            fi
            info "Added $pdir to PATH in $path_rc"
        fi
    done
    ok "PATH entries verified"

    # ── Remind user to source ─────────────────────────────────────────────
    echo ""
    echo -e "  ${YELLOW}${BOLD}ACTION REQUIRED:${NC} Reload your shell after installation:"
    if [[ -n "${rc_file:-}" ]]; then
        echo -e "    ${CYAN}source ${rc_file}${NC}"
    else
        echo -e "    ${CYAN}source ~/.config/fish/config.fish${NC}"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# run_verification  — health checks with formatted table output
# ---------------------------------------------------------------------------
run_verification() {
    section "Installation Verification"

    # Collect check results: (name, status_icon, detail)
    local -a V_NAME=()
    local -a V_STATUS=()
    local -a V_DETAIL=()
    local pass_count=0
    local total_count=0

    _chk() {
        local name="$1"
        local status="$2"   # "ok" | "warn" | "fail"
        local detail="$3"
        V_NAME+=("$name")
        V_STATUS+=("$status")
        V_DETAIL+=("$detail")
        (( total_count++ )) || true
        [[ "$status" == "ok" ]] && (( pass_count++ )) || true
    }

    # Python
    if command -v python3 &>/dev/null; then
        local py_ver; py_ver=$(python3 --version 2>&1 | awk '{print $2}')
        _chk "Python" "ok" "Python ${py_ver}"
    elif command -v python &>/dev/null; then
        local py_ver; py_ver=$(python --version 2>&1 | awk '{print $2}')
        _chk "Python" "ok" "Python ${py_ver}"
    else
        _chk "Python" "fail" "Not found"
    fi

    # Go
    if command -v go &>/dev/null; then
        local go_ver; go_ver=$(go version 2>&1 | awk '{print $3}')
        _chk "Go" "ok" "$go_ver"
    else
        _chk "Go" "fail" "Not found"
    fi

    # Rust / cargo
    if command -v cargo &>/dev/null; then
        local rs_ver; rs_ver=$(rustc --version 2>&1 | awk '{print $2}')
        _chk "Rust/cargo" "ok" "rustc ${rs_ver}"
    else
        _chk "Rust/cargo" "warn" "Not found (optional)"
    fi

    # Node.js
    if command -v node &>/dev/null; then
        local node_ver; node_ver=$(node --version 2>&1)
        _chk "Node.js" "ok" "${node_ver}"
    else
        _chk "Node.js" "warn" "Not found (optional)"
    fi

    # PostgreSQL (via Docker)
    local pg_status="fail"; local pg_detail="Container not running"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^oneinfinity-postgres$"; then
        if PGPASSWORD="$PG_PASS" docker exec oneinfinity-postgres \
               pg_isready -U "$PG_USER" -d "$PG_DB" &>/dev/null; then
            pg_status="ok"; pg_detail="Container running, pg_isready OK"
        else
            pg_status="warn"; pg_detail="Container running but not ready"
        fi
    fi
    _chk "PostgreSQL" "$pg_status" "$pg_detail"

    # Redis (via Docker)
    local redis_status="fail"; local redis_detail="Container not running"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^oneinfinity-redis$"; then
        local pong
        pong=$(docker exec oneinfinity-redis redis-cli -a "$REDIS_PASS" \
               --no-auth-warning ping 2>/dev/null | tr -d '[:space:]')
        if [[ "$pong" == "PONG" ]]; then
            redis_status="ok"; redis_detail="Container running, PONG received"
        else
            redis_status="warn"; redis_detail="Container running but not responding"
        fi
    fi
    _chk "Redis" "$redis_status" "$redis_detail"

    # Neo4j (via Docker + HTTP)
    local neo_status="fail"; local neo_detail="Container not running"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^oneinfinity-neo4j$"; then
        local neo_http
        neo_http=$(curl -s -o /dev/null -w "%{http_code}" \
                       "http://localhost:${NEO4J_HTTP}" 2>/dev/null)
        if [[ "$neo_http" == "200" ]]; then
            neo_status="ok"; neo_detail="Container running, HTTP 200"
        else
            neo_status="warn"; neo_detail="Container running, HTTP ${neo_http}"
        fi
    fi
    _chk "Neo4j" "$neo_status" "$neo_detail"

    # MobSF (via Docker + HTTP)
    local mobsf_status="fail"; local mobsf_detail="Container not running"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^oneinfinity-mobsf$"; then
        local mobsf_http
        mobsf_http=$(curl -s -o /dev/null -w "%{http_code}" \
                         "http://localhost:${MOBSF_PORT}" 2>/dev/null)
        if [[ "$mobsf_http" =~ ^(200|301|302)$ ]]; then
            mobsf_status="ok"; mobsf_detail="Container running, HTTP ${mobsf_http}"
        else
            mobsf_status="warn"; mobsf_detail="Container running, HTTP ${mobsf_http}"
        fi
    fi
    _chk "MobSF" "$mobsf_status" "$mobsf_detail"

    # Key offensive Go binaries
    local -a KEY_BINS=(nuclei subfinder httpx frida)
    for bin in "${KEY_BINS[@]}"; do
        if command -v "$bin" &>/dev/null; then
            local bver; bver=$("$bin" --version 2>&1 | head -1 | tr -d '\n' | cut -c1-40)
            _chk "$bin" "ok" "${bver:-present}"
        else
            _chk "$bin" "warn" "Not found"
        fi
    done

    # Custom OneInfinity Go binaries
    local -a OI_BINS=(
        oi-credential-spray oi-service-cve-mapper oi-ssrf
        oi-recon-probe oi-idor-engine oi-target-disc
        oi-crawler oi-oob-listener oi-lateral-portscan
    )
    for bin in "${OI_BINS[@]}"; do
        if command -v "$bin" &>/dev/null \
               || [[ -x "$HOME/.local/bin/$bin" ]] \
               || [[ -x "$HOME/go/bin/$bin" ]]; then
            _chk "$bin" "ok" "Binary present"
        else
            _chk "$bin" "warn" "Not built"
        fi
    done

    # Rust core importable
    local python_bin
    python_bin=$(command -v python3 2>/dev/null || command -v python || echo "")
    if [[ -n "$python_bin" ]]; then
        if "$python_bin" -c "import oneinfinity_core" &>/dev/null; then
            _chk "Rust core" "ok" "import oneinfinity_core OK"
        else
            _chk "Rust core" "warn" "Not importable (Python fallback active)"
        fi
    else
        _chk "Rust core" "fail" "Python not available to test"
    fi

    # .env present with key fields
    local env_ok="ok"; local env_detail=".env present"
    if [[ ! -f "$REPO_DIR/.env" ]]; then
        env_ok="fail"; env_detail=".env missing"
    else
        local missing_keys=()
        for k in POSTGRES_URL REDIS_URL NEO4J_URI ONEINFINITY_HOME; do
            grep -q "^${k}=" "$REPO_DIR/.env" || missing_keys+=("$k")
        done
        if (( ${#missing_keys[@]} > 0 )); then
            env_ok="warn"
            env_detail="Missing keys: ${missing_keys[*]}"
        else
            env_detail=".env present with all required keys"
        fi
    fi
    _chk ".env config" "$env_ok" "$env_detail"

    # Alias configured
    local alias_ok="warn"; local alias_detail="Not detected"
    local SHELL_NAME; SHELL_NAME=$(basename "${SHELL:-bash}")
    case "$SHELL_NAME" in
        zsh)  [[ -f "$HOME/.zshrc"  ]] && grep -q "alias oneinfinity=" "$HOME/.zshrc"  && alias_ok="ok" && alias_detail="In ~/.zshrc" ;;
        bash) [[ -f "$HOME/.bashrc" ]] && grep -q "alias oneinfinity=" "$HOME/.bashrc" && alias_ok="ok" && alias_detail="In ~/.bashrc" ;;
        fish) [[ -f "$HOME/.config/fish/config.fish" ]] \
                  && grep -q "function oneinfinity" "$HOME/.config/fish/config.fish" \
                  && alias_ok="ok" && alias_detail="In fish config.fish" ;;
    esac
    _chk "Alias" "$alias_ok" "$alias_detail"

    # ── Render table ──────────────────────────────────────────────────────
    local col1=16 col2=11 col3=40
    local hdr_line sep_line row_fmt

    # Build separator lines using printf
    local h1; h1=$(printf '%*s' $col1 '' | tr ' ' '═')
    local h2; h2=$(printf '%*s' $col2 '' | tr ' ' '═')
    local h3; h3=$(printf '%*s' $col3 '' | tr ' ' '═')

    echo ""
    echo -e "${BOLD}╔${h1}╦${h2}╦${h3}╗${NC}"
    printf "${BOLD}║ %-$((col1-2))s ║ %-$((col2-2))s ║ %-$((col3-2))s ║${NC}\n" \
        "OneInfinity Installation Verification" "" ""
    echo -e "${BOLD}╠${h1}╦${h2}╦${h3}╣${NC}"
    printf "${BOLD}║ %-$((col1-2))s ║ %-$((col2-2))s ║ %-$((col3-2))s ║${NC}\n" \
        " Component" " Status" " Details"
    echo -e "${BOLD}╠${h1}╬${h2}╬${h3}╣${NC}"

    for (( i=0; i<${#V_NAME[@]}; i++ )); do
        local icon detail_str color
        case "${V_STATUS[$i]}" in
            ok)   icon="✅ OK  ";    color="$GREEN" ;;
            warn) icon="⚠️  WARN";   color="$YELLOW" ;;
            fail) icon="❌ FAIL";   color="$RED" ;;
            *)    icon="?? ????";   color="$NC" ;;
        esac
        # Truncate detail to fit column
        detail_str="${V_DETAIL[$i]}"
        if (( ${#detail_str} > col3-2 )); then
            detail_str="${detail_str:0:$((col3-5))}…"
        fi
        printf "${BOLD}║${NC} ${color}%-$((col1-2))s${NC} ${BOLD}║${NC} ${color}%-$((col2-2))s${NC} ${BOLD}║${NC} %-$((col3-2))s ${BOLD}║${NC}\n" \
            "${V_NAME[$i]}" "$icon" "$detail_str"
    done

    echo -e "${BOLD}╚${h1}╩${h2}╩${h3}╝${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# print_summary  — final install summary
# ---------------------------------------------------------------------------
print_summary() {
    section "Installation Complete"

    # Count running Docker services
    local -a SERVICES=("oneinfinity-postgres" "oneinfinity-redis" "oneinfinity-neo4j" "oneinfinity-mobsf")
    local running_services=()
    local stopped_services=()
    for svc in "${SERVICES[@]}"; do
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${svc}$"; then
            running_services+=("$svc")
        else
            stopped_services+=("$svc")
        fi
    done

    # Count custom binaries present
    local bins_present=0 bins_total=9
    local -a OI_BINS=(
        oi-credential-spray oi-service-cve-mapper oi-ssrf
        oi-recon-probe oi-idor-engine oi-target-disc
        oi-crawler oi-oob-listener oi-lateral-portscan
    )
    for bin in "${OI_BINS[@]}"; do
        { command -v "$bin" &>/dev/null \
              || [[ -x "$HOME/.local/bin/$bin" ]] \
              || [[ -x "$HOME/go/bin/$bin" ]]; } && (( bins_present++ )) || true
    done

    local SHELL_NAME; SHELL_NAME=$(basename "${SHELL:-bash}")
    local rc_hint
    case "$SHELL_NAME" in
        zsh)  rc_hint="source ~/.zshrc" ;;
        bash) rc_hint="source ~/.bashrc" ;;
        fish) rc_hint="source ~/.config/fish/config.fish" ;;
        *)    rc_hint="source ~/.bashrc" ;;
    esac

    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║        OneInfinity Installation Summary              ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Custom Go binaries:${NC}  ${GREEN}${bins_present}/${bins_total}${NC} built"
    echo ""
    # ── AI provider status ────────────────────────────────────────────────
    echo -e "  ${BOLD}AI providers:${NC}"
    local _env_file="${REPO_DIR:-$PWD}/.env"
    # Ollama
    if command -v ollama &>/dev/null; then
        local _n_models; _n_models="$(ollama list 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
        echo -e "    ${GREEN}✅${NC}  Ollama (local)  — ${_n_models} model(s) available"
    else
        echo -e "    ${YELLOW}⚬${NC}  Ollama (local)  — not installed  (${CYAN}https://ollama.com${NC})"
    fi
    # Antigravity CLI
    if command -v agy &>/dev/null; then
        if [[ -s "$HOME/.gemini/antigravity-cli/credentials.json" ]] \
            || [[ -s "$HOME/.gemini/oauth_creds.json" ]]; then
            local _agy_ver; _agy_ver="$(agy --version 2>/dev/null | head -1)"
            echo -e "    ${GREEN}✅${NC}  Antigravity CLI (Gemini 2.0/2.5, free) — authenticated  ${CYAN}[${_agy_ver}]${NC}"
        else
            echo -e "    ${YELLOW}⚠️${NC}  Antigravity CLI — installed but ${BOLD}not authenticated${NC}  → run: ${CYAN}agy${NC}"
        fi
    else
        echo -e "    ${YELLOW}⚬${NC}  Antigravity CLI — not installed  (${CYAN}curl -fsSL https://antigravity.google/cli/install.sh | bash${NC})"
    fi
    # Groq
    local _groq_key; _groq_key="$(grep '^GROQ_API_KEY=' "$_env_file" 2>/dev/null | cut -d= -f2-)"
    if [[ -n "$_groq_key" && "$_groq_key" != "your-groq-key" ]]; then
        echo -e "    ${GREEN}✅${NC}  Groq (free cloud, LLaMA3-70B) — API key configured"
    else
        echo -e "    ${YELLOW}⚬${NC}  Groq (free cloud) — no key  (${CYAN}https://console.groq.com${NC})"
    fi
    # Paid providers (informational only — show if configured)
    for _paid_var in ANTHROPIC_API_KEY OPENAI_API_KEY DEEPSEEK_API_KEY; do
        local _val; _val="$(grep "^${_paid_var}=" "$_env_file" 2>/dev/null | cut -d= -f2-)"
        if [[ -n "$_val" ]]; then
            echo -e "    ${GREEN}✅${NC}  ${_paid_var%%_API_KEY*} (paid) — configured"
        fi
    done
    echo ""
    echo -e "  ${BOLD}Services running:${NC}"
    for svc in "${running_services[@]}"; do
        echo -e "    ${GREEN}✅${NC}  $svc"
    done
    for svc in "${stopped_services[@]}"; do
        echo -e "    ${RED}❌${NC}  $svc ${YELLOW}(not running)${NC}"
    done
    echo ""
    echo -e "  ${BOLD}Web UI:${NC}        ${CYAN}http://localhost:${WEB_BACKEND_PORT}${NC}"
    echo -e "  ${BOLD}MobSF:${NC}         ${CYAN}http://localhost:${MOBSF_PORT}${NC}"
    echo -e "  ${BOLD}Neo4j Browser:${NC} ${CYAN}http://localhost:${NEO4J_HTTP}${NC}"
    echo ""
    echo -e "  ${BOLD}${YELLOW}Next steps:${NC}"
    echo -e "    ${CYAN}1.${NC}  ${BOLD}${rc_hint}${NC}"
    echo -e "    ${CYAN}2.${NC}  Run:  ${BOLD}oneinfinity${NC}"
    echo ""

    if (( ${#stopped_services[@]} > 0 )); then
        echo -e "  ${YELLOW}⚠️  Some services are not running.${NC}"
        echo -e "  Start them with:"
        echo -e "    ${CYAN}docker compose -f ${REPO_DIR}/docker-compose.db.yml up -d${NC}"
        echo ""
    fi

    if [[ -z "${MOBSF_API_KEY:-}" ]] \
           || ! grep -q "^MOBSF_API_KEY=[^y]" "$REPO_DIR/.env" 2>/dev/null; then
        echo -e "  ${YELLOW}⚠️  MobSF API key not configured.${NC}"
        echo -e "  Open http://localhost:${MOBSF_PORT} → Settings → REST API Key"
        echo -e "  Then add to ${REPO_DIR}/.env:  MOBSF_API_KEY=<key>"
        echo ""
    fi

    echo -e "  ${BOLD}Log file:${NC}  $ONEINFINITY_LOG"
    echo ""
}

# ============================================================================

# ============================================================================
# SECTION K — Nim + eBPF Toolchain
# ============================================================================

# ============================================================================
# SECTION K — Nim + eBPF Toolchain
# ============================================================================

# -----------------------------------------------------------------------------
# install_nim()
# Install Nim language + Nimble package manager + required packages for
# OneInfinity's AV-evasive payload generators (src/nim/*.nim)
# Binaries: oi-fuzzer, oi-payloads, oi-privesc-gen, oi-bypass-gen,
#           oi-post-exploit, oi-shell-gen
# -----------------------------------------------------------------------------
install_nim() {
    section "Nim + Nimble (AV-evasive payload compiler)"

    if command -v nim &>/dev/null; then
        ok "Nim already installed: $(nim --version | head -1)"
    else
        info "Installing Nim..."
        case "${PKG_MGR:-}" in
            brew)
                brew install nim
                ;;
            apt)
                # choosenim is canonical (like rustup for Nim)
                if ! command -v choosenim &>/dev/null; then
                    curl https://nim-lang.org/choosenim/init.sh -sSf \
                        | sh -s -- -y 2>&1 | tee -a "$ONEINFINITY_LOG" >/dev/null
                fi
                export PATH="$HOME/.nimble/bin:$PATH"
                ;;
            dnf)
                curl https://nim-lang.org/choosenim/init.sh -sSf \
                    | sh -s -- -y 2>&1 | tee -a "$ONEINFINITY_LOG" >/dev/null
                export PATH="$HOME/.nimble/bin:$PATH"
                ;;
            pacman)
                sudo pacman -S --noconfirm nim
                ;;
            *)
                warn "Unknown package manager — trying choosenim..."
                curl https://nim-lang.org/choosenim/init.sh -sSf \
                    | sh -s -- -y 2>&1 | tee -a "$ONEINFINITY_LOG" >/dev/null
                export PATH="$HOME/.nimble/bin:$PATH"
                ;;
        esac

        if command -v nim &>/dev/null; then
            ok "Nim installed: $(nim --version | head -1)"
        else
            warn "Nim install failed — AV-evasive payload generation will be unavailable"
            return 0
        fi
    fi

    # Ensure nimble on PATH
    if ! command -v nimble &>/dev/null; then
        export PATH="$HOME/.nimble/bin:$PATH"
        # Persist to shell rc files
        for rcfile in "$HOME/.bashrc" "$HOME/.zshrc"; do
            if [[ -f "$rcfile" ]] && ! grep -q '.nimble/bin' "$rcfile" 2>/dev/null; then
                echo 'export PATH="$HOME/.nimble/bin:$PATH"' >> "$rcfile"
            fi
        done
    fi

    # Install Nim packages needed for offensive payload generation
    info "Installing Nim packages: winim, zippy, puppy..."
    # winim: Windows ABI bindings (required for Windows shellcode generation)
    nimble install winim -y 2>>"$ONEINFINITY_LOG" \
        || warn "winim: install failed (Windows cross-compile only — OK on dev machine)"
    # zippy: compression (payload packing)
    nimble install zippy -y 2>>"$ONEINFINITY_LOG" || warn "zippy: install failed"
    # puppy: HTTP client for Nim
    nimble install puppy -y 2>>"$ONEINFINITY_LOG" || warn "puppy: install failed"

    ok "Nim packages ready"

    # Build the 6 Nim payload binaries
    _build_nim_binaries
}

_build_nim_binaries() {
    local nim_src_dir="$REPO_DIR/src/nim"
    if [[ ! -d "$nim_src_dir" ]]; then
        warn "Nim source directory not found at $nim_src_dir — skipping Nim binary build"
        return 0
    fi

    local out_dir="$REPO_DIR/src/nim/bin"
    mkdir -p "$out_dir"

    info "Building Nim payload binaries from $nim_src_dir..."
    local -a nim_tools=(
        "oi-fuzzer:oi-fuzzer.nim"
        "oi-payloads:oi-payloads.nim"
        "oi-privesc-gen:oi-privesc-gen.nim"
        "oi-bypass-gen:oi-bypass-gen.nim"
        "oi-post-exploit:oi-post-exploit.nim"
        "oi-shell-gen:oi-shell-gen.nim"
    )

    local built=0 failed=0
    for entry in "${nim_tools[@]}"; do
        local bin_name="${entry%%:*}"
        local src_file="${entry##*:}"
        local src_path="$nim_src_dir/$src_file"
        local out_path="$out_dir/$bin_name"

        if [[ ! -f "$src_path" ]]; then
            warn "  $src_file not found — skipping $bin_name"
            continue
        fi

        step "Building $bin_name"
        if nim compile --opt:speed --out:"$out_path" "$src_path" \
                2>>"$ONEINFINITY_LOG"; then
            printf "${GREEN}ok${NC}\n"
            # Also symlink to ~/.local/bin for PATH access
            mkdir -p "$HOME/.local/bin"
            ln -sf "$out_path" "$HOME/.local/bin/$bin_name" 2>/dev/null || true
            (( built++ )) || true
        else
            printf "${YELLOW}warn${NC}\n"
            warn "  Failed to build $bin_name — check $ONEINFINITY_LOG"
            (( failed++ )) || true
        fi
    done

    ok "Nim binaries: $built built, $failed failed"
}

# -----------------------------------------------------------------------------
# install_ebpf_toolchain()
# Install eBPF compilation toolchain (Linux only).
# Compile BPF objects from src/ebpf/ using Clang.
# Programs: ssl_intercept.bpf, net_capture.bpf, key_extract.bpf
# macOS: skipped — StealthTracer uses DTrace/Frida instead.
# -----------------------------------------------------------------------------
install_ebpf_toolchain() {
    section "eBPF Toolchain (Linux only)"

    if [[ "${IS_LINUX:-false}" != "true" ]]; then
        info "eBPF: macOS detected — using DTrace/Frida backend instead. Skipping."
        return 0
    fi

    info "Installing eBPF toolchain: clang, llvm, bpftool, linux-headers..."

    case "${PKG_MGR:-}" in
        apt)
            sudo apt-get install -y \
                clang llvm \
                linux-headers-"$(uname -r)" \
                linux-tools-"$(uname -r)" \
                linux-tools-generic \
                bpftool \
                libbpf-dev \
                2>>"$ONEINFINITY_LOG" || {
                    # bpftool may have a different package name on some distros
                    sudo apt-get install -y linux-tools-common 2>>"$ONEINFINITY_LOG" || true
                }
            ;;
        dnf)
            sudo dnf install -y \
                clang llvm \
                kernel-headers kernel-devel \
                bpftool \
                libbpf-devel \
                2>>"$ONEINFINITY_LOG" || warn "Some eBPF packages failed on Fedora/RHEL"
            ;;
        pacman)
            sudo pacman -S --noconfirm \
                clang llvm \
                linux-headers \
                bpf \
                libbpf \
                2>>"$ONEINFINITY_LOG" || warn "Some eBPF packages failed on Arch"
            ;;
        *)
            warn "Unknown package manager — install clang, llvm, bpftool, libbpf-dev manually"
            return 0
            ;;
    esac

    # Verify clang is available
    if ! command -v clang &>/dev/null; then
        warn "clang not found after install — eBPF compilation will fail"
        return 0
    fi
    ok "eBPF toolchain: clang $(clang --version | head -1 | awk '{print $3}')"

    # Compile BPF objects from src/ebpf/
    _compile_ebpf_programs
}

_compile_ebpf_programs() {
    local ebpf_dir="$REPO_DIR/src/ebpf"
    if [[ ! -d "$ebpf_dir" ]]; then
        warn "eBPF source directory not found at $ebpf_dir — skipping BPF compilation"
        return 0
    fi
    if [[ ! -f "$ebpf_dir/Makefile" ]]; then
        warn "eBPF Makefile not found — skipping"
        return 0
    fi

    info "Compiling eBPF programs (ssl_intercept, net_capture, key_extract, syscall_trace, process_inject_detect)..."
    local arch
    arch=$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

    # Compile each BPF object: clang -O2 -target bpf -D__TARGET_ARCH_<arch>
    local -a bpf_sources=("ssl_intercept.bpf.c" "net_capture.bpf.c" "key_extract.bpf.c" "syscall_trace.bpf.c" "process_inject_detect.bpf.c")
    local compiled=0 failed=0

    for src in "${bpf_sources[@]}"; do
        local obj="${src%.c}.o"
        step "Compiling $src"
        if (cd "$ebpf_dir" && \
            clang -O2 -target bpf -D"__TARGET_ARCH_${arch}" \
                  -I. -c "$src" -o "$obj" \
                  2>>"$ONEINFINITY_LOG"); then
            printf "${GREEN}ok${NC}\n"
            (( compiled++ )) || true
        else
            printf "${YELLOW}warn${NC}\n"
            warn "  BPF compile failed for $src (non-fatal — fallback to Frida hooks)"
            (( failed++ )) || true
        fi
    done

    ok "eBPF programs: $compiled compiled, $failed failed"
    if [[ $compiled -gt 0 ]]; then
        info "Load with: sudo bpftool prog load <obj> /sys/fs/bpf/<name>"
        info "Or via OneInfinity: ONEINFINITY_EBPF=1 oneinfinity scan <target>"
    fi
}

# ============================================================================
# SECTION L — Full Database Schema Initialisation
# ============================================================================

# ============================================================================
# SECTION L — Full Database Schema Initialisation
# PostgreSQL: 35 tables + triggers + indexes + migration 001
# Neo4j:      Uniqueness constraint + 4 indexes (OI_Node, OI_REL, OI_ChainFeedback)
# Redis:      No schema (key-value); configure maxmemory + keyspace notifications
# ============================================================================

# -----------------------------------------------------------------------------
# init_postgres_schema()
# Apply db/schema.sql and all migrations idempotently.
# All statements use CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
# so it is safe to run on an existing database (upgrade mode).
# -----------------------------------------------------------------------------
init_postgres_schema() {
    section "PostgreSQL Schema Initialisation"

    # Verify PG is reachable
    if ! docker exec oneinfinity-postgres \
            pg_isready -U "$PG_USER" -d "$PG_DB" -q 2>/dev/null; then
        warn "PostgreSQL not ready — retrying schema init after 10s..."
        sleep 10
        if ! docker exec oneinfinity-postgres \
                pg_isready -U "$PG_USER" -d "$PG_DB" -q 2>/dev/null; then
            err "PostgreSQL still not ready — cannot apply schema"
            return 1
        fi
    fi

    local schema_file="$REPO_DIR/db/schema.sql"
    if [[ ! -f "$schema_file" ]]; then
        err "Schema file not found: $schema_file"
        return 1
    fi

    info "Applying db/schema.sql (35 tables, triggers, indexes)..."
    # Feed via stdin so the file stays on host; docker exec reads stdin
    if PGPASSWORD="$PG_PASS" docker exec -i oneinfinity-postgres \
            psql -U "$PG_USER" -d "$PG_DB" \
                 -v ON_ERROR_STOP=0 \
                 < "$schema_file" \
                 2>&1 | tee -a "$ONEINFINITY_LOG" >/dev/null; then
        ok "Base schema applied"
    else
        warn "Schema apply returned non-zero — existing tables are fine (idempotent DDL)"
    fi

    # Apply all migrations in order
    local migrations_dir="$REPO_DIR/db/migrations"
    if [[ -d "$migrations_dir" ]]; then
        info "Applying migrations from $migrations_dir..."
        # Ensure migration tracking table exists
        PGPASSWORD="$PG_PASS" docker exec -i oneinfinity-postgres \
            psql -U "$PG_USER" -d "$PG_DB" -q \
            <<'EOSQL' 2>>"$ONEINFINITY_LOG" || true
CREATE TABLE IF NOT EXISTS schema_migrations (
    version   TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
EOSQL

        # Apply each migration SQL file in sorted order
        for migration_file in $(ls -1 "$migrations_dir"/*.sql 2>/dev/null | sort); do
            local version
            version=$(basename "$migration_file" .sql)
            # Check if already applied
            local already_applied
            already_applied=$(PGPASSWORD="$PG_PASS" docker exec -i oneinfinity-postgres \
                psql -U "$PG_USER" -d "$PG_DB" -t -c \
                "SELECT COUNT(*) FROM schema_migrations WHERE version='$version';" \
                2>/dev/null | tr -d ' ')

            if [[ "${already_applied:-0}" -gt 0 ]]; then
                ok "Migration $version: already applied — skipping"
                continue
            fi

            step "Migration $version"
            if PGPASSWORD="$PG_PASS" docker exec -i oneinfinity-postgres \
                    psql -U "$PG_USER" -d "$PG_DB" \
                         -v ON_ERROR_STOP=0 \
                         < "$migration_file" \
                         2>>"$ONEINFINITY_LOG" >/dev/null; then
                # Record as applied
                PGPASSWORD="$PG_PASS" docker exec -i oneinfinity-postgres \
                    psql -U "$PG_USER" -d "$PG_DB" -q \
                    -c "INSERT INTO schema_migrations(version) VALUES('$version') ON CONFLICT DO NOTHING;" \
                    2>>"$ONEINFINITY_LOG" || true
                printf "${GREEN}ok${NC}\n"
            else
                printf "${YELLOW}warn${NC}\n"
                warn "  Migration $version had errors — check $ONEINFINITY_LOG"
            fi
        done
    fi

    # Verify key tables exist
    info "Verifying core tables..."
    local required_tables=(
        scans findings agents events knowledge_base recon_assets targets
        graph_nodes graph_edges attack_patterns learning_scan_sessions
        mobile_apps model_usage recon_cache scan_sessions
    )
    local missing=0
    for tbl in "${required_tables[@]}"; do
        local exists
        exists=$(PGPASSWORD="$PG_PASS" docker exec -i oneinfinity-postgres \
            psql -U "$PG_USER" -d "$PG_DB" -t -c \
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema='public' AND table_name='$tbl';" \
            2>/dev/null | tr -d ' ')
        if [[ "${exists:-0}" -lt 1 ]]; then
            warn "  Table '$tbl' missing after schema apply"
            (( missing++ )) || true
        fi
    done

    if [[ $missing -eq 0 ]]; then
        ok "All ${#required_tables[@]} core tables verified"
    else
        warn "$missing table(s) missing — scan persistence may be degraded"
    fi
}

# -----------------------------------------------------------------------------
# init_neo4j_schema()
# Bootstrap Neo4j schema: uniqueness constraint + 4 indexes.
# Node label  : OI_Node  (attack graph nodes)
# Relationship: OI_REL   (attack graph edges)
# Node label  : OI_ChainFeedback (exploit chain learning)
# Uses Cypher via neo4j-admin / curl HTTP API (no Python required).
# -----------------------------------------------------------------------------
init_neo4j_schema() {
    section "Neo4j Schema Bootstrap"

    local bolt_url="bolt://localhost:${NEO4J_BOLT}"
    local http_url="http://localhost:${NEO4J_HTTP}"

    # Wait for Neo4j HTTP to be responsive
    info "Waiting for Neo4j to accept connections..."
    local waited=0
    until curl -sf "${http_url}" -o /dev/null 2>/dev/null || [[ $waited -ge 90 ]]; do
        sleep 3
        (( waited += 3 )) || true
    done
    if [[ $waited -ge 90 ]]; then
        warn "Neo4j HTTP not responsive after 90s — schema bootstrap skipped"
        return 0
    fi

    # Helper: run a Cypher statement via Neo4j HTTP API
    _neo4j_cypher() {
        local stmt="$1"
        local payload
        payload=$(printf '{"statements":[{"statement":"%s"}]}' \
            "$(echo "$stmt" | sed 's/"/\\"/g')")
        curl -sf \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            -u "${NEO4J_USER}:${NEO4J_PASS}" \
            -d "$payload" \
            "${http_url}/db/neo4j/tx/commit" \
            2>>"$ONEINFINITY_LOG" | grep -q '"errors":\[\]'
    }

    info "Applying Neo4j schema (constraint + indexes)..."

    # These mirror Neo4jEngine.bootstrap_schema() in src/oneinfinity/core/neo4j_engine.py
    local -a cypher_stmts=(
        # Uniqueness constraint on OI_Node.id (primary key equivalent)
        "CREATE CONSTRAINT IF NOT EXISTS FOR (n:OI_Node) REQUIRE n.id IS UNIQUE"
        # Type-lookup index on OI_Node.type (used in MATCH queries)
        "CREATE INDEX IF NOT EXISTS FOR (n:OI_Node) ON (n.type)"
        # Relationship type index on OI_REL
        "CREATE INDEX IF NOT EXISTS FOR ()-[r:OI_REL]-() ON (r.type)"
        # Chain feedback indexes (exploit chain learning)
        "CREATE INDEX IF NOT EXISTS FOR (f:OI_ChainFeedback) ON (f.chain_type)"
        "CREATE INDEX IF NOT EXISTS FOR (f:OI_ChainFeedback) ON (f.success)"
    )

    local applied=0 skipped=0
    for stmt in "${cypher_stmts[@]}"; do
        step "  $(echo "$stmt" | awk '{print $1,$2,$3}')"
        if _neo4j_cypher "$stmt" 2>/dev/null; then
            printf "${GREEN}ok${NC}\n"
            (( applied++ )) || true
        else
            # IF NOT EXISTS means it likely already existed — not an error
            printf "${CYAN}skip${NC}\n"
            (( skipped++ )) || true
        fi
    done

    ok "Neo4j schema: $applied applied, $skipped already-existed"
}

# -----------------------------------------------------------------------------
# init_redis_config()
# Configure Redis for OneInfinity workloads:
#   - maxmemory: 512mb (scan cache, do not grow unbounded)
#   - maxmemory-policy: allkeys-lru (evict LRU entries under pressure)
#   - keyspace notifications: Ex (expired events — used by distributed workers)
#   - No persistence by default (AOF/RDB disabled for scan cache use-case)
#     Override: set REDIS_PERSIST=1 before running install.sh
# -----------------------------------------------------------------------------
init_redis_config() {
    section "Redis Configuration"

    if ! docker ps --filter "name=oneinfinity-redis" --filter "status=running" \
            --format '{{.Names}}' 2>/dev/null | grep -q oneinfinity-redis; then
        warn "Redis container not running — skipping Redis config"
        return 0
    fi

    info "Configuring Redis for OneInfinity scan workloads..."

    # maxmemory + eviction policy
    docker exec oneinfinity-redis \
        redis-cli -a "$REDIS_PASS" --no-auth-warning \
        CONFIG SET maxmemory 512mb 2>>"$ONEINFINITY_LOG" \
        && ok "Redis: maxmemory=512mb" \
        || warn "Redis: could not set maxmemory"

    docker exec oneinfinity-redis \
        redis-cli -a "$REDIS_PASS" --no-auth-warning \
        CONFIG SET maxmemory-policy allkeys-lru 2>>"$ONEINFINITY_LOG" \
        && ok "Redis: maxmemory-policy=allkeys-lru" \
        || warn "Redis: could not set eviction policy"

    # Keyspace notifications — distributed workers listen for expired job keys
    docker exec oneinfinity-redis \
        redis-cli -a "$REDIS_PASS" --no-auth-warning \
        CONFIG SET notify-keyspace-events "Ex" 2>>"$ONEINFINITY_LOG" \
        && ok "Redis: keyspace notifications=Ex (expired events)" \
        || warn "Redis: could not set keyspace notifications"

    # Disable persistence for cache-only use (can be overridden)
    if [[ "${REDIS_PERSIST:-0}" -ne 1 ]]; then
        docker exec oneinfinity-redis \
            redis-cli -a "$REDIS_PASS" --no-auth-warning \
            CONFIG SET save "" 2>>"$ONEINFINITY_LOG" || true
        docker exec oneinfinity-redis \
            redis-cli -a "$REDIS_PASS" --no-auth-warning \
            CONFIG SET appendonly no 2>>"$ONEINFINITY_LOG" || true
        info "Redis: persistence disabled (scan cache mode). Set REDIS_PERSIST=1 to enable."
    else
        ok "Redis: persistence enabled (REDIS_PERSIST=1)"
    fi

    # Write pre-defined queue namespaces used by distributed workers
    # These are just LRANGE-compatible queue keys — no explicit creation needed.
    # Document them here for clarity:
    info "Redis queues used by OneInfinity workers:"
    info "  swarm:tasks:recon     — recon phase jobs"
    info "  swarm:tasks:vuln      — vulnerability scan jobs"
    info "  swarm:tasks:exploit   — exploitation phase jobs"
    info "  swarm:tasks:default   — default catchall queue"
    info "  oi:scan:<scan_id>     — per-scan live findings channel"
    info "  oi:events             — global event bus"

    ok "Redis configured for OneInfinity workloads"
}

# -----------------------------------------------------------------------------
# init_all_databases()
# Top-level: call all DB init functions in sequence.
# Called from do_fresh_install() after setup_databases().
# -----------------------------------------------------------------------------
init_sqlite_databases() {
    section "SQLite Database Initialisation"

    # Resolve ONEINFINITY_HOME — mirrors path_manager._resolve_home()
    local OI_HOME="${ONEINFINITY_HOME:-$HOME/.oneinfinity}"
    local DB_DIR="$OI_HOME/databases"

    step "Creating SQLite directory layout"
    mkdir -p "$DB_DIR" "$OI_HOME/raw" "$OI_HOME/logs" "$OI_HOME/reports"
    ok "Directories: $OI_HOME/{databases,raw,logs,reports}"

    # Web backend stores mobile traffic at a repo-relative path
    mkdir -p "$REPO_DIR/db"
    ok "Web backend db/ directory: $REPO_DIR/db/"

    # Resolve python binary
    local PY
    PY="$(command -v python3 2>/dev/null || command -v python)"
    if [[ -z "$PY" ]]; then
        warn "Python not found — skipping SQLite schema initialisation"
        return 0
    fi

    # ── 1. Core findings + metadata DB ─────────────────────────────────────
    step "Initialising findings.db + metadata.db (DBManager)"
    "$PY" - <<'PYEOF' 2>>"$ONEINFINITY_LOG"
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent / "src"))
try:
    import sqlite3, os
    from pathlib import Path

    oi_home = Path(os.environ.get("ONEINFINITY_HOME", Path.home() / ".oneinfinity"))
    db_dir  = oi_home / "databases"
    db_dir.mkdir(parents=True, exist_ok=True)

    # findings.db
    findings_db = db_dir / "findings.db"
    with sqlite3.connect(str(findings_db)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id   TEXT PRIMARY KEY,
                scan_id      TEXT DEFAULT '',
                target       TEXT DEFAULT '',
                title        TEXT DEFAULT '',
                severity     TEXT DEFAULT 'info',
                vuln_type    TEXT DEFAULT '',
                url          TEXT DEFAULT '',
                tool         TEXT DEFAULT '',
                confidence   REAL DEFAULT 0.8,
                cvss         REAL DEFAULT 0.0,
                status       TEXT DEFAULT 'open',
                payload      TEXT DEFAULT '',
                evidence     TEXT DEFAULT '',
                remediation  TEXT DEFAULT '',
                raw_output   TEXT DEFAULT '',
                ai_analysis  TEXT DEFAULT '',
                created_at   REAL DEFAULT 0,
                updated_at   REAL DEFAULT 0,
                confirmed    INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id  ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_target   ON findings(target);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id      TEXT PRIMARY KEY,
                target       TEXT NOT NULL,
                scan_type    TEXT,
                profile      TEXT,
                status       TEXT NOT NULL DEFAULT 'queued',
                started_at   TEXT,
                completed_at TEXT,
                progress     INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                phase        TEXT,
                error        TEXT
            );
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                migration_name TEXT UNIQUE NOT NULL,
                applied_at     TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS exploit_chain_records (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id      TEXT NOT NULL,
                chain_json   TEXT NOT NULL,
                created_at   REAL DEFAULT 0,
                status       TEXT DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS credential_spray_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id      TEXT NOT NULL,
                target       TEXT NOT NULL,
                username     TEXT,
                success      INTEGER DEFAULT 0,
                timestamp    REAL DEFAULT 0
            );
        """)
        conn.commit()
    print(f"[ok] findings.db initialised: {findings_db}")

    # metadata.db
    metadata_db = db_dir / "metadata.db"
    with sqlite3.connect(str(metadata_db)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id      TEXT PRIMARY KEY,
                target       TEXT NOT NULL,
                scan_type    TEXT,
                profile      TEXT,
                status       TEXT NOT NULL DEFAULT 'queued',
                started_at   TEXT,
                completed_at TEXT,
                progress     INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                phase        TEXT,
                error        TEXT
            );
        """)
        conn.commit()
    print(f"[ok] metadata.db initialised: {metadata_db}")

except Exception as e:
    print(f"[warn] findings/metadata db init: {e}", file=sys.stderr)
PYEOF
    ok "findings.db + metadata.db initialised"

    # ── 2. event_bus.db ────────────────────────────────────────────────────
    step "Initialising event_bus.db"
    "$PY" - <<'PYEOF' 2>>"$ONEINFINITY_LOG"
import sys, os, sqlite3
from pathlib import Path
oi_home = Path(os.environ.get("ONEINFINITY_HOME", Path.home() / ".oneinfinity"))
db = oi_home / "databases" / "event_bus.db"
db.parent.mkdir(parents=True, exist_ok=True)
try:
    with sqlite3.connect(str(db)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  REAL NOT NULL DEFAULT 0,
                event_type TEXT NOT NULL,
                source     TEXT DEFAULT '',
                data       TEXT DEFAULT '{}',
                scan_id    TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts         ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type       ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_scan_id    ON events(scan_id);
        """)
        conn.commit()
    print(f"[ok] event_bus.db initialised: {db}")
except Exception as e:
    print(f"[warn] event_bus.db init: {e}", file=sys.stderr)
PYEOF
    ok "event_bus.db initialised"

    # ── 3. hitl_feedback.db ────────────────────────────────────────────────
    step "Initialising hitl_feedback.db (HITL RL engine)"
    "$PY" - <<'PYEOF' 2>>"$ONEINFINITY_LOG"
import sys, os, sqlite3
from pathlib import Path
oi_home = Path(os.environ.get("ONEINFINITY_HOME", Path.home() / ".oneinfinity"))
db = oi_home / "databases" / "hitl_feedback.db"
db.parent.mkdir(parents=True, exist_ok=True)
try:
    with sqlite3.connect(str(db)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hitl_feedback (
                id               TEXT PRIMARY KEY,
                finding_id       TEXT NOT NULL,
                vuln_type        TEXT NOT NULL,
                endpoint_pattern TEXT NOT NULL,
                payload_hash     TEXT NOT NULL,
                is_tp            INTEGER NOT NULL,
                notes            TEXT DEFAULT '',
                confidence       REAL DEFAULT 0.5,
                timestamp        REAL DEFAULT 0,
                reviewer         TEXT DEFAULT 'human'
            );
            CREATE TABLE IF NOT EXISTS vuln_type_stats (
                vuln_type  TEXT PRIMARY KEY,
                tp_count   INTEGER DEFAULT 0,
                fp_count   INTEGER DEFAULT 0,
                threshold  REAL DEFAULT 0.7,
                updated_at REAL NOT NULL DEFAULT 0
            );
        """)
        conn.commit()
    print(f"[ok] hitl_feedback.db initialised: {db}")
except Exception as e:
    print(f"[warn] hitl_feedback.db init: {e}", file=sys.stderr)
PYEOF
    ok "hitl_feedback.db initialised"

    # ── 4. reactive_effectiveness.db ──────────────────────────────────────
    step "Initialising reactive_effectiveness.db"
    "$PY" - <<'PYEOF' 2>>"$ONEINFINITY_LOG"
import sys, os, sqlite3
from pathlib import Path
oi_home = Path(os.environ.get("ONEINFINITY_HOME", Path.home() / ".oneinfinity"))
db = oi_home / "databases" / "reactive_effectiveness.db"
db.parent.mkdir(parents=True, exist_ok=True)
try:
    with sqlite3.connect(str(db)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS reactive_actions (
                id               TEXT PRIMARY KEY,
                scan_id          TEXT NOT NULL,
                action_type      TEXT DEFAULT '',
                target           TEXT DEFAULT '',
                trigger_phase    TEXT DEFAULT '',
                trigger_source   TEXT DEFAULT '',
                confidence       REAL DEFAULT 0.0,
                generated_at     REAL DEFAULT 0.0,
                executed         INTEGER DEFAULT 0,
                success          INTEGER DEFAULT 0,
                findings_count   INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS reactive_replans (
                id                   TEXT PRIMARY KEY,
                scan_id              TEXT NOT NULL,
                cycle                INTEGER DEFAULT 0,
                trigger_phase        TEXT DEFAULT '',
                original_plan_count  INTEGER DEFAULT 0,
                delta_count          INTEGER DEFAULT 0,
                actions_executed     INTEGER DEFAULT 0,
                findings_produced    INTEGER DEFAULT 0,
                validated_findings   INTEGER DEFAULT 0,
                generated_at         REAL DEFAULT 0.0
            );
            CREATE TABLE IF NOT EXISTS reactive_pivots (
                id               TEXT PRIMARY KEY,
                scan_id          TEXT NOT NULL,
                pivot_target     TEXT DEFAULT '',
                source_finding_id TEXT DEFAULT '',
                generated_at     REAL DEFAULT 0.0,
                scanned          INTEGER DEFAULT 0,
                scanned_at       REAL DEFAULT 0.0,
                httpx_findings   INTEGER DEFAULT 0,
                nuclei_findings  INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS reactive_scan_summaries (
                scan_id            TEXT PRIMARY KEY,
                target             TEXT DEFAULT '',
                generated_at       REAL DEFAULT 0.0,
                total_findings     INTEGER DEFAULT 0,
                baseline_findings  INTEGER DEFAULT 0,
                reactive_findings  INTEGER DEFAULT 0,
                pivot_findings     INTEGER DEFAULT 0,
                validated_total    INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_ra_scan ON reactive_actions(scan_id);
            CREATE INDEX IF NOT EXISTS idx_rp_scan ON reactive_pivots(scan_id);
        """)
        conn.commit()
    print(f"[ok] reactive_effectiveness.db initialised: {db}")
except Exception as e:
    print(f"[warn] reactive_effectiveness.db init: {e}", file=sys.stderr)
PYEOF
    ok "reactive_effectiveness.db initialised"

    # ── 5. mobile_traffic.db ──────────────────────────────────────────────
    step "Initialising mobile_traffic.db (web/backend)"
    "$PY" - <<'PYEOF' 2>>"$ONEINFINITY_LOG"
import sys, os, sqlite3
from pathlib import Path
# Path mirrors web/backend/mobile_traffic_store.py DB_PATH
backend_dir = Path(__file__).resolve().parent
db = (Path(os.environ.get("REPO_DIR", backend_dir.parent.parent)) / "db" / "mobile_traffic.db")
db.parent.mkdir(parents=True, exist_ok=True)
try:
    with sqlite3.connect(str(db)) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS traffic (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id         TEXT NOT NULL,
                timestamp         REAL NOT NULL,
                source            TEXT NOT NULL DEFAULT 'unknown',
                method            TEXT,
                url               TEXT,
                status_code       INTEGER,
                request_headers   TEXT,
                request_body      TEXT,
                response_headers  TEXT,
                response_body     TEXT,
                duration_ms       INTEGER,
                decrypted         INTEGER DEFAULT 0,
                modified          INTEGER DEFAULT 0,
                session_id        TEXT DEFAULT '',
                correlation_chain TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_traffic_device    ON traffic(device_id);
            CREATE INDEX IF NOT EXISTS idx_traffic_ts        ON traffic(timestamp);
            CREATE INDEX IF NOT EXISTS idx_traffic_session   ON traffic(session_id);
        """)
        conn.commit()
    print(f"[ok] mobile_traffic.db initialised: {db}")
except Exception as e:
    print(f"[warn] mobile_traffic.db init: {e}", file=sys.stderr)
PYEOF
    ok "mobile_traffic.db initialised"

    # ── 6. Remaining named DBs (auto-created by path_manager on first use) ─
    #    Pre-create the files so permissions + WAL mode are set correctly.
    step "Pre-creating remaining named SQLite databases"
    "$PY" - <<'PYEOF' 2>>"$ONEINFINITY_LOG"
import os, sqlite3
from pathlib import Path
oi_home = Path(os.environ.get("ONEINFINITY_HOME", Path.home() / ".oneinfinity"))
db_dir  = oi_home / "databases"
db_dir.mkdir(parents=True, exist_ok=True)
for name in ("attack_graph", "knowledge_base", "research", "recon_cache"):
    db = db_dir / f"{name}.db"
    try:
        with sqlite3.connect(str(db)) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.commit()
        print(f"[ok] {name}.db ready: {db}")
    except Exception as e:
        print(f"[warn] {name}.db: {e}")
PYEOF
    ok "attack_graph.db / knowledge_base.db / research.db / recon_cache.db pre-created"

    ok "SQLite database initialisation complete"
    info "All databases at: ${DB_DIR}/"
    info "Mobile traffic DB at: ${REPO_DIR}/db/mobile_traffic.db"
}

init_all_databases() {
    section "Database Schema & Configuration"
    info "Initialising all databases with OneInfinity schema..."

    init_postgres_schema
    init_neo4j_schema
    init_redis_config
    init_sqlite_databases

    ok "All databases initialised"
}

# ORCHESTRATION — do_fresh_install / do_update / main / entry-point
# ============================================================================

do_fresh_install() {
    install_system_deps
    install_language_runtimes
    clone_or_setup_repo
    install_go_tools
    install_python_tools
    install_system_tools
    install_nim            # Section K: AV-evasive payload compiler
    install_ebpf_toolchain # Section K: eBPF tracing (Linux) / skipped on macOS
    build_custom_go_binaries
    setup_databases        # Section G: Docker PG+Redis+Neo4j
    init_all_databases     # Section L: Apply schema, migrations, Neo4j indexes, Redis config
    setup_mobsf            # Section H: MobSF Docker
    build_rust_core        # Section I: PyO3 Rust core (oneinfinity_core)
    build_rust_fuzzer      # Section I: LibAFL fuzzer binary (oi-fuzzer)
    build_rust_jwt_crack   # Section I: Rust JWT brute-forcer (oi-jwt-crack)
    # ── Web frontend dependencies ──────────────────────────────────────────
    step "Installing web/frontend npm dependencies"
    if command -v npm &>/dev/null; then
        if [[ -f "$REPO_DIR/web/frontend/package.json" ]]; then
            if (cd "$REPO_DIR/web/frontend" && npm install >>"$ONEINFINITY_LOG" 2>&1); then
                ok "web/frontend npm dependencies installed"
            else
                warn "web/frontend npm install failed — check $ONEINFINITY_LOG"
            fi
        fi
    else
        warn "npm not found — web/frontend dependencies not installed; install Node.js and run: cd web/frontend && npm install"
    fi
    install_ai_providers   # AI providers: Ollama, Antigravity CLI, Groq key prompt
    setup_env_and_alias    # Section J: .env, alias, wordlist
    run_verification       # Section J: verification table
    print_summary          # Section J: final summary
}

do_update() {
    update_repo
    install_go_tools
    if command -v pip3 &>/dev/null; then
        step "Upgrading Python package"
        pip3 install -e ".[ai,mobile,web]" --upgrade -q 2>&1 | tee -a "${ONEINFINITY_LOG:-/dev/null}" >/dev/null && \
            printf "${GREEN}ok${NC}\n" || printf "${YELLOW}warn${NC}\n"
    fi
    build_custom_go_binaries
    build_rust_core
    build_rust_fuzzer      # LibAFL fuzzer binary
    build_rust_jwt_crack   # Rust JWT brute-forcer
    update_docker_images
    init_all_databases     # re-apply schema/migrations in case of new tables
    _build_nim_binaries    # rebuild Nim binaries from updated source
    _compile_ebpf_programs # recompile eBPF objects (Linux only)
    print_summary
}

main() {
    # Initialise log directory early
    mkdir -p "$ONEINFINITY_HOME" 2>/dev/null || true
    _ensure_log

    banner
    _log_to_file "OneInfinity v${OI_VERSION} — install started at $(date)"
    _log_to_file "Args: NO_DOCKER=${NO_DOCKER} SKIP_TOOLS=${SKIP_TOOLS} SKIP_DB=${SKIP_DB} UPDATE_ONLY=${UPDATE_ONLY} NON_INTERACTIVE=${NON_INTERACTIVE}"

    detect_os
    detect_install_mode
    preflight_checks

    if [[ "$INSTALL_MODE" == "update" ]]; then
        do_update
    else
        do_fresh_install
    fi
}

# ============================================================================
# Entry point — only run main() when this script is executed directly
# (allows other sections to source this file for shared functions)
# ============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    _parse_args "$@"
    main
fi