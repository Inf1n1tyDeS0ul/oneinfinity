#!/usr/bin/env bash
# ============================================================================
# Bug Bounty Toolchain Installer
# Installs all tools from the 0xKayala/BugBountyTools curated list
# Supports: Ubuntu / Kali Linux
# Usage: bash install_tools.sh [--skip-go] [--skip-docker] [--only <category>]
# ============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }
section() { echo -e "\n${BOLD}${BLUE}══ $* ══${NC}"; }

SKIP_GO=0; SKIP_DOCKER=0; ONLY=""
for arg in "$@"; do
    case $arg in
        --skip-go)     SKIP_GO=1 ;;
        --skip-docker) SKIP_DOCKER=1 ;;
        --only)        shift; ONLY="${1:-}" ;;
    esac
done

INSTALL_LOG="$HOME/.bounty_install.log"
FAILED_TOOLS=()
INSTALLED_TOOLS=()

log_result() {
    local status=$1 tool=$2 method=$3
    if [[ $status -eq 0 ]]; then
        ok "$tool installed via $method"
        INSTALLED_TOOLS+=("$tool")
    else
        warn "$tool FAILED via $method — skipping"
        FAILED_TOOLS+=("$tool")
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$status] $tool ($method)" >> "$INSTALL_LOG"
}

run_silent() {
    "$@" >> "$INSTALL_LOG" 2>&1
}

# ── Detect distro ─────────────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then PKG_MGR="apt"; else PKG_MGR="unknown"; fi

# ── Sudo helper ───────────────────────────────────────────────────────────────
SUDO=""
if [[ $EUID -ne 0 ]]; then
    if command -v sudo &>/dev/null; then SUDO="sudo"; fi
fi

# ============================================================================
# 1. BASE DEPENDENCIES
# ============================================================================
install_base_deps() {
    section "Base Dependencies"
    info "Updating package lists..."
    $SUDO apt-get update -qq >> "$INSTALL_LOG" 2>&1 || warn "apt update failed"

    local PKGS=(
        curl wget git python3 python3-pip python3-venv
        build-essential libssl-dev libffi-dev
        nmap masscan nikto whatweb
        dnsutils whois netcat-openbsd jq unzip tar
        libpcap-dev zlib1g-dev libpq-dev
    )
    info "Installing base packages: ${PKGS[*]}"
    $SUDO apt-get install -y -qq "${PKGS[@]}" >> "$INSTALL_LOG" 2>&1
    ok "Base packages installed"

    # pip upgrade
    python3 -m pip install --upgrade pip --quiet >> "$INSTALL_LOG" 2>&1 || true
    ok "pip upgraded"
}

# ============================================================================
# 2. GO INSTALLATION
# ============================================================================
install_go() {
    section "Go Language Runtime"
    if command -v go &>/dev/null; then
        GO_VER=$(go version 2>/dev/null | awk '{print $3}')
        ok "Go already installed: $GO_VER"
        return 0
    fi
    if [[ $SKIP_GO -eq 1 ]]; then warn "Skipping Go install (--skip-go)"; return 0; fi

    local GO_VER="1.22.4"
    local GO_ARCH="linux-amd64"
    local GO_URL="https://go.dev/dl/go${GO_VER}.${GO_ARCH}.tar.gz"
    local GO_TAR="/tmp/go_install.tar.gz"

    info "Downloading Go ${GO_VER}..."
    curl -fsSL "$GO_URL" -o "$GO_TAR" >> "$INSTALL_LOG" 2>&1
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "$GO_TAR" >> "$INSTALL_LOG" 2>&1
    rm -f "$GO_TAR"

    # Add to PATH if not already present
    if ! grep -q '/usr/local/go/bin' "$HOME/.bashrc" 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$HOME/.bashrc"
    fi
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    ok "Go ${GO_VER} installed"
}

# ── Go install wrapper ────────────────────────────────────────────────────────
go_install() {
    local pkg=$1 bin=${2:-}
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    if [[ -n $bin ]] && command -v "$bin" &>/dev/null; then
        ok "$bin already installed"
        INSTALLED_TOOLS+=("$bin")
        return 0
    fi
    run_silent go install "$pkg" && log_result 0 "${bin:-$pkg}" "go install" \
        || log_result 1 "${bin:-$pkg}" "go install"
}

# ============================================================================
# 3. RUST / CARGO
# ============================================================================
install_rust() {
    section "Rust / Cargo"
    if command -v cargo &>/dev/null; then
        ok "Rust/Cargo already installed: $(cargo --version)"
        return 0
    fi
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
        >> "$INSTALL_LOG" 2>&1
    source "$HOME/.cargo/env" 2>/dev/null || true
    ok "Rust installed"
}

# ============================================================================
# 4. NODE.JS
# ============================================================================
install_node() {
    section "Node.js"
    if command -v node &>/dev/null; then
        ok "Node.js already installed: $(node --version)"
        return 0
    fi
    info "Installing Node.js via NodeSource..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO bash - >> "$INSTALL_LOG" 2>&1
    $SUDO apt-get install -y -qq nodejs >> "$INSTALL_LOG" 2>&1
    ok "Node.js installed"
}

# ── pip install wrapper ───────────────────────────────────────────────────────
pip_install() {
    local pkg=$1 bin=${2:-}
    if [[ -n $bin ]] && command -v "$bin" &>/dev/null; then
        ok "$bin already installed"
        INSTALLED_TOOLS+=("$bin")
        return 0
    fi
    run_silent python3 -m pip install --quiet --break-system-packages "$pkg" 2>/dev/null \
        || run_silent python3 -m pip install --quiet "$pkg"
    log_result $? "${bin:-$pkg}" "pip"
}

# ── git clone + pip install ───────────────────────────────────────────────────
git_pip_install() {
    local repo=$1 dir=$2 bin=${3:-} extra_cmd=${4:-}
    local dest="$HOME/tools/$dir"
    if [[ -n $bin ]] && command -v "$bin" &>/dev/null; then
        ok "$bin already installed"
        INSTALLED_TOOLS+=("$bin")
        return 0
    fi
    mkdir -p "$HOME/tools"
    if [[ -d $dest ]]; then
        run_silent git -C "$dest" pull --quiet
    else
        run_silent git clone --quiet --depth=1 "$repo" "$dest"
    fi
    if [[ -f "$dest/requirements.txt" ]]; then
        run_silent python3 -m pip install --quiet --break-system-packages \
            -r "$dest/requirements.txt" 2>/dev/null \
            || run_silent python3 -m pip install --quiet -r "$dest/requirements.txt"
    fi
    if [[ -n $extra_cmd ]]; then
        (cd "$dest" && eval "$extra_cmd" >> "$INSTALL_LOG" 2>&1)
    fi
    log_result $? "${bin:-$dir}" "git+pip"
}

# ── Binary download ───────────────────────────────────────────────────────────
binary_install() {
    local name=$1 url=$2 dest=${3:-/usr/local/bin/$1}
    if command -v "$name" &>/dev/null; then
        ok "$name already installed"
        INSTALLED_TOOLS+=("$name")
        return 0
    fi
    info "Downloading $name binary..."
    local tmp="/tmp/${name}_dl"
    if curl -fsSL "$url" -o "$tmp" >> "$INSTALL_LOG" 2>&1; then
        if file "$tmp" | grep -q "gzip\|tar"; then
            tar -xzf "$tmp" -C /tmp >> "$INSTALL_LOG" 2>&1
            local extracted
            extracted=$(tar -tzf "$tmp" 2>/dev/null | grep "^[^/]*$" | head -1 || true)
            [[ -n $extracted ]] && mv "/tmp/$extracted" "$dest" 2>/dev/null || true
        else
            $SUDO mv "$tmp" "$dest"
        fi
        $SUDO chmod +x "$dest" 2>/dev/null || chmod +x "$dest" 2>/dev/null || true
        log_result 0 "$name" "binary"
    else
        log_result 1 "$name" "binary"
    fi
}

# ── apt install wrapper ───────────────────────────────────────────────────────
apt_install() {
    local pkg=$1 bin=${2:-$1}
    if command -v "$bin" &>/dev/null; then
        ok "$bin already installed"
        INSTALLED_TOOLS+=("$bin")
        return 0
    fi
    $SUDO apt-get install -y -qq "$pkg" >> "$INSTALL_LOG" 2>&1
    log_result $? "$bin" "apt"
}

# ============================================================================
# TOOL INSTALLATION SECTIONS
# ============================================================================

install_subdomain_tools() {
    section "Subdomain Enumeration Tools"

    # subfinder
    go_install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"

    # amass
    go_install "github.com/owasp-amass/amass/v4/...@master" "amass"

    # assetfinder
    go_install "github.com/tomnomnom/assetfinder@latest" "assetfinder"

    # findomain
    local FINDOMAIN_URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux"
    binary_install "findomain" "$FINDOMAIN_URL" "/usr/local/bin/findomain"

    # chaos-client
    go_install "github.com/projectdiscovery/chaos-client/cmd/chaos@latest" "chaos"

    # sublist3r
    git_pip_install "https://github.com/aboul3la/Sublist3r.git" "Sublist3r" "" \
        "pip install -q --break-system-packages -r requirements.txt 2>/dev/null || pip install -q -r requirements.txt"
    # Create a shim for sublist3r
    if [[ ! -f /usr/local/bin/sublist3r ]] && [[ -d "$HOME/tools/Sublist3r" ]]; then
        echo '#!/bin/bash' | $SUDO tee /usr/local/bin/sublist3r > /dev/null
        echo "python3 $HOME/tools/Sublist3r/sublist3r.py \"\$@\"" | $SUDO tee -a /usr/local/bin/sublist3r > /dev/null
        $SUDO chmod +x /usr/local/bin/sublist3r
    fi

    # knockpy
    pip_install "knock-subdomains" "knockpy"
}

install_http_recon_tools() {
    section "HTTP Probing & Web Crawling Tools"

    # httpx
    go_install "github.com/projectdiscovery/httpx/cmd/httpx@latest" "httpx"

    # katana
    go_install "github.com/projectdiscovery/katana/cmd/katana@latest" "katana"

    # hakrawler
    go_install "github.com/hakluke/hakrawler@latest" "hakrawler"

    # gauplus
    go_install "github.com/bp0lr/gauplus@latest" "gauplus"

    # waybackurls
    go_install "github.com/tomnomnom/waybackurls@latest" "waybackurls"

    # paramspider
    pip_install "paramspider" "paramspider"
    if [[ ! -f /usr/local/bin/paramspider ]] && [[ -d "$HOME/tools/ParamSpider" ]]; then
        echo '#!/bin/bash' | $SUDO tee /usr/local/bin/paramspider > /dev/null
        echo "python3 $HOME/tools/ParamSpider/paramspider.py \"\$@\"" | \
            $SUDO tee -a /usr/local/bin/paramspider > /dev/null
        $SUDO chmod +x /usr/local/bin/paramspider
    fi
}

install_port_scanning_tools() {
    section "Port Scanning Tools"

    # naabu
    go_install "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" "naabu"

    # nmap (apt)
    apt_install "nmap" "nmap"

    # masscan (apt)
    apt_install "masscan" "masscan"

    # rustscan (cargo)
    if ! command -v rustscan &>/dev/null; then
        info "Installing RustScan via cargo..."
        source "$HOME/.cargo/env" 2>/dev/null || true
        if command -v cargo &>/dev/null; then
            run_silent cargo install rustscan
            log_result $? "rustscan" "cargo"
        else
            warn "cargo not available — skipping rustscan"
            FAILED_TOOLS+=("rustscan")
        fi
    else
        ok "rustscan already installed"
        INSTALLED_TOOLS+=("rustscan")
    fi
}

install_content_discovery_tools() {
    section "Content Discovery & Fuzzing Tools"

    # ffuf
    go_install "github.com/ffuf/ffuf/v2@latest" "ffuf"

    # gobuster
    go_install "github.com/OJ/gobuster/v3@latest" "gobuster"

    # dirsearch
    pip_install "dirsearch" "dirsearch"
    git_pip_install "https://github.com/maurosoria/dirsearch.git" "dirsearch-src" "" ""
    if [[ ! -f /usr/local/bin/dirsearch ]] && [[ -d "$HOME/tools/dirsearch-src" ]]; then
        echo '#!/bin/bash' | $SUDO tee /usr/local/bin/dirsearch > /dev/null
        echo "python3 $HOME/tools/dirsearch-src/dirsearch.py \"\$@\"" | \
            $SUDO tee -a /usr/local/bin/dirsearch > /dev/null
        $SUDO chmod +x /usr/local/bin/dirsearch
    fi

    # feroxbuster (Go)
    go_install "github.com/epi052/feroxbuster@latest" "feroxbuster" || true

    # Download SecLists wordlists (lightweight subset)
    if [[ ! -d /usr/share/seclists ]]; then
        info "Installing SecLists wordlists..."
        $SUDO apt-get install -y -qq seclists >> "$INSTALL_LOG" 2>&1 \
            || warn "SecLists apt install failed — clone manually if needed"
    else
        ok "SecLists already present"
    fi
}

install_vuln_scanning_tools() {
    section "Vulnerability Scanning Tools"

    # nuclei
    go_install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "nuclei"
    # Update nuclei templates
    if command -v nuclei &>/dev/null; then
        info "Updating Nuclei templates..."
        nuclei -update-templates >> "$INSTALL_LOG" 2>&1 || warn "nuclei template update failed"
    fi

    # dalfox (XSS)
    go_install "github.com/hahwul/dalfox/v2@latest" "dalfox"

    # kxss
    go_install "github.com/Emoe/kxss@latest" "kxss"

    # crlfuzz
    go_install "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest" "crlfuzz"

    # sqlmap
    git_pip_install "https://github.com/sqlmapproject/sqlmap.git" "sqlmap" "" ""
    if [[ ! -f /usr/local/bin/sqlmap ]] && [[ -d "$HOME/tools/sqlmap" ]]; then
        echo '#!/bin/bash' | $SUDO tee /usr/local/bin/sqlmap > /dev/null
        echo "python3 $HOME/tools/sqlmap/sqlmap.py \"\$@\"" | \
            $SUDO tee -a /usr/local/bin/sqlmap > /dev/null
        $SUDO chmod +x /usr/local/bin/sqlmap
    fi

    # xssstrike
    git_pip_install "https://github.com/s0md3v/XSStrike.git" "XSStrike" "" ""
    if [[ ! -f /usr/local/bin/xssstrike ]] && [[ -d "$HOME/tools/XSStrike" ]]; then
        echo '#!/bin/bash' | $SUDO tee /usr/local/bin/xssstrike > /dev/null
        echo "python3 $HOME/tools/XSStrike/xsstrike.py \"\$@\"" | \
            $SUDO tee -a /usr/local/bin/xssstrike > /dev/null
        $SUDO chmod +x /usr/local/bin/xssstrike
    fi

    # commix
    git_pip_install "https://github.com/commixproject/commix.git" "commix" "" ""
    if [[ ! -f /usr/local/bin/commix ]] && [[ -d "$HOME/tools/commix" ]]; then
        echo '#!/bin/bash' | $SUDO tee /usr/local/bin/commix > /dev/null
        echo "python3 $HOME/tools/commix/commix.py \"\$@\"" | \
            $SUDO tee -a /usr/local/bin/commix > /dev/null
        $SUDO chmod +x /usr/local/bin/commix
    fi

    # nikto (apt)
    apt_install "nikto" "nikto"

    # whatweb (apt)
    apt_install "whatweb" "whatweb"

    # wfuzz
    pip_install "wfuzz" "wfuzz"

    # NucleiFuzzer (custom wrapper by 0xKayala)
    go_install "github.com/0xKayala/NucleiFuzzer@latest" "nucleifuzzer" || true
}

install_secrets_tools() {
    section "Secrets Discovery Tools"

    # trufflehog
    if ! command -v trufflehog &>/dev/null; then
        info "Installing TruffleHog..."
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
            | $SUDO sh -s -- -b /usr/local/bin >> "$INSTALL_LOG" 2>&1
        log_result $? "trufflehog" "script"
    else
        ok "trufflehog already installed"
        INSTALLED_TOOLS+=("trufflehog")
    fi

    # gitleaks
    go_install "github.com/gitleaks/gitleaks/v8@latest" "gitleaks"
}

install_api_tools() {
    section "API Security Testing Tools"

    # jwt_tool
    git_pip_install "https://github.com/ticarpi/jwt_tool.git" "jwt_tool" "" ""
    if [[ ! -f /usr/local/bin/jwt_tool ]] && [[ -d "$HOME/tools/jwt_tool" ]]; then
        echo '#!/bin/bash' | $SUDO tee /usr/local/bin/jwt_tool > /dev/null
        echo "python3 $HOME/tools/jwt_tool/jwt_tool.py \"\$@\"" | \
            $SUDO tee -a /usr/local/bin/jwt_tool > /dev/null
        $SUDO chmod +x /usr/local/bin/jwt_tool
    fi

    # graphqlmap
    git_pip_install "https://github.com/swisskyrepo/GraphQLmap.git" "GraphQLmap" "" ""

    # nosqlmap
    git_pip_install "https://github.com/codingo/NoSQLMap.git" "NoSQLMap" "" ""

    # kiterunner
    go_install "github.com/assetnote/kiterunner/cmd/kr@latest" "kr"

    # arjun (parameter discovery)
    pip_install "arjun" "arjun"
}

install_cloud_tools() {
    section "Cloud Recon Tools"

    # cloudbrute
    go_install "github.com/0xsha/CloudBrute@latest" "cloudbrute" || true

    # pacu (AWS exploitation framework)
    git_pip_install "https://github.com/RhinoSecurityLabs/pacu.git" "pacu" "" ""

    # S3Scanner
    pip_install "s3scanner" "s3scanner"

    # cloudmapper
    git_pip_install "https://github.com/duo-labs/cloudmapper.git" "cloudmapper" "" ""
}

install_network_tools() {
    section "Network Security Tools"

    # naabu (already covered in port scan)
    # masscan (already covered)

    # netfuzzer
    go_install "github.com/0xKayala/NetFuzzer@latest" "netfuzzer" || true
}

install_misc_tools() {
    section "Miscellaneous Utility Tools"

    # httprobe (tomnomnom)
    go_install "github.com/tomnomnom/httprobe@latest" "httprobe"

    # anew (tomnomnom — deduplicate output)
    go_install "github.com/tomnomnom/anew@latest" "anew"

    # qsreplace (tomnomnom — query string replacement)
    go_install "github.com/tomnomnom/qsreplace@latest" "qsreplace"

    # gf (tomnomnom — grep patterns for bugs)
    go_install "github.com/tomnomnom/gf@latest" "gf"
    # Install gf patterns
    if command -v gf &>/dev/null && [[ ! -d "$HOME/.gf" ]]; then
        mkdir -p "$HOME/.gf"
        git clone --quiet --depth=1 https://github.com/tomnomnom/gf.git /tmp/gf_src >> "$INSTALL_LOG" 2>&1 || true
        cp -r /tmp/gf_src/examples/* "$HOME/.gf/" 2>/dev/null || true
        git clone --quiet --depth=1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf_patterns >> "$INSTALL_LOG" 2>&1 || true
        cp /tmp/gf_patterns/*.json "$HOME/.gf/" 2>/dev/null || true
    fi

    # unfurl (tomnomnom — URL component extraction)
    go_install "github.com/tomnomnom/unfurl@latest" "unfurl"

    # dnsx
    go_install "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" "dnsx"

    # interactsh-client (OOB interaction server)
    go_install "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" "interactsh-client"

    # notify
    go_install "github.com/projectdiscovery/notify/cmd/notify@latest" "notify"

    # wappalyzer CLI
    if command -v npm &>/dev/null; then
        npm install -g wappalyzer-cli >> "$INSTALL_LOG" 2>&1 \
            && ok "wappalyzer-cli installed" || warn "wappalyzer-cli failed"
    fi
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║       Bug Bounty Toolchain Installer v2.0            ║"
    echo "  ║   Based on: 0xKayala/BugBountyTools curated list     ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  Log file: $INSTALL_LOG"
    echo "  Run date: $(date)"
    echo ""

    > "$INSTALL_LOG"

    install_base_deps
    install_go
    install_rust
    # install_node   # uncomment if you need Node.js tools

    case "${ONLY:-all}" in
        subdomain)   install_subdomain_tools ;;
        http)        install_http_recon_tools ;;
        ports)       install_port_scanning_tools ;;
        content)     install_content_discovery_tools ;;
        vuln)        install_vuln_scanning_tools ;;
        secrets)     install_secrets_tools ;;
        api)         install_api_tools ;;
        cloud)       install_cloud_tools ;;
        network)     install_network_tools ;;
        misc)        install_misc_tools ;;
        all)
            install_subdomain_tools
            install_http_recon_tools
            install_port_scanning_tools
            install_content_discovery_tools
            install_vuln_scanning_tools
            install_secrets_tools
            install_api_tools
            install_cloud_tools
            install_network_tools
            install_misc_tools
            ;;
        *) warn "Unknown category: $ONLY. Run with --only <category> or omit for all." ;;
    esac

    # ── Summary ───────────────────────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}${GREEN}══ Installation Summary ══${NC}"
    echo -e "  ${GREEN}Installed (${#INSTALLED_TOOLS[@]}):${NC} ${INSTALLED_TOOLS[*]:-none}"
    echo ""
    if [[ ${#FAILED_TOOLS[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Failed/Skipped (${#FAILED_TOOLS[@]}):${NC} ${FAILED_TOOLS[*]}"
        echo ""
        echo "  Check $INSTALL_LOG for details on failures."
    fi

    echo ""
    echo "  Add to your shell config if not already present:"
    echo "    export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin:\$HOME/.cargo/bin"
    echo ""
    echo "  Verify installations with: bounty toolcheck"
    echo ""
}

main "$@"
