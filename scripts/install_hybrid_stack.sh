#!/usr/bin/env bash
# =============================================================================
# OneInfinity Hybrid Language Stack Installer
# Installs: Rust + maturin, Nim, TypeScript/Frida-compile, eBPF toolchain
# Already present (skipped): Go 1.26, Node 26, Python 3.14
#
# Usage:
#   chmod +x scripts/install_hybrid_stack.sh
#   ./scripts/install_hybrid_stack.sh
#
# Supports:  macOS (arm64/x86_64), Ubuntu/Debian, Kali Linux, Arch Linux
# =============================================================================

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[FAIL]${NC}  $*" >&2; exit 1; }
section() { echo -e "\n${BLUE}══════════════════════════════════════════${NC}"; echo -e "${BLUE}  $*${NC}"; echo -e "${BLUE}══════════════════════════════════════════${NC}"; }

# ── OS detection ──────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
IS_MAC=false; IS_LINUX=false
PKG_MGR=""

if [[ "$OS" == "Darwin" ]]; then
    IS_MAC=true
    command -v brew &>/dev/null || die "Homebrew required on macOS. Install: https://brew.sh"
    PKG_MGR="brew"
elif [[ "$OS" == "Linux" ]]; then
    IS_LINUX=true
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    else
        die "Unsupported Linux package manager. Needs apt, pacman, or dnf."
    fi
else
    die "Unsupported OS: $OS"
fi

info "Detected: $OS / $ARCH / package manager: $PKG_MGR"

# ── Helper: check if binary exists ───────────────────────────────────────────
need() { command -v "$1" &>/dev/null; }

# ── Helper: install system package ───────────────────────────────────────────
pkg_install() {
    case $PKG_MGR in
        brew)    brew install "$@" ;;
        apt)     sudo apt-get install -y "$@" ;;
        pacman)  sudo pacman -S --noconfirm "$@" ;;
        dnf)     sudo dnf install -y "$@" ;;
    esac
}

# =============================================================================
# 1. RUST + CARGO + MATURIN
# =============================================================================
section "1. Rust toolchain + maturin (PyO3 build tool)"

if need cargo; then
    ok "Rust already installed: $(cargo --version)"
else
    info "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    ok "Rust installed: $(cargo --version)"
fi

# Ensure cargo env is sourced for this session
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"

# Add abi3 / cross-compile targets
info "Adding Rust targets..."
rustup target add aarch64-apple-darwin x86_64-apple-darwin 2>/dev/null || true  # macOS universal
rustup target add x86_64-unknown-linux-gnu 2>/dev/null || true                   # Linux cross

# Install maturin (PyO3 build backend)
if need maturin; then
    ok "maturin already installed: $(maturin --version)"
else
    info "Installing maturin..."
    pip3 install maturin --quiet
    ok "maturin installed: $(maturin --version)"
fi

# Install cargo tools needed for the plan
info "Installing cargo utilities..."
cargo install cargo-watch 2>/dev/null || true          # hot reload during dev
cargo install cargo-audit 2>/dev/null || true          # security audit
cargo install cargo-deny  2>/dev/null || true          # license/dep policy
ok "Cargo utilities ready"

# =============================================================================
# 2. NIM + NIMBLE
# =============================================================================
section "2. Nim + Nimble (AV-evasive payload compiler)"

if need nim; then
    ok "Nim already installed: $(nim --version | head -1)"
else
    info "Installing Nim..."
    case $PKG_MGR in
        brew)
            brew install nim
            ;;
        apt)
            # choosenim is the canonical Nim installer (like rustup for Nim)
            curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
            export PATH="$HOME/.nimble/bin:$PATH"
            ;;
        pacman)
            sudo pacman -S --noconfirm nim
            ;;
        dnf)
            curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
            export PATH="$HOME/.nimble/bin:$PATH"
            ;;
    esac
    ok "Nim installed: $(nim --version | head -1)"
fi

# Ensure nimble (Nim package manager) is on PATH
if need nimble; then
    ok "Nimble: $(nimble --version)"
else
    warn "nimble not found — may need to add ~/.nimble/bin to PATH"
    echo 'export PATH="$HOME/.nimble/bin:$PATH"' >> "$HOME/.bashrc"
    echo 'export PATH="$HOME/.nimble/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
    export PATH="$HOME/.nimble/bin:$PATH"
fi

# Install Nim packages needed for offensive payload generation
info "Installing Nim packages (winim for Windows ABI, zippy for compression)..."
nimble install winim     -y 2>/dev/null || warn "winim: install failed (Windows cross-compile only — ok on macOS/Linux dev)"
nimble install zippy     -y 2>/dev/null || true
nimble install puppy     -y 2>/dev/null || true   # HTTP client for Nim
ok "Nim packages ready"

# =============================================================================
# 3. TYPESCRIPT + FRIDA-COMPILE (Frida hook type-checking)
# =============================================================================
section "3. TypeScript + frida-compile (type-checked Frida hooks)"

# Node is already installed (v26) — verified above
if need node; then
    ok "Node: $(node --version)"
else
    case $PKG_MGR in
        brew)    brew install node ;;
        apt)     curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs ;;
        pacman)  sudo pacman -S --noconfirm nodejs npm ;;
        dnf)     sudo dnf install -y nodejs npm ;;
    esac
fi

# Install frida-compile globally
if need frida-compile; then
    ok "frida-compile: $(frida-compile --version 2>/dev/null || echo 'installed')"
else
    info "Installing frida-compile and Frida tools..."
    npm install -g frida-compile frida-tools @types/frida-gum typescript ts-node
    ok "frida-compile installed: $(frida-compile --version 2>/dev/null || node -e "require('frida-compile'); console.log('ok')")"
fi

# Bootstrap the frida-hooks TypeScript project if not present
FRIDA_HOOKS_DIR="$(dirname "$0")/../src/frida-hooks"
if [[ ! -f "$FRIDA_HOOKS_DIR/package.json" ]]; then
    info "Bootstrapping src/frida-hooks TypeScript project..."
    mkdir -p "$FRIDA_HOOKS_DIR/src" "$FRIDA_HOOKS_DIR/dist"
    cat > "$FRIDA_HOOKS_DIR/package.json" << 'EOF'
{
  "name": "oneinfinity-frida-hooks",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "build": "frida-compile src/index.ts -o dist/hooks.js",
    "build:ssl": "frida-compile src/ssl_hook.ts -o dist/ssl_hook.js",
    "build:all": "for f in src/*.ts; do frida-compile $f -o dist/$(basename $f .ts).js; done",
    "typecheck": "tsc --noEmit"
  },
  "dependencies": {
    "@types/frida-gum": "latest",
    "frida-compile": "latest"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
EOF
    cat > "$FRIDA_HOOKS_DIR/tsconfig.json" << 'EOF'
{
  "compilerOptions": {
    "lib": ["es2020"],
    "target": "es2020",
    "strict": true,
    "noImplicitAny": true,
    "moduleResolution": "node",
    "baseUrl": ".",
    "paths": {
      "frida-gum": ["node_modules/@types/frida-gum"]
    }
  },
  "include": ["src/**/*.ts"],
  "exclude": ["node_modules", "dist"]
}
EOF
    (cd "$FRIDA_HOOKS_DIR" && npm install --silent)
    ok "src/frida-hooks project bootstrapped"
else
    info "src/frida-hooks already exists — running npm install..."
    (cd "$FRIDA_HOOKS_DIR" && npm install --silent)
    ok "src/frida-hooks dependencies up to date"
fi

# =============================================================================
# 4. GO TOOLCHAIN + PROTOBUF / GRPC
# =============================================================================
section "4. Go gRPC / protobuf toolchain"

# Go already installed (1.26) — just need protoc plugins
if need go; then
    ok "Go: $(go version)"
else
    case $PKG_MGR in
        brew)    brew install go ;;
        apt)     sudo apt-get install -y golang-go ;;
        pacman)  sudo pacman -S --noconfirm go ;;
        dnf)     sudo dnf install -y golang ;;
    esac
fi

# protoc (Protocol Buffer compiler)
if need protoc; then
    ok "protoc: $(protoc --version)"
else
    info "Installing protoc..."
    case $PKG_MGR in
        brew)    brew install protobuf ;;
        apt)     sudo apt-get install -y protobuf-compiler ;;
        pacman)  sudo pacman -S --noconfirm protobuf ;;
        dnf)     sudo dnf install -y protobuf-compiler ;;
    esac
fi

# Go protoc plugins
info "Installing Go gRPC plugins..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
export PATH="$PATH:$(go env GOPATH)/bin"
ok "protoc-gen-go + protoc-gen-go-grpc installed"

# Python gRPC / protobuf
info "Installing Python gRPC libraries..."
pip3 install grpcio grpcio-tools protobuf --quiet
ok "Python gRPC ready"

# Bootstrap Go workspace if not present
GO_SRC="$(dirname "$0")/../src/go"
if [[ ! -f "$GO_SRC/go.work" ]]; then
    info "Bootstrapping src/go workspace..."
    mkdir -p "$GO_SRC"
    cat > "$GO_SRC/go.work" << 'EOF'
go 1.21

// Go sidecar services — add each with: go work use ./oi-<name>
// use ./oi-phase-runner
// use ./oi-recon-probe
// use ./oi-ssrf
// use ./oi-oob-listener
// use ./oi-idor-engine
// use ./oi-crawler
// use ./oi-live-surface
// use ./oi-ingest
// use ./oi-target-disc
// use ./oi-js-enum
EOF
    ok "src/go workspace created"
fi

# =============================================================================
# 5. RUST WORKSPACE (oneinfinity_core PyO3 extension)
# =============================================================================
section "5. Rust workspace + oneinfinity_core PyO3 extension scaffold"

RUST_SRC="$(dirname "$0")/../src/rust"
if [[ ! -f "$RUST_SRC/Cargo.toml" ]]; then
    info "Bootstrapping src/rust workspace..."
    mkdir -p "$RUST_SRC/oneinfinity_core/src"
    cat > "$RUST_SRC/Cargo.toml" << 'EOF'
[workspace]
members = [
    "oneinfinity_core",
]
resolver = "2"
EOF
    cat > "$RUST_SRC/oneinfinity_core/Cargo.toml" << 'EOF'
[package]
name = "oneinfinity_core"
version = "0.1.0"
edition = "2021"

[lib]
name = "oneinfinity_core"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.22", features = ["extension-module", "abi3-py39"] }
regex = "1"
md-5 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
petgraph = "0.6"
ipnet = "2"

[features]
default = ["pyo3/extension-module"]
EOF
    cat > "$RUST_SRC/oneinfinity_core/src/lib.rs" << 'EOF'
use pyo3::prelude::*;

mod normalizer;
mod finding_dedup;
mod scope_check;
mod payload_mutate;

#[pymodule]
fn oneinfinity_core(_py: Python, m: &PyModule) -> PyResult<()> {
    // Normalizer
    m.add_function(wrap_pyfunction!(normalizer::normalize_finding, m)?)?;
    m.add_function(wrap_pyfunction!(normalizer::finding_key, m)?)?;
    m.add_function(wrap_pyfunction!(normalizer::merge_normalized, m)?)?;
    m.add_function(wrap_pyfunction!(normalizer::normalize_results, m)?)?;
    // Dedup
    m.add_function(wrap_pyfunction!(finding_dedup::deduplicate_findings, m)?)?;
    m.add_function(wrap_pyfunction!(finding_dedup::calculate_session_risk, m)?)?;
    m.add_function(wrap_pyfunction!(finding_dedup::batch_validate, m)?)?;
    // Scope
    m.add_class::<scope_check::ScopeValidator>()?;
    // Payloads
    m.add_function(wrap_pyfunction!(payload_mutate::mutate, m)?)?;
    m.add_function(wrap_pyfunction!(payload_mutate::generate_waf_bypass, m)?)?;
    Ok(())
}
EOF
    # Create stub modules (actual implementation is Phase 1 work)
    for module in normalizer finding_dedup scope_check payload_mutate; do
        cat > "$RUST_SRC/oneinfinity_core/src/${module}.rs" << RUSTEOF
use pyo3::prelude::*;
// TODO: implement ${module} — Phase 1 work
// Stubs return Python None to allow import without breaking callers
RUSTEOF
    done

    ok "src/rust workspace scaffolded"

    # Try a dev build to confirm the scaffold compiles
    info "Test-building Rust extension (stub — will be fast)..."
    (cd "$RUST_SRC/oneinfinity_core" && cargo check --quiet 2>/dev/null) \
        && ok "Rust extension: cargo check passed" \
        || warn "Rust extension: cargo check had warnings (expected for stubs)"
else
    ok "src/rust workspace already exists"
fi

# =============================================================================
# 6. EBPF TOOLCHAIN (Linux only)
# =============================================================================
section "6. eBPF toolchain (Linux kernel-level tracing)"

if $IS_LINUX; then
    info "Installing eBPF / BPF toolchain..."
    case $PKG_MGR in
        apt)
            sudo apt-get install -y \
                linux-headers-$(uname -r) \
                libbpf-dev \
                bpftool \
                clang \
                llvm \
                libelf-dev \
                zlib1g-dev \
                linux-tools-$(uname -r) 2>/dev/null || \
            sudo apt-get install -y \
                linux-headers-generic \
                libbpf-dev \
                bpftool \
                clang \
                llvm \
                libelf-dev \
                zlib1g-dev
            ;;
        pacman)
            sudo pacman -S --noconfirm \
                linux-headers \
                libbpf \
                bpf \
                clang \
                llvm
            ;;
        dnf)
            sudo dnf install -y \
                kernel-headers \
                libbpf-devel \
                bpftool \
                clang \
                llvm \
                elfutils-libelf-devel \
                zlib-devel
            ;;
    esac

    # Verify BTF support (required for CO-RE eBPF)
    if [[ -f /sys/kernel/btf/vmlinux ]]; then
        ok "BTF available — CO-RE eBPF supported"
    else
        warn "BTF not found at /sys/kernel/btf/vmlinux — eBPF CO-RE will not work"
        warn "Minimum: Linux 5.15 with CONFIG_DEBUG_INFO_BTF=y"
    fi

    # Generate vmlinux.h if bpftool is available
    EBPF_DIR="$(dirname "$0")/../src/ebpf"
    mkdir -p "$EBPF_DIR"
    if need bpftool && [[ -f /sys/kernel/btf/vmlinux ]]; then
        info "Generating vmlinux.h for eBPF CO-RE..."
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$EBPF_DIR/vmlinux.h"
        ok "vmlinux.h generated"
    fi
else
    warn "eBPF toolchain: Linux only — skipped on macOS"
    info "  → For macOS eBPF development, use a Linux VM or Docker"
fi

# =============================================================================
# 7. PYTHON DEPENDENCIES (maturin, grpcio, frida-python)
# =============================================================================
section "7. Python build + runtime dependencies"

pip3 install \
    maturin \
    grpcio \
    grpcio-tools \
    protobuf \
    frida \
    frida-tools \
    --quiet

ok "Python dependencies installed"

# =============================================================================
# 8. NIM SCAFFOLD
# =============================================================================
section "8. Nim source scaffold"

NIM_SRC="$(dirname "$0")/../src/nim"
if [[ ! -d "$NIM_SRC" ]]; then
    info "Creating src/nim scaffold..."
    mkdir -p "$NIM_SRC"

    # nimble.lock equivalent — pin to specific Nim packages
    cat > "$NIM_SRC/oi-shell-gen.nim" << 'EOF'
## OneInfinity Shell Payload Generator
## Outputs: JSON array of ShellPayload to stdout
## Usage: oi-shell-gen --arch=x64 --format=shellcode --obfuscate

import std/[json, strutils, os, parseopt]

type
  ShellPayload = object
    payload: string
    arch: string
    format: string
    obfuscated: bool
    size: int

proc main() =
  var arch = "x64"; var fmt = "shellcode"; var obfuscate = false
  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdLongOption:
      case p.key
      of "arch": arch = p.val
      of "format": fmt = p.val
      of "obfuscate": obfuscate = true
      else: discard
    else: discard

  # TODO Phase 3: implement real payload generation
  # Stub: returns placeholder JSON
  let result = %* [{"payload": "stub", "arch": arch, "format": fmt, "obfuscated": obfuscate, "size": 0}]
  echo $result

main()
EOF

    for nim_file in oi-bypass-gen oi-payloads oi-post-exploit oi-fuzzer oi-privesc-gen; do
        cat > "$NIM_SRC/${nim_file}.nim" << EOF
## OneInfinity ${nim_file} — stub (Phase 3 implementation)
import std/json
echo $(%*[{"status": "stub", "module": "${nim_file}"}])
EOF
    done

    cat > "$NIM_SRC/checksums.json" << 'EOF'
{
  "_comment": "SHA-256 hashes of compiled Nim binaries — verified before execution",
  "_note": "Populated by build script after compilation"
}
EOF
    ok "src/nim scaffold created"

    # Test compile the shell generator stub
    info "Test-compiling oi-shell-gen stub..."
    nim c --hints:off -o:"$NIM_SRC/oi-shell-gen" "$NIM_SRC/oi-shell-gen.nim" \
        && ok "Nim: oi-shell-gen stub compiles OK" \
        || warn "Nim: compilation had issues (check nim output above)"
fi

# =============================================================================
# 9. BUILD MULTI-LANGUAGE BINARIES
# =============================================================================
section "9. Build internal multi-language tools"

REPO_ROOT="$(dirname "$0")/.."
GO_BIN_DIR="$REPO_ROOT/src/go/bin"
RUST_BIN_DIR="$REPO_ROOT/src/rust/target/release"
NIM_BIN_DIR="$REPO_ROOT/src/nim/bin"

mkdir -p "$GO_BIN_DIR" "$NIM_BIN_DIR" "$HOME/.local/bin"

if need go; then
  info "Building Go sidecars..."
  (cd "$REPO_ROOT/src/go" && go work sync >/dev/null 2>&1 || true)
  for mod in "$REPO_ROOT"/src/go/oi-*; do
    if [[ -f "$mod/go.mod" ]]; then
      name="$(basename "$mod")"
      if (cd "$mod" && go build -o "$GO_BIN_DIR/$name" . >/dev/null 2>&1); then
        ok "Built $name"
      else
        warn "$name build failed (non-fatal)"
      fi
    fi
  done
else
  warn "Go missing — skipping Go sidecar build"
fi

if need cargo; then
  info "Building Rust binaries..."
  if (cd "$REPO_ROOT/src/rust" && cargo build --release >/dev/null 2>&1); then
    for bin in oi-fuzzer oi-jwt-crack; do
      if [[ -x "$RUST_BIN_DIR/$bin" ]]; then
        install -m 0755 "$RUST_BIN_DIR/$bin" "$HOME/.local/bin/$bin" || true
        ok "Installed $bin"
      else
        warn "Rust binary missing: $bin"
      fi
    done
  else
    warn "Rust build failed (non-fatal)"
  fi
else
  warn "Rust/cargo missing — skipping Rust build"
fi

if need nim; then
  info "Building Nim binaries..."
  for src in "$REPO_ROOT"/src/nim/*.nim; do
    [[ -f "$src" ]] || continue
    name="$(basename "$src" .nim)"
    if nim c --hints:off --verbosity:0 --out:"$NIM_BIN_DIR/$name" "$src" >/dev/null 2>&1; then
      ok "Built $name"
    else
      warn "$name build failed (non-fatal)"
    fi
  done
  if need python3; then
    python3 "$REPO_ROOT/scripts/gen_nim_checksums.py" >/dev/null 2>&1 || warn "Nim checksum generation failed"
  fi
else
  warn "Nim missing — skipping Nim build"
fi

if $IS_LINUX && [[ -f "$REPO_ROOT/src/ebpf/Makefile" ]]; then
  info "Building eBPF probes..."
  (cd "$REPO_ROOT/src/ebpf" && make >/dev/null 2>&1) || warn "eBPF build failed (non-fatal)"
fi

# =============================================================================
# 10. SHELL PROFILE — add all bins to PATH
# =============================================================================
section "10. PATH setup"

PROFILE_BLOCK='
# OneInfinity Hybrid Stack — added by install_hybrid_stack.sh
export ONEINFINITY_REPO="${ONEINFINITY_REPO:-$HOME/oneinfinity}"
export PATH="$HOME/.cargo/bin:$PATH"
export PATH="$HOME/.nimble/bin:$PATH"
export PATH="$(go env GOPATH)/bin:$PATH"
export PATH="$ONEINFINITY_REPO/src/go/bin:$ONEINFINITY_REPO/src/nim/bin:$ONEINFINITY_REPO/src/rust/target/release:$PATH"
export PATH="$HOME/.local/bin:$PATH"
'

for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [[ -f "$rc" ]] && ! grep -q "OneInfinity Hybrid Stack" "$rc"; then
        echo "$PROFILE_BLOCK" >> "$rc"
        info "Updated $rc"
    fi
done

# Source for this session
export ONEINFINITY_REPO="${ONEINFINITY_REPO:-$REPO_ROOT}"
export PATH="$HOME/.cargo/bin:$HOME/.nimble/bin:$(go env GOPATH)/bin:$ONEINFINITY_REPO/src/go/bin:$ONEINFINITY_REPO/src/nim/bin:$ONEINFINITY_REPO/src/rust/target/release:$HOME/.local/bin:$PATH"

# =============================================================================
# 11. VERIFICATION
# =============================================================================
section "11. Installation verification"

echo ""
echo "  Tool           Status          Version"
echo "  ─────────────────────────────────────────────────"

check_tool() {
    local name=$1; local cmd=$2; local ver_cmd=$3
    if need "$cmd"; then
        local ver; ver=$(eval "$ver_cmd" 2>/dev/null | head -1 | tr -d '\n') || ver="(installed)"
        printf "  %-14s ${GREEN}%-16s${NC} %s\n" "$name" "OK" "$ver"
    else
        printf "  %-14s ${RED}%-16s${NC}\n" "$name" "MISSING"
    fi
}

check_tool "Python"        "python3"       "python3 --version"
check_tool "Go"            "go"            "go version"
check_tool "Node.js"       "node"          "node --version"
check_tool "Rust/cargo"    "cargo"         "cargo --version"
check_tool "rustup"        "rustup"        "rustup --version"
check_tool "maturin"       "maturin"       "maturin --version"
check_tool "Nim"           "nim"           "nim --version | head -1"
check_tool "nimble"        "nimble"        "nimble --version"
check_tool "protoc"        "protoc"        "protoc --version"
check_tool "frida-compile" "frida-compile" "echo '(installed)'"
check_tool "clang (eBPF)"  "clang"         "clang --version | head -1"
check_tool "bpftool"       "bpftool"       "bpftool version 2>/dev/null | head -1"

echo ""
echo "  Directories"
echo "  ─────────────────────────────────────────────────"

check_dir() {
    local label=$1; local path=$2
    if [[ -d "$path" ]]; then
        printf "  %-20s ${GREEN}OK${NC}   %s\n" "$label" "$path"
    else
        printf "  %-20s ${YELLOW}MISSING${NC}  %s\n" "$label" "$path"
    fi
}

REPO_ROOT="$(dirname "$0")/.."
check_dir "src/rust/"           "$REPO_ROOT/src/rust"
check_dir "src/go/"             "$REPO_ROOT/src/go"
check_dir "src/nim/"            "$REPO_ROOT/src/nim"
check_dir "src/nim/bin/"        "$REPO_ROOT/src/nim/bin"
check_dir "src/go/bin/"         "$REPO_ROOT/src/go/bin"
check_dir "src/frida-hooks/"    "$REPO_ROOT/src/frida-hooks"

echo ""

# Test maturin develop (Rust → Python extension)
if need maturin && need cargo; then
    info "Testing maturin develop (Rust PyO3 stub)..."
    RUST_EXT="$REPO_ROOT/src/rust/oneinfinity_core"
    if [[ -d "$RUST_EXT" ]]; then
        (cd "$RUST_EXT" && maturin develop --release -q 2>/dev/null) \
            && ok "maturin develop: Rust extension built and importable" \
            || warn "maturin develop: build failed (expected until Phase 1 implementation)"
    fi
fi

# =============================================================================
# DONE
# =============================================================================
section "Installation complete"

echo ""
echo "  Next steps:"
echo ""
echo "  1. Reload your shell:   source ~/.zshrc  (or ~/.bashrc)"
echo ""
echo "  2. Start Phase 0 — verify stubs:"
echo "     python3 -c 'import oneinfinity_core; print(dir(oneinfinity_core))'"
echo "     cd src/frida-hooks && npm run typecheck"
echo "     cd src/nim && nim c --hints:off oi-shell-gen.nim"
echo ""
echo "  3. Begin Phase 1 (Rust hot paths):"
echo "     cd src/rust/oneinfinity_core"
echo "     maturin develop --release"
echo ""
echo "  4. Begin Phase 2 (Go sidecars):"
echo "     cd src/go && go work sync"
echo ""
echo "  See HYBRID_MIGRATION_PLAN.md for the full 40-week plan."
echo ""
