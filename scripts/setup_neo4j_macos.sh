#!/usr/bin/env bash
# scripts/setup_neo4j_macos.sh — OneInfinity native Neo4j setup for macOS
# Idempotent: safe to re-run.
# Neo4j password is read from config/graph.yaml by default (neo4j123).
set -euo pipefail

NEO4J_URI="${NEO4J_URI:-bolt://localhost:7687}"
NEO4J_USERNAME="${NEO4J_USERNAME:-neo4j}"
NEO4J_PORT="${NEO4J_BOLT_PORT:-7687}"

# ── Password ──────────────────────────────────────────────────────────────────
if [[ -z "${NEO4J_PASSWORD:-}" ]]; then
  # Default from config/graph.yaml
  NEO4J_PASSWORD="neo4j123"
  echo "[i] Using default password from config/graph.yaml (neo4j123)"
  echo "    Set NEO4J_PASSWORD env var to use a different password."
fi

echo ""
echo "=== OneInfinity Neo4j Setup (macOS) ==="
echo "URI:      $NEO4J_URI"
echo "Username: $NEO4J_USERNAME"
echo "Port:     $NEO4J_PORT"
echo ""

# ── 1. Install Homebrew (if not present) ──────────────────────────────────────
if ! command -v brew &>/dev/null; then
  echo "[→] Homebrew not found — installing..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

  # Add Homebrew to PATH (for Apple Silicon Macs)
  if [[ -f /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  fi
  echo "[✓] Homebrew installed"
else
  echo "[✓] Homebrew already installed ($(brew --version | head -1))"
fi

# ── 2. Install Neo4j ──────────────────────────────────────────────────────────
if command -v neo4j &>/dev/null; then
  echo "[✓] Neo4j already installed ($(neo4j version 2>/dev/null || echo 'version check failed'))"
else
  echo "[→] Installing Neo4j via Homebrew..."
  brew install neo4j
  echo "[✓] Neo4j installed"
fi

# ── 3. Set initial password (before first start) ──────────────────────────────
if ! brew services list | grep neo4j | grep -q "started"; then
  echo "[→] Setting Neo4j initial password..."
  neo4j-admin dbms set-initial-password "$NEO4J_PASSWORD" 2>/dev/null \
    || echo "[i] Initial password already configured — skipping"
else
  echo "[✓] Neo4j already running — skipping password init"
fi

# ── 4. Start Neo4j service ────────────────────────────────────────────────────
if brew services list | grep neo4j | grep -q "started"; then
  echo "[✓] Neo4j service already running"
else
  echo "[→] Starting Neo4j service (may take 15-30s)..."
  brew services start neo4j
  echo "[✓] Neo4j service started (will auto-start on login)"
fi

# ── 5. Wait for Neo4j to be ready ────────────────────────────────────────────
echo "[→] Waiting for Neo4j to accept connections..."
for i in $(seq 1 30); do
  if command -v cypher-shell &>/dev/null && \
     NEO4J_PASSWORD="$NEO4J_PASSWORD" cypher-shell -u "$NEO4J_USERNAME" \
       -a "$NEO4J_URI" "RETURN 1" &>/dev/null; then
    echo "[✓] Neo4j accepting connections"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "[✗] Neo4j did not start within 30s — check: brew services list"
    echo "    Logs: brew services info neo4j"
    exit 1
  fi
  sleep 1
done

# ── 6. Print env vars ─────────────────────────────────────────────────────────
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Add the following to your ~/.zshrc (or ~/.bashrc):"
echo ""
echo "  export NEO4J_URI=\"$NEO4J_URI\""
echo "  export NEO4J_USERNAME=\"$NEO4J_USERNAME\""
echo "  # SECURITY: Treat this as a secret — do not commit to version control."
echo "  export NEO4J_PASSWORD=\"$NEO4J_PASSWORD\""
echo "  export NEO4J_ENABLED=1"
echo ""
echo "Then reload your shell:"
echo "  source ~/.zshrc"
echo ""
echo "Neo4j Browser available at: http://localhost:7474"
echo "  Username: $NEO4J_USERNAME  Password: $NEO4J_PASSWORD"
echo ""
echo "Verify oneinfinity uses Neo4j:"
echo "  python3 -c \"from core.graph_config import load_graph_config; c=load_graph_config(); print('Neo4j enabled:', c['neo4j']['enabled'])\""
echo ""
echo "Neo4j management commands:"
echo "  brew services start neo4j    # Start Neo4j"
echo "  brew services stop neo4j     # Stop Neo4j"
echo "  brew services restart neo4j  # Restart Neo4j"
echo "  brew services list           # List all services"
echo ""
