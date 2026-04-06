#!/usr/bin/env bash
# scripts/setup_neo4j.sh — OneInfinity native Neo4j setup
# Idempotent: safe to re-run. Requires sudo.
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
echo "=== OneInfinity Neo4j Setup ==="
echo "URI:      $NEO4J_URI"
echo "Username: $NEO4J_USERNAME"
echo "Port:     $NEO4J_PORT"
echo ""

# ── 1. Install Neo4j ──────────────────────────────────────────────────────────
if command -v neo4j &>/dev/null; then
  echo "[✓] Neo4j already installed ($(neo4j --version 2>/dev/null | head -1))"
else
  echo "[→] Adding Neo4j apt repository..."
  sudo apt-get update -qq
  sudo apt-get install -y wget gnupg apt-transport-https

  # Add Neo4j GPG key
  wget -qO- https://debian.neo4j.com/neotechnology.gpg.key \
    | sudo gpg --dearmor -o /etc/apt/keyrings/neotechnology.gpg

  # Add Neo4j repo (LTS 5.x)
  echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/neotechnology.gpg] https://debian.neo4j.com stable 5" \
    | sudo tee /etc/apt/sources.list.d/neo4j.list >/dev/null

  sudo apt-get update -qq
  sudo apt-get install -y neo4j
  echo "[✓] Neo4j installed"
fi

# ── 2. Set initial password (before first start) ──────────────────────────────
# neo4j-admin set-initial-password is safe to run before the service starts.
echo "[→] Setting Neo4j initial password..."
sudo neo4j-admin dbms set-initial-password "$NEO4J_PASSWORD" 2>/dev/null \
  || echo "[i] Password may already be set (service may have started before) — continuing"

# ── 3. Start service ──────────────────────────────────────────────────────────
if systemctl is-active --quiet neo4j; then
  echo "[✓] Neo4j service already running"
else
  echo "[→] Starting Neo4j service (may take 15-30s)..."
  sudo systemctl start neo4j
  sudo systemctl enable neo4j
fi

# ── 4. Wait for Neo4j to be ready ────────────────────────────────────────────
echo "[→] Waiting for Neo4j to accept connections..."
for i in $(seq 1 30); do
  if cypher-shell -u "$NEO4J_USERNAME" -p "$NEO4J_PASSWORD" \
       -a "$NEO4J_URI" "RETURN 1" &>/dev/null 2>&1; then
    echo "[✓] Neo4j accepting connections"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "[✗] Neo4j did not start within 30s — check: journalctl -u neo4j"
    exit 1
  fi
  sleep 1
done

# ── 5. Print env vars ─────────────────────────────────────────────────────────
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
