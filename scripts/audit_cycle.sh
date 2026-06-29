#!/usr/bin/env bash
# =============================================================================
# OneInfinity Council Audit Cycle
# Runs repeatable audit -> integrate -> validate rounds with cleanup.
# Usage:
#   bash scripts/audit_cycle.sh --target https://example.com --mode deep --rounds 2 --execute
# =============================================================================
set -euo pipefail

TARGET=""
MODE="normal"
ROUNDS=1
EXECUTE=0
SLEEP_BETWEEN=0

usage() {
  cat <<'EOF'
Usage: audit_cycle.sh --target <url|domain> [--mode normal|deep|god] [--rounds N] [--execute] [--sleep SEC]

Options:
  --target   Target URL or domain (required)
  --mode     normal | deep | god  (default: normal)
  --rounds   Number of rounds (default: 1)
  --execute  Actually run commands (default: dry-run)
  --sleep    Seconds to sleep between rounds (default: 0)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --rounds) ROUNDS="$2"; shift 2 ;;
    --execute) EXECUTE=1; shift ;;
    --sleep) SLEEP_BETWEEN="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Missing --target"
  usage
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT_DIR="$REPO_ROOT/logs/audit_cycle"

run_cmd() {
  local label="$1"; shift
  if [[ $EXECUTE -eq 1 ]]; then
    echo "[RUN] $label: $*"
    "$@" || echo "[WARN] command failed: $label"
  else
    echo "[PLAN] $label: $*"
  fi
}

scan_cmd=()
if [[ "$MODE" == "god" ]]; then
  scan_cmd=(oneinfinity scan "$TARGET" --god-mode --yes)
else
  scan_cmd=(oneinfinity scan "$TARGET" --scan-type "$MODE" --yes)
fi

for ((round=1; round<=ROUNDS; round++)); do
  rm -rf "$AUDIT_DIR"
  mkdir -p "$AUDIT_DIR"
  round_log="$AUDIT_DIR/round-${round}.log"

  {
    echo "=== Council Audit Cycle: round ${round}/${ROUNDS} ==="
    echo "target=$TARGET mode=$MODE execute=$EXECUTE"
    echo ""
    echo "Audit checklist:"
    echo "  - UI + CLI parity for updated features"
    echo "  - Tool wrappers + external integrations"
    echo "  - Findings stored in DB + chainable metadata"
    echo "  - Install scripts updated for dependencies"
    echo ""
    echo "Council approval: pending"
    echo ""

    run_cmd "Doctor" oneinfinity doctor
    run_cmd "Scan" "${scan_cmd[@]}"
    run_cmd "Findings export" oneinfinity findings list --format json
    run_cmd "Report generation" oneinfinity report --target "$TARGET"

    echo ""
    echo "Council validation: pending"
  } | tee "$round_log"

  if [[ $round -lt $ROUNDS && $SLEEP_BETWEEN -gt 0 ]]; then
    sleep "$SLEEP_BETWEEN"
  fi
done
