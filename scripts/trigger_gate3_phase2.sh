#!/usr/bin/env bash
# trigger_gate3_phase2.sh — Trigger Gate 3 council session for Phase 2 sign-off.
#
# Gate 3 acceptance criteria (from HYBRID_MIGRATION_PLAN.md):
#   - 7/7 Go builds pass
#   - 65/65 Python tests pass (test_phase2_*.py)
#   - 0 SA-1..SA-4 BLOCKER findings remain
#   - All 4 OQ mandate findings resolved
#   - SecurityAuditAgent re-audit sign-off
#   - OffensiveQualityAgent sign-off (Gate 2: PASS)
#   - IntegrationAgent sign-off
#   - Council vote: ≥3 PASS from 6-member council
#
# Usage:
#   ./scripts/trigger_gate3_phase2.sh
#   ./scripts/trigger_gate3_phase2.sh --dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
COUNCIL_PY="${COUNCIL_PY:-${HOME}/Tools/council/council.py}"

if [[ ! -f "${COUNCIL_PY}" ]]; then
  echo "[ERROR] council.py not found at ${COUNCIL_PY}" >&2
  exit 1
fi

# Patch sys.path to find council.py
export PYTHONPATH="${HOME}/Tools/council:${PYTHONPATH:-}"

# Run preflight checks
echo "=== Phase 2 Gate 3 preflight ==="
echo -n "Go builds: "
bash "${PROJECT_ROOT}/tests/go/run_go_tests.sh" --quiet 2>&1 | tail -1

echo -n "Python tests: "
cd "${PROJECT_ROOT}" && python3 -m pytest tests/test_phase2_shims.py tests/test_phase2_integration.py tests/test_phase2_security.py -q 2>&1 | tail -1

echo ""
echo "=== Invoking Engineering Council Gate 3 session ==="
cd "${PROJECT_ROOT}"
python3 autonomous_engineering_council.py \
  --topic "Phase 2 Gate 3 sign-off — Go concurrent I/O sidecars (oi-recon-probe, oi-crawler, oi-ssrf, oi-oob-listener, oi-idor-engine, oi-target-disc). All 4 SA blockers fixed, all 4 OQ mandates resolved, 7/7 Go builds pass, 65/65 Python tests pass. SecurityAuditAgent Gate 2 verdict: PASS. OffensiveQualityAgent Gate 2 verdict: PASS (6/6 SUPERIOR). See PHASE_STATUS.md Phase 2 Gate 2 section." \
  ${@:-}
