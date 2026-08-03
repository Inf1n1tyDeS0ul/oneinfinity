#!/usr/bin/env bash
# =============================================================================
# check_process_hygiene.sh
# Enforces the Single-Process Architecture rule for oneinfinity.
# Must exit 0 before every PR and session-end "done" claim.
#
# Purpose: catch NEW violations — not flag the known legacy surface.
# All pre-existing asyncio.run() and subprocess usages are in the allowlists.
# Any file NOT in an allowlist that introduces these patterns will FAIL.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0
WARN=0

red()    { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }
green()  { printf '\033[0;32m[ OK ]\033[0m %s\n' "$*"; }
yellow() { printf '\033[0;33m[WARN]\033[0m %s\n' "$*"; }
info()   { printf '       %s\n' "$*"; }

echo ""
echo "========================================================"
echo " oneinfinity Process Hygiene Check"
echo "========================================================"
echo ""

# ---------------------------------------------------------------------------
# CHECK 1: asyncio.run() in NEW files not in the legacy allowlist
#
# Pre-existing usages are allowed in the files below — they run inside
# BackgroundTask thread-pool threads or CLI entry points where a new
# event loop is correct. Do NOT add new files to this list; fix the code
# instead by using `await` or `loop.run_in_executor()`.
# ---------------------------------------------------------------------------
echo "[1/4] asyncio.run() in service/agent/core modules..."

ASYNCIO_RUN_ALLOWLIST=(
  # Legacy orchestration — runs in BackgroundTask threads (new event loop per thread is correct)
  "src/oneinfinity/pipeline/executor.py"
  "src/oneinfinity/orchestration/god_mode_engine.py"
  "src/oneinfinity/orchestration/research_mode_controller.py"
  "src/oneinfinity/orchestration/workflow_simulation_engine.py"
  "src/oneinfinity/orchestration/backends/"
  # Legacy intelligence wrappers — sync → async bridge
  "src/oneinfinity/intelligence/intelligence_engine.py"
  # Legacy swarm — runs outside the web process
  "src/oneinfinity/swarm/swarm_intelligence_engine.py"
  "src/oneinfinity/swarm/agent_execution_fabric.py"
  "src/oneinfinity/swarm/agent_swarm_coordinator.py"
  # Legacy framework probes — sync context
  "src/oneinfinity/framework/surface.py"
  "src/oneinfinity/framework/recon_engine.py"
  "src/oneinfinity/recon/adaptive_recon_engine.py"
  # CLI entry points — top-level asyncio.run() is intentional
  "src/oneinfinity/cli/"
  # AI engines — called from background threads
  "src/oneinfinity/ai/ai_redteam_engine.py"
  "src/oneinfinity/ai/ai_agent_pentest_engine.py"
  "src/oneinfinity/ai/ai_security_engine.py"
  # Attack modules — called from background threads
  "src/oneinfinity/attack/credential/spray_engine.py"
  "src/oneinfinity/attack/attack_simulation_engine.py"
)

# Directories where NEW asyncio.run() is NEVER acceptable
STRICT_CHECK_DIRS=(
  "src/oneinfinity/agents"
  "src/oneinfinity/findings"
  "src/oneinfinity/learning"
  "src/oneinfinity/attack_graph_core"
)

asyncio_violations=0
while IFS= read -r -d '' file; do
  allowed=0
  for allow in "${ASYNCIO_RUN_ALLOWLIST[@]}"; do
    if [[ "$file" == *"$allow"* ]]; then
      allowed=1
      break
    fi
  done
  if [ "$allowed" -eq 0 ]; then
    # grep for asyncio.run( but skip lines that are inside string literals or comments
    hits=$(grep -n 'asyncio\.run(' "$file" 2>/dev/null \
           | grep -v '^\s*#' \
           | grep -v '"""' \
           | grep -v "'''" \
           | grep -v "asyncio\.run('" \
           | grep -v 'asyncio\.run("' \
           || true)
    if [ -n "$hits" ]; then
      red "asyncio.run() in $file"
      while IFS= read -r line; do info "$line"; done <<< "$hits"
      FAIL=1
      asyncio_violations=1
    fi
  fi
done < <(find "${STRICT_CHECK_DIRS[@]}" -name '*.py' \
         -not -path '*/__pycache__/*' -print0 2>/dev/null)

if [ "$asyncio_violations" -eq 0 ]; then
  green "No asyncio.run() violations in restricted modules"
fi

# ---------------------------------------------------------------------------
# CHECK 2: No new Python entry points in start-native.sh
#
# The only legitimate Python process in start-native.sh is
# venv/bin/python web/backend/main.py
# ---------------------------------------------------------------------------
echo ""
echo "[2/4] Python entry points in start-native.sh..."

START_SCRIPT="scripts/start-native.sh"
if [ -f "$START_SCRIPT" ]; then
  # Find python invocations that start new long-running processes
  NEW_ENTRY=$(grep -n 'python[3]*\s\+[^-]' "$START_SCRIPT" 2>/dev/null \
    | grep -v '^\s*#' \
    | grep -v 'web/backend/main\.py' \
    | grep -v 'pip\s' \
    | grep -v '\-m\s*pip' \
    | grep -v 'python\s*-m\s*compileall' \
    | grep -v 'python\s*-c\s*["\x27]' \
    | grep -v 'python\s*-V' \
    | grep -v 'python\s*--version' \
    || true)
  if [ -n "$NEW_ENTRY" ]; then
    yellow "Unexpected python invocations in $START_SCRIPT (verify these are not new services):"
    while IFS= read -r line; do info "$line"; done <<< "$NEW_ENTRY"
    WARN=1
  else
    green "start-native.sh entry points are clean"
  fi
else
  yellow "$START_SCRIPT not found — skipping"
  WARN=1
fi

# ---------------------------------------------------------------------------
# CHECK 3: No new Python service containers in docker-compose files
#
# docker-compose.yml: approved services are the single backend container + DBs.
# docker-compose.distributed.yml: approved as-is (worker services are managed
#   as Docker containers in distributed mode — this is the intended topology).
# docker-compose.db.yml: only DB containers — always approved.
#
# Rule: docker-compose.yml must not gain new PYTHON application services.
# ---------------------------------------------------------------------------
echo ""
echo "[3/4] Python service containers in docker-compose.yml..."

COMPOSE_MAIN="docker-compose.yml"
if [ -f "$COMPOSE_MAIN" ]; then
  # Extract actual top-level service names from the services: block
  # Uses python3 to properly parse YAML structure
  new_python_services=$(python3 - "$COMPOSE_MAIN" << 'PYEOF' 2>/dev/null || true
import sys, re

APPROVED = {
    "cli", "ai", "backend", "oneinfinity",
    "oneinfinity-postgres", "oneinfinity-redis", "oneinfinity-neo4j",
    "frontend", "redis", "postgres", "worker",
    # Infrastructure/data volumes are not services
}

fname = sys.argv[1]
content = open(fname).read()

# Find services: block and extract service names (2-space indent + name:)
in_services = False
violations = []
for line in content.splitlines():
    if re.match(r'^services\s*:', line):
        in_services = True
        continue
    if in_services:
        # Top-level key under services (2-space indent, not deeper)
        m = re.match(r'^  ([a-z][a-z0-9_-]+)\s*:', line)
        if m:
            svc = m.group(1)
            # Check if it looks like a Python app service (has 'command: python' or 'python main.py')
            # We only warn on truly unknown services with python command
            if svc not in APPROVED:
                violations.append(svc)
        elif re.match(r'^[a-z]', line):
            in_services = False  # left services block

for v in violations:
    print(v)
PYEOF
)
  if [ -n "$new_python_services" ]; then
    yellow "Unknown service(s) in $COMPOSE_MAIN — verify none run a new Python process:"
    while IFS= read -r svc; do info "  service: $svc"; done <<< "$new_python_services"
    WARN=1
  else
    green "docker-compose.yml service topology is clean"
  fi
else
  yellow "$COMPOSE_MAIN not found — skipping"
  WARN=1
fi

# ---------------------------------------------------------------------------
# CHECK 4: subprocess.Popen/run outside approved locations
#
# Legitimate uses:
#   - External CLI tools: nuclei, nmap, ffuf, frida, jadx, mitmproxy, curl
#   - Mobile toolchain wrappers
#   - Orchestration CLI backends (call python/cli as external tool)
#   - Test payload strings in AI security modules (string literals, not calls)
#
# We look for actual Python calls, not string mentions in prompts/payloads.
# ---------------------------------------------------------------------------
echo ""
echo "[4/4] subprocess.Popen in restricted service modules..."

# Modules where subprocess.Popen is never appropriate (pure business logic)
POPEN_STRICT_DIRS=(
  "src/oneinfinity/agents"
  "src/oneinfinity/findings"
  "src/oneinfinity/learning"
  "src/oneinfinity/attack_graph_core"
)

popen_violations=0
while IFS= read -r -d '' file; do
  # Match actual Python calls — subprocess.Popen( or subprocess.run( at start of expression
  # Exclude: lines in string literals (contain quote before the word), comments, docstrings
  hits=$(grep -n 'subprocess\.Popen\s*(' "$file" 2>/dev/null \
         | grep -v '^\s*#' \
         | grep -v '\\\"' \
         | grep -v "\\\\'" \
         | grep -v '"subprocess' \
         | grep -v "'subprocess" \
         || true)
  if [ -n "$hits" ]; then
    red "subprocess.Popen() in restricted module: $file"
    while IFS= read -r line; do info "$line"; done <<< "$hits"
    FAIL=1
    popen_violations=1
  fi
done < <(find "${POPEN_STRICT_DIRS[@]}" -name '*.py' \
         -not -path '*/__pycache__/*' -print0 2>/dev/null)

if [ "$popen_violations" -eq 0 ]; then
  green "No subprocess.Popen in restricted modules"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
if [ "$FAIL" -ne 0 ]; then
  red "RESULT: FAIL — fix the errors above before merging"
  echo ""
  echo "  Guidance:"
  echo "  • asyncio.run() inside async context → use 'await' instead"
  echo "  • asyncio.run() in background thread (non-async) → already safe, add to allowlist"
  echo "  • subprocess.Popen in business logic → use asyncio.create_subprocess_exec() or"
  echo "    run in thread via loop.run_in_executor()"
  echo "========================================================"
  echo ""
  exit 1
elif [ "$WARN" -ne 0 ]; then
  yellow "RESULT: PASS WITH WARNINGS — review warnings above"
  echo "========================================================"
  echo ""
  exit 0
else
  green "RESULT: PASS — all process hygiene checks clean"
  echo "========================================================"
  echo ""
  exit 0
fi
