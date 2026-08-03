#!/usr/bin/env bash
# =============================================================================
# sync.sh — one-command three-way sync: Local / GitHub / EC2
#
# Usage:
#   bash scripts/sync.sh "feat(scan): add new detection module"
#   bash scripts/sync.sh   (uses auto-generated commit message)
#
# What it does:
#   1. Runs all 4 quality gates (must pass)
#   2. Commits staged changes with the provided message
#   3. Rebases on origin/main (picks up remote commits)
#   4. Pushes to GitHub
#   5. Pulls on EC2 (if reachable)
#   6. Restarts backend on EC2 if web/backend/main.py changed
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

EC2_HOST="172.31.2.127"
EC2_USER="ubuntu"
EC2_KEY="$HOME/.ssh/oneinfinity_sync"
EC2_REPO="/home/ubuntu/oneinfinity"

red()    { printf '\033[0;31m[FAIL]\033[0m %s\n' "$*"; }
green()  { printf '\033[0;32m[ OK ]\033[0m %s\n' "$*"; }
yellow() { printf '\033[0;33m[INFO]\033[0m %s\n' "$*"; }
info()   { printf '       %s\n' "$*"; }

COMMIT_MSG="${1:-}"

echo ""
echo "=============================================="
echo " oneinfinity sync — Local → GitHub → EC2"
echo "=============================================="
echo ""

# ---------------------------------------------------------------------------
# Pre-flight: check we have something to commit or push
# ---------------------------------------------------------------------------
STAGED=$(git diff --cached --name-only)
UNSTAGED=$(git diff --name-only)
UNTRACKED=$(git ls-files --others --exclude-standard | grep -v __pycache__ | head -5)
AHEAD=$(git log --oneline origin/main..HEAD 2>/dev/null | wc -l | tr -d ' ')

if [ -z "$STAGED" ] && [ -z "$UNTRACKED" ] && [ "$AHEAD" -eq 0 ]; then
  yellow "Nothing to sync — working tree is clean and up-to-date with origin"
  exit 0
fi

# ---------------------------------------------------------------------------
# Step 1: Quality gates (must pass before commit)
# ---------------------------------------------------------------------------
echo "[1/6] Running quality gates..."
if ! bash scripts/check_process_hygiene.sh > /tmp/hygiene_out.txt 2>&1; then
  red "Gate 4 (process hygiene) FAILED — fix before syncing"
  cat /tmp/hygiene_out.txt
  exit 1
fi
green "All quality gates passed"

# ---------------------------------------------------------------------------
# Step 2: Commit staged changes (if any)
# ---------------------------------------------------------------------------
echo ""
echo "[2/6] Committing staged changes..."

if [ -n "$STAGED" ] || [ -n "$UNTRACKED" ]; then
  # Auto-stage all tracked modifications if nothing is explicitly staged
  if [ -z "$STAGED" ]; then
    git add -u
    STAGED=$(git diff --cached --name-only)
  fi

  if [ -z "$STAGED" ]; then
    yellow "No staged changes to commit"
  else
    # Generate auto commit message if none provided
    if [ -z "$COMMIT_MSG" ]; then
      FILE_COUNT=$(echo "$STAGED" | wc -l | tr -d ' ')
      FIRST_FILE=$(echo "$STAGED" | head -1)
      # Infer scope from first changed file path
      if [[ "$FIRST_FILE" == src/oneinfinity/scan/* ]];        then SCOPE="scan"
      elif [[ "$FIRST_FILE" == src/oneinfinity/agents/* ]];    then SCOPE="agent"
      elif [[ "$FIRST_FILE" == src/oneinfinity/ai* ]];         then SCOPE="ai"
      elif [[ "$FIRST_FILE" == src/oneinfinity/mobile/* ]];    then SCOPE="mobile"
      elif [[ "$FIRST_FILE" == web/backend/* ]];               then SCOPE="api"
      elif [[ "$FIRST_FILE" == web/frontend/* ]];              then SCOPE="frontend"
      elif [[ "$FIRST_FILE" == scripts/* ]];                   then SCOPE="infra"
      elif [[ "$FIRST_FILE" == AGENTS.md* ]];                  then SCOPE="docs"
      else                                                          SCOPE="core"
      fi
      COMMIT_MSG="chore($SCOPE): sync $FILE_COUNT changed file(s) from $(hostname -s)"
    fi

    git commit -m "$COMMIT_MSG"
    green "Committed: $COMMIT_MSG"
  fi
else
  yellow "Working tree is clean — nothing to commit"
fi

# ---------------------------------------------------------------------------
# Step 3: Rebase on origin/main (pick up any remote commits)
# ---------------------------------------------------------------------------
echo ""
echo "[3/6] Rebasing on origin/main..."
git fetch origin --quiet

BEHIND=$(git log --oneline HEAD..origin/main 2>/dev/null | wc -l | tr -d ' ')
if [ "$BEHIND" -gt 0 ]; then
  yellow "$BEHIND remote commit(s) ahead — rebasing"
  git rebase origin/main
  green "Rebase complete"
else
  green "Already up-to-date with origin/main"
fi

# ---------------------------------------------------------------------------
# Step 4: Push to GitHub
# ---------------------------------------------------------------------------
echo ""
echo "[4/6] Pushing to GitHub..."
git push origin main
green "Pushed to GitHub ($(git rev-parse --short HEAD))"

# ---------------------------------------------------------------------------
# Step 5: Pull on EC2
# ---------------------------------------------------------------------------
echo ""
echo "[5/6] Pulling on EC2..."

EC2_REACHABLE=0
if nc -z -w 3 "$EC2_HOST" 22 > /dev/null 2>&1; then
  EC2_REACHABLE=1
fi

if [ "$EC2_REACHABLE" -eq 1 ]; then
  ssh -i "$EC2_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$EC2_USER@$EC2_HOST" \
    "cd $EC2_REPO && git pull origin main --rebase" 2>&1 \
    | grep -v 'system information\|Ubuntu\|support\|ESM\|updates\|apt list\|System load\|Memory\|Swap\|IPv4\|Temperature\|Processes\|Users' \
    | grep -v '^$' \
    | head -10
  green "EC2 pulled successfully"
else
  yellow "EC2 unreachable (VPN off?) — pull manually when connected:"
  info "  ssh oneinfinity-ec2 \"cd /home/ubuntu/oneinfinity && git pull origin main --rebase\""
fi

# ---------------------------------------------------------------------------
# Step 6: Restart backend on EC2 if main.py changed
# ---------------------------------------------------------------------------
echo ""
echo "[6/6] Checking if backend restart needed..."

CHANGED_FILES=$(git diff --name-only HEAD~1 HEAD 2>/dev/null || true)
BACKEND_CHANGED=$(echo "$CHANGED_FILES" | grep -c 'web/backend/main\.py' || true)

if [ "$BACKEND_CHANGED" -gt 0 ] && [ "$EC2_REACHABLE" -eq 1 ]; then
  yellow "web/backend/main.py changed — restarting backend on EC2"
  ssh -i "$EC2_KEY" -o StrictHostKeyChecking=no "$EC2_USER@$EC2_HOST" \
    "pkill -f 'python.*main.py' 2>/dev/null; sleep 3;
     cd /home/ubuntu/oneinfinity;
     nohup venv/bin/python -B web/backend/main.py >> logs/backend.log 2>&1 &
     sleep 8 && curl -sf http://localhost:3000/health > /dev/null && echo 'backend: UP'" 2>&1 \
    | grep -E 'UP|FAIL|Error|error' | head -5
  green "Backend restarted"
elif [ "$BACKEND_CHANGED" -gt 0 ] && [ "$EC2_REACHABLE" -eq 0 ]; then
  yellow "web/backend/main.py changed — restart backend manually when EC2 is reachable:"
  info "  ssh oneinfinity-ec2"
  info "  pkill -f 'python.*main.py'"
  info "  cd /home/ubuntu/oneinfinity"
  info "  nohup venv/bin/python -B web/backend/main.py >> logs/backend.log 2>&1 &"
else
  green "Backend unchanged — no restart needed"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
green "SYNC COMPLETE"
info "Commit:  $(git rev-parse --short HEAD)"
info "Message: $(git log -1 --format='%s')"
info "Local:   $(git rev-parse --short HEAD)"
info "GitHub:  $(git rev-parse --short origin/main)"
if [ "$EC2_REACHABLE" -eq 1 ]; then
  EC2_SHA=$(ssh -i "$EC2_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "$EC2_USER@$EC2_HOST" \
    "cd $EC2_REPO && git rev-parse --short HEAD" 2>/dev/null || echo "unknown")
  info "EC2:     $EC2_SHA"
fi
echo "=============================================="
echo ""
