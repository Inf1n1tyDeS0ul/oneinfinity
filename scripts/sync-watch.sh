#!/usr/bin/env bash
# =============================================================================
# sync-watch.sh — watch for EC2 (VPN/SSH) reachability and auto-sync the
# moment it reconnects, in both directions, via GitHub.
#
# Runs as a macOS LaunchAgent (see scripts/install-sync-watch.sh) so it is
# always alive in the background on the laptop. It does NOT poll on a fixed
# schedule while disconnected wasting cycles beyond a cheap TCP probe every
# POLL_INTERVAL seconds; work only happens on the down→up transition.
#
# What "sync" means here (never destructive, never auto-commits WIP):
#   - local:  git fetch origin; fast-forward pull if behind and tree is clean;
#             push if ahead (safety net for a push that failed while offline).
#   - EC2:    same, over ssh, with a stash/pop guard so EC2's own uncommitted
#             work is never clobbered by an incoming fast-forward pull.
#   - restarts the EC2 backend if web/backend/main.py moved (mirrors sync.sh).
#
# Real-time sync on `git commit` is handled separately by the post-commit
# hooks (scripts/hooks/post-commit-local, scripts/hooks/post-commit-ec2).
# This watcher exists to catch up on anything that happened while the two
# machines could not reach each other (EC2 pushed while laptop's VPN was
# down, or the laptop's post-commit hook queued a pending EC2 pull).
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EC2_HOST="172.31.2.127"
EC2_ALIAS="oneinfinity-ec2"
EC2_REPO="/home/ubuntu/oneinfinity"
POLL_INTERVAL=15

STATE_DIR="$HOME/.oneinfinity"
STATE_FILE="$STATE_DIR/vpn_state"
LOGFILE="$STATE_DIR/sync-watch.log"
PENDING_FILE="$STATE_DIR/sync_pending_local"
mkdir -p "$STATE_DIR"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

is_reachable() { nc -z -w 2 "$EC2_HOST" 22 >/dev/null 2>&1; }

catch_up_sync() {
  log "▶ VPN/SSH reconnected — running catch-up sync"
  cd "$REPO_ROOT"

  # ── Local side ──────────────────────────────────────────────────────────
  git fetch origin --quiet 2>>"$LOGFILE"
  if git diff --quiet && git diff --cached --quiet; then
    BEHIND=$(git rev-list HEAD..origin/main --count 2>/dev/null || echo 0)
    AHEAD=$(git rev-list origin/main..HEAD --count 2>/dev/null || echo 0)
    if [ "$BEHIND" -gt 0 ]; then
      if git pull --ff-only origin main >>"$LOGFILE" 2>&1; then
        log "  ✓ local fast-forwarded $BEHIND commit(s) from origin/main"
      else
        log "  ✗ local ff-only pull failed — diverged history, resolve manually"
      fi
    fi
    if [ "$AHEAD" -gt 0 ]; then
      if git push origin main >>"$LOGFILE" 2>&1; then
        log "  ✓ local pushed $AHEAD pending commit(s) to origin/main"
      else
        log "  ✗ local push failed (see log)"
      fi
    fi
    [ "$BEHIND" -eq 0 ] && [ "$AHEAD" -eq 0 ] && log "  = local already up to date"
  else
    log "  ⚠ local working tree dirty — skipping local pull/push (commit first)"
  fi

  # ── EC2 side ────────────────────────────────────────────────────────────
  PRE_SHA=$(ssh -o ConnectTimeout=8 -o BatchMode=yes "$EC2_ALIAS" \
    "cd $EC2_REPO && git rev-parse HEAD" 2>>"$LOGFILE")

  REMOTE_OUT=$(ssh -o ConnectTimeout=8 -o BatchMode=yes "$EC2_ALIAS" "
    set -e
    cd $EC2_REPO
    STASHED=0
    if ! git diff --quiet || ! git diff --cached --quiet; then
      git stash push -m 'auto-stash before sync-watch' --include-untracked 2>/dev/null && STASHED=1
    fi
    git fetch origin --quiet
    BEHIND=\$(git rev-list HEAD..origin/main --count)
    AHEAD=\$(git rev-list origin/main..HEAD --count)
    if [ \"\$BEHIND\" -gt 0 ]; then
      git pull --ff-only origin main
    fi
    if [ \"\$AHEAD\" -gt 0 ]; then
      git push origin main
    fi
    if [ \$STASHED -eq 1 ]; then
      git stash pop 2>/dev/null || true
    fi
    echo \"BEHIND=\$BEHIND AHEAD=\$AHEAD\"
  " 2>>"$LOGFILE")

  if [ -n "$REMOTE_OUT" ]; then
    log "  ✓ EC2 sync OK ($REMOTE_OUT)"
  else
    log "  ✗ EC2 sync failed (see log)"
  fi

  POST_SHA=$(ssh -o ConnectTimeout=8 -o BatchMode=yes "$EC2_ALIAS" \
    "cd $EC2_REPO && git rev-parse HEAD" 2>>"$LOGFILE")

  # ── Restart EC2 backend if web/backend/main.py moved ───────────────────
  if [ -n "$PRE_SHA" ] && [ -n "$POST_SHA" ] && [ "$PRE_SHA" != "$POST_SHA" ]; then
    CHANGED=$(ssh -o ConnectTimeout=8 -o BatchMode=yes "$EC2_ALIAS" \
      "cd $EC2_REPO && git diff --name-only $PRE_SHA $POST_SHA" 2>>"$LOGFILE")
    if echo "$CHANGED" | grep -q '^web/backend/main\.py$'; then
      log "  → web/backend/main.py changed on EC2 — restarting backend"
      ssh -o ConnectTimeout=8 -o BatchMode=yes "$EC2_ALIAS" "
        pkill -f 'python.*main.py' 2>/dev/null; sleep 3
        cd $EC2_REPO
        nohup venv/bin/python -B web/backend/main.py >> logs/backend.log 2>&1 &
        sleep 8 && curl -sf http://localhost:3000/health > /dev/null && echo 'backend: UP'
      " >>"$LOGFILE" 2>&1
      log "  ✓ backend restart triggered"
    fi
  fi

  rm -f "$PENDING_FILE"
  log "▶ catch-up sync done"
}

if [ "${1:-}" = "--once" ]; then
  is_reachable || { log "EC2 unreachable — nothing to do"; exit 1; }
  catch_up_sync
  exit 0
fi

log "sync-watch started (poll every ${POLL_INTERVAL}s, target ${EC2_HOST}:22)"
PREV_STATE="down"
[ -f "$STATE_FILE" ] && PREV_STATE=$(cat "$STATE_FILE")

while true; do
  if is_reachable; then
    CUR_STATE="up"
  else
    CUR_STATE="down"
  fi

  if [ "$CUR_STATE" = "up" ] && [ "$PREV_STATE" = "down" ]; then
    catch_up_sync
  fi

  echo "$CUR_STATE" > "$STATE_FILE"
  PREV_STATE="$CUR_STATE"
  sleep "$POLL_INTERVAL"
done
