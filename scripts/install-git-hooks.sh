#!/usr/bin/env bash
# =============================================================================
# install-git-hooks.sh — install the correct post-commit sync hook.
#
# .git/hooks/* is never tracked by git, so the templates live under
# scripts/hooks/ and this installer copies the right one into place on
# whichever machine it runs on.
#
# Usage:
#   bash scripts/install-git-hooks.sh          # auto-detect (ubuntu → ec2, else local)
#   bash scripts/install-git-hooks.sh local
#   bash scripts/install-git-hooks.sh ec2
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ROLE="${1:-}"
if [ -z "$ROLE" ]; then
  if [ "$(whoami)" = "ubuntu" ] && [ -d "/home/ubuntu/oneinfinity" ]; then
    ROLE="ec2"
  else
    ROLE="local"
  fi
fi

case "$ROLE" in
  local) SRC="scripts/hooks/post-commit-local" ;;
  ec2)   SRC="scripts/hooks/post-commit-ec2" ;;
  *) echo "Usage: $0 [local|ec2]"; exit 1 ;;
esac

DEST=".git/hooks/post-commit"
cp "$SRC" "$DEST"
chmod +x "$DEST"
mkdir -p "$HOME/.oneinfinity"

echo "[ OK ] Installed $SRC -> $DEST (role=$ROLE)"
