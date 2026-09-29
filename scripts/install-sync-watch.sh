#!/usr/bin/env bash
# =============================================================================
# install-sync-watch.sh — install scripts/sync-watch.sh as a macOS LaunchAgent
# so it starts at login and keeps running, triggering a bidirectional sync
# the instant EC2 becomes reachable (VPN connects).
#
# Usage:
#   bash scripts/install-sync-watch.sh          # install + load
#   bash scripts/install-sync-watch.sh uninstall
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="com.oneinfinity.syncwatch"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
LOGDIR="$HOME/.oneinfinity"
mkdir -p "$LOGDIR"

if [ "${1:-}" = "uninstall" ]; then
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  echo "[ OK ] sync-watch LaunchAgent uninstalled"
  exit 0
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${REPO_ROOT}/scripts/sync-watch.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOGDIR}/sync-watch.stdout.log</string>
  <key>StandardErrorPath</key>
  <string>${LOGDIR}/sync-watch.stderr.log</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load "$PLIST"

echo "[ OK ] sync-watch installed and running as a LaunchAgent"
echo "       Plist:  $PLIST"
echo "       Log:    $LOGDIR/sync-watch.log"
echo "       Status: launchctl list | grep ${LABEL}"
echo "       Stop:   bash scripts/install-sync-watch.sh uninstall"
