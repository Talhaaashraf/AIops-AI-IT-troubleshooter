#!/usr/bin/env bash
# AIops agent installer for macOS (launchd).
#   curl -fsSL "__SERVER_URL__/install/macos.sh" | sudo bash
set -euo pipefail

SERVER='__SERVER_URL__'
TOKEN='__TOKEN__'
INSTALL_DIR=/usr/local/sentinel-agent
LABEL=com.sentinel.agent
PLIST="/Library/LaunchDaemons/$LABEL.plist"

if [ "$(id -u)" -ne 0 ]; then echo "[AIops] Please run with sudo." >&2; exit 1; fi

echo "[AIops] Installing agent to $INSTALL_DIR (server: $SERVER)"
mkdir -p "$INSTALL_DIR"
launchctl bootout system "$PLIST" 2>/dev/null || true

if curl -fsSL -H "ngrok-skip-browser-warning: 1" "$SERVER/api/agents/binary/mac?token=$TOKEN" -o "$INSTALL_DIR/SentinelAgent.download" 2>/dev/null; then
  mv "$INSTALL_DIR/SentinelAgent.download" "$INSTALL_DIR/SentinelAgent"
  chmod 755 "$INSTALL_DIR/SentinelAgent"
  xattr -d com.apple.quarantine "$INSTALL_DIR/SentinelAgent" 2>/dev/null || true
  AGENT_DIR="$INSTALL_DIR"
  PROGRAM_ARGS="<string>$INSTALL_DIR/SentinelAgent</string>"
  MODE=binary
else
  rm -f "$INSTALL_DIR/SentinelAgent.download"
  if ! /usr/bin/python3 -c 'import sys' 2>/dev/null; then
    echo "[AIops] Python 3 is required. Run 'xcode-select --install' or install Python from python.org, then re-run." >&2
    exit 1
  fi
  [ -x "$INSTALL_DIR/venv/bin/python" ] || /usr/bin/python3 -m venv "$INSTALL_DIR/venv"
  AGENT_DIR="$INSTALL_DIR/app"
  mkdir -p "$AGENT_DIR"
  TMP_ZIP="$(mktemp)"
  curl -fsSL -H "ngrok-skip-browser-warning: 1" "$SERVER/api/agents/bundle?token=$TOKEN" -o "$TMP_ZIP"
  /usr/bin/python3 -m zipfile -e "$TMP_ZIP" "$AGENT_DIR"
  rm -f "$TMP_ZIP"
  "$INSTALL_DIR/venv/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade psutil requests
  PROGRAM_ARGS="<string>$INSTALL_DIR/venv/bin/python</string><string>$AGENT_DIR/monitor_agent.py</string>"
  MODE=python
fi

CONFIG="$AGENT_DIR/agent_config.json"
if [ -f "$CONFIG" ] && { [ -z "$TOKEN" ] || grep -q "$TOKEN" "$CONFIG"; }; then
  # Re-install: keep this device's identity, only point it at the current server address.
  sed -i.bak "s#\"server_url\": *\"[^\"]*\"#\"server_url\": \"$SERVER\"#" "$CONFIG" && rm -f "$CONFIG.bak"
else
  # Open enrollment: no token in the URL, so this device generates its own secret.
  [ -n "$TOKEN" ] || TOKEN="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
  NICKNAME="$( (scutil --get ComputerName 2>/dev/null || hostname) | tr -cd 'A-Za-z0-9._ -')"
  cat > "$CONFIG" <<EOF
{
  "server_url": "$SERVER",
  "AGENT_TOKEN": "$TOKEN",
  "nickname": "$NICKNAME",
  "interval_seconds": 10,
  "allow_remediation": true,
  "max_risk": "high"
}
EOF
  chmod 600 "$CONFIG"
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>$PROGRAM_ARGS</array>
  <key>WorkingDirectory</key><string>$AGENT_DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF
chmod 644 "$PLIST"
launchctl bootstrap system "$PLIST"
echo "[AIops] Agent installed ($MODE mode) and running. It will appear in the dashboard within a few seconds."
echo "[AIops] Logs: $AGENT_DIR/agent_log.txt"
echo "[AIops] Uninstall: curl -fsSL -H 'ngrok-skip-browser-warning: 1' '$SERVER/install/uninstall-macos.sh' | sudo bash"
