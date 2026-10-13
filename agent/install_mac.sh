#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="$HOME/Library/Application Support/SentinelMonitorAgent"
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$SCRIPT_DIR/monitor_agent" ]]; then cp "$SCRIPT_DIR/monitor_agent" "$INSTALL_DIR/monitor_agent"; chmod +x "$INSTALL_DIR/monitor_agent"; else cp "$SCRIPT_DIR/monitor_agent.py" "$INSTALL_DIR/monitor_agent.py"; fi
if [[ ! -f "$INSTALL_DIR/agent_config.json" ]]; then read -r -p "Central server URL: " SERVER_URL; read -r -p "Agent token: " TOKEN; printf '{"server_url":"%s","AGENT_TOKEN":"%s","nickname":"%s","interval_seconds":10}\n' "$SERVER_URL" "$TOKEN" "$(scutil --get ComputerName 2>/dev/null || hostname)" > "$INSTALL_DIR/agent_config.json"; fi
PLIST="$HOME/Library/LaunchAgents/com.sentinel.monitor-agent.plist"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.sentinel.monitor-agent</string><key>ProgramArguments</key><array><string>$INSTALL_DIR/monitor_agent</string></array><key>WorkingDirectory</key><string>$INSTALL_DIR</string><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>
EOF
launchctl unload "$PLIST" 2>/dev/null || true; launchctl load "$PLIST"
echo "AIops agent installed in $INSTALL_DIR"
