#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${HOME}/.local/lib/sentinel-monitor-agent"
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$SCRIPT_DIR/monitor_agent" ]]; then cp "$SCRIPT_DIR/monitor_agent" "$INSTALL_DIR/monitor_agent"; chmod +x "$INSTALL_DIR/monitor_agent"; else cp "$SCRIPT_DIR/monitor_agent.py" "$INSTALL_DIR/monitor_agent.py"; fi
if [[ ! -f "$INSTALL_DIR/agent_config.json" ]]; then read -r -p "Central server URL: " SERVER_URL; read -r -p "Agent token: " TOKEN; printf '{"server_url":"%s","AGENT_TOKEN":"%s","nickname":"%s","interval_seconds":10}\n' "$SERVER_URL" "$TOKEN" "$(hostname)" > "$INSTALL_DIR/agent_config.json"; fi
mkdir -p "$HOME/.config/systemd/user"
cat > "$HOME/.config/systemd/user/sentinel-monitor-agent.service" <<EOF
[Unit]
Description=AIops read-only monitor agent
[Service]
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/monitor_agent
Restart=always
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload; systemctl --user enable --now sentinel-monitor-agent.service || true
echo "AIops agent installed in $INSTALL_DIR"
