#!/usr/bin/env bash
# AIops agent installer for Linux (systemd).
#   curl -fsSL "__SERVER_URL__/install/linux.sh" | sudo bash
set -euo pipefail

SERVER='__SERVER_URL__'
TOKEN='__TOKEN__'
INSTALL_DIR=/opt/sentinel-agent
SERVICE=sentinel-agent

if [ "$(id -u)" -ne 0 ]; then echo "[AIops] Please run with sudo." >&2; exit 1; fi
command -v curl >/dev/null || { echo "[AIops] curl is required." >&2; exit 1; }

echo "[AIops] Installing agent to $INSTALL_DIR (server: $SERVER)"
mkdir -p "$INSTALL_DIR"
systemctl stop "$SERVICE" 2>/dev/null || true

if curl -fsSL "$SERVER/api/agents/binary/linux?token=$TOKEN" -o "$INSTALL_DIR/SentinelAgent.download" 2>/dev/null; then
  mv "$INSTALL_DIR/SentinelAgent.download" "$INSTALL_DIR/SentinelAgent"
  chmod 755 "$INSTALL_DIR/SentinelAgent"
  AGENT_DIR="$INSTALL_DIR"
  EXEC_START="$INSTALL_DIR/SentinelAgent"
  MODE=binary
else
  rm -f "$INSTALL_DIR/SentinelAgent.download"
  if ! command -v python3 >/dev/null; then
    echo "[AIops] Installing python3..."
    if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3 python3-venv
    elif command -v dnf >/dev/null; then dnf install -y -q python3
    elif command -v yum >/dev/null; then yum install -y -q python3
    elif command -v pacman >/dev/null; then pacman -Sy --noconfirm python
    else echo "[AIops] Install python3 and re-run." >&2; exit 1; fi
  fi
  if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    python3 -m venv "$INSTALL_DIR/venv" 2>/dev/null || { command -v apt-get >/dev/null && apt-get install -y -qq python3-venv && python3 -m venv "$INSTALL_DIR/venv"; }
  fi
  AGENT_DIR="$INSTALL_DIR/app"
  mkdir -p "$AGENT_DIR"
  TMP_ZIP="$(mktemp)"
  curl -fsSL "$SERVER/api/agents/bundle?token=$TOKEN" -o "$TMP_ZIP"
  python3 -m zipfile -e "$TMP_ZIP" "$AGENT_DIR"
  rm -f "$TMP_ZIP"
  "$INSTALL_DIR/venv/bin/python" -m pip install --quiet --disable-pip-version-check --upgrade psutil requests
  EXEC_START="$INSTALL_DIR/venv/bin/python $AGENT_DIR/monitor_agent.py"
  MODE=python
fi

CONFIG="$AGENT_DIR/agent_config.json"
if [ -f "$CONFIG" ] && { [ -z "$TOKEN" ] || grep -q "$TOKEN" "$CONFIG"; }; then
  # Re-install: keep this device's identity, only point it at the current server address.
  sed -i.bak "s#\"server_url\": *\"[^\"]*\"#\"server_url\": \"$SERVER\"#" "$CONFIG" && rm -f "$CONFIG.bak"
else
  # Open enrollment: no token in the URL, so this device generates its own secret.
  [ -n "$TOKEN" ] || TOKEN="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
  NICKNAME="$(hostname | tr -cd 'A-Za-z0-9._-')"
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

cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=AIops AI troubleshooting agent
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$AGENT_DIR
ExecStart=$EXEC_START
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE"
echo "[AIops] Agent installed ($MODE mode) and running. It will appear in the dashboard within a few seconds."
echo "[AIops] Logs: $AGENT_DIR/agent_log.txt  |  systemctl status $SERVICE"
echo "[AIops] Uninstall: curl -fsSL '$SERVER/install/uninstall-linux.sh' | sudo bash"
