#!/usr/bin/env bash
# AIops agent uninstaller for Linux:
#   curl -fsSL "__SERVER_URL__/install/uninstall-linux.sh" | sudo bash
set -u
systemctl disable --now sentinel-agent 2>/dev/null || true
rm -f /etc/systemd/system/sentinel-agent.service
systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/sentinel-agent
echo "[AIops] Agent removed. Revoke the device in the dashboard Agents tab to invalidate its token."
