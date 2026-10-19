#!/usr/bin/env bash
# AIops agent uninstaller for Linux:
#   curl -fsSL "__SERVER_URL__/install/uninstall-linux.sh" | sudo bash
set -u
systemctl disable --now sentinel-agent 2>/dev/null || true
rm -f /etc/systemd/system/sentinel-agent.service
systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/sentinel-agent
# Agent data (leftover scans, quarantine). Leftovers moved aside by "Remove completely" are kept.
DATA=/var/lib/aiops-agent
if [ -d "$DATA/quarantine" ] && [ -n "$(ls -A "$DATA/quarantine" 2>/dev/null)" ]; then
  find "$DATA" -mindepth 1 -maxdepth 1 ! -name quarantine -exec rm -rf {} +
  echo "[AIops] Kept the quarantined leftovers in $DATA/quarantine. Copy back what you need, then delete that folder."
else
  rm -rf "$DATA"
fi
echo "[AIops] Agent removed. Revoke the device in the dashboard Agents tab to invalidate its token."
