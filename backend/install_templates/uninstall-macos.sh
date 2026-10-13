#!/usr/bin/env bash
# AIops agent uninstaller for macOS:
#   curl -fsSL "__SERVER_URL__/install/uninstall-macos.sh" | sudo bash
set -u
launchctl bootout system /Library/LaunchDaemons/com.sentinel.agent.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.sentinel.agent.plist
rm -rf /usr/local/sentinel-agent
echo "[AIops] Agent removed. Revoke the device in the dashboard Agents tab to invalidate its token."
