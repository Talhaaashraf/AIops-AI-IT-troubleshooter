"""Operating system updates: list what Windows Update, apt/dnf or softwareupdate offers, and install the
updates a person approved.

The server only sends update ids that os_updates reported. The agent searches again and installs only
updates the fresh search still offers, so nothing the server invents can be installed. It never restarts
the computer: when an update needs a restart, the result says so and the person restarts when it suits them.
"""

import json
import os
import re
import shutil
import time

from .common import is_admin, os_name
from .registry import tool
from .software import PACKAGE_NAME, _run, _tail

UPDATE_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
MAX_UPDATE_IDS = 50
SEARCH_TIMEOUT = 540
INSTALL_TIMEOUT = 5000
WU_RESULTS = {0: "not started", 1: "in progress", 2: "installed", 3: "installed with errors", 4: "failed", 5: "aborted"}
WU_ACCESS_DENIED = -2145124284  # 0x80240044: the caller is not an administrator

WINDOWS_SEARCH = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
try {
  $result = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
} catch { [pscustomobject]@{ error = $_.Exception.Message; hresult = $_.Exception.HResult } | ConvertTo-Json -Compress; exit }
$reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
$updates = @(foreach ($u in $result.Updates) { [pscustomobject]@{
  id = $u.Identity.UpdateID; title = $u.Title; kb = ($u.KBArticleIDs -join ','); driver = ($u.Type -eq 2)
  min_mb = [math]::Round($u.MinDownloadSize / 1MB); max_mb = [math]::Round($u.MaxDownloadSize / 1MB)
  severity = $u.MsrcSeverity; categories = @($u.Categories | ForEach-Object { $_.Name }); may_restart = ($u.InstallationBehavior.RebootBehavior -ne 0)
  needs_input = $u.InstallationBehavior.CanRequestUserInput; eula = $u.EulaAccepted; recommended = $u.AutoSelectOnWebSites; downloaded = $u.IsDownloaded } })
[pscustomobject]@{ updates = $updates; reboot_pending = $reboot } | ConvertTo-Json -Compress -Depth 4
"""

# __IDS__ is replaced by quoted GUIDs that matched UPDATE_GUID, never by free text.
WINDOWS_INSTALL = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$wanted = @(__IDS__)
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
  $chosen = New-Object -ComObject Microsoft.Update.UpdateColl
  $skipped = @()
  foreach ($u in $result.Updates) {
    if (-not ($wanted -contains $u.Identity.UpdateID)) { continue }
    if (-not $u.EulaAccepted) { $skipped += [pscustomobject]@{ id = $u.Identity.UpdateID; title = $u.Title; reason = 'its license has to be accepted in Windows Update' }; continue }
    if ($u.InstallationBehavior.CanRequestUserInput) { $skipped += [pscustomobject]@{ id = $u.Identity.UpdateID; title = $u.Title; reason = 'it asks questions while installing: install it from Windows Update' }; continue }
    [void]$chosen.Add($u)
  }
  $offered = @(foreach ($u in $result.Updates) { $u.Identity.UpdateID })
  if ($chosen.Count -eq 0) { [pscustomobject]@{ installed = @(); skipped = $skipped; offered = $offered } | ConvertTo-Json -Compress -Depth 4; exit }
  $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $chosen; [void]$downloader.Download()
  $installer = $session.CreateUpdateInstaller(); $installer.Updates = $chosen
  $outcome = $installer.Install()
  $rows = @(for ($i = 0; $i -lt $chosen.Count; $i++) { [pscustomobject]@{ id = $chosen.Item($i).Identity.UpdateID; title = $chosen.Item($i).Title; code = [int]$outcome.GetUpdateResult($i).ResultCode; hresult = $outcome.GetUpdateResult($i).HResult } })
  [pscustomobject]@{ result = [int]$outcome.ResultCode; restart = $outcome.RebootRequired; installed = $rows; skipped = $skipped; offered = $offered } | ConvertTo-Json -Compress -Depth 4
} catch { [pscustomobject]@{ error = $_.Exception.Message; hresult = $_.Exception.HResult } | ConvertTo-Json -Compress }
"""


def _powershell_json(script, timeout):
    code, out, err = _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout)
    try:
        return json.loads(out.strip()) if out.strip() else {"error": _tail(err, 300) or f"PowerShell exit code {code}"}
    except json.JSONDecodeError:
        return {"error": _tail(err or out, 300)}


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _size_text(update):
    # MaxDownloadSize of a cumulative update counts every full package (tens of GB); the real download is
    # a delta near MinDownloadSize, so show the smaller figure when the two differ a lot, and nothing when
    # only the inflated maximum is known.
    low, high = update.get("min_mb") or 0, update.get("max_mb") or 0
    size = low if low and high > 4 * low else (0 if not low and high > 4096 else high or low)
    text = f"{size / 1024:.1f} GB" if size >= 1024 else f"{size} MB" if size else ""
    if update.get("downloaded"):
        text = f"{text} (downloaded)" if text else "downloaded"
    return text


def _windows_kind(update):
    categories = " ".join(update.get("categories") or []).lower()
    if update.get("driver"):
        return "driver"
    if "security" in categories or update.get("severity"):
        return "security"
    if "definition" in categories:
        return "definitions"
    return "update"


def _windows_updates():
    raw = _powershell_json(WINDOWS_SEARCH, SEARCH_TIMEOUT)
    if raw.get("error"):
        return {"ok": False, "summary": f"Windows Update search failed: {raw['error']}"[:400], "data": None}
    updates = []
    for item in _as_list(raw.get("updates")):
        if not isinstance(item, dict) or not UPDATE_GUID.match(str(item.get("id") or "")):
            continue
        updates.append({
            "id": item["id"], "title": str(item.get("title") or "")[:200], "kb": item.get("kb") or None, "kind": _windows_kind(item),
            "severity": item.get("severity"), "size_text": _size_text(item), "may_restart": bool(item.get("may_restart")),
            "recommended": bool(item.get("recommended")), "downloaded": bool(item.get("downloaded")),
            "installable": bool(item.get("eula")) and not item.get("needs_input"),
            "note": None if item.get("eula") and not item.get("needs_input") else "Install this one from Windows Update on the device",
        })
    return {"source": "Windows Update", "updates": updates, "reboot_pending": bool(raw.get("reboot_pending")), "can_install": is_admin()}


def _apt_updates():
    code, out, err = _run(["apt", "list", "--upgradable"], 120, env={"LC_ALL": "C"})
    if code not in (0,):
        return None
    updates = []
    for line in out.splitlines():
        match = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+\S+(?:\s+\[upgradable from: ([^\]]+)\])?", line)
        if match and PACKAGE_NAME.match(match.group(1)):
            updates.append({"id": match.group(1), "title": f"{match.group(1)} {match.group(4) or ''} → {match.group(3)}".replace("  ", " "),
                            "kind": "security" if "security" in match.group(2) else "update", "may_restart": match.group(1).startswith(("linux-image", "linux-generic")),
                            "recommended": True, "installable": True, "size_text": "", "note": None})
    lists = "/var/lib/apt/lists"
    age = None
    try:
        age = round((time.time() - os.path.getmtime(lists)) / 3600, 1)
    except OSError:
        pass
    note = f"From the local package lists, last refreshed {age} h ago (Check for updates refreshes them)." if age is not None else None
    return {"source": "apt", "updates": updates, "note": note}


def _dnf_updates():
    manager = "dnf" if shutil.which("dnf") else "yum"
    code, out, _err = _run([manager, "check-update", "-q"], 300)
    if code not in (0, 100):
        return None
    updates = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and "." in parts[0] and not line.startswith(" "):
            name = parts[0].rsplit(".", 1)[0]
            if PACKAGE_NAME.match(name):
                updates.append({"id": name, "title": f"{name} → {parts[1]}", "kind": "security" if "security" in parts[2].lower() else "update",
                                "may_restart": name.startswith("kernel"), "recommended": True, "installable": True, "size_text": "", "note": None})
    return {"source": manager, "updates": updates}


def _linux_updates():
    result = (_apt_updates() if shutil.which("apt") else None) or (_dnf_updates() if shutil.which("dnf") or shutil.which("yum") else None)
    if result is None:
        return {"ok": False, "summary": "No supported package manager (apt or dnf) found", "data": None}
    result["reboot_pending"] = os.path.exists("/var/run/reboot-required")
    result["can_install"] = is_admin()
    return result


def _macos_updates():
    code, out, err = _run(["softwareupdate", "-l"], SEARCH_TIMEOUT)
    updates = []
    for match in re.finditer(r"\*\s*Label:\s*(.+)\n\s*Title:\s*([^,]+),\s*Version:\s*([^,]+),\s*Size:\s*([^,]+),(.*)", out):
        details = match.group(5)
        updates.append({"id": match.group(1).strip(), "title": f"{match.group(2).strip()} {match.group(3).strip()}", "kind": "update",
                        "size_text": match.group(4).strip(), "may_restart": "restart" in details.lower(), "recommended": "YES" in details,
                        "installable": False, "note": "Install from System Settings > General > Software Update"})
    if code != 0 and not updates:
        return {"ok": False, "summary": f"softwareupdate failed: {_tail(err, 200)}", "data": None}
    return {"source": "softwareupdate", "updates": updates, "reboot_pending": False, "can_install": False}


@tool("os_updates", "List operating system updates waiting to be installed (Windows Update incl. drivers, apt/dnf, macOS softwareupdate): title, kind (security/driver/update), size and whether a restart is needed. Read-only; the search can take a minute.", timeout=600)
def os_updates():
    system = os_name()
    data = _windows_updates() if system == "Windows" else _macos_updates() if system == "Darwin" else _linux_updates()
    if data.get("ok") is False:
        return data
    updates = data["updates"]
    security = sum(1 for item in updates if item["kind"] == "security")
    drivers = sum(1 for item in updates if item["kind"] == "driver")
    data.update(count=len(updates), security_count=security, driver_count=drivers)
    if not updates:
        summary = f"{data['source']}: the system is up to date"
    else:
        parts = [f"{security} security"] if security else []
        parts += [f"{drivers} driver"] if drivers else []
        summary = f"{data['source']}: {len(updates)} update(s) waiting" + (f" ({', '.join(parts)})" if parts else "")
    if data.get("reboot_pending"):
        summary += "; a restart is pending to finish earlier updates"
    return {"ok": True, "summary": summary, "data": data}


def _wanted_ids(update_ids, pattern):
    """The ids a person ticked, or None. Empty is refused: an install always names its updates."""
    ids = [item.strip() for item in (update_ids or "").split(",") if item.strip()]
    if not ids or len(ids) > MAX_UPDATE_IDS or not all(pattern.fullmatch(item) for item in ids):
        return None
    return list(dict.fromkeys(ids))


def _windows_install(update_ids):
    wanted = _wanted_ids(update_ids, UPDATE_GUID)
    if wanted is None:
        return {"ok": False, "summary": "Invalid update ids: use the ids os_updates reported"}
    raw = _powershell_json(WINDOWS_INSTALL.replace("__IDS__", ",".join(f"'{item}'" for item in wanted)), INSTALL_TIMEOUT)
    if raw.get("error"):
        denied = raw.get("hresult") == WU_ACCESS_DENIED or not is_admin()
        hint = " The agent must run as administrator (SYSTEM) to install updates." if denied else ""
        return {"ok": False, "summary": f"Windows Update could not install: {raw['error']}"[:300] + hint}
    offered = {str(item).lower() for item in _as_list(raw.get("offered"))}
    gone = [item for item in wanted if item.lower() not in offered]
    rows = [{"id": row.get("id"), "title": row.get("title"), "result": WU_RESULTS.get(row.get("code"), str(row.get("code")))} for row in _as_list(raw.get("installed")) if isinstance(row, dict)]
    skipped = [{"id": row.get("id"), "title": row.get("title"), "reason": row.get("reason")} for row in _as_list(raw.get("skipped")) if isinstance(row, dict)]
    installed = [row for row in rows if row["result"] == "installed"]
    restart = bool(raw.get("restart"))
    parts = [f"Installed {len(installed)} of {len(rows)} update(s)"] if rows else ["No update was installed"]
    if skipped:
        parts.append(f"{len(skipped)} need Windows Update on the device")
    if gone:
        parts.append(f"{len(gone)} no longer offered (already installed?)")
    if restart:
        parts.append("restart the computer to finish (AIops never restarts it for you)")
    ok = bool(rows) and len(installed) == len(rows)
    return {"ok": ok or (not rows and not skipped and bool(gone)), "changed": bool(installed), "summary": "; ".join(parts),
            "data": {"installed": rows, "skipped": skipped, "no_longer_offered": gone, "restart_required": restart}}


def _linux_install(update_ids):
    wanted = _wanted_ids(update_ids, PACKAGE_NAME)
    if wanted is None:
        return {"ok": False, "summary": "Invalid package names: use the ids os_updates reported"}
    if not is_admin():
        return {"ok": False, "summary": "Installing updates needs root: run the agent as root"}
    current = _linux_updates()
    offered = {item["id"] for item in current.get("updates") or []}
    chosen = [item for item in wanted if item in offered]
    gone = [item for item in wanted if item not in offered]
    if wanted and not chosen:
        return {"ok": True, "changed": False, "summary": "None of these updates is offered any more (already installed?)", "data": {"no_longer_offered": gone}}
    env = {"DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}
    if current.get("source") == "apt":
        command = ["apt-get", "install", "--only-upgrade", "-y", "-o", "Dpkg::Options::=--force-confold", *chosen] if chosen else ["apt-get", "upgrade", "-y", "-o", "Dpkg::Options::=--force-confold"]
    else:
        command = [current.get("source") or "dnf", "upgrade", "-y", *chosen]
    code, out, err = _run(command, INSTALL_TIMEOUT, env=env)
    restart = os.path.exists("/var/run/reboot-required")
    summary = (f"Updated {len(chosen) or 'all'} package(s)" if code == 0 else f"Update failed (exit code {code}): {_tail(err or out, 200)}")
    if restart and code == 0:
        summary += "; restart the computer to finish (AIops never restarts it for you)"
    return {"ok": code == 0, "changed": code == 0, "summary": summary,
            "data": {"packages": chosen or "all", "no_longer_offered": gone, "restart_required": restart, "output": _tail(out or err)}}


@tool("install_os_updates", "Download and install operating system updates a person approved (Windows Update or apt/dnf). Only updates a fresh search still offers are installed; the computer is never restarted.",
      risk="high", params={"update_ids": {"type": "string", "maxLength": 2000, "description": "Comma-separated ids from os_updates (the updates a person ticked)"}},
      required=("update_ids",), os=frozenset({"Windows", "Linux"}), timeout=5400, ai_visible=False)
def install_os_updates(update_ids):
    return _windows_install(update_ids) if os_name() == "Windows" else _linux_install(update_ids)
