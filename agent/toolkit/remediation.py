"""Fix actions ("remediation") the AI may *propose* but never run on its own.

These only execute after a person approves them in the dashboard (there is no
automatic path), and the device agent can refuse them with
allow_remediation/max_risk in agent_config.json. Every action is a fixed,
allow-listed operation; arguments are validated and never reach a shell.
"""

import os
import shutil
import time

import psutil

from .common import human_size, is_admin, os_name, powershell, run_command
from .diagnostics import temp_directories, trash_directories, valid_service_name
from .registry import tool

WINDOWS = frozenset({"Windows"})

RESTARTABLE_SERVICES = {
    "Windows": {"Spooler", "wuauserv", "BITS", "Audiosrv", "AudioEndpointBuilder", "WlanSvc", "Dhcp", "W32Time", "WSearch", "bthserv", "LanmanWorkstation", "Netman", "NlaSvc"},
    "Linux": {"NetworkManager", "systemd-resolved", "cups", "bluetooth", "systemd-timesyncd", "wpa_supplicant"},
    "Darwin": {"coreaudiod": "system/com.apple.audio.coreaudiod", "mDNSResponder": "system/com.apple.mDNSResponder", "bluetoothd": "system/com.apple.bluetoothd", "cupsd": "system/org.cups.cupsd"},
}

PROTECTED_PROCESSES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "dwm.exe", "msmpeng.exe", "memory compression", "fontdrvhost.exe", "lsaiso.exe",
    "launchd", "kernel_task", "windowserver", "loginwindow", "systemd", "init", "kthreadd", "sshd", "dbus-daemon", "xorg", "gnome-shell",
    # The WSL/Docker virtual machine, the AI engine, AIops' own server processes (seen from the host it runs on)
    # and its agent: closing them stops AIops (and every container) instead of freeing memory for the user.
    "vmmem", "vmmemwsl", "vmcompute.exe", "com.docker.backend.exe", "docker desktop.exe", "dockerd", "containerd",
    "containerd-shim-runc-v2", "docker-proxy", "ollama", "ollama.exe", "ollama app.exe", "ollama_llama_server", "llama-server",
    "uvicorn", "nginx", "ngrok", "devicehealthagent", "devicehealthagent.exe",
}

STARTUP_BACKUP_KEY = r"Software\Sentinel\DisabledStartup"


def _result(command_result, success_message, failure_prefix):
    ok = command_result["returncode"] == 0
    detail = command_result["stdout"][-600:] or command_result["stderr"][-600:]
    needs_admin = not ok and not is_admin()
    summary = success_message if ok else f"{failure_prefix}: {command_result['stderr'][:200] or detail[:200] or 'command failed'}" + (" (administrator/root rights required)" if needs_admin else "")
    return {"ok": ok, "changed": ok, "summary": summary, "data": detail}


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

@tool("clear_temp_files", "Delete temporary files older than N hours from the system and user temp folders. Files in use are skipped.", risk="low",
      params={"older_than_hours": {"type": "integer", "minimum": 1, "maximum": 720, "description": "Only delete files older than this (default 24)"}}, timeout=600)
def clear_temp_files(older_than_hours=24):
    cutoff = time.time() - older_than_hours * 3600
    freed, deleted, skipped = 0, 0, 0
    for folder in temp_directories():
        for root, dirs, files in os.walk(folder, topdown=False):
            for filename in files:
                path = os.path.join(root, filename)
                try:
                    if os.path.islink(path) or os.path.getmtime(path) > cutoff:
                        continue
                    size = os.path.getsize(path)
                    os.remove(path)
                    freed += size
                    deleted += 1
                except OSError:
                    skipped += 1
            for directory in dirs:
                path = os.path.join(root, directory)
                try:
                    if not os.path.islink(path) and not os.listdir(path):
                        os.rmdir(path)
                except OSError:
                    pass
    return {"ok": True, "changed": deleted > 0, "summary": f"Deleted {deleted} temp file(s), freed {human_size(freed)}; {skipped} in-use file(s) skipped",
            "data": {"freed": human_size(freed), "deleted": deleted, "skipped": skipped}, "rollback_hint": "Temp files are disposable; nothing to restore."}


@tool("empty_recycle_bin", "Permanently empty the Recycle Bin / Trash. Deleted files cannot be recovered afterwards.", risk="medium", timeout=600)
def empty_recycle_bin():
    if os_name() == "Windows":
        result = powershell("Clear-RecycleBin -Force -ErrorAction Stop", timeout=600)
        return _result(result, "Recycle Bin emptied", "Could not empty the Recycle Bin")
    removed = 0
    for folder in trash_directories():
        for name in os.listdir(folder):
            path = os.path.join(folder, name)
            try:
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                removed += 1
            except OSError:
                continue
    return {"ok": True, "changed": removed > 0, "summary": f"Removed {removed} item(s) from the Trash"}


@tool("clear_windows_update_cache", "Stop Windows Update, delete its downloaded-update cache (SoftwareDistribution\\Download), then restart it. Fixes stuck or corrupt updates.", risk="medium", os=WINDOWS, timeout=600)
def clear_windows_update_cache():
    script = (
        "Stop-Service wuauserv,bits -Force -ErrorAction Stop;"
        "Remove-Item \"$env:SystemRoot\\SoftwareDistribution\\Download\\*\" -Recurse -Force -ErrorAction SilentlyContinue;"
        "Start-Service bits,wuauserv -ErrorAction Stop"
    )
    return _result(powershell(script, timeout=600), "Windows Update cache cleared and services restarted", "Could not clear the Windows Update cache")


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

@tool("flush_dns", "Flush the operating system DNS cache. Safe; fixes stale or poisoned DNS entries.", risk="low")
def flush_dns():
    system = os_name()
    if system == "Windows":
        return _result(run_command(["ipconfig", "/flushdns"]), "DNS cache flushed", "DNS flush failed")
    if system == "Darwin":
        run_command(["dscacheutil", "-flushcache"])
        return _result(run_command(["killall", "-HUP", "mDNSResponder"]), "DNS cache flushed", "DNS flush failed")
    result = run_command(["resolvectl", "flush-caches"])
    if result["returncode"] != 0:
        result = run_command(["systemd-resolve", "--flush-caches"])
    return _result(result, "DNS cache flushed", "DNS flush failed (no systemd-resolved cache on this system)")


@tool("renew_ip", "Ask DHCP for a fresh IP address on the active network adapters. Connection drops for a few seconds.", risk="medium", timeout=120)
def renew_ip():
    system = os_name()
    if system == "Windows":
        return _result(run_command(["ipconfig", "/renew"], timeout=110), "IP address renewed", "IP renewal failed")
    if system == "Darwin":
        interface = run_command(["route", "-n", "get", "default"])["stdout"]
        name = next((line.split(":", 1)[1].strip() for line in interface.splitlines() if "interface:" in line), "en0")
        return _result(run_command(["ipconfig", "set", name, "DHCP"]), f"DHCP renewed on {name}", "IP renewal failed")
    devices = [line.split(":")[0] for line in run_command(["nmcli", "-t", "-f", "DEVICE,STATE", "device"])["stdout"].splitlines() if line.endswith(":connected")]
    if not devices:
        return {"ok": False, "summary": "No NetworkManager-managed connected device found"}
    return _result(run_command(["nmcli", "device", "reapply", devices[0]], timeout=60), f"Connection re-applied on {devices[0]}", "IP renewal failed")


@tool("reset_network_stack", "Reset Winsock and the TCP/IP stack to defaults (netsh winsock reset + netsh int ip reset). Requires a reboot; custom network settings are lost.", risk="high", os=WINDOWS, timeout=120)
def reset_network_stack():
    winsock = run_command(["netsh", "winsock", "reset"], timeout=60)
    ip = run_command(["netsh", "int", "ip", "reset"], timeout=60)
    ok = winsock["returncode"] == 0
    return {"ok": ok, "changed": ok, "summary": "Winsock and TCP/IP reset; reboot the device to finish" if ok else f"Network reset failed: {winsock['stderr'][:200] or winsock['stdout'][:200]}",
            "data": {"winsock": winsock["stdout"][-300:], "ip": ip["stdout"][-300:]}, "rollback_hint": "Static IP/DNS/proxy settings may need to be re-entered."}


# ---------------------------------------------------------------------------
# Services and processes
# ---------------------------------------------------------------------------

@tool("restart_service", "Restart one allow-listed OS service (the allowed names depend on the OS).", risk="medium",
      params={"name": {"type": "string", "maxLength": 100, "description": "Service name"}}, required=("name",), timeout=120)
def restart_service(name):
    system = os_name()
    allowed = RESTARTABLE_SERVICES.get(system, {})
    if not valid_service_name(name) or name not in allowed:
        return {"ok": False, "summary": f"{name} is not on the restart allow-list for {system}: {', '.join(sorted(allowed))}"}
    if system == "Windows":
        return _result(powershell(f"Restart-Service -Name '{name}' -Force -ErrorAction Stop", timeout=110), f"Service {name} restarted", f"Could not restart {name}")
    if system == "Linux":
        return _result(run_command(["systemctl", "restart", name], timeout=110), f"Service {name} restarted", f"Could not restart {name}")
    return _result(run_command(["launchctl", "kickstart", "-k", allowed[name]], timeout=110), f"{name} restarted", f"Could not restart {name}")


@tool("kill_process", "End a runaway or frozen process. Requires its PID and exact process name (prevents killing the wrong process). System processes are refused.", risk="medium",
      params={"pid": {"type": "integer", "minimum": 5, "maximum": 4194304}, "expected_name": {"type": "string", "maxLength": 120, "description": "Exact process name, e.g. chrome.exe"}}, required=("pid", "expected_name"))
def kill_process(pid, expected_name):
    if pid in (os.getpid(), os.getppid()):
        return {"ok": False, "summary": "Refusing to stop the AIops agent itself"}
    try:
        process = psutil.Process(pid)
        name = process.name()
    except psutil.NoSuchProcess:
        return {"ok": True, "changed": False, "summary": f"Process {pid} is no longer running"}
    except psutil.AccessDenied:
        return {"ok": False, "summary": f"Access denied reading process {pid}"}
    if name.lower() != expected_name.lower():
        return {"ok": False, "summary": f"PID {pid} is now '{name}', not '{expected_name}'; refusing to stop it"}
    if name.lower() in PROTECTED_PROCESSES:
        return {"ok": False, "summary": f"{name} is a protected system process"}
    try:
        process.terminate()
        try:
            process.wait(timeout=5)
        except psutil.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    except psutil.NoSuchProcess:
        pass
    except (psutil.AccessDenied, psutil.TimeoutExpired) as error:
        return {"ok": False, "summary": f"Could not stop {name} ({pid}): {type(error).__name__}" + ("" if is_admin() else " (administrator/root rights required)")}
    return {"ok": True, "changed": True, "summary": f"Stopped {name} (pid {pid})", "rollback_hint": f"Start {name} again if it was needed."}


@tool("disable_startup_item", "Stop a program from launching at login by moving its Run-key entry to a AIops backup key (reversible with restore_startup_item).", risk="medium", os=WINDOWS,
      params={"name": {"type": "string", "maxLength": 200, "description": "Startup entry name as shown by startup_programs"}}, required=("name",))
def disable_startup_item(name):
    import winreg
    for hive_label, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        try:
            with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as run_key:
                value, value_type = winreg.QueryValueEx(run_key, name)
                with winreg.CreateKey(hive, STARTUP_BACKUP_KEY) as backup:
                    winreg.SetValueEx(backup, name, 0, value_type, value)
                winreg.DeleteValue(run_key, name)
                return {"ok": True, "changed": True, "summary": f"Disabled startup item '{name}' ({hive_label})", "rollback_hint": f"Run restore_startup_item with name '{name}'."}
        except FileNotFoundError:
            continue
        except PermissionError:
            return {"ok": False, "summary": f"Access denied changing {hive_label} startup entries (administrator rights required)"}
    return {"ok": False, "summary": f"No Run-key startup entry named '{name}' (startup-folder shortcuts must be removed manually)"}


@tool("restore_startup_item", "Re-enable a startup item previously disabled by AIops.", risk="low", os=WINDOWS,
      params={"name": {"type": "string", "maxLength": 200}}, required=("name",))
def restore_startup_item(name):
    import winreg
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, STARTUP_BACKUP_KEY, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as backup:
                value, value_type = winreg.QueryValueEx(backup, name)
                with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as run_key:
                    winreg.SetValueEx(run_key, name, 0, value_type, value)
                winreg.DeleteValue(backup, name)
                return {"ok": True, "changed": True, "summary": f"Restored startup item '{name}'"}
        except FileNotFoundError:
            continue
        except PermissionError:
            return {"ok": False, "summary": "Access denied (administrator rights required)"}
    return {"ok": False, "summary": f"No AIops-disabled startup item named '{name}'"}


# ---------------------------------------------------------------------------
# Printing, updates, system repair, time
# ---------------------------------------------------------------------------

@tool("clear_print_queue", "Cancel all stuck print jobs and restart the print spooler.", risk="medium", timeout=120)
def clear_print_queue():
    if os_name() == "Windows":
        script = (
            "Stop-Service Spooler -Force -ErrorAction Stop;"
            "Remove-Item \"$env:SystemRoot\\System32\\spool\\PRINTERS\\*\" -Force -ErrorAction SilentlyContinue;"
            "Start-Service Spooler -ErrorAction Stop"
        )
        return _result(powershell(script, timeout=110), "Print queue cleared and spooler restarted", "Could not clear the print queue")
    return _result(run_command(["cancel", "-a"]), "All print jobs cancelled", "Could not cancel print jobs")


@tool("trigger_update_scan", "Ask the OS to check for updates now (Windows UsoClient scan, apt update, softwareupdate -l).", risk="low", timeout=600)
def trigger_update_scan():
    system = os_name()
    if system == "Windows":
        return _result(run_command(["UsoClient.exe", "StartScan"]), "Windows Update scan started in the background", "Could not start a Windows Update scan")
    if system == "Linux":
        return _result(run_command(["apt-get", "update"], timeout=590), "Package lists refreshed", "Package refresh failed")
    return _result(run_command(["softwareupdate", "-l"], timeout=590), "macOS update check completed", "Update check failed")


@tool("sync_time", "Resynchronise the system clock with internet time servers (wrong time breaks HTTPS, logins and updates).", risk="low", timeout=60)
def sync_time():
    system = os_name()
    if system == "Windows":
        return _result(run_command(["w32tm", "/resync", "/force"], timeout=50), "Clock resynchronised", "Time sync failed (is the W32Time service running?)")
    if system == "Darwin":
        return _result(run_command(["sntp", "-sS", "time.apple.com"], timeout=50), "Clock resynchronised", "Time sync failed")
    return _result(run_command(["timedatectl", "set-ntp", "true"]), "NTP time sync enabled", "Time sync failed")


@tool("repair_system_files", "Run System File Checker (sfc /scannow) to repair corrupted Windows system files. Takes 10-30 minutes.", risk="high", os=WINDOWS, timeout=3600)
def repair_system_files():
    result = run_command(["sfc", "/scannow"], timeout=3500)
    text = (result["stdout"] or "").replace("\x00", "")
    result["stdout"] = text
    return _result(result, "System File Checker finished: " + (text.strip().splitlines()[-1] if text.strip() else "see output"), "System File Checker failed")


@tool("repair_windows_image", "Repair the Windows component store with DISM /RestoreHealth (fixes what sfc cannot). Takes 10-40 minutes and needs internet.", risk="high", os=WINDOWS, timeout=3600)
def repair_windows_image():
    return _result(run_command(["DISM", "/Online", "/Cleanup-Image", "/RestoreHealth"], timeout=3500), "DISM RestoreHealth completed", "DISM repair failed")
