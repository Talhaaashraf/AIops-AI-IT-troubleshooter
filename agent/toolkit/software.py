"""Installed software: inventory with available updates, plus uninstall and update actions.

The server only ever sends an inventory id (or a package id). The agent looks the program
up again on this device and runs that program's own registered silent uninstaller or the
package manager, so no command line from the server is ever executed. Programs without a
silent uninstaller are refused: as SYSTEM, a GUI uninstaller would open where nobody can
click it and hang.
"""

import glob
import json
import os
import re
import shutil
import subprocess
import time

from .common import is_admin, os_name
from .registry import tool

LONG_TIMEOUT = 1800
UNINSTALL_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,199}$")
WINGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$")
MSI_PRODUCT = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
INNO_UNINSTALLER = re.compile(r"unins\d{3}\.exe", re.IGNORECASE)
SKIPPED_RELEASE_TYPES = {"update", "hotfix", "security update", "service pack"}
# Never remove the agent itself, or packages whose removal takes the OS or the agent down with it.
PROTECTED_NAMES = ("aiops", "sentinel", "devicehealthagent")
# Docker and containerd too: on the server AIops runs in containers, so removing them takes AIops down.
PROTECTED_PACKAGES = re.compile(r"^(python3(\.\d+)?|python3-minimal|libc6|libc-bin|systemd|systemd-sysv|apt|dpkg|rpm|dnf|yum|bash|coreutils|sudo|openssh-server|linux-image.*|kernel.*|glibc|util-linux"
                                r"|docker-ce|docker-ce-cli|docker\.io|docker-compose-plugin|docker-buildx-plugin|containerd(\.io)?|runc)$")
# Removing these breaks winget/the Store itself (winget would report them as uninstallable).
PROTECTED_WINGET_IDS = re.compile(r"^Microsoft\.(AppInstaller|DesktopAppInstaller|WindowsStore|VCLibs.*|UI\.Xaml.*|WindowsAppRuntime.*)$", re.IGNORECASE)
UNINSTALL_WAIT_SECONDS = 180  # Inno Setup uninstallers hand off to a temp copy and exit at once


def _run(command, timeout, env=None):
    """Run a command (argument list, or a registered uninstall command line on Windows) as UTF-8 text."""
    kwargs = {"capture_output": True, "timeout": timeout}
    if os_name() == "Windows":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if env:
        kwargs["env"] = {**os.environ, **env}
    try:
        result = subprocess.run(command, **kwargs)
    except FileNotFoundError:
        return 127, "", "program not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except OSError as error:
        return 1, "", str(error)
    return result.returncode, result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace")


def _tail(text, limit=600):
    text = (text or "").strip()
    return text[-limit:]


def _protected(name):
    lowered = (name or "").lower()
    return any(word in lowered for word in PROTECTED_NAMES)


# ---------------------------------------------------------------------------
# Windows: registry inventory + winget updates
# ---------------------------------------------------------------------------

def _windows_roots():
    import winreg

    roots = [
        ("HKLM64", winreg.HKEY_LOCAL_MACHINE, UNINSTALL_PATH, winreg.KEY_WOW64_64KEY),
        ("HKLM32", winreg.HKEY_LOCAL_MACHINE, UNINSTALL_PATH, winreg.KEY_WOW64_32KEY),
        ("HKCU", winreg.HKEY_CURRENT_USER, UNINSTALL_PATH, 0),
    ]
    # The agent runs as SYSTEM, so per-user installs live in each signed-in user's hive.
    index = 0
    while True:
        try:
            sid = winreg.EnumKey(winreg.HKEY_USERS, index)
        except OSError:
            break
        index += 1
        if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
            roots.append((f"HKU:{sid}", winreg.HKEY_USERS, f"{sid}\\{UNINSTALL_PATH}", 0))
    return roots


def _registry_values(key):
    import winreg

    values, index = {}, 0
    while True:
        try:
            name, value, _kind = winreg.EnumValue(key, index)
        except OSError:
            return values
        values[name] = value
        index += 1


def _windows_entry_from_values(root_tag, subkey, values):
    name = str(values.get("DisplayName") or "").strip()
    if not name or values.get("SystemComponent") == 1 or values.get("ParentKeyName"):
        return None
    if str(values.get("ReleaseType") or "").lower() in SKIPPED_RELEASE_TYPES:
        return None
    uninstall = str(values.get("UninstallString") or "").strip()
    quiet = str(values.get("QuietUninstallString") or "").strip()
    msi = values.get("WindowsInstaller") == 1 or (bool(MSI_PRODUCT.match(subkey)) and "msiexec" in uninstall.lower())
    if not (uninstall or quiet or msi):
        return None
    date = str(values.get("InstallDate") or "")
    size_kb = values.get("EstimatedSize")
    method = "msi" if msi and MSI_PRODUCT.match(subkey) else "quiet" if quiet else "inno" if INNO_UNINSTALLER.search(uninstall) else None
    return {
        "id": f"{root_tag}|{subkey}",
        "name": name,
        "version": str(values.get("DisplayVersion") or "").strip(),
        "publisher": str(values.get("Publisher") or "").strip(),
        "install_date": f"{date[:4]}-{date[4:6]}-{date[6:8]}" if re.fullmatch(r"\d{8}", date) else None,
        "size_mb": round(size_kb / 1024, 1) if isinstance(size_kb, int) and size_kb > 0 else None,
        "scope": "user" if root_tag.startswith(("HKU", "HKCU")) else "machine",
        "uninstall_method": method,
        "can_uninstall": method is not None and not _protected(name),
        "_uninstall": uninstall,
        "_quiet": quiet,
        "_install_location": str(values.get("InstallLocation") or "").strip().strip('"') or None,
        "_uninstall_dir": _uninstaller_dir(uninstall),
    }


def _uninstaller_dir(command):
    """Folder of the program's own uninstaller ('"C:\\Program Files\\7-Zip\\Uninstall.exe" /S' -> its folder)."""
    match = re.match(r'^\s*"?([^"]+?\.exe)', command or "", re.IGNORECASE)
    if not match or "msiexec" in match.group(1).lower():
        return None
    folder = os.path.dirname(match.group(1))
    return folder if len(folder) > 3 else None


def _remember(entry_id, name, publisher=None, install_location=None, uninstall_dir=None):
    from .leftovers import remember_uninstalled

    remember_uninstalled(entry_id, {"name": name, "publisher": publisher, "install_location": install_location, "uninstall_dir": uninstall_dir})


def _windows_inventory():
    import winreg

    entries, seen = [], set()
    for root_tag, hive, path, view in _windows_roots():
        try:
            parent = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        with parent:
            index = 0
            while True:
                try:
                    subkey = winreg.EnumKey(parent, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(parent, subkey) as key:
                        entry = _windows_entry_from_values(root_tag, subkey, _registry_values(key))
                except OSError:
                    continue
                # The same program can appear under HKCU and HKU:<sid>, or in both registry views.
                if entry and (entry["name"].lower(), entry["version"]) not in seen:
                    seen.add((entry["name"].lower(), entry["version"]))
                    entries.append(entry)
    return entries


def _windows_entry(entry_id):
    """Look one inventory id up again in the registry (never trust details sent by the server)."""
    import winreg

    root_tag, _, subkey = str(entry_id).partition("|")
    if not subkey or "\\" in subkey or len(subkey) > 400:
        return None
    for tag, hive, path, view in _windows_roots():
        if tag != root_tag:
            continue
        try:
            with winreg.OpenKey(hive, f"{path}\\{subkey}", 0, winreg.KEY_READ | view) as key:
                return _windows_entry_from_values(tag, subkey, _registry_values(key))
        except OSError:
            return None
    return None


def winget_path():
    found = shutil.which("winget")
    if found:
        return found
    # SYSTEM has no winget on PATH; use the App Installer package directly (newest install wins).
    candidates = glob.glob(r"C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe")
    return max(candidates, key=os.path.getmtime) if candidates else None


def parse_winget_table(text):
    """Rows of a winget table (`winget upgrade`), sliced by the header's column positions."""
    lines = [chunk.split("\r")[-1] for chunk in (text or "").replace("\r\n", "\n").split("\n")]
    header_index = next((i for i, line in enumerate(lines) if re.search(r"\bName\b", line) and re.search(r"\bId\b", line) and re.search(r"\bVersion\b", line)), None)
    if header_index is None:
        return []
    header = lines[header_index]
    columns = [(match.group(), match.start()) for match in re.finditer(r"\S+", header)]
    rows = []
    for line in lines[header_index + 1:]:
        stripped = line.strip()
        if not stripped or set(stripped) <= {"-", "─"}:
            continue
        if "upgrades available" in stripped.lower() or "upgrade available" in stripped.lower() or "explicit targeting" in stripped.lower():
            break
        row = {}
        for index, (name, start) in enumerate(columns):
            end = columns[index + 1][1] if index + 1 < len(columns) else None
            row[name] = line[start:end].strip() if len(line) > start else ""
        if WINGET_ID.match(row.get("Id", "")):
            rows.append(row)
    return rows


def _windows_updates(entries):
    winget = winget_path()
    if not winget:
        return None, "winget (App Installer) is not installed, so updates were not checked."
    code, out, err = _run([winget, "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"], 150)
    rows = parse_winget_table(out)
    nothing_to_update = re.search(r"No installed package found|No applicable (update|upgrade)|No available upgrade", out, re.IGNORECASE)
    if not rows and code != 0 and not nothing_to_update:
        return None, f"winget could not check for updates: {_tail(err or out, 200) or f'exit code {code}'}"
    by_name = {entry["name"].lower(): entry for entry in entries}
    for row in rows:
        name = row.get("Name", "").rstrip("…").strip().lower()
        entry = by_name.get(name) or next((item for item in entries if name and item["name"].lower().startswith(name) and (not row.get("Version") or item["version"] == row.get("Version"))), None)
        update = {"update_available": True, "available_version": row.get("Available"), "update_id": row.get("Id"), "update_source": row.get("Source") or "winget"}
        if entry:
            entry.update(update)
            # winget knows the silent switches for packages it manages, so it can uninstall them too.
            if not entry["uninstall_method"] and not _protected(entry["name"]) and not PROTECTED_WINGET_IDS.match(row.get("Id", "")):
                entry.update(uninstall_method="winget", can_uninstall=True)
        else:
            entries.append({"id": f"winget|{row.get('Id')}", "name": row.get("Name", "").rstrip("…"), "version": row.get("Version", ""), "publisher": "", "install_date": None, "size_mb": None,
                            "scope": "machine", "uninstall_method": "winget", "can_uninstall": not _protected(row.get("Name")) and not PROTECTED_WINGET_IDS.match(row.get("Id", "")), **update})
    return "winget", None


def _windows_uninstall(entry_id):
    if entry_id.startswith("winget|"):
        package = entry_id.partition("|")[2]
        return _winget_uninstall(package, package)
    entry = _windows_entry(entry_id)
    if entry is None:
        return {"ok": False, "summary": "That program is no longer installed, or the id is not valid on this device."}
    name = entry["name"]
    if _protected(name):
        return {"ok": False, "summary": f"Refusing to uninstall {name}: it is part of the AIops agent."}
    subkey = entry_id.partition("|")[2]
    if entry["uninstall_method"] == "msi":
        command = ["msiexec.exe", "/x", subkey, "/qn", "/norestart"]
    elif entry["uninstall_method"] == "quiet":
        command = entry["_quiet"]  # the program's own registered silent uninstall command
    elif entry["uninstall_method"] == "inno":
        command = f"{entry['_uninstall']} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"
    else:
        return {"ok": False, "summary": f"{name} has no silent uninstaller. Uninstall it from Settings > Apps on the device."}
    code, out, err = _run(command, LONG_TIMEOUT)
    deadline = time.monotonic() + UNINSTALL_WAIT_SECONDS
    while _windows_entry(entry_id) is not None and time.monotonic() < deadline and code in (0, 3010, 1641):
        time.sleep(3)
    removed = _windows_entry(entry_id) is None
    restart = code in (3010, 1641)
    if removed:
        _remember(entry_id, name, entry.get("publisher"), entry.get("_install_location"), entry.get("_uninstall_dir"))
        return {"ok": True, "changed": True, "summary": f"Uninstalled {name}" + (" (restart the device to finish)" if restart else ""), "data": {"exit_code": code}}
    hint = "" if is_admin() else " (administrator rights required)"
    return {"ok": False, "summary": f"{name} is still installed after its uninstaller ran (exit code {code}){hint}", "data": {"exit_code": code, "output": _tail(err or out)}}


def _winget_uninstall(package, name):
    winget = winget_path()
    if not winget or not WINGET_ID.match(package):
        return {"ok": False, "summary": f"Cannot uninstall {name}: winget is not available."}
    if PROTECTED_WINGET_IDS.match(package):
        return {"ok": False, "summary": f"Refusing to uninstall {name}: winget and the Microsoft Store depend on it."}
    if not _winget_installed(winget, package):
        return {"ok": False, "summary": f"{package} is not installed on this device (checked with winget)."}
    code, out, err = _run([winget, "uninstall", "--id", package, "--exact", "--silent", "--accept-source-agreements", "--disable-interactivity"], LONG_TIMEOUT)
    ok = code == 0
    if ok:
        _remember(f"winget|{package}", name)
    return {"ok": ok, "changed": ok, "summary": f"Uninstalled {name}" if ok else f"winget could not uninstall {name} (exit code {code})", "data": {"exit_code": code, "output": _tail(out or err)}}


def _winget_installed(winget, package):
    """The server only sends a package id; act on it only if winget reports it installed here."""
    code, out, _err = _run([winget, "list", "--id", package, "--exact", "--accept-source-agreements", "--disable-interactivity"], 120)
    return code == 0 and any(row.get("Id", "").lower() == package.lower() for row in parse_winget_table(out))


def _windows_update(package):
    winget = winget_path()
    if not winget:
        return {"ok": False, "summary": "winget (App Installer) is not installed on this device."}
    if not _winget_installed(winget, package):
        return {"ok": False, "summary": f"{package} is not installed on this device (checked with winget)."}
    code, out, err = _run([winget, "upgrade", "--id", package, "--exact", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"], LONG_TIMEOUT)
    ok = code == 0
    return {"ok": ok, "changed": ok, "summary": f"Updated {package}" if ok else f"winget could not update {package} (exit code {code}): {_tail(out or err, 200)}", "data": {"exit_code": code, "output": _tail(out or err)}}


# ---------------------------------------------------------------------------
# Linux: dpkg/apt or rpm/dnf
# ---------------------------------------------------------------------------

def _linux_inventory():
    entries, updates, manager = [], {}, None
    if shutil.which("dpkg-query"):
        manager = "apt"
        _code, out, _err = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Installed-Size}\t${Maintainer}\t${db:Status-Abbrev}\n"], 90)
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 5 and parts[4].startswith("ii"):
                size = int(parts[2]) if parts[2].isdigit() else 0
                entries.append({"id": parts[0], "name": parts[0], "version": parts[1], "publisher": parts[3], "install_date": None, "size_mb": round(size / 1024, 1) if size else None})
        _code, out, _err = _run(["apt", "list", "--upgradable"], 90, env={"LC_ALL": "C"})
        for line in out.splitlines():
            match = re.match(r"^([^/\s]+)/\S+\s+(\S+)", line)
            if match:
                updates[match.group(1)] = match.group(2)
    elif shutil.which("rpm"):
        manager = "dnf" if shutil.which("dnf") else "yum"
        _code, out, _err = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SIZE}\t%{VENDOR}\t%{INSTALLTIME}\n"], 90)
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 5:
                size = int(parts[2]) if parts[2].isdigit() else 0
                installed = time.strftime("%Y-%m-%d", time.gmtime(int(parts[4]))) if parts[4].isdigit() else None
                entries.append({"id": parts[0], "name": parts[0], "version": parts[1], "publisher": parts[3], "install_date": installed, "size_mb": round(size / 1024 / 1024, 1) if size else None})
        _code, out, _err = _run([manager, "check-update", "-q"], 150)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0]:
                updates[parts[0].rsplit(".", 1)[0]] = parts[1]
    for entry in entries:
        entry.update(scope="machine", uninstall_method=manager, can_uninstall=bool(manager) and not PROTECTED_PACKAGES.match(entry["name"]) and not _protected(entry["name"]))
        if entry["name"] in updates:
            entry.update(update_available=True, available_version=updates[entry["name"]], update_id=entry["name"], update_source=manager)
    return entries, manager


def _linux_installed(package):
    if shutil.which("dpkg-query"):
        code, out, _err = _run(["dpkg-query", "-W", "-f=${Status}", package], 30)
        return code == 0 and "install ok installed" in out
    if shutil.which("rpm"):
        code, _out, _err = _run(["rpm", "-q", package], 30)
        return code == 0
    return False


def _linux_package_action(action, package):
    if not PACKAGE_NAME.match(package):
        return {"ok": False, "summary": "Invalid package name"}
    if action == "remove" and (PROTECTED_PACKAGES.match(package) or _protected(package)):
        return {"ok": False, "summary": f"Refusing to remove {package}: the system or the AIops agent depends on it."}
    if not _linux_installed(package):
        return {"ok": False, "summary": f"{package} is not installed on this device."}
    env = {"DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}
    if shutil.which("apt-get"):
        if action == "remove":
            # Removing one package can cascade into removing everything that depends on it; refuse that.
            _code, out, _err = _run(["apt-get", "-s", "remove", package], 120, env=env)
            removals = re.findall(r"^Remv (\S+)", out, re.MULTILINE)
            if len(removals) > 1:
                return {"ok": False, "summary": f"Refusing: removing {package} would also remove {len(removals) - 1} other package(s): {', '.join(removals[:8])}"}
            command = ["apt-get", "remove", "-y", package]
        else:
            command = ["apt-get", "install", "--only-upgrade", "-y", package]
    elif shutil.which("dnf") or shutil.which("yum"):
        manager = "dnf" if shutil.which("dnf") else "yum"
        command = [manager, "remove" if action == "remove" else "upgrade", "-y", package]
    else:
        return {"ok": False, "summary": "No supported package manager (apt or dnf) found."}
    code, out, err = _run(command, LONG_TIMEOUT, env=env)
    ok = code == 0
    if ok and action == "remove":
        _remember(package, package)
    verb = "Removed" if action == "remove" else "Updated"
    hint = "" if ok or is_admin() else " (root rights required)"
    return {"ok": ok, "changed": ok, "summary": f"{verb} {package}" if ok else f"Could not {action} {package} (exit code {code}){hint}: {_tail(err or out, 200)}", "data": {"exit_code": code, "output": _tail(out or err)}}


# ---------------------------------------------------------------------------
# macOS: applications list only
# ---------------------------------------------------------------------------

def _macos_inventory():
    _code, out, _err = _run(["system_profiler", "SPApplicationsDataType", "-json"], 180)
    try:
        apps = json.loads(out).get("SPApplicationsDataType", [])
    except (TypeError, ValueError):
        apps = []
    entries = []
    for app in apps:
        path = str(app.get("path") or "")
        if path.startswith(("/System/", "/Library/Apple/")):
            continue
        entries.append({"id": path, "name": app.get("_name") or os.path.basename(path), "version": str(app.get("version") or ""), "publisher": str(app.get("obtained_from") or ""),
                        "install_date": str(app.get("lastModified") or "")[:10] or None, "size_mb": None, "scope": "machine", "uninstall_method": None, "can_uninstall": False})
    return entries


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def _public(entry):
    entry.setdefault("update_available", False)
    return {key: value for key, value in entry.items() if not key.startswith("_")}


@tool("installed_software", "List installed programs with version, publisher, size and install date, and which have updates available (winget / apt / dnf).",
      params={"check_updates": {"type": "boolean", "description": "Also check for available updates (slower, default true)"}}, timeout=300, ai_visible=False)
def installed_software(check_updates=True):
    system = os_name()
    manager, note = None, None
    if system == "Windows":
        entries = _windows_inventory()
        if check_updates:
            manager, note = _windows_updates(entries)
    elif system == "Linux":
        entries, manager = _linux_inventory()
        if not manager:
            note = "No supported package manager found."
    else:
        entries = _macos_inventory()
        note = "On macOS, apps are listed only: update them from the App Store or the vendor, and uninstall them from Finder."
    software = sorted((_public(entry) for entry in entries), key=lambda item: item["name"].lower())
    updates = sum(1 for item in software if item.get("update_available"))
    summary = f"{len(software)} programs installed" + (f", {updates} with updates available" if manager else "")
    return {"ok": True, "summary": summary, "data": {"platform": system, "software": software, "count": len(software), "updates_available": updates, "update_manager": manager, "updates_note": note, "checked_at": time.time()}}


@tool("uninstall_software", "Uninstall one program by its inventory id using its own silent uninstaller (MSI, registered quiet uninstall, Inno Setup, winget) or apt/dnf. Programs without a silent uninstaller are refused.",
      risk="high", params={"id": {"type": "string", "maxLength": 600, "description": "Entry id from installed_software"}}, required=("id",), timeout=LONG_TIMEOUT, ai_visible=False)
def uninstall_software(id):  # noqa: A002 - matches the tool's public parameter name
    system = os_name()
    if system == "Windows":
        return _windows_uninstall(id)
    if system == "Linux":
        return _linux_package_action("remove", id)
    return {"ok": False, "summary": "Uninstalling is not supported on macOS yet: drag the app to the Trash on the device."}


@tool("update_software", "Update one program to its latest version with the package manager (winget on Windows, apt/dnf on Linux).",
      risk="medium", params={"package_id": {"type": "string", "maxLength": 200, "description": "update_id from installed_software"}}, required=("package_id",), timeout=LONG_TIMEOUT, ai_visible=False)
def update_software(package_id):
    system = os_name()
    if system == "Windows":
        if not WINGET_ID.match(package_id):
            return {"ok": False, "summary": "Invalid package id"}
        return _windows_update(package_id)
    if system == "Linux":
        return _linux_package_action("upgrade", package_id)
    return {"ok": False, "summary": "Updating apps is not supported on macOS yet: use the App Store or the vendor's updater."}
