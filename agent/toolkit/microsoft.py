"""Microsoft products: list them, and remove one completely (its registry keys too), with a 7-day restore.

Office and Microsoft 365 leave a Click-to-Run service, scheduled tasks, folders and registry keys behind that an
ordinary uninstall misses, and that Click-to-Run updater can block other installs ("another installation is in
progress", error 1618). remove_office uses Microsoft's own scrubber (GetHelpCmd / SaRAcmd) when it is on the
device, and otherwise does Microsoft's documented manual cleanup. Either way every registry key and folder it
removes is first backed up into the same quarantine the Software tab restores from, so a mistake is reversible.

The server only ever sends a product id that this agent's own microsoft_products listing produced; paths, keys and
package names are resolved again on the device, never taken from the server.
"""

import os
import re
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import leftovers, software
from .common import is_admin, os_name
from .registry import tool
from .software import _run, _tail

LONG_TIMEOUT = 3600
SCRUB_TIMEOUT = 2400
# Where the operator may drop Microsoft's command-line scrubber (GetHelpCmd.exe, historically SaRAcmd.exe).
SCRUBBER_NAMES = ("GetHelpCmd.exe", "SaRAcmd.exe")
SCRUBBER_ENV = "AIOPS_OFFICE_SCRUBBER"
# Office is detected by name; these are the versions the scrubber's -OfficeVersion switch accepts.
OFFICE_NAME = re.compile(r"(?i)\b(microsoft\s+office|microsoft\s+365|office\s+(professional|standard|home|business|365))\b")
OFFICE_VERSIONS = {"16.0": "2016", "15.0": "2013", "14.0": "2010", "12.0": "2007"}
# Scrubber exit codes (Get Help "Office uninstall" command line).
SCRUB_EXIT = {
    0: ("ok", "Office removed successfully. Restart the device to finish cleanup."),
    6: ("busy", "Close all open Office programs (Word, Excel, Outlook, Teams...) and run the removal again."),
    8: ("ambiguous", "Several Office versions are installed; the scrubber needs the full Get Help UI for this device."),
    9: ("failed", "The scrubber could not remove Office."),
    10: ("not_admin", "The scrubber needs administrator rights (the agent must run as SYSTEM or an administrator)."),
    66: ("wrong_version", "The scrubber did not find the specified Office version on this device."),
    67: ("invalid_version", "The Office version asked for is not valid."),
    68: ("none_found", "The scrubber found no Office version on this device."),
}

# Microsoft's documented manual Click-to-Run / MSI cleanup. Folders and keys hold %ENV% that _expand resolves.
OFFICE_FOLDERS = (
    r"%ProgramFiles%\Microsoft Office", r"%ProgramFiles(x86)%\Microsoft Office",
    r"%ProgramFiles%\Microsoft Office 15", r"%ProgramFiles%\Microsoft Office 16",
    r"%CommonProgramFiles%\Microsoft Shared\ClickToRun", r"%CommonProgramFiles(x86)%\Microsoft Shared\ClickToRun",
    r"%ProgramData%\Microsoft\ClickToRun",
)
OFFICE_FILES = (
    r"%ProgramData%\Microsoft\Office\ClickToRunPackagerLocker", r"%ProgramData%\Microsoft\office\FFPackageLocker",
)
OFFICE_TASK_PATH = "\\Microsoft\\Office\\"
OFFICE_SERVICES = ("ClickToRunSvc", "ose")
# Backed up (exported) then deleted. HKCU\...\Office holds user settings; backing it up keeps restore honest.
OFFICE_REG_KEYS = (
    r"HKLM\SOFTWARE\Microsoft\Office\ClickToRun", r"HKLM\SOFTWARE\Microsoft\Office\15.0\ClickToRun",
    r"HKLM\SOFTWARE\Microsoft\Office\16.0\ClickToRun", r"HKLM\SOFTWARE\Microsoft\AppVISV",
    r"HKCU\SOFTWARE\Microsoft\Office\ClickToRun",
)
INSTALLER_IN_PROGRESS = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress"
REBOOT_PENDING_KEYS = (
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
)

# Store (Appx) apps that keep Windows working: never offered for removal.
PROTECTED_APPX = re.compile(r"(?i)(\.VCLibs|\.NET\.Native|WindowsAppRuntime|\.UI\.Xaml|WindowsStore$|StorePurchaseApp|"
                           r"DesktopAppInstaller|AppInstaller|\.WindowsStore|WindowsStore$|XboxGameCallableUI|SecHealthUI|ShellExperienceHost|"
                           r"Windows\.CBSPreview|AAD\.BrokerPlugin|AccountsControl|LockApp|ContentDeliveryManager|"
                           r"PeopleExperienceHost|Win32WebViewHost|CapturePicker|CredDialogHost|BioEnrollment|Cortana)")
APPX_FULLNAME = re.compile(r"^[A-Za-z0-9.+-]+_[0-9][0-9.]*_[A-Za-z0-9~]*_[A-Za-z0-9]*_[A-Za-z0-9]+$")


def _expand(path):
    return os.path.expandvars(path)


def _scrubber_path():
    """Microsoft's command-line scrubber, if the operator placed it on the device (env var, agent folder, tools)."""
    candidates = []
    configured = os.getenv(SCRUBBER_ENV)
    if configured:
        candidates.append(Path(configured))
    roots = [leftovers.agent_dir(), leftovers.agent_dir() / "tools", leftovers.storage_root() / "tools"]
    for root in roots:
        for name in SCRUBBER_NAMES:
            candidates.append(root / name)
    for candidate in candidates:
        try:
            if candidate.is_file() and candidate.name.lower() in (name.lower() for name in SCRUBBER_NAMES):
                return str(candidate)
            if candidate.is_dir():
                for name in SCRUBBER_NAMES:
                    if (candidate / name).is_file():
                        return str(candidate / name)
        except OSError:
            continue
    return None


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

def _office_version(entry):
    """The scrubber -OfficeVersion value for an Office entry ('2016', 'M365', ...), or 'All' when unsure."""
    name = entry.get("name") or ""
    if re.search(r"(?i)365|subscription", name):
        return "M365"
    version = (entry.get("version") or "")[:4]
    for prefix, label in OFFICE_VERSIONS.items():
        if version.startswith(prefix) or f" {label}" in name or f"Office {label}" in name:
            return label
    return "All"


def _office_products(entries):
    """Office/365 installs from the registry inventory, plus a Click-to-Run remnant if one is left behind."""
    products, seen_versions = [], set()
    for entry in entries:
        if not OFFICE_NAME.search(entry.get("name") or ""):
            continue
        version = _office_version(entry)
        seen_versions.add(version)
        c2r = bool(re.search(r"(?i)clicktorun|officeclicktorun", entry.get("_uninstall") or "")) or version == "M365"
        products.append({
            "id": f"office|{version}", "name": entry["name"], "version": entry.get("version"), "publisher": entry.get("publisher"),
            "size_mb": entry.get("size_mb"), "kind": "office", "install_type": "Click-to-Run" if c2r else "MSI (classic installer)",
            "remove_kind": "office", "restorable": True,
            "note": "Removed with Microsoft's scrubber if present, otherwise Microsoft's documented manual cleanup (service, tasks, folders, registry).",
        })
    # A Click-to-Run service or config left behind with no matching program row: still worth removing.
    leftover = _clicktorun_state()
    if (leftover["service"] or leftover["config"]) and not any(product for product in products):
        products.append({
            "id": "office|All", "name": "Office Click-to-Run leftovers", "version": None, "publisher": "Microsoft",
            "size_mb": None, "kind": "office", "install_type": "Click-to-Run (leftover)", "remove_kind": "office", "restorable": True,
            "note": "No Office program is listed, but a Click-to-Run service, tasks or registry keys remain.",
        })
    return products


def _clicktorun_state():
    service = _service_exists("ClickToRunSvc")
    config = _reg_key_exists(r"HKLM\SOFTWARE\Microsoft\Office\ClickToRun\Configuration")
    running = any(_process_running(name) for name in ("OfficeClickToRun.exe", "OfficeC2RClient.exe"))
    return {"service": service, "config": config, "running": running}


def _service_exists(name):
    code, _out, _err = _run(["sc", "query", name], 20)
    return code == 0


def _reg_key_exists(key):
    ok, _ = leftovers._reg("query", key, timeout=20)
    return ok


def _process_running(name):
    try:
        import psutil
    except ImportError:
        return False
    lowered = name.lower()
    return any((process.info.get("name") or "").lower() == lowered for process in psutil.process_iter(["name"]))


def _install_blocker():
    """Why a new install might be refused (error 1618 and friends), for the listing and the fix tool."""
    return {
        "installer_in_progress": _reg_key_exists(INSTALLER_IN_PROGRESS),
        "clicktorun_running": any(_process_running(name) for name in ("OfficeClickToRun.exe", "OfficeC2RClient.exe")),
        "reboot_pending": any(_reg_key_exists(key) for key in REBOOT_PENDING_KEYS),
        "msiexec_count": sum(1 for _ in _msiexec_processes()),
    }


def _msiexec_processes():
    try:
        import psutil
    except ImportError:
        return
    for process in psutil.process_iter(["pid", "name", "create_time"]):
        if (process.info.get("name") or "").lower() == "msiexec.exe":
            yield process


def _store_apps():
    """Removable Store (Appx) apps for the current and all users (never frameworks or system components)."""
    from .updates import _powershell_json

    # -AllUsers needs admin (the agent runs as SYSTEM); fall back to the current user's apps when it is refused.
    script = (
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$all = try { @(Get-AppxPackage -AllUsers) } catch { @(Get-AppxPackage) };"
        "$all | Where-Object { -not $_.IsFramework -and -not $_.NonRemovable -and $_.SignatureKind -ne 'System' } |"
        " ForEach-Object { [pscustomobject]@{ name=$_.Name; full=$_.PackageFullName; publisher=$_.Publisher; version=$_.Version } } | ConvertTo-Json -Compress"
    )
    data = _powershell_json(script, 120)
    if not isinstance(data, list):
        data = [data] if isinstance(data, dict) and data.get("full") else []
    apps = []
    for item in data:
        full = str(item.get("full") or "")
        publisher = str(item.get("publisher") or "")
        # Microsoft-published apps only (the tab is for Microsoft products, not every Store app on the device).
        if not re.search(r"(?i)CN=Microsoft Corporation", publisher) and not re.match(r"(?i)^(Microsoft|MSTeams|Windows)", str(item.get("name") or "")):
            continue
        if not APPX_FULLNAME.match(full) or PROTECTED_APPX.search(full):
            continue
        apps.append({
            "id": f"appx|{full}", "name": item.get("name") or full.split("_")[0], "version": item.get("version"),
            "publisher": "Microsoft Store app", "size_mb": None, "kind": "appx", "install_type": "Microsoft Store (Appx)",
            "remove_kind": "appx", "restorable": False, "note": "Store app: removed for every user; reinstall it from the Microsoft Store to get it back.",
        })
    return apps


@tool("microsoft_products", "List Microsoft products on this device (Office/365, Store apps, other Microsoft programs) and whether a new install is being blocked. Read-only.",
      timeout=300, ai_visible=False)
def microsoft_products():
    if os_name() != "Windows":
        return {"ok": False, "summary": "Microsoft product removal is only supported on Windows."}
    inventory = software._windows_inventory()
    office = _office_products(inventory)
    office_names = {product["name"] for product in office}
    programs = []
    for entry in inventory:
        name = entry.get("name") or ""
        if name in office_names or not re.search(r"(?i)^(microsoft|windows|office|skype|visual studio|\.net|onedrive|teams)\b", name):
            continue
        public = software._public(dict(entry))
        programs.append({
            "id": public["id"], "name": public["name"], "version": public.get("version"), "publisher": public.get("publisher"),
            "size_mb": public.get("size_mb"), "kind": "program", "install_type": "Windows program",
            "remove_kind": "program", "restorable": public.get("uninstall_method") is not None,
            "can_remove": public.get("can_uninstall", False),
            "note": None if public.get("can_uninstall") else "No silent uninstaller: remove it from Settings > Apps on the device.",
        })
    for product in office:
        product["can_remove"] = True
    appx = _store_apps()
    for app in appx:
        app["can_remove"] = True
    products = office + sorted(programs, key=lambda item: item["name"].lower()) + sorted(appx, key=lambda item: item["name"].lower())
    blocker = _install_blocker()
    blocked = blocker["installer_in_progress"] or blocker["reboot_pending"]
    summary = f"{len(products)} Microsoft product(s): {len(office)} Office/365, {len(programs)} program(s), {len(appx)} Store app(s)."
    if blocked:
        summary += " A new install is likely being blocked (see the installer status)."
    return {"ok": True, "summary": summary, "data": {"products": products, "office": len(office), "appx": len(appx), "programs": len(programs),
            "blocker": blocker, "scrubber_present": bool(_scrubber_path()), "checked_at": time.time()}}


# ---------------------------------------------------------------------------
# Backup to the Software-tab quarantine (restorable for 7 days)
# ---------------------------------------------------------------------------

class _Backup:
    """Exports registry keys and moves folders into one quarantine batch, in the leftovers manifest format, so the
    Software tab's Restore puts them back. Scheduled-task XML is saved for the record (tasks are not auto-restored)."""

    def __init__(self, program):
        self.batch_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        self.batch = leftovers._quarantine_dir() / self.batch_id
        self.batch.mkdir(parents=True, exist_ok=True)
        self.program, self.items, self.tasks, self.count = program, [], [], 0

    def registry(self, key):
        if not _reg_key_exists(key):
            return
        self.count += 1
        stored = self.batch / f"r{self.count}.reg"
        ok, message = leftovers._reg("export", key, str(stored), "/y")
        self.items.append({"id": f"r{self.count}", "kind": "registry", "original": key, "stored": str(stored) if ok else None,
                           "ok": ok, "error": None if ok else message, "restored": False})
        return ok

    def folder(self, path):
        path = _expand(path)
        if not leftovers._exists(Path(path)) or leftovers._is_link(path):
            return
        self.count += 1
        entry = {"id": f"f{self.count}", "kind": "folder" if Path(path).is_dir() else "file", "original": path, "stored": None, "ok": False, "error": None, "restored": False}
        if not leftovers._same_volume(path, self.batch):
            entry["error"] = "on another drive than the quarantine; left in place"
        elif leftovers._has_links(path):
            entry["error"] = "contains a shortcut link or junction; left in place"
        else:
            stored = self.batch / f"f{self.count}_{leftovers._safe_name(Path(path).name)}"
            try:
                shutil.move(path, str(stored))
                entry.update(stored=str(stored), ok=True)
            except (OSError, shutil.Error) as error:
                entry["error"] = f"could not move (in use or access denied): {error}"[:200]
        self.items.append(entry)
        return entry["ok"]

    def task_xml(self, task_name, xml):
        self.count += 1
        stored = self.batch / f"t{self.count}.xml"
        try:
            stored.write_text(xml, encoding="utf-16")
            self.tasks.append({"task": task_name, "stored": str(stored)})
        except OSError:
            pass

    def finish(self):
        created = time.time()
        leftovers._write_json(self.batch / "manifest.json", {"batch_id": self.batch_id, "program": self.program, "entry_id": None,
                              "created": created, "items": self.items, "tasks_backed_up": self.tasks})
        restore_until = datetime.fromtimestamp(created + leftovers.QUARANTINE_DAYS * 86400, timezone.utc).isoformat()
        return {"batch_id": self.batch_id, "restore_until": restore_until, "backed_up": sum(1 for item in self.items if item["ok"])}


# ---------------------------------------------------------------------------
# Removal
# ---------------------------------------------------------------------------

def _delete_office_tasks(backup):
    """Back up (XML) and delete every task under \\Microsoft\\Office\\."""
    code, out, _err = _run(["schtasks", "/query", "/fo", "csv", "/nh"], 60)
    deleted = []
    if code != 0:
        return deleted
    names = {row.split('","')[0].strip('"') for row in out.splitlines() if OFFICE_TASK_PATH.rstrip("\\") in row}
    for name in sorted(names):
        if not name.startswith(OFFICE_TASK_PATH):
            continue
        xml_code, xml_out, _ = _run(["schtasks", "/query", "/tn", name, "/xml"], 30)
        if xml_code == 0 and xml_out.strip():
            backup.task_xml(name, xml_out)
        if _run(["schtasks", "/delete", "/tn", name, "/f"], 30)[0] == 0:
            deleted.append(name)
    return deleted


def _delete_office_services(backup):
    removed = []
    for name in OFFICE_SERVICES:
        if not _service_exists(name):
            continue
        backup.registry(f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}")
        _run(["sc", "stop", name], 60)
        if _run(["sc", "delete", name], 60)[0] == 0:
            removed.append(name)
    return removed


def _run_scrubber(scrubber, version):
    command = [scrubber, "-S", "OfficeScrubScenario", "-AcceptEula"]
    if version and version != "detect":
        command += ["-OfficeVersion", version]
    code, out, err = _run(command, SCRUB_TIMEOUT)
    status, message = SCRUB_EXIT.get(code, ("unknown", f"The scrubber finished with exit code {code}."))
    return {"ran": "scrubber", "exit_code": code, "status": status, "ok": status == "ok", "message": message, "output": _tail(out or err, 600)}


def _manual_office_removal(version):
    """Microsoft's documented manual Click-to-Run / MSI cleanup, everything backed up first."""
    for name in ("OfficeClickToRun.exe", "OfficeC2RClient.exe", "AppVShNotify.exe", "firstrun.exe"):
        _run(["taskkill", "/F", "/IM", name], 30)
    backup = _Backup(f"Microsoft Office ({version})")
    services = _delete_office_services(backup)
    tasks = _delete_office_tasks(backup)
    # Run each installed Office product's own uninstaller first (MSI setup.exe /uninstall, winget), then clean up.
    uninstalled = []
    for entry in software._windows_inventory():
        if OFFICE_NAME.search(entry.get("name") or "") and entry.get("uninstall_method"):
            result = software._windows_uninstall(entry["id"])
            uninstalled.append({"name": entry["name"], "ok": result.get("ok"), "summary": result.get("summary")})
    for key in OFFICE_REG_KEYS:
        backup.registry(key)
    for key in (r"HKLM\SOFTWARE\Microsoft\Office\16.0", r"HKLM\SOFTWARE\Microsoft\Office\15.0", r"HKCU\SOFTWARE\Microsoft\Office"):
        backup.registry(key)
    removed_keys = []
    for item in backup.items:
        if item["kind"] == "registry" and item["ok"]:
            ok, message = leftovers._reg("delete", item["original"], "/f")
            if ok:
                removed_keys.append(item["original"])
            else:
                item["error"] = f"backed up but not deleted: {message}"
    for path in OFFICE_FOLDERS:
        backup.folder(path)
    for path in OFFICE_FILES:
        backup.folder(path)
    info = backup.finish()
    moved = sum(1 for item in backup.items if item["kind"] in ("folder", "file") and item["ok"])
    return {"ran": "manual", "ok": True, "status": "ok", "services_removed": services, "tasks_removed": len(tasks),
            "registry_keys_removed": len(removed_keys), "folders_moved": moved, "uninstalled": uninstalled,
            "message": "Office removed with Microsoft's documented manual cleanup. Restart the device to finish.", **info}


def remove_office(version="All"):
    """Remove Office/365 completely: Microsoft's scrubber when present, otherwise the manual cleanup (restorable)."""
    if os_name() != "Windows":
        return {"ok": False, "summary": "Office removal is only supported on Windows."}
    if version not in set(OFFICE_VERSIONS.values()) | {"All", "M365", "2024", "detect"}:
        return {"ok": False, "summary": f"Unknown Office version '{version}'."}
    scrubber = _scrubber_path()
    if scrubber:
        # Back up the registry first (the scrubber removes folders itself; those are not restorable, only reinstallable).
        backup = _Backup(f"Microsoft Office ({version}) registry")
        for key in OFFICE_REG_KEYS + (r"HKLM\SOFTWARE\Microsoft\Office\16.0", r"HKLM\SOFTWARE\Microsoft\Office\15.0", r"HKCU\SOFTWARE\Microsoft\Office"):
            backup.registry(key)
        info = backup.finish()
        result = _run_scrubber(scrubber, version)
        changed = result["status"] in ("ok", "none_found")
        extra = " Registry settings were backed up (restorable for 7 days); program files were removed by Microsoft's tool and must be reinstalled." if changed else ""
        return {"ok": result["ok"], "changed": result["status"] == "ok", "summary": result["message"] + extra,
                "data": {**result, **info, "method": "Microsoft scrubber"}}
    result = _manual_office_removal(version)
    return {"ok": result["ok"], "changed": True, "summary": result["message"] +
            f" Removed {result['registry_keys_removed']} registry key(s), {result['folders_moved']} folder(s), {result['tasks_removed']} task(s); "
            f"all backed up (restorable until {result['restore_until'][:10]}).", "data": {**result, "method": "manual cleanup"}}


def remove_appx(full_name):
    """Remove a Store app for every user and deprovision it (so it does not return for new users)."""
    if os_name() != "Windows":
        return {"ok": False, "summary": "Store app removal is only supported on Windows."}
    if not APPX_FULLNAME.match(full_name or ""):
        return {"ok": False, "summary": "Invalid package name."}
    if PROTECTED_APPX.search(full_name):
        return {"ok": False, "summary": "Refusing to remove this package: Windows or the Store depends on it."}
    name = full_name.split("_")[0]
    script = (
        f"$ErrorActionPreference='Stop'; $full='{full_name}';"
        " try { Remove-AppxPackage -Package $full -AllUsers; $r1='removed' } catch { $r1=\"keep: $($_.Exception.Message)\" }"
        " $p = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -eq $full };"
        " if ($p) { try { Remove-AppxProvisionedPackage -Online -PackageName $full | Out-Null; $r2='deprovisioned' } catch { $r2=\"prov-keep: $($_.Exception.Message)\" } } else { $r2='no-provisioned' }"
        " $still = [bool](Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -eq $full });"
        " [pscustomobject]@{ remove=$r1; provision=$r2; still_installed=$still } | ConvertTo-Json -Compress"
    )
    from .updates import _powershell_json

    data = _powershell_json(script, 300)
    still = bool(data.get("still_installed")) if isinstance(data, dict) else True
    ok = isinstance(data, dict) and not still
    detail = (data.get("remove") or "") if isinstance(data, dict) else str(data)
    if ok:
        return {"ok": True, "changed": True, "summary": f"Removed the Store app {name} for all users ({data.get('provision')}). Reinstall it from the Microsoft Store to get it back.", "data": data}
    return {"ok": False, "summary": f"Could not remove {name}: {detail}"[:400], "data": data if isinstance(data, dict) else {"output": str(data)[:300]}}


@tool("remove_microsoft", "Completely remove one Microsoft product by its id from microsoft_products: Office/365 (scrubber or manual cleanup, registry too), a Store app, or another Microsoft program. Registry keys and folders are backed up first (restore for 7 days from the Software tab).",
      risk="high", params={"id": {"type": "string", "maxLength": 600, "description": "Product id from microsoft_products"}}, required=("id",), timeout=LONG_TIMEOUT, ai_visible=False)
def remove_microsoft(id):  # noqa: A002 - matches the tool's public parameter name
    kind, _, rest = str(id).partition("|")
    if kind == "office":
        return remove_office(rest or "All")
    if kind == "appx":
        return remove_appx(rest)
    # An ordinary Microsoft program: its own silent uninstaller (MSI removes its registry; leftovers tab cleans the rest).
    result = software._windows_uninstall(str(id)) if os_name() == "Windows" else {"ok": False, "summary": "Only supported on Windows."}
    if result.get("ok"):
        result.setdefault("data", {})["hint"] = "Use the Software tab's 'Remove completely' to clear any leftover folders or registry keys."
    return result


@tool("fix_install_blocker", "Fix a stuck installer that blocks new installs ('another installation is already in progress', error 1618): clear the stale InProgress marker (backed up first) and restart the Windows Installer and Click-to-Run services.",
      risk="medium", timeout=300, ai_visible=False)
def fix_install_blocker():
    if os_name() != "Windows":
        return {"ok": False, "summary": "This fix is only supported on Windows."}
    before = _install_blocker()
    actions, backup = [], None
    if before["installer_in_progress"]:
        backup = _Backup("Windows Installer InProgress marker")
        if backup.registry(INSTALLER_IN_PROGRESS):
            ok, message = leftovers._reg("delete", INSTALLER_IN_PROGRESS, "/f")
            actions.append("cleared the stale 'installation in progress' marker" if ok else f"could not clear the marker: {message}")
        backup.finish()
    # Bounce the Windows Installer service so a half-finished transaction is released.
    _run(["net", "stop", "msiserver"], 60)
    if _run(["net", "start", "msiserver"], 60)[0] == 0:
        actions.append("restarted the Windows Installer service")
    if before["clicktorun_running"] and _service_exists("ClickToRunSvc"):
        _run(["sc", "stop", "ClickToRunSvc"], 60)
        _run(["sc", "start", "ClickToRunSvc"], 60)
        actions.append("restarted the Click-to-Run service")
    after = _install_blocker()
    cleared = before["installer_in_progress"] and not after["installer_in_progress"]
    changed = bool(actions)
    note = ""
    if after["reboot_pending"]:
        note = " A restart is still pending: restart the device, then try the install again."
    elif after["msiexec_count"] > 0:
        note = f" {after['msiexec_count']} installer(s) are still running: let them finish, or restart the device."
    summary = ("Install blocker cleared. " if cleared or (changed and not after["installer_in_progress"]) else "Checked the installer. ") + \
        ("; ".join(actions) if actions else "nothing needed changing") + note
    return {"ok": True, "changed": changed, "summary": summary, "data": {"before": before, "after": after, "actions": actions}}
