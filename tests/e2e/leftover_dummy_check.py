"""Full-removal check on a DUMMY program (Windows, current user, no admin): never touches real software.

Creates "Contoso TestApp": an uninstall entry under HKCU whose "uninstaller" only deletes that entry (like
many real uninstallers that leave files behind), leftover folders in AppData/Programs, a Desktop shortcut
and registry keys. Then runs the agent tools exactly as the agent would: uninstall_software ->
find_leftovers -> quarantine_leftovers -> restore_quarantine, and finally deletes everything it created.

    python tests/e2e/leftover_dummy_check.py
"""

import os
import pathlib
import re
import shutil
import sys
import tempfile
import winreg

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
DATA = pathlib.Path(tempfile.mkdtemp(prefix="aiops-agent-data-"))
os.environ["AIOPS_AGENT_DATA"] = str(DATA)  # quarantine + records in a temp folder, not ProgramData

from agent.toolkit import run_tool  # noqa: E402

NAME, PUBLISHER, KEY = "Contoso TestApp", "Contoso Labs", "ContosoTestApp"
UNINSTALL_KEY = rf"Software\Microsoft\Windows\CurrentVersion\Uninstall\{KEY}"
local, roaming = pathlib.Path(os.environ["LOCALAPPDATA"]), pathlib.Path(os.environ["APPDATA"])
desktop = pathlib.Path(os.environ["USERPROFILE"]) / "Desktop"
FOLDERS = [local / "Programs" / NAME, roaming / NAME, roaming / PUBLISHER / NAME]
SHORTCUT = desktop / f"{NAME}.lnk"
REG_KEYS = [rf"Software\{NAME}", rf"Software\{PUBLISHER}\{NAME}"]
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""), flush=True)


def create():
    for folder in FOLDERS:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "settings.ini").write_text(f"[{NAME}]\nvalue=1\n")
    if desktop.is_dir():
        SHORTCUT.write_text("dummy shortcut")
    for path in REG_KEYS:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, "Setting", 0, winreg.REG_SZ, "value")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as key:
        for name, value in (("DisplayName", NAME), ("Publisher", PUBLISHER), ("DisplayVersion", "1.0"), ("InstallLocation", str(FOLDERS[0])),
                            ("UninstallString", f'"{FOLDERS[0]}\\uninstall.exe"'),
                            ("QuietUninstallString", f'reg delete "HKCU\\{UNINSTALL_KEY}" /f')):
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def registry_exists(path):
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, path))
        return True
    except OSError:
        return False


def cleanup():
    for folder in FOLDERS:
        shutil.rmtree(folder, ignore_errors=True)
    shutil.rmtree(roaming / PUBLISHER, ignore_errors=True)
    if SHORTCUT.exists():
        SHORTCUT.unlink()
    for path in [*REG_KEYS, rf"Software\{PUBLISHER}", UNINSTALL_KEY]:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except OSError:
            pass
    shutil.rmtree(DATA, ignore_errors=True)


try:
    create()
    entry_id = f"HKCU|{KEY}"
    inventory = run_tool("installed_software", {"check_updates": False}, "read")
    entry = next((item for item in inventory["data"]["software"] if item["id"] == entry_id), None)
    check("dummy program is in the inventory and removable", bool(entry) and entry["can_uninstall"], str(entry and entry["uninstall_method"]))

    scan_before = run_tool("find_leftovers", {"id": entry_id}, "read")
    check("leftover scan refuses while the program is installed", not scan_before["ok"] and "still installed" in scan_before["summary"], scan_before["summary"])

    removed = run_tool("uninstall_software", {"id": entry_id}, "high")
    check("uninstall runs its own quiet uninstaller", removed["ok"], removed["summary"])

    scan = run_tool("find_leftovers", {"id": entry_id}, "read")
    candidates = scan["data"]["candidates"] if scan["ok"] else []
    # Registry keys are reported as HKU\<your SID>\..., the same key as HKCU\...
    by_path = {re.sub(r"^HKU\\S-1-5-21-[\d-]+\\", r"HKCU\\", item["path"]): item for item in candidates}
    found = set(by_path)
    expected = {str(folder) for folder in FOLDERS} | {f"HKCU\\{path}" for path in REG_KEYS} | ({str(SHORTCUT)} if desktop.is_dir() else set())
    check("scan finds every leftover", expected <= found, f"{len(candidates)} found; missing {sorted(expected - found)}")
    unexpected = found - expected
    check("scan finds nothing else", not unexpected, str(sorted(unexpected)))

    ids = ",".join(item["id"] for path, item in by_path.items() if path in expected)
    quarantined = run_tool("quarantine_leftovers", {"scan_id": scan["data"]["scan_id"], "candidate_ids": ids}, "high")
    gone = not any(folder.exists() for folder in FOLDERS) and not any(registry_exists(path) for path in REG_KEYS)
    check("quarantine removes the leftovers", quarantined["ok"] and gone, quarantined["summary"])

    batch_id = quarantined["data"]["batch_id"]
    listed = run_tool("list_quarantine", {}, "read")["data"]["batches"]
    check("batch listed as restorable", any(batch["batch_id"] == batch_id for batch in listed))

    restored = run_tool("restore_quarantine", {"batch_id": batch_id}, "medium")
    back = all((folder / "settings.ini").exists() for folder in FOLDERS) and all(registry_exists(path) for path in REG_KEYS)
    check("restore puts everything back", restored["ok"] and back, restored["summary"])
finally:
    cleanup()
    leftover_check = not any(folder.exists() for folder in FOLDERS) and not registry_exists(UNINSTALL_KEY) and not registry_exists(REG_KEYS[0])
    check("dummy program fully cleaned up", leftover_check)

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
