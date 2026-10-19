"""Leftovers of an uninstalled program: find them, move them to a quarantine, restore them.

The server only ever sends ids: an inventory id (resolved from the record this agent kept when the program
was uninstalled), candidate ids from this agent's own last leftover scan, and quarantine batch ids. Paths
and registry keys always come from this device, never from the server.

Quarantine moves folders and files into a per-batch folder and exports registry keys to .reg files before
deleting them, so every batch can be restored for QUARANTINE_DAYS; older batches are purged by the agent.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .common import directory_size, human_size, os_name
from .registry import tool

QUARANTINE_DAYS = 7
SCAN_TTL_SECONDS = 3600
MAX_CANDIDATES = 60
UNINSTALLED_KEPT = 50
SIZE_SCAN_MAX_FILES = 50000
CANDIDATE_ID = re.compile(r"^c\d{1,3}$")
SCAN_ID = re.compile(r"^[0-9a-f]{12}$")
BATCH_ID = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
# Folder or key names that are shared by many programs: never offered as a leftover.
GENERIC_NAMES = {
    "microsoft", "windows", "common files", "microsoft shared", "windowsapps", "packages", "package cache", "temp", "tmp",
    "programs", "intel", "nvidia", "nvidia corporation", "amd", "google", "mozilla", "apple", "apple computer", "adobe", "oracle",
    "installshield installation information", "classes", "policies", "clients", "registeredapplications", "wow6432node",
    "start menu", "desktop", "documents", "downloads", "appdata", "local", "roaming", "locallow", "cache", "logs", "config",
    "software", "system", "users", "public", "default", "updater", "update", "uninstall", "setup", "installer", "data",
}
REGISTRY_ROOT_NAMES = {"HKLM", "HKCU", "HKU"}


# ---------------------------------------------------------------------------
# Storage on the device
# ---------------------------------------------------------------------------

def storage_root():
    configured = os.getenv("AIOPS_AGENT_DATA")
    if configured:
        return Path(configured)
    system = os_name()
    if system == "Windows":
        return Path(os.getenv("ProgramData", r"C:\ProgramData")) / "SentinelAgent"
    if system == "Darwin":
        return Path("/Library/Application Support/AIops")
    return Path("/var/lib/aiops-agent")


def _quarantine_dir():
    return storage_root() / "quarantine"


def _scans_dir():
    return storage_root() / "leftover-scans"


def _uninstalled_file():
    return storage_root() / "uninstalled.json"


def _read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def remember_uninstalled(entry_id, info):
    """Called after a successful uninstall: the uninstall registry entry is gone afterwards, so keep what a
    leftover scan needs (name, publisher, install folder). Never raises."""
    try:
        records = _read_agent_json(_uninstalled_file(), {})
        records[str(entry_id)] = {**info, "removed_at": time.time()}
        newest = sorted(records.items(), key=lambda item: item[1].get("removed_at", 0), reverse=True)[:UNINSTALLED_KEPT]
        _write_json(_uninstalled_file(), dict(newest))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def normalize(name):
    """'7-Zip 26.03 (x64)' -> '7 zip'; 'Adobe Acrobat (64-bit)' -> 'adobe acrobat'."""
    text = str(name or "").lower()
    text = re.sub(r"\(.*?\)|\[.*?\]", " ", text)
    text = re.sub(r"[®™©]", "", text)
    text = re.sub(r"\b(x64|x86|amd64|arm64|64[- ]?bit|32[- ]?bit)\b", " ", text)
    text = re.sub(r"\bv?\d+(?:\.\d+)+[a-z]?\b", " ", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def match_names(info):
    """Normalized names a leftover may carry: the display name, and the install folder's own name."""
    names = {normalize(info.get("name"))}
    for folder in (info.get("install_location"), info.get("uninstall_dir")):
        if folder:
            names.add(normalize(Path(str(folder).rstrip("\\/")).name))
    return {name for name in names if len(name) >= 3 and name not in GENERIC_NAMES}


def _confidence_for(normalized, names, publisher):
    if normalized in names:
        return "high"
    first = next(iter(sorted(names, key=len)), "")
    words = first.split()
    # "docker" for "docker desktop": plausible but not certain, so it is not pre-selected.
    if len(normalized) >= 4 and normalized not in GENERIC_NAMES and words and words[0] == normalized and normalized != publisher:
        return "low"
    return None


def _norm_path(path):
    return os.path.normcase(os.path.abspath(str(path))).rstrip("\\/")


def _overlaps(path, others):
    """True when `path` is, contains or sits inside another installed program's folder."""
    target = _norm_path(path)
    for other in others:
        if target == other or target.startswith(other + os.sep) or other.startswith(target + os.sep):
            return True
    return False


# ---------------------------------------------------------------------------
# Windows scan
# ---------------------------------------------------------------------------

def _is_dir(path):
    """Path.is_dir() raises PermissionError for folders this account may not read (another user's
    profile); a scan must skip those, not fail."""
    try:
        return Path(path).is_dir()
    except OSError:
        return False


def _exists(path):
    try:
        return Path(path).exists()
    except OSError:
        return False


def _windows_scan_roots():
    """(folder, label, confidence when the name matches). Shortcut folders hold .lnk files too."""
    env = os.environ
    roots = []
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        if env.get(key):
            roots.append((Path(env[key]), "Program Files", "high"))
    program_data = Path(env.get("ProgramData", r"C:\ProgramData"))
    roots.append((program_data, "ProgramData", "medium"))
    roots.append((program_data / "Microsoft" / "Windows" / "Start Menu" / "Programs", "Start Menu (all users)", "medium"))
    users = Path(env.get("SystemDrive", "C:") + "\\") / "Users"
    try:
        profiles = [item for item in users.iterdir() if _is_dir(item) and item.name.lower() not in ("public", "default", "default user", "all users")]
    except OSError:
        profiles = []
    for profile in profiles:
        for part, label in (("AppData/Roaming", "AppData Roaming"), ("AppData/Local", "AppData Local"), ("AppData/LocalLow", "AppData LocalLow")):
            roots.append((profile / part, f"{label} ({profile.name})", "medium"))
        roots.append((profile / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs", f"Start Menu ({profile.name})", "medium"))
        roots.append((profile / "Desktop", f"Desktop ({profile.name})", "medium"))
    roots.append((users / "Public" / "Desktop", "Desktop (all users)", "medium"))
    return [(root, label, confidence) for root, label, confidence in roots if _is_dir(root)]


def agent_dir():
    """Folder the agent runs from (the PyInstaller exe's folder, or the agent package)."""
    return Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]


def _protected_paths():
    env = os.environ
    windows = Path(env.get("SystemRoot", r"C:\Windows"))
    protected = {windows, storage_root(), agent_dir()}
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "SystemDrive"):
        if env.get(key):
            protected.add(Path(env[key] + ("\\" if key == "SystemDrive" else "")))
    return {_norm_path(path) for path in protected}


def _path_candidates(names, publisher, other_locations, roots):
    found, seen = [], set()
    protected = _protected_paths()
    storage = _norm_path(storage_root())
    publisher_norm = normalize(publisher)

    agent = _norm_path(agent_dir())

    def consider(path, label, confidence, reason):
        key = _norm_path(path)
        if key in seen or key in protected or _overlaps(path, other_locations | {storage, agent}):
            return
        seen.add(key)
        found.append({"kind": "folder" if _is_dir(path) else "file", "path": str(path), "location": label, "confidence": confidence, "reason": reason})

    for root, label, base_confidence in roots:
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            stem = child.stem if child.suffix.lower() == ".lnk" else child.name
            normalized = normalize(stem)
            if not normalized or normalized in GENERIC_NAMES:
                continue
            confidence = _confidence_for(normalized, names, publisher_norm)
            if confidence:
                kind = "shortcut" if child.suffix.lower() == ".lnk" else "folder"
                consider(child, label, base_confidence if confidence == "high" else "low", f"{kind} named like the program, in {label}")
            elif publisher_norm and normalized == publisher_norm and _is_dir(child):
                # Publisher\Product layout (e.g. AppData\Roaming\Adobe\Acrobat).
                try:
                    grandchildren = list(child.iterdir())
                except OSError:
                    continue
                for grandchild in grandchildren:
                    inner = normalize(grandchild.stem if grandchild.suffix.lower() == ".lnk" else grandchild.name)
                    if inner and inner not in GENERIC_NAMES and (inner in names or f"{normalized} {inner}" in names):
                        consider(grandchild, label, base_confidence, f"publisher folder {child.name}\\{grandchild.name} in {label}")
    # A bare first-word folder ("Docker", "Java") may still belong to other software: keep it only when it
    # sits in the same folder as a confident match for this program.
    confident_parents = {_norm_path(Path(item["path"]).parent) for item in found if item["confidence"] != "low"}
    return [item for item in found if item["confidence"] != "low" or _norm_path(Path(item["path"]).parent) in confident_parents]


def _registry_roots():
    import winreg

    # Users come only from HKU: HKCU is just an alias of the current user's HKU entry (scanning both lists
    # every key twice), and under the SYSTEM agent HKCU is SYSTEM's own profile.
    roots = [("HKLM", winreg.HKEY_LOCAL_MACHINE, "SOFTWARE", winreg.KEY_WOW64_64KEY),
             ("HKLM", winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node", winreg.KEY_WOW64_64KEY)]
    index = 0
    while True:
        try:
            sid = winreg.EnumKey(winreg.HKEY_USERS, index)
        except OSError:
            break
        index += 1
        if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
            roots.append(("HKU", winreg.HKEY_USERS, f"{sid}\\Software", 0))
    return roots


def _subkeys(winreg, hive, path, view):
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as key:
            names, index = [], 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                except OSError:
                    return names
                index += 1
    except OSError:
        return []


def _registry_candidates(names, publisher):
    import winreg

    found, seen = [], set()
    publisher_norm = normalize(publisher)
    for tag, hive, base, view in _registry_roots():
        for subkey in _subkeys(winreg, hive, base, view):
            normalized = normalize(subkey)
            if not normalized or normalized in GENERIC_NAMES:
                continue
            paths = []
            if normalized in names:
                paths.append((f"{base}\\{subkey}", "high"))
            elif publisher_norm and normalized == publisher_norm:
                for inner in _subkeys(winreg, hive, f"{base}\\{subkey}", view):
                    inner_norm = normalize(inner)
                    if inner_norm and inner_norm not in GENERIC_NAMES and (inner_norm in names or f"{normalized} {inner_norm}" in names):
                        paths.append((f"{base}\\{subkey}\\{inner}", "high"))
            for path, confidence in paths:
                full = f"{tag}\\{path}"
                if full.lower() not in seen:
                    seen.add(full.lower())
                    found.append({"kind": "registry", "path": full, "location": "Registry", "confidence": confidence if tag != "HKLM" or "WOW6432Node" not in path else "medium",
                                  "reason": "registry key named like the program"})
    return found


def _windows_other_locations(exclude_name):
    """Install folders of every other installed program (their files must never be offered)."""
    from . import software

    locations = set()
    for entry in software._windows_inventory():
        if entry["name"] == exclude_name:
            continue
        for folder in (entry.get("_install_location"), entry.get("_uninstall_dir")):
            if folder and len(str(folder)) > 3:
                locations.add(_norm_path(folder))
    return locations


# ---------------------------------------------------------------------------
# Linux scan
# ---------------------------------------------------------------------------

def _linux_candidates(package, homes=None, bases=("/etc", "/var/lib", "/var/log", "/opt")):
    found = []
    if homes is None:
        homes = [Path("/root")]
        try:
            homes += [item for item in Path("/home").iterdir() if _is_dir(item)]
        except OSError:
            pass
    places = [(Path(home) / sub / package, f"{sub} ({Path(home).name})", "medium") for home in homes for sub in (".config", ".local/share", ".cache")]
    places += [(Path(base) / package, str(base), "high") for base in bases]
    for path, label, confidence in places:
        if _exists(path):
            found.append({"kind": "folder" if _is_dir(path) else "file", "path": str(path), "location": label, "confidence": confidence, "reason": f"named exactly like the package, in {label}"})
    return found


# ---------------------------------------------------------------------------
# Quarantine helpers
# ---------------------------------------------------------------------------

def _size(path):
    target = Path(path)
    try:
        return directory_size(target, max_files=SIZE_SCAN_MAX_FILES) if _is_dir(target) else target.stat().st_size
    except OSError:
        return 0


def _modified(path):
    try:
        return datetime.fromtimestamp(Path(path).stat().st_mtime, timezone.utc).isoformat()
    except OSError:
        return None


def _reg(*args, timeout=60):
    try:
        result = subprocess.run(["reg", *args], capture_output=True, text=True, timeout=timeout, errors="replace",
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.returncode == 0, (result.stderr or result.stdout).strip()[:300]
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)


def _still_safe(candidate):
    """Re-check a cached candidate right before acting on it."""
    if candidate["kind"] == "registry":
        root = candidate["path"].split("\\", 1)[0]
        depth = candidate["path"].count("\\")
        return root in REGISTRY_ROOT_NAMES and depth >= 2 and normalize(candidate["path"].rsplit("\\", 1)[-1]) not in GENERIC_NAMES
    key = _norm_path(candidate["path"])
    storage = _norm_path(storage_root())
    return _exists(Path(candidate["path"])) and key not in _protected_paths() and not key.startswith(storage + os.sep) and key != storage


def _is_link(path):
    """A symlink, junction or any other reparse point (Python 3.11 cannot see junctions otherwise)."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _same_volume(first, second):
    try:
        return os.stat(first).st_dev == os.stat(second).st_dev
    except OSError:
        return False


SYSTEM_OWNERS = {"S-1-5-18", "S-1-5-32-544"}  # SYSTEM, Administrators


def _owner(path):
    """Owner of a file or folder: a SID string on Windows, a uid elsewhere; None when unknown."""
    if os_name() != "Windows":
        try:
            return os.lstat(path).st_uid
        except OSError:
            return None
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.POINTER(ctypes.c_void_p)
    advapi32.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, pointer, pointer, pointer, pointer, pointer]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, pointer]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    owner, descriptor, text = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    # SE_FILE_OBJECT = 1, OWNER_SECURITY_INFORMATION = 1
    if advapi32.GetNamedSecurityInfoW(str(path), 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(descriptor)) != 0:
        return None
    try:
        if not advapi32.ConvertSidToStringSidW(owner, ctypes.byref(text)):
            return None
        try:
            return ctypes.wstring_at(text.value)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(descriptor)


def _written_by_agent(path):
    """True when a scan or quarantine manifest was written by this agent (or an administrator), not planted
    by another user. Checked before trusting one, whatever the folder's permissions are."""
    if _is_link(path):
        return False
    owner = _owner(path)
    if owner is None:
        return False
    trusted = SYSTEM_OWNERS if os_name() == "Windows" else {0}
    return owner in trusted or owner == _owner(storage_root())


def _read_agent_json(path, default):
    return _read_json(path, default) if _written_by_agent(path) else default


def _has_links(path, limit=50000):
    """True if the item is, or contains, a symlink or junction (checked without following them), or is too big
    to check. Such items are never moved: a copy across drives, or anything that later walks the item as
    SYSTEM, would follow the link into wherever it points."""
    if _is_link(path):
        return True
    seen = 0
    for current, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            seen += 1
            if _is_link(os.path.join(current, name)) or seen > limit:
                return True
    return False


def _safe_name(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)[:60] or "item"


def purge_expired(older_than_days=QUARANTINE_DAYS):
    """Delete quarantine batches older than the restore window. Called by the agent once a day."""
    removed = []
    root = _quarantine_dir()
    if not _is_dir(root):
        return removed
    cutoff = time.time() - older_than_days * 86400
    for batch in root.iterdir():
        manifest = _read_agent_json(batch / "manifest.json", {})
        if manifest and _is_dir(batch) and not _is_link(batch) and BATCH_ID.match(batch.name) and manifest.get("created", time.time()) < cutoff:
            shutil.rmtree(batch, ignore_errors=True)
            removed.append(batch.name)
    return removed


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool("find_leftovers", "After a program was uninstalled, list folders, files, shortcuts and registry keys it left behind (preview only, nothing is changed).",
      params={"id": {"type": "string", "maxLength": 600, "description": "Inventory id of the uninstalled program"}}, required=("id",), timeout=300, ai_visible=False)
def find_leftovers(id):  # noqa: A002 - matches the tool's public parameter name
    system = os_name()
    record = _read_agent_json(_uninstalled_file(), {}).get(str(id))
    if system == "Windows":
        from . import software

        if not str(id).startswith("winget|") and software._windows_entry(str(id)) is not None:
            return {"ok": False, "summary": "This program is still installed. Uninstall it first, then look for leftovers."}
        if not record:
            return {"ok": False, "summary": "No uninstall of this program was recorded on this device, so AIops cannot tell what it left behind."}
        names = match_names(record)
        if not names:
            return {"ok": False, "summary": "The program's name is too generic to search for leftovers safely."}
        others = _windows_other_locations(record.get("name"))
        candidates = _path_candidates(names, record.get("publisher"), others, _windows_scan_roots())
        location = record.get("install_location")
        if location and _is_dir(Path(location)) and not _overlaps(location, others) and _norm_path(location) not in _protected_paths():
            if all(_norm_path(item["path"]) != _norm_path(location) for item in candidates):
                candidates.insert(0, {"kind": "folder", "path": location, "location": "Install folder", "confidence": "high", "reason": "the program's own install folder"})
        candidates += _registry_candidates(names, record.get("publisher"))
    elif system == "Linux":
        from . import software

        if not software.PACKAGE_NAME.match(str(id)):
            return {"ok": False, "summary": "Invalid package name"}
        if software._linux_installed(str(id)):
            return {"ok": False, "summary": "This package is still installed. Uninstall it first, then look for leftovers."}
        candidates = _linux_candidates(str(id))
        record = record or {"name": str(id)}
    else:
        return {"ok": False, "summary": "Leftover cleanup is not supported on macOS yet."}

    candidates = candidates[:MAX_CANDIDATES]
    for index, candidate in enumerate(candidates):
        candidate["id"] = f"c{index}"
        if candidate["kind"] != "registry":
            candidate["size"] = _size(candidate["path"])
            candidate["size_text"] = human_size(candidate["size"])
            candidate["modified"] = _modified(candidate["path"])
    scan_id = uuid.uuid4().hex[:12]
    _write_json(_scans_dir() / f"{scan_id}.json", {"created": time.time(), "program": record.get("name"), "entry_id": str(id), "candidates": candidates})
    total = sum(item.get("size", 0) for item in candidates)
    summary = f"{len(candidates)} leftover(s) of {record.get('name')} found ({human_size(total)})" if candidates else f"No leftovers of {record.get('name')} found"
    return {"ok": True, "summary": summary, "data": {"scan_id": scan_id, "program": record.get("name"), "candidates": candidates, "count": len(candidates), "total_size": total, "total_size_text": human_size(total)}}


@tool("quarantine_leftovers", "Move selected leftovers from this agent's last leftover scan into the quarantine (folders moved, registry keys exported to .reg then deleted). Restorable for 7 days.",
      risk="high", params={"scan_id": {"type": "string", "maxLength": 12, "description": "scan_id from find_leftovers"},
                           "candidate_ids": {"type": "string", "maxLength": 1000, "description": "Comma-separated candidate ids from that scan, e.g. c0,c2"}},
      required=("scan_id", "candidate_ids"), timeout=900, ai_visible=False)
def quarantine_leftovers(scan_id, candidate_ids):
    if not SCAN_ID.match(scan_id):
        return {"ok": False, "summary": "Invalid scan id"}
    scan_file = _scans_dir() / f"{scan_id}.json"
    scan = _read_agent_json(scan_file, None)
    if not scan or time.time() - scan.get("created", 0) > SCAN_TTL_SECONDS:
        return {"ok": False, "summary": "That leftover scan expired or is unknown on this device. Scan again."}
    wanted = [item.strip() for item in candidate_ids.split(",") if item.strip()]
    if not wanted or not all(CANDIDATE_ID.match(item) for item in wanted):
        return {"ok": False, "summary": "Invalid candidate ids"}
    by_id = {item["id"]: item for item in scan["candidates"]}
    unknown = [item for item in wanted if item not in by_id]
    if unknown:
        return {"ok": False, "summary": f"Unknown candidate ids for this scan: {', '.join(unknown)}"}

    batch_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    batch = _quarantine_dir() / batch_id
    batch.mkdir(parents=True, exist_ok=True)
    items = []
    for cid in wanted:
        candidate = by_id[cid]
        entry = {"id": cid, "kind": candidate["kind"], "original": candidate["path"], "stored": None, "ok": False, "error": None, "restored": False}
        if not _still_safe(candidate):
            entry["error"] = "skipped: no longer present or no longer safe to move"
        elif candidate["kind"] == "registry":
            stored = batch / f"{cid}.reg"
            ok, message = _reg("export", candidate["path"], str(stored), "/y")
            if ok:
                ok, message = _reg("delete", candidate["path"], "/f")
            entry.update(stored=str(stored), ok=ok, error=None if ok else message)
        elif _has_links(candidate["path"]):
            entry["error"] = "skipped: it contains a shortcut link or junction (or is too big to check for one); remove it by hand"
        elif candidate["kind"] == "folder" and not _same_volume(candidate["path"], batch):
            entry["error"] = "skipped: a folder on another drive than the quarantine would have to be copied; remove it by hand"
        else:
            stored = batch / f"{cid}_{_safe_name(Path(candidate['path']).name)}"
            try:
                shutil.move(candidate["path"], str(stored))
                entry.update(stored=str(stored), ok=True)
            except (OSError, shutil.Error) as error:
                entry["error"] = f"could not move (in use or access denied): {error}"[:300]
        items.append(entry)
    created = time.time()
    _write_json(batch / "manifest.json", {"batch_id": batch_id, "program": scan.get("program"), "entry_id": scan.get("entry_id"), "created": created, "items": items})
    try:
        scan_file.unlink()
    except OSError:
        pass
    moved = sum(1 for item in items if item["ok"])
    failed = [item for item in items if not item["ok"]]
    restore_until = datetime.fromtimestamp(created + QUARANTINE_DAYS * 86400, timezone.utc).isoformat()
    summary = f"Moved {moved} of {len(items)} leftover(s) of {scan.get('program')} to quarantine; restorable until {restore_until[:10]}"
    return {"ok": moved > 0, "changed": moved > 0, "summary": summary + (f"; {len(failed)} could not be moved" if failed else ""),
            "data": {"batch_id": batch_id, "moved": moved, "failed": failed, "restore_until": restore_until}}


@tool("restore_quarantine", "Put a quarantined batch of leftovers back where it was (folders moved back, registry keys re-imported).",
      risk="medium", params={"batch_id": {"type": "string", "maxLength": 40, "description": "Quarantine batch id"}}, required=("batch_id",), timeout=900, ai_visible=False)
def restore_quarantine(batch_id):
    if not BATCH_ID.match(batch_id):
        return {"ok": False, "summary": "Invalid batch id"}
    batch = _quarantine_dir() / batch_id
    manifest = _read_agent_json(batch / "manifest.json", None) if not _is_link(batch) else None
    if not manifest:
        return {"ok": False, "summary": "That quarantine batch does not exist (it may have expired)."}
    restored, failed = 0, []
    for item in manifest["items"]:
        if not item.get("ok") or item.get("restored"):
            continue
        stored = Path(item["stored"] or "")
        # Only files inside this batch are ever moved back.
        if not _exists(stored) or _norm_path(stored.parent) != _norm_path(batch):
            failed.append({**item, "error": "stored copy is missing"})
            continue
        if item["kind"] == "registry":
            exists, _ = _reg("query", item["original"])
            ok, message = (False, "the registry key exists again (was the program reinstalled?)") if exists else _reg("import", str(stored))
        elif _exists(Path(item["original"])):
            ok, message = False, "something already exists at the original location"
        elif _has_links(str(stored)):
            ok, message = False, "it now contains a shortcut link or junction; restore it by hand"
        else:
            try:
                Path(item["original"]).parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(stored), item["original"])
                # No permission changes: a move on the same drive keeps the item's own permissions, and a copy
                # across drives inherits them from the original folder.
                ok, message = True, ""
            except (OSError, shutil.Error) as error:
                ok, message = False, str(error)[:300]
        if ok:
            item["restored"] = True
            restored += 1
        else:
            failed.append({**item, "error": message})
    _write_json(batch / "manifest.json", manifest)
    if all(item.get("restored") or not item.get("ok") for item in manifest["items"]):
        shutil.rmtree(batch, ignore_errors=True)
    summary = f"Restored {restored} item(s) of {manifest.get('program')}" + (f"; {len(failed)} could not be restored" if failed else "")
    return {"ok": restored > 0 or not failed, "changed": restored > 0, "summary": summary, "data": {"restored": restored, "failed": failed}}


@tool("list_quarantine", "List quarantined leftover batches that can still be restored.", timeout=60, ai_visible=False)
def list_quarantine():
    purge_expired()
    root = _quarantine_dir()
    batches = []
    for batch in sorted(root.iterdir(), reverse=True) if _is_dir(root) else []:
        manifest = _read_agent_json(batch / "manifest.json", None) if not _is_link(batch) else None
        if not manifest or not BATCH_ID.match(batch.name):
            continue  # not a batch this agent wrote
        stored = [item for item in manifest["items"] if item.get("ok") and not item.get("restored")]
        created = manifest.get("created", 0)
        batches.append({
            "batch_id": batch.name, "program": manifest.get("program"), "created": datetime.fromtimestamp(created, timezone.utc).isoformat(),
            "expires": datetime.fromtimestamp(created + QUARANTINE_DAYS * 86400, timezone.utc).isoformat(), "items": len(stored),
            "size_text": human_size(sum(_size(item["stored"]) for item in stored if item["kind"] != "registry")),
            "paths": [item["original"] for item in stored][:20],
        })
    return {"ok": True, "summary": f"{len(batches)} quarantine batch(es)", "data": {"batches": batches, "days": QUARANTINE_DAYS}}
