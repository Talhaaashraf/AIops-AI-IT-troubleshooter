"""Read-only security observations. No arbitrary paths, shell execution or environment-file access."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET

import psutil

from .common import os_name
from .leftovers import agent_dir
from .registry import tool

_lock = threading.RLock()
HASH_LIMIT = 25
_candidates = {}
_transport = None
CHANNELS = ("Security", "System", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Windows Defender/Operational")


def scan_hashes(scan_id, items):
    """Hash only executable scan findings, with the same bounded path checks as process hashes.

    Works on its own candidate list, so it never holds or swaps the shared process-candidate state."""
    permitted = []
    for item in items[:100]:
        path = item.get("path") or ""
        if item.get("kind") == "malware" and item.get("on_disk") and Path(path).suffix.lower() in (".exe", ".dll", ".sys", ".com", ".scr", ".msi", ".bin", ".dylib", ".so") and _safe_path(path):
            permitted.append((f"scan:{scan_id}:{item['id']}", path))
    result = _hash_paths(permitted)
    for row in result["files"]:
        _, row["scan_id"], row["item_id"] = row.pop("process_id").split(":")
    return result


def _run(args, timeout=20):
    try:
        result = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=timeout,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os_name() == "Windows" else 0)
        return result.returncode, result.stdout[:500000]
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def features(text):
    """Return indicators, never raw command lines or potentially credential-bearing log text."""
    text = (text or "")[:32000].lower()
    patterns = {"encoded_shell": r"(?:powershell|pwsh).*(?:-enc\b|-encodedcommand)",
                "download_execute": r"(?:curl|wget|invoke-webrequest|\birm\b).*(?:\biex\b|invoke-expression|\|\s*(?:sh|bash))",
                "authentication_failure": r"failed password|authentication fail|failed logon|invalid user",
                "protection_tampering": r"(?:disable|stop).*(?:antivirus|defender|security service)",
                "log_cleared": r"audit log was cleared|clear-eventlog|wevtutil\s+cl"}
    return [name for name, pattern in patterns.items() if re.search(pattern, text)]


def _identity(source, data):
    return hashlib.sha256((source + json.dumps(data, sort_keys=True, default=str)).encode()).hexdigest()


def _safe_path(path):
    candidate = Path(path)
    blocked = {".ssh", ".aws", ".azure", ".gnupg", "credentials", "secrets"}
    if not candidate.is_absolute() or any(p.lower().startswith(".env") or p.lower() in blocked for p in candidate.parts):
        return False
    try:
        for parent in (candidate, *candidate.parents):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return False
        return stat.S_ISREG(candidate.stat().st_mode)
    except OSError:
        return False


@tool("security_processes", "Bounded process and connection observations with stable process identities and redacted command indicators.", timeout=30, ai_visible=False)
def process_snapshot():
    processes, networks, unavailable = [], [], []
    boot = int(psutil.boot_time())
    for process in psutil.process_iter(["pid", "ppid", "name", "exe", "create_time", "cmdline"], ad_value=None):
        if len(processes) >= 200:
            unavailable.append("Process inventory capped at 200 entries")
            break
        row = process.info
        identity = f"{boot}:{row['pid']}:{row.get('create_time')}"
        path = row.get("exe") or ""
        if path and _safe_path(path):
            with _lock:
                _candidates[identity] = path
                while len(_candidates) > 200:
                    _candidates.pop(next(iter(_candidates)))
        processes.append({"process_id": identity, "pid": row["pid"], "parent_pid": row.get("ppid"), "name": row.get("name"), "path": path,
                          "created_at": row.get("create_time"), "indicators": features(" ".join(row.get("cmdline") or []))})
    ids = {row["pid"]: row["process_id"] for row in processes}
    for row in processes:
        row["parent_process_id"] = ids.get(row.pop("parent_pid"))
    try:
        for connection in psutil.net_connections(kind="inet")[:500]:
            if connection.raddr:
                networks.append({"process_id": ids.get(connection.pid), "destination": connection.raddr.ip, "port": connection.raddr.port})
    except (psutil.AccessDenied, OSError):
        unavailable.append("Process-associated network connections unavailable")
    return {"ok": True, "summary": "Snapshot observations can miss short-lived activity", "data": {"processes": processes, "connections": networks, "gaps": unavailable, "mode": "snapshot", "boot": boot}}


@tool("security_hashes", "Hash only executable paths discovered by this agent's process snapshot. Never accepts a caller-supplied path.", timeout=30, ai_visible=False)
def executable_hashes():
    with _lock:
        candidates = list(_candidates.items())
    result = _hash_paths(candidates)
    return {"ok": True, "summary": f"Hashed {len(result['files'])} observed executables within a 10-second/256-MiB budget", "data": result}


def _hash_paths(candidates, limit=HASH_LIMIT):
    """Hash up to `limit` (identity, path) pairs within a 10-second/256-MiB budget. Holds no lock."""
    started, total, rows = time.monotonic(), 0, []
    eligible = len(candidates)
    candidates = candidates[:limit]
    for identity, path in candidates:
        if time.monotonic() - started > 10 or total >= 256 * 1024 ** 2:
            break
        if not _safe_path(path):
            continue
        try:
            before = os.stat(path, follow_symlinks=False)
            if before.st_size > min(100 * 1024 ** 2, 256 * 1024 ** 2 - total):
                continue
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            with os.fdopen(os.open(path, flags), "rb") as handle:
                opened = os.fstat(handle.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
                    continue
                digest = hashlib.sha256()
                while block := handle.read(1024 * 1024):
                    total += len(block)
                    if total > 256 * 1024 ** 2 or time.monotonic() - started > 10:
                        break
                    digest.update(block)
                else:
                    after = os.fstat(handle.fileno())
                    if (after.st_size, after.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns):
                        signature = {"status": "not collected (budget)"}
                        remaining = 10 - (time.monotonic() - started)
                        if remaining > 1:
                            if os_name() == "Windows":
                                code, signed = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-AuthenticodeSignature -LiteralPath '" + path.replace("'", "''") + "' | Select-Object Status | ConvertTo-Json -Compress"], timeout=min(2, remaining))
                                try:
                                    signature = {"status": json.loads(signed).get("Status"), "source": "Authenticode"} if code == 0 else {"status": "unavailable"}
                                except (ValueError, AttributeError):
                                    signature = {"status": "unavailable"}
                            elif os_name() == "Darwin":
                                code, _ = _run(["codesign", "--verify", "--strict", path], timeout=min(2, remaining))
                                signature = {"status": "verified" if code == 0 else "unsigned or verification unavailable", "source": "codesign"}
                        rows.append({"process_id": identity, "path": path, "sha256": digest.hexdigest(), "size": after.st_size, "signature": signature})
        except OSError:
            continue
    gaps = ["Signatures are budgeted and platform-dependent; a valid signature is not a safety verdict"]
    if eligible > limit:
        gaps.append(f"{eligible - limit} further executables were not hashed (limit {limit} per run)")
    return {"files": rows, "candidates": eligible, "deferred": eligible - len(rows), "gaps": gaps}


@tool("security_persistence", "Observe supported persistence metadata without reading environment files or executing entries.", timeout=30, ai_visible=False)
def persistence_snapshot():
    rows, gaps = [], []
    if os_name() == "Windows":
        script = "@{ services=@(Get-CimInstance Win32_Service | Select-Object -First 100 Name,StartMode,State); tasks=@(Get-ScheduledTask | Select-Object -First 100 TaskName,TaskPath,State) } | ConvertTo-Json -Compress -Depth 4"
        code, output = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        try:
            data = json.loads(output) if code == 0 else {}
            rows = [{"kind": kind, "details": row} for kind, values in data.items() for row in values]
        except (ValueError, AttributeError, TypeError):
            gaps.append("Service/task inventory unavailable")
        try:
            import winreg
            for hive, label in ((winreg.HKEY_LOCAL_MACHINE, "machine"), (winreg.HKEY_CURRENT_USER, "service-user")):
                with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                    for index in range(min(winreg.QueryInfoKey(key)[1], 100)):
                        name, value, _ = winreg.EnumValue(key, index)
                        rows.append({"kind": "Run", "scope": label, "name": name, "fingerprint": hashlib.sha256(str(value).encode()).hexdigest(), "indicators": features(str(value))})
        except OSError:
            gaps.append("Some Run-key scopes unavailable; interactive user hives are not all visible")
    else:
        roots = ("/etc/systemd/system", "/etc/cron.d", "/etc/cron.daily", "/etc/xdg/autostart") if os_name() == "Linux" else ("/Library/LaunchAgents", "/Library/LaunchDaemons", "/System/Library/LaunchAgents")
        for root in roots:
            try:
                for entry in list(Path(root).iterdir())[:100]:
                    if entry.name.startswith(".env") or entry.is_symlink():
                        continue
                    info = entry.stat()
                    rows.append({"kind": "persistence_file", "path": str(entry), "size": info.st_size, "modified": info.st_mtime_ns})
            except OSError:
                gaps.append(f"Unavailable: {root}")
        gaps.append("System persistence metadata only; user crontabs/login items and file contents are not collected")
    return {"ok": True, "summary": "Persistence observations; changes require review, not automatic malware classification", "data": {"entries": rows[:500], "gaps": gaps}}


def collect_events(cursors):
    events, coverage, next_cursors = [], {}, dict(cursors)
    if os_name() == "Windows":
        # Numeric bookmarks only; no user-supplied PowerShell expressions.
        for channel in CHANNELS:
            cursor = max(0, int(cursors.get(channel, 0)))
            script = f"$ErrorActionPreference='Stop';$n='{channel}';try{{$last=Get-WinEvent -LogName $n -MaxEvents 1;$c={cursor};$reset=$last.RecordId -lt $c;if($reset){{$c=0}};if($c -eq 0){{$c=[Math]::Max(0,$last.RecordId-100)}};$events=@(Get-WinEvent -LogName $n -FilterXPath \"*[System[EventRecordID > $c]]\" -Oldest -MaxEvents 100 -ErrorAction SilentlyContinue|ForEach-Object{{[pscustomobject]@{{id=$_.RecordId;event_id=$_.Id;time=$_.TimeCreated.ToUniversalTime().ToString('o');xml=$_.ToXml()}}}});@{{reset=$reset;events=$events;latest=$last.RecordId}}|ConvertTo-Json -Compress -Depth 4}}catch{{'{{\"error\":\"Log unavailable or access denied\"}}'}}"
            code, output = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=5)
            try:
                result = json.loads(output)
                if code or result.get("error"):
                    raise ValueError()
                generation = cursors.get(channel + ":generation", 0) + int(bool(result.get("reset")))
                for raw in result.get("events", []):
                    fields = {item.get("Name"): item.text or "" for item in ET.fromstring(raw["xml"]).iter() if item.tag.endswith("}Data")}
                    selected = {key: fields[key][:300] for key in ("Image", "ParentImage", "ProcessGuid", "ParentProcessGuid", "TargetFilename", "DestinationIp", "DestinationPort") if key in fields}
                    signals = features(fields.get("CommandLine", "") + " " + fields.get("ScriptBlockText", ""))
                    signals += {4625: ["authentication_failure"], 1102: ["log_cleared"], 7045: ["persistence_change"], 4698: ["persistence_change"], 5001: ["protection_tampering"]}.get(raw["event_id"], [])
                    events.append({"id": f"{channel}:{generation}:{raw['id']}", "source": channel, "event_id": raw["event_id"], "event_time": raw["time"], "indicators": signals, **selected})
                    next_cursors[channel] = raw["id"]
                next_cursors[channel + ":generation"] = generation
                coverage[channel] = {"available": True, "mode": "event", "reset": bool(result.get("reset")), "backlog": result.get("latest", 0) > next_cursors.get(channel, 0)}
            except (ValueError, TypeError, KeyError, ET.ParseError):
                coverage[channel] = {"available": False, "detail": "Source unavailable, permission denied or malformed output"}
    elif os_name() == "Linux":
        args = ["journalctl", "--no-pager", "-o", "json", "-n", "100"]
        cursor = cursors.get("journal")
        args += ["--after-cursor=" + str(cursor)] if cursor else ["--since=-5min"]
        code, output = _run(args)
        reset = False
        if code and cursor:
            code, output = _run(["journalctl", "--no-pager", "-o", "json", "-n", "100", "--since=-5min"])
            reset = True
        for line in output.splitlines():
            try:
                row = json.loads(line)
                cursor = row.get("__CURSOR")
                if not cursor:
                    continue
                events.append({"id": cursor, "source": "journal", "event_time": row.get("__REALTIME_TIMESTAMP"), "process": row.get("_COMM"), "boot": row.get("_BOOT_ID"), "indicators": features(row.get("MESSAGE", ""))})
                next_cursors["journal"] = cursor
            except (ValueError, TypeError):
                continue
        coverage["journal"] = {"available": code == 0, "mode": "event", "reset": reset, "gap_possible": len(events) >= 100, "detail": "Bounded journal tail; heavy traffic can exceed collection capacity"}
    else:
        code, output = _run(["log", "show", "--last", "1m", "--style", "ndjson", "--predicate", 'process == "sshd" OR process == "authd" OR process == "syspolicyd" OR process == "launchd"'])
        for line in output.splitlines()[:200]:
            try:
                row = json.loads(line)
                signals = features(row.get("eventMessage", ""))
                event = {"source": "unified-log", "event_time": row.get("timestamp"), "process": row.get("processImagePath"), "indicators": signals}
                event["id"] = _identity("macos", event)
                events.append(event)
            except (ValueError, TypeError):
                continue
        coverage["unified-log"] = {"available": code == 0, "mode": "overlapping-window", "detail": "Limited system logs; not Endpoint Security event coverage. Disconnections can leave gaps."}
    return events[:500], coverage, next_cursors


def state_db():
    root = Path(agent_dir()) / "security_state"
    root.mkdir(exist_ok=True)
    db = sqlite3.connect(root / "spool.db", timeout=5)
    db.execute("CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, body TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS batches (id TEXT PRIMARY KEY, created REAL, body TEXT)")
    return db


def enqueue_observations(kind):
    with state_db() as db:
        old = db.execute("SELECT body FROM state WHERE name='cursors'").fetchone()
        cursors = json.loads(old[0]) if old else {}
        if kind == "events":
            events, coverage, cursors = collect_events(cursors)
        else:
            result = process_snapshot() if kind == "processes" else persistence_snapshot()
            data = result["data"]
            events = [{"id": uuid.uuid4().hex, "source": kind, "event_time": time.time(), "snapshot": data}]
            coverage = {kind: {"available": result["ok"], "mode": "snapshot", "gaps": data.get("gaps", [])}}
        identity = uuid.uuid4().hex
        batch = {"id": identity, "events": events, "coverage": coverage}
        db.execute("INSERT OR REPLACE INTO state VALUES ('cursors',?)", (json.dumps(cursors),))
        db.execute("INSERT INTO batches VALUES (?,?,?)", (identity, time.time(), json.dumps(batch)))
        # Bound by count and bytes. Drop oldest with an explicit coverage notice.
        dropped = 0
        while db.execute("SELECT COUNT(*) FROM batches").fetchone()[0] > 1000 or db.execute("SELECT COALESCE(SUM(LENGTH(body)),0) FROM batches").fetchone()[0] > 20 * 1024 ** 2:
            db.execute("DELETE FROM batches WHERE id=(SELECT id FROM batches ORDER BY created LIMIT 1)")
            dropped += 1
        if dropped:
            batch["coverage"]["spool"] = {"available": False, "dropped_batches": dropped}
            db.execute("UPDATE batches SET body=? WHERE id=?", (json.dumps(batch), identity))
    return batch


@tool("security_capabilities", "Report collection coverage; does not install or enable operating-system auditing.", ai_visible=False)
def capabilities():
    return {"ok": True, "summary": "Capabilities depend on available permissions and event sources", "data": {"version": 1, "os": os_name(), "process_network": "snapshot", "events": "native-logs", "hashing": "observed-executables-only", "signatures": "budgeted Authenticode/codesign; unavailable on Linux", "advanced_macos": "not installed", "env_access": False}}


@tool("security_events", "Collect a bounded incremental security event batch with coverage and durable bookmarks.", timeout=35, ai_visible=False)
def event_snapshot():
    with _lock:
        batch = enqueue_observations("events")
    return {"ok": True, "summary": "Event collection completed; review source coverage", "data": batch}


@tool("security_sample_transfer", "Transfer one explicitly approved, unchanged trusted scan item to the Sentinel HTTPS server; never to a provider directly.", risk="medium", ai_visible=False, timeout=90,
      params={"scan_id": {"type": "string", "maxLength": 12}, "item_id": {"type": "string", "maxLength": 32}, "sha256": {"type": "string", "maxLength": 64}, "transfer_id": {"type": "string", "maxLength": 64}}, required=("scan_id", "item_id", "sha256", "transfer_id"))
def transfer_sample(scan_id, item_id, sha256, transfer_id):
    from .threats import _scan_item
    import requests
    if not _transport or not _transport[0].startswith("https://") or not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        return {"ok": False, "summary": "Sample transfer requires a configured HTTPS server and valid hash"}
    item, reason = _scan_item(scan_id, item_id)
    if reason or not _safe_path(item["path"]):
        return {"ok": False, "summary": reason or "Sensitive, linked or inaccessible file refused"}
    try:
        before = os.stat(item["path"], follow_symlinks=False)
        if before.st_size > 32 * 1024 ** 2:
            return {"ok": False, "summary": "Sample exceeds 32 MiB"}
        with os.fdopen(os.open(item["path"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)), "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return {"ok": False, "summary": "File changed before transfer"}
            content = handle.read(32 * 1024 ** 2 + 1)
        if len(content) > 32 * 1024 ** 2 or hashlib.sha256(content).hexdigest() != sha256.lower():
            return {"ok": False, "summary": "File changed; a new hash and approval are required"}
        response = requests.post(_transport[0].rstrip("/") + "/api/agents/security/sample-transfer", headers={"Authorization": "Bearer " + _transport[1], "X-Transfer-Id": transfer_id}, files={"file": (sha256 + ".bin", content)}, timeout=40, allow_redirects=False)
        if response.status_code != 200:
            return {"ok": False, "summary": "Server rejected the transfer; no provider upload occurred"}
        return {"ok": True, "summary": "Sample staged on Sentinel; provider upload still requires its separate approval", "data": response.json()}
    except (OSError, requests.RequestException):
        return {"ok": False, "summary": "Sample transfer failed; check its status before retrying"}
