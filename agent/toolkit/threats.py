"""Endpoint threat detection: what the antivirus found and the security events worth a look, read from the
device's own logs, plus the actions a person can approve on one finding (rescan, quarantine, delete).

threat_scan is read-only. It reads Kaspersky Endpoint Security, the Kaspersky Network Agent log, Microsoft
Defender, the Windows Security / System / PowerShell logs (Linux: sshd/sudo/useradd and ClamAV; macOS: sshd and
sudo), groups what belongs together (606 detections inside one ISO are one item) and writes a scan file.

The server only ever sends a scan id and an item id. The path an action works on always comes from this agent's
own scan file, never from the server (the rule leftovers.py follows). A quarantined threat goes into the leftovers
quarantine, so the Software tab's Restore puts it back.
"""

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import leftovers
from .common import is_admin, os_name
from .registry import tool
from .software import _run, _tail

SCAN_TTL_SECONDS = 6 * 3600
MAX_ITEMS = 60
MAX_OBJECTS = 5
FIELD_MAX_CHARS = 300
DATA_LIMIT = 120_000  # well under the server's 200 KB task-result cap
SCAN_ID = re.compile(r"^[0-9a-f]{12}$")
ITEM_ID = re.compile(r"^d\d{1,3}$")
SCAN_TIMEOUT = 150
RESCAN_TIMEOUT = 1800

# The order items are listed (and cut, when there are too many): what needs a person first.
KIND_PRIORITY = {
    "malware": 0, "av_disabled": 1, "log_cleared": 2, "av_report_cleared": 2, "group_member_added": 3, "user_created": 4, "powershell_suspicious": 5,
    "service_installed": 6, "task_created": 7, "lockout": 8, "failed_logon": 9, "sudo_failure": 9,
    "av_settings_changed": 10, "av_update_failed": 11, "av_health": 12,
}
LOGON_TYPES = {"2": "interactive (at the keyboard)", "3": "network (file share, SMB)", "4": "batch", "5": "service", "7": "unlock",
               "8": "network, clear-text password", "10": "remote desktop (RDP)", "11": "cached credentials"}

# One PowerShell process reads every channel. Each log is probed first: for a non-administrator, Get-WinEvent
# answers "No events were found" for the Security log, which must never read as "clean".
# The script must never contain attack words (POWERSHELL_ATTACK_SIGNS is matched in Python): the antivirus scans
# every script PowerShell runs, and one with such words looks like an attack, so the agent itself gets blocked.
WINDOWS_SCRIPT = r"""
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$since = (Get-Date).AddHours(-__HOURS__)
$sources = New-Object System.Collections.ArrayList
$events = New-Object System.Collections.ArrayList
function Fields($e) {
  $x = [xml]$e.ToXml(); $d = @{}
  if ($x.Event.EventData) { $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = [string]$_.'#text' } } }
  if ($x.Event.UserData) { foreach ($node in $x.Event.UserData.FirstChild.ChildNodes) { $d[$node.LocalName] = [string]$node.InnerText } }
  $d
}
function Pick($d, $names) { $k = [ordered]@{}; foreach ($n in $names) { if ($d[$n]) { $k[$n] = $d[$n] } }; $k }
function Probe($log) {
  try { [void][System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation($log, [System.Diagnostics.Eventing.Reader.PathType]::LogName); return $null }
  catch {
    $inner = $_.Exception.InnerException
    if ($inner -is [UnauthorizedAccessException]) { return 'access denied: the agent must run as SYSTEM or an administrator' }
    if ($inner -is [System.Diagnostics.Eventing.Reader.EventLogNotFoundException]) { return 'not on this device' }
    return [string]$_.Exception.Message
  }
}
function Source($label, $log, $ok, $count, $detail) { [void]$sources.Add([pscustomobject]@{ name = $label; log = $log; available = $ok; count = $count; detail = $detail }) }
function Read-Log($label, $log, $filter, $max, $shape) {
  $problem = Probe $log
  if ($problem) { Source $label $log $false 0 $problem; return }
  $filter.LogName = $log; $filter.StartTime = $since
  try { $rows = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $max -ErrorAction Stop | ForEach-Object -Process $shape) }
  catch {
    if ([string]$_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { Source $label $log $false 0 ([string]$_.Exception.Message); return }
    $rows = @()
  }
  foreach ($row in $rows) { [void]$events.Add($row) }
  Source $label $log $true $rows.Count $(if ($rows.Count -ge $max) { "only the newest $max events were read" } else { '' })
}
Read-Log 'Kaspersky Endpoint Security' 'Kaspersky Endpoint Security' @{} 3000 {
  $text = if ($_.Properties.Count) { [string]$_.Properties[0].Value } else { [string]$_.Message }
  [pscustomobject]@{ src = 'kes'; id = $_.Id; t = $_.TimeCreated.ToString('o'); text = $text } }
$problem = Probe 'Kaspersky Event Log'
if ($problem) { Source 'Kaspersky Network Agent' 'Kaspersky Event Log' $false 0 $problem }
else {
  try { $raw = @(Get-WinEvent -FilterHashtable @{ LogName = 'Kaspersky Event Log'; Level = 1, 2; StartTime = $since } -MaxEvents 3000 -ErrorAction Stop) }
  catch { $raw = @() }
  $groups = @($raw | Group-Object ProviderName, Id | ForEach-Object {
    $f = $_.Group[0]; $lines = @(([string]$f.Message) -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 2)
    [pscustomobject]@{ src = 'kel'; id = $f.Id; provider = $f.ProviderName; count = $_.Count; t = $f.TimeCreated.ToString('o'); first = $_.Group[-1].TimeCreated.ToString('o'); text = ($lines -join ' ') } })
  foreach ($row in $groups) { [void]$events.Add($row) }
  Source 'Kaspersky Network Agent' 'Kaspersky Event Log' $true $raw.Count ''
}
Read-Log 'Microsoft Defender' 'Microsoft-Windows-Windows Defender/Operational' @{ Id = 1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 2001, 2003, 5001, 5010, 5012, 5013 } 300 {
  [pscustomobject]@{ src = 'defender'; id = $_.Id; t = $_.TimeCreated.ToString('o'); f = (Pick (Fields $_) @('Threat Name', 'Severity Name', 'Category Name', 'Path', 'Detection User', 'Process Name', 'Action Name', 'Error Description', 'Feature Name', 'Value')) } }
Read-Log 'Windows Security log' 'Security' @{ Id = 4625, 4740, 4720, 4728, 4732, 4756, 1102, 4697, 4698 } 2000 {
  [pscustomobject]@{ src = 'security'; id = $_.Id; t = $_.TimeCreated.ToString('o'); f = (Pick (Fields $_) @('TargetUserName', 'TargetDomainName', 'IpAddress', 'LogonType', 'WorkstationName', 'SubjectUserName', 'MemberName', 'MemberSid', 'ServiceName', 'ServiceFileName', 'TaskName', 'Status', 'SubStatus')) } }
Read-Log 'Windows System log' 'System' @{ Id = 7045, 104 } 200 {
  [pscustomobject]@{ src = 'system'; id = $_.Id; t = $_.TimeCreated.ToString('o'); f = (Pick (Fields $_) @('ServiceName', 'ImagePath', 'StartType', 'AccountName', 'Channel', 'SubjectUserName')) } }
# Level 3 (warning) script blocks are the ones PowerShell itself flags as suspicious, logged even without a policy.
Read-Log 'PowerShell' 'Microsoft-Windows-PowerShell/Operational' @{ Id = 4104; Level = 3 } 300 {
  $d = Fields $_; $text = [string]$d.ScriptBlockText
  [pscustomobject]@{ src = 'powershell'; id = $_.Id; t = $_.TimeCreated.ToString('o'); f = [ordered]@{ ScriptBlockText = $text.Substring(0, [Math]::Min(3000, $text.Length)); Path = [string]$d.Path } } }
$av = @()
try { $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
  $state = [int]$_.productState; [pscustomobject]@{ name = $_.displayName; enabled = ((($state -shr 12) -band 0xF) -eq 1); up_to_date = ((($state -shr 4) -band 0xF) -eq 0) } }) } catch { }
[pscustomobject]@{ sources = $sources; events = $events; antivirus = $av } | ConvertTo-Json -Compress -Depth 5
"""

# Signs of an attack in a PowerShell script block: encoded commands, download-and-run, turning off or bypassing
# protection (AMSI, Defender exclusions), credential theft, code injection. Matched here in Python, never inside a
# PowerShell script (see WINDOWS_SCRIPT). PowerShell's own warning flag also fires on harmless Windows modules.
POWERSHELL_ATTACK_SIGNS = re.compile(
    r"(?i)(-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|FromBase64String|DownloadString|DownloadFile|DownloadData|Net\.WebClient"
    r"|\|\s*(?:iex|Invoke-Expression)\b|\biex\s*\(|-ExecutionPolicy\s+Bypass|\s-ep\s+bypass|Add-MpPreference[^\r\n]*-Exclusion"
    r"|Set-MpPreference[^\r\n]*-Disable|\bamsi\w*|mimikatz|sekurlsa|Invoke-Shellcode|Reflection\.Assembly\]::Load|VirtualAlloc)")
# AIops' own install command ("irm .../install/windows.ps1 | iex") downloads and runs a script too.
AIOPS_INSTALL = re.compile(r"/install/(?:windows|linux|macos)\.(?:ps1|sh)")


def powershell_attack_signs(script):
    """The distinct attack signs in a script block (at most 5), or [] for a harmless one."""
    if not script or AIOPS_INSTALL.search(script):
        return []
    signs = []
    for match in POWERSHELL_ATTACK_SIGNS.finditer(script):
        sign = " ".join(match.group(0).split())
        if sign.lower() not in (item.lower() for item in signs):
            signs.append(sign[:60])
        if len(signs) == 5:
            break
    return signs


LINUX_AUTH = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"), "failed_logon"),
    (re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"), "failed_logon"),
    (re.compile(r"authentication error for (?:illegal user )?(?P<user>\S+) from (?P<ip>\S+)"), "failed_logon"),  # macOS sshd
    (re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*?\buser=(?P<user>\S+)"), "sudo_failure"),
    (re.compile(r"^\s*(?P<user>\S+) : (?:\d+ )?incorrect password attempts?"), "sudo_failure"),
    (re.compile(r"new user: name=(?P<user>[^,\s]+)"), "user_created"),
    (re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>sudo|wheel|admin|root)'"), "group_member_added"),
    (re.compile(r"user (?P<user>\S+) added by \S+ to group (?P<group>sudo|wheel|admin|root)\b"), "group_member_added"),
]
CLAMAV_FOUND = re.compile(r"(?:(?P<t>\w{3} \w{3}\s+\d+ [\d:]+ \d{4}) -> )?(?P<path>/.+?): (?P<name>\S+) FOUND")
SYSLOG_TIME = re.compile(r"^(?P<t>\w{3}\s+\d+ [\d:]{8}) ")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _clip(value, limit=FIELD_MAX_CHARS):
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _time(text):
    """A UTC datetime from PowerShell's 'o' format (7 fraction digits), ISO text or epoch seconds; None if unreadable."""
    if text is None or text == "":
        return None
    if isinstance(text, (int, float)):
        return datetime.fromtimestamp(text, timezone.utc)
    value = re.sub(r"(\.\d{6})\d+", r"\1", str(text).strip()).replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).isoformat() if moment else None


def peak_per_hour(moments):
    """The most events inside any 60-minute window."""
    stamps = sorted(moment.timestamp() for moment in moments if moment)
    best, start = 0, 0
    for end, stamp in enumerate(stamps):
        while stamp - stamps[start] > 3600:
            start += 1
        best = max(best, end - start + 1)
    return best


def parse_kaspersky(text):
    """'Key: Value' lines of a Kaspersky Endpoint Security event into a dict (first value wins)."""
    fields = {}
    for line in str(text or "").splitlines():
        key, separator, value = line.partition(":")
        key = key.strip()
        if separator and key and len(key) <= 40 and not key.startswith(("\\", "/")):
            fields.setdefault(key, value.strip())
    return fields


def split_container(path, object_name=None):
    """(file on disk, path inside it or None). Kaspersky writes 'C:\\x.iso//inner//deeper'; Defender 'C:\\x.zip->inner'."""
    text = str(path or "").strip()
    for marker in ("//", "->"):
        if marker in text:
            outer, inner = text.split(marker, 1)
            inner = inner.replace("//", " > ")
            return outer.strip(), (f"{inner}/{object_name}" if object_name and not inner.endswith(object_name) else inner).strip()
    if object_name and text and not os.path.basename(text.rstrip("\\/")).lower() == object_name.lower():
        joined = os.path.join(text, object_name)
        if os.path.isfile(joined) or not os.path.isfile(text):
            return joined, None
    return (text or object_name or "").strip(), None


def _on_disk(path):
    try:
        return bool(path) and os.path.isfile(path)
    except (OSError, ValueError):
        return False


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _running(paths):
    """{normalised exe path: [{pid, name}]} for processes started from one of these files."""
    wanted = {leftovers._norm_path(path) for path in paths if path}
    found = {}
    if not wanted:
        return found
    try:
        import psutil
    except ImportError:
        return found
    for process in psutil.process_iter(["pid", "name", "exe"]):
        exe = process.info.get("exe")
        if exe and leftovers._norm_path(exe) in wanted:
            found.setdefault(leftovers._norm_path(exe), []).append({"pid": process.info["pid"], "name": process.info.get("name") or os.path.basename(exe)})
    return found


class _Groups:
    """Collects events into items keyed by what they are about (a file, an account and source address, ...)."""

    def __init__(self):
        self.items = {}

    def add(self, key, kind, source, event_id, moment, fields, path=None, inner=None, extra=None):
        item = self.items.get(key)
        if item is None:
            item = self.items[key] = {"kind": kind, "source": source, "event_ids": [], "count": 0, "times": [], "fields": {},
                                      "path": path, "objects": [], "names": Counter(), "results": Counter()}
        item["count"] += 1
        if event_id not in item["event_ids"]:
            item["event_ids"].append(event_id)
        item["times"].append(moment)
        for name, value in (fields or {}).items():
            if value not in (None, "") and name not in item["fields"]:
                item["fields"][name] = _clip(value)
        if inner and inner not in item["objects"] and len(item["objects"]) < MAX_OBJECTS:
            item["objects"].append(_clip(inner, 240))
        for name, value in (extra or {}).items():
            if value:
                item[name][value] += 1
        return item

    def finish(self):
        items = []
        for item in self.items.values():
            times = [moment for moment in item.pop("times") if moment]
            names, results = item.pop("names"), item.pop("results")
            item.update(first_seen=_iso(min(times)) if times else None, last_seen=_iso(max(times)) if times else None)
            if item["kind"] in ("failed_logon", "sudo_failure"):
                item["peak_per_hour"] = peak_per_hour(times)
            if names:
                item["threats"] = [{"name": name, "count": count} for name, count in names.most_common(5)]
                item["fields"]["Threat"] = names.most_common(1)[0][0] + (f" (+{len(names) - 1} other threat names)" if len(names) > 1 else "")
            if results:
                item["results"] = dict(results.most_common(5))
                item["fields"]["Result"] = results.most_common(1)[0][0]
            items.append(item)
        return items


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

def _kes_kind(fields, text):
    event_type = (fields.get("Event type") or "").lower()
    if re.search(r"protection|component|self-defense|application", event_type) and re.search(r"disabled|turned off|paused|stopped", event_type):
        return "av_disabled"
    if "settings changed" in event_type:
        return "av_settings_changed"
    if "report" in event_type and re.search(r"clear|delet", event_type):
        return "av_report_cleared"
    if re.search(r"malicious|detected|infected|disinfect|deleted|quarantin|blocked|dangerous|suspicious|intruders", event_type) and (fields.get("Path to object") or fields.get("Object name")):
        return "malware"
    if "kaspersky security network" in text.lower() and "disabled" in text.lower():
        return "ksn_off"
    return None


def _add_kaspersky(groups, event):
    text = event.get("text") or ""
    fields = parse_kaspersky(text)
    kind = _kes_kind(fields, text)
    moment = _time(event.get("t"))
    if kind == "malware":
        path, inner = split_container(fields.get("Path to object"), fields.get("Object name"))
        groups.add(("kes", path.lower()), "malware", "Kaspersky Endpoint Security", event.get("id"), moment, {
            "Type": fields.get("Type"), "Detected by": f"Kaspersky Endpoint Security ({fields.get('Component') or 'protection'})",
            "Threat level": fields.get("Threat level"), "Precision": fields.get("Precision"), "Reason": fields.get("Reason"),
            "User": fields.get("User"), "SHA256": fields.get("SHA256"), "MD5": fields.get("MD5"), "Database date": fields.get("Database release date"),
        }, path=path, inner=inner, extra={"names": fields.get("Name"), "results": fields.get("Result description")})
    elif kind == "av_report_cleared":
        # One event per cleared record type (1549 at once is normal): one item per kind of report.
        groups.add(("kes", kind, fields.get("Object")), kind, "Kaspersky Endpoint Security", event.get("id"), moment,
                   {"Event": fields.get("Event type"), "Reports": fields.get("Object"), "Cleared by": fields.get("User"),
                    "With": f"{fields.get('Name')} ({fields.get('Application path')})" if fields.get("Name") else None})
    elif kind in ("av_disabled", "av_settings_changed"):
        groups.add(("kes", kind, fields.get("Event type")), kind, "Kaspersky Endpoint Security", event.get("id"), moment,
                   {"Event": fields.get("Event type"), "User": fields.get("User"), "Component": fields.get("Component"), "Detail": fields.get("Result description")})
    elif kind == "ksn_off":
        groups.add(("kes", "ksn"), "av_health", "Kaspersky Endpoint Security", event.get("id"), moment,
                   {"Problem": "Kaspersky Security Network (cloud reputation checks) is turned off", "Event": _clip(text, 200)})


DEFENDER_DETECTIONS = {1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119}


def _defender_path(raw):
    for part in str(raw or "").split(";"):
        part = part.strip()
        if part.lower().startswith("file:_"):
            return part[6:]
    return str(raw or "").split(";")[0].strip()


def _add_windows_event(groups, event):
    source, event_id, fields, moment = event.get("src"), event.get("id"), event.get("f") or {}, _time(event.get("t"))
    if source == "defender":
        if event_id in DEFENDER_DETECTIONS:
            path, inner = split_container(_defender_path(fields.get("Path")))
            result = "Detected" if event_id in (1006, 1116, 1015) else f"Action taken: {fields.get('Action Name') or 'removed'}" if event_id in (1007, 1117) else f"Action failed: {fields.get('Error Description') or fields.get('Action Name') or 'unknown error'}"
            groups.add(("defender", path.lower()), "malware", "Microsoft Defender", event_id, moment, {
                "Type": fields.get("Category Name"), "Detected by": "Microsoft Defender", "Threat level": fields.get("Severity Name"),
                "User": fields.get("Detection User"), "Process": fields.get("Process Name"),
            }, path=path, inner=inner, extra={"names": fields.get("Threat Name"), "results": result})
        elif event_id in (5001, 5010, 5012):
            what = {5001: "real-time protection", 5010: "spyware scanning", 5012: "virus scanning"}[event_id]
            groups.add(("defender", "off", event_id), "av_disabled", "Microsoft Defender", event_id, moment, {"Event": f"Microsoft Defender {what} was turned off"})
        elif event_id == 5013:
            groups.add(("defender", "tamper"), "av_settings_changed", "Microsoft Defender", event_id, moment, {"Event": "Tamper protection blocked a change to Defender settings", "Setting": fields.get("Value")})
        elif event_id in (2001, 2003):
            groups.add(("defender", "update"), "av_update_failed", "Microsoft Defender", event_id, moment, {"Event": "Microsoft Defender could not update", "Error": fields.get("Error Description")})
    elif source == "kel":
        component = {"klnagent": "Kaspersky Network Agent", "klsecuritycenter": "Kaspersky Security Center"}.get(str(event.get("provider")).lower(), event.get("provider"))
        item = groups.add(("kel", event.get("provider"), event_id), "av_health", component or "Kaspersky", event_id, moment, {"Component": component, "Message": event.get("text")})
        item["count"] += max(0, int(event.get("count") or 1) - 1)
        item["times"].append(_time(event.get("first")))
    elif source == "security":
        user = fields.get("TargetUserName") or "?"
        account = f"{fields['TargetDomainName']}\\{user}" if fields.get("TargetDomainName") and event_id != 4740 else user
        if event_id == 4625:
            ip = fields.get("IpAddress") or "-"
            groups.add(("logon", user.lower(), ip), "failed_logon", "Windows Security log", event_id, moment, {
                "Account": account, "Source address": ip, "Logon type": LOGON_TYPES.get(str(fields.get("LogonType")), fields.get("LogonType")),
                "Workstation": fields.get("WorkstationName"), "Failure code": fields.get("SubStatus") or fields.get("Status")})
        elif event_id == 4740:
            groups.add(("lockout", user.lower()), "lockout", "Windows Security log", event_id, moment, {"Account": user, "Locked out from": fields.get("TargetDomainName")})
        elif event_id == 4720:
            groups.add(("user", user.lower()), "user_created", "Windows Security log", event_id, moment, {"New account": account, "Created by": fields.get("SubjectUserName")})
        elif event_id in (4728, 4732, 4756):
            member = fields.get("MemberName") or fields.get("MemberSid") or "?"
            groups.add(("group", member.lower(), user.lower()), "group_member_added", "Windows Security log", event_id, moment,
                       {"Member": member, "Group": user, "Added by": fields.get("SubjectUserName")})
        elif event_id == 1102:
            groups.add(("cleared", "security"), "log_cleared", "Windows Security log", event_id, moment, {"Log": "Security", "Cleared by": fields.get("SubjectUserName")})
        elif event_id == 4697:
            groups.add(("service", (fields.get("ServiceName") or "").lower()), "service_installed", "Windows Security log", event_id, moment,
                       {"Service": fields.get("ServiceName"), "Program": fields.get("ServiceFileName"), "Installed by": fields.get("SubjectUserName")})
        elif event_id == 4698:
            groups.add(("task", (fields.get("TaskName") or "").lower()), "task_created", "Windows Security log", event_id, moment, {"Task": fields.get("TaskName"), "Created by": fields.get("SubjectUserName")})
    elif source == "system":
        if event_id == 7045:
            groups.add(("service", (fields.get("ServiceName") or "").lower()), "service_installed", "Windows System log", event_id, moment, {
                "Service": fields.get("ServiceName"), "Program": fields.get("ImagePath"), "Runs as": fields.get("AccountName"), "Start type": fields.get("StartType")})
        elif event_id == 104:
            groups.add(("cleared", (fields.get("Channel") or "").lower()), "log_cleared", "Windows System log", event_id, moment, {"Log": fields.get("Channel"), "Cleared by": fields.get("SubjectUserName")})
    elif source == "powershell":
        script = fields.get("ScriptBlockText") or ""
        signs = powershell_attack_signs(script)
        if signs:
            groups.add(("ps", fields.get("Path") or script[:80]), "powershell_suspicious", "PowerShell", event_id, moment,
                       {"Attack signs": ", ".join(signs), "Script": _clip(script, 240), "Script file": fields.get("Path")})


def _collect_windows(hours):
    from .updates import _powershell_json

    raw = _powershell_json(WINDOWS_SCRIPT.replace("__HOURS__", str(int(hours))), SCAN_TIMEOUT)
    if "error" in raw and "sources" not in raw:
        return [{"name": "Windows event logs", "available": False, "count": 0, "detail": raw["error"]}], [], []
    groups = _Groups()
    for event in raw.get("events") or []:
        if not isinstance(event, dict):
            continue
        if event.get("src") == "kes":
            _add_kaspersky(groups, event)
        else:
            _add_windows_event(groups, event)
    sources = [{key: source.get(key) for key in ("name", "log", "available", "count", "detail")} for source in raw.get("sources") or [] if isinstance(source, dict)]
    antivirus = [item for item in raw.get("antivirus") or [] if isinstance(item, dict)]
    return sources, groups.finish(), antivirus


# ---------------------------------------------------------------------------
# Linux and macOS
# ---------------------------------------------------------------------------

def _add_auth_line(groups, message, moment, source):
    for pattern, kind in LINUX_AUTH:
        match = pattern.search(message)
        if not match:
            continue
        found = match.groupdict()
        user = found.get("user") or "?"
        if kind == "failed_logon":
            groups.add(("logon", user.lower(), found.get("ip")), kind, source, "sshd", moment, {"Account": user, "Source address": found.get("ip"), "Logon type": "SSH"})
        elif kind == "sudo_failure":
            groups.add(("sudo", user.lower()), kind, source, "sudo", moment, {"Account": user, "What": "wrong password for sudo"})
        elif kind == "user_created":
            groups.add(("user", user.lower()), kind, source, "useradd", moment, {"New account": user})
        else:
            groups.add(("group", user.lower(), found.get("group")), kind, source, "usermod", moment, {"Member": user, "Group": found.get("group")})
        return


def _journal_auth(hours, groups):
    code, out, err = _run(["journalctl", f"--since=-{int(hours)}h", "-o", "json", "--no-pager", "-n", "5000",
                           "_COMM=sshd", "_COMM=sudo", "_COMM=useradd", "_COMM=usermod", "_COMM=gpasswd"], 60)
    if code != 0:
        return None, _tail(err, 200) or f"journalctl exit code {code}"
    count = 0
    for line in out.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("MESSAGE")
        if isinstance(message, list):  # binary messages come as a list of byte values
            message = bytes(value for value in message if isinstance(value, int) and 0 <= value < 256).decode("utf-8", "replace")
        try:
            moment = datetime.fromtimestamp(int(entry.get("__REALTIME_TIMESTAMP")) / 1_000_000, timezone.utc)
        except (TypeError, ValueError):
            moment = None
        count += 1
        _add_auth_line(groups, str(message or ""), moment, "Auth log")
    return count, None


def _file_auth(hours, groups):
    """Debian/Ubuntu auth.log or RHEL secure, for systems without a persistent journal."""
    path = next((candidate for candidate in ("/var/log/auth.log", "/var/log/secure") if os.path.isfile(candidate)), None)
    if not path:
        return None, "no journal entries and no /var/log/auth.log or /var/log/secure"
    try:
        with open(path, "rb") as handle:
            handle.seek(max(0, os.path.getsize(path) - 2_000_000))
            lines = handle.read().decode("utf-8", "replace").splitlines()
    except OSError as error:
        return None, f"cannot read {path}: {error}"
    cutoff, now, count = time.time() - hours * 3600, datetime.now(timezone.utc), 0
    for line in lines:
        match = SYSLOG_TIME.match(line)
        moment = None
        if match:
            try:
                moment = datetime.strptime(f"{now.year} {match.group('t')}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                moment = None
        if moment and moment.timestamp() < cutoff:
            continue
        count += 1
        _add_auth_line(groups, line, moment, "Auth log")
    return count, None


def _clamav(hours, groups):
    path = "/var/log/clamav/clamav.log"
    if not os.path.isfile(path):
        return {"name": "ClamAV", "available": False, "count": 0, "detail": "not on this device"}
    cutoff, count = time.time() - hours * 3600, 0
    try:
        with open(path, "rb") as handle:
            handle.seek(max(0, os.path.getsize(path) - 2_000_000))
            lines = handle.read().decode("utf-8", "replace").splitlines()
    except OSError as error:
        return {"name": "ClamAV", "available": False, "count": 0, "detail": f"cannot read {path}: {error}"}
    for line in lines:
        match = CLAMAV_FOUND.search(line)
        if not match:
            continue
        moment = None
        if match.group("t"):
            try:
                moment = datetime.strptime(" ".join(match.group("t").split()), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            except ValueError:
                moment = None
        if moment and moment.timestamp() < cutoff:
            continue
        count += 1
        groups.add(("clamav", match.group("path").lower()), "malware", "ClamAV", "FOUND", moment, {"Detected by": "ClamAV"},
                   path=match.group("path"), extra={"names": match.group("name"), "results": "Detected"})
    return {"name": "ClamAV", "available": True, "count": count, "detail": ""}


def _collect_linux(hours):
    groups = _Groups()
    count, problem = _journal_auth(hours, groups)
    if count is None or count == 0:
        count, problem = _file_auth(hours, groups) if count is None else (count, problem)
    detail = problem or ("" if is_admin() else "not running as root: some sign-in events may be hidden")
    sources = [{"name": "Auth log (sshd, sudo, user changes)", "available": count is not None, "count": count or 0, "detail": detail}, _clamav(hours, groups)]
    if shutil.which("kesl-control"):
        sources.append({"name": "Kaspersky for Linux", "available": False, "count": 0, "detail": "installed; reading its detections is not supported yet (see its own console)"})
    return sources, groups.finish(), []


def _collect_macos(hours):
    groups = _Groups()
    code, out, err = _run(["log", "show", "--last", f"{int(hours)}h", "--style", "ndjson", "--predicate", 'process == "sshd" OR process == "sudo"'], 90)
    if code != 0:
        return [{"name": "Unified log (sshd, sudo)", "available": False, "count": 0, "detail": _tail(err, 200) or f"log exit code {code}"}], [], []
    count = 0
    for line in out.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        count += 1
        _add_auth_line(groups, str(entry.get("eventMessage") or ""), _time(str(entry.get("timestamp") or "").replace(" ", "T", 1)), "Unified log")
    detail = "" if is_admin() else "not running as root: some events are hidden"
    return [{"name": "Unified log (sshd, sudo)", "available": True, "count": count, "detail": detail}], groups.finish(), []


# ---------------------------------------------------------------------------
# Scan files (what an action may touch)
# ---------------------------------------------------------------------------

def _scans_dir():
    return leftovers.storage_root() / "threat-scans"


def _purge_old_scans():
    folder = _scans_dir()
    if not leftovers._is_dir(folder):
        return
    for item in folder.glob("*.json"):
        try:
            if time.time() - item.stat().st_mtime > SCAN_TTL_SECONDS:
                item.unlink()
        except OSError:
            continue


def _scan_item(scan_id, item_id):
    """(item from this agent's own scan file, None) or (None, why not)."""
    if not SCAN_ID.match(str(scan_id)) or not ITEM_ID.match(str(item_id)):
        return None, "Invalid scan or item id"
    scan = leftovers._read_agent_json(_scans_dir() / f"{scan_id}.json", None)
    if not scan or time.time() - scan.get("created", 0) > SCAN_TTL_SECONDS:
        return None, "That threat scan expired or is unknown on this device. Scan again."
    item = next((entry for entry in scan.get("items") or [] if entry.get("id") == item_id), None)
    if not item or not item.get("path"):
        return None, "That finding has no file on this device."
    return item, None


def _protected_roots():
    """Folders whose files an action never moves or deletes (the OS, the antivirus itself, this agent)."""
    env = os.environ
    if os_name() == "Windows":
        roots = [Path(env.get("SystemRoot", r"C:\Windows"))]
        for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            if env.get(key):
                roots += [Path(env[key]) / "Kaspersky Lab", Path(env[key]) / "Windows Defender", Path(env[key]) / "Windows Defender Advanced Threat Protection"]
        program_data = Path(env.get("ProgramData", r"C:\ProgramData"))
        roots += [program_data / "Kaspersky Lab", program_data / "Microsoft" / "Windows Defender"]
    elif os_name() == "Darwin":
        roots = [Path(item) for item in ("/System", "/usr", "/bin", "/sbin", "/Library/Apple", "/private/var/db")]
    else:
        roots = [Path(item) for item in ("/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/boot", "/etc", "/proc", "/sys", "/dev", "/opt/kaspersky", "/var/lib/clamav")]
    roots += [leftovers.storage_root(), leftovers.agent_dir()]
    return [leftovers._norm_path(root) for root in roots]


def _allowed_inside():
    """Folders inside a protected root where downloaded or dropped files commonly sit."""
    if os_name() == "Windows":
        return [leftovers._norm_path(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp")]
    return []


def unsafe_reason(path):
    """None when an action may move or delete this file, otherwise why not."""
    target = Path(path)
    try:
        if leftovers._is_link(target):
            return "it is a shortcut link or junction"
        if not target.is_file():
            return "the file is no longer there (or is not a regular file)"
        # A link anywhere in the folders above it would make the move land somewhere else.
        if leftovers._norm_path(os.path.realpath(target)) != leftovers._norm_path(target):
            return "a folder in its path is a link or junction"
    except (OSError, ValueError) as error:
        return f"it cannot be checked: {error}"
    norm = leftovers._norm_path(target)
    allowed = _allowed_inside()
    for root in _protected_roots():
        if (norm == root or norm.startswith(root + os.sep)) and not any(norm.startswith(inside + os.sep) for inside in allowed):
            return f"it is inside a protected folder ({root}): remove it with the antivirus or by hand"
    return None


def _sha256(path, limit=4 * 1024 ** 3):
    digest = hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
                read += len(block)
                if read > limit:
                    return None
    except OSError:
        return None
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def _summary(items, sources, hours):
    counts = Counter(item["kind"] for item in items)
    malware = [item for item in items if item["kind"] == "malware"]
    parts = []
    if malware:
        detections = sum(item["count"] for item in malware)
        on_disk = sum(1 for item in malware if item.get("on_disk"))
        parts.append(f"{detections} malware detection(s) in {len(malware)} file(s), {on_disk} still on disk")
    labels = {"failed_logon": "failed sign-in group(s)", "lockout": "lockout(s)", "user_created": "new account(s)", "group_member_added": "group change(s)",
              "log_cleared": "log clearing(s)", "av_report_cleared": "antivirus report clearing(s)", "service_installed": "new service(s)", "task_created": "new scheduled task(s)",
              "powershell_suspicious": "suspicious PowerShell script(s)", "av_disabled": "protection turned off", "av_health": "antivirus health problem(s)"}
    parts += [f"{counts[kind]} {label}" for kind, label in labels.items() if counts.get(kind)]
    unreadable = [f"{source['name']}: {source['detail']}" for source in sources if not source.get("available") and source.get("detail") != "not on this device"]
    text = f"Threat scan of the last {hours} h: " + ("; ".join(parts) if parts else "nothing suspicious found")
    return text + (f". Not readable: {'; '.join(unreadable)}" if unreadable else "")


def _fit(data):
    """Keep the result under DATA_LIMIT: fewer inner objects first, then the least urgent items."""
    if len(json.dumps(data, default=str)) <= DATA_LIMIT:
        return data
    for item in data["items"]:
        item["objects"] = item["objects"][:2]
        item.pop("threats", None) if len(item.get("threats") or []) > 3 else None
    while data["items"] and len(json.dumps(data, default=str)) > DATA_LIMIT:
        data["items"].pop()
        data["truncated"] = True
    return data


@tool("threat_scan", "Endpoint threat scan (read-only): antivirus detections (Kaspersky, Defender, ClamAV), failed sign-ins, new admin "
      "accounts, cleared logs, new services and tasks, suspicious PowerShell, antivirus health. Groups detections by file.",
      params={"hours": {"type": "integer", "minimum": 1, "maximum": 168, "description": "How far back to look, in hours (default 168 = 7 days)"}}, timeout=SCAN_TIMEOUT + 30)
def threat_scan(hours=168):
    hours = int(hours)
    system = os_name()
    if system == "Windows":
        sources, items, antivirus = _collect_windows(hours)
    elif system == "Linux":
        sources, items, antivirus = _collect_linux(hours)
    elif system == "Darwin":
        sources, items, antivirus = _collect_macos(hours)
    else:
        return {"ok": False, "summary": f"Threat scan is not supported on {system}"}
    malware = [item for item in items if item["kind"] == "malware"]
    for item in malware:
        item["on_disk"] = _on_disk(item["path"])
        item["size"] = _size(item["path"]) if item["on_disk"] else None
    running = _running([item["path"] for item in malware if item.get("on_disk")])
    for item in malware:
        item["running"] = running.get(leftovers._norm_path(item["path"]), []) if item.get("on_disk") else []
    items.sort(key=lambda item: (KIND_PRIORITY.get(item["kind"], 99), -item["count"]))
    items = items[:MAX_ITEMS]
    for index, item in enumerate(items):
        item["id"] = f"d{index}"
    db_dates = [item["fields"].get("Database date") for item in malware if item["fields"].get("Database date")]

    scan_id = uuid.uuid4().hex[:12]
    _purge_old_scans()
    leftovers._write_json(_scans_dir() / f"{scan_id}.json", {"created": time.time(), "items": [
        {"id": item["id"], "kind": item["kind"], "path": item["path"], "name": item["fields"].get("Threat") or item["kind"]} for item in items if item.get("path")]})
    data = _fit({"scan_id": scan_id, "platform": system, "hours": hours, "scanned_at": datetime.now(timezone.utc).isoformat(), "admin": is_admin(),
                 "sources": sources, "antivirus": antivirus, "kaspersky_db_date": db_dates[0] if db_dates else None, "items": items, "truncated": False})
    return {"ok": True, "summary": _summary(data["items"], sources, hours), "data": data}


def _kaspersky_cli():
    for key in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(key)
        if base:
            found = sorted(Path(base, "Kaspersky Lab").glob("*/avp.com"), reverse=True)
            if found:
                return str(found[0])
    return None


def _version_key(path):
    return [int(part) if part.isdigit() else 0 for part in re.split(r"[.-]", path.parent.name)]


def _defender_cli():
    platform_dir = Path(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender", "Platform")
    found = sorted(platform_dir.glob("*/MpCmdRun.exe"), key=_version_key, reverse=True)
    if found:
        return str(found[0])
    fallback = Path(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
    return str(fallback) if fallback.is_file() else None


def _scan_command(path):
    """(scanner name, argument list) for an inform-only scan of one file, or (None, why not)."""
    system = os_name()
    if system == "Windows":
        kaspersky = _kaspersky_cli()
        if kaspersky:
            return "Kaspersky Endpoint Security", [kaspersky, "SCAN", path, "/i0"]  # /i0: report only, take no action
        defender = _defender_cli()
        if defender:
            return "Microsoft Defender", [defender, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"]
        return None, "No command-line antivirus scanner found (Kaspersky avp.com or Defender MpCmdRun.exe)."
    if system == "Linux":
        if shutil.which("kesl-control"):
            return "Kaspersky for Linux", ["kesl-control", "--scan-file", path, "--action", "Skip"]
        if shutil.which("clamscan"):
            return "ClamAV", ["clamscan", "--no-summary", path]
        return None, "No command-line antivirus scanner found (kesl-control or clamscan)."
    return None, "No command-line antivirus scanner is available on this system."


@tool("threat_rescan", "Scan the file of one threat finding again with the installed antivirus, in report-only mode (nothing is changed).",
      risk="low", params={"scan_id": {"type": "string", "maxLength": 12, "description": "scan_id from threat_scan"},
                          "item_id": {"type": "string", "maxLength": 4, "description": "Item id from that scan, e.g. d0"}},
      required=("scan_id", "item_id"), timeout=RESCAN_TIMEOUT + 30, ai_visible=False)
def threat_rescan(scan_id, item_id):
    item, problem = _scan_item(scan_id, item_id)
    if problem:
        return {"ok": False, "summary": problem}
    if not _on_disk(item["path"]):
        return {"ok": True, "summary": f"{item['path']} is no longer on disk: nothing to scan.", "data": {"path": item["path"], "on_disk": False}}
    scanner, command = _scan_command(item["path"])
    if scanner is None:
        return {"ok": False, "summary": command}
    started = time.time()
    code, out, err = _run(command, RESCAN_TIMEOUT)
    output = _tail(out or err, 1500)
    if scanner == "Microsoft Defender":
        verdict = "threats found" if code == 2 else "no threats found" if code == 0 else f"scanner exit code {code}"
    elif scanner == "ClamAV":
        verdict = "threats found" if code == 1 else "no threats found" if code == 0 else f"scanner exit code {code}"
    else:
        counts = re.findall(r"(?im)^\s*(detected|infected|threats? found)\s*[:=]?\s*(\d+)", out or "")
        found = sum(int(number) for _, number in counts)
        verdict = f"{found} detection(s) reported" if counts else f"finished (exit code {code}); see the scanner output"
    summary = f"{scanner} rescan of {item['path']}: {verdict} ({time.time() - started:.0f} s). Report-only: nothing was changed."
    return {"ok": code in (0, 1, 2) or bool(out), "summary": summary, "data": {"path": item["path"], "scanner": scanner, "exit_code": code, "verdict": verdict, "output": output}}


@tool("quarantine_threat", "Move the file of one threat finding into the AIops quarantine (renamed so it cannot be started). Restorable for 7 days from the Software tab.",
      risk="high", params={"scan_id": {"type": "string", "maxLength": 12, "description": "scan_id from threat_scan"},
                           "item_id": {"type": "string", "maxLength": 4, "description": "Item id from that scan, e.g. d0"}},
      required=("scan_id", "item_id"), timeout=900, ai_visible=False)
def quarantine_threat(scan_id, item_id):
    item, problem = _scan_item(scan_id, item_id)
    if problem:
        return {"ok": False, "summary": problem}
    path = item["path"]
    reason = unsafe_reason(path)
    if reason:
        return {"ok": False, "summary": f"Not quarantined: {reason}."}
    batch_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    batch = leftovers._quarantine_dir() / batch_id
    batch.mkdir(parents=True, exist_ok=True)
    if not leftovers._same_volume(path, batch):
        shutil.rmtree(batch, ignore_errors=True)
        return {"ok": False, "summary": "Not quarantined: the file is on another drive than the quarantine, so it would have to be copied. Delete it, or move it by hand."}
    size, digest = _size(path), _sha256(path)
    stored = batch / f"{item_id}_{leftovers._safe_name(Path(path).name)}.quarantined"
    try:
        shutil.move(path, str(stored))
    except (OSError, shutil.Error) as error:
        shutil.rmtree(batch, ignore_errors=True)
        return {"ok": False, "summary": f"Not quarantined: the file could not be moved (in use by a running program, or access denied): {error}"[:400]}
    created = time.time()
    # The leftovers manifest format, so list_quarantine and restore_quarantine handle threats as well.
    leftovers._write_json(batch / "manifest.json", {"batch_id": batch_id, "program": f"Threat: {item.get('name') or 'file'}", "entry_id": None, "created": created,
                                                    "items": [{"id": item_id, "kind": "file", "original": path, "stored": str(stored), "ok": True, "error": None,
                                                               "restored": False, "sha256": digest, "size": size}]})
    restore_until = datetime.fromtimestamp(created + leftovers.QUARANTINE_DAYS * 86400, timezone.utc).isoformat()
    return {"ok": True, "changed": True, "summary": f"Moved {path} to the quarantine (batch {batch_id}); restorable until {restore_until[:10]}.",
            "data": {"batch_id": batch_id, "path": path, "sha256": digest, "size": size, "restore_until": restore_until}}


@tool("delete_threat", "Permanently delete the file of one threat finding. It cannot be restored. confirm must be the file's name.",
      risk="high", params={"scan_id": {"type": "string", "maxLength": 12, "description": "scan_id from threat_scan"},
                           "item_id": {"type": "string", "maxLength": 4, "description": "Item id from that scan, e.g. d0"},
                           "confirm": {"type": "string", "maxLength": 260, "description": "The file name, typed by the person who approved it"}},
      required=("scan_id", "item_id", "confirm"), timeout=300, ai_visible=False)
def delete_threat(scan_id, item_id, confirm):
    item, problem = _scan_item(scan_id, item_id)
    if problem:
        return {"ok": False, "summary": problem}
    path = item["path"]
    name = Path(path).name
    same = confirm.strip().lower() == name.lower() if os_name() == "Windows" else confirm.strip() == name
    if not same:
        return {"ok": False, "summary": f"Not deleted: the confirmation must be the file name ({name})."}
    reason = unsafe_reason(path)
    if reason:
        return {"ok": False, "summary": f"Not deleted: {reason}."}
    size, digest = _size(path), _sha256(path)
    try:
        os.remove(path)
    except OSError as error:
        return {"ok": False, "summary": f"Not deleted (in use by a running program, or access denied): {error}"[:400]}
    return {"ok": True, "changed": True, "summary": f"Deleted {path} permanently (SHA256 {digest or 'unknown'}).", "data": {"path": path, "sha256": digest, "size": size}}
