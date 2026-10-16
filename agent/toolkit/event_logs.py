"""Cross-platform recent error/warning event log collection.

Reads the OS-native event log (Windows Event Viewer, Linux journald, macOS
unified log) for recent Warning/Error/Critical entries. Read-only, capped in
both time window and event count, and every branch fails safe to an empty,
clearly-labeled result rather than raising.
"""

import json
import platform
import subprocess

LOOKBACK_HOURS = 24
MAX_EVENTS = 50
MESSAGE_MAX_CHARS = 300
# Rendering 50 event messages takes PowerShell well over 15 s as SYSTEM on a busy laptop.
TIMEOUT_SECONDS = 45


def _run(command, timeout=TIMEOUT_SECONDS):
    """stdout text, or None when the command failed or timed out. A failure must never read as
    "no events": that would hide real errors from every diagnosis."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, errors="replace")
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _truncate(message):
    text = " ".join(str(message or "").split())
    return text if len(text) <= MESSAGE_MAX_CHARS else text[:MESSAGE_MAX_CHARS] + "..."


def _collect_windows():
    # ConvertTo-Json serializes [datetime] as the legacy /Date(...)/ format, which
    # browsers' Date() can't parse — format TimeCreated as ISO 8601 text ourselves.
    script = (
        "Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2,3; "
        f"StartTime=(Get-Date).AddHours(-{LOOKBACK_HOURS})}} -MaxEvents {MAX_EVENTS} -ErrorAction SilentlyContinue "
        "| Select-Object @{N='TimeCreated';E={$_.TimeCreated.ToString('o')}},LevelDisplayName,ProviderName,Id,Message "
        "| ConvertTo-Json -Compress"
    )
    output = _run(["powershell", "-NoProfile", "-Command", script])
    if output is None:
        return {"available": False, "events": [], "detail": f"Reading Windows Event Viewer timed out after {TIMEOUT_SECONDS}s; it is retried on the next check"}
    if not output:
        return {"available": True, "events": [], "detail": f"No warning, error, or critical events in the last {LOOKBACK_HOURS} hours"}

    try:
        parsed = json.loads(output)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {"available": False, "events": [], "detail": "Could not parse Windows Event Viewer output"}

    rows = parsed if isinstance(parsed, list) else [parsed]
    events = [
        {
            "time": row.get("TimeCreated"),
            "level": row.get("LevelDisplayName"),
            "source": row.get("ProviderName"),
            "id": row.get("Id"),
            "message": _truncate(row.get("Message")),
        }
        for row in rows
    ]
    return {"available": True, "events": events, "detail": f"{len(events)} event(s) from the System and Application logs"}


def _collect_linux():
    output = _run(["journalctl", "-p", "err", f"--since=-{LOOKBACK_HOURS}h", "-n", str(MAX_EVENTS), "--no-pager", "-o", "json"])
    if not output:
        return {"available": False, "events": [], "detail": "journalctl not available or returned no output; check /var/log manually"}

    events = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        events.append({
            "time": row.get("__REALTIME_TIMESTAMP"),
            "level": "Error",
            "source": row.get("SYSLOG_IDENTIFIER") or row.get("_COMM"),
            "id": row.get("PRIORITY"),
            "message": _truncate(row.get("MESSAGE")),
        })
    return {"available": True, "events": events, "detail": f"{len(events)} error-priority event(s) from journald"}


def _collect_macos():
    output = _run(
        ["log", "show", "--last", f"{LOOKBACK_HOURS}h", "--predicate", "messageType == 16 OR messageType == 17", "--style", "ndjson"],
        timeout=30,
    )
    if not output:
        return {"available": False, "events": [], "detail": "Could not read the macOS unified log (may require additional privacy permissions)"}

    events = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if "eventMessage" not in row:
            continue
        events.append({
            "time": row.get("timestamp"),
            "level": "Fault" if row.get("messageType") == "Fault" else "Error",
            "source": row.get("process"),
            "id": row.get("eventType"),
            "message": _truncate(row.get("eventMessage")),
        })
        if len(events) >= MAX_EVENTS:
            break
    return {"available": True, "events": events, "detail": f"{len(events)} error/fault event(s) from the unified log"}


def collect_event_log_report():
    system = platform.system()
    if system == "Windows":
        result = _collect_windows()
    elif system == "Linux":
        result = _collect_linux()
    elif system == "Darwin":
        result = _collect_macos()
    else:
        result = {"available": False, "events": [], "detail": f"Event log reading is not implemented for {system}"}

    events = result.get("events", [])
    levels = [str(event.get("level", "")).lower() for event in events]
    return {
        "platform": system,
        "lookback_hours": LOOKBACK_HOURS,
        "available": result.get("available", False),
        "detail": result.get("detail", ""),
        "events": events,
        "critical_count": sum(1 for level in levels if level in ("critical", "fault")),
        "error_count": sum(1 for level in levels if level == "error"),
        "warning_count": sum(1 for level in levels if level == "warning"),
    }
