"""Instant, rule-based findings from diagnostic evidence (no LLM).

These run in milliseconds right after the baseline checks, so the operator sees
concrete problems within seconds. They also feed the LLM pre-digested facts,
stand in for the AI report when the model is unavailable or too slow, and let a
fix be verified deterministically by checking whether its finding disappeared.

A finding is {key, severity, title, detail, source, fixes: [{tool_id, args, why}], tips: [manual suggestions]}.
`key` identifies the same problem across runs (used for verification).

Which findings can explain the user's complaint is decided by the playbook (playbooks.RELATED_FINDINGS); the
rest are separate problems. Severity says how bad a finding is, not whether it caused the complaint.
"""

import re

from agent.toolkit.remediation import PROTECTED_PROCESSES, RESTARTABLE_SERVICES

from ..rules_engine import disk_space_severity
from .playbooks import LINUX, MACOS, WINDOWS, is_complaint, is_related

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SIZE_PATTERN = re.compile(r"([\d.]+)\s*(B|KB|MB|GB|TB)")
SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
UPTIME_DAYS = re.compile(r"(\d+)\s+day")
# USB sticks, SD cards, optical media and cloud-drive mounts (Google Drive shows up as a "full"
# FAT32 disk): a full one never slows the computer down, so it is not a disk-full problem.
NON_SYSTEM_FILESYSTEMS = {"fat", "fat32", "vfat", "exfat", "msdos", "cdfs", "iso9660", "udf", "squashfs", "fuse", "fuseblk"}


def _finding(key, severity, title, detail, source, fixes=(), tips=()):
    return {"key": key, "severity": severity, "title": title, "detail": detail, "source": source, "fixes": list(fixes), "tips": list(tips)}


def _fix(tool_id, why, **args):
    return {"tool_id": tool_id, "args": args, "why": why}


def _bytes(text):
    match = SIZE_PATTERN.search(str(text or ""))
    return float(match.group(1)) * SIZE_UNITS[match.group(2)] if match else 0


def _percent(value):
    match = re.search(r"(\d+(?:\.\d+)?)", str(value or ""))
    return float(match.group(1)) if match else None


# ---------------------------------------------------------------------------
# One rule function per diagnostic tool: (data, summary, args, os_type) -> [finding]
# ---------------------------------------------------------------------------

def _system_overview(data, summary, args, os_type):
    found = []
    for disk in data.get("disks") or []:
        used = disk.get("used_percent") or 0
        if str(disk.get("fs", "")).lower() in NON_SYSTEM_FILESYSTEMS:
            continue
        severity = disk_space_severity(used, disk.get("free"))
        if severity:
            fixes = [_fix("clear_temp_files", "frees space taken by temporary files"), _fix("empty_recycle_bin", "frees space held by deleted files")]
            found.append(_finding(f"disk_full:{disk.get('mount')}", severity, f"Disk {disk.get('mount')} is {used}% full", f"Only {disk.get('free')} free of {disk.get('total')}.", "system_overview", fixes))
    ram = data.get("ram_percent") or 0
    if ram >= 80:
        found.append(_finding("ram_high", "high" if ram >= 90 else "medium", f"Memory is {ram}% used", f"{data.get('ram_used')} of {data.get('ram_total')} in use; swap {data.get('swap_percent')}%.", "system_overview"))
    cpu = data.get("cpu_percent") or 0
    if cpu >= 75:
        found.append(_finding("cpu_high", "high" if cpu >= 90 else "medium", f"CPU is {cpu}% busy", "Sustained high CPU makes the computer slow and hot.", "system_overview"))
    days = UPTIME_DAYS.search(str(data.get("uptime") or ""))
    if days and int(days.group(1)) >= 7:
        found.append(_finding("long_uptime", "medium" if int(days.group(1)) >= 14 else "low", f"Not restarted for {days.group(1)} days", "A restart clears leaked memory and finishes pending updates.", "system_overview"))
    battery = data.get("battery") or {}
    if battery and not battery.get("plugged_in") and (battery.get("percent") or 100) <= 15:
        found.append(_finding("battery_low", "medium", f"Battery at {battery.get('percent')}% and unplugged", "Windows and macOS throttle performance on a low battery.", "system_overview"))
    return found


def _top_processes(data, summary, args, os_type):
    found = []
    rows = data if isinstance(data, list) else []
    by_cpu = (args or {}).get("sort_by", "cpu") == "cpu"
    for row in rows[:3]:
        name = str(row.get("name") or "")
        value = row.get("cpu_percent" if by_cpu else "memory_percent") or 0
        threshold = 40 if by_cpu else 25
        if value < threshold or name.lower().startswith(AI_ENGINE_PROCESSES):
            continue  # the AI engine is busy because AIops is diagnosing right now
        kind = "CPU" if by_cpu else "memory"
        severity = "high" if value >= (75 if by_cpu else 45) else "medium"
        fixes = [] if name.lower() in PROTECTED_PROCESSES else [_fix("kill_process", f"{name} is using {value}% {kind}", pid=row.get("pid"), expected_name=name)]
        found.append(_finding(f"process_{kind.lower()}:{name.lower()}", severity, f"{name} is using {value}% {kind}", f"PID {row.get('pid')}, memory {row.get('memory')}.", "top_processes", fixes))
    return found


def _check_internet(data, summary, args, os_type):
    stages = data or {}
    gateway_ping = stages.get("gateway_ping") or {}
    online = all((stages.get(stage) or {}).get("ok") for stage in ("dns_resolution", "tcp_to_internet", "http"))
    if online:
        return _speed_findings(stages, gateway_ping)
    if not stages.get("adapters_with_ip"):
        return [_finding("net_no_adapter", "critical", "No network connection", "No network adapter has an IP address: cable unplugged, Wi-Fi off or adapter disabled.", "check_internet")]
    if not stages.get("default_gateway"):
        return [_finding("net_no_gateway", "high", "No route to the router", summary, "check_internet", [_fix("renew_ip", "asks the router (DHCP) for a fresh address and route")])]
    if gateway_ping and gateway_ping.get("reachable") is False and not (stages.get("tcp_to_internet") or {}).get("ok"):
        return [_finding("net_router_down", "high", "Router is not answering", summary, "check_internet", [_fix("renew_ip", "re-joins the local network")])]
    if not (stages.get("tcp_to_internet") or {}).get("ok"):
        return [_finding("net_no_internet", "high", "Local network works but the internet is unreachable", "The router or internet provider is down, or a firewall blocks traffic.", "check_internet")]
    if not (stages.get("dns_resolution") or {}).get("ok"):
        return [_finding("net_dns", "high", "DNS is failing", "Websites cannot be found by name although the internet is reachable.", "check_internet", [_fix("flush_dns", "clears the broken DNS cache")])]
    if not (stages.get("http") or {}).get("ok"):
        return [_finding("net_http", "medium", "Web traffic is blocked", "A proxy, captive portal (hotel/guest Wi-Fi login) or web filter is interfering.", "check_internet")]
    return _speed_findings(stages, gateway_ping)


def _speed_findings(stages, gateway_ping):
    found = []
    dns_ms = (stages.get("dns_resolution") or {}).get("ms") or 0
    tcp_ms = (stages.get("tcp_to_internet") or {}).get("ms") or 0
    if dns_ms > 300:
        found.append(_finding("net_dns_slow", "medium", f"DNS is slow ({dns_ms} ms)", "Every new website waits for the slow DNS answer.", "check_internet", [_fix("flush_dns", "clears stale DNS entries")]))
    if tcp_ms > 300:
        found.append(_finding("net_latency", "medium", f"High internet latency ({tcp_ms} ms)", "The connection to the internet is slow (weak Wi-Fi, busy network or provider).", "check_internet"))
    loss = gateway_ping.get("packet_loss_percent") or 0
    if loss and loss >= 25:
        found.append(_finding("net_packet_loss", "high", f"{loss}% packet loss to the router", "Local network is unreliable (weak Wi-Fi or a bad cable).", "check_internet"))
    return found


def _wifi_status(data, summary, args, os_type):
    data = data if isinstance(data, dict) else {}
    signal = _percent(data.get("Signal") or data.get("signal_percent"))
    if signal is not None and signal < 50:
        return [_finding("wifi_weak", "high" if signal < 30 else "medium", f"Weak Wi-Fi signal ({int(signal)}%)", "Move closer to the router or remove obstacles; weak signal causes drops and slow speed.", "wifi_status", [_fix("renew_ip", "re-joins the network after reconnecting")])]
    if str(data.get("State", "")).lower() == "disconnected":
        return [_finding("wifi_disconnected", "high", "Wi-Fi is disconnected", summary, "wifi_status")]
    return []


def _security_posture(data, summary, args, os_type):
    data = data or {}
    found = []
    if (data.get("firewall") or {}).get("enabled") is False:
        found.append(_finding("sec_firewall_off", "high", "Firewall is off", "The device accepts unsolicited network connections.", "security_posture"))
    if (data.get("antivirus") or {}).get("enabled") is False:
        found.append(_finding("sec_av_off", "high", "Antivirus / real-time protection is off", "Malware would not be blocked.", "security_posture", [_fix("trigger_update_scan", "updates protection definitions")]))
    if (data.get("disk_encryption") or {}).get("encrypted") is False:
        found.append(_finding("sec_no_encryption", "low", "Disk is not encrypted", "Data is readable if the laptop is lost or stolen.", "security_posture"))
    risky = (data.get("listening_ports") or {}).get("risky_exposed") or []
    if risky:
        # One port can listen on several addresses (0.0.0.0 and ::); name each port once.
        ports = ", ".join(dict.fromkeys(str(port.get("port")) for port in risky))
        found.append(_finding("sec_risky_ports", "medium", f"Risky ports exposed to the network ({ports})", "Services like RDP/SMB/Telnet listening on all interfaces are common attack targets.", "security_posture"))
    return found


def _event_log_errors(data, summary, args, os_type):
    found = []
    critical = re.match(r"(\d+) critical", summary or "")
    if critical and int(critical.group(1)) > 0:
        found.append(_finding("log_critical", "medium", f"{critical.group(1)} critical system event(s) in 24h", summary, "event_log_errors"))
    for group in ((data or {}).get("groups") or [])[:2]:
        if group.get("count", 0) >= 10 and str(group.get("level", "")).lower() in ("error", "critical"):
            found.append(_finding(f"log_repeat:{group.get('source')}", "medium", f"{group.get('source')} logged {group.get('count')} errors", str(group.get("sample") or "")[:200], "event_log_errors"))
    return found


def _recent_crashes(data, summary, args, os_type):
    events = data if isinstance(data, list) else []
    found = []
    bsod = [event for event in events if re.search(r"blue screen|kernel|panic|power loss", str(event.get("type")), re.I)]
    if bsod:
        found.append(_finding("crash_system", "high", f"{len(bsod)} system crash(es) / unexpected restarts in 7 days", str(bsod[0].get("message") or "")[:200], "recent_crashes", [_fix("repair_system_files", "repairs corrupted system files that can cause crashes")] if os_type == "Windows" else []))
    apps = [event for event in events if "application" in str(event.get("type"))]
    if len(apps) >= 3:
        found.append(_finding("crash_apps", "medium", f"{len(apps)} application crashes/hangs in 7 days", str(apps[0].get("message") or "")[:200], "recent_crashes"))
    return found


def _disk_health(data, summary, args, os_type):
    rows = data if isinstance(data, list) else []
    bad = [row for row in rows if isinstance(row, dict) and (
        ("HealthStatus" in row and str(row.get("HealthStatus")).lower() not in ("healthy", "0"))
        or ("smart" in row and not re.search(r"passed|ok|unknown|not installed|unavailable", str(row.get("smart")), re.I))
    )]
    if bad or re.search(r"SMART status: (?!Verified)", summary or ""):
        return [_finding("disk_failing", "critical", "A physical disk reports failing health", (summary or "")[:200] + ". Back up important files now and replace the drive.", "disk_health")]
    return []


def _battery_health(data, summary, args, os_type):
    data = data or {}
    health = data.get("health_percent")
    if health is not None and health < 70:
        return [_finding("battery_worn", "high" if health < 50 else "medium", f"Battery holds only {health}% of its original capacity", "A worn battery drains fast; replacement is the fix.", "battery_health")]
    condition = str(data.get("condition") or "")
    if condition and condition.lower() not in ("normal", "good"):
        return [_finding("battery_worn", "medium", f"Battery condition: {condition}", summary, "battery_health")]
    return []


def _update_status(data, summary, args, os_type):
    data = data or {}
    found = []
    if data.get("reboot_pending"):
        found.append(_finding("reboot_pending", "medium", "A restart is pending to finish updates", "Updates stay half-installed until the computer restarts.", "update_status"))
    if len(data.get("available_updates") or []) >= 1:
        found.append(_finding("updates_available", "low", f"{len(data['available_updates'])} update(s) available", summary, "update_status", [_fix("trigger_update_scan", "starts the update check")]))
    return found


def _printer_status(data, summary, args, os_type):
    data = data or {}
    found = []
    spooler = str(data.get("spooler") or "").lower()
    if spooler and spooler not in ("running", "unknown"):
        found.append(_finding("print_spooler_down", "high", f"Print spooler is {spooler}", "Nothing can print while the spooler service is stopped.", "printer_status", [_fix("restart_service", "starts the print spooler again", name="Spooler")]))
    queued = sum(int(printer.get("JobCount") or 0) for printer in data.get("printers") or [] if isinstance(printer, dict)) + len(data.get("jobs") or [])
    if queued:
        found.append(_finding("print_queue_stuck", "medium", f"{queued} print job(s) stuck in the queue", "A stuck job blocks every job behind it.", "printer_status", [_fix("clear_print_queue", "removes the stuck jobs")]))
    return found


def _service_status(data, summary, args, os_type):
    data = data if isinstance(data, dict) else {}
    name = (args or {}).get("name") or data.get("name")
    state = str(data.get("status") or data.get("state") or "").lower()
    if not name or not state or state in ("running", "active"):
        return []
    restartable = name in RESTARTABLE_SERVICES.get(os_type, ())
    return [_finding(f"service_down:{name}", "high", f"Service {name} is {state}", summary, "service_status", [_fix("restart_service", f"starts {name} again", name=name)] if restartable else [])]


def _failed_services(data, summary, args, os_type):
    if os_type == "Linux" and isinstance(data, list) and data:
        return [_finding("services_failed", "medium", f"{len(data)} failed system service(s)", summary, "failed_services")]
    return []


def _cleanup_candidates(data, summary, args, os_type):
    found = []
    for item in data if isinstance(data, list) else []:
        size, kind = _bytes(item.get("size")), str(item.get("kind"))
        if kind == "temp" and size >= 1024 ** 3:
            found.append(_finding(f"cleanup_temp:{item.get('location')}", "medium", f"{item.get('size')} of temporary files", item.get("location", ""), "cleanup_candidates", [_fix("clear_temp_files", "deletes old temporary files")]))
        elif kind == "trash" and size >= 1024 ** 3:
            found.append(_finding("cleanup_trash", "low", f"{item.get('size')} in the Recycle Bin / Trash", "Deleted files still take disk space.", "cleanup_candidates", [_fix("empty_recycle_bin", "permanently frees that space")]))
        elif kind == "windows update cache" and size >= 2 * 1024 ** 3:
            found.append(_finding("cleanup_update_cache", "low", f"{item.get('size')} Windows Update cache", "Old downloaded updates can be removed safely.", "cleanup_candidates", [_fix("clear_windows_update_cache", "removes old update downloads")]))
    return found


def _startup_programs(data, summary, args, os_type):
    items = data if isinstance(data, list) else []
    if len(items) >= 15:
        return [_finding("startup_many", "low", f"{len(items)} programs start automatically", "Many startup programs slow down boot and use memory in the background.", "startup_programs")]
    return []


def _hardware_health(data, summary, args, os_type):
    data = data or {}
    found = []
    temp = data.get("max_temperature_c")
    if temp is not None and temp >= 85:
        found.append(_finding("hw_overheating", "critical" if temp >= 95 else "high", f"Overheating: {temp} C", "Clean the vents/fan, use the laptop on a hard surface and check that the fan spins.", "hardware_health"))
    if data.get("throttling_suspected"):
        performance = (data.get("cpu") or {}).get("performance_percent")
        found.append(_finding("hw_throttling", "high", f"CPU is throttled to {performance}% of its base clock", "Usually heat or a power-saving plan/weak charger; the computer feels slow.", "hardware_health"))
    if data.get("thermal_warning"):
        found.append(_finding("hw_thermal_warning", "high", "The system recorded a thermal warning", "macOS slowed the CPU because of heat.", "hardware_health"))
    for gpu in data.get("gpus") or []:
        if not gpu.get("ok"):
            found.append(_finding(f"hw_gpu:{gpu.get('name')}", "high", f"Graphics driver problem: {gpu.get('name')}", f"Status {gpu.get('status')}, driver {gpu.get('driver')}. Update or reinstall the graphics driver.", "hardware_health", [_fix("rescan_hardware", "re-detects the graphics adapter")] if os_type == "Windows" else []))
    devices = data.get("problem_devices") or []
    if devices:
        names = ", ".join(f"{device.get('name')} ({device.get('problem')})" for device in devices[:3])
        found.append(_finding("hw_devices", "medium", f"{len(devices)} device(s) with driver/hardware problems", names[:300], "hardware_health", [_fix("rescan_hardware", "re-detects devices and reloads their drivers")] if os_type == "Windows" else []))
    if data.get("hardware_errors_7d"):
        found.append(_finding("hw_errors", "high", f"{data['hardware_errors_7d']} hardware error(s) logged in 7 days", "WHEA/machine-check errors point to failing RAM, CPU, disk or overheating; run a memory test.", "hardware_health"))
    return found


def _boot_performance(data, summary, args, os_type):
    data = data or {}
    found = []
    # Windows' total boot time includes the settle-down after sign-in (often 20-60 s on a healthy PC), so it
    # judges the time until the desktop is ready; elsewhere only the total is known, with a higher bar.
    desktop = data.get("desktop_ready_seconds")
    seconds, limit = (desktop, 60) if desktop else (data.get("last_boot_seconds"), 90)
    if seconds and seconds >= limit:
        culprits = ", ".join(item["name"] for item in (data.get("slowed_by") or [])[:3])
        what = f"the desktop was ready after {seconds:.0f} s" if desktop else f"the last boot took {seconds:.0f} s"
        found.append(_finding("boot_slow", "high" if seconds >= 2 * limit else "medium", f"Start-up is slow: {what}",
                              (f"Slowed down in the last 30 days by {culprits}. " if culprits else "") + "Fewer startup programs and an SSD make it faster.", "boot_performance"))
    if (data.get("startup_programs") or 0) >= 15:
        found.append(_finding("startup_many", "low", f"{data['startup_programs']} programs start automatically", "Many startup programs slow down boot and use memory in the background.", "boot_performance"))
    return found


def _os_updates(data, summary, args, os_type):
    data = data or {}
    found = []
    security = data.get("security_count") or 0
    if security:
        # Medium, not high: right after the monthly patch day nearly every PC has a few waiting for a while.
        found.append(_finding("os_updates_security", "medium", f"{security} security update(s) are waiting to be installed",
                              "Security updates close holes attackers use; install them from the Performance tab or the system's updater.", "os_updates"))
    elif (data.get("count") or 0) - (data.get("driver_count") or 0) > 0:
        found.append(_finding("os_updates_waiting", "low", f"{data['count']} system update(s) waiting", summary, "os_updates"))
    if data.get("reboot_pending"):
        found.append(_finding("reboot_pending", "medium", "A restart is pending to finish updates", "Updates stay half-installed until the computer restarts.", "os_updates"))
    return found


def _input_devices(data, summary, args, os_type):
    data = data or {}
    found = []
    for device in [item for item in data.get("devices") or [] if item.get("status") == "problem"][:3]:
        found.append(_finding(f"input_device:{device.get('name')}", "medium", f"{str(device.get('kind', 'input device')).capitalize()} driver problem: {device.get('name')}",
                              f"Windows reports: {device.get('problem')}. Re-plug it, or update/reinstall its driver.", "input_devices",
                              [_fix("rescan_hardware", "re-detects the device and reloads its driver")] if os_type == "Windows" else []))
    # Servers, VMs and containers have no input devices at all; only a touchpad or mouse without any
    # keyboard points to a keyboard (or its driver) that stopped working.
    if data.get("pointing") and not data.get("keyboards"):
        found.append(_finding("input_no_keyboard", "medium", "No working keyboard detected", "Check the cable or receiver, or the keyboard's battery.", "input_devices"))
    return found


def _performance_benchmark(data, summary, args, os_type):
    disk = (data or {}).get("disk") or {}
    write = disk.get("write_mbps")
    if disk.get("available") and write is not None and write < 15:
        return [_finding("disk_slow", "medium", f"The disk is slow: it writes only {write} MB/s", "An old hard disk, a nearly full disk or heavy background disk use makes everything slow; an SSD helps most.", "performance_benchmark")]
    return []


RULES = {
    "boot_performance": _boot_performance,
    "os_updates": _os_updates,
    "input_devices": _input_devices,
    "performance_benchmark": _performance_benchmark,
    "system_overview": _system_overview,
    "top_processes": _top_processes,
    "check_internet": _check_internet,
    "wifi_status": _wifi_status,
    "security_posture": _security_posture,
    "event_log_errors": _event_log_errors,
    "recent_crashes": _recent_crashes,
    "disk_health": _disk_health,
    "battery_health": _battery_health,
    "update_status": _update_status,
    "printer_status": _printer_status,
    "service_status": _service_status,
    "failed_services": _failed_services,
    "cleanup_candidates": _cleanup_candidates,
    "startup_programs": _startup_programs,
    "hardware_health": _hardware_health,
}


AI_ENGINE_PROCESSES = ("ollama", "llama-server", "llama_server")
# What well-known processes are, so neither the AI nor a person mistakes them for an ordinary app.
PROCESS_ROLES = {
    "vmmemwsl": "WSL/Docker virtual machine", "vmmem": "WSL/Docker virtual machine", "com.docker.backend.exe": "Docker Desktop",
    "msmpeng.exe": "Microsoft Defender antivirus", "memcompression": "Windows memory compression", "memory compression": "Windows memory compression",
    "searchindexer.exe": "Windows search indexing", "tiworker.exe": "Windows Update installer", "ollama": "the AIops AI engine",
    "ollama.exe": "the AIops AI engine", "ollama_llama_server": "the AIops AI engine", "llama-server": "the AIops AI engine",
    "dwm.exe": "Windows desktop graphics", "kernel_task": "macOS (cooling down the CPU)", "windowserver": "macOS display server",
}
BROWSERS = ("chrome", "msedge", "firefox", "brave", "opera", "safari")


def process_role(name):
    return PROCESS_ROLES.get(str(name or "").lower())


def group_processes(rows, field):
    """Rows of one process each -> one entry per program (Chrome runs as dozens of processes), biggest first."""
    apps = {}
    for row in rows if isinstance(rows, list) else []:
        name = str(row.get("name") or "Unknown")
        entry = apps.setdefault(name.lower(), {"name": name, "percent": 0.0, "count": 0, "pids": []})
        entry["percent"] += row.get(field) or 0
        entry["count"] += 1
        entry["pids"].append(row.get("pid"))
    for entry in apps.values():
        entry["percent"] = round(entry["percent"], 1)
        entry["role"] = process_role(entry["name"])
    return sorted(apps.values(), key=lambda entry: entry["percent"], reverse=True)


def describe_apps(apps, limit=4):
    parts = []
    for entry in apps[:limit]:
        text = f"{entry['name']} {entry['percent']}%"
        if entry["count"] > 1:
            text += f" in {entry['count']} processes"
        if entry["role"]:
            text += f" ({entry['role']})"
        parts.append(text)
    return ", ".join(parts)


def _uptime_days(data):
    days = UPTIME_DAYS.search(str((data or {}).get("uptime") or ""))
    return int(days.group(1)) if days else 0


def _memory_tips(os_type, apps, overview):
    """Concrete, OS-specific things a person can do about memory pressure, naming what holds the memory."""
    tips, top = [], [entry for entry in apps if not entry["role"]][:2]
    names = " and ".join(entry["name"] for entry in top)
    if os_type == "Windows":
        tips.append(_tip_dict(f"Close {names}" if names else "Close the apps using the most memory", f"{describe_apps(apps, 3) or 'A few apps'} hold the most memory.",
                              "Save your work.", "Open Task Manager (Ctrl+Shift+Esc), sort by Memory and close what you do not need."))
        if any(entry["name"].lower() in ("vmmemwsl", "vmmem") for entry in apps):
            tips.append(_tip_dict("Shut down WSL/Docker when you do not need it", "The WSL/Docker virtual machine keeps its memory until it is stopped.",
                                  "Quit Docker Desktop, or run: wsl --shutdown", "To cap it, add memory=4GB under [wsl2] in %UserProfile%\\.wslconfig"))
    elif os_type == "Linux":
        tips.append(_tip_dict(f"Stop or restart {names}" if names else "Stop what uses the most memory", f"{describe_apps(apps, 3) or 'A few processes'} hold the most memory.",
                              "Run: top (press M to sort by memory).", "Restart its service (sudo systemctl restart <service>) or stop it if it is not needed."))
    elif os_type == "Darwin":
        tips.append(_tip_dict(f"Quit {names}" if names else "Quit the apps using the most memory", f"{describe_apps(apps, 3) or 'A few apps'} hold the most memory.",
                              "Open Activity Monitor > Memory.", "Quit what you do not need."))
    else:
        tips.append(_tip_dict(f"Close {names}" if names else "Close the programs using the most memory", f"{describe_apps(apps, 3) or 'A few programs'} hold the most memory.",
                              "Open the system's task or activity monitor and sort by memory.", "Close what you do not need."))
    if any(entry["name"].lower().startswith(BROWSERS) for entry in apps[:4]):
        tips.append(_tip_dict("Close browser tabs you do not need", "Every tab is a separate process and keeps its memory.", "Close tabs and windows you are not using.",
                              "Turn on the browser's memory saver (Chrome/Edge: Settings > Performance)."))
    days = _uptime_days(overview)
    if days >= 3:
        restart = {"Windows": "Use Restart (not Shut down) from the Start menu.", "Linux": "Run: sudo reboot", "Darwin": "Apple menu > Restart."}.get(os_type, "Restart it.")
        tips.append(_tip_dict("Restart the computer", f"It has been running for {days} days; a restart clears leaked memory.", "Save your work.", restart))
    total = _size_gb((overview or {}).get("ram_total"))
    if total and total <= 8.5:
        tips.append(_tip_dict("Add more memory (RAM)", f"{total:g} GB is little for today's apps and browsers.", "Check the free slots and supported size on the maker's site."))
    return tips


def _tip_dict(title, why, *steps):
    return {"title": title, "why": why, "steps": list(steps), "risk": "low"}


def _size_gb(text):
    value = _bytes(text)
    return round(value / 1024 ** 3, 1) if value else None


def analyze(evidence, os_type):
    """Evidence is [(tool_id, args, result)]. Returns de-duplicated findings, most severe first."""
    found = {}
    for tool_id, args, result in evidence:
        rule = RULES.get(tool_id)
        if not rule or not result.get("ok"):
            continue
        try:
            items = rule(result.get("data"), result.get("summary") or "", args, os_type)
        except Exception:  # a rule must never break a diagnosis
            continue
        for item in items:
            current = found.get(item["key"])
            if current is None or SEVERITY_ORDER[item["severity"]] < SEVERITY_ORDER[current["severity"]]:
                found[item["key"]] = item
    _name_the_culprits(found, evidence, os_type)
    return sorted(found.values(), key=lambda item: SEVERITY_ORDER[item["severity"]])


def _name_the_culprits(found, evidence, os_type=None):
    """High RAM/CPU from system_overview says what; top_processes says who (per program, not per process).
    Memory also gets concrete tips for this OS."""
    overview = next((result.get("data") for tool_id, _args, result in evidence if tool_id == "system_overview" and isinstance(result.get("data"), dict)), {})
    for key, field in (("ram_high", "memory_percent"), ("cpu_high", "cpu_percent")):
        if key not in found:
            continue
        rows = next((result.get("data") for tool_id, args, result in evidence if tool_id == "top_processes" and (args or {}).get("sort_by", "cpu") == field.split("_")[0] and isinstance(result.get("data"), list)), None)
        apps = group_processes(rows, field) if rows else []
        if apps:
            found[key]["detail"] += " Biggest users: " + describe_apps(apps) + "."
            found[key]["apps"] = [{name: entry[name] for name in ("name", "percent", "count", "role")} for entry in apps[:5]]
        if key == "ram_high":
            found[key]["tips"] = _memory_tips(os_type, apps, overview)


def summarize(findings):
    if not findings:
        return "No problems detected by the instant checks."
    counts = {}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return f"{len(findings)} problem(s) found instantly (" + ", ".join(f"{count} {severity}" for severity, count in sorted(counts.items(), key=lambda pair: SEVERITY_ORDER[pair[0]])) + ")"


# How the main cause of a diagnosis names a finding, by key prefix (first match in the text wins).
FINDING_TOPICS = (
    ("disk_full", r"\b(disk|drive|storage|ssd|hdd)\b[^.]{0,60}\b(full|space)\b|\b(free|disk|storage) space\b|\bfull\b[^.]{0,30}\b(disk|drive)\b|[A-Z]:\\ "),
    ("ram_high", r"\bmemory\b|\bram\b|\bswap|paging|page file"),
    ("cpu_high", r"\bcpu\b|processor"),
    ("net_dns", r"\bdns\b|name resolution"),
    ("net_latency", r"latency|slow (internet|connection)"),
    ("net_packet_loss", r"packet loss"),
    ("net_", r"router|gateway|no (internet|network)|network adapter|offline|captive portal|proxy"),
    ("wifi_", r"signal|wi-?fi|wireless"),
    ("print_spooler_down", r"spooler"),
    ("service_down:Spooler", r"spooler"),
    ("print_queue_stuck", r"print queue|stuck (print )?jobs?"),
    ("hw_overheating", r"overheat|temperature|\bhot\b|thermal|fan\b"),
    ("hw_throttling", r"throttl|clock speed"),
    ("hw_gpu", r"graphics|\bgpu\b|display driver"),
    ("hw_devices", r"device manager|driver problem|device .{0,20}(error|problem|cannot start)"),
    ("hw_errors", r"hardware error|whea|machine.check"),
    ("disk_failing", r"failing (disk|drive)|smart|disk health"),
    ("disk_slow", r"slow (disk|drive|storage)|disk speed|hard disk|\bhdd\b"),
    ("startup_many", r"startup|start-up|login items"),
    ("boot_slow", r"\bboot|start-up time|startup time"),
    ("long_uptime", r"not (been )?restarted|uptime|running for \d+ days"),
    ("crash_", r"crash|blue screen|bsod|kernel panic"),
    ("log_", r"event log|error log"),
    ("reboot_pending", r"pending restart|restart is pending|reboot pending"),
    ("updates_available", r"updates? (are )?(available|waiting)"),
    ("os_updates_", r"updates? (are )?(available|waiting)|security update"),
    ("battery_", r"battery"),
    ("sec_", r"firewall|antivirus|encrypt|exposed port|malware"),
)
MAIN_CAUSE_END = re.compile(r"\b(?:Separate problems?|Other problems?)\b", re.I)


def _topics(finding):
    patterns = [pattern for prefix, pattern in FINDING_TOPICS if finding["key"].startswith(prefix)]
    if finding["key"].startswith("process_"):
        patterns.append(re.escape(finding["key"].split(":", 1)[-1]))
    return patterns


def cited_finding(text, findings):
    """The finding a diagnosis blames: the one its main cause (before any "Separate problems") names first."""
    main = MAIN_CAUSE_END.split(text or "", maxsplit=1)[0]
    best = None
    for item in findings or []:
        for pattern in _topics(item):
            match = re.search(pattern, main, re.I)
            if match and (best is None or match.start() < best[0] or (match.start() == best[0] and SEVERITY_ORDER.get(item.get("severity"), 9) < SEVERITY_ORDER.get(best[1].get("severity"), 9))):
                best = (match.start(), item)
    return best[1] if best else None


def split_by_relevance(findings, playbook):
    """(findings that can explain the complaint, separate problems), each most severe first."""
    related = [item for item in findings or [] if is_related(item, playbook)]
    other = [item for item in findings or [] if not is_related(item, playbook)]
    return related, other


def numbered(findings, playbook=None, limit=10):
    """Findings in the order the AI sees them (complaint-related first), so F1, F2... map back to them."""
    related, other = split_by_relevance(findings, playbook)
    return (related + other)[:limit]


def findings_block(findings, playbook=None):
    """Compact text for the LLM prompt. With a specific complaint, findings are split into those that can
    explain it and separate problems, and numbered F1, F2... so the answer can point at one."""
    if not findings:
        return "- none (the automatic checks found nothing abnormal)"

    def line(index, item):
        return f"- F{index} [{item['severity']}] {item['title']}: {item['detail']}"

    items = numbered(findings, playbook)
    if not is_complaint(playbook):
        return "\n".join(line(index, item) for index, item in enumerate(items, 1))
    related, other = split_by_relevance(items, playbook)
    lines = ["Can explain the complaint:"] + ([line(items.index(item) + 1, item) for item in related] or ["- none: the checks for this complaint found nothing wrong"])
    if other:
        lines += ["Separate problems (they cannot cause this complaint; mention them only as separate problems):"] + [line(items.index(item) + 1, item) for item in other]
    return "\n".join(lines)


DECISIVE_KEYS = ("net_no_adapter", "net_dns", "net_no_internet", "net_router_down", "disk_failing", "print_spooler_down", "service_down:", "crash_system", "disk_full")


def rule_report(findings, issue, note=None, playbook=None):
    """A complete diagnosis built only from findings (instant mode, or when the AI is unavailable). It blames
    only a finding that can explain the complaint; the rest are listed as separate problems."""
    related, other = split_by_relevance(findings, playbook)
    reasoning = [f"Rules: complaint type '{(playbook or {}).get('title') or 'general'}'."]
    if related:
        top = related[0]
        root_cause = f"{top['title']}. {top['detail']}"
        if len(related) > 1:
            root_cause += " Also found: " + "; ".join(item["title"] for item in related[1:3]) + "."
        if other:
            root_cause += " Separate problems: " + "; ".join(item["title"] for item in other[:3]) + "."
        severe = top["severity"] in ("critical", "high")
        confidence = "high" if severe and is_complaint(playbook) and top["key"].startswith(DECISIVE_KEYS) else "medium" if severe or is_complaint(playbook) else "low"
        severity = top["severity"]
        reasoning.append(f"{top['title']} can explain it ({top['severity']}).")
    elif other:
        root_cause = ("The checks for this complaint did not show the problem, so it may come and go. "
                      "Separate problems found: " + "; ".join(item["title"] for item in other[:4]) + ".")
        confidence = "low"
        severity = "medium" if any(item["severity"] in ("critical", "high") for item in other) else "low"
        reasoning.append("Nothing found can explain it; the findings are separate problems.")
    else:
        root_cause = "The automatic checks found nothing abnormal for this issue. Try the AI diagnosis for a deeper look, or describe the problem in more detail."
        confidence, severity = "low", "low"
        reasoning.append("Nothing abnormal found.")
    if note:
        root_cause = f"{root_cause} ({note})"
    raw_fixes = [fix for item in related + other for fix in item["fixes"]]
    return {
        "issue_summary": issue[:500],
        "root_cause": root_cause[:1500],
        "confidence": confidence,
        "severity": severity,
        "evidence": [f"{item['title']}: {item['detail']}"[:300] for item in (related + other)[:10]],
        "raw_fixes": raw_fixes,
        "manual_steps": [],
        "reasoning": " ".join(reasoning),
    }


def related_findings(findings, tool_id):
    """Findings a given fix tool is meant to resolve."""
    return [item for item in findings or [] if any(fix["tool_id"] == tool_id for fix in item.get("fixes", []))]
