"""Instant, rule-based findings from diagnostic evidence (no LLM).

These run in milliseconds right after the baseline checks, so the operator sees
concrete problems within seconds. They also feed the LLM pre-digested facts,
stand in for the AI report when the model is unavailable or too slow, and let a
fix be verified deterministically by checking whether its finding disappeared.

A finding is {key, severity, title, detail, source, fixes: [{tool_id, args, why}]}.
`key` identifies the same problem across runs (used for verification).
"""

import re

from agent.toolkit.remediation import PROTECTED_PROCESSES, RESTARTABLE_SERVICES

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SIZE_PATTERN = re.compile(r"([\d.]+)\s*(B|KB|MB|GB|TB)")
SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
UPTIME_DAYS = re.compile(r"(\d+)\s+day")
# USB sticks, SD cards, optical media and cloud-drive mounts (Google Drive shows up as a "full"
# FAT32 disk): a full one never slows the computer down, so it is not a disk-full problem.
NON_SYSTEM_FILESYSTEMS = {"fat", "fat32", "vfat", "exfat", "msdos", "cdfs", "iso9660", "udf", "squashfs", "fuse", "fuseblk"}


def _finding(key, severity, title, detail, source, fixes=()):
    return {"key": key, "severity": severity, "title": title, "detail": detail, "source": source, "fixes": list(fixes)}


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
        if used >= 85:
            severity = "critical" if used >= 95 else "high" if used >= 90 else "medium"
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
        if value < threshold:
            continue
        kind = "CPU" if by_cpu else "memory"
        severity = "high" if value >= (75 if by_cpu else 45) else "medium"
        fixes = [] if name.lower() in PROTECTED_PROCESSES else [_fix("kill_process", f"{name} is using {value}% {kind}", pid=row.get("pid"), expected_name=name)]
        found.append(_finding(f"process_{kind.lower()}:{name.lower()}", severity, f"{name} is using {value}% {kind}", f"PID {row.get('pid')}, memory {row.get('memory')}.", "top_processes", fixes))
    return found


def _check_internet(data, summary, args, os_type):
    stages = data or {}
    gateway_ping = stages.get("gateway_ping") or {}
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
        ports = ", ".join(str(port.get("port")) for port in risky[:5])
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


RULES = {
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
    _name_the_culprits(found, evidence)
    return sorted(found.values(), key=lambda item: SEVERITY_ORDER[item["severity"]])


def _name_the_culprits(found, evidence):
    """High RAM/CPU from system_overview says what; top_processes says who. Join them."""
    for key, field in (("ram_high", "memory_percent"), ("cpu_high", "cpu_percent")):
        if key not in found:
            continue
        rows = next((result.get("data") for tool_id, args, result in evidence if tool_id == "top_processes" and (args or {}).get("sort_by", "cpu") == field.split("_")[0] and isinstance(result.get("data"), list)), None)
        if rows:
            top = sorted(rows, key=lambda row: row.get(field) or 0, reverse=True)[:3]
            found[key]["detail"] += " Biggest users: " + ", ".join(f"{row.get('name')} {row.get(field)}%" for row in top) + "."


def summarize(findings):
    if not findings:
        return "No problems detected by the instant checks."
    counts = {}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return f"{len(findings)} problem(s) found instantly (" + ", ".join(f"{count} {severity}" for severity, count in sorted(counts.items(), key=lambda pair: SEVERITY_ORDER[pair[0]])) + ")"


def findings_block(findings):
    """Compact text for the LLM prompt."""
    if not findings:
        return "- none (the automatic checks found nothing abnormal)"
    return "\n".join(f"- [{item['severity']}] {item['title']}: {item['detail']}" for item in findings[:10])


def rule_report(findings, issue, note=None):
    """A complete diagnosis built only from findings (instant mode, or when the AI is unavailable)."""
    if findings:
        top = findings[0]
        root_cause = f"{top['title']}. {top['detail']}"
        if len(findings) > 1:
            root_cause += " Other problems: " + "; ".join(item["title"] for item in findings[1:4]) + "."
        confidence = "high" if top["severity"] in ("critical", "high") else "medium"
        severity = top["severity"]
    else:
        root_cause = "The automatic checks found nothing abnormal for this issue. Try the AI diagnosis for a deeper look, or describe the problem in more detail."
        confidence, severity = "low", "low"
    if note:
        root_cause = f"{root_cause} ({note})"
    raw_fixes = [fix for item in findings for fix in item["fixes"]]
    return {
        "issue_summary": issue[:500],
        "root_cause": root_cause[:1500],
        "confidence": confidence,
        "severity": severity,
        "evidence": [f"{item['title']}: {item['detail']}"[:300] for item in findings[:10]],
        "raw_fixes": raw_fixes,
        "manual_steps": [],
    }


def related_findings(findings, tool_id):
    """Findings a given fix tool is meant to resolve."""
    return [item for item in findings or [] if any(fix["tool_id"] == tool_id for fix in item.get("fixes", []))]
