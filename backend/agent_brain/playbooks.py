"""Built-in IT troubleshooting playbooks.

A playbook gives the agent a deterministic head start: its baseline tools run
before the LLM is consulted, so even a small local model starts from real
evidence instead of guessing which checks matter.
"""

ANY = None
WINDOWS = {"Windows"}
INPUT_OS = {"Windows", "Linux"}

PLAYBOOKS = [
    {"id": "slow_pc", "title": "Slow / hanging PC", "issue": "The computer is slow, laggy or keeps hanging.",
     "tools": [("top_processes", {"sort_by": "cpu"}, ANY), ("top_processes", {"sort_by": "memory"}, ANY), ("startup_programs", {}, ANY), ("hardware_health", {}, ANY)],
     "keywords": ["slow", "hang", "lag", "freeze", "frozen", "sluggish", "stuck", "not responding", "faster", "ahista", "atak"]},
    {"id": "no_internet", "title": "No / slow internet", "issue": "Internet is not working or is very slow.",
     "tools": [("check_internet", {}, ANY), ("wifi_status", {}, ANY)],
     "keywords": ["internet", "network", "website", "browser", "dns", "connect", "online", "offline", "ethernet", "lan"]},
    {"id": "wifi_drops", "title": "Wi-Fi keeps dropping", "issue": "Wi-Fi disconnects frequently or has a weak signal.",
     "tools": [("wifi_status", {}, ANY), ("check_internet", {}, ANY), ("event_log_errors", {}, ANY)],
     "keywords": ["wifi", "wi-fi", "wireless", "signal", "disconnect", "drops"]},
    {"id": "disk_full", "title": "Disk full", "issue": "The disk is full or running out of storage space.",
     "tools": [("cleanup_candidates", {}, ANY)],
     "keywords": ["disk", "storage", "space", "full", "drive", "low disk"]},
    {"id": "high_usage", "title": "High CPU / RAM", "issue": "CPU or memory usage is very high and the fan is loud.",
     "tools": [("top_processes", {"sort_by": "cpu"}, ANY), ("top_processes", {"sort_by": "memory"}, ANY), ("hardware_health", {}, ANY)],
     "keywords": ["cpu", "ram", "memory", "fan", "100%", "usage"]},
    {"id": "printer", "title": "Printer not working", "issue": "The printer is not printing or jobs are stuck in the queue.",
     "tools": [("printer_status", {}, ANY), ("service_status", {"name": "Spooler"}, WINDOWS)],
     "keywords": ["print", "printer", "spooler", "queue"]},
    {"id": "windows_update", "title": "Updates stuck / failing", "issue": "Operating system updates are stuck, failing or not installing.",
     "tools": [("update_status", {}, ANY), ("service_status", {"name": "wuauserv"}, WINDOWS), ("event_log_errors", {}, ANY)],
     "keywords": ["update", "patch", "upgrade", "windows update"]},
    {"id": "crashes", "title": "Crashes / blue screen", "issue": "The computer or apps crash, restart unexpectedly or show a blue screen.",
     "tools": [("recent_crashes", {}, ANY), ("event_log_errors", {}, ANY), ("disk_health", {}, ANY), ("hardware_health", {}, ANY)],
     "keywords": ["crash", "blue screen", "bsod", "restart", "reboot", "shutdown", "panic", "closes"]},
    {"id": "battery", "title": "Battery drains fast", "issue": "The battery drains quickly or does not hold charge.",
     "tools": [("battery_health", {}, ANY), ("top_processes", {"sort_by": "cpu"}, ANY)],
     "keywords": ["battery", "charge", "charging", "drain", "power"]},
    {"id": "audio", "title": "No sound", "issue": "There is no sound or the microphone does not work.",
     "tools": [("service_status", {"name": "Audiosrv"}, WINDOWS), ("service_status", {"name": "AudioEndpointBuilder"}, WINDOWS), ("event_log_errors", {}, ANY)],
     "keywords": ["sound", "audio", "speaker", "mic", "microphone", "headphone", "volume"]},
    {"id": "security", "title": "Security check", "issue": "Check this computer for security problems, malware signs or risky settings.",
     "tools": [("security_posture", {}, ANY), ("startup_programs", {}, ANY), ("top_processes", {"sort_by": "cpu"}, ANY)],
     "keywords": ["virus", "malware", "hack", "security", "firewall", "antivirus", "suspicious", "popup"]},
    {"id": "hardware", "title": "Hardware check", "issue": "Check the hardware: overheating, failing disk, battery wear, RAM, graphics and devices with driver problems.",
     "tools": [("hardware_health", {}, ANY), ("disk_health", {}, ANY), ("battery_health", {}, ANY), ("input_devices", {}, INPUT_OS)],
     "keywords": ["hardware", "overheat", "temperature", "hot", "heat", "thermal", "driver", "device manager", "gpu", "graphics", "display", "screen", "usb", "keyboard", "touchpad", "mouse", "webcam", "camera", "bluetooth", "ram stick", "ssd", "hdd"]},
    {"id": "os_health", "title": "Operating system health", "issue": "Check the operating system: failed services, pending updates or restarts, crashes and system errors.",
     "tools": [("update_status", {}, ANY), ("failed_services", {}, ANY), ("recent_crashes", {}, ANY), ("event_log_errors", {}, ANY)],
     "keywords": ["operating system", "os health", "corrupt", "boot", "won't start", "wont start", "system files", "dll", "registry", "service", "login", "black screen"]},
    {"id": "performance", "title": "Performance test", "issue": "Analyse this computer's performance: what slows it down (start-up, CPU, memory, disk, heat, updates) and how to make it faster.",
     "tools": [("top_processes", {"sort_by": "cpu"}, ANY), ("top_processes", {"sort_by": "memory"}, ANY), ("performance_benchmark", {}, ANY), ("boot_performance", {}, ANY),
               ("hardware_health", {}, ANY), ("disk_health", {}, ANY), ("battery_health", {}, ANY), ("os_updates", {}, ANY)],
     "keywords": ["performance test", "benchmark", "boot time", "startup time", "start-up time"]},
    {"id": "full_checkup", "title": "Full health check-up", "issue": "Run a full health check-up of the OS and hardware and report anything wrong.",
     "tools": [("top_processes", {"sort_by": "cpu"}, ANY), ("check_internet", {}, ANY), ("event_log_errors", {}, ANY), ("security_posture", {}, ANY), ("disk_health", {}, ANY), ("hardware_health", {}, ANY), ("battery_health", {}, ANY), ("update_status", {}, ANY)],
     "keywords": ["checkup", "check-up", "health check", "everything", "general"]},
]

GENERAL_TOOLS = [("event_log_errors", {}, ANY), ("top_processes", {"sort_by": "cpu"}, ANY), ("hardware_health", {}, ANY)]

# Tools that measure live CPU load. They run first, before PowerShell-heavy checks
# start and skew the numbers; everything else then runs in parallel.
CPU_SENSITIVE_TOOLS = {"system_overview", "top_processes"}

# Fixes that can plausibly address each playbook's problem. Small models like to
# propose unrelated fixes (e.g. renew_ip for a full disk); these lists filter them out.
RELEVANT_FIXES = {
    "slow_pc": {"kill_process", "disable_startup_item", "clear_temp_files", "restart_service", "repair_system_files", "rescan_hardware"},
    "performance": {"kill_process", "disable_startup_item", "clear_temp_files", "empty_recycle_bin", "restart_service", "repair_system_files", "rescan_hardware", "trigger_update_scan"},
    "no_internet": {"flush_dns", "renew_ip", "reset_network_stack", "restart_service", "sync_time"},
    "wifi_drops": {"renew_ip", "flush_dns", "restart_service", "reset_network_stack"},
    "disk_full": {"clear_temp_files", "empty_recycle_bin", "clear_windows_update_cache"},
    "high_usage": {"kill_process", "disable_startup_item", "restart_service"},
    "printer": {"clear_print_queue", "restart_service"},
    "windows_update": {"clear_windows_update_cache", "trigger_update_scan", "restart_service", "sync_time", "repair_windows_image", "repair_system_files"},
    "crashes": {"repair_system_files", "repair_windows_image", "kill_process", "rescan_hardware"},
    "hardware": {"rescan_hardware", "restart_service", "kill_process"},
    "os_health": {"repair_system_files", "repair_windows_image", "restart_service", "trigger_update_scan", "clear_windows_update_cache", "sync_time"},
    "battery": {"kill_process", "disable_startup_item"},
    "audio": {"restart_service", "rescan_hardware"},
    "security": {"disable_startup_item", "kill_process", "trigger_update_scan"},
}


def filter_relevant_fixes(fixes, playbook):
    """Drop fixes unrelated to the matched playbook (learned fixes are always kept)."""
    allowed = RELEVANT_FIXES.get((playbook or {}).get("id"))
    if not allowed:
        return fixes
    return [fix for fix in fixes if fix["tool_id"] in allowed or fix.get("learned")]


def public_playbooks():
    return [{"id": item["id"], "title": item["title"], "issue": item["issue"]} for item in PLAYBOOKS]


def get_playbook(playbook_id):
    return next((item for item in PLAYBOOKS if item["id"] == playbook_id), None)


def match_playbook(issue):
    """Pick the playbook whose keywords best match a free-text issue (None if nothing matches)."""
    text = (issue or "").lower()
    best, best_score = None, 0
    for item in PLAYBOOKS:
        score = sum(len(keyword) for keyword in item["keywords"] if keyword in text)
        if score > best_score:
            best, best_score = item, score
    return best


def baseline_tools(playbook, os_type):
    """system_overview first, then the playbook's tools that apply to this OS, de-duplicated."""
    entries = [("system_overview", {}, ANY)] + (playbook["tools"] if playbook else GENERAL_TOOLS)
    seen, result = set(), []
    for tool_id, args, systems in entries:
        key = (tool_id, tuple(sorted(args.items())))
        if key in seen or (systems and os_type not in systems):
            continue
        seen.add(key)
        result.append((tool_id, args))
    return result


def baseline_phases(playbook, os_type):
    """Baseline tools split into [CPU-sensitive tools, everything else]; each phase runs in parallel."""
    tools = baseline_tools(playbook, os_type)
    first = [item for item in tools if item[0] in CPU_SENSITIVE_TOOLS]
    return [phase for phase in (first, [item for item in tools if item[0] not in CPU_SENSITIVE_TOOLS]) if phase]


def _tip(title, why, *steps):
    return {"title": title, "why": why, "steps": list(steps), "risk": "low"}


# Safe, manual suggestions used only to top a diagnosis up to 3 options when the model and the rules
# offered fewer. They never run anything: the person follows them by hand.
PLAYBOOK_TIPS = {
    "no_internet": [
        _tip("Restart the router and this computer's network", "Clears a stuck connection on either side.", "Turn the router off for 30 seconds, then on.", "Turn Wi-Fi off and on again on the computer."),
        _tip("Try another network", "Tells a problem with this computer apart from a problem with the network.", "Connect to a phone hotspot.", "If websites work there, the router or provider is the problem."),
        _tip("Check whether only some websites fail", "A single failing site is usually that site's problem, not yours.", "Open two or three well-known sites.", "Try the failing site on a phone on the same network."),
    ],
    "wifi_drops": [
        _tip("Move closer to the router or remove obstacles", "Weak signal is the most common cause of drops.", "Check the signal bars where the drops happen.", "Avoid thick walls and microwaves between you and the router."),
        _tip("Forget and re-join the Wi-Fi network", "Refreshes stored settings that may be corrupt.", "Open Wi-Fi settings, choose Forget for this network.", "Connect again and enter the password."),
        _tip("Update the Wi-Fi adapter driver", "Old drivers often cause random disconnects.", "Open Device Manager > Network adapters.", "Update the Wi-Fi adapter from the laptop maker's support site."),
    ],
    "slow_pc": [
        _tip("Close programs you are not using", "Frees memory and CPU straight away.", "Open Task Manager, sort by Memory.", "Close the apps at the top you do not need."),
        _tip("Restart the computer", "Clears memory leaks and finishes pending updates.", "Save your work.", "Use Restart (not Shut down) from the Start menu."),
        _tip("Reduce startup programs", "Fewer programs at sign-in means a faster, lighter system.", "Open Task Manager > Startup apps.", "Disable apps you do not need at sign-in."),
    ],
    "performance": [
        _tip("Reduce startup programs", "Fewer programs at sign-in means a faster start-up and more free memory.", "Open Task Manager > Startup apps.", "Disable apps you do not need at sign-in."),
        _tip("Install pending updates, then restart", "Updates fix slowdowns in Windows and drivers, and a restart finishes them.", "Install updates from the Performance tab or Windows Update.", "Restart the computer afterwards."),
        _tip("Upgrade to an SSD or add memory", "If the disk test is slow or memory is always full, hardware is the bottleneck.", "Check the disk speed and memory use in the Performance tab.", "An SSD or more RAM is the biggest speed-up for an older PC."),
    ],
    "disk_full": [
        _tip("Remove large files you no longer need", "Large videos and installers fill disks fastest.", "Open Settings > System > Storage.", "Review Downloads and large files and delete what you do not need."),
        _tip("Uninstall programs you do not use", "Unused programs take space and run updates in the background.", "Open the Software tab and sort out unused programs."),
        _tip("Move files to another drive or cloud storage", "Keeps the system drive free for Windows and updates.", "Move photos and videos to another drive or cloud folder."),
    ],
    "high_usage": [
        _tip("Find and close the busy program", "One program is usually behind high CPU or memory.", "Open Task Manager and sort by CPU or Memory.", "Close the top program if you do not need it."),
        _tip("Restart the computer", "Stops runaway background processes.", "Save your work and restart."),
        _tip("Check for malware", "Unknown processes using a lot of CPU can be malware.", "Run a full scan with your antivirus."),
    ],
    "crashes": [
        _tip("Install all pending updates", "Many crashes are fixed by driver and system updates.", "Open Settings > Windows Update and install everything."),
        _tip("Update graphics and chipset drivers", "Faulty drivers are the most common cause of blue screens.", "Get the latest drivers from the laptop maker's support site."),
        _tip("Check the disk and memory", "Failing disks or RAM cause random crashes.", "Run the Windows Memory Diagnostic.", "Check disk health in the Performance tab."),
    ],
}
GENERIC_TIPS = [
    _tip("Restart the computer", "Many temporary problems disappear after a restart.", "Save your work.", "Restart from the Start menu."),
    _tip("Install pending updates", "Updates fix known bugs in the system and drivers.", "Open Settings > Windows Update (or your system's updater) and install everything."),
    _tip("Note when the problem happens", "A pattern (time, app, network) points to the cause.", "Write down what you were doing when it happened and run a new diagnosis then."),
]


def playbook_tips(playbook):
    return PLAYBOOK_TIPS.get((playbook or {}).get("id"), []) + GENERIC_TIPS
