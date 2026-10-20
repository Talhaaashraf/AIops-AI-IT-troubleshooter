"""Built-in IT troubleshooting playbooks.

A playbook gives the agent a deterministic head start: its baseline tools run
before the LLM is consulted, so even a small local model starts from real
evidence instead of guessing which checks matter.
"""

from ..text import stem, stems

ANY = None
WINDOWS = {"Windows"}
INPUT_OS = {"Windows", "Linux"}

PLAYBOOKS = [
    {"id": "slow_pc", "title": "Slow / hanging PC", "issue": "The computer is slow, laggy or keeps hanging.",
     "tools": [("top_processes", {"sort_by": "cpu"}, ANY), ("top_processes", {"sort_by": "memory"}, ANY), ("startup_programs", {}, ANY), ("hardware_health", {}, ANY),
               ("recent_crashes", {}, ANY)],
     "keywords": ["slow", "slowly", "slower", "slowness", "hang", "lag", "freeze", "frozen", "sluggish", "stuck", "not responding", "faster", "ahista", "atak"]},
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

# For a complaint no playbook matches: a broad look, since fast mode no longer lets the AI pick extra checks.
GENERAL_TOOLS = [("top_processes", {"sort_by": "cpu"}, ANY), ("top_processes", {"sort_by": "memory"}, ANY), ("event_log_errors", {}, ANY),
                 ("recent_crashes", {}, ANY), ("hardware_health", {}, ANY)]

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


# Findings (by key prefix) that can explain each complaint. Everything else found is a separate problem: a full
# disk does not break DNS, high memory does not stop a printer. "!" means only at high or critical severity
# (a 90% full disk with 23 GB free does not make a PC slow; one with 1.5 GB free does).
SLOW_CAUSES = ("ram_high", "cpu_high", "process_", "hw_overheating", "hw_throttling", "hw_thermal_warning", "hw_errors", "disk_slow",
               "disk_failing", "startup_many", "long_uptime", "crash_apps", "boot_slow", "disk_full!")
RELATED_FINDINGS = {
    "slow_pc": SLOW_CAUSES,
    "high_usage": SLOW_CAUSES,
    "performance": SLOW_CAUSES + ("os_updates_", "reboot_pending", "battery_low"),
    "no_internet": ("net_", "wifi_", "service_down:Dhcp", "service_down:NlaSvc", "service_down:Dnscache"),
    "wifi_drops": ("wifi_", "net_", "log_"),
    "disk_full": ("disk_full", "cleanup_"),
    "printer": ("print_", "service_down:Spooler"),
    "windows_update": ("reboot_pending", "updates_available", "os_updates_", "service_down:wuauserv", "service_down:BITS", "log_", "disk_full"),
    "crashes": ("crash_", "log_", "disk_failing", "hw_", "ram_high"),
    "battery": ("battery_", "process_cpu", "cpu_high", "hw_overheating"),
    "audio": ("service_down:Audio", "log_", "hw_devices"),
    "security": ("sec_", "startup_many", "process_cpu"),
    "hardware": ("hw_", "disk_failing", "disk_slow", "battery_worn", "input_"),
    "os_health": ("services_failed", "service_down", "reboot_pending", "os_updates_", "updates_available", "crash_", "log_", "disk_failing"),
}


def is_related(finding, playbook):
    """Can this finding explain the playbook's complaint? Without a specific complaint (no playbook, a check-up)
    every finding counts."""
    prefixes = RELATED_FINDINGS.get((playbook or {}).get("id"))
    if prefixes is None:
        return True
    for prefix in prefixes:
        severe_only = prefix.endswith("!")
        if finding["key"].startswith(prefix.rstrip("!")):
            return not severe_only or finding.get("severity", "medium") in ("high", "critical")
    return False


def is_complaint(playbook):
    """A specific complaint whose evidence can confirm or rule it out (not a check-up)."""
    return (playbook or {}).get("id") in RELATED_FINDINGS


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


# Words that describe how something misbehaves rather than what: they help, but weigh less than a subject
# ("wifi is slow" is a Wi-Fi problem, not a slow PC).
SYMPTOM_WORDS = {stem(word) for word in ("slow", "slowly", "slower", "slowness", "stuck", "lag", "faster", "usage", "full", "drops", "disconnect",
                                          "restart", "closes", "update", "connect", "online", "offline")}


def _keyword_hits(keyword, tokens):
    """Positions where a (possibly multi-word) keyword occurs as whole, stemmed words."""
    parts = stems(keyword)
    return [index for index in range(len(tokens) - len(parts) + 1) if tokens[index:index + len(parts)] == parts] if parts else []


def match_playbook(issue):
    """Pick the playbook whose keywords best match a free-text issue (None if nothing matches). Whole words only
    ("mic" is not in "Microsoft", "ram" is not in "program"), word forms count ("freezing" is "freeze"), a subject
    weighs twice a symptom, and a tie goes to whatever the user mentioned first."""
    tokens = stems(issue)
    best, best_key = None, None
    for item in PLAYBOOKS:
        score, first = 0, len(tokens)
        for keyword in item["keywords"]:
            hits = _keyword_hits(keyword, tokens)
            if hits:
                score += 1 if " ".join(stems(keyword)) in SYMPTOM_WORDS else 2
                first = min(first, hits[0])
        if score and (best_key is None or (score, -first) > best_key):
            best, best_key = item, (score, -first)
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


LINUX = {"Linux"}
MACOS = {"Darwin"}


def _tip(title, why, *steps, os=None):
    """A manual suggestion; `os` limits it to those systems (None: any)."""
    return {"title": title, "why": why, "steps": list(steps), "risk": "low", "os": os}


# Safe, manual suggestions used only to top a diagnosis up to 3 options when the model and the rules
# offered fewer. They never run anything: the person follows them by hand. Steps name the tools of each OS.
PLAYBOOK_TIPS = {
    "no_internet": [
        _tip("Restart the router and this computer's network", "Clears a stuck connection on either side.", "Turn the router off for 30 seconds, then on.", "Turn Wi-Fi off and on again on the computer."),
        _tip("Try another network", "Tells a problem with this computer apart from a problem with the network.", "Connect to a phone hotspot.", "If websites work there, the router or provider is the problem."),
        _tip("Check whether only some websites fail", "A single failing site is usually that site's problem, not yours.", "Open two or three well-known sites.", "Try the failing site on a phone on the same network."),
    ],
    "wifi_drops": [
        _tip("Move closer to the router or remove obstacles", "Weak signal is the most common cause of drops.", "Check the signal bars where the drops happen.", "Avoid thick walls and microwaves between you and the router."),
        _tip("Forget and re-join the Wi-Fi network", "Refreshes stored settings that may be corrupt.", "Open Wi-Fi settings, choose Forget for this network.", "Connect again and enter the password."),
        _tip("Update the Wi-Fi adapter driver", "Old drivers often cause random disconnects.", "Open Device Manager > Network adapters.", "Update the Wi-Fi adapter from the laptop maker's support site.", os=WINDOWS),
        _tip("Update the Wi-Fi driver and firmware", "Old drivers and firmware often cause random disconnects.", "Run: sudo apt update && sudo apt upgrade (installs new linux-firmware).", "Restart afterwards.", os=LINUX),
        _tip("Install macOS updates", "They carry the Wi-Fi driver fixes.", "Open System Settings > General > Software Update.", os=MACOS),
    ],
    "slow_pc": [
        _tip("Close programs you are not using", "Frees memory and CPU straight away.", "Open Task Manager, sort by Memory.", "Close the apps at the top you do not need.", os=WINDOWS),
        _tip("Restart the computer", "Clears memory leaks and finishes pending updates.", "Save your work.", "Use Restart (not Shut down) from the Start menu.", os=WINDOWS),
        _tip("Reduce startup programs", "Fewer programs at sign-in means a faster, lighter system.", "Open Task Manager > Startup apps.", "Disable apps you do not need at sign-in.", os=WINDOWS),
        _tip("Find and stop what uses the most memory and CPU", "One process or service is usually behind the slowness.", "Run: top (press M to sort by memory, P by CPU).", "Stop the program, or restart its service: sudo systemctl restart <service>.", os=LINUX),
        _tip("Restart the machine at a quiet time", "Clears memory leaks and finishes kernel updates.", "Run: sudo reboot", os=LINUX),
        _tip("Disable services you do not need at boot", "Fewer services means more free memory and CPU.", "List them: systemctl list-unit-files --state=enabled", "Disable one you do not need: sudo systemctl disable --now <service>", os=LINUX),
        _tip("Close apps you are not using", "Frees memory and CPU straight away.", "Open Activity Monitor, sort by Memory.", "Quit the apps at the top you do not need.", os=MACOS),
        _tip("Restart the Mac", "Clears memory leaks and finishes updates.", "Apple menu > Restart.", os=MACOS),
        _tip("Remove login items", "Fewer apps at login means a lighter system.", "Open System Settings > General > Login Items.", "Remove apps you do not need.", os=MACOS),
    ],
    "performance": [
        _tip("Reduce startup programs", "Fewer programs at sign-in means a faster start-up and more free memory.", "Open Task Manager > Startup apps.", "Disable apps you do not need at sign-in.", os=WINDOWS),
        _tip("Install pending updates, then restart", "Updates fix slowdowns in Windows and drivers, and a restart finishes them.", "Install updates from the Performance tab or Windows Update.", "Restart the computer afterwards.", os=WINDOWS),
        _tip("Disable services you do not need at boot", "Fewer services means a faster start and more free memory.", "List them: systemctl list-unit-files --state=enabled", "Disable one you do not need: sudo systemctl disable --now <service>", os=LINUX),
        _tip("Install pending updates, then restart", "Updates fix slowdowns in the kernel and drivers.", "Run: sudo apt update && sudo apt upgrade", "Then: sudo reboot", os=LINUX),
        _tip("Remove login items and install updates", "Fewer apps at login and current macOS fixes make the Mac faster.", "System Settings > General > Login Items.", "System Settings > General > Software Update.", os=MACOS),
        _tip("Upgrade to an SSD or add memory", "If the disk test is slow or memory is always full, hardware is the bottleneck.", "Check the disk speed and memory use in the Performance tab.", "An SSD or more RAM is the biggest speed-up for an older machine."),
    ],
    "disk_full": [
        _tip("Remove large files you no longer need", "Large videos and installers fill disks fastest.", "Open Settings > System > Storage.", "Review Downloads and large files and delete what you do not need.", os=WINDOWS),
        _tip("Find what fills the disk", "A few large folders usually take most of the space.", "Run: sudo du -xh / --max-depth=2 | sort -h | tail -20", "Delete or move what you do not need.", os=LINUX),
        _tip("Clean package caches and old logs", "They grow quietly on servers.", "Run: sudo apt clean", "Run: sudo journalctl --vacuum-time=7d", os=LINUX),
        _tip("Review large files in Storage settings", "Large files and old backups fill disks fastest.", "Open System Settings > General > Storage.", "Review the recommendations and large files.", os=MACOS),
        _tip("Uninstall programs you do not use", "Unused programs take space and run updates in the background.", "Open the Software tab and sort out unused programs."),
        _tip("Move files to another drive or cloud storage", "Keeps the system drive free for the system and its updates.", "Move photos and videos to another drive or cloud folder."),
    ],
    "high_usage": [
        _tip("Find and close the busy program", "One program is usually behind high CPU or memory.", "Open Task Manager and sort by CPU or Memory.", "Close the top program if you do not need it.", os=WINDOWS),
        _tip("Find and stop the busy process", "One process is usually behind high CPU or memory.", "Run: top (P sorts by CPU, M by memory).", "Stop it, or restart its service: sudo systemctl restart <service>.", os=LINUX),
        _tip("Find and quit the busy app", "One app is usually behind high CPU or memory.", "Open Activity Monitor and sort by CPU or Memory.", "Quit the top app if you do not need it.", os=MACOS),
        _tip("Restart the computer", "Stops runaway background processes.", "Save your work and restart."),
        _tip("Check for malware", "Unknown processes using a lot of CPU can be malware.", "Run a full scan with your antivirus."),
    ],
    "crashes": [
        _tip("Install all pending updates", "Many crashes are fixed by driver and system updates.", "Open Settings > Windows Update and install everything.", os=WINDOWS),
        _tip("Update graphics and chipset drivers", "Faulty drivers are the most common cause of blue screens.", "Get the latest drivers from the laptop maker's support site.", os=WINDOWS),
        _tip("Check the disk and memory", "Failing disks or RAM cause random crashes.", "Run the Windows Memory Diagnostic.", "Check disk health in the Performance tab.", os=WINDOWS),
        _tip("Install pending updates", "Many crashes are fixed by kernel and driver updates.", "Run: sudo apt update && sudo apt upgrade", os=LINUX),
        _tip("Read the errors from the last boot", "The log names what failed before the crash.", "Run: journalctl -p err -b -1 | tail -50", os=LINUX),
        _tip("Test the memory", "Failing RAM causes random crashes.", "Choose memtest86+ in the boot menu and let it run a full pass.", os=LINUX),
        _tip("Install macOS updates", "Many crashes are fixed by system updates.", "Open System Settings > General > Software Update.", os=MACOS),
        _tip("Read the crash reports", "They name the app or driver that failed.", "Open Console > Crash Reports.", os=MACOS),
    ],
}
GENERIC_TIPS = [
    _tip("Restart the computer", "Many temporary problems disappear after a restart.", "Save your work.", "Restart from the Start menu.", os=WINDOWS),
    _tip("Restart the machine", "Many temporary problems disappear after a restart.", "Save your work.", "Run: sudo reboot", os=LINUX),
    _tip("Restart the Mac", "Many temporary problems disappear after a restart.", "Save your work.", "Apple menu > Restart.", os=MACOS),
    _tip("Install pending updates", "Updates fix known bugs in the system and drivers.", "Open Settings > Windows Update and install everything.", os=WINDOWS),
    _tip("Install pending updates", "Updates fix known bugs in the system and drivers.", "Run: sudo apt update && sudo apt upgrade", os=LINUX),
    _tip("Install pending updates", "Updates fix known bugs in the system and drivers.", "Open System Settings > General > Software Update.", os=MACOS),
    _tip("Note when the problem happens", "A pattern (time, app, network) points to the cause.", "Write down what you were doing when it happened and run a new diagnosis then."),
]
DNS_TIP = _tip("Use a faster DNS server", "Every new website waits for the DNS answer, and this one is slow.",
               "Set the DNS servers to 1.1.1.1 and 8.8.8.8 in the network adapter or router settings.", "Open a few websites again and compare.")


KNOWN_OS = {"Windows", "Linux", "Darwin"}


def _for_os(tips, os_type):
    """Tips for this OS; an unknown OS keeps them all (better a Windows step than none)."""
    return [tip for tip in tips if tip["os"] is None or os_type not in KNOWN_OS or os_type in tip["os"]]


def playbook_tips(playbook, os_type=None, evidence=()):
    """The playbook's manual tips for this OS, then general ones. Network tips depend on what the checks saw."""
    tips = PLAYBOOK_TIPS.get((playbook or {}).get("id"), [])
    if (playbook or {}).get("id") in ("no_internet", "wifi_drops"):
        stages = next(((result.get("data") or {}) for tool_id, _args, result in evidence if tool_id == "check_internet" and result.get("ok")), {})
        if ((stages.get("dns_resolution") or {}).get("ms") or 0) > 150:
            tips = [DNS_TIP] + tips
    return _for_os(tips, os_type) + _for_os(GENERIC_TIPS, os_type)
