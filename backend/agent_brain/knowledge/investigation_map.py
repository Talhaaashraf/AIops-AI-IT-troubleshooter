"""The universal "where do I look?" map (spec §8).

Each component is one place a problem can live, named in a few words and tied to the read-only
tools that reveal it. Domain cards (domains.py) reference these keys so a card stays short and the
labels stay consistent; the unknown-problem path (a later phase) walks this map directly.

Kept compact on purpose: these labels are rendered into the CPU model's prompt, where every token
costs time. One short phrase per component, not a paragraph.
"""

# component key -> (short where-to-look label, tools that reveal it)
INVESTIGATION_MAP = {
    "cpu": ("CPU load & busiest processes", ("system_overview", "top_processes")),
    "memory": ("RAM/commit use & biggest memory users", ("system_overview", "top_processes")),
    "disk_space": ("free space on the system drive", ("system_overview", "cleanup_candidates")),
    "disk_io": ("disk speed/latency & SMART health", ("performance_benchmark", "disk_health")),
    "startup": ("programs/services starting at sign-in", ("startup_programs", "boot_performance")),
    "thermal": ("temperature & CPU throttling", ("hardware_health",)),
    "services": ("stopped or failed system services", ("service_status", "failed_services")),
    "drivers": ("device-manager problems & driver status", ("hardware_health", "driver_inventory")),
    "event_logs": ("System/Application error & critical events", ("event_log_errors",)),
    "crashes": ("BSOD/unexpected restarts & crash history", ("recent_crashes",)),
    "updates": ("pending/failed OS updates & pending reboot", ("update_status", "os_updates")),
    "network_l3": ("IP address, gateway & adapter state", ("check_internet",)),
    "network_l4": ("TCP reachability to the service/port", ("check_internet", "ping_host", "test_tcp_port")),
    "dns": ("name resolution (DNS)", ("check_internet", "dns_lookup")),
    "wifi": ("Wi-Fi signal strength & link", ("wifi_status",)),
    "spooler": ("print spooler service & the queue", ("printer_status", "service_status")),
    "printer_net": ("printer reachability (ping, TCP 9100/515/631, web UI)", ("ping_host", "test_tcp_port", "printer_status")),
    "battery": ("battery wear & power mode", ("battery_health",)),
    "security": ("firewall, antivirus & real-time protection", ("security_posture",)),
    "threats": ("antivirus detections & security logs", ("threat_scan",)),
    "office_state": ("Office install type (Click-to-Run/MSI), build, channel, ClickToRunSvc", ("microsoft_products", "installed_software")),
    "app_state": ("the app's install, version, dependencies, permissions & logs", ("installed_software", "event_log_errors")),
    "recent_change": ("what changed just before (updates, drivers, new software)", ("update_status", "os_updates", "installed_software")),
}


def label(key):
    entry = INVESTIGATION_MAP.get(key)
    return entry[0] if entry else key.replace("_", " ")


def tools_for(key):
    entry = INVESTIGATION_MAP.get(key)
    return entry[1] if entry else ()


def where(keys):
    """A compact "where to look" phrase list for the given component keys."""
    return [label(key) for key in keys]
