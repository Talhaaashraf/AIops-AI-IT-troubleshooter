"""Specialist troubleshooting agents: Hardware, Operating system and Network.

A specialist is not a separate model. Every specialist uses the same local brain, the Ollama `aiops-brain`
model, with the same suggest-only principles. What a specialist adds is its own instructions: what to focus
on, what must not be concluded, and which read-only checks it may run in deep mode. A smaller tool list
also makes the prompt shorter, which matters on a CPU server.

Routing is deterministic: the matched playbook decides, never the model. A problem outside the three domains
(security, a full check-up, an unclear complaint) goes to the general technician, which is how every diagnosis
worked before.

The specialist's instructions go at the top of the user message, not into the system prompt. The system
prompt stays identical for every diagnosis, so Ollama can reuse its cached prompt and answer sooner.
"""

# Read-only checks every specialist may use when investigating.
COMMON_TOOLS = frozenset({"system_overview", "event_log_errors", "service_status"})

SPECIALISTS = {
    "hardware": {
        "id": "hardware",
        "name": "Hardware specialist",
        "playbooks": frozenset({"hardware", "battery", "audio", "printer"}),
        "focus": (
            "You are the AIops Hardware specialist. You own physical components and their drivers: CPU heat and "
            "throttling, disks (SMART health, slow or failing drives), memory, battery wear, graphics, audio devices, "
            "printers, USB and input devices.",
            "Separate a failing part from a driver or configuration problem: a device with a driver error is not a "
            "broken device, and a worn battery is not a charging fault.",
            "Name the component and the reading that proves it (temperature, SMART status, wear percentage, device "
            "error code). Without such a reading, say the part is not proven faulty.",
            "Suggest a hardware replacement only when a reading shows failure; otherwise suggest a driver, firmware "
            "or setting step first.",
        ),
        "tools": frozenset({"hardware_health", "disk_health", "battery_health", "input_devices", "driver_inventory",
                            "printer_status", "test_tcp_port", "ping_host", "top_processes", "performance_benchmark",
                            "recent_crashes"}),
    },
    "os": {
        "id": "os",
        "name": "Operating system specialist",
        "playbooks": frozenset({"os_health", "windows_update", "crashes", "slow_pc", "high_usage", "disk_full", "performance"}),
        "focus": (
            "You are the AIops Operating system specialist. You own the OS and the software on it: processes and "
            "memory, start-up items and boot time, services, updates, system files, crashes and disk space.",
            "Find the process, service, update or setting behind the complaint, and cite its name and numbers from the "
            "evidence.",
            "A crash or blue screen with hardware evidence (WHEA errors, a failing disk, overheating) is a hardware "
            "problem: say so instead of suggesting OS repairs.",
            "Prefer reversible steps (stop a program, disable a start-up item, clear temporary files) before repairs "
            "such as system file checks or update resets.",
        ),
        "tools": frozenset({"top_processes", "startup_programs", "boot_performance", "cleanup_candidates", "update_status",
                            "os_updates", "failed_services", "recent_crashes", "driver_inventory", "disk_health",
                            "hardware_health", "performance_benchmark"}),
    },
    "network": {
        "id": "network",
        "name": "Network specialist",
        "playbooks": frozenset({"no_internet", "wifi_drops"}),
        "focus": (
            "You are the AIops Network specialist. You own connectivity: the adapter and its driver, Wi-Fi signal, "
            "IP address and DHCP, DNS, the gateway, the firewall and reaching the internet.",
            "Work through the layers in order: adapter and link, IP address, gateway, DNS, then internet and the "
            "website. The first layer that fails is the cause; later failures follow from it.",
            "If every network test passed, say the problem did not show up in the checks. Do not blame the computer "
            "for a problem with the router, the provider or one website.",
            "Prefer the least disruptive step first: flush DNS or renew the IP address before a network reset.",
        ),
        "tools": frozenset({"check_internet", "ping_host", "dns_lookup", "test_tcp_port", "wifi_status", "driver_inventory",
                            "security_posture"}),
    },
}

GENERAL = {
    "id": "general",
    "name": "General technician",
    "playbooks": frozenset(),
    "focus": (),
    "tools": None,  # every read-only check, as before specialists existed
}


def route(playbook):
    """The specialist that owns this playbook, or the general technician."""
    playbook_id = (playbook or {}).get("id")
    return next((item for item in SPECIALISTS.values() if playbook_id in item["playbooks"]), GENERAL)


def get(specialist_id):
    return SPECIALISTS.get(specialist_id, GENERAL if specialist_id == "general" else None)


def instructions(specialist):
    """The specialist's block for the top of a user message ("" for the general technician)."""
    if not specialist or not specialist["focus"]:
        return ""
    return "Specialist instructions:\n" + "\n".join(f"- {line}" for line in specialist["focus"]) + "\n\n"


def investigation_tools(specialist):
    """Read-only tool ids this specialist may call in deep mode (None: no limit)."""
    if not specialist or specialist["tools"] is None:
        return None
    return specialist["tools"] | COMMON_TOOLS


def label(specialist):
    return {"id": specialist["id"], "name": specialist["name"]}


def public_specialists():
    return [{"id": item["id"], "name": item["name"], "playbooks": sorted(item["playbooks"]),
             "focus": item["focus"][0] if item["focus"] else "Problems outside the three specialist areas: security, full check-ups and unclear complaints.",
             } for item in (*SPECIALISTS.values(), GENERAL)]
