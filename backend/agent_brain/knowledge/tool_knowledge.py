"""Tool knowledge (spec §42, §6-7): what question each read-only check answers.

This teaches the model to pick a check to TEST A HYPOTHESIS, not run it because it exists. Kept to one
short "question answered" line per tool (the registry already holds the description, risk, params and OS);
the retriever renders a few of these as a hint during the deep-mode investigation, scoped to the domain.

Only diagnostic (read) tools belong here; change tools are proposed as fixes, never as investigation.
"""

# tool_id -> the question it answers (one short line)
TOOL_QUESTIONS = {
    "system_overview": "What are the overall CPU, memory, disk and uptime numbers right now?",
    "top_processes": "Which programs use the most CPU or memory (all their processes added up)?",
    "startup_programs": "What starts automatically at sign-in?",
    "hardware_health": "Is anything wrong with temperature, GPU, devices or logged hardware (WHEA) errors?",
    "disk_health": "Does any physical disk report failing SMART health?",
    "performance_benchmark": "How fast is the disk actually reading/writing?",
    "boot_performance": "How long does start-up take and what slows it down?",
    "recent_crashes": "Have there been BSODs or unexpected restarts, and how often?",
    "event_log_errors": "What error/critical events is the OS logging, and how often?",
    "check_internet": "Which network layer works and which fails (adapter, gateway, TCP, DNS, HTTP)?",
    "dns_lookup": "Does a given name resolve, and to what address?",
    "ping_host": "Is a given host reachable on the network?",
    "test_tcp_port": "Is a specific TCP port open on a host (e.g. printer 9100/515/631, a web UI, a database)?",
    "driver_inventory": "Which drivers are installed, and are any unsigned or recently updated?",
    "wifi_status": "What is the Wi-Fi signal strength and link state?",
    "printer_status": "Is the spooler running and are jobs stuck in the queue?",
    "service_status": "Is a specific system service running?",
    "failed_services": "Which system services have failed?",
    "update_status": "Are updates pending or failing, and is a reboot pending?",
    "os_updates": "Which OS/security updates are waiting to install?",
    "cleanup_candidates": "What can be safely cleaned up, and how much space would it free?",
    "battery_health": "How worn is the battery (capacity vs original)?",
    "security_posture": "Are the firewall, antivirus and encryption on, and are risky ports exposed?",
    "threat_scan": "What has the antivirus/security log actually detected?",
    "input_devices": "Are the keyboard, mouse or other input devices working?",
    "installed_software": "What is installed, and at what version?",
    "microsoft_products": "What Microsoft/Office products are installed and is an install blocked?",
}


def question(tool_id):
    return TOOL_QUESTIONS.get(tool_id)


def hint_lines(tool_ids):
    """Compact `- tool: question` lines for the tools we have a question for, in the given order."""
    lines, seen = [], set()
    for tool_id in tool_ids:
        text = TOOL_QUESTIONS.get(tool_id)
        if text and tool_id not in seen:
            seen.add(tool_id)
            lines.append(f"- {tool_id}: {text}")
    return lines
