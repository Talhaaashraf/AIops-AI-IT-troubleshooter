"""Detailed, rule-based health report for one device snapshot (no AI, instant).

The AI analysis is layered on top of this: the rules decide *what* is wrong from the
measurements, the model explains *why* and how to fix it, so a small local model
cannot invent problems the data does not show.
"""

import re

from .ai_technician import _event_groups
from .rules_engine import (
    CPU_WARNING_PERCENT,
    RAM_WARNING_PERCENT,
    SEVERITY_ORDER,
    evaluate_event_log_rules,
    evaluate_performance_rules,
    evaluate_rules,
    evaluate_security_rules,
)

SEVERITY_PENALTY = {"critical": 25, "high": 15, "medium": 8, "low": 3}
# Each further issue counts a bit less, so ten small issues do not read as a dead machine.
PENALTY_DECAY = 0.75
SWAP_WARNING_PERCENT = 60
IDLE_PROCESS_NAMES = {"system idle process", "idle"}
HOG_CPU_PERCENT = 50  # per-process, summed across cores
HOG_MEMORY_PERCENT = 15


def _issue(severity, category, title, evidence):
    return {"severity": severity, "category": category, "title": title, "evidence": evidence}


def _from_alert(alert):
    return _issue(alert["severity"], alert["category"], alert["description"], alert["description"])


def _real_processes(items):
    return [item for item in items or [] if item.get("pid") != 0 and (item.get("name") or "").lower() not in IDLE_PROCESS_NAMES]


def _hog_issues(report):
    """Name the processes behind high CPU/RAM, which is what a technician needs to act on."""
    found = []
    processes = report.get("top_processes") or {}
    cpu = (report.get("cpu") or {}).get("total_usage_percent") or 0
    ram = ((report.get("memory") or {}).get("ram") or {}).get("usage_percent") or 0
    if cpu > CPU_WARNING_PERCENT:
        hogs = [item for item in _real_processes(processes.get("top_by_cpu")) if (item.get("cpu_percent") or 0) >= HOG_CPU_PERCENT]
        if hogs:
            names = ", ".join(f"{item.get('name')} ({item.get('cpu_percent')}%)" for item in hogs[:3])
            found.append(_issue("medium", "CPU", f"Processes using the most CPU: {names}", f"Total CPU {cpu}%"))
    if ram > RAM_WARNING_PERCENT:
        hogs = [item for item in processes.get("top_by_memory") or [] if (item.get("memory_percent") or 0) >= HOG_MEMORY_PERCENT]
        top = hogs or (processes.get("top_by_memory") or [])[:3]
        if top:
            names = ", ".join(f"{item.get('name')} ({item.get('memory_percent')}%)" for item in top[:3])
            found.append(_issue("medium", "Memory", f"Processes using the most memory: {names}", f"RAM {ram}% used"))
    return found


def _extra_issues(report):
    found = []
    swap = ((report.get("memory") or {}).get("swap") or {}).get("usage_percent") or 0
    if swap > SWAP_WARNING_PERCENT:
        found.append(_issue("medium", "Memory", f"Page file / swap is {swap}% used", "The system is short of RAM and paging to disk, which makes it slow."))
    antivirus = (report.get("security") or {}).get("antivirus") or {}
    if antivirus.get("available") is False:
        found.append(_issue("low", "Security", "Antivirus status could not be read", antivirus.get("detail") or "No antivirus information"))
    return found


ADAPTER_DOWN = re.compile(r"^(.+) is down but has a configured IP$")
PORT_LISTENING = re.compile(r"^(.+ port (\d+)) is listening on (\S+) \((.*)\)\.$")


def _merge_noise(issues):
    """The alert rules fire once per adapter and per address; a report reads better with one line each."""
    merged, adapters, ports = [], [], {}
    for item in issues:
        adapter = ADAPTER_DOWN.match(item["title"])
        port = PORT_LISTENING.match(item["title"])
        if adapter:
            adapters.append(adapter.group(1))
        elif port:
            key = port.group(2)
            if key in ports:
                ports[key]["addresses"].append(port.group(3))
                continue
            ports[key] = {"item": item, "label": port.group(1), "addresses": [port.group(3)], "process": port.group(4)}
            merged.append(item)
        else:
            merged.append(item)
    for entry in ports.values():
        entry["item"]["title"] = entry["item"]["evidence"] = f"{entry['label']} is listening on {', '.join(entry['addresses'])} ({entry['process']})"
    if adapters:
        # Mostly disconnected cables and virtual Wi-Fi Direct adapters: worth a mention, rarely a problem.
        title = f"{len(adapters)} network adapter(s) are down but keep an IP configuration: {', '.join(adapters[:4])}"
        merged.append(_issue("low", "Network", title, title))
    return merged


def detect_issues(report):
    alerts = (
        evaluate_rules(report)
        + evaluate_security_rules(report.get("security"))
        + evaluate_performance_rules(report.get("performance"))
        + evaluate_event_log_rules(report.get("event_logs"))
    )
    issues = _merge_noise([_from_alert(alert) for alert in alerts]) + _hog_issues(report) + _extra_issues(report)
    return sorted(issues, key=lambda item: SEVERITY_ORDER.get(item["severity"], 9))


def score(issues):
    penalties = sorted((SEVERITY_PENALTY.get(item["severity"], 0) for item in issues), reverse=True)
    value = max(0, round(100 - sum(penalty * PENALTY_DECAY ** index for index, penalty in enumerate(penalties))))
    rating = "good" if value >= 85 else "fair" if value >= 65 else "poor" if value >= 40 else "critical"
    return value, rating


def _detail(section):
    return section.get("detail") if isinstance(section, dict) and section.get("available") is not False else None


def details(report):
    """Everything worth showing about the machine, grouped for display."""
    system = report.get("system") or {}
    cpu = report.get("cpu") or {}
    memory = report.get("memory") or {}
    ram, swap = memory.get("ram") or {}, memory.get("swap") or {}
    security = report.get("security") or {}
    performance = report.get("performance") or {}
    event_logs = report.get("event_logs") or {}
    network = report.get("network") or {}
    processes = report.get("top_processes") or {}
    battery = report.get("battery")
    return {
        "system": {
            "Hostname": system.get("hostname"),
            "Operating system": " ".join(str(part) for part in (system.get("os_name"), system.get("os_release"), system.get("os_version")) if part),
            "Architecture": system.get("architecture"),
            "Processor": system.get("processor"),
            "CPU cores": f"{cpu.get('physical_cores')} physical / {cpu.get('logical_cores')} logical",
            "CPU frequency": f"{cpu.get('current_frequency_mhz')} / {cpu.get('max_frequency_mhz')} MHz",
            "Memory": ram.get("total"),
            "Processes running": report.get("processes_count"),
        },
        "resources": {
            "cpu_percent": cpu.get("total_usage_percent"),
            "ram_percent": ram.get("usage_percent"),
            "ram": f"{ram.get('used')} used of {ram.get('total')} ({ram.get('available')} free)",
            "swap": f"{swap.get('used')} of {swap.get('total')} ({swap.get('usage_percent')}%)",
        },
        "disks": [
            {"name": disk.get("mountpoint") or disk.get("device"), "filesystem": disk.get("filesystem"), "percent": disk.get("usage_percent"), "used": disk.get("used"), "free": disk.get("free"), "total": disk.get("total")}
            for disk in report.get("disk") or []
        ],
        "battery": {"percent": battery.get("percent"), "charging": battery.get("charging"), "time_remaining": battery.get("time_remaining")} if isinstance(battery, dict) else None,
        "top_cpu": [{"name": item.get("name"), "pid": item.get("pid"), "value": item.get("cpu_percent")} for item in _real_processes(processes.get("top_by_cpu"))[:5]],
        "top_memory": [{"name": item.get("name"), "pid": item.get("pid"), "value": item.get("memory_percent")} for item in (processes.get("top_by_memory") or [])[:5]],
        "security": {
            "Firewall": _detail(security.get("firewall")),
            "Antivirus": _detail(security.get("antivirus")),
            "Disk encryption": _detail(security.get("disk_encryption")),
            "Updates": _detail(security.get("updates")),
            "Listening ports": (security.get("listening_ports") or {}).get("count"),
            "Running as admin": security.get("running_as_admin"),
        },
        "performance": {
            "CPU benchmark": _detail(performance.get("cpu")),
            "Disk speed": _detail(performance.get("disk")),
            "Network latency": _detail(performance.get("network")),
        },
        "event_logs": {
            "available": bool(event_logs.get("available")),
            "lookback_hours": event_logs.get("lookback_hours"),
            "critical": event_logs.get("critical_count"),
            "errors": event_logs.get("error_count"),
            "warnings": event_logs.get("warning_count"),
            "most_frequent": _event_groups(event_logs, 8),
        },
        "network": {
            "Sent": network.get("bytes_sent"),
            "Received": network.get("bytes_received"),
            "Interfaces up": sum(1 for item in network.get("interfaces") or [] if item.get("status") == "UP"),
        },
    }


def build(report, collected_at=None):
    issues = detect_issues(report or {})
    value, rating = score(issues)
    return {"collected_at": collected_at, "score": value, "rating": rating, "issues": issues, "details": details(report or {})}
