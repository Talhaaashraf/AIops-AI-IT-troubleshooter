"""Windows-safe psutil collectors returning JSON-serializable dictionaries."""

import datetime
import logging
import platform
import socket

import psutil

from agent.toolkit.common import cpu_frequency

logger = logging.getLogger(__name__)
_failed_sections = set()


def human_size(value):
    if value is None:
        return "N/A"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def get_system_info():
    boot = psutil.boot_time()
    uptime = max(0, datetime.datetime.now().timestamp() - boot)
    return {
        "os_name": platform.system(),
        "os_version": platform.version(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "processor": platform.processor() or "Unknown",
        "hostname": socket.gethostname(),
        "boot_time": datetime.datetime.fromtimestamp(boot).isoformat(sep=" ", timespec="seconds"),
        "uptime": str(datetime.timedelta(seconds=int(uptime))),
        "uptime_seconds": round(uptime, 2),
    }


def get_cpu_info():
    frequency = cpu_frequency()
    per_core = psutil.cpu_percent(interval=0.15, percpu=True)
    return {
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "max_frequency_mhz": round(frequency.max, 2) if frequency else None,
        "current_frequency_mhz": round(frequency.current, 2) if frequency else None,
        "per_core_usage_percent": [round(value, 2) for value in per_core],
        "total_usage_percent": round(psutil.cpu_percent(interval=None), 2),
    }


def get_memory_info():
    memory, swap = psutil.virtual_memory(), psutil.swap_memory()
    return {
        "ram": {
            "total": human_size(memory.total),
            "available": human_size(memory.available),
            "used": human_size(memory.used),
            "usage_percent": round(memory.percent, 2),
        },
        "swap": {
            "total": human_size(swap.total),
            "used": human_size(swap.used),
            "usage_percent": round(swap.percent, 2),
        },
    }


def get_disk_info():
    disks = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.append({
            "device": partition.device,
            "mountpoint": partition.mountpoint,
            "filesystem": partition.fstype,
            "total": human_size(usage.total),
            "used": human_size(usage.used),
            "free": human_size(usage.free),
            "usage_percent": round(usage.percent, 2),
        })
    return disks


def get_network_info():
    counters, stats = psutil.net_io_counters(), psutil.net_if_stats()
    interfaces = []
    for name, addresses in psutil.net_if_addrs().items():
        ipv4 = [address.address for address in addresses if address.family == socket.AF_INET]
        interface_stats = stats.get(name)
        interfaces.append({
            "name": name,
            "status": "UP" if interface_stats and interface_stats.isup else "DOWN",
            "ipv4_addresses": ipv4,
        })
    return {
        "bytes_sent": human_size(counters.bytes_sent) if counters else "N/A",
        "bytes_received": human_size(counters.bytes_recv) if counters else "N/A",
        "interfaces": interfaces,
    }


def get_battery_info():
    try:
        battery = psutil.sensors_battery()
    except (AttributeError, OSError):
        battery = None
    if battery is None:
        return None
    remaining = "Unknown" if battery.secsleft < 0 else str(datetime.timedelta(seconds=int(battery.secsleft)))
    return {
        "percent": round(battery.percent, 2),
        "charging": bool(battery.power_plugged),
        "time_remaining": remaining,
    }


def get_top_processes():
    processes = []
    for process in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = process.info
            processes.append({
                "pid": info["pid"],
                "name": info.get("name") or "Unknown",
                "cpu_percent": round(info.get("cpu_percent") or 0, 2),
                "memory_percent": round(info.get("memory_percent") or 0, 2),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {
        "top_by_cpu": sorted(processes, key=lambda item: item["cpu_percent"], reverse=True)[:5],
        "top_by_memory": sorted(processes, key=lambda item: item["memory_percent"], reverse=True)[:5],
    }


def _safe(section, collector, fallback=None):
    """One unreadable section must not blank the whole dashboard. Logged once per section, not every 5 s."""
    try:
        value = collector()
    except Exception:
        if section not in _failed_sections:
            _failed_sections.add(section)
            logger.warning("Could not read the %s section of this server's report", section, exc_info=True)
        return fallback
    _failed_sections.discard(section)
    return value


def collect_report():
    try:
        process_count = len(list(psutil.process_iter()))
    except (OSError, psutil.Error):
        process_count = None
    return {
        "system": _safe("system", get_system_info, {}),
        "cpu": _safe("cpu", get_cpu_info, {}),
        "memory": _safe("memory", get_memory_info, {}),
        "disk": _safe("disk", get_disk_info, []),
        "network": _safe("network", get_network_info, {}),
        "battery": _safe("battery", get_battery_info),
        "processes_count": process_count,
    }
