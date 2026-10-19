"""Diagnosis scenarios that measure how well the AI decides (python -m backend.agent_brain.evaluate) and that the
unit tests reuse as regression cases.

Each case is the evidence the baseline checks returned on a real ticket (names, addresses and SSIDs removed)
and what a correct diagnosis must, and must not, say. Regexes are matched case-insensitively.
  cause        the main root cause (the text before "Separate/Other problems") must match it
  not_blamed   the main root cause must not match it (a finding that cannot cause this complaint)
  confidence   the allowed confidence values
  first        the first solution (title, why, steps) must match it
  forbidden    no solution may match it (steps for the wrong operating system)
"""

WINDOWS_ONLY = r"\bsudo\b|apt(-get)? |systemctl|journalctl"
NOT_WINDOWS = r"Task Manager|Windows Update|\bregedit\b|Control Panel|PowerShell|Settings\s*>|\.exe\b"


def _ok(summary, data):
    return {"ok": True, "summary": summary, "data": data}


def _overview(cpu, ram, swap, disks, os_name="Windows 11 (10.0.26300)", uptime="3 days, 7:34:30", ram_total="15.6 GB"):
    fullest = max(disks, key=lambda disk: disk["used_percent"])
    summary = f"CPU {cpu}%, RAM {ram}% of {ram_total}, uptime {uptime}, fullest disk {fullest['mount']} {fullest['used_percent']}% ({fullest['free']} free)"
    data = {"os": os_name, "uptime": uptime, "cpu_percent": cpu, "cpu_cores_logical": 12, "ram_percent": ram,
            "ram_used": f"{round(ram * 15.6 / 100, 1)} GB", "ram_total": ram_total, "swap_percent": swap, "disks": disks,
            "battery": {"percent": 100, "plugged_in": True}, "process_count": 418}
    return ("system_overview", {}, _ok(summary, data))


def _processes(sort_by, rows):
    field = "cpu_percent" if sort_by == "cpu" else "memory_percent"
    top = ", ".join(f"{row['name']} (pid {row['pid']}) {row[field]}%" for row in rows[:3])
    return ("top_processes", {"sort_by": sort_by}, _ok(f"Top by {sort_by}: {top}", rows))


def _process(pid, name, cpu, memory_percent, memory):
    return {"pid": pid, "name": name, "cpu_percent": cpu, "memory_percent": memory_percent, "memory": memory}


STARTUP_ITEMS = ("startup_programs", {}, _ok("7 startup item(s)", [
    {"name": name, "location": "HKCU"} for name in ("GoogleDriveFS", "SecurityHealth", "RtkAudUService", "Teams", "OneDrive", "Zoom", "Docker Desktop")]))

HEALTHY_HARDWARE = ("hardware_health", {}, _ok(
    "12th Gen Intel(R) Core(TM) i5-1235U; running at 158% of base clock; max temp 66.1 C; RAM 15.6 GB in 1 module(s); GPU Intel(R) UHD Graphics",
    {"model": "Business laptop", "cpu": {"name": "12th Gen Intel(R) Core(TM) i5-1235U", "threads": 12, "performance_percent": 158},
     "gpus": [{"name": "Intel(R) UHD Graphics", "status": "OK", "ok": True}], "problem_devices": [], "hardware_errors_7d": 0,
     "ram_total": "15.6 GB", "max_temperature_c": 66.1, "throttling_suspected": False}))

C_DRIVE_90 = {"mount": "C:\\", "fs": "NTFS", "used_percent": 90.1, "free": "23.3 GB", "total": "236.1 GB"}
D_DRIVE = {"mount": "D:\\", "fs": "NTFS", "used_percent": 44.4, "free": "133.4 GB", "total": "239.8 GB"}

MEMORY_HOGS = [
    _process(18520, "vmmemWSL", 0.4, 16.3, "2.6 GB"), _process(20772, "chrome.exe", 0.2, 6.9, "1.1 GB"),
    _process(21100, "chrome.exe", 0.0, 3.8, "614.3 MB"), _process(21468, "chrome.exe", 0.1, 3.5, "555.3 MB"),
    _process(11072, "msedge.exe", 0.0, 2.3, "365.5 MB"), _process(7432, "chrome.exe", 0.0, 2.0, "327.2 MB"),
]
QUIET_CPU = [
    _process(7148, "klnagent.exe", 3.2, 0.1, "23.4 MB"), _process(3284, "powershell.exe", 2.6, 0.2, "28.7 MB"),
    _process(5772, "avp.exe", 2.0, 1.6, "251.3 MB"), _process(9444, "chrome.exe", 1.0, 0.5, "82.9 MB"),
]


def _internet(dns_ok=True, dns_ms=8, tcp_ms=11, http_ok=True, gateway_loss=0):
    data = {"adapters_with_ip": [{"name": "Wi-Fi", "up": True, "ipv4": ["192.0.2.20"], "speed_mbps": 400}], "self_assigned_ip": False,
            "default_gateway": "192.0.2.1", "gateway_ping": {"reachable": True, "packet_loss_percent": gateway_loss, "avg_ms": 4},
            "dns_servers": ["192.0.2.1"], "dns_resolution": {"ok": dns_ok, "ms": dns_ms},
            "tcp_to_internet": {"ok": True, "ms": tcp_ms}, "http": {"ok": http_ok, "status": 204 if http_ok else None, "ms": 64}}
    if dns_ok and http_ok:
        summary = "Internet connectivity works normally"
    elif not dns_ok:
        summary = "DNS resolution failed: names cannot be resolved although the internet is reachable"
    else:
        summary = "Web requests fail although DNS and TCP work"
    return ("check_internet", {}, _ok(summary, data))


def _wifi(signal):
    return ("wifi_status", {}, _ok(f"Wi-Fi connected to office-wifi, signal {signal}%, rx 144 Mbps",
                                   {"State": "connected", "SSID": "office-wifi", "Signal": f"{signal}%", "Receive rate (Mbps)": "144"}))


CASES = [
    {
        "id": "slow_memory_win",
        "os_type": "Windows",
        "issue": "My laptop is very slow and hangs",
        "evidence": [_overview(17.0, 93.6, 32.9, [C_DRIVE_90, D_DRIVE]), _processes("cpu", QUIET_CPU), _processes("memory", MEMORY_HOGS),
                     STARTUP_ITEMS, HEALTHY_HARDWARE],
        "expect": {"cause": r"memor|\bram\b|swap", "not_blamed": r"\bdisk\b|\bdrive\b|storage|C:\\",
                   "confidence": ("medium", "high"), "first": r"memor|\bram\b|close|chrome|browser|tab|wsl|docker|restart",
                   "forbidden": WINDOWS_ONLY},
    },
    {
        "id": "slow_disk_critical_win",
        "os_type": "Windows",
        "issue": "Laptop is very slow and programs take ages to open",
        "evidence": [_overview(14.0, 58.0, 4.0, [{**C_DRIVE_90, "used_percent": 99.4, "free": "1.5 GB"}, D_DRIVE]),
                     _processes("cpu", QUIET_CPU), _processes("memory", MEMORY_HOGS[1:]), STARTUP_ITEMS, HEALTHY_HARDWARE],
        "expect": {"cause": r"\bdisk\b|\bdrive\b|storage|space|C:\\", "not_blamed": r"memor|\bram\b",
                   "confidence": ("medium", "high"), "first": r"space|clean|temp|delete|disk|storage|recycle|free",
                   "forbidden": WINDOWS_ONLY},
    },
    {
        "id": "internet_ok_win",
        "os_type": "Windows",
        "issue": "Internet is slow and websites take long to open",
        "evidence": [_overview(12.3, 91.9, 29.8, [C_DRIVE_90, D_DRIVE]), _internet(), _wifi(99)],
        "expect": {"cause": r"pass|normal|did not|not (confirm|reproduce|show)|intermittent|works", "not_blamed": r"\bdisk\b|memor|\bram\b",
                   "confidence": ("low",), "first": r"router|restart|another network|speed|test|check|websites|dns|browser",
                   "forbidden": WINDOWS_ONLY},
    },
    {
        "id": "dns_fail_win",
        "os_type": "Windows",
        "issue": "Websites are not opening but Teams still works",
        "evidence": [_overview(9.0, 61.0, 5.0, [{**C_DRIVE_90, "used_percent": 71.0, "free": "68.5 GB"}]), _internet(dns_ok=False, http_ok=False), _wifi(87)],
        "expect": {"cause": r"\bdns\b|name resol|resolv", "not_blamed": r"\bdisk\b|memor",
                   "confidence": ("medium", "high"), "first": r"\bdns\b|flush|resolv",
                   "forbidden": WINDOWS_ONLY},
    },
    {
        "id": "wifi_weak_win",
        "os_type": "Windows",
        "issue": "Wi-Fi keeps disconnecting every few minutes",
        "evidence": [_wifi(22), _internet(gateway_loss=30), ("event_log_errors", {}, _ok("0 critical, 3 errors, 12 warnings in 24h", {"groups": []}))],
        "expect": {"cause": r"signal|wi-?fi|weak|packet loss|router", "not_blamed": r"\bdisk\b|memor",
                   "confidence": ("medium", "high"), "first": r"closer|router|signal|reconnect|renew|wi-?fi|access point|cable",
                   "forbidden": WINDOWS_ONLY},
    },
    {
        "id": "printer_spooler_win",
        "os_type": "Windows",
        "issue": "The printer is not printing anything",
        "evidence": [("printer_status", {}, _ok("Spooler stopped; 1 printer(s), 2 job(s) waiting", {"spooler": "Stopped", "printers": [{"Name": "Office LaserJet", "JobCount": 2}], "jobs": []})),
                     ("service_status", {"name": "Spooler"}, _ok("Spooler is Stopped", {"name": "Spooler", "status": "Stopped"}))],
        "expect": {"cause": r"spooler", "not_blamed": r"\bdisk\b|memor|driver",
                   "confidence": ("medium", "high"), "first": r"spooler|restart",
                   "forbidden": WINDOWS_ONLY},
    },
    {
        "id": "linux_server_cpu",
        "os_type": "Linux",
        "issue": "The server is very slow",
        "evidence": [_overview(96.0, 61.0, 0.0, [{"mount": "/", "fs": "ext4", "used_percent": 48.0, "free": "251.2 GB", "total": "490.0 GB"}],
                               os_name="Linux Ubuntu 24.04", uptime="12 days, 4:10:00"),
                     _processes("cpu", [_process(4121, "python3", 85.2, 4.1, "640.0 MB"), _process(911, "postgres", 6.0, 3.2, "500.0 MB"), _process(1, "systemd", 0.1, 0.1, "12.0 MB")]),
                     _processes("memory", [_process(911, "postgres", 6.0, 3.2, "500.0 MB"), _process(4121, "python3", 85.2, 4.1, "640.0 MB")]),
                     ("startup_programs", {}, _ok("4 startup item(s)", [{"name": name} for name in ("ssh", "cron", "postgresql", "docker")]))],
        "expect": {"cause": r"\bcpu\b|processor|python3", "not_blamed": r"\bdisk\b|memor",
                   "confidence": ("medium", "high"), "first": r"python3|process|cpu|pid|kill|stop|restart",
                   "forbidden": NOT_WINDOWS},
    },
    {
        "id": "clean_checks_win",
        "os_type": "Windows",
        "issue": "My laptop is slow sometimes",
        "evidence": [_overview(11.0, 52.0, 3.0, [{**C_DRIVE_90, "used_percent": 61.0, "free": "92.1 GB"}], uptime="0 days, 5:12:00"),
                     _processes("cpu", QUIET_CPU), _processes("memory", MEMORY_HOGS[1:4]), STARTUP_ITEMS, HEALTHY_HARDWARE],
        "expect": {"cause": r"did not|not (show|confirm|find|reproduce)|no (problem|issue)|normal|healthy|nothing", "not_blamed": r"\bdisk\b is|memory is",
                   "confidence": ("low",), "first": r"check|when|monitor|note|watch|run|test|task manager|resource",
                   "forbidden": WINDOWS_ONLY},
    },
]

CASES_BY_ID = {case["id"]: case for case in CASES}
