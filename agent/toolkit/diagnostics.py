"""Read-only diagnostic tools the AI troubleshooter may call on its own.

Each tool returns {ok, summary, data}. `summary` is a one-line, human-readable
finding and `data` is kept compact on purpose: these results are fed to a
small local LLM, so every extra token slows the diagnosis down.
"""

import datetime
import glob
import json
import os
import platform
import re
import socket
import tempfile
import threading
import time
import urllib.request
from collections import Counter
from pathlib import Path

import psutil

from .common import human_size, is_admin, os_name, powershell, run_command, directory_size
from .event_logs import collect_event_log_report
from .performance_checks import collect_performance_report
from .registry import tool
from .security_checks import RISKY_PORTS, collect_security_report, get_pending_updates

HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:\-]{0,252}$")
SERVICE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@\-]{0,99}$")
CONNECTIVITY_URL = "http://connectivitycheck.gstatic.com/generate_204"


def valid_host(host):
    return bool(HOST_PATTERN.match(host or ""))


def valid_service_name(name):
    return bool(SERVICE_PATTERN.match(name or ""))


# ---------------------------------------------------------------------------
# Shared path helpers (also used by remediation)
# ---------------------------------------------------------------------------

def temp_directories():
    paths = {tempfile.gettempdir()}
    system = os_name()
    if system == "Windows":
        windir = os.environ.get("SystemRoot", r"C:\Windows")
        paths.add(os.path.join(windir, "Temp"))
        if is_admin():
            system_drive = os.environ.get("SystemDrive", "C:")
            paths.update(glob.glob(os.path.join(system_drive + "\\", "Users", "*", "AppData", "Local", "Temp")))
    elif system == "Linux":
        paths.update({"/tmp", "/var/tmp"})
    return sorted(path for path in paths if os.path.isdir(path))


def trash_directories():
    system = os_name()
    if system == "Windows":
        path = os.path.join(os.environ.get("SystemDrive", "C:") + "\\", "$Recycle.Bin")
        return [path] if os.path.isdir(path) else []
    if system == "Darwin":
        path = os.path.expanduser("~/.Trash")
    else:
        path = os.path.expanduser("~/.local/share/Trash")
    return [path] if os.path.isdir(path) else []


# ---------------------------------------------------------------------------
# System / processes / storage
# ---------------------------------------------------------------------------

@tool("system_overview", "Snapshot of OS, uptime, CPU, RAM, swap, disks, battery and process count. Good first step for any issue.")
def system_overview():
    cpu = psutil.cpu_percent(interval=0.5)
    memory, swap = psutil.virtual_memory(), psutil.swap_memory()
    frequency = psutil.cpu_freq()
    uptime_seconds = int(time.time() - psutil.boot_time())
    disks = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.append({"mount": partition.mountpoint, "fs": partition.fstype, "used_percent": round(usage.percent, 1), "free": human_size(usage.free), "total": human_size(usage.total)})
    battery = None
    try:
        sensed = psutil.sensors_battery()
        if sensed:
            battery = {"percent": round(sensed.percent), "plugged_in": bool(sensed.power_plugged)}
    except (AttributeError, OSError):
        pass
    data = {
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "hostname": socket.gethostname(),
        "uptime": str(datetime.timedelta(seconds=uptime_seconds)),
        "running_as_admin": is_admin(),
        "cpu_percent": cpu,
        "cpu_cores_logical": psutil.cpu_count(logical=True),
        "cpu_freq_mhz": round(frequency.current) if frequency else None,
        "ram_percent": memory.percent,
        "ram_used": human_size(memory.used),
        "ram_total": human_size(memory.total),
        "swap_percent": swap.percent,
        "disks": disks,
        "battery": battery,
        "process_count": len(psutil.pids()),
    }
    worst_disk = max(disks, key=lambda item: item["used_percent"], default=None)
    summary = f"CPU {cpu}%, RAM {memory.percent}% of {data['ram_total']}, uptime {data['uptime']}"
    if worst_disk:
        summary += f", fullest disk {worst_disk['mount']} {worst_disk['used_percent']}% ({worst_disk['free']} free)"
    return {"ok": True, "summary": summary, "data": data}


# CPU% needs two readings one second apart for every process. On Windows each reading of a
# process the agent cannot open falls back to a full system query, so one sample costs seconds.
# Calls that arrive together (the CPU and memory views of one diagnosis) share a single sample.
_sample_lock = threading.Lock()
_sample = {"rows": None, "at": 0.0}
SAMPLE_REUSE_SECONDS = 1.5


def _process_sample():
    with _sample_lock:
        if _sample["rows"] is not None and time.monotonic() - _sample["at"] < SAMPLE_REUSE_SECONDS:
            return _sample["rows"]
        _sample["rows"] = _measure_processes()
        _sample["at"] = time.monotonic()
        return _sample["rows"]


def _measure_processes():
    # memory_percent is derived from the prefetched memory_info: asking psutil for both reads it twice.
    processes = list(psutil.process_iter(["pid", "name", "memory_info"]))
    total_memory = psutil.virtual_memory().total or 1
    for process in processes:
        try:
            process.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    time.sleep(1.0)
    cores = psutil.cpu_count(logical=True) or 1
    rows = []
    for process in processes:
        try:
            cpu = process.cpu_percent(None) / cores
            info = process.info
            if info["name"] in ("System Idle Process", "idle"):
                continue
            rows.append({
                "pid": info["pid"],
                "name": info.get("name") or "Unknown",
                "cpu_percent": round(cpu, 1),
                "memory_percent": round(info["memory_info"].rss / total_memory * 100, 1) if info.get("memory_info") else 0.0,
                "memory": human_size(info["memory_info"].rss) if info.get("memory_info") else "N/A",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return rows


@tool(
    "top_processes",
    "List the processes using the most CPU or memory right now (measured over one second).",
    params={"sort_by": {"type": "string", "enum": ["cpu", "memory"], "description": "Sort by cpu or memory"}, "limit": {"type": "integer", "minimum": 1, "maximum": 20, "description": "How many processes (default 8)"}},
)
def top_processes(sort_by="cpu", limit=8):
    key = "cpu_percent" if sort_by == "cpu" else "memory_percent"
    rows = sorted(_process_sample(), key=lambda item: item[key], reverse=True)[:limit]
    top = rows[0] if rows else None
    summary = f"Top by {sort_by}: " + ", ".join(f"{row['name']} (pid {row['pid']}) {row[key]}%" for row in rows[:3]) if top else "No processes readable"
    return {"ok": True, "summary": summary, "data": rows}


@tool("cleanup_candidates", "Measure how much space temp folders, the recycle bin/trash, Downloads and the Windows Update cache use. Read-only.")
def cleanup_candidates():
    items = []
    for path in temp_directories():
        items.append({"location": path, "kind": "temp", "size_bytes": directory_size(path)})
    for path in trash_directories():
        items.append({"location": path, "kind": "trash", "size_bytes": directory_size(path)})
    downloads = Path.home() / "Downloads"
    if downloads.is_dir():
        items.append({"location": str(downloads), "kind": "downloads (user files, never auto-deleted)", "size_bytes": directory_size(downloads)})
    if os_name() == "Windows":
        update_cache = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SoftwareDistribution", "Download")
        if os.path.isdir(update_cache):
            items.append({"location": update_cache, "kind": "windows update cache", "size_bytes": directory_size(update_cache)})
    for item in items:
        item["size"] = human_size(item.pop("size_bytes"))
    summary = "; ".join(f"{item['kind']} {item['size']}" for item in items) or "No cleanup locations found"
    return {"ok": True, "summary": summary, "data": items}


@tool("startup_programs", "List programs that start automatically at login (registry Run keys, startup folders, LaunchAgents, autostart).")
def startup_programs():
    items = []
    system = os_name()
    if system == "Windows":
        import winreg
        locations = [
            ("HKCU", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM32", winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for label, hive, path in locations:
            try:
                with winreg.OpenKey(hive, path) as key:
                    for index in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, index)
                        items.append({"name": name, "location": label, "command": str(value)[:160]})
            except OSError:
                continue
        folders = [os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\StartUp")]
    elif system == "Darwin":
        folders = [os.path.expanduser("~/Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    else:
        folders = [os.path.expanduser("~/.config/autostart"), "/etc/xdg/autostart"]
    for folder in folders:
        if os.path.isdir(folder):
            for name in sorted(os.listdir(folder))[:40]:
                if name.lower() != "desktop.ini":
                    items.append({"name": name, "location": folder, "command": ""})
    return {"ok": True, "summary": f"{len(items)} startup item(s)", "data": items[:60]}


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def _default_gateway():
    system = os_name()
    if system == "Windows":
        output = powershell("(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop")["stdout"]
        return output.strip() or None
    if system == "Darwin":
        match = re.search(r"gateway:\s*(\S+)", run_command(["route", "-n", "get", "default"])["stdout"])
        return match.group(1) if match else None
    match = re.search(r"default via (\S+)", run_command(["ip", "route", "show", "default"])["stdout"])
    return match.group(1) if match else None


def _dns_servers():
    system = os_name()
    if system == "Windows":
        output = powershell("(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses | Sort-Object -Unique")["stdout"]
        return [line.strip() for line in output.splitlines() if line.strip()][:6]
    if system == "Darwin":
        output = run_command(["scutil", "--dns"])["stdout"]
        return sorted(set(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", output)))[:6]
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as handle:
            return [line.split()[1] for line in handle if line.startswith("nameserver")][:6]
    except OSError:
        return []


def _ping(host, count=4):
    command = ["ping", "-n", str(count), "-w", "1500", host] if os_name() == "Windows" else ["ping", "-c", str(count), "-W", "2", host]
    result = run_command(command, timeout=count * 3 + 5)
    output = result["stdout"]
    loss = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss", output, re.IGNORECASE)
    average = re.search(r"Average\s*=\s*(\d+)\s*ms", output) or re.search(r"=\s*[\d.]+/([\d.]+)/", output)
    return {
        "host": host,
        "reachable": result["returncode"] == 0,
        "packet_loss_percent": float(loss.group(1)) if loss else (0.0 if result["returncode"] == 0 else 100.0),
        "avg_ms": float(average.group(1)) if average else None,
    }


@tool("check_internet", "Step-by-step internet connectivity test: network adapters, default gateway, DNS servers, DNS resolution, raw TCP and HTTP. Use for any 'no internet' / 'slow internet' issue.", timeout=60)
def check_internet():
    stats = psutil.net_if_stats()
    adapters = []
    for name, addresses in psutil.net_if_addrs().items():
        ipv4 = [item.address for item in addresses if item.family == socket.AF_INET and not item.address.startswith("127.")]
        if ipv4:
            adapters.append({"name": name, "up": bool(stats.get(name) and stats[name].isup), "ipv4": ipv4, "speed_mbps": stats[name].speed if stats.get(name) else None})
    stages = {"adapters_with_ip": [item for item in adapters if item["up"]]}
    stages["self_assigned_ip"] = any(ip.startswith("169.254.") for item in adapters for ip in item["ipv4"])
    gateway = _default_gateway()
    stages["default_gateway"] = gateway
    stages["gateway_ping"] = _ping(gateway, 3) if gateway and valid_host(gateway) else None
    stages["dns_servers"] = _dns_servers()
    started = time.perf_counter()
    try:
        socket.getaddrinfo("www.google.com", 443)
        stages["dns_resolution"] = {"ok": True, "ms": round((time.perf_counter() - started) * 1000)}
    except OSError as error:
        stages["dns_resolution"] = {"ok": False, "error": str(error)}
    started = time.perf_counter()
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=4):
            stages["tcp_to_internet"] = {"ok": True, "ms": round((time.perf_counter() - started) * 1000)}
    except OSError as error:
        stages["tcp_to_internet"] = {"ok": False, "error": str(error)}
    try:
        started = time.perf_counter()
        with urllib.request.urlopen(CONNECTIVITY_URL, timeout=6) as response:
            status = response.status
        stages["http"] = {"ok": status == 204, "status": status, "ms": round((time.perf_counter() - started) * 1000), "captive_portal_suspected": status != 204}
    except Exception as error:
        stages["http"] = {"ok": False, "error": str(error)[:200]}

    if not stages["adapters_with_ip"]:
        verdict = "No active network adapter has an IP address (cable/Wi-Fi disconnected or adapter disabled)"
    elif stages["self_assigned_ip"] and not gateway:
        verdict = "Adapter has a self-assigned 169.254.x.x address: DHCP failed, IP renewal is likely needed"
    elif not gateway:
        verdict = "No default gateway: the device is not getting a route from the router/DHCP"
    elif stages["gateway_ping"] and not stages["gateway_ping"]["reachable"]:
        verdict = "Router/gateway is not answering pings (local network or Wi-Fi problem; some routers block ping)"
    elif not stages["tcp_to_internet"]["ok"]:
        verdict = "Local network works but the internet is unreachable (ISP/router upstream or firewall problem)"
    elif not stages["dns_resolution"]["ok"]:
        verdict = "Internet reachable by IP but DNS resolution fails: DNS problem (flush DNS / change DNS servers)"
    elif not stages["http"]["ok"]:
        verdict = "TCP works but HTTP check failed: proxy, captive portal or web filtering suspected"
    else:
        slow = (stages["dns_resolution"].get("ms") or 0) > 300 or (stages["tcp_to_internet"].get("ms") or 0) > 300
        verdict = "Internet connectivity works" + (" but latency is high" if slow else " normally")
    return {"ok": True, "summary": verdict, "data": stages}


@tool("ping_host", "Ping a host name or IP address 4 times and report packet loss and average latency.", params={"host": {"type": "string", "maxLength": 253, "description": "Host name or IP address, e.g. 8.8.8.8"}}, required=("host",), timeout=40)
def ping_host(host):
    if not valid_host(host):
        return {"ok": False, "summary": "Invalid host name"}
    result = _ping(host)
    return {"ok": True, "summary": f"{host}: {'reachable' if result['reachable'] else 'unreachable'}, loss {result['packet_loss_percent']}%, avg {result['avg_ms']} ms", "data": result}


@tool("dns_lookup", "Resolve a host name with the system DNS resolver and time it.", params={"hostname": {"type": "string", "maxLength": 253}}, required=("hostname",))
def dns_lookup(hostname):
    if not valid_host(hostname):
        return {"ok": False, "summary": "Invalid host name"}
    started = time.perf_counter()
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None)})
    except OSError as error:
        return {"ok": True, "summary": f"DNS lookup for {hostname} failed: {error}", "data": {"resolved": False, "error": str(error)}}
    elapsed = round((time.perf_counter() - started) * 1000)
    return {"ok": True, "summary": f"{hostname} resolved to {', '.join(addresses[:3])} in {elapsed} ms", "data": {"resolved": True, "addresses": addresses[:8], "ms": elapsed}}


@tool("wifi_status", "Show the current Wi-Fi connection: network name, signal strength, radio type and link speed.")
def wifi_status():
    system = os_name()
    if system == "Windows":
        output = run_command(["netsh", "wlan", "show", "interfaces"])["stdout"]
        if not output or "There is no wireless interface" in output:
            return {"ok": True, "summary": "No Wi-Fi interface (wired or Wi-Fi service off)", "data": None}
        fields = {}
        for line in output.splitlines():
            if " : " in line:
                key, value = line.split(" : ", 1)
                fields[key.strip()] = value.strip()
        data = {key: fields.get(key) for key in ("State", "SSID", "Signal", "Radio type", "Channel", "Receive rate (Mbps)", "Transmit rate (Mbps)")}
        return {"ok": True, "summary": f"Wi-Fi {data['State']} to {data['SSID']}, signal {data['Signal']}, rx {data['Receive rate (Mbps)']} Mbps", "data": data}
    if system == "Darwin":
        output = run_command(["system_profiler", "SPAirPortDataType"], timeout=30)["stdout"]
        current = output.split("Current Network Information:", 1)[1][:800] if "Current Network Information:" in output else ""
        signal = re.search(r"Signal / Noise:\s*(.+)", current)
        return {"ok": True, "summary": f"Wi-Fi signal/noise {signal.group(1).strip()}" if signal else "No active Wi-Fi network", "data": current.strip() or None}
    output = run_command(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,RATE,CHAN", "dev", "wifi"])["stdout"]
    active = [line.split(":") for line in output.splitlines() if line.startswith("yes:")]
    if not active:
        return {"ok": True, "summary": "No active Wi-Fi connection (or nmcli unavailable)", "data": None}
    _, ssid, signal, rate, channel = (active[0] + ["", "", "", ""])[:5]
    return {"ok": True, "summary": f"Wi-Fi {ssid}, signal {signal}%, rate {rate}", "data": {"ssid": ssid, "signal_percent": signal, "rate": rate, "channel": channel}}


# ---------------------------------------------------------------------------
# Security, logs, crashes
# ---------------------------------------------------------------------------

@tool("security_posture", "Firewall, antivirus, disk encryption, patch history and risky listening ports.", timeout=60)
def security_posture():
    report = collect_security_report()
    ports = (report.get("listening_ports") or {}).get("ports", [])
    risky = [port for port in ports if port["port"] in RISKY_PORTS and not str(port["address"]).startswith(("127.", "::1"))]
    report["listening_ports"] = {"count": len(ports), "risky_exposed": risky}
    problems = []
    if report["firewall"].get("enabled") is False:
        problems.append("firewall OFF")
    if report["antivirus"].get("enabled") is False:
        problems.append("antivirus/real-time protection OFF")
    if report["disk_encryption"].get("encrypted") is False:
        problems.append("disk not encrypted")
    if risky:
        problems.append(f"{len(risky)} risky port(s) exposed")
    return {"ok": True, "summary": "Security issues: " + ", ".join(problems) if problems else "No security posture problems detected", "data": report}


@tool("event_log_errors", "Recent (24h) warning/error/critical OS event log entries, grouped by source so repeated failures stand out.", timeout=60)
def event_log_errors():
    report = collect_event_log_report()
    groups = Counter()
    samples = {}
    for event in report.get("events", []):
        key = (event.get("source") or "unknown", event.get("id"), event.get("level"))
        groups[key] += 1
        samples.setdefault(key, event.get("message", "")[:200])
    grouped = [{"source": source, "event_id": event_id, "level": level, "count": count, "sample": samples[(source, event_id, level)]} for (source, event_id, level), count in groups.most_common(12)]
    summary = f"{report.get('critical_count', 0)} critical, {report.get('error_count', 0)} errors, {report.get('warning_count', 0)} warnings in {report.get('lookback_hours')}h"
    if grouped:
        summary += f"; most frequent: {grouped[0]['source']} (x{grouped[0]['count']})"
    return {"ok": report.get("available", False), "summary": summary, "data": {"detail": report.get("detail"), "groups": grouped}}


@tool("recent_crashes", "Find crashes in the last 7 days: blue screens / kernel panics, unexpected shutdowns, application crashes and hangs, out-of-memory kills.", timeout=60)
def recent_crashes():
    system = os_name()
    if system == "Windows":
        script = (
            "$s=(Get-Date).AddDays(-7);"
            "$e=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=41,1001,6008;StartTime=$s} -MaxEvents 15 -ErrorAction SilentlyContinue)"
            "+@(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000,1002;StartTime=$s} -MaxEvents 25 -ErrorAction SilentlyContinue);"
            "$e | Select-Object @{N='time';E={$_.TimeCreated.ToString('o')}},Id,ProviderName,@{N='message';E={($_.Message -split \"`n\")[0..2] -join ' '}} | ConvertTo-Json -Compress"
        )
        output = powershell(script, timeout=50)["stdout"]
        try:
            rows = json.loads(output) if output else []
        except json.JSONDecodeError:
            rows = []
        rows = rows if isinstance(rows, list) else [rows]
        labels = {41: "unexpected power loss/reboot (Kernel-Power)", 1001: "blue screen / error report", 6008: "unexpected shutdown", 1000: "application crash", 1002: "application hang"}
        events = [{"time": row.get("time"), "type": labels.get(row.get("Id"), str(row.get("Id"))), "source": row.get("ProviderName"), "message": str(row.get("message", ""))[:220]} for row in rows]
    elif system == "Linux":
        output = run_command(["journalctl", "--since=-7d", "--no-pager", "-o", "short-iso", "-g", "Out of memory|oom-kill|segfault|kernel panic|Call Trace|core dumped"], timeout=40)["stdout"]
        events = [{"type": "kernel/app fault", "message": line[:220]} for line in output.splitlines()[-25:]]
    else:
        events = []
        for folder in ("/Library/Logs/DiagnosticReports", os.path.expanduser("~/Library/Logs/DiagnosticReports")):
            for path in sorted(glob.glob(os.path.join(folder, "*")), key=os.path.getmtime, reverse=True)[:20]:
                if time.time() - os.path.getmtime(path) < 7 * 86400:
                    kind = "kernel panic" if "panic" in path.lower() else "application crash/hang"
                    events.append({"time": datetime.datetime.fromtimestamp(os.path.getmtime(path)).isoformat(), "type": kind, "message": os.path.basename(path)})
    kinds = Counter(event["type"] for event in events)
    summary = ", ".join(f"{count}x {kind}" for kind, count in kinds.most_common()) or "No crashes found in the last 7 days"
    return {"ok": True, "summary": summary, "data": events[:25]}


# ---------------------------------------------------------------------------
# Services, updates, hardware health, printers
# ---------------------------------------------------------------------------

@tool("service_status", "Check whether one OS service is running (e.g. Spooler, wuauserv, WlanSvc, Audiosrv, NetworkManager, cups).", params={"name": {"type": "string", "maxLength": 100, "description": "Service name"}}, required=("name",))
def service_status(name):
    if not valid_service_name(name):
        return {"ok": False, "summary": "Invalid service name"}
    system = os_name()
    if system == "Windows":
        try:
            service = psutil.win_service_get(name).as_dict()
        except psutil.NoSuchProcess:
            return {"ok": True, "summary": f"Service {name} does not exist", "data": None}
        except Exception as error:
            return {"ok": False, "summary": f"Could not query {name}: {error}"}
        data = {key: service.get(key) for key in ("name", "display_name", "status", "start_type", "pid")}
        return {"ok": True, "summary": f"{data['display_name']} is {data['status']} (start type {data['start_type']})", "data": data}
    if system == "Linux":
        state = run_command(["systemctl", "is-active", name])["stdout"] or "unknown"
        detail = run_command(["systemctl", "status", name, "--no-pager", "-n", "5"])["stdout"]
        return {"ok": True, "summary": f"{name} is {state}", "data": {"state": state, "status": detail[:1200]}}
    output = run_command(["launchctl", "list"])["stdout"]
    lines = [line for line in output.splitlines() if name.lower() in line.lower()][:5]
    return {"ok": True, "summary": f"{len(lines)} launchd job(s) matching {name}", "data": lines}


@tool("failed_services", "List services that failed or should be running but are stopped.")
def failed_services():
    system = os_name()
    if system == "Windows":
        rows = []
        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
            except Exception:
                continue
            if info.get("start_type") == "automatic" and info.get("status") != "running":
                rows.append({"name": info["name"], "display_name": info["display_name"], "status": info["status"]})
        return {"ok": True, "summary": f"{len(rows)} automatic service(s) not running (some auto-start services stop by design)", "data": rows[:25]}
    if system == "Linux":
        output = run_command(["systemctl", "--failed", "--no-legend", "--plain"])["stdout"]
        rows = [line.split()[0] for line in output.splitlines() if line.strip()]
        return {"ok": True, "summary": f"{len(rows)} failed systemd unit(s)" + (f": {', '.join(rows[:5])}" if rows else ""), "data": rows}
    output = run_command(["launchctl", "list"])["stdout"]
    rows = []
    for line in output.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) == 3 and parts[0] == "-" and parts[1] not in ("0", "-"):
            rows.append({"label": parts[2], "last_exit_status": parts[1]})
    return {"ok": True, "summary": f"{len(rows)} launchd job(s) exited with an error", "data": rows[:20]}


@tool("update_status", "OS update state: last installed patch, pending reboot, update service state, upgradable packages.", timeout=90)
def update_status():
    system = os_name()
    data = {"history": get_pending_updates()}
    if system == "Windows":
        script = (
            "$p=(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending')"
            " -or (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired');$p"
        )
        data["reboot_pending"] = powershell(script)["stdout"].strip().lower() == "true"
        try:
            data["windows_update_service"] = psutil.win_service_get("wuauserv").status()
        except Exception:
            data["windows_update_service"] = "unknown"
        summary = f"{data['history'].get('detail')}; reboot pending: {data['reboot_pending']}; wuauserv {data['windows_update_service']}"
    elif system == "Linux":
        data["reboot_pending"] = os.path.exists("/var/run/reboot-required")
        summary = f"{data['history'].get('detail')}; reboot pending: {data['reboot_pending']}"
    else:
        output = run_command(["softwareupdate", "-l"], timeout=80)
        data["available_updates"] = [line.strip() for line in output["stdout"].splitlines() if line.strip().startswith("*")][:15]
        summary = f"{len(data['available_updates'])} macOS update(s) available"
    return {"ok": True, "summary": summary, "data": data}


@tool("battery_health", "Battery wear: design vs. full-charge capacity, cycle count and condition.")
def battery_health():
    system = os_name()
    data = {}
    if system == "Windows":
        script = (
            "$f=(Get-CimInstance -Namespace root/wmi -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue | Select-Object -First 1).FullChargedCapacity;"
            "$d=(Get-CimInstance -Namespace root/wmi -ClassName BatteryStaticData -ErrorAction SilentlyContinue | Select-Object -First 1).DesignedCapacity;\"$f,$d\""
        )
        full, _, design = powershell(script)["stdout"].partition(",")
        if full.strip().isdigit() and design.strip().isdigit():
            data = {"full_charge_mwh": int(full), "design_mwh": int(design)}
    elif system == "Linux":
        for battery in glob.glob("/sys/class/power_supply/BAT*"):
            def read(name):
                try:
                    with open(os.path.join(battery, name), encoding="utf-8") as handle:
                        return int(handle.read().strip())
                except (OSError, ValueError):
                    return None
            full, design = read("energy_full") or read("charge_full"), read("energy_full_design") or read("charge_full_design")
            if full and design:
                data = {"full_charge_mwh": full, "design_mwh": design, "cycle_count": read("cycle_count")}
                break
    else:
        output = run_command(["system_profiler", "SPPowerDataType"], timeout=30)["stdout"]
        for key in ("Cycle Count", "Condition", "Maximum Capacity"):
            match = re.search(rf"{key}:\s*(.+)", output)
            if match:
                data[key.lower().replace(" ", "_")] = match.group(1).strip()
    if not data:
        return {"ok": True, "summary": "No battery detected or battery data unavailable", "data": None}
    if data.get("design_mwh"):
        data["health_percent"] = round(data["full_charge_mwh"] / data["design_mwh"] * 100, 1)
        summary = f"Battery holds {data['health_percent']}% of its design capacity"
    else:
        summary = f"Battery condition {data.get('condition', 'unknown')}, max capacity {data.get('maximum_capacity', 'unknown')}, cycles {data.get('cycle_count', 'unknown')}"
    return {"ok": True, "summary": summary, "data": data}


@tool("disk_health", "Physical disk health (SMART / storage health status, SSD vs HDD).", timeout=60)
def disk_health():
    system = os_name()
    if system == "Windows":
        output = powershell("Get-PhysicalDisk | Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus,@{N='SizeGB';E={[math]::Round($_.Size/1GB)}} | ConvertTo-Json -Compress")["stdout"]
        try:
            rows = json.loads(output) if output else []
        except json.JSONDecodeError:
            rows = []
        rows = rows if isinstance(rows, list) else [rows]
        unhealthy = [row for row in rows if str(row.get("HealthStatus")).lower() not in ("healthy", "0")]
        summary = f"{len(rows)} disk(s), {len(unhealthy)} not healthy" if rows else "Could not read physical disk health"
        return {"ok": bool(rows), "summary": summary, "data": rows}
    if system == "Darwin":
        output = run_command(["diskutil", "info", "disk0"])["stdout"]
        match = re.search(r"SMART Status:\s*(.+)", output)
        return {"ok": bool(match), "summary": f"disk0 SMART status: {match.group(1).strip()}" if match else "SMART status unavailable", "data": None}
    disks = run_command(["lsblk", "-d", "-n", "-o", "NAME,ROTA,SIZE,MODEL"])["stdout"].splitlines()
    rows = []
    for line in disks:
        name = line.split()[0] if line.split() else ""
        if not name or name.startswith(("loop", "zram", "sr")):
            continue
        smart = run_command(["smartctl", "-H", f"/dev/{name}"])
        verdict = re.search(r"(?:overall-health self-assessment test result|SMART Health Status):\s*(.+)", smart["stdout"])
        rows.append({"disk": line.strip(), "smart": verdict.group(1).strip() if verdict else (smart["stderr"][:80] or "unknown")})
    return {"ok": True, "summary": "; ".join(f"{row['disk'].split()[0]}: {row['smart']}" for row in rows) or "No disks found", "data": rows}


@tool("printer_status", "Printers, their status and stuck print jobs, plus the print spooler state.")
def printer_status():
    system = os_name()
    if system == "Windows":
        output = powershell("Get-Printer | Select-Object Name,PrinterStatus,JobCount,PortName,Shared | ConvertTo-Json -Compress")["stdout"]
        try:
            printers = json.loads(output) if output else []
        except json.JSONDecodeError:
            printers = []
        printers = printers if isinstance(printers, list) else [printers]
        try:
            spooler = psutil.win_service_get("Spooler").status()
        except Exception:
            spooler = "unknown"
        stuck = sum(int(printer.get("JobCount") or 0) for printer in printers)
        return {"ok": True, "summary": f"Spooler {spooler}; {len(printers)} printer(s); {stuck} queued job(s)", "data": {"spooler": spooler, "printers": printers[:15]}}
    printers = run_command(["lpstat", "-p", "-d"])
    jobs = run_command(["lpstat", "-o"])["stdout"].splitlines()
    if printers["returncode"] == 127:
        return {"ok": True, "summary": "CUPS (lpstat) is not installed", "data": None}
    return {"ok": True, "summary": f"{len(jobs)} queued job(s)", "data": {"printers": printers["stdout"][:1500], "jobs": jobs[:20]}}


@tool("performance_benchmark", "Short active benchmark of CPU, disk read/write speed and network latency (takes a few seconds).", timeout=120)
def performance_benchmark():
    report = collect_performance_report()
    parts = [str((report.get(key) or {}).get("detail", "")) for key in ("cpu", "disk", "network")]
    return {"ok": True, "summary": " | ".join(part for part in parts if part), "data": report}
