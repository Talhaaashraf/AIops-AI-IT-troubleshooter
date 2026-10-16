"""Standalone cross-platform health reporter for the central Device Health server."""

import datetime
import json
import logging
import platform
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psutil
import requests

try:
    from toolkit import TOOLKIT_VERSION, get_tool, risk_rank, run_tool
    from toolkit.event_logs import collect_event_log_report
    from toolkit.leftovers import purge_expired
    from toolkit.performance_checks import collect_performance_report
    from toolkit.security_checks import collect_security_report
except ImportError:
    from .toolkit import TOOLKIT_VERSION, get_tool, risk_rank, run_tool
    from .toolkit.event_logs import collect_event_log_report
    from .toolkit.leftovers import purge_expired
    from .toolkit.performance_checks import collect_performance_report
    from .toolkit.security_checks import collect_security_report

AGENT_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
CONFIG_PATH = AGENT_DIR / "agent_config.json"
LOG_PATH = AGENT_DIR / "agent_log.txt"
DEFAULT_INTERVAL = 10
SECURITY_REFRESH_SECONDS = 300
EVENT_LOG_REFRESH_SECONDS = 600
DEFAULT_PERFORMANCE_INTERVAL_SECONDS = 1800
TASK_POLL_WAIT_SECONDS = 25
# Read-only diagnostics run side by side so a diagnosis' baseline finishes in the time of
# its slowest check; fixes always run one at a time.
MAX_PARALLEL_DIAGNOSTICS = 4
logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
_security_cache = {"data": None, "checked_at": 0}
_performance_cache = {"data": None, "checked_at": 0}
_event_log_cache = {"data": None, "checked_at": 0}


def get_security():
    """Refresh security posture on a fixed slow cadence; every check here is read-only."""
    now = time.time()
    if _security_cache["data"] is None or now - _security_cache["checked_at"] > SECURITY_REFRESH_SECONDS:
        try:
            _security_cache["data"] = collect_security_report()
        except Exception:
            logging.exception("Security check failed")
            _security_cache["data"] = _security_cache["data"] or {}
        _security_cache["checked_at"] = now
    return _security_cache["data"]


def get_event_logs():
    """Refresh recent OS event log entries on a fixed slow cadence; read-only."""
    now = time.time()
    if _event_log_cache["data"] is None or now - _event_log_cache["checked_at"] > EVENT_LOG_REFRESH_SECONDS:
        try:
            fresh = collect_event_log_report()
        except Exception:
            logging.exception("Event log check failed")
            fresh = {}
        previous = _event_log_cache["data"] or {}
        # A failed read (timeout on a busy machine) keeps the last good result instead of replacing it.
        if fresh.get("available") or not previous.get("available"):
            _event_log_cache["data"] = fresh
        else:
            logging.warning("Event log check failed (%s); keeping the previous result", fresh.get("detail"))
        _event_log_cache["checked_at"] = now
    return _event_log_cache["data"]


def get_performance(config):
    """Refresh the active benchmark suite on a configurable cadence.

    Unlike get_security(), this briefly writes to disk and burns CPU, so it is
    opt-out (enable_performance_benchmark: false in agent_config.json) and
    defaults to a much longer interval than the report cycle itself.
    """
    if not config.get("enable_performance_benchmark", True):
        return None
    interval = max(300, int(config.get("performance_interval_seconds", DEFAULT_PERFORMANCE_INTERVAL_SECONDS)))
    now = time.time()
    if _performance_cache["data"] is None or now - _performance_cache["checked_at"] > interval:
        try:
            _performance_cache["data"] = collect_performance_report()
        except Exception:
            logging.exception("Performance benchmark failed")
            _performance_cache["data"] = _performance_cache["data"] or {}
        _performance_cache["checked_at"] = now
    return _performance_cache["data"]


def human_size(value):
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"


def collect_report(config):
    frequency = psutil.cpu_freq()
    per_core = psutil.cpu_percent(interval=0.15, percpu=True)
    memory, swap = psutil.virtual_memory(), psutil.swap_memory()
    disks = []
    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.append({"device": partition.device, "mountpoint": partition.mountpoint, "filesystem": partition.fstype, "total": human_size(usage.total), "used": human_size(usage.used), "free": human_size(usage.free), "usage_percent": round(usage.percent, 2)})
    stats = psutil.net_if_stats()
    interfaces = []
    for name, addresses in psutil.net_if_addrs().items():
        interfaces.append({"name": name, "status": "UP" if stats.get(name) and stats[name].isup else "DOWN", "ipv4_addresses": [item.address for item in addresses if item.family == 2]})
    battery = None
    try:
        sensed = psutil.sensors_battery()
        if sensed:
            battery = {"percent": round(sensed.percent, 2), "charging": bool(sensed.power_plugged), "time_remaining": str(datetime.timedelta(seconds=max(0, sensed.secsleft))) if sensed.secsleft >= 0 else "Unknown"}
    except (AttributeError, OSError):
        pass
    processes = []
    for process in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = process.info
            if info["pid"] == 0 or (info.get("name") or "").lower() in IDLE_PROCESS_NAMES:
                continue  # idle capacity, not a process using the CPU
            processes.append({"pid": info["pid"], "name": info.get("name") or "Unknown", "cpu_percent": round(info.get("cpu_percent") or 0, 2), "memory_percent": round(info.get("memory_percent") or 0, 2)})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {"system": {"os_name": platform.system(), "os_version": platform.version(), "os_release": platform.release(), "architecture": platform.machine(), "processor": processor_name(), "hostname": socket.gethostname()}, "cpu": {"physical_cores": psutil.cpu_count(logical=False), "logical_cores": psutil.cpu_count(logical=True), "max_frequency_mhz": frequency.max if frequency else None, "current_frequency_mhz": frequency.current if frequency else None, "per_core_usage_percent": per_core, "total_usage_percent": psutil.cpu_percent(interval=None)}, "memory": {"ram": {"total": human_size(memory.total), "available": human_size(memory.available), "used": human_size(memory.used), "usage_percent": memory.percent}, "swap": {"total": human_size(swap.total), "used": human_size(swap.used), "usage_percent": swap.percent}}, "disk": disks, "network": {"bytes_sent": human_size(psutil.net_io_counters().bytes_sent), "bytes_received": human_size(psutil.net_io_counters().bytes_recv), "interfaces": interfaces}, "battery": battery, "processes_count": len(processes), "top_processes": {"top_by_cpu": sorted(processes, key=lambda item: item["cpu_percent"], reverse=True)[:5], "top_by_memory": sorted(processes, key=lambda item: item["memory_percent"], reverse=True)[:5]}, "security": get_security(), "performance": get_performance(config), "event_logs": get_event_logs()}


IDLE_PROCESS_NAMES = {"system idle process", "idle"}
# Leftovers moved to quarantine can be restored for 7 days; expired batches are deleted once a day.
QUARANTINE_PURGE_SECONDS = 86400


def processor_name():
    """The marketing name (e.g. "12th Gen Intel(R) Core(TM) i5-1235U"); platform.processor()
    only gives "Intel64 Family 6 Model 154" on Windows."""
    if platform.system() == "Windows":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        except OSError:
            pass
    return platform.processor() or "Unknown"


def load_config():
    if not CONFIG_PATH.exists():
        raise RuntimeError(f"Create {CONFIG_PATH} with server_url, AGENT_TOKEN, and nickname")
    with CONFIG_PATH.open(encoding="utf-8-sig") as config_file:
        config = json.load(config_file)
    if not config.get("AGENT_TOKEN") and config.get("token"):
        config["AGENT_TOKEN"] = config["token"]
    for key in ("server_url", "AGENT_TOKEN"):
        if not config.get(key):
            raise RuntimeError(f"agent_config.json requires {key} (or token)")
    return config


def save_config(config):
    with CONFIG_PATH.open("w", encoding="utf-8") as config_file:
        json.dump(config, config_file, indent=2)


# ngrok's free plan answers browser-like requests with a warning page; this header skips it.
DEFAULT_HEADERS = {"ngrok-skip-browser-warning": "1", "User-Agent": f"AIops-Agent/{TOOLKIT_VERSION}"}


def _headers(extra=None):
    return {**DEFAULT_HEADERS, **(extra or {})}


def request_with_retry(method, url, **kwargs):
    kwargs["headers"] = _headers(kwargs.get("headers"))
    delay = 1
    while True:
        try:
            response = requests.request(method, url, timeout=15, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as error:
            logging.warning("Server request failed: %s; retrying in %ss", error, delay)
            time.sleep(delay)
            delay = min(delay * 2, 60)


def register(config):
    if config.get("device_id"):
        return config["device_id"]
    payload = {"token": config["AGENT_TOKEN"], "hostname": socket.gethostname(), "os_type": platform.system(), "nickname": config.get("nickname", socket.gethostname())}
    response = request_with_retry("POST", config["server_url"].rstrip("/") + "/api/agents/register", json=payload)
    device_id = response.json()["device_id"]
    config["device_id"] = device_id
    save_config(config)
    return device_id


def _task_result_for(config, task):
    """Run a server-requested tool, enforcing this device's own remediation policy first."""
    tool_id = task.get("tool_id")
    server_limit = task.get("max_risk", "read")
    if not config.get("allow_remediation", True):
        local_limit = "read"
    else:
        local_limit = str(config.get("max_risk", "high")).lower()
    limit = server_limit if risk_rank(server_limit) <= risk_rank(local_limit) else local_limit
    result = run_tool(tool_id, task.get("args") or {}, max_risk=limit)
    if not result["ok"] and result["summary"].endswith(f"(limit: {limit})") and limit == local_limit:
        result["summary"] = f"Refused by this device's policy: {tool_id} needs '{result.get('risk')}' but agent_config.json allows up to '{local_limit}'"
    return result


def _post_result(base, headers, task, result):
    for attempt in range(5):
        try:
            posted = requests.post(f"{base}/api/agents/tasks/{task['task_id']}/result", headers=headers, json=result, timeout=30)
            if posted.status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2 ** attempt)


def _run_task(config, base, headers, task, slots):
    try:
        logging.info("Running task %s: %s %s", task["task_id"], task["tool_id"], task.get("args"))
        result = _task_result_for(config, task)
        logging.info("Task %s finished ok=%s: %s", task["task_id"], result["ok"], result["summary"])
        _post_result(base, headers, task, result)
    except Exception:
        logging.exception("Task %s crashed", task.get("task_id"))
    finally:
        slots.release()


def task_worker(config, device_id):
    """Long-poll the server for diagnose/fix tasks (outbound only, works behind NAT)."""
    base = config["server_url"].rstrip("/")
    headers = _headers({"Authorization": "Bearer " + config["AGENT_TOKEN"]})
    diagnostics = ThreadPoolExecutor(MAX_PARALLEL_DIAGNOSTICS, thread_name_prefix="sentinel-diag")
    fixes = ThreadPoolExecutor(1, thread_name_prefix="sentinel-fix")
    slots = threading.BoundedSemaphore(MAX_PARALLEL_DIAGNOSTICS)
    delay = 2
    while True:
        # Only claim a task when a worker is free, so claimed tasks never wait in a local queue.
        slots.acquire()
        try:
            response = requests.get(f"{base}/api/agents/tasks/next", headers=headers, params={"wait": TASK_POLL_WAIT_SECONDS}, timeout=TASK_POLL_WAIT_SECONDS + 15)
            if response.status_code == 404:
                logging.warning("Server does not support remote tasks; task polling disabled")
                slots.release()
                return
            response.raise_for_status()
            task = response.json().get("task")
            delay = 2
            if not task:
                slots.release()
                continue
            item = get_tool(task.get("tool_id"))
            pool = diagnostics if item is not None and item.risk == "read" else fixes
            pool.submit(_run_task, config, base, headers, task, slots)
        except Exception as error:
            slots.release()
            logging.warning("Task polling failed: %s; retrying in %ss", error, delay)
            time.sleep(delay)
            delay = min(delay * 2, 60)


def run():
    config = load_config()
    device_id = register(config)
    threading.Thread(target=task_worker, args=(config, device_id), name="sentinel-tasks", daemon=True).start()
    previous = None
    interval = max(2, int(config.get("interval_seconds", DEFAULT_INTERVAL)))
    logging.info("Agent %s started for device %s", config.get("nickname", socket.gethostname()), device_id)
    last_purge = 0.0
    while True:
        if time.time() - last_purge > QUARANTINE_PURGE_SECONDS:
            last_purge = time.time()
            try:
                removed = purge_expired()
                if removed:
                    logging.info("Purged expired quarantine batches: %s", ", ".join(removed))
            except Exception:  # cleanup must never stop health reporting
                logging.exception("Quarantine purge failed")
        report = collect_report(config)
        cpu_before = (previous or {}).get("cpu", {}).get("total_usage_percent", 0)
        ram_before = (previous or {}).get("memory", {}).get("ram", {}).get("usage_percent", 0)
        cpu_now = report["cpu"]["total_usage_percent"]
        ram_now = report["memory"]["ram"]["usage_percent"]
        spike = cpu_now - cpu_before > 40 or ram_now - ram_before > 40
        payload = {"device_id": device_id, "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "diagnostics": report, "spike_detected": spike, "agent_version": TOOLKIT_VERSION}
        try:
            request_with_retry("POST", config["server_url"].rstrip("/") + "/api/agents/report", headers={"Authorization": "Bearer " + config["AGENT_TOKEN"]}, json=payload)
            logging.info("Report sent; spike_detected=%s", spike)
        except Exception:
            logging.exception("Unexpected report failure")
        previous = report
        time.sleep(interval)


if __name__ == "__main__":
    try:
        run()
    except Exception:
        logging.exception("Agent stopped during setup")
        raise
