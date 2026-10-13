"""Hardware health diagnostics: temperatures, CPU throttling, RAM, GPU and driver/device errors.

Everything is collected in as few subprocesses as possible (one PowerShell call on
Windows), because spawning shells is the slowest part of a diagnosis on a laptop.
"""

import json
import re
from collections import Counter

import psutil

from .common import human_size, os_name, powershell, run_command
from .registry import tool

# Device Manager problem codes worth reporting (22 = disabled by the user, 45 = not plugged in: not faults).
PNP_ERRORS = {
    1: "not configured correctly", 3: "driver corrupted or out of memory", 10: "device cannot start",
    12: "not enough free resources", 14: "needs a restart", 18: "drivers need reinstalling",
    19: "registry configuration damaged", 21: "Windows is removing the device", 24: "not present or not working",
    28: "drivers not installed", 31: "driver failed to load", 32: "driver service disabled",
    39: "driver missing or corrupted", 41: "driver loaded but device not found", 43: "device reported a problem (stopped)",
    48: "driver blocked (known compatibility problem)", 52: "driver signature could not be verified",
}
IGNORED_PNP_CODES = {0, 22, 45}
HOT_CELSIUS, CRITICAL_CELSIUS = 85, 95
KERNEL_HARDWARE_PATTERN = re.compile(r"hardware error|mce:|machine check|i/o error|ata\d+.*(error|failed)|nvme.*(error|timeout)|thermal|throttl|usb.*(error|fail)|pcie bus error|edac", re.I)

WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 Name, NumberOfCores, NumberOfLogicalProcessors, LoadPercentage, CurrentClockSpeed, MaxClockSpeed
# Get-Counter is ~1 s; the equivalent Win32_PerfFormatted* WMI class can take a minute on first use.
$perf = [math]::Round((Get-Counter '\Processor Information(_Total)\% Processor Performance').CounterSamples[0].CookedValue)
$mem = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [pscustomobject]@{ gb = [math]::Round($_.Capacity / 1GB, 1); mhz = $_.ConfiguredClockSpeed; maker = "$($_.Manufacturer)".Trim(); slot = $_.DeviceLocator } })
$gpu = @(Get-CimInstance Win32_VideoController | ForEach-Object { [pscustomobject]@{ name = $_.Name; driver = $_.DriverVersion; status = $_.Status; code = $_.ConfigManagerErrorCode } })
$therm = @(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature | ForEach-Object { [math]::Round($_.CurrentTemperature / 10 - 273.15, 1) })
$bad = @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' | Select-Object -First 25 | ForEach-Object { [pscustomobject]@{ name = $_.Name; code = $_.ConfigManagerErrorCode; class = $_.PNPClass } })
$whea = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 20).Count
$model = Get-CimInstance Win32_ComputerSystem | Select-Object -First 1 Manufacturer, Model
[pscustomobject]@{ cpu = $cpu; cpu_performance_percent = $perf; memory_modules = $mem; gpus = $gpu; thermal_c = $therm; problem_devices = $bad; whea_errors_7d = $whea; model = $model } | ConvertTo-Json -Compress -Depth 4
"""


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _model_name(maker, model):
    maker, model = (maker or "").strip(), (model or "").strip()
    return (model if model.lower().startswith(maker.lower()) else f"{maker} {model}".strip()) or None


def _windows():
    output = powershell(WINDOWS_SCRIPT, timeout=45)["stdout"]
    try:
        raw = json.loads(output) if output else {}
    except json.JSONDecodeError:
        raw = {}
    cpu = raw.get("cpu") or {}
    model = raw.get("model") or {}
    devices = [
        {"name": item.get("name"), "class": item.get("class"), "code": item.get("code"), "problem": PNP_ERRORS.get(item.get("code"), f"error code {item.get('code')}")}
        for item in _as_list(raw.get("problem_devices")) if item.get("code") not in IGNORED_PNP_CODES
    ]
    gpus = [{"name": item.get("name"), "driver": item.get("driver"), "status": item.get("status"), "ok": item.get("code") in (0, None)} for item in _as_list(raw.get("gpus"))]
    modules = _as_list(raw.get("memory_modules"))
    return {
        "model": _model_name(model.get("Manufacturer"), model.get("Model")),
        "cpu": {
            "name": (cpu.get("Name") or "").strip() or None,
            "cores": cpu.get("NumberOfCores"),
            "threads": cpu.get("NumberOfLogicalProcessors"),
            "load_percent": cpu.get("LoadPercentage"),
            "max_mhz": cpu.get("MaxClockSpeed"),
            "performance_percent": raw.get("cpu_performance_percent"),
        },
        # ACPI zones often report a fixed ~28 C placeholder; drop it.
        "temperatures_c": [value for value in _as_list(raw.get("thermal_c")) if isinstance(value, (int, float)) and 30 <= value <= 125],
        "memory_modules": modules,
        "gpus": gpus,
        "problem_devices": devices,
        "hardware_errors_7d": raw.get("whea_errors_7d") or 0,
    }


def _read(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _linux():
    data = {"cpu": {}, "temperatures_c": [], "fans": [], "gpus": [], "problem_devices": [], "memory_modules": []}
    data["model"] = _model_name(_read("/sys/devices/virtual/dmi/id/sys_vendor"), _read("/sys/devices/virtual/dmi/id/product_name"))
    try:
        for line in open("/proc/cpuinfo", encoding="utf-8"):
            if line.startswith("model name"):
                data["cpu"]["name"] = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    sensors = getattr(psutil, "sensors_temperatures", lambda: {})() or {}
    for chip, readings in sensors.items():
        for reading in readings:
            if reading.current and 0 < reading.current < 130:
                data["temperatures_c"].append({"sensor": f"{chip} {reading.label}".strip(), "c": round(reading.current, 1), "high": reading.high, "critical": reading.critical})
    for chip, fans in (getattr(psutil, "sensors_fans", lambda: {})() or {}).items():
        data["fans"] += [{"fan": f"{chip} {fan.label}".strip(), "rpm": fan.current} for fan in fans]
    output = run_command(["lspci", "-mm"])["stdout"]
    data["gpus"] = [{"name": line.split('"')[5] if line.count('"') >= 6 else line, "ok": True} for line in output.splitlines() if re.search(r"VGA|3D|Display", line)]
    kernel = run_command(["journalctl", "-k", "-b", "-p", "warning", "--no-pager", "-n", "400", "-o", "cat"], timeout=30)["stdout"]
    if not kernel:
        kernel = run_command(["dmesg", "--level=err,warn"], timeout=15)["stdout"]
    hits = Counter(re.sub(r"\[\s*[\d.]+\]\s*", "", line)[:120] for line in kernel.splitlines() if KERNEL_HARDWARE_PATTERN.search(line))
    data["problem_devices"] = [{"name": text, "problem": f"kernel reported x{count}"} for text, count in hits.most_common(10)]
    data["hardware_errors_7d"] = sum(count for text, count in hits.items() if re.search(r"hardware error|mce|machine check|edac", text, re.I))
    return data


def _macos():
    data = {"cpu": {}, "temperatures_c": [], "gpus": [], "problem_devices": [], "memory_modules": []}
    output = run_command(["system_profiler", "SPHardwareDataType", "SPDisplaysDataType"], timeout=40)["stdout"]
    for key, target in (("Model Name", "model"), ("Chip", "chip"), ("Processor Name", "chip"), ("Memory", "memory")):
        match = re.search(rf"^\s*{key}:\s*(.+)$", output, re.M)
        if match:
            data[target] = match.group(1).strip()
    data["cpu"]["name"] = data.pop("chip", None)
    data["gpus"] = [{"name": name.strip(), "ok": True} for name in re.findall(r"Chipset Model:\s*(.+)", output)]
    therm = run_command(["pmset", "-g", "therm"])["stdout"]
    limit = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", therm)
    if limit:
        data["cpu"]["performance_percent"] = int(limit.group(1))
    data["thermal_warning"] = "No thermal warning level has been recorded" not in therm and "warning" in therm.lower()
    return data


def _finalize(data):
    """Add the cross-platform bits (frequency, RAM total) and derive the one-line summary."""
    frequency = psutil.cpu_freq()
    cpu = data.setdefault("cpu", {})
    if frequency:
        cpu.setdefault("max_mhz", round(frequency.max) if frequency.max else None)
        cpu["current_mhz"] = round(frequency.current) if frequency.current else None
    cpu.setdefault("threads", psutil.cpu_count(logical=True))
    data["ram_total"] = human_size(psutil.virtual_memory().total)

    temps = [item["c"] if isinstance(item, dict) else item for item in data.get("temperatures_c") or []]
    data["max_temperature_c"] = max(temps) if temps else None
    performance = cpu.get("performance_percent")
    load = cpu.get("load_percent")
    # Running far below the base clock while busy means thermal or power throttling.
    data["throttling_suspected"] = bool(performance is not None and performance < 60 and (load is None or load > 40))

    parts = [f"{cpu.get('name') or 'CPU'}"]
    if performance is not None:
        parts.append(f"running at {performance}% of base clock" + (" (throttled)" if data["throttling_suspected"] else ""))
    parts.append(f"max temp {data['max_temperature_c']} C" if data["max_temperature_c"] is not None else "temperature sensors unavailable")
    parts.append(f"RAM {data['ram_total']}" + (f" in {len(data['memory_modules'])} module(s)" if data.get("memory_modules") else ""))
    bad_gpus = [gpu for gpu in data.get("gpus") or [] if not gpu.get("ok")]
    if data.get("gpus"):
        parts.append(f"GPU {data['gpus'][0].get('name')}" + (" has a driver problem" if bad_gpus else ""))
    devices = data.get("problem_devices") or []
    parts.append(f"{len(devices)} device/driver problem(s)" if devices else "no device/driver problems")
    if data.get("hardware_errors_7d"):
        parts.append(f"{data['hardware_errors_7d']} hardware error event(s) in 7 days")
    return {"ok": True, "summary": "; ".join(parts), "data": data}


@tool("hardware_health", "Hardware check: CPU model and throttling, temperatures, fans, RAM modules, GPU and driver status, devices with driver errors, and logged hardware errors (WHEA/MCE). Use for overheating, crashes, devices not working, or slow hardware.", timeout=60)
def hardware_health():
    system = os_name()
    data = _windows() if system == "Windows" else _macos() if system == "Darwin" else _linux()
    return _finalize(data)


@tool("rescan_hardware", "Ask the OS to re-detect hardware (Device Manager 'Scan for hardware changes'). Fixes devices that are missing or stuck after a driver install or replug.", risk="low", os=frozenset({"Windows"}), timeout=120)
def rescan_hardware():
    result = run_command(["pnputil", "/scan-devices"], timeout=110)
    ok = result["returncode"] == 0
    return {"ok": ok, "summary": "Hardware rescan finished" if ok else f"Hardware rescan failed: {result['stderr'][:200] or result['stdout'][:200]}", "changed": ok}
