"""Component observations and explicitly started, bounded load checks."""
import glob
import hashlib
import json
import os
import tempfile
import time

import psutil

from .common import cpu_frequency, os_name, powershell, run_command
from .registry import tool
from .security_checks import collect_security_report


@tool("security_snapshot", "Read full firewall, antivirus, encryption, updates and listening-port evidence.", timeout=120, ai_visible=False)
def security_snapshot():
    return {"ok": True, "summary": "Security snapshot collected; unavailable checks remain unknown", "data": collect_security_report()}


@tool("component_observation", "Read CPU, RAM, power or peripheral inventory; not a functional pass.",
      params={"component": {"type": "string", "enum": ["cpu", "ram", "power", "peripherals"]}}, required=("component",), timeout=60, ai_visible=False)
def component_observation(component):
    if component == "cpu":
        frequency = cpu_frequency()
        data = {"logical_cores": psutil.cpu_count(), "physical_cores": psutil.cpu_count(logical=False),
                "load_percent": psutil.cpu_percent(interval=0.25), "frequency_mhz": frequency.current if frequency else None}
    elif component == "ram":
        memory = psutil.virtual_memory()
        data = {"total_gb": round(memory.total / 1024 ** 3, 2), "available_gb": round(memory.available / 1024 ** 3, 2),
                "used_percent": memory.percent, "note": "Usage observation only. A short RAM load check cannot rule out every memory fault."}
    elif component == "power":
        battery = psutil.sensors_battery()
        data = {"battery_present": battery is not None, "charge_percent": battery.percent if battery else None,
                "plugged_in": battery.power_plugged if battery else None,
                "note": "AC adapter/PSU electrical output cannot be verified by this software."}
    elif component == "peripherals":
        data = _peripherals()
    else:
        return {"ok": False, "summary": "Unknown component"}
    return {"ok": True, "summary": "Observation collected; use the interactive checks to verify operation", "data": data}


def _peripherals():
    if os_name() == "Windows":
        result = powershell("Get-CimInstance Win32_PnPEntity -Filter \"PNPClass='Camera' OR PNPClass='Image' OR PNPClass='AudioEndpoint' OR PNPClass='MEDIA' OR PNPClass='Monitor' OR PNPClass='Display'\" | Select-Object Name,PNPClass,Status,ConfigManagerErrorCode | ConvertTo-Json -Compress", timeout=45)
        try:
            rows = json.loads(result.get("stdout") or "[]")
        except ValueError:
            rows = []
        rows = rows if isinstance(rows, list) else [rows]
        return {"available": result.get("returncode") == 0, "devices": rows[:80],
                "note": "Device inventory only. Test camera, microphone, speakers and display in a browser on this device."}
    if os_name() == "Linux":
        audio = run_command(["arecord", "-l"], timeout=10)
        graphics = run_command(["lspci"], timeout=10)
        return {"cameras": glob.glob("/sys/class/video4linux/video*")[:16], "audio": audio.get("stdout", "")[:2000],
                "graphics": "\n".join(line for line in graphics.get("stdout", "").splitlines() if any(word in line for word in ("VGA", "Display", "3D")))[:1500],
                "note": "Inventory only; empty output can mean unavailable tools or no device. Interactive checks are required."}
    result = run_command(["system_profiler", "SPAudioDataType", "SPCameraDataType", "SPDisplaysDataType"], timeout=45)
    return {"available": result.get("returncode") == 0, "inventory": result.get("stdout", "")[:6000], "note": "Inventory only; interactive checks are required."}


def _temperature():
    try:
        sensors = getattr(psutil, "sensors_temperatures", lambda: {})() or {}
        readings = [row.current for rows in sensors.values() for row in rows if row.current is not None and 0 < row.current < 130]
        return max(readings) if readings else None
    except (OSError, RuntimeError):
        return None


def _load_guard():
    temperature = _temperature()
    if temperature is not None and temperature >= 85:
        raise RuntimeError("Stopped: a temperature sensor reached 85 C")
    battery = psutil.sensors_battery()
    if battery and not battery.power_plugged and battery.percent < 20:
        raise RuntimeError("Stopped: connect power before testing with less than 20% battery")
    return temperature


@tool("bounded_stress", "Explicitly approved short load check: one CPU worker, at most 128 MiB RAM, or 64 MiB temporary storage. Not an exhaustive hardware test.",
      risk="medium", params={"component": {"type": "string", "enum": ["cpu", "ram", "storage"]},
                             "approved": {"type": "boolean"}}, required=("component", "approved"), timeout=45, ai_visible=False)
def bounded_stress(component, approved=False):
    if approved is not True:
        return {"ok": False, "summary": "Explicit approval is required"}
    if component not in ("cpu", "ram", "storage"):
        return {"ok": False, "summary": "Unknown stress test"}
    started = time.monotonic()
    data = {"component": component, "duration_limit_seconds": 10, "operations": 0, "bytes_tested": 0}
    try:
        initial = _load_guard()
        data["thermal_monitoring"] = initial is not None
        data["start_temperature_c"] = initial
        if component == "storage":
            if psutil.disk_usage(tempfile.gettempdir()).free < 512 * 1024 ** 2:
                raise RuntimeError("Stopped: less than 512 MiB free in the temporary-file volume")
            chunk = b"Sentinel integrity pattern\x00" * 40000
            digest = hashlib.sha256()
            with tempfile.TemporaryFile(prefix="sentinel_stress_") as handle:
                for _ in range(64):
                    if time.monotonic() - started >= 10:
                        break
                    _load_guard()
                    block = chunk[:1024 * 1024]
                    handle.write(block)
                    digest.update(block)
                    data["bytes_tested"] += len(block)
                handle.flush()
                os.fsync(handle.fileno())
                handle.seek(0)
                observed = hashlib.sha256()
                while block := handle.read(1024 * 1024):
                    _load_guard()
                    observed.update(block)
                if observed.digest() != digest.digest():
                    raise RuntimeError("Storage data verification failed")
            data["operations"] = 1
            data["scope"] = "Temporary-file volume only; cached I/O is possible. No raw disk writes."
        elif component == "ram":
            size = min(128 * 1024 ** 2, int(psutil.virtual_memory().available * 0.10))
            if size < 8 * 1024 ** 2:
                raise RuntimeError("Stopped: insufficient available memory")
            block = bytearray(size)
            data["bytes_tested"] = size
            while time.monotonic() - started < 10:
                _load_guard()
                for pattern in (0x55, 0xAA):
                    for offset in range(0, size, 1024 * 1024):
                        if time.monotonic() - started >= 10:
                            break
                        length = min(1024 * 1024, size - offset)
                        expected = bytes([pattern]) * length
                        block[offset:offset + length] = expected
                        if block[offset:offset + length] != expected:
                            raise RuntimeError("RAM pattern verification failed")
                        data["operations"] += 1
            del block
        else:
            block = b"Sentinel CPU check" * 4096
            expected = hashlib.sha256(block).digest()
            while time.monotonic() - started < 10:
                _load_guard()
                for _ in range(100):
                    if hashlib.sha256(block).digest() != expected:
                        raise RuntimeError("CPU checksum verification failed")
                    data["operations"] += 1
            data["scope"] = "One CPU worker; not a full multicore burn-in"
        data["elapsed_seconds"] = round(time.monotonic() - started, 2)
        return {"ok": True, "summary": "Bounded load check completed without a detected error; this does not certify component health", "data": data}
    except (OSError, RuntimeError, MemoryError) as error:
        data["elapsed_seconds"] = round(time.monotonic() - started, 2)
        return {"ok": False, "summary": str(error), "data": data}
