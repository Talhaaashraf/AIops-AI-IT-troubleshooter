"""Cross-platform, read-only security posture checks. Every check fails safe to 'unknown' rather than raising."""

import ctypes
import json
import os
import platform
import re
import subprocess

import psutil

TIMEOUT_SECONDS = 8
RISKY_PORTS = {21: "FTP (unencrypted)", 23: "Telnet (unencrypted)", 445: "SMB", 3389: "RDP", 5900: "VNC"}
LOOPBACK_PREFIXES = ("127.", "::1")


def _run(command, timeout=TIMEOUT_SECONDS):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def is_admin():
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return None


def get_firewall_status():
    system = platform.system()
    if system == "Windows":
        output = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        states = re.findall(r"State\s+(ON|OFF)", output, re.IGNORECASE)
        if not states:
            return {"available": False, "enabled": None, "detail": "Could not query Windows Firewall"}
        enabled = all(state.upper() == "ON" for state in states)
        return {"available": True, "enabled": enabled, "detail": f"{states.count('ON')}/{len(states)} firewall profiles active"}
    if system == "Linux":
        output = _run(["ufw", "status"])
        if output:
            enabled = output.strip().lower().startswith("status: active")
            return {"available": True, "enabled": enabled, "detail": output.splitlines()[0]}
        return {"available": False, "enabled": None, "detail": "ufw not installed; check iptables/firewalld manually"}
    if system == "Darwin":
        output = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if not output:
            return {"available": False, "enabled": None, "detail": "Could not query macOS firewall"}
        return {"available": True, "enabled": "enabled" in output.lower(), "detail": output}
    return {"available": False, "enabled": None, "detail": f"Firewall check not implemented for {system}"}


def windows_security_center_antivirus():
    """Antivirus products registered with Windows Security Center, third-party ones included.

    productState packs the status in its middle bytes: 0x1000 set means real-time protection is
    on, 0x10 set means signatures are out of date (e.g. 0x41000 = on and current)."""
    output = _run(["powershell", "-NoProfile", "-Command", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | ConvertTo-Json -Compress"])
    if not output:
        return []
    try:
        data = json.loads(output)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    products = []
    for item in data if isinstance(data, list) else [data]:
        try:
            state = int(item.get("productState") or 0)
        except (TypeError, ValueError):
            continue
        products.append({"name": item.get("displayName") or "Unknown antivirus", "enabled": (state >> 12) & 0xF == 1, "up_to_date": (state >> 4) & 0xF == 0})
    return products


def get_antivirus_status():
    system = platform.system()
    if system == "Windows":
        # Windows turns Defender off when another antivirus (Kaspersky, ESET, ...) takes over,
        # so ask Security Center first; Get-MpComputerStatus alone reports such machines as unprotected.
        active = [product for product in windows_security_center_antivirus() if product["enabled"]]
        if active:
            names = ", ".join(product["name"] for product in active)
            outdated = [product["name"] for product in active if not product["up_to_date"]]
            detail = f"{names}: real-time protection on, " + (f"signatures out of date ({', '.join(outdated)})" if outdated else "signatures up to date")
            return {"available": True, "enabled": True, "detail": detail}
        output = _run(["powershell", "-NoProfile", "-Command", "Get-MpComputerStatus | ConvertTo-Json -Compress"])
        if not output:
            return {"available": False, "enabled": None, "detail": "Windows Defender status unavailable (a third-party antivirus may be active instead)"}
        try:
            data = json.loads(output)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {"available": False, "enabled": None, "detail": "Could not parse Windows Defender status"}
        enabled = bool(data.get("AntivirusEnabled")) and bool(data.get("RealTimeProtectionEnabled"))
        # 65535 is Defender's "never updated / not running" placeholder, not a real age.
        age = data.get("AntivirusSignatureAge")
        age_text = "signature age unknown" if age in (None, 65535) else f"signatures {age} day(s) old"
        return {"available": True, "enabled": enabled, "detail": f"Windows Defender real-time protection {'on' if data.get('RealTimeProtectionEnabled') else 'off'}, {age_text}"}
    if system == "Darwin":
        return {"available": True, "enabled": True, "detail": "macOS includes built-in XProtect malware signatures; no user action needed"}
    if system == "Linux":
        output = _run(["systemctl", "is-active", "clamav-daemon"])
        if output:
            return {"available": True, "enabled": output.strip() == "active", "detail": f"clamav-daemon service is {output.strip()}"}
        return {"available": False, "enabled": None, "detail": "No supported antivirus service detected (checked clamav-daemon)"}
    return {"available": False, "enabled": None, "detail": f"Antivirus check not implemented for {system}"}


def get_disk_encryption_status():
    system = platform.system()
    if system == "Windows":
        output = _run(["powershell", "-NoProfile", "-Command", "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus"])
        if not output:
            return {"available": False, "encrypted": None, "detail": "Could not query BitLocker (may require admin rights or an unsupported Windows edition)"}
        encrypted = output.strip().lower() in ("on", "1")
        return {"available": True, "encrypted": encrypted, "detail": f"BitLocker protection status: {output.strip()}"}
    if system == "Darwin":
        output = _run(["fdesetup", "status"])
        if not output:
            return {"available": False, "encrypted": None, "detail": "Could not query FileVault"}
        return {"available": True, "encrypted": "filevault is on" in output.lower(), "detail": output}
    if system == "Linux":
        output = _run(["lsblk", "-o", "NAME,TYPE,FSTYPE"])
        if not output:
            return {"available": False, "encrypted": None, "detail": "Could not query block devices with lsblk"}
        encrypted = "crypto_luks" in output.lower()
        return {"available": True, "encrypted": encrypted, "detail": "LUKS-encrypted volume detected" if encrypted else "No LUKS-encrypted volumes detected"}
    return {"available": False, "encrypted": None, "detail": f"Disk encryption check not implemented for {system}"}


def get_pending_updates():
    system = platform.system()
    if system == "Windows":
        output = _run(["powershell", "-NoProfile", "-Command", "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"])
        return {"available": bool(output), "detail": f"Most recent hotfix installed {output.strip()}" if output else "Could not read Windows update history", "note": "Reflects patch history only; does not query pending Windows Update items"}
    if system == "Linux":
        output = _run(["apt", "list", "--upgradable"])
        if output:
            lines = [line for line in output.splitlines() if line.strip() and not line.startswith("Listing")]
            return {"available": True, "pending_count": len(lines), "detail": f"{len(lines)} package(s) upgradable (from local apt cache; run apt update to refresh)"}
        return {"available": False, "detail": "apt not found; check your distro's package manager manually (dnf/yum/pacman)"}
    if system == "Darwin":
        return {"available": False, "detail": "Run 'softwareupdate -l' manually; automatic checks require network access and can be slow"}
    return {"available": False, "detail": f"Update check not implemented for {system}"}


def get_listening_ports():
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return {"available": False, "ports": [], "detail": "Insufficient permissions to list network connections"}
    seen = {}
    for connection in connections:
        if connection.status != psutil.CONN_LISTEN or not connection.laddr:
            continue
        process_name = "Unknown"
        if connection.pid:
            try:
                process_name = psutil.Process(connection.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        seen[(connection.laddr.ip, connection.laddr.port)] = {"address": connection.laddr.ip, "port": connection.laddr.port, "process": process_name}
    ports = sorted(seen.values(), key=lambda item: item["port"])
    return {"available": True, "ports": ports, "count": len(ports)}


def get_macos_protections():
    if platform.system() != "Darwin":
        return None
    gatekeeper = _run(["spctl", "--status"])
    sip = _run(["csrutil", "status"])
    return {"gatekeeper_enabled": "assessments enabled" in gatekeeper.lower(), "sip_enabled": "enabled" in sip.lower()}


def collect_security_report():
    return {
        "running_as_admin": is_admin(),
        "firewall": get_firewall_status(),
        "antivirus": get_antivirus_status(),
        "disk_encryption": get_disk_encryption_status(),
        "updates": get_pending_updates(),
        "listening_ports": get_listening_ports(),
        "macos_protections": get_macos_protections(),
    }
