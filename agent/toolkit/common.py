"""Small helpers shared by diagnostic and remediation tools.

Commands are always passed as argument lists (never through a shell), so a
tool argument can never be interpreted as extra shell syntax.
"""

import ctypes
import os
import platform
import subprocess

DEFAULT_TIMEOUT_SECONDS = 20
OUTPUT_MAX_CHARS = 4000


def os_name():
    return platform.system()


def cpu_frequency():
    """psutil.cpu_freq(), or None where it raises (some VMs and ARM boards expose no CPU frequency)."""
    import psutil

    try:
        return psutil.cpu_freq()
    except (NotImplementedError, OSError):
        return None


def is_admin():
    try:
        if os_name() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def run_command(command, timeout=DEFAULT_TIMEOUT_SECONDS):
    """Run an argument-list command and return {returncode, stdout, stderr}; never raises."""
    kwargs = {"capture_output": True, "text": True, "timeout": timeout, "errors": "replace"}
    if os_name() == "Windows":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(command, **kwargs)
        return {"returncode": result.returncode, "stdout": result.stdout.strip()[:OUTPUT_MAX_CHARS], "stderr": result.stderr.strip()[:OUTPUT_MAX_CHARS]}
    except FileNotFoundError:
        return {"returncode": 127, "stdout": "", "stderr": f"{command[0]} is not installed"}
    except subprocess.TimeoutExpired:
        return {"returncode": 124, "stdout": "", "stderr": f"{command[0]} timed out after {timeout}s"}
    except (OSError, subprocess.SubprocessError) as error:
        return {"returncode": 1, "stdout": "", "stderr": str(error)}


def powershell(script, timeout=DEFAULT_TIMEOUT_SECONDS):
    return run_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)


def human_size(value):
    if value is None:
        return "N/A"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def directory_size(path, max_files=200000):
    total, count = 0, 0
    for root, _, files in os.walk(path):
        for filename in files:
            count += 1
            if count > max_files:
                return total
            try:
                total += os.path.getsize(os.path.join(root, filename))
            except OSError:
                continue
    return total
