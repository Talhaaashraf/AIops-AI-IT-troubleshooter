"""Which machine "This server" is.

In Docker the AIops app only sees its own container: a random hostname and the container's processes,
network and mounts. The real server appears once the AIops agent runs on the host itself. It is recognised
by the host's hostname: AIOPS_SERVER_HOSTNAME in .env (the deploy workflow writes it), or a file such as a
read-only mount of the host's /etc/hostname (HOST_HOSTNAME_FILE). The dashboard and the device pickers then
show that agent as "This server".
"""

import logging
import os
import socket
import time
from datetime import datetime, timezone

from .collectors import collect_report
from .device_store import get_latest_report, list_devices

logger = logging.getLogger(__name__)
CACHE_SECONDS = 30
# An agent reports every 10 s by default; older data is shown, but marked stale.
STALE_SECONDS = 60
_cache = {"at": 0.0, "device": None}
_warned = set()


def in_docker():
    return bool(os.getenv("SENTINEL_IN_DOCKER"))


def is_container_target(device_id):
    """The AIops container itself (Docker): not a user's computer, so it is never learned from."""
    return in_docker() and (device_id or "local") in ("local", "local-server")


def host_hostname():
    """The host's hostname, or None when unknown (no mount, e.g. AIops running directly on a PC)."""
    override = os.getenv("AIOPS_SERVER_HOSTNAME", "").strip()
    if override:
        return override
    try:
        with open(os.getenv("HOST_HOSTNAME_FILE", "/host/etc/hostname"), encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def _short(name):
    return (name or "").strip().split(".")[0].lower()


def server_device(refresh=False):
    """The enrolled agent running on this server's host, or None. AIOPS_SERVER_DEVICE_ID pins it; otherwise the
    hostname decides, and among several devices with that name the online one enrolled first wins (a device
    enrolled later under the same name cannot take its place)."""
    now = time.monotonic()
    if not refresh and now - _cache["at"] < CACHE_SECONDS:
        return _cache["device"]
    devices = list_devices()
    pinned = os.getenv("AIOPS_SERVER_DEVICE_ID", "").strip()
    name = _short(host_hostname())
    if pinned:
        matches = [device for device in devices if device["device_id"] == pinned]
    else:
        matches = [device for device in devices if name and _short(device.get("hostname")) == name]
    matches.sort(key=lambda device: (device.get("status") != "online", device.get("first_seen") or ""))
    if len(matches) > 1 and name not in _warned:
        _warned.add(name)
        logger.warning("%d devices are named %s; showing %s as this server. Set AIOPS_SERVER_DEVICE_ID to choose.", len(matches), name, matches[0]["device_id"])
    _cache.update(at=now, device=matches[0] if matches else None)
    return _cache["device"]


def server_report_section(field):
    """A section (e.g. "security", "event_logs") of the host agent's latest report, or None without one."""
    device = server_device()
    latest = get_latest_report(device["device_id"]) if device else None
    return (latest or {}).get("diagnostics", {}).get(field)


def _age_seconds(timestamp):
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(timestamp)).total_seconds()
    except (TypeError, ValueError):
        return None


def server_snapshot():
    """The dashboard's live report: the host agent's latest report when there is one, else this process's own
    view (the container, in Docker). `source` says which, so the dashboard can label it."""
    device = server_device()
    latest = get_latest_report(device["device_id"]) if device else None
    if latest:
        age = _age_seconds(latest.get("timestamp"))
        return {**latest["diagnostics"], "source": {
            "kind": "host-agent", "device_id": device["device_id"], "label": device.get("nickname") or device.get("hostname"),
            "received_at": latest.get("timestamp"), "stale": age is None or age > STALE_SECONDS}}
    report = collect_report()
    kind = "container" if in_docker() else "local"
    return {**report, "source": {"kind": kind, "label": "AIops container" if kind == "container" else socket.gethostname()}}


def identity():
    device = server_device()
    return {
        "in_docker": in_docker(),
        "container_hostname": socket.gethostname() if in_docker() else None,
        "host_hostname": host_hostname(),
        "server_device_id": device["device_id"] if device else None,
        "label": (device.get("nickname") or device.get("hostname")) if device else None,
        "status": device.get("status") if device else None,
    }
