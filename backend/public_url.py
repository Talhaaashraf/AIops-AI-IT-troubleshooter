"""Addresses agents can use: the public https address ngrok gives this server (the free plan changes it on
every restart), and the server's own LAN IP, detected automatically (DHCP can change it)."""

import ipaddress
import logging
import os
import pathlib
import socket
import time

import httpx

logger = logging.getLogger(__name__)
CACHE_SECONDS = 30
_cache = {"url": None, "checked_at": 0.0}


def enabled():
    return os.getenv("PUBLIC_URL_FROM_NGROK", "true").strip().lower() in ("1", "true", "yes")


def tunnel_url(tunnels):
    """The https public URL from an ngrok `/api/tunnels` response, or None."""
    urls = [tunnel.get("public_url") or "" for tunnel in (tunnels or {}).get("tunnels") or []]
    return next((url for url in urls if url.startswith("https://")), None) or next((url for url in urls if url), None)


def ngrok_url():
    """Cached lookup; None when ngrok is not running, has no token, or is disabled."""
    if not enabled():
        return None
    now = time.monotonic()
    if now - _cache["checked_at"] < CACHE_SECONDS:
        return _cache["url"]
    url = None
    try:
        response = httpx.get(f"{os.getenv('NGROK_API_URL', 'http://ngrok:4040').rstrip('/')}/api/tunnels", timeout=2)
        response.raise_for_status()
        url = tunnel_url(response.json())
    except (httpx.HTTPError, ValueError):
        pass
    if url != _cache["url"] and url:
        logger.info("ngrok public URL: %s", url)
    _cache.update(url=url, checked_at=now)
    return url


HOST_IP_FILE = "/run/hostinfo/lan_ip"


def _usable(text):
    """A private (LAN) IPv4 address, or None. Loopback, link-local (169.254.x) and anything public is refused."""
    try:
        ip = ipaddress.IPv4Address((text or "").strip())
    except ValueError:
        return None
    return str(ip) if ip.is_private and not ip.is_loopback and not ip.is_link_local else None


def lan_ip():
    """The server's LAN IP. In Docker the app only sees the container's own address, so the `hostip` service
    (host network) writes the host's IP to a shared file every 30 s. Run directly on a PC (no Docker), the
    address of the interface that reaches the network is used. No packet is sent: a UDP connect only picks
    the route."""
    path = pathlib.Path(os.getenv("HOST_IP_FILE", HOST_IP_FILE))
    try:
        return _usable(path.read_text(encoding="utf-8"))
    except OSError:
        pass
    if pathlib.Path("/.dockerenv").exists():
        return None  # inside Docker without the helper: the container's own IP would be wrong
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.255.255.255", 1))
            return _usable(probe.getsockname()[0])
    except OSError:
        return None


def lan_url(port=None):
    """http://<LAN IP>[:port] (nginx answers on port 80, so in Docker no port is added), or None."""
    ip = lan_ip()
    if not ip:
        return None
    return f"http://{ip}" if port in (None, 80) else f"http://{ip}:{port}"
