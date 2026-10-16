"""The public https address ngrok gives this server (the free plan changes it on every restart)."""

import logging
import os
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
