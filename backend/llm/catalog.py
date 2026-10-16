"""Local models offered in the dashboard's model switcher, the saved choice, and background downloads."""

import json
import logging
import os
import sqlite3
import threading

import httpx

from ..settings_store import get_setting, set_setting

logger = logging.getLogger(__name__)
SETTING_KEY = "ollama_model"

# Sizes are Ollama's Q4_K_M downloads; RAM is what the model needs free to load and run with an 8K context.
CATALOG = [
    {
        "name": "qwen3:4b", "label": "Qwen3 4B", "size_gb": 2.5, "ram_gb": 4, "license": "Apache 2.0", "commercial": True,
        "speed": "about 2 min per answer on a laptop CPU",
        "note": "Best fit for laptops: the current Qwen generation with tool calling, in half the 8B's memory.",
    },
    {
        "name": "qwen3:8b", "label": "Qwen3 8B", "size_gb": 5.2, "ram_gb": 7, "license": "Apache 2.0", "commercial": True,
        "speed": "about 3-5 min per answer on a laptop CPU",
        "note": "Most accurate diagnoses. Needs about 6 GB of free RAM or it will fail to load.",
    },
    {
        "name": "qwen2.5:3b", "label": "Qwen2.5 3B", "size_gb": 1.9, "ram_gb": 3, "license": "Qwen Research", "commercial": False,
        "speed": "about 1-1.5 min per answer on a laptop CPU",
        "note": "Previous default: fastest and smallest. Research license: no commercial use.",
    },
]
CATALOG_NAMES = {item["name"] for item in CATALOG}

_pulls = {}
_pulls_lock = threading.Lock()


def selected_model():
    """The model picked in the dashboard, else OLLAMA_MODEL from .env."""
    try:
        saved = get_setting(SETTING_KEY)
    except sqlite3.Error:
        saved = None
    return (saved or os.getenv("OLLAMA_MODEL", "qwen3:8b")).strip()


def save_selected_model(name):
    set_setting(SETTING_KEY, name)


def pull_progress():
    with _pulls_lock:
        return {name: dict(progress) for name, progress in _pulls.items()}


def start_pull(host, name):
    """Download a model in the background; returns False if it is already downloading."""
    with _pulls_lock:
        if _pulls.get(name, {}).get("state") == "downloading":
            return False
        _pulls[name] = {"state": "downloading", "status": "starting", "completed": 0, "total": 0, "error": None}
    threading.Thread(target=_pull, args=(host, name), name=f"pull-{name}", daemon=True).start()
    return True


def _update(name, **fields):
    with _pulls_lock:
        _pulls[name].update(fields)


def _pull(host, name):
    try:
        with httpx.stream("POST", f"{host}/api/pull", json={"model": name, "stream": True}, timeout=httpx.Timeout(30, read=600)) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if not line:
                    continue
                event = json.loads(line)
                if event.get("error"):
                    raise RuntimeError(event["error"])
                fields = {"status": event.get("status", "")}
                if event.get("total"):
                    fields.update(total=event["total"], completed=event.get("completed", 0))
                _update(name, **fields)
        _update(name, state="done", status="success")
        logger.info("Downloaded model %s", name)
    except (httpx.HTTPError, ValueError, RuntimeError) as error:
        logger.warning("Downloading %s failed: %s", name, error)
        _update(name, state="error", error=str(error)[:300])
