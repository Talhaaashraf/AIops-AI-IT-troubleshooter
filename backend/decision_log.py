"""Every AI decision and every human approval, saved as files in the decisions folder.

decisions/YYYY-MM-DD/HHMMSS_<kind>_<id>.json holds the full record; decisions/YYYY-MM-DD/index.md gets
one line per decision so a person can skim a day. The AI only ever *suggests*; records of actions say who
approved them, so the folder is an audit trail of what the model advised and what people chose.
"""

import hashlib
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import PROJECT_ROOT

logger = logging.getLogger(__name__)
_lock = threading.Lock()
SAFE_PART = re.compile(r"[^A-Za-z0-9_-]+")
KINDS = {
    "diagnosis", "fix_approved", "fix_rejected", "fix_done_manually", "fix_result", "health_analysis",
    "log_analysis", "chat_answer", "software_action", "performance_analysis", "model_switch", "leftover_review",
}


def decisions_dir():
    configured = os.getenv("DECISIONS_DIR", "decisions")
    path = Path(configured)
    return path if path.is_absolute() else PROJECT_ROOT / path


def prompt_hash(messages):
    """Short fingerprint of what the model was asked, to group identical prompts without storing them twice."""
    return hashlib.sha256(json.dumps(messages, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def _summary(kind, payload):
    for key in ("summary", "root_cause", "action", "title", "verdict"):
        if payload.get(key):
            return " ".join(str(payload[key]).split())[:160]
    return kind


def record(kind, subject_id, payload):
    """Write one decision; never raises (a full disk must not break a diagnosis). Returns the file path or None."""
    if kind not in KINDS:
        raise ValueError(f"Unknown decision kind: {kind}")
    now = datetime.now(timezone.utc)
    entry = {"kind": kind, "subject_id": subject_id, "recorded_at": now.isoformat(), **payload}
    try:
        day = decisions_dir() / now.strftime("%Y-%m-%d")
        name = f"{now.strftime('%H%M%S%f')[:9]}_{kind}_{SAFE_PART.sub('-', str(subject_id or 'none'))[:40]}.json"
        with _lock:
            day.mkdir(parents=True, exist_ok=True)
            path = day / name
            path.write_text(json.dumps(entry, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            index = day / "index.md"
            if not index.exists():
                index.write_text(f"# AIops decisions {now.strftime('%Y-%m-%d')} (UTC)\n\n", encoding="utf-8")
            device = payload.get("device") or payload.get("device_id") or ""
            approved = f" · approved by {payload['approved_by']}" if payload.get("approved_by") else ""
            with index.open("a", encoding="utf-8") as handle:
                handle.write(f"- {now.strftime('%H:%M:%S')} **{kind}** {device} - {_summary(kind, payload)}{approved} ([json]({name}))\n")
        return str(path)
    except OSError as error:
        logger.warning("Could not save decision %s for %s: %s", kind, subject_id, error)
        return None


def recent(limit=50):
    """Newest decisions first, across days."""
    root = decisions_dir()
    if not root.exists():
        return []
    files = sorted((path for day in root.iterdir() if day.is_dir() for path in day.glob("*.json")), key=lambda path: (path.parent.name, path.name), reverse=True)
    items = []
    for path in files[:limit]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        items.append({"file": f"{path.parent.name}/{path.name}", "kind": data.get("kind"), "subject_id": data.get("subject_id"),
                      "recorded_at": data.get("recorded_at"), "device": data.get("device"), "summary": _summary(data.get("kind", ""), data),
                      "approved_by": data.get("approved_by"), "model": data.get("model"), "thinking": data.get("thinking")})
    return items
