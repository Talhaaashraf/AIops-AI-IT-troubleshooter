"""Fleet-wide correlation (spec §31, §41): read-only, over the learned-cases store.

When the same kind of problem (same playbook) is diagnosed on several DIFFERENT devices within a short
window, it may be a common-cause incident — a bad update or driver rollout, a printer or network outage —
rather than one endpoint's problem. This module only reads what the app already records and surfaces a
note; it never changes anything and starts no scans.
"""

import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .learning import store as learning_store


def _window_days():
    try:
        return max(1, int(os.getenv("FLEET_WINDOW_DAYS", "7")))
    except ValueError:
        return 7


def _min_devices():
    try:
        return max(2, int(os.getenv("FLEET_MIN_DEVICES", "3")))
    except ValueError:
        return 3


def _recent(cases, window_days):
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    recent = []
    for case in cases:
        try:
            when = datetime.fromisoformat(case["created_at"])
        except (KeyError, TypeError, ValueError):
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when >= cutoff:
            recent.append(case)
    return recent


def fleet_clusters(window_days=None, min_devices=None, limit=1000):
    """Clusters of the same playbook diagnosed on >= min_devices distinct devices in the window.
    Most-affected first. Read-only."""
    window_days = window_days or _window_days()
    min_devices = min_devices or _min_devices()
    cases = _recent(learning_store.list_cases(limit), window_days)
    groups = defaultdict(list)
    for case in cases:
        signature = case.get("playbook_id")
        if signature and case.get("device_id"):
            groups[signature].append(case)
    clusters = []
    for signature, items in groups.items():
        devices = sorted({case["device_id"] for case in items})
        if len(devices) >= min_devices:
            clusters.append({
                "signature": signature,
                "title": signature.replace("_", " "),
                "device_count": len(devices),
                "devices": devices[:50],
                "os_types": sorted({case.get("os_type") for case in items if case.get("os_type")}),
                "case_count": len(items),
                "example_issue": (items[0].get("issue") or "")[:160],
            })
    clusters.sort(key=lambda cluster: cluster["device_count"], reverse=True)
    return clusters


def note_for(device_id, playbook_id, window_days=None, min_devices=None):
    """A fleet note for a diagnosis in progress, or None. Counts this device plus other distinct devices
    with the same playbook in the window; a note is returned only when the total reaches min_devices and
    at least one OTHER device is involved (so a single device's repeats never trip it)."""
    if not playbook_id:
        return None
    window_days = window_days or _window_days()
    min_devices = min_devices or _min_devices()
    cases = _recent(learning_store.list_cases(1000), window_days)
    others = sorted({case["device_id"] for case in cases
                     if case.get("playbook_id") == playbook_id and case.get("device_id") and case["device_id"] != device_id})
    total = len(others) + 1  # include the device being diagnosed now
    if others and total >= min_devices:
        return {
            "signature": playbook_id,
            "device_count": total,
            "other_devices": others[:10],
            "message": f"The same kind of problem ({playbook_id.replace('_', ' ')}) has been seen on {total} devices "
                       f"in the last {window_days} days — this may be a fleet-wide (common-cause) issue, not only this device.",
        }
    return None
