"""Last software inventory per device, so the Software tab opens without a 1-2 minute rescan."""

import json
import sqlite3
from datetime import datetime, timezone

from .config import DB_PATH


def _connect():
    connection = sqlite3.connect(DB_PATH)
    connection.execute("CREATE TABLE IF NOT EXISTS software_inventory (device_id TEXT PRIMARY KEY, collected_at TEXT NOT NULL, data_json TEXT NOT NULL)")
    return connection


def save_inventory(device_id, data):
    with _connect() as connection:
        connection.execute(
            "INSERT INTO software_inventory (device_id, collected_at, data_json) VALUES (?, ?, ?) "
            "ON CONFLICT(device_id) DO UPDATE SET collected_at = excluded.collected_at, data_json = excluded.data_json",
            (device_id, datetime.now(timezone.utc).isoformat(), json.dumps(data)),
        )


def get_inventory(device_id):
    with _connect() as connection:
        row = connection.execute("SELECT collected_at, data_json FROM software_inventory WHERE device_id = ?", (device_id,)).fetchone()
    return {"collected_at": row[0], **json.loads(row[1])} if row else None


def _update(device_id, change):
    inventory = get_inventory(device_id)
    if not inventory:
        return
    inventory.pop("collected_at")
    change(inventory)
    inventory["count"] = len(inventory.get("software", []))
    inventory["updates_available"] = sum(1 for item in inventory.get("software", []) if item.get("update_available"))
    with _connect() as connection:
        connection.execute("UPDATE software_inventory SET data_json = ? WHERE device_id = ?", (json.dumps(inventory), device_id))


def mark_uninstalled(device_id, entry_id):
    _update(device_id, lambda inventory: inventory.update(software=[item for item in inventory.get("software", []) if item.get("id") != entry_id]))


def mark_updated(device_id, package_id):
    def change(inventory):
        for item in inventory.get("software", []):
            if item.get("update_id") == package_id:
                item.update(version=item.get("available_version") or item.get("version"), update_available=False, available_version=None)
    _update(device_id, change)
