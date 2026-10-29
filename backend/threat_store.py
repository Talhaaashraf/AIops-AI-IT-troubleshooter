"""SQLite storage for endpoint threat scans and the marks people put on findings (acknowledged, false positive).

Only the raw scan is stored: findings are worked out from it on every read (backend/threat_rules.py), so a better
rule also applies to scans that ran before it.
"""

import json
import sqlite3
from datetime import datetime, timezone

from .config import DB_PATH

SCANS_KEPT_PER_DEVICE = 10
MARK_STATUSES = ("acknowledged", "false_positive")


def _connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS threat_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            scan_id TEXT,
            created_at TEXT NOT NULL,
            data_json TEXT NOT NULL
        )
    """)
    connection.execute("CREATE INDEX IF NOT EXISTS threat_scans_device ON threat_scans (device_id, id)")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS threat_marks (
            device_id TEXT NOT NULL,
            dedup_key TEXT NOT NULL,
            status TEXT NOT NULL,
            note TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (device_id, dedup_key)
        )
    """)
    connection.commit()
    return connection


def save_scan(device_id, data):
    now = datetime.now(timezone.utc).isoformat()
    with _connect() as connection:
        connection.execute("INSERT INTO threat_scans (device_id, scan_id, created_at, data_json) VALUES (?, ?, ?, ?)",
                           (device_id, data.get("scan_id"), now, json.dumps(data, default=str)))
        connection.execute("DELETE FROM threat_scans WHERE device_id = ? AND id NOT IN (SELECT id FROM threat_scans WHERE device_id = ? ORDER BY id DESC LIMIT ?)",
                           (device_id, device_id, SCANS_KEPT_PER_DEVICE))
        connection.commit()
    return now


def latest_scan(device_id):
    """{"created_at", "data"} of the device's newest scan, or None."""
    with _connect() as connection:
        row = connection.execute("SELECT created_at, data_json FROM threat_scans WHERE device_id = ? ORDER BY id DESC LIMIT 1", (device_id,)).fetchone()
    return {"created_at": row["created_at"], "data": json.loads(row["data_json"])} if row else None


def latest_scans():
    """{device_id: {"created_at", "data"}} with each device's newest scan."""
    with _connect() as connection:
        rows = connection.execute("SELECT device_id, created_at, data_json FROM threat_scans WHERE id IN (SELECT MAX(id) FROM threat_scans GROUP BY device_id)").fetchall()
    return {row["device_id"]: {"created_at": row["created_at"], "data": json.loads(row["data_json"])} for row in rows}


def set_mark(device_id, dedup_key, status, note=None):
    """status: acknowledged / false_positive, or None to reopen the finding."""
    with _connect() as connection:
        if status is None:
            connection.execute("DELETE FROM threat_marks WHERE device_id = ? AND dedup_key = ?", (device_id, dedup_key))
        else:
            connection.execute(
                "INSERT INTO threat_marks (device_id, dedup_key, status, note, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(device_id, dedup_key) DO UPDATE SET status = excluded.status, note = excluded.note, updated_at = excluded.updated_at",
                (device_id, dedup_key, status, note, datetime.now(timezone.utc).isoformat()))
        connection.commit()


def get_marks(device_id):
    with _connect() as connection:
        rows = connection.execute("SELECT dedup_key, status, note, updated_at FROM threat_marks WHERE device_id = ?", (device_id,)).fetchall()
    return {row["dedup_key"]: {"status": row["status"], "note": row["note"], "updated_at": row["updated_at"]} for row in rows}
