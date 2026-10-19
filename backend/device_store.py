"""SQLite persistence for registered agents using hashed bearer tokens."""

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from .config import DB_PATH
OFFLINE_SECONDS = 30


def hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            nickname TEXT NOT NULL,
            hostname TEXT NOT NULL,
            os_type TEXT NOT NULL,
            agent_token TEXT,
            agent_token_hash TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'offline',
            token_expires_at TEXT
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS device_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            diagnostics_json TEXT NOT NULL,
            spike_detected INTEGER NOT NULL DEFAULT 0
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS pending_agent_tokens (
            token_hash TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL
        )
    """)

    # The upgrades below write to the database, so they run once per database file and process, not on
    # every connection (every agent report and dashboard poll opens one).
    if str(DB_PATH) not in _upgraded:
        with _upgrade_lock:
            if str(DB_PATH) not in _upgraded:
                _upgrade(connection)
                _upgraded.add(str(DB_PATH))
    return connection


_upgraded = set()
_upgrade_lock = threading.Lock()


def _upgrade(connection):
    columns = {row[1] for row in connection.execute("PRAGMA table_info(devices)").fetchall()}
    for column, definition in (("agent_token_hash", "TEXT"), ("token_expires_at", "TEXT"), ("onboarding_session_id", "TEXT")):
        if column not in columns:
            connection.execute(f"ALTER TABLE devices ADD COLUMN {column} {definition}")

    # Devices enrolled before the fix above inherited the enrollment expiry and would
    # silently stop authenticating 24h later; clear it.
    connection.execute("UPDATE devices SET token_expires_at = NULL WHERE token_expires_at IS NOT NULL")

    legacy_rows = connection.execute(
        "SELECT device_id, agent_token FROM devices WHERE agent_token_hash IS NULL AND agent_token IS NOT NULL"
    ).fetchall()
    for row in legacy_rows:
        legacy_hash = hash_token(row["agent_token"])
        connection.execute(
            "UPDATE devices SET agent_token_hash = ?, agent_token = ? WHERE device_id = ?",
            (legacy_hash, legacy_hash, row["device_id"]),
        )

    connection.commit()


MAX_PENDING_TOKENS = 10


def create_pending_token(hours=24):
    """A one-time enrollment token. The Add Agent page makes one each time it opens, so expired tokens are
    purged and only the newest MAX_PENDING_TOKENS unclaimed ones stay valid."""
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = datetime.fromtimestamp(now.timestamp() + hours * 3600, timezone.utc).isoformat()
    with _connect() as connection:
        connection.execute("DELETE FROM pending_agent_tokens WHERE expires_at <= ?", (now.isoformat(),))
        connection.execute(
            "INSERT INTO pending_agent_tokens (token_hash, expires_at) VALUES (?, ?)",
            (hash_token(token), expires_at),
        )
        connection.execute(
            "DELETE FROM pending_agent_tokens WHERE token_hash NOT IN (SELECT token_hash FROM pending_agent_tokens ORDER BY expires_at DESC LIMIT ?)",
            (MAX_PENDING_TOKENS,),
        )
        connection.commit()
    return token, expires_at


MIN_SELF_TOKEN_LENGTH = 24


DEVICE_ID_PATTERN = re.compile(r"^agent-[0-9a-f]{12}$")
KNOWN_OS = {"Windows", "Linux", "Darwin"}


def clean_label(value, limit=100):
    """Hostnames and nicknames come from the device: keep printable text without markup characters."""
    text = "".join(char for char in str(value or "") if char.isprintable() and char not in '<>"\'`')
    return " ".join(text.split())[:limit]


def register_device(token, hostname, os_type, nickname="", device_id=None, allow_open=False):
    """Claim a pending enrollment token, re-register a known device, or (open enrollment)
    enroll a new device with a secret it generated itself."""
    hostname, nickname = clean_label(hostname) or "Unknown", clean_label(nickname)
    os_type = os_type if os_type in KNOWN_OS else "Unknown"
    # The server names devices; a client-chosen id ("tasks", "report1", ...) could collide with routes.
    device_id = device_id if isinstance(device_id, str) and DEVICE_ID_PATTERN.match(device_id) else None
    token_hash = hash_token(token)
    now = utc_now()
    with _connect() as connection:
        pending = connection.execute(
            "SELECT expires_at FROM pending_agent_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        existing = connection.execute(
            "SELECT * FROM devices WHERE agent_token_hash = ?", (token_hash,)
        ).fetchone()

        if pending:
            if datetime.fromisoformat(pending["expires_at"]) <= datetime.now(timezone.utc):
                connection.execute("DELETE FROM pending_agent_tokens WHERE token_hash = ?", (token_hash,))
                connection.commit()
                raise ValueError("Agent token has expired")
            # The 24h expiry only limits how long an unclaimed enrollment token is valid;
            # once a device claims it, the token becomes that device's permanent credential.
            token_expires_at = None
            connection.execute("DELETE FROM pending_agent_tokens WHERE token_hash = ?", (token_hash,))
        elif existing:
            token_expires_at = existing["token_expires_at"]
            if token_expires_at and datetime.fromisoformat(token_expires_at) <= datetime.now(timezone.utc):
                raise ValueError("Agent token has expired")
        elif allow_open and len(token) >= MIN_SELF_TOKEN_LENGTH:
            token_expires_at = None
        else:
            raise ValueError("Invalid or unclaimed agent token")

        if existing:
            device_id = existing["device_id"]
            connection.execute(
                "UPDATE devices SET hostname = ?, os_type = ?, nickname = ?, last_seen = ?, status = 'online' WHERE device_id = ?",
                (hostname, os_type, nickname or existing["nickname"], now, device_id),
            )
        else:
            device_id = device_id or f"agent-{uuid.uuid4().hex[:12]}"
            connection.execute(
                "INSERT INTO devices (device_id, nickname, hostname, os_type, agent_token_hash, first_seen, last_seen, status, token_expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'online', ?)",
                (device_id, nickname or hostname, hostname, os_type, token_hash, now, now, token_expires_at),
            )

        connection.commit()
        row = connection.execute(
            "SELECT device_id, nickname, hostname, os_type, first_seen, last_seen, status, token_expires_at FROM devices WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        return dict(row)


def get_device_by_token(token):
    with _connect() as connection:
        row = connection.execute("SELECT * FROM devices WHERE agent_token_hash = ?", (hash_token(token),)).fetchone()
        if not row:
            return None
        if row["token_expires_at"] and datetime.fromisoformat(row["token_expires_at"]) <= datetime.now(timezone.utc):
            return None
        return dict(row)


def claim_onboarding(device_id, session_id):
    """Record the onboarding check for a device once; False if it already has one (or another request won)."""
    with _connect() as connection:
        changed = connection.execute(
            "UPDATE devices SET onboarding_session_id = ? WHERE device_id = ? AND onboarding_session_id IS NULL",
            (session_id, device_id),
        ).rowcount
        connection.commit()
        return changed == 1


def set_onboarding_session(device_id, session_id):
    with _connect() as connection:
        connection.execute("UPDATE devices SET onboarding_session_id = ? WHERE device_id = ?", (session_id, device_id))
        connection.commit()


def get_device(device_id):
    with _connect() as connection:
        row = connection.execute(
            "SELECT device_id, nickname, hostname, os_type, first_seen, last_seen, status, onboarding_session_id FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        return dict(row) if row else None


def is_valid_install_token(token):
    """True for an unexpired enrollment token or a token an enrolled device already owns (re-install)."""
    if not token:
        return False
    with _connect() as connection:
        pending = connection.execute("SELECT expires_at FROM pending_agent_tokens WHERE token_hash = ?", (hash_token(token),)).fetchone()
    if pending:
        return datetime.fromisoformat(pending["expires_at"]) > datetime.now(timezone.utc)
    return get_device_by_token(token) is not None


def delete_device(device_id):
    with _connect() as connection:
        connection.execute("DELETE FROM device_reports WHERE device_id = ?", (device_id,))
        cursor = connection.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
        connection.commit()
        return cursor.rowcount > 0


def save_report(device_id, timestamp, diagnostics, spike_detected=False):
    with _connect() as connection:
        connection.execute(
            "INSERT INTO device_reports (device_id, timestamp, diagnostics_json, spike_detected) VALUES (?, ?, ?, ?)",
            (device_id, timestamp, json.dumps(diagnostics), int(bool(spike_detected))),
        )
        connection.execute(
            "UPDATE devices SET last_seen = ?, status = 'online' WHERE device_id = ?", (timestamp, device_id)
        )
        connection.execute(
            "DELETE FROM device_reports WHERE device_id = ? AND id NOT IN "
            "(SELECT id FROM device_reports WHERE device_id = ? ORDER BY id DESC LIMIT 20)",
            (device_id, device_id),
        )
        connection.commit()


def _decode_report(row):
    if not row:
        return None
    result = dict(row)
    result["diagnostics"] = json.loads(result.pop("diagnostics_json"))
    result["spike_detected"] = bool(result["spike_detected"])
    return result


def get_latest_report(device_id):
    with _connect() as connection:
        row = connection.execute(
            "SELECT id, device_id, timestamp, diagnostics_json, spike_detected FROM device_reports WHERE device_id = ? ORDER BY id DESC LIMIT 1",
            (device_id,),
        ).fetchone()
        return _decode_report(row)


def mark_offline_devices():
    cutoff = datetime.now(timezone.utc).timestamp() - OFFLINE_SECONDS
    with _connect() as connection:
        rows = connection.execute("SELECT device_id, last_seen FROM devices WHERE status = 'online'").fetchall()
        for row in rows:
            try:
                seen = datetime.fromisoformat(row["last_seen"]).timestamp()
            except ValueError:
                seen = 0
            if seen < cutoff:
                connection.execute("UPDATE devices SET status = 'offline' WHERE device_id = ?", (row["device_id"],))
        connection.commit()


def list_devices():
    mark_offline_devices()
    with _connect() as connection:
        rows = connection.execute(
            "SELECT device_id, nickname, hostname, os_type, first_seen, last_seen, status, token_expires_at, onboarding_session_id FROM devices ORDER BY nickname"
        ).fetchall()
        return [dict(row) for row in rows]
