"""Encrypted provider credentials. No dotenv discovery and no credential responses.

An externally provisioned Fernet key enables persistence. Without it, both the
encryption key and encrypted credentials live only in this server process.

A provider can hold several keys (MAX_KEYS), saved together as one encrypted list of {"id", "key"}. The
first one is the primary key. A credential saved before lists existed (one plain key) reads as a list of one.
"""
import json
import os
import secrets
import threading

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

from . import security_store as store

_lock = threading.RLock()
_cipher = None
_persistent = False
_memory = {}
MAX_KEYS = 5


def cipher():
    global _cipher, _persistent
    with _lock:
        if _cipher is None:
            master = os.environ.get("SENTINEL_INTELLIGENCE_MASTER_KEY")
            try:
                _cipher = Fernet(master.encode() if master else Fernet.generate_key())
            except (ValueError, TypeError):
                raise HTTPException(503, "The externally provisioned intelligence encryption key is invalid") from None
            _persistent = bool(master)
        return _cipher


def mode():
    cipher()
    return "encrypted-database" if _persistent else "encrypted-memory (re-enter provider keys after restart)"


def _decode(text, legacy_id):
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict) and isinstance(data.get("keys"), list):
        return [{"id": str(item["id"]), "key": str(item["key"])} for item in data["keys"]
                if isinstance(item, dict) and item.get("id") and item.get("key")][:MAX_KEYS]
    return [{"id": legacy_id or "primary", "key": text}]


def get_all(provider, legacy_id=None):
    """Every saved key of a provider as [{"id", "key"}], primary first. `legacy_id` names a key saved before lists."""
    encryption = cipher()
    with _lock:
        if _persistent:
            with store.connect() as db:
                row = db.execute("SELECT ciphertext FROM intelligence_credentials WHERE provider=?", (provider,)).fetchone()
            value = row[0] if row else None
        else:
            value = _memory.get(provider)
        if not value:
            return []
        try:
            return _decode(encryption.decrypt(value.encode()).decode(), legacy_id)
        except InvalidToken:
            raise HTTPException(503, "Provider credential cannot be decrypted; restore the master key or replace the provider key") from None


def get(provider):
    """The primary key, or None."""
    keys = get_all(provider)
    return keys[0]["key"] if keys else None


def put_all(provider, keys):
    """Replace a provider's keys with [{"id", "key"}] (an empty list deletes them)."""
    encryption = cipher()
    keys = [{"id": str(item["id"]), "key": str(item["key"])} for item in keys][:MAX_KEYS]
    value = encryption.encrypt(json.dumps({"keys": keys}).encode()).decode() if keys else None
    with _lock:
        # Deletion also removes persistent ciphertext when running in temporary mode.
        with store.connect() as db:
            db.execute("DELETE FROM intelligence_credentials WHERE provider=?", (provider,))
            if value and _persistent:
                db.execute("INSERT INTO intelligence_credentials VALUES (?,?)", (provider, value))
        _memory.pop(provider, None)
        if value and not _persistent:
            _memory[provider] = value


def put(provider, key):
    """Replace a provider's keys with this one key (empty deletes them)."""
    put_all(provider, [{"id": secrets.token_hex(12), "key": key}] if key else [])
