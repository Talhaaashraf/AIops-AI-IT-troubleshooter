"""Encrypted provider credentials. No dotenv discovery and no credential responses.

An externally provisioned Fernet key enables persistence. Without it, both the
encryption key and encrypted credentials live only in this server process.
"""
import os
import threading

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

from . import security_store as store

_lock = threading.RLock()
_cipher = None
_persistent = False
_memory = {}


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


def get(provider):
    encryption = cipher()
    with _lock:
        if _persistent:
            with store.connect() as db:
                row = db.execute("SELECT ciphertext FROM intelligence_credentials WHERE provider=?", (provider,)).fetchone()
            value = row[0] if row else None
        else:
            value = _memory.get(provider)
        if not value:
            return None
        try:
            return encryption.decrypt(value.encode()).decode()
        except InvalidToken:
            raise HTTPException(503, "Provider credential cannot be decrypted; restore the master key or replace the provider key") from None


def put(provider, key):
    encryption = cipher()
    with _lock:
        # Deletion also removes persistent ciphertext when running in temporary mode.
        with store.connect() as db:
            db.execute("DELETE FROM intelligence_credentials WHERE provider=?", (provider,))
            if key and _persistent:
                db.execute("INSERT INTO intelligence_credentials VALUES (?,?)", (provider, encryption.encrypt(key.encode()).decode()))
        _memory.pop(provider, None)
        if key and not _persistent:
            _memory[provider] = encryption.encrypt(key.encode()).decode()
