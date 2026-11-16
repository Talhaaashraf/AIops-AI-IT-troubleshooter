"""Keep new security state isolated from a developer's device database."""
import pytest


@pytest.fixture(autouse=True)
def isolated_security_state(tmp_path, monkeypatch):
    from backend import security_store, security_chat, intelligence
    monkeypatch.setattr(security_store, "DB_PATH", tmp_path / "security.db")
    monkeypatch.setattr(security_chat, "_sessions", {})
    monkeypatch.setattr(intelligence, "_keys", {})
