"""Keep new security state isolated from a developer's device database."""
import os

# Set before test modules import backend.config or any model provider.
os.environ["PYTHON_DOTENV_DISABLED"] = "1"

import pytest


@pytest.fixture(autouse=True)
def isolated_security_state(tmp_path, monkeypatch):
    from backend import security_store, security_chat, intelligence_secrets, security_samples
    monkeypatch.setattr(security_store, "DB_PATH", tmp_path / "security.db")
    monkeypatch.setattr(security_chat, "_sessions", {})
    monkeypatch.setattr(intelligence_secrets, "_memory", {})
    monkeypatch.setattr(intelligence_secrets, "_cipher", None)
    monkeypatch.setattr(intelligence_secrets, "_persistent", False)
    monkeypatch.delenv("SENTINEL_INTELLIGENCE_MASTER_KEY", raising=False)
    monkeypatch.setattr(security_samples, "_stages", {})
