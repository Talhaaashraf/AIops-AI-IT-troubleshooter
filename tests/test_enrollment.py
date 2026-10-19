import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from backend import device_store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(device_store, "DB_PATH", tmp_path / "test.db")


def test_open_enrollment_accepts_a_self_generated_secret():
    secret = "x" * 43
    with pytest.raises(ValueError):
        device_store.register_device(secret, "pc-1", "Windows")
    device = device_store.register_device(secret, "pc-1", "Windows", allow_open=True)
    assert device_store.get_device_by_token(secret)["device_id"] == device["device_id"]
    again = device_store.register_device(secret, "pc-1", "Windows", allow_open=True)
    assert again["device_id"] == device["device_id"]


def test_open_enrollment_rejects_short_secrets():
    with pytest.raises(ValueError):
        device_store.register_device("short", "pc-1", "Windows", allow_open=True)


def _request(cookies=None, headers=None):
    return SimpleNamespace(cookies=cookies or {}, headers=headers or {})


def test_the_dashboard_login_alone_mints_a_one_time_token(monkeypatch):
    from backend import auth, main

    monkeypatch.setenv("DASHBOARD_PASSWORD", "dashboard-secret")
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    response = main.generate_agent_token(_request({auth.SESSION_COOKIE_NAME: auth.session_token()}))
    assert device_store.is_valid_install_token(json.loads(response.body)["token"])
    assert response.headers["cache-control"] == "no-store"
    with pytest.raises(HTTPException) as error:
        main.generate_agent_token(_request())
    assert error.value.status_code == 401


def test_tokens_are_refused_when_no_login_is_configured(monkeypatch):
    from backend import main

    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    with pytest.raises(HTTPException) as error:
        main.generate_agent_token(_request())
    assert error.value.status_code == 403


def test_revoking_needs_the_admin_key_and_odd_input_is_a_401_not_a_crash(monkeypatch):
    from backend import auth, main

    monkeypatch.setenv("ADMIN_API_KEY", "admin-key-123")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "dashboard-secret")
    for headers in ({}, {"X-Admin-Key": "wrong"}, {"X-Admin-Key": "admin-key-12\u00e9"}, {"X-Admin-Key": "admin\u00a0key"}):
        with pytest.raises(HTTPException) as error:
            main.revoke_agent("agent-000000000000", _request(headers=headers))
        assert error.value.status_code == 401
    with pytest.raises(HTTPException) as error:  # the right key reaches the lookup
        main.revoke_agent("agent-000000000000", _request(headers={"X-Admin-Key": "admin-key-123"}))
    assert error.value.status_code == 404
    assert not auth.check_password("dashboard-secr\u00e9t")
    assert not auth.has_valid_session({auth.SESSION_COOKIE_NAME: "\u00e9"})


def test_expired_and_surplus_enrollment_tokens_are_purged():
    expired, _ = device_store.create_pending_token(hours=-1)
    tokens = [device_store.create_pending_token()[0] for _ in range(device_store.MAX_PENDING_TOKENS + 1)]
    assert not device_store.is_valid_install_token(expired)
    assert not device_store.is_valid_install_token(tokens[0])
    assert all(device_store.is_valid_install_token(token) for token in tokens[1:])
