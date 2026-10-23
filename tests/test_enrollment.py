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


def test_the_newest_token_survives_even_when_many_share_one_clock_tick(monkeypatch):
    from datetime import datetime, timezone

    frozen = datetime.now(timezone.utc)  # one instant for every token (not a fixed date that later lies in the past)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen

    monkeypatch.setattr(device_store, "datetime", Clock)
    tokens = [device_store.create_pending_token()[0] for _ in range(device_store.MAX_PENDING_TOKENS + 5)]
    monkeypatch.setattr(device_store, "datetime", datetime)
    assert device_store.is_valid_install_token(tokens[-1]) and not device_store.is_valid_install_token(tokens[0])


def test_by_default_any_device_installs_with_the_same_command_and_no_token(monkeypatch):
    from fastapi.testclient import TestClient

    from backend import main

    monkeypatch.delenv("OPEN_ENROLLMENT", raising=False)
    client = TestClient(main.app)
    for script in ("windows.ps1", "linux.sh", "macos.sh"):
        body = client.get(f"/install/{script}")
        assert body.status_code == 200 and "__TOKEN__" not in body.text, script
    assert client.get("/api/agents/bundle").content[:2] == b"PK"
    # Two laptops run the same command: each makes its own secret and becomes its own device.
    first = client.post("/api/agents/register", json={"token": "a" * 43, "hostname": "laptop-1", "os_type": "Windows"}).json()
    second = client.post("/api/agents/register", json={"token": "b" * 43, "hostname": "macbook", "os_type": "Darwin"}).json()
    again = client.post("/api/agents/register", json={"token": "a" * 43, "hostname": "laptop-1", "os_type": "Windows"}).json()
    assert first["device_id"] != second["device_id"] and again["device_id"] == first["device_id"]


def test_one_time_tokens_come_back_when_open_enrollment_is_off(monkeypatch):
    from fastapi.testclient import TestClient

    from backend import main

    monkeypatch.setenv("OPEN_ENROLLMENT", "false")
    client = TestClient(main.app)
    assert client.get("/install/linux.sh").status_code == 401
    assert client.post("/api/agents/register", json={"token": "c" * 43, "hostname": "stranger", "os_type": "Linux"}).status_code == 401


def _report(token, hostname="old-laptop", device_id="agent-a90854fe9061"):
    return {"device_id": device_id, "diagnostics": {"system": {"hostname": hostname, "os_name": "Windows"}, "cpu": {}, "memory": {}}}


def test_an_agent_from_another_server_is_enrolled_by_its_first_report(monkeypatch):
    """An agent installed against an old server keeps its secret and device id; the new server must accept it."""
    from fastapi.testclient import TestClient

    from backend import main

    monkeypatch.delenv("OPEN_ENROLLMENT", raising=False)
    monkeypatch.setenv("ONBOARDING_CHECK", "false")
    client = TestClient(main.app)
    secret = "s" * 43
    first = client.post("/api/agents/report", json=_report(secret), headers={"Authorization": f"Bearer {secret}"})
    assert first.status_code == 200 and first.json()["device_id"] == "agent-a90854fe9061"
    assert client.get("/api/agents/tasks/next?wait=1", headers={"Authorization": f"Bearer {secret}"}).status_code == 200
    # Another agent claiming the same id gets an id of its own instead of taking that device over.
    other = "o" * 43
    second = client.post("/api/agents/report", json=_report(other, "desktop"), headers={"Authorization": f"Bearer {other}"})
    assert second.status_code == 200 and second.json()["device_id"] not in ("agent-a90854fe9061", None)


def test_an_unknown_agent_is_still_refused_when_enrollment_is_closed(monkeypatch):
    from fastapi.testclient import TestClient

    from backend import main

    monkeypatch.setenv("OPEN_ENROLLMENT", "false")
    client = TestClient(main.app)
    assert client.post("/api/agents/report", json=_report("t" * 43), headers={"Authorization": f"Bearer {'t' * 43}"}).status_code == 401
    assert client.post("/api/agents/report", json=_report("short"), headers={"Authorization": "Bearer short"}).status_code == 401


def test_the_agent_registers_again_when_the_server_does_not_know_it(monkeypatch, tmp_path):
    from agent import monitor_agent

    class Response:
        def __init__(self, status, body=None):
            self.status_code, self._body, self.text = status, body or {}, ""

        def json(self):
            return self._body

        def raise_for_status(self):
            if self.status_code >= 400:
                raise monitor_agent.requests.HTTPError(str(self.status_code))

    calls = []

    def fake_request(method, url, **kwargs):
        calls.append(url.rsplit("/", 1)[-1])
        return Response(401) if url.endswith("/report") else Response(200, {"device_id": "agent-000000000001"})

    monkeypatch.setattr(monitor_agent.requests, "request", fake_request)
    monkeypatch.setattr(monitor_agent, "save_config", lambda config: None)
    with pytest.raises(monitor_agent.NotEnrolled):  # a 401 is not retried forever
        monitor_agent.request_with_retry("POST", "http://server/api/agents/report", json={})
    config = {"server_url": "http://server", "AGENT_TOKEN": "x" * 43, "device_id": "agent-old"}
    config.pop("device_id")
    assert monitor_agent.register_until_accepted(config) == "agent-000000000001" and calls == ["report", "register"]
