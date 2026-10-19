import secrets
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from backend import device_store, main, server_identity


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(device_store, "DB_PATH", tmp_path / "devices.db")
    hostname_file = tmp_path / "hostname"
    hostname_file.write_text("ubuntu-srv\n", encoding="utf-8")
    monkeypatch.setenv("HOST_HOSTNAME_FILE", str(hostname_file))
    monkeypatch.delenv("AIOPS_SERVER_HOSTNAME", raising=False)
    monkeypatch.delenv("SENTINEL_IN_DOCKER", raising=False)
    monkeypatch.setattr(server_identity, "CACHE_SECONDS", 0)


def _enroll(hostname, os_type="Linux"):
    device = device_store.register_device(secrets.token_urlsafe(32), hostname, os_type, allow_open=True)
    report = {"system": {"hostname": hostname, "os_name": os_type}, "cpu": {"total_usage_percent": 12.0}, "memory": {"ram": {"usage_percent": 40.0}}}
    device_store.save_report(device["device_id"], datetime.now(timezone.utc).isoformat(), report)
    return device


def test_the_agent_on_the_host_is_this_server():
    _enroll("laptop-1", "Windows")
    server = _enroll("ubuntu-srv.lan")
    snapshot = server_identity.server_snapshot()
    assert snapshot["source"]["kind"] == "host-agent" and snapshot["source"]["device_id"] == server["device_id"]
    assert snapshot["system"]["hostname"] == "ubuntu-srv.lan" and snapshot["source"]["stale"] is False
    assert server_identity.identity()["server_device_id"] == server["device_id"]


def test_without_a_host_agent_the_container_is_shown_and_labelled(monkeypatch):
    monkeypatch.setenv("SENTINEL_IN_DOCKER", "1")
    _enroll("laptop-1", "Windows")
    snapshot = server_identity.server_snapshot()
    assert snapshot["source"]["kind"] == "container"
    assert "ram" in snapshot["memory"]


def test_in_docker_the_container_is_not_offered_as_a_device(monkeypatch):
    monkeypatch.setenv("SENTINEL_IN_DOCKER", "1")
    laptop = _enroll("laptop-1", "Windows")
    targets = main.troubleshoot_targets()["targets"]
    assert [target["device_id"] for target in targets] == [laptop["device_id"]]
    with pytest.raises(HTTPException) as error:  # a request without a device must not silently run on the container
        main._default_target_id()
    assert error.value.status_code == 400
    assert "local" in [target["device_id"] for target in main.troubleshoot_targets(include_container=True)["targets"]]

    server = _enroll("ubuntu-srv")
    targets = main.troubleshoot_targets()["targets"]
    labelled = next(target for target in targets if target["device_id"] == server["device_id"])
    assert labelled["server"] is True and labelled["label"] == "This server (ubuntu-srv)"
    assert main._default_target_id() == server["device_id"]


def test_outside_docker_this_server_is_still_a_target():
    assert main.troubleshoot_targets()["targets"][0]["device_id"] == "local"
    assert main._default_target_id() == "local"
