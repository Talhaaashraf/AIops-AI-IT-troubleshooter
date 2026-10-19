import asyncio
import secrets
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from backend import device_store, main, server_identity
from backend.agent_brain import planner, session_store
from backend.learning import store as learning_store


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(device_store, "DB_PATH", tmp_path / "devices.db")
    hostname_file = tmp_path / "hostname"
    hostname_file.write_text("ubuntu-srv\n", encoding="utf-8")
    monkeypatch.setenv("HOST_HOSTNAME_FILE", str(hostname_file))
    monkeypatch.delenv("AIOPS_SERVER_HOSTNAME", raising=False)
    monkeypatch.delenv("SENTINEL_IN_DOCKER", raising=False)
    monkeypatch.delenv("AIOPS_SERVER_DEVICE_ID", raising=False)
    monkeypatch.setattr(server_identity, "CACHE_SECONDS", 0)
    for module in (session_store, learning_store):
        monkeypatch.setattr(module, "DB_PATH", tmp_path / "devices.db")
    yield
    server_identity._cache.update(at=0.0, device=None)  # no device from this test's database outlives it


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


def test_a_device_enrolled_later_under_the_servers_name_does_not_take_its_place(monkeypatch):
    first = _enroll("ubuntu-srv")
    second = _enroll("ubuntu-srv")
    assert server_identity.server_device()["device_id"] == first["device_id"]
    monkeypatch.setenv("AIOPS_SERVER_DEVICE_ID", second["device_id"])  # pinned by id wins
    assert server_identity.server_device()["device_id"] == second["device_id"]


def test_container_diagnoses_teach_nothing_and_cannot_be_rated(monkeypatch):
    monkeypatch.setenv("SENTINEL_IN_DOCKER", "1")
    session_id = session_store.create_session("local", "AIops server container", "Linux", "Internet is slow", None)
    session_store.update_session(session_id, status="diagnosed", report={"root_cause": "DNS is slow", "evidence": [], "proposed_fixes": []})
    asyncio.run(planner.learn_from(session_id))
    assert learning_store.get_case(session_id) is None
    with pytest.raises(HTTPException) as error:
        main.troubleshoot_feedback(session_id, {"helpful": False, "corrected_root_cause": "It was my laptop"})
    assert error.value.status_code == 400 and learning_store.get_case(session_id) is None


def test_the_performance_tab_tests_the_host_agent_instead_of_the_container(monkeypatch):
    monkeypatch.setenv("SENTINEL_IN_DOCKER", "1")
    with pytest.raises(HTTPException) as error:
        main._performance_target("local")
    assert error.value.status_code == 400
    server = _enroll("ubuntu-srv")
    assert main._performance_target("local").device_id == server["device_id"]
