"""Two devices at once: the global limit of diagnoses, the multi-device start, and the Live Troubleshooting feed."""

import asyncio
import json

import pytest
from fastapi import HTTPException

from backend import main, task_queue, workers
from backend.agent_brain import planner, session_store
from backend.agent_brain.executor import Target
from backend.learning import model_builder
from backend.learning import store as learning_store

HEALTHY_DISK = {"cpu_percent": 10, "ram_percent": 40, "disks": [{"mount": "C:\\", "used_percent": 60.0, "free": "100 GB", "total": "256 GB"}], "uptime": "1 day, 2:00:00"}


class Provider:
    name = "fake"

    def status(self):
        return {"available": True, "provider": "fake", "model": "fake"}

    def chat(self, messages, **kwargs):
        return {"content": json.dumps(REPORT), "tool_calls": []}


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    for module in (session_store, task_queue, learning_store):
        monkeypatch.setattr(module, "DB_PATH", db)
    monkeypatch.setattr(model_builder, "LEARNED_DIR", tmp_path / "sentinel-tech")
    monkeypatch.setattr(model_builder, "VERSION_FILE", tmp_path / "sentinel-tech" / "version.json")
    monkeypatch.setattr(planner, "get_alerts", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner, "server_device", lambda: None)
    monkeypatch.delenv("MAX_CONCURRENT_DIAGNOSES", raising=False)


REPORT = {"cause": "none", "root_cause": "Nothing abnormal", "confidence": "low", "severity": "low", "evidence": [], "solutions": []}


def test_at_most_two_diagnoses_run_at_once_and_the_third_waits_in_line(monkeypatch):
    monkeypatch.setattr(planner, "get_provider", Provider)
    gate = {}

    async def execute(target, tool_id, args, max_risk, session_id=None):
        await gate["open"].wait()
        return {"tool_id": tool_id, "ok": True, "summary": "ok", "data": HEALTHY_DISK if tool_id == "system_overview" else {}}

    monkeypatch.setattr(planner, "execute", execute)
    monkeypatch.setattr(planner, "resolve_target", lambda device_id: Target(device_id, "Windows", device_id))
    ids = [session_store.create_session(f"dev{n}", f"dev{n}", "Windows", "my laptop is slow sometimes", None) for n in range(3)]

    async def scenario():
        gate["open"] = asyncio.Event()
        tasks = [asyncio.create_task(planner.run_diagnosis(session_id, mode="fast")) for session_id in ids]
        for _ in range(50):
            await asyncio.sleep(0.01)
        # Two diagnoses hold the two slots (their checks are blocked); the third waits for a slot.
        running = [session_id for session_id in ids if session_store.get_session(session_id, include_steps=False)["status"] == "running"]
        assert len(running) == 2
        waiting = next(session_id for session_id in ids if session_id not in running)
        assert session_store.get_session(waiting, include_steps=False)["status"] == "queued"
        assert planner.live_phase(waiting)["waiting"] is True and "Waiting in line" in planner.live_phase(waiting)["phase"]
        assert planner.live_phase(running[0])["phase"].startswith("Running checks: ")
        feed = main.troubleshoot_active()
        assert feed["limit"] == 2 and feed["in_use"] == 2
        assert [session["queue_position"] for session in feed["sessions"] if session["waiting"]] == [1]
        gate["open"].set()
        await asyncio.gather(*tasks)

    asyncio.run(scenario())
    # The third started once a slot was free: all three finished, and none is left in the live feed.
    assert all(session_store.get_session(session_id, include_steps=False)["status"] == "diagnosed" for session_id in ids)
    assert planner.live == {}
    assert main.troubleshoot_active()["sessions"] == []
    assert len(main.troubleshoot_active()["recent"]) == 3


def test_the_limit_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_DIAGNOSES", "1")

    async def scenario():
        return workers.diagnosis_slots()._value

    assert asyncio.run(scenario()) == 1 and workers.diagnosis_limit() == 1


def test_the_phase_says_when_a_diagnosis_waits_for_the_ai(monkeypatch):
    seen = []
    monkeypatch.setattr(planner, "get_provider", Provider)

    async def scenario():
        with planner._tracked("s1", "Starting"):
            async with workers.ai_gate():  # another diagnosis is generating
                task = asyncio.create_task(planner._chat([{"role": "user", "content": "hi"}], json_mode=True))
                await asyncio.sleep(0.05)
                seen.append(planner.live_phase("s1")["phase"])
            await task
            seen.append(planner.live_phase("s1")["phase"])

    asyncio.run(scenario())
    assert seen[0].startswith("Waiting for the AI")
    assert seen[1] == "The AI is writing its answer"
    assert planner.live_phase("s1") is None


def _targets(monkeypatch, *ids):
    targets = {device_id: Target(device_id, "Windows", f"laptop {device_id}") for device_id in ids}
    monkeypatch.setattr(main, "resolve_target", targets.get)
    started = []

    async def fake_run_diagnosis(session_id, mode=None, preset_evidence=None):
        started.append(session_id)

    monkeypatch.setattr(main, "run_diagnosis", fake_run_diagnosis)
    return started


def test_one_start_diagnoses_up_to_two_devices(monkeypatch):
    started = _targets(monkeypatch, "a", "b", "c")

    async def scenario():
        reply = await main.start_troubleshoot({"issue": "slow", "device_ids": ["a", "b", "a"], "mode": "fast"})
        await asyncio.sleep(0)
        return reply

    reply = asyncio.run(scenario())
    assert [item["device_id"] for item in reply["sessions"]] == ["a", "b"]  # duplicates dropped
    assert reply["session_id"] == reply["sessions"][0]["session_id"]  # older clients read the top-level fields
    assert sorted(started) == sorted(item["session_id"] for item in reply["sessions"])

    with pytest.raises(HTTPException) as too_many:
        asyncio.run(main.start_troubleshoot({"issue": "slow", "device_ids": ["a", "b", "c"]}))
    assert too_many.value.status_code == 400

    # "a" and "b" are still queued (the fake diagnosis never ran): a second start on "b" is refused and starts nothing.
    before = len(session_store.list_sessions())
    with pytest.raises(HTTPException) as busy:
        asyncio.run(main.start_troubleshoot({"issue": "slow", "device_ids": ["c", "b"]}))
    assert busy.value.status_code == 409 and "already being diagnosed" in busy.value.detail
    assert len(session_store.list_sessions()) == before

    single = asyncio.run(main.start_troubleshoot({"issue": "slow", "device_id": "c"}))
    assert single["device_id"] == "c" and len(single["sessions"]) == 1

    with pytest.raises(HTTPException) as bad:
        asyncio.run(main.start_troubleshoot({"issue": "slow", "device_ids": "a"}))
    assert bad.value.status_code == 400


def test_the_live_feed_route_is_not_taken_for_a_session_id(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("ADMIN_API_KEY", raising=False)
    session_store.create_session("dev1", "laptop", "Windows", main.ONBOARDING_ISSUE, "full_checkup")
    session_store.create_session("dev2", "server", "Linux", "slow", "performance")
    response = TestClient(main.app).get("/api/troubleshoot/active")
    assert response.status_code == 200
    data = response.json()
    assert [session["source"] for session in data["sessions"]] == ["Onboarding check", "Performance test"]
    # Not running in this process (a fresh start would have failed them): no phase, no slot in use.
    assert data["in_use"] == 0 and all(session["phase"] is None for session in data["sessions"])
