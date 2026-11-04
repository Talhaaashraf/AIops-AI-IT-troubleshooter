"""A successful command is not a verified resolution when the evidence is missing."""

import asyncio
import json

import pytest

from backend.agent_brain import planner, session_store
from backend.agent_brain.executor import Target
from backend.learning import store


@pytest.fixture
def diagnosis(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "DB_PATH", tmp_path / "sessions.db")
    sid = session_store.create_session("agent-one", "test device", "Windows", "disk full")
    report = {"root_cause": "Disk space is low", "quick_findings": [{
        "key": "disk_full:C", "title": "Disk space is low", "source": "system_overview",
        "fixes": [{"tool_id": "clear_temp_files"}],
    }]}
    session_store.update_session(sid, report=report)
    return sid, report, {"tool_id": "clear_temp_files", "result": {"ok": True, "summary": "Cleanup completed"}}


@pytest.mark.parametrize("evidence", [
    [],
    [("system_overview", {}, {"ok": False, "summary": "Device unreachable", "data": None})],
    [("check_internet", {}, {"ok": True, "data": {}})],
])
def test_missing_or_failed_checks_never_mark_fix_resolved(diagnosis, monkeypatch, evidence):
    sid, report, fix = diagnosis

    async def rerun(*args, **kwargs):
        return evidence

    async def no_ai(*args, **kwargs):
        pytest.fail("Incomplete verification must not ask the model to guess success")

    monkeypatch.setattr(planner, "_run_parallel", rerun)
    monkeypatch.setattr(planner, "_chat", no_ai)
    asyncio.run(planner._verify(session_store.get_session(sid), Target("agent-one", "Windows", "test device"), report, fix))
    session = session_store.get_session(sid)
    assert session["verify"]["resolved"] is None
    assert session["status"] == "diagnosed"
    assert store.outcome_for(session) == "diagnosed"


@pytest.mark.parametrize("raw_resolved, expected", [("false", None), ("true", None), (None, None), (True, True), (False, False)])
def test_ai_verification_requires_a_boolean(diagnosis, monkeypatch, raw_resolved, expected):
    sid, report, fix = diagnosis
    report["quick_findings"] = []

    async def rerun(*args, **kwargs):
        return [("check_internet", {}, {"ok": True, "data": {}})]

    async def reply(*args, **kwargs):
        return {"content": json.dumps({"resolved": raw_resolved, "explanation": "Checked", "next_steps": []})}

    monkeypatch.setattr(planner, "_run_parallel", rerun)
    monkeypatch.setattr(planner, "_chat", reply)
    asyncio.run(planner._verify(session_store.get_session(sid), Target("agent-one", "Windows", "test device"), report, fix))
    assert session_store.get_session(sid)["verify"]["resolved"] is expected
