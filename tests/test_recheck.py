"""Recheck after a finished diagnosis: read-only checks again, findings compared, nothing changed, outcome kept."""
import asyncio
import json

import pytest
from fastapi import HTTPException

from backend import main
from backend.agent_brain import planner, session_store
from backend.agent_brain.executor import Target

ONLINE = Target("dev1", "Windows", "office-pc", "online")
BUSY_RAM = {"ram_percent": 95, "cpu_percent": 20, "disks": []}
CALM = {"ram_percent": 40, "cpu_percent": 95, "disks": []}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(planner, "resolve_target", lambda device_id: ONLINE)


def diagnosed(status="diagnosed"):
    session_id = session_store.create_session("dev1", "office-pc", "Windows", "my pc is slow")
    session_store.add_step(session_id, "tool", "system_overview", {}, {"ok": True, "data": BUSY_RAM})
    session_store.add_step(session_id, "tool", "performance_benchmark", {}, {"ok": True})
    session_store.add_step(session_id, "tool", "system_overview", {}, {"ok": True, "data": BUSY_RAM})  # a duplicate runs once
    found = planner.findings.analyze([("system_overview", {}, {"ok": True, "data": BUSY_RAM})], "Windows")
    report = {"root_cause": "Memory is full", "quick_findings": found, "cause_finding": "ram_high", "proposed_fixes": []}
    session_store.update_session(session_id, status=status, report=report)
    return session_id


def fake_checks(monkeypatch, data, ok=True):
    ran = []

    async def run(session_id, target, calls, kind="tool"):
        ran.append((calls, kind))
        return [(tool_id, args, {"ok": ok, "data": data, "summary": "x"}) for tool_id, args in calls]

    monkeypatch.setattr(planner, "_run_parallel", run)
    return ran


def test_recheck_reports_the_cause_cleared_and_a_new_problem(monkeypatch):
    session_id = diagnosed("resolved")
    ran = fake_checks(monkeypatch, CALM)
    result = asyncio.run(planner.recheck(session_id))
    assert ran == [([("system_overview", {})], "verify")]  # the diagnosis's checks, read-only "verify" steps, no benchmark
    assert result["cause"] == "cleared" and result["cleared"] == ["Memory is 95% used"] and result["new"] == ["CPU is 95% busy"]
    assert "no longer detected" in result["summary"] and "New since the diagnosis" in result["summary"]
    session = session_store.get_session(session_id, include_steps=False)
    assert session["status"] == "resolved"  # the outcome is never changed by a recheck
    assert session["report"]["recheck"]["method"] == "rules"


def test_a_failed_check_never_counts_as_cleared(monkeypatch):
    session_id = diagnosed()
    fake_checks(monkeypatch, {}, ok=False)
    result = asyncio.run(planner.recheck(session_id))
    assert result["cause"] == "not_rechecked" and result["cleared"] == [] and result["failed_checks"] == ["system_overview"]
    assert "Not confirmed" in result["summary"]


def test_still_detected(monkeypatch):
    session_id = diagnosed()
    fake_checks(monkeypatch, BUSY_RAM)
    assert asyncio.run(planner.recheck(session_id))["cause"] == "still_detected"


def test_recheck_is_refused_while_busy_offline_or_unknown(monkeypatch):
    fake_checks(monkeypatch, CALM)
    with pytest.raises(ValueError, match="busy"):
        asyncio.run(planner.recheck(diagnosed("fixing")))
    monkeypatch.setattr(planner, "resolve_target", lambda device_id: Target("dev1", "Windows", "office-pc", "offline"))
    with pytest.raises(ValueError, match="offline"):
        asyncio.run(planner.recheck(diagnosed()))
    with pytest.raises(HTTPException) as missing:
        asyncio.run(main.troubleshoot_recheck("nope"))
    assert missing.value.status_code == 404


def test_recheck_is_recorded(monkeypatch, tmp_path):
    session_id = diagnosed()
    fake_checks(monkeypatch, CALM)
    asyncio.run(main.troubleshoot_recheck(session_id))
    records = [json.loads(path.read_text(encoding="utf-8")) for path in (tmp_path / "decisions").rglob("*.json")]
    assert any(item["kind"] == "recheck" and item["cause"] == "cleared" for item in records)
