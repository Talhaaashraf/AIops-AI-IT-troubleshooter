"""Specialist agents: Hardware, OS and Network use the same AI brain with their own instructions and read-only checks."""
import asyncio
import json

import pytest

from agent.toolkit import get_tool, list_tools
from backend.agent_brain import knowledge, planner, session_store, specialists
from backend.agent_brain.executor import Target
from backend.agent_brain.playbooks import PLAYBOOKS, get_playbook


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "DB_PATH", tmp_path / "test.db")


@pytest.mark.parametrize("playbook_id, expected", [
    ("hardware", "hardware"), ("battery", "hardware"), ("audio", "hardware"), ("printer", "hardware"),
    ("os_health", "os"), ("windows_update", "os"), ("crashes", "os"), ("slow_pc", "os"), ("high_usage", "os"),
    ("disk_full", "os"), ("performance", "os"),
    ("no_internet", "network"), ("wifi_drops", "network"),
    ("security", "general"), ("full_checkup", "general"),
])
def test_each_playbook_goes_to_one_specialist(playbook_id, expected):
    assert specialists.route(get_playbook(playbook_id))["id"] == expected


def test_an_unclear_problem_goes_to_the_general_technician_with_every_check():
    general = specialists.route(None)
    assert general["id"] == "general" and specialists.instructions(general) == "" and specialists.investigation_tools(general) is None


def test_no_playbook_belongs_to_two_specialists():
    owners = [item["id"] for item in specialists.SPECIALISTS.values() for _ in item["playbooks"]]
    playbooks = [playbook for item in specialists.SPECIALISTS.values() for playbook in item["playbooks"]]
    assert len(playbooks) == len(set(playbooks)) and len(owners) == len(playbooks)
    assert set(playbooks) <= {item["id"] for item in PLAYBOOKS}


def test_a_specialist_can_only_investigate_with_read_only_checks():
    visible = {tool.id for os_type in ("Windows", "Linux", "Darwin") for tool in list_tools(os_type, max_risk="read") if tool.ai_visible}
    for item in specialists.SPECIALISTS.values():
        own = specialists.investigation_tools(item)
        assert own <= visible, f"{item['id']}: {own - visible}"
        assert all(get_tool(tool_id).risk == "read" for tool_id in own)


def test_the_knowledge_hint_never_points_outside_the_specialists_checks():
    for item in specialists.SPECIALISTS.values():
        for playbook_id in item["playbooks"]:
            playbook = get_playbook(playbook_id)
            card = knowledge.match_domain(playbook["issue"], playbook, set())
            if card:
                assert set(card["tools"]) <= specialists.investigation_tools(item), (playbook_id, set(card["tools"]) - specialists.investigation_tools(item))


def _fake_brain(monkeypatch, calls, tool_calls=()):
    class Brain:
        name = "ollama"

        def status(self):
            return {"available": True, "model": "aiops-brain"}

        def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None, timeout=None, think=None, on_delta=None):
            calls.append({"system": messages[0]["content"], "user": messages[1]["content"], "tools": [item["function"]["name"] for item in tools or []]})
            if tools:
                return {"content": "", "tool_calls": list(tool_calls)} if len(calls) == 1 and tool_calls else {"content": "Done.", "tool_calls": []}
            return {"content": json.dumps({"cause": "none", "root_cause": "The checks did not show the problem.", "confidence": "low", "severity": "low",
                                           "solutions": [{"title": "Restart the router", "why": "x", "steps": ["a"], "risk": "low", "tool_id": None}] * 3}),
                    "tool_calls": [], "model": "aiops-brain"}

    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        assert max_risk == "read"
        return {"tool_id": tool_id, "ok": True, "summary": f"{tool_id} ran", "data": {}}

    monkeypatch.setattr(planner, "get_provider", lambda: Brain())
    monkeypatch.setattr(planner, "execute", fake_execute)
    monkeypatch.setattr(planner, "server_device", lambda: None)
    monkeypatch.setattr(planner, "get_alerts", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner.learning_store, "find_similar", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner.learning_store, "learned_fixes_for", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner.fleet_correlation, "note_for", lambda *args, **kwargs: None)


def test_the_network_specialist_writes_the_report_with_the_same_brain(monkeypatch):
    calls = []
    _fake_brain(monkeypatch, calls)
    session_id = session_store.create_session("local", "box", "Windows", "internet is not working", None)
    asyncio.run(planner.run_diagnosis(session_id, mode="fast"))

    report = session_store.get_session(session_id)["report"]
    assert report["specialist"] == {"id": "network", "name": "Network specialist"}
    assert calls[-1]["user"].startswith("Specialist instructions:\n- You are the AIops Network specialist")
    # The system prompt is the shared brain prompt (cached by Ollama), not a specialist copy.
    assert calls[-1]["system"] == planner.REPORT_PROMPT


def test_a_specialist_investigates_only_with_its_own_checks(monkeypatch):
    calls = []
    _fake_brain(monkeypatch, calls, tool_calls=[{"id": "c1", "name": "top_processes", "arguments": {"sort_by": "cpu"}}])
    monkeypatch.setenv("AGENT_MAX_STEPS", "2")
    monkeypatch.setenv("DIAGNOSIS_THINKING", "false")
    session_id = session_store.create_session("local", "box", "Windows", "wifi keeps dropping", None)
    asyncio.run(planner.run_diagnosis(session_id, mode="deep"))

    investigate = calls[0]
    assert investigate["user"].startswith("Specialist instructions:\n- You are the AIops Network specialist")
    assert set(investigate["tools"]) <= specialists.investigation_tools(specialists.SPECIALISTS["network"])
    assert "top_processes" not in investigate["tools"]
    steps = session_store.get_session(session_id)["steps"]
    assert "top_processes" not in [step["tool_id"] for step in steps if step["kind"] == "tool"]  # refused, never run


def test_an_instant_diagnosis_still_names_its_specialist(monkeypatch):
    calls = []
    _fake_brain(monkeypatch, calls)
    session_id = session_store.create_session("local", "box", "Windows", "the laptop is overheating", None)
    asyncio.run(planner.run_diagnosis(session_id, mode="instant"))
    assert session_store.get_session(session_id)["report"]["specialist"]["id"] == "hardware" and calls == []


def test_the_verification_uses_the_specialists_instructions(monkeypatch):
    seen = []

    async def fake_parallel(*args, **kwargs):
        return [("check_internet", {}, {"ok": True, "summary": "Network checks passed", "data": {}})]

    async def fake_chat(messages, **kwargs):
        seen.append(messages[1]["content"])
        return {"content": json.dumps({"resolved": True, "explanation": "Websites work now."})}

    monkeypatch.setattr(planner, "_run_parallel", fake_parallel)
    monkeypatch.setattr(planner, "_chat", fake_chat)
    session_id = session_store.create_session("local", "box", "Windows", "websites do not open", None)
    report = planner.link_solutions(planner.normalize_report({"root_cause": "DNS", "solutions": [{"title": "Flush DNS", "tool_id": "flush_dns"}]}, "websites do not open", "Windows"))
    report["specialist"] = specialists.label(specialists.SPECIALISTS["network"])
    session_store.update_session(session_id, status="diagnosed", report=report)
    fix = report["proposed_fixes"][0]
    fix["result"] = {"ok": True, "summary": "DNS cache flushed"}
    asyncio.run(planner._verify(session_store.get_session(session_id, include_steps=False), Target("local", "Windows", "box"), report, fix))
    assert seen and seen[0].startswith("Specialist instructions:\n- You are the AIops Network specialist")


def test_the_specialists_are_listed_for_the_dashboard():
    from backend import main

    listed = main.troubleshoot_specialists()["specialists"]
    assert [item["id"] for item in listed] == ["hardware", "os", "network", "general"]
    assert "no_internet" in next(item for item in listed if item["id"] == "network")["playbooks"]
