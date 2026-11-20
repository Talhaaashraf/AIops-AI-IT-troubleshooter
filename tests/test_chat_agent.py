"""AI Chat (LLM + tools): read-only checks run by themselves, a fix only after a person approves its card."""
import asyncio
import json

import pytest
from fastapi import HTTPException

from backend import chat_agent, main, task_queue
from backend.agent_brain import session_store
from backend.agent_brain.executor import Target

ONLINE = Target("dev1", "Windows", "laptop", "online")
OFFLINE = Target("dev1", "Windows", "laptop", "offline")
DNS_FAIL = {"dns_resolution": {"ok": False, "ms": None}, "tcp_to_internet": {"ok": True}, "http": {"ok": False}}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(task_queue, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(chat_agent, "turns", {})


class Brain:
    """A scripted model: `picks` are its tool calls round by round, `answer` its final JSON."""

    def __init__(self, picks=(), answer=None):
        self.picks, self.answer, self.calls = list(picks), answer or {}, []

    async def __call__(self, messages, tools=None, json_mode=False, max_tokens=None, think=False, **kwargs):
        self.calls.append({"messages": messages, "tools": [item["function"]["name"] for item in tools or []], "think": think})
        if tools:
            calls = self.picks.pop(0) if self.picks else []
            return {"content": "" if calls else "I have what I need.", "tool_calls": calls}
        return {"content": json.dumps(self.answer)}


def device(monkeypatch, brain, data=None):
    ran = []

    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        ran.append((tool_id, args, max_risk))
        payload = (data or {}).get(tool_id, {})
        return {"tool_id": tool_id, "ok": True, "summary": f"{tool_id} ran", "data": payload}

    monkeypatch.setattr(chat_agent, "_chat", brain)
    monkeypatch.setattr(chat_agent, "execute", fake_execute)
    return ran


def call(tool_id, **args):
    return {"id": tool_id, "name": tool_id, "arguments": args}


def turn_for(message, target=ONLINE, think=False):
    return chat_agent.create_turn(message, target, None, {"source": "agent", "status": target.status}, [], think)


def test_the_chat_runs_read_only_checks_and_proposes_a_fix_card(monkeypatch):
    brain = Brain(picks=[[call("check_internet")]], answer={"plain_explanation": "DNS is failing: names do not resolve.", "technical_root_cause": "DNS lookup failed",
                                                             "recommendations": ["Flush the DNS cache"], "fix": {"tool_id": "flush_dns", "args": {}, "why": "Clears stale DNS answers."}})
    ran = device(monkeypatch, brain, {"check_internet": DNS_FAIL})
    turn = turn_for("internet is not working")
    asyncio.run(chat_agent.run_turn(turn))

    view = chat_agent.public(turn)
    assert view["state"] == "done" and view["specialist"]["id"] == "network"
    assert ran == [("check_internet", {}, "read")]  # only the read-only check ran
    assert [step["tool_id"] for step in view["steps"]] == ["check_internet"] and view["steps"][0]["state"] == "done"
    assert view["reply"]["plain_explanation"].startswith("DNS is failing")
    assert view["proposal"]["tool_id"] == "flush_dns" and view["proposal"]["state"] == "proposed"
    # Both model calls carry the Network specialist's instructions; the answer call gets the fix list.
    users = [next(message for message in item["messages"] if message["role"] == "user") for item in brain.calls]
    assert all(message["content"].startswith("Specialist instructions:\n- You are the AIops Network specialist") for message in users)
    assert "flush_dns" in brain.calls[-1]["messages"][-1]["content"]


def test_a_change_tool_asked_for_as_a_check_never_runs(monkeypatch):
    brain = Brain(picks=[[call("flush_dns"), call("delete_threat", scan_id="s", item_id="i", confirm_name="x")]], answer={"plain_explanation": "ok"})
    ran = device(monkeypatch, brain)
    turn = turn_for("internet is not working")
    asyncio.run(chat_agent.run_turn(turn))

    assert ran == [] and turn["steps"] == []
    assert "flush_dns" not in brain.calls[0]["tools"] and "delete_threat" not in brain.calls[0]["tools"]
    refused = [message["content"] for message in brain.calls[1]["messages"] if message["role"] == "tool"]
    assert all("not an available read-only check" in text for text in refused)


def test_rounds_and_checks_are_capped_for_a_cpu_server(monkeypatch):
    many = [[call("ping_host", host=f"10.0.0.{n}"), call("dns_lookup", name=f"site{n}.com"), call("wifi_status")] for n in range(6)]
    brain = Brain(picks=many, answer={"plain_explanation": "done"})
    ran = device(monkeypatch, brain)
    asyncio.run(chat_agent.run_turn(turn_for("wifi keeps dropping")))
    assert len([item for item in brain.calls if item["tools"]]) == chat_agent.FAST_ROUNDS
    assert len(ran) <= chat_agent.TOOLS_PER_TURN

    brain = Brain(picks=[[call("ping_host", host=f"10.1.0.{n}")] for n in range(6)], answer={"plain_explanation": "done"})
    device(monkeypatch, brain)
    asyncio.run(chat_agent.run_turn(turn_for("wifi keeps dropping", think=True)))
    assert len([item for item in brain.calls if item["tools"]]) == chat_agent.DEEP_ROUNDS
    assert brain.calls[-1]["think"] is True


def test_a_general_question_needs_no_check_and_offers_no_fix(monkeypatch):
    brain = Brain(answer={"plain_explanation": "DNS turns names into addresses.", "fix": {"tool_id": "flush_dns", "args": {}}})
    ran = device(monkeypatch, brain)
    turn = turn_for("what is dns?")
    asyncio.run(chat_agent.run_turn(turn))
    assert ran == [] and turn["proposal"] is None  # no evidence: no fix card, whatever the model says
    assert "none: do not propose a fix" in brain.calls[-1]["messages"][-1]["content"]


def test_an_offline_device_gets_no_checks(monkeypatch):
    brain = Brain(answer={"plain_explanation": "The device is offline; from its last snapshot memory was high."})
    ran = device(monkeypatch, brain)
    turn = turn_for("why is my pc slow", target=OFFLINE)
    asyncio.run(chat_agent.run_turn(turn))
    assert ran == [] and not turn["can_check"] and all(not item["tools"] for item in brain.calls)
    assert turn["state"] == "done"


def test_a_fix_naming_a_process_the_checks_never_saw_is_dropped(monkeypatch):
    brain = Brain(picks=[[call("top_processes", sort_by="cpu")]], answer={"plain_explanation": "x", "fix": {"tool_id": "kill_process", "args": {"pid": 4242, "expected_name": "evil.exe"}}})
    device(monkeypatch, brain, {"top_processes": [{"pid": 10, "name": "chrome.exe", "cpu_percent": 90}]})
    turn = turn_for("my pc is slow")
    asyncio.run(chat_agent.run_turn(turn))
    assert turn["proposal"] is None


def _proposed(monkeypatch):
    brain = Brain(picks=[[call("check_internet")]], answer={"plain_explanation": "DNS fails", "fix": {"tool_id": "flush_dns", "args": {}}})
    ran = device(monkeypatch, brain, {"check_internet": DNS_FAIL})
    turn = turn_for("internet is not working")
    asyncio.run(chat_agent.run_turn(turn))
    assert turn["proposal"]
    return turn, ran


def test_an_approved_card_runs_once_is_recorded_and_checked_again(tmp_path, monkeypatch):
    turn, ran = _proposed(monkeypatch)
    proposal_id = turn["proposal"]["id"]
    ran.clear()

    async def approve_and_wait():
        view = await main.chat_approve(turn["turn_id"], {"proposal_id": proposal_id})
        assert view["proposal"]["state"] == "running"
        with pytest.raises(HTTPException) as again:
            await main.chat_approve(turn["turn_id"], {"proposal_id": proposal_id})
        assert again.value.status_code == 409  # one change at a time, and a card runs once
        await asyncio.gather(*list(main.background_tasks))

    asyncio.run(approve_and_wait())
    assert ran[0] == ("flush_dns", {}, "low")
    assert all(risk == "read" for _tool, _args, risk in ran[1:])  # the re-check only reads
    assert turn["proposal"]["state"] == "applied" and turn["proposal"]["verify"]["method"] in ("rules", "none")
    audit = session_store.list_audit()
    assert len(audit) == 1 and audit[0]["tool_id"] == "flush_dns" and audit[0]["approved_by"] == "operator"
    kinds = [json.loads(path.read_text(encoding="utf-8"))["kind"] for path in sorted((tmp_path / "decisions").rglob("*.json"))]
    assert {"chat_answer", "fix_approved", "fix_result"} <= set(kinds)
    assert "dev1" not in main.fixes_starting


def test_a_wrong_expired_or_rejected_card_never_runs(monkeypatch):
    turn, ran = _proposed(monkeypatch)
    ran.clear()
    with pytest.raises(LookupError):
        chat_agent.claim(turn["turn_id"], "guessed-id")
    chat_agent.reject(turn["turn_id"], turn["proposal"]["id"])
    with pytest.raises(ValueError, match="rejected"):
        chat_agent.claim(turn["turn_id"], turn["proposal"]["id"])

    turn, ran = _proposed(monkeypatch)
    ran.clear()
    turn["proposal"]["expires"] = 0
    with pytest.raises(ValueError, match="expired"):
        chat_agent.claim(turn["turn_id"], turn["proposal"]["id"])
    assert ran == []


def test_the_model_being_down_changes_nothing(monkeypatch):
    from backend.llm import LLMUnavailableError

    async def down(*args, **kwargs):
        raise LLMUnavailableError("Ollama is not running")

    ran = device(monkeypatch, down)
    turn = turn_for("internet is not working")
    asyncio.run(chat_agent.run_turn(turn))
    assert turn["state"] == "failed" and "Nothing was changed" in turn["error"] and ran == []


def test_greetings_are_answered_without_the_model(monkeypatch):
    monkeypatch.setattr(main, "_chat_device", lambda payload: ("local", None, {"source": "local", "status": "online"}))
    monkeypatch.setattr(main, "is_ai_available", lambda: True)
    view = asyncio.run(main.chat_start({"message": "hello", "device_id": "local"}))
    assert view["state"] == "done" and view["steps"] == [] and view["reply"]["plain_explanation"].startswith("Hello")
    with pytest.raises(HTTPException):
        asyncio.run(main.chat_start({"message": "   "}))


def test_startup_route_logging_handles_included_routers():
    """FastAPI 0.143 lists an included router (threat intelligence, security) without a .path; logging the routes
    at startup used to crash the whole app there."""
    lines = main.route_lines()
    assert any("/api/chat" in line for line in lines)
    assert len(lines) == len(main.app.routes)


def test_the_login_page(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("DASHBOARD_PASSWORD", "check-pass-123")
    client = TestClient(main.app)
    page = client.get("/login")
    assert page.status_code == 200 and "Authenticate &amp; Launch Console" in page.text
    assert "<h1>AIops</h1>" in page.text and "AI IT Troubleshooter" in page.text and "Remember session" not in page.text
    assert "cdn." not in page.text  # works on a LAN server without internet
    assert client.post("/login", data={"password": "wrong"}, follow_redirects=False).headers["location"] == "/login?error=1"
    signed_in = client.post("/login", data={"password": "check-pass-123"}, follow_redirects=False)
    assert signed_in.status_code == 303 and "Max-Age=2592000" in signed_in.headers["set-cookie"]
