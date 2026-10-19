import asyncio
import json

import pytest

from backend import task_queue
from backend.agent_brain import planner, session_store
from backend.learning import model_builder
from backend.learning import store as learning_store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    monkeypatch.setattr(session_store, "DB_PATH", db)
    monkeypatch.setattr(task_queue, "DB_PATH", db)
    monkeypatch.setattr(learning_store, "DB_PATH", db)
    monkeypatch.setattr(model_builder, "LEARNED_DIR", tmp_path / "sentinel-tech")
    monkeypatch.setattr(model_builder, "VERSION_FILE", tmp_path / "sentinel-tech" / "version.json")
    monkeypatch.setattr(planner, "get_alerts", lambda *args, **kwargs: [])
    yield db


class FakeProvider:
    """Scripted LLM: one tool call, then a plain-text finding, then the JSON report."""

    name = "fake"

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def status(self):
        return {"available": True, "provider": "fake", "model": "fake"}

    def is_available(self):
        return True

    def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None, timeout=None, think=None, on_delta=None):
        self.calls.append({"tools": [tool["function"]["name"] for tool in tools or []], "json_mode": json_mode})
        return self.replies.pop(0)


def fake_execute(log):
    async def execute(target, tool_id, args, max_risk, session_id=None):
        log.append((tool_id, args, max_risk))
        return {"tool_id": tool_id, "args": args, "ok": True, "summary": f"{tool_id} ran", "data": {"value": 1}}
    return execute


def test_full_session_diagnose_fix_and_verify(monkeypatch):
    report = {
        "issue_summary": "Internet is slow",
        "root_cause": "Stale DNS cache",
        "confidence": "high",
        "severity": "medium",
        "evidence": ["DNS lookup took 900 ms"],
        "proposed_fixes": [
            {"tool_id": "flush_dns", "args": {}, "why": "clears stale entries"},
            {"tool_id": "format_disk", "args": {}, "why": "hallucinated tool"},
            {"tool_id": "system_overview", "args": {}, "why": "read tool is not a fix"},
            {"tool_id": "kill_process", "args": {"pid": "oops"}, "why": "bad args"},
        ],
        "manual_steps": ["Restart the router if it persists"],
    }
    provider = FakeProvider([
        {"content": "", "tool_calls": [{"id": "1", "name": "dns_lookup", "arguments": {"hostname": "example.com"}}, {"id": "2", "name": "flush_dns", "arguments": {}}]},
        {"content": "DNS is slow.", "tool_calls": []},
        {"content": json.dumps(report), "tool_calls": []},
        {"content": json.dumps({"resolved": True, "explanation": "DNS is fast now", "next_steps": []}), "tool_calls": []},
    ])
    log = []
    monkeypatch.setattr(planner, "get_provider", lambda: provider)
    monkeypatch.setattr(planner, "execute", fake_execute(log))

    session_id = session_store.create_session("local", "test box", "Windows", "internet slow", None)
    asyncio.run(planner.run_diagnosis(session_id, mode="deep"))

    session = session_store.get_session(session_id)
    assert session["status"] == "diagnosed"
    fixes = session["report"]["proposed_fixes"]
    assert [fix["tool_id"] for fix in fixes] == ["flush_dns"]
    # Investigation only ever offers read-only tools, and the model's attempt to call a fix tool was not executed.
    assert "flush_dns" not in provider.calls[0]["tools"]
    assert all(max_risk == "read" for _, _, max_risk in log)
    assert ("flush_dns", {}, "read") not in log
    assert any(tool_id == "dns_lookup" for tool_id, _, _ in log)

    asyncio.run(planner.apply_fix(session_id, 0))
    session = session_store.get_session(session_id)
    assert session["status"] == "resolved"
    assert session["report"]["proposed_fixes"][0]["status"] == "applied"
    assert ("flush_dns", {}, "high") in log
    audit = session_store.list_audit()
    assert audit[0]["tool_id"] == "flush_dns" and audit[0]["approved_by"] == "operator"


def test_inline_tool_calls_are_parsed():
    calls = planner.parse_inline_tool_calls('<tool_call>{"name": "check_internet", "arguments": {}}</tool_call> and {"name": "evil"}', {"check_internet"})
    assert [call["name"] for call in calls] == ["check_internet"]


def test_task_queue_lifecycle():
    task_id = task_queue.enqueue_task("dev-1", "flush_dns", {}, "high", 60, "s1")
    assert task_queue.claim_next_task("dev-2") is None
    task = task_queue.claim_next_task("dev-1")
    assert task["task_id"] == task_id and task["status"] == "running"
    assert task_queue.claim_next_task("dev-1") is None
    assert task_queue.complete_task(task_id, "dev-2", {"ok": True}) is False
    assert task_queue.complete_task(task_id, "dev-1", {"ok": True, "summary": "done"}) is True
    assert task_queue.get_task(task_id)["status"] == "done"


def test_manual_steps_that_a_tool_can_do_become_fixes():
    report = planner.normalize_report({"manual_steps": ["Open Command Prompt as Administrator and run: ipconfig /flushdns", "Restart your router"]}, "dns", "Windows")
    assert [fix["tool_id"] for fix in report["proposed_fixes"]] == ["flush_dns"]
    assert report["manual_steps"] == ["Restart your router"]
    linux = planner.normalize_report({"manual_steps": ["Run sfc /scannow"]}, "x", "Linux")
    assert linux["proposed_fixes"] == [] and linux["manual_steps"] == ["Run sfc /scannow"]


def _resolved_case(session_id, issue, cause, tool_id="flush_dns", outcome_resolved=True):
    session = {
        "session_id": session_id, "device_id": "local", "os_type": "Windows", "issue": issue, "playbook_id": None,
        "report": {"root_cause": cause, "evidence": ["dns slow"], "proposed_fixes": [{"tool_id": tool_id, "args": {}, "status": "applied", "result": {"ok": True}}]},
        "verify": {"resolved": outcome_resolved},
    }
    return learning_store.record_session(session)


def test_learning_memory_recalls_similar_cases_and_successful_fixes():
    _resolved_case("a", "Websites not opening, DNS broken", "Stale DNS cache")
    _resolved_case("b", "Some websites do not open in Chrome", "Stale DNS cache")
    _resolved_case("c", "Printer stuck with jobs", "Stuck spooler", tool_id="clear_print_queue")
    similar = learning_store.find_similar("websites are not opening", "Windows")
    assert similar and similar[0]["session_id"] in ("a", "b")
    learned = learning_store.learned_fixes_for("websites are not opening", "Windows")
    assert [item["tool_id"] for item in learned] == ["flush_dns"]
    report = planner.add_learned_fixes({"proposed_fixes": []}, learned, "Windows")
    assert report["proposed_fixes"][0]["learned"] is True


def test_operator_feedback_overrides_the_agent():
    _resolved_case("d", "Slow internet", "Wrong cause")
    learning_store.set_feedback("d", helpful=False)
    assert not learning_store.is_trusted(learning_store.get_case("d"))
    learning_store.set_feedback("d", helpful=False, corrected_root_cause="ISP outage")
    case = learning_store.get_case("d")
    assert learning_store.is_trusted(case) and case["effective_root_cause"] == "ISP outage"


def test_model_builder_writes_modelfile_and_dataset(monkeypatch):
    calls = []

    class Response:
        def raise_for_status(self):
            pass

    monkeypatch.setattr(model_builder.httpx, "post", lambda url, json, timeout: calls.append(json) or Response())
    for index in range(3):
        _resolved_case(f"m{index}", f"Websites not opening {index}", "Stale DNS cache")
    info = model_builder.maybe_rebuild()
    assert info and info["version"] == 1 and info["created_in_ollama"] is True
    modelfile = (model_builder.LEARNED_DIR / "Modelfile").read_text(encoding="utf-8")
    assert "FROM " in modelfile and "Stale DNS cache" in modelfile and "MESSAGE assistant" in modelfile
    assert len((model_builder.LEARNED_DIR / "training_data.jsonl").read_text(encoding="utf-8").splitlines()) == 3
    assert calls[0]["model"] == model_builder.learned_model_name() and calls[0]["messages"]
    assert model_builder.maybe_rebuild() is None


def test_unrelated_fixes_are_dropped_for_a_playbook():
    from backend.agent_brain.playbooks import filter_relevant_fixes, get_playbook
    fixes = [{"tool_id": "clear_temp_files"}, {"tool_id": "renew_ip"}, {"tool_id": "sync_time", "learned": True}]
    kept = filter_relevant_fixes(fixes, get_playbook("disk_full"))
    assert [fix["tool_id"] for fix in kept] == ["clear_temp_files", "sync_time"]
    assert filter_relevant_fixes(fixes, None) == fixes
