import asyncio
import json
import pathlib

import pytest

from backend import decision_log
from backend.agent_brain import planner, session_store
from backend.agent_brain.playbooks import get_playbook
from backend.llm import ollama_provider

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(session_store, "DB_PATH", tmp_path / "test.db")


def test_solutions_keep_only_real_tools_and_cap_at_four():
    raw = [
        {"title": "Flush the DNS cache", "why": "Clears stale entries", "steps": "1. Open a terminal\n2. Run the flush", "tool_id": "flush_dns", "args": {}},
        {"title": "Restart the router", "why": "Clears its cache", "steps": ["Unplug it", "Wait 30 s"], "tool_id": "reboot_router_now"},
        {"title": "Change DNS servers", "tool_id": None},
        "Try another network",
        {"title": "Fifth idea", "tool_id": None},
    ]
    solutions = planner.normalize_solutions(raw, "Windows")
    assert [item["title"] for item in solutions] == ["Flush the DNS cache", "Restart the router", "Change DNS servers", "Try another network"]
    assert solutions[0]["tool_id"] == "flush_dns" and solutions[0]["risk"] == "low" and solutions[0]["steps"] == ["Open a terminal", "Run the flush"]
    # A tool the registry does not know stays a manual suggestion.
    assert solutions[1]["tool_id"] is None and solutions[1]["steps"] == ["Unplug it", "Wait 30 s"]


def test_report_is_topped_up_to_three_and_linked_to_runnable_fixes():
    report = planner.normalize_report({"root_cause": "DNS cache is stale", "confidence": "high", "solutions": [
        {"title": "Flush the DNS cache", "tool_id": "flush_dns"}]}, "websites do not open", "Windows")
    report["proposed_fixes"] = [fix for fix in report["proposed_fixes"]]
    planner.link_solutions(planner.complete_solutions(report, get_playbook("no_internet")))
    solutions = report["solutions"]
    assert len(solutions) == 3
    assert solutions[0]["tool_id"] == "flush_dns" and report["proposed_fixes"][solutions[0]["fix_index"]]["tool_id"] == "flush_dns"
    assert all(item["tool_id"] is None and item["fix_index"] is None for item in solutions[1:])
    assert {item["source"] for item in solutions[1:]} == {"playbook"}


def test_a_filtered_out_fix_turns_its_solution_manual():
    report = planner.normalize_report({"root_cause": "x", "solutions": [{"title": "Flush DNS", "tool_id": "flush_dns"}]}, "x", "Windows")
    report["proposed_fixes"] = []  # e.g. removed by ground_fixes
    planner.link_solutions(report)
    assert report["solutions"][0]["tool_id"] is None and report["solutions"][0]["fix_index"] is None


def test_no_code_path_applies_a_fix_without_a_person():
    """apply_fix is reached only from the approval endpoint (through its wrapper), and the auto-fix setting is gone."""
    import ast

    sources = {path: path.read_text(encoding="utf-8") for path in (ROOT / "backend").rglob("*.py")}

    def callers_of(name):
        found = set()
        for path, text in sources.items():
            for function in ast.walk(ast.parse(text)):
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                        isinstance(call, ast.Call) and getattr(call.func, "id", None) == name for call in ast.walk(function)):
                    found.add(f"{path.name}:{function.name}")
        return found

    assert callers_of("apply_fix") == {"main.py:_apply_approved_fix"}
    assert callers_of("_apply_approved_fix") == {"main.py:troubleshoot_apply_fix"}
    assert not any("AUTO_FIX_MAX_RISK" in text or "_auto_fix" in text for text in sources.values())


def test_decisions_are_saved_as_json_and_indexed(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISIONS_DIR", str(tmp_path / "decisions"))
    path = decision_log.record("diagnosis", "abc123", {"device": "laptop", "root_cause": "Disk is full", "approved_by": None})
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    assert data["kind"] == "diagnosis" and data["root_cause"] == "Disk is full"
    index = (pathlib.Path(path).parent / "index.md").read_text(encoding="utf-8")
    assert "**diagnosis** laptop - Disk is full" in index
    assert decision_log.recent(5)[0]["summary"] == "Disk is full"
    with pytest.raises(ValueError):
        decision_log.record("not-a-kind", "x", {})


def test_rejecting_a_solution_is_recorded_and_runs_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISIONS_DIR", str(tmp_path / "decisions"))
    session_id = session_store.create_session("local", "box", "Windows", "slow", None)
    report = planner.normalize_report({"root_cause": "x", "solutions": [{"title": "Restart the computer"}]}, "slow", "Windows")
    session_store.update_session(session_id, status="diagnosed", report=report)

    solution = asyncio.run(planner.decide_solution(session_id, 0, "rejected"))

    assert solution["status"] == "rejected"
    assert session_store.get_session(session_id)["report"]["solutions"][0]["status"] == "rejected"
    assert decision_log.recent(1)[0]["kind"] == "fix_rejected"
    with pytest.raises(ValueError):
        asyncio.run(planner.decide_solution(session_id, 0, "apply"))


def test_streamed_reply_forwards_thinking_and_returns_the_answer(monkeypatch):
    lines = [json.dumps({"message": {"thinking": "Disk is "}}), json.dumps({"message": {"thinking": "full."}}),
             json.dumps({"message": {"content": '{"ok": true}'}}), json.dumps({"done": True, "eval_count": 9})]

    class FakeStream:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def iter_lines(self):
            return iter(lines)

    monkeypatch.setattr(ollama_provider.httpx, "stream", lambda *args, **kwargs: FakeStream())
    provider = ollama_provider.OllamaProvider()
    provider._status, provider._status_at = {"model": "qwen3:4b"}, float("inf")
    provider._capabilities["qwen3:4b"] = {"thinking"}
    pieces = []

    result = provider.chat([{"role": "user", "content": "hi"}], json_mode=True, think=True, on_delta=lambda kind, text: pieces.append((kind, text)))

    assert result["content"] == '{"ok": true}' and result["thinking"] == "Disk is full." and result["thought"] is True
    assert pieces == [("thinking", "Disk is "), ("thinking", "full."), ("content", '{"ok": true}')]


def test_reasoning_that_used_the_whole_budget_is_written_up_by_a_second_call(monkeypatch):
    calls = []

    class ThinkingProvider:
        name = "fake"

        def status(self):
            return {"available": True, "model": "fake"}

        def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None, timeout=None, think=None, on_delta=None):
            calls.append({"think": think, "last": messages[-1]["content"][:22]})
            if think:  # thinking used the whole budget: no JSON written
                return {"content": "", "tool_calls": [], "thinking": "The disk is nearly full, so suggest cleanup.", "model": "fake", "thought": True}
            return {"content": json.dumps({"root_cause": "Disk C: is almost full", "confidence": "high", "severity": "high",
                                           "solutions": [{"title": "Clear temp files", "tool_id": "clear_temp_files"}]}), "tool_calls": []}

    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        data = {"cpu_percent": 10, "ram_percent": 40, "disks": [{"mount": "C:\\", "used_percent": 97.0, "free": "2 GB", "total": "256 GB"}]}
        return {"tool_id": tool_id, "ok": True, "summary": f"{tool_id} ran", "data": data if tool_id == "system_overview" else {}}

    provider = ThinkingProvider()
    monkeypatch.setattr(planner, "get_provider", lambda: provider)
    monkeypatch.setattr(planner, "execute", fake_execute)
    monkeypatch.setattr(planner, "get_alerts", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner.learning_store, "find_similar", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner.learning_store, "learned_fixes_for", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner, "learn_from", lambda session_id: asyncio.sleep(0))
    monkeypatch.setenv("DIAGNOSIS_THINKING", "true")
    session_id = session_store.create_session("local", "box", "Windows", "my disk is full", None)

    asyncio.run(planner.run_diagnosis(session_id, mode="fast"))

    report = session_store.get_session(session_id)["report"]
    assert report["root_cause"] == "Disk C: is almost full"
    assert [call["think"] for call in calls] == [True, False] and calls[1]["last"].startswith("Your reasoning so far")
    assert report["ai"]["thinking"] is True and "nearly full" in report["reasoning"]
    assert report["solutions"][0]["tool_id"] == "clear_temp_files" and 3 <= len(report["solutions"]) <= 4


def test_grounding_uses_the_traffic_tests_even_when_an_old_agent_writes_a_wrong_summary():
    report = {"root_cause": "Memory is 91.8% used", "confidence": "high"}
    found = [{"key": "ram_high", "title": "Memory is 91.8% used"}]
    stages = {"dns_resolution": {"ok": True}, "tcp_to_internet": {"ok": True}, "http": {"ok": True}}
    evidence = [("check_internet", {}, {"ok": True, "summary": "Adapter has a self-assigned 169.254.x.x address: DHCP failed", "data": stages})]
    grounded = planner.ground_root_cause(dict(report), get_playbook("no_internet"), found, evidence)
    assert grounded["root_cause"].startswith("The network checks passed (DNS, TCP and HTTP tests to the internet all succeeded)")
    assert grounded["confidence"] == "low"


def _diagnosed_session(report_raw):
    session_id = session_store.create_session("local", "box", "Windows", "websites do not open", None)
    report = planner.link_solutions(planner.normalize_report(report_raw, "websites do not open", "Windows"))
    session_store.update_session(session_id, status="diagnosed", report=report)
    return session_id, report


def test_a_rejected_solution_cannot_be_run_and_a_running_one_cannot_be_rejected(tmp_path, monkeypatch):
    session_id, report = _diagnosed_session({"root_cause": "DNS", "solutions": [{"title": "Flush DNS", "tool_id": "flush_dns"}]})
    asyncio.run(planner.decide_solution(session_id, 0, "rejected"))
    with pytest.raises(ValueError, match="rejected"):
        asyncio.run(planner.apply_fix(session_id, report["solutions"][0]["fix_index"]))

    session_id, report = _diagnosed_session({"root_cause": "DNS", "solutions": [{"title": "Flush DNS", "tool_id": "flush_dns"}]})
    report["solutions"][0]["status"] = "applied"
    session_store.update_session(session_id, report=report)
    with pytest.raises(ValueError, match="already applied"):
        asyncio.run(planner.decide_solution(session_id, 0, "rejected"))


def test_a_manual_solution_naming_a_fix_tool_becomes_runnable_once():
    solutions = planner.normalize_solutions([
        {"title": "Flush the DNS cache", "steps": ["Run ipconfig /flushdns"], "tool_id": None},
        {"title": "Clear DNS cache again", "tool_id": "flush_dns"},
    ], "Windows")
    assert solutions[0]["tool_id"] == "flush_dns" and len([item for item in solutions if item["tool_id"] == "flush_dns"]) == 1


def test_a_fix_cannot_resolve_a_problem_that_never_showed_up(monkeypatch):
    session_id, report = _diagnosed_session({"root_cause": "x", "solutions": [{"title": "Flush DNS", "tool_id": "flush_dns"}]})
    report["complaint_reproduced"] = False
    fix = report["proposed_fixes"][0]
    fix["result"] = {"ok": True, "summary": "DNS cache flushed"}

    async def fake_parallel(*args, **kwargs):
        return []

    async def fake_chat(*args, **kwargs):
        return {"content": json.dumps({"resolved": True, "explanation": "Websites work now."})}

    monkeypatch.setattr(planner, "_run_parallel", fake_parallel)
    monkeypatch.setattr(planner, "_chat", fake_chat)
    session = session_store.get_session(session_id, include_steps=False)
    from backend.agent_brain.executor import Target
    asyncio.run(planner._verify(session, Target("local", "Windows", "box"), report, fix))

    verify = session_store.get_session(session_id)["verify"]
    assert verify["resolved"] is None and "cannot confirm" in verify["explanation"]


def test_devices_cannot_choose_route_like_ids_or_markup_names(tmp_path, monkeypatch):
    from backend import device_store

    monkeypatch.setattr(device_store, "DB_PATH", tmp_path / "devices.db")
    device = device_store.register_device("z" * 43, "<img src=x onerror=alert(1)>", "Windows", device_id="report1", allow_open=True)
    assert device["device_id"].startswith("agent-") and device["device_id"] != "report1"
    assert "<" not in device["hostname"] and ">" not in device["hostname"]


def test_only_person_triggered_code_can_change_a_device():
    """Every call that may change a device (risk above "read") sits in a function reached only from an
    approval endpoint: apply_fix (Approve & run), the Software tab's uninstall/update/leftover endpoints and the
    Performance tab's Install OS updates."""
    import ast

    # Position of max_risk in each call, and its default when left out. A risk that is not the literal "read"
    # (another literal, or a variable) counts as a call that may change the device.
    risk_argument = {"execute": (3, None), "_run_step": (4, "read"), "_start_software_job": (5, None), "run_tool": (2, "read")}
    risky_callers = set()
    for path in (ROOT / "backend").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for call in ast.walk(function):
                if not isinstance(call, ast.Call):
                    continue
                args = call.args
                wrapper = getattr(call.func, "attr", None) or getattr(call.func, "id", None)
                if wrapper in ("to_thread", "run_ai", "run_monitor") and args and isinstance(args[0], ast.Name):
                    name, args = args[0].id, args[1:]  # asyncio.to_thread(run_tool, ...), run_ai(...) from backend/workers.py
                else:
                    name = call.func.id if isinstance(call.func, ast.Name) else None  # connection.execute(sql) is not ours
                if name not in risk_argument:
                    continue
                position, default = risk_argument[name]
                node = args[position] if len(args) > position else next((kw.value for kw in call.keywords if kw.arg == "max_risk"), None)
                risk = default if node is None else node.value if isinstance(node, ast.Constant) else "<variable>"
                if risk != "read":
                    risky_callers.add(f"{path.name}:{function.name}")
    # Plumbing that passes a caller's risk through: execute (runs the tool), _run_step (session step around
    # execute) and _run_software_job (job around execute). Everything else here is an endpoint a person clicks.
    plumbing = {"executor.py:execute", "planner.py:_run_step", "main.py:_run_software_job"}
    # Adding a device-changing path must be a deliberate change to this list.
    assert risky_callers == plumbing | {"planner.py:apply_fix", "main.py:uninstall_device_software", "main.py:update_device_software",
                                        "main.py:quarantine_device_leftovers", "main.py:restore_device_quarantine", "main.py:install_device_os_updates"}


def test_a_failed_fix_is_recorded(tmp_path, monkeypatch):
    monkeypatch.setenv("DECISIONS_DIR", str(tmp_path / "decisions"))
    session_id, report = _diagnosed_session({"root_cause": "DNS", "solutions": [{"title": "Flush DNS", "tool_id": "flush_dns"}]})

    async def failing_step(*args, **kwargs):
        return {"ok": False, "summary": "Access denied"}

    monkeypatch.setattr(planner, "_run_step", failing_step)
    monkeypatch.setattr(planner, "learn_from", lambda session_id: asyncio.sleep(0))
    fix = asyncio.run(planner.apply_fix(session_id, 0))

    assert fix["status"] == "failed"
    kinds = [item["kind"] for item in decision_log.recent(5)]
    assert kinds[:2] == ["fix_result", "fix_approved"]


def test_stream_deadline_returns_the_partial_reasoning(monkeypatch):
    lines = [json.dumps({"message": {"thinking": "Disk is nearly full"}}), json.dumps({"message": {"thinking": " so..."}})]

    class SlowStream:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def iter_lines(self):
            return iter(lines)

    clock = iter([0.0, 1.0, 999.0, 999.0])
    monkeypatch.setattr(ollama_provider.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(ollama_provider.httpx, "stream", lambda *args, **kwargs: SlowStream())
    provider = ollama_provider.OllamaProvider()
    status, error, payload = provider._stream({"model": "x"}, 10, lambda kind, text: None)

    assert status == 200 and payload["done_reason"] == "deadline" and payload["message"]["thinking"] == "Disk is nearly full"
