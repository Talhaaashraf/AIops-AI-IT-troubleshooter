"""Diagnosis accuracy: which findings can explain a complaint, grounding, confidence, solutions, evidence, retries."""

import asyncio
import json

import pytest

from backend import decision_log, rules_engine, task_queue
from backend.agent_brain import findings, planner, session_store
from backend.agent_brain.eval_cases import CASES_BY_ID
from backend.agent_brain.executor import Target
from backend.agent_brain.playbooks import PLAYBOOKS, get_playbook, match_playbook, playbook_tips
from backend.learning import model_builder
from backend.learning import store as learning_store
from backend.llm import LLMDisconnectedError


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    for module in (session_store, task_queue, learning_store):
        monkeypatch.setattr(module, "DB_PATH", db)
    monkeypatch.setattr(model_builder, "LEARNED_DIR", tmp_path / "brain")
    monkeypatch.setattr(model_builder, "VERSION_FILE", tmp_path / "brain" / "version.json")
    monkeypatch.setattr(planner, "get_alerts", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner, "DISCONNECT_RETRY_SECONDS", 0)


class Scripted:
    """A model that answers from a list (a dict becomes its JSON; an exception is raised)."""

    name = "fake"

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def status(self):
        return {"available": True, "provider": "fake", "model": "fake"}

    def chat(self, messages, **kwargs):
        self.calls.append({"messages": messages, **kwargs})
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return {"content": json.dumps(reply) if isinstance(reply, dict) else reply, "tool_calls": [], "model": "fake-model", "thought": False}


def _diagnose(case_id, provider, mode="fast", monkeypatch=None):
    case = CASES_BY_ID[case_id]
    monkeypatch.setattr(planner, "get_provider", lambda: provider)
    session_id = session_store.create_session("dev1", "laptop", case["os_type"], case["issue"], None)
    target = Target("dev1", case["os_type"], "laptop")
    asyncio.run(planner._diagnose(session_store.get_session(session_id, include_steps=False), target, mode, preset_evidence=case["evidence"]))
    return session_store.get_session(session_id)["report"]


DISK_BLAMED = {"cause": "F2", "root_cause": "The C:\\ drive is 90.1% full, which can cause the system to hang.", "confidence": "high", "severity": "high",
               "solutions": [{"title": "Free up disk space", "why": "Disk is nearly full", "steps": ["Delete files"], "risk": "low", "tool_id": None},
                             {"title": "Restart the Windows Update service", "why": "x", "steps": [], "risk": "medium", "tool_id": None},
                             {"title": "Check for driver issues", "why": "x", "steps": [], "risk": "medium", "tool_id": None}]}


def test_a_full_disk_with_plenty_of_space_left_is_not_a_serious_problem():
    assert rules_engine.disk_space_severity(90.1, "23.3 GB") == "low"
    assert rules_engine.disk_space_severity(90.1, "6.1 GB") == "high"
    assert rules_engine.disk_space_severity(99.4, "1.5 GB") == "critical"
    assert rules_engine.disk_space_severity(60.0, "1.5 GB") is None  # below the warning level: not a disk problem
    assert rules_engine.disk_space_severity(92.0, None) == "high"  # size unknown: the percentage decides
    health = rules_engine.health_from_report({"disk": [{"usage_percent": 90.1, "free": "23.30 GB"}]})
    assert health["status"] == "ok"
    assert rules_engine.health_from_report({"disk": [{"usage_percent": 99.4, "free": "1.50 GB"}]})["status"] == "critical"


def test_memory_pressure_names_the_programs_and_suggests_what_to_close():
    found = findings.analyze(CASES_BY_ID["slow_memory_win"]["evidence"], "Windows")
    ram = next(item for item in found if item["key"] == "ram_high")
    assert "chrome.exe 16.2% in 4 processes" in ram["detail"] and "vmmemWSL 16.3% (WSL/Docker virtual machine)" in ram["detail"]
    titles = [tip["title"] for tip in ram["tips"]]
    assert titles[0] == "Close chrome.exe and msedge.exe" and "Shut down WSL/Docker when you do not need it" in titles
    assert ram["fixes"] == []  # nobody is offered a button to close the WSL/Docker VM
    disk = next(item for item in found if item["key"].startswith("disk_full"))
    assert disk["severity"] == "low"


def test_findings_are_split_into_possible_causes_and_separate_problems():
    found = findings.analyze(CASES_BY_ID["slow_memory_win"]["evidence"], "Windows")
    block = findings.findings_block(found, get_playbook("slow_pc"))
    assert block.index("Can explain the complaint:\n- F1 [high] Memory") < block.index("Separate problems") < block.index("F2 [low] Disk C:")
    internet = findings.analyze(CASES_BY_ID["internet_ok_win"]["evidence"], "Windows")
    related, other = findings.split_by_relevance(internet, get_playbook("no_internet"))
    assert related == [] and {item["key"] for item in other} >= {"ram_high"}


def test_a_finding_that_cannot_cause_the_complaint_is_replaced_by_one_that_can(monkeypatch):
    report = _diagnose("slow_memory_win", Scripted(DISK_BLAMED), monkeypatch=monkeypatch)
    assert report["root_cause"].startswith("Memory is 93.6% used.") and "Separate problem: Disk C:" in report["root_cause"]
    assert report["ai_root_cause"] == DISK_BLAMED["root_cause"] and report["cause_finding"] == "ram_high"
    assert report["confidence"] == "medium" and "overruled" in report["confidence_note"]
    assert report["ai_cause"] == "F2" and report["ai_confidence"] == "high"  # the model's own pick stays on record
    scopes = [item["scope"] for item in report["solutions"]]
    assert scopes[0] == "cause" and scopes.count("separate") <= 1 and scopes[-1] in ("separate", "cause")
    assert not any("Windows Update" in item["title"] for item in report["solutions"])  # written for the wrong cause


def test_a_correct_answer_keeps_its_words_and_high_confidence(monkeypatch):
    good = {"cause": "F1", "root_cause": "Memory is 93.6% used: WSL/Docker and Chrome hold most of it, so Windows swaps to disk.", "confidence": "high", "severity": "high",
            "solutions": [{"title": "Close Chrome tabs you do not need", "why": "Chrome holds 2.6 GB", "steps": ["Close tabs"], "risk": "low", "tool_id": None},
                          {"title": "Shut down WSL when not in use", "why": "vmmemWSL holds 2.6 GB", "steps": ["wsl --shutdown"], "risk": "low", "tool_id": None},
                          {"title": "Restart the laptop", "why": "Up 3 days", "steps": ["Restart"], "risk": "low", "tool_id": None}]}
    report = _diagnose("slow_memory_win", Scripted(good), monkeypatch=monkeypatch)
    assert report["root_cause"] == good["root_cause"] and report["confidence"] == "high" and "ai_root_cause" not in report
    assert report["solutions"][0]["title"] == "Close Chrome tabs you do not need"


def test_when_nothing_explains_the_complaint_confidence_is_low_and_no_fix_can_resolve_it(monkeypatch):
    nothing = {"cause": "none", "root_cause": "The checks did not show the slowness: memory, CPU and disk are normal.", "confidence": "medium", "severity": "low",
               "solutions": [{"title": "Note when it happens", "why": "x", "steps": [], "risk": "low", "tool_id": None}]}
    report = _diagnose("clean_checks_win", Scripted(nothing), monkeypatch=monkeypatch)
    assert report["confidence"] == "low" and report["complaint_reproduced"] is False
    assert 3 <= len(report["solutions"]) <= 4


def test_a_reply_cut_off_by_the_token_cap_keeps_its_complete_parts():
    raw, truncated = planner.parse_reply('{"cause": "F1", "root_cause": "Memory is full", "confidence": "high", "solutions": [{"title": "Close Chrome", "steps": []}, {"title": "Re')
    assert truncated is True and raw["root_cause"] == "Memory is full" and [item["title"] for item in raw["solutions"]] == ["Close Chrome"]
    assert planner.parse_reply('{"a": 1}') == ({"a": 1}, False) and planner.parse_reply("no json") == ({}, False)


def test_the_fast_prompt_is_short_and_names_what_matters(monkeypatch):
    provider = Scripted(DISK_BLAMED)
    _diagnose("slow_memory_win", provider, monkeypatch=monkeypatch)
    system, user = (message["content"] for message in provider.calls[0]["messages"])
    assert "Computer:" not in system and "Fix tools" not in system  # the same for every computer, so Ollama reuses its cached prompt
    assert len(user) < 4500
    assert "startup programs (7): GoogleDriveFS" in user and "chrome.exe 16.2% in 4 processes" in user and "Device: Windows 11" in user
    assert provider.calls[0]["think"] is False and provider.calls[0]["max_tokens"] == planner.REPORT_MAX_TOKENS


def test_a_dropped_connection_is_retried_once(monkeypatch):
    good = {**DISK_BLAMED, "cause": "F1", "root_cause": "Memory is 93.6% used."}
    report = _diagnose("slow_memory_win", Scripted(LLMDisconnectedError("Server disconnected"), good), monkeypatch=monkeypatch)
    assert report["ai"]["model"] == "fake-model" and not report["ai"].get("fallback")
    report = _diagnose("slow_memory_win", Scripted(LLMDisconnectedError("x"), LLMDisconnectedError("x")), monkeypatch=monkeypatch)
    assert report["ai"]["fallback"] is True and "dropped the connection" in report["root_cause"]
    record = [item for item in decision_log.recent(5) if item["kind"] == "diagnosis"][0]
    saved = json.loads((decision_log.decisions_dir() / record["file"]).read_text(encoding="utf-8"))
    assert "dropped the connection" in saved["ai"]["fallback_reason"] and saved["cause_finding"] == "ram_high"


def test_playbooks_match_whole_words_and_word_forms():
    assert match_playbook("Microsoft Teams crashes")["id"] == "crashes"  # not "mic"
    assert match_playbook("PowerPoint keeps freezing")["id"] == "slow_pc"  # not "power"; freezing = freeze
    assert match_playbook("wifi is slow")["id"] == "wifi_drops"  # the subject outweighs the symptom
    assert match_playbook("Internet is slow and websites take long to open")["id"] == "no_internet"
    assert match_playbook("Laptop is slow and programs take ages to open")["id"] == "slow_pc"  # not "ram" in "program"


def test_tips_use_the_tools_of_the_computers_own_system():
    windows_words = r"Task Manager|Windows Update|Device Manager|Start menu|Settings >"
    for playbook in PLAYBOOKS + [None]:
        for tip in playbook_tips(playbook, "Linux"):
            assert not __import__("re").search(windows_words, " ".join([tip["title"], *tip["steps"]])), (playbook and playbook["id"], tip["title"])
    slow_dns = [("check_internet", {}, {"ok": True, "data": {"dns_resolution": {"ok": True, "ms": 420}}})]
    assert playbook_tips(get_playbook("no_internet"), "Windows", slow_dns)[0]["title"] == "Use a faster DNS server"


def test_fix_tools_are_described_with_the_arguments_the_model_may_use():
    catalog = planner.fix_catalog("Windows")
    restart = next(line for line in catalog.splitlines() if line.startswith("- restart_service"))
    assert "Spooler" in restart and "(e.g" not in restart
    assert planner.first_sentence("Restart one service (e.g. Spooler). Then wait.") == "Restart one service (e.g. Spooler)"
    assert planner.fix_title("kill_process", {"pid": 812, "expected_name": "chrome.exe"}) == "Close chrome.exe (PID 812)"


def test_a_fix_may_only_name_a_process_the_checks_saw():
    evidence = [("top_processes", {"sort_by": "memory"}, {"ok": True, "data": [{"pid": 812, "name": "chrome.exe"}]})]
    known = planner.known_items(evidence)
    raw = [{"tool_id": "kill_process", "args": {"pid": 812, "expected_name": "chrome.exe"}},
           {"tool_id": "kill_process", "args": {"pid": 999, "expected_name": "chrome.exe"}}]
    assert [fix["args"]["pid"] for fix in planner.validate_fixes(raw, "Windows", known)] == [812]
    assert len(planner.validate_fixes(raw, "Windows")) == 2  # without evidence the old behaviour stays


def test_fixing_a_separate_problem_does_not_mark_the_complaint_resolved(monkeypatch):
    disk = {"key": "disk_full:C:\\", "severity": "low", "title": "Disk C:\\ is 90.1% full", "detail": "", "source": "system_overview",
            "fixes": [{"tool_id": "clear_temp_files", "args": {}, "why": "x"}]}
    session_id = session_store.create_session("dev1", "laptop", "Windows", "laptop is slow", None)
    report = planner.link_solutions(planner.normalize_report({"root_cause": "Memory", "solutions": [{"title": "Clear temp files", "tool_id": "clear_temp_files"}]}, "slow", "Windows"))
    report.update(quick_findings=[disk], other_findings=[disk["key"]], related_findings=["ram_high"])
    session_store.update_session(session_id, status="diagnosed", report=report)
    fix = report["proposed_fixes"][0]
    fix["result"] = {"ok": True, "summary": "Deleted 2 GB"}

    async def rerun(session_id, target, calls, kind="tool"):  # the disk finding is gone after the fix
        return [("system_overview", {}, {"ok": True, "summary": "", "data": {"disks": [{"mount": "C:\\", "used_percent": 80, "free": "45 GB"}]}})]

    async def no_steps(*args, **kwargs):
        return None

    monkeypatch.setattr(planner, "_run_parallel", rerun)
    monkeypatch.setattr(session_store, "get_session", lambda sid, include_steps=True, _real=session_store.get_session: {
        **_real(sid, include_steps=False), "steps": [{"kind": "tool", "tool_id": "system_overview", "args": {}}]})
    asyncio.run(planner._verify(session_store.get_session(session_id), Target("dev1", "Windows", "laptop"), report, fix))
    verify = planner.session_store.get_session.__defaults__[1](session_id, include_steps=False)["verify"]
    assert verify["resolved"] is None and "separate problem is fixed" in verify["explanation"]


def test_a_network_complaint_whose_checks_passed_blames_no_finding(monkeypatch):
    blamed = {**DISK_BLAMED, "cause": "F2"}
    report = _diagnose("internet_ok_win", Scripted(blamed), monkeypatch=monkeypatch)
    assert report["root_cause"].startswith("The network checks passed") and report["cause_finding"] is None
    assert report["solutions"][-1]["scope"] == "separate" and [item["scope"] for item in report["solutions"]].count("separate") == 1


def test_none_is_overruled_when_a_severe_finding_explains_the_complaint(monkeypatch):
    nothing = {"cause": "none", "root_cause": "The checks did not show the slowness.", "confidence": "low", "severity": "low", "solutions": []}
    report = _diagnose("slow_memory_win", Scripted(nothing), monkeypatch=monkeypatch)
    assert report["root_cause"].startswith("Memory is 93.6% used") and report.get("complaint_reproduced") is not False
    assert report["confidence"] == "low" and report["solutions"][0]["scope"] == "cause"  # the AI's own low confidence stays


def test_the_schema_only_lets_the_model_blame_a_finding_that_can_explain_the_complaint(monkeypatch):
    provider = Scripted(DISK_BLAMED)
    _diagnose("slow_memory_win", provider, monkeypatch=monkeypatch)
    assert provider.calls[0]["json_mode"]["properties"]["cause"]["enum"] == ["F1", "none"]  # F2, the disk, is a separate problem


def test_a_cause_found_by_the_deep_investigation_becomes_a_finding(monkeypatch):
    failing = {"ok": True, "summary": "SMART status: Failing", "data": [{"FriendlyName": "SSD", "HealthStatus": "Unhealthy"}]}

    async def execute(target, tool_id, args, max_risk, session_id=None):
        return {**failing, "tool_id": tool_id, "args": args} if tool_id == "disk_health" else {"ok": False, "summary": "n/a"}

    answer = {"cause": "F1", "root_cause": "The SSD reports failing health.", "confidence": "high", "severity": "critical", "solutions": []}
    provider = Scripted({"__tool": True}, "The disk is failing.", answer)
    original_chat = provider.chat

    def chat(messages, **kwargs):
        if kwargs.get("tools") and not provider.calls:
            provider.calls.append(kwargs)
            provider.replies.pop(0)
            return {"content": "", "tool_calls": [{"id": "1", "name": "disk_health", "arguments": {}}]}
        return original_chat(messages, **kwargs)

    provider.chat = chat
    monkeypatch.setattr(planner, "execute", execute)
    monkeypatch.setenv("AGENT_MAX_STEPS", "2")
    monkeypatch.setenv("DIAGNOSIS_THINKING", "false")
    report = _diagnose("clean_checks_win", provider, mode="deep", monkeypatch=monkeypatch)
    assert report["cause_finding"] == "disk_failing" and report.get("complaint_reproduced") is not False
    schema = provider.calls[-1]["json_mode"]
    assert "investigation" in schema["properties"]["cause"]["enum"]


def test_disk_alerts_keep_the_same_text_while_the_level_stays():
    first = rules_engine.evaluate_rules({"disk": [{"mountpoint": "C:\\", "usage_percent": 96.1, "free": "6.32 GB"}]})
    second = rules_engine.evaluate_rules({"disk": [{"mountpoint": "C:\\", "usage_percent": 96.2, "free": "6.31 GB"}]})
    assert [alert["description"] for alert in first] == [alert["description"] for alert in second] == ["C:\ is running low on space (less than 8 GB free)"]
    assert rules_engine.evaluate_rules({"disk": [{"mountpoint": "C:\\", "usage_percent": 90.1, "free": "23.3 GB"}]}) == []  # plenty left: no alert
    assert rules_engine.size_in_bytes("1.2.3 GB") is not None and rules_engine.disk_space_severity(90, "." ) == "high"


def test_slower_and_unknown_systems_are_handled():
    for issue in ("My PC runs slowly", "computer is slower than usual", "slowness everywhere"):
        assert match_playbook(issue)["id"] == "slow_pc", issue
    assert len(playbook_tips(get_playbook("slow_pc"), "Unknown")) >= 3
    found = findings.analyze(CASES_BY_ID["slow_memory_win"]["evidence"], "Unknown")
    assert "Activity Monitor" not in json.dumps(next(item for item in found if item["key"] == "ram_high")["tips"])


def test_the_models_finding_labels_never_reach_the_person():
    assert planner.without_finding_ids("F2 [high] 30% packet loss to the router: the network is unreliable.") == "30% packet loss to the router: the network is unreliable."
    assert planner.without_finding_ids("The print spooler is stopped (F1), and 2 jobs are stuck (see F3).") == "The print spooler is stopped, and 2 jobs are stuck."
    assert planner.without_finding_ids("Memory (F1 and F2) is full") == "Memory is full"
    assert planner.without_finding_ids("Fix the FAT32 drive") == "Fix the FAT32 drive"  # only the labels go
