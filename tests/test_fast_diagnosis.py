"""Speed paths: parallel baseline, instant findings, fast/instant modes, rule verification, task wake-ups."""

import asyncio
import json
import time

import pytest

from backend import task_queue, task_signals
from backend.agent_brain import executor, findings, planner, session_store
from backend.agent_brain.playbooks import baseline_phases, get_playbook, match_playbook
from backend.learning import model_builder
from backend.learning import store as learning_store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    for module in (session_store, task_queue, learning_store):
        monkeypatch.setattr(module, "DB_PATH", db)
    monkeypatch.setattr(model_builder, "LEARNED_DIR", tmp_path / "sentinel-tech")
    monkeypatch.setattr(model_builder, "VERSION_FILE", tmp_path / "sentinel-tech" / "version.json")
    monkeypatch.setattr(planner, "get_alerts", lambda *args, **kwargs: [])


class Provider:
    name = "fake"

    def __init__(self, replies=(), available=True):
        self.replies, self.available, self.calls = list(replies), available, []

    def status(self):
        return {"available": self.available, "provider": "fake", "model": "fake", "message": "fake is down"}

    def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None, timeout=None, think=None, on_delta=None):
        self.calls.append({"tools": bool(tools), "json_mode": json_mode, "max_tokens": max_tokens})
        return self.replies.pop(0)


FULL_DISK = {"cpu_percent": 10, "ram_percent": 40, "disks": [{"mount": "C:\\", "used_percent": 97.0, "free": "2.0 GB", "total": "256 GB"}], "uptime": "1 day, 2:00:00"}
HEALTHY_DISK = {**FULL_DISK, "disks": [{"mount": "C:\\", "used_percent": 60.0, "free": "100 GB", "total": "256 GB"}]}


def scripted_execute(log, data_for, delay=0.2):
    async def execute(target, tool_id, args, max_risk, session_id=None):
        log.append((tool_id, args, max_risk, time.perf_counter()))
        await asyncio.sleep(delay)
        return {"tool_id": tool_id, "args": args, "ok": True, "summary": f"{tool_id} ran", "data": data_for(tool_id)}
    return execute


def test_fast_mode_runs_the_baseline_in_parallel_and_calls_the_llm_once(monkeypatch):
    report = {"root_cause": "Disk C: is almost full", "confidence": "high", "severity": "high", "evidence": ["97% used"], "proposed_fixes": [], "manual_steps": []}
    provider = Provider([{"content": json.dumps(report), "tool_calls": []}])
    log = []
    monkeypatch.setattr(planner, "get_provider", lambda: provider)
    monkeypatch.setattr(planner, "execute", scripted_execute(log, lambda tool_id: FULL_DISK if tool_id == "system_overview" else {}))

    session_id = session_store.create_session("local", "box", "Windows", "my disk is full", None)
    started = time.perf_counter()
    asyncio.run(planner.run_diagnosis(session_id, mode="fast"))
    elapsed = time.perf_counter() - started

    session = session_store.get_session(session_id)
    assert session["status"] == "diagnosed"
    # One report call, no investigation round, output capped.
    # Diagnoses think deeply by default, so the report gets the larger cap (thinking tokens count toward it).
    expected_cap = planner.REPORT_THINKING_MAX_TOKENS if planner.diagnosis_thinking() else planner.REPORT_MAX_TOKENS
    assert provider.calls == [{"tools": False, "json_mode": True, "max_tokens": expected_cap}]
    # disk_full playbook: system_overview, then cleanup_candidates: 2 phases of 0.2 s, not one per tool.
    assert [entry[0] for entry in log] == ["system_overview", "cleanup_candidates"]
    assert elapsed < 1.5
    report = session["report"]
    assert report["mode"] == "fast" and report["timing"]["total_seconds"] >= 0
    assert report["quick_findings"][0]["key"] == "disk_full:C:\\"
    # The rule finding adds its one-click fixes even though the model proposed none.
    assert {fix["tool_id"] for fix in report["proposed_fixes"]} >= {"clear_temp_files"}
    assert any(step["kind"] == "findings" for step in session["steps"])


def test_parallel_phase_runs_tools_concurrently(monkeypatch):
    log = []
    monkeypatch.setattr(planner, "execute", scripted_execute(log, lambda tool_id: {}, delay=0.3))
    session_id = session_store.create_session("local", "box", "Windows", "check-up", None)
    target = executor.Target("local", "Windows", "box")
    started = time.perf_counter()
    evidence = asyncio.run(planner.collect_baseline(session_id, target, get_playbook("full_checkup")))
    elapsed = time.perf_counter() - started
    assert len(evidence) == 9
    assert elapsed < 1.8  # sequential would be 9 x 0.3 s = 2.7 s; the margin is for a busy laptop


def test_instant_mode_needs_no_llm_and_verifies_fixes_by_rules(monkeypatch):
    provider = Provider()
    log, state = [], {"disk": FULL_DISK}
    monkeypatch.setattr(planner, "get_provider", lambda: provider)
    monkeypatch.setattr(planner, "execute", scripted_execute(log, lambda tool_id: state["disk"] if tool_id == "system_overview" else {}, delay=0))

    session_id = session_store.create_session("local", "box", "Windows", "disk full", None)
    asyncio.run(planner.run_diagnosis(session_id, mode="instant"))
    session = session_store.get_session(session_id)
    report = session["report"]
    assert provider.calls == []
    assert report["severity"] == "critical" and "97.0% full" in report["root_cause"]
    index = next(i for i, fix in enumerate(report["proposed_fixes"]) if fix["tool_id"] == "clear_temp_files")
    assert report["proposed_fixes"][index]["rule"] is True

    state["disk"] = HEALTHY_DISK
    asyncio.run(planner.apply_fix(session_id, index))
    session = session_store.get_session(session_id)
    assert session["status"] == "resolved"
    assert session["verify"]["method"] == "rules"
    assert provider.calls == []


def test_unavailable_ai_falls_back_to_the_rule_based_diagnosis(monkeypatch):
    provider = Provider(available=False)
    monkeypatch.setattr(planner, "get_provider", lambda: provider)
    monkeypatch.setattr(planner, "execute", scripted_execute([], lambda tool_id: FULL_DISK if tool_id == "system_overview" else {}, delay=0))
    session_id = session_store.create_session("local", "box", "Windows", "disk full", None)
    asyncio.run(planner.run_diagnosis(session_id, mode="fast"))
    session = session_store.get_session(session_id)
    assert session["status"] == "diagnosed"
    assert session["report"]["mode"] == "instant"
    assert "AI unavailable" in session["report"]["root_cause"]


def test_slow_llm_report_falls_back_to_rules(monkeypatch):
    class Timeout(Provider):
        def chat(self, *args, **kwargs):
            raise planner.LLMUnavailableError("Ollama did not answer within 600s")

    monkeypatch.setattr(planner, "get_provider", lambda: Timeout())
    monkeypatch.setattr(planner, "execute", scripted_execute([], lambda tool_id: FULL_DISK if tool_id == "system_overview" else {}, delay=0))
    session_id = session_store.create_session("local", "box", "Windows", "disk full", None)
    asyncio.run(planner.run_diagnosis(session_id, mode="fast"))
    session = session_store.get_session(session_id)
    assert session["status"] == "diagnosed"
    assert "did not answer" in session["report"]["root_cause"]


def test_findings_rules():
    internet = findings.analyze([("check_internet", {}, {"ok": True, "summary": "", "data": {
        "adapters_with_ip": [{"name": "wifi"}], "default_gateway": "192.168.1.1", "gateway_ping": {"reachable": True},
        "tcp_to_internet": {"ok": True, "ms": 20}, "dns_resolution": {"ok": False}, "http": {"ok": False}}})], "Windows")
    assert internet[0]["key"] == "net_dns" and internet[0]["fixes"][0]["tool_id"] == "flush_dns"

    processes = findings.analyze([("top_processes", {"sort_by": "cpu"}, {"ok": True, "summary": "", "data": [
        {"pid": 4, "name": "System", "cpu_percent": 90}, {"pid": 800, "name": "chrome.exe", "cpu_percent": 55, "memory": "1 GB"}]})], "Windows")
    by_name = {item["title"].split()[0]: item for item in processes}
    assert by_name["System"]["fixes"] == []  # protected processes are never offered for killing
    assert by_name["chrome.exe"]["fixes"][0]["args"] == {"pid": 800, "expected_name": "chrome.exe"}
    assert planner.validate_fixes(by_name["chrome.exe"]["fixes"], "Windows")[0]["tool_id"] == "kill_process"

    hardware = findings.analyze([("hardware_health", {}, {"ok": True, "summary": "", "data": {
        "max_temperature_c": 97, "throttling_suspected": True, "cpu": {"performance_percent": 40},
        "gpus": [{"name": "GPU", "ok": False}], "problem_devices": [{"name": "Touchpad", "problem": "drivers not installed", "code": 28}], "hardware_errors_7d": 2}})], "Windows")
    assert [item["key"] for item in hardware][:1] == ["hw_overheating"] and hardware[0]["severity"] == "critical"
    assert {"hw_throttling", "hw_gpu:GPU", "hw_devices", "hw_errors"} <= {item["key"] for item in hardware}

    # Failed tools and unknown data never break the analysis.
    assert findings.analyze([("system_overview", {}, {"ok": False, "summary": "x", "data": None}), ("wifi_status", {}, {"ok": True, "data": "junk"})], "Linux") == []


def test_hardware_and_os_playbooks():
    assert match_playbook("my laptop is overheating")["id"] == "hardware"
    assert match_playbook("touchpad and keyboard stopped working")["id"] == "hardware"
    assert match_playbook("system files are corrupt")["id"] == "os_health"
    phases = baseline_phases(get_playbook("slow_pc"), "Windows")
    assert [tool for tool, _ in phases[0]] == ["system_overview", "top_processes", "top_processes"]
    assert "hardware_health" in [tool for tool, _ in phases[1]]


def test_remote_result_wakes_the_planner_immediately():
    async def scenario():
        target = executor.Target("dev-1", "Windows", "laptop")
        waiting = asyncio.create_task(executor.execute(target, "system_overview", {}, "read"))
        await asyncio.sleep(0.05)
        task = task_queue.claim_next_task("dev-1")
        started = time.perf_counter()
        task_queue.complete_task(task["task_id"], "dev-1", {"ok": True, "summary": "fine", "data": {}})
        task_signals.notify(task_signals.task_key(task["task_id"]))
        result = await waiting
        return result, time.perf_counter() - started

    result, waited = asyncio.run(scenario())
    assert result["ok"] and result["summary"] == "fine"
    assert waited < 0.5  # previously polled once a second


def test_hardware_summary_from_collected_data():
    from agent.toolkit import hardware
    result = hardware._finalize({"cpu": {"name": "Test CPU", "performance_percent": 45, "load_percent": 80}, "temperatures_c": [72.0, 91.5], "gpus": [{"name": "GPU", "ok": True}], "problem_devices": [], "memory_modules": [{"gb": 8}]})
    data = result["data"]
    assert data["max_temperature_c"] == 91.5 and data["throttling_suspected"] is True
    assert "throttled" in result["summary"] and "max temp 91.5 C" in result["summary"]


def test_fixes_the_device_would_refuse_are_never_proposed():
    raw = [
        {"tool_id": "restart_service", "args": {"name": "uvicorn"}},
        {"tool_id": "restart_service", "args": {"name": "Spooler"}},
        {"tool_id": "kill_process", "args": {"pid": 600, "expected_name": "lsass.exe"}},
        # The WSL/Docker VM and the AI engine: closing them stops AIops itself.
        {"tool_id": "kill_process", "args": {"pid": 700, "expected_name": "vmmemWSL"}},
        {"tool_id": "kill_process", "args": {"pid": 800, "expected_name": "ollama.exe"}},
    ]
    kept = planner.validate_fixes(raw, "Windows")
    assert [(fix["tool_id"], fix["args"]) for fix in kept] == [("restart_service", {"name": "Spooler"})]


def test_checkup_only_keeps_fixes_backed_by_a_finding():
    found = findings.analyze([("system_overview", {}, {"ok": True, "summary": "", "data": FULL_DISK})], "Windows")
    fixes = [{"tool_id": "clear_print_queue"}, {"tool_id": "clear_temp_files"}, {"tool_id": "sync_time", "learned": True}]
    kept = planner.ground_fixes(fixes, {"confidence": "high"}, found, get_playbook("full_checkup"))
    assert [fix["tool_id"] for fix in kept] == ["clear_temp_files", "sync_time"]
    # Clean checks + low confidence: nothing to fix.
    assert planner.ground_fixes([{"tool_id": "flush_dns"}], {"confidence": "low"}, [], None) == []
    # A specific complaint with real evidence keeps the AI's fixes.
    assert planner.ground_fixes([{"tool_id": "flush_dns"}], {"confidence": "medium"}, [], get_playbook("no_internet")) == [{"tool_id": "flush_dns"}]


def test_virtual_and_removable_drives_are_not_disk_full_problems():
    data = {**HEALTHY_DISK, "ram_percent": 94.4, "ram_used": "14.7 GB", "ram_total": "15.6 GB", "disks": [
        {"mount": "C:\\", "fs": "NTFS", "used_percent": 76.0, "free": "56 GB", "total": "236 GB"},
        {"mount": "G:\\", "fs": "FAT32", "used_percent": 100.0, "free": "0.0 B", "total": "15 GB"},
    ]}
    memory = [{"pid": 10, "name": "vmmemWSL", "memory_percent": 15.5}, {"pid": 11, "name": "chrome.exe", "memory_percent": 6.4}]
    found = findings.analyze([
        ("system_overview", {}, {"ok": True, "summary": "", "data": data}),
        ("top_processes", {"sort_by": "memory"}, {"ok": True, "summary": "", "data": memory}),
    ], "Windows")
    assert [item["key"] for item in found] == ["ram_high"]
    assert "vmmemWSL 15.5%" in found[0]["detail"]


def test_deep_mode_falls_back_to_rules_when_the_ai_investigation_times_out(monkeypatch):
    from backend.llm import LLMUnavailableError

    class SlowProvider(Provider):
        def chat(self, messages, tools=None, json_mode=False, temperature=0.2, max_tokens=None, timeout=None, think=None, on_delta=None):
            self.calls.append({"tools": bool(tools), "max_tokens": max_tokens, "timeout": timeout})
            raise LLMUnavailableError(f"Ollama did not answer within {timeout}s")

    provider = SlowProvider()
    monkeypatch.setattr(planner, "get_provider", lambda: provider)
    monkeypatch.setattr(planner, "execute", scripted_execute([], lambda tool_id: FULL_DISK if tool_id == "system_overview" else {}, delay=0))
    session_id = session_store.create_session("local", "box", "Windows", "my disk is full", None)
    asyncio.run(planner.run_diagnosis(session_id, mode="deep"))

    session = session_store.get_session(session_id)
    assert session["status"] == "diagnosed"  # not "failed": the evidence already collected still answers
    assert "AI did not answer in time" in session["report"]["root_cause"] or session["report"]["quick_findings"]
    # The investigation call is capped and uses the diagnosis deadline, not the global 10-minute timeout.
    assert provider.calls[0] == {"tools": True, "max_tokens": planner.INVESTIGATE_MAX_TOKENS, "timeout": planner.ai_call_timeout()}
    assert len(provider.calls) == 1  # no second slow call for the report


def test_working_internet_is_not_reported_broken_when_the_gateway_lookup_fails():
    stages = {"adapters_with_ip": [{"name": "Wi-Fi"}], "self_assigned_ip": True, "default_gateway": None, "gateway_ping": None,
              "dns_resolution": {"ok": True, "ms": 20}, "tcp_to_internet": {"ok": True, "ms": 15}, "http": {"ok": True, "status": 204}}
    assert findings._check_internet(stages, "Internet connectivity works normally", {}, "Windows") == []
    broken = {**stages, "tcp_to_internet": {"ok": False}, "http": {"ok": False}}
    assert findings._check_internet(broken, "No default gateway", {}, "Windows")[0]["key"] == "net_no_gateway"


def test_network_complaint_is_not_blamed_on_an_unrelated_finding():
    report = {"root_cause": "The disk is nearly full, which might cause DNS issues", "confidence": "medium"}
    found = [{"key": "disk_full:C:\\", "title": "Disk C:\\ is 86.5% full"}]
    evidence = [("check_internet", {}, {"ok": True, "summary": "Internet connectivity works normally"}),
                ("wifi_status", {}, {"ok": True, "summary": "Wi-Fi connected to Office, signal 83%"})]
    grounded = planner.ground_root_cause(dict(report), get_playbook("no_internet"), found, evidence)
    assert grounded["root_cause"].startswith("The network checks passed (Internet connectivity works normally; Wi-Fi connected to Office")
    assert "Separate problems found: Disk C:\\ is 86.5% full." in grounded["root_cause"] and grounded["confidence"] == "low"
    # A real network finding, or a different complaint, keeps the model's diagnosis.
    assert planner.ground_root_cause(dict(report), get_playbook("no_internet"), found + [{"key": "net_dns", "title": "DNS is failing"}], evidence) == report
    assert planner.ground_root_cause(dict(report), get_playbook("slow_pc"), found, evidence) == report
