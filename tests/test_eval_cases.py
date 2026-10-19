"""The evaluation scenarios (backend/agent_brain/eval_cases.py) and the scorer, run without a model."""

import asyncio
import json

import pytest

from backend import task_queue
from backend.agent_brain import evaluate, findings, planner, session_store
from backend.agent_brain.eval_cases import CASES, CASES_BY_ID
from backend.learning import model_builder
from backend.learning import store as learning_store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    db = tmp_path / "test.db"
    for module in (session_store, task_queue, learning_store):
        monkeypatch.setattr(module, "DB_PATH", db)
    monkeypatch.setattr(model_builder, "LEARNED_DIR", tmp_path / "brain")
    monkeypatch.setattr(model_builder, "VERSION_FILE", tmp_path / "brain" / "version.json")
    monkeypatch.setattr(planner, "get_alerts", lambda *args, **kwargs: [])
    monkeypatch.setattr(planner, "execute", planner.execute)  # run_case replaces it; restored after each test


class ScriptedProvider:
    name = "fake"

    def __init__(self, reply):
        self.reply = reply

    def status(self):
        return {"available": True, "provider": "fake", "model": "fake", "message": "ok"}

    def chat(self, messages, **kwargs):
        return {"content": json.dumps(self.reply), "tool_calls": [], "thinking": "", "model": "fake-model", "thought": False}


def test_every_scenario_produces_the_findings_it_was_built_for():
    keys = {case["id"]: {item["key"] for item in findings.analyze(case["evidence"], case["os_type"])} for case in CASES}
    assert "ram_high" in keys["slow_memory_win"] and "disk_full:C:\\" in keys["slow_memory_win"]
    assert "disk_full:C:\\" in keys["slow_disk_critical_win"]
    assert {"ram_high", "disk_full:C:\\"} <= keys["internet_ok_win"] and not any(key.startswith("net_") for key in keys["internet_ok_win"])
    assert "net_dns" in keys["dns_fail_win"]
    assert {"wifi_weak", "net_packet_loss"} <= keys["wifi_weak_win"]
    assert "print_spooler_down" in keys["printer_spooler_win"]
    assert {"cpu_high", "process_cpu:python3"} <= keys["linux_server_cpu"]
    assert keys["clean_checks_win"] == set()


def test_every_scenario_runs_through_the_pipeline_and_keeps_at_least_three_solutions():
    for case in CASES:
        row = asyncio.run(evaluate.run_case(case, "instant"))
        assert row["solutions"], (case["id"], row)
        assert row["fallback"] is True  # instant mode never asks the model


def test_a_fast_run_with_a_model_is_scored(monkeypatch):
    reply = {"root_cause": "Memory is 93.6% used and Windows is swapping. Separate problems: Disk C:\\ is 90.1% full.", "confidence": "high",
             "severity": "high", "solutions": [
                 {"title": "Close Chrome tabs you do not need", "why": "Chrome uses the most memory", "steps": ["Close tabs"], "risk": "low", "tool_id": None},
                 {"title": "Shut down WSL when not in use", "why": "vmmemWSL holds 2.6 GB", "steps": ["wsl --shutdown"], "risk": "low", "tool_id": None},
                 {"title": "Restart the laptop", "why": "Up for 3 days", "steps": ["Restart"], "risk": "low", "tool_id": None}]}
    monkeypatch.setattr(planner, "get_provider", lambda: ScriptedProvider(reply))
    row = asyncio.run(evaluate.run_case(CASES_BY_ID["slow_memory_win"], "fast"))
    assert row["fallback"] is False
    assert row["cause"] and row["not_blamed"] and row["first"] and row["os_steps"] and row["solutions"]


def test_the_scorer_catches_a_finding_blamed_for_a_complaint_it_cannot_cause():
    case = CASES_BY_ID["slow_memory_win"]
    blamed = {"root_cause": "The C:\\ drive is 90.1% full, which can cause the system to hang.", "confidence": "high", "ai": {"model": "m"},
              "solutions": [{"title": "Free up disk space", "steps": ["Delete files"]}, {"title": "Restart the Windows Update service"}, {"title": "Check for driver issues"}]}
    row = evaluate.score(case, blamed)
    assert row["cause"] is False and row["not_blamed"] is False and row["first"] is False
    linux = evaluate.score(CASES_BY_ID["linux_server_cpu"], {"root_cause": "python3 uses 85% CPU", "confidence": "high", "ai": {"model": "m"},
                                                             "solutions": [{"title": "Open Task Manager and end python3"}]})
    assert linux["os_steps"] is False and linux["solutions"] is False
    assert "TOTAL: cause 0/1" in evaluate.format_rows([row])
