"""Chat conversation isolation and device grounding; no model or device actions."""

from datetime import datetime, timezone
import json

import pytest
from fastapi import HTTPException

from backend import main


@pytest.fixture
def chat_server(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "chat_sessions", {})
    monkeypatch.setattr(main, "is_ai_available", lambda: True)
    monkeypatch.setattr(main, "_record_ai", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.server_identity, "server_device", lambda: None)
    monkeypatch.setattr(main, "get_device", lambda device_id: {"device_id": device_id, "status": "online", "os_type": "Windows"})
    monkeypatch.setattr(main, "get_latest_report", lambda device_id: {
        "timestamp": datetime.now(timezone.utc).isoformat(), "diagnostics": {"system": {"hostname": device_id}}})

    def no_collection():
        raise AssertionError("An agent conversation must not collect server/container data")

    monkeypatch.setattr(main, "collect_report", no_collection)

    def fake_chat(message, report, history, **kwargs):
        calls.append({"message": message, "report": report, "history": list(history), **kwargs})
        return {"plain_explanation": "Check the settings", "technical_root_cause": "",
                "recommendations": ["Open Settings", "Open Network & Internet"]}

    monkeypatch.setattr(main, "chat", fake_chat)
    return calls


def test_browser_history_is_used_and_empty_history_starts_fresh(chat_server):
    history = [{"role": "assistant", "content": {"plain_explanation": "Advice", "recommendations": ["Open WiFi settings"]}}]
    main.agent_chat({"device_id": "a", "message": "How?", "conversation_history": history})
    assert json.loads(chat_server[-1]["history"][0]["content"])["recommendations"] == ["Open WiFi settings"]
    main.agent_chat({"device_id": "a", "message": "New question", "conversation_history": []})
    assert chat_server[-1]["history"] == []
    assert main.chat_sessions == {}  # browser chats never create a shared default history


def test_sessions_are_distinct_reusable_and_scoped_to_device(chat_server):
    first = main.agent_chat({"device_id": "a", "message": "Help"})
    second = main.agent_chat({"device_id": "a", "message": "Unrelated new chat"})
    assert first["session_id"] != second["session_id"] and chat_server[-1]["history"] == []
    followup = main.agent_chat({"device_id": "a", "message": "Step 2?", "session_id": first["session_id"]})
    assert followup["session_id"] == first["session_id"]
    assert json.loads(chat_server[-1]["history"][-1]["content"])["recommendations"][1] == "Open Network & Internet"
    main.agent_chat({"device_id": "b", "message": "Other device", "session_id": first["session_id"]})
    assert chat_server[-1]["history"] == []
    assert chat_server[-1]["report"]["system"]["hostname"] == "b"


@pytest.mark.parametrize("timestamp,status,stale", [
    ("2020-01-01T00:00:00+00:00", "online", True),
    (None, "online", True),
    ("bad timestamp", "online", True),
    ("now", "offline", True),
    ("now", "online", False),
])
def test_snapshot_age_and_device_status_reach_the_model(chat_server, monkeypatch, timestamp, status, stale):
    if timestamp == "now":
        timestamp = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(main, "get_device", lambda device_id: {"status": status})
    monkeypatch.setattr(main, "get_latest_report", lambda device_id: {"timestamp": timestamp, "diagnostics": {"cpu": {"total_usage_percent": 91}}})
    result = main.agent_chat({"device_id": "a", "message": "CPU ab high hai?", "conversation_history": []})
    assert result["device_context"]["stale"] is stale
    assert chat_server[-1]["context"] == result["device_context"]


def test_no_agent_snapshot_allows_general_questions_without_substituting_server_data(chat_server, monkeypatch):
    monkeypatch.setattr(main, "get_latest_report", lambda device_id: None)
    result = main.agent_chat({"device_id": "a", "message": "What is RAM?", "diagnostics": {"wrong_device": True}})
    assert chat_server[-1]["report"] is None
    assert result["device_context"]["has_snapshot"] is False and result["device_context"]["stale"] is True


def test_local_alias_uses_the_host_agent_even_if_offline(chat_server, monkeypatch):
    monkeypatch.setattr(main.server_identity, "server_device", lambda: {"device_id": "host-agent"})
    monkeypatch.setattr(main, "get_device", lambda device_id: {"status": "offline"})
    result = main.agent_chat({"device_id": "local", "message": "Help"})
    assert result["device_context"]["device_id"] == "host-agent"
    assert result["device_context"]["stale"] is True
    assert chat_server[-1]["report"]["system"]["hostname"] == "host-agent"


def test_container_fallback_is_explicit_and_ignores_client_snapshot(chat_server, monkeypatch):
    monkeypatch.setattr(main.server_identity, "in_docker", lambda: True)
    monkeypatch.setattr(main, "collect_report", lambda: {"system": {"hostname": "container"}})
    result = main.agent_chat({"device_id": "local", "message": "Help", "diagnostics": {"wrong_device": True}})
    assert result["device_context"]["source"] == "container"
    assert chat_server[-1]["report"]["system"]["hostname"] == "container"


def test_unknown_device_and_invalid_history_do_not_reach_model(chat_server, monkeypatch):
    monkeypatch.setattr(main, "get_device", lambda device_id: None)
    with pytest.raises(HTTPException) as error:
        main.agent_chat({"device_id": "unknown", "message": "Help"})
    assert error.value.status_code == 404
    with pytest.raises(HTTPException) as error:
        main.agent_chat({"device_id": "a", "message": "Help", "conversation_history": "bad"})
    assert error.value.status_code == 400
    assert chat_server == []
