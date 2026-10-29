"""The Threat Detection API: scan jobs, stored findings, approved actions (checked again on the server) and the action
chat, which proposes but never runs anything."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from backend import ai_technician, alert_store, device_store, main, software_store, task_queue, threat_store
from backend.agent_brain import session_store
from backend.agent_brain.executor import Target

ISO = "C:\\Users\\alice\\Downloads\\kali-linux-installer-amd64.iso"


def scan_data(scanned_at=None):
    return {"scan_id": "abc123abc123", "platform": "Windows", "hours": 168, "admin": True,
            "scanned_at": (scanned_at or datetime.now(timezone.utc)).isoformat(),
            "antivirus": [{"name": "Kaspersky Endpoint Security for Windows", "enabled": True}],
            "sources": [{"name": "Kaspersky Endpoint Security", "available": True, "count": 606, "detail": ""},
                        {"name": "Windows Security log", "available": False, "count": 0, "detail": "access denied"}],
            "items": [
                {"id": "d0", "kind": "malware", "source": "Kaspersky Endpoint Security", "count": 606, "path": ISO, "on_disk": True,
                 "running": [{"pid": 4242, "name": "vncviewer.exe"}], "objects": ["ISO9660 > vncviewer.exe"], "threats": [{"name": "HEUR:Backdoor.Win32.Poison.gen", "count": 606}],
                 "fields": {"Threat": "HEUR:Backdoor.Win32.Poison.gen", "Result": "Detected", "Threat level": "Heuristic analysis", "User": "CORP\\alice"}},
                {"id": "d1", "kind": "failed_logon", "source": "Windows Security log", "count": 3, "peak_per_hour": 3, "fields": {"Account": "PC1\\admin", "Source address": "203.0.113.9"}},
            ]}


@pytest.fixture(autouse=True)
def server(tmp_path, monkeypatch):
    for module in (threat_store, session_store, alert_store, software_store, device_store, task_queue):
        monkeypatch.setattr(module, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setenv("DECISIONS_DIR", str(tmp_path / "decisions"))
    target = Target("dev1", "Windows", "laptop")
    monkeypatch.setattr(main, "resolve_target", lambda device_id: target if device_id == "dev1" else None)
    monkeypatch.setattr(main, "_change_in_progress", lambda device_id: None)
    monkeypatch.setattr(main, "is_ai_available", lambda: False)
    main.software_jobs.clear()
    main.chat_sessions.clear()
    calls = []

    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        calls.append((tool_id, args, max_risk))
        if tool_id == "threat_scan":
            return {"ok": True, "summary": "1 malware detection group", "data": scan_data()}
        return {"ok": True, "changed": True, "summary": f"{tool_id} done", "data": {"path": ISO}}

    monkeypatch.setattr(main, "execute", fake_execute)
    return calls


async def finished(job):
    for _ in range(200):
        if job["state"] != "running":
            return job
        await asyncio.sleep(0.01)
    raise AssertionError("job did not finish")


def scanned():
    async def run():
        return await finished(await main.scan_device_threats("dev1"))
    return asyncio.run(run())


def test_a_scan_is_stored_with_categorised_findings_and_alerts(server):
    job = scanned()
    assert job["state"] == "done" and job["data"]["scan_id"] == "abc123abc123"
    assert server == [("threat_scan", {"hours": 168}, "read")]
    view = main.device_threats("dev1")
    findings = view["scan"]["findings"]
    assert [finding["id"] for finding in findings] == ["T1", "T2"] and findings[0]["category"] == "malware"
    assert findings[0]["severity"] == "critical"  # it is running right now
    assert view["scan"]["unreadable"][0]["name"] == "Windows Security log" and view["stale"] is False
    alerts = alert_store.get_alerts(device_id="dev1")
    assert len(alerts) == 1 and alerts[0]["category"] == "Threat" and alerts[0]["severity"] == "critical"
    scanned()
    assert len(alert_store.get_alerts(device_id="dev1")) == 1  # one alert per finding while it stays open
    overview = main.threats_overview()
    assert overview["scan_minutes"] == 60


def test_actions_are_checked_again_on_the_server(server, monkeypatch):
    scanned()

    def action(payload):
        async def run():
            return await finished(await main.threat_action("dev1", payload))
        return asyncio.run(run())

    for payload, code in (({"finding_id": "T9", "action": "rescan"}, 404), ({"finding_id": "T2", "action": "quarantine"}, 400),
                          ({"finding_id": "T1", "action": "format"}, 400), ({"finding_id": "T1", "action": "delete", "confirm": "yes"}, 400),
                          ({"finding_id": "T1", "action": "kill", "pid": 1}, 400)):
        with pytest.raises(HTTPException) as refused:
            action(payload)
        assert refused.value.status_code == code, payload
    assert server == [("threat_scan", {"hours": 168}, "read")]  # nothing refused reached the device

    action({"finding_id": "T1", "action": "quarantine"})
    action({"finding_id": "T1", "action": "delete", "confirm": "KALI-LINUX-INSTALLER-AMD64.ISO"})
    action({"finding_id": "T1", "action": "kill", "pid": 4242})
    assert server[1:] == [("quarantine_threat", {"scan_id": "abc123abc123", "item_id": "d0"}, "high"),
                          ("delete_threat", {"scan_id": "abc123abc123", "item_id": "d0", "confirm": "KALI-LINUX-INSTALLER-AMD64.ISO"}, "high"),
                          ("kill_process", {"pid": 4242, "expected_name": "vncviewer.exe"}, "medium")]

    monkeypatch.setattr(main, "_change_in_progress", lambda device_id: "uninstall of 7-Zip")
    with pytest.raises(HTTPException) as busy:
        action({"finding_id": "T1", "action": "rescan"})
    assert busy.value.status_code == 409

    monkeypatch.setattr(main, "_change_in_progress", lambda device_id: None)
    threat_store.save_scan("dev1", scan_data(datetime.now(timezone.utc) - timedelta(hours=7)))
    with pytest.raises(HTTPException) as stale:
        action({"finding_id": "T1", "action": "rescan"})
    assert stale.value.status_code == 409 and "scan again" in stale.value.detail


def test_the_action_chat_proposes_and_never_runs_anything(server, monkeypatch):
    scanned()
    reply = main.threat_chat_endpoint("dev1", {"message": "T1 ko quarantine karo"})
    assert reply["source"] == "rules" and reply["proposal"]["action"] == "quarantine" and reply["proposal"]["finding_id"] == "T1"
    assert "Approve it below" in reply["reply"]
    assert main.threat_chat_endpoint("dev1", {"message": "T2 delete karo"})["proposal"] is None  # a sign-in has no file

    monkeypatch.setattr(main, "is_ai_available", lambda: True)
    monkeypatch.setattr(main, "threat_chat", lambda message, analysis, history, think=False: {"reply": "T1 is a Kali ISO.", "finding_id": "T1", "action": "delete", "pid": None})
    answer = main.threat_chat_endpoint("dev1", {"message": "isay mita do"})
    assert answer["source"] == "ai" and answer["proposal"]["action"] == "delete" and answer["proposal"]["confirm"] == "kali-linux-installer-amd64.iso"
    # The AI proposing an action the finding does not offer gives no card.
    monkeypatch.setattr(main, "threat_chat", lambda message, analysis, history, think=False: {"reply": "Done!", "finding_id": "T2", "action": "quarantine", "pid": None})
    assert main.threat_chat_endpoint("dev1", {"message": "what about T2"})["proposal"] is None
    assert server == [("threat_scan", {"hours": 168}, "read")]  # the chat ran nothing on the device
    with pytest.raises(HTTPException):
        main.threat_chat_endpoint("dev1", {"message": "  "})


def test_marks_and_the_rules_explanation(server):
    scanned()
    main.threat_mark("dev1", {"finding_id": "T1", "status": "false_positive", "note": "pentest ISO, IT knows"})
    findings = main.device_threats("dev1")["scan"]["findings"]
    assert findings[0]["status"] == "false_positive" and findings[0]["mark_note"] == "pentest ISO, IT knows"
    with pytest.raises(HTTPException):
        main.threat_mark("dev1", {"finding_id": "T1", "status": "deleted"})
    main.threat_mark("dev1", {"finding_id": "T1", "status": None})
    assert main.device_threats("dev1")["scan"]["findings"][0]["status"] == "active"
    explanation = main.threat_explain("dev1", {})
    assert explanation["source"] == "rules" and explanation["priorities"][0]["finding_id"] == "T1"


def test_no_scan_yet_and_unknown_devices(server):
    assert main.device_threats("dev1")["scan"] is None
    with pytest.raises(HTTPException) as unknown:
        main.device_threats("nope")
    assert unknown.value.status_code == 404
    with pytest.raises(HTTPException) as first:
        main.threat_chat_endpoint("dev1", {"message": "hi"})
    assert first.value.status_code == 404


def test_a_cloud_ai_never_sees_names_or_addresses(monkeypatch, server):
    from backend import threat_rules

    analysis = threat_rules.analyze_threats(scan_data(), "Windows")
    monkeypatch.setattr(ai_technician, "get_provider", lambda: type("Groq", (), {"name": "groq"})())
    cloud = ai_technician._threat_context(analysis)
    assert "PC1\\admin" not in cloud and "203.0.113.9" not in cloud and "CORP\\alice" not in cloud and "[hidden]" in cloud
    assert "\\Users\\alice" not in cloud and "\\Users\\[user]\\Downloads" in cloud  # the user's folder name too
    monkeypatch.setattr(ai_technician, "get_provider", lambda: type("Ollama", (), {"name": "ollama"})())
    assert "203.0.113.9" in ai_technician._threat_context(analysis)


def test_an_old_agent_is_not_asked_again_for_a_while(server, monkeypatch):
    async def old_agent(target, tool_id, args, max_risk, session_id=None):
        return {"ok": False, "summary": "Unknown or disallowed tool: threat_scan"}

    monkeypatch.setattr(main, "execute", old_agent)
    job = scanned()
    assert job["summary"] == main.NEW_AGENT_MESSAGE and main.threat_unsupported["dev1"] > 0
    main.threat_unsupported.clear()
