"""Approved changes are always on record, even when the server restarts while a device is still working."""

import asyncio
import json

import pytest

from backend import main, software_store, task_queue
from backend.agent_brain import planner, session_store
from backend.agent_brain.executor import Target

DEVICE = {"device_id": "dev1", "nickname": "laptop", "hostname": "laptop-1"}


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    for module in (session_store, software_store, task_queue):
        monkeypatch.setattr(module, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(main, "authenticated_device", lambda request: DEVICE)


def _records(tmp_path, kind):
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted((tmp_path / "decisions").rglob(f"*_{kind}_*.json"))]


def _job(name="Adobe Acrobat"):
    return {"job_id": "j1", "device_id": "dev1", "action": "uninstall", "name": name, "state": "running"}


def _running_task(tool_id="uninstall_software", args=None, max_risk="high", session_id=None):
    task_id = task_queue.enqueue_task("dev1", tool_id, args or {"id": "HKLM64|x"}, max_risk, 60, session_id)
    assert task_queue.claim_next_task("dev1")["task_id"] == task_id
    return task_id


def test_a_change_on_this_server_is_recorded_when_approved_and_when_finished(tmp_path, monkeypatch):
    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        return {"ok": True, "summary": "Uninstalled Adobe Acrobat"}

    monkeypatch.setattr(main, "execute", fake_execute)
    asyncio.run(main._run_software_job(_job(), Target("local", "Windows", "box"), "uninstall_software", {"id": "HKLM64|x"}, "high"))
    states = [record["state"] for record in _records(tmp_path, "software_action")]
    assert states == ["approved", "finished"]
    audit = session_store.list_audit()
    assert len(audit) == 1 and audit[0]["tool_id"] == "uninstall_software" and audit[0]["ok"]


def test_an_agent_result_is_recorded_when_it_arrives_even_without_the_job(tmp_path, monkeypatch):
    """The server restarted during the uninstall: no job is waiting any more, the result is still recorded."""
    task_id = _running_task()
    reply = asyncio.run(main.agent_task_result(task_id, {"ok": True, "summary": "Uninstalled Adobe Acrobat (64-bit)"}, request=None))
    assert reply == {"accepted": True}
    finished = _records(tmp_path, "software_action")
    assert [record["state"] for record in finished] == ["finished"] and finished[0]["task_id"] == task_id and finished[0]["ok"]
    assert len(session_store.list_audit()) == 1

    # The job that was waiting (no restart case) does not record it a second time.
    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        return {"ok": True, "summary": "Uninstalled Adobe Acrobat (64-bit)", "remote_task_id": task_id}

    monkeypatch.setattr(main, "execute", fake_execute)
    asyncio.run(main._run_software_job(_job(), Target("dev1", "Windows", "laptop"), "uninstall_software", {"id": "HKLM64|x"}, "high"))
    assert [record["state"] for record in _records(tmp_path, "software_action")] == ["finished", "approved"]
    assert len(session_store.list_audit()) == 1


def test_read_only_results_are_not_recorded_as_changes(tmp_path):
    task_id = _running_task("installed_software", {"check_updates": True}, "read")
    asyncio.run(main.agent_task_result(task_id, {"ok": True, "summary": "40 programs"}, request=None))
    assert _records(tmp_path, "software_action") == [] and session_store.list_audit() == []


def test_a_change_still_running_on_the_device_blocks_the_next_one_across_restarts():
    task_queue.enqueue_task("dev1", "installed_software", {}, "read", 60)
    assert task_queue.pending_change("dev1") is None and main._change_in_progress("dev1") is None
    task_queue.enqueue_task("dev1", "install_os_updates", {"update_ids": "x"}, "high", 5400)
    assert task_queue.pending_change("dev1") == "install_os_updates"
    with pytest.raises(main.HTTPException) as busy:
        main._refuse_if_changing("dev1")
    assert busy.value.status_code == 409 and "install_os_updates" in busy.value.detail


def test_an_interrupted_fix_is_not_stuck_and_its_late_result_is_recorded(tmp_path):
    session_id = session_store.create_session("dev1", "laptop", "Windows", "websites do not open", None)
    report = {"root_cause": "DNS", "proposed_fixes": [{"tool_id": "flush_dns", "args": {}, "risk": "low", "status": "running", "result": None}],
              "solutions": [{"title": "Flush DNS", "tool_id": "flush_dns", "args": {}, "fix_index": 0, "status": "running"}]}
    session_store.update_session(session_id, status="fixing", report=report)

    session_store.mark_interrupted_sessions()  # what a server restart does at startup
    session = session_store.get_session(session_id, include_steps=False)
    fix = session["report"]["proposed_fixes"][0]
    assert session["status"] == "failed" and fix["status"] == "failed" and fix["result"]["interrupted"]
    assert session["report"]["solutions"][0]["status"] == "failed"  # can be retried or rejected again

    task = {"session_id": session_id, "device_id": "dev1", "tool_id": "flush_dns", "args": {}}
    assert planner.record_late_fix_result(task, {"ok": True, "summary": "DNS cache flushed"}, "laptop") is True
    session = session_store.get_session(session_id, include_steps=False)
    assert session["report"]["proposed_fixes"][0]["status"] == "applied" and session["report"]["solutions"][0]["status"] == "applied"
    assert session_store.list_audit()[0]["summary"] == "DNS cache flushed"
    assert _records(tmp_path, "fix_result")[0]["method"] == "late result"


def test_a_late_result_for_a_live_session_is_left_to_the_session(tmp_path):
    session_id = session_store.create_session("dev1", "laptop", "Windows", "printer stuck", None)
    session_store.update_session(session_id, status="fixing", report={"proposed_fixes": []})
    task = {"session_id": session_id, "device_id": "dev1", "tool_id": "clear_print_queue", "args": {}}
    assert planner.record_late_fix_result(task, {"ok": True, "summary": "cleared"}, "laptop") is False
    assert session_store.list_audit() == []


def test_agent_download_answers_without_crashing():
    for platform in ("windows", "mac", "linux"):
        response = main.download_agent(platform)
        assert response.status_code in (200, 404)


def test_last_seen_uses_the_servers_clock(monkeypatch):
    saved = {}
    monkeypatch.setenv("ONBOARDING_CHECK", "false")
    for name in ("evaluate_rules", "evaluate_security_rules", "evaluate_performance_rules", "evaluate_event_log_rules"):
        monkeypatch.setattr(main, name, lambda *args, **kwargs: [])
    monkeypatch.setattr(main, "save_report", lambda device_id, timestamp, diagnostics, spike=False: saved.update(timestamp=timestamp))
    main.agent_report({"timestamp": "2000-01-01T00:00:00+00:00", "diagnostics": {}}, request=None)
    assert not saved["timestamp"].startswith("2000")


def test_a_refused_approval_does_not_lock_the_device():
    session_id = session_store.create_session("dev1", "laptop", "Windows", "dns", None)
    session_store.update_session(session_id, status="diagnosed", report={"proposed_fixes": [{"tool_id": "flush_dns", "args": {}, "status": "applied"}], "solutions": []})
    with pytest.raises(main.HTTPException) as refused:
        asyncio.run(main.troubleshoot_apply_fix(session_id, 0))
    assert refused.value.status_code == 409 and main._change_in_progress("dev1") is None and "dev1" not in main.fixes_starting


def test_a_change_whose_result_never_arrives_is_recorded_as_unknown(tmp_path):
    software_store.save_inventory("dev1", {"software": [{"id": "HKLM64|x", "name": "Adobe Acrobat"}]})
    task_id = _running_task()
    with task_queue._connect() as connection:  # claimed long ago, never reported back
        connection.execute("UPDATE agent_tasks SET claimed_at = '2026-01-01T00:00:00+00:00' WHERE task_id = ?", (task_id,))
        connection.commit()
    task_queue.expire_stale_tasks()
    record = _records(tmp_path, "software_action")[0]
    assert record["state"] == "no result" and record["ok"] is False and "Adobe Acrobat" in record["action"] and "check the device" in record["result"]
    assert session_store.list_audit()[0]["ok"] == 0


def test_a_wait_that_runs_out_is_recorded_as_waiting_not_finished(tmp_path, monkeypatch):
    task_id = _running_task()

    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        return {"ok": False, "summary": "No result from laptop in time", "remote_task_id": task_id}

    monkeypatch.setattr(main, "execute", fake_execute)
    asyncio.run(main._run_software_job(_job(), Target("dev1", "Windows", "laptop"), "uninstall_software", {"id": "HKLM64|x"}, "high"))
    assert [record["state"] for record in _records(tmp_path, "software_action")] == ["approved", "waiting"]
    assert session_store.list_audit() == []


def test_the_finished_record_names_the_program(tmp_path):
    software_store.save_inventory("dev1", {"software": [{"id": "HKLM64|x", "name": "Adobe Acrobat (64-bit)"}]})
    task_id = _running_task()
    asyncio.run(main.agent_task_result(task_id, {"ok": True, "summary": "Uninstalled"}, request=None))
    assert _records(tmp_path, "software_action")[0]["action"] == "uninstall_software Adobe Acrobat (64-bit)"
    assert software_store.get_inventory("dev1")["software"] == []  # looked up before the inventory was updated


def test_a_late_result_for_a_fix_that_was_not_interrupted_is_not_recorded_again():
    session_id = session_store.create_session("dev1", "laptop", "Windows", "dns", None)
    session_store.update_session(session_id, status="diagnosed", report={"proposed_fixes": [{"tool_id": "flush_dns", "args": {}, "status": "failed", "result": {"ok": False}}]})
    task = {"session_id": session_id, "device_id": "dev1", "tool_id": "flush_dns", "args": {}}
    assert planner.record_late_fix_result(task, {"ok": False, "summary": "failed"}, "laptop") is False
    assert session_store.list_audit() == []


def test_a_change_the_device_never_picked_up_is_recorded_as_not_run(tmp_path):
    task_id = task_queue.enqueue_task("dev1", "update_software", {"package_id": "7zip.7zip"}, "medium", 60)
    with task_queue._connect() as connection:
        connection.execute("UPDATE agent_tasks SET created_at = '2026-01-01T00:00:00+00:00' WHERE task_id = ?", (task_id,))
        connection.commit()
    task_queue.expire_stale_tasks()
    task_queue.expire_stale_tasks()  # a second call must not record it again
    records = _records(tmp_path, "software_action")
    assert len(records) == 1 and records[0]["result"].endswith("It did not run.") and len(session_store.list_audit()) == 1
