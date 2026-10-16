import asyncio
import json

import pytest
from fastapi import HTTPException

from agent.toolkit import diagnostics, get_tool, hardware, updates
from backend import main, software_store
from backend.agent_brain import findings, planner, session_store
from backend.agent_brain.executor import Target
from backend.agent_brain.playbooks import get_playbook

GUID_A = "d125362d-3c64-4321-bd85-5bba34bb6dbf"
GUID_B = "45196795-f455-42ad-831b-41263bef6edd"
GUID_C = "9839f3cc-8075-45a1-92a3-87d264ebad09"


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    for module in (software_store, session_store):
        monkeypatch.setattr(module, "DB_PATH", tmp_path / "test.db")


# ---------------------------------------------------------------------------
# Agent tools
# ---------------------------------------------------------------------------

PROC_INPUT = """I: Bus=0011 Vendor=0001 Product=0001 Version=ab41
N: Name="AT Translated Set 2 keyboard"
H: Handlers=sysrq kbd event3 leds
B: EV=120013

I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name="Power Button"
H: Handlers=kbd event0
B: EV=3

I: Bus=0018 Vendor=04f3 Product=3282 Version=0100
N: Name="ELAN0001:00 04F3:3282 Touchpad"
H: Handlers=event5 mouse0
B: EV=1b

I: Bus=0003 Vendor=046d Product=c52b Version=0111
N: Name="Logitech USB Receiver"
H: Handlers=sysrq kbd leds event7
B: EV=120013

I: Bus=0003 Vendor=046d Product=c52b Version=0111
N: Name="Logitech USB Receiver Mouse"
H: Handlers=event8 mouse1
B: EV=17
"""


def test_linux_input_devices_are_parsed_and_system_buttons_ignored():
    devices = hardware.parse_proc_input(PROC_INPUT)
    assert [(item["name"], item["kind"], item["connection"]) for item in devices] == [
        ("AT Translated Set 2 keyboard", "keyboard", "built-in"),
        ("ELAN0001:00 04F3:3282 Touchpad", "touchpad", "built-in"),
        ("Logitech USB Receiver", "keyboard", "USB"),
        ("Logitech USB Receiver Mouse", "mouse", "USB"),
    ]


def test_an_input_device_driver_problem_is_a_finding_with_a_rescan_fix(monkeypatch):
    rows = [
        {"name": "Standard PS/2 Keyboard", "class": "Keyboard", "status": "OK", "code": 0, "device_id": r"ACPI\HPQ8002\4"},
        {"name": "HID Keyboard Device", "class": "Keyboard", "status": "OK", "code": 0, "device_id": r"HID\CONVERTEDDEVICE&COL01\5"},
        {"name": "HID-compliant mouse", "class": "Mouse", "status": "Error", "code": 43, "device_id": r"HID\VID_046D&PID_C542&COL01\6"},
        {"name": "HID-compliant touch pad", "class": "HIDClass", "status": "OK", "code": 0, "device_id": r"HID\ELAN076D&COL03\5&36A7250&0&0002"},
        {"name": "HID-compliant mouse", "class": "Mouse", "status": "OK", "code": 0, "device_id": r"HID\ELAN076D&COL01\5&36A7250&0&0000"},
        {"name": "HID Keyboard Device", "class": "Keyboard", "status": "OK", "code": 0, "device_id": r"HID\INTC816&COL01\3&10839A5C&0&0000"},
    ]
    monkeypatch.setattr(hardware, "os_name", lambda: "Windows")
    monkeypatch.setattr(hardware, "powershell", lambda script, timeout=0: {"stdout": json.dumps(rows), "stderr": "", "returncode": 0})
    result = hardware.input_devices()
    # The converted and hotkey-filter "keyboards" are not counted, and the touchpad's mouse collection is the touchpad.
    assert result["data"]["keyboards"] == 1 and result["data"]["pointing"] == 2 and result["data"]["problems"] == 1
    assert result["summary"].startswith("1 keyboard, 1 mouse, 1 touchpad") and "device reported a problem" in result["summary"]
    found = findings.analyze([("input_devices", {}, result)], "Windows")
    assert found[0]["key"].startswith("input_device:") and found[0]["fixes"][0]["tool_id"] == "rescan_hardware"
    # A headless server has no input devices at all: that is not a missing keyboard.
    headless = {"ok": True, "summary": "none", "data": {"devices": [], "keyboards": 0, "pointing": 0, "problems": 0}}
    touchpad_only = {"ok": True, "summary": "touchpad", "data": {"devices": [], "keyboards": 0, "pointing": 1, "problems": 0}}
    assert findings.analyze([("input_devices", {}, headless)], "Linux") == []
    assert [item["key"] for item in findings.analyze([("input_devices", {}, touchpad_only)], "Windows")] == ["input_no_keyboard"]


def test_systemd_times_are_converted_to_seconds():
    assert diagnostics.parse_systemd_seconds("1min 2.345s") == 62.3
    assert diagnostics.parse_systemd_seconds("1.5s") == 1.5
    assert diagnostics.parse_systemd_seconds("850ms") == pytest.approx(0.85, abs=0.06)
    assert diagnostics.parse_systemd_seconds("") is None


def test_windows_boot_timing_names_what_slowed_it(monkeypatch):
    raw = {"fast_startup": 1, "boot_type": 1,
           "boots": [{"at": "a", "total_ms": 95000, "main_ms": 70000, "post_ms": 25000}, {"at": "b", "total_ms": 45000, "main_ms": 20000, "post_ms": 25000}],
           "slowdowns": [{"kind": 101, "name": "OneDrive", "total_ms": 9000, "slower_by_ms": 6000}, {"kind": 101, "name": "OneDrive", "total_ms": 5000, "slower_by_ms": 2000},
                         {"kind": 103, "name": "Print Spooler", "total_ms": 3000, "slower_by_ms": 2500}]}
    monkeypatch.setattr(diagnostics, "os_name", lambda: "Windows")
    monkeypatch.setattr(diagnostics, "powershell", lambda script, timeout=0: {"stdout": json.dumps(raw), "stderr": "", "returncode": 0})
    monkeypatch.setattr(diagnostics, "startup_programs", lambda: {"data": [{}] * 16})
    result = diagnostics.boot_performance()
    data = result["data"]
    assert data["last_boot_seconds"] == 95.0 and data["average_boot_seconds"] == 70.0 and data["boots_measured"] == 2
    assert [item["name"] for item in data["slowed_by"]] == ["OneDrive", "Print Spooler"] and data["slowed_by"][0]["slower_by_ms"] == 6000
    assert data["last_boot_type"] == "fast startup (hybrid boot)" and "fast startup on" in result["summary"]
    found = {item["key"]: item for item in findings.analyze([("boot_performance", {}, result)], "Windows")}
    assert set(found) == {"boot_slow", "startup_many"} and found["boot_slow"]["severity"] == "medium"
    assert "desktop was ready after 70 s" in found["boot_slow"]["title"] and "last 30 days by OneDrive" in found["boot_slow"]["detail"]
    # 95 s in total but the desktop was ready after 40 s: the settle-down after sign-in is normal.
    healthy = {"ok": True, "summary": "", "data": {"last_boot_seconds": 95.0, "desktop_ready_seconds": 40.0, "startup_programs": 5}}
    assert findings.analyze([("boot_performance", {}, healthy)], "Windows") == []


WU_SEARCH = {"reboot_pending": True, "updates": [
    {"id": GUID_A, "title": ".NET 8.0 Security Update (KB5130034)", "kb": "5130034", "driver": False, "min_mb": 0, "max_mb": 213, "severity": "Important",
     "categories": [".NET 8.0", "Security Updates"], "may_restart": True, "needs_input": False, "eula": True, "recommended": True, "downloaded": True},
    {"id": GUID_B, "title": "2026-10 Cumulative Update (KB5127648)", "kb": "5127648", "driver": False, "min_mb": 600, "max_mb": 92638, "severity": None,
     "categories": ["Security Updates"], "may_restart": True, "needs_input": False, "eula": True, "recommended": True, "downloaded": False},
    {"id": GUID_C, "title": "HP printer driver", "driver": True, "min_mb": 13, "max_mb": 13, "categories": ["Drivers"], "needs_input": True, "eula": True, "recommended": False},
    {"id": "not-a-guid", "title": "bogus"},
]}


def test_windows_update_search_is_parsed(monkeypatch):
    monkeypatch.setattr(updates, "os_name", lambda: "Windows")
    monkeypatch.setattr(updates, "is_admin", lambda: True)
    monkeypatch.setattr(updates, "_powershell_json", lambda script, timeout: WU_SEARCH)
    result = updates.os_updates()
    data = result["data"]
    assert [item["kind"] for item in data["updates"]] == ["security", "security", "driver"]  # the bogus id is dropped
    assert data["updates"][0]["size_text"] == "213 MB (downloaded)"
    assert data["updates"][1]["size_text"] == "600 MB"  # a cumulative update shows its delta size, not 90 GB
    assert updates._size_text({"min_mb": 0, "max_mb": 92638, "downloaded": True}) == "downloaded"
    assert data["updates"][2]["installable"] is False and data["updates"][2]["note"]
    assert data["security_count"] == 2 and data["driver_count"] == 1 and data["can_install"]
    assert "restart is pending" in result["summary"]
    keys = {item["key"] for item in findings.analyze([("os_updates", {}, result)], "Windows")}
    assert {"os_updates_security", "reboot_pending"} <= keys


def test_os_update_install_takes_only_validated_ids_and_never_restarts(monkeypatch):
    seen = {}

    def fake(script, timeout):
        seen["script"] = script
        return {"result": 2, "restart": True, "offered": [GUID_A, GUID_B], "installed": [{"id": GUID_A, "title": "A", "code": 2}], "skipped": []}

    monkeypatch.setattr(updates, "os_name", lambda: "Windows")
    monkeypatch.setattr(updates, "_powershell_json", fake)
    assert updates.install_os_updates("abc;Remove-Item C:\\")["ok"] is False and "script" not in seen
    assert updates.install_os_updates("")["ok"] is False and "script" not in seen
    result = updates.install_os_updates(f"{GUID_A},{GUID_C}")
    assert f"$wanted = @('{GUID_A}','{GUID_C}')" in seen["script"]
    assert result["ok"] and result["changed"] and result["data"]["restart_required"] and result["data"]["no_longer_offered"] == [GUID_C]
    assert "restart the computer" in result["summary"] and "never restarts" in result["summary"]

    monkeypatch.setattr(updates, "_powershell_json", lambda script, timeout: {"error": "0x80240044", "hresult": updates.WU_ACCESS_DENIED})
    assert "administrator" in updates.install_os_updates(GUID_A)["summary"]
    tool = get_tool("install_os_updates")
    assert tool.risk == "high" and not tool.ai_visible and "install_os_updates" not in planner.fix_catalog("Windows")


def test_apt_and_linux_installs_only_upgrade_offered_packages(monkeypatch):
    listing = "Listing...\nopenssl/jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.17]\nvlc/jammy-updates 3.0.20 amd64 [upgradable from: 3.0.16]\n"
    monkeypatch.setattr(updates, "_run", lambda command, timeout, env=None: (0, listing, ""))
    data = updates._apt_updates()
    assert [(item["id"], item["kind"]) for item in data["updates"]] == [("openssl", "security"), ("vlc", "update")]

    calls = []
    monkeypatch.setattr(updates, "is_admin", lambda: True)
    monkeypatch.setattr(updates, "_linux_updates", lambda: {"source": "apt", "updates": [{"id": "vlc"}]})
    monkeypatch.setattr(updates, "_run", lambda command, timeout, env=None: calls.append(command) or (0, "", ""))
    assert updates._linux_install("vlc;rm -rf /")["ok"] is False and updates._linux_install("")["ok"] is False and not calls
    result = updates._linux_install("vlc,curl")
    assert calls == [["apt-get", "install", "--only-upgrade", "-y", "-o", "Dpkg::Options::=--force-confold", "vlc"]]
    assert result["ok"] and result["data"]["no_longer_offered"] == ["curl"]


# ---------------------------------------------------------------------------
# Server: full test job, AI analysis hand-off, OS update install endpoint
# ---------------------------------------------------------------------------

def test_full_test_runs_every_check_read_only_and_feeds_the_ai_analysis(monkeypatch):
    target = Target("dev1", "Windows", "laptop")
    monkeypatch.setattr(main, "resolve_target", lambda device_id: target if device_id == "dev1" else None)
    calls = []

    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        calls.append((tool_id, max_risk))
        if tool_id == "installed_software":
            return {"ok": True, "summary": "2 programs", "data": {"software": [
                {"id": "a", "name": "7-Zip", "update_available": True, "update_id": "7zip.7zip", "version": "1", "available_version": "2"}, {"id": "b", "name": "Old"}]}}
        if tool_id == "boot_performance":
            return {"ok": True, "summary": "slow start-up", "data": {"last_boot_seconds": 200, "startup_programs": 4}}
        if tool_id == "input_devices":
            return {"ok": False, "summary": "Unknown or disallowed tool: input_devices", "data": None}
        return {"ok": True, "summary": f"{tool_id} fine", "data": {}}

    started = {}

    async def fake_run_diagnosis(session_id, mode=None, preset_evidence=None):
        started.update(session_id=session_id, mode=mode, evidence=preset_evidence)

    monkeypatch.setattr(main, "execute", fake_execute)
    monkeypatch.setattr(main, "run_diagnosis", fake_run_diagnosis)

    async def scenario():
        job = await main.start_performance_test("dev1")
        assert (await main.start_performance_test("dev1"))["job_id"] == job["job_id"]  # one test at a time per device
        with pytest.raises(HTTPException) as busy:
            await main.analyse_performance_test("dev1", {"job_id": job["job_id"]})
        assert busy.value.status_code == 409
        for _ in range(500):
            if job["state"] == "done":
                break
            await asyncio.sleep(0.01)
        reply = await main.analyse_performance_test("dev1", {"job_id": job["job_id"], "think": True})
        for _ in range(5):
            await asyncio.sleep(0)
        again = await main.analyse_performance_test("dev1", {"job_id": job["job_id"]})
        assert again["session_id"] == reply["session_id"]  # one analysis per test while it runs
        return job, reply

    job, reply = asyncio.run(scenario())
    assert {risk for _tool_id, risk in calls} == {"read"} and len(calls) == sum(len(phase) for phase in main.PERFORMANCE_PHASES)
    sections = job["sections"]
    assert sections["apps"]["data"]["updates"][0]["update_id"] == "7zip.7zip" and "software" not in sections["apps"]["data"]
    assert sections["input"]["summary"] == main.NEW_AGENT_MESSAGE
    assert any(item["key"] == "boot_slow" and item["severity"] == "high" for item in job["findings"])
    assert main.latest_performance_test("dev1")["job_id"] == job["job_id"]
    assert reply["mode"] == "deep" and started["session_id"] == reply["session_id"] == job["analysis_session_id"]
    assert "input_devices" not in {tool_id for tool_id, _args, _result in started["evidence"]}
    assert session_store.get_session(reply["session_id"], include_steps=False)["playbook_id"] == "performance"

    monkeypatch.setattr(main, "resolve_target", lambda device_id: Target("dev2", "Windows", "old pc", "offline"))
    with pytest.raises(HTTPException) as offline:
        asyncio.run(main.start_performance_test("dev2"))
    assert offline.value.status_code == 409 and "offline" in offline.value.detail


def test_os_update_install_endpoint_validates_ids(monkeypatch):
    monkeypatch.setattr(main, "resolve_target", lambda device_id: Target("dev1", "Windows", "laptop"))
    started = []
    monkeypatch.setattr(main, "_start_software_job", lambda target, action, name, tool_id, args, max_risk: started.append((action, name, tool_id, args, max_risk)) or {"job_id": "x"})
    for bad in (["$(Restart-Computer)"], [GUID_A + "\n"], [], None):
        with pytest.raises(HTTPException):
            asyncio.run(main.install_device_os_updates("dev1", {"update_ids": bad}))
    asyncio.run(main.install_device_os_updates("dev1", {"update_ids": [GUID_A]}))
    assert started == [("os-update", "1 OS update", "install_os_updates", {"update_ids": GUID_A}, "high")]


def test_a_diagnosis_can_start_from_checks_that_already_ran(monkeypatch, tmp_path):
    session_id = session_store.create_session("local", "box", "Windows", get_playbook("performance")["issue"], "performance")

    async def no_baseline(*args):
        raise AssertionError("the checks already ran")

    monkeypatch.setattr(planner, "collect_baseline", no_baseline)
    monkeypatch.setattr(planner, "learn_from", lambda session_id: asyncio.sleep(0))
    monkeypatch.setattr(planner.learning_store, "learned_fixes_for", lambda issue, os_type: [])
    evidence = [("boot_performance", {}, {"ok": True, "summary": "Last start-up took 130 s", "data": {"last_boot_seconds": 130, "startup_programs": 3}})]
    asyncio.run(planner.run_diagnosis(session_id, "instant", preset_evidence=evidence))
    session = session_store.get_session(session_id)
    assert session["status"] == "diagnosed"
    assert [step["tool_id"] for step in session["steps"] if step["kind"] == "tool"] == ["boot_performance"]
    assert any(item["key"] == "boot_slow" for item in session["report"]["quick_findings"])
    assert 3 <= len(session["report"]["solutions"]) <= 4
    assert len(list((tmp_path / "decisions").rglob("*_performance_analysis_*.json"))) == 1


def test_changes_run_one_at_a_time_per_device(monkeypatch):
    target = Target("dev9", "Windows", "laptop")
    monkeypatch.setattr(main, "_spawn", lambda coroutine: coroutine.close())
    monkeypatch.setitem(main.software_jobs, "busy", {"job_id": "busy", "device_id": "dev9", "state": "running", "risk": "high", "action": "os-update", "name": "2 OS updates"})
    try:
        with pytest.raises(HTTPException) as busy:
            main._start_software_job(target, "update", "7-Zip", "update_software", {"package_id": "7zip.7zip"}, "medium")
        assert busy.value.status_code == 409 and "os-update of 2 OS updates" in busy.value.detail
        assert main._start_software_job(target, "scan", "Software inventory", "installed_software", {"check_updates": True}, "read")["state"] == "running"
        main.software_jobs["busy"]["state"] = "done"
        session_id = session_store.create_session("dev9", "laptop", "Windows", "printer stuck", None)
        session_store.update_session(session_id, status="fixing")  # an approved fix is running
        with pytest.raises(HTTPException) as fixing:
            main._start_software_job(target, "update", "7-Zip", "update_software", {"package_id": "7zip.7zip"}, "medium")
        assert "approved fix" in fixing.value.detail
    finally:
        for job_id in [job_id for job_id, job in main.software_jobs.items() if job["device_id"] == "dev9" and job_id != "busy"]:
            main.software_jobs.pop(job_id)


def test_the_server_container_offers_no_install_buttons(monkeypatch):
    monkeypatch.setenv("SENTINEL_IN_DOCKER", "1")
    target = Target("local", "Linux", "AIops server container")

    async def fake_execute(target, tool_id, args, max_risk, session_id=None):
        if tool_id == "os_updates":
            return {"ok": True, "summary": "apt: 1 update", "data": {"source": "apt", "can_install": True, "updates": [{"id": "vlc"}]}}
        return {"ok": True, "summary": "1 program", "data": {"software": [{"id": "vlc", "name": "vlc", "update_available": True, "update_id": "vlc"}]}}

    monkeypatch.setattr(main, "execute", fake_execute)
    job = {"sections": {"os_updates": {"tool_id": "os_updates", "args": {}, "state": "queued", "ok": None, "summary": None, "data": None},
                        "apps": {"tool_id": "installed_software", "args": {"check_updates": True}, "state": "queued", "ok": None, "summary": None, "data": None}}}
    asyncio.run(main._run_performance_check(job, target, "os_updates", "os_updates", {}))
    asyncio.run(main._run_performance_check(job, target, "apps", "installed_software", {"check_updates": True}))
    assert job["sections"]["os_updates"]["data"]["can_install"] is False and "Docker image" in job["sections"]["os_updates"]["data"]["install_note"]
    assert job["sections"]["apps"]["data"]["can_update"] is False
