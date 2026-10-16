import asyncio

import pytest

from agent.toolkit import software
from backend import device_store, health_report, software_store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    for module in (device_store, software_store):
        monkeypatch.setattr(module, "DB_PATH", tmp_path / "test.db")


def _report(**overrides):
    report = {
        "system": {"os_name": "Windows", "os_release": "11", "hostname": "laptop"},
        "cpu": {"total_usage_percent": 40.0, "logical_cores": 12},
        "memory": {"ram": {"usage_percent": 50.0, "total": "16 GB"}, "swap": {"usage_percent": 10.0}},
        "disk": [{"mountpoint": "C:\\", "usage_percent": 60.0, "free": "90 GB", "total": "236 GB"}],
        "top_processes": {"top_by_cpu": [], "top_by_memory": []},
        "security": {"firewall": {"available": True, "enabled": True}, "antivirus": {"available": True, "enabled": True}},
    }
    report.update(overrides)
    return report


def test_healthy_snapshot_scores_100():
    result = health_report.build(_report())
    assert result["issues"] == [] and result["score"] == 100 and result["rating"] == "good"
    assert result["details"]["system"]["Hostname"] == "laptop"


def test_issues_name_the_culprit_processes_and_lower_the_score():
    result = health_report.build(_report(
        memory={"ram": {"usage_percent": 91.2}, "swap": {"usage_percent": 70.0}},
        top_processes={"top_by_cpu": [], "top_by_memory": [{"name": "vmmemWSL", "memory_percent": 15.6}]},
        security={"antivirus": {"available": True, "enabled": False}},
    ))
    titles = [item["title"] for item in result["issues"]]
    assert result["issues"][0]["severity"] == "critical"  # antivirus off sorts first
    assert any("RAM usage is 91.2%" in title for title in titles)
    assert any("vmmemWSL (15.6%)" in title for title in titles)
    assert any("swap is 70.0% used" in title for title in titles)
    assert result["score"] < 60 and result["rating"] in ("poor", "critical")


WINGET_OUTPUT = (
    "   - \r   \\ \r"
    "Name                   Id                     Version   Available Source\n"
    "-----------------------------------------------------------------------\n"
    "7-Zip 26.03 (x64)      7zip.7zip              26.03     26.04     winget\n"
    "Docker Desktop         Docker.DockerDesktop   4.76.0    4.95.0    winget\n"
    "2 upgrades available.\n"
)


def test_winget_table_is_parsed_by_column_positions():
    rows = software.parse_winget_table(WINGET_OUTPUT)
    assert [(row["Name"], row["Id"], row["Version"], row["Available"]) for row in rows] == [
        ("7-Zip 26.03 (x64)", "7zip.7zip", "26.03", "26.04"),
        ("Docker Desktop", "Docker.DockerDesktop", "4.76.0", "4.95.0"),
    ]


def test_uninstall_method_comes_from_the_registry_entry():
    guid = "{12345678-1234-1234-1234-123456789ABC}"
    msi = software._windows_entry_from_values("HKLM64", guid, {"DisplayName": "Tool", "UninstallString": f"MsiExec.exe /X{guid}", "WindowsInstaller": 1})
    quiet = software._windows_entry_from_values("HKLM64", "App", {"DisplayName": "App", "UninstallString": "u.exe", "QuietUninstallString": "u.exe /S"})
    inno = software._windows_entry_from_values("HKLM32", "X_is1", {"DisplayName": "X", "UninstallString": r'"C:\X\unins000.exe"'})
    manual = software._windows_entry_from_values("HKLM64", "Y", {"DisplayName": "Y", "UninstallString": r"C:\Y\setup.exe /remove"})
    agent = software._windows_entry_from_values("HKLM64", "A", {"DisplayName": "AIops Agent", "QuietUninstallString": "x /S"})
    hidden = software._windows_entry_from_values("HKLM64", "Z", {"DisplayName": "Z", "UninstallString": "z", "SystemComponent": 1})
    assert (msi["uninstall_method"], quiet["uninstall_method"], inno["uninstall_method"]) == ("msi", "quiet", "inno")
    assert manual["can_uninstall"] is False and agent["can_uninstall"] is False and hidden is None
    assert msi["id"] == f"HKLM64|{guid}" and "_quiet" not in software._public(dict(quiet))


def test_linux_refuses_protected_and_invalid_packages():
    assert software._linux_package_action("remove", "python3")["ok"] is False
    assert "Invalid" in software._linux_package_action("remove", "vim; rm -rf /")["summary"]
    assert software.PROTECTED_WINGET_IDS.match("Microsoft.AppInstaller") and not software.PROTECTED_WINGET_IDS.match("7zip.7zip")


def test_inventory_store_tracks_uninstalls_and_updates():
    software_store.save_inventory("dev1", {"software": [
        {"id": "a", "name": "A", "version": "1", "update_available": True, "available_version": "2", "update_id": "Vendor.A"},
        {"id": "b", "name": "B", "version": "1", "update_available": False},
    ], "count": 2, "updates_available": 1})
    software_store.mark_updated("dev1", "Vendor.A")
    software_store.mark_uninstalled("dev1", "b")
    inventory = software_store.get_inventory("dev1")
    assert inventory["count"] == 1 and inventory["updates_available"] == 0
    assert inventory["software"][0]["version"] == "2" and inventory["collected_at"]


def test_onboarding_is_claimed_once_per_device():
    device = device_store.register_device("y" * 43, "pc-1", "Windows", allow_open=True)
    assert device_store.claim_onboarding(device["device_id"], "starting") is True
    assert device_store.claim_onboarding(device["device_id"], "starting") is False
    device_store.set_onboarding_session(device["device_id"], "session-1")
    assert device_store.get_device(device["device_id"])["onboarding_session_id"] == "session-1"


def test_old_agent_gets_an_actionable_message(monkeypatch):
    from backend import main
    from backend.agent_brain.executor import Target

    async def old_agent(target, tool_id, args, max_risk, session_id=None):
        return {"ok": False, "summary": f"Unknown or disallowed tool: {tool_id}"}

    monkeypatch.setattr(main, "execute", old_agent)
    job = {"job_id": "j1", "action": "scan", "name": "Software inventory", "state": "running"}
    asyncio.run(main._run_software_job(job, Target("dev1", "Windows", "pc-1"), "installed_software", {"check_updates": True}, "read"))
    assert job["state"] == "failed" and job["summary"] == main.OLD_AGENT_MESSAGE


def test_noisy_alerts_are_merged_and_scoring_decays():
    report = _report(
        network={"interfaces": [{"name": name, "status": "DOWN", "ipv4_addresses": ["169.254.1.1"]} for name in ("Ethernet", "Local Area Connection* 9", "Local Area Connection* 10")]},
        security={"listening_ports": {"ports": [{"port": 445, "address": "0.0.0.0", "process": "System"}, {"port": 445, "address": "::", "process": "System"}]}},
    )
    titles = [item["title"] for item in health_report.detect_issues(report)]
    assert titles == ["SMB port 445 is listening on 0.0.0.0, :: (System)", "3 network adapter(s) are down but keep an IP configuration: Ethernet, Local Area Connection* 9, Local Area Connection* 10"]
    # high (15) + low (3 x 0.75): two issues no longer cost the full sum of their penalties
    assert health_report.score(health_report.detect_issues(report)) == (83, "fair")


def test_onboarding_cut_short_by_a_restart_runs_again_once(monkeypatch):
    from backend import main

    started = []
    monkeypatch.setattr(main, "start_onboarding_check", lambda device_id: started.append(device_id) or "new-session")
    monkeypatch.setattr(main.session_store, "get_session", lambda session_id, include_steps=False: {"status": "failed", "error": "Interrupted by a server restart"})
    monkeypatch.setattr(main, "onboarding_rechecked", set())
    device = {"device_id": "dev1", "onboarding_session_id": "old-session"}

    main._ensure_onboarding(device)
    main._ensure_onboarding(device)  # later reports do not check again

    assert started == ["dev1"]


def test_idle_process_is_not_reported_as_a_cpu_user():
    report = _report(cpu={"total_usage_percent": 95.0}, top_processes={"top_by_cpu": [
        {"pid": 0, "name": "System Idle Process", "cpu_percent": 904.7}, {"pid": 42, "name": "chrome.exe", "cpu_percent": 120.0}], "top_by_memory": []})
    result = health_report.build(report)
    assert [item["name"] for item in result["details"]["top_cpu"]] == ["chrome.exe"]
    assert any("chrome.exe (120.0%)" in item["title"] and "Idle" not in item["title"] for item in result["issues"] if item["category"] == "CPU")


def test_event_log_timeout_is_not_reported_as_a_clean_log(monkeypatch):
    from agent.toolkit import event_logs

    monkeypatch.setattr(event_logs, "_run", lambda command, timeout=None: None)  # timed out
    result = event_logs._collect_windows()
    assert result["available"] is False and "timed out" in result["detail"]
    monkeypatch.setattr(event_logs, "_run", lambda command, timeout=None: "")  # genuinely empty
    assert event_logs._collect_windows()["available"] is True
