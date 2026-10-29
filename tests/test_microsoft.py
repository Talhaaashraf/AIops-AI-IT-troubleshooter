"""Microsoft product removal on the agent: listing, Office cleanup with a full backup, Store apps, the install fix."""

import json
from pathlib import Path

import pytest

from agent.toolkit import get_tool, leftovers, microsoft, software


@pytest.fixture
def agent_data(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOPS_AGENT_DATA", str(tmp_path / "agent-data"))
    (tmp_path / "agent-data").mkdir()
    monkeypatch.setattr(microsoft, "os_name", lambda: "Windows")
    return tmp_path


OFFICE_ENTRY = {"id": "HKLM64|Office16.STANDARD", "name": "Microsoft Office Standard 2016", "version": "16.0.4266.1001",
                "publisher": "Microsoft Corporation", "size_mb": 2000, "uninstall_method": "msi", "can_uninstall": True,
                "_uninstall": '"C:\\...\\Office Setup Controller\\setup.exe" /uninstall STANDARD', "_quiet": "", "_install_location": None, "_uninstall_dir": None}
EDGE_ENTRY = {"id": "HKLM32|Microsoft Edge", "name": "Microsoft Edge", "version": "156.0", "publisher": "Microsoft Corporation",
              "uninstall_method": None, "can_uninstall": False, "_uninstall": "", "_quiet": "", "_install_location": None, "_uninstall_dir": None}
VLC_ENTRY = {"id": "HKLM64|VLC", "name": "VLC media player", "version": "3.0", "publisher": "VideoLAN",
             "uninstall_method": "inno", "can_uninstall": True, "_uninstall": "", "_quiet": "", "_install_location": None, "_uninstall_dir": None}


def test_listing_separates_office_programs_and_store_apps(agent_data, monkeypatch):
    monkeypatch.setattr(software, "_windows_inventory", lambda: [OFFICE_ENTRY, EDGE_ENTRY, VLC_ENTRY])
    monkeypatch.setattr(microsoft, "_store_apps", lambda: [{"id": "appx|Microsoft.BingNews_1_x64__8wekyb3d8bbwe", "name": "Microsoft.BingNews",
                        "version": "1", "publisher": "Store", "size_mb": None, "kind": "appx", "install_type": "Microsoft Store (Appx)",
                        "remove_kind": "appx", "restorable": False, "note": "", "can_remove": True}])
    monkeypatch.setattr(microsoft, "_clicktorun_state", lambda: {"service": False, "config": True, "running": False})
    monkeypatch.setattr(microsoft, "_install_blocker", lambda: {"installer_in_progress": True, "clicktorun_running": False, "reboot_pending": False, "msiexec_count": 0})
    monkeypatch.setattr(microsoft, "_scrubber_path", lambda: None)

    result = microsoft.microsoft_products()
    products = {item["id"]: item for item in result["data"]["products"]}
    assert "office|2016" in products and products["office|2016"]["install_type"].startswith("MSI")
    assert products["office|2016"]["remove_kind"] == "office" and products["office|2016"]["restorable"] is True
    assert "appx|Microsoft.BingNews_1_x64__8wekyb3d8bbwe" in products
    assert "HKLM64|VLC" not in products  # VideoLAN is not a Microsoft product
    assert products["HKLM32|Microsoft Edge"]["can_remove"] is False  # Edge has no silent uninstaller: not removed
    assert result["data"]["blocker"]["installer_in_progress"] is True and "blocked" in result["summary"]


def test_office_version_is_detected_for_the_scrubber():
    assert microsoft._office_version({"name": "Microsoft 365 Apps for enterprise", "version": "16.0.1"}) == "M365"
    assert microsoft._office_version({"name": "Microsoft Office Standard 2016", "version": "16.0.4266"}) == "2016"
    assert microsoft._office_version({"name": "Microsoft Office Professional Plus 2013", "version": "15.0.1"}) == "2013"


def _office_env(tmp_path, monkeypatch, scrubber=False):
    """A fake Office install on disk: folders, a backup-able registry key, a scheduled task."""
    office = tmp_path / "Program Files" / "Microsoft Office"
    office.mkdir(parents=True)
    (office / "root").mkdir()
    (office / "root" / "licensing.dll").write_text("x")
    monkeypatch.setattr(microsoft, "OFFICE_FOLDERS", (str(office),))
    monkeypatch.setattr(microsoft, "OFFICE_FILES", ())
    monkeypatch.setattr(microsoft, "OFFICE_REG_KEYS", (r"HKCU\Software\AIopsTest\Office",))
    monkeypatch.setattr(microsoft, "_scrubber_path", lambda: "C:\\tools\\GetHelpCmd.exe" if scrubber else None)
    # No real Office entries to uninstall, no real services, one fake task.
    monkeypatch.setattr(software, "_windows_inventory", lambda: [])
    monkeypatch.setattr(microsoft, "_delete_office_services", lambda backup: [])

    def fake_tasks(backup):
        backup.task_xml("\\Microsoft\\Office\\FakeTask", "<Task/>")
        return ["\\Microsoft\\Office\\FakeTask"]

    monkeypatch.setattr(microsoft, "_delete_office_tasks", fake_tasks)
    return office


def test_manual_office_removal_backs_everything_up_before_deleting(agent_data, monkeypatch):
    office = _office_env(agent_data, monkeypatch)
    reg_calls = []

    def fake_reg(*args, timeout=60):
        reg_calls.append(args)
        if args[0] == "query":
            return True, ""  # the key "exists" so it is backed up
        if args[0] == "export":
            Path(args[2]).write_text("Windows Registry Editor Version 5.00\n")
            return True, ""
        if args[0] == "delete":
            return True, ""
        return False, "?"

    monkeypatch.setattr(leftovers, "_reg", fake_reg)
    result = microsoft.remove_office("2016")
    assert result["ok"] and result["changed"] and result["data"]["method"] == "manual cleanup"
    # The folder was moved into the quarantine, not deleted outright.
    assert not office.exists()
    batches = list((Path(agent_data, "agent-data", "quarantine")).glob("*/manifest.json"))
    assert len(batches) == 1
    manifest = json.loads(batches[0].read_text())
    assert manifest["program"].startswith("Microsoft Office")
    kinds = [item["kind"] for item in manifest["items"]]
    assert "registry" in kinds and "folder" in kinds
    assert manifest["tasks_backed_up"][0]["task"] == "\\Microsoft\\Office\\FakeTask"
    # Export happened before delete for the registry key.
    order = [call[0] for call in reg_calls]
    assert order.index("export") < order.index("delete")
    # The Software tab's Restore puts the Office folder back.
    restored = leftovers.restore_quarantine(manifest["batch_id"])
    assert restored["ok"] and office.exists() and (office / "root" / "licensing.dll").exists()


def test_the_scrubber_is_used_when_present_and_registry_is_still_backed_up(agent_data, monkeypatch):
    _office_env(agent_data, monkeypatch, scrubber=True)
    monkeypatch.setattr(leftovers, "_reg", lambda *a, timeout=60: (True, Path(a[2]).write_text("reg") if a[0] == "export" else "") if a[0] in ("query", "export") else (True, ""))
    ran = {}

    def fake_run(command, timeout):
        ran["cmd"] = command
        return (0, "00: Successfully completed this scenario.", "")

    monkeypatch.setattr(microsoft, "_run", fake_run)
    result = microsoft.remove_office("2016")
    assert ran["cmd"] == ["C:\\tools\\GetHelpCmd.exe", "-S", "OfficeScrubScenario", "-AcceptEula", "-OfficeVersion", "2016"]
    assert result["ok"] and result["data"]["method"] == "Microsoft scrubber" and result["data"]["exit_code"] == 0
    assert "backed up" in result["summary"]
    # The exit code is turned into a readable verdict.
    monkeypatch.setattr(microsoft, "_run", lambda command, timeout: (6, "06: Office programs are running.", ""))
    busy = microsoft.remove_office("2016")
    assert busy["ok"] is False and "Close all open Office" in busy["summary"]


def test_remove_microsoft_dispatches_by_id(agent_data, monkeypatch):
    seen = {}

    def record(key, value, result=None):
        seen[key] = value
        return result if result is not None else {"ok": True}

    monkeypatch.setattr(microsoft, "remove_office", lambda version: record("office", version))
    monkeypatch.setattr(microsoft, "remove_appx", lambda full: record("appx", full))
    monkeypatch.setattr(software, "_windows_uninstall", lambda id: record("program", id, {"ok": True, "data": {}}))
    microsoft.remove_microsoft("office|M365")
    microsoft.remove_microsoft("appx|Microsoft.BingNews_1_x64__8wekyb3d8bbwe")
    microsoft.remove_microsoft("HKLM64|{guid}")
    assert seen == {"office": "M365", "appx": "Microsoft.BingNews_1_x64__8wekyb3d8bbwe", "program": "HKLM64|{guid}"}


def test_remove_appx_refuses_protected_packages(agent_data, monkeypatch):
    assert microsoft.remove_appx("Microsoft.VCLibs.140.00_14_x64__8wekyb3d8bbwe")["ok"] is False
    assert "depends on it" in microsoft.remove_appx("Microsoft.WindowsStore_1_x64__8wekyb3d8bbwe")["summary"]
    assert microsoft.remove_appx("not a package")["ok"] is False


def test_remove_appx_removes_and_deprovisions(agent_data, monkeypatch):
    monkeypatch.setattr("agent.toolkit.updates._powershell_json", lambda script, timeout: {"remove": "removed", "provision": "deprovisioned", "still_installed": False})
    result = microsoft.remove_appx("Microsoft.BingNews_1.0.0.0_x64__8wekyb3d8bbwe")
    assert result["ok"] and result["changed"] and "all users" in result["summary"]
    monkeypatch.setattr("agent.toolkit.updates._powershell_json", lambda script, timeout: {"remove": "keep: access denied", "still_installed": True})
    assert microsoft.remove_appx("Microsoft.BingNews_1.0.0.0_x64__8wekyb3d8bbwe")["ok"] is False


def test_fix_install_blocker_clears_the_stale_marker(agent_data, monkeypatch):
    state = {"in_progress": True}
    monkeypatch.setattr(microsoft, "_install_blocker", lambda: {"installer_in_progress": state["in_progress"], "clicktorun_running": False, "reboot_pending": False, "msiexec_count": 0})

    def fake_reg(*args, timeout=60):
        if args[0] == "query":
            return state["in_progress"], ""
        if args[0] == "export":
            Path(args[2]).write_text("reg")
            return True, ""
        if args[0] == "delete":
            state["in_progress"] = False
            return True, ""
        return False, "?"

    monkeypatch.setattr(leftovers, "_reg", fake_reg)
    monkeypatch.setattr(microsoft, "_run", lambda command, timeout: (0, "", ""))
    monkeypatch.setattr(microsoft, "_service_exists", lambda name: False)
    result = microsoft.fix_install_blocker()
    assert result["ok"] and result["changed"]
    assert "cleared the stale" in " ".join(result["data"]["actions"])
    assert result["data"]["after"]["installer_in_progress"] is False
    assert "cleared" in result["summary"].lower()


def test_the_tools_are_registered_with_the_right_risk():
    assert get_tool("microsoft_products").risk == "read" and not get_tool("microsoft_products").ai_visible
    assert get_tool("remove_microsoft").risk == "high" and not get_tool("remove_microsoft").ai_visible
    assert get_tool("fix_install_blocker").risk == "medium"
