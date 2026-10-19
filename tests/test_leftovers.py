import json
import os
import time

import pytest

from agent.toolkit import leftovers, software


@pytest.fixture(autouse=True)
def agent_data(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOPS_AGENT_DATA", str(tmp_path / "agent-data"))
    return tmp_path


def test_names_are_normalized_for_matching():
    assert leftovers.normalize("7-Zip 26.03 (x64)") == "7 zip"
    assert leftovers.normalize("Adobe Acrobat (64-bit)") == "adobe acrobat"
    names = leftovers.match_names({"name": "Docker Desktop", "install_location": "C:\\Program Files\\Docker\\Docker"})
    assert names == {"docker desktop", "docker"}
    # Generic names are never used for matching.
    assert leftovers.match_names({"name": "Updater"}) == set()
    assert software._uninstaller_dir('"C:\\Program Files\\7-Zip\\Uninstall.exe" /S') == "C:\\Program Files\\7-Zip"
    assert software._uninstaller_dir("MsiExec.exe /X{ABC}") is None


def _layout(tmp_path):
    program_files = tmp_path / "Program Files"
    appdata = tmp_path / "AppData"
    for folder in (program_files / "7-Zip", program_files / "Common Files", program_files / "7-Zip Helper",
                   appdata / "7-Zip", appdata / "Igor Pavlov" / "7-Zip", appdata / "Microsoft", appdata / "OtherApp"):
        folder.mkdir(parents=True)
    (appdata / "7-Zip" / "settings.ini").write_text("x")
    (tmp_path / "Desktop").mkdir()
    (tmp_path / "Desktop" / "7-Zip.lnk").write_text("lnk")
    return [(program_files, "Program Files", "high"), (appdata, "AppData Roaming", "medium"), (tmp_path / "Desktop", "Desktop", "medium")]


def test_leftover_scan_finds_the_program_and_skips_shared_and_other_programs(tmp_path):
    roots = _layout(tmp_path)
    others = {leftovers._norm_path(tmp_path / "Program Files" / "7-Zip Helper")}
    found = leftovers._path_candidates({"7 zip"}, "Igor Pavlov", others, roots)
    paths = {os.path.relpath(item["path"], tmp_path) for item in found}
    assert paths == {os.path.join("Program Files", "7-Zip"), os.path.join("AppData", "7-Zip"),
                     os.path.join("AppData", "Igor Pavlov", "7-Zip"), os.path.join("Desktop", "7-Zip.lnk")}
    by_path = {os.path.relpath(item["path"], tmp_path): item for item in found}
    assert by_path[os.path.join("Program Files", "7-Zip")]["confidence"] == "high"
    assert by_path[os.path.join("Desktop", "7-Zip.lnk")]["kind"] == "file"


def _scan(tmp_path, candidates):
    scan_id = "0123456789ab"
    for index, candidate in enumerate(candidates):
        candidate["id"] = f"c{index}"
    leftovers._write_json(leftovers._scans_dir() / f"{scan_id}.json", {"created": time.time(), "program": "7-Zip", "entry_id": "HKLM64|7-Zip", "candidates": candidates})
    return scan_id


def test_quarantine_moves_only_scanned_ids_and_restore_puts_everything_back(tmp_path):
    folder = tmp_path / "AppData" / "7-Zip"
    folder.mkdir(parents=True)
    (folder / "settings.ini").write_text("keep me")
    scan_id = _scan(tmp_path, [{"kind": "folder", "path": str(folder), "location": "AppData", "confidence": "high", "reason": "test"}])

    assert leftovers.quarantine_leftovers(scan_id, "c9")["ok"] is False  # not in the scan
    assert leftovers.quarantine_leftovers(scan_id, "../../etc")["ok"] is False  # not an id at all
    result = leftovers.quarantine_leftovers(scan_id, "c0")
    assert result["ok"] and not folder.exists()
    batch_id = result["data"]["batch_id"]
    listed = leftovers.list_quarantine()["data"]["batches"]
    assert listed[0]["batch_id"] == batch_id and listed[0]["items"] == 1
    # A scan is single-use.
    assert leftovers.quarantine_leftovers(scan_id, "c0")["ok"] is False

    restored = leftovers.restore_quarantine(batch_id)
    assert restored["ok"] and (folder / "settings.ini").read_text() == "keep me"
    assert leftovers.list_quarantine()["data"]["batches"] == []
    assert leftovers.restore_quarantine("../../x")["ok"] is False


def test_expired_scans_and_old_batches(tmp_path):
    scan_id = _scan(tmp_path, [{"kind": "folder", "path": str(tmp_path), "location": "x", "confidence": "high", "reason": "x"}])
    path = leftovers._scans_dir() / f"{scan_id}.json"
    data = json.loads(path.read_text())
    data["created"] -= leftovers.SCAN_TTL_SECONDS + 1
    path.write_text(json.dumps(data))
    assert "expired" in leftovers.quarantine_leftovers(scan_id, "c0")["summary"]

    old = leftovers._quarantine_dir() / "20260101-000000-abcdef"
    old.mkdir(parents=True)
    leftovers._write_json(old / "manifest.json", {"created": time.time() - 8 * 86400, "items": []})
    assert leftovers.purge_expired() == ["20260101-000000-abcdef"] and not old.exists()


def test_scan_refuses_programs_that_are_still_installed_or_never_recorded(monkeypatch):
    monkeypatch.setattr(leftovers, "os_name", lambda: "Windows")
    monkeypatch.setattr(software, "_windows_entry", lambda entry_id: {"name": "7-Zip"})
    assert "still installed" in leftovers.find_leftovers("HKLM64|7-Zip")["summary"]
    monkeypatch.setattr(software, "_windows_entry", lambda entry_id: None)
    assert "No uninstall of this program was recorded" in leftovers.find_leftovers("HKLM64|7-Zip")["summary"]


@pytest.mark.skipif(os.name != "nt", reason="registry round trip needs Windows")
def test_registry_leftover_is_exported_deleted_and_restored(tmp_path):
    import winreg

    key_path = "Software\\AIops Test App"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
        winreg.SetValueEx(key, "Setting", 0, winreg.REG_SZ, "value")
    try:
        scan_id = _scan(tmp_path, [{"kind": "registry", "path": f"HKCU\\{key_path}", "location": "Registry", "confidence": "high", "reason": "test"}])
        result = leftovers.quarantine_leftovers(scan_id, "c0")
        assert result["ok"]
        with pytest.raises(OSError):
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
        assert leftovers.restore_quarantine(result["data"]["batch_id"])["ok"]
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            assert winreg.QueryValueEx(key, "Setting")[0] == "value"
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        except OSError:
            pass


def test_storage_agent_and_folders_holding_another_program_are_never_offered(tmp_path, monkeypatch):
    program_files = tmp_path / "PF"
    (program_files / "7-Zip" / "plugins").mkdir(parents=True)
    storage = program_files / "Seven Zip"  # the agent's own data folder, even if it looked like the program
    storage.mkdir()
    monkeypatch.setenv("AIOPS_AGENT_DATA", str(storage))
    # Another installed program lives inside the 7-Zip folder: the 7-Zip folder must not be offered.
    others = {leftovers._norm_path(program_files / "7-Zip" / "plugins")}
    found = leftovers._path_candidates({"7 zip", "seven zip"}, None, others, [(program_files, "Program Files", "high")])
    assert found == []
    assert leftovers._norm_path(leftovers.agent_dir()) in leftovers._protected_paths()


def test_a_bare_first_word_folder_is_only_offered_beside_a_confident_match(tmp_path):
    alone, beside = tmp_path / "alone", tmp_path / "beside"
    (alone / "Docker").mkdir(parents=True)
    (beside / "Docker").mkdir(parents=True)
    (beside / "Docker Desktop").mkdir()
    found = leftovers._path_candidates({"docker desktop"}, "Docker Inc", set(), [(alone, "A", "medium"), (beside, "B", "medium")])
    paths = sorted(os.path.relpath(item["path"], tmp_path) for item in found)
    assert paths == [os.path.join("beside", "Docker"), os.path.join("beside", "Docker Desktop")]
    assert {item["confidence"] for item in found} == {"low", "medium"}


def test_restore_only_moves_files_that_live_inside_the_batch(tmp_path):
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("not ours")
    batch = leftovers._quarantine_dir() / "20261016-120000-abcdef"
    batch.mkdir(parents=True)
    leftovers._write_json(batch / "manifest.json", {"created": time.time(), "program": "x", "items": [
        {"id": "c0", "kind": "file", "original": str(tmp_path / "restored.txt"), "stored": str(outside), "ok": True, "restored": False}]})
    result = leftovers.restore_quarantine("20261016-120000-abcdef")
    assert result["ok"] is False and outside.exists() and not (tmp_path / "restored.txt").exists()


def test_partial_failures_are_reported_and_cross_drive_links_are_refused(tmp_path, monkeypatch):
    first, second, linked = tmp_path / "A" / "App", tmp_path / "B" / "App", tmp_path / "C" / "App"
    for folder in (first, second, linked):
        folder.mkdir(parents=True)
    scan_id = _scan(tmp_path, [{"kind": "folder", "path": str(path), "location": "x", "confidence": "high", "reason": "x"} for path in (first, second, linked)])
    real_move = leftovers.shutil.move

    def flaky_move(source, destination):
        if source == str(second):
            raise PermissionError("in use")
        return real_move(source, destination)

    monkeypatch.setattr(leftovers.shutil, "move", flaky_move)
    monkeypatch.setattr(leftovers, "_has_links", lambda path: path == str(linked))  # on any drive
    result = leftovers.quarantine_leftovers(scan_id, "c0,c1,c2")
    assert result["ok"] and result["data"]["moved"] == 1
    errors = {item["id"]: item["error"] for item in result["data"]["failed"]}
    assert "in use" in errors["c1"] and "junction" in errors["c2"]
    assert not first.exists() and second.exists() and linked.exists()


def test_linux_leftovers_match_the_package_name_exactly(tmp_path):
    home, etc = tmp_path / "home" / "ana", tmp_path / "etc"
    (home / ".config" / "vlc").mkdir(parents=True)
    (home / ".config" / "vlc-extra").mkdir(parents=True)
    (etc / "vlc").mkdir(parents=True)
    found = leftovers._linux_candidates("vlc", homes=[home], bases=[etc])
    assert sorted(item["path"] for item in found) == sorted([str(home / ".config" / "vlc"), str(etc / "vlc")])


@pytest.mark.skipif(os.name != "nt", reason="registry needs Windows")
def test_registry_publisher_product_keys_are_found(monkeypatch):
    import winreg

    monkeypatch.setattr(leftovers, "_registry_roots", lambda: [("HKCU", winreg.HKEY_CURRENT_USER, "Software", 0)])
    path = r"Software\Contoso Labs\Contoso TestApp"
    winreg.CloseKey(winreg.CreateKey(winreg.HKEY_CURRENT_USER, path))
    try:
        found = leftovers._registry_candidates({"contoso testapp"}, "Contoso Labs")
        assert r"HKCU\Software\Contoso Labs\Contoso TestApp" in {item["path"] for item in found}
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\Contoso Labs")


def test_restore_refuses_an_item_that_now_contains_a_link(tmp_path, monkeypatch):
    stored_dir = leftovers._quarantine_dir() / "20261016-130000-abcdef"
    (stored_dir / "c0_App").mkdir(parents=True)
    leftovers._write_json(stored_dir / "manifest.json", {"created": time.time(), "program": "x", "items": [
        {"id": "c0", "kind": "folder", "original": str(tmp_path / "App"), "stored": str(stored_dir / "c0_App"), "ok": True, "restored": False}]})
    monkeypatch.setattr(leftovers, "_has_links", lambda path: True)  # e.g. a junction planted after quarantine
    result = leftovers.restore_quarantine("20261016-130000-abcdef")
    assert result["ok"] is False and "junction" in result["data"]["failed"][0]["error"] and not (tmp_path / "App").exists()


@pytest.mark.skipif(os.name != "nt", reason="junctions are a Windows feature")
def test_a_real_junction_is_seen_as_a_link(tmp_path):
    import subprocess

    target, folder = tmp_path / "target", tmp_path / "leftover"
    target.mkdir()
    folder.mkdir()
    subprocess.run(["cmd", "/c", "mklink", "/J", str(folder / "j"), str(target)], check=True, capture_output=True)
    assert leftovers._is_link(folder / "j") and leftovers._has_links(str(folder)) and not leftovers._has_links(str(target))


def test_only_manifests_and_scans_the_agent_wrote_are_trusted(tmp_path, monkeypatch):
    batch = leftovers._quarantine_dir() / "20261016-140000-abcdef"
    batch.mkdir(parents=True)
    leftovers._write_json(batch / "manifest.json", {"created": time.time(), "program": "Old App", "items": []})
    assert leftovers._written_by_agent(batch / "manifest.json")  # written by the account the agent runs as
    assert [item["batch_id"] for item in leftovers.list_quarantine()["data"]["batches"]] == ["20261016-140000-abcdef"]

    # Planted by another user: neither listed nor restorable.
    monkeypatch.setattr(leftovers, "_owner", lambda path: "S-1-5-21-1-2-3-1001" if str(path).endswith("manifest.json") else "S-1-5-18")
    assert not leftovers._written_by_agent(batch / "manifest.json")
    assert leftovers.list_quarantine()["data"]["batches"] == []
    assert leftovers.restore_quarantine("20261016-140000-abcdef")["ok"] is False


def test_a_folder_on_another_drive_is_not_copied_into_quarantine(tmp_path, monkeypatch):
    folder = tmp_path / "D-drive" / "App"
    folder.mkdir(parents=True)
    scan_id = _scan(tmp_path, [{"kind": "folder", "path": str(folder), "location": "x", "confidence": "high", "reason": "x"}])
    monkeypatch.setattr(leftovers, "_same_volume", lambda first, second: False)
    result = leftovers.quarantine_leftovers(scan_id, "c0")
    assert "another drive" in result["data"]["failed"][0]["error"] and folder.exists()
