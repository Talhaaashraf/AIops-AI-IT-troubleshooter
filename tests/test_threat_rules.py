"""Threat findings: categories, severity from the evidence, proof and path, the action path, approvable actions."""

from datetime import datetime, timezone

from backend import threat_rules

SHA = "7C9FBECC1C81CF501709029B0DF80A201519ACD6445FCC66EA66108919120E20"
KASPERSKY_ON = [{"name": "Windows Defender", "enabled": False}, {"name": "Kaspersky Endpoint Security for Windows", "enabled": True}]


def iso_item(**changes):
    item = {"id": "d0", "kind": "malware", "source": "Kaspersky Endpoint Security", "event_ids": [302], "count": 606,
            "path": "C:\\Users\\alice\\Downloads\\kali-linux-installer-amd64.iso", "on_disk": True, "size": 4_000_000_000, "running": [],
            "objects": ["ISO9660 > data.tar//./usr/bin/vncviewer.exe"], "threats": [{"name": "HEUR:Backdoor.Win32.Poison.gen", "count": 606}],
            "results": {"Detected": 606}, "first_seen": "2026-10-20T13:28:45+00:00", "last_seen": "2026-10-20T14:25:52+00:00",
            "fields": {"Threat": "HEUR:Backdoor.Win32.Poison.gen", "Result": "Detected", "Type": "Trojan", "Detected by": "Kaspersky Endpoint Security (Malware Scan)",
                       "Threat level": "Heuristic analysis", "User": "CORP\\alice (Initiator)", "SHA256": SHA}}
    item.update(changes)
    return item


def analyse(*items, antivirus=KASPERSKY_ON, **data):
    return threat_rules.analyze_threats({"scan_id": "abc123abc123", "platform": "Windows", "antivirus": antivirus, "items": list(items),
                                         "sources": [{"name": "Kaspersky Endpoint Security", "available": True}], **data}, "Windows")


def one(analysis):
    assert len(analysis["findings"]) == 1, analysis["findings"]
    return analysis["findings"][0]


def test_a_heuristic_hit_in_an_iso_is_high_with_proof_path_steps_and_actions():
    finding = one(analyse(iso_item()))
    assert finding["id"] == "T1" and finding["category"] == "malware" and finding["severity"] == "high" and finding["status"] == "active"
    assert finding["title"] == "HEUR:Backdoor.Win32.Poison.gen in kali-linux-installer-amd64.iso"
    assert "606 objects in this one file" in finding["summary"] and "Heuristic" in finding["summary"]
    assert [item["label"] for item in finding["proof"]][:4] == ["Threat", "Type", "Result", "Detected by"]
    assert {"label": "SHA256", "value": SHA} in finding["proof"] and finding["path"].endswith(".iso")
    assert [action["action"] for action in finding["actions"]] == ["rescan", "quarantine", "delete"]
    assert finding["actions"][-1]["confirm"] == "kali-linux-installer-amd64.iso"
    steps = [step["text"] for step in finding["steps"]]
    assert steps[0].startswith("Do not open") and any("Kaspersky exclusion" in step for step in steps)
    assert [step["action"] for step in finding["steps"] if step["action"]] == ["rescan", "quarantine", "delete"]
    assert [link["label"] for link in finding["lookups"]] == ["Kaspersky OpenTIP", "VirusTotal"] and SHA in finding["lookups"][0]["url"]
    malware = next(category for category in analyse(iso_item())["categories"] if category["id"] == "malware")
    assert malware == {**malware, "count": 1, "open": 1, "severity": "high"}


def test_a_running_detection_is_critical_and_offers_to_end_the_process():
    finding = one(analyse(iso_item(path="C:\\Users\\alice\\AppData\\evil.exe", objects=[], count=1, running=[{"pid": 4242, "name": "evil.exe"}],
                                   threats=[{"name": "Trojan.Win32.Agent.xyz", "count": 1}], fields={"Threat": "Trojan.Win32.Agent.xyz", "Result": "Detected"})))
    assert finding["severity"] == "critical"
    kill = next(action for action in finding["actions"] if action["action"] == "kill")
    assert kill["pid"] == 4242 and kill["name"] == "evil.exe" and finding["steps"][1]["action"] == "kill"


def test_a_file_the_antivirus_removed_is_low_and_offers_no_action():
    finding = one(analyse(iso_item(on_disk=False, results={"Deleted": 1}, fields={"Threat": "EICAR-Test-File", "Result": "Deleted"})))
    assert finding["severity"] == "low" and finding["status"] == "neutralised" and finding["actions"] == []
    assert "removed by the antivirus" in finding["summary"]


def test_defender_switched_off_by_kaspersky_is_not_a_threat():
    item = {"id": "d1", "kind": "av_disabled", "source": "Microsoft Defender", "count": 1, "fields": {"Event": "Microsoft Defender real-time protection was turned off"}}
    assert analyse(item)["findings"] == []
    finding = one(analyse(item, antivirus=[{"name": "Windows Defender", "enabled": False}]))
    assert finding["severity"] == "critical" and finding["category"] == "tampering"


def test_failed_sign_ins_are_rated_by_their_busiest_hour():
    def logon(peak):
        return {"id": "d2", "kind": "failed_logon", "source": "Windows Security log", "count": peak, "peak_per_hour": peak,
                "fields": {"Account": "PC1\\admin", "Source address": "203.0.113.9", "Logon type": "remote desktop (RDP)"}}
    assert [one(analyse(logon(peak)))["severity"] for peak in (12, 6, 2)] == ["high", "medium", "low"]
    steps = " ".join(step["text"] for step in one(analyse(logon(12)))["steps"])
    assert "block it in the firewall" in steps and "Remote Desktop" in steps and one(analyse(logon(12)))["category"] == "sign_ins"


def test_account_persistence_and_tampering_rules():
    admins = {"id": "d3", "kind": "group_member_added", "source": "Windows Security log", "count": 1, "fields": {"Member": "bob", "Group": "Administrators", "Added by": "alice"}}
    users = {**admins, "fields": {"Member": "bob", "Group": "Users"}}
    assert one(analyse(admins))["severity"] == "high" and one(analyse(users))["severity"] == "low"
    assert 'net localgroup "Administrators" "bob" /delete' in one(analyse(admins))["steps"][1]["text"]
    service = {"id": "d4", "kind": "service_installed", "source": "Windows System log", "count": 1, "fields": {"Service": "updsvc", "Program": "C:\\Users\\alice\\AppData\\Roaming\\upd.exe"}}
    signed = {**service, "fields": {"Service": "Spooler2", "Program": "C:\\Program Files\\Vendor\\svc.exe"}}
    assert one(analyse(service))["severity"] == "high" and one(analyse(signed))["severity"] == "low"
    cleared = {"id": "d5", "kind": "log_cleared", "source": "Windows Security log", "count": 1, "fields": {"Log": "Security", "Cleared by": "alice"}}
    assert one(analyse(cleared))["severity"] == "critical"
    reports = {"id": "d6", "kind": "av_report_cleared", "source": "Kaspersky Endpoint Security", "count": 1549, "fields": {"Reports": "Backup", "Cleared by": "CORP\\alice"}}
    finding = one(analyse(reports))
    assert finding["severity"] == "medium" and finding["category"] == "tampering" and "earlier detections can no longer be seen" in finding["summary"]
    powershell = {"id": "d7", "kind": "powershell_suspicious", "source": "PowerShell", "count": 1, "fields": {"Attack signs": "Net.WebClient, DownloadFile"}}
    assert one(analyse(powershell))["severity"] == "high"
    agent = {"id": "d8", "kind": "av_health", "source": "Kaspersky Network Agent", "count": 1417, "fields": {"Component": "Kaspersky Network Agent", "Message": "Transport error"}}
    assert one(analyse(agent))["severity"] == "medium" and one(analyse(agent))["category"] == "av_health"


def test_old_kaspersky_databases_are_a_finding():
    now = datetime(2026, 11, 5, tzinfo=timezone.utc)
    analysis = threat_rules.analyze_threats({"items": [], "platform": "Windows", "kaspersky_db_date": "10/20/2026 6:04:00 PM"}, "Windows", now=now)
    assert one(analysis)["title"] == "Kaspersky databases are 15 days old"


def test_marks_keep_across_scans_and_findings_are_ordered_by_category():
    item = iso_item()
    key = threat_rules.dedup_key(item)
    assert key == threat_rules.dedup_key(iso_item(count=700, id="d3"))  # the same file in the next scan
    logon = {"id": "d1", "kind": "failed_logon", "source": "Windows Security log", "count": 3, "peak_per_hour": 3, "fields": {"Account": "x", "Source address": "1.2.3.4"}}
    analysis = threat_rules.analyze_threats({"items": [logon, item], "platform": "Windows", "antivirus": KASPERSKY_ON}, "Windows",
                                            marks={key: {"status": "false_positive", "note": "pentest ISO"}})
    malware, sign_in = analysis["findings"]
    assert malware["category"] == "malware" and sign_in["category"] == "sign_ins"
    assert malware["status"] == "false_positive" and malware["mark_note"] == "pentest ISO" and malware["actions"]  # still actionable
    assert next(category for category in analysis["categories"] if category["id"] == "malware")["open"] == 0


def test_the_chat_understands_english_and_roman_urdu_and_only_proposes_offered_actions():
    analysis = analyse(iso_item(), {"id": "d1", "kind": "failed_logon", "source": "Windows Security log", "count": 3, "peak_per_hour": 3, "fields": {"Account": "x"}})
    assert threat_rules.parse_request("T1 ko quarantine karo", analysis) == ("T1", "quarantine")
    assert threat_rules.parse_request("please rescan it", analysis) == ("T1", "rescan")  # the only finding with actions
    assert threat_rules.parse_request("T2 delete kar do", analysis) == ("T2", "delete")
    assert threat_rules.parse_request("is this file dangerous?", analysis) == ("T1", None)
    card = threat_rules.proposal(analysis, "t1", "delete")
    assert card["finding_id"] == "T1" and card["confirm"] == "kali-linux-installer-amd64.iso" and card["risk"] == "high"
    assert threat_rules.proposal(analysis, "T2", "delete") is None  # a sign-in has no file to delete
    assert threat_rules.proposal(analysis, "T9", "rescan") is None and threat_rules.proposal(analysis, "T1", "format") is None


def test_the_rules_explain_the_findings_without_ai():
    result = threat_rules.rules_explanation(analyse(iso_item()))
    assert result["summary"].startswith("1 open finding(s): 1 high") and result["priorities"][0]["finding_id"] == "T1"
    assert threat_rules.rules_explanation(analyse())["summary"].startswith("No open threat findings")
    text = threat_rules.finding_text(one(analyse(iso_item())))
    assert text.startswith("T1 [high, active] Malware detected:") and "Approvable actions: rescan, quarantine, delete" in text
