"""A device's threat_scan (agent/toolkit/threats.py) as categorised findings T1..Tn: each one with its proof (the
real event fields), the file's path, a suggested action path (ordered steps) and the actions a person may approve.

Rules only, no AI: what a finding is, how severe it is and which actions it offers come from the evidence. The
AI explains findings and drafts proposals in the action chat, but a proposal is checked against `actions` here
and nothing runs until a person approves it.
"""

import os
import re
from datetime import datetime, timezone

SEVERITIES = ("info", "low", "medium", "high", "critical")
CATEGORIES = (
    ("malware", "Malware detected", "Files the antivirus flagged, grouped by file (detections inside one archive or ISO are one finding)."),
    ("sign_ins", "Suspicious sign-ins", "Failed and blocked sign-ins: password guessing shows up here."),
    ("accounts", "Account and privilege changes", "New accounts, and accounts given administrator rights."),
    ("persistence", "Persistence (services and tasks)", "New services and scheduled tasks: how malware starts itself again after a restart."),
    ("powershell", "Suspicious PowerShell", "Scripts with signs of an attack: encoded commands, download-and-run, protection bypasses."),
    ("tampering", "Defence tampering", "Protection turned off, settings changed, and logs or antivirus reports cleared."),
    ("av_health", "Antivirus health", "Updates, cloud reputation checks and the connection to the Kaspersky server."),
)
CATEGORY_TITLES = {key: title for key, title, _ in CATEGORIES}
KIND_CATEGORY = {
    "malware": "malware", "failed_logon": "sign_ins", "lockout": "sign_ins", "sudo_failure": "sign_ins",
    "user_created": "accounts", "group_member_added": "accounts", "service_installed": "persistence", "task_created": "persistence",
    "powershell_suspicious": "powershell", "av_disabled": "tampering", "log_cleared": "tampering", "av_report_cleared": "tampering",
    "av_settings_changed": "tampering", "av_update_failed": "av_health", "av_health": "av_health",
}
# Fields that tell one finding of a kind from another, for marks (acknowledged / false positive) and alerts.
KEY_FIELDS = {
    "failed_logon": ("Account", "Source address"), "lockout": ("Account",), "sudo_failure": ("Account",), "user_created": ("New account",),
    "group_member_added": ("Member", "Group"), "service_installed": ("Service",), "task_created": ("Task",), "powershell_suspicious": ("Script file", "Script"),
    "av_disabled": ("Event",), "log_cleared": ("Log",), "av_report_cleared": ("Reports",), "av_settings_changed": ("Event",), "av_update_failed": ("Event",),
    "av_health": ("Problem", "Component"),
}
PRIVILEGED_GROUPS = {"administrators", "domain admins", "enterprise admins", "schema admins", "remote desktop users", "backup operators",
                     "account operators", "server operators", "hyper-v administrators", "sudo", "wheel", "admin", "root"}
NEUTRALISED = re.compile(r"(?i)delet|disinfect|quarantin|removed|action taken|cured|moved to backup")
HEURISTIC = re.compile(r"(?i)\bheur|heuristic|machine learning|\bpdm:|not-a-virus")
USER_WRITABLE = re.compile(r"(?i)\\users\\|\\appdata\\|\\temp\\|\\downloads\\|^/tmp/|^/home/|^/var/tmp/|^/dev/shm/")
SYSTEM_PATH = re.compile(r"(?i)^\"?[a-z]:\\(windows|program files|program files \(x86\))\\|^\"?\\systemroot\\|^\"?%systemroot%|^/(usr|bin|sbin|lib)/")
STRONG_POWERSHELL = re.compile(r"(?i)-e(nc|ncodedcommand)?\s|frombase64|download|webclient|amsi|mimikatz|sekurlsa|exclusion|-disable|shellcode|virtualalloc|assembly")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
ACTION_LABELS = {"rescan": "Rescan", "quarantine": "Quarantine", "kill": "End the process", "delete": "Delete permanently"}
ACTION_RISK = {"rescan": "low", "quarantine": "high", "kill": "medium", "delete": "high"}
ACTION_TOOLS = {"rescan": "threat_rescan", "quarantine": "quarantine_threat", "kill": "kill_process", "delete": "delete_threat"}
DB_DATE_FORMATS = ("%m/%d/%Y %I:%M:%S %p", "%d.%m.%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S")
DB_STALE_DAYS = 7


def _name(path):
    return os.path.basename(str(path or "").replace("\\", "/").rstrip("/")) or str(path or "")


def _proof(fields, *first):
    """The event fields as [{label, value}], the most telling ones first."""
    order = [key for key in first if fields.get(key)] + [key for key in fields if key not in first]
    return [{"label": key, "value": str(fields[key])} for key in order if fields.get(key) not in (None, "")]


def dedup_key(item):
    if item.get("path"):
        return f"{item['kind']}|{str(item['path']).lower()}"
    fields = item.get("fields") or {}
    values = [str(fields.get(name) or "").lower()[:120] for name in KEY_FIELDS.get(item["kind"], ())]
    return f"{item['kind']}|{item.get('source', '').lower()}|" + "|".join(values)


def _other_antivirus_on(antivirus):
    return any(product.get("enabled") and "defender" not in str(product.get("name", "")).lower() for product in antivirus or [])


def _db_age_days(text, now):
    for pattern in DB_DATE_FORMATS:
        try:
            moment = datetime.strptime(str(text).strip(), pattern).replace(tzinfo=timezone.utc)
            return (now - moment).days
        except (TypeError, ValueError):
            continue
    return None


def _step(text, action=None, pid=None):
    return {"text": text, "action": action, "pid": pid}


# ---------------------------------------------------------------------------
# One rule per kind: (severity, status, title, summary, steps) or None when it is not a finding
# ---------------------------------------------------------------------------

def _malware(item, os_type, scanner):
    fields, path, name = item.get("fields") or {}, item.get("path"), _name(item.get("path"))
    threat = fields.get("Threat") or "a threat"
    results = " ".join((item.get("results") or {}).keys()) or fields.get("Result") or ""
    inside = len(item.get("objects") or [])
    archive = inside and item["count"] > 1 or bool(re.search(r"(?i)\.(iso|zip|rar|7z|tar|gz|img|vhdx?|cab|msi)$", name))
    running = item.get("running") or []
    names = " ".join(entry.get("name", "") for entry in item.get("threats") or []) + " " + str(fields.get("Threat level") or "") + " " + str(fields.get("Reason") or "")
    heuristic = bool(HEURISTIC.search(names))
    if not item.get("on_disk"):
        summary = f"{item['count']} detection(s) of {threat} by {item['source']}. The file is no longer on disk ({'removed by the antivirus' if NEUTRALISED.search(results) else 'moved or deleted'})."
        return "low", "neutralised", f"{threat} in {name}", summary, [
            _step(f"Nothing is left at {path}. Run a full scan of the device in {scanner} to make sure no other copy is left."),
            _step("If it came from a download or a USB stick, check where it came from and warn the user."),
        ]
    severity = "critical" if running or not heuristic else "high"
    where = f" inside {name} ({item['count']} objects in this one file)" if archive and item["count"] > 1 else f" in {name}"
    summary = (f"{item['source']} found {threat}{where}. Result: {fields.get('Result') or 'detected'}; the file is still on disk"
               + (f" and running now ({', '.join(str(entry['pid']) for entry in running)})" if running else "") + "."
               + (" Heuristic or machine-learning detection: often a hacking or admin tool rather than active malware." if heuristic else ""))
    steps = [_step(f"Do not open, run or mount {name}.")]
    for entry in running:
        steps.append(_step(f"End the running program {entry['name']} (PID {entry['pid']}) first, so the file can be moved.", "kill", entry["pid"]))
    steps.append(_step(f"Rescan it with {scanner} to confirm (report-only: nothing is changed).", "rescan"))
    steps.append(_step("If nobody needs this file, quarantine it: it moves to the AIops quarantine and can be restored for 7 days.", "quarantine"))
    if archive:
        steps.append(_step("If it is a security-tools image someone uses on purpose (for example a Kali Linux ISO), keep it and ask IT for a "
                           "Kaspersky exclusion instead: pentest tools inside such images are detected by design."))
    if SHA256.match(str(fields.get("SHA256") or "")):
        steps.append(_step("Look up the SHA256 on Kaspersky OpenTIP or VirusTotal (links below) to see what other vendors say."))
    steps.append(_step("Delete it permanently only when you are sure: it cannot be restored.", "delete"))
    steps.append(_step(f"Afterwards, run a full scan of the device in {scanner}."))
    return severity, "active", f"{threat} in {name}", summary, steps


def _failed_logon(item, os_type):
    fields = item.get("fields") or {}
    account, address, peak = fields.get("Account", "?"), fields.get("Source address", "-"), item.get("peak_per_hour") or item["count"]
    severity = "high" if peak >= 10 else "medium" if peak >= 5 else "low"
    remote = "remote desktop" in str(fields.get("Logon type", "")).lower() or fields.get("Logon type") == "SSH"
    summary = f"{item['count']} failed sign-in(s) for {account} from {address} (up to {peak} in one hour), {item['source']}."
    steps = [_step(f"Ask whether {account} is a real user who mistyped or forgot the password. If not, someone is guessing passwords.")]
    if address not in ("-", "", "127.0.0.1", "::1"):
        steps.append(_step(f"If {address} is not one of your machines, block it in the firewall."))
    if os_type == "Windows":
        if remote:
            steps.append(_step("Turn Remote Desktop off if it is not needed, or allow it only over the VPN."))
        steps.append(_step("Check the account has a strong password and that an account lockout policy is set (Local Security Policy > Account Lockout Policy)."))
    else:
        steps.append(_step("Use SSH keys and turn password logins off (PasswordAuthentication no in /etc/ssh/sshd_config); fail2ban blocks guessing addresses."))
    return severity, "active", f"{item['count']} failed sign-ins for {account} from {address}", summary, steps


def _sudo_failure(item, os_type):
    account, peak = (item.get("fields") or {}).get("Account", "?"), item.get("peak_per_hour") or item["count"]
    return ("medium" if peak >= 5 else "low"), "active", f"{item['count']} wrong sudo passwords for {account}", \
        f"{item['count']} failed sudo attempt(s) by {account} (up to {peak} in one hour).", [
            _step(f"Ask {account} whether it was them. Repeated failures from a session nobody owns mean someone is trying to become root.")]


def _lockout(item, os_type):
    fields = item.get("fields") or {}
    return "high", "active", f"Account {fields.get('Account', '?')} was locked out", \
        f"{fields.get('Account', '?')} was locked out {item['count']} time(s)" + (f", last from {fields['Locked out from']}" if fields.get("Locked out from") else "") + ".", [
            _step("Ask the user whether they locked themselves out. If not, reset the password and look at the failed sign-ins in this tab."),
        ]


def _user_created(item, os_type):
    fields = item.get("fields") or {}
    account, by = fields.get("New account", "?"), fields.get("Created by")
    disable = f"net user {_name(account)} /active:no" if os_type == "Windows" else f"sudo usermod -L {account}"
    return "high", "active", f"New account {account}", f"The account {account} was created" + (f" by {by}" if by else "") + ".", [
        _step(f"Confirm with IT that {account} was created on purpose."),
        _step(f"If not, disable it at once ({disable}) and change the passwords of the admin accounts."),
    ]


def _group_member_added(item, os_type):
    fields = item.get("fields") or {}
    member, group, by = fields.get("Member", "?"), fields.get("Group", "?"), fields.get("Added by")
    privileged = str(group).lower() in PRIVILEGED_GROUPS
    remove = f'net localgroup "{group}" "{member}" /delete' if os_type == "Windows" else f"sudo gpasswd -d {member} {group}"
    return ("high" if privileged else "low"), "active", f"{member} added to {group}", \
        f"{member} was added to the group {group}" + (f" by {by}" if by else "") + (": that group has administrator rights." if privileged else "."), [
            _step(f"Confirm {member} should be in {group}."),
            _step(f"If not, remove it ({remove}) and find out who added it."),
        ]


def _service_installed(item, os_type):
    fields = item.get("fields") or {}
    service, program = fields.get("Service", "?"), str(fields.get("Program") or "")
    severity = "high" if USER_WRITABLE.search(program) else "low" if SYSTEM_PATH.search(program) else "medium"
    return severity, "active", f"New service {service}", f"The service {service} was installed" + (f", running {program}" if program else "") + (
        ". It runs from a folder any user can write to, which legitimate services rarely do." if severity == "high" else "."), [
        _step(f"Check the program {program or 'of the service'}: is it from a known vendor (right-click > Properties > Digital Signatures)?"),
        _step("If nobody knows it, stop and disable the service (services.msc), then scan its file with the antivirus."),
    ]


def _task_created(item, os_type):
    fields = item.get("fields") or {}
    return "medium", "active", f"New scheduled task {fields.get('Task', '?')}", \
        f"The scheduled task {fields.get('Task', '?')} was created" + (f" by {fields['Created by']}" if fields.get("Created by") else "") + ".", [
            _step(f"Open Task Scheduler and look at {fields.get('Task', 'the task')}: what it runs, and who created it."),
            _step("Delete it if nobody recognises it, and scan the program it starts."),
        ]


def _powershell(item, os_type):
    fields = item.get("fields") or {}
    signs = str(fields.get("Attack signs") or "")
    severity = "high" if STRONG_POWERSHELL.search(signs) else "medium"
    return severity, "active", f"Suspicious PowerShell script ({signs[:80]})", \
        f"PowerShell flagged {item['count']} script block(s) with signs of an attack: {signs}.", [
            _step(f"Find out who ran this script (last seen {item.get('last_seen') or 'recently'}). Encoded or downloaded scripts are a common first step of an attack."),
            _step("If nobody recognises it, disconnect the device from the network and run a full antivirus scan."),
            _step("Turn on PowerShell script block logging by policy, so every script is recorded."),
        ]


def _av_disabled(item, os_type, antivirus):
    if item.get("source") == "Microsoft Defender" and _other_antivirus_on(antivirus):
        return None  # Windows switches Defender off when another antivirus (Kaspersky) takes over: expected
    fields = item.get("fields") or {}
    return "critical", "active", fields.get("Event") or f"{item['source']} protection turned off", \
        f"{fields.get('Event') or 'Protection was turned off'} ({item['source']}, {item['count']} time(s)).", [
            _step(f"Turn protection back on in {item['source']}."),
            _step("Find out who turned it off. If nobody did on purpose, treat the device as compromised and run a full scan."),
        ]


def _log_cleared(item, os_type):
    fields = item.get("fields") or {}
    log = fields.get("Log") or "an event"
    return ("critical" if str(log).lower() == "security" else "high"), "active", f"{log} log cleared", \
        f"The {log} log was cleared" + (f" by {fields['Cleared by']}" if fields.get("Cleared by") else "") + ": what happened before is gone.", [
            _step(f"Ask {fields.get('Cleared by') or 'the user'} why. Attackers clear logs to hide what they did."),
            _step("If nobody did it on purpose, treat the device as compromised: disconnect it and run a full scan."),
        ]


def _av_report_cleared(item, os_type):
    fields = item.get("fields") or {}
    return "medium", "active", f"Antivirus reports cleared ({fields.get('Reports') or 'reports'})", \
        f"{item['source']} reports ({fields.get('Reports') or 'detections'}) were cleared" + (f" by {fields['Cleared by']}" if fields.get("Cleared by") else "") + \
        f" ({item['count']} records): earlier detections can no longer be seen on this device.", [
            _step("Confirm the reports were cleared on purpose. Clearing them also hides what was detected before."),
            _step("If not, run a full scan and check the device's history in Kaspersky Security Center."),
        ]


def _av_settings_changed(item, os_type):
    fields = item.get("fields") or {}
    tamper = "tamper" in str(fields.get("Event", "")).lower()
    return ("medium" if tamper else "low"), "active", f"{item['source']}: {fields.get('Event') or 'settings changed'}", \
        f"{fields.get('Event') or 'Settings changed'} ({item['count']} time(s))" + (f", component {fields['Component']}" if fields.get("Component") else "") + \
        (f", by {fields['User']}" if fields.get("User") else "") + ".", [
            _step(f"Check in {item['source']} that the protection settings are still what your policy requires."),
        ]


def _av_update_failed(item, os_type):
    return "medium", "active", f"{item['source']} could not update", f"{item['count']} failed update(s) of {item['source']}.", [
        _step("Check the internet connection, then update the antivirus databases by hand."),
    ]


def _av_health(item, os_type):
    fields = item.get("fields") or {}
    if fields.get("Problem"):
        return "low", "active", fields["Problem"], fields["Problem"] + ".", [
            _step("Turn Kaspersky Security Network on if your policy allows: without it new threats are recognised later."),
        ]
    component = fields.get("Component") or item["source"]
    return ("medium" if item["count"] >= 50 else "low"), "active", f"{component}: {item['count']} error(s)", \
        f"{component} logged {item['count']} error(s): {fields.get('Message') or ''}".strip(), [
            _step(f"{component} errors usually mean it cannot reach the Kaspersky Administration Server: policies and database updates may not arrive."),
            _step("Check the network or VPN, and the server address in Network Agent (klnagchk.exe shows the connection)."),
        ]


RULES = {
    "failed_logon": _failed_logon, "sudo_failure": _sudo_failure, "lockout": _lockout, "user_created": _user_created,
    "group_member_added": _group_member_added, "service_installed": _service_installed, "task_created": _task_created,
    "powershell_suspicious": _powershell, "log_cleared": _log_cleared, "av_report_cleared": _av_report_cleared,
    "av_settings_changed": _av_settings_changed, "av_update_failed": _av_update_failed, "av_health": _av_health,
}


def _actions(item):
    """What a person may approve on this finding: only for a file still on disk."""
    if item["kind"] != "malware" or not item.get("on_disk") or not item.get("path"):
        return []
    name = _name(item["path"])
    actions = [{"action": "rescan", "label": ACTION_LABELS["rescan"], "risk": ACTION_RISK["rescan"]},
               {"action": "quarantine", "label": ACTION_LABELS["quarantine"], "risk": ACTION_RISK["quarantine"]}]
    actions += [{"action": "kill", "label": f"End {entry['name']} (PID {entry['pid']})", "risk": ACTION_RISK["kill"], "pid": entry["pid"], "name": entry["name"]}
                for entry in item.get("running") or []]
    actions.append({"action": "delete", "label": ACTION_LABELS["delete"], "risk": ACTION_RISK["delete"], "confirm": name})
    return actions


def _lookups(fields):
    sha = str(fields.get("SHA256") or "")
    if not SHA256.match(sha):
        return []
    return [{"label": "Kaspersky OpenTIP", "url": f"https://opentip.kaspersky.com/{sha.upper()}/"},
            {"label": "VirusTotal", "url": f"https://www.virustotal.com/gui/file/{sha.lower()}"}]


def _scanner(data):
    names = " ".join(str(product.get("name", "")) for product in data.get("antivirus") or [] if product.get("enabled")).lower()
    if "kaspersky" in names or any(source.get("name") == "Kaspersky Endpoint Security" and source.get("available") for source in data.get("sources") or []):
        return "Kaspersky"
    return "Microsoft Defender" if data.get("platform") == "Windows" else "the antivirus"


def analyze_threats(data, os_type=None, marks=None, now=None):
    """The scan as {categories, findings, sources, unreadable, ...}. marks: {dedup_key: {status, note}} from threat_store."""
    data, marks, now = data or {}, marks or {}, now or datetime.now(timezone.utc)
    os_type = os_type or data.get("platform") or "Windows"
    scanner = _scanner(data)
    findings = []
    for item in data.get("items") or []:
        kind = item.get("kind")
        if kind == "malware":
            result = _malware(item, os_type, scanner)
        elif kind == "av_disabled":
            result = _av_disabled(item, os_type, data.get("antivirus"))
        elif kind in RULES:
            result = RULES[kind](item, os_type)
        else:
            continue
        if result is None:
            continue
        severity, status, title, summary, steps = result
        fields = item.get("fields") or {}
        key = dedup_key(item)
        mark = marks.get(key)
        first = ("Threat", "Type", "Result", "Detected by") if kind == "malware" else ()
        findings.append({
            "item_id": item.get("id"), "kind": kind, "category": KIND_CATEGORY.get(kind, "tampering"), "severity": severity,
            "status": mark["status"] if mark else status, "mark_note": (mark or {}).get("note"), "title": title, "summary": summary,
            "source": item.get("source"), "event_ids": item.get("event_ids") or [], "count": item.get("count", 1),
            "first_seen": item.get("first_seen"), "last_seen": item.get("last_seen"), "proof": _proof(fields, *first),
            "path": item.get("path"), "objects": item.get("objects") or [], "threats": item.get("threats") or [], "size": item.get("size"),
            "steps": steps, "actions": _actions(item), "lookups": _lookups(fields), "dedup_key": key,
        })
    age = _db_age_days(data.get("kaspersky_db_date"), now) if data.get("kaspersky_db_date") else None
    if age is not None and age > DB_STALE_DAYS:
        key = "av_health|kaspersky|databases"
        findings.append({
            "item_id": None, "kind": "av_health", "category": "av_health", "severity": "medium", "status": (marks.get(key) or {}).get("status", "active"),
            "mark_note": None, "title": f"Kaspersky databases are {age} days old", "summary": f"The newest detection used databases released {data['kaspersky_db_date']}.",
            "source": "Kaspersky Endpoint Security", "event_ids": [], "count": 1, "first_seen": None, "last_seen": None,
            "proof": [{"label": "Database date", "value": str(data["kaspersky_db_date"])}], "path": None, "objects": [], "threats": [], "size": None,
            "steps": [_step("Update the Kaspersky databases now (Kaspersky > Update), and check why automatic updates stopped.")],
            "actions": [], "lookups": [], "dedup_key": key,
        })
    order = {key: index for index, (key, _, _) in enumerate(CATEGORIES)}
    findings.sort(key=lambda finding: (order.get(finding["category"], 99), finding["status"] in ("acknowledged", "false_positive", "neutralised"),
                                       -SEVERITIES.index(finding["severity"]), -finding["count"]))
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"T{index}"
    categories = []
    for key, title, description in CATEGORIES:
        mine = [finding for finding in findings if finding["category"] == key]
        open_ones = [finding for finding in mine if finding["status"] == "active"]
        worst = max((finding["severity"] for finding in open_ones), key=SEVERITIES.index, default=None)
        categories.append({"id": key, "title": title, "description": description, "count": len(mine), "open": len(open_ones), "severity": worst})
    sources = data.get("sources") or []
    return {
        "scan_id": data.get("scan_id"), "scanned_at": data.get("scanned_at"), "hours": data.get("hours"), "platform": data.get("platform"),
        "admin": data.get("admin"), "antivirus": data.get("antivirus") or [], "sources": sources, "truncated": bool(data.get("truncated")),
        "unreadable": [source for source in sources if not source.get("available") and source.get("detail") != "not on this device"],
        "categories": categories, "findings": findings,
    }


def find(analysis, finding_id):
    return next((finding for finding in (analysis or {}).get("findings") or [] if finding["id"] == str(finding_id or "").strip().upper()), None)


def proposal(analysis, finding_id, action, pid=None):
    """An action card for the action chat, only for an action this finding offers; None otherwise. It is a
    proposal: the dashboard asks the person to approve it, and the actions endpoint checks it again."""
    finding = find(analysis, finding_id)
    if not finding or action not in ACTION_LABELS:
        return None
    offered = [item for item in finding["actions"] if item["action"] == action]
    if action == "kill":
        # A named process must be one of the finding's; without a pid, only when it has just one.
        offered = [item for item in offered if str(item.get("pid")) == str(pid)] if pid is not None else offered if len(offered) == 1 else []
    if not offered:
        return None
    chosen = offered[0]
    return {"finding_id": finding["id"], "action": action, "label": chosen["label"], "risk": chosen["risk"], "pid": chosen.get("pid"),
            "confirm": chosen.get("confirm"), "title": finding["title"], "path": finding.get("path")}


# Words people use for each action, English and Roman Urdu. Checked in this order: "rescan" also matches "scan".
ACTION_WORDS = (
    ("quarantine", re.compile(r"(?i)quarantin|isolate|alag kar")),
    ("delete", re.compile(r"(?i)\bdelete|\berase|\bremove|mita\s?d|khatam kar")),
    ("kill", re.compile(r"(?i)\bkill|\bend (the )?process|\bterminate|\bstop (the )?process|process band|band kar")),
    ("rescan", re.compile(r"(?i)\bre-?scan|\bscan|dobara check|check again")),
)


def parse_request(message, analysis):
    """(finding_id, action) asked for in plain words, e.g. "quarantine T1" or "T2 ko delete karo"; Nones when unclear.
    Without a finding id, the only finding that offers actions is meant."""
    text = str(message or "")
    action = next((name for name, pattern in ACTION_WORDS if pattern.search(text)), None)
    ids = [f"T{number}" for number in re.findall(r"(?i)\bT(\d{1,3})\b", text)]
    if not ids:
        actionable = [finding["id"] for finding in (analysis or {}).get("findings") or [] if finding["actions"]]
        ids = actionable if len(actionable) == 1 else []
    return (ids[0] if ids else None), action


def rules_explanation(analysis):
    """What the findings mean without the AI: counts, the most urgent ones, and their first steps."""
    open_ones = [finding for finding in analysis["findings"] if finding["status"] == "active"]
    if not open_ones:
        unreadable = ", ".join(source["name"] for source in analysis.get("unreadable") or [])
        return {"summary": "No open threat findings in this scan." + (f" Not readable: {unreadable}." if unreadable else ""), "priorities": [], "next_steps": []}
    urgent = sorted(open_ones, key=lambda finding: -SEVERITIES.index(finding["severity"]))[:3]
    counts = {severity: sum(1 for finding in open_ones if finding["severity"] == severity) for severity in reversed(SEVERITIES)}
    summary = f"{len(open_ones)} open finding(s): " + ", ".join(f"{count} {severity}" for severity, count in counts.items() if count) + \
        f". Most urgent: {urgent[0]['id']} {urgent[0]['title']}."
    return {"summary": summary, "priorities": [{"finding_id": finding["id"], "why": finding["summary"]} for finding in urgent],
            "next_steps": [f"{finding['id']}: {finding['steps'][0]['text']}" for finding in urgent if finding["steps"]]}


def finding_text(finding, limit=600):
    """One finding in a few lines, for the AI: id, title, severity, status, proof, path and offered actions."""
    # What the AI must not miss (the actions it may propose, the file) comes before what may be cut.
    actions = ", ".join(action["action"] + (f"(pid {action['pid']})" if action.get("pid") else "") for action in finding["actions"]) or "none (manual steps only)"
    proof = "; ".join(f"{item['label']}: {item['value'][:80]}" for item in finding["proof"][:8] if item["label"] not in ("SHA256", "MD5"))
    text = (f"{finding['id']} [{finding['severity']}, {finding['status']}] {CATEGORY_TITLES.get(finding['category'], finding['category'])}: {finding['title']}. "
            f"Approvable actions: {actions}." + (f" Path: {finding['path']}." if finding.get("path") else "") + f" {finding['summary']} Proof: {proof}.")
    return text[:limit]
