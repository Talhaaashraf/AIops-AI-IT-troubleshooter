"""Playbook-engine extras (spec §27, §29, §40): the investigative logic layer on top of the domain cards.

A domain card (domains.py) says WHAT a problem is and WHERE to look. These extras add HOW a senior
engineer works it: the targeted questions that narrow an unclear report, the decision points that pick
the next check, when to escalate, and whether the domain's fixes are reversible. Kept separate so the
cards stay compact and these are rendered only where they are used (questions/escalation in the
unknown-handling and escalation steps; decision points in the deep-mode investigation hint).

Keyed by domain id (domains.py). Every key must be a real domain id (a test enforces this).
"""

DOMAIN_EXTRAS = {
    "slow_pc": {
        "questions": ["Is it slow all the time, or only when a certain program runs?",
                      "Did it start right after a Windows/driver update or new software?",
                      "Is it slow from the moment it starts, or only after running a while?"],
        "decision_points": ["If one metric (RAM, CPU or disk) is clearly worst, that is the bottleneck — do not act on the others.",
                            "If every metric looks normal, the slowness is likely intermittent — ask when it happens rather than guessing."],
        "escalate_when": ["the disk reports failing SMART health", "hardware/WHEA errors repeat"],
        "rollback": "Closing a program or disabling a startup item is reversible and deletes no data.",
    },
    "no_internet": {
        "questions": ["Does it fail on every site, or only some?", "Does another device on the same network work?",
                      "Wired or Wi-Fi, and did it start after a change?"],
        "decision_points": ["If DNS fails but TCP to an IP works, it is a DNS problem, not connectivity.",
                            "If no adapter has an IP, stop at the adapter/DHCP layer before anything else."],
        "escalate_when": ["every device on the network is affected (infrastructure, not this PC)"],
        "rollback": "Flush/renew/reset network actions are reversible; none delete data.",
    },
    "printer": {
        "questions": ["Does any user print, or only this one?", "Is it USB or network?",
                      "Did it ever work on this PC, or is it a new setup?"],
        "decision_points": ["If ping/TCP 9100/web UI succeed but Windows can't print, suspect the Windows port/driver/spooler, not the network.",
                            "If the spooler is stopped, start there before touching the driver."],
        "escalate_when": ["a whole floor/department cannot print (printer or network infrastructure)"],
        "rollback": "Restarting the spooler or clearing the queue is reversible.",
    },
    "crashes": {
        "questions": ["Does it happen at a certain time or action (sleep, a specific app, startup)?",
                      "Did it start after a driver or Windows update?", "How often — once, or many times a day?"],
        "decision_points": ["Correlate the bugcheck, the faulting driver, WHEA and recent changes before blaming anything.",
                            "A single crash naming a driver is weak; repetition plus a recent change is strong."],
        "escalate_when": ["blue screens repeat", "WHEA hardware errors appear", "possible data loss"],
        "rollback": "Repairs re-run system checks; a driver change should be noted so it can be rolled back.",
    },
    "windows_update": {
        "questions": ["Does it fail with a specific error code?", "Is a restart pending?",
                      "Did it start after a particular update?"],
        "decision_points": ["Read the actual error code first; a pending reboot or stopped service is the cheapest cause.",
                            "0x800F codes point at component-store corruption (repair), not the disk."],
        "escalate_when": ["the component store is corrupt and repairs fail repeatedly"],
        "rollback": "Clearing the update cache and restarting services is reversible.",
    },
    "office": {
        "questions": ["Which product and does it open at all?", "Is it Click-to-Run or an MSI install?",
                      "What exact error code appears, and did it follow an update?"],
        "decision_points": ["Gather install type/build/channel and the exact code before any repair or removal.",
                            "Error 1618 is a stuck/pending installer — clear it, do not reinstall blindly."],
        "escalate_when": ["removal is being considered without evidence it is the cause"],
        "rollback": "The Microsoft Removal tab backs up registry/folders to a 7-day quarantine before removing.",
    },
    "app_crash": {
        "questions": ["Does it crash on launch, after opening, or on a specific action?",
                      "For every user or only this account?", "Did it start after an app or Windows update?"],
        "decision_points": ["Read the faulting module in the Application/WER event — the app, a plugin, or a shared DLL/runtime.",
                            "A missing-runtime code (0xC0000135/007b) is a dependency problem, not corruption."],
        "escalate_when": ["the faulting module is a system driver, not the app"],
        "rollback": "Investigation is read-only; any repair/reinstall is approved separately.",
    },
    "hardware": {
        "questions": ["Which part seems affected (heat, disk, battery, a device)?",
                      "Did anything change physically (a knock, new peripheral, dusty vents)?", "How often does it happen?"],
        "decision_points": ["Distinguish a hardware fault from a driver/firmware/config problem before blaming a part.",
                            "Correlate WHEA and crash history; one corrected error is not a dead part."],
        "escalate_when": ["SMART reports a failing disk (back up now)", "repeated WHEA errors", "possible data loss"],
        "rollback": "Diagnostics are read-only; a part replacement is a hardware decision, not an app action.",
    },
    "security": {
        "questions": ["What made you suspect it (a popup, slowness, a message)?",
                      "Did you install or open anything unusual recently?", "Is anything encrypting or renaming files right now?"],
        "decision_points": ["Treat the device's own detections as facts; a tool inside an ISO/archive is usually downloaded, not an infection.",
                            "Never disable protection to make an error disappear."],
        "escalate_when": ["a real infection or active ransomware is suspected", "credentials may be compromised"],
        "rollback": "Quarantine is restorable for 7 days; nothing is deleted without the file name typed and approval.",
    },
    "wifi_drops": {
        "questions": ["Does it drop everywhere or in one spot?", "Only this device or others too?",
                      "Did it start after an update?"],
        "decision_points": ["Separate weak signal from a driver/router problem before changing the driver.",
                            "Drops only at distance point to signal, not software."],
        "escalate_when": ["many devices drop on the same access point (infrastructure)"],
        "rollback": "Reconnecting or renewing the address is reversible.",
    },
    "dns": {
        "questions": ["Does it fail by name but work by IP?", "On every name or one?", "On VPN or off?"],
        "decision_points": ["If the IP reaches while the name fails, it is DNS, not the network.",
                            "One failing name is that record/site; all names failing is the resolver."],
        "escalate_when": ["internal/domain DNS is down for many devices"],
        "rollback": "Changing the DNS server or flushing the cache is reversible.",
    },
}

# When no domain matches at all (truly unknown problem): questions that fit anything, each with a purpose.
GENERIC_QUESTIONS = [
    "When did it start, and did anything change just before (an update, new software, a driver)?",
    "Does it happen for every user on the device or only your account?",
    "Does it happen all the time, or only during a specific action?",
    "What exactly happens — any error message, code or screen you can quote?",
]


def extras_for(domain_id):
    return DOMAIN_EXTRAS.get(domain_id, {})
