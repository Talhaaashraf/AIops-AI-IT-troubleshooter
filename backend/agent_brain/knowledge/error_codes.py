"""Error-code knowledge (spec §25): how to INVESTIGATE a code, not just "X means Y".

Each entry is terse data with `triggers` (regexes matched against the issue text and the evidence), a
plain meaning, where to look next, and a "do not conclude" guard against the obvious wrong jump. The
retriever renders only the entries whose code is actually present, within a small budget, so the CPU
model gets the right lead without a wall of codes.
"""

ERROR_CODES = [
    {"id": "1618", "label": "Windows Installer 1618 (another install in progress)",
     "triggers": [r"\b1618\b"],
     "meaning": "A Windows Installer/Click-to-Run operation is already running or left a stale 'in progress' marker, so a new install is blocked.",
     "investigate": "Office/Click-to-Run install state, the ClickToRunSvc service, and the Installer\\InProgress marker (microsoft_products).",
     "do_not": "do not assume the installer is corrupt; it is usually a stuck/pending operation that clears with the install-blocker fix."},
    {"id": "office_30xxx", "label": "Office setup 3001x/3018x (e.g. 30015-xx, 30182-44, 30038-25)",
     "triggers": [r"\b3001[0-9]-?\d*\b", r"\b3018[0-9]-?\d*\b", r"\b3003[0-9]-?\d*\b"],
     "meaning": "A Click-to-Run setup/streaming step failed; the second number is the sub-error (disk, network, cancelled, or a conflicting product).",
     "investigate": "Office install type/build/channel, free disk space, a conflicting Office product, and the setup logs (microsoft_products, cleanup_candidates).",
     "do_not": "do not jump to a full removal before checking disk space and a conflicting install."},
    {"id": "wu_0x8024", "label": "Windows Update 0x8024xxxx",
     "triggers": [r"0x8024[0-9a-fA-F]{4}"],
     "meaning": "A Windows Update client error (reach/scan/download), e.g. a WSUS/endpoint, cache or servicing-stack problem.",
     "investigate": "the update service state, pending reboot, free disk, and the component store (update_status, service_status, os_updates).",
     "do_not": "do not reinstall Windows; most 0x8024 codes clear by fixing the service/cache or a specific policy."},
    {"id": "wu_0x800f", "label": "Servicing / component-store 0x800Fxxxx",
     "triggers": [r"0x800[fF][0-9a-fA-F]{3}"],
     "meaning": "A servicing-stack or component-store (CBS) error: a feature/update could not be applied, often corruption.",
     "investigate": "the component store health and CBS log; a repair (repair_windows_image, repair_system_files) is the usual path.",
     "do_not": "do not conclude the disk is failing from this alone; it is a software corruption code."},
    {"id": "access_denied_5", "label": "Error 5 / 0x80070005 (access denied)",
     "triggers": [r"\b0x80070005\b", r"access is denied", r"\berror 5\b"],
     "meaning": "A permission problem: the account or service lacks rights to a file, key or service.",
     "investigate": "which object is denied and under which account; a service running as the wrong user, or a locked file/key.",
     "do_not": "do not loosen permissions broadly to make it pass; identify the specific object first."},
    {"id": "app_crash_0xc000", "label": "Application crash 0xC000xxxx (e.g. 0xC0000005 access violation, 0xC0000135 missing DLL)",
     "triggers": [r"0x[cC]0000005", r"0x[cC]0000135", r"0x[cC]0000142", r"0x[cC]000007b"],
     "meaning": "An app fault: 0xC0000005 is an access violation (often a bad plugin/driver/corruption), 0xC0000135/007b a missing or mismatched runtime/DLL/architecture.",
     "investigate": "the Application/WER event for the faulting module, the app's runtime/dependencies and version/architecture (event_log_errors, installed_software).",
     "do_not": "do not reinstall Windows for one app's fault; isolate the faulting module or missing runtime."},
]
