"""Event ID knowledge (spec §26): an Event ID is EVIDENCE, not a root cause.

Each entry teaches what the event means, what to correlate it with, and the wrong conclusion to avoid.
`triggers` match the provider name or an "event/id NNNN" mention in the issue text or the evidence
(summaries and log samples). Only present events are rendered, within a budget.
"""

EVENT_IDS = [
    {"id": "kernel_power_41", "label": "Kernel-Power 41 (system rebooted without a clean shutdown)",
     "triggers": [r"kernel-?power", r"\bevent\s*(id\s*)?41\b"],
     "meaning": "The machine lost power or hard-reset instead of shutting down cleanly — the symptom of a crash/power loss, not the cause.",
     "investigate": "a matching BugCheck 1001 (a true BSOD) vs none (power/thermal/hardware cut-out); overheating and the PSU/battery.",
     "do_not": "do not call it a Windows bug; 41 only records that power was lost — find why."},
    {"id": "bugcheck_1001", "label": "BugCheck 1001 (a blue screen occurred)",
     "triggers": [r"bugcheck", r"\bevent\s*(id\s*)?1001\b"],
     "meaning": "Records a real BSOD with its bugcheck code and parameters.",
     "investigate": "the bugcheck code (see the BSOD knowledge), the faulting driver, and whether it repeats; correlate with WHEA and recent driver/update changes.",
     "do_not": "do not blame the first driver named without correlating repetition and recent change."},
    {"id": "whea_logger", "label": "WHEA-Logger 17/18/19/47 (hardware error)",
     "triggers": [r"whea", r"\bevent\s*(id\s*)?1[789]\b", r"\bevent\s*(id\s*)?47\b"],
     "meaning": "The hardware reported a machine-check/corrected error (CPU, memory, PCIe, bus) — a strong hardware-failure signal.",
     "investigate": "frequency and which component; correlate with crashes, a memory test and temperatures.",
     "do_not": "do not dismiss as noise if it repeats; do not instantly replace RAM on a single corrected error."},
    {"id": "scm_7000_7001_7031_7034", "label": "Service Control Manager 7000/7001/7031/7034 (a service failed/crashed)",
     "triggers": [r"service control manager", r"\bevent\s*(id\s*)?70(00|01|31|34)\b"],
     "meaning": "A service failed to start, depends on one that failed, or terminated unexpectedly.",
     "investigate": "which service and its dependency chain; the error code it logged and whether it restarts repeatedly.",
     "do_not": "do not restart it blindly in a loop; find why it fails first."},
    {"id": "disk_ntfs", "label": "disk 7/11/51 or Ntfs 55 (storage errors / filesystem corruption)",
     "triggers": [r"\bevent\s*(id\s*)?55\b", r"ntfs.{0,40}(corrupt|error)", r"\bevent\s*(id\s*)?(7|11|51)\b.{0,40}disk", r"disk.{0,40}\bevent\s*(id\s*)?(7|11|51)\b"],
     "meaning": "The storage stack reported bad blocks, controller errors (11/51) or filesystem corruption (Ntfs 55) — a disk-health signal.",
     "investigate": "SMART health, the cable/controller, and a chkdsk; correlate with crashes and slow I/O (disk_health).",
     "do_not": "do not blame software corruption alone when these repeat; check the physical disk."},
    {"id": "app_error_1000_1002", "label": "Application Error 1000 / Application Hang 1002",
     "triggers": [r"\bevent\s*(id\s*)?1000\b", r"\bevent\s*(id\s*)?1002\b", r"application error", r"application hang"],
     "meaning": "A user-mode app crashed (1000, names the faulting module) or stopped responding (1002).",
     "investigate": "the faulting module in the event — the app, a plugin, or a shared DLL/runtime; its version and dependencies.",
     "do_not": "do not treat the app as the cause when the faulting module is a shared component or driver."},
    {"id": "dcom_10016", "label": "DistributedCOM 10016 (usually harmless noise)",
     "triggers": [r"\bevent\s*(id\s*)?10016\b", r"distributedcom"],
     "meaning": "A DCOM permission warning that Microsoft documents as safe to ignore on most systems.",
     "investigate": "nothing, unless it correlates with a real symptom — treat as background noise.",
     "do_not": "do not present 10016 as a root cause; it is almost always benign."},
]
