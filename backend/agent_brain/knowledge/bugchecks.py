"""BSOD bugcheck knowledge (spec §12): correlate, never blame on sight.

Each entry maps a bugcheck code/name to what it usually means and what to correlate it with. `triggers`
match the hex code or the SCREAMING_CASE name in the issue text or the crash evidence. The guiding rule
(shared by all): never blame a driver only because it appears in one crash — look for repetition, a
recent change, WHEA and disk/RAM errors.
"""

BUGCHECKS = [
    {"id": "0x1A", "label": "MEMORY_MANAGEMENT (0x1A)", "triggers": [r"0x0*1a\b", r"memory_management"],
     "meaning": "The memory manager hit a severe fault — often faulty RAM, but also a driver corrupting memory.",
     "correlate": "a memory test, WHEA events, recent driver/update changes, and whether it repeats."},
    {"id": "0x50", "label": "PAGE_FAULT_IN_NONPAGED_AREA (0x50)", "triggers": [r"0x0*50\b", r"page_fault_in_nonpaged_area"],
     "meaning": "Referenced invalid memory — faulty RAM, a bad driver, or corrupted system service.",
     "correlate": "RAM test, the faulting driver in the dump, and recent changes."},
    {"id": "0xD1", "label": "DRIVER_IRQL_NOT_LESS_OR_EQUAL (0xD1)", "triggers": [r"0x0*d1\b", r"driver_irql_not_less_or_equal"],
     "meaning": "A driver accessed memory at the wrong IRQL — almost always a specific faulty driver.",
     "correlate": "the faulting driver name/version/date and whether it was recently updated."},
    {"id": "0x0A", "label": "IRQL_NOT_LESS_OR_EQUAL (0x0A)", "triggers": [r"0x0*0a\b", r"(?<!driver_)irql_not_less_or_equal"],
     "meaning": "Kernel/driver accessed paged memory at high IRQL — typically a driver or hardware fault.",
     "correlate": "recent drivers, WHEA, and a memory test."},
    {"id": "0x7E", "label": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (0x7E)", "triggers": [r"0x0*7e\b", r"system_thread_exception_not_handled"],
     "meaning": "A system thread raised an unhandled exception — usually a driver (the dump names it).",
     "correlate": "the named driver/module and recent driver or Windows updates."},
    {"id": "0x9F", "label": "DRIVER_POWER_STATE_FAILURE (0x9F)", "triggers": [r"0x0*9f\b", r"driver_power_state_failure"],
     "meaning": "A driver did not handle a sleep/resume power transition — often storage, network or GPU drivers.",
     "correlate": "sleep/resume timing, the driver in the dump, and power events."},
    {"id": "0xEF", "label": "CRITICAL_PROCESS_DIED (0xEF)", "triggers": [r"0x0*ef\b", r"critical_process_died"],
     "meaning": "A critical system process ended — often system-file corruption, a bad update, or disk problems.",
     "correlate": "system-file/component-store health, a recent update, and disk health."},
    {"id": "0x139", "label": "KERNEL_SECURITY_CHECK_FAILURE (0x139)", "triggers": [r"0x0*139\b", r"kernel_security_check_failure"],
     "meaning": "A kernel data-structure corruption was caught — a driver, memory, or (rarely) incompatible software.",
     "correlate": "recent drivers/updates, a memory test, and repetition."},
]
