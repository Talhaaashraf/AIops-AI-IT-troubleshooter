"""Domain knowledge cards (spec §9-24): how a senior engineer investigates each kind of problem.

A card is terse, structured data, NOT prose: where to look (component keys from investigation_map),
the investigative approach in one line, the likely causes, the read-only tools that help, and how to
confirm a fix. The retriever (knowledge/__init__.py) renders at most one card, within a character
budget, into the diagnosis prompt — so the CPU model gets senior-engineer guidance without a wall of text.

`id` matches a playbook id (playbooks.py) where one exists, so retrieval keys straight off the matched
playbook; `keywords` cover domains that have no playbook (Office, drivers, generic app crashes).
"""

# Each card: id, title, keywords, where (investigation_map keys), approach, causes, tools, confirm.
DOMAINS = [
    {
        "id": "slow_pc", "title": "Slow / hanging PC", "keywords": ["slow", "hang", "lag", "freeze", "sluggish", "stuck"],
        "where": ["cpu", "memory", "disk_io", "disk_space", "startup", "thermal", "recent_change"],
        "approach": "Find the single primary bottleneck from the metrics before suggesting anything; never default to cleanup.",
        "causes": ["memory pressure (a program or the browser)", "a runaway CPU process", "a slow or failing disk", "thermal throttling", "too many startup programs"],
        "tools": ["system_overview", "top_processes", "performance_benchmark", "hardware_health", "startup_programs"],
        "confirm": "The metric that was abnormal returns to normal (memory frees, CPU settles, disk speed/space recovers).",
    },
    {
        "id": "high_usage", "title": "High CPU / RAM", "keywords": ["cpu", "ram", "memory", "100%", "fan loud"],
        "where": ["cpu", "memory", "startup", "thermal"],
        "approach": "Name the program (all its processes added up) that holds the CPU or memory before acting.",
        "causes": ["one heavy program or its many processes", "a background indexer/update/scan", "a memory leak over long uptime", "malware"],
        "tools": ["top_processes", "system_overview", "hardware_health"],
        "confirm": "After closing/restarting the culprit, overall CPU or memory use drops back to normal.",
    },
    {
        "id": "disk_full", "title": "Disk full / low space", "keywords": ["disk full", "storage", "space", "low disk", "drive full"],
        "where": ["disk_space"],
        "approach": "Judge by space left, not percentage: 90% of a big disk can still be fine; it's the GB free that matter.",
        "causes": ["temporary files", "the recycle bin/trash", "old Windows Update cache", "large user files", "shadow copies/logs"],
        "tools": ["cleanup_candidates", "system_overview"],
        "confirm": "Free space rises above a safe margin (several GB) after cleanup.",
    },
    {
        "id": "no_internet", "title": "No / slow internet", "keywords": ["internet", "no internet", "offline", "website", "can't connect", "network down"],
        "where": ["network_l3", "network_l4", "dns"],
        "approach": "Work the layers: adapter/IP, then gateway, then TCP to the internet, then DNS, then HTTP. Name the FAILED layer; never just say 'internet is broken'.",
        "causes": ["no IP/adapter down", "no route to the router", "ISP/router down", "DNS failing", "proxy/captive portal blocking HTTP"],
        "tools": ["check_internet", "dns_lookup", "ping_host"],
        "confirm": "The layer that failed now passes end to end (DNS resolves, TCP and HTTP succeed).",
    },
    {
        "id": "wifi_drops", "title": "Wi-Fi drops / weak", "keywords": ["wifi", "wi-fi", "wireless", "signal", "disconnect", "drops"],
        "where": ["wifi", "network_l3", "event_logs", "drivers"],
        "approach": "Separate a weak-signal/radio problem from a driver or router problem before recommending a driver change.",
        "causes": ["weak signal/distance/interference", "an old Wi-Fi driver", "a flaky access point", "power-saving on the adapter"],
        "tools": ["wifi_status", "check_internet", "event_log_errors"],
        "confirm": "Signal is strong and the link stays up (no repeated disconnect events) over time.",
    },
    {
        "id": "dns", "title": "DNS / name resolution", "keywords": ["dns", "name resolution", "by ip but not", "hostname", "resolve"],
        "where": ["dns", "network_l4", "network_l3"],
        "approach": "Prove it is DNS, not the network or the app: does the name resolve, and does the IP reach while the name fails?",
        "causes": ["wrong/slow DNS server", "stale DNS cache", "split/VPN DNS", "a single bad record"],
        "tools": ["dns_lookup", "check_internet", "ping_host"],
        "confirm": "The failing name resolves to the right address and the site opens.",
    },
    {
        "id": "printer", "title": "Printer not printing", "keywords": ["printer", "print", "spooler", "queue", "cannot print"],
        "where": ["spooler", "printer_net", "services"],
        "approach": "Split reachable-but-can't-print from unreachable: if ping/TCP 9100/web UI succeed but Windows can't print, suspect the Windows port/driver/spooler, not the network.",
        "causes": ["stopped spooler", "stuck queue", "wrong/WSD port instead of TCP/IP", "bad driver", "printer offline status (SNMP)"],
        "tools": ["printer_status", "service_status", "ping_host", "test_tcp_port"],
        "confirm": "The spooler runs, the queue is clear, and a test page prints.",
    },
    {
        "id": "crashes", "title": "Crashes / blue screen", "keywords": ["crash", "blue screen", "bsod", "restart", "reboot", "shutdown"],
        "where": ["crashes", "event_logs", "drivers", "disk_io", "thermal", "recent_change"],
        "approach": "Build a crash timeline and correlate. Never blame a driver only because it appears in one crash; look for repetition, WHEA, disk/RAM errors and a recent change.",
        "causes": ["a faulty/updated driver", "failing RAM or disk (WHEA)", "overheating", "a recent Windows update", "power loss"],
        "tools": ["recent_crashes", "event_log_errors", "disk_health", "hardware_health", "driver_inventory"],
        "confirm": "No new crashes of the same bugcheck/pattern after the change, over several days.",
    },
    {
        "id": "windows_update", "title": "Windows Update stuck/failing", "keywords": ["update", "windows update", "patch", "0x8024", "wsus"],
        "where": ["updates", "services", "disk_space", "event_logs"],
        "approach": "Read the actual error code and the servicing state; a pending reboot or a stopped service is a common, cheap cause.",
        "causes": ["pending reboot", "stopped wuauserv/BITS", "component-store corruption", "low disk", "a specific update error code"],
        "tools": ["update_status", "service_status", "os_updates", "event_log_errors"],
        "confirm": "The update installs (or the scan completes) and no reboot stays pending.",
    },
    {
        "id": "battery", "title": "Battery drains fast", "keywords": ["battery", "charge", "drain", "power"],
        "where": ["battery", "cpu", "thermal"],
        "approach": "Separate worn hardware (low design-capacity health) from a background process draining power.",
        "causes": ["a worn battery (low health %)", "a CPU-heavy background process", "a high-power plan", "bright display/peripherals"],
        "tools": ["battery_health", "top_processes"],
        "confirm": "Battery health explains the drain, or closing the heavy process extends runtime.",
    },
    {
        "id": "audio", "title": "No / broken audio", "keywords": ["sound", "audio", "speaker", "mic", "microphone", "headphone", "static"],
        "where": ["services", "drivers", "event_logs"],
        "approach": "Check the audio services and driver/device state; static-then-freeze can be DPC/driver, not the speaker.",
        "causes": ["stopped Audiosrv/AudioEndpointBuilder", "a bad audio driver", "wrong default device", "a driver causing DPC latency"],
        "tools": ["service_status", "hardware_health", "event_log_errors"],
        "confirm": "The audio services run, the device is healthy, and sound plays on the right output.",
    },
    {
        "id": "hardware", "title": "Hardware check", "keywords": ["hardware", "overheat", "temperature", "gpu", "graphics", "usb", "device manager", "driver"],
        "where": ["thermal", "drivers", "disk_io", "battery", "event_logs"],
        "approach": "Distinguish hardware failure from a driver/firmware/config problem; correlate WHEA and crash history before blaming a part.",
        "causes": ["overheating/throttling", "a failing disk (SMART)", "a worn battery", "a device with a driver error", "WHEA machine-check errors"],
        "tools": ["hardware_health", "disk_health", "battery_health", "event_log_errors", "driver_inventory"],
        "confirm": "The failing signal (temperature, SMART, device error, WHEA) is gone after the fix/replacement.",
    },
    {
        "id": "os_health", "title": "OS health / services", "keywords": ["service", "boot", "won't start", "system files", "corrupt", "login", "black screen"],
        "where": ["services", "updates", "crashes", "event_logs", "disk_io"],
        "approach": "Look for stopped/failed services, a pending reboot, corruption and recent crashes together rather than one in isolation.",
        "causes": ["a stopped critical service", "component-store/system-file corruption", "a pending reboot", "a failing disk", "a bad update"],
        "tools": ["failed_services", "update_status", "recent_crashes", "event_log_errors"],
        "confirm": "The failed service runs, repairs report healthy, and the errors stop recurring.",
    },
    {
        "id": "security", "title": "Security / malware signs", "keywords": ["virus", "malware", "hacked", "security", "suspicious", "popup", "ransom"],
        "where": ["threats", "security", "startup", "cpu"],
        "approach": "Use the device's own detections and logs as facts; a security tool inside an ISO/archive is usually a downloaded tool, not an infection. Never disable protection to hide an error.",
        "causes": ["an antivirus detection still on disk", "a disabled firewall/AV", "a suspicious startup item or process", "risky exposed ports"],
        "tools": ["security_posture", "threat_scan", "startup_programs", "top_processes"],
        "confirm": "Detections are quarantined/cleared, protection is on, and no suspicious persistence remains.",
    },
    # Keyword-only domains (no playbook yet).
    {
        "id": "office", "title": "Microsoft Office / 365", "keywords": ["office", "365", "outlook", "word", "excel", "powerpoint", "teams", "onedrive", "click-to-run", "30015", "30182", "1618"],
        "where": ["office_state", "app_state", "recent_change", "updates"],
        "approach": "Gather install type (Click-to-Run vs MSI), build, channel and installer state BEFORE suggesting a repair or removal; read the exact error code. Do not recommend removal until the evidence supports it.",
        "causes": ["a stuck ClickToRunSvc / pending installer (1618)", "a conflicting product/architecture", "a broken Click-to-Run state", "a specific setup error code (3001x/3018x)"],
        "tools": ["microsoft_products", "installed_software", "event_log_errors"],
        "confirm": "Office opens, the failing action completes, and no installer stays in progress.",
    },
    {
        "id": "app_crash", "title": "Application crash / won't start", "keywords": ["app crash", "application crash", "won't open", "wont open", "keeps closing", "not responding", "0xc000"],
        "where": ["app_state", "event_logs", "crashes", "recent_change"],
        "approach": "Investigate even an unfamiliar app by its parts: install integrity, version/architecture, dependencies/runtime, permissions, and the Application/WER error it logs.",
        "causes": ["corrupt install", "a missing runtime/DLL", "an architecture mismatch", "a permission or profile problem", "a bad plugin/add-in", "a recent update"],
        "tools": ["event_log_errors", "installed_software", "recent_crashes"],
        "confirm": "The app launches and the specific fault event no longer appears.",
    },
]

DOMAINS_BY_ID = {card["id"]: card for card in DOMAINS}
