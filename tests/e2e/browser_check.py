"""Headless browser smoke test of the dashboard: real server, real data, JS errors collected."""

import json
import os
import pathlib
import sys

from playwright.sync_api import sync_playwright

BASE = os.getenv("AIOPS_URL", "http://localhost").rstrip("/")
PASSWORD = sys.argv[1]
OUT = pathlib.Path(sys.argv[2])
DEVICE = sys.argv[3] if len(sys.argv) > 3 else "agent-69910f0b6612"
results, errors = [], []

FAKE_AI = {
    "summary": "Memory is almost full and the C: drive is filling up, which explains the slowness.",
    "root_cause": "WSL/Docker and Chrome use most of the RAM.",
    "severity": "high",
    "issues": [{"title": "RAM usage is high", "explanation": "Docker's VM and Chrome hold most memory.", "fix_steps": ["Close unused Chrome tabs", "Stop Docker when not needed"]}],
    "steps": ["Close memory-heavy apps", "Free space on C:"],
    "prevention": ["Restart weekly"],
}
FAKE_INVENTORY = {
    "device_id": DEVICE, "device": "TALHAASHRAF-IT", "os_type": "Windows", "jobs": [],
    "inventory": {"collected_at": "2026-10-14T08:00:00+00:00", "count": 3, "updates_available": 1, "update_manager": "winget", "updates_note": None, "software": [
        {"id": "HKLM64|7zip", "name": "7-Zip 26.03 (x64)", "version": "26.03", "publisher": "Igor Pavlov", "install_date": "2026-09-01", "size_mb": 5.6, "scope": "machine",
         "uninstall_method": "quiet", "can_uninstall": True, "update_available": True, "available_version": "26.04", "update_id": "7zip.7zip"},
        {"id": "HKLM64|acrobat", "name": "Adobe Acrobat (64-bit)", "version": "26.0", "publisher": "Adobe", "install_date": None, "size_mb": 1169.6, "scope": "machine",
         "uninstall_method": "msi", "can_uninstall": True, "update_available": False},
        {"id": "HKLM64|3u", "name": "3uTools", "version": "9.07", "publisher": "Shenzhen", "install_date": None, "size_mb": None, "scope": "user",
         "uninstall_method": None, "can_uninstall": False, "update_available": False},
    ]},
}


def _done(tool_id, data, summary="ok"):
    return {"tool_id": tool_id, "args": {}, "state": "done", "ok": True, "summary": summary, "data": data}


PROCESSES = [{"name": "chrome.exe", "cpu_percent": 12.0, "memory_percent": 5.0, "memory": "800 MB"}]
FAKE_PERF_JOB = {
    "job_id": "pfake", "device_id": DEVICE, "device": "TALHAASHRAF-IT", "os_type": "Windows", "state": "done", "analysis_session_id": None,
    "started_at": "2026-10-16T12:00:00+00:00", "finished_at": "2026-10-16T12:02:00+00:00",
    "findings": [{"key": "boot_slow", "severity": "medium", "title": "Start-up is slow: the last boot took 95 s", "detail": "Slowed down by OneDrive.", "source": "boot_performance"}],
    "sections": {
        "system": _done("system_overview", {"cpu_percent": 20.5, "cpu_cores_logical": 12, "ram_percent": 71.0, "ram_used": "11 GB", "ram_total": "15.6 GB", "swap_percent": 10,
                                            "uptime": "3 days, 2:00:00", "process_count": 300, "disks": [{"mount": "C:\\", "used_percent": 82.3, "free": "41 GB", "total": "236 GB"}]}),
        "processes": _done("top_processes", PROCESSES), "memory": _done("top_processes", PROCESSES),
        "benchmark": _done("performance_benchmark", {"cpu": {"ops_per_second": 190000}, "disk": {"write_mbps": 330, "read_mbps": 570}, "network": {"average_latency_ms": 21.6, "available": True}}),
        "boot": _done("boot_performance", {"last_boot_seconds": 95.0, "average_boot_seconds": 70.0, "boots_measured": 2, "startup_programs": 11, "uptime_days": 3.1,
                                           "fast_startup": False, "last_boot_type": "full boot", "slowed_by": [{"name": "OneDrive", "kind": "app", "slower_by_ms": 6000, "total_ms": 9000}]}),
        "hardware": _done("hardware_health", {"model": "HP ProBook", "cpu": {"name": "i5-1235U", "performance_percent": 126}, "max_temperature_c": None, "ram_total": "15.6 GB",
                                              "gpus": [{"name": "Intel UHD", "ok": True}], "problem_devices": [], "hardware_errors_7d": 0}),
        "disks": _done("disk_health", [{"FriendlyName": "KINGSTON", "MediaType": "SSD", "HealthStatus": "Healthy", "SizeGB": 477}]),
        "battery": _done("battery_health", {"health_percent": 88.0, "full_charge_mwh": 40000, "design_mwh": 45000}),
        "input": _done("input_devices", {"devices": [{"name": "HID Keyboard Device", "kind": "keyboard", "connection": "built-in", "status": "working", "problem": None}], "keyboards": 1, "pointing": 0, "problems": 0}),
        "os_updates": _done("os_updates", {"source": "Windows Update", "can_install": True, "reboot_pending": False, "count": 2, "security_count": 1, "driver_count": 1, "updates": [
            {"id": "d125362d-3c64-4321-bd85-5bba34bb6dbf", "title": ".NET 8.0 Security Update (KB5130034)", "kind": "security", "size_text": "213 MB", "may_restart": True, "recommended": True, "installable": True, "note": None},
            {"id": "9839f3cc-8075-45a1-92a3-87d264ebad09", "title": "HP printer driver", "kind": "driver", "size_text": "13 MB", "may_restart": True, "recommended": False, "installable": False,
             "note": "Install this one from Windows Update on the device"}]}),
        "apps": _done("installed_software", {"count": 3, "updates_available": 2, "updates": [
            {"id": "a", "name": "7-Zip", "version": "26.03", "available_version": "26.04", "update_id": "7zip.7zip"},
            {"id": "b", "name": "Docker Desktop", "version": "4.76", "available_version": "4.95", "update_id": "Docker.DockerDesktop"}]}),
    },
}


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""), flush=True)


with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    page = browser.new_page(viewport={"width": 1366, "height": 900})
    page.on("pageerror", lambda error: errors.append(f"pageerror: {error}"))
    page.on("console", lambda message: errors.append(f"console.{message.type}: {message.text}") if message.type == "error" else None)

    page.goto(f"{BASE}/login")
    page.fill("input[name=password]", PASSWORD)
    page.press("input[name=password]", "Enter")
    page.wait_for_url(f"{BASE}/")
    page.wait_for_function("document.getElementById('ai-chip-text').textContent.startsWith('Model:')", timeout=15000)
    chip = page.inner_text("#ai-chip")
    check("model chip visible with Change label", "Model:" in chip and "Change" in chip, chip.replace("\n", " "))
    # The footer says "connected" only once data arrived, and the dashboard names the machine it shows.
    page.wait_for_function("document.getElementById('hostname').textContent !== '--'", timeout=30000)
    footer, source = page.inner_text("#connection-state"), page.inner_text("#server-source")
    check("dashboard shows live data and says whose", "connected" in footer.lower() and "Waiting" not in source, f"{footer.splitlines()[0]} / {source}")
    page.screenshot(path=str(OUT / "01-dashboard.png"))

    # Add Agent: the install command is ready at once, with no key to paste (and no token unless OPEN_ENROLLMENT=false).
    page.click("button.nav-item[data-tab=add-agent]")
    page.wait_for_function("document.getElementById('install-command').textContent.includes('/install/windows.ps1')", timeout=15000)
    check("Add Agent: install command ready to copy", page.locator("#admin-key-input").count() == 0 and not page.locator("#copy-install").is_disabled(), page.inner_text("#install-command")[:120])
    page.click("button.nav-item[data-tab=dashboard]")

    page.click("#ai-chip")
    page.wait_for_selector("#model-panel:not(.hidden) .model-option", timeout=10000)
    options = page.locator(".model-option").count()
    active = page.inner_text(".model-option.active strong")
    check("model panel lists models", options == 3, f"{options} options, active {active}")
    page.wait_for_timeout(400)  # let the 150 ms fade-in finish before judging the layering
    on_top = page.evaluate("""() => { const panel = document.getElementById('model-panel'); const r = panel.getBoundingClientRect();
        return [[r.left + 20, r.top + 20], [r.left + r.width / 2, r.top + r.height / 2], [r.right - 20, r.top + 100], [r.right - 20, r.bottom - 20]]
          .every(([x, y]) => panel.contains(document.elementFromPoint(x, y))); }""")
    check("model panel draws above the page", on_top)
    page.screenshot(path=str(OUT / "02-model-panel.png"))
    page.keyboard.press("Escape")
    check("Escape closes model panel", page.locator("#model-panel.hidden").count() == 1)

    page.click("button.nav-item[data-tab=agents]")
    page.wait_for_selector(f"[data-device='{DEVICE}']", timeout=15000)
    page.click(f"[data-device='{DEVICE}']")
    page.wait_for_selector("#device-onboarding .onb-head", timeout=20000)
    onboarding = page.inner_text("#device-onboarding")
    check("onboarding card rendered", "Onboarding health check" in onboarding, onboarding.splitlines()[0] if onboarding else "")

    page.route("**/agent-diagnose*", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(FAKE_AI)))
    page.click(f"[data-device-diagnose='{DEVICE}']")
    page.wait_for_selector(".hr-score", timeout=20000)
    page.wait_for_selector(".hr-ai-issue", timeout=20000)
    score = page.inner_text(".hr-score strong")
    issues = page.locator(".hr-issues li").count()
    cards = page.locator(".hr-card").count()
    check("health report rendered", issues > 0 and cards == 6, f"score {score}, {issues} issues, {cards} detail cards")
    check("AI analysis rendered", "Close unused Chrome tabs" in page.inner_text("#ai-analysis"))
    page.locator("#device-detail").screenshot(path=str(OUT / "03-health-report.png"))
    page.unroute("**/agent-diagnose*")

    open_button = page.locator("[data-onboarding-open]")
    if open_button.count():
        open_button.first.click()
        page.wait_for_selector("#ts-session:not(.hidden)", timeout=15000)
        page.wait_for_function("!document.getElementById('ts-report').textContent.includes('Loading session')", timeout=20000)
        check("Open full report opens the session", "troubleshoot" in page.url, page.inner_text("#ts-session-issue")[:80])
        page.screenshot(path=str(OUT / "04-onboarding-report.png"))
    else:
        check("Open full report button present", False, onboarding[:120])

    # Software tab against the real (old) agent: it must explain how to update the agent.
    page.click("button.nav-item[data-tab=software]")
    page.wait_for_function("document.getElementById('sw-device').options.length > 0", timeout=10000)
    page.select_option("#sw-device", DEVICE)
    page.wait_for_timeout(1500)
    if page.is_enabled("#sw-scan"):  # a device without an inventory yet starts its first scan by itself
        page.click("#sw-scan")
    page.wait_for_function("document.getElementById('sw-status').classList.contains('error') || document.getElementById('sw-body').querySelectorAll('tr td strong').length > 0", timeout=420000)
    status = page.inner_text("#sw-status")
    check("software scan reports a clear result", "too old" in status or page.locator("#sw-body tr td strong").count() > 0, status[:140])

    # Rendering, search, filter and confirm with a sample inventory.
    page.route(f"**/api/agents/{DEVICE}/software", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps(FAKE_INVENTORY)))
    page.evaluate(f"loadSoftware('{DEVICE}')")
    page.wait_for_selector("#sw-body [data-sw-uninstall]", timeout=10000)
    rows = page.locator("#sw-body tr").count()
    check("software table rendered", rows == 3 and page.locator("[data-sw-update]").count() == 1 and page.locator(".sw-manual").count() == 1, f"{rows} rows")
    page.screenshot(path=str(OUT / "05-software.png"))
    page.click("#sw-filter [data-filter=updates]")
    check("Updates filter", page.locator("#sw-body tr").count() == 1)
    page.click("#sw-filter [data-filter=all]")
    page.fill("#sw-search", "adobe")
    check("search filter", page.locator("#sw-body tr").count() == 1)
    page.fill("#sw-search", "")
    asked = []
    page.once("dialog", lambda dialog: (asked.append(dialog.message), dialog.dismiss()))
    posted = []
    page.on("request", lambda request: posted.append(request.url) if request.method == "POST" and "/software/uninstall" in request.url else None)
    page.click("#sw-body [data-sw-uninstall]")
    page.wait_for_timeout(800)
    check("uninstall asks for confirmation and cancel sends nothing", bool(asked) and not posted, asked[0][:60] if asked else "no dialog")

    # Phase 4: Remove completely -> leftover preview -> quarantine, with sample job results (nothing is removed).
    leftovers = {"scan_id": "0123456789ab", "program": "7-Zip 26.03 (x64)", "count": 3, "total_size_text": "12.0 MB", "candidates": [
        {"id": "c0", "kind": "folder", "path": r"C:\Program Files\7-Zip", "location": "Program Files", "confidence": "high", "reason": "folder named like the program", "size_text": "10.0 MB"},
        {"id": "c1", "kind": "registry", "path": r"HKLM\SOFTWARE\7-Zip", "location": "Registry", "confidence": "high", "reason": "registry key named like the program"},
        {"id": "c2", "kind": "folder", "path": r"C:\Users\me\AppData\Local\7", "location": "AppData Local", "confidence": "low", "reason": "partial name match", "size_text": "2.0 MB"}]}
    jobs = {"jun": {"state": "done", "summary": "Uninstalled 7-Zip", "device_id": DEVICE},
            "jlo": {"state": "done", "summary": "3 leftover(s) found", "device_id": DEVICE, "action": "leftovers", "data": leftovers, "job_id": "jlo"},
            "jq": {"state": "done", "summary": "1 quarantine batch(es)", "device_id": DEVICE, "data": {"days": 7, "batches": [
                {"batch_id": "20261016-120000-abcdef", "program": "Old App", "created": "2026-10-16T12:00:00+00:00", "expires": "2026-10-23T12:00:00+00:00", "items": 2, "size_text": "5.0 MB", "paths": [r"C:\Old App"]}]}}}
    page.route("**/software/uninstall", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"job_id": "jun"})))
    page.route("**/software/leftovers", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"job_id": "jlo"})))
    page.route("**/software/quarantine-list", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"job_id": "jq"})))
    def serve_job(route):
        job = jobs.get(route.request.url.rsplit("/", 1)[-1])
        # Jobs started for real earlier in this check pass through to the server.
        return route.fulfill(status=200, content_type="application/json", body=json.dumps(job)) if job else route.continue_()

    page.route("**/api/software/jobs/*", serve_job)
    page.once("dialog", lambda dialog: dialog.accept())  # "Remove 7-Zip completely?"
    page.click("#sw-body [data-sw-remove]")
    page.wait_for_selector("#sw-leftovers [data-lo-id]", timeout=20000)
    boxes = {box.get_attribute("data-lo-id"): box.is_checked() for box in page.locator("#sw-leftovers [data-lo-id]").all()}
    check("leftover preview: low-confidence items start unticked", boxes == {"c0": True, "c1": True, "c2": False}, str(boxes))
    page.locator("#sw-leftovers").screenshot(path=str(OUT / "09-leftovers.png"))
    quarantine_posts = []
    page.on("request", lambda request: quarantine_posts.append(request.url) if request.method == "POST" and request.url.endswith("/software/quarantine") else None)
    page.once("dialog", lambda dialog: dialog.dismiss())
    page.click("[data-lo-quarantine]")
    page.wait_for_timeout(800)
    check("quarantine asks first and cancel sends nothing", not quarantine_posts)
    page.click("#sw-quarantine-btn")
    page.wait_for_selector("#sw-quarantine [data-q-restore]", timeout=20000)
    check("quarantine panel lists restorable batches", page.locator("#sw-quarantine [data-q-restore]").count() == 1)
    page.locator("#sw-quarantine").screenshot(path=str(OUT / "10-quarantine.png"))
    for pattern in ("**/software/uninstall", "**/software/leftovers", "**/software/quarantine-list", "**/api/software/jobs/*"):
        page.unroute(pattern)
    page.unroute(f"**/api/agents/{DEVICE}/software")

    page.click("button.nav-item[data-tab=logs]")
    page.wait_for_function("document.getElementById('logs-device').options.length > 0", timeout=10000)
    page.wait_for_timeout(2000)
    check("Event Logs defaults to the device", page.input_value("#logs-device") == DEVICE, page.inner_text("#logs-body tr")[:80])
    page.click("button.nav-item[data-tab=technician]")
    page.wait_for_function("document.getElementById('chat-device').options.length > 0", timeout=10000)
    page.wait_for_timeout(2000)
    host = page.inner_text("#chat-host")
    check("Ask Technician uses the device's context", page.input_value("#chat-device") == DEVICE and host not in ("", "--"), host)
    page.wait_for_timeout(6000)  # one live-monitor tick must not overwrite it with the server's data
    check("live monitor leaves the chosen device's context alone", page.inner_text("#chat-host") == host)

    # Phase 3: suggest-only solutions, think toggles, decisions audit trail.
    check("Think deeper toggles exist", all(page.locator(f"#{name}").count() == 1 for name in ("chat-think", "logs-think")))
    # The sessions list carries only a summary; open each session to find one with solutions.
    with_solutions = page.evaluate("""async () => {
        const { sessions } = await fetch('/api/troubleshoot/sessions?limit=20').then((r) => r.json());
        for (const item of sessions) {
            const session = await fetch(`/api/troubleshoot/${item.session_id}`).then((r) => r.json());
            if ((session.report?.solutions || []).length) return session.session_id;
        }
        return null;
    }""")
    if with_solutions:
        page.click("button.nav-item[data-tab=troubleshoot]")
        page.evaluate(f"openTroubleshootSession('{with_solutions}')")
        page.wait_for_selector(".solution-card", timeout=20000)
        cards = page.locator(".solution-card").count()
        buttons = page.locator(".solution-card button").all_inner_texts()
        check("solution cards (3-4) with approve/done/reject", 3 <= cards <= 4 and "Reject" in buttons and any(b in buttons for b in ("Approve & run", "Mark as done", "Retry")), f"{cards} cards, buttons {sorted(set(buttons))}")
        page.locator("#ts-session").screenshot(path=str(OUT / "07-solutions.png"))
    else:
        check("a session with solutions exists", False, "run a diagnosis first")
    page.click("button.nav-item[data-tab=decisions]")
    page.wait_for_function("document.querySelectorAll('#decisions-body tr').length > 0", timeout=10000)
    page.wait_for_timeout(1000)
    rows = page.locator("#decisions-body tr").count()
    check("Decisions tab lists the audit trail", rows > 0 and "No decisions" not in page.inner_text("#decisions-body"), f"{rows} rows")
    page.screenshot(path=str(OUT / "08-decisions.png"))

    # Phase 5: Performance tab. The full test runs for real on the device (read-only checks only); the update
    # panel is then checked with a sample job, and every install/update click is cancelled at the confirmation.
    page.click("button.nav-item[data-tab=performance]")
    page.wait_for_function("document.getElementById('perf-device').options.length > 0", timeout=10000)
    page.select_option("#perf-device", DEVICE)
    page.wait_for_timeout(1500)
    page.click("#perf-run")
    page.wait_for_selector("#perf-sections .perf-card", timeout=20000)
    check("full test shows a card per section", page.locator("#perf-sections .perf-card").count() == 9)
    page.wait_for_function("!document.getElementById('perf-run').disabled", timeout=900000)
    states = page.evaluate("Object.fromEntries(Object.entries(perfJob.sections).map(([key, value]) => [key, value.state]))")
    check("every check of the real test finished", all(state in ("done", "failed", "skipped") for state in states.values()),
          ", ".join(f"{key}={value}" for key, value in states.items()))
    page.screenshot(path=str(OUT / "11-performance-real.png"), full_page=True)

    page.evaluate("(job) => { perfJob = job; renderPerformanceJob(); }", FAKE_PERF_JOB)
    boot_card = page.locator("[data-perf-section=boot]")
    check("a finding colours its card and names the culprit", "warning" in (boot_card.get_attribute("class") or "") and "OneDrive" in boot_card.inner_text())
    check("problems banner lists the rule findings", page.locator("#perf-findings:not(.hidden) .perf-finding").count() == 1)
    boxes = page.locator("#perf-updates [data-os-update]")
    check("only installable OS updates can be ticked (recommended ones start ticked)", boxes.count() == 1 and boxes.first.is_checked())
    check("app updates have Update buttons and Update all", page.locator("[data-perf-app-update]").count() == 2 and page.locator("[data-perf-app-all]").count() == 1)
    installs = []
    page.on("request", lambda request: installs.append(request.url) if request.method == "POST" and ("/os-updates/install" in request.url or "/software/update" in request.url) else None)
    asked = []
    page.once("dialog", lambda dialog: (asked.append(dialog.message), dialog.dismiss()))
    page.click("[data-perf-install-os]")
    page.wait_for_timeout(600)
    page.once("dialog", lambda dialog: (asked.append(dialog.message), dialog.dismiss()))
    page.click("[data-perf-app-update]")
    page.wait_for_timeout(600)
    check("installs ask first (restart warning included) and cancel sends nothing",
          len(asked) == 2 and "never restarts" in asked[0] and not installs, asked[0][:80] if asked else "no dialog")
    page.screenshot(path=str(OUT / "12-performance-sample.png"), full_page=True)

    page.click("#kb-tester")
    for key in ("KeyA", "Space", "Enter"):
        page.keyboard.press(key)
    page.keyboard.down("KeyB")
    page.wait_for_timeout(2600)
    page.keyboard.up("KeyB")
    check("keyboard tester lights keys and flags a held key", page.locator("#kb-layout .kb-key.tested").count() == 4 and page.locator("#kb-layout .kb-key.stuck").count() == 1,
          page.inner_text("#kb-result")[:120])
    pad = page.locator("#mouse-pad").bounding_box()
    page.mouse.move(pad["x"] + 40, pad["y"] + 120)
    for step in range(30):
        page.mouse.move(pad["x"] + 40 + step * 6, pad["y"] + 120 + (step % 5) * 4)
    page.mouse.move(pad["x"] + 120, pad["y"] + 150)
    for button in ("left", "right", "middle"):
        page.mouse.down(button=button)
        page.mouse.up(button=button)
        page.wait_for_timeout(150)
    page.mouse.down()
    page.mouse.up()
    page.wait_for_timeout(90)  # a fast human double-click
    page.mouse.down(click_count=2)
    page.mouse.up(click_count=2)
    page.mouse.wheel(0, -200)
    page.mouse.wheel(0, 200)
    page.wait_for_timeout(400)
    tested = page.locator("#mouse-pad .mouse-btn.tested").count()
    result = page.inner_text("#mouse-result")
    check("mouse tester registers buttons, double-click and scroll without leaving the page", tested == 6 and "#performance" in page.url and "worn" not in result, result[:120])
    page.locator(".perf-input-test").screenshot(path=str(OUT / "13-input-tester.png"))
    page.mouse.down()
    page.mouse.up()
    page.mouse.down()  # pressed again within a few ms: a bouncing switch
    page.mouse.up()
    page.wait_for_timeout(200)
    check("a bouncing mouse switch is flagged", "worn switch" in page.inner_text("#mouse-result"))

    if with_solutions:
        page.route("**/performance/analyse", lambda route: route.fulfill(status=200, content_type="application/json", body=json.dumps({"session_id": with_solutions, "mode": "fast"})))
        page.click("[data-perf-analyse]")
        page.wait_for_selector("#ts-session:not(.hidden)", timeout=15000)
        check("Analyse with AI opens the diagnosis with solution cards", "troubleshoot" in page.url and page.locator(".solution-card").count() >= 3)
        page.unroute("**/performance/analyse")

    mobile = browser.new_page(viewport={"width": 390, "height": 844})
    mobile.context.add_cookies(page.context.cookies())
    mobile.on("pageerror", lambda error: errors.append(f"mobile pageerror: {error}"))
    mobile.goto(f"{BASE}/#software")
    mobile.wait_for_timeout(2500)
    overflow = mobile.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    check("no horizontal scroll on phone width", overflow <= 1, f"overflow {overflow}px")
    mobile.goto(f"{BASE}/#performance")
    mobile.wait_for_timeout(2500)
    mobile.evaluate("(job) => { perfJob = job; renderPerformanceJob(); }", FAKE_PERF_JOB)
    overflow = mobile.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    check("Performance tab fits a phone (keyboard scrolls inside its box)", overflow <= 1, f"overflow {overflow}px")
    mobile.screenshot(path=str(OUT / "14-mobile-performance.png"), full_page=True)
    mobile.click("#ai-chip") if mobile.locator("#ai-chip").is_visible() else None
    mobile.wait_for_timeout(1500)
    mobile.screenshot(path=str(OUT / "06-mobile-model-panel.png"))
    browser.close()

check("no JavaScript errors", not errors, "; ".join(errors)[:600])
print(f"\n{sum(ok for _, ok, _ in results)}/{len(results)} browser checks passed", flush=True)
