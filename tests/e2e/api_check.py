"""End-to-end check of every agentic flow through the real API (run against the live server)."""

import json
import os
import sys
import time

import requests

BASE = os.getenv("AIOPS_URL", "http://localhost").rstrip("/")
DEVICE = sys.argv[2] if len(sys.argv) > 2 else "agent-69910f0b6612"
ONLY = set(sys.argv[3].split(",")) if len(sys.argv) > 3 else None
s = requests.Session()
assert s.post(f"{BASE}/login", data={"password": sys.argv[1]}, allow_redirects=False).status_code == 303, "login failed"
results = []


def log(text=""):
    print(text, flush=True)


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    log(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def wait_session(session_id, busy=("queued", "running", "fixing", "verifying"), limit=900):
    started = time.time()
    while time.time() - started < limit:
        session = s.get(f"{BASE}/api/troubleshoot/{session_id}").json()
        if session["status"] not in busy:
            return session, time.time() - started
        time.sleep(3)
    return session, time.time() - started


def show_session(session, elapsed):
    report = session.get("report") or {}
    log(f"  status={session['status']} in {elapsed:.0f}s error={session.get('error')}")
    for step in session.get("steps", []):
        result = step.get("result") or {}
        if step["kind"] in ("tool", "fix", "verify", "investigate"):
            log(f"    {step['kind']:<6} {step.get('tool_id') or '':<22} ok={result.get('ok')} {str(result.get('summary'))[:110]}")
        else:
            log(f"    {step['kind']:<6} {str(step.get('text') or '')[:130]}")
    log(f"  root_cause: {str(report.get('root_cause'))[:300]}")
    log(f"  confidence={report.get('confidence')} severity={report.get('severity')} mode={report.get('mode')} timing={report.get('timing')}")
    log(f"  findings: {[f.get('title') for f in report.get('quick_findings') or []]}")
    log(f"  fixes: {[(f['tool_id'], f['risk'], f['status']) for f in report.get('proposed_fixes') or []]}")
    log(f"  manual: {[m[:80] for m in report.get('manual_steps') or []]}")
    return report


def run_session(name, issue, mode, device=DEVICE, playbook=None):
    log(f"\n=== {name}: '{issue}' mode={mode} device={device}")
    response = s.post(f"{BASE}/api/troubleshoot", json={"issue": issue, "mode": mode, "device_id": device, "playbook_id": playbook})
    if response.status_code != 200:
        check(name, False, f"start failed {response.status_code} {response.text[:200]}")
        return None, {}
    session, elapsed = wait_session(response.json()["session_id"])
    report = show_session(session, elapsed)
    tool_steps = [step for step in session.get("steps", []) if step["kind"] == "tool"]
    failed_tools = [step["tool_id"] for step in tool_steps if not (step.get("result") or {}).get("ok")]
    check(f"{name}: finished diagnosed", session["status"] == "diagnosed", session["status"])
    check(f"{name}: tools ran on device", bool(tool_steps), f"{len(tool_steps)} tools, failed: {failed_tools}")
    check(f"{name}: has root cause", bool(report.get("root_cause")) and "could not determine" not in str(report.get("root_cause")))
    solutions = report.get("solutions") or []
    log(f"  solutions: {[(item['title'][:50], item.get('tool_id'), item.get('source')) for item in solutions]}")
    check(f"{name}: 3-4 suggested solutions", 3 <= len(solutions) <= 4, f"{len(solutions)} solutions")
    check(f"{name}: nothing ran without approval", not any(fix.get("status") in ("applied", "running") for fix in report.get("proposed_fixes") or []))
    if mode != "instant":
        log(f"  thinking: {(report.get('ai') or {}).get('thinking')} reasoning chars: {len(report.get('reasoning') or '')}")
    decisions = s.get(f"{BASE}/api/decisions?limit=20").json().get("decisions", [])
    check(f"{name}: diagnosis saved to decisions/", any(item["kind"] == "diagnosis" and item["subject_id"] == session["session_id"] for item in decisions))
    return session, report


def wanted(key):
    return ONLY is None or key in ONLY


if wanted("status"):
    log("=== AI status / models")
    status = s.get(f"{BASE}/api/ai/status").json()
    check("AI available", status.get("available") is True, f"{status.get('model')} load_error={status.get('load_error')}")
    targets = s.get(f"{BASE}/api/troubleshoot/targets").json()["targets"]
    device = next((t for t in targets if t["device_id"] == DEVICE), None)
    check("device online", bool(device) and device["status"] == "online", str(device))

if wanted("instant"):
    run_session("instant", "Internet is slow and websites take long to open", "instant")

if wanted("fast"):
    fast_session, fast_report = run_session("fast", "My laptop is very slow and hangs", "fast")

if wanted("deep"):
    run_session("deep", "Some websites do not open but others work", "deep")

if wanted("fix"):
    session, report = run_session("fix-source", "Websites stopped opening, maybe DNS", "fast")
    fixes = report.get("proposed_fixes") or []
    low = next((i for i, fix in enumerate(fixes) if fix["risk"] == "low"), None)
    if session and low is not None:
        log(f"\n=== apply fix #{low} {fixes[low]['tool_id']}")
        response = s.post(f"{BASE}/api/troubleshoot/{session['session_id']}/fixes/{low}/apply")
        check("apply accepted", response.status_code == 200, response.text[:150])
        time.sleep(2)
        after, elapsed = wait_session(session["session_id"])
        applied = (after.get("report") or {}).get("proposed_fixes", [])[low]
        log(f"  status={after['status']} in {elapsed:.0f}s fix={applied['status']} result={str((applied.get('result') or {}).get('summary'))[:150]}")
        log(f"  verify={json.dumps(after.get('verify'))[:400]}")
        check("fix applied on device", applied["status"] == "applied", applied["status"])
        check("re-check produced a verdict", bool(after.get("verify")), str((after.get("verify") or {}).get("method")))
        kinds = [item["kind"] for item in s.get(f"{BASE}/api/decisions?limit=20").json()["decisions"] if item["subject_id"] == session["session_id"]]
        check("approval and result saved to decisions/", {"fix_approved", "fix_result"} <= set(kinds), str(kinds))
        manual = next((i for i, item in enumerate(after["report"].get("solutions") or []) if item.get("status") == "suggested"), None)
        if manual is not None:
            response = s.post(f"{BASE}/api/troubleshoot/{session['session_id']}/solutions/{manual}/decision", json={"decision": "rejected"})
            kinds = [item["kind"] for item in s.get(f"{BASE}/api/decisions?limit=20").json()["decisions"] if item["subject_id"] == session["session_id"]]
            check("rejecting a solution is recorded", response.status_code == 200 and "fix_rejected" in kinds, response.text[:120])
    else:
        check("low-risk fix proposed", False, str([(f['tool_id'], f['risk']) for f in fixes]))

if wanted("chat"):
    log("\n=== chat")
    started = time.time()
    response = s.post(f"{BASE}/api/agent/chat", json={"message": "Why is my computer slow?", "session_id": "e2e", "device_id": DEVICE})
    body = response.json()
    log(f"  {response.status_code} in {time.time() - started:.0f}s: {json.dumps(body)[:500]}")
    check("chat answers about the laptop", response.status_code == 200 and bool((body.get("reply") or {}).get("plain_explanation")) and "WSL2" not in json.dumps(body))

if wanted("report"):
    log("\n=== AI health report")
    report = s.get(f"{BASE}/api/agents/{DEVICE}/health-report").json()
    check("health report", "score" in report, f"score={report.get('score')} issues={len(report.get('issues', []))}")
    started = time.time()
    response = s.post(f"{BASE}/api/agents/{DEVICE}/agent-diagnose")
    body = response.json()
    log(f"  {response.status_code} in {time.time() - started:.0f}s summary={str(body.get('summary'))[:300]}")
    log(f"  issues explained: {[(i.get('title') or '')[:50] for i in body.get('issues', [])]}")
    check("AI analysis explains issues", response.status_code == 200 and bool(body.get("issues")), f"{len(body.get('issues', []))} issues")

if wanted("logs"):
    log("\n=== event-log diagnosis (server)")
    started = time.time()
    response = s.post(f"{BASE}/api/agents/{DEVICE}/logs/diagnose")
    log(f"  {response.status_code} in {time.time() - started:.0f}s: {response.text[:300]}")
    check("event-log diagnosis of the laptop", response.status_code == 200 and "No summary returned" not in response.text)

if wanted("local"):
    run_session("local-instant", "Disk is full", "instant", device="local")

log("\n=== SUMMARY")
for name, ok, detail in results:
    log(f"  {'PASS' if ok else 'FAIL'}  {name}  {detail}")
log(f"  {sum(ok for _, ok, _ in results)}/{len(results)} passed")
