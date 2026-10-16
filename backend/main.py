"""FastAPI server for a local, Wazuh-inspired, AI-powered device health monitor."""

import asyncio
import io
import json
import logging
import os
import re
import secrets
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from agent.toolkit import TOOLKIT_VERSION, describe_tools, get_tool

from . import decision_log, health_report, public_url, software_store, task_signals
from .actions import run_action
from .agent_brain import events as troubleshoot_events
from .agent_brain import findings as rule_findings
from .agent_brain import session_store
from .agent_brain.executor import LOCAL_DEVICE_ID, execute, resolve_target
from .agent_brain.planner import apply_fix, decide_solution, default_mode, diagnosis_thinking, normalize_mode, run_diagnosis
from .agent_brain.playbooks import get_playbook, public_playbooks
from .learning import model_builder
from .learning import store as learning_store
from .llm import catalog as llm_catalog
from .llm import get_provider as get_llm_provider
from .ai_technician import AIModelUnavailableError, AIUnavailableError, ai_status, chat, diagnose, diagnose_logs, is_ai_available, review_leftovers
from .alert_store import add_alert, get_alerts
from .auth import SESSION_COOKIE_NAME, auth_enabled, check_password, has_valid_session, is_public_path, session_token
from .collectors import collect_report
from .device_store import claim_onboarding, create_pending_token, delete_device, get_device, get_device_by_token, get_latest_report, is_valid_install_token, list_devices, mark_offline_devices, register_device, save_report, set_onboarding_session
from .event_logs import collect_event_log_report
from .performance_checks import collect_performance_report
from .rules_engine import evaluate_event_log_rules, evaluate_performance_rules, evaluate_rules, evaluate_security_rules, health_from_report
from .security_checks import collect_security_report
from .task_queue import claim_next_task, complete_task, list_tasks

@asynccontextmanager
async def lifespan(_app):
    # start_monitor is defined further down; it is looked up when the server starts, not at import.
    await start_monitor()
    yield


app = FastAPI(title="AIops Device Health Monitor", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
INSTALL_TEMPLATES_DIR = Path(__file__).resolve().parent / "install_templates"
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

logger = logging.getLogger(__name__)
# Uvicorn only configures its own loggers; without this the app's INFO lines (AI timings,
# model preload, session failures below ERROR) never reach `docker compose logs`.
logging.getLogger("backend").setLevel(logging.INFO)
if not logging.getLogger().handlers:
    logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# In-memory state for the local-server monitor loop and its dashboard-facing caches.
connections = set()
previous_report = None
previous_reports = {}
chat_sessions = {}
background_tasks = set()
latest_security_report = None
latest_performance_report = None
latest_event_log_report = None

SECURITY_REFRESH_SECONDS = 300
EVENT_LOG_REFRESH_SECONDS = 600


# ============================================================================
# Auth
# ============================================================================

def require_admin(request):
    """Stricter, separate gate for provisioning actions (generate/revoke agent tokens)."""
    configured = os.getenv("ADMIN_API_KEY", "").strip()
    if not configured or not secrets.compare_digest(request.headers.get("X-Admin-Key", ""), configured):
        raise HTTPException(status_code=401, detail="Admin authentication required")


@app.middleware("http")
async def revalidate_frontend_middleware(request: Request, call_next):
    """Without this, browsers keep serving a cached dashboard for hours after an update, so new
    features (e.g. the model switcher) do not appear. no-cache still allows cheap ETag 304s."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path == "/login" or path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


@app.middleware("http")
async def dashboard_auth_middleware(request: Request, call_next):
    path = request.url.path
    if not auth_enabled() or is_public_path(path):
        return await call_next(request)
    if has_valid_session(request.cookies):
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse(status_code=401, content={"detail": "Login required"})
    return RedirectResponse(url="/login")


@app.get("/login", include_in_schema=False)
def login_page():
    return FileResponse(FRONTEND_DIR / "login.html")


@app.post("/login", include_in_schema=False)
async def login_submit(request: Request):
    form = await request.form()
    if not check_password(str(form.get("password", ""))):
        return RedirectResponse(url="/login?error=1", status_code=303)
    response = RedirectResponse(url="/", status_code=303)
    # Secure over https (ngrok); plain http on the LAN still needs a non-secure cookie to work.
    response.set_cookie(SESSION_COOKIE_NAME, session_token(), httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30, secure=request.url.scheme == "https")
    return response


@app.get("/logout", include_in_schema=False)
def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response


# ============================================================================
# Startup and background loops
# ============================================================================

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled server error for %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def snapshot_with_alerts(report):
    global previous_report
    for alert in evaluate_rules(report, previous_report):
        add_alert(alert, "local-server")
    previous_report = report
    return report


async def start_monitor():
    logger.info("Registered FastAPI routes:")
    for route in app.routes:
        methods = ",".join(sorted(getattr(route, "methods", set()) or []))
        route_line = f"  {methods or 'WEBSOCKET'} {route.path}"
        logger.info(route_line)
        print(route_line, flush=True)
    if auth_enabled():
        logger.info("Dashboard login is enabled (DASHBOARD_PASSWORD/ADMIN_API_KEY set).")
    else:
        logger.warning("Dashboard login is disabled: set DASHBOARD_PASSWORD or ADMIN_API_KEY in .env to require sign-in.")
    session_store.mark_interrupted_sessions()
    global main_loop
    main_loop = asyncio.get_running_loop()
    status = ai_status()
    logger.info("AI provider: %s / %s - %s", status.get("provider"), status.get("model"), status.get("message"))
    _spawn(asyncio.to_thread(prepare_ai, "startup"))
    asyncio.create_task(monitor_loop())
    asyncio.create_task(offline_loop())
    asyncio.create_task(security_loop())
    asyncio.create_task(event_log_loop())


def prepare_ai(reason):
    """Create or refresh the aiops-brain model for the selected base model, then load it into RAM."""
    try:
        info = model_builder.ensure_brain(reason)
        if info:
            logger.info("Built %s v%s on %s (%s)", info["model"], info["version"], info["base_model"], reason)
            getattr(get_llm_provider(), "refresh", lambda: None)()
    except Exception:
        logger.warning("Could not prepare the aiops-brain model", exc_info=True)
    warm_up_llm()


def _ai_label(device_id):
    target = resolve_target(device_id) if device_id else None
    return target.label if target else device_id


def _record_ai(kind, device_id, think, payload, used_ai=True):
    """Decision-log entry for a one-shot AI answer (health analysis, log analysis, chat). Answers written
    without the model (e.g. "no events to analyse") are recorded as rules, not credited to the AI."""
    decision_log.record(kind, device_id or LOCAL_DEVICE_ID, {
        "device": _ai_label(device_id or LOCAL_DEVICE_ID), "device_id": device_id or LOCAL_DEVICE_ID,
        "model": getattr(get_llm_provider(), "model", None) if used_ai else None, "thinking": bool(think) and used_ai,
        "source": "ai" if used_ai else "rules", "approved_by": None, **payload,
    })


def warm_up_llm():
    """Preload the model so the first diagnosis does not wait for it to load from disk."""
    warm = getattr(get_llm_provider(), "warm_up", None)
    try:
        if warm and warm():
            logger.info("AI model preloaded")
    except Exception:
        logger.warning("Could not preload the AI model", exc_info=True)


async def monitor_loop():
    while True:
        try:
            report = snapshot_with_alerts(collect_report())
            for connection in list(connections):
                try:
                    await connection.send_json(report)
                except Exception:
                    connections.discard(connection)
        except Exception:
            pass
        await asyncio.sleep(5)


async def offline_loop():
    while True:
        try:
            mark_offline_devices()
        except Exception:
            logger.exception("Failed to update remote device statuses")
        await asyncio.sleep(10)


async def refresh_security():
    global latest_security_report
    report = await asyncio.to_thread(collect_security_report)
    for alert in evaluate_security_rules(report):
        add_alert(alert, "local-server")
    latest_security_report = report
    return report


async def security_loop():
    while True:
        try:
            await refresh_security()
        except Exception:
            logger.exception("Security check failed")
        await asyncio.sleep(SECURITY_REFRESH_SECONDS)


async def refresh_performance():
    """Run the active benchmark suite. Called on demand only (see /api/diagnostics/performance);
    unlike security or event-log checks it briefly writes to disk and uses CPU, so it never runs
    on a timer here."""
    global latest_performance_report
    previous = latest_performance_report
    report = await asyncio.to_thread(collect_performance_report)
    for alert in evaluate_performance_rules(report, previous):
        add_alert(alert, "local-server")
    latest_performance_report = report
    return report


async def refresh_event_logs():
    global latest_event_log_report
    report = await asyncio.to_thread(collect_event_log_report)
    for alert in evaluate_event_log_rules(report):
        add_alert(alert, "local-server")
    latest_event_log_report = report
    return report


async def event_log_loop():
    while True:
        try:
            await refresh_event_logs()
        except Exception:
            logger.exception("Event log check failed")
        await asyncio.sleep(EVENT_LOG_REFRESH_SECONDS)


# ============================================================================
# Local device diagnostics
# ============================================================================

@app.get("/", include_in_schema=False)
def frontend():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/diagnostics")
def diagnostics():
    return snapshot_with_alerts(collect_report())


@app.get("/api/diagnostics/health")
def health():
    return health_from_report(collect_report())


@app.websocket("/ws/monitor")
async def monitor(websocket: WebSocket):
    await websocket.accept()
    if not has_valid_session(websocket.cookies):
        await websocket.close(code=4401)
        return
    connections.add(websocket)
    try:
        await websocket.send_json(snapshot_with_alerts(collect_report()))
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        connections.discard(websocket)


@app.get("/api/diagnostics/security")
async def security():
    if latest_security_report is None:
        return await refresh_security()
    return latest_security_report


@app.get("/api/diagnostics/performance")
def performance():
    if latest_performance_report is None:
        return JSONResponse(status_code=404, content={"detail": "No performance test has run yet. POST to this endpoint to run one."})
    return latest_performance_report


@app.post("/api/diagnostics/performance")
async def run_performance():
    return await refresh_performance()


@app.get("/api/diagnostics/logs")
async def event_logs_endpoint():
    if latest_event_log_report is None:
        return await refresh_event_logs()
    return latest_event_log_report


@app.post("/api/diagnostics/logs/diagnose")
def diagnose_event_logs_endpoint(think: bool = False):
    if not is_ai_available():
        raise HTTPException(status_code=503, detail=ai_status().get("message", "AI technician unavailable"))
    if latest_event_log_report is None:
        raise HTTPException(status_code=404, detail="No event log data collected yet")
    try:
        result = diagnose_logs(latest_event_log_report, think=think)
    except (AIModelUnavailableError, AIUnavailableError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    _record_ai("log_analysis", LOCAL_DEVICE_ID, think, {"summary": result.get("summary"), "root_cause": result.get("root_cause"), "steps": result.get("steps")}, used_ai=result.get("source") != "rules")
    return result


@app.get("/api/alerts")
def alerts(limit: int = 100):
    return {"alerts": get_alerts(max(1, min(limit, 500)), "local-server")}


# ============================================================================
# Remote agent provisioning and reporting
# ============================================================================

@app.post("/api/agents/generate-token")
def generate_agent_token(request: Request):
    require_admin(request)
    token, expires_at = create_pending_token()
    return {"token": token, "expires_at": expires_at, "message": "Use this token once when registering a new agent."}


@app.post("/api/agents/register")
def register_agent(payload: dict):
    token = str(payload.get("token", "")).strip()
    hostname = str(payload.get("hostname", "Unknown")).strip()
    if not token or not hostname:
        raise HTTPException(status_code=400, detail="token and hostname are required")
    try:
        return register_device(token, hostname, str(payload.get("os_type", "Unknown")), str(payload.get("nickname", "")), payload.get("device_id"), allow_open=open_enrollment())
    except ValueError as error:
        raise HTTPException(status_code=401, detail="Invalid or expired agent token") from error


def authenticated_device(request: Request):
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer agent token required")
    device = get_device_by_token(authorization[7:].strip())
    if not device:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return device


@app.post("/api/agents/report")
def agent_report(payload: dict, request: Request):
    device = authenticated_device(request)
    diagnostics_payload = payload.get("diagnostics")
    if not isinstance(diagnostics_payload, dict):
        raise HTTPException(status_code=400, detail="diagnostics object is required")

    device_id = device["device_id"]
    previous = previous_reports.get(device_id) or {}
    alerts_for_report = (
        evaluate_rules(diagnostics_payload, previous)
        + evaluate_security_rules(diagnostics_payload.get("security"))
        + evaluate_performance_rules(diagnostics_payload.get("performance"), previous.get("performance"))
        + evaluate_event_log_rules(diagnostics_payload.get("event_logs"))
    )
    for alert in alerts_for_report:
        add_alert(alert, device_id)
    previous_reports[device_id] = diagnostics_payload

    timestamp = str(payload.get("timestamp") or datetime.now(timezone.utc).isoformat())
    save_report(device_id, timestamp, diagnostics_payload, payload.get("spike_detected", False))
    if onboarding_enabled():
        _ensure_onboarding(device)
    return {"accepted": True, "device_id": device_id, "alerts_created": len(alerts_for_report)}


ONBOARDING_ISSUE = "Onboarding health check: full diagnosis of a newly connected device"
main_loop = None
onboarding_rechecked = set()  # devices whose onboarding was checked for restart damage since this server started


def _ensure_onboarding(device):
    """Start the onboarding check on a device's first report, and re-run it once if a server
    restart cut it short (restarts mark running sessions failed, which would skip it forever)."""
    device_id, session_id = device["device_id"], device.get("onboarding_session_id")
    if not session_id:
        if claim_onboarding(device_id, "starting") and not start_onboarding_check(device_id):
            set_onboarding_session(device_id, None)  # retried on the next report
        return
    if device_id in onboarding_rechecked:
        return
    onboarding_rechecked.add(device_id)
    session = session_store.get_session(session_id, include_steps=False) if session_id != "starting" else None
    if session_id == "starting" or (session and session["status"] == "failed" and "server restart" in (session.get("error") or "")):
        start_onboarding_check(device_id)


def onboarding_enabled():
    return os.getenv("ONBOARDING_CHECK", "true").strip().lower() in ("1", "true", "yes")


def start_onboarding_check(device_id):
    """Run a full check-up with AI on a device, recorded as its onboarding report. Called from the
    report handler's worker thread, so the diagnosis is handed to the event loop."""
    target = resolve_target(device_id)
    if target is None or main_loop is None:
        return None
    session_id = session_store.create_session(target.device_id, target.label, target.os_type, ONBOARDING_ISSUE, "full_checkup")
    set_onboarding_session(device_id, session_id)
    main_loop.call_soon_threadsafe(lambda: _spawn(run_diagnosis(session_id, default_mode())))
    logger.info("Onboarding check %s started for %s", session_id, device_id)
    return session_id


@app.get("/api/agents/{device_id}/onboarding")
def onboarding_status(device_id: str):
    device = get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    session_id = device.get("onboarding_session_id")
    session = session_store.get_session(session_id, include_steps=False) if session_id and session_id != "starting" else None
    if not session:
        return {"session_id": None, "status": "starting" if session_id else "none"}
    report = session.get("report") or {}
    return {
        "session_id": session_id, "status": session["status"], "created_at": session.get("created_at"),
        "root_cause": report.get("root_cause"), "severity": report.get("severity"), "confidence": report.get("confidence"),
        "findings": [item.get("title") for item in report.get("quick_findings") or []][:8],
        "fixes": len(report.get("proposed_fixes") or []), "manual_steps": len(report.get("manual_steps") or []),
    }


@app.post("/api/agents/{device_id}/onboarding")
async def rerun_onboarding(device_id: str):
    if not get_device(device_id):
        raise HTTPException(status_code=404, detail="Device not found")
    session_id = await asyncio.to_thread(start_onboarding_check, device_id)
    if not session_id:
        raise HTTPException(status_code=409, detail="Could not start the health check")
    return {"session_id": session_id}


# ============================================================================
# Software tab: inventory, uninstall and update (long-running, so run as jobs)
# ============================================================================

software_jobs = {}
SOFTWARE_JOBS_KEPT = 200
# Tools whose result data the dashboard needs to show (the rest only report a summary).
JOB_DATA_TOOLS = {"find_leftovers", "quarantine_leftovers", "restore_quarantine", "list_quarantine", "install_os_updates"}
CANDIDATE_ID_PATTERN = re.compile(r"^c\d{1,3}$")
SCAN_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
BATCH_ID_PATTERN = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
OLD_AGENT_MESSAGE = "This device's agent is too old for software management. Re-run the install command from Add Agent on the device to update it."


def _software_target(device_id, manage=False):
    target = resolve_target(device_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if manage and target.is_local and os.getenv("SENTINEL_IN_DOCKER"):
        raise HTTPException(status_code=400, detail="The server container's packages come from its Docker image: rebuild the image instead of changing them here.")
    return target


def _change_in_progress(device_id):
    """What is changing this device right now (a Software/Performance job or an approved fix), or None.
    The agent runs changes one at a time: a second one would wait behind the first, and the server could
    report it as failed while the agent still runs it later."""
    for job in list(software_jobs.values()):
        if job["device_id"] == device_id and job["state"] == "running" and job.get("risk", "read") != "read":
            return f"{job['action']} of {job['name']}"
    for session in session_store.list_sessions(device_id, 20):
        if session["status"] == "fixing":
            return f"an approved fix for \"{session['issue'][:80]}\""
    return None


def _refuse_if_changing(device_id):
    busy = _change_in_progress(device_id)
    if busy:
        raise HTTPException(status_code=409, detail=f"Wait until the {busy} on this device has finished: changes run one at a time.")


def _start_software_job(target, action, name, tool_id, args, max_risk):
    if max_risk != "read":
        _refuse_if_changing(target.device_id)
    finished = [job_id for job_id, job in list(software_jobs.items()) if job["state"] != "running"]
    for job_id in finished[: max(0, len(software_jobs) - SOFTWARE_JOBS_KEPT + 1)]:
        software_jobs.pop(job_id, None)
    job = {"job_id": secrets.token_hex(8), "device_id": target.device_id, "device": target.label, "action": action, "name": name, "state": "running",
           "risk": max_risk, "summary": None, "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None}
    software_jobs[job["job_id"]] = job
    _spawn(_run_software_job(job, target, tool_id, args, max_risk))
    return job


async def _run_software_job(job, target, tool_id, args, max_risk):
    tool = get_tool(tool_id)
    changes_device = tool is not None and tool.risk != "read"
    if changes_device:
        # Recorded before it runs: an OS update can take an hour, and a restart meanwhile must not leave a
        # changed device without a record of who approved what.
        await asyncio.to_thread(decision_log.record, "software_action", target.device_id, {
            "device": target.label, "device_id": target.device_id, "action": f"{job['action']} {job['name']}", "tool_id": tool_id,
            "args": args, "approved_by": "operator", "state": "approved", "job_id": job["job_id"]})
    try:
        result = await execute(target, tool_id, args, max_risk)
    except Exception as error:  # the job must still finish in the dashboard
        logger.exception("Software job %s failed", job["job_id"])
        result = {"ok": False, "summary": f"{job['action']} failed: {error}"}
    ok = bool(result.get("ok"))
    summary = result.get("summary") or ""
    if not ok and "Unknown or disallowed tool" in summary:
        summary = OLD_AGENT_MESSAGE
    if ok and tool_id == "installed_software":
        await asyncio.to_thread(software_store.save_inventory, target.device_id, result.get("data") or {})
    elif ok and tool_id == "uninstall_software":
        await asyncio.to_thread(software_store.mark_uninstalled, target.device_id, args["id"])
    elif ok and tool_id == "update_software":
        await asyncio.to_thread(software_store.mark_updated, target.device_id, args["package_id"])
    if changes_device:
        await asyncio.to_thread(session_store.add_audit, None, target.device_id, tool_id, {**args, "name": job["name"]}, "operator (Software tab)", ok, summary)
        await asyncio.to_thread(decision_log.record, "software_action", target.device_id, {
            "device": target.label, "device_id": target.device_id, "action": f"{job['action']} {job['name']}", "tool_id": tool_id,
            "args": args, "approved_by": "operator", "state": "finished", "job_id": job["job_id"], "ok": ok, "result": summary})
    data = result.get("data") if tool_id in JOB_DATA_TOOLS else None
    job.update(state="done" if ok else "failed", summary=summary, data=data, finished_at=datetime.now(timezone.utc).isoformat())


@app.get("/api/agents/{device_id}/software")
def device_software(device_id: str):
    target = _software_target(device_id)
    running = [job for job in list(software_jobs.values()) if job["device_id"] == target.device_id and job["state"] == "running"]
    return {"device_id": target.device_id, "device": target.label, "os_type": target.os_type, "inventory": software_store.get_inventory(target.device_id), "jobs": running}


@app.post("/api/agents/{device_id}/software/scan")
async def scan_device_software(device_id: str):
    target = _software_target(device_id)
    running = next((job for job in list(software_jobs.values()) if job["device_id"] == target.device_id and job["action"] == "scan" and job["state"] == "running"), None)
    return running or _start_software_job(target, "scan", "Software inventory", "installed_software", {"check_updates": True}, "read")


@app.post("/api/agents/{device_id}/software/uninstall")
async def uninstall_device_software(device_id: str, payload: dict):
    target = _software_target(device_id, manage=True)
    entry_id = str(payload.get("id") or "").strip()
    if not entry_id:
        raise HTTPException(status_code=400, detail="id is required")
    return _start_software_job(target, "uninstall", str(payload.get("name") or entry_id)[:200], "uninstall_software", {"id": entry_id}, "high")


@app.post("/api/agents/{device_id}/software/update")
async def update_device_software(device_id: str, payload: dict):
    target = _software_target(device_id, manage=True)
    package_id = str(payload.get("package_id") or "").strip()
    if not package_id:
        raise HTTPException(status_code=400, detail="package_id is required")
    return _start_software_job(target, "update", str(payload.get("name") or package_id)[:200], "update_software", {"package_id": package_id}, "medium")


@app.post("/api/agents/{device_id}/software/leftovers")
async def find_device_leftovers(device_id: str, payload: dict):
    """Preview what an uninstalled program left behind (read-only scan on the device)."""
    target = _software_target(device_id, manage=True)
    entry_id = str(payload.get("id") or "").strip()
    if not entry_id or len(entry_id) > 600:
        raise HTTPException(status_code=400, detail="id is required")
    return _start_software_job(target, "leftovers", str(payload.get("name") or entry_id)[:200], "find_leftovers", {"id": entry_id}, "read")


@app.post("/api/agents/{device_id}/software/quarantine")
async def quarantine_device_leftovers(device_id: str, payload: dict):
    """Move the leftovers a person ticked to the device's quarantine (restorable for 7 days)."""
    target = _software_target(device_id, manage=True)
    scan_id = str(payload.get("scan_id") or "")
    ids = payload.get("candidate_ids") or []
    if not SCAN_ID_PATTERN.fullmatch(scan_id) or not isinstance(ids, list) or not ids or len(ids) > 60 or not all(isinstance(item, str) and CANDIDATE_ID_PATTERN.fullmatch(item) for item in ids):
        raise HTTPException(status_code=400, detail="scan_id and a list of candidate ids are required")
    return _start_software_job(target, "quarantine", str(payload.get("name") or "leftovers")[:200], "quarantine_leftovers",
                               {"scan_id": scan_id, "candidate_ids": ",".join(ids)}, "high")


@app.post("/api/agents/{device_id}/software/restore")
async def restore_device_quarantine(device_id: str, payload: dict):
    target = _software_target(device_id, manage=True)
    batch_id = str(payload.get("batch_id") or "")
    if not BATCH_ID_PATTERN.fullmatch(batch_id):
        raise HTTPException(status_code=400, detail="batch_id is required")
    return _start_software_job(target, "restore", str(payload.get("name") or batch_id)[:200], "restore_quarantine", {"batch_id": batch_id}, "medium")


@app.post("/api/agents/{device_id}/software/quarantine-list")
async def list_device_quarantine(device_id: str):
    target = _software_target(device_id, manage=True)
    return _start_software_job(target, "quarantine-list", "Quarantine", "list_quarantine", {}, "read")


@app.post("/api/agents/{device_id}/software/leftovers/review")
def review_device_leftovers(device_id: str, payload: dict):
    """AI advice on a finished leftover scan (which items look shared or risky). Advice only: nothing moves."""
    job = software_jobs.get(str(payload.get("job_id") or ""))
    if not job or job["device_id"] != device_id or job["action"] != "leftovers" or not (job.get("data") or {}).get("candidates"):
        raise HTTPException(status_code=404, detail="Run a leftover scan first")
    if not is_ai_available():
        raise HTTPException(status_code=503, detail=ai_status().get("message", "AI technician unavailable"))
    think = bool(payload.get("think"))
    try:
        result = review_leftovers(job["data"].get("program"), job["data"]["candidates"], think=think)
    except (AIModelUnavailableError, AIUnavailableError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    _record_ai("leftover_review", device_id, think, {"summary": result.get("summary"), "program": job["data"].get("program"), "advice": result.get("items")})
    return result


@app.get("/api/software/jobs/{job_id}")
def software_job(job_id: str):
    job = software_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found (the server may have restarted)")
    return job


@app.post("/api/agents/{device_id}/os-updates/install")
async def install_device_os_updates(device_id: str, payload: dict):
    """Install the OS updates a person ticked (ids from the device's own os_updates search). Never restarts."""
    target = _software_target(device_id, manage=True)
    ids = payload.get("update_ids") or []
    if not isinstance(ids, list) or not ids or len(ids) > MAX_OS_UPDATE_IDS or not all(isinstance(item, str) and OS_UPDATE_ID_PATTERN.fullmatch(item) for item in ids):
        raise HTTPException(status_code=400, detail="update_ids must list the updates to install (ids from the update search)")
    name = f"{len(ids)} OS update{'s' if len(ids) != 1 else ''}"
    return _start_software_job(target, "os-update", name, "install_os_updates", {"update_ids": ",".join(ids)}, "high")


# ---------------------------------------------------------------------------
# Performance tab: one full test per device, shown section by section as each check finishes
# ---------------------------------------------------------------------------

performance_jobs = {}
PERFORMANCE_JOBS_KEPT = 50
MAX_OS_UPDATE_IDS = 50
OS_UPDATE_ID_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,199})$")
# Phases run one after another and the checks inside a phase run side by side. Live CPU and memory readings
# come first and the benchmark runs alone, so the other checks' PowerShell work skews neither.
PERFORMANCE_PHASES = (
    (("system", "system_overview", {}), ("processes", "top_processes", {"sort_by": "cpu"}), ("memory", "top_processes", {"sort_by": "memory"})),
    (("benchmark", "performance_benchmark", {}),),
    (("os_updates", "os_updates", {}), ("apps", "installed_software", {"check_updates": True}), ("boot", "boot_performance", {}),
     ("hardware", "hardware_health", {}), ("disks", "disk_health", {}), ("battery", "battery_health", {}), ("input", "input_devices", {})),
)
# Keyboard and mouse status is shown, but it has nothing to do with speed, so the AI analysis leaves it out.
ANALYSIS_SKIPPED_SECTIONS = {"input"}
NEW_AGENT_MESSAGE = "This check needs the newer agent: re-run the install command from Add Agent on the device."


IMAGE_MANAGED_NOTE = "The server container's packages come from its Docker image: rebuild the image to update them."


def _image_managed(target):
    return target.is_local and bool(os.getenv("SENTINEL_IN_DOCKER"))


def _app_updates(inventory, can_update=True):
    """The Performance tab only needs the programs with an update (the full list is in the Software tab)."""
    software = (inventory or {}).get("software") or []
    updates = [{key: item.get(key) for key in ("id", "name", "version", "available_version", "update_id", "update_source")} for item in software if item.get("update_available") and item.get("update_id")]
    note = (inventory or {}).get("updates_note") if can_update else IMAGE_MANAGED_NOTE
    return {"count": len(software), "updates_available": len(updates), "updates": updates[:100], "updates_note": note, "can_update": can_update}


async def _run_performance_check(job, target, section, tool_id, args):
    entry = job["sections"][section]
    tool = get_tool(tool_id)
    if tool is None or target.os_type not in tool.os:
        entry.update(state="skipped", ok=False, summary=f"Not available on {target.os_type}")
        return
    entry["state"] = "running"
    try:
        result = await execute(target, tool_id, args, "read")
    except Exception as error:  # one broken check must not stop the others
        logger.exception("Performance check %s failed", tool_id)
        result = {"ok": False, "summary": f"{tool_id} failed: {error}"}
    ok, summary, data = bool(result.get("ok")), result.get("summary") or "", result.get("data")
    if not ok and "Unknown or disallowed tool" in summary:
        summary = NEW_AGENT_MESSAGE
    if ok and tool_id == "installed_software":
        await asyncio.to_thread(software_store.save_inventory, target.device_id, data or {})
        data = _app_updates(data, can_update=not _image_managed(target))
    elif ok and tool_id == "os_updates" and isinstance(data, dict) and _image_managed(target):
        data = {**data, "can_install": False, "install_note": IMAGE_MANAGED_NOTE}
    entry.update(state="done" if ok else "failed", ok=ok, summary=summary, data=data, duration_ms=result.get("duration_ms"))
    # Instant rule findings (milliseconds) so each card can show what is wrong while the rest still runs.
    evidence = [(item["tool_id"], item["args"], {"ok": item["ok"], "summary": item["summary"], "data": item["data"]}) for item in list(job["sections"].values()) if item["state"] == "done"]
    job["findings"] = [{key: item[key] for key in ("key", "severity", "title", "detail", "source")} for item in rule_findings.analyze(evidence, target.os_type)]


async def _run_performance_job(job, target):
    try:
        for phase in PERFORMANCE_PHASES:
            await asyncio.gather(*(_run_performance_check(job, target, section, tool_id, args) for section, tool_id, args in phase))
    except Exception:
        logger.exception("Performance test %s failed", job["job_id"])
    finally:
        job.update(state="done", finished_at=datetime.now(timezone.utc).isoformat())


def _performance_target(device_id):
    target = resolve_target(device_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return target


@app.post("/api/agents/{device_id}/performance/test")
async def start_performance_test(device_id: str):
    """Run every read-only performance, hardware and update check on the device. Nothing is changed."""
    target = _performance_target(device_id)
    running = next((job for job in list(performance_jobs.values()) if job["device_id"] == target.device_id and job["state"] == "running"), None)
    if running:
        return running
    if not target.is_local and target.status != "online":
        # Its checks would only time out one by one (minutes) while nobody picks them up.
        raise HTTPException(status_code=409, detail=f"{target.label} is offline: start the device (its agent connects by itself), then run the test")
    finished = [job_id for job_id, job in list(performance_jobs.items()) if job["state"] != "running"]
    for job_id in finished[: max(0, len(performance_jobs) - PERFORMANCE_JOBS_KEPT + 1)]:
        performance_jobs.pop(job_id, None)
    sections = {section: {"tool_id": tool_id, "args": args, "state": "queued", "ok": None, "summary": None, "data": None} for phase in PERFORMANCE_PHASES for section, tool_id, args in phase}
    job = {"job_id": secrets.token_hex(8), "device_id": target.device_id, "device": target.label, "os_type": target.os_type, "state": "running",
           "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None, "sections": sections, "findings": [], "analysis_session_id": None}
    performance_jobs[job["job_id"]] = job
    _spawn(_run_performance_job(job, target))
    return job


@app.get("/api/performance/jobs/{job_id}")
def performance_job(job_id: str):
    job = performance_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Test not found (the server may have restarted). Run it again.")
    return job


@app.get("/api/agents/{device_id}/performance/latest")
def latest_performance_test(device_id: str):
    target = _performance_target(device_id)
    jobs = [job for job in list(performance_jobs.values()) if job["device_id"] == target.device_id]
    if not jobs:
        return Response(status_code=204)  # no test since the server started (not an error)
    return max(jobs, key=lambda job: job["started_at"])


@app.post("/api/agents/{device_id}/performance/analyse")
async def analyse_performance_test(device_id: str, payload: dict):
    """Deep AI analysis of a finished full test: a diagnosis session (3-4 ranked solutions, suggest-only)
    that starts from the test's results instead of running the checks again."""
    target = _performance_target(device_id)
    job = performance_jobs.get(str(payload.get("job_id") or ""))
    if not job or job["device_id"] != target.device_id:
        raise HTTPException(status_code=404, detail="Run the full test first")
    if job["state"] == "running":
        raise HTTPException(status_code=409, detail="Wait for the full test to finish")
    previous = session_store.get_session(job["analysis_session_id"], include_steps=False) if job.get("analysis_session_id") else None
    if previous and previous["status"] in ("queued", "running"):
        return {"session_id": previous["session_id"], "status": previous["status"], "device": target.label, "mode": None}
    evidence = [(entry["tool_id"], entry["args"], {"ok": entry["ok"], "summary": entry["summary"], "data": entry["data"]})
                for section, entry in job["sections"].items() if section not in ANALYSIS_SKIPPED_SECTIONS and entry["state"] in ("done", "failed")]
    if not any(result["ok"] for _tool_id, _args, result in evidence):
        raise HTTPException(status_code=400, detail="The test returned no results to analyse")
    mode = "deep" if payload.get("think") else "fast"
    playbook = get_playbook("performance")
    session_id = session_store.create_session(target.device_id, target.label, target.os_type, playbook["issue"], playbook["id"])
    job["analysis_session_id"] = session_id
    _spawn(run_diagnosis(session_id, mode, preset_evidence=evidence))
    return {"session_id": session_id, "status": "queued", "device": target.label, "mode": mode}


@app.get("/api/agents")
def agents():
    result = []
    for device in list_devices():
        latest = get_latest_report(device["device_id"])
        health_result = health_from_report(latest["diagnostics"]) if latest else {"status": "unknown", "message": "No report received yet.", "issues": []}
        result.append({**device, "health": health_result})
    return {"agents": result}


@app.get("/api/agents/{device_id}/diagnostics")
def agent_diagnostics(device_id: str):
    latest = get_latest_report(device_id)
    if not latest:
        raise HTTPException(status_code=404, detail="No diagnostics found for device")
    return latest


def _device_diagnostics_field(device_id, field, missing_message):
    latest = get_latest_report(device_id)
    if not latest:
        raise HTTPException(status_code=404, detail="No diagnostics found for device")
    value = latest["diagnostics"].get(field)
    if value is None:
        raise HTTPException(status_code=404, detail=missing_message)
    return value


@app.get("/api/agents/{device_id}/security")
def agent_security(device_id: str):
    return _device_diagnostics_field(device_id, "security", "This device has not reported security data yet")


@app.get("/api/agents/{device_id}/performance")
def agent_performance(device_id: str):
    return _device_diagnostics_field(device_id, "performance", "This device has not reported performance data yet")


@app.get("/api/agents/{device_id}/logs")
def agent_logs(device_id: str):
    return _device_diagnostics_field(device_id, "event_logs", "This device has not reported event log data yet")


@app.post("/api/agents/{device_id}/logs/diagnose")
def diagnose_device_event_logs(device_id: str, think: bool = False):
    latest = get_latest_report(device_id)
    if not latest:
        raise HTTPException(status_code=404, detail="This device has not reported event log data yet")
    event_logs = latest["diagnostics"].get("event_logs") or {}
    if event_logs.get("available") and event_logs.get("events") and not is_ai_available():
        raise HTTPException(status_code=503, detail=ai_status().get("message", "AI technician unavailable"))
    try:
        result = diagnose_logs(event_logs, think=think)
    except (AIModelUnavailableError, AIUnavailableError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    _record_ai("log_analysis", device_id, think, {"summary": result.get("summary"), "root_cause": result.get("root_cause"), "steps": result.get("steps")}, used_ai=result.get("source") != "rules")
    return result


@app.get("/api/agents/{device_id}/alerts")
def agent_alerts(device_id: str, limit: int = 100):
    return {"alerts": get_alerts(max(1, min(limit, 500)), device_id)}


@app.delete("/api/agents/{device_id}")
def revoke_agent(device_id: str, request: Request):
    require_admin(request)
    if not delete_device(device_id):
        raise HTTPException(status_code=404, detail="Device not found")
    return {"deleted": True, "device_id": device_id}


@app.get("/api/agents/{device_id}/health-report")
def device_health_report(device_id: str):
    """Instant rule-based report: score, every detected issue and the full system details."""
    latest = get_latest_report(device_id)
    if not latest:
        raise HTTPException(status_code=404, detail="No diagnostics found for device")
    return health_report.build(latest["diagnostics"], latest.get("timestamp"))


@app.post("/api/agents/{device_id}/agent-diagnose")
def diagnose_device(device_id: str, think: bool = False):
    if not is_ai_available():
        raise HTTPException(status_code=503, detail=ai_status().get("message", "AI technician unavailable"))
    latest = get_latest_report(device_id)
    if not latest:
        raise HTTPException(status_code=404, detail="No diagnostics found for device")
    try:
        report = latest["diagnostics"]
        issues = health_report.detect_issues(report)
        result = diagnose(report, get_alerts(20, device_id), issues, think=think)
    except (AIModelUnavailableError, AIUnavailableError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    _record_ai("health_analysis", device_id, think, {"summary": result.get("summary"), "root_cause": result.get("root_cause"),
               "issues": [item["title"] for item in issues], "explanations": result.get("issues"), "steps": result.get("steps")})
    return result


@app.get("/api/agents/download/{platform}")
def download_agent(platform: str):
    safe_platform = platform.lower()
    if safe_platform not in {"windows", "mac", "linux"}:
        raise HTTPException(status_code=404, detail="Platform must be windows, mac, or linux")

    builds = Path(__file__).resolve().parent.parent / "agent_builds"
    candidates = {
        "windows": ("DeviceHealthAgent.exe", "application/vnd.microsoft.portable-executable"),
        "mac": ("DeviceHealthAgent", "application/octet-stream"),
        "linux": ("DeviceHealthAgent", "application/octet-stream"),
    }
    folder = "macos" if safe_platform == "mac" else safe_platform
    filename, media_type = candidates[safe_platform]

    root = os.path.realpath(builds)
    path = os.path.realpath(builds / folder / filename)
    if os.path.commonpath([root, path]) != root:
        raise HTTPException(status_code=400, detail="Invalid download path")

    if not path.exists():
        messages = {
            "windows": "Windows installer not built yet. See agent/README.md",
            "mac": "macOS installer not built yet. See agent/README.md",
            "linux": "Linux installer not built yet. See agent/README.md",
        }
        return JSONResponse(status_code=404, content={
            "available": False,
            "message": messages[safe_platform],
            "manual_install": "pip install -r agent_requirements.txt && python monitor_agent.py",
        })
    return FileResponse(path, filename=filename, media_type=media_type)


# ============================================================================
# AI technician
# ============================================================================

@app.post("/api/agent/diagnose")
def agent_diagnose(payload: dict):
    if not is_ai_available():
        raise HTTPException(status_code=503, detail=ai_status().get("message", "AI technician unavailable"))
    try:
        result = diagnose(payload.get("diagnostics") or payload.get("report") or collect_report(), payload.get("alert_history") or get_alerts(20))
    except AIModelUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except AIUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    _record_ai("health_analysis", LOCAL_DEVICE_ID, False, {"summary": result.get("summary"), "root_cause": result.get("root_cause"), "steps": result.get("steps")})
    return result


@app.post("/api/agent/action")
def agent_action(payload: dict):
    try:
        return run_action(payload.get("action_id"))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.get("/api/agent/chat")
def chat_status():
    return ai_status()


@app.post("/api/agent/chat")
def agent_chat(payload: dict):
    if not is_ai_available():
        raise HTTPException(status_code=503, detail=ai_status().get("message", "AI technician unavailable"))
    message = str(payload.get("message", "")).strip()
    if not message:
        raise HTTPException(status_code=400, detail="message is required")

    # Chat about a chosen device; in Docker "this server" is only the container.
    device_id = str(payload.get("device_id") or "").strip()
    report = None
    if device_id and device_id not in (LOCAL_DEVICE_ID, "local-server"):
        latest = get_latest_report(device_id)
        if not latest:
            raise HTTPException(status_code=404, detail="This device has not reported any data yet")
        report = latest["diagnostics"]
    session_id = f"{payload.get('session_id', 'default')}:{device_id or LOCAL_DEVICE_ID}"
    history = chat_sessions.setdefault(session_id, [])
    try:
        think = bool(payload.get("think"))
        reply = chat(message, report or payload.get("diagnostics") or collect_report(), history, think=think)
        history.extend([{"role": "user", "content": message}, {"role": "assistant", "content": reply.get("plain_explanation", "")}])
        chat_sessions[session_id] = history[-6:]
        _record_ai("chat_answer", device_id or LOCAL_DEVICE_ID, think, {"question": message[:500], "summary": reply.get("plain_explanation"),
                   "root_cause": reply.get("technical_root_cause"), "steps": reply.get("recommendations")})
        return {"reply": reply, "session_id": session_id}
    except AIModelUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except AIUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.get("/api/ai/status")
def ai_status_endpoint():
    return {**ai_status(), "load_error": getattr(get_llm_provider(), "last_load_error", None), "suggest_only": True, "diagnosis_thinking": diagnosis_thinking(),
            "diagnosis_mode": default_mode(), "learned_model": model_builder.version_info()}


def _ollama_provider():
    provider = get_llm_provider()
    if provider.name != "ollama":
        raise HTTPException(status_code=400, detail="Model switching needs LLM_PROVIDER=ollama")
    return provider


def _catalog_model(payload):
    name = str(payload.get("model", "")).strip()
    if name not in llm_catalog.CATALOG_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown model '{name}'. Choose one of: {', '.join(sorted(llm_catalog.CATALOG_NAMES))}")
    return name


@app.get("/api/ai/models")
def ai_models():
    provider = get_llm_provider()
    if provider.name != "ollama":
        return {"provider": provider.name, "switchable": False, "current": getattr(provider, "model", None), "models": []}
    status = provider.status()
    installed = set(status.get("installed_models") or [])
    pulls = llm_catalog.pull_progress()
    models = [
        {
            **item,
            # A finished download counts at once; Ollama's model list is cached for a few seconds.
            "installed": item["name"] in installed or f"{item['name']}:latest" in installed or (pulls.get(item["name"]) or {}).get("state") == "done",
            "active": item["name"] == provider.base_model,
            "pull": pulls.get(item["name"]),
        }
        for item in llm_catalog.CATALOG
    ]
    return {"provider": "ollama", "switchable": True, "current": provider.base_model, "running_model": status.get("model"), "available": status.get("available"), "load_error": provider.last_load_error, "models": models}


@app.post("/api/ai/models/select")
async def ai_select_model(payload: dict):
    provider = _ollama_provider()
    name = _catalog_model(payload)
    catalog = await asyncio.to_thread(ai_models)
    if not next(model for model in catalog["models"] if model["name"] == name)["installed"]:
        raise HTTPException(status_code=409, detail=f"{name} is not downloaded yet")
    previous = provider.base_model
    llm_catalog.save_selected_model(name)
    await asyncio.to_thread(provider.use_model, name)
    logger.info("AI model switched to %s", name)
    await asyncio.to_thread(decision_log.record, "model_switch", name, {"action": f"Switched the AI base model from {previous} to {name}", "previous": previous, "model": name, "approved_by": "operator"})
    _spawn(asyncio.to_thread(prepare_ai, "model switch"))
    return await asyncio.to_thread(ai_models)


@app.post("/api/ai/models/pull")
def ai_pull_model(payload: dict):
    provider = _ollama_provider()
    name = _catalog_model(payload)
    return {"model": name, "started": llm_catalog.start_pull(provider.host, name)}


# ============================================================================
# Agentic troubleshooting ("What's the issue?")
# ============================================================================

def _spawn(coroutine):
    task = asyncio.create_task(coroutine)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    return task


@app.get("/api/troubleshoot/playbooks")
def troubleshoot_playbooks():
    return {"playbooks": public_playbooks()}


@app.get("/api/troubleshoot/targets")
def troubleshoot_targets():
    local = resolve_target(LOCAL_DEVICE_ID)
    targets = [{"device_id": local.device_id, "label": local.label, "os_type": local.os_type, "status": "online"}]
    targets += [{"device_id": device["device_id"], "label": f"{device['nickname']} ({device['hostname']})", "os_type": device["os_type"], "status": device["status"]} for device in list_devices()]
    return {"targets": targets}


@app.get("/api/troubleshoot/tools")
def troubleshoot_tools(device_id: str = LOCAL_DEVICE_ID):
    target = resolve_target(device_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"os_type": target.os_type, "tools": describe_tools(target.os_type)}


@app.post("/api/troubleshoot")
async def start_troubleshoot(payload: dict):
    issue = str(payload.get("issue", "")).strip()[:1000]
    playbook_id = str(payload.get("playbook_id") or "").strip() or None
    if not issue:
        raise HTTPException(status_code=400, detail="Describe the issue first")
    target = resolve_target(str(payload.get("device_id") or LOCAL_DEVICE_ID))
    if target is None:
        raise HTTPException(status_code=404, detail="Device not found")
    # Without a working AI the session still runs and returns the instant rule-based diagnosis.
    mode = normalize_mode(payload.get("mode"))
    session_id = session_store.create_session(target.device_id, target.label, target.os_type, issue, playbook_id)
    _spawn(run_diagnosis(session_id, mode))
    return {"session_id": session_id, "status": "queued", "device": target.label, "mode": mode}


@app.get("/api/troubleshoot/sessions")
def troubleshoot_sessions(device_id: str | None = None, limit: int = 30):
    return {"sessions": session_store.list_sessions(device_id, max(1, min(limit, 200)))}


@app.get("/api/troubleshoot/audit")
def troubleshoot_audit(device_id: str | None = None, limit: int = 100):
    return {"audit": session_store.list_audit(max(1, min(limit, 500)), device_id)}


@app.get("/api/troubleshoot/{session_id}")
def troubleshoot_session(session_id: str):
    session = session_store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.post("/api/troubleshoot/{session_id}/fixes/{index}/apply")
async def troubleshoot_apply_fix(session_id: str, index: int):
    session = session_store.get_session(session_id, include_steps=False)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    fixes = (session.get("report") or {}).get("proposed_fixes", [])
    if not 0 <= index < len(fixes):
        raise HTTPException(status_code=404, detail="Fix not found")
    if session["status"] in ("queued", "running", "fixing", "verifying"):
        raise HTTPException(status_code=409, detail="The agent is busy with this session; wait for it to finish")
    _refuse_if_changing(session["device_id"])
    if fixes[index]["status"] in ("running", "applied"):
        raise HTTPException(status_code=409, detail="This fix was already applied")
    solutions = (session.get("report") or {}).get("solutions") or []
    if any(item.get("fix_index") == index and item.get("status") in ("rejected", "done") for item in solutions):
        raise HTTPException(status_code=409, detail="This solution was rejected or done by hand; it will not be run")
    _spawn(apply_fix(session_id, index, approved_by="operator"))
    return {"accepted": True, "session_id": session_id, "index": index}


@app.post("/api/troubleshoot/{session_id}/solutions/{index}/decision")
async def troubleshoot_solution_decision(session_id: str, index: int, payload: dict):
    """A person marks a suggested solution as done by hand, or rejects it (recorded, never executed)."""
    try:
        solution = await decide_solution(session_id, index, str(payload.get("decision") or ""), decided_by="operator")
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"session_id": session_id, "index": index, "solution": solution}


@app.get("/api/decisions")
def decisions_feed(limit: int = 50):
    """Newest AI decisions and human approvals from the decisions folder."""
    # In Docker the folder is the project's ./decisions, mounted into the container.
    folder = "decisions/ in the AIops project folder" if os.getenv("SENTINEL_IN_DOCKER") else str(decision_log.decisions_dir())
    return {"folder": folder, "decisions": decision_log.recent(max(1, min(limit, 500)))}


@app.websocket("/ws/troubleshoot/{session_id}")
async def troubleshoot_stream(websocket: WebSocket, session_id: str):
    await websocket.accept()
    if not has_valid_session(websocket.cookies):
        await websocket.close(code=4401)
        return
    queue = troubleshoot_events.subscribe(session_id)
    try:
        session = session_store.get_session(session_id)
        if not session:
            await websocket.send_json({"type": "error", "message": "Session not found"})
            return
        await websocket.send_json({"type": "snapshot", "session": session})
        while True:
            await websocket.send_json(await queue.get())
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        troubleshoot_events.unsubscribe(session_id, queue)


# ============================================================================
# Remote task channel (agents long-poll with their bearer token)
# ============================================================================

TASK_RESULT_KEYS = ("tool_id", "risk", "args", "ok", "summary", "data", "changed", "rollback_hint", "duration_ms")
TASK_RESULT_MAX_BYTES = 200_000


@app.get("/api/agents/tasks/next")
async def agent_next_task(request: Request, wait: int = 25):
    device = authenticated_device(request)
    deadline = asyncio.get_running_loop().time() + max(1, min(wait, 30))
    while True:
        # Listen before claiming so a task enqueued in between still wakes this poll at once.
        with task_signals.listen(task_signals.device_key(device["device_id"])) as queued:
            task = await asyncio.to_thread(claim_next_task, device["device_id"])
            if task:
                return {"task": {key: task[key] for key in ("task_id", "tool_id", "args", "max_risk", "timeout_seconds")}}
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return {"task": None}
            await task_signals.wait(queued, min(remaining, 5))


@app.post("/api/agents/tasks/{task_id}/result")
async def agent_task_result(task_id: str, payload: dict, request: Request):
    device = await asyncio.to_thread(authenticated_device, request)
    result = {key: payload.get(key) for key in TASK_RESULT_KEYS}
    result["ok"] = bool(result["ok"])
    result["summary"] = str(result["summary"] or "")[:2000]
    if len(json.dumps(result.get("data"), default=str)) > TASK_RESULT_MAX_BYTES:
        result["data"] = "(result data too large; truncated by server)"
    if not await asyncio.to_thread(complete_task, task_id, device["device_id"], result):
        raise HTTPException(status_code=409, detail="Task is not running for this device (expired or unknown)")
    task_signals.notify(task_signals.task_key(task_id))
    return {"accepted": True}


@app.get("/api/agents/{device_id}/tasks")
def agent_tasks(device_id: str, limit: int = 50):
    return {"tasks": list_tasks(device_id, max(1, min(limit, 200)))}


# ============================================================================
# One-line agent enrollment (install scripts + agent bundle)
# ============================================================================

TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{20,128}$")
SERVER_URL_PATTERN = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._\-/]*)?$")
INSTALL_SCRIPTS = {
    "windows.ps1": True, "linux.sh": True, "macos.sh": True,
    "uninstall-windows.ps1": False, "uninstall-linux.sh": False, "uninstall-macos.sh": False,
}
BINARY_BUILDS = {"windows": ("windows", "DeviceHealthAgent.exe"), "linux": ("linux", "DeviceHealthAgent"), "mac": ("macos", "DeviceHealthAgent")}


def _server_url(request, override=None):
    """Address agents should use: an explicit override, then the configured SENTINEL_PUBLIC_URL (stable),
    then the live ngrok URL (free URLs change when ngrok restarts, which strands installed agents), then
    the address the browser used."""
    for candidate in (override, os.getenv("SENTINEL_PUBLIC_URL", ""), public_url.ngrok_url()):
        candidate = (candidate or "").strip().rstrip("/")
        if candidate:
            if not SERVER_URL_PATTERN.fullmatch(candidate):
                raise HTTPException(status_code=400, detail="Invalid server URL")
            return candidate
    return str(request.base_url).rstrip("/")


def open_enrollment():
    """When true, install scripts need no enrollment token: each agent generates its own secret."""
    return os.getenv("OPEN_ENROLLMENT", "false").strip().lower() in ("1", "true", "yes")


@app.get("/api/agents/enrollment")
def enrollment_info(request: Request):
    ngrok = public_url.ngrok_url()
    return {"open": open_enrollment(), "server_url": _server_url(request), "ngrok_url": ngrok,
            "ngrok_note": "Use it for devices outside this network. Free ngrok URLs change when ngrok restarts, so devices installed with it must re-run the install command after a change." if ngrok else None}


def _require_install_token(token):
    if open_enrollment() and not token:
        return
    if not TOKEN_PATTERN.fullmatch(token or "") or not is_valid_install_token(token):
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token. Generate a new one in the dashboard.")


@app.get("/install/{script_name}", include_in_schema=False)
def install_script(script_name: str, request: Request, token: str = "", server: str = ""):
    needs_token = INSTALL_SCRIPTS.get(script_name)
    if needs_token is None:
        raise HTTPException(status_code=404, detail="Unknown install script")
    if needs_token:
        _require_install_token(token)
    text = (INSTALL_TEMPLATES_DIR / script_name).read_text(encoding="utf-8")
    text = text.replace("__SERVER_URL__", _server_url(request, server)).replace("__TOKEN__", token if needs_token and token else "")
    text = text.replace("\r\n", "\n")
    if script_name.endswith(".ps1"):
        text = text.replace("\n", "\r\n")
    return PlainTextResponse(text, headers={"Cache-Control": "no-store"})


@app.get("/api/agents/bundle", include_in_schema=False)
def agent_bundle(token: str = ""):
    _require_install_token(token)
    agent_dir = PROJECT_ROOT / "agent"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(agent_dir / "monitor_agent.py", "monitor_agent.py")
        for path in sorted((agent_dir / "toolkit").glob("*.py")):
            archive.write(path, f"toolkit/{path.name}")
    headers = {"Content-Disposition": f'attachment; filename="sentinel-agent-{TOOLKIT_VERSION}.zip"', "Cache-Control": "no-store"}
    return Response(buffer.getvalue(), media_type="application/zip", headers=headers)


@app.get("/api/agents/binary/{platform}", include_in_schema=False)
def agent_binary(platform: str, token: str = ""):
    _require_install_token(token)
    if platform not in BINARY_BUILDS:
        raise HTTPException(status_code=404, detail="Unknown platform")
    folder, filename = BINARY_BUILDS[platform]
    path = PROJECT_ROOT / "agent_builds" / folder / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No prebuilt binary; the installer will use the Python bundle")
    return FileResponse(path, filename=filename, media_type="application/octet-stream")


# ============================================================================
# Self-improvement (learned cases and the aiops-brain model)
# ============================================================================

@app.post("/api/troubleshoot/{session_id}/feedback")
def troubleshoot_feedback(session_id: str, payload: dict):
    session = session_store.get_session(session_id, include_steps=False)
    if not session or not session.get("report"):
        raise HTTPException(status_code=404, detail="No diagnosis to rate for this session")
    if not learning_store.get_case(session_id):
        learning_store.record_session(session)
    learning_store.set_feedback(session_id, bool(payload.get("helpful")), str(payload.get("note") or ""), str(payload.get("corrected_root_cause") or ""))
    rebuilt = model_builder.maybe_rebuild()
    if rebuilt:
        getattr(get_llm_provider(), "refresh", lambda: None)()
    return {"case": learning_store.get_case(session_id), "model_rebuilt": bool(rebuilt)}


@app.get("/api/learning/stats")
def learning_stats():
    return {**learning_store.stats(), "model": model_builder.version_info(), "rebuild_every": model_builder.rebuild_every(), "learned_model_name": model_builder.learned_model_name(), "base_model": model_builder.base_model_name()}


@app.get("/api/learning/cases")
def learning_cases(limit: int = 50):
    return {"cases": learning_store.list_cases(max(1, min(limit, 500)))}


@app.get("/api/learning/lessons")
def learning_lessons():
    return {"lessons": model_builder.lessons(learning_store.list_cases(5000))}


@app.post("/api/learning/rebuild")
async def learning_rebuild():
    info = await asyncio.to_thread(model_builder.build, "manual")
    getattr(get_llm_provider(), "refresh", lambda: None)()
    return info


@app.get("/api/learning/dataset", include_in_schema=False)
def learning_dataset():
    data = model_builder.export_training_data(learning_store.list_cases(5000))
    return Response(data, media_type="application/jsonl", headers={"Content-Disposition": 'attachment; filename="sentinel_training_data.jsonl"'})
