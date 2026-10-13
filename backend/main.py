"""FastAPI server for a local, Wazuh-inspired, AI-powered device health monitor."""

import asyncio
import io
import json
import logging
import os
import re
import secrets
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from agent.toolkit import TOOLKIT_VERSION, describe_tools

from . import task_signals
from .actions import run_action
from .agent_brain import events as troubleshoot_events
from .agent_brain import session_store
from .agent_brain.executor import LOCAL_DEVICE_ID, resolve_target
from .agent_brain.planner import apply_fix, auto_fix_max_risk, default_mode, normalize_mode, run_diagnosis
from .agent_brain.playbooks import public_playbooks
from .learning import model_builder
from .learning import store as learning_store
from .llm import get_provider as get_llm_provider
from .ai_technician import AIModelUnavailableError, AIUnavailableError, ai_status, chat, diagnose, diagnose_logs, is_ai_available
from .alert_store import add_alert, get_alerts
from .auth import PUBLIC_PATH_PREFIXES, SESSION_COOKIE_NAME, auth_enabled, check_password, has_valid_session, session_token
from .collectors import collect_report
from .device_store import create_pending_token, delete_device, get_device_by_token, get_latest_report, is_valid_install_token, list_devices, mark_offline_devices, register_device, save_report
from .event_logs import collect_event_log_report
from .performance_checks import collect_performance_report
from .rules_engine import evaluate_event_log_rules, evaluate_performance_rules, evaluate_rules, evaluate_security_rules, health_from_report
from .security_checks import collect_security_report
from .task_queue import claim_next_task, complete_task, list_tasks

app = FastAPI(title="AIops Device Health Monitor")
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
async def dashboard_auth_middleware(request: Request, call_next):
    path = request.url.path
    if not auth_enabled() or path.startswith(PUBLIC_PATH_PREFIXES):
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
    response.set_cookie(SESSION_COOKIE_NAME, session_token(), httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30)
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


@app.on_event("startup")
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
    status = ai_status()
    logger.info("AI provider: %s / %s - %s", status.get("provider"), status.get("model"), status.get("message"))
    _spawn(asyncio.to_thread(warm_up_llm))
    asyncio.create_task(monitor_loop())
    asyncio.create_task(offline_loop())
    asyncio.create_task(security_loop())
    asyncio.create_task(event_log_loop())


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
def diagnose_event_logs_endpoint():
    if not is_ai_available():
        raise HTTPException(status_code=503, detail=ai_status().get("message", "AI technician unavailable"))
    if latest_event_log_report is None:
        raise HTTPException(status_code=404, detail="No event log data collected yet")
    try:
        return diagnose_logs(latest_event_log_report)
    except (AIModelUnavailableError, AIUnavailableError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


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
    return {"accepted": True, "device_id": device_id, "alerts_created": len(alerts_for_report)}


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


@app.get("/api/agents/{device_id}/alerts")
def agent_alerts(device_id: str, limit: int = 100):
    return {"alerts": get_alerts(max(1, min(limit, 500)), device_id)}


@app.delete("/api/agents/{device_id}")
def revoke_agent(device_id: str, request: Request):
    require_admin(request)
    if not delete_device(device_id):
        raise HTTPException(status_code=404, detail="Device not found")
    return {"deleted": True, "device_id": device_id}


@app.post("/api/agents/{device_id}/agent-diagnose")
def diagnose_device(device_id: str):
    if not is_ai_available():
        raise HTTPException(status_code=503, detail=ai_status().get("message", "AI technician unavailable"))
    latest = get_latest_report(device_id)
    if not latest:
        raise HTTPException(status_code=404, detail="No diagnostics found for device")
    try:
        return diagnose(latest["diagnostics"], get_alerts(20, device_id))
    except (AIModelUnavailableError, AIUnavailableError) as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


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
        return diagnose(payload.get("diagnostics") or payload.get("report") or collect_report(), payload.get("alert_history") or get_alerts(20))
    except AIModelUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except AIUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


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

    session_id = str(payload.get("session_id", "default"))
    history = chat_sessions.setdefault(session_id, [])
    try:
        reply = chat(message, payload.get("diagnostics") or collect_report(), history)
        history.extend([{"role": "user", "content": message}, {"role": "assistant", "content": reply.get("plain_explanation", "")}])
        chat_sessions[session_id] = history[-6:]
        return {"reply": reply, "session_id": session_id}
    except AIModelUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
    except AIUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


@app.get("/api/ai/status")
def ai_status_endpoint():
    return {**ai_status(), "auto_fix_max_risk": auto_fix_max_risk() or "none", "diagnosis_mode": default_mode(), "learned_model": model_builder.version_info()}


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
    if fixes[index]["status"] in ("running", "applied"):
        raise HTTPException(status_code=409, detail="This fix was already applied")
    _spawn(apply_fix(session_id, index, approved_by="operator"))
    return {"accepted": True, "session_id": session_id, "index": index}


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
    for candidate in (override, os.getenv("SENTINEL_PUBLIC_URL", "")):
        candidate = (candidate or "").strip().rstrip("/")
        if candidate:
            if not SERVER_URL_PATTERN.match(candidate):
                raise HTTPException(status_code=400, detail="Invalid server URL")
            return candidate
    return str(request.base_url).rstrip("/")


def open_enrollment():
    """When true, install scripts need no enrollment token: each agent generates its own secret."""
    return os.getenv("OPEN_ENROLLMENT", "false").strip().lower() in ("1", "true", "yes")


@app.get("/api/agents/enrollment")
def enrollment_info(request: Request):
    return {"open": open_enrollment(), "server_url": _server_url(request)}


def _require_install_token(token):
    if open_enrollment() and not token:
        return
    if not TOKEN_PATTERN.match(token or "") or not is_valid_install_token(token):
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
# Self-improvement (learned cases and the sentinel-tech model)
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
