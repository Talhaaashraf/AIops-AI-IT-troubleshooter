"""Dashboard investigations/search; agent batch ingress remains explicitly authenticated."""
import asyncio
import json
import time

from fastapi import APIRouter, HTTPException, Request, UploadFile, File

from . import security_agent, security_store as store
from . import intelligence, security_samples

router = APIRouter()


def target(device):
    from .main import _threat_target
    return _threat_target(device)


@router.post("/api/security/investigations")
async def start(payload: dict):
    selected = target(str(payload.get("device_id") or "local"))
    if selected.status != "online":
        raise HTTPException(409, "This device is offline; general chat remains available")
    job = store.job_create(selected.device_id, question=str(payload.get("question") or "Security investigation"))
    asyncio.create_task(security_agent.run(job["id"]))
    return job


@router.get("/api/security/investigations/{identity}")
def progress(identity: str):
    job = store.job_get(identity)
    if not job:
        raise HTTPException(404, "Investigation not found")
    return job


@router.get("/api/security/{device}/findings")
def findings(device: str, q: str = "", severity: str = "", status: str = "", source: str = "", rule: str = "", since: float = 0, until: float | None = None, offset: int = 0, limit: int = 50, events: bool = False):
    selected = target(device)
    if not 1 <= limit <= 100 or offset < 0 or len(q) > 200:
        raise HTTPException(400, "Invalid search or pagination")
    coverage = store.state_get("coverage:" + selected.device_id, {})
    return {**store.search(selected.device_id, q, severity, status, source, rule, since, until, offset, limit, events), "coverage": coverage,
            "stale": time.time() - coverage.get("received_at", 0) > 120, "device_status": selected.status}


@router.post("/api/agents/security/events")
def ingest(payload: dict, request: Request):
    from .main import authenticated_device
    device = authenticated_device(request)
    if not isinstance(payload.get("id"), str) or not 1 <= len(payload["id"]) <= 128 or not isinstance(payload.get("events"), list):
        raise HTTPException(400, "Invalid security event batch")
    if len(payload["events"]) > 500 or len(json.dumps(payload)) > 1024 * 1024 or not isinstance(payload.get("coverage", {}), dict):
        raise HTTPException(413, "Security batch exceeds its limits")
    for event in payload["events"]:
        if not isinstance(event, dict) or not isinstance(event.get("id"), str) or len(event["id"]) > 1024:
            raise HTTPException(400, "Invalid event identity")
    if store.ingest(device["device_id"], payload):
        security_agent.correlate(device["device_id"], payload["events"])
    return {"accepted": True, "batch_id": payload["id"]}


@router.post("/api/security/{device}/sample-transfer")
async def prepare_sample(device: str, payload: dict, request: Request):
    intelligence.operator(request)
    intelligence.secure_transport(request)
    if payload.get("approved_transfer") is not True:
        raise HTTPException(400, "Approve transfer of this file to Sentinel first")
    from .main import _current_finding
    from .agent_brain.executor import execute
    selected = target(device)
    analysis, finding = _current_finding(selected, payload.get("finding_id"))
    provider, sha = intelligence.reputation_provider(str(payload.get("provider"))), intelligence.valid_hash(payload.get("sha256"))
    if selected.is_local or selected.status != "online" or not finding.get("path") or not finding.get("item_id"):
        raise HTTPException(409, "Select an online agent finding with a transferable file")
    if not intelligence.allowed(provider):
        raise HTTPException(403, "Provider must be configured and authorized for business use")
    if payload.get("scan_id") != analysis["scan_id"]:
        raise HTTPException(409, "The scan changed; review the file again")
    size = payload.get("size")
    if type(size) is not int or not 0 < size <= security_samples.MAX_BYTES:
        raise HTTPException(400, "Confirm the file size in bytes (maximum 32 MiB)")
    body = {"device": selected.device_id, "provider": provider, "sha256": sha, "size": size,
            "path": finding["path"], "scan_id": analysis["scan_id"], "item_id": finding["item_id"]}
    transfer = store.approval_issue(selected.device_id, body)
    store.state_set("transfer:" + transfer, body)
    result = await execute(selected, "security_sample_transfer", {"scan_id": analysis["scan_id"], "item_id": finding["item_id"], "sha256": sha, "transfer_id": transfer}, "medium")
    return result


@router.post("/api/agents/security/sample-transfer")
def accept_sample(request: Request, file: UploadFile = File(...)):
    from .main import authenticated_device
    intelligence.secure_transport(request)
    device = authenticated_device(request)
    token = request.headers.get("X-Transfer-Id", "")
    body = store.state_get("transfer:" + token)
    if not body or body["device"] != device["device_id"]:
        raise HTTPException(403, "Transfer does not belong to this agent")
    try:
        content = file.file.read(security_samples.MAX_BYTES + 1)
    finally:
        file.file.close()
    import hashlib
    if len(content) != body["size"] or len(content) > security_samples.MAX_BYTES or hashlib.sha256(content).hexdigest() != body["sha256"]:
        raise HTTPException(409, "File content does not match approval")
    if not store.approval_consume(token, device["device_id"], body):
        raise HTTPException(409, "Transfer approval expired or was already used")
    return security_samples.stage(body["provider"], content, "agent:" + device["device_id"])
