"""Provider-bound, single-use submission approvals. Bytes are never executed or persisted."""
import hashlib
import re
import secrets
import threading
import time

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile

from . import intelligence as intel, security_store as store

MAX_BYTES = 32 * 1024 * 1024
TTL = 600
_stages = {}
_lock = threading.RLock()
router = APIRouter(prefix="/api/threat-intelligence", dependencies=[Depends(intel.operator)])


def discard(token):
    with _lock:
        _stages.pop(token, None)


def clear(provider):
    with _lock:
        for token in list(_stages):
            if _stages[token]["provider"] == provider:
                _stages.pop(token)


def stage(provider, content, source="browser"):
    if not content or len(content) > MAX_BYTES:
        raise HTTPException(413, "Select a non-empty file no larger than 32 MiB")
    sha = hashlib.sha256(content).hexdigest()
    report = intel.lookup(provider, sha)
    if report["found"]:
        return report
    body = {"provider": provider, "sha256": sha, "size": len(content), "source": source, "configuration": intel.policy(provider).get("generation")}
    with _lock:
        for token in list(_stages):
            if _stages[token]["expires"] <= time.time():
                _stages.pop(token)
        if len(_stages) >= 3:
            raise HTTPException(409, "Three samples await approval; discard one before selecting another")
        token = store.approval_issue(source, body, TTL)
        _stages[token] = {**body, "expires": time.time() + TTL, "bytes": content, "binding": body}
        timer = threading.Timer(TTL, discard, args=(token,))
        timer.daemon = True
        timer.start()
    store.state_set("submission:" + token, {**body, "state": "pending_approval", "expires": time.time() + TTL})
    return {**report, "upload_token": token, "source": source, "expires_in_seconds": TTL}


@router.post("/{provider}/check-file")
def check_file(provider: str, request: Request, file: UploadFile = File(...)):
    intel.secure_transport(request)
    try:
        content = file.file.read(MAX_BYTES + 1)
    finally:
        file.file.close()
    return stage(provider, content)


@router.delete("/{provider}/uploads/{token}")
def cancel(provider: str, token: str):
    item = store.state_get("submission:" + token)
    if not item or item["provider"] != provider:
        raise HTTPException(404, "Sample not found")
    discard(token)
    store.state_set("submission:" + token, {**item, "state": "expired"})
    return {"discarded": True}


@router.post("/{provider}/uploads/{token}")
def upload(provider: str, token: str, payload: dict, request: Request):
    intel.secure_transport(request)
    if payload.get("approved") is not True:
        raise HTTPException(400, "Explicit provider-specific approval is required")
    environment = payload.get("environment_id")
    if provider == "hybrid_analysis":
        capabilities = store.state_get("capabilities:" + provider, {})
        if type(environment) is not int or environment not in capabilities.get("environments", []):
            raise HTTPException(400, "Test Hybrid Analysis capabilities and select a supported sandbox environment")
    with _lock:
        item = _stages.get(token)
        if not item or item["provider"] != provider or item["expires"] <= time.time():
            raise HTTPException(409, "Sample expired, was submitted, or belongs to another provider")
        if item["configuration"] != intel.policy(provider).get("generation") or hashlib.sha256(item["bytes"]).hexdigest() != item["sha256"]:
            discard(token)
            raise HTTPException(409, "Sample or provider configuration changed; approval must be renewed")
        if not store.approval_consume(token, item["source"], item["binding"]):
            raise HTTPException(409, "Approval expired or already used")
        item = _stages.pop(token)
    record = {**item["binding"], "state": "submitting", "approved_at": time.time()}
    # Durable state before network I/O: ambiguous uploads can never be retried automatically.
    store.state_set("submission:" + token, record)
    try:
        kwargs = {"files": {"file": (item["sha256"] + ".bin", item["bytes"], "application/octet-stream")}}
        if provider == "hybrid_analysis":
            kwargs["data"] = {"environment_id": str(environment)}
        raw = intel.request(provider, "POST", "/files" if provider == "virustotal" else "/submit/file", **kwargs)
        identity = (raw or {}).get("data", {}).get("id") if provider == "virustotal" else (raw or {}).get("job_id")
        if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_=-]{1,300}", identity):
            raise HTTPException(502, "Submission outcome is unknown; look up the hash later instead of resubmitting")
        record.update(state="submitted", analysis_id=identity, next_poll=time.time() + 30)
    except HTTPException as error:
        record["state"] = "failed" if error.status_code in (400, 401, 403, 409, 429) else "outcome_unknown"
        record["detail"] = error.detail
        store.state_set("submission:" + token, record)
        raise
    finally:
        item.pop("bytes", None)
    store.state_set("submission:" + token, record)
    return {"analysis_token": token, "sha256": record["sha256"], "status": "queued", "provider": provider}


@router.get("/{provider}/analyses/{token}")
def analysis(provider: str, token: str):
    item = store.state_get("submission:" + token)
    if not item or item["provider"] != provider:
        raise HTTPException(404, "Analysis not found")
    return {"provider": provider, "sha256": item["sha256"], "status": item["state"], **item.get("report", {}), "detail": item.get("detail")}


def poll_due():
    with store.connect() as db:
        rows = db.execute("SELECT name,body FROM security_state WHERE name LIKE 'submission:%'").fetchall()
    import json
    for row in rows:
        item = json.loads(row["body"])
        if item["state"] not in ("submitted", "analysing") or item.get("next_poll", 0) > time.time() or not intel.allowed(item["provider"]):
            continue
        if time.time() - item.get("approved_at", 0) > 3600:
            store.state_set(row["name"], {**item, "state": "outcome_unknown", "detail": "Polling deadline reached; look up the hash later"})
            continue
        provider = item["provider"]
        try:
            raw = intel.request(provider, "GET", "/analyses/" + item["analysis_id"] if provider == "virustotal" else "/report/" + item["analysis_id"] + "/summary")
            if provider == "virustotal":
                from .virustotal import _report
                report = _report(raw, item["sha256"])
                complete = report.get("status") == "completed"
            else:
                report = intel.normalize(provider, [raw] if raw else [], item["sha256"])
                complete = bool(raw and raw.get("state") in ("SUCCESS", "ERROR"))
            item.update(state="completed" if complete else "analysing", report=report, next_poll=time.time() + 60)
        except HTTPException as error:
            item.update(detail=error.detail, next_poll=time.time() + 120)
        store.state_set(row["name"], item)
