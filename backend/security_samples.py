"""Provider-bound, single-use approvals. Samples are never executed.

Staged bytes live in memory; the framework may temporarily spool multipart input.
"""
import hashlib
import json
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


def discard(token, state="expired"):
    with _lock:
        _stages.pop(token, None)
    item = store.state_get("submission:" + token)
    if item and item.get("state") == "pending_approval":
        store.state_set("submission:" + token, {**item, "state": state})


def clear(provider):
    with _lock:
        for token in list(_stages):
            if _stages[token]["provider"] == provider:
                discard(token, "cancelled")


def stage(provider, content, source="browser"):
    if not content or len(content) > MAX_BYTES:
        raise HTTPException(413, "Select a non-empty file no larger than 32 MiB")
    sha = hashlib.sha256(content).hexdigest()
    # Hash lookup first: a previously submitted file must still return its known report.
    report = intel.lookup(provider, sha)
    if report["found"]:
        return report
    with store.connect() as db:
        prior = db.execute("SELECT token,state FROM intelligence_submissions WHERE provider=? AND hash=?", (provider, sha)).fetchone()
    if prior and prior["state"] not in ("failed", "cancelled"):
        raise HTTPException(409, "This file was already submitted or its outcome is unknown; check its existing analysis instead of uploading again")
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
    store.audit("sample_staged", provider=provider, sha256=sha, token=token, state="pending_approval")
    return {**report, "upload_token": token, "source": source, "size": len(content), "expires_in_seconds": TTL}


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
    if item["state"] != "pending_approval":
        raise HTTPException(409, "An in-flight or completed submission cannot be cancelled")
    discard(token, "cancelled")
    return {"discarded": True}


@router.post("/{provider}/uploads/{token}")
def upload(provider: str, token: str, payload: dict, request: Request):
    intel.secure_transport(request)
    # The configuration lock covers validation and the single-use claim only, never network I/O.
    with intel._lock:
        item, record = _claim(provider, token, payload)
    return _submit(provider, token, item, record)


def _claim(provider, token, payload):
    if not intel.allowed(provider) or not intel.policy(provider)["upload_authorized"]:
        raise HTTPException(403, "External submission is disabled; record provider-specific upload permission first")
    if payload.get("approved") is not True:
        raise HTTPException(400, "Explicit provider-specific approval is required")
    environment = payload.get("environment_id")
    capabilities = store.state_get("capabilities:" + provider, {})
    if not capabilities.get("verified"):
        raise HTTPException(409, "Test this provider connection before approving an upload")
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
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT state FROM intelligence_submissions WHERE provider=? AND hash=?", (provider, item["sha256"])).fetchone()
            if prior and prior["state"] not in ("failed", "cancelled"):
                raise HTTPException(409, "Duplicate submission refused; inspect the existing analysis")
            db.execute("INSERT OR REPLACE INTO intelligence_submissions VALUES (?,?,?,?)", (provider, item["sha256"], token, "submitting"))
        item = _stages.pop(token)
    record = {**item["binding"], "state": "submitting", "approved_at": time.time(), "environment_id": environment,
              "key_generation": intel.policy(provider).get("key_generation")}
    # Durable state before network I/O: ambiguous uploads can never be retried automatically.
    store.state_set("submission:" + token, record)
    return item, record


def _submit(provider, token, item, record):
    environment = record["environment_id"]
    try:
        store.audit("sample_upload_approved", provider=provider, sha256=item["sha256"], token=token, state="submitting")
        kwargs = {"files": {"file": (item["sha256"] + ".bin", item["bytes"], "application/octet-stream")}}
        if provider == "hybrid_analysis":
            kwargs["data"] = {"environment_id": str(environment)}
        # Re-checked at send time under the configuration lock: a key rotation or upload revocation after
        # the claim refuses the send instead of using another account's key.
        raw = intel.request(provider, "POST", "/files" if provider == "virustotal" else "/submit/file",
                            expect={"generation": record["configuration"], "upload": True}, **kwargs)
        identity = (raw or {}).get("data", {}).get("id") if provider == "virustotal" else (raw or {}).get("job_id")
        if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_=-]{1,300}", identity):
            raise HTTPException(502, "Submission outcome is unknown; look up the hash later instead of resubmitting")
        record.update(state="submitted", analysis_id=identity, next_poll=time.time() + 30)
    except HTTPException as error:
        record["state"] = "failed" if error.status_code in (400, 401, 403, 409, 429) else "outcome_unknown"
        record["detail"] = error.detail
        store.state_set("submission:" + token, record)
        raise
    except Exception:
        record.update(state="outcome_unknown", detail="Submission outcome is unknown; no automatic retry")
        store.state_set("submission:" + token, record)
        raise HTTPException(502, record["detail"]) from None
    finally:
        item.pop("bytes", None)
        with store.connect() as db:
            db.execute("UPDATE intelligence_submissions SET state=? WHERE token=?", (record["state"], token))
        store.audit("sample_upload_result", provider=provider, sha256=record["sha256"], token=token, state=record["state"])
    store.state_set("submission:" + token, record)
    return {"analysis_token": token, "sha256": record["sha256"], "status": "queued", "provider": provider}


@router.get("/{provider}/analyses/{token}")
def analysis(provider: str, token: str):
    item = store.state_get("submission:" + token)
    if not item or item["provider"] != provider:
        raise HTTPException(404, "Analysis not found")
    if item["state"] == "pending_approval" and item.get("expires", 0) <= time.time():
        discard(token)
        item = store.state_get("submission:" + token)
    return {**item.get("report", {}), "provider": provider, "sha256": item["sha256"], "status": item["state"], "analysis_token": token, "detail": item.get("detail"), "source": item.get("source"), "provenance": "external-sandbox-or-reputation"}


ACTIVE = ("pending_approval", "submitting", "submitted", "analysing")


def _active_rows():
    # Only unfinished submissions; finished records are kept for history but never rescanned.
    marks = ",".join("?" * len(ACTIVE))
    with store.connect() as db:
        return db.execute(f"SELECT name,body FROM security_state WHERE name >= 'submission:' AND name < 'submission;' AND json_extract(body,'$.state') IN ({marks})", ACTIVE).fetchall()


def _save(token, item):
    """Persist a submission record and keep the duplicate-guard table in the same state."""
    with store.connect() as db:
        db.execute("INSERT OR REPLACE INTO security_state VALUES (?,?,?)", ("submission:" + token, time.time(), json.dumps(item)))
        db.execute("UPDATE intelligence_submissions SET state=? WHERE token=?", (item["state"], token))


def reconcile(restarting=False, rows=None):
    for row in _active_rows() if rows is None else rows:
        item = json.loads(row["body"])
        token = row["name"].split(":", 1)[1]
        if item["state"] == "pending_approval" and (restarting or item.get("expires", 0) <= time.time()):
            discard(token)
        elif restarting and item["state"] == "submitting":
            item.update(state="outcome_unknown", detail="Server restarted during submission; do not resubmit automatically")
            _save(token, item)
    if restarting:
        with store.connect() as db:
            db.execute("UPDATE intelligence_submissions SET state='outcome_unknown' WHERE state='submitting'")


POLLS_PER_PASS = 2  # Per provider: polling must leave most of the shared budget to hash lookups.


def poll_due(rows=None):
    providers, polled = {}, {}
    for row in _active_rows() if rows is None else rows:
        item = json.loads(row["body"])
        token = row["name"].split(":", 1)[1]
        provider = item.get("provider")
        if item["state"] not in ("submitted", "analysing") or item.get("next_poll", 0) > time.time():
            continue
        if provider not in providers:
            try:
                providers[provider] = intel.policy(provider).get("key_generation") if intel.allowed(provider) else False
            except HTTPException:
                providers[provider] = False
        if providers[provider] is False or polled.get(provider, 0) >= POLLS_PER_PASS:
            continue
        if time.time() - item.get("approved_at", 0) > 3600:
            _save(token, {**item, "state": "outcome_unknown", "detail": "Polling deadline reached; look up the hash later"})
            continue
        if item.get("key_generation") != providers[provider]:
            _save(token, {**item, "state": "outcome_unknown", "detail": "Provider API key changed after submission; look up the hash instead"})
            continue
        polled[provider] = polled.get(provider, 0) + 1
        try:
            # Bound to the submitting account's key: a rotation mid-pass refuses instead of using the new key.
            raw = intel.request(provider, "GET", "/analyses/" + item["analysis_id"] if provider == "virustotal" else "/report/" + item["analysis_id"] + "/summary",
                                expect={"key_generation": item.get("key_generation")})
            if provider == "virustotal":
                from .virustotal import _report
                report = _report(raw, item["sha256"])
                complete = report.get("status") == "completed"
            else:
                from .intelligence_jobs import summary
                report = summary(raw, item["sha256"])
                complete = bool(raw and raw.get("state") in ("SUCCESS", "ERROR"))
            item.update(state="failed" if provider == "hybrid_analysis" and raw.get("state") == "ERROR" else "completed" if complete else "analysing", report=report, next_poll=time.time() + 60)
        except HTTPException as error:
            item.update(detail=error.detail, next_poll=time.time() + 120)
            if error.status_code in (429, 502, 503):
                providers[provider] = False  # Rate limited or unreachable: stop polling it this pass.
        _save(token, item)


def maintain():
    """One worker pass: a single read of unfinished submissions serves both expiry and polling."""
    rows = _active_rows()
    reconcile(rows=rows)
    poll_due(rows=rows)
