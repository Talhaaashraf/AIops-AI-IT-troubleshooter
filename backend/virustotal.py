"""Operator-controlled VirusTotal integration. Secrets and staged files stay in RAM.

No environment files, automatic submissions, file execution or persistent API keys.
"""
import hashlib
import re
import secrets
import threading
import time

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile

from .auth import auth_enabled, has_valid_session
from . import decision_log

BASE = "https://www.virustotal.com/api/v3"
MAX_FILE = 32 * 1024 * 1024
TTL = 600
_lock = threading.RLock()
_key = ""
_next_call = 0.0
_cache = {}
_pending = {}
_analyses = {}


def operator(request: Request):
    if not auth_enabled() or not has_valid_session(request.cookies):
        raise HTTPException(401, "Sign in to a password-protected dashboard to use VirusTotal")
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
        raise HTTPException(403, "Cross-origin requests are not allowed")


router = APIRouter(prefix="/api/virustotal", dependencies=[Depends(operator)])


def _prune():
    now = time.monotonic()
    for collection in (_cache, _pending, _analyses):
        for key in list(collection):
            if collection[key][0] <= now:
                collection.pop(key, None)


def _request(method, path, **kwargs):
    global _next_call
    with _lock:
        if not _key:
            raise HTTPException(409, "Enter your VirusTotal API key first")
        now = time.monotonic()
        if now < _next_call:
            raise HTTPException(429, "Wait 15 seconds between VirusTotal requests")
        _next_call = now + 15
        api_key = _key
    try:
        # Fixed origin, no redirects: the key must never follow a third-party URL.
        with httpx.Client(timeout=45, follow_redirects=False, trust_env=False) as client:
            response = client.request(method, BASE + path, headers={"x-apikey": api_key}, **kwargs)
        if response.status_code == 404:
            return None
        errors = {401: "VirusTotal rejected the API key", 403: "This VirusTotal account does not permit this operation",
                  429: "VirusTotal quota reached; wait before trying again"}
        if response.status_code in errors:
            raise HTTPException(response.status_code, errors[response.status_code])
        if not 200 <= response.status_code < 300:
            raise HTTPException(502, "VirusTotal could not complete the request")
        return response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, "VirusTotal is unreachable or returned an invalid response") from None


def _report(raw, sha):
    if raw is not None and (not isinstance(raw, dict) or not isinstance(raw.get("data"), dict)):
        raise HTTPException(502, "VirusTotal returned an invalid report")
    attrs = (raw or {}).get("data", {}).get("attributes", {})
    if not isinstance(attrs, dict):
        raise HTTPException(502, "VirusTotal returned invalid report attributes")
    stats = attrs.get("last_analysis_stats", attrs.get("stats", {}))
    results = attrs.get("last_analysis_results", attrs.get("results", {}))
    if not isinstance(stats, dict) or not isinstance(results, dict):
        raise HTTPException(502, "VirusTotal returned invalid analysis results")
    return {"sha256": sha, "found": raw is not None,
            "status": attrs.get("status", "known" if raw else "unknown"),
            "stats": {name: value for name, value in stats.items() if isinstance(value, int) and not isinstance(value, bool) and value >= 0},
            "analysed_at": attrs.get("last_analysis_date"),
            "detections": [{"engine": str(name)[:120], "category": row.get("category"), "result": str(row.get("result") or "")[:240]}
                           for name, row in list(results.items())[:100] if isinstance(row, dict) and row.get("category") in ("malicious", "suspicious")],
            "url": f"https://www.virustotal.com/gui/file/{sha}",
            "note": "No detections is not proof that a file is safe. Unknown means no report was found."}


@router.get("/settings")
def settings():
    return {"configured": bool(_key), "storage": "Memory only; re-enter after server restart", "max_file_bytes": MAX_FILE}


@router.post("/settings")
def configure(payload: dict):
    global _key, _next_call
    key = payload.get("api_key", "")
    if not isinstance(key, str) or (key and not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", key)):
        raise HTTPException(400, "Invalid API key format")
    with _lock:
        _key, _next_call = key, 0.0
        _cache.clear()
        _pending.clear()
        _analyses.clear()
    return settings()


@router.get("/files/{sha}")
def lookup(sha: str):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha):
        raise HTTPException(400, "Enter a SHA-256 hash (64 hexadecimal characters)")
    sha = sha.lower()
    with _lock:
        _prune()
        if sha in _cache:
            return _cache[sha][1]
    report = _report(_request("GET", "/files/" + sha), sha)
    with _lock:
        _cache[sha] = (time.monotonic() + TTL, report)
        if len(_cache) > 256:
            _cache.pop(next(iter(_cache)))
    return report


@router.post("/check-file")
def check_file(file: UploadFile = File(...)):
    # Read a bounded amount; the selected file is never opened as a program.
    try:
        content = file.file.read(MAX_FILE + 1)
    finally:
        file.file.close()
    if len(content) > MAX_FILE:
        raise HTTPException(413, "Select a file no larger than 32 MB")
    if not content:
        raise HTTPException(400, "The file is empty")
    sha = hashlib.sha256(content).hexdigest()
    report = lookup(sha)
    if report["found"]:
        return report
    with _lock:
        _prune()
        if len(_pending) >= 3:
            raise HTTPException(409, "Three files are awaiting approval. Cancel one or wait ten minutes.")
        token = secrets.token_urlsafe(24)
        _pending[token] = (time.monotonic() + TTL, content, sha)
        expiry = threading.Timer(TTL, discard, args=(token,))
        expiry.daemon = True
        expiry.start()
    return {**report, "upload_token": token, "expires_in_seconds": TTL,
            "upload_notice": "Uploading shares this file with VirusTotal and its security partners. Only approve files you are authorized to share."}


@router.delete("/uploads/{token}")
def discard(token: str):
    with _lock:
        _pending.pop(token, None)
    return {"discarded": True}


@router.post("/uploads/{token}")
def upload(token: str, payload: dict):
    if payload.get("approved") is not True:
        raise HTTPException(400, "Explicit approval is required before sending a file to VirusTotal")
    with _lock:
        _prune()
        pending = _pending.get(token)
        if not pending:
            raise HTTPException(404, "File approval expired; select the file again")
        _, content, sha = pending
        if not decision_log.record("file_reputation", sha, {"action": "upload", "state": "approved", "approved_by": "dashboard user", "sha256": sha, "bytes": len(content)}):
            raise HTTPException(503, "Could not record approval; file was not submitted")
        # Serialize this submission so the same approval cannot upload twice.
        raw = _request("POST", "/files", files={"file": (sha + ".bin", content, "application/octet-stream")})
        _pending.pop(token, None)
        analysis_id = (raw or {}).get("data", {}).get("id", "")
        if not isinstance(analysis_id, str) or not re.fullmatch(r"[A-Za-z0-9=_-]{1,300}", analysis_id):
            raise HTTPException(502, "VirusTotal accepted the request but did not return a usable analysis id; look up the hash later")
        _analyses[token] = (time.monotonic() + 3600, analysis_id, sha)
        _cache.pop(sha, None)
        decision_log.record("file_reputation", sha, {"action": "upload", "state": "submitted", "sha256": sha})
    return {"analysis_token": token, "sha256": sha, "status": "queued"}


@router.get("/analyses/{token}")
def analysis(token: str):
    with _lock:
        _prune()
        item = _analyses.get(token)
    if not item:
        raise HTTPException(404, "Analysis expired; look up the file hash")
    return _report(_request("GET", "/analyses/" + item[1]), item[2])
