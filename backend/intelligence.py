"""Provider policy, memory-only credentials and durable shared lookup budgets."""
import asyncio
import hashlib
import json
import re
import secrets
import threading
import time

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

from .auth import auth_enabled, has_valid_session
from . import security_store as store

PROVIDERS = {"virustotal": "https://www.virustotal.com/api/v3", "hybrid_analysis": "https://hybrid-analysis.com/api/v2"}
_keys = {}
_lock = threading.RLock()


def operator(request: Request):
    if not auth_enabled() or not has_valid_session(request.cookies):
        raise HTTPException(401, "Sign in to a password-protected dashboard")
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
        raise HTTPException(403, "Cross-origin requests are not allowed")


def secure_transport(request):
    # Loopback HTTP permits local administration; forwarded headers are trusted only by the configured proxy.
    if request.url.scheme != "https" and request.url.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise HTTPException(400, "Use HTTPS for remote API-key entry and sample transfer")


def policy(provider):
    if provider not in PROVIDERS:
        raise HTTPException(404, "Unknown intelligence provider")
    return store.state_get("provider:" + provider, {"business_authorized": False, "use_basis": "", "per_minute": 4 if provider == "virustotal" else 1, "per_day": 500 if provider == "virustotal" else 60, "retry_at": 0})


def allowed(provider):
    return bool(policy(provider).get("business_authorized") and _keys.get(provider))


def status(provider):
    rules = policy(provider)
    return {"provider": provider, "configured": bool(_keys.get(provider)), "enabled": allowed(provider), "policy": rules,
            "storage": "Server memory only; re-enter key after restart", "capabilities": store.state_get("capabilities:" + provider, {"verified": False})}


def configure(provider, payload):
    rules = policy(provider)
    if "business_authorized" in payload:
        if not isinstance(payload["business_authorized"], bool):
            raise HTTPException(400, "Business-use authorization must be a boolean")
        basis = str(payload.get("use_basis", "")).strip()
        if payload["business_authorized"] and len(basis) < 20:
            raise HTTPException(400, "Record the licence or provider permission that permits this office/business use")
        rules.update(business_authorized=payload["business_authorized"], use_basis=basis[:500])
    for name, maximum in (("per_minute", 100), ("per_day", 100000)):
        if name in payload:
            value = payload[name]
            if type(value) is not int or not 1 <= value <= maximum:
                raise HTTPException(400, f"Invalid {name} budget")
            rules[name] = value
    key = payload.get("api_key")
    if key is not None and (not isinstance(key, str) or key and not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", key)):
        raise HTTPException(400, "Invalid API key format")
    store.state_set("provider:" + provider, rules)
    if key is not None:
        with _lock:
            from .security_samples import clear
            clear(provider)
            rules["generation"] = secrets.token_hex(12)
            store.state_set("provider:" + provider, rules)
            if key:
                _keys[provider] = key
            else:
                _keys.pop(provider, None)
    return status(provider)


def _reserve(provider):
    rules = policy(provider)
    if not rules.get("business_authorized"):
        raise HTTPException(403, "Provider disabled: verify permission for this office/business use before enabling it")
    if not _keys.get(provider):
        raise HTTPException(409, "Provider API key is not configured")
    now = time.time()
    if rules.get("retry_at", 0) > now:
        raise HTTPException(429, "Provider backoff is active", headers={"Retry-After": str(int(rules["retry_at"] - now) + 1)})
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        minute = db.execute("SELECT COUNT(*) FROM intelligence_usage WHERE provider=? AND stamp>?", (provider, now - 60)).fetchone()[0]
        day = db.execute("SELECT COUNT(*) FROM intelligence_usage WHERE provider=? AND stamp>?", (provider, now - 86400)).fetchone()[0]
        if minute >= rules["per_minute"] or day >= rules["per_day"]:
            raise HTTPException(429, "Shared provider request budget reached", headers={"Retry-After": "60" if day < rules["per_day"] else "3600"})
        db.execute("INSERT INTO intelligence_usage VALUES (?,?)", (provider, now))
    return _keys[provider]


def request(provider, method, path, **kwargs):
    key = _reserve(provider)
    headers = {"x-apikey": key} if provider == "virustotal" else {"api-key": key, "User-Agent": "Falcon Sandbox"}
    try:
        with httpx.Client(timeout=40, follow_redirects=False, trust_env=False) as client:
            response = client.request(method, PROVIDERS[provider] + path, headers=headers, **kwargs)
        if response.status_code == 404:
            return None
        if response.status_code == 429:
            delay = response.headers.get("Retry-After", "60")
            try:
                seconds = max(1, min(86400, int(delay)))
            except ValueError:
                seconds = 60
            rules = policy(provider)
            rules["retry_at"] = time.time() + seconds
            store.state_set("provider:" + provider, rules)
            raise HTTPException(429, "Provider rate limit reached", headers={"Retry-After": str(seconds)})
        if response.status_code in (401, 403):
            raise HTTPException(response.status_code, "Provider rejected the key or this account lacks the requested capability")
        if not 200 <= response.status_code < 300:
            raise HTTPException(502, "Provider failed or attempted a redirect")
        return response.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, "Provider unavailable or malformed response; no safety verdict is available") from None


def valid_hash(sha):
    if not isinstance(sha, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", sha):
        raise HTTPException(400, "A 64-character SHA-256 hash is required")
    return sha.lower()


def normalize(provider, raw, sha):
    if provider == "virustotal":
        from .virustotal import _report
        if raw and raw.get("data", {}).get("id", sha).lower() != sha:
            raise HTTPException(502, "Provider report hash does not match the requested file")
        result = _report(raw, sha)
    else:
        reports = raw if isinstance(raw, list) else (raw or {}).get("reports", [])
        if not isinstance(reports, list):
            raise HTTPException(502, "Unsupported Hybrid Analysis response")
        matching = [row for row in reports if isinstance(row, dict) and str(row.get("sha256", "")).lower() == sha]
        result = {"sha256": sha, "found": bool(matching), "status": "known" if matching else "unknown", "reports": [
            {key: row.get(key) for key in ("job_id", "environment_description", "verdict", "threat_score", "analysis_start_time", "mitre_attcks")}
            for row in matching[:10]], "url": "https://hybrid-analysis.com/sample/" + sha}
    return {**result, "provider": provider, "provenance": "external-sandbox-or-reputation", "fetched_at": time.time(),
            "note": "External report only. Unknown or zero detections is not proof of safety or of behaviour on this endpoint."}


def enqueue_hash(provider, sha):
    sha = valid_hash(sha)
    policy(provider)
    identity = hashlib.sha256((provider + sha + "lookup").encode()).hexdigest()
    with store.connect() as db:
        db.execute("INSERT OR IGNORE INTO intelligence_jobs VALUES (?,?,?,?,?,?,?,?)", (identity, provider, sha, "lookup", "queued", time.time(), time.time(), "{}"))
    return identity


def lookup(provider, sha):
    sha = valid_hash(sha)
    if not allowed(provider):
        raise HTTPException(403, "Provider is disabled or its key is not configured")
    cached = store.state_get(f"report:{provider}:{sha}")
    if cached and cached["expires"] > time.time():
        return {**cached["report"], "cached": True}
    raw = request(provider, "GET", "/files/" + sha) if provider == "virustotal" else request(provider, "POST", "/search/hash", data={"hash": sha})
    report = normalize(provider, raw, sha)
    malicious = (report.get("stats", {}).get("malicious", 0) or report.get("stats", {}).get("suspicious", 0) or any(row.get("verdict") in ("malicious", "suspicious") for row in report.get("reports", [])))
    ttl = 3600 if not report["found"] else 21600 if malicious else 86400
    store.state_set(f"report:{provider}:{sha}", {"expires": time.time() + ttl, "report": report})
    return report


async def worker():
    while True:
        try:
            from .security_samples import poll_due
            await asyncio.to_thread(poll_due)
            with store.connect() as db:
                rows = [dict(row) for row in db.execute("SELECT * FROM intelligence_jobs WHERE due<=? AND operation='lookup' ORDER BY due LIMIT 20", (time.time(),))]
            for row in rows:
                if not allowed(row["provider"]):
                    continue
                try:
                    report = await asyncio.to_thread(lookup, row["provider"], row["hash"])
                    state, delay, body = "completed", 3600 if not report["found"] else 21600, report
                except HTTPException as error:
                    state, delay, body = "restricted" if error.status_code in (401, 403) else "retry", 3600 if error.status_code in (401, 403) else 60, {"detail": error.detail}
                with store.connect() as db:
                    db.execute("UPDATE intelligence_jobs SET state=?,due=?,body=? WHERE id=?", (state, time.time() + delay, json.dumps(body), row["id"]))
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Intelligence queue iteration failed")
        await asyncio.sleep(5)


router = APIRouter(prefix="/api/threat-intelligence", dependencies=[Depends(operator)])


@router.get("/{provider}/settings")
def get_settings(provider: str):
    return status(provider)


@router.post("/{provider}/settings")
def set_settings(provider: str, payload: dict, request: Request):
    secure_transport(request)
    return configure(provider, payload)


@router.post("/{provider}/test")
def test_connection(provider: str):
    # Capability probe only; never uploads a test sample.
    raw = request(provider, "GET", "/users/me" if provider == "virustotal" else "/key/current")
    result = {"verified": bool(raw), "tested_at": time.time(), "hash_lookup": "requires successful lookup", "private_submission": "not assumed"}
    if provider == "hybrid_analysis" and raw:
        environments = request(provider, "GET", "/system/environments")
        entries = environments if isinstance(environments, list) else (environments or {}).get("data", [])
        result["environments"] = [row["id"] for row in entries if isinstance(row, dict) and type(row.get("id")) is int]
    store.state_set("capabilities:" + provider, result)
    return result


@router.get("/{provider}/files/{sha}")
def get_file(provider: str, sha: str):
    identity = enqueue_hash(provider, sha)
    return {"job_id": identity, **lookup(provider, sha)}
