"""Durable, deduplicated provider work and device-bound evidence history."""
import hashlib
import json
import re
import time

from fastapi import HTTPException

from . import intelligence as intel, security_store as store


def job(identity):
    with store.connect() as db:
        row = db.execute("SELECT * FROM intelligence_jobs WHERE id=?", (identity,)).fetchone()
    if not row:
        raise HTTPException(404, "Intelligence job not found")
    value = dict(row)
    value["result"] = json.loads(value.pop("body"))
    value["job_id"] = value.pop("id")
    return value


def _enqueue(db, provider, sha, operation, body, now):
    identity = hashlib.sha256((provider + sha + operation).encode()).hexdigest()
    row = db.execute("SELECT state,due FROM intelligence_jobs WHERE id=?", (identity,)).fetchone()
    if not row:
        db.execute("INSERT INTO intelligence_jobs VALUES (?,?,?,?,?,?,?,?)", (identity, provider, sha, operation, "queued", now, now, json.dumps(body or {})))
    elif row["state"] in ("completed", "restricted", "disabled", "failed") and (row["due"] <= now or operation == "capability" or row["state"] == "disabled"):
        db.execute("UPDATE intelligence_jobs SET state='queued',due=?,body=? WHERE id=?", (now, json.dumps(body or {}), identity))
    return identity


def enqueue(provider, sha, operation="lookup", body=None):
    intel.reputation_provider(provider)
    if operation == "lookup":
        sha = intel.valid_hash(sha)
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        return _enqueue(db, provider, sha, operation, body, time.time())


def observe(device, files, investigation=None):
    # Agent output is untrusted: malformed rows are skipped, never allowed to abort the caller.
    rows = []
    if not isinstance(files, list):
        return
    for row in files[:25]:
        if not isinstance(row, dict):
            continue
        try:
            sha = intel.valid_hash(row.get("sha256"))
        except HTTPException:
            continue
        identity = hashlib.sha256((device + sha + str(row.get("path", ""))).encode()).hexdigest()
        body = {key: row.get(key) for key in ("sha256", "path", "size", "process_id", "signature", "scan_id", "item_id")}
        body.update(investigation=investigation, provenance="endpoint", device_id=device)
        rows.append((identity, device, sha, time.time(), json.dumps(body)))
    if not rows:
        return
    now = time.time()
    with store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        db.executemany("INSERT OR REPLACE INTO intelligence_observations VALUES (?,?,?,?,?)", rows)
        for sha in dict.fromkeys(row[2] for row in rows):
            for provider in intel.PROVIDERS:
                _enqueue(db, provider, sha, "lookup", None, now)


def recover():
    with store.connect() as db:
        db.execute("UPDATE intelligence_jobs SET state='retry',due=? WHERE state='running'", (time.time(),))


def _allowed_providers():
    result = []
    for provider in intel.PROVIDERS:
        try:
            if intel.allowed(provider):
                result.append(provider)
        except HTTPException:
            pass  # Unreadable credential: treated as disabled.
    return result


def tick():
    # Jobs of disabled providers stay queued (visibly disabled) but never occupy the claim window.
    providers = _allowed_providers()
    if not providers:
        return
    marks = ",".join("?" * len(providers))
    with store.connect() as db:
        rows = [dict(row) for row in db.execute(f"SELECT * FROM intelligence_jobs WHERE state IN ('queued','retry') AND due<=? AND provider IN ({marks}) ORDER BY CASE operation WHEN 'capability' THEN 0 ELSE 1 END,due LIMIT 20", (time.time(), *providers))]
    for row in rows:
        provider = row["provider"]
        if provider not in _allowed_providers():
            continue  # Disabled during this tick; stays queued and untouched.
        with store.connect() as db:
            claimed = db.execute("UPDATE intelligence_jobs SET state='running' WHERE id=? AND state IN ('queued','retry')", (row["id"],)).rowcount
        if not claimed:
            continue
        try:
            previous = json.loads(row["body"])
            if row["operation"] == "lookup":
                result = intel.lookup(provider, row["hash"])
                expiry = store.state_get(f"report:{provider}:{row['hash']}", {}).get("expires", time.time()+3600)
                state, due = "completed", expiry
            elif row["operation"] == "capability":
                result, done = probe(provider, previous)
                state, due = ("completed", time.time()+300) if done else ("retry", time.time()+61)
            elif row["operation"].startswith("summary:"):
                raw = intel.request(provider, "GET", "/report/" + row["operation"].split(":", 1)[1] + "/summary")
                result = summary(raw, row["hash"])
                state, due = "completed", time.time()+21600
            else:
                raise HTTPException(400, "Unsupported intelligence operation")
        except HTTPException as error:
            result = {**json.loads(row["body"]), "detail": error.detail, "http_status": error.status_code, "classification": "provider_unavailable"}
            state = "restricted" if error.status_code in (401, 403) else "failed" if error.status_code == 400 else "retry"
            due = time.time() + max(60, int((error.headers or {}).get("Retry-After", 120)))
        except Exception:
            result, state, due = {"detail": "Provider work failed; no safety verdict available", "classification": "provider_unavailable"}, "retry", time.time()+120
        else:
            result.pop("detail", None)
            result.pop("http_status", None)
        with store.connect() as db:
            db.execute("UPDATE intelligence_jobs SET state=?,due=?,body=? WHERE id=?", (state, due, json.dumps(result), row["id"]))


def probe(provider, previous):
    # Each phase consumes at most one request; continuation survives process restart.
    generation = intel.policy(provider).get("generation")
    if previous.get("generation") != generation:
        previous = {}
    if provider == "hybrid_analysis" and previous.get("phase") == "environments":
        raw = intel.request(provider, "GET", "/system/environments")
        entries = raw if isinstance(raw, list) else (raw or {}).get("data", [])
        if not isinstance(entries, list):
            raise HTTPException(502, "Invalid sandbox environment response")
        result = {**previous, "phase": "complete", "environments": [row["id"] for row in entries if isinstance(row, dict) and type(row.get("id")) is int]}
        if intel.policy(provider).get("generation") != generation:
            raise HTTPException(409, "Provider configuration changed during capability check")
        store.state_set("capabilities:" + provider, result)
        return result, True
    raw = intel.request(provider, "GET", "/users/me" if provider == "virustotal" else "/key/current")
    if not isinstance(raw, dict) or not raw:
        raise HTTPException(502, "Invalid account capability response")
    if intel.policy(provider).get("generation") != generation:
        raise HTTPException(409, "Provider configuration changed during capability check")
    result = {"generation": generation, "verified": True, "tested_at": time.time(), "private_submission": "not assumed", "submission": "requires provider permission; API may restrict this account",
              "hash_lookup": "authentication verified; lookup permission verified per request"}
    if provider == "hybrid_analysis":
        result.update(phase="environments", account={key: raw[key] for key in ("auth_level", "is_active", "is_restricted") if isinstance(raw.get(key), (int, bool))})
    store.state_set("capabilities:" + provider, result)
    return result, provider != "hybrid_analysis"


def summary(raw, sha):
    if not isinstance(raw, dict) or str(raw.get("sha256", "")).lower() != sha:
        raise HTTPException(502, "Sandbox summary has no matching file identity")
    result = intel.normalize("hybrid_analysis", [raw], sha)
    # Bounded report fields, not raw provider objects/credentials or downloaded artifacts.
    result["behaviour"] = {key: raw[key][:100] if isinstance(raw[key], list) else raw[key]
                           for key in ("domains", "hosts", "compromised_hosts", "processes", "signatures", "mitre_attcks")
                           if isinstance(raw.get(key), list)}
    if len(json.dumps(result)) > 100000:
        result["behaviour"] = {"detail": "Report exceeds display limit; use the provider report link"}
    result["sandbox_state"] = raw.get("state", "unknown")
    return result
