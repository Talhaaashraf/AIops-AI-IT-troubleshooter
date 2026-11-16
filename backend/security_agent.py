"""Security Specialist: bounded read-only evidence collection, correlation and recovery."""
import asyncio
import hashlib
import json
import logging
import time

from . import security_store as store, task_queue, task_signals
from .agent_brain.executor import execute, resolve_target
from .security_chat import INSTRUCTIONS, VERSION

ALLOWLIST = ("security_capabilities", "threat_scan", "security_snapshot", "security_processes", "security_persistence", "security_hashes")
COLLECTION_SECONDS = 180
MAX_CALLS = 6
_active = set()


def correlate(device, events):
    prior = store.state_get("persistence:" + device)
    process_state = store.state_get("processes:" + device, {})
    for event in events:
        source = event.get("source", "unknown")
        event_id = str(event.get("id", ""))
        for signal in event.get("indicators", []):
            if signal not in ("encoded_shell", "download_execute", "authentication_failure", "protection_tampering", "log_cleared", "persistence_change"):
                continue
            # A single failed sign-in is evidence, not an incident.
            if signal == "authentication_failure":
                failures = store.state_get("failures:" + device, [])
                failures = [stamp for stamp in failures if stamp > time.time() - 300] + [time.time()]
                store.state_set("failures:" + device, failures[-100:])
                if len(failures) < 5:
                    continue
            severity = "high" if signal in ("download_execute", "protection_tampering", "log_cleared") else "medium"
            store.finding_put(device, {"key": signal + ":" + source, "rule": signal, "source": source, "severity": severity,
                "confidence": "medium", "title": signal.replace("_", " ").capitalize(), "evidence_refs": [event_id],
                "details": event, "explanation": "Review the observed activity and its authorized context before deciding it is malicious.",
                "next_checks": ["Review associated process, account and change history", "Compare file reputation with local evidence"]})
        snapshot = event.get("snapshot", {})
        if source == "persistence":
            current = {hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest(): row for row in snapshot.get("entries", [])}
            if prior is not None:
                changed = [row for key, row in current.items() if key not in prior]
                if changed:
                    store.finding_put(device, {"key": "persistence_delta", "rule": "persistence_delta", "source": source, "severity": "medium", "confidence": "medium",
                        "title": "Persistence metadata changed", "details": changed[:25], "evidence_refs": [event_id], "explanation": "May be an authorized installation or update; review the change owner."})
            store.state_set("persistence:" + device, current)
        if source == "processes":
            processes = {row["process_id"]: row for row in snapshot.get("processes", []) if row.get("process_id")}
            for identity, row in processes.items():
                parent = processes.get(row.get("parent_process_id"), process_state.get(row.get("parent_process_id"), {}))
                signals = row.get("indicators", [])
                if signals:
                    store.finding_put(device, {"key": "execution:" + identity, "rule": "execution_chain", "source": source, "severity": "high" if "download_execute" in signals else "medium", "confidence": "medium", "title": "Execution indicators need review", "details": {"process": row, "parent": parent}, "evidence_refs": [event_id], "explanation": "Indicators can occur in legitimate administration. Confirm intent and file identity."})
            connections = snapshot.get("connections", [])
            history = store.state_get("connections:" + device, {})
            current_keys = set()
            for connection in connections:
                key = str(connection.get("process_id")) + ":" + str(connection.get("destination")) + ":" + str(connection.get("port"))
                if key in current_keys:
                    continue
                current_keys.add(key)
                history[key] = min(history.get(key, 0) + 1, 100)
                process = processes.get(connection.get("process_id"), {})
                if history[key] >= 3 and process.get("indicators"):
                    store.finding_put(device, {"key": "connection:" + key, "rule": "repeated_connection", "source": source, "severity": "medium", "confidence": "medium", "title": "Repeated connection associated with an execution indicator", "details": {"connection": connection, "process": process}, "evidence_refs": [event_id], "explanation": "A repeated or new destination alone is not evidence of malicious activity."})
            store.state_set("connections:" + device, {key: history[key] for key in list(history)[-1000:]})
            store.state_set("processes:" + device, processes)


async def _step(job, step, target, remaining):
    tool_id = step["tool"]
    if tool_id not in ALLOWLIST:
        raise ValueError("Tool is not allowed for the Security Specialist")
    if target.is_local:
        return await asyncio.wait_for(execute(target, tool_id, {}, "read"), timeout=remaining)
    if not step.get("task_id"):
        # Deterministic task id closes the enqueue/save crash window.
        task_id = hashlib.sha256((job["id"] + ":" + tool_id).encode()).hexdigest()
        step["task_id"] = task_id
        store.job_save(job)
        task_queue.enqueue_task(target.device_id, tool_id, {}, "read", min(90, max(1, int(remaining))), task_id=task_id)
        task_signals.notify(task_signals.device_key(target.device_id))
    elif task_queue.get_task(step["task_id"]) is None:
        task_queue.enqueue_task(target.device_id, tool_id, {}, "read", min(90, max(1, int(remaining))), task_id=step["task_id"])
    deadline = time.monotonic() + remaining
    while time.monotonic() < deadline:
        task_queue.expire_stale_tasks()
        task = task_queue.get_task(step["task_id"])
        if task and task["status"] in ("done", "failed", "expired"):
            return task.get("result") or {"ok": False, "summary": "No result"}
        await asyncio.sleep(1)
    raise asyncio.TimeoutError()


async def run(identity):
    if identity in _active:
        return
    job = store.job_get(identity)
    target = resolve_target(job["device"]) if job else None
    if not target or target.status != "online" or job["state"] not in ("queued", "running"):
        return
    _active.add(identity)
    started = time.monotonic()
    job["state"] = "running"
    job.setdefault("collection_spent", 0)
    job.setdefault("deadline", time.time() + COLLECTION_SECONDS)
    try:
        for tool_id in ALLOWLIST[:MAX_CALLS]:
            remaining = min(job["deadline"] - time.time(), COLLECTION_SECONDS - job["collection_spent"] - (time.monotonic() - started))
            if remaining <= 0:
                break
            step = next((row for row in job["steps"] if row["tool"] == tool_id), None)
            if step and "result" in step:
                continue
            if step is None:
                step = {"tool": tool_id}
                job["steps"].append(step)
            store.job_save(job)
            try:
                step["result"] = await _step(job, step, target, remaining)
            except asyncio.TimeoutError:
                step["result"] = {"ok": False, "summary": "Collection budget expired; a dispatched read-only task may finish later"}
                break
            except Exception:
                step["result"] = {"ok": False, "summary": "This collection step failed; coverage is incomplete"}
            store.job_save(job)
        job["collection_spent"] += time.monotonic() - started
        completed = {row["tool"] for row in job["steps"] if row.get("result", {}).get("ok")}
        job["unfinished"] = [tool for tool in ALLOWLIST if tool not in completed]
        job["state"] = "partial" if job["unfinished"] else "completed"
        job["instruction_version"] = VERSION
        for step in job["steps"]:
            if not step.get("result", {}).get("ok"):
                continue
            data = step["result"].get("data") or {}
            if step["tool"] in ("security_processes", "security_persistence"):
                correlate(target.device_id, [{"id": job["id"] + step["tool"], "source": "processes" if step["tool"] == "security_processes" else "persistence", "snapshot": data}])
            if step["tool"] == "threat_scan":
                from .main import _after_threat_scan
                # SQLite work and alerting run off the event loop (they can wait on the 10 s busy timeout).
                await asyncio.to_thread(_after_threat_scan, target, True, step["result"].get("summary", ""), data)
            if step["tool"] == "security_hashes":
                try:
                    from .intelligence_jobs import observe
                    await asyncio.to_thread(observe, target.device_id, data.get("files", []), job["id"])
                except Exception:
                    logging.getLogger(__name__).exception("Recording investigation hashes for intelligence lookups failed")
        job["evidence"] = [{"id": str(index + 1), "tool": row["tool"], "summary": row.get("result", {}).get("summary"), "ok": row.get("result", {}).get("ok", False)} for index, row in enumerate(job["steps"])]
        job["summary"] = "Security evidence collected. Review findings and unavailable sources; this is not a clean-device certification."
        job["explanation_status"] = "unavailable"
        store.job_save(job)
        try:
            explanation = await asyncio.wait_for(asyncio.to_thread(explain, job), 90)
            job.update(explanation)
        except Exception:
            job["explanation_status"] = "unavailable"
        store.job_save(job)
    finally:
        _active.discard(identity)


def explain(job):
    from .ai_technician import _schema_completion, is_ai_available
    if not is_ai_available():
        return {"explanation_status": "unavailable", "explanation_note": "AI unavailable; collected evidence and rule findings remain usable"}
    context = [{"id": str(index + 1), "tool": step["tool"], "result": step.get("result")} for index, step in enumerate(job["steps"])]
    schema = {"type": "object", "properties": {"summary": {"type": "string"}, "evidence_refs": {"type": "array", "items": {"type": "string"}}, "next_checks": {"type": "array", "items": {"type": "string"}}}, "required": ["summary", "evidence_refs", "next_checks"]}
    from .llm.base import loads_lenient
    raw = _schema_completion([{"role": "system", "content": INSTRUCTIONS + " Return only the requested JSON. Evidence ids are numbered tool results. Reference only successful observations."},
                              {"role": "user", "content": json.dumps({"question": job.get("question"), "evidence": context}, default=str)[:18000]}], schema, 700)
    result = loads_lenient(raw)
    if not isinstance(result, dict) or not isinstance(result.get("summary"), str):
        raise ValueError("Invalid specialist explanation")
    valid = {row["id"] for row in job["evidence"] if row["ok"]}
    return {"summary": result["summary"][:4000], "evidence_refs": [ref for ref in result.get("evidence_refs", []) if isinstance(ref, str) and ref in valid],
            "next_checks": [text[:500] for text in result.get("next_checks", []) if isinstance(text, str)][:6], "explanation_status": "completed"}


async def loop():
    cleanup_due = 0
    while True:
        try:
            for job in store.pending_jobs():
                if len(_active) >= 3:
                    break
                if job["id"] not in _active:
                    # Await each launch boundary so the concurrency cap takes effect.
                    asyncio.create_task(run(job["id"]))
                    await asyncio.sleep(0)
            if time.monotonic() >= cleanup_due:
                # Retention cleanup scans whole tables: run it in a thread, every 10 minutes.
                await asyncio.to_thread(store.cleanup)
                cleanup_due = time.monotonic() + 600
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Security scheduler iteration failed")
        await asyncio.sleep(5)
