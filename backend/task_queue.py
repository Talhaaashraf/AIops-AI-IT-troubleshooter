"""Pull-based command channel to remote agents (Wazuh-style: the agent polls, no inbound port).

The server enqueues an allow-listed tool call for a device; the device's agent
long-polls /api/agents/tasks/next, runs the tool from its own local registry
(and its own risk limits), and posts the result back.
"""

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from .config import DB_PATH
CLAIM_TIMEOUT_SECONDS = 75


def _now():
    return datetime.now(timezone.utc)


def _connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS agent_tasks (
            task_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            args_json TEXT NOT NULL,
            max_risk TEXT NOT NULL,
            timeout_seconds INTEGER NOT NULL,
            status TEXT NOT NULL,
            result_json TEXT,
            session_id TEXT,
            created_at TEXT NOT NULL,
            claimed_at TEXT,
            completed_at TEXT
        )
    """)
    connection.commit()
    return connection


def _task_dict(row):
    task = dict(row)
    task["args"] = json.loads(task.pop("args_json"))
    task["result"] = json.loads(task["result_json"]) if task.get("result_json") else None
    task.pop("result_json", None)
    return task


def enqueue_task(device_id, tool_id, args, max_risk, timeout_seconds, session_id=None):
    task_id = uuid.uuid4().hex
    with _connect() as connection:
        connection.execute(
            "INSERT INTO agent_tasks (task_id, device_id, tool_id, args_json, max_risk, timeout_seconds, status, session_id, created_at) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)",
            (task_id, device_id, tool_id, json.dumps(args or {}), max_risk, int(timeout_seconds), session_id, _now().isoformat()),
        )
        connection.commit()
    return task_id


# Set by the server: called with each device-changing task that expires, so its outcome is on record.
on_change_expired = None


def expire_stale_tasks():
    now = _now()
    expired_changes = []
    with _connect() as connection:
        rows = connection.execute("SELECT task_id, status, created_at, claimed_at, timeout_seconds, max_risk FROM agent_tasks WHERE status IN ('queued', 'running')").fetchall()
        for row in rows:
            if row["status"] == "queued":
                stale = datetime.fromisoformat(row["created_at"]) + timedelta(seconds=CLAIM_TIMEOUT_SECONDS) < now
                reason = "The device did not pick up the task. It may be offline or running an older agent without remote tasks."
            else:
                stale = datetime.fromisoformat(row["claimed_at"]) + timedelta(seconds=row["timeout_seconds"] + 60) < now
                reason = "The device started the task but never reported a result."
            if stale:
                result = {"tool_id": None, "ok": False, "summary": reason, "data": None}
                cursor = connection.execute(
                    "UPDATE agent_tasks SET status = 'expired', result_json = ?, completed_at = ? WHERE task_id = ? AND status = ?",
                    (json.dumps(result), now.isoformat(), row["task_id"], row["status"]),
                )
                if cursor.rowcount == 1 and row["max_risk"] != "read":
                    expired_changes.append(row["task_id"])
        connection.commit()
    for task_id in expired_changes:
        if on_change_expired:
            try:
                on_change_expired(get_task(task_id))
            except Exception:  # recording must never break task handling
                logging.getLogger(__name__).exception("Could not record expired task %s", task_id)


def pending_change(device_id):
    """The tool id of a queued or running device-changing task, or None. Lives in the database, so it
    survives server restarts (the agent keeps running a change while the server is down)."""
    expire_stale_tasks()
    with _connect() as connection:
        row = connection.execute(
            "SELECT tool_id FROM agent_tasks WHERE device_id = ? AND status IN ('queued', 'running') AND max_risk != 'read' ORDER BY created_at LIMIT 1",
            (device_id,),
        ).fetchone()
        return row["tool_id"] if row else None


def claim_next_task(device_id):
    expire_stale_tasks()
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT * FROM agent_tasks WHERE device_id = ? AND status = 'queued' ORDER BY created_at LIMIT 1", (device_id,)).fetchone()
        if not row:
            connection.commit()
            return None
        connection.execute("UPDATE agent_tasks SET status = 'running', claimed_at = ? WHERE task_id = ?", (_now().isoformat(), row["task_id"]))
        connection.commit()
        task = _task_dict(row)
        task["status"] = "running"
        return task


def complete_task(task_id, device_id, result):
    with _connect() as connection:
        cursor = connection.execute(
            "UPDATE agent_tasks SET status = ?, result_json = ?, completed_at = ? WHERE task_id = ? AND device_id = ? AND status = 'running'",
            ("done" if result.get("ok") else "failed", json.dumps(result, default=str), _now().isoformat(), task_id, device_id),
        )
        connection.commit()
        return cursor.rowcount == 1


def get_task(task_id):
    with _connect() as connection:
        row = connection.execute("SELECT * FROM agent_tasks WHERE task_id = ?", (task_id,)).fetchone()
        return _task_dict(row) if row else None


def list_tasks(device_id, limit=50):
    with _connect() as connection:
        rows = connection.execute("SELECT * FROM agent_tasks WHERE device_id = ? ORDER BY created_at DESC LIMIT ?", (device_id, limit)).fetchall()
        return [_task_dict(row) for row in rows]
