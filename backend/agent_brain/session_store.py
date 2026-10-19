"""SQLite persistence for troubleshooting sessions, their steps, and the remediation audit log."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone

from ..config import DB_PATH


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def _connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS troubleshoot_sessions (
            session_id TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            device_label TEXT,
            os_type TEXT,
            issue TEXT NOT NULL,
            playbook_id TEXT,
            status TEXT NOT NULL,
            report_json TEXT,
            verify_json TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS troubleshoot_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            tool_id TEXT,
            args_json TEXT,
            result_json TEXT,
            text TEXT,
            created_at TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS remediation_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            session_id TEXT,
            device_id TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            args_json TEXT,
            approved_by TEXT NOT NULL,
            ok INTEGER NOT NULL,
            summary TEXT
        )
    """)
    connection.commit()
    return connection


def _loads(value):
    return json.loads(value) if value else None


def _session_dict(row):
    data = dict(row)
    data["report"] = _loads(data.pop("report_json"))
    data["verify"] = _loads(data.pop("verify_json"))
    return data


def _step_dict(row):
    data = dict(row)
    data["args"] = _loads(data.pop("args_json"))
    data["result"] = _loads(data.pop("result_json"))
    return data


def create_session(device_id, device_label, os_type, issue, playbook_id=None):
    session_id = uuid.uuid4().hex[:16]
    now = utc_now()
    with _connect() as connection:
        connection.execute(
            "INSERT INTO troubleshoot_sessions (session_id, device_id, device_label, os_type, issue, playbook_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)",
            (session_id, device_id, device_label, os_type, issue, playbook_id, now, now),
        )
        connection.commit()
    return session_id


def update_session(session_id, status=None, report=None, verify=None, error=None):
    fields, values = ["updated_at = ?"], [utc_now()]
    if status is not None:
        fields.append("status = ?")
        values.append(status)
    if report is not None:
        fields.append("report_json = ?")
        values.append(json.dumps(report, default=str))
    if verify is not None:
        fields.append("verify_json = ?")
        values.append(json.dumps(verify, default=str))
    if error is not None:
        fields.append("error = ?")
        values.append(error)
    values.append(session_id)
    with _connect() as connection:
        connection.execute(f"UPDATE troubleshoot_sessions SET {', '.join(fields)} WHERE session_id = ?", values)
        connection.commit()


def get_session(session_id, include_steps=True):
    with _connect() as connection:
        row = connection.execute("SELECT * FROM troubleshoot_sessions WHERE session_id = ?", (session_id,)).fetchone()
        if not row:
            return None
        session = _session_dict(row)
        if include_steps:
            steps = connection.execute("SELECT * FROM troubleshoot_steps WHERE session_id = ? ORDER BY id", (session_id,)).fetchall()
            session["steps"] = [_step_dict(step) for step in steps]
        return session


def list_sessions(device_id=None, limit=30):
    with _connect() as connection:
        query = "SELECT session_id, device_id, device_label, os_type, issue, playbook_id, status, report_json, created_at, updated_at, NULL AS verify_json, error FROM troubleshoot_sessions"
        params = []
        if device_id:
            query += " WHERE device_id = ?"
            params.append(device_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        sessions = []
        for row in connection.execute(query, params).fetchall():
            session = _session_dict(row)
            report = session.pop("report") or {}
            session["root_cause"] = report.get("root_cause")
            session["severity"] = report.get("severity")
            sessions.append(session)
        return sessions


INTERRUPTED_FIX_SUMMARY = ("Interrupted by a server restart before the device reported back. The fix may still have run: "
                           "its result is recorded if the device reports it later. Check the device before running it again.")


def mark_interrupted_sessions():
    """Sessions left running by a server restart can never finish; close them out. A fix that was running is
    marked failed (outcome unknown) instead of staying "running", which would block both retry and reject."""
    now = utc_now()
    with _connect() as connection:
        rows = connection.execute("SELECT session_id, report_json FROM troubleshoot_sessions WHERE status IN ('queued', 'running', 'fixing', 'verifying')").fetchall()
        for row in rows:
            report = _loads(row["report_json"])
            if isinstance(report, dict):
                for fix in report.get("proposed_fixes") or []:
                    if fix.get("status") == "running":
                        fix["status"], fix["result"] = "failed", {"ok": False, "summary": INTERRUPTED_FIX_SUMMARY, "interrupted": True}
                for solution in report.get("solutions") or []:
                    if solution.get("status") == "running":
                        solution["status"] = "failed"
            connection.execute(
                "UPDATE troubleshoot_sessions SET status = 'failed', error = 'Interrupted by a server restart', report_json = ?, updated_at = ? WHERE session_id = ?",
                (json.dumps(report, default=str) if report is not None else None, now, row["session_id"]),
            )
        connection.commit()


def add_step(session_id, kind, tool_id=None, args=None, result=None, text=None):
    now = utc_now()
    with _connect() as connection:
        cursor = connection.execute(
            "INSERT INTO troubleshoot_steps (session_id, kind, tool_id, args_json, result_json, text, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, kind, tool_id, json.dumps(args) if args is not None else None, json.dumps(result, default=str) if result is not None else None, text, now),
        )
        connection.commit()
        return {"id": cursor.lastrowid, "session_id": session_id, "kind": kind, "tool_id": tool_id, "args": args, "result": result, "text": text, "created_at": now}


def add_audit(session_id, device_id, tool_id, args, approved_by, ok, summary):
    with _connect() as connection:
        connection.execute(
            "INSERT INTO remediation_audit (timestamp, session_id, device_id, tool_id, args_json, approved_by, ok, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (utc_now(), session_id, device_id, tool_id, json.dumps(args or {}), approved_by, int(bool(ok)), summary),
        )
        connection.commit()


def list_audit(limit=100, device_id=None):
    with _connect() as connection:
        if device_id:
            rows = connection.execute("SELECT * FROM remediation_audit WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, limit)).fetchall()
        else:
            rows = connection.execute("SELECT * FROM remediation_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["args"] = _loads(item.pop("args_json"))
            item["ok"] = bool(item["ok"])
            result.append(item)
        return result
