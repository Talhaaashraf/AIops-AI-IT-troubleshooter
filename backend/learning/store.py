"""Experience memory: every finished troubleshooting session becomes a learned case.

The agent consults this memory before diagnosing (similar past cases and the
fixes that actually resolved them) and the model builder distills it into the
self-improving `aiops-brain` model. Operator feedback (thumbs up/down and a
corrected root cause) outranks the agent's own verdict.
"""

import json
import math
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone

from ..config import DB_PATH

STOPWORDS = set("""a an and are as at be but by can do does for from has have i in is it its laptop computer pc my me of on or so the
this to very was when with not no it's im i'm keeps keep since some all any after before while ka ki ke hai ho raha rahi nahi""".split())
GOOD_OUTCOMES = ("resolved",)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def tokenize(text):
    return [word for word in re.findall(r"[a-z0-9][a-z0-9\-]+", (text or "").lower()) if word not in STOPWORDS and len(word) > 1]


def _connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("""
        CREATE TABLE IF NOT EXISTS learned_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            device_id TEXT,
            os_type TEXT,
            issue TEXT NOT NULL,
            playbook_id TEXT,
            root_cause TEXT,
            evidence_json TEXT,
            fixes_json TEXT,
            outcome TEXT NOT NULL,
            feedback TEXT,
            feedback_note TEXT,
            corrected_root_cause TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    connection.commit()
    return connection


def _case_dict(row):
    case = dict(row)
    case["evidence"] = json.loads(case.pop("evidence_json") or "[]")
    case["fixes"] = json.loads(case.pop("fixes_json") or "[]")
    case["effective_root_cause"] = case.get("corrected_root_cause") or case.get("root_cause")
    return case


def outcome_for(session):
    """Collapse a finished session into a learning outcome."""
    report = session.get("report") or {}
    verify = session.get("verify") or {}
    applied = [fix for fix in report.get("proposed_fixes", []) if fix.get("status") == "applied"]
    failed = [fix for fix in report.get("proposed_fixes", []) if fix.get("status") == "failed"]
    if verify.get("resolved") is True:
        return "resolved"
    if verify.get("resolved") is False:
        return "unresolved"
    if failed and not applied:
        return "fix_failed"
    return "diagnosed"


def record_session(session):
    """Insert or refresh the learned case for a session that has a report."""
    report = session.get("report")
    if not report:
        return None
    fixes = [{"tool_id": fix["tool_id"], "args": fix.get("args") or {}, "status": fix.get("status"), "ok": (fix.get("result") or {}).get("ok")} for fix in report.get("proposed_fixes", [])]
    now = utc_now()
    with _connect() as connection:
        connection.execute(
            """INSERT INTO learned_cases (session_id, device_id, os_type, issue, playbook_id, root_cause, evidence_json, fixes_json, outcome, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET root_cause=excluded.root_cause, evidence_json=excluded.evidence_json,
               fixes_json=excluded.fixes_json, outcome=excluded.outcome, updated_at=excluded.updated_at""",
            (session["session_id"], session.get("device_id"), session.get("os_type"), session["issue"], session.get("playbook_id"),
             report.get("root_cause"), json.dumps(report.get("evidence", [])[:6]), json.dumps(fixes), outcome_for(session), now, now),
        )
        connection.commit()
    return get_case(session["session_id"])


def set_feedback(session_id, helpful, note=None, corrected_root_cause=None):
    with _connect() as connection:
        cursor = connection.execute(
            "UPDATE learned_cases SET feedback = ?, feedback_note = ?, corrected_root_cause = ?, updated_at = ? WHERE session_id = ?",
            ("up" if helpful else "down", (note or "")[:1000] or None, (corrected_root_cause or "")[:1000] or None, utc_now(), session_id),
        )
        connection.commit()
        return cursor.rowcount == 1


def get_case(session_id):
    with _connect() as connection:
        row = connection.execute("SELECT * FROM learned_cases WHERE session_id = ?", (session_id,)).fetchone()
        return _case_dict(row) if row else None


def list_cases(limit=100):
    with _connect() as connection:
        rows = connection.execute("SELECT * FROM learned_cases ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [_case_dict(row) for row in rows]


def is_trusted(case):
    """A case worth learning from: verified resolved or confirmed by the operator, and never rejected."""
    if case.get("feedback") == "down":
        return bool(case.get("corrected_root_cause"))
    return case.get("feedback") == "up" or case.get("outcome") in GOOD_OUTCOMES


def find_similar(issue, os_type=None, limit=3, trusted_only=True):
    """Rank past cases by keyword overlap (idf-weighted) with the new issue."""
    cases = [case for case in list_cases(1000) if (not trusted_only or is_trusted(case))]
    if not cases:
        return []
    query = set(tokenize(issue))
    if not query:
        return []
    documents = [set(tokenize(f"{case['issue']} {case.get('playbook_id') or ''} {case.get('effective_root_cause') or ''}")) for case in cases]
    document_frequency = Counter(token for document in documents for token in document)
    total = len(documents)
    scored = []
    for case, document in zip(cases, documents):
        overlap = query & document
        if not overlap:
            continue
        score = sum(math.log(1 + total / document_frequency[token]) for token in overlap) / math.sqrt(len(document) + 1)
        if os_type and case.get("os_type") == os_type:
            score *= 1.2
        scored.append((score, case))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [dict(case, similarity=round(score, 3)) for score, case in scored[:limit]]


def fix_success_stats(cases):
    """tool_id -> {"attempts", "resolved"} over cases where that fix was applied."""
    stats = defaultdict(lambda: {"attempts": 0, "resolved": 0})
    for case in cases:
        for fix in case.get("fixes", []):
            if fix.get("status") == "applied":
                stats[fix["tool_id"]]["attempts"] += 1
                if case.get("outcome") == "resolved" and case.get("feedback") != "down":
                    stats[fix["tool_id"]]["resolved"] += 1
    return dict(stats)


def learned_fixes_for(issue, os_type, min_resolved=2, min_rate=0.6):
    """Fixes that resolved most of the similar past cases (candidates to propose again)."""
    similar = find_similar(issue, os_type, limit=10, trusted_only=False)
    result = []
    for tool_id, stat in fix_success_stats(similar).items():
        rate = stat["resolved"] / stat["attempts"] if stat["attempts"] else 0
        if stat["resolved"] >= min_resolved and rate >= min_rate:
            result.append({"tool_id": tool_id, **stat, "rate": round(rate, 2)})
    return sorted(result, key=lambda item: (item["resolved"], item["rate"]), reverse=True)


def stats():
    cases = list_cases(5000)
    outcomes = Counter(case["outcome"] for case in cases)
    feedback = Counter(case["feedback"] for case in cases if case.get("feedback"))
    fixes = fix_success_stats(cases)
    top_fixes = sorted(({"tool_id": tool_id, **value, "rate": round(value["resolved"] / value["attempts"], 2) if value["attempts"] else 0} for tool_id, value in fixes.items()), key=lambda item: item["resolved"], reverse=True)
    trusted = [case for case in cases if is_trusted(case)]
    return {
        "total_cases": len(cases),
        "trusted_cases": len(trusted),
        "outcomes": dict(outcomes),
        "feedback": dict(feedback),
        "resolution_rate": round(outcomes.get("resolved", 0) / max(1, sum(outcomes[key] for key in ("resolved", "unresolved", "fix_failed"))), 2),
        "top_fixes": top_fixes[:10],
    }
