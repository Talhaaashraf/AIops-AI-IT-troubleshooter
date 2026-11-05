"""One-shot AI technician (explain a snapshot, explain logs, chat) on the configured LLM provider."""

import json
import logging
import re

from .llm import LLMModelError, LLMUnavailableError, get_provider
from .llm.base import loads_lenient
from .llm.brain import BRAIN_PRINCIPLES

DIAGNOSIS_SYSTEM_PROMPT = (
    "You are an experienced IT help desk technician analyzing a device's health data. "
    "Explain issues in plain, non-technical language first, then give a technical root-cause "
    "explanation, then concrete step-by-step recommendations a normal user can follow. "
    + BRAIN_PRINCIPLES + " Return valid JSON only."
)
LOG_SYSTEM_PROMPT = (
    "You are an experienced IT support engineer analyzing recent operating system event log "
    "entries (Windows Event Viewer, journald, or the macOS unified log). Identify the most "
    "likely root cause behind any critical or error patterns, explain it in plain language "
    "first, then give the technical detail, then concrete remediation steps. If the logs show "
    "no meaningful problem, say so plainly. " + BRAIN_PRINCIPLES + " Return valid JSON only."
)
CHAT_SYSTEM_PROMPT = (
    "You are a helpful IT technician having a conversation. Answer the user's actual question directly, "
    "using the conversation for follow-ups such as 'how do I do step 2?'. Always reply in English. "
    "A greeting or general question needs a direct answer, "
    "not a device diagnosis. Use device_snapshot only when relevant; quote measurements supporting a device claim. "
    "device_context describes its source and freshness: stale/offline data is historical, never live proof. "
    "Missing data means unknown, not healthy or faulty. A container snapshot describes only the container, "
    "not its host PC. Reference guidance is general knowledge, not evidence that a fault exists on this device. "
    "If the cause is unclear, explain what is known and ask one or two specific questions before guessing. "
    "You cannot browse, inspect files, run checks or execute fixes in this chat. Never claim you did; "
    "ask for an error message or suggest a relevant check in Performance or Troubleshoot when needed. "
    + BRAIN_PRINCIPLES +
    ' Return only JSON: {"plain_explanation": "direct answer", "technical_root_cause": "", '
    '"recommendations": []}. Leave technical_root_cause empty unless a technical explanation is relevant. '
    "Recommendations are optional; do not add fixes to an unrelated question. Keep the answer concise."
)

logger = logging.getLogger(__name__)

# A 3B model on a laptop CPU reads ~90 prompt tokens/s and writes ~7 tokens/s, and the provider
# serves one request at a time. The raw report (event logs alone are ~4k tokens) made a quick
# summary take many minutes and stalled every other AI call behind it, so prompts get a digest
# and answers get a length cap.
SUMMARY_MAX_TOKENS = 400
CHAT_MAX_TOKENS = 700
CHAT_HISTORY_MESSAGES = 6
CHAT_HISTORY_CHARS = 6000
# The detailed report explains every detected issue, so it gets more room (~2.5 min on a laptop CPU).
REPORT_MAX_TOKENS = 700
MAX_REPORT_ISSUES = 6
MAX_EVENT_GROUPS = 8
MAX_LOG_EVENT_GROUPS = 25
MAX_ALERT_GROUPS = 8

# Kept under their historical names so callers did not have to change.
AIUnavailableError = LLMUnavailableError
AIModelUnavailableError = LLMModelError


def ai_status():
    try:
        return get_provider().status()
    except LLMUnavailableError as error:
        return {"available": False, "provider": "unknown", "model": None, "message": str(error)}


def is_ai_available():
    return bool(ai_status().get("available"))


# "Think deeper": the model reasons before answering. Thinking tokens count toward the cap, and on a
# laptop CPU it takes several minutes, so it is opt-in for chat and summaries.
THINKING_MAX_TOKENS = 1800
THINKING_TIMEOUT_SECONDS = 900


def _completion(messages, max_tokens=SUMMARY_MAX_TOKENS, think=False):
    if think:
        return get_provider().chat(messages, json_mode=True, max_tokens=max(max_tokens, THINKING_MAX_TOKENS), think=True, timeout=THINKING_TIMEOUT_SECONDS)["content"]
    return get_provider().chat(messages, json_mode=True, max_tokens=max_tokens, think=False)["content"]


def _clip(text, limit=140):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _event_groups(event_logs, limit):
    """Collapse repeated events into 'source #id xN: message', most frequent first."""
    groups = {}
    for event in (event_logs or {}).get("events") or []:
        key = (event.get("source") or "?", event.get("id"))
        group = groups.setdefault(key, {"count": 0, "level": event.get("level"), "message": ""})
        group["count"] += 1
        if not group["message"] and event.get("message"):
            group["message"] = _clip(event["message"], 120)
    ranked = sorted(groups.items(), key=lambda item: -item[1]["count"])[:limit]
    return [
        f"{source} #{event_id} x{group['count']}" + (f" [{group['level']}]" if group["level"] else "") + (f": {group['message']}" if group["message"] else "")
        for (source, event_id), group in ranked
    ]


def _alert_groups(alerts, limit=MAX_ALERT_GROUPS):
    """One line per category/severity with a count and the latest description."""
    groups = {}
    for alert in alerts or []:
        key = (alert.get("category") or "General", alert.get("severity") or "medium")
        group = groups.setdefault(key, {"count": 0, "latest": _clip(alert.get("description"), 120)})
        group["count"] += 1
    return [f"{severity} {category} x{group['count']}: {group['latest']}" for (category, severity), group in list(groups.items())[:limit]]


def _detail(section):
    if not isinstance(section, dict) or section.get("available") is False:
        return None
    return _clip(section.get("detail"), 120) or None


def compact_report(report, alert_history=None):
    """A few hundred tokens with what a technician looks at first, instead of the raw report."""
    report = report or {}
    system = report.get("system") or {}
    cpu = report.get("cpu") or {}
    memory = report.get("memory") or {}
    ram, swap = memory.get("ram") or {}, memory.get("swap") or {}
    processes = report.get("top_processes") or {}
    security = report.get("security") or {}
    performance = report.get("performance") or {}
    event_logs = report.get("event_logs") or {}
    battery = report.get("battery")
    digest = {
        "system": " ".join(str(part) for part in (system.get("os_name"), system.get("os_release"), system.get("hostname")) if part),
        "cpu": f"{cpu.get('total_usage_percent')}% used, {cpu.get('logical_cores')} logical cores at {cpu.get('current_frequency_mhz')}/{cpu.get('max_frequency_mhz')} MHz",
        "ram": f"{ram.get('usage_percent')}% used ({ram.get('available')} free of {ram.get('total')})",
        "swap": f"{swap.get('usage_percent')}% of {swap.get('total')}",
        "disks": [f"{disk.get('mountpoint') or disk.get('device')} {disk.get('usage_percent')}% used ({disk.get('free')} free)" for disk in (report.get("disk") or [])[:4]],
        "battery": f"{battery.get('percent')}%{' charging' if battery.get('charging') else ''}" if isinstance(battery, dict) else None,
        "top_cpu": [f"{item.get('name')} {item.get('cpu_percent')}%" for item in (processes.get("top_by_cpu") or [])[:5]],
        "top_memory": [f"{item.get('name')} {item.get('memory_percent')}%" for item in (processes.get("top_by_memory") or [])[:5]],
        "security": {name: _detail(security.get(name)) for name in ("firewall", "antivirus", "disk_encryption", "updates") if _detail(security.get(name))},
        "performance": [detail for detail in (_detail(performance.get(name)) for name in ("cpu", "disk", "network")) if detail],
    }
    if event_logs.get("available"):
        digest["event_logs"] = {
            "last_hours": event_logs.get("lookback_hours"),
            "critical": event_logs.get("critical_count"),
            "errors": event_logs.get("error_count"),
            "warnings": event_logs.get("warning_count"),
            "most_frequent": _event_groups(event_logs, MAX_EVENT_GROUPS),
        }
    if alert_history:
        digest["recent_alerts"] = _alert_groups(alert_history)
    return {key: value for key, value in digest.items() if value not in (None, "", [], {})}


_loads_lenient = loads_lenient  # moved to backend/llm/base.py; the planner uses it too


def _as_text(item):
    if isinstance(item, dict):
        # e.g. {"summary": "Restart", "details": "Close apps first"} -> "Restart: Close apps first"
        return ": ".join(str(value).strip() for value in item.values() if isinstance(value, (str, int, float)) and str(value).strip())
    return str(item)


def _as_list(value):
    """Small models return list fields as a numbered string, a list of strings or a list of
    objects; iterating a string would yield single characters, so normalise to readable lines."""
    if isinstance(value, str):
        items = [re.sub(r"^\s*(?:\d+[.)]|[-*•])\s*", "", line) for line in value.splitlines()]
    elif isinstance(value, (list, tuple)):
        items = [_as_text(item) for item in value]
    else:
        items = []
    return [item.strip() for item in items if item and item.strip()]


def _parse_diagnosis(raw):
    try:
        result = _loads_lenient(raw)
    except (TypeError, ValueError):
        return {
            "summary": raw,
            "root_cause": "The technician returned an unstructured response.",
            "severity": "medium",
            "steps": [
                "Review the current alerts and metrics above.",
                "Ask the technician a follow-up question for a more focused explanation.",
            ],
            "suggested_actions": [],
        }
    return {
        "summary": str(result.get("summary", "No summary returned.")),
        "root_cause": str(result.get("root_cause", "Unknown")),
        "severity": str(result.get("severity", "medium")).strip().lower() or "medium",
        "steps": _as_list(result.get("steps")),
        "suggested_actions": _as_list(result.get("suggested_actions")),
        "issues": _issue_explanations(result.get("issues")),
        "prevention": _as_list(result.get("prevention")),
    }


def _issue_explanations(value):
    """[{title, explanation, fix_steps}] from whatever shape the model returned."""
    items = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, dict):
            title = str(item.get("title") or item.get("issue") or item.get("name") or "").strip()
            explanation = str(item.get("explanation") or item.get("why") or item.get("description") or "").strip()
            steps = _as_list(item.get("fix_steps") or item.get("steps") or item.get("fix"))
        else:
            title, explanation, steps = str(item).strip(), "", []
        if title or explanation:
            items.append({"title": title, "explanation": explanation, "fix_steps": steps})
    return items


def diagnose(report, alert_history, issues=None, think=False):
    """Explain a device snapshot: the model explains each rule-detected problem (health_report)
    instead of judging raw numbers itself, which a small model gets wrong."""
    schema_hint = (
        " Use this schema: {summary, root_cause, severity, issues, steps, prevention}."
        " summary: 3-4 sentences on the overall health of the computer and what matters most."
        " issues: one entry per detected issue, {title, explanation, fix_steps}; explanation is 1-2 plain sentences on why it"
        " happens and how it affects the user, fix_steps is a JSON array of 2-3 concrete steps."
        " steps: the 3-5 most important actions overall, in priority order. prevention: 1-3 habits that keep the PC healthy."
        " Only describe problems listed in detected_issues; if the list is empty, say the computer is healthy."
        " Keep the whole answer under 300 words."
    )
    if issues is None:
        from .health_report import detect_issues  # lazy: health_report imports this module
        issues = detect_issues(report or {})
    digest = compact_report(report, alert_history)
    digest["detected_issues"] = [f"{item['severity']} {item['category']}: {item['title']}" for item in issues[:MAX_REPORT_ISSUES]]
    raw = _completion([
        {"role": "system", "content": DIAGNOSIS_SYSTEM_PROMPT + schema_hint},
        {"role": "user", "content": json.dumps(digest, default=str)},
    ], max_tokens=REPORT_MAX_TOKENS, think=think)
    return _parse_diagnosis(raw)


def diagnose_logs(event_log_report, think=False):
    report = event_log_report or {}
    if not report.get("available") or not report.get("events"):
        detail = report.get("detail") or "No event log entries were collected."
        return {
            "summary": f"There are no event log entries to analyse: {detail}",
            "root_cause": "No warning, error or critical events are available for this device.",
            "severity": "low",
            "steps": ["If you expected events, pick a device under Event Logs, or check that its agent runs as administrator/root."],
            "suggested_actions": [], "issues": [], "prevention": [], "source": "rules",
        }
    schema_hint = " Use this schema: {summary, root_cause, severity, steps, suggested_actions}."
    raw = _completion([
        {"role": "system", "content": LOG_SYSTEM_PROMPT + schema_hint},
        {"role": "user", "content": json.dumps({
            "event_logs": {
                "detail": (event_log_report or {}).get("detail"),
                "critical": (event_log_report or {}).get("critical_count"),
                "errors": (event_log_report or {}).get("error_count"),
                "warnings": (event_log_report or {}).get("warning_count"),
                "most_frequent": _event_groups(event_log_report, MAX_LOG_EVENT_GROUPS),
            },
        }, default=str)},
    ], think=think)
    return _parse_diagnosis(raw)


def _parse_chat_reply(raw):
    text = raw.strip()
    if text.startswith("```"):
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        result = _loads_lenient(text)
        if not isinstance(result, dict):
            raise ValueError("Chat reply must be an object")
    except (TypeError, ValueError):
        return {
            "plain_explanation": raw,
            "technical_root_cause": "",
            "recommendations": [],
        }
    return {
        "plain_explanation": str(result.get("plain_explanation", result.get("summary", "No plain-language explanation returned."))),
        "technical_root_cause": str(result.get("technical_root_cause") or result.get("root_cause") or ""),
        "recommendations": _as_list(result.get("recommendations", result.get("steps"))),
    }


def normalize_chat_history(history):
    """Bound client/server history and retain the steps a follow-up can refer to."""
    if not isinstance(history, list):
        return []
    kept = []
    remaining = CHAT_HISTORY_CHARS
    for item in reversed(history[-CHAT_HISTORY_MESSAGES:]):
        if not isinstance(item, dict) or item.get("role") not in ("user", "assistant"):
            continue
        content = item.get("content")
        if item["role"] == "assistant" and isinstance(content, dict):
            content = json.dumps({key: content[key] for key in (
                "plain_explanation", "technical_root_cause", "recommendations"
            ) if key in content}, ensure_ascii=False)
        if not isinstance(content, str) or not content.strip():
            continue
        content = content[:min(2000, remaining)]
        kept.append({"role": item["role"], "content": content})
        remaining -= len(content)
        if remaining <= 0:
            break
    return list(reversed(kept))


def chat(message, report, conversation_history, think=False, context=None):
    from .agent_brain.knowledge import retrieve, retrieve_codes

    messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]
    messages.extend(normalize_chat_history(conversation_history))
    guidance = "\n".join(filter(None, [retrieve(message, mode="fast"), retrieve_codes(message)]))
    messages.append({"role": "user", "content": json.dumps({
        "question": message,
        "device_context": context or {"source": "unknown", "stale": True},
        "device_snapshot": compact_report(report) if report else None,
        "reference_guidance": guidance,
    }, default=str, ensure_ascii=False)})
    return _parse_chat_reply(_completion(messages, max_tokens=CHAT_MAX_TOKENS, think=think))


LEFTOVER_PROMPT = (
    "You are an experienced Windows and Linux IT technician. A program was uninstalled and these items it left behind are "
    "about to be moved to a quarantine the user can restore for 7 days. For each item judge whether it belongs only to this "
    "program (remove), should be kept because it is shared with other software or holds user documents or system data (keep), "
    "or you cannot tell (unsure). " + BRAIN_PRINCIPLES + " Return valid JSON only."
)
LEFTOVER_VERDICTS = ("remove", "keep", "unsure")


def review_leftovers(program, candidates, think=False):
    """Advice only: a person still ticks the boxes and approves the quarantine."""
    schema = ' Use this schema: {"summary": "one or two sentences", "items": [{"id": "c0", "verdict": "remove|keep|unsure", "reason": "short reason"}]}.'
    payload = {"program": program, "leftovers": [{key: item.get(key) for key in ("id", "kind", "path", "location", "reason", "size_text")} for item in candidates[:40]]}
    raw = _completion([
        {"role": "system", "content": LEFTOVER_PROMPT + schema},
        {"role": "user", "content": json.dumps(payload, default=str)},
    ], max_tokens=700, think=think)
    try:
        result = _loads_lenient(raw)
    except (TypeError, ValueError):
        result = {}
    known = {item.get("id") for item in candidates}
    items = []
    for entry in result.get("items") or []:
        if isinstance(entry, dict) and entry.get("id") in known:
            verdict = str(entry.get("verdict") or "unsure").lower()
            items.append({"id": entry["id"], "verdict": verdict if verdict in LEFTOVER_VERDICTS else "unsure", "reason": " ".join(str(entry.get("reason") or "").split())[:240]})
    return {"summary": " ".join(str(result.get("summary") or "").split())[:500], "items": items}


# ---------------------------------------------------------------------------
# Endpoint threat detection: explain the findings, and the action chat
# ---------------------------------------------------------------------------

THREAT_PROMPT = (
    "You are an experienced security analyst helping an IT technician with one device's endpoint threat findings: antivirus "
    "detections, failed sign-ins, account changes, new services and tasks, PowerShell, tampering and antivirus health. "
    "The findings T1..Tn are facts from the device's own logs, checked by rules: never invent others, and name the ids you use. "
    "Heuristic detections of security tools inside an ISO or archive (for example a Kali Linux image) are usually a tool someone "
    "downloaded, not an infection; say so when it fits. " + BRAIN_PRINCIPLES + " Return valid JSON only."
)
THREAT_CHAT_RULES = (
    " You are the dashboard's action chat. Answer only in English, in a few sentences. "
    "When the person asks to do something to a finding, set finding_id and action to it, but only an action that finding lists "
    "as approvable; the dashboard then shows an approval card and nothing runs until the person approves it. Never say an "
    "action was done or started. If they ask for something that is not approvable, set action to none and say how to do it by "
    "hand (from the finding's steps). For a question, set action to none."
)
THREAT_ACTIONS = ("none", "rescan", "quarantine", "kill", "delete")
# Fields with people's names, addresses and computer names: they stay on this server when the AI is a cloud one.
PERSONAL_FIELDS = {"Account", "User", "Created by", "Cleared by", "Member", "Added by", "Installed by", "Source address", "Workstation",
                   "New account", "Locked out from", "Runs as"}
MAX_THREAT_FINDINGS = 25


def _cloud_ai():
    return getattr(get_provider(), "name", "") == "groq"


USER_FOLDER = re.compile(r"(?i)([\\/](?:users|home)[\\/])[^\\/]+")


def _for_ai(finding, cloud):
    """The finding as the AI may see it. For a cloud AI, names, addresses and user folders are hidden everywhere
    (title and summary repeat the proof's values)."""
    if not cloud:
        return finding
    personal = sorted({str(item["value"]) for item in finding["proof"] if item["label"] in PERSONAL_FIELDS and len(str(item["value"])) > 1}, key=len, reverse=True)

    def hide(text):
        text = str(text or "")
        for value in personal:
            text = text.replace(value, "[hidden]")
        return USER_FOLDER.sub(r"\1[user]", text)

    return {**finding, "title": hide(finding["title"]), "summary": hide(finding["summary"]), "path": hide(finding.get("path")) if finding.get("path") else None,
            "proof": [{**item, "value": "[hidden]" if item["label"] in PERSONAL_FIELDS else hide(item["value"])} for item in finding["proof"]]}


def _threat_context(analysis):
    from .threat_rules import finding_text

    cloud = _cloud_ai()
    lines = [finding_text(_for_ai(finding, cloud)) for finding in analysis["findings"][:MAX_THREAT_FINDINGS]]
    unreadable = "; ".join(f"{source['name']}: {source['detail']}" for source in analysis.get("unreadable") or [])
    return ("\n".join(lines) or "No findings: the scan found nothing suspicious.") + (f"\nNot readable on this device: {unreadable}" if unreadable else "")


def _schema_completion(messages, schema, max_tokens, think=False):
    if think:
        return get_provider().chat(messages, json_mode=schema, max_tokens=max(max_tokens, THINKING_MAX_TOKENS), think=True, timeout=THINKING_TIMEOUT_SECONDS)["content"]
    return get_provider().chat(messages, json_mode=schema, max_tokens=max_tokens, think=False)["content"]


def explain_threats(analysis, think=False):
    """What the findings mean and which come first. Advice only: actions are approved per finding in the dashboard."""
    ids = [finding["id"] for finding in analysis["findings"][:MAX_THREAT_FINDINGS]] or ["none"]
    schema = {"type": "object", "required": ["summary", "priorities", "next_steps"], "properties": {
        "summary": {"type": "string"},
        "priorities": {"type": "array", "items": {"type": "object", "required": ["finding_id", "why"],
                                                  "properties": {"finding_id": {"type": "string", "enum": ids}, "why": {"type": "string"}}}},
        "next_steps": {"type": "array", "items": {"type": "string"}}}}
    raw = _schema_completion([
        {"role": "system", "content": THREAT_PROMPT + ' Schema: {"summary": "2-3 sentences", "priorities": [{"finding_id": "T1", "why": "..."}], "next_steps": ["..."]}.'},
        {"role": "user", "content": f"Device platform: {analysis.get('platform')}\nFindings:\n{_threat_context(analysis)}"},
    ], schema, 500, think)
    try:
        result = _loads_lenient(raw)
    except (TypeError, ValueError):
        result = {}
    known = set(ids)
    priorities = [{"finding_id": item["finding_id"], "why": " ".join(str(item.get("why") or "").split())[:300]}
                  for item in result.get("priorities") or [] if isinstance(item, dict) and item.get("finding_id") in known][:5]
    return {"summary": " ".join(str(result.get("summary") or "").split())[:800], "priorities": priorities,
            "next_steps": [" ".join(str(step).split())[:300] for step in _as_list(result.get("next_steps"))][:6], "source": "ai"}


def threat_chat(message, analysis, history, think=False):
    """{reply, finding_id, action, pid} from the action chat. The caller checks the proposal against the finding's
    approvable actions (backend/threat_rules.proposal); nothing here runs anything."""
    ids = [finding["id"] for finding in analysis["findings"][:MAX_THREAT_FINDINGS]] + ["none"]
    schema = {"type": "object", "required": ["reply", "finding_id", "action"], "properties": {
        "reply": {"type": "string"}, "finding_id": {"type": "string", "enum": ids},
        "action": {"type": "string", "enum": list(THREAT_ACTIONS)}, "pid": {"type": "integer"}}}
    messages = [{"role": "system", "content": THREAT_PROMPT + THREAT_CHAT_RULES +
                 ' Schema: {"reply": "...", "finding_id": "T1 or none", "action": "none|rescan|quarantine|kill|delete", "pid": 0}.'}]
    messages.extend({"role": item["role"], "content": str(item.get("content", ""))} for item in history[-6:])
    messages.append({"role": "user", "content": f"Findings:\n{_threat_context(analysis)}\n\nQuestion: {message}"})
    raw = _schema_completion(messages, schema, 350, think)
    try:
        result = _loads_lenient(raw)
    except (TypeError, ValueError):
        result = {"reply": raw}
    pid = result.get("pid")
    return {"reply": " ".join(str(result.get("reply") or "").split())[:1200], "finding_id": str(result.get("finding_id") or "none"),
            "action": str(result.get("action") or "none"), "pid": pid if isinstance(pid, int) and pid > 0 else None}
