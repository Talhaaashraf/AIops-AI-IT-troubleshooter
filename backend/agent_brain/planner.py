"""The agentic troubleshooting loop.

1. Baseline: run system_overview plus the matched playbook's tools, in parallel
   (CPU-sensitive measurements first). The model is loaded at the same time.
2. Instant findings: deterministic rules turn the evidence into concrete problems
   within seconds (see findings.py). "instant" mode stops here.
3. Investigate (deep mode only): the LLM calls further read-only tools until it has enough evidence.
4. Report: one call whose answer must follow a JSON schema turns evidence + findings + the model's own
   IT knowledge into a root cause and 3-4 ranked solutions. Fast mode answers directly; deep mode thinks
   first (streamed live, within a budget). Findings are split into those that can explain the complaint
   and separate problems, and the answer names the one it blames, so the server can check it
   (ground_root_cause) and set the confidence from the evidence rather than the model's say-so.
   A solution may name an allow-listed remediation tool, which makes it runnable after a person approves it.
5. Fix: ONLY when a person approves a solution in the dashboard. There is no automatic path.
   Then re-verify: by rules when the fix targeted a finding, otherwise by the LLM.

The LLM can never execute a fix itself: during investigation it only sees read-risk tool schemas,
every proposed fix is validated against the registry, and every diagnosis and every approval or
rejection is written to the decisions folder (backend/decision_log.py).
"""

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime

from agent.toolkit import get_tool, list_tools, tool_schemas
from agent.toolkit.registry import validate_args
from agent.toolkit.remediation import PROTECTED_PROCESSES, RESTARTABLE_SERVICES

from .. import decision_log
from ..alert_store import get_alerts
from ..learning import model_builder
from ..learning import store as learning_store
from ..llm import LLMDisconnectedError, LLMTimeoutError, LLMUnavailableError, get_provider
from ..llm.base import loads_lenient
from ..llm.brain import BRAIN_PRINCIPLES, MAX_SOLUTIONS, MIN_SOLUTIONS
from ..server_identity import is_container_target, server_device
from ..workers import ai_gate, run_ai
from . import events, findings, session_store
from .executor import execute, resolve_target
from .playbooks import RELEVANT_FIXES, baseline_phases, filter_relevant_fixes, get_playbook, is_complaint, match_playbook, playbook_tips

logger = logging.getLogger(__name__)

# Kept small on purpose: on a laptop CPU, prompt length dominates how long each LLM call takes.
TOOL_RESULT_CHARS = 1200
REPORT_EVIDENCE_CHARS = 700
MAX_CALLS_PER_TURN = 3
# Output cap for the report / verify calls: generation is the slowest part on a CPU. 4 solutions with steps fit.
REPORT_MAX_TOKENS = 700
# With deep thinking the reasoning tokens count toward the cap; the provider also stops the reasoning itself
# after OLLAMA_MAX_THINKING_CHARS, so this is only the hard limit.
REPORT_THINKING_MAX_TOKENS = 2400
# When thinking used its budget before the JSON was written, a short no-thinking call turns the reasoning into
# the answer. It gets the start (the plan) and the end (the conclusion) of the reasoning.
REASONING_HANDOFF_HEAD_CHARS = 1000
REASONING_HANDOFF_TAIL_CHARS = 2500
# An AI engine that dropped the connection (e.g. restarted under memory pressure) gets one more try.
DISCONNECT_RETRY_SECONDS = 5
RISKS = ("low", "medium", "high")
# Tool calls are short; without a cap a slow model can ramble past the deadline.
INVESTIGATE_MAX_TOKENS = 300
VERIFY_MAX_TOKENS = 300
# instant: rules only (seconds, no AI) / fast: baseline + one AI call / deep: AI investigates further.
MODES = ("instant", "fast", "deep")
SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")

_session_locks = {}

INVESTIGATE_PROMPT = """You are AIops, an expert IT support technician remotely diagnosing a {os_type} computer.
""" + BRAIN_PRINCIPLES + """
Your job: find the ROOT CAUSE of the user's problem using the diagnostic tools provided.
Rules:
- Base every conclusion on tool output. Never invent numbers or facts.
- Baseline evidence is already collected below; do not re-run those exact checks.
- Call at most 2 tools at a time. Only read-only diagnostics are available now; fixes come later.
- Stop as soon as the evidence clearly explains the problem (usually 1-4 extra tool calls).
- When done, reply in plain text with a short summary of your findings and NO tool call."""

# The evidence list and issue summary are built by the server, not generated: on a laptop CPU every output token
# costs ~0.2 s, so the model only writes what needs judgement. The system prompt is the same for every diagnosis
# (the computer's details go in the user message), so Ollama reuses its cached prompt and starts sooner.
REPORT_PROMPT = """You are AIops, a senior IT support technician. Write the final diagnosis of a computer as JSON.
""" + BRAIN_PRINCIPLES + """
How to decide:
- The automatic findings are numbered F1, F2... Only those under "Can explain the complaint" can be its cause. Those under
  "Separate problems" cannot cause it: mention them only as separate problems, never as the cause.
- Put the id of the finding that best explains the complaint in "cause": the most likely cause, not the most severe finding.
  Severity says how bad a finding is, not how sure you are.
- If the cause comes from the investigator's extra checks rather than a numbered finding, set "cause" to "investigation".
- If nothing explains the complaint, set "cause" to "none", say plainly in root_cause that the checks did not show the
  problem, set confidence to "low", and give 3 next diagnostic steps instead of fixes.
- confidence "high" only when a finding clearly explains the complaint; "medium" when it probably does.
- The first solution must fix the cause. A solution for a separate problem comes last (at most one).
- Write the steps for the computer's operating system, in simple language a non-technical user understands.
- Set tool_id only when one of the listed fix tools performs that solution (a person still approves it), otherwise null.
  Use only process ids and startup item names that appear in the evidence. Never close system processes.
JSON fields: cause, root_cause (1-2 sentences citing the evidence), confidence (low|medium|high),
severity (low|medium|high|critical), solutions: 3 or 4 of {title, why (one sentence), steps (up to 4), risk (low|medium|high), tool_id, args}.
Keep any private reasoning short and focused, then write the JSON."""


def report_schema(finding_ids, fix_ids, investigated=False):
    """The JSON schema the answer must follow (Ollama enforces it while generating). "cause" comes first, so the model
    commits to a finding before it writes the explanation, and it can only be a finding that can explain the
    complaint (or "none", or what the investigation found)."""
    return {
        "type": "object",
        "properties": {
            "cause": {"enum": list(finding_ids) + (["investigation"] if investigated else []) + ["none"]},
            "root_cause": {"type": "string"},
            "confidence": {"enum": list(CONFIDENCES)},
            "severity": {"enum": list(SEVERITIES)},
            "solutions": {"type": "array", "minItems": MIN_SOLUTIONS, "maxItems": MAX_SOLUTIONS, "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "why": {"type": "string"},
                    "steps": {"type": "array", "maxItems": 4, "items": {"type": "string"}},
                    "risk": {"enum": list(RISKS)},
                    "tool_id": {"enum": sorted(fix_ids) + [None]},
                    "args": {"type": "object"},
                },
                "required": ["title", "why", "steps", "risk", "tool_id"],
            }},
        },
        "required": ["cause", "root_cause", "confidence", "severity", "solutions"],
    }


# Small models often write a fix as a manual instruction ("run ipconfig /flushdns").
# These patterns turn such steps into one-click fixes when a matching tool exists.
MANUAL_STEP_FIXES = (
    (re.compile(r"flushdns|flush\w*\s+(the\s+)?dns|dns\s+cache", re.I), "flush_dns"),
    (re.compile(r"ipconfig\s*/renew|renew\w*\s+(the\s+|your\s+)?ip", re.I), "renew_ip"),
    (re.compile(r"winsock|netsh\s+int\w*\s+ip\s+reset", re.I), "reset_network_stack"),
    (re.compile(r"sfc\s*/scannow|system file checker", re.I), "repair_system_files"),
    (re.compile(r"dism\b", re.I), "repair_windows_image"),
    (re.compile(r"(delete|clear|clean)\w*\s+(the\s+|all\s+)?temp", re.I), "clear_temp_files"),
    (re.compile(r"(empty|clear)\w*\s+(the\s+)?(recycle\s*bin|trash)", re.I), "empty_recycle_bin"),
    (re.compile(r"print\s+queue|stuck\s+print|spooler", re.I), "clear_print_queue"),
    (re.compile(r"w32tm|sync\w*\s+(the\s+)?(system\s+)?(time|clock)", re.I), "sync_time"),
    (re.compile(r"softwaredistribution|update\s+cache", re.I), "clear_windows_update_cache"),
)

VERIFY_PROMPT = """You are AIops, an IT technician verifying whether a fix worked on a {os_type} computer.
""" + BRAIN_PRINCIPLES + """
Compare the original diagnosis with the fresh evidence collected after the fix. Reply as JSON:
{{"resolved": true|false, "explanation": "plain-language verdict citing the fresh evidence", "next_steps": ["..."]}}"""


def diagnosis_thinking(mode=None):
    """Deep thinking for the diagnosis report, in deep mode only (DIAGNOSIS_THINKING turns it off there too). On a
    CPU thinking costs several minutes; fast mode answers in one direct call from pre-digested evidence."""
    enabled = os.getenv("DIAGNOSIS_THINKING", "true").strip().lower() in ("1", "true", "yes")
    return enabled if mode is None else enabled and mode == "deep"


def max_investigation_steps():
    try:
        return max(0, min(12, int(os.getenv("AGENT_MAX_STEPS", "3"))))
    except ValueError:
        return 3


def default_mode():
    value = os.getenv("DIAGNOSIS_MODE", "fast").strip().lower()
    return value if value in MODES else "fast"


def normalize_mode(value):
    value = str(value or "").strip().lower()
    return value if value in MODES else default_mode()


def investigation_rounds(mode, playbook):
    """Fast mode goes straight to the report from the baseline (a playbook's, or the broad general one)."""
    return max_investigation_steps() if mode == "deep" else 0


def _compact(result, limit=TOOL_RESULT_CHARS):
    data = result.get("data")
    if isinstance(data, dict) and "hostname" in data:
        data = {key: value for key, value in data.items() if key != "hostname"}  # adds nothing, and must not leave for a cloud AI
    payload = json.dumps({"ok": result.get("ok"), "summary": result.get("summary"), "data": data}, default=str)
    return payload if len(payload) <= limit else payload[:limit] + "...(truncated)"


def _lock(session_id):
    return _session_locks.setdefault(session_id, asyncio.Lock())


def _publish_status(session_id, status, message=""):
    session_store.update_session(session_id, status=status)
    events.publish(session_id, {"type": "status", "status": status, "message": message})


async def _run_step(session_id, target, tool_id, args, max_risk="read", kind="tool"):
    events.publish(session_id, {"type": "step_started", "kind": kind, "tool_id": tool_id, "args": args})
    result = await execute(target, tool_id, args, max_risk, session_id)
    step = session_store.add_step(session_id, kind, tool_id, args, result)
    events.publish(session_id, {"type": "step", "step": step})
    return result


def _think(session_id, text):
    if text:
        step = session_store.add_step(session_id, "thought", text=text[:2000])
        events.publish(session_id, {"type": "step", "step": step})


def parse_inline_tool_calls(content, allowed):
    """Small local models sometimes write the tool call as JSON text instead of a real call."""
    calls, decoder, index = [], json.JSONDecoder(), 0
    text = content or ""
    while (index := text.find("{", index)) != -1:
        try:
            obj, end = decoder.raw_decode(text, index)
        except ValueError:
            index += 1
            continue
        index = end
        if isinstance(obj, dict) and obj.get("name") in allowed:
            arguments = obj.get("arguments", obj.get("parameters", {}))
            calls.append({"id": f"inline-{len(calls)}", "name": obj["name"], "arguments": arguments if isinstance(arguments, dict) else {}})
    return calls


def parse_reply(text):
    """(dict, truncated): the JSON object in a reply. A reply cut off by the token cap keeps its complete parts
    instead of falling back to the rules."""
    text = (text or "").strip()
    try:
        value = json.loads(text)
        return (value if isinstance(value, dict) else {}), False
    except ValueError:
        pass
    try:
        value = loads_lenient(text)
    except ValueError:
        return {}, False
    return (value if isinstance(value, dict) else {}), True


def _parse_json(text):
    return parse_reply(text)[0]


SENTENCE_END = re.compile(r"\.(\s|$)")


def first_sentence(text):
    """The first sentence, not cut at "e.g." or "i.e." or inside brackets ("... service (e.g. Spooler, BITS)")."""
    text = text or ""
    for match in SENTENCE_END.finditer(text):
        before = text[:match.start()]
        if before.endswith(("e.g", "i.e", "etc")) or before.count("(") > before.count(")"):
            continue
        return before
    return text.rstrip(".")


def _arg_hint(tool, os_type):
    """How the model fills a fix's arguments: the allowed values, or where in the evidence they come from."""
    if tool.id == "restart_service":
        return "name: one of " + ", ".join(sorted(RESTARTABLE_SERVICES.get(os_type, ())))
    if tool.id == "kill_process":
        return "pid and expected_name of a process listed in the evidence"
    if tool.id == "disable_startup_item":
        return "name of a startup item listed in the evidence"
    return ", ".join(f"{name}: {spec.get('type')}" for name, spec in tool.params.items())


def catalog_tools(os_type, only=None):
    return [item for item in list_tools(os_type, max_risk="high", min_risk="low") if item.ai_visible and (not only or item.id in only)
            and (item.id != "restart_service" or RESTARTABLE_SERVICES.get(os_type))]


def fix_catalog(os_type, only=None):
    """One compact line per fix tool: `- id (risk) args {...}: first sentence of the description`.
    `only` limits the catalog (e.g. to a playbook's relevant fixes) to keep the prompt short."""
    lines = []
    for item in catalog_tools(os_type, only):
        hint = _arg_hint(item, os_type)
        lines.append(f"- {item.id} ({item.risk})" + (f" args {{{hint}}}" if hint else "") + f": {first_sentence(item.description)}")
    return "\n".join(lines)


def known_items(evidence):
    """Process ids/names and startup items the checks saw: the only ones a fix may name (the agent acts only on
    things it discovered itself, and the server holds the AI to the same rule)."""
    processes, startup = set(), set()
    for tool_id, _args, result in evidence or []:
        data = result.get("data")
        if tool_id == "top_processes" and isinstance(data, list):
            processes |= {(row.get("pid"), str(row.get("name") or "").lower()) for row in data if isinstance(row, dict)}
        elif tool_id == "startup_programs" and isinstance(data, list):
            startup |= {str(row.get("name") or "").lower() for row in data if isinstance(row, dict)}
    return {"processes": processes, "startup": startup}


def _device_would_accept(tool_id, args, os_type):
    """Drop fixes the device is certain to refuse, so the operator never sees a dead button."""
    if tool_id == "restart_service":
        return args.get("name") in RESTARTABLE_SERVICES.get(os_type, ())
    if tool_id == "kill_process":
        return str(args.get("expected_name", "")).lower() not in PROTECTED_PROCESSES
    return True


def _seen_by_the_checks(tool_id, args, known):
    if tool_id == "kill_process":
        return (args.get("pid"), str(args.get("expected_name", "")).lower()) in known["processes"]
    if tool_id == "disable_startup_item":
        return str(args.get("name", "")).lower() in known["startup"]
    return True


def validate_fixes(raw_fixes, os_type, known=None):
    """Keep only fixes that name a real remediation tool for this OS with valid arguments. With `known`
    (known_items of the evidence), a process or startup item must be one the checks actually saw."""
    fixes, seen = [], set()
    for raw in raw_fixes if isinstance(raw_fixes, list) else []:
        if not isinstance(raw, dict):
            continue
        item = get_tool(str(raw.get("tool_id", "")).strip())
        if item is None or item.risk == "read" or os_type not in item.os or not item.ai_visible:
            continue
        try:
            args = validate_args(item, raw.get("args") or {})
        except ValueError:
            continue
        if not _device_would_accept(item.id, args, os_type) or (known is not None and not _seen_by_the_checks(item.id, args, known)):
            continue
        key = (item.id, json.dumps(args, sort_keys=True))
        if key in seen:
            continue
        seen.add(key)
        fixes.append({"tool_id": item.id, "args": args, "risk": item.risk, "description": item.description, "why": str(raw.get("why", ""))[:500], "status": "proposed", "result": None})
    return fixes


def _offerable_without_args(item, os_type):
    """A fix tool that may become a one-click solution without arguments: a real change tool for this OS that
    the AI is allowed to propose (actions only a person starts, like installing OS updates, never qualify)."""
    return item is not None and item.risk != "read" and item.ai_visible and os_type in item.os and not item.required


def promote_manual_steps(manual_steps, fixes, os_type):
    """Turn manual instructions that a fix tool can perform into proposed fixes."""
    remaining, present = [], {fix["tool_id"] for fix in fixes}
    for step in manual_steps:
        tool_id = next((tool_id for pattern, tool_id in MANUAL_STEP_FIXES if pattern.search(step)), None)
        item = get_tool(tool_id) if tool_id else None
        if not _offerable_without_args(item, os_type):
            remaining.append(step)
            continue
        if tool_id not in present:
            present.add(tool_id)
            fixes.append({"tool_id": tool_id, "args": {}, "risk": item.risk, "description": item.description, "why": f"AIops can do this step for you: {step[:300]}", "status": "proposed", "result": None})
    return remaining, fixes


def _fix_key(item):
    return (item.get("tool_id"), json.dumps(item.get("args") or {}, sort_keys=True))


def _steps(value):
    if isinstance(value, str):
        value = [line.strip(" -*0123456789.)") for line in value.splitlines()]
    return [str(step).strip()[:300] for step in (value if isinstance(value, list) else []) if str(step).strip()][:6]


def normalize_solutions(raw_solutions, os_type, known=None):
    """3-4 ranked solutions from the model. A tool_id survives only if the registry accepts it for this
    OS; otherwise the solution stays manual (the user follows its steps by hand)."""
    solutions = []
    for entry in raw_solutions if isinstance(raw_solutions, list) else []:
        if isinstance(entry, str):
            entry = {"title": entry}
        if not isinstance(entry, dict):
            continue
        title = " ".join(str(entry.get("title") or entry.get("action") or entry.get("name") or "").split())[:160]
        if not title:
            continue
        tool_id = str(entry.get("tool_id") or "").strip()
        fix = None
        if tool_id and tool_id.lower() not in ("null", "none"):
            valid = validate_fixes([{"tool_id": tool_id, "args": entry.get("args") or {}, "why": entry.get("why", "")}], os_type, known)
            fix = valid[0] if valid else None
        if fix and any(item["tool_id"] == fix["tool_id"] and item["args"] == fix["args"] for item in solutions):
            continue  # the same runnable fix twice
        if fix is None:
            # Title only: a tool named in a later step ("if that fails, reset winsock") must not turn a
            # card titled "Update the network driver" into a one-click button for something else.
            promoted = next((tool for pattern, tool in MANUAL_STEP_FIXES if pattern.search(title)), None)
            item = get_tool(promoted) if promoted else None
            if _offerable_without_args(item, os_type) and not any(existing["tool_id"] == promoted for existing in solutions):
                fix = {"tool_id": item.id, "args": {}, "risk": item.risk}
        risk = str(entry.get("risk") or "low").lower()
        solutions.append({
            "title": title,
            "why": " ".join(str(entry.get("why") or entry.get("reason") or "").split())[:500],
            "steps": _steps(entry.get("steps")),
            "risk": fix["risk"] if fix else (risk if risk in RISKS else "low"),
            "tool_id": fix["tool_id"] if fix else None,
            "args": fix["args"] if fix else {},
            "source": "ai",
            "status": "suggested",
        })
        if len(solutions) >= MAX_SOLUTIONS:
            break
    return solutions


def fix_title(tool_id, args):
    """A card title that says what this fix does here ("Close chrome.exe (PID 812)"), not the tool's description."""
    args = args or {}
    if tool_id == "kill_process" and args.get("expected_name"):
        return f"Close {args['expected_name']}" + (f" (PID {args['pid']})" if args.get("pid") else "")
    if tool_id == "restart_service" and args.get("name"):
        return f"Restart the {args['name']} service"
    if tool_id == "disable_startup_item" and args.get("name"):
        return f"Stop {args['name']} from starting at sign-in"
    tool = get_tool(tool_id)
    return first_sentence(tool.description) if tool else tool_id


def _solution_from_fix(fix):
    return {
        "title": fix_title(fix["tool_id"], fix.get("args"))[:160],
        "why": fix.get("why") or "",
        "steps": [],
        "risk": fix["risk"],
        "tool_id": fix["tool_id"],
        "args": fix.get("args") or {},
        "source": "learned" if fix.get("learned") else "rule" if fix.get("rule") else "ai",
        "status": "suggested",
    }


def _targets(solution, finding):
    """Does this solution act on this finding (its fix, or it talks about it)?"""
    if solution.get("tool_id") and solution["tool_id"] in {fix["tool_id"] for fix in finding.get("fixes") or []}:
        return True
    text = " ".join([str(solution.get("title") or ""), str(solution.get("why") or "")])
    if findings.cited_finding(text, [finding]) is not None:
        return True
    # "Close Chrome tabs" acts on memory pressure that Chrome causes.
    names = {str(app.get("name") or "").lower().removesuffix(".exe") for app in finding.get("apps") or []} - {""}
    return any(re.search(rf"{re.escape(name)}", text, re.I) for name in names)


def _as_solution(tip, source):
    return {**{key: tip[key] for key in ("title", "why", "risk")}, "steps": list(tip["steps"]), "tool_id": None, "args": {}, "source": source, "status": "suggested"}


def complete_solutions(report, playbook, found=(), os_type=None, evidence=()):
    """Order the solutions so the ones that fix the cause come first and at most one is for a separate problem,
    then top them up to 3-4: runnable fixes for the complaint's findings, the cause's own tips (e.g. which apps to
    close), then safe manual tips for this kind of problem and this OS. Never more than MAX_SOLUTIONS."""
    related, other = findings.split_by_relevance(found, playbook)
    cause = next((item for item in found if item["key"] == report.get("cause_finding")), None)
    solutions = []
    for item in report.get("solutions") or []:
        scope = "cause" if cause and _targets(item, cause) else "separate" if any(_targets(item, finding) for finding in other) else None
        solutions.append({**item, "scope": scope})
    if report.get("regrounded"):
        # The model's other suggestions were written for the cause it wrongly blamed.
        solutions = [item for item in solutions if item["scope"] is not None]
    solutions.sort(key=lambda item: {"cause": 0, None: 1, "separate": 2}[item["scope"]])
    separate = [item for item in solutions if item["scope"] == "separate"]
    solutions = [item for item in solutions if item["scope"] != "separate"] + separate[:1]

    keys = {_fix_key(item) for item in solutions if item.get("tool_id")}
    related_tools = {fix["tool_id"] for finding in related for fix in finding["fixes"]}
    fixes = sorted(report.get("proposed_fixes") or [], key=lambda fix: fix["tool_id"] not in related_tools)
    for fix in fixes:
        if len(solutions) >= MAX_SOLUTIONS:
            break
        is_separate = fix["tool_id"] not in related_tools and not fix.get("learned") and bool(other)
        if _fix_key(fix) in keys or (is_separate and any(item.get("scope") == "separate" for item in solutions)):
            continue
        keys.add(_fix_key(fix))
        solutions.append({**_solution_from_fix(fix), "scope": "separate" if is_separate else "cause" if cause and fix["tool_id"] in {f["tool_id"] for f in cause["fixes"]} else None})
    titles = {item["title"].lower() for item in solutions}
    finding_tips = [(tip, "rule") for finding in ([cause] if cause else []) + [item for item in related if item is not cause] for tip in finding.get("tips") or []]
    for tip, source in finding_tips + [(tip, "playbook") for tip in playbook_tips(playbook, os_type, evidence)]:
        if len(solutions) >= (MAX_SOLUTIONS if source == "rule" else MIN_SOLUTIONS):
            continue
        if tip["title"].lower() not in titles:
            titles.add(tip["title"].lower())
            solutions.append({**_as_solution(tip, source), "scope": "cause" if source == "rule" and cause else "next_step" if report.get("cause_id") == "none" else None})
    # A separate problem always last; otherwise the order stands (the model's own first, then the top-ups).
    solutions.sort(key=lambda item: item["scope"] == "separate")
    report["solutions"] = solutions[:MAX_SOLUTIONS]
    return report


def link_solutions(report):
    """Point each runnable solution at its entry in proposed_fixes (the list the approval endpoint uses).
    A solution whose fix was filtered out becomes manual."""
    index = {_fix_key(fix): position for position, fix in enumerate(report.get("proposed_fixes") or [])}
    for solution in report.get("solutions") or []:
        position = index.get(_fix_key(solution)) if solution.get("tool_id") else None
        solution["fix_index"] = position
        if position is None:
            solution["tool_id"], solution["args"] = None, {}
    return report


def normalize_report(raw, issue, os_type, fallback_note=None, evidence=None):
    """evidence: when given, fixes may name only processes and startup items the checks saw."""
    known = known_items(evidence) if evidence is not None else None
    severity = str(raw.get("severity", "medium")).lower()
    confidence = str(raw.get("confidence", "medium")).lower()
    solutions = normalize_solutions(raw.get("solutions"), os_type, known)
    solution_fixes = [{"tool_id": item["tool_id"], "args": item["args"], "why": item["why"] or item["title"]} for item in solutions if item["tool_id"]]
    manual_steps, fixes = promote_manual_steps(
        [str(item)[:400] for item in (raw.get("manual_steps") or [])][:10] + [item["title"] for item in solutions if not item["tool_id"]],
        validate_fixes(list(raw.get("proposed_fixes") or []) + solution_fixes, os_type, known),
        os_type,
    )
    if not solutions:
        # Rule-based or older reports: their manual steps become solutions too.
        solutions = [{"title": step[:160], "why": "", "steps": [], "risk": "low", "tool_id": None, "args": {}, "source": "rule", "status": "suggested"} for step in manual_steps][:MAX_SOLUTIONS]
    return {
        "solutions": solutions,
        "issue_summary": str(raw.get("issue_summary") or issue)[:500],
        "root_cause": str(raw.get("root_cause") or fallback_note or "The agent could not determine a root cause from the evidence.")[:1500],
        "confidence": confidence if confidence in CONFIDENCES else "medium",
        "severity": severity if severity in SEVERITIES else "medium",
        "evidence": [str(item)[:300] for item in (raw.get("evidence") or [])][:10],
        "proposed_fixes": fixes,
        "manual_steps": manual_steps,
    }


FINDING_LABEL = re.compile(r"^\s*F\d+\s*(?:\[[a-z]+\])?\s*[:\-]?\s*")
FINDING_REFERENCE = re.compile(r"\s*\((?:see\s+)?F\d+(?:\s*(?:,|and)\s*F\d+)*\)", re.I)


def without_finding_ids(text):
    """The F1, F2... labels are for the model's answer only; a person reading the diagnosis does not know them."""
    return FINDING_REFERENCE.sub("", FINDING_LABEL.sub("", str(text or ""))).strip()


def hide_finding_ids(report):
    report["root_cause"] = without_finding_ids(report.get("root_cause"))
    for solution in report.get("solutions") or []:
        solution["title"] = without_finding_ids(solution.get("title"))
        solution["why"] = without_finding_ids(solution.get("why"))
        solution["steps"] = [without_finding_ids(step) for step in solution.get("steps") or []]
    return report


def tail_at_sentence(text, limit=3000):
    """The end of a long reasoning text, starting at a sentence (not mid-word), marked when cut."""
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    tail = text[-limit:]
    start = re.search(r"[.!?\n]\s+", tail)
    return "... " + (tail[start.end():] if start and start.end() < limit // 2 else tail)


def _handoff_reasoning(thinking):
    """Start (the plan) and end (the conclusion) of a reasoning that ran out of budget."""
    if len(thinking) <= REASONING_HANDOFF_HEAD_CHARS + REASONING_HANDOFF_TAIL_CHARS:
        return thinking
    return thinking[:REASONING_HANDOFF_HEAD_CHARS] + "\n...\n" + tail_at_sentence(thinking, REASONING_HANDOFF_TAIL_CHARS)


def _past_cases_block(similar):
    if not similar:
        return ""
    lines = []
    for case in similar:
        fixes = [fix["tool_id"] for fix in case.get("fixes", []) if fix.get("status") == "applied"]
        lines.append(f"- \"{case['issue'][:120]}\" ({case.get('os_type')}): cause was {case.get('effective_root_cause', '')[:200]}" + (f"; fixed by {', '.join(fixes)}" if fixes else ""))
    return "\n\nSimilar tickets resolved before (use as hints, but trust today's evidence first):\n" + "\n".join(lines)


def add_learned_fixes(report, learned, os_type):
    """Propose fixes that resolved most similar past tickets if the model did not."""
    present = {fix["tool_id"] for fix in report["proposed_fixes"]}
    for item in learned:
        tool = get_tool(item["tool_id"])
        if not _offerable_without_args(tool, os_type) or item["tool_id"] in present:
            continue
        report["proposed_fixes"].append({
            "tool_id": tool.id, "args": {}, "risk": tool.risk, "description": tool.description,
            "why": f"Learned: this fix resolved {item['resolved']} of {item['attempts']} similar past tickets.",
            "status": "proposed", "result": None, "learned": True,
        })
    return report


async def learn_from(session_id):
    """Record the session as a learned case and rebuild the aiops-brain model when due. A diagnosis of the AIops
    container (Docker) teaches nothing: it describes the container, not a user's computer."""
    try:
        session = session_store.get_session(session_id, include_steps=False)
        if session and is_container_target(session.get("device_id")):
            return
        if session and session.get("report"):
            await asyncio.to_thread(learning_store.record_session, session)
            info = await run_ai(model_builder.maybe_rebuild)
            if info:
                logger.info("Rebuilt %s v%s from %s trusted cases", info["model"], info["version"], info["trusted_cases"])
                refresh = getattr(get_provider(), "refresh", None)
                if refresh:
                    refresh()
    except Exception:
        logger.exception("Learning from session %s failed", session_id)


def _evidence_block(evidence, limit):
    return "\n".join(f"- {tool_id} {json.dumps(args) if args else ''}: {_compact(result, limit)}" for tool_id, args, result in evidence)


DIGEST_LINE_CHARS = 200


def device_profile(evidence):
    """One line about the machine (no hostname: it adds nothing and would leave the server with a cloud AI)."""
    overview = next((result.get("data") for tool_id, _args, result in evidence if tool_id == "system_overview" and result.get("ok") and isinstance(result.get("data"), dict)), {})
    hardware = next((result.get("data") for tool_id, _args, result in evidence if tool_id == "hardware_health" and result.get("ok") and isinstance(result.get("data"), dict)), {})
    cpu = (hardware.get("cpu") or {}).get("name")
    parts = [overview.get("os"), (f"{cpu}" if cpu else "") + (f" ({overview['cpu_cores_logical']} threads)" if overview.get("cpu_cores_logical") else ""),
             f"RAM {overview['ram_total']}" if overview.get("ram_total") else "",
             ", ".join(f"{disk.get('mount')} {disk.get('free')} free of {disk.get('total')}" for disk in overview.get("disks") or []),
             f"up {overview['uptime']}" if overview.get("uptime") else ""]
    battery = overview.get("battery") or {}
    if battery:
        parts.append(f"battery {battery.get('percent')}%" + (" plugged in" if battery.get("plugged_in") else " on battery"))
    parts = [part.strip() for part in parts if part and part.strip()]
    return "Device: " + "; ".join(parts) if parts else ""


def _digest_line(tool_id, args, result):
    data, summary = result.get("data"), (result.get("summary") or "").strip()
    if not result.get("ok"):
        return f"- {tool_id}: (failed) {summary}"
    if tool_id == "top_processes" and isinstance(data, list):
        field = "memory_percent" if (args or {}).get("sort_by") == "memory" else "cpu_percent"
        return f"- busiest programs by {field.split('_')[0]} (all their processes added up): " + findings.describe_apps(findings.group_processes(data, field), 5)
    if tool_id == "startup_programs" and isinstance(data, list):
        names = [str(row.get("name")) for row in data if isinstance(row, dict) and row.get("name")]
        return f"- startup programs ({len(names)}): " + ", ".join(names[:10])
    if tool_id == "check_internet" and isinstance(data, dict):
        stages = ", ".join(f"{label} {(data.get(stage) or {}).get('ms')} ms" for stage, label in (("dns_resolution", "DNS"), ("tcp_to_internet", "TCP"), ("http", "HTTP"))
                           if (data.get(stage) or {}).get("ms") is not None)
        loss = (data.get("gateway_ping") or {}).get("packet_loss_percent")
        return f"- {tool_id}: {summary}" + (f" ({stages}" + (f", router packet loss {loss}%" if loss else "") + ")" if stages else "")
    return f"- {tool_id}{' ' + json.dumps(args) if args else ''}: {summary}"


def evidence_digest(evidence):
    """What the fast-mode prompt says about the checks: one short line each, with the names and numbers that
    matter (which apps use the memory, which programs start at sign-in) instead of raw data. Prompt length is
    about half of the AI time on a CPU."""
    lines = [device_profile(evidence)] + [_digest_line(tool_id, args, result)[:DIGEST_LINE_CHARS] for tool_id, args, result in evidence]
    return "\n".join(line for line in lines if line)


def _summary_block(evidence):
    return evidence_digest(evidence)


def ai_call_timeout(deep=False):
    """Deadline for one AI call during a diagnosis; past it the user gets the rule-based diagnosis instead
    of waiting for a model that is swapping. Deep-thinking calls get a longer deadline (they reason first)."""
    name, default = ("AGENT_AI_TIMEOUT_SECONDS_DEEP", "900") if deep else ("AGENT_AI_TIMEOUT_SECONDS", "300")
    try:
        return max(30, int(os.getenv(name, default)))
    except ValueError:
        return int(default)


async def _chat(messages, **kwargs):
    kwargs.setdefault("timeout", ai_call_timeout(deep=bool(kwargs.get("think"))))
    # Queued diagnoses wait for the gate as coroutines; only the running call holds a thread (backend/workers.py).
    async with ai_gate():
        try:
            return await run_ai(get_provider().chat, messages, **kwargs)
        except LLMDisconnectedError as error:
            # Usually the model runner restarted (often under memory pressure): one more try after a pause.
            logger.warning("AI engine dropped the connection (%s); retrying once in %ss", error, DISCONNECT_RETRY_SECONDS)
            await asyncio.sleep(DISCONNECT_RETRY_SECONDS)
            return await run_ai(get_provider().chat, messages, **kwargs)


def _thinking_publisher(session_id):
    """on_delta callback for a streamed AI call: forwards the model's reasoning to the session view about
    every 1.5 s. It runs in the provider's worker thread, so events are handed to the event loop."""
    loop = asyncio.get_running_loop()
    state = {"thinking": "", "content": "", "last": 0.0}

    def on_delta(kind, piece):
        state[kind] += piece
        now = time.monotonic()
        if now - state["last"] >= 1.5:
            state["last"] = now
            event = {"type": "thinking", "thinking": state["thinking"][-1500:], "chars": len(state["thinking"]), "writing": bool(state["content"])}
            loop.call_soon_threadsafe(events.publish, session_id, event)

    return on_delta


def _warm_up():
    warm = getattr(get_provider(), "warm_up", None)
    try:
        if warm:
            warm()
    except Exception:
        logger.debug("LLM warm-up failed", exc_info=True)


async def _run_parallel(session_id, target, calls, kind="tool"):
    """Run [(tool_id, args)] concurrently; returns [(tool_id, args, result)] in input order."""
    results = await asyncio.gather(*(_run_step(session_id, target, tool_id, args, kind=kind) for tool_id, args in calls))
    return [(tool_id, args, result) for (tool_id, args), result in zip(calls, results)]


async def collect_baseline(session_id, target, playbook):
    evidence = []
    for phase in baseline_phases(playbook, target.os_type):
        evidence += await _run_parallel(session_id, target, phase)
    return evidence


def _record_findings(session_id, found):
    summary = findings.summarize(found)
    step = session_store.add_step(session_id, "findings", result={"ok": True, "summary": summary, "data": found}, text=summary)
    events.publish(session_id, {"type": "step", "step": step})


def ground_fixes(fixes, report, found, playbook):
    """A check-up has no complaint to anchor fixes to, and a clean low-confidence diagnosis has
    nothing to fix: in both cases only fixes tied to a finding (or learned) survive."""
    if (playbook or {}).get("id") != "full_checkup" and (found or report["confidence"] != "low"):
        return fixes
    linked = {fix["tool_id"] for item in found for fix in item["fixes"]}
    return [fix for fix in fixes if fix["tool_id"] in linked or fix.get("learned")]


def add_rule_fixes(report, found, os_type):
    """Propose fixes that the instant findings point to, if the model did not already."""
    present = {fix["tool_id"] for fix in report["proposed_fixes"]}
    for fix in validate_fixes([fix for item in found if item["severity"] != "low" for fix in item["fixes"]], os_type):
        if fix["tool_id"] not in present:
            present.add(fix["tool_id"])
            report["proposed_fixes"].append({**fix, "rule": True})
    return report


def _rule_based_report(found, issue, os_type, note=None, playbook=None):
    raw = findings.rule_report(found, issue, note, playbook)
    report = normalize_report({**raw, "proposed_fixes": raw.pop("raw_fixes")}, issue, os_type)
    for fix in report["proposed_fixes"]:
        fix["rule"] = True
    report["reasoning"] = raw["reasoning"]
    report["reasoning_source"] = "rules"
    return report


def fallback_note(error):
    """Why the AI gave no answer, in words that match what happened."""
    if isinstance(error, LLMTimeoutError):
        lead = "AI did not answer in time"
    elif isinstance(error, LLMDisconnectedError):
        lead = "the AI engine dropped the connection (tried twice)"
    else:
        lead = "AI unavailable"
    return f"{lead}, instant rule-based diagnosis: {error}"


def _ai_fallback(found, issue, target, playbook, reason, ai=None):
    report = _rule_based_report(found, issue, target.os_type, reason, playbook)
    report["ai"] = {**(ai or {"provider": getattr(get_provider(), "name", None), "model": None}), "fallback": True, "fallback_reason": reason}
    return report


async def run_diagnosis(session_id, mode=None, preset_evidence=None):
    """preset_evidence: [(tool_id, args, result)] that already ran (e.g. the Performance tab's full test);
    the diagnosis then starts from those results instead of running the baseline checks again."""
    session = session_store.get_session(session_id, include_steps=False)
    target = resolve_target(session["device_id"])
    if target is None:
        session_store.update_session(session_id, status="failed", error="Device no longer exists")
        events.publish(session_id, {"type": "error", "message": "Device no longer exists"})
        return
    async with _lock(session_id):
        try:
            await _diagnose(session, target, normalize_mode(mode), preset_evidence)
        except LLMUnavailableError as error:
            logger.warning("Troubleshoot %s: LLM unavailable: %s", session_id, error)
            session_store.update_session(session_id, status="failed", error=str(error))
            events.publish(session_id, {"type": "error", "message": str(error)})
        except Exception as error:
            logger.exception("Troubleshoot session %s failed", session_id)
            session_store.update_session(session_id, status="failed", error=f"{type(error).__name__}: {error}")
            events.publish(session_id, {"type": "error", "message": "The troubleshooting agent hit an internal error. See server logs."})
    # Suggest-only: nothing is applied here. A person approves solutions in the dashboard.
    await learn_from(session_id)


def _record_preset(session_id, preset_evidence):
    """Show checks that ran before the session as its steps, so the session view and the AI see them."""
    evidence = []
    for tool_id, args, result in preset_evidence:
        step = session_store.add_step(session_id, "tool", tool_id, args, result)
        events.publish(session_id, {"type": "step", "step": step})
        evidence.append((tool_id, args, result))
    return evidence


async def _diagnose(session, target, mode, preset_evidence=None):
    session_id, issue = session["session_id"], session["issue"]
    started = time.perf_counter()
    note = None
    if mode != "instant":
        status = await asyncio.to_thread(get_provider().status)
        if not status.get("available"):
            # Never leave the user without an answer: fall back to the instant rule-based diagnosis.
            note = f"AI unavailable, instant rule-based diagnosis: {status.get('message', 'AI provider unavailable')}"
            _think(session_id, note)
            mode = "instant"
    # Load the model while the checks run, so the first AI call does not pay the load time. While another
    # diagnosis is generating, the model is already loaded. On the server AIops runs on, loading it now would
    # skew the very CPU and memory numbers being measured, so it loads after the checks there.
    server = await asyncio.to_thread(server_device)
    measuring_the_ai_host = bool(server) and server["device_id"] == target.device_id
    warm_up = None
    if mode != "instant" and not ai_gate().locked() and not measuring_the_ai_host:
        warm_up = asyncio.create_task(run_ai(_warm_up))

    playbook = get_playbook(session.get("playbook_id")) or match_playbook(issue)
    if preset_evidence:
        _think(session_id, f"Starting from the {len(preset_evidence)} checks that just ran on {target.label} ({mode} mode).")
        evidence = _record_preset(session_id, preset_evidence)
    else:
        _publish_status(session_id, "running", f"Running checks on {target.label} in parallel")
        if playbook:
            _think(session_id, f"Using the '{playbook['title']}' playbook for the baseline checks ({mode} mode).")
        evidence = await collect_baseline(session_id, target, playbook)
    found = findings.analyze(evidence, target.os_type)
    _record_findings(session_id, found)
    evidence_seconds = time.perf_counter() - started

    learned_fixes = await asyncio.to_thread(learning_store.learned_fixes_for, issue, target.os_type)
    if mode == "instant":
        report, similar = _rule_based_report(found, issue, target.os_type, note, playbook), []
    else:
        report, similar, found = await _ai_report(session_id, target, issue, playbook, evidence, found, mode, warm_up)
    report = ground_root_cause(report, playbook, found, evidence)
    report = add_learned_fixes(report, learned_fixes, target.os_type)
    report = add_rule_fixes(report, found, target.os_type)
    report["proposed_fixes"] = ground_fixes(filter_relevant_fixes(report["proposed_fixes"], playbook), report, found, playbook)
    report["similar_cases"] = [{"session_id": case["session_id"], "issue": case["issue"][:160], "root_cause": (case.get("effective_root_cause") or "")[:240], "outcome": case["outcome"]} for case in similar]
    report["quick_findings"] = found
    report["mode"] = mode
    report["playbook_id"] = (playbook or {}).get("id")
    link_solutions(complete_solutions(report, playbook, found, target.os_type, evidence))
    total = time.perf_counter() - started
    report["timing"] = {"evidence_seconds": round(evidence_seconds, 1), "ai_seconds": round(total - evidence_seconds, 1), "total_seconds": round(total, 1)}
    session_store.update_session(session_id, status="diagnosed", report=report)
    await asyncio.to_thread(_record_diagnosis, session, target, report, found)
    events.publish(session_id, {"type": "report", "report": report})
    _publish_status(session_id, "diagnosed", f"Diagnosis ready in {total:.0f}s")


RECENT_ALERT_SECONDS = 6 * 3600


def _recent_alert_lines(alerts, limit=3):
    now = time.time()
    lines = []
    for alert in alerts:
        try:
            age = now - datetime.fromisoformat(alert["timestamp"]).timestamp()
        except (KeyError, TypeError, ValueError):
            continue
        if age <= RECENT_ALERT_SECONDS:
            lines.append(f"- [{alert['severity']}] {alert['category']}: {alert['description']}")
    return lines[:limit]


async def _ai_report(session_id, target, issue, playbook, evidence, found, mode, warm_up):
    alerts = get_alerts(10, "local-server" if target.is_local else target.device_id)
    alert_lines = "\n".join(f"- [{alert['severity']}] {alert['category']}: {alert['description']}" for alert in alerts) or "- none"
    similar = await asyncio.to_thread(learning_store.find_similar, issue, target.os_type, 3)
    if similar:
        _think(session_id, f"Memory: found {len(similar)} similar ticket(s) solved before; using them as hints.")
    past_cases = _past_cases_block(similar)
    numbered = findings.numbered(found, playbook)
    found_block = findings.findings_block(found, playbook)
    provider_name = getattr(get_provider(), "name", None)
    if warm_up:
        await warm_up

    notes = ""
    rounds = investigation_rounds(mode, playbook)
    if rounds:
        checked = len(evidence)
        try:
            notes = await _investigate(session_id, target, issue, evidence, found_block, alert_lines, past_cases, rounds)
        except LLMUnavailableError as error:
            # Another call would most likely fail the same way, so answer from the rules.
            logger.warning("Troubleshoot %s: investigation failed, using rules: %s", session_id, error)
            return _ai_fallback(found, issue, target, playbook, fallback_note(error)), similar, found
        if len(evidence) > checked:
            # The extra checks can find the cause (e.g. a failing disk): it becomes a finding like any other.
            found = findings.analyze(evidence, target.os_type)
            _record_findings(session_id, found)
            numbered, found_block = findings.numbered(found, playbook), findings.findings_block(found, playbook)

    only = RELEVANT_FIXES.get((playbook or {}).get("id")) if mode == "fast" else None
    tools = catalog_tools(target.os_type, only)
    evidence_text = evidence_digest(evidence) if mode == "fast" else device_profile(evidence) + "\n" + _evidence_block(evidence, REPORT_EVIDENCE_CHARS)
    recent = _recent_alert_lines(alerts)
    causes = [f"F{index}" for index, item in enumerate(numbered, 1) if findings.is_related(item, playbook)]
    schema = report_schema(causes, [tool.id for tool in tools], investigated=bool(rounds))
    report_messages = [
        {"role": "system", "content": REPORT_PROMPT},
        {"role": "user", "content": f"Computer: {target.os_type}\nUser's problem: {issue}\n\nAutomatic findings:\n{found_block}\n\nEvidence:\n{evidence_text}"
                                    + ("\n\nRecent monitoring alerts:\n" + "\n".join(recent) if recent else "")
                                    + (f"\n\nInvestigator notes: {notes}" if notes else "") + past_cases
                                    + f"\n\nFix tools you may name (id, risk, args: what it does):\n{fix_catalog(target.os_type, only) or '- none'}"},
    ]
    thinking = diagnosis_thinking(mode)
    _publish_status(session_id, "running", "AI is thinking deeply about the diagnosis" if thinking else "AI is writing the diagnosis")
    try:
        reply = await _chat(report_messages, json_mode=schema, max_tokens=REPORT_THINKING_MAX_TOKENS if thinking else REPORT_MAX_TOKENS,
                            think=thinking, on_delta=_thinking_publisher(session_id))
    except LLMUnavailableError as error:
        # A slow or crashed model must not throw away the evidence already collected.
        logger.warning("Troubleshoot %s: report call failed, using rules: %s", session_id, error)
        return _ai_fallback(found, issue, target, playbook, fallback_note(error)), similar, found
    raw, truncated = parse_reply(reply["content"])
    reasoning = reply.get("thinking") or ""
    ai = {"provider": provider_name, "model": reply.get("model"), "thinking": bool(reply.get("thought")), "thinking_requested": thinking,
          "thinking_chars": len(reasoning), "handoff": False, "schema": bool(reply.get("schema")), "truncated": truncated,
          "usage": reply.get("usage"), "prompt_hash": decision_log.prompt_hash(report_messages)}
    if not raw.get("root_cause") and reasoning:
        # Thinking used its budget before the answer: hand the reasoning to a quick call that only writes it up.
        _publish_status(session_id, "running", "AI is writing the diagnosis from its reasoning")
        handoff = report_messages + [{"role": "user", "content": "Your reasoning so far:\n" + _handoff_reasoning(reasoning)
                                       + "\n\nNow write ONLY the final JSON answer in the schema above, with 3 or 4 solutions."}]
        ai["handoff"] = True
        try:
            written = await _chat(handoff, json_mode=schema, max_tokens=REPORT_MAX_TOKENS + 150, think=False)
            raw, ai["truncated"] = parse_reply(written["content"])
            ai["handoff_usage"] = written.get("usage")
        except LLMUnavailableError as error:
            logger.warning("Troubleshoot %s: write-up after thinking failed: %s", session_id, error)
    if not raw.get("root_cause"):
        report = _ai_fallback(found, issue, target, playbook, "the AI reply had no usable diagnosis; showing the instant rule-based diagnosis", ai)
        report["reasoning"] = tail_at_sentence(reasoning) or report["reasoning"]
        return report, similar, found
    raw.setdefault("evidence", evidence_facts(found, evidence))
    report = normalize_report(raw, issue, target.os_type, fallback_note=notes, evidence=evidence)
    hide_finding_ids(report)
    cause_id = str(raw.get("cause") or "").strip().upper()
    report["cause_id"] = cause_id.lower() if cause_id in ("NONE", "INVESTIGATION") else cause_id or None
    report["ai_cause"], report["ai_confidence"] = report["cause_id"], report["confidence"]
    if re.fullmatch(r"F\d+", cause_id) and int(cause_id[1:]) <= len(numbered):
        report["cause_finding"] = numbered[int(cause_id[1:]) - 1]["key"]
    report["ai"] = ai
    report["reasoning"] = tail_at_sentence(reasoning)
    report["reasoning_source"] = "ai"
    return report, similar, found


NETWORK_PLAYBOOKS = {"no_internet", "wifi_drops"}


def _ground_network(report, playbook, found, evidence):
    """Small models blame whatever finding they see for a network complaint (e.g. "a full disk breaks DNS"), even
    when told not to. When the traffic tests for it passed and found nothing network-related, say that plainly and
    list other findings as separate problems. Returns True when it did."""
    if (playbook or {}).get("id") not in NETWORK_PLAYBOOKS or any(item["key"].startswith(("net_", "wifi_")) for item in found):
        return False
    summaries = {tool_id: str(result.get("summary") or "") for tool_id, _, result in evidence if result.get("ok")}
    # Judge by the real traffic tests, not the summary line: older agents can write a wrong summary
    # (e.g. "DHCP failed" because of a virtual adapter) while DNS, TCP and HTTP all work.
    stages = next((result.get("data") or {} for tool_id, _, result in evidence if tool_id == "check_internet" and result.get("ok")), {})
    online = all((stages.get(stage) or {}).get("ok") for stage in ("dns_resolution", "tcp_to_internet", "http")) if stages else False
    if not (online or summaries.get("check_internet", "").startswith("Internet connectivity works")):
        return False
    if online and not summaries["check_internet"].startswith("Internet connectivity works"):
        summaries["check_internet"] = "DNS, TCP and HTTP tests to the internet all succeeded"
    wifi = f"; {summaries['wifi_status'].rstrip('.')}" if summaries.get("wifi_status") else ""
    others = [item["title"] for item in found]
    report["ai_root_cause"] = report.get("root_cause")
    report["root_cause_source"] = "rules: the network checks for this complaint passed"
    report["complaint_reproduced"] = False
    report["cause_finding"] = None  # whatever the model blamed, nothing found explains a network complaint
    report["root_cause"] = (
        f"The network checks passed ({summaries['check_internet'].rstrip('.')}{wifi}). The problem did not show up during the check, "
        "so it may be intermittent or limited to certain websites."
        + (f" Separate problems found: {', '.join(others)}." if others else "")
    )
    report["confidence"] = "low"
    report["confidence_note"] = "the checks did not show the problem"
    return True


CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _cap_confidence(report, cap, why):
    if CONFIDENCE_RANK.get(report.get("confidence"), 1) > CONFIDENCE_RANK[cap]:
        report["confidence"] = cap
        report["confidence_note"] = why


def ground_root_cause(report, playbook, found, evidence):
    """Check the diagnosis against the findings. A finding that cannot cause the complaint is never the cause:
    the one that can takes its place (the model's text is kept as ai_root_cause), or, when nothing found can
    explain the complaint, the report says the checks did not show it. Confidence follows the evidence:
    "high" needs a cause backed by a severe finding that can explain the complaint."""
    related, other = findings.split_by_relevance(found, playbook)
    report["related_findings"] = [item["key"] for item in related]
    report["other_findings"] = [item["key"] for item in other]
    if _ground_network(report, playbook, found, evidence):
        return report
    cited = next((item for item in found if item["key"] == report.get("cause_finding")), None)
    if cited is None and report.get("cause_id") not in ("none", "investigation"):
        cited = findings.cited_finding(report.get("root_cause"), found)
    severe = [item for item in related if item.get("severity") in ("high", "critical")]
    if is_complaint(playbook) and report.get("cause_id") == "none" and severe:
        # "Nothing explains it" while a severe finding that can explain it is right there.
        top = severe[0]
        report["ai_root_cause"] = report.get("root_cause")
        report["root_cause"] = f"{top['title']}. {top.get('detail') or ''}".strip()
        report["root_cause_source"] = f"rules: {top['title']} can explain the complaint"
        report["cause_id"], report["regrounded"], cited = None, True, top
    if is_complaint(playbook) and cited is not None and cited in other:
        report["ai_root_cause"] = report.get("root_cause")
        if related:
            top = related[0]
            report["root_cause"] = (f"{top['title']}. {top.get('detail') or ''} Separate problem: {cited['title']} "
                                    "(it cannot cause this kind of problem, although the first answer blamed it).")
            report["root_cause_source"] = f"rules: {top['title']} can explain the complaint; {cited['title']} cannot"
            report["regrounded"] = True
            cited = top
        else:
            report["root_cause"] = ("The checks for this complaint did not show the problem, so it may come and go. "
                                    "Separate problems found: " + "; ".join(item["title"] for item in other[:4]) + ".")
            report["root_cause_source"] = "rules: nothing found can explain the complaint"
            report["complaint_reproduced"] = False
            cited = None
    if is_complaint(playbook) and report.get("cause_id") == "none":
        report["complaint_reproduced"] = False
    report["cause_finding"] = cited["key"] if cited else None
    if report.get("complaint_reproduced") is False:
        _cap_confidence(report, "low", "the checks did not show the problem")
    elif report.get("regrounded"):
        _cap_confidence(report, "medium", "the AI's own pick of the cause was overruled by the findings; the cause comes from the rules")
    elif report.get("cause_id") == "investigation":
        _cap_confidence(report, "medium", "the cause comes from the investigation, not from a rule finding")
    elif cited is None:
        _cap_confidence(report, "medium", "no finding from the checks backs the cause")
    elif cited.get("severity", "medium") in ("low", "medium"):
        _cap_confidence(report, "medium", f"the finding behind the cause is only {cited.get('severity', 'medium')}")
    return report


def _record_diagnosis(session, target, report, found):
    ai = report.get("ai") or {}
    kind = "performance_analysis" if session.get("playbook_id") == "performance" else "diagnosis"
    decision_log.record(kind, session["session_id"], {
        "device": target.label, "device_id": target.device_id, "os_type": target.os_type, "issue": session["issue"],
        "mode": report.get("mode"), "playbook_id": report.get("playbook_id"), "provider": ai.get("provider"), "model": ai.get("model"),
        "thinking": ai.get("thinking", False), "prompt_hash": ai.get("prompt_hash"),
        "ai": {key: ai.get(key) for key in ("thinking_requested", "thinking_chars", "handoff", "schema", "truncated", "fallback", "fallback_reason", "usage", "handoff_usage") if key in ai},
        "root_cause": report.get("root_cause"), "root_cause_source": report.get("root_cause_source") or ("ai" if ai.get("model") and not ai.get("fallback") else "rules"),
        "ai_root_cause": report.get("ai_root_cause"), "confidence": report.get("confidence"), "confidence_note": report.get("confidence_note"),
        "severity": report.get("severity"), "cause_finding": report.get("cause_finding"), "complaint_reproduced": report.get("complaint_reproduced"),
        "ai_cause": report.get("ai_cause"), "ai_confidence": report.get("ai_confidence"),
        "related_findings": report.get("related_findings"), "other_findings": report.get("other_findings"),
        "solutions": [{key: item.get(key) for key in ("title", "why", "steps", "risk", "tool_id", "source", "scope")} for item in report.get("solutions") or []],
        "findings": [item["title"] for item in found], "evidence": report.get("evidence"),
        "reasoning_summary": tail_at_sentence(report.get("reasoning"), 1500), "reasoning_source": report.get("reasoning_source"), "timing": report.get("timing"),
        "approved_by": None, "note": "Suggestions only: nothing was changed on the device.",
    })


def evidence_facts(found, evidence, limit=8):
    """Evidence bullets straight from the findings and tool summaries (no tokens spent generating them)."""
    facts = [f"{item['title']}: {item['detail']}" for item in found]
    facts += [f"{tool_id.replace('_', ' ')}: {result.get('summary')}" for tool_id, _, result in evidence if result.get("summary")]
    return facts[:limit]


async def _investigate(session_id, target, issue, evidence, found_block, alert_lines, past_cases, rounds):
    """Let the LLM call more read-only tools (in parallel); returns its closing notes."""
    messages = [
        {"role": "system", "content": INVESTIGATE_PROMPT.format(os_type=target.os_type)},
        {"role": "user", "content": f"User's problem: {issue}\n\nAutomatic findings:\n{found_block}\n\nBaseline evidence:\n{_evidence_block(evidence, TOOL_RESULT_CHARS)}\n\nRecent monitoring alerts:\n{alert_lines}{past_cases}"},
    ]
    schemas = tool_schemas(target.os_type, max_risk="read")
    allowed = {schema["function"]["name"] for schema in schemas}
    executed = {(tool_id, json.dumps(args, sort_keys=True)) for tool_id, args, _ in evidence}
    _publish_status(session_id, "running", "AI is investigating")
    for _ in range(rounds):
        # Picking the next check is simple; deep thinking is kept for the final diagnosis.
        reply = await _chat(messages, tools=schemas, max_tokens=INVESTIGATE_MAX_TOKENS, think=False)
        calls = reply["tool_calls"] or parse_inline_tool_calls(reply["content"], allowed)
        if not calls:
            _think(session_id, reply["content"])
            return reply["content"]
        if reply["content"]:
            _think(session_id, reply["content"])
        calls = calls[:MAX_CALLS_PER_TURN]
        messages.append({"role": "assistant", "content": reply["content"], "tool_calls": calls})
        contents, to_run = {}, []
        for call in calls:
            key = (call["name"], json.dumps(call.get("arguments") or {}, sort_keys=True))
            if call["name"] not in allowed:
                contents[call["id"]] = json.dumps({"ok": False, "summary": f"{call['name']} is not an available diagnostic tool"})
            elif key in executed:
                contents[call["id"]] = json.dumps({"ok": True, "summary": "Already collected above; use that evidence."})
            else:
                executed.add(key)
                to_run.append(call)
        ran = await _run_parallel(session_id, target, [(call["name"], call.get("arguments") or {}) for call in to_run])
        for call, item in zip(to_run, ran):
            evidence.append(item)
            contents[call["id"]] = _compact(item[2])
        for call in calls:
            messages.append({"role": "tool", "tool_call_id": call["id"], "name": call["name"], "content": contents[call["id"]]})
    return ""


async def apply_fix(session_id, index, approved_by="operator"):
    async with _lock(session_id):
        session = session_store.get_session(session_id, include_steps=False)
        report = (session or {}).get("report") or {}
        fixes = report.get("proposed_fixes", [])
        if not 0 <= index < len(fixes):
            raise ValueError("Unknown fix")
        fix = fixes[index]
        if fix["status"] in ("running", "applied"):
            return fix
        if any(item.get("fix_index") == index and item.get("status") in ("rejected", "done") for item in report.get("solutions") or []):
            raise ValueError("This solution was rejected or done by hand; it will not be run")
        target = resolve_target(session["device_id"])
        if target is None:
            raise ValueError("Device no longer exists")

        fix["status"] = "running"
        _set_solution_status(report, index, "running")
        session_store.update_session(session_id, status="fixing", report=report)
        events.publish(session_id, {"type": "fix", "index": index, "fix": fix})
        await asyncio.to_thread(decision_log.record, "fix_approved", session_id, {"device": target.label, "device_id": target.device_id, "action": fix["tool_id"], "args": fix["args"], "risk": fix["risk"], "approved_by": approved_by})
        result = await _run_step(session_id, target, fix["tool_id"], fix["args"], max_risk="high", kind="fix")
        fix["status"], fix["result"] = ("applied" if result.get("ok") else "failed"), result
        _set_solution_status(report, index, fix["status"])
        session_store.add_audit(session_id, target.device_id, fix["tool_id"], fix["args"], approved_by, result.get("ok"), result.get("summary"))
        session_store.update_session(session_id, status="fixing", report=report)
        events.publish(session_id, {"type": "fix", "index": index, "fix": fix})

        if result.get("ok"):
            await _verify(session, target, report, fix)
        else:
            _publish_status(session_id, "diagnosed", "Fix failed; see the result")
            await asyncio.to_thread(decision_log.record, "fix_result", session_id, {
                "device": target.label, "device_id": target.device_id, "action": fix["tool_id"], "result": result.get("summary"),
                "verdict": "The fix failed on the device", "resolved": False, "method": "none"})
    await learn_from(session_id)
    return fix


def record_late_fix_result(task, result, device_label):
    """An approved fix whose result reached the server after a restart: the coroutine that would have
    recorded it is gone, so record it here (audit row, decision, fix status). Returns False when the
    session is still running and records the result itself."""
    session = session_store.get_session(task["session_id"], include_steps=False)
    if not session or session["status"] in ("queued", "running", "fixing", "verifying"):
        return False
    report = session.get("report") or {}
    for index, fix in enumerate(report.get("proposed_fixes") or []):
        if fix.get("tool_id") == task["tool_id"] and (fix.get("args") or {}) == (task.get("args") or {}) and (fix.get("result") or {}).get("interrupted"):
            fix["status"], fix["result"] = ("applied" if result.get("ok") else "failed"), result
            _set_solution_status(report, index, fix["status"])
            session_store.update_session(task["session_id"], report=report)
            break
    else:
        return False  # not a fix a restart interrupted: the session already recorded it
    session_store.add_audit(task["session_id"], task["device_id"], task["tool_id"], task.get("args") or {}, "operator (approved before a server restart)", result.get("ok"), result.get("summary"))
    decision_log.record("fix_result", task["session_id"], {
        "device": device_label, "device_id": task["device_id"], "action": task["tool_id"], "result": result.get("summary"),
        "verdict": "The result arrived after a server restart and was not re-verified", "resolved": None, "method": "late result"})
    return True


def _set_solution_status(report, fix_index, status):
    for solution in report.get("solutions") or []:
        if solution.get("fix_index") == fix_index:
            solution["status"] = status


async def decide_solution(session_id, index, decision, decided_by="operator"):
    """A person marks a suggested solution as done by hand, or rejects it. Recorded, never executed."""
    if decision not in ("done", "rejected"):
        raise ValueError("decision must be 'done' or 'rejected'")
    async with _lock(session_id):
        session = session_store.get_session(session_id, include_steps=False)
        report = (session or {}).get("report") or {}
        solutions = report.get("solutions") or []
        if not 0 <= index < len(solutions):
            raise ValueError("Unknown solution")
        solution = solutions[index]
        if solution.get("status") in ("running", "applied"):
            raise ValueError(f"This solution is already {solution['status']}")
        solution["status"] = decision
        session_store.update_session(session_id, report=report)
        events.publish(session_id, {"type": "solution", "index": index, "solution": solution})
    await asyncio.to_thread(decision_log.record, "fix_done_manually" if decision == "done" else "fix_rejected", session_id, {
        "device": session.get("device_label"), "device_id": session.get("device_id"), "action": solution["title"],
        "tool_id": solution.get("tool_id"), "approved_by": decided_by if decision == "done" else None, "decided_by": decided_by,
    })
    return solution


async def _verify(session, target, report, fix):
    session_id = session["session_id"]
    _publish_status(session_id, "verifying", "Re-checking after the fix")
    related = findings.related_findings(report.get("quick_findings"), fix["tool_id"])
    sources = {item["source"] for item in related}
    steps = session_store.get_session(session_id)["steps"]
    tool_ids = []
    # Re-run the checks that produced the targeted findings first, then the other baseline checks.
    for step in sorted((step for step in steps if step["kind"] == "tool"), key=lambda step: step["tool_id"] not in sources):
        if step["tool_id"] != "performance_benchmark" and (step["tool_id"], step["args"]) not in tool_ids:
            tool_ids.append((step["tool_id"], step["args"]))
    evidence = await _run_parallel(session_id, target, [(tool_id, args or {}) for tool_id, args in tool_ids[:4]], kind="verify")
    rerun = {tool_id for tool_id, _, _ in evidence}

    if related and sources <= rerun:
        # Deterministic verdict, no AI call: did the problems this fix targeted disappear?
        after = {item["key"]: item for item in findings.analyze(evidence, target.os_type)}
        remaining = [after[item["key"]] for item in related if item["key"] in after]
        verdict = {
            "resolved": not remaining,
            "explanation": "Re-check passed: " + "; ".join(item["title"] for item in related) + " is no longer detected." if not remaining
            else "Still detected after the fix: " + "; ".join(item["title"] for item in remaining),
            "next_steps": [] if not remaining else ["Try the next proposed fix, or run a deep AI diagnosis."],
            "after_fix": fix["tool_id"], "method": "rules",
        }
    else:
        try:
            reply = await _chat([
                {"role": "system", "content": VERIFY_PROMPT.format(os_type=target.os_type)},
                {"role": "user", "content": f"Problem: {session['issue']}\nOriginal root cause: {report['root_cause']}\nFix applied: {fix['tool_id']} -> {fix['result'].get('summary')}\n\nFresh evidence:\n{_evidence_block(evidence, REPORT_EVIDENCE_CHARS)}"},
            ], json_mode=True, max_tokens=VERIFY_MAX_TOKENS, think=False)
            raw = _parse_json(reply["content"])
            verdict = {"resolved": bool(raw.get("resolved")), "explanation": str(raw.get("explanation", ""))[:1500], "next_steps": [str(item) for item in raw.get("next_steps", [])][:8], "after_fix": fix["tool_id"], "method": "ai"}
        except LLMUnavailableError as error:
            verdict = {"resolved": None, "explanation": f"Fix applied, but the AI could not verify it: {error}", "next_steps": [], "after_fix": fix["tool_id"], "method": "none"}
    separate = set(report.get("other_findings") or [])
    if verdict["resolved"] and verdict["method"] == "rules" and related and separate and all(item["key"] in separate for item in related):
        # The fix cleared a separate problem, not the one the user reported: say so instead of "resolved".
        verdict.update(resolved=None, explanation=f"The separate problem is fixed ({'; '.join(item['title'] for item in related)}), "
                                                  "but it was not what caused the reported problem. " + verdict["explanation"])
    if report.get("complaint_reproduced") is False and verdict["resolved"]:
        # Never let a fix "resolve" a complaint that never showed up: that would teach the AI a false lesson.
        lead = ("The finding this fix targeted is cleared, but the reported problem did not show up in the checks before the fix, "
                "so AIops cannot confirm it fixed that problem. ") if verdict["method"] == "rules" else (
                "The fix ran, but the problem did not show up in the checks before it either, so AIops cannot confirm it fixed anything. ")
        verdict.update(resolved=None, explanation=lead + verdict["explanation"])
    status = "resolved" if verdict["resolved"] else "diagnosed" if verdict["resolved"] is None else "unresolved"
    session_store.update_session(session_id, status=status, verify=verdict)
    await asyncio.to_thread(decision_log.record, "fix_result", session_id, {"device": target.label, "device_id": target.device_id, "action": fix["tool_id"], "result": (fix.get("result") or {}).get("summary"),
                                                   "verdict": verdict["explanation"], "resolved": verdict["resolved"], "method": verdict["method"]})
    events.publish(session_id, {"type": "verify", "verify": verdict})
    _publish_status(session_id, status, verdict["explanation"][:200])
