"""The agentic troubleshooting loop.

1. Baseline: run system_overview plus the matched playbook's tools, in parallel
   (CPU-sensitive measurements first). The model is loaded at the same time.
2. Instant findings: deterministic rules turn the evidence into concrete problems
   within seconds (see findings.py). "instant" mode stops here.
3. Investigate (deep mode, or fast mode without a matching playbook): the LLM calls
   further read-only tools until it has enough evidence.
4. Report: one JSON-mode call (with deep thinking, streamed live) turns evidence + findings +
   the model's own IT knowledge into a root cause and 3-4 ranked solutions. A solution may name an
   allow-listed remediation tool, which makes it runnable after a person approves it.
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

from agent.toolkit import get_tool, list_tools, tool_schemas
from agent.toolkit.registry import validate_args
from agent.toolkit.remediation import PROTECTED_PROCESSES, RESTARTABLE_SERVICES

from .. import decision_log
from ..alert_store import get_alerts
from ..learning import model_builder
from ..learning import store as learning_store
from ..llm import LLMUnavailableError, get_provider
from ..llm.brain import BRAIN_PRINCIPLES, MAX_SOLUTIONS, MIN_SOLUTIONS
from ..workers import ai_gate, run_ai
from . import events, findings, session_store
from .executor import execute, resolve_target
from .playbooks import RELEVANT_FIXES, baseline_phases, filter_relevant_fixes, get_playbook, match_playbook, playbook_tips

logger = logging.getLogger(__name__)

# Kept small on purpose: on a laptop CPU, prompt length dominates how long each LLM call takes.
TOOL_RESULT_CHARS = 1200
REPORT_EVIDENCE_CHARS = 700
MAX_CALLS_PER_TURN = 3
# Output cap for the report / verify calls: generation is the slowest part on a CPU.
REPORT_MAX_TOKENS = 450
# With deep thinking the reasoning tokens count toward the cap, so the report gets far more room.
REPORT_THINKING_MAX_TOKENS = 1400
# When thinking used the whole budget before the JSON was written, a short no-thinking call turns the
# reasoning into the answer (instead of throwing minutes of reasoning away).
REASONING_HANDOFF_CHARS = 3000
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

# The evidence list and issue summary are built by the server, not generated: on a laptop CPU
# every output token costs ~0.2 s, so the model only writes what needs judgement.
REPORT_PROMPT = """You are AIops, a senior IT support technician. Write the final diagnosis for a {os_type} computer as JSON.
""" + BRAIN_PRINCIPLES + """
Use the evidence first and your own IT knowledge second. Explain in simple language a non-technical user understands.
If the evidence does NOT confirm the user's complaint (for example the disk has plenty of free space), say so plainly
in root_cause and set confidence to "low".
Only blame a finding for the complaint if it can really cause it (a full disk does not break DNS or websites;
high memory does not cause a network outage). If the checks for the complaint passed, say they passed, mention
other findings only as separate problems, and suggest what to check next.
JSON schema:
{{
  "root_cause": "1-2 sentences: the most likely root cause, citing the evidence",
  "confidence": "low|medium|high",
  "severity": "low|medium|high|critical",
  "solutions": [
    {{"title": "short action", "why": "one sentence: why this helps", "steps": ["concrete step", "..."], "risk": "low|medium|high", "tool_id": "<fix tool id, or null>", "args": {{}}}}
  ]
}}
Keep your private reasoning short and focused (a few hundred words), then write the JSON.
Give 3 or 4 genuinely different solutions, best first. Set tool_id ONLY when one of these tools performs the
solution (the user must still approve it); otherwise use null and write the steps the user follows by hand.
Never suggest kill_process for system processes. Available fix tools (id, risk, description, params):
{fix_catalog}"""

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


def diagnosis_thinking():
    """Deep thinking for the diagnosis report (the decision that matters). On by default."""
    return os.getenv("DIAGNOSIS_THINKING", "true").strip().lower() in ("1", "true", "yes")


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
    """Fast mode trusts a matched playbook's baseline and goes straight to the report."""
    if mode == "instant":
        return 0
    if mode == "fast":
        return 0 if playbook else min(1, max_investigation_steps())
    return max_investigation_steps()


def _compact(result, limit=TOOL_RESULT_CHARS):
    payload = json.dumps({"ok": result.get("ok"), "summary": result.get("summary"), "data": result.get("data")}, default=str)
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


def _parse_json(text):
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`").removeprefix("json").strip()
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except ValueError:
                pass
    return {}


def fix_catalog(os_type, only=None):
    """One compact line per fix tool: `- id (risk) args {...}: first sentence of the description`.
    `only` limits the catalog (e.g. to a playbook's relevant fixes) to keep the prompt short."""
    lines = []
    for item in list_tools(os_type, max_risk="high", min_risk="low"):
        if (only and item.id not in only) or not item.ai_visible:
            continue
        params = ", ".join(f"{name}: {spec.get('type')}" for name, spec in item.params.items())
        summary = item.description.split(". ")[0].rstrip(".")
        lines.append(f"- {item.id} ({item.risk})" + (f" args {{{params}}}" if params else "") + f": {summary}")
    return "\n".join(lines)


def _device_would_accept(tool_id, args, os_type):
    """Drop fixes the device is certain to refuse, so the operator never sees a dead button."""
    if tool_id == "restart_service":
        return args.get("name") in RESTARTABLE_SERVICES.get(os_type, ())
    if tool_id == "kill_process":
        return str(args.get("expected_name", "")).lower() not in PROTECTED_PROCESSES
    return True


def validate_fixes(raw_fixes, os_type):
    """Keep only fixes that name a real remediation tool for this OS with valid arguments."""
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
        if not _device_would_accept(item.id, args, os_type):
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


def normalize_solutions(raw_solutions, os_type):
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
            valid = validate_fixes([{"tool_id": tool_id, "args": entry.get("args") or {}, "why": entry.get("why", "")}], os_type)
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


def _solution_from_fix(fix):
    tool = get_tool(fix["tool_id"])
    return {
        "title": (tool.description.split(". ")[0].rstrip(".") if tool else fix["tool_id"])[:160],
        "why": fix.get("why") or "",
        "steps": [],
        "risk": fix["risk"],
        "tool_id": fix["tool_id"],
        "args": fix.get("args") or {},
        "source": "learned" if fix.get("learned") else "rule" if fix.get("rule") else "ai",
        "status": "suggested",
    }


def complete_solutions(report, playbook):
    """Top the solutions up to 3-4: first with runnable fixes the rules or past tickets proposed, then with
    safe manual tips for this kind of problem. Never more than MAX_SOLUTIONS."""
    solutions = list(report.get("solutions") or [])
    keys = {_fix_key(item) for item in solutions if item.get("tool_id")}
    for fix in report.get("proposed_fixes") or []:
        if len(solutions) >= MAX_SOLUTIONS:
            break
        if _fix_key(fix) not in keys:
            keys.add(_fix_key(fix))
            solutions.append(_solution_from_fix(fix))
    titles = {item["title"].lower() for item in solutions}
    for tip in playbook_tips(playbook):
        if len(solutions) >= MIN_SOLUTIONS:
            break
        if tip["title"].lower() not in titles:
            titles.add(tip["title"].lower())
            solutions.append({**tip, "steps": list(tip["steps"]), "tool_id": None, "args": {}, "source": "playbook", "status": "suggested"})
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


def normalize_report(raw, issue, os_type, fallback_note=None):
    severity = str(raw.get("severity", "medium")).lower()
    confidence = str(raw.get("confidence", "medium")).lower()
    solutions = normalize_solutions(raw.get("solutions"), os_type)
    solution_fixes = [{"tool_id": item["tool_id"], "args": item["args"], "why": item["why"] or item["title"]} for item in solutions if item["tool_id"]]
    manual_steps, fixes = promote_manual_steps(
        [str(item)[:400] for item in (raw.get("manual_steps") or [])][:10] + [item["title"] for item in solutions if not item["tool_id"]],
        validate_fixes(list(raw.get("proposed_fixes") or []) + solution_fixes, os_type),
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
    """Record the session as a learned case and rebuild the aiops-brain model when due."""
    try:
        session = session_store.get_session(session_id, include_steps=False)
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


def _summary_block(evidence):
    """One line per check. Fast mode sends this instead of raw data: the rules already digested
    the data into findings, and prompt evaluation is about half of the AI time on a laptop CPU."""
    return "\n".join(f"- {tool_id}{' ' + json.dumps(args) if args else ''}: {'' if result.get('ok') else '(failed) '}{(result.get('summary') or '')[:300]}" for tool_id, args, result in evidence)


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


def _rule_based_report(found, issue, os_type, note=None):
    raw = findings.rule_report(found, issue, note)
    report = normalize_report({**raw, "proposed_fixes": raw.pop("raw_fixes")}, issue, os_type)
    for fix in report["proposed_fixes"]:
        fix["rule"] = True
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
    # diagnosis is generating, the model is already loaded.
    warm_up = asyncio.create_task(run_ai(_warm_up)) if mode != "instant" and not ai_gate().locked() else None

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
        report, similar = _rule_based_report(found, issue, target.os_type, note), []
    else:
        report, similar = await _ai_report(session_id, target, issue, playbook, evidence, found, mode, warm_up)
    report = ground_root_cause(report, playbook, found, evidence)
    report = add_learned_fixes(report, learned_fixes, target.os_type)
    report = add_rule_fixes(report, found, target.os_type)
    report["proposed_fixes"] = ground_fixes(filter_relevant_fixes(report["proposed_fixes"], playbook), report, found, playbook)
    report["similar_cases"] = [{"session_id": case["session_id"], "issue": case["issue"][:160], "root_cause": (case.get("effective_root_cause") or "")[:240], "outcome": case["outcome"]} for case in similar]
    report["quick_findings"] = found
    report["mode"] = mode
    link_solutions(complete_solutions(report, playbook))
    total = time.perf_counter() - started
    report["timing"] = {"evidence_seconds": round(evidence_seconds, 1), "ai_seconds": round(total - evidence_seconds, 1), "total_seconds": round(total, 1)}
    session_store.update_session(session_id, status="diagnosed", report=report)
    await asyncio.to_thread(_record_diagnosis, session, target, report, found)
    events.publish(session_id, {"type": "report", "report": report})
    _publish_status(session_id, "diagnosed", f"Diagnosis ready in {total:.0f}s")


async def _ai_report(session_id, target, issue, playbook, evidence, found, mode, warm_up):
    alerts = get_alerts(10, "local-server" if target.is_local else target.device_id)
    alert_lines = "\n".join(f"- [{alert['severity']}] {alert['category']}: {alert['description']}" for alert in alerts) or "- none"
    similar = await asyncio.to_thread(learning_store.find_similar, issue, target.os_type, 3)
    if similar:
        _think(session_id, f"Memory: found {len(similar)} similar ticket(s) solved before; using them as hints.")
    past_cases = _past_cases_block(similar)
    found_block = findings.findings_block(found)
    if warm_up:
        await warm_up

    notes = ""
    rounds = investigation_rounds(mode, playbook)
    if rounds:
        try:
            notes = await _investigate(session_id, target, issue, evidence, found_block, alert_lines, past_cases, rounds)
        except LLMUnavailableError as error:
            # The model is too slow right now; another call would fail the same way, so answer from the rules.
            logger.warning("Troubleshoot %s: investigation failed, using rules: %s", session_id, error)
            return _rule_based_report(found, issue, target.os_type, f"AI did not answer in time, instant rule-based diagnosis: {error}"), similar

    only = RELEVANT_FIXES.get((playbook or {}).get("id")) if mode == "fast" else None
    evidence_text = _summary_block(evidence) if mode == "fast" else _evidence_block(evidence, REPORT_EVIDENCE_CHARS)
    # Small models invent a cause when nothing is wrong; say so explicitly when the checks are clean.
    clean = "" if found else "\n\nIMPORTANT: the automatic checks found nothing abnormal. Unless the evidence clearly shows a problem, say the checks did not confirm the complaint, set confidence to \"low\" and propose no fixes."
    report_messages = [
        {"role": "system", "content": REPORT_PROMPT.format(os_type=target.os_type, fix_catalog=fix_catalog(target.os_type, only) or "- none")},
        {"role": "user", "content": f"User's problem: {issue}\n\nAutomatic findings (already verified by rules):\n{found_block}\n\nEvidence:\n{evidence_text}\n\nInvestigator notes: {notes or 'none'}{past_cases}{clean}"},
    ]
    thinking = diagnosis_thinking()
    _publish_status(session_id, "running", "AI is thinking deeply about the diagnosis" if thinking else "AI is writing the diagnosis")
    try:
        reply = await _chat(report_messages, json_mode=True, max_tokens=REPORT_THINKING_MAX_TOKENS if thinking else REPORT_MAX_TOKENS,
                            think=thinking, on_delta=_thinking_publisher(session_id))
    except LLMUnavailableError as error:
        # A slow or crashed model must not throw away the evidence already collected.
        logger.warning("Troubleshoot %s: report call failed, using rules: %s", session_id, error)
        return _rule_based_report(found, issue, target.os_type, f"AI did not answer, instant rule-based diagnosis: {error}"), similar
    raw = _parse_json(reply["content"])
    if not raw.get("root_cause") and reply.get("thinking"):
        # Thinking ran out of budget before the answer: hand the reasoning to a quick call that only writes it up.
        _publish_status(session_id, "running", "AI is writing the diagnosis from its reasoning")
        handoff = report_messages + [{"role": "user", "content": "Your reasoning so far:\n" + reply["thinking"][-REASONING_HANDOFF_CHARS:]
                                       + "\n\nNow write ONLY the final JSON answer in the schema above, with 3 or 4 solutions."}]
        try:
            written = await _chat(handoff, json_mode=True, max_tokens=REPORT_MAX_TOKENS + 150, think=False)
            raw = _parse_json(written["content"])
        except LLMUnavailableError as error:
            logger.warning("Troubleshoot %s: write-up after thinking failed: %s", session_id, error)
    if not raw.get("root_cause"):
        report = _rule_based_report(found, issue, target.os_type, "AI returned no usable diagnosis; showing the instant rule-based diagnosis")
        # Keep what the AI did try, so the decision record shows it.
        report["ai"] = {"model": reply.get("model"), "thinking": bool(reply.get("thought")), "prompt_hash": decision_log.prompt_hash(report_messages), "fallback": True}
        report["reasoning"] = (reply.get("thinking") or "")[-3000:]
        return report, similar
    raw.setdefault("evidence", evidence_facts(found, evidence))
    report = normalize_report(raw, issue, target.os_type, fallback_note=notes)
    report["ai"] = {"model": reply.get("model"), "thinking": bool(reply.get("thought")), "prompt_hash": decision_log.prompt_hash(report_messages)}
    report["reasoning"] = (reply.get("thinking") or "")[-3000:]
    return report, similar


NETWORK_PLAYBOOKS = {"no_internet", "wifi_drops"}


def ground_root_cause(report, playbook, found, evidence):
    """Small models blame whatever finding they see for the complaint (e.g. "a full disk breaks
    DNS"), even when told not to. When the checks for a network complaint passed and found
    nothing network-related, say that plainly and list other findings as separate problems."""
    if (playbook or {}).get("id") not in NETWORK_PLAYBOOKS or any(item["key"].startswith(("net_", "wifi_")) for item in found):
        return report
    summaries = {tool_id: str(result.get("summary") or "") for tool_id, _, result in evidence if result.get("ok")}
    # Judge by the real traffic tests, not the summary line: older agents can write a wrong summary
    # (e.g. "DHCP failed" because of a virtual adapter) while DNS, TCP and HTTP all work.
    stages = next((result.get("data") or {} for tool_id, _, result in evidence if tool_id == "check_internet" and result.get("ok")), {})
    online = all((stages.get(stage) or {}).get("ok") for stage in ("dns_resolution", "tcp_to_internet", "http")) if stages else False
    if not (online or summaries.get("check_internet", "").startswith("Internet connectivity works")):
        return report
    if online and not summaries["check_internet"].startswith("Internet connectivity works"):
        summaries["check_internet"] = "DNS, TCP and HTTP tests to the internet all succeeded"
    wifi = f"; {summaries['wifi_status'].rstrip('.')}" if summaries.get("wifi_status") else ""
    others = [item["title"] for item in found]
    report["ai_root_cause"] = report.get("root_cause")
    report["root_cause_source"] = "rules: the network checks for this complaint passed"
    report["complaint_reproduced"] = False
    report["root_cause"] = (
        f"The network checks passed ({summaries['check_internet'].rstrip('.')}{wifi}). The problem did not show up during the check, "
        "so it may be intermittent or limited to certain websites."
        + (f" Separate problems found: {', '.join(others)}." if others else "")
    )
    report["confidence"] = "low"
    return report


def _record_diagnosis(session, target, report, found):
    ai = report.get("ai") or {}
    kind = "performance_analysis" if session.get("playbook_id") == "performance" else "diagnosis"
    decision_log.record(kind, session["session_id"], {
        "device": target.label, "device_id": target.device_id, "os_type": target.os_type, "issue": session["issue"],
        "mode": report.get("mode"), "model": ai.get("model"), "thinking": ai.get("thinking", False), "prompt_hash": ai.get("prompt_hash"),
        "root_cause": report.get("root_cause"), "root_cause_source": report.get("root_cause_source") or ("ai" if ai.get("model") and not ai.get("fallback") else "rules"),
        "ai_root_cause": report.get("ai_root_cause"), "confidence": report.get("confidence"), "severity": report.get("severity"),
        "solutions": [{key: item.get(key) for key in ("title", "why", "steps", "risk", "tool_id", "source")} for item in report.get("solutions") or []],
        "findings": [item["title"] for item in found], "evidence": report.get("evidence"),
        "reasoning_summary": (report.get("reasoning") or "")[-1500:], "timing": report.get("timing"),
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
