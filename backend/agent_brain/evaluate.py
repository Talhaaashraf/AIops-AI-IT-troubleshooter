"""Measure the AI's diagnoses on fixed scenarios (eval_cases.py) without touching devices or the real database.

    docker compose exec -T sentinel python -m backend.agent_brain.evaluate [--mode fast|deep] [--case id,id] [--model qwen3:8b] [--json-out PATH]

It runs the same pipeline as a real diagnosis (rules, prompt, model, grounding), starting from recorded
evidence, against a throw-away database and decisions folder: nothing is learned, nothing runs on a device.
The model answers one request at a time, so run it while no diagnosis is running. On a CPU a fast run of all
cases takes roughly 10-30 minutes.
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from .eval_cases import CASES, CASES_BY_ID

MAIN_CAUSE_END = re.compile(r"\b(?:Separate problems?|Other problems?)\b", re.I)
COLUMNS = ("case", "cause", "not_blamed", "confidence", "os_steps", "solutions", "first", "fallback", "seconds", "prompt_tok", "output_tok")


def main_cause(report):
    """The root cause without the "Separate/Other problems" tail, which may name findings that did not cause it."""
    return MAIN_CAUSE_END.split(report.get("root_cause") or "", maxsplit=1)[0]


def _solution_text(solution):
    return " ".join([str(solution.get("title") or ""), str(solution.get("why") or "")] + [str(step) for step in solution.get("steps") or []])


def score(case, report, seconds=None):
    """One result row. Each check is True/False; the totals line counts the Trues."""
    expect = case["expect"]
    cause = main_cause(report)
    solutions = report.get("solutions") or []
    ai = report.get("ai") or {}
    usage = ai.get("usage") or {}
    # A report without an AI model (or marked as a fallback) is the rule-based answer given when the AI failed.
    fallback = bool(ai.get("fallback")) or not ai.get("model")
    return {
        "case": case["id"],
        "cause": bool(re.search(expect["cause"], cause, re.I)),
        "not_blamed": not re.search(expect["not_blamed"], cause, re.I),
        "confidence": report.get("confidence") in expect["confidence"],
        "os_steps": not any(re.search(expect["forbidden"], _solution_text(item), re.I) for item in solutions),
        "solutions": 3 <= len(solutions) <= 4,
        "first": bool(solutions) and bool(re.search(expect["first"], _solution_text(solutions[0]), re.I)),
        "fallback": fallback,
        "seconds": round(seconds, 1) if seconds is not None else None,
        "prompt_tok": usage.get("prompt_tokens"),
        "output_tok": usage.get("output_tokens"),
        "root_cause": (report.get("root_cause") or "")[:300],
        "confidence_value": report.get("confidence"),
        "first_solution": (solutions[0].get("title") if solutions else None),
    }


def fixture_executor(case):
    """Deep-mode investigation tools get the case's recorded evidence, or "not available"; nothing changes."""
    recorded = {}
    for tool_id, _args, result in case["evidence"]:
        recorded.setdefault(tool_id, result)

    async def run(target, tool_id, args, max_risk, session_id=None):
        if max_risk != "read":
            return {"ok": False, "summary": "The evaluation never changes anything."}
        result = recorded.get(tool_id)
        return {**result, "tool_id": tool_id, "args": args} if result else {"ok": False, "summary": f"{tool_id} is not available in the offline evaluation."}

    return run


async def run_case(case, mode):
    from . import planner, session_store
    from .executor import Target

    planner.execute = fixture_executor(case)
    target = Target("eval-device", case["os_type"], "evaluation device")
    session_id = session_store.create_session(target.device_id, target.label, target.os_type, case["issue"], None)
    started = time.perf_counter()
    await planner._diagnose(session_store.get_session(session_id, include_steps=False), target, mode, preset_evidence=case["evidence"])
    report = session_store.get_session(session_id, include_steps=False).get("report") or {}
    return score(case, report, time.perf_counter() - started)


def format_rows(rows):
    def cell(value):
        return "ok" if value is True else "NO" if value is False else "-" if value is None else str(value)

    lines = [" | ".join(COLUMNS)]
    lines += [" | ".join(cell(row.get(column)) for column in COLUMNS) for row in rows]
    checks = ("cause", "not_blamed", "confidence", "os_steps", "solutions", "first")
    totals = ", ".join(f"{column} {sum(1 for row in rows if row.get(column) is True)}/{len(rows)}" for column in checks)
    seconds = [row["seconds"] for row in rows if row.get("seconds") is not None]
    lines.append(f"TOTAL: {totals}; fallbacks {sum(1 for row in rows if row.get('fallback'))}; AI+checks {sum(seconds):.0f} s")
    return "\n".join(lines)


def _saved_model(db_path):
    """The model picked in the dashboard (read-only), so the evaluation measures what the app uses."""
    if not db_path or not Path(db_path).exists():
        return None
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            row = connection.execute("SELECT value FROM settings WHERE key = 'ollama_model'").fetchone()
        finally:
            connection.close()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--mode", choices=("fast", "deep", "instant"), default="fast")
    parser.add_argument("--case", default="", help="comma-separated case ids (default: all)")
    parser.add_argument("--model", default="", help="base model to test (default: the one picked in the dashboard); skips the aiops-brain model")
    parser.add_argument("--json-out", default="", help="also write the rows as JSON to this file")
    args = parser.parse_args(argv)

    unknown = [item for item in args.case.split(",") if item and item not in CASES_BY_ID]
    if unknown:
        parser.error(f"unknown case(s) {', '.join(unknown)}; choose from {', '.join(CASES_BY_ID)}")
    cases = [CASES_BY_ID[item] for item in args.case.split(",") if item] if args.case else CASES
    model = args.model or _saved_model(os.getenv("SENTINEL_DB_PATH"))
    # Before any backend module reads its configuration: a throw-away database and decisions folder.
    workdir = Path(tempfile.mkdtemp(prefix="aiops-eval-"))
    os.environ["SENTINEL_DB_PATH"] = str(workdir / "eval.db")
    os.environ["DECISIONS_DIR"] = str(workdir / "decisions")
    if model:
        os.environ["OLLAMA_MODEL"] = model
    if args.model:
        os.environ["LEARNING_USE_MODEL"] = "false"

    try:
        from ..llm import get_provider

        status = get_provider().status()
        print(f"AIops evaluation: {len(cases)} case(s), mode {args.mode}, model {status.get('model')} ({status.get('message')})", flush=True)
        rows = []
        for case in cases:
            print(f"- {case['id']}: {case['issue']}", flush=True)
            try:
                row = asyncio.run(run_case(case, args.mode))
            except Exception as error:  # one broken case must not lose the others' results
                row = {"case": case["id"], "error": f"{type(error).__name__}: {error}"}
            print(f"  {row.get('error') or row.get('root_cause')} [{row.get('confidence_value')}; {row.get('seconds')} s]", flush=True)
            rows.append(row)
        print()
        print(format_rows(rows))
        if args.json_out:
            Path(args.json_out).write_text(json.dumps({"mode": args.mode, "model": status.get("model"), "rows": rows}, indent=2), encoding="utf-8")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
