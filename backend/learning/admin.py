"""Inspect and clean the AI's learned cases (the memory it uses as hints and to build aiops-brain).

    docker compose exec -T sentinel python -m backend.learning.admin list [--trusted] [--device local]
    docker compose exec -T sentinel python -m backend.learning.admin delete --id 32 [--yes]
    docker compose exec -T sentinel python -m backend.learning.admin untrust-container [--yes]
    docker compose exec -T sentinel python -m backend.learning.admin delete-test-cases --since 2026-10-19 [--yes]
    docker compose exec -T sentinel python -m backend.learning.admin rebuild

The changing commands only show what they would change until --yes is given. Wrong lessons come from test
tickets with made-up complaints and from diagnoses of the AIops container mistaken for a real PC.
"""

import argparse
import sys

from . import model_builder
from . import store

# Complaints the end-to-end checks (tests/e2e/api_check.py) send; their cases teach nothing true.
TEST_ISSUES = (
    "Internet is slow and websites take long to open", "My laptop is very slow and hangs", "Some websites do not open but others work",
    "Websites stopped opening, maybe DNS", "Disk is full",
)
CONTAINER_DEVICES = ("local", "local-server")


def _show(cases):
    if not cases:
        print("No matching cases.")
    for case in cases:
        trusted = "trusted" if store.is_trusted(case) else "-"
        print(f"#{case['id']} {case['created_at'][:16]} {case.get('device_id')} {case.get('os_type')} {case['outcome']} {case.get('feedback') or '-'} {trusted}")
        print(f"    issue: {case['issue'][:100]}")
        print(f"    cause: {(case.get('effective_root_cause') or '')[:160]}")


def _select(where, params=()):
    with store._connect() as connection:
        rows = connection.execute(f"SELECT * FROM learned_cases WHERE {where} ORDER BY id", params).fetchall()
    return [store._case_dict(row) for row in rows]


def _apply(cases, statement, yes, done):
    _show(cases)
    if not cases:
        return
    if not yes:
        print(f"\n{len(cases)} case(s) would be changed. Run again with --yes to do it.")
        return
    with store._connect() as connection:
        connection.executemany(statement, [(case["id"],) for case in cases])
        connection.commit()
    print(f"\n{len(cases)} case(s) {done}. Run 'rebuild' so the aiops-brain model forgets them.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="show learned cases")
    listing.add_argument("--trusted", action="store_true", help="only cases the AI learns from")
    listing.add_argument("--device", default="", help="only this device id (local = the AIops container)")
    deleting = commands.add_parser("delete", help="delete cases by id or session")
    deleting.add_argument("--id", type=int, nargs="*", default=[])
    deleting.add_argument("--session", nargs="*", default=[])
    deleting.add_argument("--yes", action="store_true")
    untrust = commands.add_parser("untrust-container", help="stop learning from diagnoses of the AIops container")
    untrust.add_argument("--yes", action="store_true")
    tests = commands.add_parser("delete-test-cases", help="delete cases made by the end-to-end test tickets")
    tests.add_argument("--since", required=True, help="YYYY-MM-DD")
    tests.add_argument("--yes", action="store_true")
    commands.add_parser("rebuild", help="rebuild the aiops-brain model from the remaining cases")
    args = parser.parse_args(argv)

    if args.command == "list":
        cases = [case for case in store.list_cases(5000) if (not args.trusted or store.is_trusted(case)) and (not args.device or case.get("device_id") == args.device)]
        _show(list(reversed(cases)))
    elif args.command == "delete":
        if not args.id and not args.session:
            parser.error("give --id and/or --session")
        marks = ",".join("?" * (len(args.id) + len(args.session)))
        cases = _select(f"id IN ({marks}) OR session_id IN ({marks})", (*args.id, *args.session, *args.id, *args.session))
        _apply(cases, "DELETE FROM learned_cases WHERE id = ?", args.yes, "deleted")
    elif args.command == "untrust-container":
        cases = [case for case in _select("device_id IN (?, ?)", CONTAINER_DEVICES) if store.is_trusted(case)]
        _apply(cases, "UPDATE learned_cases SET feedback = NULL, feedback_note = NULL, corrected_root_cause = NULL, "
                      "outcome = CASE WHEN outcome = 'resolved' THEN 'diagnosed' ELSE outcome END WHERE id = ?", args.yes, "no longer trusted")
    elif args.command == "delete-test-cases":
        marks = ",".join("?" * len(TEST_ISSUES))
        cases = _select(f"created_at >= ? AND issue IN ({marks})", (args.since, *TEST_ISSUES))
        _apply(cases, "DELETE FROM learned_cases WHERE id = ?", args.yes, "deleted")
    elif args.command == "rebuild":
        info = model_builder.build("manual")
        print(f"Rebuilt {info['model']} v{info['version']}: {info['trusted_cases']} trusted case(s), {info['lessons']} lesson(s), {info['examples']} example(s).")
        if not info["created_in_ollama"]:
            print(f"Ollama was not updated: {info['error']}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
