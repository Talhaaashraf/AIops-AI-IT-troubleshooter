"""I6: reasoning-based evaluation and the learning (training-data) upgrade.

Scores the new reasoning cases through the same rule pipeline a real diagnosis uses (no AI, no DB), so
the eval's reasoning-contract check (`hypotheses`) is exercised, and checks that the curated
bad->good exemplars land in the exported fine-tune data."""

import pytest

from backend.agent_brain import evaluate, findings, planner
from backend.agent_brain.eval_cases import CASES_BY_ID
from backend.agent_brain.playbooks import match_playbook
from backend.learning import model_builder


def _instant_report(case):
    """A rule-based report built exactly as _diagnose builds one in instant mode, minus the DB writes."""
    found = findings.analyze(case["evidence"], case["os_type"])
    playbook = match_playbook(case["issue"])
    report = planner._rule_based_report(found, case["issue"], case["os_type"], None, playbook)
    planner.ground_root_cause(report, playbook, found, case["evidence"])
    planner.link_solutions(planner.complete_solutions(report, playbook, found, case["os_type"], case["evidence"]))
    planner.enrich_report(report, found, playbook, case["evidence"], case["issue"])
    report["quick_findings"] = found
    report["mode"] = "instant"
    return report


@pytest.mark.parametrize("case_id", ["bsod_driver_win", "audio_service_win", "slow_memory_win", "printer_spooler_win"])
def test_reasoning_cases_score_on_the_contract(case_id):
    case = CASES_BY_ID[case_id]
    row = evaluate.score(case, _instant_report(case))
    for key in ("cause", "not_blamed", "confidence", "os_steps", "solutions", "first", "hypotheses"):
        assert row[key] is True, f"{case_id} failed check {key}"


def test_hypotheses_check_fails_without_the_contract():
    # A report missing hypotheses/verification must fail the new check (guards against a no-op metric).
    case = CASES_BY_ID["bsod_driver_win"]
    bare = {"root_cause": "x", "confidence": "high", "solutions": [], "quick_findings": [{"key": "crash_system"}]}
    assert evaluate.score(case, bare)["hypotheses"] is False


def test_training_export_includes_the_bad_to_good_exemplars():
    data = model_builder.export_training_data([])
    assert "reinstall the driver" in data and "WSD port" in data  # the printer negative->positive contrast
    assert "bottleneck" in data  # the slow-PC exemplar
    assert "Weak:" in data and "Evidence-first:" in data
