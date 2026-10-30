"""I1 reasoning contract: hypotheses, eliminated causes, tests performed, verification plan,
remaining uncertainty and the affected component. All computed by rules, so these tests need no AI
and no database — they drive the same rule pipeline a diagnosis uses."""

import re

from backend.agent_brain import findings, planner
from backend.agent_brain.eval_cases import CASES_BY_ID
from backend.agent_brain.playbooks import match_playbook


def _contract(case_id):
    """Run the rule pipeline for a recorded eval case and return (report, found, evidence)."""
    case = CASES_BY_ID[case_id]
    found = findings.analyze(case["evidence"], case["os_type"])
    playbook = match_playbook(case["issue"])
    report = planner._rule_based_report(found, case["issue"], case["os_type"], None, playbook)
    planner.ground_root_cause(report, playbook, found, case["evidence"])
    planner.enrich_report(report, found, playbook, case["evidence"], case["issue"])
    return report, found, case["evidence"]


def test_memory_cause_names_the_component_and_rules_disk_out():
    report, _found, _evidence = _contract("slow_memory_win")
    assert report["affected_component"] == "Memory (RAM)"
    likely = [item for item in report["hypotheses"] if item["status"] == "likely"]
    assert likely and re.search(r"memor|\bram\b", likely[0]["title"], re.I)
    # The 90%-but-23GB-free disk is a separate problem, not the cause.
    assert any(re.search(r"disk|c:", text, re.I) for text in report["eliminated_causes"])
    assert any(item["status"] == "ruled_out" and re.search(r"disk", item["title"], re.I) for item in report["hypotheses"])


def test_tests_performed_and_verification_plan_point_at_the_cause():
    report, _found, _evidence = _contract("slow_memory_win")
    assert "Overall CPU, memory and disk usage" in report["tests_performed"]
    plan = report["verification_plan"]
    assert plan["steps"] and "memory" in plan["steps"][0].lower()
    assert "memory" in plan["success"].lower()


def test_unreproduced_complaint_has_uncertainty_and_no_component():
    report, _found, _evidence = _contract("internet_ok_win")
    assert report["complaint_reproduced"] is False
    assert "intermittent" in report["remaining_uncertainty"].lower()
    assert report["affected_component"] is None
    # The network checks are named as tests performed; the generic verification plan asks to reproduce.
    assert "Internet connectivity (DNS, TCP, HTTP)" in report["tests_performed"]
    assert any("reproduce" in step.lower() for step in report["verification_plan"]["steps"])
    # High memory here is a separate problem, listed as eliminated, not the cause.
    assert report["eliminated_causes"]


def test_clean_machine_keeps_a_low_confidence_note():
    report, _found, _evidence = _contract("clean_checks_win")
    assert report["confidence"] == "low"
    assert report["remaining_uncertainty"]


def test_verification_steps_helper():
    assert findings.verification_steps(None) is None
    recipe = findings.verification_steps({"title": "Disk C: is 99% full", "source": "system_overview"})
    assert recipe["source"] == "system_overview" and "Disk C:" in recipe["success"]


def test_enrich_is_safe_with_no_findings():
    report = {"root_cause": "x", "confidence": "low", "related_findings": [], "other_findings": []}
    planner.enrich_report(report, [], None, [])
    assert report["hypotheses"] == [] and report["eliminated_causes"] == []
    assert report["affected_component"] is None and report["verification_plan"]["steps"]


# --- I5: clarifying questions and escalation ---

def test_uncertain_diagnosis_gets_clarifying_questions():
    report, _found, _evidence = _contract("internet_ok_win")
    assert report["clarifying_questions"]  # checks ran clean -> ask, don't guess
    assert all(isinstance(q, str) and q for q in report["clarifying_questions"])


def test_confident_cause_has_no_clarifying_questions():
    report, _found, _evidence = _contract("slow_memory_win")
    assert report["clarifying_questions"] == []


def test_escalation_only_on_real_signals():
    assert planner._escalation({}, [{"key": "disk_failing"}], []) is not None
    assert "data loss" in " ".join(planner._escalation({}, [{"key": "disk_failing"}], [])["reasons"]).lower()
    assert planner._escalation({}, [{"key": "ram_high"}], []) is None
    # A check that could not run makes the evidence incomplete -> escalate.
    incomplete = planner._escalation({}, [], [("security_posture", {}, {"ok": False, "summary": "access denied"})])
    assert incomplete and "incomplete" in incomplete["reasons"][0].lower()
