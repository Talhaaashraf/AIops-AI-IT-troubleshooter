"""I2 knowledge package: selective, budgeted retrieval of domain knowledge and tool hints.
Pure functions — no AI, no database."""

from agent.toolkit import get_tool

from backend.agent_brain import knowledge
from backend.agent_brain.knowledge import tool_knowledge
from backend.agent_brain.knowledge.domains import DOMAINS
from backend.agent_brain.knowledge.investigation_map import INVESTIGATION_MAP
from backend.agent_brain.playbooks import get_playbook, match_playbook


def test_matched_playbook_selects_its_domain_card():
    card = knowledge.match_domain("printer not printing", get_playbook("printer"))
    assert card["id"] == "printer"
    # The performance playbook reuses the slow-PC card.
    assert knowledge.match_domain("", get_playbook("performance"))["id"] == "slow_pc"


def test_keyword_match_when_no_playbook():
    assert knowledge.match_domain("Office keeps failing to install", None)["id"] == "office"
    assert knowledge.match_domain("my app keeps closing when I open it", None)["id"] == "app_crash"


def test_retrieve_is_selective_for_a_printer_issue():
    block = knowledge.retrieve("the printer will not print", get_playbook("printer"), set(), "Windows")
    assert block.startswith("DOMAIN: Printer")
    assert "Where to look" in block and "spooler" in block.lower()
    # Spec §34: do NOT load unrelated Office / BSOD / AD knowledge.
    assert "office" not in block.lower()
    assert "blue screen" not in block.lower() and "bsod" not in block.lower()


def test_retrieve_empty_when_nothing_matches():
    assert knowledge.retrieve("zzzz qwptx asdf", None, set(), "Windows") == ""


def test_retrieve_respects_the_budget_and_never_cuts_mid_line(monkeypatch):
    monkeypatch.setenv("KNOWLEDGE_BUDGET_CHARS", "60")
    block = knowledge.retrieve("printer not printing", get_playbook("printer"), set(), "Windows")
    assert 0 < len(block) <= 60
    assert block.startswith("DOMAIN:")
    # Whole lines only: the kept text equals itself split and rejoined (no dangling partial).
    assert all(line.strip() for line in block.splitlines())


def test_investigate_tool_hint_names_relevant_checks():
    hint = knowledge.investigate_tool_hint("the printer will not print", get_playbook("printer"), set(), "Windows")
    assert "printer_status" in hint and ":" in hint
    assert knowledge.investigate_tool_hint("zzzz qwptx", None, set(), "Windows") == ""


def test_every_card_where_key_exists_in_the_map():
    for card in DOMAINS:
        for key in card["where"]:
            assert key in INVESTIGATION_MAP, f"{card['id']} references unknown map key {key}"


def test_tool_knowledge_and_card_tools_are_real_registered_tools():
    for tool_id in tool_knowledge.TOOL_QUESTIONS:
        assert get_tool(tool_id) is not None, f"tool_knowledge names unknown tool {tool_id}"
    for card in DOMAINS:
        for tool_id in card["tools"]:
            assert get_tool(tool_id) is not None, f"domain {card['id']} names unknown tool {tool_id}"


# --- I3: error-code / Event-ID / BSOD engines ---

def _ev(tool_id, summary, data):
    return (tool_id, {}, {"ok": True, "summary": summary, "data": data})


def test_error_code_detected_in_issue_text():
    block = knowledge.retrieve_codes("Office 365 install fails with error 1618", [])
    assert "1618" in block and "install" in block.lower()


def test_bugcheck_detected_in_crash_evidence():
    evidence = [_ev("recent_crashes", "1 crash in 7 days", [{"type": "blue screen", "message": "The bugcheck was 0x0000001a (MEMORY_MANAGEMENT)"}])]
    block = knowledge.retrieve_codes("random blue screens", evidence)
    assert "MEMORY_MANAGEMENT" in block and "Correlate" in block


def test_event_id_detected_from_log_sample():
    evidence = [_ev("event_log_errors", "5 errors in 24h", {"groups": [{"source": "WHEA-Logger", "count": 5, "level": "error", "sample": "A corrected hardware error occurred"}]})]
    kinds = {kind for kind, _entry in knowledge.detect_codes("hardware errors", evidence)}
    assert "EVENT" in kinds
    assert any(entry["id"] == "whea_logger" for _kind, entry in knowledge.detect_codes("hardware errors", evidence))


def test_plain_ntfs_filesystem_label_is_not_a_false_positive():
    # A healthy disk reported as NTFS must NOT trigger the Ntfs-corruption event entry.
    evidence = [_ev("system_overview", "fullest disk C:\\ 90%", {"disks": [{"mount": "C:\\", "fs": "NTFS", "used_percent": 90.1, "free": "23 GB"}]})]
    assert all(entry["id"] != "disk_ntfs" for _kind, entry in knowledge.detect_codes("laptop is slow", evidence))


def test_no_codes_present_returns_empty():
    evidence = [_ev("system_overview", "CPU 10%, RAM 40%", {"cpu_percent": 10, "ram_percent": 40})]
    assert knowledge.retrieve_codes("my laptop is a bit slow", evidence) == ""


# --- I4: playbook-engine extras (questions, decision points, escalation) ---

def test_every_extras_key_is_a_real_domain():
    from backend.agent_brain.knowledge.domains import DOMAINS_BY_ID
    from backend.agent_brain.knowledge.playbook_extras import DOMAIN_EXTRAS
    for domain_id in DOMAIN_EXTRAS:
        assert domain_id in DOMAINS_BY_ID, f"extras for unknown domain {domain_id}"


def test_clarifying_questions_domain_then_generic():
    from backend.agent_brain.knowledge.playbook_extras import GENERIC_QUESTIONS
    dq = knowledge.clarifying_questions("printer won't print", get_playbook("printer"))
    assert dq and any("user" in q.lower() for q in dq)
    generic = knowledge.clarifying_questions("my laptop is doing something weird", None)
    assert generic == GENERIC_QUESTIONS[:3]


def test_decision_points_appear_in_investigate_hint():
    hint = knowledge.investigate_tool_hint("my laptop is very slow", get_playbook("slow_pc"))
    assert "decision:" in hint and "bottleneck" in hint.lower()


def test_escalation_reasons_for_crashes():
    reasons = knowledge.escalation_reasons("random blue screens", get_playbook("crashes"))
    assert any("repeat" in r.lower() or "whea" in r.lower() for r in reasons)


def test_codes_block_respects_budget(monkeypatch):
    issue = "errors 1618 and 0x80070005 and bugcheck 0x0000001a MEMORY_MANAGEMENT"
    assert len(knowledge.detect_codes(issue, [])) >= 2  # several distinct codes detected
    monkeypatch.setenv("KNOWLEDGE_CODES_CHARS", "100000")
    lines = knowledge.retrieve_codes(issue, []).splitlines()
    assert len(lines) >= 2
    # A budget of exactly one line keeps one whole line, never a partial one.
    monkeypatch.setenv("KNOWLEDGE_CODES_CHARS", str(len(lines[0])))
    assert knowledge.retrieve_codes(issue, []) == lines[0]
