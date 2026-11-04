"""Past tickets must be relevant evidence, not global instructions for unrelated devices."""

import json
import sqlite3

import pytest

from backend import fleet_correlation
from backend.learning import model_builder, store


@pytest.fixture(autouse=True)
def isolated_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "memory.db")
    monkeypatch.setattr(model_builder, "LEARNED_DIR", tmp_path / "brain")
    monkeypatch.setattr(model_builder, "VERSION_FILE", tmp_path / "brain" / "version.json")
    monkeypatch.delenv("SENTINEL_IN_DOCKER", raising=False)


def case(session_id, issue="Printer stops printing", os_type="Windows", playbook="printer",
         device="agent-one", resolved=True):
    return store.record_session({
        "session_id": session_id, "device_id": device, "os_type": os_type,
        "issue": issue, "playbook_id": playbook,
        "report": {"root_cause": "Stuck print queue", "evidence": ["Queue blocked"],
                   "proposed_fixes": [{"tool_id": "clear_print_queue", "status": "applied"}]},
        "verify": {"resolved": resolved},
    })


def test_recall_requires_same_os_and_selected_playbook():
    case("windows")
    case("linux", os_type="Linux")
    case("different-domain", playbook="no_internet")
    case("unknown-os", os_type=None)
    recalled = store.find_similar("Printer stops printing", "windows", playbook_id="printer")
    assert [item["session_id"] for item in recalled] == ["windows"]


def test_weak_overlap_and_previous_root_cause_do_not_create_a_match():
    case("weak", issue="Printer network hostname configuration discovery firewall connection setup")
    case("unrelated", issue="Spooler service crashes")
    with store._connect() as connection:
        connection.execute("UPDATE learned_cases SET root_cause = 'Printer toner smudges' WHERE session_id = 'unrelated'")
    assert store.find_similar("Printer toner smudges", "Windows", playbook_id="printer") == []


def test_common_ticket_inflections_match():
    case("past", issue="Printers stopped printing")
    recalled = store.find_similar("Printer stops printing", "Windows", playbook_id="printer")
    assert recalled[0]["session_id"] == "past"
    assert store.tokenize("crashes crashed") == ["crash", "crash"]
    assert store.tokenize("freezes freezing") == ["freez", "freez"]


def test_unknown_playbook_does_not_recall_a_known_different_domain():
    case("printer", issue="strange intermittent behaviour")
    assert store.find_similar("strange intermittent behaviour", "Windows") == []


def test_legacy_cases_infer_playbook_from_the_complaint():
    case("legacy", issue="Printer not working", playbook=None)
    assert store.find_similar("Printer not working", "Windows", playbook_id="printer")


def test_container_provenance_survives_moving_database_to_a_native_host(monkeypatch):
    monkeypatch.setenv("SENTINEL_IN_DOCKER", "1")
    container = case("container", device="local")
    case("endpoint")
    monkeypatch.delenv("SENTINEL_IN_DOCKER")
    # Refreshing a saved result must not rewrite where the original evidence came from.
    refreshed = case("container", device="local")
    assert refreshed["target_kind"] == container["target_kind"] == "container"
    assert not store.is_trusted(refreshed)
    assert [item["session_id"] for item in store.find_similar("Printer stops printing", "Windows")] == ["endpoint"]
    assert "container" not in model_builder.export_training_data([refreshed])
    assert model_builder.lessons([refreshed]) == []


def test_real_native_local_device_remains_eligible():
    native = case("native", device="local")
    assert native["target_kind"] == "local" and store.is_trusted(native)
    assert store.find_similar("Printer stops printing", "Windows")


def test_legacy_database_migration_preserves_cases_and_excludes_ambiguous_local_origin():
    with sqlite3.connect(store.DB_PATH) as connection:
        connection.execute("""CREATE TABLE learned_cases (
            id INTEGER PRIMARY KEY, session_id TEXT UNIQUE NOT NULL, device_id TEXT, os_type TEXT,
            issue TEXT NOT NULL, playbook_id TEXT, root_cause TEXT, evidence_json TEXT, fixes_json TEXT,
            outcome TEXT NOT NULL, feedback TEXT, feedback_note TEXT, corrected_root_cause TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        connection.execute("""INSERT INTO learned_cases
            (session_id, device_id, os_type, issue, outcome, created_at, updated_at)
            VALUES ('legacy', 'local', 'Linux', 'Printer stops printing', 'resolved', '2026-10-19', '2026-10-19')""")
    legacy = store.get_case("legacy")
    assert legacy["outcome"] == "resolved" and legacy["target_kind"] is None
    assert not store.is_trusted(legacy)
    case("new")
    assert len(store.list_cases()) == 2


def test_learned_fix_success_rate_keeps_failures_and_excludes_other_platforms():
    case("success-1")
    case("success-2")
    for index in range(3):
        case(f"failure-{index}", resolved=False)
        case(f"linux-{index}", os_type="Linux")
    assert store.learned_fixes_for("Printer stops printing", "Windows", playbook_id="printer") == []


def test_containers_and_ambiguous_legacy_local_cases_do_not_inflate_fleet(monkeypatch):
    monkeypatch.setenv("SENTINEL_IN_DOCKER", "1")
    case("container", device="local")
    case("legacy", device="local-server")
    with store._connect() as connection:
        connection.execute("UPDATE learned_cases SET target_kind = NULL WHERE session_id = 'legacy'")
    case("endpoint", device="agent-one")
    assert fleet_correlation.fleet_clusters(min_devices=2) == []
    assert fleet_correlation.note_for("agent-two", "printer", min_devices=3) is None


@pytest.mark.parametrize("fingerprint, created", [("old-policy", True), (None, False)])
def test_old_or_failed_model_policy_triggers_refresh(monkeypatch, fingerprint, created):
    model_builder.LEARNED_DIR.mkdir()
    model_builder.VERSION_FILE.write_text(json.dumps({
        "base_model": "qwen3:4b", "system_fingerprint": fingerprint or model_builder.system_fingerprint(),
        "created_in_ollama": created,
    }))
    monkeypatch.setattr(model_builder, "base_model_name", lambda: "qwen3:4b")
    monkeypatch.setattr(model_builder, "_installed_models", lambda host: {model_builder.learned_model_name()})
    calls = []
    monkeypatch.setattr(model_builder, "build", lambda reason: calls.append(reason) or {"rebuilt": True})
    assert model_builder.ensure_brain() == {"rebuilt": True}
    assert calls == ["startup"]
