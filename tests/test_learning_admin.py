import pytest

from backend.learning import admin
from backend.learning import store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "test.db")


def _case(session_id, device_id, issue, outcome="diagnosed"):
    store.record_session({"session_id": session_id, "device_id": device_id, "os_type": "Windows", "issue": issue,
                          "report": {"root_cause": "cause", "evidence": [], "proposed_fixes": []}})
    if outcome != "diagnosed":
        with store._connect() as connection:
            connection.execute("UPDATE learned_cases SET outcome = ? WHERE session_id = ?", (outcome, session_id))
            connection.commit()


def test_changes_are_only_shown_until_yes_is_given(capsys):
    _case("s1", "agent-aaaaaaaaaaaa", "Printer jams")
    admin.main(["delete", "--id", "1"])
    assert "would be changed" in capsys.readouterr().out and store.get_case("s1")
    admin.main(["delete", "--session", "s1", "--yes"])
    assert store.get_case("s1") is None


def test_container_lessons_stop_being_trusted():
    _case("container", "local", "Internet is slow")
    store.set_feedback("container", False, corrected_root_cause="It was the laptop's BitLocker")
    _case("device", "agent-aaaaaaaaaaaa", "Printer jams", outcome="resolved")
    assert store.is_trusted(store.get_case("container"))
    admin.main(["untrust-container", "--yes"])
    assert not store.is_trusted(store.get_case("container"))
    assert store.is_trusted(store.get_case("device"))  # a real device's verified case is kept


def test_only_test_tickets_since_the_date_are_deleted():
    _case("test", "agent-aaaaaaaaaaaa", "Disk is full")
    _case("real", "agent-aaaaaaaaaaaa", "Disk is full of photos")
    admin.main(["delete-test-cases", "--since", "2000-01-01", "--yes"])
    assert store.get_case("test") is None and store.get_case("real")
