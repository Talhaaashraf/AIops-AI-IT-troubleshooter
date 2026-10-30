"""I8: fleet-wide correlation over the learned-cases store (read-only)."""

from datetime import datetime, timezone

import pytest

from backend import fleet_correlation
from backend.learning import store as learning_store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(learning_store, "DB_PATH", tmp_path / "fleet.db")


def _case(session_id, device_id, playbook_id, issue="problem"):
    """Insert a resolved case directly, as record_session would, with a current timestamp."""
    now = datetime.now(timezone.utc).isoformat()
    with learning_store._connect() as connection:
        connection.execute(
            """INSERT INTO learned_cases (session_id, device_id, os_type, issue, playbook_id, root_cause, evidence_json, fixes_json, outcome, created_at, updated_at)
               VALUES (?, ?, 'Windows', ?, ?, 'cause', '[]', '[]', 'resolved', ?, ?)""",
            (session_id, device_id, issue, playbook_id, now, now))
        connection.commit()


def test_cluster_needs_several_distinct_devices():
    for i, device in enumerate(["d1", "d2", "d3"]):
        _case(f"s{i}", device, "windows_update")
    clusters = fleet_correlation.fleet_clusters(min_devices=3)
    assert len(clusters) == 1
    assert clusters[0]["signature"] == "windows_update" and clusters[0]["device_count"] == 3


def test_one_device_repeating_is_not_a_cluster():
    for i in range(4):
        _case(f"s{i}", "same-device", "crashes")
    assert fleet_correlation.fleet_clusters(min_devices=3) == []


def test_note_for_counts_other_devices_plus_this_one():
    _case("a", "d2", "printer")
    _case("b", "d3", "printer")
    # Diagnosing d1 now -> d1 + d2 + d3 = 3 devices with the same playbook.
    note = fleet_correlation.note_for("d1", "printer", min_devices=3)
    assert note and note["device_count"] == 3 and "d1" not in note["other_devices"]
    # Below the threshold (only one other device) -> no note.
    assert fleet_correlation.note_for("d1", "no_internet", min_devices=3) is None


def test_note_for_ignores_missing_playbook():
    assert fleet_correlation.note_for("d1", None) is None
