import pytest


@pytest.fixture(autouse=True)
def isolated_decisions(tmp_path, monkeypatch):
    """Tests run real diagnoses; their decision records must not land in the project's decisions/ folder."""
    monkeypatch.setenv("DECISIONS_DIR", str(tmp_path / "decisions"))
