import pytest

from backend import device_store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(device_store, "DB_PATH", tmp_path / "test.db")


def test_open_enrollment_accepts_a_self_generated_secret():
    secret = "x" * 43
    with pytest.raises(ValueError):
        device_store.register_device(secret, "pc-1", "Windows")
    device = device_store.register_device(secret, "pc-1", "Windows", allow_open=True)
    assert device_store.get_device_by_token(secret)["device_id"] == device["device_id"]
    again = device_store.register_device(secret, "pc-1", "Windows", allow_open=True)
    assert again["device_id"] == device["device_id"]


def test_open_enrollment_rejects_short_secrets():
    with pytest.raises(ValueError):
        device_store.register_device("short", "pc-1", "Windows", allow_open=True)
