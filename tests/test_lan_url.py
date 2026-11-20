"""The server's LAN IP is detected automatically and used in install commands (SENTINEL_PUBLIC_URL=auto)."""
from types import SimpleNamespace

import pytest

from backend import main, public_url


@pytest.fixture
def host_ip(tmp_path, monkeypatch):
    path = tmp_path / "lan_ip"
    monkeypatch.setenv("HOST_IP_FILE", str(path))
    monkeypatch.setattr(public_url, "ngrok_url", lambda: None)
    return path


def request(port=None):
    return SimpleNamespace(url=SimpleNamespace(port=port), base_url="http://localhost:8000/")


def test_lan_ip_comes_from_the_helper_file_and_only_private_addresses_count(host_ip):
    host_ip.write_text("10.164.68.200\n")
    assert public_url.lan_ip() == "10.164.68.200" and public_url.lan_url() == "http://10.164.68.200"
    assert public_url.lan_url(8000) == "http://10.164.68.200:8000"
    for bad in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "not-an-ip", "10.0.0.1; rm -rf /"):
        host_ip.write_text(bad)
        assert public_url.lan_ip() is None


def test_auto_uses_the_detected_ip_and_follows_a_change(host_ip, monkeypatch):
    monkeypatch.setenv("SENTINEL_PUBLIC_URL", "auto")
    monkeypatch.setattr(main, "_lan_url", lambda req: public_url.lan_url())
    host_ip.write_text("10.164.68.170")
    assert main._server_url(request()) == "http://10.164.68.170"
    host_ip.write_text("10.164.68.201")  # DHCP gave the server a new address
    assert main._server_url(request()) == "http://10.164.68.201"


def test_a_fixed_address_still_wins_and_a_stale_one_is_flagged(host_ip, monkeypatch):
    monkeypatch.setenv("SENTINEL_PUBLIC_URL", "http://10.164.68.170")
    monkeypatch.setattr(main, "_lan_url", lambda req: public_url.lan_url())
    host_ip.write_text("10.164.68.201")
    assert main._server_url(request()) == "http://10.164.68.170"
    info = main.enrollment_info(request())
    assert info["lan_url"] == "http://10.164.68.201" and "10.164.68.201" in info["lan_note"]
    host_ip.write_text("10.164.68.170")
    assert main.enrollment_info(request())["lan_note"] is None


def test_without_a_setting_or_ngrok_the_detected_ip_beats_localhost(host_ip, monkeypatch):
    monkeypatch.delenv("SENTINEL_PUBLIC_URL", raising=False)
    monkeypatch.setattr(main, "_lan_url", lambda req: public_url.lan_url())
    host_ip.write_text("192.168.1.20")
    assert main._server_url(request()) == "http://192.168.1.20"
    host_ip.unlink()
    monkeypatch.setattr(main, "_lan_url", lambda req: None)
    assert main._server_url(request()) == "http://localhost:8000"
