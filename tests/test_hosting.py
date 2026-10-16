from backend import public_url


def test_ngrok_https_tunnel_is_preferred():
    tunnels = {"tunnels": [{"public_url": "http://abc.ngrok-free.app"}, {"public_url": "https://abc.ngrok-free.app"}]}
    assert public_url.tunnel_url(tunnels) == "https://abc.ngrok-free.app"
    assert public_url.tunnel_url({"tunnels": []}) is None and public_url.tunnel_url(None) is None


def test_ngrok_lookup_is_skipped_when_disabled(monkeypatch):
    monkeypatch.setenv("PUBLIC_URL_FROM_NGROK", "false")
    assert public_url.ngrok_url() is None


def test_configured_address_beats_the_temporary_ngrok_url(monkeypatch):
    from types import SimpleNamespace

    from backend import main

    request = SimpleNamespace(base_url="http://localhost:8000/")
    monkeypatch.setattr(main.public_url, "ngrok_url", lambda: "https://abc.ngrok-free.app")
    monkeypatch.setenv("SENTINEL_PUBLIC_URL", "http://192.168.1.20")
    assert main._server_url(request) == "http://192.168.1.20"
    monkeypatch.setenv("SENTINEL_PUBLIC_URL", "")
    assert main._server_url(request) == "https://abc.ngrok-free.app"
    assert main._server_url(request, "http://10.0.0.5") == "http://10.0.0.5"


def test_public_paths_are_exact():
    from backend.auth import is_public_path

    assert is_public_path("/api/agents/report") and is_public_path("/api/agents/tasks/next") and is_public_path("/static/app.js")
    assert not is_public_path("/api/agents/report1/onboarding") and not is_public_path("/api/agents/registerx")
