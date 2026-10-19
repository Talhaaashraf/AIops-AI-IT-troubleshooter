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


def test_windows_installer_locks_the_agent_folder_to_system_and_administrators():
    """ProgramData lets every user create files; the SYSTEM agent's folder must not. The folder is created under
    an unpredictable name with its permissions set at creation, checked, then renamed into place (a rename fails
    if anything appeared meanwhile); an existing folder is renamed aside and never walked."""
    import pathlib

    script = (pathlib.Path(__file__).resolve().parent.parent / "backend" / "install_templates" / "windows.ps1").read_text(encoding="utf-8")
    block = script[script.index("# --- agent folder (begin) ---"):script.index("# --- agent folder (end) ---")]
    assert "$LockSddl = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'" in block and "$TrustedOwners = @('S-1-5-18', 'S-1-5-32-544')" in block
    create, check, rename, recheck = (block.index(text) for text in (
        "[IO.Directory]::CreateDirectory($staging, $security)", "Assert-LockedFolder $staging",
        "Rename-Item -LiteralPath $staging", "Assert-LockedFolder $InstallDir"))
    assert create < check < rename < recheck and "NewGuid()" in block.split("$staging =")[1].splitlines()[0]
    assert "$OldDir = \"$InstallDir.old-$([guid]::NewGuid()" in block  # not predictable
    assert "AreAccessRulesProtected" in block and "ReparsePoint" in block
    assert "icacls" not in script and "/T" not in block and "Remove-Item" not in block  # nothing walks an old folder
    assert "Test-TrustedItem $manifestPath" in block  # only quarantine batches the agent wrote
    # After a failure the old task starts only when this installer knows the old folder is back; otherwise it is disabled.
    assert "Resume-OldAgent $putBack" in block and "Resume-OldAgent $true" in block and "Disable-ScheduledTask" in block
    assert "$movedAside = $true" in block  # the rename's own success, not "the path exists again"
    assert "Test-TrustedItem (Join-Path $OldDir 'app')" in block  # no reads or deletes through a planted app junction
    assert script.index("Stop-ScheduledTask") < script.index("# --- agent folder (begin) ---") and script.index("# --- agent folder (end) ---") < script.index("Invoke-WebRequest")
