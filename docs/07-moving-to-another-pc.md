# Moving AIops to another PC

AIops has two parts: the source code, which is on GitHub, and the private data, which must never be uploaded.

| What | Where it lives | How it moves |
| --- | --- | --- |
| Source code | This repository | `git clone` |
| `.env`: dashboard password, admin key, ngrok token | Project folder (git-ignored) | Private zip |
| Database `sentinel.db`: devices, diagnoses, learned cases, alerts, audit log, software inventory | Docker volume `sentinel_sentinel_data` | Exported into the private zip |
| `decisions/`: every AI decision and every approval | Project folder (git-ignored) | Private zip |
| `agent_builds/`: the agent exe that devices download | Project folder (git-ignored) | Private zip, or rebuild it |
| AI models (`qwen3:4b`, `aiops-brain`, ...) | Docker volume `sentinel_ollama_data` (about 12 GB) | Not copied. The new PC downloads `qwen3:4b` (about 2.5 GB) on first start and rebuilds `aiops-brain` from it. Download other models from the model switcher. |

The private zip is `migration/aiops-private-data-<date>.zip`. It holds your password and device data, so copy it by USB drive or another private route, never through GitHub, and delete every copy once the new PC works.

## On the old PC: make the private zip

Skip this if the zip is already made. Run these in PowerShell in the project folder while the stack is running:

```powershell
# 1. A consistent copy of the live database
docker compose exec -T sentinel python -c "import sqlite3; s = sqlite3.connect('/data/sentinel.db'); t = sqlite3.connect('/data/export.db'); s.backup(t); t.close()"
New-Item -ItemType Directory -Force migration | Out-Null
docker compose cp sentinel:/data/export.db migration/sentinel.db
docker compose exec -T sentinel rm /data/export.db

# 2. One zip with everything that is not on GitHub
$stage = Join-Path $env:TEMP "aiops-bundle"; New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item .env, migration\sentinel.db $stage; Copy-Item -Recurse decisions, agent_builds $stage
Compress-Archive -Path "$stage\*" -DestinationPath "migration\aiops-private-data-$(Get-Date -Format yyyy-MM-dd).zip"
Remove-Item -Recurse -Force $stage
```

`migration/` is git-ignored.

## On the new PC

1. **Install the tools.**
   - Docker Desktop (WSL 2 backend). Turn on *Start Docker Desktop when you sign in*.
   - Git.
   - Python 3.12, only if you want to rebuild the agent exe or run the tests.

2. **Get the code.**

   ```powershell
   git clone https://github.com/Talhaaashraf/Sentinel-LOCAL-DEVICE-AGENT.git
   cd Sentinel-LOCAL-DEVICE-AGENT
   ```

3. **Unpack the private zip into the project folder.** It contains `.env`, `sentinel.db`, `decisions/` and `agent_builds/`:

   ```powershell
   Expand-Archive <path>\aiops-private-data-2026-10-16.zip -DestinationPath .
   ```

4. **Point `.env` at the new PC.** Find its address with `ipconfig`, then set `SENTINEL_PUBLIC_URL=http://<new IP>`. Add `NGROK_AUTHTOKEN=` if you want the public link.

5. **Restore the database before the first start.** Otherwise the server creates an empty one:

   ```powershell
   docker volume create sentinel_sentinel_data
   docker run --rm -v sentinel_sentinel_data:/data -v "${PWD}:/backup" alpine cp /backup/sentinel.db /data/sentinel.db
   Remove-Item sentinel.db
   ```

   If the stack already started once, run `docker compose stop sentinel` first and `docker compose start sentinel` after.

6. **Start everything.**

   ```powershell
   docker compose up -d --build
   docker compose ps
   ```

   - The first start downloads the images and `qwen3:4b`, which takes several minutes.
   - In `docker compose ps`, every service should be healthy. `model-init` shows `Exited (0)` when it is done.
   - Open `http://localhost` and sign in with the password from `.env`.

7. **Let devices on the network reach it.** Run this once, in an Administrator PowerShell:

   ```powershell
   New-NetFirewallRule -DisplayName "AIops HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
   ```

8. **Reconnect the devices.** Agents still point at the old PC's address.
   - On each device, run the command from **Add Agent** on the new server, in an Administrator PowerShell.
   - The old device entries come over from the database and show as offline. Remove them under **Agents** once the new ones appear. Their history stays in the diagnoses, decisions and learned cases.

9. **Agent exe.** It comes in the zip. If you cloned without the zip, rebuild it with `powershell -ExecutionPolicy Bypass -File agent\build_windows.ps1` (needs Python 3.12).

10. **Optional checks.**
    - `python -m pip install -r requirements.txt`, then `python -m pytest -q`.
    - The live checks in [tests/e2e/README.md](../tests/e2e/README.md).

11. **Delete the private zip** from the USB drive and the download folder.
