# Running AIops in Docker

```powershell
Copy-Item .env.example .env      # set DASHBOARD_PASSWORD, ADMIN_API_KEY, OLLAMA_MODEL, SENTINEL_PUBLIC_URL
docker compose up -d --build
```

Then open <http://localhost> and sign in with `DASHBOARD_PASSWORD` from `.env`. The first start downloads the base model and builds `aiops-brain` from it, which takes a few minutes. If you need to install without internet access, see [06-models-and-licensing.md](06-models-and-licensing.md).

## Services

| Service | What it does |
| --- | --- |
| `nginx` | The entry point, on **port 80**. It proxies pages, the API and WebSockets to the app, with one-hour timeouts for long AI calls. It rate-limits sign-in attempts (`POST /login`). |
| `sentinel` | The FastAPI app. The database (SQLite) lives in the `sentinel_data` volume. `./models` is mounted so AIops' own model files are written into the project, and `./decisions` so every AI decision and approval lands in the project folder. |
| `ollama` | The AI server. Its models live in the `ollama_data` volume. |
| `model-init` | Runs once. It loads the base model from `models/<model-name>/Modelfile` if that folder exists, otherwise it runs `ollama pull`. Then it exits. |
| `ngrok` | Publishes nginx on a public https URL when `NGROK_AUTHTOKEN` is set. Without a token it idles, and LAN access still works. Its inspector is on `127.0.0.1:4040`. |

Settings come from `.env` (`env_file`). Compose overrides `OLLAMA_HOST`, `SENTINEL_DB_PATH`, `SENTINEL_MODELS_DIR`, `DECISIONS_DIR` and `NGROK_API_URL` with container values.

## Ports

- **80 (nginx)** is the address for browsers and for agents installed from Add Agent.
- **8000 (the app)** answers only on the server itself (`127.0.0.1:8000`), for debugging. Devices and browsers use nginx on port 80, so set `SENTINEL_PUBLIC_URL=http://<server IP>` (no `:8000`). An agent installed with an old `:8000` address must re-run the install command.
- **4040** is the ngrok inspector, reachable only from this PC.

## Public URL (ngrok)

1. Copy your authtoken from <https://dashboard.ngrok.com/get-started/your-authtoken> into `NGROK_AUTHTOKEN` in `.env`.
2. Run `docker compose up -d`.
3. **Add Agent** shows the live https URL and uses it in install commands (`PUBLIC_URL_FROM_NGROK=true`).

How it works:

- The app reads the URL from ngrok's API.
- ngrok sits at a fixed address on a private network, so nginx trusts forwarding headers only from it. That gives the app the visitor's real IP and https, and the session cookie becomes `Secure`.
- Install scripts and agents send `ngrok-skip-browser-warning`, so ngrok's warning page does not get in the way.

Free ngrok URLs change every time ngrok restarts. Devices installed with an old URL then need the install command again. Set `OPEN_ENROLLMENT=false` while the URL is public: otherwise anyone who finds it can add a device.

## Things to know

- **"AIops server container" is the container, not your PC.** To diagnose the PC itself, install the agent on it from **Add Agent** (Windows: an Administrator PowerShell).
- **Memory.**
  - The `ollama` container loads the model inside Docker's VM. With little free RAM, pick `qwen3:4b` in the model switcher and close heavy apps.
  - To use Ollama installed on the host instead, set `OLLAMA_HOST: http://host.docker.internal:11434` for `sentinel` and remove the `ollama` and `model-init` services.
- **Speed.**
  - `ollama` runs with `OLLAMA_NUM_PARALLEL=1`, `OLLAMA_MAX_LOADED_MODELS=1` and flash attention, the best settings for a CPU.
  - The app preloads the model at startup, and `OLLAMA_KEEP_ALIVE` (default `30m`) keeps it in RAM between calls.
  - AI calls run one at a time, so a second diagnosis waits for the first.
- **Where the time goes.** Each AI call logs its token counts and durations, for example `Ollama aiops-brain: prompt 801 tok in 8.8s, output 72 tok in 13.4s`. See them with `docker compose logs sentinel | grep ollama_provider`.
- **Decisions.** `decisions/<date>/` holds one JSON file per AI decision or approval, plus a daily `index.md`. It holds device data and is git-ignored.
- **Logs:** `docker compose logs -f sentinel`
- **Stop:** `docker compose down` keeps the data. `docker compose down -v` also deletes the volumes: the database and the downloaded models.
- **Back up or move the data:** see [07-moving-to-another-pc.md](07-moving-to-another-pc.md).

## LAN hosting with tokenless enrollment (the default)

- Set `SENTINEL_PUBLIC_URL=http://<your-LAN-IP>` (nginx, port 80) in `.env`. Install commands then point agents at that address.
- With `OPEN_ENROLLMENT=true` (the default), the Add Agent tab has no token step: open it and run the command.
  - The install script generates a random 256-bit secret on the device, and the device registers with it.
  - Re-running the script keeps the same device and only updates the server address. Run it again whenever the server's address changes.
- The prebuilt `agent_builds/windows/DeviceHealthAgent.exe` (from `agent/build_windows.ps1`) is mounted into the container, so Windows devices do not need Python.
- Trade-off: anyone who can reach the server can attach a new device. They cannot read or control other devices, and the dashboard still needs the password. Use this only on a trusted network.

## Backups

`deploy/backup.sh` makes one file a day with the database (a consistent copy, taken while the app runs), the
`decisions/` folder and `~/app-config/.env`, and keeps 14 days. The files hold the dashboard password and device data
(owner-only). Install it on the server once:

```bash
mkdir -p ~/bin && cp deploy/backup.sh ~/bin/aiops-backup.sh && chmod 700 ~/bin/aiops-backup.sh
(crontab -l 2>/dev/null; echo "30 2 * * * $HOME/bin/aiops-backup.sh >> $HOME/backups/aiops/backup.log 2>&1") | crontab -
```

**Restore** (from the deploy folder, newest backup):

```bash
f=$(ls -t ~/backups/aiops/aiops-*.tar.gz | head -1); mkdir -p /tmp/restore && tar xzf "$f" -C /tmp/restore
docker compose stop sentinel
docker compose cp /tmp/restore/sentinel.db sentinel:/data/sentinel.db
docker compose start sentinel
```

The decision records are in `/tmp/restore/decisions/` and the settings in `/tmp/restore/app-config.env`.
Copy a backup off the server now and then (a USB drive or another machine): a dead disk takes the backups with it.

## Troubleshooting: an agent shows up, then goes offline

- **The server is down or unreachable.** The server marks a device offline after 30 s without a report. When the server is back, the agent reconnects by itself.
- **Exit code 101 / `2147942501` in Task Scheduler.**
  - This means a Python-mode agent was installed with the Microsoft Store Python, which only runs for the user who installed it, not for the SYSTEM task.
  - The installer now rejects Store Python and prefers the prebuilt `.exe`. Re-run the install command.
  - It moves the old config, removes the stale `app\` and `venv\` folders, and prints "Connected as agent-…" only after the agent's first report reaches the server.
