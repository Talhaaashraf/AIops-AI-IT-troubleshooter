# Running AIops in Docker

```powershell
python models/migrate_model.py qwen2.5:3b   # once: copy the model into models/qwen2.5-3b/
docker compose up -d --build
```

Then open <http://localhost:8000> and sign in with `DASHBOARD_PASSWORD` from `.env`.

## Services

| Service | What it does |
| --- | --- |
| `ollama` | The AI server. Its models live in the `ollama_data` volume. |
| `model-init` | Runs once. It creates the base model from `models/<model-name>/Modelfile`, so no internet download is needed. If the folder is missing, it falls back to `ollama pull`. |
| `sentinel` | The FastAPI app on port 8000. Its data (SQLite) lives in the `sentinel_data` volume. `./models` is mounted so the self-improving model's files are written into the project. |

Settings come from `.env` (`env_file`). Compose overrides `OLLAMA_HOST`, `SENTINEL_DB_PATH` and `SENTINEL_MODELS_DIR` with container paths.

## Things to know

- **"AIops server container" is the container, not your laptop.** To diagnose the laptop itself, open **Add Agent** and run the Windows command on the laptop (as Administrator). The agent connects to `http://localhost:8000`, which the container port is mapped to.
- **Memory.** The `ollama` container loads the model inside Docker's VM. On a laptop with little free RAM, close heavy apps, or point the app at Ollama on the host instead. To do that, set `OLLAMA_HOST: http://host.docker.internal:11434` for the `sentinel` service and remove the `ollama` and `model-init` services.
- **Speed tuning.** The `ollama` service runs with `OLLAMA_NUM_PARALLEL=1`, `OLLAMA_MAX_LOADED_MODELS=1` and flash attention, the best settings for a CPU. The app preloads the model at startup and again when a diagnosis starts, and `OLLAMA_KEEP_ALIVE` (default `30m`) keeps it in RAM between diagnoses. Leave Ollama's thread count on auto: on the i5-1235U development laptop, auto generated 7.2 tokens/s against 3.4-5.7 with 4-10 fixed threads.
- **Where the time goes.** Each AI call logs its token counts and durations, for example `Ollama qwen2.5:3b: prompt 801 tok in 8.8s, output 72 tok in 13.4s`. View them with `docker compose logs sentinel | grep ollama_provider`.
- **Logs:** `docker compose logs -f sentinel`
- **Stop:** `docker compose down` (data is kept). `docker compose down -v` also deletes the volumes.

## Hosting on your LAN IP with tokenless enrollment

- Set `SENTINEL_PUBLIC_URL=http://<your-LAN-IP>:8000` in `.env`. Install scripts then point agents at that address instead of `localhost`. Docker already publishes port 8000 on all interfaces.
- With `OPEN_ENROLLMENT=true`, the Add Agent tab skips the token step. The install script generates a random 256-bit secret on the device, and the device registers with it. Re-running the script keeps the same device and only updates the server address, so run it again if the server's IP changes.
- A prebuilt `agent_builds/windows/DeviceHealthAgent.exe` (from `agent/build_windows.ps1`) is mounted into the container, so Windows devices do not need Python.
- Trade-off: anyone who can reach port 8000 can attach a new device. They cannot read or control other devices, and the dashboard still needs the password. Use this only on a trusted network.

## Troubleshooting: agent shows up, then goes offline

- **The server is down or unreachable.** The server marks a device offline after 30 s without a report. When the server is back, the agent reconnects by itself.
- **Exit code 101 / `2147942501` in Task Scheduler** means a Python-mode agent was built on the Microsoft Store Python. That Python only runs for the user who installed it, not for the SYSTEM task. The installer now rejects Store Python and prefers the prebuilt `.exe`. Re-run the install command. It moves the old config, removes the stale `app\` and `venv\` folders, and prints "Connected as agent-…" only after the agent's first report reaches the server.
