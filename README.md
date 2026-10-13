# AIops — Agentic AI IT Troubleshooter

A local, Wazuh-inspired device health monitor that also **diagnoses and fixes problems on its own**. You describe an issue ("internet is slow", "laptop keeps hanging"). An AI agent running on a **free local LLM (Ollama)** then:

1. runs diagnostic tools on the chosen device (this server or any remote agent),
2. finds the root cause from the evidence,
3. proposes fixes that you apply with one click,
4. re-checks the device to confirm the issue is resolved.

It supports Windows, macOS and Linux. FastAPI and `psutil` collect telemetry, a local rules engine stores alerts in SQLite, and remote agents connect with a single install command.

## Setup (Windows / VS Code)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

### The AI brain: Ollama (free, local)

1. Install Ollama from <https://ollama.com> (or `winget install Ollama.Ollama`).
2. Pull a model that supports tool calling:

   ```powershell
   ollama pull qwen2.5:3b     # default: runs on most laptop CPUs, a fast diagnosis takes 25-60 seconds
   ollama pull qwen2.5:7b     # better reasoning; needs about 6 GB of free RAM
   ```

3. Set it in `.env`:

   ```text
   LLM_PROVIDER=ollama
   OLLAMA_MODEL=qwen2.5:3b
   ```

On a CPU-only laptop, a **Fast AI** diagnosis takes 25-60 seconds and an **Instant** one takes 5-15 seconds without any AI (see the speed modes below). `qwen2.5:7b` gives better root-cause explanations, but if it times out, use `qwen2.5:3b`, close memory-heavy apps, or raise `OLLAMA_TIMEOUT_SECONDS`. To use Groq instead (cloud), set `LLM_PROVIDER=groq` and `GROQ_API_KEY`.

Monitoring, alerts and the dashboard all work without any AI. Only troubleshooting, diagnosis and chat need it. The status of the AI is shown at the top of the **What's the issue?** tab and at `GET /api/ai/status`.

## Run with Docker

```powershell
python models/migrate_model.py qwen2.5:3b   # once: copies the model into models/qwen2.5-3b/
docker compose up -d --build                # ollama + model-init + sentinel
```

Open `http://localhost:8000`, or your LAN IP when `SENTINEL_PUBLIC_URL` is set. With `OPEN_ENROLLMENT=true`, agents attach with just the install script and no token. Details: [docs/04-docker.md](docs/04-docker.md). The design notes and decisions for the whole project are in [docs/](docs/README.md), including the self-improving `sentinel-tech` model ([docs/05-self-improving-model.md](docs/05-self-improving-model.md)) and model licensing ([docs/06-models-and-licensing.md](docs/06-models-and-licensing.md)).

## Run

```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. To let remote devices connect, bind to your LAN address instead (`--host 0.0.0.0`) and read the security section below.

## What's the issue? — automated troubleshooting

1. Open **What's the issue?** and pick the device: this server or any enrolled agent.
2. Type the problem, or click a common one: slow PC, no internet, Wi-Fi drops, disk full, high CPU/RAM, printer, updates stuck, crashes/BSOD, battery, no sound, security check, **hardware check**, **OS health**, or a full check-up.
3. Pick a speed and click **Diagnose**. The activity feed shows each step live:
   - **Baseline:** `system_overview` plus the playbook's checks run **in parallel** (CPU measurements first, so the other checks don't skew them). The AI model loads at the same time.
   - **Instant findings:** rules turn the results into concrete problems within seconds, such as "Disk C: 96% full", "Memory 94% used, biggest users: chrome.exe, vmmemWSL", "DNS failing", "CPU throttled", "2 devices with driver problems" or "battery holds 48% of its capacity". They show up before the AI has written anything.
   - **Investigate** (Deep AI only, or Fast AI when no playbook matches): the LLM calls more **read-only** diagnostics until it understands the problem (`AGENT_MAX_STEPS`, default 3).
   - **Report:** root cause, confidence, evidence, proposed fixes and manual steps.
4. Each proposed fix has an **Apply fix** button with a risk badge (low / medium / high) and a confirmation step. After a fix runs, the agent re-runs the checks and marks the session **Resolved** or **Not resolved**.

### Speed modes

| Mode | What runs | Typical time on a laptop CPU |
| --- | --- | --- |
| **Instant** | Parallel checks + rules. No AI; also used automatically when the AI is offline or does not answer. | 5-15 s |
| **Fast AI** (default, `DIAGNOSIS_MODE=fast`) | Checks + rules + one short AI report. | 25-60 s |
| **Deep AI** | The AI may run extra checks before reporting. | 1-4 min |

Fixes are verified by rules when possible: if the fix targeted a finding, AIops re-runs that check and confirms the finding is gone, with no AI call. The report shows how long the checks and the AI took.

Diagnostic tools (read-only): system overview, top processes, **hardware health** (CPU model and throttling, temperatures, fans, RAM modules, GPU/driver status, Device Manager errors, WHEA/MCE hardware errors), cleanup candidates, startup programs, internet connectivity (gateway, DNS, TCP, HTTP and captive-portal checks), ping, DNS lookup, Wi-Fi status, security posture, grouped event-log errors, recent crashes/BSODs, service status, failed services, update status, battery health, disk SMART health, printer status, performance benchmark.

Fix tools: rescan hardware (Windows), clear temp files, empty recycle bin, clear the Windows Update cache, flush DNS, renew IP, reset network stack (Windows), restart an allow-listed service, kill a process (PID + exact name), disable/restore a startup item (Windows), clear the print queue, trigger an update scan, sync time, SFC and DISM repair (Windows).

All tools live in one shared, allow-listed registry, [agent/toolkit/](agent/toolkit/), used by both the server and the agents.

## Add remote agents (one command, Wazuh-style)

Open **Add Agent**:

1. Check the server address that devices will use, e.g. `http://192.168.1.20:8000`. You can also set `SENTINEL_PUBLIC_URL` in `.env`.
2. Enter `ADMIN_API_KEY` and click **Generate token**. The token is single-use and valid for 24 hours.
3. Copy the command for the device's OS and run it there:

   ```powershell
   # Windows (PowerShell as Administrator)
   irm "http://SERVER:8000/install/windows.ps1?token=TOKEN" | iex
   ```

   ```bash
   # Linux
   curl -fsSL "http://SERVER:8000/install/linux.sh?token=TOKEN" | sudo bash
   # macOS
   curl -fsSL "http://SERVER:8000/install/macos.sh?token=TOKEN" | sudo bash
   ```

The script does the following:

- uses a prebuilt binary from `agent_builds/` if one exists; otherwise it downloads the Python agent bundle into a private venv (on Windows it installs Python via winget if it is missing),
- writes `agent_config.json`,
- registers a service: a Scheduled Task running as SYSTEM on Windows, a systemd unit on Linux, a LaunchDaemon on macOS.

The page waits until the new device connects. Uninstall commands are under **Uninstall command / manual install**.

Agents are **pull-based**: they send outbound reports and long-poll `GET /api/agents/tasks/next` for work. No inbound port is opened on the device, so agents behind NAT work too.

Optional per-device policy in `agent_config.json`:

```json
{
  "server_url": "http://192.168.1.20:8000",
  "AGENT_TOKEN": "token-from-the-dashboard",
  "nickname": "Finance laptop",
  "interval_seconds": 10,
  "allow_remediation": true,
  "max_risk": "high"
}
```

Set `"allow_remediation": false` to allow diagnostics only, or set `"max_risk": "low"` or `"medium"` to refuse riskier fixes. The device enforces this itself, whatever the server asks.

## Security model

- **No arbitrary commands.** The LLM can only name registered tools. Arguments are schema-validated, and commands run as argument lists, never through a shell. Service restarts use an allow-list, and process kills need the exact PID and name; system processes are refused.
- **The AI cannot fix things by itself.** During investigation it only sees read-only tools. Proposed fixes are validated against the registry, and each one runs only after an operator clicks **Apply**. The exception is `AUTO_FIX_MAX_RISK` (default `none`), which lets you allow, for example, `low`-risk fixes automatically.
- **Audit trail.** Every fix (device, tool, arguments, who approved it, result) is recorded. See `GET /api/troubleshoot/audit`.
- **Dashboard login.** Set `DASHBOARD_PASSWORD` (or, as a fallback, `ADMIN_API_KEY`) and all pages, APIs and WebSockets require signing in at `/login`. Agent endpoints (`/api/agents/register`, `/report`, `/tasks/*`, `/install/*`, the bundle) use their own agent or enrollment token instead.
- **LAN only.** There is no built-in HTTPS, and install scripts over plain HTTP are only safe on a trusted network. For remote sites, put a reverse proxy with HTTPS (nginx, Caddy) in front, and never expose the server directly to the internet.

## Configuration (`.env`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLM_PROVIDER` | `ollama` | `ollama` or `groq` |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama server |
| `OLLAMA_MODEL` | `qwen2.5:3b` | Model; use `qwen2.5:7b` when RAM allows |
| `OLLAMA_NUM_CTX` | `8192` | Context window |
| `OLLAMA_TIMEOUT_SECONDS` | `600` | Per-call timeout |
| `OLLAMA_KEEP_ALIVE` | `30m` | How long the model stays in RAM (reloading costs 10-30 s) |
| `GROQ_API_KEY`, `GROQ_MODEL` | — | Optional cloud fallback |
| `DIAGNOSIS_MODE` | `fast` | Default speed: `instant`, `fast` or `deep` |
| `AGENT_MAX_STEPS` | `3` | Extra AI investigation rounds in deep mode |
| `AUTO_FIX_MAX_RISK` | `none` | Auto-apply fixes up to `low` / `medium` / `high` |
| `ADMIN_API_KEY` | — | Required to generate enrollment tokens |
| `DASHBOARD_PASSWORD` | — | Enables the dashboard login |
| `SENTINEL_PUBLIC_URL` | browser URL | Server address written into install scripts |

## API overview

- Monitoring: `GET /api/diagnostics`, `/api/diagnostics/health`, `/api/diagnostics/security`, `GET|POST /api/diagnostics/performance`, `/api/diagnostics/logs`, `POST /api/diagnostics/logs/diagnose`, `GET /api/alerts`, WebSocket `/ws/monitor`
- Troubleshooting:
  - `GET /api/troubleshoot/playbooks`, `/targets`, `/tools?device_id=`, `/sessions`, `/audit`
  - `POST /api/troubleshoot` `{issue, device_id, playbook_id?}`
  - `GET /api/troubleshoot/{id}`
  - `POST /api/troubleshoot/{id}/fixes/{index}/apply`
  - WebSocket `/ws/troubleshoot/{id}`
- AI: `GET /api/ai/status`, `POST /api/agent/diagnose`, `GET|POST /api/agent/chat`, `POST /api/agent/action`
- Fleet:
  - `GET /api/agents`, `/api/agents/{id}/diagnostics|security|performance|logs|alerts|tasks`, `DELETE /api/agents/{id}`
  - `POST /api/agents/generate-token`
- Agent channel (agent token): `POST /api/agents/register`, `POST /api/agents/report`, `GET /api/agents/tasks/next`, `POST /api/agents/tasks/{task_id}/result`
- Enrollment (enrollment token): `GET /install/{windows.ps1|linux.sh|macos.sh}?token=`, `GET /api/agents/bundle?token=`, `GET /api/agents/binary/{windows|linux|mac}?token=`

## Tests

```powershell
pip install pytest
python -m pytest tests
```

## Building agent binaries (optional)

Build on each target OS (PyInstaller does not cross-compile). See [agent/README.md](agent/README.md). Place the outputs under `agent_builds/` and the install scripts will use them automatically.
