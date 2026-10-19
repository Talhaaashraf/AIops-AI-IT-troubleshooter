# AIops: AI IT troubleshooter

AIops monitors Windows, Linux and macOS computers and troubleshoots their software and hardware problems with a **local AI** (Ollama). You describe a problem, such as "internet is slow" or "the laptop keeps hanging". AIops then:

1. runs diagnostic checks on the chosen device, in parallel;
2. turns the results into concrete findings within seconds, using rules and no AI;
3. lets the AI think the evidence through and suggest **3-4 ranked solutions**, best first;
4. runs a solution **only after you approve it**, then checks the device again to confirm the fix.

**The AI never changes a computer by itself.** It only suggests. Every action is a button a person clicks and confirms. Every AI decision and every approval is saved in the `decisions/` folder.

## What is in the dashboard

| Tab | What it does |
| --- | --- |
| **What's the issue?** | Describe a problem or pick a common one: slow PC, no internet, Wi-Fi drops, disk full, high CPU/RAM, printer, stuck updates, crashes, battery, sound, security, hardware, OS health, performance test or full check-up. The AI's reasoning streams live, and the solutions come as cards with **Approve & run**, **Mark as done** and **Reject**. |
| **Performance** | One full test per device: live load, the busiest programs, a CPU/disk/network benchmark, start-up time and what slows it, hardware, disk health, battery, and keyboard/mouse/touchpad status. Every waiting OS and app update is listed with **Update** buttons. **Analyse with AI** asks for 3-4 ranked speed-ups. The tab also has a keyboard and mouse tester for the computer you browse from: it flags stuck keys, double-typing keys and worn mouse switches. |
| **Software** | Every installed program with its version, size and available update. **Update** uses winget, apt or dnf. **Uninstall** runs the program's own silent uninstaller. **Remove completely** also finds the folders, shortcuts and registry keys it left behind and moves the ones you tick to a quarantine you can restore for 7 days. |
| **Agents** | Enrolled devices with an **AI health report**: a 0-100 score, every detected issue and full system details. Each new device gets an automatic onboarding check-up. |
| **Dashboard, Alerts, Security, Event Logs** | Live monitoring, alert rules, the security posture (firewall, antivirus, encryption, updates, open ports) and grouped event-log errors. These work without any AI. |
| **Ask Technician** | Chat about a device's current state. |
| **Learning** | Past tickets and the lessons the AI learned from them. |
| **Decisions** | The audit trail of every AI decision and every approval or rejection. |
| **Add Agent** | A one-line install command for each OS. |

## Quick start (Docker)

You need Docker Desktop on Windows (WSL 2) or Docker Engine on Linux.

```powershell
git clone https://github.com/Talhaaashraf/Sentinel-LOCAL-DEVICE-AGENT.git
cd Sentinel-LOCAL-DEVICE-AGENT
Copy-Item .env.example .env
```

Edit `.env`:

- `DASHBOARD_PASSWORD` and `ADMIN_API_KEY`: two different long random values.
- `OLLAMA_MODEL`: `qwen3:8b` (most accurate, needs about 7 GB of free RAM) or `qwen3:4b` (for laptops with less free memory).
- `SENTINEL_PUBLIC_URL=http://<this PC's LAN IP>`: the address devices use to reach the server. Find the IP with `ipconfig`.

Then start everything:

```powershell
docker compose up -d --build
docker compose ps
```

- Open **<http://localhost>** and sign in with `DASHBOARD_PASSWORD`.
- The first start downloads the model (2.5-5 GB) and builds the `aiops-brain` model from it, so give it a few minutes.
- When it is ready, every service is healthy and `model-init` shows `Exited (0)`.

| Service | Role |
| --- | --- |
| `nginx` | Reverse proxy on **port 80**: the address for the browser and for new agents. |
| `sentinel` | The FastAPI app. Its database lives in the `sentinel_data` volume. Port 8000 is also published so agents installed before nginx keep reporting; once every agent is reinstalled, restrict it to `127.0.0.1:8000:8000`. |
| `ollama` | The local AI. Models live in the `ollama_data` volume. |
| `model-init` | Loads the base model once at startup, then exits. |
| `ngrok` | Optional: publishes nginx on a public https URL when `NGROK_AUTHTOKEN` is set. |

To reach the dashboard from outside your network, put your token from <https://dashboard.ngrok.com> into `NGROK_AUTHTOKEN` and run `docker compose up -d` again. Add Agent then shows the https URL. Free ngrok URLs change whenever ngrok restarts.

More detail: [docs/04-docker.md](docs/04-docker.md). Moving to another PC: [docs/07-moving-to-another-pc.md](docs/07-moving-to-another-pc.md). Deploying on a PC that has only Docker (no source code, Intel or ARM): [deploy/deploy.md](deploy/deploy.md).

## Add devices (agents)

1. Open **Add Agent**. Check the server address: the ngrok https URL, or `http://<LAN IP>`.
2. A one-time token is created when the page opens (the dashboard login is enough; no key to paste). It is single-use and valid for 24 hours; **New token** makes another.
3. Run the command on the device:

   ```powershell
   # Windows: PowerShell as Administrator
   irm "http://SERVER/install/windows.ps1?token=TOKEN" | iex
   ```

   ```bash
   # Linux / macOS
   curl -fsSL "http://SERVER/install/linux.sh?token=TOKEN" | sudo bash
   curl -fsSL "http://SERVER/install/macos.sh?token=TOKEN" | sudo bash
   ```

The script installs the agent from `agent_builds/` when a prebuilt binary exists, otherwise from the Python bundle. It runs as SYSTEM on Windows (a Scheduled Task), as a systemd unit on Linux and as a LaunchDaemon on macOS. The page waits until the device connects.

Agents only make outbound connections: they send reports and long-poll for work. No port is opened on the device, so devices behind NAT work too. When the server's toolkit gains new checks, some features say "needs the newer agent": re-run the install command on that device.

Optional per-device limits in the agent's `agent_config.json`:

```json
{ "allow_remediation": true, "max_risk": "high" }
```

`"allow_remediation": false` allows diagnostics only. `"max_risk": "low"` or `"medium"` refuses riskier actions. The device enforces these limits itself, whatever the server asks.

## The AI brain

- **Models.** Click the AI chip at the top right to switch models. **Download** pulls a model with a progress bar, and **Switch** frees the old one first. The choice survives restarts.

  | Model | Download | Free RAM | License | Typical answer on a laptop CPU |
  | --- | --- | --- | --- | --- |
  | `qwen3:4b` | 2.5 GB | 4 GB | Apache 2.0 | about 2 min |
  | `qwen3:8b` (default) | 5.2 GB | 7 GB | Apache 2.0 | about 3-5 min |
  | `qwen2.5:3b` | 1.9 GB | 3 GB | Qwen Research, no commercial use | about 1-1.5 min |

- **`aiops-brain`.** At startup AIops builds its own model on top of the selected one. It adds the troubleshooting principles (best effort, evidence first, suggest only, 3-4 solutions, say when unsure) and the lessons from resolved tickets. This is training by instructions and examples, not by retraining the model's weights. The Learning tab exports the dataset if you want real fine-tuning. See [docs/05-self-improving-model.md](docs/05-self-improving-model.md).
- **Deep thinking.** The model reasons before writing each diagnosis (`DIAGNOSIS_THINKING=true`), and the reasoning streams live in the session view. Chat, summaries and log analysis answer directly unless you tick **Think deeper**.
- **Speed modes** on the What's the issue? tab:

  | Mode | What runs | Typical time on a laptop CPU |
  | --- | --- | --- |
  | **Instant** | Parallel checks and rules, no AI. Also used automatically when the AI is offline or too slow. | 5-15 s |
  | **Fast** (default) | Checks, rules and one AI report with deep thinking. | 2-6 min |
  | **Deep** | The AI also runs extra read-only checks before reporting. | 5-15 min |

  AI calls run one at a time, so a diagnosis waits while another one is running.
- **Cloud option.** Set `LLM_PROVIDER=groq` and `GROQ_API_KEY` to use Groq instead of the local model.

## Security model

- **Suggest-only.**
  - While investigating, the AI sees only read-only tools.
  - A solution can run only if it names a registered fix tool, the arguments pass validation, and a person clicks **Approve & run** and confirms.
  - There is no auto-fix setting, and tools meant only for people, such as installing OS updates, are never offered by the AI.
  - A test pins every code path that can change a device.
- **No arbitrary commands.**
  - The server only sends tool ids and validated arguments: inventory ids, update ids, scan ids.
  - The agent looks everything up again on the device and runs commands as argument lists, never through a shell.
  - Service restarts use an allow-list, and process kills need the exact PID and name.
- **One change at a time.** A device runs one approved change at a time, and a second one is refused until the first finishes, even across a server restart.
- **The agent's folder is locked.**
  - On Windows the installer creates the folder under a random name, with only SYSTEM and Administrators allowed, checks it, then renames it into place. A standard user can neither plant code for the SYSTEM agent nor read its token. If another process interferes, the install stops instead.
  - An existing folder is moved aside, never walked. Some items are carried over, each into fresh locked files: the agent's identity, its remembered uninstalls, and the quarantine batches it wrote. That happens only when SYSTEM or an administrator owns them.
  - The agent only trusts scans and quarantine manifests it wrote itself.
  - Agents installed before 1.4.0 kept their token where every user could read it. Reinstall them with a new token from Add Agent.
- **Reversible removals.**
  - Leftovers of uninstalled programs go to a quarantine for 7 days, with registry keys exported first.
  - The agent's own folder, Windows and shared folders are never offered for removal.
  - Items that contain a link or junction are left for a person to remove.
- **Updates.** OS and app updates install only after you tick them and confirm. AIops never restarts a computer; it tells you when a restart is needed.
- **Records.**
  - `decisions/` holds every AI decision, approval, rejection and result as JSON, with a daily `index.md`.
  - A change is recorded twice: when it is approved, and when the device's result arrives. Both survive a server restart. If a result never arrives, the change is recorded with an unknown outcome.
  - The remediation audit log is at `GET /api/troubleshoot/audit`.
  - `decisions/` holds device data, so it is git-ignored.
- **Access.**
  - The dashboard, its API and WebSockets need the `DASHBOARD_PASSWORD` login.
  - Agents use their own tokens. Install scripts need a one-time enrollment token unless `OPEN_ENROLLMENT=true`, which is for a trusted LAN only.
  - Behind ngrok the session cookie is `Secure`, and nginx rate-limits login attempts.
  - Never publish port 8000 to the internet.

## Configuration (`.env`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `LLM_PROVIDER` | `ollama` | `ollama` or `groq` |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama address (Docker sets `http://ollama:11434`) |
| `OLLAMA_MODEL` | `qwen3:8b` | Base model, until one is picked in the model switcher |
| `OLLAMA_NUM_CTX` | `8192` | Context window |
| `OLLAMA_TIMEOUT_SECONDS` | `600` | Per-call timeout |
| `OLLAMA_KEEP_ALIVE` | `10m` (`.env.example`: `30m`) | How long the model stays in RAM (reloading costs 10-30 s) |
| `OLLAMA_MAX_PARALLEL` | `1` | AI calls that run at the same time; more than one crawls on a laptop CPU |
| `OLLAMA_THINK` | `false` | Thinking for calls that do not choose for themselves |
| `GROQ_API_KEY`, `GROQ_MODEL` | none | Optional cloud provider |
| `DIAGNOSIS_MODE` | `fast` | Default speed: `instant`, `fast` or `deep` |
| `DIAGNOSIS_THINKING` | `true` | Deep thinking for diagnosis reports |
| `AGENT_MAX_STEPS` | `3` | Extra AI investigation rounds in deep mode |
| `AGENT_AI_TIMEOUT_SECONDS` | `300` | Longest one AI call may take. Past it the rule-based diagnosis is shown. Calls with thinking use `AGENT_AI_TIMEOUT_SECONDS_DEEP` (900). |
| `ADMIN_API_KEY` | none | `X-Admin-Key` for `DELETE /api/agents/{id}`; also the login password when `DASHBOARD_PASSWORD` is empty |
| `DASHBOARD_PASSWORD` | none | Turns on the dashboard login |
| `ONBOARDING_CHECK` | `true` | AI check-up the first time a device reports |
| `OPEN_ENROLLMENT` | `false` | Enroll agents without a token (trusted LAN only) |
| `SENTINEL_PUBLIC_URL` | browser URL | Server address written into install commands |
| `AIOPS_SERVER_HOSTNAME` | written by the deploy workflow | The host's name: its AIops agent is shown as "This server" instead of the container |
| `AIOPS_SERVER_DEVICE_ID` | empty | Pins "This server" to one agent when several have the host's name |
| `AI_WORKER_THREADS`, `DEFAULT_WORKER_THREADS` | `4`, `16` | Thread pools for AI work and for everything else, kept apart so a slow model never stalls the dashboard |
| `NGROK_AUTHTOKEN` | empty | Turns on the public https URL |
| `PUBLIC_URL_FROM_NGROK` | `true` | Use the live ngrok URL in install commands |
| `LEARNED_MODEL_NAME` | `aiops-brain` | Name of AIops' own model in Ollama |
| `LEARNING_USE_MODEL` | `true` | Use that model instead of the plain base model |
| `LEARNING_REBUILD_EVERY` | `3` | Rebuild it after this many new lessons |
| `DECISIONS_DIR` | `decisions` | Where decision records are written |

## Run without Docker (development)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env          # then edit it as above, with OLLAMA_HOST=http://127.0.0.1:11434
winget install Ollama.Ollama
ollama pull qwen3:8b
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`. In this mode, "this server" in the device lists is your own computer. In Docker it is only the container: diagnose your PC by installing the agent on it.

## API overview

All routes need the dashboard login, except the agent and enrollment routes.

- **Monitoring:**
  - `GET /api/diagnostics`, `/api/diagnostics/health|security|logs`
  - `POST /api/diagnostics/logs/diagnose`
  - `GET /api/alerts`
  - WebSocket `/ws/monitor`
- **Troubleshooting:**
  - `POST /api/troubleshoot` `{issue, device_id, playbook_id?, mode?}`
  - `GET /api/troubleshoot/{id}`
  - `POST /api/troubleshoot/{id}/fixes/{index}/apply`
  - `POST /api/troubleshoot/{id}/solutions/{index}/decision` `{decision: done|rejected}`
  - WebSocket `/ws/troubleshoot/{id}`
  - `GET /api/troubleshoot/playbooks|targets|sessions|audit`
- **Performance:**
  - `POST /api/agents/{id}/performance/test`
  - `GET /api/performance/jobs/{job_id}`
  - `GET /api/agents/{id}/performance/latest`
  - `POST /api/agents/{id}/performance/analyse`
  - `POST /api/agents/{id}/os-updates/install` `{update_ids: [...]}`
- **Software:**
  - `GET /api/agents/{id}/software`
  - `POST /api/agents/{id}/software/scan|uninstall|update|leftovers|quarantine|restore|quarantine-list|leftovers/review`
  - `GET /api/software/jobs/{job_id}`
- **AI:**
  - `GET /api/ai/status`, `GET /api/ai/models`
  - `POST /api/ai/models/select|pull`
  - `GET|POST /api/agent/chat`
  - `GET /api/decisions`
  - `GET /api/learning/stats|cases|lessons`, `POST /api/learning/rebuild`
- **Fleet:**
  - `GET /api/agents`, `/api/agents/{id}/diagnostics|security|logs|alerts|tasks|health-report|onboarding`
  - `DELETE /api/agents/{id}` (also needs the `X-Admin-Key` header)
  - `POST /api/agents/generate-token`
  - `GET /api/server/identity`
- **Agent channel** (agent token):
  - `POST /api/agents/register`, `POST /api/agents/report`
  - `GET /api/agents/tasks/next`, `POST /api/agents/tasks/{task_id}/result`
- **Enrollment** (enrollment token):
  - `GET /install/{windows.ps1|linux.sh|macos.sh}?token=`
  - `GET /api/agents/bundle?token=`
  - `GET /api/agents/binary/{windows|linux|mac}?token=`

## Tests

```powershell
pip install -r requirements.txt pytest
python -m pytest -q
```

[tests/e2e/](tests/e2e/README.md) has live checks against the running stack: API flows, a headless-browser check of every tab, and a full-removal test on a dummy program.

## Building the agent

Build on each target OS, because PyInstaller does not cross-compile. On Windows run `powershell -ExecutionPolicy Bypass -File agent\build_windows.ps1`. Outputs go to `agent_builds/`, and install scripts use them automatically. See [agent/README.md](agent/README.md).

## Project notes

The plan, decisions and implementation log are in [docs/](docs/README.md), and [task.md](task.md) tracks the work phase by phase.
