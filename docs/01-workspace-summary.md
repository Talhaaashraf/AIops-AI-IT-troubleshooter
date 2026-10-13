# Workspace summary (before the AI work)

AIops started as a Wazuh-style **device health monitor** for Windows, macOS and Linux, about 3,700 lines of code.

- **Backend (FastAPI).** `backend/main.py` collected telemetry with `psutil` every 5 seconds and streamed it over the `/ws/monitor` WebSocket. Separate modules ran security checks (firewall, antivirus, disk encryption, patches, listening ports), an on-demand performance benchmark, and OS event-log collection.
- **Rules engine.** `backend/rules_engine.py` turned telemetry into alerts stored in SQLite (`alerts.db`).
- **AI.** `backend/groq_agent.py` called **Groq cloud** (API key required) to explain a snapshot in one shot. It was not agentic: it could not call tools or fix anything.
- **Actions.** Four read-only actions in `backend/actions.py`.
- **Remote agents.** `agent/monitor_agent.py` registered with a token and **pushed** reports. The server could not send work back. Install scripts and PyInstaller build scripts existed.
- **Frontend.** Seven tabs (Dashboard, Alerts, Security, Performance, Event Logs, Ask Technician, Agents) and an optional password login.
- **Duplication.** `security_checks.py`, `performance_checks.py` and `event_logs.py` existed as identical copies in both `backend/` and `agent/`.

## The goal

1. Make AIops **fully agentic**, with a **free Ollama model** as the brain: it receives a problem, diagnoses the laptop, finds the issue, and fixes it.
2. Offer built-in **IT troubleshooting options** (common problems).
3. Add a **"What's the issue?"** tab: you type the issue, it gets fully diagnosed, and you get **action buttons** to fix it.
4. Add an agents tab with a **one-line script** (PowerShell, bash or macOS bash) that enrolls a machine so it can be troubleshot remotely, like Wazuh agents.
5. Purpose: **automate the diagnosis process and save technician time**.

Later requests:

- run the app in **Docker**,
- collect the discussion in a folder (this one),
- **fully update the UI**,
- **migrate the model** into a project folder named after the model,
- build a separate **self-improving model** that learns from resolved queries.
