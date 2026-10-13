> Approved plan from the planning session (2026-10-09). Kept verbatim for reference; see 03-implementation-log.md for what changed during the build.

# AIops → Agentic AI IT Troubleshooter (Ollama brain)

## Context
AIops today is a **read-only monitor**: FastAPI + psutil collect telemetry, a rules engine raises alerts, and Groq (cloud, needs API key) only *explains* data in one shot. Remote agents (`agent/monitor_agent.py`) only **push** reports — the server cannot send them work, and nothing gets fixed.

Goal: turn it into an **agentic troubleshooter** that runs on a free local LLM (Ollama). The user types a problem ("internet slow", "laptop hang ho raha hai"), the AI agent decides which diagnostic tools to run, gathers evidence, finds the root cause, proposes fixes, and applies them on an **Action button** click — on the local machine or any remote device enrolled Wazuh-style via a one-line install script. Purpose: automate the diagnose process and save technician time.

Machine facts: Ollama not installed yet, 16 GB RAM, no NVIDIA GPU → CPU inference, so default to a 7B tool-calling model.

## Architecture (target)
```
Dashboard ──"What's the issue?"──► /api/troubleshoot (session)
                                      │
                         Agent loop (backend/agent_brain/)
                         Ollama /api/chat with tools  ◄── LLM_PROVIDER=ollama|groq
                                      │ tool_call
                                      ▼
                         Executor ──local──► toolkit (in-process)
                                  └─remote─► task queue (SQLite) ◄─poll── monitor_agent.py ──► toolkit
                                      │
               findings + proposed fixes ──► UI [Apply fix] ──► same executor ──► re-verify
```

## Phase 1 — LLM provider abstraction + Ollama
- New `backend/llm/` with `base.py` (interface `chat(messages, tools=None, json=False)`), `ollama_provider.py` (HTTP to `OLLAMA_HOST`, default `http://127.0.0.1:11434`, `/api/chat` with `tools`, `format: "json"`), `groq_provider.py` (move `_client`/`_completion` from `backend/groq_agent.py`).
- `.env`: `LLM_PROVIDER=ollama`, `OLLAMA_MODEL=qwen2.5:7b` (best free tool-calling at 7B; fallback `llama3.2:3b` for low-RAM), `OLLAMA_HOST`.
- Refactor `backend/groq_agent.py` → `backend/ai_technician.py` keeping `diagnose`, `diagnose_logs`, `chat`, `_parse_diagnosis`, `_parse_chat_reply` but calling the provider. `is_ai_available()` pings Ollama `/api/tags` and checks the model is pulled.
- Add `ollama` health to `GET /api/agent/chat` status + README setup (`winget install Ollama.Ollama`, `ollama pull qwen2.5:7b`).

## Phase 2 — Shared toolkit (diagnose + fix registry)
Today checks are duplicated in `backend/` and `agent/` (`security_checks.py`, `performance_checks.py`, `event_logs.py`). Create one package **`agent/toolkit/`** used by both backend (local executor) and the agent binary:
- `registry.py`: `Tool(id, description, params_schema, risk: "read"|"low"|"medium"|"high", os: set, fn)`. Exposes `list_tools(os)` → Ollama tool JSON schemas, and `run(tool_id, args)` with strict param validation. **No arbitrary shell, ever** — only registered IDs with typed args.
- `diagnostics/` (risk=read): reuse `collect_report` from `agent/monitor_agent.py`, `collect_security_report`, `collect_performance_report`, `collect_event_log_report`, and actions from `backend/actions.py` (`list_top_processes`, `check_disk_cleanup_candidates`, `check_startup_programs`, `check_network_details`). Add: `ping_host`, `dns_lookup`, `check_internet` (gateway/DNS/HTTP stages), `list_services` / `service_status`, `pending_updates`, `disk_smart_health`, `battery_health`, `printer_spooler_status`, `wifi_signal`, `recent_crashes` (BSOD/kernel panic/OOM from logs).
- `remediation/` (risk low→high, per-OS implementations Windows/Linux/macOS): `clear_temp_files`, `empty_recycle_bin`, `flush_dns`, `renew_ip`, `reset_winsock` (high), `restart_network_adapter`, `restart_service(name ∈ allowlist)`, `kill_process(pid)` (medium, refuses system PIDs), `disable_startup_item`, `restart_print_spooler`, `run_sfc_scan` / `dism_restore` (high, long-running), `trigger_windows_update_scan`.
- Every tool returns `{ok, data, summary}`; remediation also returns `{changed: bool, rollback_hint}`.
- Backend's duplicate modules become thin re-exports, then removed.

## Phase 3 — Agent brain (the agentic loop)
New `backend/agent_brain/`:
- `planner.py`: ReAct-style loop. System prompt = senior IT technician; inputs: user issue + device OS + latest snapshot summary + recent alerts (`backend/alert_store.get_alerts`). Model may only call **read-risk tools** autonomously (max ~12 steps, per-step timeout). It ends with a JSON `final_report`: `{issue_summary, root_cause, confidence, evidence[], severity, proposed_fixes:[{tool_id, args, risk, why}], manual_steps[]}`.
- Proposed fixes are validated against the registry (unknown tool/args dropped) — the LLM never executes fixes itself.
- `session_store.py` (SQLite, same DB pattern as `backend/device_store.py`): tables `troubleshoot_sessions` (id, device_id|"local", issue, status, final_report, created_at) and `troubleshoot_steps` (session_id, idx, tool_id, args, result, thought).
- After a fix is applied: auto **re-verify** run (agent re-runs the relevant diagnostics and marks the issue Resolved / Not resolved).
- Settings: `AUTO_FIX_MAX_RISK=none` (default: every fix needs the button); can be set to `low` to auto-apply safe fixes like temp cleanup / DNS flush.
- Built-in playbooks (`playbooks.py`): presets "Slow PC", "No/slow internet", "Disk full", "High CPU/RAM", "Wi-Fi drops", "Printer not working", "Windows Update stuck", "Frequent crashes", "Battery drain", "Security check" — each = seed prompt + preferred tool hints so the small model stays focused.

## Phase 4 — Remote command channel (Wazuh-style)
Agents stay **pull-based** (works through NAT/firewalls, no inbound port):
- `device_store.py` new table `agent_tasks` (task_id, device_id, tool_id, args, status queued|running|done|failed|expired, result, session_id, created_at, approved).
- Endpoints (Bearer agent token via existing `authenticated_device`): `GET /api/agents/tasks/next` (long-poll ~25s), `POST /api/agents/tasks/{id}/result`.
- `agent/monitor_agent.py`: background thread polls tasks, runs via `toolkit.registry.run`, posts results. Agent-side config `allow_remediation: true|false` and `max_risk` — device owner can refuse fixes regardless of server.
- Executor in backend: local → in-process; remote → enqueue task and await result (asyncio future, timeout → step marked "device unreachable").
- Audit log of every remediation (who clicked, device, tool, args, result) shown in Alerts/History.

## Phase 5 — One-line agent enrollment ("Add Agent" tab)
- `GET /install/windows.ps1?token=…`, `/install/linux.sh?token=…`, `/install/macos.sh?token=…` — server renders scripts from templates with server URL + one-time token (`create_pending_token` already exists).
- Scripts: download agent bundle (`GET /api/agents/download/{platform}` — binary if built in `agent_builds/`, else a zip of `agent/` + venv + `pip install -r agent_requirements.txt`), write `agent_config.json`, install service (reuse logic in `agent/install_windows.ps1` Scheduled Task → upgrade to run as SYSTEM at startup; `install_linux.sh` systemd; `install_mac.sh` launchd), start it.
- Usage shown in UI with copy buttons:
  - Windows (admin PowerShell): `irm "http://SERVER:8000/install/windows.ps1?token=XXX" | iex`
  - Linux: `curl -fsSL "http://SERVER:8000/install/linux.sh?token=XXX" | sudo bash`
  - macOS: `curl -fsSL "http://SERVER:8000/install/macos.sh?token=XXX" | sudo bash`
- Uninstall scripts too. Device appears in Agents tab automatically on first report.

## Phase 6 — Dashboard UI (`frontend/index.html`, `frontend/app.js`)
- New tab **"Troubleshoot / What's the issue?"**: device selector (This PC + online agents), free-text issue box, playbook quick buttons, **Diagnose** button. Live step timeline streamed over WebSocket `/ws/troubleshoot/{session_id}` ("Checking DNS… ✓", "Top CPU: chrome.exe 87%"). Result card: root cause, confidence, evidence, and each proposed fix as an **Action button** with risk badge + confirm dialog → then re-verify result.
- New tab **"Add Agent"**: generate token, OS picker, one-liner commands with copy, download links, live "waiting for device…" indicator.
- Session history list (past troubleshoots per device).
- Existing "Ask Technician" chat moves onto the provider abstraction (Ollama).

## Security guardrails (must-haves)
- LLM output never reaches a shell; only allow-listed tool IDs with schema-validated args.
- Fix execution requires dashboard auth (existing `auth.py` session) + explicit click (unless `AUTO_FIX_MAX_RISK` raised).
- Agent-side `allow_remediation`/`max_risk` override; tasks expire after N minutes; one-time enrollment tokens (24h, already implemented).
- README warning stays: LAN only, put HTTPS reverse proxy in front for remote sites (install scripts over plain HTTP are only safe on trusted LAN).

## Critical files
Modify: `backend/main.py`, `backend/groq_agent.py`→`backend/ai_technician.py`, `backend/actions.py`, `backend/device_store.py`, `agent/monitor_agent.py`, `agent/install_*.{ps1,sh}`, `agent/build_installer.py`, `frontend/index.html`, `frontend/app.js`, `frontend/style.css`, `requirements.txt`, `.env.example`, `README.md`.
New: `backend/llm/`, `backend/agent_brain/`, `agent/toolkit/`, `backend/install_templates/`, `tests/`.

## Verification
1. `ollama pull qwen2.5:7b`; `uvicorn backend.main:app --reload`; status endpoint shows model ready.
2. Unit tests (`pytest`): registry rejects unknown tools/bad args; planner with a mocked provider produces a valid `final_report`; task queue lifecycle.
3. Local E2E: Troubleshoot tab → "Disk full" playbook → steps stream → fix "Clear temp files" button → re-verify shows freed space.
4. Remote E2E: run Windows one-liner in a second terminal (or VM/WSL for Linux script) → device appears → diagnose "No internet" on it → `flush_dns` task executes on agent, result back in UI, audit entry recorded.
5. Set agent `allow_remediation:false` → fix is refused by the agent.

## Build order
Phase 1 → 2 → 3 (local-only working end-to-end) → 6 (Troubleshoot tab) → 4 → 5 (+ Add Agent tab). Each phase is shippable on its own.
