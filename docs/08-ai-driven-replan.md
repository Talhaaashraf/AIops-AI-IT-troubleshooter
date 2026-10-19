# AIops replan: AI-driven troubleshooting app, served by nginx + ngrok

## Context

AIops is a working FastAPI app in Docker, with a local Ollama brain (qwen3:4b), device agents, Software/onboarding/health-report features, and 55 passing tests. The user wants it reshaped into an **AI-driven troubleshooting web app** with these changes:

- The Ollama brain reasons deeply (thinking mode) on diagnoses and always offers **3-4 ranked fixes from its own knowledge**.
- It **never changes anything on its own**. Every action is a suggestion that the user approves.
- Every AI decision is saved to a local **`decisions/`** folder.
- A **full-removal** flow for installed software deletes leftovers (folders and registry keys) after the uninstall.
- A rebuilt **Performance** tab tests the OS and hardware (keyboard, mouse, OS performance) and lists updates, each with an Update button.
- Hosting through **nginx (reverse proxy) + ngrok (public URL)**.
- A **`task.md`** tracker.
- A **reviewer subagent** that reviews changes and checks that the app works.

**Decisions taken with the user:**
- Evolve the current app; don't rewrite it.
- Deep thinking is on for diagnoses and the fix suggestions; chat and summaries stay fast. A "Think deeper" toggle turns deep thinking on per request anywhere.
- ngrok runs with an authtoken only, so it gives a random URL.
- Full removal shows a preview, then moves leftovers to quarantine, restorable for 7 days.

**Hard constraints:**
- No auto-fix code path may remain.
- The agent only ever acts on ids it discovered itself, never on paths or commands sent by the server.
- Deep diagnoses will take about 5-10 minutes on this laptop (1-2 GB of RAM free), so the UI must stream progress.

## Phase 0: Tracking, reviewer subagent, committed checks

1. **`task.md`** (repo root): a checklist of Phases 0-6 below, one checkbox per task, with an owner and a status. It's updated as work lands, and the reviewer verifies each item before it's ticked.
2. **`.claude/agents/aiops-reviewer.md`**: a project subagent, read-only (`tools: Read, Grep, Glob, Bash, PowerShell`, no Edit/Write). It's described as "review AIops changes and verify the running app; use after each task.md phase". Its checklist:
   - **Review the diff:** correctness; security (command injection, path traversal, XSS via `escapeHtml`, auth on new routes); the suggest-only rule (grep for any call of `apply_fix`/`execute(...max_risk>read)` without a user-approval endpoint); every AI decision written to `decisions/`.
   - Run `python -m pytest -q`.
   - Run `docker compose ps`: every service healthy (model-init `Exited (0)` is expected).
   - Check access through nginx (`http://localhost/login` returns 200, the WebSocket upgrades) and through the ngrok public URL.
   - Run `tests/e2e/api_check.py` and `tests/e2e/browser_check.py`.
   - Never rebuild or restart containers while an e2e run is in progress.
   - Report a PASS/FAIL table with evidence.
3. **Move my scratchpad checks into the repo:**
   - `tests/e2e/api_check.py` (from the session's `e2e_agentic.py`): Instant, Fast and Deep diagnoses, apply-fix-and-verify, chat, health report, log analysis, software, performance and decisions.
   - `tests/e2e/browser_check.py` (Playwright).
   - Neither file has a `test_` prefix, so pytest won't collect them. Add a short README on running Playwright from a short-path venv (`%TEMP%\aiops-pw`; long paths break pip on Windows) and on cleaning up learned cases after test tickets.

## Phase 1: Hosting with nginx and ngrok

- **`deploy/nginx/aiops.conf`:**
  - `upstream sentinel:8000`.
  - A WebSocket upgrade for `/ws/` (`/ws/monitor`, `/ws/troubleshoot/*`).
  - `proxy_read_timeout 900s`, since deep AI calls take minutes.
  - `X-Forwarded-For/Proto/Host` headers, gzip, `client_max_body_size 20m`.
  - A `limit_req` zone on `POST /login`.
- **`docker-compose.yml`:**
  - Add an `nginx` service (pinned `nginx:1.27-alpine`, `ports: "80:80"`, depends on sentinel being healthy).
  - Change the sentinel port to `127.0.0.1:8000:8000`, local debugging only.
  - Add an `ngrok` service (pinned `ngrok/ngrok:3` tag, `NGROK_AUTHTOKEN` from `.env`, `command: http nginx:80 --log stdout`, inspector on `127.0.0.1:4040`, `restart: unless-stopped`).
- **`Dockerfile` CMD:** add `--proxy-headers --forwarded-allow-ips="*"`, so `_server_url()` in `backend/main.py` sees the `https` ngrok host.
- **Public URL:** a new `backend/public_url.py` reads `http://ngrok:4040/api/tunnels` (cached for 30 s) when `PUBLIC_URL_FROM_NGROK=true`.
  - `_server_url()` and `GET /api/agents/enrollment` prefer it.
  - The Add Agent tab shows the live public URL and warns that random URLs change on restart, which means re-running the install command.
- **Getting past ngrok's browser warning page:**
  - Install templates and `agent/monitor_agent.py` send the `ngrok-skip-browser-warning: 1` header on every request.
  - Install templates: `backend/install_templates/windows.ps1`, `linux.sh`, `macos.sh`.
- **Security once public:**
  - Set `OPEN_ENROLLMENT=false`, so agents enroll with one-time tokens (the token flow already exists).
  - Set the session cookie `secure` when the request arrives over https.
  - Rely on the login rate limit in nginx.
- Document `NGROK_AUTHTOKEN`, `PUBLIC_URL_FROM_NGROK` and `DECISIONS_DIR` in `.env.example`.

## Phase 2: The decisions folder

- **`backend/decision_log.py`:** `record(kind, subject_id, payload)` writes `decisions/YYYY-MM-DD/HHMMSS_<kind>_<id>.json` and adds one line per decision to `decisions/YYYY-MM-DD/index.md`. Each record holds:
  - the model, whether thinking was on, and a hash of the prompt;
  - the device;
  - the evidence summary;
  - the AI output (root cause, 3-4 solutions, reasoning summary);
  - timing;
  - `approved_by` (user or none) and the outcome.
- **Recorded kinds:**
  - diagnosis;
  - fix approved or rejected, with its result and verification verdict;
  - health analysis, log analysis and chat answer;
  - software uninstall, update and leftover removal;
  - performance analysis;
  - model switch.
- **Hooks:** existing points in `backend/agent_brain/planner.py` (`_diagnose`, `apply_fix`, verify) and `backend/main.py` (`diagnose_device`, `agent_chat`, `diagnose_*_logs`, `_run_software_job`, `ai_select_model`).
- **Storage:** mount `./decisions:/app/decisions` in compose; add `decisions/` to `.gitignore` (it contains device data).
- **API and UI:** `GET /api/decisions?limit=` (newest first) and a read-only **Decisions** tab showing them as a timeline.

## Phase 3: The AI brain (deep, suggest-only, 3-4 fixes)

- **Brain model `aiops-brain`:**
  - Built at startup from the selected base model (`backend/llm/catalog.py: selected_model()`) via Ollama's create API.
  - Reuse `backend/learning/model_builder.py`, extending `BASE_SYSTEM` with: always give best effort; reason from the evidence plus its own IT knowledge; **never act, only suggest**; always return 3-4 ranked solutions; say when unsure.
  - The learned few-shot cases (the existing learning store) are appended, as `sentinel-tech` does today.
  - Honest note for the README: this is training by system prompt and examples, not weight fine-tuning. The training dataset export already exists for real fine-tuning.
- **Report schema** (`REPORT_PROMPT` and `normalize_report` in `planner.py`):
  - New `solutions: [{title, why, steps[], risk, tool_id?, confidence}]`, 3-4 items, ranked.
  - A `tool_id` is kept only if `validate_fixes()` accepts it; otherwise the solution stays manual.
  - If the model returns fewer than 3, fill from the rule fixes (`add_rule_fixes`) and playbook defaults.
  - `proposed_fixes` and `manual_steps` are derived from `solutions` for backward compatibility. Keep `ground_root_cause()` and the instant-report fallback.
- **Deep thinking:**
  - `OllamaProvider.chat(..., think=None)` overrides the global `OLLAMA_THINK` per call.
  - Thinking is on for the diagnosis report call and for Deep investigation rounds, and off for chat and summaries unless the request sets `think: true` (the "Think deeper" toggle in the UI).
  - Raise `num_predict` for thinking calls (about 1800, since thinking tokens count toward it) and the per-call deadline (`AGENT_AI_TIMEOUT_SECONDS_DEEP`, default 900).
- **Live reasoning stream:** a new `OllamaProvider.chat_stream()` (`stream: true`) feeds thinking and answer deltas to `events.publish(session_id, {"type": "thinking", ...})`, throttled to about every 2 s. The session view shows an "AI is thinking..." panel, and a short reasoning summary goes into the decision record.
- **Suggest-only, enforced:**
  - Delete `_auto_fix` and `auto_fix_max_risk()` (`planner.py:106,574`), and the `AUTO_FIX_MAX_RISK` setting and UI label.
  - Every action needs an explicit approval endpoint call plus a confirmation dialog that states what will happen.
  - Add a test asserting that no code path calls `apply_fix` other than the approval endpoint.
- **UI ("What's the issue?"):**
  - Solution cards (rank, why, steps, risk badge), each with **Approve & run** (automatable) or **Mark as done** (manual).
  - A "Think deeper" toggle and the live thinking panel.
  - Rejecting a solution is also recorded.

## Phase 4: Software full removal (preview, then quarantine)

- **New agent tools in `agent/toolkit/software.py`:**
  - **`find_leftovers(id)`** (read): looks up the entry again and scans:
    - Program Files and Program Files (x86);
    - ProgramData;
    - every user's AppData Roaming/Local/LocalLow;
    - Start Menu shortcuts;
    - registry `Software\<Publisher>\<Product>` and `Software\<Product>` under HKLM, WOW6432Node and HKU.
    - It matches on the normalized product, publisher and install location.
    - It excludes system and shared paths (Windows, System32, Common Files, Microsoft, WindowsApps, the agent's own folder) and anything inside another installed program's `InstallLocation`.
    - It returns candidates with a candidate id, path, size, last-modified time and match reason, and caches them on the agent.
  - **`quarantine_leftovers(candidate_ids[])`** (high risk): accepts **only cached candidate ids**.
    - Folders move to `C:\ProgramData\SentinelAgent\quarantine\<ts>\`.
    - Registry keys are exported with `reg export` (backed up to a `.reg` file), then deleted.
    - A `manifest.json` is written for restore.
  - **`restore_quarantine(batch_id)`** (medium risk).
  - **`list_quarantine`** (read).
  - A daily purge of batches older than 7 days in `agent/monitor_agent.py`.
- **Linux:** removal with apt `purge`, plus leftovers under `~/.config/<pkg>` and `~/.local/share/<pkg>`, through the same flow.
- **Server:** endpoints `POST /api/agents/{id}/software/leftovers`, `.../software/quarantine` and `.../software/restore`, run as jobs through the existing `_start_software_job()` and `_run_software_job()` in `backend/main.py`. Each one is audited and recorded in the decision log.
- **UI flow in the Software tab:**
  - **Remove completely** runs the uninstall, then the leftover scan.
  - A checklist preview shows sizes and reasons, all ticked by default except low-confidence items.
  - **Move to quarantine** with confirmation.
  - A Quarantine list with Restore buttons.
  - Optional **Ask AI to review leftovers**, which flags shared or risky items as advice only.

## Phase 5: The Performance tab (per device)

- Replace the current server-only Performance tab with a device-scoped page: a device picker, reusing `fillDeviceSelect()` in `frontend/app.js`. **Run full test** starts one job that runs the read tools in parallel through `executor.execute`. The sections:
  - **OS performance:** `performance_benchmark` (existing); boot time and startup impact (new `boot_performance`: last boot duration from the Diagnostics-Performance event 100, uptime, startup item count via `startup_programs`).
  - **Hardware:** `hardware_health`, `disk_health` and `battery_health` (all existing).
  - **Input devices:** a new agent tool `input_devices` lists keyboard, mouse and touchpad devices with their driver status, from `Win32_PnPEntity` PNPClass Keyboard/Mouse/HIDClass, or `/proc/bus/input` on Linux.
  - **Browser testers** for the computer you're browsing from, labelled as such:
    - Keyboard: an on-screen layout that lights up keys as they're pressed and flags keys that never registered or seem stuck.
    - Mouse: left, right and middle click, double-click, scroll, and movement or jitter.
  - **Updates:** new `os_updates` (read; Windows Update COM search via PowerShell, apt/dnf on Linux) plus app updates from `installed_software`. Buttons: **Update** per app (existing `update_software`) and **Install OS updates** (new `install_os_updates`, high risk, confirmation, reboot warning).
  - **AI analysis** (deep): what is slowing this PC, with 3-4 ranked suggestions as solution cards, recorded in the decision log.
- New tools are registered with `ai_visible=False` where their output is large, following the existing pattern in `agent/toolkit/registry.py`. Bump `TOOLKIT_VERSION` to 1.3.0. Older agents get the existing "agent too old" message (`OLD_AGENT_MESSAGE` in `main.py`).

## Phase 6: Rebuild, reinstall, review

- Rebuild the agent exe with `agent/build_windows.ps1`, then `docker compose up -d --build`.
- The user re-runs the Add Agent install command as Administrator, using the ngrok or LAN URL.
- Run the **aiops-reviewer** subagent over the whole change set, fix what it finds, re-run it until it's clean, then tick everything in `task.md`.
- Update `README.md` and `docs/04-docker.md` with the nginx/ngrok setup, the decisions folder, suggest-only behavior and the new tabs.

## Files (main)

| File | Status |
|---|---|
| `task.md` | new |
| `.claude/agents/aiops-reviewer.md` | new |
| `tests/e2e/api_check.py`, `tests/e2e/browser_check.py` | new |
| `deploy/nginx/aiops.conf` | new |
| `docker-compose.yml`, `Dockerfile`, `.env.example`, `.gitignore` | changed |
| `backend/decision_log.py`, `backend/public_url.py` | new |
| `backend/main.py` | changed: routes, hooks, jobs |
| `backend/agent_brain/planner.py` | changed: solutions schema, deep thinking, streaming, auto-fix removed |
| `backend/llm/ollama_provider.py` | changed: per-call `think`, `chat_stream` |
| `backend/learning/model_builder.py` | changed: aiops-brain |
| `agent/toolkit/software.py` | changed: leftovers, quarantine |
| `agent/toolkit/updates.py`, `agent/toolkit/input_devices.py` | new |
| `agent/monitor_agent.py` | changed: ngrok header, quarantine purge |
| `frontend/index.html`, `frontend/app.js`, `frontend/style.css` | changed: solution cards, thinking panel, Performance tab, removal flow, Decisions tab |

## Verification

- **Unit tests:**
  - solutions normalization (3-4 items, invalid tool ids become manual);
  - no auto-apply path;
  - decision files written;
  - the leftover matcher excludes shared and system paths and other programs' folders;
  - quarantine accepts only cached ids;
  - restore round-trip on a temp folder and registry test key;
  - winget/Windows Update output parsing;
  - `public_url` parsing;
  - nginx config passes `nginx -t` in its container.
- **Live checks:**
  - `curl http://localhost/login` returns 200 through nginx; the WebSocket works through nginx (browser check).
  - The ngrok URL from `:4040/api/tunnels` serves the login page and agent API calls with the skip header.
  - A Deep diagnosis on the laptop finishes (about 5-10 min) with 3-4 solutions, streams thinking, and creates `decisions/<date>/...json`. Approving one solution runs it and records approval plus verification.
- **Full removal, tested safely:** on a **dummy program** (a test uninstall registry entry plus folders created by the test, e.g. "AIops Test App"), never on real software without asking. The flow: scan, quarantine, restore.
- **Performance tab:** Run full test returns every section; the keyboard and mouse testers react in the browser check; updates are listed.
- **The aiops-reviewer subagent** runs everything above and reports all PASS.
