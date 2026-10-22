# AIops task tracker

AI-driven troubleshooting web app: the Ollama brain diagnoses PC software and hardware issues with deep
thinking, suggests 3-4 ranked fixes, and **never changes anything on its own**: every action is approved
by a person. Served from Docker behind nginx, published with ngrok.

Status: `[ ]` todo · `[~]` in progress · `[x]` done and verified by the `aiops-reviewer` subagent.
Plan: see the approved plan (phases 0-6). Update this file as work lands.

Deployed: phases 0-6 run in Docker (nginx on port 80; ngrok waits for NGROK_AUTHTOKEN). Phases 0-6 verified by the aiops-reviewer; the Phase 4 agent tools run on devices after the agent is reinstalled; the open [~] items need an ngrok token or the agent reinstall to verify.

## Phase 0: Tracking and review

- [x] `task.md` tracker (this file)
- [x] `aiops-reviewer` subagent (`.claude/agents/aiops-reviewer.md`, read-only)
- [x] End-to-end checks committed: `tests/e2e/api_check.py`, `tests/e2e/browser_check.py`, `tests/e2e/README.md`

## Phase 1: Hosting (Docker + nginx + ngrok)

- [x] nginx reverse proxy (`deploy/nginx/aiops.conf`): WebSockets, 3600 s timeouts for AI calls, login rate limit
- [~] `docker-compose.yml`: `nginx` on port 80, `ngrok` service (port 8000 stays open until agents are reinstalled)
- [x] Proxy headers in uvicorn so the app sees the https ngrok host
- [~] Public URL discovered from the ngrok API and shown in Add Agent
- [~] Install scripts and agent send `ngrok-skip-browser-warning`
- [x] Public hardening: token enrollment (`OPEN_ENROLLMENT=false`), secure cookie on https
- [x] `.env.example` documents `NGROK_AUTHTOKEN`, `PUBLIC_URL_FROM_NGROK`, `DECISIONS_DIR`

## Phase 2: Decisions folder

- [x] `backend/decision_log.py` writes `decisions/YYYY-MM-DD/*.json` + `index.md`
- [x] Every AI decision and every approval/rejection is recorded
- [x] `./decisions` mounted in Docker, ignored by git
- [x] `GET /api/decisions` and a read-only Decisions tab

## Phase 3: AI brain (deep thinking, suggest-only, 3-4 fixes)

- [x] `aiops-brain` model: best-effort, suggest-only system prompt + learned examples
- [x] Report returns 3-4 ranked `solutions` (AI knowledge + evidence; tool-backed ones can be run after approval)
- [x] Deep thinking for diagnoses, per-call `think`, "Think deeper" toggle elsewhere
- [x] Live reasoning stream in the session view
- [x] Auto-fix removed; test proves no action runs without approval
- [x] Solution cards: Approve & run / Mark as done / Reject, all recorded

## Phase 4: Software full removal

- [x] Agent `find_leftovers`, `quarantine_leftovers`, `restore_quarantine`, `list_quarantine`, 7-day purge
- [x] Server jobs + endpoints, audited and recorded
- [x] UI: Remove completely → leftover preview → quarantine → restore
- [x] Tested on a dummy program ("Contoso TestApp": the agent refuses names containing "aiops"), never on real software: `tests/e2e/leftover_dummy_check.py`
- [x] Agent re-checks every `winget|…` id and Linux package name against a fresh inventory before acting (review finding #14)
- [x] Review fixes: no cross-drive moves through junctions, low-confidence matches only beside a confident one, winget table parsed, restore never merges into a recreated key, agent folder always protected

## Phase 5: Performance tab (per device)

- [x] Device picker + "Run full test" job (read-only checks in 3 phases, cards fill in live, rule findings per card; offline devices refused)
- [x] OS performance, boot/startup (`boot_performance`), hardware, disks, battery
- [x] `input_devices` tool + in-browser keyboard (stuck/double-typing keys) and mouse (buttons, double-click, scroll, trail, worn-switch) testers
- [x] OS updates (`os_updates`, `install_os_updates`: high risk, only ids a fresh search still offers, never restarts) + app updates with Update / Update all
- [x] Deep AI analysis with 3-4 suggestions: a `performance` playbook diagnosis that starts from the test results (no re-run), recorded as `performance_analysis`
- [x] Review fixes: one change at a time per device (409), approvals recorded before long installs, installs always name their updates (empty list refused), boot judged on desktop-ready time, input devices grouped (touchpad collections, Intel hotkey filter), no install buttons for the server container, hidden tools never promoted to one-click fixes, stronger AST guard
- [~] Live run of the new checks on the laptop: every read-only check of toolkit 1.5.0 ran for real on the dev laptop on 2026-10-20 (24 of 25 OK; `find_leftovers` correctly refused a program that was never uninstalled). The *installed* agent there is still 1.3.0 until it is reinstalled

## Phase 6: Rebuild, reinstall, review

- [x] Agent exe rebuilt (toolkit 1.4.0), `docker compose up -d --build`
- [ ] Agent reinstalled (user, Administrator PowerShell): do it on the new PC after the move ([docs/07](docs/07-moving-to-another-pc.md)); the new installer also locks the agent folder. On the old laptop the agent's folder keeps its old permissions until the agent is reinstalled or uninstalled there
- [x] `aiops-reviewer`: a final whole-project review plus four focused re-checks. Every finding was fixed; the last round's fixes were verified with scripted race, junction and corrupt-manifest tests (installer) and unit tests
- [x] README and docs updated: README rewritten, docs/03-06 brought up to date, docs/07 (moving to another PC), docs/08 (the replan)
- [x] Review fixes:
  - the Windows agent folder is created under a random name, locked to SYSTEM and Administrators, checked, then renamed into place (the install stops if another process interferes). An existing folder is moved aside and never walked, and only agent-written quarantine batches are carried over;
  - the agent trusts only scans and quarantine manifests it wrote, and sees every reparse point as a link;
  - approvals and results are recorded even across server restarts, with an unknown outcome when a result never arrives;
  - one change at a time, also checked against the task table;
  - interrupted fixes are no longer stuck;
  - restored leftovers keep their own permissions (nothing walks or resets them), and uninstallers keep the quarantine;
  - the download button works, and last-seen uses the server clock;
  - dead code removed, versions pinned
- [x] The Adobe Acrobat uninstall at 09:29 UTC (a dashboard click) lost its record in a server restart: backfilled from the task log and labelled "recorded afterwards"

## Phase 7: Accurate, faster AI, the real server, Add Agent without an admin key

Why: the real decision records showed wrong causes with high confidence (a 90% full disk with 23 GB free blamed for hangs while
RAM was 93%), 11-13 minutes per answer, rule fallbacks, a dashboard stuck on "Waiting", and container diagnoses mistaken for
the PC. The app now deploys to an Ubuntu server (GitHub Actions, self-hosted runner, 16 GB, no GPU): **nothing runs on the dev
laptop**. Code and unit tests are checked there; live checks run on the server, done by the user (`[~]` until then).

### Push 1: dashboard, real server, Add Agent, evaluation

- [~] AI work on its own thread pool, queued diagnoses wait without holding threads (`backend/workers.py`); live monitor on its own pool with a cached snapshot; errors logged and shown instead of swallowed
- [~] "This server" is the AIops agent on the host (`backend/server_identity.py`, `AIOPS_SERVER_HOSTNAME` written by the deploy workflow); in Docker the container is no longer offered as a device to diagnose
- [~] Dashboard footer says "connected" only once data arrives, names the source, and offers "Install the agent on this server"
- [~] Add Agent: no admin key; a one-time token is created when the page opens (dashboard login is the gate); expired and surplus tokens purged; odd input gives 401, not 500
- [~] WSL/Docker VM, Ollama and the agent itself can never be closed by a fix (toolkit 1.5.0); agent reports uptime; `cpu_freq` failures no longer break reports
- [~] Default model qwen3:4b (fits a 16 GB CPU server)
- [~] Evaluation: `python -m backend.agent_brain.evaluate` scores 8 real-ticket scenarios (baseline before Push 2)
- [~] Learned-case cleanup CLI: `python -m backend.learning.admin` (remove case 32 and test tickets)

### Push 2: diagnosis accuracy and speed

- [~] Fast mode: one non-thinking call with a JSON schema (plain JSON if Ollama refuses it); Qwen3 sampling; partial-JSON recovery; deep mode thinks within a budget, then writes up
- [~] Findings split into "can explain the complaint" and "separate problems" (`playbooks.RELATED_FINDINGS`); the AI names the finding it blames; a finding that cannot cause the complaint is replaced; confidence follows the evidence
- [~] Disk severity by free space (shared by findings, alerts and health); memory culprits grouped per program with OS-specific tips; fast-mode evidence names startup items, programs and a device profile (no hostname)
- [~] Solutions: the cause first, at most one for a separate problem, tips for the device's OS; whole-word playbook matching; one retry when Ollama drops the connection; the decision record says why the AI fell back
- [~] Decision records written in the same millisecond no longer overwrite each other (an approval could vanish)
- Offline evaluation, rules only (instant): cause 8/8, not wrongly blamed 8/8, confidence 8/8, OS-appropriate steps 8/8, first solution on the cause 8/8 (was 7/8 on four checks). The model's numbers come from the server run.

### Verification on the dev laptop, 2026-10-20 (no Docker, no server, nothing listening on a port)

- Unit tests: 164 passed.
- In-process end-to-end (`verify_app.py` in the session scratchpad): the real app with a throw-away database; a simulated agent enrolled
  with a one-time token, sent a real report of the laptop and served the server's tasks. Read-only tools ran for real; every
  device-changing task (fix, update, uninstall, quarantine, restore, OS update) was approved first and only simulated, never run.
  The AI was a scripted stand-in, so this checks plumbing, grounding and records, not the model's wording. Result: 102/102.
- Dashboard UI in headless Chromium against the same in-process app (`verify_ui.py`): login, dashboard, Add Agent, Agents,
  instant and AI diagnoses, Performance full test, Software scan, Ask Technician, every other tab, phone width, no JS errors: 25/25.
- Bugs found and fixed by these runs: an agent's poll looked its token up on the event loop (a locked database could stall the
  server for 5 s); the enrollment-token cap could delete the newest token when several were made in one clock tick; the first
  CPU reading was always 0%; the keyboard tester widened the Performance tab on phones; the UI still said fast mode "thinks
  deeply"; solution cards for a separate problem now say so.
- Still to check on the server (the user): the real qwen3:4b answers and timings (`evaluate --mode fast`), Ollama accepting the
  JSON schema with thinking, nginx/ngrok, the host agent install, and the cleanup of case 32.

### Add Agent: open and install

- [~] No token step by default (`OPEN_ENROLLMENT` defaults to true): the same install command works on every Windows, Linux and macOS
  device, each device makes its own secret, and a re-install keeps the device. `OPEN_ENROLLMENT=false` brings back one-time tokens
  for a public address

### Push 3: learning hygiene

- [ ] Recall: stemming, threshold, same OS and playbook, no container cases; no Modelfile MESSAGE examples

### Push 4: Groq as an optional, clearly labelled cloud choice; docs

- [ ] Groq selectable in the model switcher after a cloud warning; local stays the default
- [ ] README, docs/04, docs/05, .env.example
