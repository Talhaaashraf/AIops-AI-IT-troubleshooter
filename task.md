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
- [ ] Live run of the new checks on the laptop: needs the agent reinstalled with toolkit 1.4.0 (the agent installed today is 1.3.0)

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
