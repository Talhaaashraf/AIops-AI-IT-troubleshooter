# AIops task tracker

AI-driven troubleshooting web app: the Ollama brain diagnoses PC software and hardware issues with deep
thinking, suggests 3-4 ranked fixes, and **never changes anything on its own**: every action is approved
by a person. Served from Docker behind nginx, published with ngrok.

Status: `[ ]` todo · `[~]` implemented with verification outstanding · `[x]` verified as described in the relevant entry. Earlier phases used the `aiops-reviewer` subagent; later entries name their actual checks.
Plan: see the approved plan (phases 0-6). Update this file as work lands.

Historical deployment: phases 0-6 ran in Docker. Later phases below supersede their settings and verification status. As of the local review on 2026-11-04, server deployment and device versions have not been rechecked. See [the current project review](docs/09-sentinel-review-and-alignment.md).

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

### Production on the Ubuntu server (2026-10-23)

- [x] Server settings filled in (`~/app-config/.env` was empty, so the dashboard had no login and Add Agent could not work); model `qwen3:4b` (the server has 7.1 GB RAM); Windows agent exe in `agent_builds/windows/`
- [x] Install commands go through nginx on port 80 (`SENTINEL_PUBLIC_URL=http://10.164.68.170`); model kept loaded for 2 h
- [x] Daily backup at 02:30 (`deploy/backup.sh` as `~/bin/aiops-backup.sh`, 14 days, `~/backups/aiops/`), tested once
- [x] Old copies removed after a backup (`~/backups/aiops-old-copies-20261023.tar.gz`); the repo rename to `AIops-AI-IT-troubleshooter` moved the deploy folder
- [~] Log rotation (3 x 10 MB per container) and port 8000 only on the server: applied by the next deploy
- [~] Real-model evaluation (`evaluate --mode fast`) on the server

## Phase 8: two devices at once, Live Troubleshooting, Endpoint Threat Detection

Checked on the dev laptop (unit tests, a read-only scan of its real logs, the browser checks). Live checks on the Ubuntu
server are done by the user after the push.

### Push A: two devices at once, Live Troubleshooting

- [x] At most 2 diagnoses at once across the server (`MAX_CONCURRENT_DIAGNOSES`); more wait in line as "queued"
- [x] What's the issue? diagnoses up to 2 ticked devices, one session each, with a switcher between them
- [x] Live Troubleshooting tab: every device being diagnosed, fixed or re-checked, what it is doing now, and the last hour
- [ ] On the server: 2 devices plus a Performance analysis show 2 running and 1 "#1 in line"

### Push B: Endpoint Threat Detection

- [x] Agent `threat_scan` (toolkit 1.6.0, read-only): Kaspersky Endpoint Security, Kaspersky Network Agent, Defender, Windows
  Security / System / PowerShell; Linux sshd, sudo, user changes, ClamAV; macOS sshd and sudo. Detections grouped by file
- [x] An unreadable log says so (the Security log without admin rights read as "no events" before the probe)
- [x] Seven categories, each finding with its proof, path, suggested action path and approvable actions
- [x] Actions after approval only: rescan (report-only), quarantine (restorable 7 days), end the process, delete (file name typed);
  the server sends a scan id and an item id, the agent takes the path from its own scan file
- [x] Action chat: proposes an approval card, never runs anything; names and addresses hidden from a cloud AI
- [x] Attack words matched in Python, never inside the PowerShell script: in it, they made Kaspersky block the AIops processes
- [ ] On the server: Windows agents updated to 1.6.0 (re-run the install command; rebuild `DeviceHealthAgent.exe`)
- [ ] On the server: Scan now on the laptop, Rescan, then Quarantine and Restore on an EICAR test file

## Phase 9: Microsoft Removal tab (complete removal incl. registry, + install-blocker fix)

Checked on the dev laptop (unit tests, a read-only listing of its real Microsoft products). The destructive paths
are covered by mocked tests only; live removal on the server is the user's call.

- [x] Agent `microsoft_products` (read-only): Office/365, Store (Appx) apps, other Microsoft programs, and whether a new install is blocked
- [x] `remove_microsoft` (high): Office via Microsoft's scrubber (GetHelpCmd/SaRAcmd) when present, else Microsoft's documented manual cleanup (service, tasks, folders, registry); Store apps via Remove-AppxPackage -AllUsers + deprovision; other programs via their silent uninstaller
- [x] Every registry key and folder removed is exported/moved to the Software-tab quarantine first (restore for 7 days); scrubber path backs up the registry (program files are reinstalled, not restored)
- [x] `fix_install_blocker` (medium): clears the stale `Installer\InProgress` marker (backed up) and restarts the Windows Installer and Click-to-Run services (error 1618)
- [x] New "Microsoft Removal" tab: list with filters, per-product Remove with an approval dialog naming the registry + backup, and the install-blocker banner with a Fix button
- [x] Attack-safe: ids validated on the server; paths/keys/package names resolved on the device, never from the server; the AST guard lists the two new endpoints
- [ ] On the server: list Microsoft products on a device; remove a harmless Microsoft program and restore it from Quarantine; (optional) drop Microsoft's GetHelpCmd.exe in the agent's tools folder for the scrubber path

### Push 3: learning hygiene

- [~] Recall: common-inflection stemming, similarity threshold, same OS and playbook, container/ambiguous legacy-local exclusion, no global Modelfile lessons or MESSAGE examples. Implemented in the 2026-11-04 alignment pass; regression tests cover migration, recall, exports, and model-policy refresh. Real-model server evaluation remains outstanding.

### Push 4: Groq as an optional, clearly labelled cloud choice; docs

- [ ] Groq selectable in the model switcher after a cloud warning; local stays the default
- [ ] README, docs/04, docs/05, .env.example

## Phase 10: Troubleshooting Intelligence (senior-engineer reasoning)

Deepen the AI brain's reasoning without redesigning the app or weakening suggest-only. Full plan:
[docs/TROUBLESHOOTING_INTELLIGENCE_PLAN.md](docs/TROUBLESHOOTING_INTELLIGENCE_PLAN.md). Server/rules build the
structure; the CPU model only supplies the judgement a rule cannot. Phases I1-I6 and I8 are server-only (no
agent reinstall); I7 adds device tools (reinstall).

- [~] I1: Reasoning contract + hypotheses (server-only). `enrich_report` adds affected component, hypotheses
  (likely/possible/ruled-out), eliminated causes, tests performed, verification plan, remaining uncertainty;
  fact-vs-hypothesis clause in the brain principles; "What we considered" + verification-plan UI. Model output
  surface unchanged (cause/why/confidence/solutions). Unit tests green (222 passed, `tests/test_reasoning_contract.py`).
  On the server (user): browser render of the new report sections; `evaluate --mode fast` accuracy/timing not regressed.
- [~] I2: Knowledge package + budgeted retriever (`backend/agent_brain/knowledge/`): investigation map (§8),
  16 domain cards (§9-24), tool-knowledge (§42); `retrieve()` injects one selective, budget-capped domain card
  into the report prompt and a tool hint into deep-mode investigate. Keyed off playbook else issue keywords.
  Unit tests green (230 passed, `tests/test_knowledge.py`). Server (user): confirm `evaluate` timings hold.
- [~] I3: Error-code / Event-ID / BSOD knowledge engines. `knowledge/{error_codes,event_ids,bugchecks}.py` + a
  `detect_codes`/`retrieve_codes` that scans the issue text and evidence and injects ONLY the codes present
  (1618, Office 3001x/3018x, 0x8024/0x800F, 0xC000xxxx; Kernel-Power 41, BugCheck 1001, WHEA 17-19/47, SCM
  7000/7001, disk/Ntfs, App Error 1000/1002, benign DCOM 10016; bugchecks 0x1A/0x50/0xD1/0x0A/0x7E/0x9F/0xEF/0x139),
  each teaching how to investigate and what NOT to conclude. NTFS-filesystem false positive guarded. Unit tests
  green (236 passed, `tests/test_knowledge.py`).
- [~] I4: Playbook engine upgrade. `knowledge/playbook_extras.py` adds per-domain clarifying questions, decision
  points (rendered into deep-mode investigate), escalate-when and rollback; generic questions for unknown problems.
- [~] I5: Unknown-handling + clarifying questions + escalation. `enrich_report` adds `clarifying_questions` when no
  cause is pinned and a fact-based `escalation` note (failing disk / WHEA / crash / incomplete evidence); shown on the
  report card and recorded. §39 holds (no auto-repeat).
- [~] I6: Reasoning-based evaluation + learning upgrade. 2 new eval cases (bsod/audio), eval `hypotheses` check
  (weighed + verification plan), and curated bad->good exemplars exported to training_data.jsonl (no live-prompt cost).
- [~] I7: New read-only agent tools. `test_tcp_port` (printer 9100/515/631 + generic L4) and `driver_inventory`
  (unsigned/recent drivers on Windows; modules on Linux/macOS) in diagnostics.py; wired into the knowledge layer.
  TOOLKIT_VERSION 1.7.0->1.8.0. Bugcheck extraction not needed (codes engine reads it from crash text). Unit tests
  green (256 passed). USER: rebuild the agent + re-run install so devices get 1.8.0 (I1-I6 work without it).
- [~] I8: Fleet-wide correlation. `backend/fleet_correlation.py` groups recent learned cases by playbook across
  distinct devices; adds a 'seen on N devices' note to a diagnosis (FLEET_MIN_DEVICES=3) and `GET /api/fleet`.
  Shown on the report card, recorded in the decision log. Unit tests green (`tests/test_fleet.py`).

## Alignment review (2026-11-04)

- Reviewed the root task tracker, historical plans, reachable Git history, current backend paths, all 14 local decision JSON records, and local database/model metadata. The local database has no saved sessions, learned cases, tasks, or remediation audit rows; it does not establish the Ubuntu server's current state.
- Implemented scoped learning and persistent target origin, excluded container cases from fleet counts, and kept historical records intact. Legacy local cases with unknown origin are retained but not learned from.
- Removed globally embedded ticket examples and lessons; they remain available as eligible exports and selective recall. A build-policy fingerprint refreshes the old brain at startup when Ollama is available.
- Verification now leaves missing/failed checks unconfirmed and accepts only actual JSON booleans from AI verification, preventing false successful outcomes from entering learning.
- Aligned the Learning tab, README, model documentation, concurrency explanation, and historical-plan status with the current implementation.
- Validation: 276 tests passed (baseline 256); the 10-scenario offline Instant evaluation passed all seven scoring checks. Browser rendering and real-model Fast/Deep evaluation remain outstanding. Full details are in [docs/09-sentinel-review-and-alignment.md](docs/09-sentinel-review-and-alignment.md). No live device actions or server deployment were performed by this review.

## Ask Technician conversation fixes (2026-11-05)

- [~] Separate conversational prompt: answer the actual question in English only, use optional technical detail, ask for missing evidence, and distinguish historical snapshots from current observations. Per the user's language preference, shared AI principles and threat chat also require English answers regardless of the input language. Relevant existing domain/error-code guidance is included as reference knowledge, not device evidence.
- [~] Use the browser's conversation history; retain previous recommendations for follow-ups. Legacy API session ids remain stable and device-scoped; new sessions no longer share a default history. Bound and normalize history and reject privileged roles.
- [~] Supply snapshot age, device status and source to the model and decision record. Missing agent telemetry never falls back to another machine's data; general questions still work without a snapshot.
- [~] Clear the visible conversation when switching devices, prevent overlapping submissions, show a pending answer, and label snapshot timestamps. General answers no longer display an invented "Unknown" root cause.
- Local validation: 292 unit tests passed (16 added), JavaScript syntax passed, and isolated frontend logic checks passed for history, device switching, pending/error cleanup and historical labels. Browser rendering and real-model answer quality have not been checked. These changes are not yet deployed to the app at `http://10.164.48.204`; live validation remains outstanding.
