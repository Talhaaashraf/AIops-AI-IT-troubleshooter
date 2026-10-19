# Implementation log

## Phase by phase

| Phase | Result | Where |
| --- | --- | --- |
| 1. LLM provider layer | Ollama is the default; Groq is an optional fallback. Errors are surfaced to the UI. | `backend/llm/`, `backend/ai_technician.py` |
| 2. Shared toolkit | 18 read-only diagnostics and 15 fixes in one allow-listed registry, used by both the server and the agents. The duplicated check modules were merged. | `agent/toolkit/` |
| 3. Agent brain | Runs baseline playbook checks, then LLM investigation (read-only tools only), then a JSON report with validated fix proposals, then fix-on-click, then re-verification. | `backend/agent_brain/` |
| 4. Remote tasks | Pull-based task queue: agents long-poll, run tools from their own registry, and apply their own `allow_remediation` / `max_risk` policy. | `backend/task_queue.py`, `agent/monitor_agent.py` |
| 5. One-line enrollment | `irm … \| iex` and `curl … \| sudo bash` scripts serve a binary or a Python bundle and install a service. | `backend/install_templates/` |
| 6. UI | "What's the issue?" tab with a live step feed and fix buttons; "Add Agent" tab with copyable commands. | `frontend/` |
| Docker | Compose stack with `ollama`, `model-init` and `sentinel`. | `Dockerfile`, `docker-compose.yml` |
| Model folder | The base model is migrated into `models/qwen2.5-3b/` (GGUF, Modelfile, LICENSE). | `models/migrate_model.py` |
| Self-improving model | Learned-case memory, feedback, and the `sentinel-tech` model rebuilt from lessons. | `backend/learning/`, `models/sentinel-tech/` |
| UI redesign | New design system with light/dark theme, ring gauges, icon sidebar, AI status chip, Learning tab, and feedback buttons. | `frontend/` |

## Safety design

- The LLM never reaches a shell. It can only name registered tools, and their arguments are validated against a schema.
- During investigation the model only sees **read** tools. Fixes are proposals that run when an operator clicks **Apply**. (The `AUTO_FIX_MAX_RISK` auto-apply option from this first version was removed in the replan below: nothing runs without a person's approval.)
- `restart_service` uses an allow-list. `kill_process` needs both the PID and the exact process name, and refuses system processes.
- Every fix is written to the remediation audit log (`GET /api/troubleshoot/audit`).

## Bugs found in the original code along the way

1. **Agents were blocked by the dashboard login.** With `DASHBOARD_PASSWORD` set, `/api/agents/register` and `/report` returned 401 because the session middleware covered them. Agent endpoints are now public, and each checks its own token.
2. **Every agent died after 24 hours.** The enrollment token's 24-hour expiry was copied onto the device's credential. Claimed tokens are now permanent, and a migration clears the bad expiry on existing devices.

## Test results (on the development laptop)

- **Unit tests:** 15 pass (`python -m pytest tests`). They cover registry safety, a full mocked session, the task queue, manual-step promotion, the learning memory, operator feedback, and the model builder.
- **Remote end-to-end with `qwen2.5:7b`:** failed. The report call timed out at 300 s, with laptop RAM 97% used and only 0.3 GB free.
- **Remote end-to-end with `qwen2.5:3b`:** the issue "Websites are not opening, DNS broken" was diagnosed in about 186 s, `flush_dns` ran on the remote agent, the re-check passed, and the session was marked **Resolved**.
- **UI:** checked in headless Edge with no JS console errors.
- **Docker stack:**
  - `model-init` created `qwen2.5:3b` from `models/qwen2.5-3b/` with no download.
  - Login, diagnosis, applying a fix, re-verification, feedback, and `sentinel-tech` v1 creation all worked through the API.
  - Once built, the provider switched to `sentinel-tech` automatically.
- **Docker test, quality problem found:** for "disk almost full", the 3B model claimed the disk was full even though the evidence showed 1.3% used. It also proposed unrelated fixes (`renew_ip`, `sync_time`). After the fix, re-verification correctly reported *Not resolved*.
- **Fixes for that problem:**
  - Each playbook now has a list of relevant fixes (`RELEVANT_FIXES`), and unrelated proposals are dropped.
  - The report prompt now tells the model to say so plainly, with low confidence and no fixes, when the evidence does not confirm the complaint.
  - The test run had given 👍 to that wrong diagnosis automatically. Its learned case and `sentinel-tech` v1 were deleted so the model does not learn a wrong lesson. **Only give 👍 to diagnoses you have checked.**

## Deviations from the plan, and why

- **Default model `qwen2.5:3b` instead of `qwen2.5:7b`.** The 7B model timed out on this laptop. Use 7B when about 6 GB of RAM is free; it reasons better.
- **Prompts were shrunk** (smaller tool results, a compact fix catalog) because on a CPU, prompt length dominates latency.
- **Manual steps are promoted to fixes.** The 3B model wrote "run `ipconfig /flushdns`" as a manual step instead of proposing the `flush_dns` tool, so a deterministic mapper turns such steps into one-click fixes.
- **The local target in Docker is the container**, not the laptop. To troubleshoot the laptop from the Docker stack, install the agent on it with the one-line command from the Add Agent tab.

## Not yet verified

- The Windows install script has not been run in an elevated shell, because it registers a SYSTEM task. Only script rendering and the agent bundle were tested.
- The Linux and macOS install scripts have not been run on real machines.
- High-risk fixes (SFC, DISM, network reset) have not been executed on any device.

## Agent "connects then disconnects" (2026-10-09)

The first install on the development PC never connected.

- **Cause.** The Python-mode venv was built on the Microsoft Store Python, so the SYSTEM task exited instantly with code 101. There was no log, and `device_id` stayed empty.
- **Why it looked connected.** The "connected, then offline" seen in the dashboard was the 25-second `EXE-TEST` run, followed by the server being stopped.
- **Installer fixes.**
  - Rejects interpreters that resolve inside `WindowsApps`.
  - Prefers the `.exe`, migrates the old config, and removes the stale runtime.
  - Verifies the first successful report before saying it is connected; otherwise it prints the task result and the log tail.

## Fast diagnosis and hardware checks (2026-10-13)

Goal: cut the time to diagnose a laptop's OS and hardware problems. Before: about 3 minutes per diagnosis (sequential checks, up to 4 CPU-bound LLM calls).

- **Parallel baseline.** Playbook checks run concurrently in two phases: the CPU-sensitive ones (`system_overview`, `top_processes`) first, then everything else. The remote agent runs up to 4 read-only checks at once; fixes stay one at a time.
- **No more 1-second polling.** The agent's long-poll and the planner's wait for a remote result used to poll SQLite every second. They are now woken immediately (`backend/task_signals.py`), and the database stays the source of truth.
- **Instant findings** (`backend/agent_brain/findings.py`). Rules over every check's output, ready in milliseconds. They are shown first and fed to the LLM as facts. They also act as the full report in Instant mode or when the AI is down or times out, and they verify fixes without an AI call.
- **Speed modes:** instant / fast (default) / deep. Fast mode skips investigation when a playbook matched and makes one report call.
- **Smaller AI calls.**
  - The model no longer writes the evidence list or the issue summary; the server builds them.
  - Fast mode sends one summary line per check instead of raw data.
  - Output is capped (`num_predict`).
  - Measured on the dev laptop: about 1,700 prompt and 350 output tokens became about 800 and 70-150.
- **Model preloading.** At startup, and in parallel with each diagnosis's checks.
- **Grounding guards.**
  - Fixes the device would refuse are never proposed: services not on the allow-list (the model once proposed restarting `uvicorn`) and protected processes.
  - A full check-up, or a clean low-confidence diagnosis, keeps only fixes tied to a finding.
  - When the checks are clean, the prompt says so explicitly: the 3B model invented "overheating" otherwise.
- **Hardware.**
  - New `hardware_health` tool. On Windows it is one PowerShell call covering CPU model/clock, `% Processor Performance` (throttling), ACPI temperatures, RAM modules, GPU/driver, Device Manager error codes and WHEA errors.
  - `% Processor Performance` uses `Get-Counter` (~1 s); the WMI perf class took 54 s on first use.
  - New `rescan_hardware` fix (Windows, low risk). New Hardware check and OS health playbooks; `hardware_health` was added to the slow PC, high usage, crashes and check-up playbooks.
- **Fixed on the real laptop.**
  - `top_processes` CPU and memory views now share one sample. On Windows, each process the agent cannot open costs a full system query; together the two views took 11.5 s.
  - FAT32/exFAT drives no longer raise "disk full": the Google Drive mount reported G: as 100% full.

Measured on the dev laptop (i5-1235U, Docker, qwen2.5:3b, laptop under heavy load):

| Run | Checks | AI | Total |
| --- | --- | --- | --- |
| Instant, slow PC, via agent | 11 s | - | 11 s |
| Fast, hardware check, via agent | 7 s | 32 s | 40 s |
| Fast, full check-up, server container | 3 s | 23 s | 26 s |

Still not verified: temperature readings need the agent to run as SYSTEM/Administrator (the test agent ran as a normal user). The 3B model can still draw a weak link between findings (for example blaming a firmware device for heat); `qwen2.5:7b` reasons better if RAM allows.

## AI-driven replan (2026-10-14 to 2026-10-16)

The app was reshaped into an AI-driven troubleshooter that only suggests, hosted behind nginx and ngrok. [task.md](../task.md) tracks every item. Each phase was checked by the read-only `aiops-reviewer` subagent (`.claude/agents/aiops-reviewer.md`) before its boxes were ticked.

| Phase | Result | Where |
| --- | --- | --- |
| 0. Tracking | `task.md`, the reviewer subagent, and the live checks moved into the repo. | `tests/e2e/` |
| 1. Hosting | nginx on port 80 (WebSockets, long timeouts, rate-limited login). ngrok publishes it on https. The app reads the ngrok URL for install commands. Agents send `ngrok-skip-browser-warning`. The session cookie is `Secure` over https. | `deploy/nginx/`, `docker-compose.yml`, `backend/public_url.py` |
| 2. Decisions folder | Every AI decision, approval, rejection and result is written as JSON, with a daily `index.md`, and shown in the Decisions tab. | `backend/decision_log.py` |
| 3. AI brain | Covers four things: (1) `aiops-brain` built at startup from the selected base model and the principles; (2) deep thinking for diagnosis reports, streamed live; (3) 3-4 ranked solutions with Approve & run / Mark as done / Reject; (4) auto-fix removed, with a test pinning every code path that can change a device. | `backend/llm/brain.py`, `backend/agent_brain/planner.py`, `backend/learning/model_builder.py` |
| 4. Full removal | After an uninstall, leftovers are found, moved to a 7-day quarantine (registry keys exported first) and can be restored. Purged daily. | `agent/toolkit/leftovers.py` |
| 5. Performance tab | A full read-only test per device: benchmark, start-up (`boot_performance`), hardware, disks, battery, input devices (`input_devices`), and OS and app updates (`os_updates`, `install_os_updates`). It adds keyboard and mouse testers, and an AI analysis that starts from the test results. | `agent/toolkit/updates.py`, `backend/main.py`, `frontend/` |
| 6. Wrap-up | Covers: (1) a final whole-project review and re-check; (2) the Windows agent folder locked to SYSTEM and Administrators; (3) approvals and results recorded even across server restarts; (4) one change at a time per device, also from the task table; (5) dead code removed and versions pinned; (6) rebuilt agent (toolkit 1.4.0), updated README and docs, migration guide. | `backend/main.py`, `backend/install_templates/` |

### Test results

- 118 unit tests pass.
- The headless-browser check passes 36 of 36 against the live stack, covering every tab.
- The full-removal check passes 9 of 9 on a dummy program ("Contoso TestApp"; the agent refuses names containing "aiops").
- A real AI performance analysis finished end to end with 4 suggestions and was recorded as `performance_analysis`.

### Deviations from the plan, and why

- **Thinking costs minutes on a laptop CPU.** Fast mode keeps one AI report, with thinking on, as the default. Deep mode, where the AI also runs extra checks, is opt-in. If thinking uses up its token budget before the answer, its reasoning is handed to a short second call that only writes the answer.
- **Ollama ignores a Modelfile's system prompt** whenever a request has its own system message. The brain's principles are therefore repeated in every request prompt.
- **Leftover scans read user registry hives through `HKU\<SID>`**, not `HKCU`. Scanning both listed every key twice.
- **nginx allows one hour per request** (the plan said 900 s), because a deep diagnosis on a laptop CPU can take longer.
- **Port 8000 stays published** until every agent is reinstalled, because agents installed before nginx report to `:8000`. Then it becomes `127.0.0.1:8000:8000`.
- **The dev laptop runs `qwen3:4b`.** With 16 GB of RAM and WSL/Docker using most of it, `qwen3:8b` did not fit.
- **Rules were adjusted after the review.**
  - A slow start-up is judged by when the desktop was ready, not total boot time.
  - Pending security updates are medium, not high.
  - A touchpad's extra "mouse" entry and Intel's hotkey filter no longer count as separate devices.
  - Headless machines no longer raise "no keyboard".

### Not yet verified

- ngrok: no authtoken has been set yet.
- `install_os_updates` has never run for real. It is covered by unit tests and a PowerShell parse check, and the browser check cancels every install dialog.
- The Phase 4 and 5 agent tools through an installed agent: the agent installed on the dev laptop is 1.3.0, and 1.4.0 needs a reinstall. Boot timing needs the agent's SYSTEM rights.
- The Linux and macOS paths of the new tools have unit tests only.
