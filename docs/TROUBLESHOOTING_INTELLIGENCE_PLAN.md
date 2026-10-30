# Troubleshooting Intelligence Plan

Make the existing AIops brain reason like a senior Windows / desktop / infrastructure
troubleshooting engineer: investigate unfamiliar problems from evidence, separate
fact from hypothesis, rank root causes with honest confidence, pick the right tool
for the question, verify fixes, and learn — **without** redesigning the app, replacing
the architecture, adding a second AI framework, requiring a GPU or a bigger model, or
weakening the suggest-only safety model.

This is a **plan for review**. Nothing here is implemented yet. Status legend:
`[ ]` planned · `[~]` in progress · `[x]` done and verified.

---

## 0. The one constraint that shapes everything

The brain runs on **Ollama `qwen3:4b`, CPU-only, 7.1 GB RAM, `num_ctx` 8192**. On that
host every **prompt** token costs ~0.01 s and every **output** token ~0.14 s
(`backend/ai_technician.py:30`, `backend/agent_brain/planner.py:52`). So the governing
rule, already followed by this codebase, is:

> **The server and the rules build the structure; the model only supplies the judgement
> a rule cannot.** Evidence is pre-digested (`evidence_digest`), findings are computed by
> rules (`findings.py`), the cause the model names is re-checked against the evidence
> (`ground_root_cause`), and confidence is set from the evidence, not the model's say-so.

Every improvement below is designed to add **reasoning quality**, not prompt length.
Where the spec asks for a richer output (hypotheses, eliminated causes, verification
plan), we compute as much as possible on the server from data we already have, and ask
the model only for the few fields that need a mind.

---

## 1. What already exists (inspection results)

The current pipeline (`backend/agent_brain/planner.py`) is already an agentic,
evidence-first loop. Mapping it to the spec's asks:

| Spec asks for | Already implemented | Where |
| --- | --- | --- |
| Agentic loop (observe → tools → report → verify) | Yes: baseline → findings → investigate (deep) → report → ground → verify | `planner.run_diagnosis`, `_diagnose`, `_investigate`, `_verify` |
| Evidence over guessing | Yes: baseline tools run before the LLM; model told "never invent numbers" | `collect_baseline`, `INVESTIGATE_PROMPT`, `brain.BRAIN_PRINCIPLES` |
| Tool selection by registry (no arbitrary shell) | Yes: allow-listed `Tool` registry, typed args, risk gating | `agent/toolkit/registry.py`, `tool_schemas`, `validate_args` |
| Diagnostic tool catalog | 52 read tools + change tools | `agent/toolkit/*` (`system_overview`, `check_internet`, `hardware_health`, `recent_crashes`, `event_log_errors`, `ping_host`, `dns_lookup`, `printer_status`, …) |
| Playbooks (deterministic head start) | 15 playbooks with keyword matching + baseline tools | `backend/agent_brain/playbooks.py` |
| Rule findings from evidence | Yes: one rule per tool, severity, fixes, tips | `backend/agent_brain/findings.py` (`RULES`, `analyze`) |
| "Separate problem vs the cause" | Yes: `RELATED_FINDINGS` / `is_related` / `split_by_relevance` | `playbooks.py`, `findings.py` |
| Root-cause grounding / overrule the model | Yes: `ground_root_cause`, `_ground_network`, regrounding | `planner.py:1099` |
| Confidence calibrated to evidence | Yes (low/medium/high), capped when the cause is weak | `_cap_confidence`, `ground_root_cause` |
| "Insufficient evidence" / did-not-reproduce | Yes: `cause="none"`, `complaint_reproduced=False`, low confidence | `REPORT_PROMPT`, `ground_root_cause` |
| 3–4 ranked solutions, cause first | Yes: `normalize_solutions`, `complete_solutions` | `planner.py` |
| Suggest-only + human approval + audit | Yes: AST guard test, decision log, one-change-at-a-time | `tests/test_brain.py`, `decision_log.py`, `apply_fix` |
| Verification (not "command succeeded") | Yes: rules re-check the finding, else an AI verdict | `_verify` |
| Similar past incidents / learning | Yes: idf-weighted recall, learned fixes, self-rebuilt model | `backend/learning/store.py`, `model_builder.py` |
| Platform awareness (Win/Linux/macOS) | Yes: tools carry `os`, tips are OS-specific, eval has `forbidden` OS steps | registry `os`, `playbook_tips`, `eval_cases.py` |
| Evaluation framework | Yes: 8 recorded cases, offline scoring | `backend/agent_brain/evaluate.py`, `eval_cases.py` |
| Selective prompt (no giant knowledge dump) | Partly: playbook-scoped baseline + fixes; knowledge itself is not retrieved | `RELEVANT_FIXES`, `fix_catalog(only=…)` |

**Conclusion: ~70% of the spec's *behaviour* already exists.** The brain is not naive;
it is missing *depth of reasoning* and *structured domain knowledge*.

---

## 2. What is missing (the gaps to close)

Grouped by the spec sections they come from:

1. **Explicit reasoning structure** (spec §3–5, §36, §52):
   - No hypothesis set (H1…Hn with likely / possible / ruled-out).
   - No FACT / OBSERVATION / INFERENCE / HYPOTHESIS vocabulary.
   - Output contract is thinner than §36 (no eliminated-causes, tests-performed,
     verification-plan, remaining-uncertainty, affected-component as first-class fields).
2. **Structured, retrievable domain knowledge** (spec §8–26, §34):
   - No knowledge base for error codes, Event IDs, BSOD bugchecks, the "where do I look"
     map, printer/network-layer/DNS/Office/AD/Entra/driver playbook knowledge.
   - Knowledge is not *retrieved per issue*; the model relies on its own weights.
3. **Richer playbook engine** (spec §27): current playbooks are {keywords, baseline
   tools, relevant fixes}. They lack initial questions, decision points, root-cause
   criteria, rollback and escalation as data.
4. **Tool knowledge for the model** (spec §42, §7): tools have a `description` but not a
   machine-readable "what question it answers / when to use / when not / how to read the
   result / expected vs opposite evidence."
5. **Unknown-problem handling & targeted questions** (spec §28–29): no clarifying-question
   step; a vague complaint goes straight to the general baseline.
6. **Fleet vs single-endpoint correlation** (spec §31, §41): diagnosis is per-device; no
   "same driver/update/app across N devices" signal, though the data exists in stores.
7. **Negative / reasoning training examples** (spec §46–48): learning distils resolved
   cases into one-line lessons and few-shot answers, but not *reasoning* exemplars or
   bad-vs-good contrasts.
8. **Evaluation of reasoning** (spec §49): eval scores the final text (cause, confidence,
   first solution, OS-appropriate steps), not tool selection, hypothesis ranking,
   hallucination resistance, or unknown-handling.
9. **New evidence sources** some scenarios need (spec §12, §16, §21): no generic TCP-port
   test (printer 9100/515/631), no full driver inventory with versions/signatures, no
   bugcheck-code extraction, no AD/Entra tools. These require **agent/toolkit changes and
   a device reinstall**, so they are isolated into their own late phase.

---

## 3. Design principles for every change

1. **Preserve the safety model.** Suggest-only; the AST guard
   (`tests/test_brain.py::test_only_person_triggered_code_can_change_a_device`) must keep
   passing; the server still sends ids only; `escapeHtml` on all new UI; decision log and
   audit unchanged.
2. **No new AI framework, no GPU, no bigger model required.** Everything runs on the
   existing Ollama provider and the existing `aiops-brain` build process.
3. **Server/rules do structure; model does judgement.** Prefer deterministic computation
   of new output fields over asking the model for them.
4. **Selective retrieval.** Load only the knowledge relevant to the matched playbook /
   detected findings / named error codes — never the whole knowledge base. A hard
   per-prompt budget (characters) with graceful trimming.
5. **Additive and reversible.** Every phase leaves the app fully working; new behaviour is
   behind small, testable functions; env flags can disable the heavier steps
   (`DIAGNOSIS_THINKING`, `AGENT_MAX_STEPS` already set this precedent).
6. **Knowledge as data, not prose in a prompt.** Domain knowledge lives in versioned
   Python/JSON data modules with tests, retrieved and rendered compactly at prompt time.

---

## 4. Knowledge architecture (how knowledge is structured & retrieved)

Per spec §34–35, knowledge is split into layers, each a small data module under a new
`backend/agent_brain/knowledge/` package. **None of it is injected wholesale**; a
retriever assembles a compact, budgeted block for the current issue.

```
backend/agent_brain/knowledge/
  __init__.py          # retrieve(context) -> compact knowledge block (budgeted)
  investigation_map.py # §8 "where do I look": component -> tools/logs/signals
  domains.py           # §9-24 per-domain: symptoms, likely/possible causes, evidence, tools, verification
  error_codes.py       # §25 error-code entries (Office 30015-25, 1618, Windows Update 0x8024…)
  event_ids.py         # §26 Event ID entries (Kernel-Power 41, 6008, BugCheck 1001, WHEA 17/18/19, 7045, 7000/7001…)
  bugchecks.py         # §12 BSOD bugcheck names -> meaning, correlate-with, do-not-conclude
  tool_knowledge.py    # §42 per-tool: question answered, when to use/not, expected vs opposite evidence
```

**Retrieval (`knowledge.retrieve`)** takes the issue text, matched playbook, detected
finding keys, OS, and any error/event ids seen in the evidence, and returns:

- the matched **domain card(s)** (usually one, at most two);
- the **investigation-map rows** for the components that domain touches;
- **error-code / event-id entries** only for codes actually present in the evidence or the
  issue text;
- nothing else.

Output is capped (e.g. `KNOWLEDGE_BUDGET_CHARS`, default ~1200) and rendered as terse
`key: value` lines, the same compact style as `findings_block` / `evidence_digest`.

**Where it plugs in:** one extra block in the `REPORT_PROMPT` user message
(`planner._ai_report`), and optionally a hint line in `_investigate`. Fast mode gets a
tighter budget than deep mode. When retrieval finds nothing specific, the block is empty
and the prompt is unchanged (no regression for today's cases).

Error-code and Event-ID entries deliberately teach *how to investigate*, not just
"X means Y" (spec §25–26): each entry carries `where_to_look`, `diagnostic_tools`,
`related_events`, and `do_not_conclude`.

---

## 5. The enriched reasoning loop & output contract

### 5.1 Hypotheses (spec §3–5, §36)

Add a **hypothesis set** computed mostly by rules, ranked with help from the model:

- **Seed (rules):** from the matched playbook's `RELATED_FINDINGS` and the detected
  findings, build candidate hypotheses (e.g. slow_pc → memory pressure, CPU, disk I/O,
  thermal/throttle, startup load, failing disk). Each seeded hypothesis maps to the
  evidence that supports or weakens it.
- **Status (rules + model):** a finding that fired and can explain the complaint →
  `likely`; a related finding that did **not** fire (its check ran clean) → `ruled_out`
  with the reason; a plausible cause with no check yet → `possible`. The model may adjust
  wording but cannot promote a `ruled_out` hypothesis without evidence.
- Hypotheses are recorded in the report and the decision log, and shown in the UI as a
  short "What we considered" list. This is the single most senior-engineer-like change and
  is almost free in output tokens because it is rules-driven.

### 5.2 Fact vocabulary (spec §3)

Teach the vocabulary in `BRAIN_PRINCIPLES` / `REPORT_PROMPT` so the model labels claims as
observed fact vs inference vs hypothesis, and **never states a hypothesis as confirmed**.
Reinforced by one reasoning exemplar (§5.5) rather than extra prose.

### 5.3 Output contract (spec §36)

Extend the report (and its JSON schema in `report_schema`) with fields that are mostly
**server-computed**, so model output stays small:

| Field | Source |
| --- | --- |
| `affected_component` | rules, from the cause finding's source/domain |
| `symptom` | the issue text (already have `issue_summary`) |
| `evidence` | already computed (`evidence_facts`) |
| `key_findings` | already have `quick_findings` |
| `hypotheses` | §5.1 (rules + light model input) |
| `root_cause`, `confidence`, `why` | model + `ground_root_cause` (already) |
| `eliminated_causes` | rules: the `ruled_out` hypotheses + "separate problems" |
| `tests_performed` | rules: the tools actually run (from the session steps) |
| `recommended_solutions` | already (`solutions`) |
| `verification_plan` | rules: derived from the cause finding's verification recipe (§5.4) |
| `remaining_uncertainty` | rules: from `confidence_note` / `complaint_reproduced` |

Only `root_cause`, `why`, `confidence`, and `solutions` come from the model — exactly what
it produces today. The rest are assembled in `normalize_report` / a new
`enrich_report`. **Net new output tokens ≈ 0.**

Numeric confidence (spec §5, 0–100): keep the evidence-grounded low/medium/high as the
source of truth (this is the anti-hallucination guard), and **derive** a band
(weak/possible/likely/highly-likely/confirmed) with a representative number for display.
The model is never allowed to assert "95%"; the number follows the grounding, matching
the spec's "high confidence must require strong supporting evidence."

### 5.4 Verification recipes (spec §38)

Give each finding (or its domain card) a `verify` recipe: which checks to re-run and the
success condition. `_verify` already re-runs the findings' source tools; this makes the
success condition explicit and lets the report print a concrete `verification_plan`
before a fix is approved. Final state stays RESOLVED / PARTIALLY / NOT / UNKNOWN (already
in `_verify`); add the `partially_resolved` wording path the spec names.

### 5.5 Reasoning & negative examples (spec §46–48)

Add a small, curated set of **reasoning exemplars** (not weight training) used two ways:
as a few-shot `MESSAGE` pair in the `aiops-brain` Modelfile build (`model_builder._modelfile`
already supports this) and/or as one compact exemplar in the report prompt. Each shows
evidence → ruled-out causes → named cause → honest confidence, plus one **bad→good**
contrast (the printer §48 example: "offline, reinstall driver" ✗ vs port-config reasoning
✓). Curated exemplars live beside the knowledge package and are OS-tagged.

### 5.6 Unknown problems & targeted questions (spec §28–29)

When no playbook matches **and** the instant findings are empty/ambiguous, return a short
list of **targeted clarifying questions** (each tied to a diagnostic purpose: "did it start
after an update?", "all users or one?", "before or after login?") instead of a confident
guess. Rules generate these from the detected domain; the model may refine. The UI already
has a chat surface to collect answers; a follow-up diagnosis uses them. Gated so it never
blocks a clear diagnosis.

### 5.7 Fleet vs single endpoint (spec §31, §41)

A read-only correlation over existing stores (`device_store`, `learning_store`,
`alert_store`, `threat_store`): when the same finding key / fix / failing driver / Event ID
appears on ≥N devices in a window, surface a "possible fleet-wide issue" note on the
diagnosis and (optionally) an alert. No new agent data required — it reads what is already
collected. Shipped as its own phase because it is orthogonal to single-device reasoning.

---

## 6. Implementation phases

Ordered by **intelligence gained per unit of effort and risk**. Phases I1–I6 are
**server-only** (no agent reinstall, no toolkit bump). I7 is the only one touching the
device agent.

### I1 — Reasoning contract & hypotheses (server-only) `[~]`
Code complete; unit tests green (`tests/test_reasoning_contract.py`, full suite 222 passed on
Python 3.12). Browser render and the server eval are verified by the user. Implemented:
`enrich_report` + helpers in `planner.py`, `verification_steps` in `findings.py`, the fact/
hypothesis clause in `llm/brain.py`, decision-log fields in `_record_diagnosis`, and the
"What we considered" / affected-component / remaining-uncertainty / verification-plan UI in
`frontend/{app.js,index.html,style.css}`. No agent reinstall; model output surface unchanged.

- `enrich_report()` adds `affected_component`, `eliminated_causes`, `tests_performed`,
  `verification_plan`, `remaining_uncertainty`, `hypotheses` (rules-seeded).
- Extend `report_schema` minimally (hypotheses wording optional); keep model output small.
- Fact vocabulary + "never assert a hypothesis" into `REPORT_PROMPT` / `BRAIN_PRINCIPLES`.
- UI: show "What we considered" (hypotheses) and the verification plan on the report card.
- Files: `planner.py`, `llm/brain.py`, `findings.py` (verify recipes), `frontend/{app.js,index.html,style.css}`, `decision_log.py`.
- Acceptance: all existing tests pass; new `tests/test_reasoning_contract.py`; eval unchanged or better.

### I2 — Knowledge package + retriever (server-only) `[~]`
Code complete; unit tests green (`tests/test_knowledge.py`, full suite 230 passed). Created
`backend/agent_brain/knowledge/` with `investigation_map.py` (§8 universal map), `domains.py`
(16 domain cards incl. slow/CPU-RAM/disk, network/DNS, Wi-Fi, printer, crashes/BSOD, updates,
battery, audio, hardware, OS-health, security, Office, app-crash), `tool_knowledge.py` (§42 what
each check answers), and `__init__.py` `retrieve()` / `investigate_tool_hint()` — selective
(one card, keyed off the playbook else issue keywords), budgeted (`KNOWLEDGE_BUDGET_CHARS`
default 1200 deep / 700 fast, trimmed at line boundaries), deterministic. Wired into the report
prompt and the deep-mode investigate prompt in `planner.py`. Model output surface unchanged; a
printer issue pulls no Office/BSOD text (verified). On the server (user): `evaluate` timings not
materially regressed. Error-code/Event-ID/BSOD engines are I3.

### I3 — Error-code & Event-ID knowledge engines (server-only) `[~]`
Code complete; unit tests green (236 passed). Added `knowledge/error_codes.py`,
`knowledge/event_ids.py`, `knowledge/bugchecks.py` (spec §12/§25/§26), each entry teaching how to
investigate and what NOT to conclude. `detect_codes(issue, evidence)` scans the issue text plus each
check's summary and a capped data dump; `retrieve_codes()` renders only the codes present, budget-capped
(`KNOWLEDGE_CODES_CHARS` default 1000), and the report prompt in `planner._ai_report` carries it as
"Known codes seen (how to read them, not automatic causes)". Guarded against the plain-NTFS-filesystem
false positive; trigger tightened so 0xD1 doesn't double-match 0x0A. On the server (user): confirm a real
crash/Office ticket surfaces the right codes.

### I4 — Playbook engine upgrade (server-only) `[~]`
Code complete; tests green. Added `knowledge/playbook_extras.py` as the playbook-engine layer keyed by
domain id (kept separate from the compact domain cards): per-domain `questions` (§29), `decision_points`
(§27), `escalate_when` (§40) and `rollback`, plus `GENERIC_QUESTIONS` for a truly unknown problem. The
retriever renders decision points into the deep-mode investigate hint and exposes
`clarifying_questions()` / `escalation_reasons()` (consumed by I5). New playbooks the spec lists that
need new device tools (e.g. a TCP-port test) are deferred to I7; the domain cards already serve Office
and generic app-crash via keyword match without a playbook.

### I5 — Unknown-handling, clarifying questions, escalation (server-only) `[~]`
Code complete; tests green. `enrich_report` now adds `clarifying_questions` when the checks did not pin a
cause (low confidence + no cause finding) — the matched domain's targeted questions, else generic — so an
unclear report asks instead of guessing (§28-29). `_escalation` adds an escalation note only on real
signals (failing disk, WHEA errors, a system crash, or a check that could not run), assembled from facts
already in the report (§40); never invented. Both surfaced on the report card (`renderEscalation`,
`renderClarifyingQuestions`) and recorded in the decision log. §39 "don't repeat a failed fix" already
holds — nothing auto-runs and the operator decides each retry.

### I6 — Evaluation of reasoning + learning upgrade (server-only) `[~]`
Code complete; tests green. Added two reasoning eval cases (`bsod_driver_win`, `audio_service_win`); the
eval scorer now has a `hypotheses` check (report lists what it weighed AND carries a verification plan).
`model_builder` exports curated bad→good reasoning exemplars (§46-48, incl. the printer and slow-PC
contrasts) into `training_data.jsonl` for a future fine-tune — kept out of the live prompt, so no CPU
cost at inference. On the server (user): run `evaluate --mode fast/deep` to score the real model's
reasoning and timings. Deep-mode tool-selection scoring and a hallucination-resistance metric can extend
this later.

### I7 — New evidence tools (agent/toolkit; **needs reinstall**) `[~]` (unit-tested; reinstall pending)
Code complete; unit tests green. Added two registered **read-only** tools in `agent/toolkit/diagnostics.py`:
`test_tcp_port(host, port)` (printer 9100/515/631 and generic L4 reachability, §16/§17) and
`driver_inventory()` (Windows unsigned/recently-updated drivers; Linux/macOS loaded modules, §21). Wired
both into the knowledge layer (investigation map, printer/crashes/hardware cards, tool-knowledge).
`TOOLKIT_VERSION` 1.7.0 → **1.8.0**. Bugcheck extraction was **not** needed as a tool change — the I3 codes
engine already reads the bugcheck from the `recent_crashes` message text. AD/Entra live tools (§19-20)
remain out of scope (privileged, domain-specific). **User step:** rebuild the agent and re-run the install
command so devices pick up toolkit 1.8.0; I1-I6 all work without this.

### I8 — Fleet correlation (server-only) `[~]`
Code complete; unit tests green. New `backend/fleet_correlation.py` reads the learned-cases store (read-only):
`fleet_clusters()` groups recent diagnoses by playbook across **distinct** devices (a single device's repeats
never trip it); `note_for()` adds a "seen on N devices" note to a live diagnosis when the same playbook spans
several devices in the window (`FLEET_WINDOW_DAYS` 7, `FLEET_MIN_DEVICES` 3). Surfaced on the report card
(`renderFleet`), recorded in the decision log, and exposed at `GET /api/fleet` for a fleet overview.
Container diagnoses are skipped. On the server (user): confirm the note appears once several devices hit the
same playbook.

Each phase ends with the `aiops-reviewer` subagent review before its `task.md` boxes are
ticked, matching the project's existing workflow.

---

## 7. How each spec requirement is satisfied (traceability)

- **§6–7 tool selection reasoning** → tool-knowledge cards (I2) + investigate prompt hint;
  the registry already prevents arbitrary shell.
- **§8 where-do-I-look** → `investigation_map.py` (I2).
- **§9–24 domain knowledge** → `domains.py` cards, retrieved per issue (I2–I4).
- **§10–11 performance/hardware "find the bottleneck", don't jump to cleanup / "RAM faulty"**
  → already partly in `findings.py` (disk-vs-RAM grounding, correlate WHEA before blaming
  RAM); domain cards make the bottleneck reasoning explicit.
- **§12 BSOD** → `bugchecks.py` + correlation rules (I3), deeper with I7 bugcheck extraction.
- **§13 Event logs** → `event_ids.py` + existing `event_log_errors`/`recent_crashes` (I3).
- **§25–26 error/Event-ID engines** → I3.
- **§27 playbook engine** → I4.
- **§28–29 unknown/questions** → I5.
- **§30 recent-change correlation** → a domain-agnostic "what changed" hypothesis (I1/I4)
  from updates/driver/software events already collected.
- **§31/§41 fleet** → I8.
- **§32–33, §46 learning/lessons** → existing learning + reasoning exemplars (I6).
- **§34–35 structured, selective, CPU-friendly knowledge** → §4 retriever with a budget.
- **§36 output contract** → §5.3 `enrich_report` (I1).
- **§37 remediation safety** → unchanged; AST guard still enforced.
- **§38–39 verification / failed remediation** → §5.4 (I1) + existing `_verify`; add the
  "don't repeat a failed fix; re-observe" note.
- **§42 tool knowledge** → `tool_knowledge.py` (I2).
- **§43 platform awareness** → already enforced; knowledge cards are OS-tagged.
- **§44–45 data protection / security boundaries** → unchanged; knowledge cards must never
  suggest disabling security to hide an error (encoded as a `do_not` in the security card).
- **§49 evaluation** → I6.
- **§50 no false certainty** → confidence grounding (exists) + hallucination checks in eval (I6).

---

## 8. Acceptance criteria (spec §54) & how we verify

Locally (no Docker, venv at `C:\Users\talhaashraf\Documents\AiOps`):
`C:\Users\talhaashraf\Documents\AiOps\Scripts\python.exe -m pytest -q` stays green at every
phase, including the safety/AST tests (criteria 1–7). New tests cover criteria 8–20
(investigate unknowns, tool selection, fact/hypothesis split, ranked causes, calibrated
confidence, "insufficient evidence", no invented evidence, verification, lessons without
blind copying, fleet detection, platform safety, selective retrieval, CPU practicality).

On the server (user-run, per project rules): `evaluate --mode fast|deep` on `qwen3:4b`
before/after each phase to confirm accuracy ↑ and timings stay practical; the real-model
reasoning checks; nginx/ngrok/agent untouched by I1–I6/I8.

---

## 9. Out of scope / deferred / risks

- **AD / Entra ID live diagnostics** (§19–20): knowledge/advice only for now; live
  domain-join/secure-channel collection needs privileged, environment-specific tooling.
- **Writing Kaspersky/Defender policy, toggling audit policies**: already out of scope.
- **LoRA / weight fine-tuning**: `training_data.jsonl` is exported for a future GPU
  fine-tune; not done here.
- **Risk — prompt growth on CPU:** mitigated by the hard knowledge budget, fast-mode
  tighter budgets, and server-computed output fields. Every phase checks eval timings.
- **Risk — small-model drift with richer schema:** mitigated by keeping the model's output
  surface identical (cause/why/confidence/solutions) and computing the rest server-side,
  plus partial-JSON recovery that already exists (`parse_reply`, handoff call).
- **I7 requires a device agent reinstall**, so it ships last and nothing earlier depends on it.

---

## 10. Suggested sequencing

I1 → I2 → I3 → I4 → I5 → I6, reviewing and measuring after each; then I7 (agent tools) and
I8 (fleet) as independent add-ons. I1 and I2 deliver most of the "senior engineer" feel
(hypotheses, eliminated causes, verification plan, retrieved domain knowledge) with
server-only changes and no agent reinstall.
