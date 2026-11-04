# The AIops brain (`aiops-brain`)

AIops runs on its own Ollama model, `aiops-brain`, built on top of the base model picked in the model switcher (`qwen3:4b` by default, `qwen3:8b` or `qwen2.5:3b`). It uses relevant trusted tickets as troubleshooting hints; this does not retrain the base model.

## What the brain is told

Every brain carries the same principles (`backend/llm/brain.py`):

- always give your best effort;
- reason from the evidence first and your own IT knowledge second;
- **never change the computer yourself: only suggest, and a person approves every action**;
- offer 3-4 genuinely different solutions, best first, with concrete steps;
- say plainly when you are unsure, and never invent numbers.

Ollama ignores a model's built-in system prompt whenever a request brings its own system message, and every AIops request does. So the principles are repeated in every request prompt, not only in the Modelfile.

## Building and rebuilding

- **At startup**, `model_builder.ensure_brain()` checks whether `aiops-brain` exists and was built from the current base model, principles, and learning policy. A policy fingerprint change refreshes older models when Ollama is reachable. Switching the base model in the dashboard rebuilds it too.
- **A build** (`backend/learning/model_builder.py`):
  - writes `models/aiops-brain/Modelfile`: the base model and the principles, with no ticket-specific system lessons or `MESSAGE` pairs;
  - writes `knowledge.json` (up to 25 lessons and stats), `training_data.jsonl` (trusted cases and curated reasoning examples for possible fine-tuning) and `version.json`;
  - creates or updates `aiops-brain` in Ollama through `/api/create`.
- **Use.** The provider uses `aiops-brain` instead of the plain base model (`LEARNING_USE_MODEL=true`). The AI chip in the top bar shows the version.

## Learning loop

1. **Record.** Finished device sessions are saved in `learned_cases`: issue, OS, playbook, root cause, evidence, fixes, outcome, and target origin (`agent`, native `local`, or `container`). The planner skips container sessions. The store also rejects container-origin cases from learning if they are present through another path.
2. **Feedback.** Under each diagnosis, the operator can click 👍 *Correct* or 👎 *Wrong* and optionally enter the real root cause. A correction outranks the AI's own verdict.
3. **Trust.** A device case is *trusted* when verified as resolved or confirmed with 👍. A 👎 case is only used if it has a correction. Container cases and legacy local cases without recorded host/container origin remain available as records but are excluded from recall, model exports, and fleet correlation. Known native local-device cases remain eligible.
4. **Recall** (on every new ticket):
   - Candidates must have the same OS and playbook. For older cases without a playbook, it is inferred from their complaint. Unknown problem types only match other unknown types.
   - Common word inflections are folded, then IDF-weighted cosine similarity is calculated from complaint text with a minimum score of 0.35. An old model's guessed root cause cannot create a match. Up to three trusted cases become prompt hints.
   - Fixes that resolved at least 2 similar tickets, with a success rate of 60% or more, are proposed with a **learned** badge. Unsuccessful similar tickets stay in the denominator. Approval and current-evidence checks still apply.
5. **Rebuild.** After every `LEARNING_REBUILD_EVERY` new trusted cases (default 3), or when you click **Rebuild model now**, instructions are refreshed and lessons/datasets exported. Scoped recall reads current cases directly and does not wait for a rebuild.

Test tickets with made-up complaints teach wrong lessons. Remove their learned cases afterwards (see [tests/e2e/README.md](../tests/e2e/README.md)), and give 👍 only to diagnoses you have checked.

## Honest limits

- This is **instruction and retrieval-based learning**: principles and relevant case hints go into the prompt. It does **not** retrain the model's weights or guarantee improving accuracy.
- Missing or failed verification checks leave the result unconfirmed. A successful fix command alone does not make a case a verified resolution.
- The additive `target_kind` database migration preserves existing records. Legacy local cases cannot reliably distinguish a Docker container from a real machine, so their origin is not guessed.
- `training_data.jsonl` is exported so you can run a real LoRA fine-tune later, for example with Unsloth or Axolotl on a GPU. The trained adapter can then be loaded with `ADAPTER` in the Modelfile.
- Keyword similarity is simple and works offline. If recall needs to improve, an embedding model such as `nomic-embed-text` is the next step.
- `models/sentinel-tech/` and the `sentinel-tech` Ollama model come from an earlier version. Nothing uses them any more: remove the model with `docker compose exec ollama ollama rm sentinel-tech`.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `LEARNED_MODEL_NAME` | `aiops-brain` | Name of AIops' model in Ollama |
| `LEARNING_USE_MODEL` | `true` | Use it instead of the plain base model |
| `LEARNING_REBUILD_EVERY` | `3` | Rebuild after this many new trusted cases |

## API

- `GET /api/learning/stats`, `GET /api/learning/cases`, `GET /api/learning/lessons`
- `POST /api/learning/rebuild`
- `GET /api/learning/dataset` (JSONL download)
- `POST /api/troubleshoot/{id}/feedback` with `{helpful, note?, corrected_root_cause?}`
