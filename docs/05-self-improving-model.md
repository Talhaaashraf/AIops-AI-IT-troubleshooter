# The AIops brain (`aiops-brain`)

AIops runs on its own Ollama model, `aiops-brain`, built on top of the base model picked in the model switcher (`qwen3:4b`, `qwen3:8b` or `qwen2.5:3b`). The brain learns from every ticket.

## What the brain is told

Every brain carries the same principles (`backend/llm/brain.py`):

- always give your best effort;
- reason from the evidence first and your own IT knowledge second;
- **never change the computer yourself: only suggest, and a person approves every action**;
- offer 3-4 genuinely different solutions, best first, with concrete steps;
- say plainly when you are unsure, and never invent numbers.

Ollama ignores a model's built-in system prompt whenever a request brings its own system message, and every AIops request does. So the principles are repeated in every request prompt, not only in the Modelfile.

## Building and rebuilding

- **At startup**, `model_builder.ensure_brain()` checks whether `aiops-brain` exists and was built from the current base model and the current principles. If not, it builds it before the first diagnosis. Switching the base model in the dashboard rebuilds it too.
- **A build** (`backend/learning/model_builder.py`):
  - writes `models/aiops-brain/Modelfile`: the base model, the principles, up to 25 lessons and up to 3 worked examples as `MESSAGE` pairs;
  - writes `knowledge.json` (lessons and stats), `training_data.jsonl` (chat-format data for fine-tuning) and `version.json`;
  - creates or updates `aiops-brain` in Ollama through `/api/create`.
- **Use.** The provider uses `aiops-brain` instead of the plain base model (`LEARNING_USE_MODEL=true`). The AI chip in the top bar shows the version.

## Learning loop

1. **Record.** Every finished session is saved as a learned case in the `learned_cases` table: the issue, OS, root cause, evidence, the fixes that ran, and the outcome.
2. **Feedback.** Under each diagnosis, the operator can click 👍 *Correct* or 👎 *Wrong* and optionally enter the real root cause. A correction outranks the AI's own verdict.
3. **Trust.** A case is *trusted* when it was verified as resolved or confirmed with 👍. A 👎 case is only used if it has a correction.
4. **Recall** (on every new ticket):
   - Similar trusted cases are found by idf-weighted keyword similarity and given to the AI as hints.
   - Fixes that resolved at least 2 similar tickets, with a success rate of 60% or more, are suggested with a **learned** badge. Like every other solution, they run only when a person approves them.
5. **Rebuild.** After every `LEARNING_REBUILD_EVERY` new trusted cases (default 3), or when you click **Rebuild model now**, the brain is rebuilt with the new lessons.

Test tickets with made-up complaints teach wrong lessons. Remove their learned cases afterwards (see [tests/e2e/README.md](../tests/e2e/README.md)), and give 👍 only to diagnoses you have checked.

## Honest limits

- This is **in-context learning**: principles, lessons and examples go into the prompt. It does **not** retrain the model's weights.
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
