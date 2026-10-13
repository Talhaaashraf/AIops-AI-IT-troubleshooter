# The self-improving model (`sentinel-tech`)

AIops learns from every ticket it works on.

## Learning loop

1. **Record.** When a session finishes (diagnosed, fix applied, verified, or failed), it is saved as a learned case in the `learned_cases` table: the issue, OS, root cause, evidence, applied fixes, and outcome.
2. **Feedback.** Under each diagnosis, the operator can click 👍 *Correct* or 👎 *Wrong*, and optionally enter the real root cause. A correction outranks the AI's own verdict.
3. **Trust.** A case is *trusted* when it was verified as resolved or confirmed with 👍. A 👎 case is only used if it has a correction.
4. **Recall (every new ticket).**
   - Similar trusted cases are found by idf-weighted keyword similarity and given to the LLM as hints.
   - Fixes that resolved at least 2 similar tickets, with a success rate of 60% or more, are proposed automatically and shown with a **learned** badge.
5. **Distill (rebuild the model).** Every `LEARNING_REBUILD_EVERY` new trusted cases (default 3), or when you click **Rebuild model now**, `backend/learning/model_builder.py`:
   - writes `models/sentinel-tech/Modelfile`: the base model, a system prompt with up to 25 lessons, and up to 3 worked examples as `MESSAGE` pairs,
   - writes `knowledge.json` (lessons and stats) and `training_data.jsonl` (chat-format data for fine-tuning),
   - creates or updates `sentinel-tech` in Ollama through `/api/create`.
6. **Use.** Once `sentinel-tech` exists, the provider uses it instead of the base model (`LEARNING_USE_MODEL=true`). The AI chip in the top bar shows the version.

## Honest limits

- This is **in-context learning and knowledge distillation**: lessons and examples go into the prompt. It does **not** retrain the model weights.
- `training_data.jsonl` is exported so you can run a real LoRA fine-tune later (for example with Unsloth or Axolotl on a GPU). The trained adapter can then be loaded with `ADAPTER` in the Modelfile.
- Keyword similarity is simple and works offline. If recall needs to improve, an embedding model (such as `nomic-embed-text`) is the next step.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `LEARNED_MODEL_NAME` | `sentinel-tech` | Name of the learned model in Ollama |
| `LEARNING_USE_MODEL` | `true` | Use the learned model once it exists |
| `LEARNING_REBUILD_EVERY` | `3` | Auto-rebuild after this many new trusted cases |

## API

- `GET /api/learning/stats`, `GET /api/learning/cases`, `GET /api/learning/lessons`
- `POST /api/learning/rebuild`
- `GET /api/learning/dataset` (JSONL download)
- `POST /api/troubleshoot/{id}/feedback` with `{helpful, note?, corrected_root_cause?}`
