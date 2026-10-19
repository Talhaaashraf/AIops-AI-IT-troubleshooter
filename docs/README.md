# AIops project notes

This folder holds the design discussion and decisions behind turning AIops from a read-only monitor into an AI troubleshooter that suggests fixes and lets a person approve them.

| File | What it covers |
| --- | --- |
| [01-workspace-summary.md](01-workspace-summary.md) | What the project was before the AI work started |
| [02-agentic-ai-plan.md](02-agentic-ai-plan.md) | The first approved plan, kept verbatim (its auto-fix option was later removed) |
| [03-implementation-log.md](03-implementation-log.md) | What was built, bugs found, test results, and deviations from the plan |
| [04-docker.md](04-docker.md) | How to run the whole stack in Docker |
| [05-self-improving-model.md](05-self-improving-model.md) | The `aiops-brain` model: its principles, how it is built, and how it learns from resolved tickets |
| [06-models-and-licensing.md](06-models-and-licensing.md) | The model folder, migration, and license constraints |
| [07-moving-to-another-pc.md](07-moving-to-another-pc.md) | Moving AIops to another PC: code from GitHub, private data (`.env`, database, decisions) by a private zip |
| [08-ai-driven-replan.md](08-ai-driven-replan.md) | The second approved plan, kept verbatim: suggest-only AI with deep thinking, decisions folder, full removal, Performance tab, nginx + ngrok |

The day-to-day setup guide is the top-level [README.md](../README.md).
