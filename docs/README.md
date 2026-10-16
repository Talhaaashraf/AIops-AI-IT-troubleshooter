# AIops project notes

This folder holds the design discussion and decisions behind turning AIops from a read-only monitor into an agentic AI IT troubleshooter.

| File | What it covers |
| --- | --- |
| [01-workspace-summary.md](01-workspace-summary.md) | What the project was before the AI work started |
| [02-agentic-ai-plan.md](02-agentic-ai-plan.md) | The approved plan, kept verbatim |
| [03-implementation-log.md](03-implementation-log.md) | What was built, bugs found, test results, and deviations from the plan |
| [04-docker.md](04-docker.md) | How to run the whole stack in Docker |
| [05-self-improving-model.md](05-self-improving-model.md) | How AIops learns from resolved tickets (`sentinel-tech`) |
| [06-models-and-licensing.md](06-models-and-licensing.md) | The model folder, migration, and license constraints |
| [07-moving-to-another-pc.md](07-moving-to-another-pc.md) | Moving AIops to another PC: code from GitHub, private data (`.env`, database, decisions) by a private zip |

The day-to-day setup guide is the top-level [README.md](../README.md).
